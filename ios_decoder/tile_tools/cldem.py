#!/usr/bin/env python3
"""Apple CLDEM elevation tile (``cl3.apple.com/3/v2/<dir_lat>/<dir_lon>/<lat>_<lon>.gz``).

Reverse-engineered from locationd's ``readCLDEMTileHeaderHelper`` / ``getAltitude``. After
gunzip the payload is a generic ``0xABBA`` envelope; scan ≤256 bytes for the ASCII ``CLDEM``
magic, then a 100-byte header (mixed-endian as noted) + a column-major uint8 elevation grid
(``altitude = raw·(max−min)/255 + min``; 0xFF = no-data).

Uniform tile-tool API (see :mod:`ios_decoder.tile_tools`): :func:`parse` (bytes, gunzips),
:func:`render` (header + elevation samples), :func:`bounds` (the tile extent).  CLI:
``python -m ios_decoder.tile_tools.cldem FILE``.
"""

from __future__ import annotations

import math
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple

from . import Bounds
from ._section import maybe_gunzip

OUTER_MAGIC = 0xABBA
OUTER_TYPE_DEM = 0x0004
CLDEM_MAGIC = b"CLDEM"
CLDEM_HDR_SIZE = 100
CLDEM_VERSION = 2


@dataclass
class CLDEMHeader:
    version: int
    subtype: int
    no_data_value: int
    importance: int
    overlap_pixels: int
    data_elem_type: int
    compression: int
    expiration_age: int
    timestamp_raw: int
    ncols: int               # longitude dimension
    nrows: int               # latitude dimension
    data_size: int
    crc32: int
    lat_ll: float            # latitude of lower-left corner (°N)
    lon_ll: float            # longitude of lower-left corner (°E)
    cellsize: float          # degrees per cell
    max_alt: float
    min_alt: float
    uncertainty_x: float
    uncertainty_y: float
    extra_float: float


class CLDEMTile:
    """A parsed CLDEM elevation tile: header + column-major uint8 grid."""

    def __init__(self, header: CLDEMHeader, data: bytes, warnings: Optional[list] = None):
        self.header = header
        self.data = data
        self.warnings = warnings or []      # surfaced in-band by render() as // WARNING: lines

    @classmethod
    def from_bytes(cls, raw: bytes) -> "CLDEMTile":
        data = maybe_gunzip(raw)
        magic, typ, _hdr_len, _body_len = struct.unpack_from(">HHII", data, 0)
        if magic != OUTER_MAGIC:
            raise ValueError(f"Bad outer magic: 0x{magic:04X} (expected 0x{OUTER_MAGIC:04X})")
        if typ != OUTER_TYPE_DEM:
            raise ValueError(f"Unexpected tile type: 0x{typ:04X}")
        off = cls._find_cldem(data, max_scan=256)
        if off is None:
            raise ValueError("CLDEM magic not found in first 256 bytes")
        header = cls._parse_cldem_header(data, off)
        warnings: list[str] = []
        if header.data_size != header.ncols * header.nrows:
            warnings.append(f"declared dataSize {header.data_size} != ncols*nrows "
                            f"{header.ncols * header.nrows} (header self-inconsistent; grid "
                            f"reads may be clamped)")
        cell_start = off + CLDEM_HDR_SIZE
        cell_data = data[cell_start:cell_start + header.data_size]
        if len(cell_data) != header.data_size:
            raise ValueError(f"Truncated cell data: got {len(cell_data)}, "
                             f"expected {header.data_size}")
        return cls(header, cell_data, warnings)

    @classmethod
    def from_file(cls, path: str) -> "CLDEMTile":
        return cls.from_bytes(Path(path).read_bytes())

    @staticmethod
    def _find_cldem(data: bytes, max_scan: int = 256) -> Optional[int]:
        limit = min(max_scan, len(data) - 5)
        for i in range(limit):
            if data[i] == ord("C") and data[i:i + 5] == CLDEM_MAGIC:
                return i
        return None

    @staticmethod
    def _parse_cldem_header(data: bytes, offset: int) -> CLDEMHeader:
        h = data[offset:]
        if h[0:5] != CLDEM_MAGIC:
            raise ValueError(f"CLDEM magic mismatch at offset {offset}")
        version, header_len = h[14], h[15]
        if version != CLDEM_VERSION:
            raise ValueError(f"Unsupported CLDEM version {version} (expected {CLDEM_VERSION})")
        if header_len != CLDEM_HDR_SIZE:
            raise ValueError(f"Bad headerLength {header_len} (expected {CLDEM_HDR_SIZE})")
        ncols = struct.unpack_from(">H", h, 44)[0]
        nrows = struct.unpack_from(">H", h, 46)[0]
        data_size = struct.unpack_from(">I", h, 48)[0]
        header = CLDEMHeader(
            version=version, subtype=h[5], no_data_value=h[16], importance=h[17],
            overlap_pixels=struct.unpack_from("<H", h, 18)[0],       # LE per asm
            data_elem_type=struct.unpack_from("<I", h, 20)[0],       # LE per asm
            compression=h[23],
            expiration_age=struct.unpack_from(">I", h, 24)[0],
            timestamp_raw=struct.unpack_from(">I", h, 28)[0],
            ncols=ncols, nrows=nrows, data_size=data_size,
            crc32=struct.unpack_from(">I", h, 52)[0],
            lat_ll=struct.unpack_from(">d", h, 56)[0],
            lon_ll=struct.unpack_from(">d", h, 64)[0],
            cellsize=struct.unpack_from(">d", h, 72)[0],
            max_alt=struct.unpack_from(">f", h, 80)[0],
            min_alt=struct.unpack_from(">f", h, 84)[0],
            uncertainty_x=struct.unpack_from(">f", h, 88)[0],
            uncertainty_y=struct.unpack_from(">f", h, 92)[0],
            extra_float=struct.unpack_from(">f", h, 96)[0],
        )
        if header.cellsize <= 0:                          # guards every later lat/lon division
            raise ValueError(f"CLDEM cellsize must be > 0, got {header.cellsize}")
        return header

    def _raw_to_altitude(self, raw: int) -> Optional[float]:
        if raw == self.header.no_data_value:
            return None
        scale = (self.header.max_alt - self.header.min_alt) / 255.0
        return raw * scale + self.header.min_alt

    def _cell_altitude(self, col: int, row: int) -> Optional[float]:
        h = self.header
        col = max(0, min(col, h.ncols - 1))
        row = max(0, min(row, h.nrows - 1))
        return self._raw_to_altitude(self.data[col * h.nrows + row])   # column-major

    def contains(self, lat: float, lon: float) -> bool:
        h = self.header
        lat_max = h.lat_ll + h.nrows * h.cellsize
        lon_max = h.lon_ll + h.ncols * h.cellsize
        return (h.lat_ll <= lat <= lat_max) and (h.lon_ll <= lon <= lon_max)

    def get_altitude(
        self, lat: float, lon: float
    ) -> Tuple[Optional[float], Optional[float], Optional[str]]:
        """(altitude_m, uncertainty_m, method), or (None, None, None) if outside the tile.

        ``method`` names how the value was derived so the caller can flag non-ideal samples:
        ``"bilinear"`` (the 4 surrounding cells all had data), ``"bilinear (edge-clamped)"``
        (a +1 neighbour fell off the grid and was clamped to the edge cell), or
        ``"nearest-neighbour (corner no-data)"`` (≥1 corner was no-data, so the headline
        bilinear degraded to the nearest cell)."""
        h = self.header
        if not self.contains(lat, lon):
            return None, None, None
        fy = (lat - h.lat_ll) / h.cellsize
        fx = (lon - h.lon_ll) / h.cellsize
        c0, r0 = int(math.floor(fx)), int(math.floor(fy))
        dx, dy = fx - c0, fy - r0
        edge = c0 < 0 or r0 < 0 or c0 + 1 >= h.ncols or r0 + 1 >= h.nrows
        a00 = self._cell_altitude(c0, r0)
        a10 = self._cell_altitude(c0 + 1, r0)
        a01 = self._cell_altitude(c0, r0 + 1)
        a11 = self._cell_altitude(c0 + 1, r0 + 1)
        valid = [v for v in (a00, a10, a01, a11) if v is not None]
        if not valid:
            return None, None, None
        if len(valid) < 4:
            return (self._cell_altitude(c0 + round(dx), r0 + round(dy)),
                    h.uncertainty_y, "nearest-neighbour (corner no-data)")
        alt = (a00 * (1 - dx) * (1 - dy) + a10 * dx * (1 - dy)
               + a01 * (1 - dx) * dy + a11 * dx * dy)
        return alt, h.uncertainty_y, ("bilinear (edge-clamped)" if edge else "bilinear")

    @staticmethod
    def tile_coords(lat: float, lon: float) -> Tuple[int, int, int, int]:
        lat_int = round((lat + 90) * 10000)
        lon_int = round((lon + 180) * 10000)
        return lat_int // 10000, lon_int // 10000, lat_int, lon_int

    @staticmethod
    def tile_url(lat: float, lon: float) -> str:
        d_la, d_lo, la, lo = CLDEMTile.tile_coords(lat, lon)
        return f"https://cl3.apple.com/3/v2/{d_la}/{d_lo}/{la}_{lo}.gz"

    def __repr__(self) -> str:
        h = self.header
        lat_max = h.lat_ll + h.nrows * h.cellsize
        lon_max = h.lon_ll + h.ncols * h.cellsize
        return (f"<CLDEMTile {h.ncols}×{h.nrows} cells | "
                f"lat [{h.lat_ll:.4f}, {lat_max:.4f}] lon [{h.lon_ll:.4f}, {lon_max:.4f}] | "
                f"alt [{h.min_alt:.0f}, {h.max_alt:.0f}] m>")

    def info(self) -> str:
        h = self.header
        lat_max = h.lat_ll + h.nrows * h.cellsize
        lon_max = h.lon_ll + h.ncols * h.cellsize
        return "\n".join([
            "=== CLDEM Tile Header ===",
            f"  Version:         {h.version}  (subtype 0x{h.subtype:02X})",
            f"  Grid size:       {h.ncols} cols × {h.nrows} rows  ({h.data_size:,} bytes)",
            f"  Cell size:       {h.cellsize:.8f}°  ≈ {h.cellsize * 111_320:.1f} m",
            f"  Overlap:         {h.overlap_pixels} px",
            f"  Extent lat:      [{h.lat_ll:.6f}°N, {lat_max:.6f}°N]",
            f"  Extent lon:      [{h.lon_ll:.6f}°E, {lon_max:.6f}°E]",
            f"  Altitude range:  {h.min_alt:.1f} m – {h.max_alt:.1f} m",
            f"  No-data value:   0x{h.no_data_value:02X}",
            f"  CRC-32:          0x{h.crc32:08X}",
            f"  Uncertainty x/y: {h.uncertainty_x:.3f} m / {h.uncertainty_y:.4f} m",
            f"  Expiry age:      {h.expiration_age} s  ({h.expiration_age / 86400:.1f} days)",
            f"  Timestamp raw:   0x{h.timestamp_raw:08X}  ({h.timestamp_raw} s)",
            f"  Data elem type:  {h.data_elem_type}  (0=uint8)",
            f"  Compression:     {h.compression}  (0=none)",
        ])


# --- uniform tile-tool API ---------------------------------------------------

def parse(data: bytes) -> CLDEMTile:
    """Parse a CLDEM tile body (raw or gzipped) into a :class:`CLDEMTile`."""
    return CLDEMTile.from_bytes(data)


def parse_file(path: "str | Path") -> CLDEMTile:
    return CLDEMTile.from_file(str(path))


def bounds(tile: CLDEMTile) -> Optional[Bounds]:
    h = tile.header
    return Bounds(h.lat_ll, h.lat_ll + h.nrows * h.cellsize,
                 h.lon_ll, h.lon_ll + h.ncols * h.cellsize)


def render(tile: CLDEMTile) -> str:
    h = tile.header
    lat_max = h.lat_ll + h.nrows * h.cellsize
    lon_max = h.lon_ll + h.ncols * h.cellsize
    lines = [f"// WARNING: {w}" for w in tile.warnings]
    lines += [repr(tile), "", tile.info(), "", "=== Elevation samples across tile ===",
              "// note: altitudes are bilinearly interpolated; a tag in [brackets] marks any "
              "sample that instead used a fallback (nearest-neighbour or edge-clamped)"]
    for i in range(5):
        for j in range(5):
            lat = h.lat_ll + (i + 0.5) / 5 * (lat_max - h.lat_ll)
            lon = h.lon_ll + (j + 0.5) / 5 * (lon_max - h.lon_ll)
            alt, unc, method = tile.get_altitude(lat, lon)
            if alt is not None:
                tag = "" if method == "bilinear" else f"  [{method}]"
                lines.append(f"  ({lat:.4f}°N, {lon:.4f}°E)  →  {alt:6.1f} m  (±{unc:.2f} m){tag}")
            else:
                lines.append(f"  ({lat:.4f}°N, {lon:.4f}°E)  →  no data")
    return "\n".join(lines)


def main(argv=None) -> int:
    import argparse
    ap = argparse.ArgumentParser(description="Parse an Apple CLDEM elevation tile")
    ap.add_argument("file", help="tile file (.gz or decompressed)")
    args = ap.parse_args(argv)
    print(render(CLDEMTile.from_file(args.file)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
