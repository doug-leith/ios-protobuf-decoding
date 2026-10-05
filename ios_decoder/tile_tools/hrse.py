#!/usr/bin/env python3
"""Apple locationd HRSE (High-Resolution Signal Environment) tile.

Served from ``cl3.apple.com/2/v1/<latDir>/<lonDir>/<lat>_<lon>.gz``; format reverse-
engineered from locationd's ``CLHighResolutionSignalEnvironmentDataManager``.  After gunzip
the payload is a generic ``0xABBA`` envelope; locationd just scans forward (≤256 bytes) for
the ASCII magic ``CLHRSE`` and parses a fixed 184-byte big-endian header + a nibble-packed
signal-environment grid (one 4-bit cell per nibble, even=high, odd=low). All numbers BE.

Uniform tile-tool API (see :mod:`ios_decoder.tile_tools`): :func:`parse` (bytes, gunzips),
:func:`render` (report + ASCII preview), :func:`bounds` (the tile coverage box).  CLI:
``python -m ios_decoder.tile_tools.hrse FILE``.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from . import Bounds
from ._section import cf_to_utc, crc32_zeroed, find_magic, maybe_gunzip, nibble_of

HRSE_MAGIC = b"CLHRSE"
HEADER_LEN = 0xB8          # 184
MAX_SCAN = 256             # locationd scans at most this far for the magic
CRC_OFF = 64

# Raw on-disk nibble → human label ({5, 7..15} are rejected by locationd).
SIGNAL_ENV = {0: "Unavailable", 1: "Rural", 2: "Urban", 3: "DenseUrban",
              4: "DenseUrbanCanyon", 6: "Marine"}


class HRSEError(Exception):
    """Raised when a buffer is not a valid HRSE tile."""


@dataclass
class HRSEHeader:
    version: int
    header_length: int
    compression_type: int
    expiration_age: int
    timestamp: float          # CFAbsoluteTime (seconds since 2001-01-01 UTC)
    nrows: int
    ncols: int
    xllcorner: float          # lower-left longitude (minLon)
    yllcorner: float          # lower-left latitude  (minLat)
    cellsize: float           # degrees per cell
    crc: int
    data_size_bytes: int

    @property
    def min_lon(self) -> float:
        return self.xllcorner

    @property
    def min_lat(self) -> float:
        return self.yllcorner

    @property
    def max_lon(self) -> float:
        return self.xllcorner + self.ncols * self.cellsize

    @property
    def max_lat(self) -> float:
        return self.yllcorner + self.nrows * self.cellsize


class HRSETile:
    """A parsed CLHRSE tile: header + decoded nibble grid."""

    def __init__(self, header: HRSEHeader, data: bytes):
        self.header = header
        self.data = data

    @classmethod
    def parse(cls, buf: bytes, *, verify_crc: bool = True) -> "HRSETile":
        buf = maybe_gunzip(buf)
        region = buf[find_magic(buf, HRSE_MAGIC, MAX_SCAN, full_fallback=True, exc=HRSEError):]
        if len(region) < HEADER_LEN:
            raise HRSEError("truncated: region shorter than 184-byte header")
        h = _parse_header(region)
        end = HEADER_LEN + h.data_size_bytes
        if len(region) < end:
            raise HRSEError(f"truncated: need {end} bytes of CLHRSE region, have {len(region)}")
        if verify_crc:
            calc = crc32_zeroed(region[:end], CRC_OFF)
            if calc != h.crc:
                raise HRSEError(f"CRC mismatch: calculated 0x{calc:08X}, header 0x{h.crc:08X}")
        return cls(h, region[HEADER_LEN:end])

    @classmethod
    def from_file(cls, path: str, *, verify_crc: bool = True) -> "HRSETile":
        return cls.parse(Path(path).read_bytes(), verify_crc=verify_crc)

    def nibble_at(self, row: int, col: int) -> int:
        h = self.header
        if not (0 <= row < h.nrows and 0 <= col < h.ncols):
            raise IndexError(f"({row},{col}) outside {h.nrows}x{h.ncols} grid")
        i = row * h.ncols + col
        byte = self.data[i >> 1]
        return nibble_of(byte, i, high_even=True)             # CLHRSE: even idx = high nibble

    def at_latlon(self, lat: float, lon: float) -> int:
        h = self.header
        if h.cellsize == 0:
            raise HRSEError("cellsize is zero")
        col = int((lon - h.xllcorner) // h.cellsize)
        row = int((lat - h.yllcorner) // h.cellsize)
        return self.nibble_at(row, col)

    def label_at_latlon(self, lat: float, lon: float) -> str:
        n = self.at_latlon(lat, lon)
        return SIGNAL_ENV.get(n, f"Invalid(0x{n:X})")

    def histogram(self) -> dict[int, int]:
        h = self.header
        counts: dict[int, int] = {}
        for i in range(h.nrows * h.ncols):
            byte = self.data[i >> 1]
            n = nibble_of(byte, i, high_even=True)
            counts[n] = counts.get(n, 0) + 1
        return dict(sorted(counts.items()))


def _parse_header(region: bytes) -> HRSEHeader:
    if region[:6] != HRSE_MAGIC:
        raise HRSEError("region does not start with CLHRSE magic")
    version = struct.unpack_from(">H", region, 8)[0]
    if version != 1:
        raise HRSEError(f"unexpected version: {version}")
    header_length = struct.unpack_from(">I", region, 10)[0]
    if header_length != HEADER_LEN:
        raise HRSEError(f"unexpected headerLength: {header_length} (want {HEADER_LEN})")
    nrows = struct.unpack_from(">I", region, 28)[0]
    ncols = struct.unpack_from(">I", region, 32)[0]
    data_size_bytes = struct.unpack_from(">I", region, 68)[0]
    if data_size_bytes != (nrows * ncols) // 2:
        raise HRSEError(f"dataSizeBytes ({data_size_bytes}) != nrows*ncols/2 "
                        f"({(nrows * ncols) // 2})")
    return HRSEHeader(
        version=version, header_length=header_length,
        compression_type=struct.unpack_from(">H", region, 14)[0],
        expiration_age=struct.unpack_from(">I", region, 16)[0],
        timestamp=struct.unpack_from(">d", region, 20)[0],
        nrows=nrows, ncols=ncols,
        xllcorner=struct.unpack_from(">d", region, 36)[0],
        yllcorner=struct.unpack_from(">d", region, 44)[0],
        cellsize=struct.unpack_from(">f", region, 52)[0],
        crc=struct.unpack_from(">I", region, 64)[0],
        data_size_bytes=data_size_bytes,
    )


# --- uniform tile-tool API ---------------------------------------------------

def parse(data: bytes) -> HRSETile:
    """Parse an HRSE tile body (raw or gzipped) into an :class:`HRSETile`."""
    return HRSETile.parse(data)


def parse_file(path: "str | Path") -> HRSETile:
    return HRSETile.from_file(str(path))


def bounds(tile: HRSETile) -> Optional[Bounds]:
    h = tile.header
    return Bounds(h.min_lat, h.max_lat, h.min_lon, h.max_lon)


def _format_report(tile: HRSETile) -> str:
    h = tile.header
    when = cf_to_utc(h.timestamp)
    lines = [
        "== CLHRSE tile ==",
        f"  version           {h.version}",
        f"  headerLength      {h.header_length}",
        f"  compressionType   {h.compression_type}",
        f"  expirationAge     {h.expiration_age} s",
        f"  timestamp         {h.timestamp:.1f} (CFAbsoluteTime) = {when:%Y-%m-%d %H:%M:%S UTC}",
        f"  grid              {h.nrows} rows x {h.ncols} cols = {h.nrows * h.ncols} cells",
        f"  dataSizeBytes     {h.data_size_bytes}",
        f"  cellsize          {h.cellsize:.7f} deg/cell",
        f"  lower-left        lat {h.yllcorner:.5f}, lon {h.xllcorner:.5f}",
        f"  coverage          lat [{h.min_lat:.4f} .. {h.max_lat:.4f}], "
        f"lon [{h.min_lon:.4f} .. {h.max_lon:.4f}]",
        f"  crc               0x{h.crc:08X} (verified)",
        "",
        "== signal-environment histogram ==",
    ]
    total = h.nrows * h.ncols
    for n, c in tile.histogram().items():
        name = SIGNAL_ENV.get(n, f"Invalid(0x{n:X})")
        lines.append(f"  {n}  {name:<17} {c:6d}  ({100.0 * c / total:5.1f}%)")
    clat = (h.min_lat + h.max_lat) / 2
    clon = (h.min_lon + h.max_lon) / 2
    lines += ["", f"== lookup at tile centre ({clat:.4f}, {clon:.4f}) ==",
              f"  -> {tile.label_at_latlon(clat, clon)}"]
    return "\n".join(lines)


def _format_preview(tile: HRSETile, step: int = 6) -> str:
    glyph = {0: ".", 1: "_", 2: "u", 3: "U", 4: "C", 6: "~"}
    h = tile.header
    lines = ["", f"== ascii preview (1 char per {step}x{step} block, north up) =="]
    for r in range(h.nrows - 1, -1, -step):
        lines.append("  " + "".join(glyph.get(tile.nibble_at(r, c), "?")
                                    for c in range(0, h.ncols, step)))
    return "\n".join(lines)


def render(tile: HRSETile) -> str:
    return _format_report(tile) + "\n" + _format_preview(tile)


def main(argv=None) -> int:
    import argparse
    ap = argparse.ArgumentParser(description="Parse an Apple HRSE tile (cl3.apple.com/2/v1/…)")
    ap.add_argument("file", help="tile file (.gz or decompressed)")
    ap.add_argument("--no-crc", action="store_true", help="skip CRC verification")
    args = ap.parse_args(argv)
    print(render(HRSETile.from_file(args.file, verify_crc=not args.no_crc)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
