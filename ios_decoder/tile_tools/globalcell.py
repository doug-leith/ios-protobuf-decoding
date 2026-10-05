#!/usr/bin/env python3
"""Apple locationd global CoarseCell tile (``cl2.apple.com/{6,7,8,11}/v1/…``).

One file format serves four radio technologies (GSM / CDMA / LTE / 5G-NR), distinguished by
URL; the decoder is identical and only the ``CID`` column label differs.  After gunzip the
body is ``0xABBA`` sections: 5 TileHeader, 6 Index (mcc/mnc/cid → record), 7 Data
(mcc/mnc/cid + lat/lon fractional coords + LE accuracy).  Coordinates use the cell-centre:
``lat = SW_lat + lat_extent·(frac+0.5)/65536`` (likewise lon).

Uniform tile-tool API (see :mod:`ios_decoder.tile_tools`): :func:`parse` (bytes, gunzips),
:func:`render` (header + up to 100 cells; pass ``kind=`` for the column label), :func:`bounds`
(None — see below).  CLI: ``python -m ios_decoder.tile_tools.globalcell FILE [--lookup MCC MNC CID]``.
"""

from __future__ import annotations

import datetime
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Optional

from . import Bounds
from ._section import iter_sections, maybe_gunzip

SECT_HEADER, SECT_INDEX, SECT_DATA = 0x0005, 0x0006, 0x0007
COORD_DENOM = 65536.0


@dataclass(frozen=True)
class TileHeader:
    version: int
    sw_lat: float
    sw_lon: float
    lat_extent: float
    lon_extent: float
    timestamp: int

    @property
    def ne_lat(self) -> float:
        return self.sw_lat + self.lat_extent

    @property
    def ne_lon(self) -> float:
        return self.sw_lon + self.lon_extent

    @property
    def utc_time(self) -> datetime.datetime:
        return datetime.datetime.fromtimestamp(self.timestamp, tz=datetime.timezone.utc)


@dataclass(frozen=True)
class IndexEntry:
    mcc: int
    mnc: int
    cid: int
    record_idx: int


@dataclass(frozen=True)
class DataEntry:
    mcc: int
    mnc: int
    cid: int
    lat_frac: int
    lon_frac: int
    accuracy_code: int


@dataclass(frozen=True)
class Cell:
    mcc: int
    mnc: int
    cid: int
    lat: float
    lon: float
    accuracy_code: int


def _parse_tile_header(meta: bytes) -> TileHeader:
    if len(meta) < 36:                     # fail noisily (like gsmcell) vs an opaque struct.error
        raise ValueError(f"global-cell tile header too short: {len(meta)} bytes (need >= 36)")
    version = struct.unpack_from(">I", meta, 0)[0]
    sw_lat, sw_lon, lat_extent, lon_extent = struct.unpack_from(">ffff", meta, 12)
    timestamp = struct.unpack_from(">I", meta, 32)[0]
    return TileHeader(version, sw_lat, sw_lon, lat_extent, lon_extent, timestamp)


def _parse_index(meta: bytes, data: bytes) -> list[IndexEntry]:
    entry_count, entry_stride = struct.unpack_from(">II", meta, 0)
    if entry_stride != 12:
        raise ValueError(f"Unexpected index stride {entry_stride} (expected 12)")
    if len(data) != entry_count * 12:
        raise ValueError(f"Index data length {len(data)} ≠ {entry_count * 12}")
    return [IndexEntry(*struct.unpack_from(">HHII", data, i * 12)) for i in range(entry_count)]


def _parse_data(meta: bytes, data: bytes) -> list[DataEntry]:
    entry_count, entry_stride = struct.unpack_from(">II", meta, 0)
    if entry_stride != 16:
        raise ValueError(f"Unexpected data stride {entry_stride} (expected 16)")
    if len(data) != entry_count * 16:
        raise ValueError(f"Data section length {len(data)} ≠ {entry_count * 16}")
    out = []
    for i in range(entry_count):
        off = i * 16
        mcc, mnc, cid = struct.unpack_from(">HHI", data, off)
        lat_frac, lon_frac = struct.unpack_from(">HH", data, off + 8)
        # little-endian inside a big-endian record — VERIFIED against real tiles: LE gives a
        # small sensible code (149 for lte/gsm/cdma, 3 for 5g); BE gives a >2-billion garbage value.
        accuracy_code, = struct.unpack_from("<I", data, off + 12)
        out.append(DataEntry(mcc, mnc, cid, lat_frac, lon_frac, accuracy_code))
    return out


def _decode_coords(hdr: TileHeader, lat_frac: int, lon_frac: int):
    lat = hdr.sw_lat + hdr.lat_extent * (lat_frac + 0.5) / COORD_DENOM
    lon = hdr.sw_lon + hdr.lon_extent * (lon_frac + 0.5) / COORD_DENOM
    return lat, lon


class CoarseCellTile:
    """A parsed global CoarseCell tile: header + index + data, with (mcc,mnc,cid) lookup."""

    def __init__(self, header: TileHeader, index: list[IndexEntry], data: list[DataEntry]):
        self.header = header
        self.index = index
        self.data = data
        self._by_key = {(e.mcc, e.mnc, e.cid): e for e in data}

    def lookup(self, mcc: int, mnc: int, cid: int) -> Optional[Cell]:
        e = self._by_key.get((mcc, mnc, cid))
        if e is None:
            return None
        lat, lon = _decode_coords(self.header, e.lat_frac, e.lon_frac)
        return Cell(mcc, mnc, cid, lat, lon, e.accuracy_code)

    def cells(self) -> Iterator[Cell]:
        for e in self.data:
            lat, lon = _decode_coords(self.header, e.lat_frac, e.lon_frac)
            yield Cell(e.mcc, e.mnc, e.cid, lat, lon, e.accuracy_code)


# --- uniform tile-tool API ---------------------------------------------------

def parse(data: bytes) -> CoarseCellTile:
    """Parse a global CoarseCell tile body (raw or gzipped) into a :class:`CoarseCellTile`."""
    header: Optional[TileHeader] = None
    index_e: Optional[list[IndexEntry]] = None
    data_e: Optional[list[DataEntry]] = None
    for sec in iter_sections(maybe_gunzip(data)):
        if sec.id == SECT_HEADER:
            header = _parse_tile_header(sec.meta)
        elif sec.id == SECT_INDEX:
            index_e = _parse_index(sec.meta, sec.data)
        elif sec.id == SECT_DATA:
            data_e = _parse_data(sec.meta, sec.data)
    if header is None:
        raise ValueError("Section 0x0005 (tile header) not found")
    if index_e is None:
        raise ValueError("Section 0x0006 (index) not found")
    if data_e is None:
        raise ValueError("Section 0x0007 (data) not found")
    return CoarseCellTile(header, index_e, data_e)


def parse_file(path: "str | Path") -> CoarseCellTile:
    return parse(Path(path).read_bytes())


def bounds(tile: CoarseCellTile) -> Optional[Bounds]:
    """The tile's geographic extent (header SW/NE corners) → a ``+++LATLON_BOUNDBOX``."""
    h = tile.header
    return Bounds(h.sw_lat, h.ne_lat, h.sw_lon, h.ne_lon)


def _format_info(tile: CoarseCellTile) -> str:
    hdr = tile.header
    lines = [
        f"Version    : {hdr.version}",
        f"Timestamp  : {hdr.utc_time.isoformat()}  (unix {hdr.timestamp})",
        f"SW corner  : lat {hdr.sw_lat:.4f}  lon {hdr.sw_lon:.4f}",
        f"NE corner  : lat {hdr.ne_lat:.4f}  lon {hdr.ne_lon:.4f}",
        f"Extent     : {hdr.lat_extent:.4f}° × {hdr.lon_extent:.4f}°",
        f"Index rows : {len(tile.index):,}",
        f"Data rows  : {len(tile.data):,}",
    ]
    acc_vals = {e.accuracy_code for e in tile.data}
    if len(acc_vals) == 1:
        lines.append(f"Acc. codes : {acc_vals.pop()} (uniform)")
    else:
        lines.append(f"Acc. codes : {len(acc_vals)} distinct values, "
                     f"sample: {sorted(acc_vals)[:5]}")
    return "\n".join(lines)


def _format_dump(tile: CoarseCellTile, limit: Optional[int] = 100,
                 kind: str = "CID") -> str:
    lines = [f"{'MCC':>5}  {'MNC':>5}  {kind:>20}  {'LAT':>10}  {'LON':>11}  {'ACC':>6}",
             "-" * 60]
    count = 0
    for cell in tile.cells():
        lines.append(f"{cell.mcc:5d}  {cell.mnc:5d}  {cell.cid:20d}  "
                     f"{cell.lat:10.5f}  {cell.lon:11.5f}  {cell.accuracy_code:6d}")
        count += 1
        if limit and count >= limit:
            lines.append(f"  … (stopped after {limit} rows)")
            break
    lines.append(f"\n{count} rows")
    return "\n".join(lines)


def render(tile: CoarseCellTile, kind: str = "CID") -> str:
    """Header info + up to 100 decoded cells; ``kind`` sets the CID column label."""
    note = ("// note: lat/lon are tile-grid quantized (cell-centre, (frac+0.5)/65536 × "
            "extent), not surveyed precision; see ACC\n")
    return note + _format_info(tile) + "\n" + _format_dump(tile, limit=100, kind=kind)


def main(argv=None) -> int:
    import argparse
    ap = argparse.ArgumentParser(description="Parse an Apple global CoarseCell tile")
    ap.add_argument("file", help="tile file (.gz or decompressed)")
    ap.add_argument("--lookup", nargs=3, type=lambda x: int(x, 0),
                    metavar=("MCC", "MNC", "CID"), help="resolve one cell")
    args = ap.parse_args(argv)
    tile = parse_file(args.file)
    print(render(tile))
    if args.lookup:
        c = tile.lookup(*args.lookup)
        print()
        if c is None:
            print(f"Not found: MCC={args.lookup[0]} MNC={args.lookup[1]} CID={args.lookup[2]}")
        else:
            print(f"MCC={c.mcc} MNC={c.mnc} CID={c.cid}: lat={c.lat:.6f} lon={c.lon:.6f} "
                  f"acc={c.accuracy_code}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
