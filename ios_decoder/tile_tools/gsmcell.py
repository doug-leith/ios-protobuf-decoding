#!/usr/bin/env python3
"""Apple GSM cell-location tile (``cl2.apple.com/3/v1/…``).

After gunzip the body is a sequence of ``0xABBA`` sections: 5 TileHeader, 6 Index,
7 CellRecords.  Each cell record gives a (lac, cid) and a tile-relative lat/lon fraction
(``lat = SW_lat + frac/65536 · d_lat``); ``cid == 0xFFFFFFFF`` is a LAC-level wildcard.

Uniform tile-tool API (see :mod:`ios_decoder.tile_tools`): :func:`parse` (bytes, gunzips),
:func:`render` (header + first 32 records), :func:`bounds` (the tile's SW/NE box → a
``+++LATLON_BOUNDBOX`` marker).  CLI:
``python -m ios_decoder.tile_tools.gsmcell FILE [--lookup LAC CID] [--csv OUT]``.
"""

from __future__ import annotations

import datetime as _dt
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from . import Bounds
from ._section import Section, iter_sections, maybe_gunzip, usable_record_count

SEC_TILE_HEADER, SEC_INDEX, SEC_RECORDS = 5, 6, 7
WILDCARD_CID = 0xFFFFFFFF
FRAC_DEN = 65536.0


@dataclass
class TileHeader:
    version: int
    tile_y: int
    tile_x: int
    sw_lat: float
    sw_lon: float
    d_lat: float
    d_lon: float
    build_time: int
    sec_key_lo: int

    @classmethod
    def parse(cls, meta: bytes) -> "TileHeader":
        if len(meta) < 184:
            raise ValueError(f"tile header too short: {len(meta)} bytes")
        version, tile_y, tile_x = struct.unpack_from(">III", meta, 0)
        sw_lat, sw_lon, d_lat, d_lon = struct.unpack_from(">ffff", meta, 12)
        build_time = struct.unpack_from(">I", meta, 32)[0]
        sec_key_lo = struct.unpack_from(">I", meta, 180)[0]
        return cls(version, tile_y, tile_x, sw_lat, sw_lon, d_lat, d_lon,
                   build_time, sec_key_lo)

    @property
    def build_datetime(self) -> _dt.datetime:
        return _dt.datetime.fromtimestamp(self.build_time, _dt.timezone.utc)


@dataclass
class IndexEntry:
    lac: int
    cid: int
    record_index: int


@dataclass
class CellRecord:
    lac: int
    cid: int
    lat_frac: int
    lon_frac: int
    uncertainty: int
    flags: int

    def latitude(self, hdr: TileHeader) -> float:
        return hdr.sw_lat + (self.lat_frac / FRAC_DEN) * hdr.d_lat

    def longitude(self, hdr: TileHeader) -> float:
        return hdr.sw_lon + (self.lon_frac / FRAC_DEN) * hdr.d_lon

    @property
    def is_wildcard(self) -> bool:
        return self.cid == WILDCARD_CID

    @property
    def uncertainty_m(self) -> int:
        return self.uncertainty * 1000


def _count_stride(meta: bytes) -> tuple[int, int]:
    return struct.unpack_from(">II", meta, 0)


def parse_index(sec: Section):
    count, stride = _count_stride(sec.meta)
    count, note = usable_record_count(count, stride, len(sec.data), "index")
    entries = [IndexEntry(*struct.unpack_from(">III", sec.data, i * stride))
               for i in range(count)]
    return entries, note


def parse_records(sec: Section):
    count, stride = _count_stride(sec.meta)
    count, note = usable_record_count(count, stride, len(sec.data), "cell records")
    out = []
    for i in range(count):
        base = i * stride
        lac, cid = struct.unpack_from(">II", sec.data, base)
        lat_frac, lon_frac = struct.unpack_from(">HH", sec.data, base + 8)
        out.append(CellRecord(lac, cid, lat_frac, lon_frac,
                              sec.data[base + 12], sec.data[base + 13]))
    return out, note


@dataclass
class CellTile:
    header: TileHeader
    index: list[IndexEntry]
    records: list[CellRecord]
    extra_sections: list[Section] = field(default_factory=list, repr=False)
    warnings: list[str] = field(default_factory=list, repr=False)

    @classmethod
    def from_bytes(cls, blob: bytes) -> "CellTile":
        blob = maybe_gunzip(blob)
        header: Optional[TileHeader] = None
        index: list[IndexEntry] = []
        records: list[CellRecord] = []
        extra: list[Section] = []
        warnings: list[str] = []
        for sec in iter_sections(blob):
            if sec.id == SEC_TILE_HEADER:
                header = TileHeader.parse(sec.meta)
            elif sec.id == SEC_INDEX:
                index, note = parse_index(sec)
                if note:
                    warnings.append(note)
            elif sec.id == SEC_RECORDS:
                records, note = parse_records(sec)
                if note:
                    warnings.append(note)
            else:
                extra.append(sec)
        if header is None:
            raise ValueError("no TileHeader (section id=5) found")
        return cls(header, index, records, extra, warnings)

    @classmethod
    def from_file(cls, path: str) -> "CellTile":
        return cls.from_bytes(Path(path).read_bytes())

    def lookup(self, lac: int, cid: int) -> Optional[CellRecord]:
        wildcard = None
        for r in self.records:
            if r.lac == lac:
                if r.cid == cid:
                    return r
                if r.cid == WILDCARD_CID:
                    wildcard = r
        return wildcard

    def location_of(self, lac: int, cid: int):
        r = self.lookup(lac, cid)
        if r is None:
            return None
        return (r.latitude(self.header), r.longitude(self.header), r.uncertainty_m)


# --- uniform tile-tool API ---------------------------------------------------

def parse(data: bytes) -> CellTile:
    """Parse a GSM cell tile body (raw or gzipped) into a :class:`CellTile`."""
    return CellTile.from_bytes(data)


def parse_file(path: "str | Path") -> CellTile:
    return CellTile.from_file(str(path))


def bounds(tile: CellTile) -> Optional[Bounds]:
    """The tile's geographic extent (SW corner + d_lat/d_lon) → a ``+++LATLON_BOUNDBOX``."""
    h = tile.header
    return Bounds(h.sw_lat, h.sw_lat + h.d_lat, h.sw_lon, h.sw_lon + h.d_lon)


def render(tile: CellTile, num_records: int = 32) -> str:
    h = tile.header
    lines = [f"// WARNING: {w}" for w in tile.warnings]
    lines.append("// note: lat/lon are tile-grid quantized (frac/65536 × tile extent), "
                 "not surveyed precision; see unc_m")
    lines += [
        "Tile header",
        f"  version       : {h.version}",
        f"  tile grid     : tileY={h.tile_y}  tileX={h.tile_x}",
        f"  SW corner     : lat={h.sw_lat:.6f}  lon={h.sw_lon:.6f}",
        f"  tile span     : dLat={h.d_lat:g}  dLon={h.d_lon:g}  "
        f"(covers lat [{h.sw_lat:g},{h.sw_lat + h.d_lat:g}], "
        f"lon [{h.sw_lon:g},{h.sw_lon + h.d_lon:g}])",
        f"  built         : {h.build_time}  ({h.build_datetime:%Y-%m-%d %H:%M:%S} UTC)",
        f"  sec_key (lo)  : 0x{h.sec_key_lo:08x}",
        "",
        f"Index entries   : {len(tile.index)}",
        f"Cell records    : {len(tile.records)}",
        f"  of which LAC-level (cid=0xFFFFFFFF): "
        f"{sum(1 for r in tile.records if r.is_wildcard)}",
    ]
    if tile.extra_sections:
        lines.append(f"Other sections  : {[s.id for s in tile.extra_sections]}")
    lines.append("")
    n = num_records if (num_records and num_records < len(tile.records)) else len(tile.records)
    if num_records and num_records < len(tile.records):
        lines.append(f"First {num_records} cell records:")
    lines.append(f"  {'lac':>6}  {'cid':>10}  {'lat':>10}  {'lon':>10}  {'unc_m':>7}  flags")
    for r in tile.records[:n]:
        cid = "wildcard" if r.is_wildcard else str(r.cid)
        lines.append(f"  {r.lac:>6}  {cid:>10}  {r.latitude(h):>10.5f}  "
                     f"{r.longitude(h):>10.5f}  {r.uncertainty_m:>7}  {r.flags}")
    return "\n".join(lines)


def main(argv=None) -> int:
    import argparse
    ap = argparse.ArgumentParser(description="Parse an Apple GSM cell-location tile")
    ap.add_argument("tile", help="path to the tile (.gz body or inflated)")
    ap.add_argument("--lookup", nargs=2, type=int, metavar=("LAC", "CID"),
                    help="resolve one cell to a location")
    ap.add_argument("--csv", metavar="OUT", help="write all records to a CSV file")
    args = ap.parse_args(argv)
    tile = CellTile.from_file(args.tile)
    print(render(tile))
    if args.lookup:
        loc = tile.location_of(*args.lookup)
        print()
        print(f"lookup lac={args.lookup[0]} cid={args.lookup[1]}: "
              + ("not found" if loc is None
                 else f"lat={loc[0]:.6f} lon={loc[1]:.6f} ~{loc[2]} m"))
    if args.csv:
        import csv
        h = tile.header
        with open(args.csv, "w", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(["lac", "cid", "latitude", "longitude", "uncertainty_m", "flags"])
            for r in tile.records:
                w.writerow([r.lac, "" if r.is_wildcard else r.cid,
                            f"{r.latitude(h):.6f}", f"{r.longitude(h):.6f}",
                            r.uncertainty_m, r.flags])
        print(f"\nwrote {len(tile.records)} records to {args.csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
