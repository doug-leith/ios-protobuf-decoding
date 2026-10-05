#!/usr/bin/env python3
"""Apple CoarseCell (LTE) location tile (``cl2.apple.com/4/v1/…``).

Reverse-engineered from locationd's ``CLCoarseCellTilesManager``.  After gunzip the body is
a sequence of ``0xABBA`` sections: 0x5 Metadata (tile extent), 0x6 sparse Index, 0x7 Data
(14-byte cell records: TAC, CID, grid_y/grid_x fractional coords, LE accuracy).  Coordinates
``lat = SW_lat + grid_y/65536 · d_lat`` (likewise lon); ``CID == 0xFFFFFFFF`` is unknown.

Uniform tile-tool API (see :mod:`ios_decoder.tile_tools`): :func:`parse` (bytes, gunzips),
:func:`render` (metadata + first 20 cell/index entries), :func:`bounds` (the tile's SW/NE box
→ a ``+++LATLON_BOUNDBOX`` marker).
CLI: ``python -m ios_decoder.tile_tools.ltecell FILE [--lookup TAC CID]``.
"""

from __future__ import annotations

import bisect
import dataclasses
import struct
from pathlib import Path
from typing import List, Optional

from . import Bounds
from ._section import iter_sections, maybe_gunzip, usable_record_count

_KIND_METADATA, _KIND_INDEX, _KIND_DATA = 0x0005, 0x0006, 0x0007
_COORD_SCALE = 65536.0
_UNKNOWN_CID = 0xFFFFFFFF


@dataclasses.dataclass
class TileMetadata:
    tile_version: int
    tile_x: int
    tile_y: int
    sw_lat: float
    sw_lon: float
    d_lat: float
    d_lon: float
    timestamp: int
    grid_rows: int
    grid_cols: int

    @property
    def ne_lat(self) -> float:
        return self.sw_lat + self.d_lat

    @property
    def ne_lon(self) -> float:
        return self.sw_lon + self.d_lon

    def __str__(self) -> str:
        return (f"\n{'Version:':>12} {self.tile_version}\n"
                f"{'Timestamp:':>12} unix {self.timestamp}\n"
                f"{'SW corner:':>12} lat {self.sw_lat:.4f} lon {self.sw_lon:.4f}\n"
                f"{'NE corner:':>12} lat {self.ne_lat:.4f} lon {self.ne_lon:.4f}\n"
                f"{'tile span:':>12} dLat={self.d_lat:g}  dLon={self.d_lon:g}\n"
                f"{'grid:':>12} {self.grid_rows} rows x {self.grid_cols} cols\n")


@dataclasses.dataclass
class CellEntry:
    tac: int
    cid: int
    lat: float
    lon: float
    accuracy: int
    reserved: int

    @property
    def cid_unknown(self) -> bool:
        return self.cid == _UNKNOWN_CID

    def __str__(self) -> str:
        cid_s = "UNKNOWN" if self.cid_unknown else f"0x{self.cid:08x}"
        return (f"CellEntry(tac={self.tac}, cid={cid_s}, "
                f"lat={self.lat:.5f}, lon={self.lon:.5f}, acc={self.accuracy})")


@dataclasses.dataclass
class IndexEntry:
    tac: int
    cid: int
    data_start_index: int


def _parse_primary_meta(data: bytes, offset: int):
    num_entries = struct.unpack_from(">H", data, offset + 2)[0]
    entry_size = struct.unpack_from(">I", data, offset + 4)[0]
    return num_entries, entry_size


def _parse_metadata_section(data: bytes, base: int) -> TileMetadata:
    tile_version = struct.unpack_from(">H", data, base + 2)[0]
    tile_x, tile_y = struct.unpack_from(">II", data, base + 4)
    sw_lat, sw_lon, d_lat, d_lon = struct.unpack_from(">ffff", data, base + 12)
    timestamp = struct.unpack_from(">I", data, base + 32)[0]
    grid_rows = struct.unpack_from("<I", data, base + 44)[0]
    grid_cols = struct.unpack_from("<I", data, base + 48)[0]
    return TileMetadata(tile_version, tile_x, tile_y, sw_lat, sw_lon, d_lat, d_lon,
                        timestamp, grid_rows, grid_cols)


def _decode_index_entry(data: bytes, offset: int) -> IndexEntry:
    tac = struct.unpack_from(">H", data, offset + 2)[0]
    cid = struct.unpack_from(">I", data, offset + 4)[0]
    start_idx = struct.unpack_from(">I", data, offset + 8)[0]
    return IndexEntry(tac, cid, start_idx)


def _decode_data_entry(data, offset, sw_lat, sw_lon, d_lat, d_lon) -> CellEntry:
    reserved = struct.unpack_from(">H", data, offset + 0)[0]
    tac = struct.unpack_from(">H", data, offset + 2)[0]
    cid = struct.unpack_from(">I", data, offset + 4)[0]
    grid_y = struct.unpack_from(">H", data, offset + 8)[0]
    grid_x = struct.unpack_from(">H", data, offset + 10)[0]
    # little-endian inside an otherwise big-endian record — VERIFIED against real tiles:
    # LE yields sensible values (2..150, clustered low); BE yields byte-swapped garbage (×256).
    accuracy = struct.unpack_from("<H", data, offset + 12)[0]
    lat = sw_lat + (grid_y / _COORD_SCALE) * d_lat
    lon = sw_lon + (grid_x / _COORD_SCALE) * d_lon
    return CellEntry(tac, cid, lat, lon, accuracy, reserved)


def _signed_cid(cid: int) -> int:
    return cid if cid <= 0x7FFFFFFF else cid - 0x100000000


class CoarseCellTile:
    """A parsed Apple CoarseCell (LTE) location tile: metadata + cell records + index."""

    def __init__(self, metadata: TileMetadata, entries: List[CellEntry],
                 index_entries: List[IndexEntry], warnings: Optional[List[str]] = None):
        self.metadata = metadata
        self.entries = entries
        self.index_entries = index_entries
        self.warnings = warnings or []
        self._data_keys = [(e.tac, _signed_cid(e.cid)) for e in entries]
        self._index_keys = [(ie.tac, _signed_cid(ie.cid)) for ie in index_entries]

    @classmethod
    def from_bytes(cls, data: bytes) -> "CoarseCellTile":
        return cls._parse_raw(maybe_gunzip(data))

    @classmethod
    def from_file(cls, path: str) -> "CoarseCellTile":
        return cls.from_bytes(Path(path).read_bytes())

    @classmethod
    def _parse_raw(cls, raw: bytes) -> "CoarseCellTile":
        metadata: Optional[TileMetadata] = None
        entries: List[CellEntry] = []
        index_entries: List[IndexEntry] = []
        warnings: List[str] = []
        for sec in iter_sections(raw):
            if sec.id == _KIND_METADATA:
                metadata = _parse_metadata_section(sec.meta, 0)
            elif sec.id == _KIND_INDEX:
                n_entries, entry_size = _parse_primary_meta(sec.meta, 0)
                if entry_size != 12:
                    raise ValueError(f"Unexpected index entry size {entry_size} (expected 12)")
                n_entries, note = usable_record_count(n_entries, entry_size, len(sec.data), "index")
                if note:
                    warnings.append(note)
                for i in range(n_entries):
                    index_entries.append(_decode_index_entry(sec.data, i * entry_size))
            elif sec.id == _KIND_DATA:
                if metadata is None:
                    raise ValueError("Data section encountered before Metadata section")
                n_entries, entry_size = _parse_primary_meta(sec.meta, 0)
                if entry_size != 14:
                    raise ValueError(f"Unexpected data entry size {entry_size} (expected 14)")
                n_entries, note = usable_record_count(n_entries, entry_size, len(sec.data),
                                                      "cell records")
                if note:
                    warnings.append(note)
                for i in range(n_entries):
                    entries.append(_decode_data_entry(
                        sec.data, i * entry_size,
                        metadata.sw_lat, metadata.sw_lon, metadata.d_lat, metadata.d_lon))
        if metadata is None:
            raise ValueError("No Metadata section found in tile")
        return cls(metadata, entries, index_entries, warnings)

    def lookup(self, tac: int, cid: int) -> Optional[CellEntry]:
        if not self.entries:
            return None
        key = (tac, _signed_cid(cid))
        start_idx = 0
        if self.index_entries:
            pos = bisect.bisect_right(self._index_keys, key) - 1
            if pos >= 0:
                start_idx = self.index_entries[pos].data_start_index
        idx = bisect.bisect_left(self._data_keys, key, start_idx, len(self.entries))
        if idx < len(self.entries) and self._data_keys[idx] == key:
            return self.entries[idx]
        return None

    def __len__(self) -> int:
        return len(self.entries)

    def __repr__(self) -> str:
        return (f"CoarseCellTile({self.metadata}, {len(self.entries)} entries, "
                f"{len(self.index_entries)} index entries)")


# --- uniform tile-tool API ---------------------------------------------------

def parse(data: bytes) -> CoarseCellTile:
    """Parse an LTE coarse-cell tile body (raw or gzipped) into a :class:`CoarseCellTile`."""
    return CoarseCellTile.from_bytes(data)


def parse_file(path: "str | Path") -> CoarseCellTile:
    return CoarseCellTile.from_file(str(path))


def bounds(tile: CoarseCellTile) -> Optional[Bounds]:
    """The tile's geographic extent (metadata SW/NE corners) → a ``+++LATLON_BOUNDBOX``."""
    m = tile.metadata
    return Bounds(m.sw_lat, m.ne_lat, m.sw_lon, m.ne_lon)


def render(tile: CoarseCellTile, num_entries: int = 20) -> str:
    lines = [f"// WARNING: {w}" for w in tile.warnings]
    lines.append("// note: lat/lon are tile-grid quantized (grid/65536 × tile extent), "
                 "not surveyed precision; see acc")
    lines += [f"  {tile.metadata}",
              f"  {len(tile.entries):,} data entries, {len(tile.index_entries)} index entries",
              ""]
    n = min(num_entries, len(tile.entries))
    lines.append(f"First {n} cell entries:")
    lines += [f"  [{i:5d}] {e}" for i, e in enumerate(tile.entries[:n])]
    n = min(num_entries, len(tile.index_entries))
    lines.append(f"First {n} index entries:")
    lines += [f"  [{i:5d}] {e}" for i, e in enumerate(tile.index_entries[:n])]
    return "\n".join(lines)


def main(argv=None) -> int:
    import argparse
    ap = argparse.ArgumentParser(description="Parse an Apple LTE coarse-cell tile")
    ap.add_argument("file", help="tile file (.gz or decompressed)")
    ap.add_argument("--lookup", nargs=2, type=int, metavar=("TAC", "CID"),
                    help="resolve one cell to a location")
    args = ap.parse_args(argv)
    tile = CoarseCellTile.from_file(args.file)
    print(render(tile))
    if args.lookup:
        e = tile.lookup(*args.lookup)
        print()
        print(f"lookup tac={args.lookup[0]} cid={args.lookup[1]}: {e if e else 'not found'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
