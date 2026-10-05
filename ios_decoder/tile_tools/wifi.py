#!/usr/bin/env python3
"""Apple WiFi tile (``cl2.apple.com/1/v1/<y>/<x>/<tileY>_<tileX>.gz``).

Format confirmed by disassembling ``CLWifiTileFile::traverseTileFile`` in locationd.
After gzip decompression the file is a sequence of sections, each a 12-byte big-endian
header (``sig=0xABBA · id · meta_size · data_size``) then ``meta+data`` bytes:

  1 TileHeader — TILE_Y/X + SW lat/lon + tile size (°)
  2 Index      — sparse sorted MAC index (count, stride, then mac[6] + ap_idx u32)
  3 APTable    — all access points (count, stride, then mac[6] + lat/lon u16 offsets)

AP coordinates are tile-relative: ``lat = SW_lat + (u16/65535)·d_lat`` (likewise lon).

Uniform tile-tool API (see :mod:`ios_decoder.tile_tools`): :func:`parse` (bytes,
gunzips), :func:`render` (JSON text), :func:`bounds` (the tile box), :func:`tile_xyz`
(the tile's x/y/zoom, for the ``+++XYZ`` marker).  Standalone CLI:
``python -m ios_decoder.tile_tools.wifi FILE [--aps] [--index] [--json] [--csv] …``.
"""

from __future__ import annotations

import json
import math
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from . import Bounds
from ._section import iter_sections, maybe_gunzip


@dataclass
class TileHeader:
    tile_y: int          # (lat + 90) * 10000, snapped to tile grid
    tile_x: int          # (lon + 180) * 10000, snapped to tile grid
    sw_lat: float        # south-west corner latitude, degrees
    sw_lon: float        # south-west corner longitude, degrees
    d_lat: float         # tile height, degrees (typically 0.05)
    d_lon: float         # tile width,  degrees


@dataclass
class IndexEntry:
    mac: str
    ap_table_idx: int


@dataclass
class APEntry:
    mac: str
    lat: float
    lon: float
    lat_raw: int
    lon_raw: int


@dataclass
class WifiTile:
    header: TileHeader
    index: list[IndexEntry]
    aps: list[APEntry]
    warnings: list[str] = field(default_factory=list)   # surfaced in-band by render()


def mac_str(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


def decode_tile_header(body: bytes) -> TileHeader:
    if len(body) < 32:
        raise ValueError(f"TileHeader body too short: {len(body)}")
    tile_y, tile_x = struct.unpack_from(">II", body, 4)
    sw_lat, sw_lon = struct.unpack_from(">ff", body, 16)
    d_lat, d_lon = struct.unpack_from(">ff", body, 24)
    return TileHeader(tile_y, tile_x, sw_lat, sw_lon, d_lat, d_lon)


def decode_index(body: bytes, warn: Callable[[str], None] = lambda _m: None) -> list[IndexEntry]:
    if len(body) < 8:
        raise ValueError(f"Index section body too short: {len(body)}")
    count, stride = struct.unpack_from(">II", body, 0)
    if stride == 0:
        return []
    entries, pos = [], 8
    for i in range(count):
        if pos + stride > len(body):
            warn(f"index truncated at entry {i}/{count} (declared {count}; data ran short)")
            break
        idx, = struct.unpack_from(">I", body, pos + 6)
        entries.append(IndexEntry(mac_str(body[pos:pos + 6]), idx))
        pos += stride
    return entries


def decode_aps(body: bytes, hdr: TileHeader,
               warn: Callable[[str], None] = lambda _m: None) -> list[APEntry]:
    if len(body) < 8:
        raise ValueError(f"APTable section body too short: {len(body)}")
    count, stride = struct.unpack_from(">II", body, 0)
    if stride == 0:
        return []
    entries, pos = [], 8
    for i in range(count):
        if pos + stride > len(body):
            warn(f"AP table truncated at entry {i}/{count} (declared {count}; data ran short)")
            break
        lat_raw, lon_raw = struct.unpack_from(">HH", body, pos + 6)
        lat = hdr.sw_lat + (lat_raw / 65535.0) * hdr.d_lat
        lon = hdr.sw_lon + (lon_raw / 65535.0) * hdr.d_lon
        entries.append(APEntry(mac_str(body[pos:pos + 6]), lat, lon, lat_raw, lon_raw))
        pos += stride
    return entries


def parse(data: bytes) -> WifiTile:
    """Parse a WiFi tile body (raw or gzipped) into a :class:`WifiTile`."""
    tile_hdr: Optional[TileHeader] = None
    index: list[IndexEntry] = []
    aps: list[APEntry] = []
    warnings: list[str] = []                # collected in-band; surfaced by render()
    warn = warnings.append
    for sec in iter_sections(maybe_gunzip(data), lenient=True, warn=warn):
        body = sec.body                    # WiFi sections don't split meta/data
        if sec.id == 1:
            tile_hdr = decode_tile_header(body)
        elif sec.id == 2:
            index = decode_index(body, warn)
        elif sec.id == 3:
            if tile_hdr is None:
                raise ValueError("APTable (section 3) appeared before TileHeader (section 1)")
            aps = decode_aps(body, tile_hdr, warn)
        else:
            warn(f"unknown sectionId {sec.id} (skipped)")
    if tile_hdr is None:
        raise ValueError("No TileHeader section found in tile")
    return WifiTile(tile_hdr, index, aps, warnings)


def parse_file(path: "str | Path") -> WifiTile:
    return parse(Path(path).read_bytes())


# --- output ------------------------------------------------------------------

def to_json(hdr: TileHeader, index: list[IndexEntry], aps: list[APEntry]) -> str:
    return json.dumps({
        "tile_y": hdr.tile_y,
        "tile_x": hdr.tile_x,
        "sw_lat": hdr.sw_lat,
        "sw_lon": hdr.sw_lon,
        "d_lat": hdr.d_lat,
        "d_lon": hdr.d_lon,
        "index": [{"mac": e.mac, "ap_table_idx": e.ap_table_idx} for e in index],
        "aps": [{"mac": a.mac, "lat": round(a.lat, 8), "lon": round(a.lon, 8)} for a in aps],
    }, indent=2)


def summary(hdr: TileHeader, index: list[IndexEntry], aps: list[APEntry]) -> str:
    ne_lat, ne_lon = hdr.sw_lat + hdr.d_lat, hdr.sw_lon + hdr.d_lon
    lines = [
        f"Tile            : TILE_Y={hdr.tile_y}  TILE_X={hdr.tile_x}",
        f"SW corner       : {hdr.sw_lat:.6f}°N  {hdr.sw_lon:.6f}°E",
        f"NE corner       : {ne_lat:.6f}°N  {ne_lon:.6f}°E",
        f"Tile size       : {hdr.d_lat:.4f}° × {hdr.d_lon:.4f}°",
        f"Index entries   : {len(index)}",
        f"AP entries      : {len(aps)}",
    ]
    if aps:
        lats, lons = [a.lat for a in aps], [a.lon for a in aps]
        lines.append(f"AP lat range    : {min(lats):.6f} .. {max(lats):.6f}")
        lines.append(f"AP lon range    : {min(lons):.6f} .. {max(lons):.6f}")
    return "\n".join(lines)


# --- uniform tile-tool API ---------------------------------------------------

def render(tile: WifiTile) -> str:
    body = to_json(tile.header, tile.index, tile.aps)
    if tile.warnings:
        # lenient parsing dropped/clamped data — surface it in-band, never silently
        head = "".join(f"// WARNING: {w}\n" for w in tile.warnings)
        return head + body
    return body


def bounds(tile: WifiTile) -> Optional[Bounds]:
    h = tile.header
    return Bounds(h.sw_lat, h.sw_lat + h.d_lat, h.sw_lon, h.sw_lon + h.d_lon)


def tile_xyz(tile: WifiTile) -> Optional[tuple[int, int, int]]:
    """The tile's (x, y, zoom) for a ``+++XYZ`` marker (zoom from the tile's degree span)."""
    h = tile.header
    if h.d_lat <= 0:
        return None
    zoom = int(abs(math.log(h.d_lat / 360, 2)) + 0.5)
    return h.tile_x, h.tile_y, zoom


# --- CLI ---------------------------------------------------------------------

def main(argv=None) -> int:
    import argparse

    ap = argparse.ArgumentParser(description="Parse an Apple WiFi tile (cl2.apple.com/1/v1/…)")
    ap.add_argument("file", help="tile file (.gz or decompressed)")
    ap.add_argument("--aps", action="store_true", help="print the AP table")
    ap.add_argument("--index", action="store_true", help="print the index section")
    ap.add_argument("--json", action="store_true", help="dump everything as JSON")
    ap.add_argument("--csv", action="store_true", help="output APs as CSV")
    ap.add_argument("--all", action="store_true", help="no row limit")
    ap.add_argument("--limit", type=int, default=40, help="row limit (default 40)")
    args = ap.parse_args(argv)

    tile = parse_file(args.file)
    hdr, index, aps = tile.header, tile.index, tile.aps
    if args.json:
        print(to_json(hdr, index, aps))
        return 0
    if args.csv:
        print("mac,latitude,longitude,lat_raw,lon_raw")
        for a in aps:
            print(f"{a.mac},{a.lat:.8f},{a.lon:.8f},{a.lat_raw},{a.lon_raw}")
        return 0
    print(summary(hdr, index, aps))
    limit = None if args.all else args.limit
    if args.index:
        print(f"\nIndex ({len(index)} entries):")
        for i, e in enumerate(index):
            print(f"  {i:<5} {e.mac:<17} {e.ap_table_idx}")
            if limit and i + 1 >= limit:
                print(f"  … {len(index) - limit} more")
                break
    if args.aps:
        print(f"\nAP Table ({len(aps)} entries):")
        for i, a in enumerate(aps):
            print(f"  {a.mac:<17} {a.lat:>12.6f} {a.lon:>13.6f}")
            if limit and i + 1 >= limit:
                print(f"  … {len(aps) - limit} more")
                break
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
