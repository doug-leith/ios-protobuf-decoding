#!/usr/bin/env python3
"""Apple locationd DEM tile-availability file (``cldavl.avl.gz`` from ``cl3.apple.com/3/v2/``).

Format derived by reverse-engineering ``CLDemTileAvailability::readAvlHelper()`` and
``isTileAvailableBasedOnAvlFile()`` in locationd.  See the module-level layout notes below.

Uniform tile-tool API (see :mod:`ios_decoder.tile_tools`): :func:`parse` (bytes in, gunzips
if needed), :func:`render` (returns text), :func:`bounds` (None — this is a near-global
availability raster, not a single-tile box).  Standalone CLI:
``python -m ios_decoder.tile_tools.cldavl FILE [--lookup LAT LON] [--count] [--dump-csv OUT]``.

FILE LAYOUT (after gzip decompression)
  12-byte outer wrapper (0xABBA marker, sizes) then the inner 132-byte header at the CLAVL
  magic: magic(5) · copyright/pad(99) · version(u8) · headerLength(u8) · minLat(i8) ·
  maxLat(i8) · binSize(f32 BE, ~0.1°) · timestamp(f64 BE, Apple CFAbsoluteTime) ·
  expirationAge(u32 BE) · dataSize(u32 BE) · crc32(u32 BE) · then the row-major LSB-first
  bitmap (set bit ⇒ a DEM tile exists for that 0.1° cell).
"""

from __future__ import annotations

import math
import struct
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional

from . import Bounds
from ._section import cf_to_utc, find_magic, maybe_gunzip

MAGIC = b"CLAVL"
HEADER_SIZE = 132          # bytes from start of magic to start of bitmap
N_COLS = 3600              # fixed: 360° ÷ 0.1°
EXPECTED_BINSIZE = 0.1     # degrees
BINSIZE_TOLERANCE = 0.0001


# --- data classes ------------------------------------------------------------

@dataclass
class CLDEMAvlHeader:
    magic: bytes            # 5 bytes – always b"CLAVL"
    reserved: bytes         # 99 bytes – copyright notice + NUL padding
    version: int            # uint8
    header_length: int      # uint8  (= 132, the total inner header size)
    min_lat: int            # int8  degrees (e.g. -57)
    max_lat: int            # int8  degrees (e.g. +80)
    bin_size: float         # float32 BE – expected ~0.1°
    timestamp: float        # float64 BE – Apple CFAbsoluteTime (s since 2001-01-01)
    expiration_age: int     # uint32 BE – seconds until stale
    data_size: int          # uint32 BE – bytes of bitmap
    crc32: int              # uint32 BE

    @property
    def n_rows(self) -> int:
        return round(10 * (self.max_lat - self.min_lat))

    @property
    def utc_datetime(self) -> datetime:
        return cf_to_utc(self.timestamp)

    @property
    def expiry_datetime(self) -> datetime:
        return cf_to_utc(self.timestamp + self.expiration_age)


@dataclass
class CLDEMAvlFile:
    header: CLDEMAvlHeader
    bitmap: bytes           # raw bitmap bytes (length == header.data_size)


# --- parsing -----------------------------------------------------------------

def parse_header(data: bytes, magic_offset: int = 0) -> CLDEMAvlHeader:
    """Parse the 132-byte inner header starting at *magic_offset*."""
    b = magic_offset
    if len(data) < b + HEADER_SIZE:
        raise ValueError(f"Data too short for header: need {b + HEADER_SIZE} bytes, "
                         f"got {len(data)}")
    magic = data[b:b + 5]
    if magic != MAGIC:
        raise ValueError(f"Bad magic: {magic!r}, expected {MAGIC!r}")
    bin_size = struct.unpack_from(">f", data, b + 108)[0]
    if abs(bin_size - EXPECTED_BINSIZE) > BINSIZE_TOLERANCE:
        raise ValueError(f"Unexpected binSize {bin_size:.4f}°; expected ~{EXPECTED_BINSIZE}°")
    return CLDEMAvlHeader(
        magic=magic,
        reserved=data[b + 5:b + 104],
        version=data[b + 104],
        header_length=data[b + 105],
        min_lat=struct.unpack_from(">b", data, b + 106)[0],
        max_lat=struct.unpack_from(">b", data, b + 107)[0],
        bin_size=bin_size,
        timestamp=struct.unpack_from(">d", data, b + 112)[0],   # float64 BE, NOT uint64
        expiration_age=struct.unpack_from(">I", data, b + 120)[0],
        data_size=struct.unpack_from(">I", data, b + 124)[0],
        crc32=struct.unpack_from(">I", data, b + 128)[0],
    )


def parse(data: bytes) -> CLDEMAvlFile:
    """Parse a cldavl body (raw or gzipped) into a :class:`CLDEMAvlFile`."""
    data = maybe_gunzip(data)
    magic_offset = find_magic(data, MAGIC, 512)
    header = parse_header(data, magic_offset)
    start = magic_offset + HEADER_SIZE
    end = start + header.data_size
    if len(data) < end:
        raise ValueError(f"Truncated bitmap: header says {header.data_size} bytes, "
                         f"only {len(data) - start} available")
    return CLDEMAvlFile(header=header, bitmap=data[start:end])


def parse_file(path: "str | Path") -> CLDEMAvlFile:
    """Read *path* (raw ``.avl`` or ``.avl.gz``) and parse it."""
    return parse(Path(path).read_bytes())


# --- tile lookup -------------------------------------------------------------

def _normalize_lon(lon: float) -> float:
    """Shift negative longitudes into [0°, 360°) (mirrors locationd's sub_1001b0eb0)."""
    return lon + 360.0 if lon < 0.0 else lon


def is_tile_available(avl: CLDEMAvlFile, lat: float, lon: float) -> bool:
    """True if a DEM elevation tile exists for (lat, lon)."""
    hdr = avl.header
    if lat < hdr.min_lat:
        raise ValueError(f"Latitude {lat:.3f}° < minLat {hdr.min_lat}°")
    if lat >= hdr.max_lat:
        raise ValueError(f"Latitude {lat:.3f}° >= maxLat {hdr.max_lat}°")
    row = math.floor(lat * 10) - 10 * hdr.min_lat
    col = math.floor(_normalize_lon(lon) * 10)
    bit_idx = row * N_COLS + col
    byte_idx, bit_pos = bit_idx // 8, bit_idx % 8
    if byte_idx >= hdr.data_size:
        raise IndexError(f"Byte index {byte_idx} exceeds data size {hdr.data_size}")
    return bool((avl.bitmap[byte_idx] >> bit_pos) & 1)


def iter_available_tiles(avl: CLDEMAvlFile):
    """Yield (lat, lon) SW-corner of every 0.1° cell whose bit is set."""
    hdr = avl.header
    for byte_idx, byte_val in enumerate(avl.bitmap):
        if byte_val == 0:
            continue
        for bit_pos in range(8):
            if (byte_val >> bit_pos) & 1:
                bit_idx = byte_idx * 8 + bit_pos
                row, col = bit_idx // N_COLS, bit_idx % N_COLS
                lat = (row + 10 * hdr.min_lat) / 10.0
                lon_n = col / 10.0
                yield lat, (lon_n - 360.0 if lon_n >= 180.0 else lon_n)


# --- uniform tile-tool API ---------------------------------------------------

def bounds(avl: CLDEMAvlFile) -> Optional[Bounds]:
    """No single bounding box — cldavl is a near-global availability raster (returns None)."""
    return None


def format_header(hdr: CLDEMAvlHeader) -> str:
    copyright_text = hdr.reserved.rstrip(b"\x00").decode("ascii", errors="replace")
    return "\n".join([
        "=" * 62,
        "  cldavl.avl — Apple DEM Tile Availability File",
        "=" * 62,
        f"  copyright      : {copyright_text!r}",
        f"  version        : {hdr.version}",
        f"  headerLength   : {hdr.header_length} bytes",
        f"  minLat         : {hdr.min_lat}°",
        f"  maxLat         : {hdr.max_lat}°",
        f"  binSize        : {hdr.bin_size:.4f}°/cell",
        f"  timestamp      : {hdr.utc_datetime.isoformat()}  "
        f"(CFAbsoluteTime {hdr.timestamp:.2f})",
        f"  expirationAge  : {hdr.expiration_age:,} s  "
        f"({hdr.expiration_age / 86400:.1f} days)",
        f"  expires        : {hdr.expiry_datetime.isoformat()}",
        f"  dataSize       : {hdr.data_size:,} bytes  ({hdr.data_size * 8:,} bits)",
        f"  crc32          : 0x{hdr.crc32:08X}",
        f"  grid           : {hdr.n_rows} rows × {N_COLS} cols  "
        f"(0.1°/cell, lat {hdr.min_lat}° → {hdr.max_lat}°)",
        "=" * 62,
    ])


def render(avl: CLDEMAvlFile, max_tiles: int = 32) -> str:
    """Header summary + the first *max_tiles* available DEM-tile coordinates."""
    shown = []
    for i, (lat, lon) in enumerate(iter_available_tiles(avl)):
        if i >= max_tiles:
            break
        shown.append(f"({lat:.2f},{lon:.2f})")
    return (format_header(avl.header) + f"\nFirst {max_tiles} available DEM tiles:\n"
            + " ".join(shown))


# --- CLI ---------------------------------------------------------------------

def main(argv=None) -> int:
    import argparse
    import sys

    ap = argparse.ArgumentParser(
        description="Parse Apple locationd DEM availability file (cldavl.avl[.gz])")
    ap.add_argument("file", help="path to cldavl.avl or cldavl.avl.gz")
    ap.add_argument("--lookup", nargs=2, metavar=("LAT", "LON"), type=float,
                    help="check tile availability for a specific lat/lon")
    ap.add_argument("--count", action="store_true",
                    help="count the total number of available tiles")
    ap.add_argument("--dump-csv", metavar="OUT.CSV",
                    help="write all available tile SW-corner coordinates to a CSV")
    args = ap.parse_args(argv)

    avl = parse_file(args.file)
    print(render(avl))
    if args.lookup:
        lat, lon = args.lookup
        try:
            ok = is_tile_available(avl, lat, lon)
            print(f"\n  Tile ({lat:.3f}°, {lon:.3f}°): "
                  f"{'AVAILABLE ✓' if ok else 'NOT AVAILABLE ✗'}")
        except (ValueError, IndexError) as e:
            print(f"\n  Lookup error: {e}", file=sys.stderr)
    if args.count:
        n = sum(1 for _ in iter_available_tiles(avl))
        print(f"\n  Available tiles : {n:,}")
    if args.dump_csv:
        out = Path(args.dump_csv)
        with out.open("w") as f:
            f.write("lat_sw,lon_sw\n")
            for lat, lon in iter_available_tiles(avl):
                f.write(f"{lat:.1f},{lon:.1f}\n")
        print(f"\n  Wrote tile coordinates → {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
