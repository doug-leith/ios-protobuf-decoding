#!/usr/bin/env python3
"""Apple CLSEF coarse signal-environment file (``clsef.bin.gz`` from ``cl3.apple.com/1/v2/``).

Reverse-engineered from locationd's ``readSignalEnvHelper`` / ``getSignalEnvironment``.  After
gunzip, scan ≤256 bytes for the ASCII ``CLSEF`` magic, then a 132-byte header (int8 min/max
lat, f32 binsize ≈0.05°, f64 CFAbsoluteTime, CRC) + a nibble-packed global raster (ncols
hardcoded to 7200; low nibble = even cell, high = odd).  Each nibble is a signal-environment
type (0 Unavailable / 1 Rural / 2 Urban / 3 DenseUrban / 6 DenseUrbanCanyon).

Uniform tile-tool API (see :mod:`ios_decoder.tile_tools`): :func:`parse` (bytes, gunzips),
:func:`render` (header + first 32 raster cells), :func:`bounds` (None — global raster).  CLI:
``python -m ios_decoder.tile_tools.clsef FILE [--lookup LAT LON]``.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from . import Bounds
from ._section import cf_to_utc, crc32_zeroed, find_magic, maybe_gunzip, nibble_of

MAGIC = b"CLSEF"
MAGIC_SCAN_LIMIT = 256
EXPECTED_BINSIZE = 0.05
BINSIZE_TOLERANCE = 0.0001
EXPECTED_VERSION = 1
NCOLS_HARDCODED = 7200

HDR_VERSION_OFF = 104
HDR_HDRLEN_OFF = 105
HDR_MINLAT_OFF = 106
HDR_MAXLAT_OFF = 107
HDR_BINSIZE_OFF = 108
HDR_TIMESTAMP_OFF = 112
HDR_EXPIRY_OFF = 120
HDR_DATASIZE_OFF = 124
HDR_CRC_OFF = 128
HDR_TOTAL_SIZE = 132

VALID_NIBBLE_MASK = 0x4F           # bits set at {0,1,2,3,6}
SIGNAL_ENV_NAMES = {0: "Unavailable", 1: "Rural", 2: "Urban", 3: "DenseUrban",
                    6: "DenseUrbanCanyon"}


@dataclass
class CLSEFHeader:
    version: int
    header_length: int
    min_lat: int
    max_lat: int
    binsize: float
    timestamp: float
    expiration_age: int
    data_size: int
    crc: int

    @property
    def nrows(self) -> int:
        return round((self.max_lat - self.min_lat) / self.binsize)

    @property
    def ncols(self) -> int:
        return NCOLS_HARDCODED

    def __str__(self) -> str:
        ts = cf_to_utc(self.timestamp)
        return (f"CLSEFHeader:\n"
                f"  version       : {self.version}\n"
                f"  header_length : {self.header_length}\n"
                f"  min_lat       : {self.min_lat}°\n"
                f"  max_lat       : {self.max_lat}°\n"
                f"  binsize       : {self.binsize}° ({1 / self.binsize:.0f} cells/deg)\n"
                f"  timestamp     : {ts.isoformat()} (CFAbsTime={self.timestamp:.0f})\n"
                f"  expiration    : {self.expiration_age}s "
                f"({self.expiration_age / 86400:.1f} days)\n"
                f"  data_size     : {self.data_size:,} bytes "
                f"({self.nrows}×{self.ncols}÷2={self.nrows * self.ncols // 2:,} expected)\n"
                f"  ncols         : {self.ncols} (ASSUMED — CLSEF has no column-count field; "
                f"cross-checked only via data_size)\n"
                f"  stored_crc    : 0x{self.crc & 0xFFFFFFFF:08X}\n")


class CLSEFParser:
    """Parse Apple's clsef.bin coarse signal-environment file."""

    def __init__(self, data: bytes):
        self._raw = data
        # Integrity anomalies that don't prevent decoding (bad CRC, size mismatch). They are
        # collected here and surfaced by render() as `// WARNING:` lines, so a corrupt raster
        # is flagged in the user-visible output rather than only on a stderr warning channel.
        self.warnings: list[str] = []
        self._magic_offset = find_magic(data, MAGIC, MAGIC_SCAN_LIMIT)
        self.header = self._parse_header()
        self._verify_crc()
        self._data = self._load_data()

    @classmethod
    def from_file(cls, path: "str | Path") -> "CLSEFParser":
        return cls.from_bytes(Path(path).read_bytes())

    @classmethod
    def from_bytes(cls, raw: bytes) -> "CLSEFParser":
        return cls(maybe_gunzip(raw))

    def _parse_header(self) -> CLSEFHeader:
        off, raw = self._magic_offset, self._raw
        if len(raw) < off + HDR_TOTAL_SIZE:
            raise ValueError("File too short to contain a full CLSEF header")
        hdr = CLSEFHeader(
            version=raw[off + HDR_VERSION_OFF],
            header_length=raw[off + HDR_HDRLEN_OFF],
            min_lat=struct.unpack_from("b", raw, off + HDR_MINLAT_OFF)[0],
            max_lat=struct.unpack_from("b", raw, off + HDR_MAXLAT_OFF)[0],
            binsize=struct.unpack_from(">f", raw, off + HDR_BINSIZE_OFF)[0],
            timestamp=struct.unpack_from(">d", raw, off + HDR_TIMESTAMP_OFF)[0],
            expiration_age=struct.unpack_from(">i", raw, off + HDR_EXPIRY_OFF)[0],
            data_size=struct.unpack_from(">i", raw, off + HDR_DATASIZE_OFF)[0],
            crc=struct.unpack_from(">I", raw, off + HDR_CRC_OFF)[0],
        )
        if hdr.version != EXPECTED_VERSION:
            raise ValueError(f"CLSEF version mismatch: got {hdr.version}, "
                             f"expected {EXPECTED_VERSION}")
        if abs(hdr.binsize - EXPECTED_BINSIZE) > BINSIZE_TOLERANCE:
            raise ValueError(f"CLSEF binsize unexpected: got {hdr.binsize:.6f}°")
        if not (-90 <= hdr.min_lat < hdr.max_lat <= 90):
            raise ValueError(f"CLSEF lat range invalid: min={hdr.min_lat}, max={hdr.max_lat}")
        expected = hdr.nrows * NCOLS_HARDCODED // 2
        if hdr.data_size != expected:
            self.warnings.append(f"data_size mismatch: header says {hdr.data_size}, "
                                 f"expected nrows×ncols÷2={expected}")
        return hdr

    def _verify_crc(self):
        off = self._magic_offset
        total = HDR_TOTAL_SIZE + self.header.data_size
        if len(self._raw) < off + total:
            raise ValueError(f"File too short: need {total} CLSEF bytes, "
                             f"have {len(self._raw) - off}")
        # A stored CRC of 0 means the field is unused (real Apple clsef tiles ship this way),
        # not a mismatch — only a non-zero CRC that disagrees signals corruption.
        if self.header.crc == 0:
            return
        computed = crc32_zeroed(self._raw[off:off + total], HDR_CRC_OFF)
        if computed != self.header.crc:
            self.warnings.append(f"CRC mismatch: computed 0x{computed:08X}, "
                                 f"stored 0x{self.header.crc:08X} — values may be corrupt")

    def _load_data(self) -> bytes:
        off = self._magic_offset + HDR_TOTAL_SIZE
        return self._raw[off:off + self.header.data_size]

    def get_nibble(self, lat: float, lon: float) -> int:
        hdr = self.header
        if not (hdr.min_lat <= lat < hdr.max_lat):
            raise ValueError(f"Latitude {lat} out of range [{hdr.min_lat}, {hdr.max_lat})")
        lon_norm = lon + 180.0
        if not (0.0 <= lon_norm < 360.0):
            raise ValueError(f"Longitude {lon} out of supported range")
        row = int((lat - hdr.min_lat) / hdr.binsize)
        col = int(lon_norm / hdr.binsize)
        nibble_idx = row * NCOLS_HARDCODED + col
        byte_off = nibble_idx >> 1
        if byte_off >= len(self._data):
            raise ValueError(f"Byte offset {byte_off} >= data_size {len(self._data)}")
        byte = self._data[byte_off]
        return nibble_of(byte, nibble_idx, high_even=False)   # CLSEF: even idx = low nibble

    def get_signal_environment(self, lat: float, lon: float) -> tuple[int, str]:
        nibble = self.get_nibble(lat, lon)
        if nibble >= 7 or not ((VALID_NIBBLE_MASK >> nibble) & 1):
            return (-1, "INVALID")
        return (nibble, SIGNAL_ENV_NAMES.get(nibble, f"Unknown({nibble})"))

    def get_entries(self, num_entries: int, skip_invalid: bool = False):
        """First *num_entries* raster cells as (lat, lon, signal_environment) triples."""
        hdr = self.header
        # bound by BOTH the declared cell count AND the actual data length — a tile whose
        # data_size is short (the mismatch render already warns about) must not index past
        # the buffer and raise an opaque IndexError mid-render.
        num_entries = min(num_entries, hdr.nrows * NCOLS_HARDCODED, len(self._data) * 2)
        results, nibble_idx = [], 0
        for byte_off in range((num_entries + 1) // 2):
            byte = self._data[byte_off]
            for half in range(2):
                if nibble_idx >= num_entries:
                    break
                nibble = nibble_of(byte, half, high_even=False)
                valid = nibble < 7 and bool((VALID_NIBBLE_MASK >> nibble) & 1)
                if not valid and skip_invalid:
                    nibble_idx += 1
                    continue
                row, col = nibble_idx // NCOLS_HARDCODED, nibble_idx % NCOLS_HARDCODED
                lat = hdr.min_lat + row * hdr.binsize
                lon = col * hdr.binsize - 180.0
                env = SIGNAL_ENV_NAMES.get(nibble, "INVALID") if valid else "INVALID"
                results.append((round(lat, 6), round(lon, 6), env))
                nibble_idx += 1
        return results


# --- uniform tile-tool API ---------------------------------------------------

def parse(data: bytes) -> CLSEFParser:
    """Parse a CLSEF file body (raw or gzipped) into a :class:`CLSEFParser`."""
    return CLSEFParser.from_bytes(data)


def parse_file(path: "str | Path") -> CLSEFParser:
    return CLSEFParser.from_file(path)


def bounds(tile: CLSEFParser) -> Optional[Bounds]:
    """None — CLSEF is a near-global signal-environment raster, not a single-tile box."""
    return None


def render(tile: CLSEFParser, num_entries: int = 32) -> str:
    lines = [f"// WARNING: {w}" for w in tile.warnings]   # integrity flags first, in-band
    if tile.header.crc == 0:                              # parallel to HRSE's "crc (verified)"
        lines.append("// note: stored CRC is 0 (unused by Apple clsef tiles) — "
                     "integrity NOT verified")
    lines += [
        str(tile.header),
        "First 32 entries from the RF signal-environment raster:",
        str(tile.get_entries(num_entries=num_entries)),
    ]
    return "\n".join(lines)


def main(argv=None) -> int:
    import argparse
    ap = argparse.ArgumentParser(description="Parse an Apple CLSEF signal-environment file")
    ap.add_argument("file", help="clsef.bin or clsef.bin.gz")
    ap.add_argument("--lookup", nargs=2, type=float, metavar=("LAT", "LON"),
                    help="signal environment at a lat/lon")
    args = ap.parse_args(argv)
    parser = CLSEFParser.from_file(args.file)
    print(render(parser))
    if args.lookup:
        nibble, name = parser.get_signal_environment(*args.lookup)
        print(f"\n  ({args.lookup[0]}, {args.lookup[1]}) → {name} (nibble {nibble})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
