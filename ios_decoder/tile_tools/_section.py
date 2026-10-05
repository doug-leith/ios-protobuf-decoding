"""Shared low-level primitives for the Apple tile parsers.

The eight ``tile_tools`` parsers were migrated one-by-one from standalone scripts, so each
had grown its own copy of the same handful of wire primitives — the ``0xABBA`` section
framing, gzip sniffing, the forward magic scan, the self-referential CRC, and the
CFAbsoluteTime epoch — with gratuitous (and occasionally diverging) variation.  They now
share these implementations, so malformed input is handled the same way everywhere and the
framing lives in exactly one place.
"""

from __future__ import annotations

import gzip
import struct
import zlib
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Iterator, Optional

SECTION_SIG = 0xABBA
CF_EPOCH = 978307200          # CFAbsoluteTime epoch (2001-01-01) in Unix seconds


def maybe_gunzip(blob: bytes) -> bytes:
    """Gzip-decompress *blob* if it carries the gzip magic, else return it unchanged.

    Tile bodies arrive either raw or gzipped; sniffing the two-byte magic (rather than
    catching a decompression error) means a *corrupt* gzip stream fails noisily instead of
    being silently treated as raw bytes.
    """
    return gzip.decompress(blob) if blob[:2] == b"\x1f\x8b" else blob


def cf_to_utc(cf_seconds: float) -> datetime:
    """Apple CFAbsoluteTime (seconds since 2001-01-01) → an aware UTC ``datetime``."""
    return datetime.fromtimestamp(cf_seconds + CF_EPOCH, tz=timezone.utc)


def find_magic(blob: bytes, magic: bytes, limit: int = 256, *,
               full_fallback: bool = False, exc: type = ValueError) -> int:
    """Return the index of *magic* within the first *limit* bytes of *blob*.

    The tile framing places the inner ASCII header a short distance in, so locationd scans
    forward for it; we mirror that bounded scan.  Raises *exc* (default :class:`ValueError`)
    if the magic is absent.  With *full_fallback*, a miss inside the window retries across the
    whole buffer before giving up.
    """
    idx = blob.find(magic, 0, limit + len(magic))
    if idx < 0 and full_fallback:
        idx = blob.find(magic)
    if idx < 0:
        raise exc(f"{magic.decode('ascii', 'replace')} magic not found in first {limit} bytes")
    return idx


def nibble_of(byte: int, idx: int, *, high_even: bool) -> int:
    """The 4-bit nibble at packed index *idx* within *byte* (two nibbles per byte).

    *high_even* selects the packing convention, which differs between locationd raster
    formats: ``True`` = an even index is the HIGH nibble (CLHRSE), ``False`` = an even index
    is the LOW nibble (CLSEF). Naming the choice here keeps the per-format convention explicit
    in one place instead of inlining two contradictory ``byte >> 4`` / ``byte & 0xF``
    expressions at each call site (where the divergence is invisible and error-prone).
    """
    take_high = ((idx & 1) == 0) == high_even
    return (byte >> 4) if take_high else (byte & 0x0F)


def crc32_zeroed(buf: bytes, crc_off: int) -> int:
    """CRC-32 of *buf* with its own 4-byte CRC field (at *crc_off*) zeroed.

    Apple's tile headers store a CRC computed over the section with the CRC slot itself set to
    zero; callers compare this against the stored value (raising or warning as they see fit).
    """
    b = bytearray(buf)
    b[crc_off:crc_off + 4] = b"\x00\x00\x00\x00"
    return zlib.crc32(bytes(b)) & 0xFFFFFFFF


def usable_record_count(declared: int, stride: int, data_len: int,
                        what: str) -> tuple[int, Optional[str]]:
    """Clamp a header-declared record count to what the section data can actually hold.

    A tile section header states how many fixed-``stride`` records follow; if the data block
    is shorter than that claims, the old code walked off the end and raised an opaque
    ``struct.error`` mid-loop (dropping the whole tile).  This returns ``(count, note)`` —
    *count* is how many records genuinely fit, and *note* is ``None`` when all fit or a
    truncation message otherwise, so the caller can yield the valid records and surface the
    shortfall in its output instead of crashing.
    """
    if stride <= 0:
        return 0, f"{what}: invalid record stride {stride}"
    fits = data_len // stride
    if declared > fits:
        return fits, (f"{what} truncated: header declares {declared} entries but the section "
                      f"holds only {fits}")
    return declared, None


@dataclass
class Section:
    """One ``0xABBA`` framing section: numeric *id* plus its meta and data byte blocks."""
    id: int
    meta: bytes
    data: bytes

    @property
    def body(self) -> bytes:
        """The meta and data blocks concatenated — for tiles that don't split the two."""
        return self.meta + self.data


def iter_sections(blob: bytes, *, lenient: bool = False,
                  warn: Optional[Callable[[str], None]] = None) -> Iterator[Section]:
    """Walk *blob* as a sequence of 12-byte ``0xABBA`` section frames.

    Each frame is ``sig(u16) · id(u16) · meta_len(u32) · data_len(u32)`` big-endian, then the
    meta and data blocks.  Trailing bytes shorter than a full 12-byte header always end
    iteration cleanly (tile padding).

    Strict (default): a bad signature, a body running past the buffer, or a partial tail left
    *after* at least one good section (mid-stream truncation) raises :class:`ValueError`.  A
    buffer too short to hold even one section is left for the caller to report (e.g. "required
    section not found"), so it is not treated as a tail here.  Lenient: a bad signature ends
    iteration (trailing padding) and an over-long body is clamped to the buffer (reported via
    *warn* if given) — the tolerant behaviour the WiFi tile relies on.
    """
    off, n = 0, len(blob)
    while off + 12 <= n:
        sig, sid, meta_len, data_len = struct.unpack_from(">HHII", blob, off)
        if sig != SECTION_SIG:
            if lenient:
                break
            raise ValueError(f"bad section signature {sig:#06x} at offset {off}")
        meta_start = off + 12
        data_start = meta_start + meta_len
        data_end = data_start + data_len
        if data_end > n:
            if lenient:
                if warn:
                    warn(f"section id={sid} body extends past EOF, clamping")
                data_end = n
            else:
                raise ValueError(f"section id={sid} at offset {off} runs past EOF")
        yield Section(sid, blob[meta_start:data_start], blob[data_start:data_end])
        off = data_end
    if not lenient and 0 < off < n:
        raise ValueError(f"{n - off} trailing byte(s) after the last section "
                         f"(truncated or corrupt framing)")
