"""``protoc --decode_raw``-compatible rendering of schema-free protobuf wire bytes.

Reproduces protoc's exact raw output so the tool matches the reference it replaced:

* varint            -> ``N: <unsigned decimal>``
* fixed64 / fixed32 -> ``N: 0x<16 hex>`` / ``N: 0x<8 hex>`` (raw little-endian value)
* length-delimited  -> a nested message ``N { … }`` **iff** the bytes parse cleanly and
  completely as wire fields; otherwise a C-escaped string ``N: "…"`` (protoc's
  "parse fully or it's a string" rule)
* 2-space indent per level; strings escaped exactly like protoc's ``CEscape``
  (``\\n \\r \\t \\" \\' \\\\`` as letters, everything else 3-digit octal ``\\NNN``)

Verified byte-for-byte against the ``protoc`` binary in tests/test_rawproto.py.
Groups (wire types 3/4) are not parsed as messages here — a buffer containing them
renders as a string, which is vanishingly rare in this traffic (noted, not silent).
"""

from __future__ import annotations

import struct
from typing import Optional

__all__ = ["RawDecodeError", "cescape", "parse_fields", "render_fields", "decode_raw",
           "format_double", "format_float", "is_valid_protobuf"]


def format_double(d: float) -> str:
    """Format a double exactly like protobuf's ``DoubleToBuffer``.

    ``%.15g`` (DBL_DIG); if that doesn't round-trip, ``%.17g`` (DBL_DIG+2) — protobuf
    deliberately skips 16 digits.  Whole numbers come out without a decimal (``0``,
    ``-1``, ``360``), matching protoc — unlike Python's ``repr`` (``0.0``, ``-1.0``).
    """
    s = "%.15g" % d
    if float(s) != d:
        s = "%.17g" % d
    return s


def _as_float32(x: float) -> float:
    """Narrow a Python float to float32 precision (what a TYPE_FLOAT field really holds)."""
    return struct.unpack("<f", struct.pack("<f", x))[0]


def format_float(f: float) -> str:
    """Format a 32-bit float like protobuf's ``FloatToBuffer``.

    ``%.6g`` (FLT_DIG); if it doesn't round-trip *at float32 precision*, ``%.9g``
    (FLT_DIG+3).  The round-trip check narrows back to float32 (protobuf uses strtof),
    so it matches protoc rather than a 64-bit round-trip.
    """
    s = "%.6g" % f
    if _as_float32(float(s)) != _as_float32(f):
        s = "%.9g" % f
    return s


class RawDecodeError(Exception):
    """Raised when bytes are not valid protobuf wire format (protoc would error too)."""


_LETTER_ESCAPES = {0x09: "\\t", 0x0A: "\\n", 0x0D: "\\r",
                   0x22: '\\"', 0x27: "\\'", 0x5C: "\\\\"}


def cescape(data: bytes) -> str:
    """C-escape bytes exactly as protoc does (letter escapes + 3-digit octal)."""
    out = []
    for c in data:
        esc = _LETTER_ESCAPES.get(c)
        if esc is not None:
            out.append(esc)
        elif 0x20 <= c <= 0x7E:
            out.append(chr(c))
        else:
            out.append("\\%03o" % c)
    return "".join(out)


def _read_varint(data: bytes, pos: int) -> tuple[int, int]:
    result = shift = 0
    n = len(data)
    while True:
        if pos >= n:
            raise RawDecodeError("truncated varint")
        b = data[pos]; pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, pos
        shift += 7
        if shift > 63:
            raise RawDecodeError("varint too long")


def parse_fields(data: bytes) -> Optional[list[tuple[int, int, object]]]:
    """Parse the whole buffer as a flat list of ``(field, wire_type, value)``.

    Returns None if the bytes don't *completely and validly* parse as wire fields —
    this is exactly protoc's test for whether a length-delimited value is a nested
    message or a string.  ``value`` is an int for varint/fixed, bytes for length-delimited.
    """
    fields: list[tuple[int, int, object]] = []
    pos, n = 0, len(data)
    while pos < n:
        try:
            tag, pos = _read_varint(data, pos)
        except RawDecodeError:
            return None
        field, wt = tag >> 3, tag & 7
        if field == 0:
            return None
        if wt == 0:        # varint
            try:
                val, pos = _read_varint(data, pos)
            except RawDecodeError:
                return None
        elif wt == 1:      # fixed64
            if pos + 8 > n:
                return None
            val = int.from_bytes(data[pos:pos + 8], "little"); pos += 8
        elif wt == 2:      # length-delimited
            try:
                ln, pos = _read_varint(data, pos)
            except RawDecodeError:
                return None
            if pos + ln > n:
                return None
            val = data[pos:pos + ln]; pos += ln
        elif wt == 5:      # fixed32
            if pos + 4 > n:
                return None
            val = int.from_bytes(data[pos:pos + 4], "little"); pos += 4
        else:              # groups (3/4) or invalid (6/7): not a clean message
            return None
        fields.append((field, wt, val))
    return fields


def is_valid_protobuf(data: bytes, min_fields: int = 1) -> bool:
    """True if `data` cleanly parses as protobuf wire with at least `min_fields` fields.

    A *detection* sniff (not interpretation): a full scan to EOF with all-valid wire
    types and non-zero field numbers is a strong (not infallible) signal, separating
    protobuf bodies from JSON/text/cert/empty bodies before a decode is attempted.

    Built on :func:`parse_fields` (the same scanner :func:`decode_raw` uses), so the
    sniff agrees exactly with what ios_decoder can actually render — including that a
    body whose top level contains a group (wire type 3/4) is treated as *not* a clean
    message, matching ``protoc``'s "parse fully or it's a string" rule.  Such bodies are
    vanishingly rare in this traffic.  Compressed (gzip / bvx-LZ4) bodies must be
    inflated by the caller before sniffing — see :mod:`ios_decoder.arpc`.
    """
    if not data:
        return False
    fields = parse_fields(data)
    return fields is not None and len(fields) >= min_fields


def render_fields(fields: list[tuple[int, int, object]], indent: int = 0) -> str:
    """Render parsed fields as protoc-style text (2 spaces per indent level)."""
    pad = "  " * indent
    out = []
    for field, wt, val in fields:
        if wt == 0:
            out.append(f"{pad}{field}: {val}")
        elif wt == 1:
            out.append(f"{pad}{field}: 0x{val:016x}")
        elif wt == 5:
            out.append(f"{pad}{field}: 0x{val:08x}")
        else:  # wt == 2
            sub = parse_fields(val)
            if val and sub is not None:
                out.append(f"{pad}{field} {{")
                out.append(render_fields(sub, indent + 1))
                out.append(f"{pad}}}")
            else:
                out.append(f'{pad}{field}: "{cescape(val)}"')
    return "\n".join(out)


def decode_raw(data: bytes) -> str:
    """Render schema-free wire ``data`` exactly like ``protoc --decode_raw``.

    Raises :class:`RawDecodeError` if the bytes aren't valid wire format (no trailing
    newline; the caller adds one when printing)."""
    fields = parse_fields(data)
    if fields is None:
        raise RawDecodeError("not valid protobuf wire format")
    return render_fields(fields, 0)
