"""Apple ARPC framing + payload decompression for ios_decoder.

Self-contained: parses Apple's ARPC v1/v2 request/response headers and handles
bvx/LZ4 + gzip decompression as plain ``bytes`` in / dataclass out (no mitmproxy),
then adds the human-readable header *summary* lines and the strip helpers the rest
of ios_decoder uses.

This was originally re-exported from ``mitm_traffic_parser.arpc``; the framing code
is vendored here so ios_decoder has no cross-tool import dependency.  The two copies
must stay wire-compatible (both decode the same captured Apple traffic).

All multi-byte integers are big-endian.  Strings are u16-length-prefixed.

Request header:
  v1:  u16 version=1
       <str locale> <str appIdentifier> <str osVersion>
       u32 functionId
       u32 payloadLength
  v2:  as v1 but with an extra <str compressionAlgo> (e.g. "LZ4") before
       functionId; the payload is then compressed with Apple's bvx LZ4 framing.

Response header:
  v1:  u16 version=1
       u32 responseType
       u32 payloadLength
"""

from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass
from typing import Optional

__all__ = [
    "ArpcRequestHeader",
    "ArpcResponseHeader",
    "DecompressError",
    "decompress_bvx",
    "decompress_gzip",
    "decompress_payload",
    "looks_compressed",
    "looks_gzip",
    "parse_request_header",
    "parse_response_header",
    "format_request_header",
    "format_response_header",
    "strip_request",
    "strip_response",
]


@dataclass
class ArpcRequestHeader:
    """Parsed fields of an ARPC request header (see module docstring for layout)."""
    version: int
    locale: str
    app_identifier: str
    os_version: str
    function_id: int
    payload_length: int
    payload_offset: int          # index in buf where the (possibly compressed) payload starts
    compression_algo: str = ""   # "" when uncompressed (v1)
    length_ok: bool = False      # payload_offset + payload_length == len(buf)


@dataclass
class ArpcResponseHeader:
    """Parsed fields of an ARPC response header (version, responseType, length)."""
    version: int
    response_type: int
    payload_length: int
    payload_offset: int


def _read_str(buf: bytes, p: int) -> tuple[str, int]:
    """Read a u16-length-prefixed UTF-8 string at `p`; return (text, next offset)."""
    if p + 2 > len(buf):
        raise ValueError("truncated string length")
    n = (buf[p] << 8) | buf[p + 1]
    p += 2
    if p + n > len(buf):
        raise ValueError("truncated string body")
    # Strict UTF-8: a real ARPC header carries ASCII identifiers; bytes that
    # don't decode are a strong signal this isn't an ARPC header at all.
    return buf[p:p + n].decode("utf-8"), p + n


def _is_header_text(s: str) -> bool:
    """ARPC header strings (locale/app/os) are printable identifiers, no controls."""
    return all(ch >= " " for ch in s)


def parse_request_header(buf: bytes) -> Optional[ArpcRequestHeader]:
    """Parse an ARPC request header, or return None if `buf` is not ARPC.

    Recognised by a leading u16 version of 1 or 2 followed by three printable
    length-prefixed strings (a non-empty app identifier) that stay within the
    buffer and a payload length that lands at or before the buffer end.  The
    printability + strict-UTF-8 checks keep a protobuf body that coincidentally
    starts with 0x0001/0x0002 from being misread as an ARPC header.
    """
    if len(buf) < 2:
        return None
    (version,) = struct.unpack_from("!H", buf, 0)
    if version not in (1, 2):
        return None
    p = 2
    try:
        locale, p = _read_str(buf, p)
        app, p = _read_str(buf, p)
        osv, p = _read_str(buf, p)
        algo = ""
        if version == 2:
            algo, p = _read_str(buf, p)
        if p + 8 > len(buf):
            return None
        (function_id,) = struct.unpack_from("!I", buf, p); p += 4
        (payload_length,) = struct.unpack_from("!I", buf, p); p += 4
    except ValueError:        # truncated, or non-UTF-8 string => not ARPC
        return None
    if not app or not all(_is_header_text(s) for s in (locale, app, osv, algo)):
        return None
    # Sanity: payload must fit. Compressed (v2) payloads sometimes report the
    # *decompressed* length, so only require that what's present isn't shorter
    # than a plausible body; accept and flag rather than reject.
    hdr = ArpcRequestHeader(
        version=version, locale=locale, app_identifier=app, os_version=osv,
        function_id=function_id, payload_length=payload_length,
        payload_offset=p, compression_algo=algo,
        length_ok=(p + payload_length == len(buf)),
    )
    return hdr


def parse_response_header(buf: bytes) -> Optional[ArpcResponseHeader]:
    """Parse an ARPC response header (version 1), or None if not ARPC-shaped."""
    if len(buf) < 10:
        return None
    (version,) = struct.unpack_from("!H", buf, 0)
    if version != 1:
        return None
    (response_type,) = struct.unpack_from("!I", buf, 2)
    (payload_length,) = struct.unpack_from("!I", buf, 6)
    if 10 + payload_length > len(buf):
        return None
    return ArpcResponseHeader(
        version=version, response_type=response_type,
        payload_length=payload_length, payload_offset=10,
    )


# --- Apple bvx (LZ4) payload decompression -----------------------------------
#
# Apple's "LZ4" compression framing differs from the standard lz4 frame:
#   bv41 <u32 decoded_size LE> <u32 encoded_size LE> <lz4 block>   (compressed)
#   bv4- <u32 raw_size LE> <raw bytes>                             (stored)
#   bv4$                                                           (end marker)

class DecompressError(Exception):
    """Raised for any bvx/LZ4 decompression failure (framing, size cap, or lz4)."""


# Upper bound on a single decompressed payload.  bvx headers carry an
# attacker-controlled 32-bit decoded-size; without a ceiling a corrupt or
# hostile capture could force a multi-gigabyte allocation.  GeoServices payloads
# are kilobytes; 64 MiB is comfortably generous.
MAX_DECOMPRESSED_SIZE = 64 * 1024 * 1024


def _read_u32le(data: bytes, p: int) -> int:
    """Read a little-endian uint32 at offset `p` (bvx block sizes)."""
    return int.from_bytes(data[p:p + 4], "little")


def _read_bv41_block(data, p, n, out, max_output, lz4block) -> tuple[bytes, int]:
    """Decode one compressed bv41 block; return (plaintext, new position).

    Apple's bvx CHAINS blocks: a block's LZ4 matches can back-reference the previously
    decompressed output, so the prior output (its trailing 64 KiB — the LZ4 max match offset)
    is handed to lz4 as a preset dictionary.  Without it the first block decodes but any later
    block that references earlier bytes fails with an lz4 'insufficient space' error."""
    if p + 8 > n:
        raise DecompressError("truncated bv41 header")
    dec_size = _read_u32le(data, p); enc_size = _read_u32le(data, p + 4); p += 8
    if len(out) + dec_size > max_output:
        raise DecompressError(f"bv41 decoded size {dec_size} exceeds cap {max_output}")
    block = data[p:p + enc_size]; p += enc_size
    if len(block) != enc_size:
        raise DecompressError("truncated bv41 block")
    try:
        window = bytes(out[-65536:])     # preset dict for inter-block back-references
        return lz4block.decompress(block, uncompressed_size=dec_size, dict=window), p
    except Exception as e:   # LZ4BlockError, ValueError, OverflowError, ...
        raise DecompressError(f"lz4 block decode failed: {e}")


def _read_bv4dash_block(data, p, n, produced, max_output) -> tuple[bytes, int]:
    """Read one stored (uncompressed) bv4- block; return (bytes, new position)."""
    if p + 4 > n:
        raise DecompressError("truncated bv4- header")
    raw_size = _read_u32le(data, p); p += 4
    if produced + raw_size > max_output:
        raise DecompressError(f"bv4- stored size {raw_size} exceeds cap {max_output}")
    block = data[p:p + raw_size]; p += raw_size
    if len(block) != raw_size:
        raise DecompressError("truncated bv4- block")
    return block, p


def decompress_bvx(data: bytes, max_output: int = MAX_DECOMPRESSED_SIZE) -> bytes:
    """Decompress an Apple bvx (bv41/bv4-/bv4$) LZ4 stream to plaintext bytes.

    Every failure mode -- bad framing, an oversized decoded-size, or an lz4
    block-decode error -- is raised as DecompressError so callers can treat
    decompression as fallible without catching library-specific exceptions.
    """
    try:
        import lz4.block as lz4block
    except Exception as e:  # pragma: no cover - dependency presence checked at runtime
        raise DecompressError(f"lz4 module unavailable: {e}")

    out = bytearray()
    p, n = 0, len(data)
    while p + 4 <= n:
        magic = data[p:p + 4]; p += 4
        if magic == b"bv4$":
            break
        elif magic == b"bv41":
            chunk, p = _read_bv41_block(data, p, n, out, max_output, lz4block)
        elif magic == b"bv4-":
            chunk, p = _read_bv4dash_block(data, p, n, len(out), max_output)
        else:
            raise DecompressError(f"unknown bvx magic {magic!r} at offset {p - 4}")
        out += chunk
    return bytes(out)


def looks_compressed(payload: bytes) -> bool:
    """True if `payload` begins with an Apple bvx (LZ4) frame magic."""
    return payload[:4] in (b"bv41", b"bv4-")


def decompress_payload(payload: bytes, algo: str) -> bytes:
    """Return decompressed payload for the given compression algo ("" = none)."""
    if not algo:
        return payload
    if algo.upper() == "LZ4":
        return decompress_bvx(payload)
    raise DecompressError(f"unsupported compression algo {algo!r}")


# --- gzip payload decompression ----------------------------------------------
#
# Some non-ARPC bodies are gzip-compressed at the *application* layer (the body
# bytes themselves start with the gzip magic 1f 8b), which is distinct from HTTP
# Content-Encoding: gzip -- mitmproxy already undoes the latter when we read
# msg.content.  These have to be inflated before the protobuf sniff can see the
# wire structure underneath.

def looks_gzip(payload: bytes) -> bool:
    """True if `payload` begins with the gzip magic (0x1f 0x8b)."""
    return payload[:2] == b"\x1f\x8b"


def decompress_gzip(data: bytes, max_output: int = MAX_DECOMPRESSED_SIZE) -> bytes:
    """Inflate a gzip-framed body to plaintext, capped at `max_output` bytes.

    Like decompress_bvx, every failure mode -- bad framing, a corrupt stream, or
    output exceeding the cap -- is raised as DecompressError so callers can treat
    decompression as fallible without catching zlib-specific exceptions.  The cap
    bounds the allocation a hostile/corrupt capture can force (a gzip "bomb").
    """
    dobj = zlib.decompressobj(16 + zlib.MAX_WBITS)   # 16 = expect a gzip header
    try:
        out = dobj.decompress(data, max_output)
    except zlib.error as e:
        raise DecompressError(f"gzip decode failed: {e}")
    if dobj.unconsumed_tail:        # capped out before consuming all input
        raise DecompressError(f"gzip output exceeds cap {max_output}")
    if not dobj.eof:               # input ran out before the stream's end marker
        raise DecompressError("truncated or corrupt gzip stream")
    return out


# --- human-readable summaries + header-strip helpers (ios_decoder additions) --

def format_request_header(hdr: ArpcRequestHeader) -> str:
    """One-line summary of an ARPC request header (matches the addon's output)."""
    parts = [
        f"version={hdr.version}",
        f"locale={hdr.locale}",
        f"app={hdr.app_identifier}",
        f"osVersion={hdr.os_version}",
    ]
    if hdr.compression_algo:
        parts.append(f"compressionAlgo={hdr.compression_algo}")
    parts += [f"requestType={hdr.function_id}", f"length={hdr.payload_length}"]
    return "apple arpc header: " + ", ".join(parts)


def format_response_header(hdr: ArpcResponseHeader) -> str:
    """One-line summary of an ARPC response header (matches the addon's output)."""
    return (
        f"apple header: version={hdr.version}, "
        f"responseType={hdr.response_type}, payloadLength={hdr.payload_length}"
    )


def strip_request(
    body: bytes,
) -> tuple[ArpcRequestHeader | None, bytes, str | None]:
    """Parse + strip an ARPC request header, returning (header, payload, warning).

    Returns ``(None, body, None)`` if ``body`` is not ARPC-framed.  ``warning`` is a
    non-fatal message the caller MUST surface (never ``None`` silently): a declared
    LZ4 payload that won't decompress, or a header length that doesn't match what's
    present.  When a problem occurs the raw post-header bytes are returned so a decode
    can still be attempted — but flagged, not hidden.
    """
    hdr = parse_request_header(body)
    if hdr is None:
        return None, body, None
    raw = body[hdr.payload_offset:]
    if hdr.compression_algo:
        try:
            return hdr, decompress_payload(raw, hdr.compression_algo), None
        except DecompressError as e:
            return hdr, raw, (
                f"ARPC {hdr.compression_algo} decompression failed: {e}; "
                "showing raw (still-compressed) bytes"
            )
    if hdr.length_ok:
        return hdr, body[hdr.payload_offset:hdr.payload_offset + hdr.payload_length], None
    return hdr, raw, (
        f"ARPC payload length mismatch: header declares {hdr.payload_length} bytes, "
        f"{len(raw)} present after the header"
    )


def strip_response(
    body: bytes,
) -> tuple[ArpcResponseHeader | None, bytes, str | None]:
    """Parse + strip an ARPC response header, returning (header, payload, warning).

    Returns ``(None, body, None)`` if not ARPC-framed.  A bvx/LZ4-framed payload (some
    responses are) is transparently decompressed; if that decompression fails the
    ``warning`` says so rather than silently passing the compressed bytes downstream.
    """
    hdr = parse_response_header(body)
    if hdr is None:
        return None, body, None
    payload = body[hdr.payload_offset:hdr.payload_offset + hdr.payload_length]
    # trailing bytes after the declared payload are dropped — say so (mirrors strip_request,
    # which surfaces a length mismatch; the response path used to hide it).
    extra = len(body) - (hdr.payload_offset + hdr.payload_length)
    len_warn = (f"ARPC response has {extra} trailing byte(s) after the declared "
                f"{hdr.payload_length}-byte payload (dropped)") if extra > 0 else None
    if looks_compressed(payload):
        try:
            return hdr, decompress_bvx(payload), len_warn
        except DecompressError as e:
            return hdr, payload, (
                f"ARPC LZ4 response decompression failed: {e}; "
                "showing raw (still-compressed) bytes"
            )
    return hdr, payload, len_warn
