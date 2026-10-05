"""Apple iAd (advertising SDK) framing — an 8-byte header wrapping a protobuf body.

The ``iadsdk.apple.com`` endpoints prefix their protobuf with a fixed 8-byte header that
has **no magic bytes**, so this framing can't be detected structurally — it is applied by
endpoint URL only (see endpoints.py), never sniffed onto an arbitrary body (that would be
a guess).  There is no iAd ``.proto``, so the payload is raw-decoded (fields by number).

Header (big-endian), confirmed against real optout/segment *and* config/settings traffic:

    u32 extra · u32 payload_length · <protobuf>

`extra` is a small endpoint-dependent code (8=optout, 7=segment, 0x1a=config); it's shown
raw, not interpreted.  `payload_length` always equals `len(body) - 8` in observed traffic.

(The original addon decoded the config/settings endpoints with a *separate* parser that read
the length as a u16 at offset 6.  That is the same field — it only worked because these
lengths fit in 16 bits (bytes 4-5 are zero); it would truncate a length >= 65536.  There is
one header type, parsed here as the full u32.)
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Optional

from .protobuf import DecodeError, decode_to_text

__all__ = ["IadHeader", "parse_header", "decode_iad"]

_HEADER_LEN = 8


@dataclass
class IadHeader:
    """Parsed iAd header: the raw leading ``extra`` bytes + the payload length."""
    extra: bytes                 # 4 leading bytes (shown as hex, not interpreted)
    payload_length: int
    payload_offset: int = _HEADER_LEN
    length_ok: bool = False      # payload_offset + payload_length == len(body)


def parse_header(body: bytes) -> Optional[IadHeader]:
    """Parse the 8-byte iAd header (u32 extra, u32 length), or None if too short."""
    if len(body) < _HEADER_LEN:
        return None
    (length,) = struct.unpack_from("!I", body, 4)
    return IadHeader(body[:4], length, _HEADER_LEN,
                     _HEADER_LEN + length == len(body))


def decode_iad(body: bytes) -> str:
    """Decode an iAd body: strip the 8-byte header and raw-decode the protobuf payload.

    Surfaces a short-body warning, a length-mismatch warning, or a payload-decode error —
    none silently.
    """
    hdr = parse_header(body)
    if hdr is None:
        return (f"// WARNING: body too short ({len(body)} bytes) for an "
                f"{_HEADER_LEN}-byte iAd header")
    lines = [f"apple iAd header: extra=0x{hdr.extra.hex()}, length={hdr.payload_length}"]
    payload = body[hdr.payload_offset:hdr.payload_offset + hdr.payload_length]
    if not hdr.length_ok:
        avail = len(body) - hdr.payload_offset
        lines.append(f"// WARNING: iAd payload length mismatch: header declares "
                     f"{hdr.payload_length}, {avail} present after the header")
    if not payload:
        lines.append("(empty payload)")
        return "\n".join(lines)
    try:
        lines.append(decode_to_text(payload))
    except DecodeError as e:
        lines.append(f"// ERROR: iAd payload did not decode as protobuf: {e}")
    return "\n".join(lines)
