"""Builders for synthetic ARPC frames used across the decode tests."""

import struct


def _s(text: str) -> bytes:
    b = text.encode()
    return struct.pack("!H", len(b)) + b


def build_request(*, locale="en_US", app="com.apple.test", osv="1.0",
                  function_id=1, payload=b"", version=1, algo="",
                  declared_len=None) -> bytes:
    """Build an ARPC request frame.  ``declared_len`` overrides the header length
    field (to simulate a mismatch); ``algo`` (v2) names a compression algorithm."""
    out = struct.pack("!H", version) + _s(locale) + _s(app) + _s(osv)
    if version == 2:
        out += _s(algo)
    n = len(payload) if declared_len is None else declared_len
    out += struct.pack("!I", function_id) + struct.pack("!I", n) + payload
    return out


def build_response(*, response_type=1, payload=b"", version=1) -> bytes:
    """Build an ARPC v1 response frame."""
    return (struct.pack("!H", version) + struct.pack("!I", response_type)
            + struct.pack("!I", len(payload)) + payload)


# A minimal valid protobuf body: field 1, varint = 150  ->  "1: 150"
PROTOBUF_150 = bytes.fromhex("089601")
