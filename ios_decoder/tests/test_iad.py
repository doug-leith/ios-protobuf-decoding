"""iAd framing: 8-byte header strip + raw protobuf decode, with mismatch/short warnings."""

import struct

from ios_decoder import iad
from ios_decoder.endpoints import default_table
from ._arpc_fixtures import PROTOBUF_150


def _iad_body(payload=PROTOBUF_150, extra=0xCAFEBABE, declared=None):
    n = len(payload) if declared is None else declared
    return struct.pack("!II", extra, n) + payload


def test_decode_iad_strips_header_and_decodes():
    out = iad.decode_iad(_iad_body())
    assert "apple iAd header:" in out
    assert "extra=0xcafebabe" in out
    assert "1: 150" in out


def test_decode_iad_length_mismatch_warns():
    out = iad.decode_iad(_iad_body(declared=len(PROTOBUF_150) + 50))
    assert "// WARNING:" in out and "length mismatch" in out


def test_decode_iad_too_short_warns():
    out = iad.decode_iad(b"\x00\x01\x02")
    assert "// WARNING:" in out and "too short" in out


def test_decode_iad_empty_payload():
    out = iad.decode_iad(struct.pack("!II", 0, 0))
    assert "(empty payload)" in out


def test_decode_iad_bad_payload_reports_error():
    # header says 1 byte, payload is a truncated length-delimited field -> not protobuf
    out = iad.decode_iad(struct.pack("!II", 0, 1) + b"\x0a")
    assert "// ERROR:" in out and "did not decode" in out


def test_length_field_is_full_u32_not_u16():
    # A payload >= 64 KiB has non-zero bytes 4-5 in the length field; the old addon's
    # u16-at-offset-6 reading would truncate it. The single u32 parser must get it right.
    payload = b"\xab" * 70000                        # > 64 KiB; only the header is under test
    assert len(payload) > 0xFFFF
    hdr = iad.parse_header(struct.pack("!II", 0, len(payload)) + payload)
    assert hdr is not None and hdr.payload_length == len(payload) and hdr.length_ok


def test_iad_endpoints_are_wired():
    t = default_table()
    assert t.request_rule(
        "https://iadsdk.apple.com/adserver/2.6/optout/optout_optin") is not None
    assert t.response_rule(
        "https://iadsdk.apple.com/adserver/2.6/segment/update") is not None
    assert t.response_rule(
        "https://tr.iadsdk.apple.com/adserver/2.6/settings") is not None
    assert t.response_rule(
        "https://cf.iadsdk.apple.com/adserver/2.6/config") is not None
