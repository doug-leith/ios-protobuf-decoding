"""iAd advertising SDK endpoints: the 8-byte header + a protobuf from the AdCore framework.

The six ``iadsdk.apple.com/adserver/2.6/...`` endpoints decode against the schemas the extractor
recovered from AdCore (``protos/AdCore/ad.proto``).  Real iAd bodies carry device advertising
identifiers, so none is committed: these tests round-trip synthetic messages built from the real
schema through the real endpoint table.  (The mapping itself was checked against every captured
body: the named message parses it with no unknown fields.)
"""

from __future__ import annotations

import shutil
import struct
import tempfile
from pathlib import Path

import pytest

from ios_decoder import iad
from ios_decoder.decode import decode_request_body, decode_response_body
from ios_decoder.endpoints import DecodeContext, default_table
from ios_decoder.paths import DEFAULT_PROTO_DIRS
from ios_decoder.schemas import SchemaRegistry

_AD_PROTO = Path(__file__).resolve().parents[1] / "protos" / "AdCore" / "ad.proto"

requires_schemas = pytest.mark.skipif(
    not _AD_PROTO.exists() or shutil.which("protoc") is None,
    reason="AdCore schema or protoc not available",
)

# (url, request message, request fields, response message, response fields, header `extra` code)
CASES = [
    ("https://iadsdk.apple.com/adserver/2.6/optout/optout_optin",
     "ADOptOutRequest", {"optedOutStatus": True, "timezone": 1.0},
     "ADOptOutResponse", {}, 8),
    ("https://iadsdk.apple.com/adserver/2.6/segment/update",
     "ADSegmentUpdateRequest", {"osVersionAndBuild": "TEST-OS", "localeIdentifier": "xx_XX"},
     "ADSegmentUpdateResponse", {"segmentRefreshIntervalInSeconds": 3600.0}, 7),
    ("https://tr.iadsdk.apple.com/adserver/2.6/settings",
     "ADClientSettingsRequest", {"iAdIDString": "TEST"},
     "ADClientSettingsResponse", {"expirationDate": 1.0}, 32),
    ("https://cf.iadsdk.apple.com/adserver/2.6/config",
     "ADConfigurationRequest", {},
     "ADConfigurationResponse", {"configVersion": "TEST-VERSION"}, 26),
    ("https://iadsdk.apple.com/adserver/2.6/event/analytics",
     "ADLogAnalyticsRequest", {"bundleID": "com.example.test"},
     "ADLogAnalyticsResponse", {}, 23),
    ("https://iadsdk.apple.com/adserver/2.6/privacy/user-transparency",
     "ADUserTransparencyRequest", {"localeIdentifier": "xx_XX", "limitAdTracking": True},
     "ADUserTransparencyResponse", {"transparencyDetails": None}, 31),
]


def _frame(payload: bytes, extra: int) -> bytes:
    return struct.pack(">II", extra, len(payload)) + payload


@pytest.fixture(scope="module")
def ctx_table():
    reg = SchemaRegistry(list(DEFAULT_PROTO_DIRS), cache_dir=tempfile.mkdtemp())
    return DecodeContext(schemas=reg), default_table()


def _build(ctx, name, fields):
    msg = ctx.schemas.message_class("ad.proto", f"ad.{name}")()
    for key, value in fields.items():
        if value is None:                       # a nested message: just mark it present
            getattr(msg, key).SetInParent()
        else:
            setattr(msg, key, value)
    return msg.SerializeToString()


@requires_schemas
@pytest.mark.parametrize("url, req_name, req_fields, resp_name, resp_fields, extra", CASES,
                         ids=[c[0].split("/2.6/")[1] for c in CASES])
def test_round_trip_names_every_field(ctx_table, url, req_name, req_fields, resp_name, resp_fields, extra):
    ctx, table = ctx_table
    for fn, name, fields in ((decode_request_body, req_name, req_fields),
                             (decode_response_body, resp_name, resp_fields)):
        body = _frame(_build(ctx, name, fields), extra)
        out = fn(url, body, table, ctx)
        assert out.startswith(f"apple iAd header: extra=0x{extra:08x}"), out[:80]
        assert "// note:" not in out and "// WARNING" not in out and "// ERROR" not in out, out
        for key in fields:                      # named fields, not "1: ..." numbers
            assert f"{key}" in out, (name, key, out)
        if not fields:
            assert "(empty payload)" in out


@requires_schemas
def test_every_endpoint_resolves_to_an_ad_message_with_iad_framing():
    table = default_table()
    for url, req_name, _, resp_name, _, _ in CASES:
        for rule, name in ((table.request_rule(url), req_name), (table.response_rule(url), resp_name)):
            assert rule is not None and rule.framing == "iad" and rule.message == f"ad.{name}", (url, name)


@requires_schemas
def test_an_unlisted_iad_path_strips_the_header_and_raw_decodes(ctx_table):
    ctx, table = ctx_table
    out = decode_request_body("https://iadsdk.apple.com/adserver/2.6/other/thing",
                              _frame(b"\x0a\x01a", 5), table, ctx)
    assert out.splitlines()[0] == "apple iAd header: extra=0x00000005, length=3"
    assert '1: "a"' in out            # by-number raw decode: no schema is known for this path


def test_strip_header_flags_a_short_body_and_a_length_mismatch():
    head, payload = iad.strip_header(b"\x00\x01")
    assert "too short" in head and payload == b""
    head, payload = iad.strip_header(struct.pack(">II", 1, 10) + b"abc")
    assert "length mismatch" in head and payload == b"abc"
    head, payload = iad.strip_header(_frame(b"xyz", 2))
    assert head == "apple iAd header: extra=0x00000002, length=3\n" and payload == b"xyz"
