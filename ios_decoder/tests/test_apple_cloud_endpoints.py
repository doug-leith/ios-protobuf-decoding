"""iCloud / store endpoints that carry Apple protobuf outside ARPC.

Private Relay (mask-api), CloudKit (ckdatabase), cloudd's C2 metrics, the store's
inAppMessagesSync and the artist new-releases bundle decode against schemas the extractor
recovered from NetworkServiceProxy, CloudKitDaemon, C2, iTunesCloud and itunescloudd.  Covered
here: the two decode paths these needed (a binary body under a form-urlencoded label; CloudKit's
length-delimited operation streams), a protobuf rule standing aside for a JSON error reply, the
table entries on synthetic messages, and -- when the git-ignored captures are present -- every
captured body: named schema, unknown fields, and a byte-identical re-serialisation.
"""

from __future__ import annotations

import glob
import shutil
import tempfile
from pathlib import Path

import pytest
from google.protobuf.internal.encoder import _VarintBytes
from google.protobuf.unknown_fields import UnknownFieldSet

from ios_decoder import mime
from ios_decoder.decode import _generic, decode_request_body, decode_response_body
from ios_decoder.endpoints import DecodeContext, Endpoint, EndpointTable, Rule, default_table
from ios_decoder.httputil import is_form_urlencoded
from ios_decoder.paths import DEFAULT_PROTO_DIRS, PROTOS_ROOT
from ios_decoder.protobuf import split_delimited
from ios_decoder.schemas import SchemaRegistry

_REPO = Path(__file__).resolve().parents[2]
_FORM = "application/x-www-form-urlencoded"
# a small protobuf: field 1 = "abc", field 2 = 7 (tag 0x0a carries a control byte, 0x0a)
_PB = b"\x0a\x03abc\x10\x07"


# --- form-urlencoded label on a binary body -------------------------------------------

def test_form_validator_accepts_text_and_rejects_binary():
    assert is_form_urlencoded(b"name=a%20b&x=1")
    assert is_form_urlencoded(b"q=caf\xc3\xa9")             # sloppy raw UTF-8 is still text
    assert not is_form_urlencoded(_PB)                       # control bytes
    assert not is_form_urlencoded(b"\x80\x81\x82")           # not UTF-8


def test_binary_body_under_form_label_is_sniffed_as_protobuf():
    out = _generic(_PB, "request", _FORM)
    assert out is not None
    assert "does not fit the body" in out and _FORM in out  # the contradicted label is named
    assert "not schema- or ARPC-confirmed" in out            # still only a structural decode
    assert '1: "abc"' in out and "2: 7" in out


def test_real_form_body_is_left_to_the_mime_layer():
    assert _generic(b"name=a%20b&x=1", "request", _FORM) is None
    assert mime.decode_by_content_type(b"name=a%20b&x=1", _FORM) == "name=a b&x=1"


def test_mime_form_decoder_declines_binary():
    assert mime.decode_by_content_type(_PB, _FORM) is None


# --- length-delimited streams ------------------------------------------------------------

def test_split_delimited():
    assert split_delimited(b"\x02ab\x00\x01c") == [b"ab", b"", b"c"]
    assert split_delimited(b"") == []
    assert split_delimited(b"\x05ab") is None                 # length runs past the end
    assert split_delimited(b"\x80") is None                   # truncated varint


class _StubSchemas:
    """Returns one canned decode per record, so the framing is tested without protoc."""

    def __init__(self, results):
        self.results = list(results)

    def decode_with_coverage(self, proto_file, message, data, embedded=None):
        return self.results.pop(0)


def test_delimited_rule_shows_each_record_and_totals_unknowns():
    rule = Rule("x.proto", "x.M", "delimited")
    ctx = DecodeContext(schemas=_StubSchemas([("a: 1", [9], 1), ("a: 2", [9, 12], 2)]))
    out = rule.decode(b"\x02\x08\x01\x02\x08\x02", ctx)
    assert "[1] {\n   a: 1\n}" in out and "[2] {\n   a: 2\n}" in out
    assert "2 top-level (shown by number: 9, 12)" in out
    assert "3 inside known sub-message(s)" in out


def test_delimited_rule_flags_a_body_that_is_not_a_stream():
    rule = Rule("x.proto", "x.M", "delimited")
    out = rule.decode(b"\x7f\x08\x01", DecodeContext(schemas=_StubSchemas([])))
    assert "not a length-delimited message stream" in out


# --- a JSON reply to a protobuf endpoint ---------------------------------------------------

def test_json_reply_bypasses_a_protobuf_rule():
    table = EndpointTable([Endpoint(r"example\.com/x", None, Rule("x.proto", "x.M", "plain"))])
    ctx = DecodeContext(schemas=_StubSchemas([]))           # would fail if the rule ran
    body = b'{"code":403,"status":"forbidden"}'
    assert decode_response_body("https://example.com/x", body, table, ctx,
                                "application/json;charset=utf-8") is None


def test_json_label_does_not_bypass_a_custom_handler():
    seen = []
    table = EndpointTable([Endpoint(r"example\.com/x", None,
                                    Rule(handler=lambda b, c: seen.append(b) or "handled"))])
    ctx = DecodeContext(schemas=_StubSchemas([]))
    assert decode_response_body("https://example.com/x", b"{}", table, ctx,
                                "application/json") == "handled"


# --- the table entries, on synthetic messages built from the committed schemas ----------

_NEW_PROTOS = ["NetworkServiceProxy/nsp.proto", "CloudKitDaemon/ckdp.proto",
               "C2/c2mpmetric.proto", "iTunesCloud/iciam.proto", "itunescloudd/amp.proto"]

requires_schemas = pytest.mark.skipif(
    shutil.which("protoc") is None
    or not all((PROTOS_ROOT / p).exists() for p in _NEW_PROTOS),
    reason="extracted schemas or protoc not available",
)


@pytest.fixture(scope="module")
def ctx_table():
    reg = SchemaRegistry(list(DEFAULT_PROTO_DIRS), cache_dir=tempfile.mkdtemp())
    return DecodeContext(schemas=reg), default_table()


# (url, direction, proto file, message, fields to set, text the decode must show)
CASES = [
    ("https://mask-api.icloud.com/v1/fetchAuthTokens", "request",
     "nsp.proto", "nsp.NSPPrivacyProxyTokenActivationQuery",
     {"tokenInfo.proxyURL": "https://proxy.example:443"}, 'proxyURL: "https://proxy.example:443"'),
    ("https://mask-api.icloud.com/v1/fetchAuthTokens", "response",
     "nsp.proto", "nsp.NSPPrivacyProxyTokenActivationResponse",
     {"tokenExpiryTimestamp": 1234}, "tokenExpiryTimestamp: 1234"),
    ("https://mask-api.icloud.com/v2_4/fetchConfigFile", "response",
     "nsp.proto", "nsp.NSPPrivacyProxySignedConfiguration",
     {"signature": b"sig"}, 'signature: "sig"'),
    ("https://metrics.icloud.com/c2", "request",
     "c2mpmetric.proto", "c2mpmetric.C2MPMetric",
     {"reportFrequency": 3}, "reportFrequency: 3"),
    ("https://se2.itunes.apple.com/WebObjects/MZStoreElements2.woa/wa/inAppMessagesSync",
     "request", "iciam.proto", "iciam.ICIAMSynchronizeMessagesRequest",
     {"commandSerialNumber": 29}, "commandSerialNumber: 29"),
    ("https://se2.itunes.apple.com/WebObjects/MZStoreElements2.woa/wa/inAppMessagesSync",
     "response", "iciam.proto", "iciam.ICIAMSynchronizeMessagesResponse",
     {"applicationMessageSyncResponses[].bundleID": "com.example.app"},
     'bundleID: "com.example.app"'),
    ("https://radio-services.itunes.apple.com/resources/v1/bundle/new-releases-model/143449",
     "response", "amp.proto", "amp.AMPMusicArtistNewContentResponse",
     {"recoId": "r1"}, 'recoId: "r1"'),
]


def _build(ctx, proto, message, fields):
    """Serialise *message* with each dotted field path set (``name[]`` adds a repeated element)."""
    msg = ctx.schemas.message_class(proto, message)()
    for path, value in fields.items():
        *parents, leaf = path.split(".")
        target = msg
        for p in parents:
            target = getattr(target, p[:-2]).add() if p.endswith("[]") else getattr(target, p)
        setattr(target, leaf, value)
    return msg.SerializeToString()


@requires_schemas
@pytest.mark.parametrize("url, direction, proto, message, fields, expect", CASES,
                         ids=[f"{c[3]}" for c in CASES])
def test_endpoint_decodes_named_fields(ctx_table, url, direction, proto, message, fields, expect):
    ctx, table = ctx_table
    body = _build(ctx, proto, message, fields)
    decode = decode_request_body if direction == "request" else decode_response_body
    out = decode(url, body, table, ctx, "application/x-protobuf")
    assert expect in out
    assert "// note:" not in out and "// WARNING" not in out


@requires_schemas
def test_private_relay_request_decodes_despite_its_form_label(ctx_table):
    ctx, table = ctx_table
    body = _build(ctx, "nsp.proto", "nsp.NSPPrivacyProxyTokenActivationQuery",
                  {"tokenInfo.vendor": "TestVendor"})
    out = decode_request_body("https://mask-api.icloud.com/v1/fetchAuthTokens", body,
                              table, ctx, _FORM)
    assert 'vendor: "TestVendor"' in out


@requires_schemas
def test_cloudkit_stream_decodes_every_operation(ctx_table):
    ctx, table = ctx_table
    one = _build(ctx, "ckdp.proto", "ckdp.CKDPRequestOperation",
                 {"header.applicationBundle": "com.example.one"})
    two = _build(ctx, "ckdp.proto", "ckdp.CKDPRequestOperation",
                 {"header.applicationBundle": "com.example.two"})
    body = _VarintBytes(len(one)) + one + _VarintBytes(len(two)) + two
    out = decode_request_body("https://gateway.icloud.com/ckdatabase/api/client/record/sync",
                              body, table, ctx, "application/x-protobuf; delimited=true")
    assert out.startswith("[1] {") and "\n[2] {" in out
    assert 'applicationBundle: "com.example.one"' in out
    assert 'applicationBundle: "com.example.two"' in out


# --- live: every captured body (git-ignored captures; skipped when absent) --------------

# Wire fields the iPhone 8 (iOS 16.7.11) client does not know.  Each is absent from the iOS 16
# CloudKitDaemon class (no property, no readFrom case) and named in the iOS 27 CloudKitDaemon:
# CKDPRecord protectionInfoKeysToRemove (31), chainProtectionInfoKeysToRemove (33) and
# timestamps (34); CKDPRecordRetrieveChangesResponse zoneSummary (12).  Newer server fields.
_KNOWN_SERVER_ONLY = {("CKDPRecord", 31), ("CKDPRecord", 33), ("CKDPRecord", 34),
                      ("CKDPRecordRetrieveChangesResponse", 12)}

_LIVE_URLS = ("/fetchAuthTokens", "/fetchConfigFile", "/ckdatabase/api/client/",
              "metrics.icloud.com/c2", "inAppMessagesSync",
              "radio-services.itunes.apple.com/resources/v1/bundle/",
              "ls.apple.com/config/announcements")


@pytest.fixture(scope="module")
def live_bodies():
    """(url, direction, content-type, body) for the endpoints above, from the iPhone 8 captures."""
    try:
        from mitmproxy import http, io as mio
    except Exception:
        return []
    out = []
    for cap in sorted(glob.glob(str(_REPO / "iphone8_data" / "captures" / "*.mitm"))):
        with open(cap, "rb") as fh:
            for fl in mio.FlowReader(fh).stream():
                if not isinstance(fl, http.HTTPFlow):
                    continue
                url = fl.request.pretty_url
                if not any(u in url for u in _LIVE_URLS):
                    continue
                for direction, m in (("request", fl.request), ("response", fl.response)):
                    if m is not None and m.content:
                        out.append((url, direction, m.headers.get("content-type", ""), m.content))
    return out


def _unknowns(msg, out):
    for f in UnknownFieldSet(msg):
        out.add((msg.DESCRIPTOR.name, f.field_number))
    for fd, v in msg.ListFields():
        if fd.message_type is not None and not fd.message_type.GetOptions().map_entry:
            for x in (v if fd.is_repeated else [v]):
                _unknowns(x, out)
    return out


@requires_schemas
def test_live_bodies_decode_fully_and_round_trip(ctx_table, live_bodies):
    if not live_bodies:
        pytest.skip("no iPhone 8 captures with these endpoints present")
    ctx, table = ctx_table
    checked = 0
    for url, direction, ct, body in live_bodies:
        rule = table.request_rule(url) if direction == "request" else table.response_rule(url)
        assert rule is not None and rule.message is not None, url
        decode = decode_request_body if direction == "request" else decode_response_body
        out = decode(url, body, table, ctx, ct)
        if "json" in ct.lower():                 # the store's JSON error replies
            assert out is None
            continue
        assert "// WARNING" not in out and "// ERROR" not in out, (url, out[:300])
        cls = ctx.schemas.message_class(rule.schema_file, rule.message)
        records = split_delimited(body) if rule.framing == "delimited" else [body]
        rebuilt, unknown = b"", set()
        for r in records:
            m = cls()
            m.ParseFromString(r)
            _unknowns(m, unknown)
            s = m.SerializeToString()
            rebuilt += _VarintBytes(len(s)) + s if rule.framing == "delimited" else s
        assert unknown <= _KNOWN_SERVER_ONLY, (url, direction, unknown)
        assert rebuilt == body, (url, direction)
        checked += 1
    assert checked
