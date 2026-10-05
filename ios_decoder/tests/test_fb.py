"""smoot /fb polymorphic feedback decoder (ios_decoder.fb).

Three layers:
  * unit      — ?type= parsing + dispatch logic, no protoc (StubSchemas);
  * round-trip — build each message via the REAL schema, serialise, decode back
                 (privacy-safe synthetic data; gated on addon_ios schemas present);
  * live      — decode REAL /fb bodies from a git-ignored capture if one is present,
                else skip (no device data is committed).
"""

from __future__ import annotations

import glob
from pathlib import Path

import pytest

from ios_decoder import fb
from ios_decoder.decode import decode_request_body
from ios_decoder.endpoints import DecodeContext, default_table

import shutil

from ios_decoder.paths import DEFAULT_PROTO_DIRS

_REPO = Path(__file__).resolve().parents[2]
# The /fb schemas are UNMODIFIED extractor output committed under ios_decoder/protos.
_PROTO_DIR = Path(__file__).resolve().parents[1] / "protos"


# ── unit: parsing + dispatch (no protoc) ─────────────────────────────────────

class _RecordingSchemas:
    """SchemaRegistry stand-in that records the (proto_file, message) it's asked for."""

    def __init__(self):
        self.calls = []

    def decode_with_coverage(self, proto_file, message, data):
        self.calls.append((proto_file, message))
        return (f"decoded {message}\n", [], 0)


def _ctx(url, schemas=None):
    c = DecodeContext(schemas=schemas or _RecordingSchemas())
    c.url = url
    return c


def test_fb_type_parses_query_param():
    assert fb.fb_type("https://fbs.smoot.apple.com/fb?key=k&type=Usage") == "Usage"
    assert fb.fb_type("https://api.smoot.apple.com/fb?type=DuetExpert") == "DuetExpert"
    assert fb.fb_type("https://fbs.smoot.apple.com/fb") is None


def test_endpoint_registered_request_only():
    table = default_table()
    url = "https://fbs.smoot.apple.com/fb?type=Usage"
    assert table.request_rule(url) is not None
    assert table.response_rule(url) is None          # /fb response is an ack, not protobuf


@pytest.mark.parametrize("typ,schema_file,message", [
    ("FeedbackV2PB", "_cpclientsession.proto", "_cpclientsession._CPClientSession"),
    ("Usage", "_cpusageenvelope.proto", "_cpusageenvelope._CPUsageEnvelope"),
    ("ProactiveEventTracker", "pet.proto", "pet.PETUpload"),
    ("ProactiveEventTrackerAggregated", "pet.proto", "pet.PETUpload"),
    ("DuetExpert", "atx.proto", "atx.ATXNotificationsPBLogWrapper"),
])
def test_known_type_dispatches_to_its_schema(typ, schema_file, message):
    rec = _RecordingSchemas()
    ctx = _ctx(f"https://fbs.smoot.apple.com/fb?type={typ}", rec)
    out = fb.decode_fb(b"\x08\x01", ctx)
    assert rec.calls == [(schema_file, message)]
    assert f"type={typ!r}" in out
    # the type is asserted from the URL, not verified against the body — say so
    assert "asserted from the ?type= channel" in out
    assert "not confirmed against this body" in out


def test_unknown_type_raw_decodes_without_schema():
    rec = _RecordingSchemas()
    ctx = _ctx("https://fbs.smoot.apple.com/fb?type=SafariAutoFill", rec)
    out = fb.decode_fb(b"\x08\x01", ctx)
    assert rec.calls == []                            # never consults a schema
    assert "no RE-verified schema" in out
    assert "type='SafariAutoFill'" in out


def test_missing_type_is_treated_as_unmapped():
    rec = _RecordingSchemas()
    ctx = _ctx("https://fbs.smoot.apple.com/fb", rec)
    out = fb.decode_fb(b"\x08\x01", ctx)
    assert rec.calls == []
    assert "raw decode" in out


# ── round-trip through the real schemas (privacy-safe synthetic data) ────────

requires_schemas = pytest.mark.skipif(
    not (_PROTO_DIR / "CoreParsec" / "_cpclientsession.proto").exists()
    or shutil.which("protoc") is None,
    reason="/fb extractor schemas or protoc not available",
)


@pytest.fixture(scope="module")
def live_ctx():
    import tempfile
    from ios_decoder.schemas import SchemaRegistry
    # the real default dirs (ios_decoder/protos first), isolated cache
    reg = SchemaRegistry(list(DEFAULT_PROTO_DIRS), cache_dir=tempfile.mkdtemp())
    return DecodeContext(schemas=reg), default_table()


@requires_schemas
def test_usage_roundtrip(live_ctx):
    ctx, table = live_ctx
    Env = ctx.schemas.message_class("_cpusageenvelope.proto", "_cpusageenvelope._CPUsageEnvelope")
    msg = Env()
    msg.usageSinceLookback.collectionStartTimestamp = 111
    msg.usageSinceLookback.context.deviceModel = "iPhoneTEST,1"
    msg.context.country = "ZZ"                        # the field-14 context (the RE fix)
    msg.uuidBytes = b"\x01" * 16
    body = msg.SerializeToString()
    out = decode_request_body("https://api.smoot.apple.com/fb?type=Usage", body, table, ctx)
    assert "type='Usage'" in out
    assert 'deviceModel: "iPhoneTEST,1"' in out
    assert 'country: "ZZ"' in out                     # decoded at field 14, not mis-numbered
    assert "ERROR" not in out


@requires_schemas
def test_proactiveeventtracker_roundtrip(live_ctx):
    ctx, table = live_ctx
    Up = ctx.schemas.message_class("pet.proto", "pet.PETUpload")
    msg = Up()
    msg.metadata.platform = "iOS"
    msg.metadata.device = "iPhoneTEST,1"
    msg.isCompressed = True
    body = msg.SerializeToString()
    out = decode_request_body("https://fbs.smoot.apple.com/fb?type=ProactiveEventTracker",
                              body, table, ctx)
    assert "type='ProactiveEventTracker'" in out
    assert 'platform: "iOS"' in out
    assert "isCompressed: true" in out
    assert "ERROR" not in out


@requires_schemas
def test_duetexpert_roundtrip(live_ctx):
    ctx, table = live_ctx
    Wrap = ctx.schemas.message_class("atx.proto", "atx.ATXNotificationsPBLogWrapper")
    msg = Wrap()
    du = msg.periodiclog.dataUnits.add()
    du.key = "AppLaunchTEST"
    du.value = 7.0
    body = msg.SerializeToString()
    out = decode_request_body("https://fbs.smoot.apple.com/fb?type=DuetExpert", body, table, ctx)
    assert "type='DuetExpert'" in out
    assert 'key: "AppLaunchTEST"' in out
    assert "ERROR" not in out


@requires_schemas
def test_feedbackv2pb_roundtrip(live_ctx):
    ctx, table = live_ctx
    Sess = ctx.schemas.message_class("_cpclientsession.proto", "_cpclientsession._CPClientSession")
    msg = Sess()
    msg.agent = "parsecd/TEST"
    msg.countryCode = "ZZ"
    body = msg.SerializeToString()
    out = decode_request_body("https://fbs.smoot.apple.com/fb?key=k&type=FeedbackV2PB",
                              body, table, ctx)
    assert "type='FeedbackV2PB'" in out
    assert 'agent: "parsecd/TEST"' in out
    assert "ERROR" not in out


# ── live: decode REAL /fb bodies from a git-ignored capture if present ────────

def _fb_bodies():
    """(url, body) for every smoot /fb request across available git-ignored captures,
    or [] if no capture is present (then the live test skips)."""
    from mitmproxy import io as mio
    caps = (sorted(glob.glob(str(_REPO / "ios_decoder" / "comparison" / "*.mitm")))
            + sorted(glob.glob(str(_REPO / "iphone8_data" / "captures" / "*.mitm")))
            + sorted(glob.glob(str(_REPO / "iphone12_data" / "captures" / "*.mitm"))))
    out = []
    for cap in caps:
        try:
            with open(cap, "rb") as fh:
                flows = list(mio.FlowReader(fh).stream())
        except Exception:
            continue
        for fl in flows:
            if getattr(fl, "request", None) is None:
                continue
            u = fl.request.pretty_url
            if "smoot.apple.com/fb" in u and (fl.request.content or b""):
                out.append((u, fl.request.content))
        if out:
            break          # one capture with /fb traffic is enough for the live check
    return out


@requires_schemas
def test_live_fb_bodies_decode(live_ctx):
    ctx, table = live_ctx
    bodies = _fb_bodies()
    if not bodies:
        pytest.skip("no git-ignored capture with smoot /fb traffic present")
    seen_types = set()
    for url, body in bodies:
        out = decode_request_body(url, body, table, ctx)
        assert out is not None and "type=" in out
        t = fb.fb_type(url)
        seen_types.add(t)
        if t in fb.FB_TYPE_MAP:
            # a mapped channel must decode against its schema, never error out
            assert "// ERROR" not in out, f"{t} body errored: {out[:200]}"
    # the captures are known to carry these channels; guard against silent regression
    assert "Usage" in seen_types or "FeedbackV2PB" in seen_types
