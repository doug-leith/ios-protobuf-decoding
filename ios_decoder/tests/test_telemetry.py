"""XP / AMP telemetry decoders (ios_decoder.telemetry).

These two handlers are wired into live endpoints (xp.apple.com/report, amp engagement) but
had no test coverage. They decode JSON, emit one ``+++XP``/``+++AMP`` marker per event/ad,
and fall back to raw text for non-JSON. We exercise the marker emission, the AMP shape
dispatch (results.ads list vs top-level fallback vs no-identifiers), and the fallback path
— with synthetic JSON only (no captures, no device data).
"""

import json

from ios_decoder.endpoints import DecodeContext
from ios_decoder import telemetry


class _Schemas:
    """telemetry never touches ctx.schemas; a stand-in keeps DecodeContext happy."""
    def decode_with_coverage(self, *a):       # pragma: no cover - must never be called
        raise AssertionError("telemetry should not consult schemas")


def _ctx():
    return DecodeContext(schemas=_Schemas())


# --- XP ----------------------------------------------------------------------

def test_decode_xp_emits_one_marker_per_dict_event():
    ctx = _ctx()
    body = json.dumps({"events": [
        {"eventType": "impression", "dsId": "12345"},
        {"eventType": "click", "impressionId": "abc"},
        "not-a-dict",                        # skipped by the isinstance guard
    ]}).encode()
    out = telemetry.decode_xp(body, ctx)
    lines = ctx.markers.lines()
    assert "// nested-decoded XP telemetry" in out
    assert len(lines) == 2                   # the non-dict event yields no marker
    assert any(l.startswith("+++XP impression") for l in lines)
    assert any(l.startswith("+++XP click") for l in lines)


def test_decode_xp_event_without_type_uses_placeholder():
    ctx = _ctx()
    out = telemetry.decode_xp(json.dumps({"events": [{"dsId": "1"}]}).encode(), ctx)
    assert any(l.startswith("+++XP <none>") for l in ctx.markers.lines())
    assert out.startswith("// nested-decoded XP telemetry")


def test_decode_xp_non_json_falls_back_to_text():
    ctx = _ctx()
    out = telemetry.decode_xp(b"plain text, not json", ctx)
    assert "XP telemetry: not JSON/plist" in out
    assert not ctx.markers                   # no markers on the fallback path


# --- AMP ---------------------------------------------------------------------

def test_decode_amp_results_ads_list_one_marker_per_ad():
    ctx = _ctx()
    body = json.dumps({"results": {"ads": [
        {"impressionId": "i1"}, {"adId": "a2"},
    ]}}).encode()
    out = telemetry.decode_amp(body, ctx)
    lines = ctx.markers.lines()
    assert "// nested-decoded AMP engagement" in out
    assert len(lines) == 2
    assert all(l.startswith("+++AMP") for l in lines)


def test_decode_amp_top_level_fallback_when_no_ads():
    # no results.ads -> the whole tree is the single target
    ctx = _ctx()
    telemetry.decode_amp(json.dumps({"clientId": "xyz"}).encode(), ctx)
    assert len(ctx.markers.lines()) == 1


def test_decode_amp_no_identifiers_emits_no_marker():
    ctx = _ctx()
    telemetry.decode_amp(json.dumps({"results": {"ads": [{"price": 5}]}}).encode(), ctx)
    assert not ctx.markers                   # the `if ids:` guard suppresses empty ads


def test_decode_amp_undecodable_bytes_fallback():
    ctx = _ctx()
    out = telemetry.decode_amp(b"\x80\x81\x82\x83", ctx)   # invalid utf-8, not json
    assert "AMP engagement: not JSON/plist" in out
    assert "bytes)" in out                   # the UnicodeDecodeError branch
