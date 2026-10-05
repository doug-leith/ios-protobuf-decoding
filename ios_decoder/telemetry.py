"""XP / AMP telemetry decoders — nested JSON, with identifier markers for analysis.

Both are JSON bodies that the recursive :mod:`ios_decoder.nested` decoder expands (AMP's
``meta.adResult`` is a JSON string whose ``metadata`` is base64→protobuf).  On top of the
readable decode, identifier-shaped keys (``dsId``, ``clientId``, ``impressionId``, …) are
surfaced as ``+++XP`` / ``+++AMP`` markers for grep/awk analysis, with long values hashed.

The decoded output is prefixed with a ``// nested-decoded …`` note so the reader always
knows decoding took place.
"""

from __future__ import annotations

from . import markers, nested, reqlog

__all__ = ["decode_xp", "decode_amp"]


def _id_summary(ids) -> str:
    """``key=value~`` summary of identifier findings, long values SHA-256-hashed."""
    return "".join(f"{k}={reqlog.hash_long_string(str(v))}~" for _, k, v in ids)


def _fallback(body: bytes, label: str) -> str:
    try:
        return f"// {label}: not JSON/plist, raw text:\n" + body.decode("utf-8")
    except UnicodeDecodeError:
        return f"// {label}: not JSON/plist ({len(body)} bytes)"


def decode_xp(body: bytes, ctx) -> str:
    """Decode an ``xp.apple.com/report`` body; emit one ``+++XP <eventType> …`` per event."""
    parsed = nested.parse_container(body, "application/json")
    if parsed is None:
        return _fallback(body, "XP telemetry")
    kind, tree = parsed
    events = tree.get("events", []) if isinstance(tree, dict) else []
    for ev in events:
        if not isinstance(ev, dict):
            continue
        event_type = ev.get("eventType", "<none>")   # explicit absence (no internal space → 1 awk field)
        ctx.markers.emit(markers.custom("XP", event_type, _id_summary(
            nested.extract_identifiers(ev))))
    note = f"// nested-decoded XP telemetry ({kind}; embedded base64/protobuf expanded in place):"
    return note + "\n" + nested.render(tree)


def decode_amp(body: bytes, ctx) -> str:
    """Decode an AMP ``/v1/engagement`` body; emit one ``+++AMP …`` per ad (or for the body)."""
    parsed = nested.parse_container(body, "application/json")
    if parsed is None:
        return _fallback(body, "AMP engagement")
    kind, tree = parsed
    ads = None
    if isinstance(tree, dict) and isinstance(tree.get("results"), dict):
        ads = tree["results"].get("ads")
    targets = ads if isinstance(ads, list) else [tree]
    for ad in targets:
        ids = nested.extract_identifiers(ad)
        if ids:
            ctx.markers.emit(markers.custom("AMP", _id_summary(ids)))
    note = f"// nested-decoded AMP engagement ({kind}; embedded base64/protobuf expanded in place):"
    return note + "\n" + nested.render(tree)
