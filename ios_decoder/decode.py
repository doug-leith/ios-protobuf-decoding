"""Body decoding: pick the right decoder for one HTTP message body.

Resolution order, per direction:
  1. a matching :class:`~ios_decoder.endpoints.Endpoint` rule (named schema), unless the
     body is JSON labelled as JSON (then ``None``: the MIME layer shows it);
  2. generic ARPC strip + raw protobuf decode, if the body is ARPC-framed;
  3. raw protobuf decode, if the body sniffs as protobuf wire;
  4. ``None`` — nothing protobuf-ish here (caller may handle by MIME type).

This is the pure-library half of the offline tool: ``bytes`` (+ url/content-type)
in, decoded ``str`` out, no mitmproxy.
"""

from __future__ import annotations

import json
from typing import Optional

from . import arpc
from .endpoints import DecodeContext, EndpointTable, decode_arpc_or_raw
from .httputil import is_form_urlencoded
from .protobuf import DecodeError, decode_to_text

__all__ = ["decode_request_body", "decode_response_body"]

# Provenance line for a sniff-only decode: unlike a schema or ARPC decode (a positive ID), a
# bare body that merely *sniffs* as protobuf is a structural guess, so the output says so —
# the reader shouldn't mistake a coincidental wire-format match for a confirmed decode.
_SNIFF_NOTE = ("// note: not schema- or ARPC-confirmed; decoded because the body "
               "structurally matches protobuf wire format\n")


def _sniff_protobuf(body: bytes) -> bool:
    """True if ``body`` plausibly is protobuf wire (schema-free detection sniff)."""
    from .rawproto import is_valid_protobuf
    return is_valid_protobuf(body)


def _label_contradicted(content_type: str, body: bytes) -> bool:
    """True when the declared Content-Type cannot describe *body*.

    Only a form label is checked: ``application/x-www-form-urlencoded`` promises text, so a
    binary body under it (Private Relay posts its protobuf token request with that label) is
    not form data whatever the header says.  A label the bytes contradict carries no
    information, so it must not block the protobuf sniff.
    """
    ct = (content_type or "").strip().lower().split(";", 1)[0]
    return ct == "application/x-www-form-urlencoded" and not is_form_urlencoded(body)


def _sniff_allowed(content_type: str, body: bytes = b"") -> bool:
    """Whether the weak protobuf *sniff* may run, given the server's Content-Type.

    Cautious: a short non-protobuf body (a PNG header, some text) can pass the
    structural sniff by coincidence, so we only sniff when the label doesn't say
    otherwise — absent, generic ``octet-stream``, explicitly protobuf, or a label the
    body contradicts (:func:`_label_contradicted`).  A body the server labelled
    ``image/png`` / ``application/cbor`` / etc. is trusted as labelled and left for the
    MIME layer (or the undecoded-body summary), never sniff-decoded.
    Structural ARPC detection is unaffected — it's a strong signal, not a guess.
    """
    ct = (content_type or "").strip().lower().split(";", 1)[0]
    return (ct in ("", "application/octet-stream") or "protobuf" in ct
            or _label_contradicted(content_type, body))


def _generic(body: bytes, direction: str, content_type: str) -> Optional[str]:
    """Fallback decode: ARPC-strip if framed, else raw decode if it sniffs as protobuf.

    An ARPC-framed body is a *positive* identification (the header parsed), so it always
    produces output — including an explicit error line if the inner bytes don't decode,
    rather than vanishing.  A bare body that merely *sniffs* as protobuf is only a guess,
    so it runs only when the Content-Type permits (:func:`_sniff_allowed`) and a decode
    failure there returns ``None`` (defer to the caller's MIME/raw handling).
    """
    is_arpc = (arpc.parse_request_header(body) if direction == "request"
               else arpc.parse_response_header(body)) is not None
    if is_arpc:
        framing = "arpc_request" if direction == "request" else "arpc_response"
        return decode_arpc_or_raw(body, framing)
    if body[:6] == b"bplist":           # a binary plist — defer to the MIME/plist layer
        return None
    if _sniff_allowed(content_type, body) and _sniff_protobuf(body):
        try:
            text = decode_to_text(body)
        except DecodeError:
            return None
        label = (f"// note: declared Content-Type ({content_type}) does not fit the body "
                 f"(not form data)\n" if _label_contradicted(content_type, body) else "")
        return label + _SNIFF_NOTE + text
    return None


def _rule_applies(rule, body: bytes, content_type: str) -> bool:
    """Whether the URL's rule should decode *body*.

    A declarative protobuf rule names the message an endpoint normally carries, but a server
    can answer the same URL with something else and say so: the store answers some
    inAppMessagesSync calls with a ``application/json`` error object.  When the label is JSON
    and the body is JSON, the label is confirmed and the protobuf rule does not apply (the MIME
    layer shows the JSON).  Custom handlers decide for themselves (XP/AMP telemetry *is* JSON).
    """
    if rule.message is None:
        return True
    if "json" not in (content_type or "").lower():
        return True
    try:
        json.loads(body)
    except (UnicodeDecodeError, ValueError):
        return True
    return False


def decode_request_body(url: str, body: bytes, table: EndpointTable,
                        ctx: DecodeContext, content_type: str = "") -> Optional[str]:
    """Decode a request body, or return None if it isn't protobuf/ARPC.

    ``content_type`` gates the weak protobuf sniff so a labelled non-protobuf body
    isn't mis-decoded; endpoint rules and ARPC detection ignore it (strong signals), except
    that a JSON label the body confirms overrides a protobuf rule (:func:`_rule_applies`).
    """
    if not body:
        return None
    ctx.url = url                       # let URL-polymorphic rules (smoot /fb) see it
    rule = table.request_rule(url)
    if rule is not None:
        return rule.decode(body, ctx) if _rule_applies(rule, body, content_type) else None
    return _generic(body, "request", content_type)


def decode_response_body(url: str, body: bytes, table: EndpointTable,
                         ctx: DecodeContext, content_type: str = "") -> Optional[str]:
    """Decode a response body, or return None if it isn't protobuf/ARPC."""
    if not body:
        return None
    ctx.url = url                       # let URL-polymorphic rules (smoot /fb) see it
    rule = table.response_rule(url)
    if rule is not None:
        return rule.decode(body, ctx) if _rule_applies(rule, body, content_type) else None
    return _generic(body, "response", content_type)
