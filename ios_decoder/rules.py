"""The decode-rule interface: what a rule is, and how a declarative one is applied.

A LEAF of the decoder graph: it imports the framing/schema layers below it
(:mod:`arpc`, :mod:`protobuf`, :mod:`schemas`, :mod:`markers`, :mod:`rawproto`) and
nothing above.  That is the point of the module.

:mod:`ios_decoder.endpoints` owns the URL dispatch TABLE; :mod:`ios_decoder.fb` and
:mod:`ios_decoder.tiles` supply rules that go into it.  Both sides need these three
names — ``DecodeContext``, ``Rule``, ``decode_arpc_or_raw`` — so while they lived in
``endpoints`` the providers had to import the table's own module, and ``endpoints`` had
to defer its import of them into a function body to keep the package loadable
(``endpoints -> fb`` and ``endpoints -> tiles`` were labelled "cycle-breakers" there).
Holding the interface in a module below both ends the cycle instead of working around
it: the table imports its providers at top level, and the providers import only this.

``endpoints`` re-exports all three, so ``from .endpoints import DecodeContext`` keeps
working for the reporter, the decoder and the tests.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional

from . import arpc, rawproto
from .markers import MarkerSink
from .protobuf import DecodeError, decode_to_text
from .schemas import SchemaError, SchemaRegistry

__all__ = ["DecodeContext", "Rule", "RuleHandler", "decode_arpc_or_raw"]


@dataclass
class DecodeContext:
    """Per-run decoding state handed to every rule: the schema set and a marker sink
    that handlers emit ``+++`` analysis markers into (the reporter resets it per flow).

    ``url`` carries the current body's request URL, set per-call by
    :mod:`ios_decoder.decode`. Most rules ignore it; the handful that are
    URL-polymorphic (smoot ``/fb?type=`` -> a per-channel message) read it."""
    schemas: SchemaRegistry
    markers: MarkerSink = field(default_factory=MarkerSink)
    url: str = ""


# A rule handler takes the raw HTTP body + context and returns decoded text.
RuleHandler = Callable[[bytes, DecodeContext], str]


@dataclass
class Rule:
    """How to decode one direction of an endpoint.

    Either declarative (``schema_file`` + ``message`` + ``framing``) or a custom
    ``handler``.  ``framing`` selects how the body is unwrapped before the protobuf
    decode:

      * ``arpc_request`` / ``arpc_response`` — strip the ARPC header (and decompress);
      * ``plain``                            — body is bare protobuf.
    """
    schema_file: Optional[str] = None
    message: Optional[str] = None
    framing: str = "plain"
    handler: Optional[RuleHandler] = None
    # ``bytes`` fields that carry another protobuf: field full name -> (schema_file, message),
    # decoded and shown as nested messages (e.g. geod's traffic probe, whose
    # ``locationCollection`` bytes hold a CoreLocationProtobuf LocationCollectionRequest).
    embedded: Optional[dict] = None

    def decode(self, body: bytes, ctx: DecodeContext) -> str:
        if self.handler is not None:
            return self.handler(body, ctx)
        return _decode_schema_rule(self, body, ctx)


def _text_sentinel(body: bytes) -> Optional[str]:
    """A short, fully-printable, non-protobuf body — return its text, else None.

    Some protobuf endpoints reply with a plain-text sentinel instead of a message: a tile
    server returns the literal ``Not Found`` when it has no tile for a key.  Showing that text
    is the honest decode; emitting a "protobuf decode failed" error for it is noise.

    Cautious gate (to avoid mislabelling a short/truncated binary body as text): 3..256 bytes,
    every byte printable-graphic or standard whitespace, at least one ASCII letter, and the
    bytes do not parse as protobuf wire format.
    """
    if not (3 <= len(body) <= 256):
        return None
    if any(not (0x20 <= b <= 0x7E or b in (0x09, 0x0A, 0x0D)) for b in body):
        return None
    if not any(0x41 <= b <= 0x5A or 0x61 <= b <= 0x7A for b in body):   # needs a letter
        return None
    if rawproto.parse_fields(body) is not None:        # it's protobuf, not a text sentinel
        return None
    return body.decode("ascii")


def _sentinel_text(text: str) -> str:
    return f"// server returned a plain-text body, not protobuf:\n{text}"


def _sentinel_response(body: bytes) -> Optional[str]:
    """The rendered plain-text-sentinel note if *body* is one, else ``None``.

    The shared preamble every generic/ schema decoder runs first, so a tile server's literal
    ``Not Found`` is shown as text rather than producing a protobuf-decode error.
    """
    sentinel = _text_sentinel(body)
    return _sentinel_text(sentinel) if sentinel is not None else None


def _header_and_payload(body: bytes, framing: str) -> tuple[str, bytes]:
    """Apply ``framing`` to ``body``: return (header summary + any warnings, payload).

    Any non-fatal ARPC issue (failed decompression, length mismatch) is rendered as a
    ``// WARNING`` line in the header text — surfaced, never swallowed.
    """
    if framing == "arpc_request":
        hdr, payload, warn = arpc.strip_request(body)
        head = (arpc.format_request_header(hdr) + "\n") if hdr else ""
    elif framing == "arpc_response":
        hdr, payload, warn = arpc.strip_response(body)
        head = (arpc.format_response_header(hdr) + "\n") if hdr else ""
    else:
        return "", body
    if warn:
        head += f"// WARNING: {warn}\n"
    return head, payload


def _decode_schema_rule(rule: Rule, body: bytes, ctx: DecodeContext) -> str:
    """Decode a declarative protobuf rule: unframe, decode against the schema, and
    fall back to a clearly-tagged raw decode if the named decode fails.

    On success, if the wire carried fields the schema doesn't declare, an explicit
    ``// note:`` line names them (and the schema) — the reader shouldn't have to infer
    a partial schema from by-number fields buried in the body.
    """
    sentinel = _sentinel_response(body)    # e.g. a tile server's literal "Not Found"
    if sentinel is not None:
        return sentinel
    head, payload = _header_and_payload(body, rule.framing)
    if not payload:
        return head + "(empty payload)"
    try:
        if rule.embedded:
            text, unknown, nested = ctx.schemas.decode_with_coverage(
                rule.schema_file, rule.message, payload, embedded=rule.embedded)
        else:
            text, unknown, nested = ctx.schemas.decode_with_coverage(
                rule.schema_file, rule.message, payload)
    except (SchemaError, DecodeError) as e:
        try:
            raw = decode_to_text(payload)
        except DecodeError as e2:
            return head + (f"// ERROR: schema decode failed ({e}); "
                           f"raw decode also failed ({e2})\n")
        return head + (f"// WARNING: schema decode failed ({e}); "
                       f"showing schema-free raw decode\n") + raw
    note = ""
    if unknown or nested:                # partial schema — name the gap, both top-level + nested
        parts = []
        if unknown:
            parts.append(f"{len(unknown)} top-level (shown by number: "
                         + ", ".join(str(n) for n in unknown) + ")")
        if nested:
            parts.append(f"{nested} inside known sub-message(s)")
        note = (f"// note: fields present on the wire are not in schema "
                f"{rule.schema_file}:{rule.message} — " + "; ".join(parts) + "\n")
    return head + note + text


def decode_arpc_or_raw(body: bytes, framing: str) -> str:
    """Strip an ARPC header (per *framing*) and raw-decode the payload.

    The single generic ARPC path shared by the table-driven ``arpc_*`` endpoints and the
    no-rule fallback in :mod:`ios_decoder.decode`: a plain-text sentinel is surfaced as text,
    an empty payload is stated, and an undecodable payload is flagged rather than dropped.
    """
    sentinel = _sentinel_response(body)
    if sentinel is not None:
        return sentinel
    head, payload = _header_and_payload(body, framing)
    if not payload:
        return head + "(empty payload)"
    try:
        return head + decode_to_text(payload)
    except DecodeError as e:
        return head + f"[undecodable: {e}]"
