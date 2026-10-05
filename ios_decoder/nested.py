"""Recursive decoder for nested-encoded bodies (JSON / plist with embedded payloads).

Apple telemetry (XP, AMP) and many plist bodies wrap further-encoded payloads inside a
structured container: a base64 string that is really protobuf, a JSON string inside JSON,
a plist ``<data>`` blob that is gzip'd protobuf, etc. — sometimes several layers deep.

This walks the container and expands those payloads **in place**, annotating every transform
(``<base64 → protobuf?>``, ``<json>``, ``<gzip → plist>``) so the decoding is transparent: the
reader can see exactly what was decoded and how.

**Cautious** (the agreed policy): a string/blob is only expanded when the result is
*confidently typed* — valid JSON, gzip/plist magic, or clean UTF-8 text — OR parses cleanly as
protobuf wire.  That last tier is the weakest signal, so it is annotated ``protobuf?`` (with a
trailing ``?``) to flag it as a structural guess rather than a confirmed type; the confidently
typed tiers carry no ``?``.  Opaque or encrypted strings (e.g. the ad tokens inside AMP
metadata) are left exactly as they are, never rendered as a guessed structure.
"""

from __future__ import annotations

import base64
import gzip
import json
import plistlib
import re
from typing import Any, Optional

from . import rawproto

__all__ = ["parse_container", "render", "extract_identifiers", "is_identifier_key",
           "is_mostly_printable"]

_B64_RE = re.compile(r"[A-Za-z0-9+/]*={0,2}")
_MIN_B64 = 16            # don't bother trying very short strings as base64


# --- container parsing -------------------------------------------------------

def parse_container(body: bytes, content_type: str = "") -> Optional[tuple[str, Any]]:
    """Parse ``body`` as a JSON or plist container; return ``(kind, tree)`` or None.

    ``kind`` is ``"json"`` or ``"plist"``.  Detection is by content/magic, not solely the
    Content-Type, so it works on sniffed bodies too.
    """
    ct = (content_type or "").lower()
    head = body[:1]
    if "json" in ct or head in (b"{", b"["):
        try:
            return "json", json.loads(body)
        except (ValueError, UnicodeDecodeError):
            pass
    if (body[:6] == b"bplist" or "plist" in ct
            or (body[:5] == b"<?xml" and b"plist" in body[:300])):
        try:
            return "plist", plistlib.loads(body)
        except Exception:        # plistlib raises a variety of types
            pass
    return None


# --- rendering ---------------------------------------------------------------

def render(value: Any, indent: int = 0) -> str:
    """Render a (possibly nested-encoded) value to annotated, indented text."""
    pad = "  " * indent
    if isinstance(value, dict):
        if not value:
            return "{}"
        body = "\n".join(f"{pad}  {k}: {render(v, indent + 1)}" for k, v in value.items())
        return "{\n" + body + "\n" + pad + "}"
    if isinstance(value, list):
        if not value:
            return "[]"
        body = "\n".join(f"{pad}  {render(v, indent + 1)}" for v in value)
        return "[\n" + body + "\n" + pad + "]"
    if isinstance(value, str):
        return _render_string(value, indent)
    if isinstance(value, (bytes, bytearray)):
        return _render_bytes(bytes(value), indent)
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "null"
    return str(value)            # int / float


def _render_string(s: str, indent: int) -> str:
    """A string leaf: expand JSON-in-string or base64-of-something, else quote as-is."""
    st = s.strip()
    if len(st) >= 2 and st[0] in "{[":
        try:
            parsed = json.loads(s)
            if isinstance(parsed, (dict, list)):
                return "<json> " + render(parsed, indent)
        except ValueError:
            pass
    if _looks_base64(s):
        try:
            raw = base64.b64decode(s, validate=True)
        except Exception:
            raw = b""
        if raw:
            exp = _expand_bytes(raw, indent)
            if exp is not None:
                label, text = exp
                return f"<base64 → {label}> {text}"
    return _quote(s)


def _render_bytes(b: bytes, indent: int) -> str:
    """A bytes leaf (e.g. a plist ``<data>`` blob): expand if confidently typed."""
    exp = _expand_bytes(b, indent)
    if exp is not None:
        label, text = exp
        return f"<{label}> {text}"
    return f"<{len(b)} bytes>"   # opaque: report size, don't dump


def _expand_bytes(b: bytes, indent: int) -> Optional[tuple[str, str]]:
    """Try to decode raw bytes into a confidently-typed structure.

    Returns ``(label, rendered_text)`` or None when the bytes are opaque/encrypted (the
    cautious default — we never render a guess).  Order is by strength of signal.
    """
    if b[:2] == b"\x1f\x8b":                       # gzip magic
        try:
            inner = gzip.decompress(b)
        except OSError:
            return None
        sub = _expand_bytes(inner, indent)
        if sub is not None:
            return f"gzip → {sub[0]}", sub[1]
        if is_mostly_printable(inner):
            return "gzip → utf8", _quote(inner.decode("utf-8", "replace"))
        return None
    if b[:6] == b"bplist" or (b[:5] == b"<?xml" and b"plist" in b[:300]):
        try:
            return "plist", render(plistlib.loads(b), indent)
        except Exception:
            pass
    if b[:1] in (b"{", b"["):                       # json
        try:
            parsed = json.loads(b)
            if isinstance(parsed, (dict, list)):
                return "json", render(parsed, indent)
        except (ValueError, UnicodeDecodeError):
            pass
    if is_mostly_printable(b):                     # clean text wins over a protobuf guess
        return "utf8", _quote(b.decode("utf-8", "replace"))
    fields = rawproto.parse_fields(b)              # binary that parses cleanly as wire
    if fields is not None and len(b) > 2:
        inner = rawproto.render_fields(fields, indent + 1)
        # "protobuf?" (not "protobuf"): unlike the gzip/plist/json/utf8 tiers above — which are
        # confidently typed by magic or a strict parse — this is the WEAKEST signal (arbitrary
        # binary often parses cleanly as wire by coincidence). The "?" flags it as a structural
        # guess, not a confirmed type (cf. decode.py's _SNIFF_NOTE for the same call one layer up).
        return "protobuf?", "{\n" + inner + "\n" + "  " * indent + "}"
    return None


# --- helpers -----------------------------------------------------------------

def _looks_base64(s: str) -> bool:
    """Loose gate: base64 charset, padded length, long enough to be worth trying.

    Intentionally permissive — the real safeguard is :func:`_expand_bytes` returning None
    for anything that isn't confidently typed, so a coincidental match stays a plain string.
    """
    return len(s) >= _MIN_B64 and len(s) % 4 == 0 and _B64_RE.fullmatch(s) is not None


def is_mostly_printable(b: bytes, threshold: float = 0.85) -> bool:
    """True if ``b`` is valid UTF-8 and overwhelmingly printable (so: text, not binary)."""
    try:
        b.decode("utf-8")
    except UnicodeDecodeError:
        return False
    printable = sum(1 for c in b if 0x20 <= c < 0x7F or c in (9, 10, 13))
    return bool(b) and printable / len(b) >= threshold


def _quote(s: str) -> str:
    return '"' + rawproto.cescape(s.encode("utf-8", "surrogatepass")) + '"'


# --- identifier extraction (for the XP/AMP markers) --------------------------

_ID_KEY = re.compile(r"(id|ids|guid|uuid|token|attribution|ns)$", re.IGNORECASE)
_ID_EXACT = {"dsid", "userns", "guid", "udid", "anonymous", "clientid"}


def is_identifier_key(key: str) -> bool:
    """Pattern-based: True for identifier-shaped keys (``*Id``, ``guid``, ``dsId``, …)."""
    return bool(_ID_KEY.search(key)) or key.lower() in _ID_EXACT


def extract_identifiers(tree: Any) -> list[tuple[str, str, Any]]:
    """Collect ``(path, key, value)`` for identifier-keyed scalars anywhere in ``tree``.

    Descends into JSON-in-string values (e.g. AMP's ``adResult``) so nested identifiers are
    found too.  base64→protobuf payloads use field numbers, not names, so they're skipped.
    """
    out: list[tuple[str, str, Any]] = []

    def walk(o: Any, path: str) -> None:
        if isinstance(o, dict):
            for k, v in o.items():
                child = f"{path}.{k}" if path else k
                if not isinstance(v, (dict, list)) and is_identifier_key(k):
                    out.append((child, k, v))
                walk(v, child)
        elif isinstance(o, list):
            for i, v in enumerate(o):
                walk(v, f"{path}[{i}]")
        elif isinstance(o, str) and o.strip()[:1] in "{[":
            try:
                parsed = json.loads(o)
            except ValueError:
                parsed = None              # not actually JSON — a plain string leaf
            if isinstance(parsed, (dict, list)):
                walk(parsed, path)

    walk(tree, "")
    return out
