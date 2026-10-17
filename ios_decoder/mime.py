"""Content-Type dispatch — decode a body by its MIME type when no endpoint rule fits.

Ported from the addon's ``printUsingMimeType``, but as a pure library: ``bytes`` +
content-type in, decoded ``str`` (or ``None`` when this layer can't handle the type) out.
``None`` is the honest "I don't decode this" answer — the caller then shows the raw body
rather than this layer pretending.

Protobuf framings (single message, length-prefixed array, gRPC) all go through the
schema-free core in :mod:`ios_decoder.protobuf`; nothing here shells out.
"""

from __future__ import annotations

import json
import urllib.parse
from typing import Callable, Optional

from . import archives, arpc, certs, doh, nested
from .httputil import is_form_urlencoded
from .protobuf import DecodeError, decode_to_text, split_delimited

__all__ = [
    "decode_by_content_type",
    "decode_protobuf_payload",
    "decode_protobuf_array",
    "decode_grpc",
]


# --- protobuf framings -------------------------------------------------------

def decode_protobuf_array(body: bytes) -> Optional[str]:
    """Decode a length-prefixed protobuf array (``<varint len><msg>`` repeated).

    Returns ``None`` unless the framing consumes the whole buffer with at least two
    elements — the cautious choice, so a single message isn't mis-announced as an
    array (a single protobuf also parses as a degenerate one-element array).
    """
    msgs = split_delimited(body)
    if msgs is None or len(msgs) < 2:
        return None
    parts = []
    for count, msg in enumerate(msgs, 1):
        try:
            text = decode_to_text(msg)
        except DecodeError:
            return None
        parts.append(f"[{count}] {{\n" + _indent(text) + "}")
    return "\n".join(parts)


def decode_grpc(body: bytes) -> Optional[str]:
    """Decode gRPC length-prefixed framing (``<u8 compressed><u32 len><msg>`` repeated).

    Compressed frames are gunzipped (the common encoding).  Returns ``None`` if the
    framing doesn't cleanly consume the buffer, so a non-gRPC body isn't mis-decoded.
    """
    import struct

    pos, count, parts = 0, 0, []
    n = len(body)
    while pos < n:
        if pos + 5 > n:
            return None
        compressed = body[pos]
        (length,) = struct.unpack_from("!I", body, pos + 1)
        start = pos + 5
        end = start + length
        if compressed not in (0, 1) or end > n:
            return None
        msg = body[start:end]
        if compressed:
            try:
                msg = arpc.decompress_gzip(msg)
            except arpc.DecompressError as e:
                return None if count == 0 else _append_err(parts, count, e)
        try:
            text = decode_to_text(msg)
        except DecodeError:
            return None
        count += 1
        parts.append(f"[{count}] {{\n" + _indent(text) + "}")
        pos = end
    if count == 0:
        return None
    return "\n".join(parts)


def decode_protobuf_payload(body: bytes) -> Optional[str]:
    """Decode a protobuf body: single message, else array, else gRPC; else ``None``.

    Single-message is tried first (the common case); a raw protobuf is not length-
    prefixed, so the array/gRPC framings only win when single-decode is ambiguous.
    """
    try:
        return decode_to_text(body)
    except DecodeError:
        pass
    # single-message failed -> the array / gRPC framing is INFERRED by structural fit (not
    # declared by a Content-Type), so flag which framing won rather than presenting it as fact.
    arr = decode_protobuf_array(body)
    if arr is not None:
        return ("// note: decoded as a length-prefixed protobuf array "
                "(framing inferred by structural fit, not declared)\n" + arr)
    grpc = decode_grpc(body)
    if grpc is not None:
        return ("// note: decoded as gRPC length-prefixed framing "
                "(inferred by structural fit, not declared)\n" + grpc)
    return None


# --- text-ish framings -------------------------------------------------------

def _decode_json(body: bytes, ct: str) -> Optional[str]:
    try:
        obj = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return json.dumps(obj, indent=2, ensure_ascii=False)


def _decode_form(body: bytes, ct: str) -> Optional[str]:
    if not is_form_urlencoded(body):    # binary under a form label: not form data
        return None
    return urllib.parse.unquote(body.decode("utf-8"))


def _decode_text(body: bytes, ct: str) -> Optional[str]:
    try:
        return body.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _decode_gzip(body: bytes, ct: str) -> Optional[str]:
    """Inflate a gzip body and decode the inner payload (protobuf, else text)."""
    if not arpc.looks_gzip(body):
        return None
    try:
        inner = arpc.decompress_gzip(body)
    except arpc.DecompressError as e:
        return f"// ERROR: gzip decode failed: {e}"
    pb = decode_protobuf_payload(inner)
    if pb is not None:
        return "// gunzipped, decoded as protobuf:\n" + pb
    txt = _decode_text(inner, "")
    if txt is not None:
        return "// gunzipped:\n" + txt
    return f"// gunzipped {len(inner)} bytes (binary):\n{inner!r}"


def _decode_protobuf(body: bytes, ct: str) -> Optional[str]:
    return decode_protobuf_payload(body)


def _decode_plist(body: bytes, ct: str) -> Optional[str]:
    """Decode a plist (XML or binary), expanding embedded base64/protobuf via nested."""
    parsed = nested.parse_container(body, ct or "application/x-apple-plist")
    if parsed is None:
        return None
    _, tree = parsed
    return ("// nested-decoded plist (embedded base64/protobuf expanded in place):\n"
            + nested.render(tree))


def _decode_xml(body: bytes, ct: str) -> Optional[str]:
    """XML may be an (Apple) plist — try that first, else fall back to plain text."""
    return _decode_plist(body, ct) or _decode_text(body, ct)


def _decode_ocsp(body: bytes, ct: str) -> Optional[str]:
    return certs.decode_ocsp(body)


def _decode_cert(body: bytes, ct: str) -> Optional[str]:
    return certs.decode_certificates(body)


def _decode_zip(body: bytes, ct: str) -> Optional[str]:
    return archives.decode_zip(body)


def _decode_cbor(body: bytes, ct: str) -> Optional[str]:
    return archives.decode_cbor(body)


def _decode_grpc(body: bytes, ct: str) -> Optional[str]:
    return decode_grpc(body)


def _decode_dns(body: bytes, ct: str) -> Optional[str]:
    return doh.decode_dns_message(body)


# --- dispatch table ----------------------------------------------------------

MimeHandler = Callable[[bytes, str], Optional[str]]

# (substring to look for in the lower-cased content-type, handler)
_HANDLERS: list[tuple[str, MimeHandler]] = [
    ("application/grpc", _decode_grpc),
    ("protobuf", _decode_protobuf),
    ("application/json", _decode_json),
    ("+json", _decode_json),
    ("application/x-www-form-urlencoded", _decode_form),
    ("application/gzip", _decode_gzip),
    ("application/x-gzip", _decode_gzip),
    ("application/ocsp-response", _decode_ocsp),
    ("pkix-cert", _decode_cert),
    ("x-x509-ca-cert", _decode_cert),
    ("pkcs7", _decode_cert),
    ("application/zip", _decode_zip),
    ("application/cbor", _decode_cbor),
    ("dns-message", _decode_dns),
    ("plist", _decode_plist),
    ("text/", _decode_text),
    ("xml", _decode_xml),         # XML may be a plist; falls back to text if not
]


_GENERIC_CT = ("", "application/octet-stream", "binary/octet-stream")


def _magic_override_note(kind: str, expect: str, content_type: str) -> str:
    """A note when a magic-byte catch fires despite a declared Content-Type that names a
    DIFFERENT type (a contradiction). Empty when the CT is absent, generic, or already agrees —
    so it only speaks up when the magic genuinely overrides a conflicting label."""
    ct = (content_type or "").lower().split(";", 1)[0].strip()
    if ct and ct not in _GENERIC_CT and expect not in ct:
        return (f"// note: dispatched by {kind} magic bytes; declared Content-Type "
                f"({content_type}) disagrees\n")
    return ""


def decode_by_content_type(body: bytes, content_type: str) -> Optional[str]:
    """Decode ``body`` per its Content-Type, or ``None`` if this layer doesn't cover it.

    A returned string may itself carry ``// WARNING`` / ``// ERROR`` lines when a
    declared encoding is malformed — surfaced, never silent.
    """
    if not body:
        return None
    # magic-based catches, independent of a declared (or wrong) Content-Type — but if the
    # declared type CONTRADICTS the magic, say so rather than overriding it silently.
    if body[:6] == b"bplist":     # binary plist
        out = _decode_plist(body, content_type)
        if out is not None:
            return _magic_override_note("bplist", "plist", content_type) + out
    if body[:4] == b"PK\x03\x04":  # zip
        out = _decode_zip(body, content_type)
        if out is not None:
            return _magic_override_note("zip", "zip", content_type) + out
    if archives.looks_like_img4(body):
        return _magic_override_note("img4", "img4", content_type) + archives.decode_img4(body)
    ct = (content_type or "").lower()
    for needle, handler in _HANDLERS:
        if needle in ct:
            out = handler(body, ct)
            if out is not None:
                return out
    return None


# --- helpers -----------------------------------------------------------------

def _indent(text: str) -> str:
    return "".join("   " + line + "\n" for line in text.splitlines())


def _append_err(parts: list[str], count: int, e: Exception) -> str:
    parts.append(f"// WARNING: gRPC frame {count + 1} decompression failed: {e}")
    return "\n".join(parts)
