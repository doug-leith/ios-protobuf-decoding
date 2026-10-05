"""Per-request log markers — ``+++REQUEST`` and ``+++REQHEADERS``.

Ported from the addon's `response()` tail: one ``+++REQUEST`` line (url, request byte
count, timestamp) and one ``+++REQHEADERS`` line summarising the request headers, with
sensitive identifier headers and cookies surfaced and any long value SHA-256-hashed (so
the marker stays compact and the raw secret isn't emitted).

Pure: ``(url, headers, body, timestamp, user_agent)`` in, markers out — no mitmproxy.
``headers`` is a list of (name, value) pairs (order + original casing preserved).
"""

from __future__ import annotations

import hashlib

from . import markers
from .httputil import header_get_ci as _get_ci
from .markers import Marker

__all__ = ["INTERESTING_HEADERS", "hash_long_string", "content_sum", "request_log"]

# Identifier / auth headers worth surfacing explicitly (and first) in the summary.
INTERESTING_HEADERS = [
    "X-Apple-I-MD-M", "X-Apple-I-MD-RINFO", "x-apple-seid", "X-Mme-Device-Id",
    "x-jmet-deviceid", "X-Apple-I-SRL-NO", "X-Apple-I-Baa-S", "x-apple-baa-signature",
    "x-apple-baa-certs", "baa-certs", "authorization", "X-Apple-Baa", "x-apple-uuid",
    "maps-auth-token", "siri-absinthe-token-bin",
]

_HASH_THRESHOLD = 128


def hash_long_string(value: str, threshold: int = _HASH_THRESHOLD) -> str:
    """Return ``value`` unchanged, or ``sha256#<digest>`` if longer than ``threshold``."""
    if len(value) > threshold:
        return "sha256#" + hashlib.sha256(value.encode("utf-8")).hexdigest()
    return value


def content_sum(headers, body: bytes) -> int:
    """Total request byte count: sum of header value lengths + body length."""
    return sum(len(v) for _, v in headers) + (len(body) if body else 0)


def _header_summary(headers) -> str:
    """``key=value~``-joined summary: interesting headers first, then each cookie, then the
    remaining headers — long values hashed, secrets never emitted raw."""
    interesting_lower = {h.lower() for h in INTERESTING_HEADERS}
    parts: list[str] = []
    for h in INTERESTING_HEADERS:
        v = _get_ci(headers, h)
        if v is not None:
            parts.append(f"{h}={hash_long_string(v)}~")
    cookie = _get_ci(headers, "cookie")
    if cookie is not None:
        for p in cookie.split(" "):
            if p:
                parts.append(f"cookie={p}~")
    for k, v in headers:
        if k.lower() in interesting_lower or k.lower() == "cookie":
            continue
        parts.append(f"{k}={hash_long_string(v)}~")
    return "".join(parts)


def request_log(url: str, headers, body: bytes, timestamp,
                user_agent: str = "") -> list[Marker]:
    """The ``+++REQUEST`` + ``+++REQHEADERS`` markers for one request."""
    ua = f"User-Agent='{user_agent}'" if user_agent else "-"
    return [
        markers.request(url, content_sum(headers, body), timestamp),
        markers.reqheaders(url, ua, _header_summary(headers)),
    ]
