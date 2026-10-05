"""Helpers for tile-tool tests: synthesize section-framed tiles + pull real ones.

The real-tile helper reads a response body out of a git-ignored capture (the golden
``comparison/`` subset has one of every tile type), so the live-gated tests run on a dev
machine with captures present and skip cleanly on a fresh checkout.
"""

from __future__ import annotations

import functools
import re
import struct
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
# git-ignored captures that carry tile responses, smallest/most-complete first
_CAPTURES = [
    _REPO / "ios_decoder" / "comparison" / "subset_large.mitm",
]
# git-ignored real tile bodies extracted by extract_tile_samples (one per type)
_TILES_REAL = Path(__file__).parent / "fixtures" / "tiles_real"


def section(sid: int, meta: bytes, data: bytes = b"") -> bytes:
    """A 12-byte ``0xABBA`` section header (sig, id, meta_size, data_size) + body."""
    return struct.pack(">HHII", 0xABBA, sid, len(meta), len(data)) + meta + data


def saved_tile(name: str):
    """A real tile body extracted by ``extract_tile_samples`` (e.g. ``saved_tile("hrse")``),
    or None if the fixtures aren't present — the caller then ``pytest.skip``s."""
    p = _TILES_REAL / f"{name}.bin"
    return p.read_bytes() if p.exists() else None


@functools.lru_cache(maxsize=1)
def _available_capture():
    for cap in _CAPTURES:
        if cap.exists():
            return cap
    return None


@functools.lru_cache(maxsize=None)
def real_tile_body(url_regex: str):
    """First HTTP response body whose request URL matches ``url_regex``, or None if no
    capture is available / no match (the caller then ``pytest.skip``s)."""
    cap = _available_capture()
    if cap is None:
        return None
    from mitmproxy import io, http
    rx = re.compile(url_regex)
    with open(cap, "rb") as fh:
        for flow in io.FlowReader(fh).stream():
            if (isinstance(flow, http.HTTPFlow) and flow.response
                    and flow.response.content and rx.search(flow.request.pretty_url)):
                return flow.response.content
    return None
