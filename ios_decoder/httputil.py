"""Small HTTP helpers shared across the decoder modules."""

from __future__ import annotations

from typing import Optional


def header_get_ci(headers, name: str) -> Optional[str]:
    """Case-insensitive lookup of *name* over a list of ``(name, value)`` header pairs.

    Returns the first matching value, or ``None`` if absent.  mitmproxy header lists keep
    original casing and may repeat names, so callers that need a header look it up this way.
    """
    nl = name.lower()
    for k, v in headers:
        if k.lower() == nl:
            return v
    return None


def indent(text: str, spaces: int) -> str:
    """Indent every line of *text* by *spaces* spaces, joined with newlines (no trailing
    newline). Shared by the nested-decode renderers (archives, siri)."""
    pad = " " * spaces
    return "\n".join(pad + line for line in text.splitlines())
