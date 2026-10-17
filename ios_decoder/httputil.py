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


def is_form_urlencoded(body: bytes) -> bool:
    """Whether *body* can be ``application/x-www-form-urlencoded`` data at all.

    Form encoding is text: ``name=value`` pairs, percent-escaped.  Clients are sloppy about
    which characters they escape, so this does not demand strict escaping; it rejects only a
    body that cannot be form data -- one that is not UTF-8, or that holds a control byte other
    than tab/CR/LF.  A binary body sent under this label (Private Relay's ``fetchAuthTokens``
    posts a protobuf with it) fails, so callers can treat the label as contradicted.
    """
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return not any((ord(c) < 0x20 and c not in "\t\r\n") or c == "\x7f" for c in text)


def indent(text: str, spaces: int) -> str:
    """Indent every line of *text* by *spaces* spaces, joined with newlines (no trailing
    newline). Shared by the nested-decode renderers (archives, siri)."""
    pad = " " * spaces
    return "\n".join(pad + line for line in text.splitlines())
