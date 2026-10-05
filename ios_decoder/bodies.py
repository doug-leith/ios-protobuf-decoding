"""How an *undecoded* body is shown — placeholders, preview vs full, repr vs hexdump.

When neither the protobuf/ARPC layer nor the MIME layer decodes a body, the reporter
still surfaces it (never a silent drop).  This module owns *how*:

* **Placeholder types** — image / video / audio / font bodies are large, opaque, and
  uninteresting to read, so they're always replaced by a one-line
  ``<image: image/png, 12345 bytes>`` summary (generalising the old addon's ``<image>`` /
  ``<video>``), regardless of the preview flags.
* **Everything else** — a byte preview whose form is controlled by CLI options:
  ``repr`` (default, surfaces ASCII substrings like DNS labels) or a ``hexdump``
  (offset + hex + ASCII gutter), truncated to ``preview_bytes`` unless ``full``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

__all__ = ["BodyDisplayOptions", "summarize_undecoded", "hexdump", "placeholder_kind"]


@dataclass(frozen=True)
class BodyDisplayOptions:
    """Presentation choices for undecoded bodies (built from the CLI flags)."""
    hexdump: bool = False        # --hex
    full: bool = False           # --full-bodies (no truncation)
    preview_bytes: int = 64      # bytes shown when not full


# Content-type families that are always shown as a placeholder, never dumped.
_PLACEHOLDER_PREFIXES = (
    ("image/", "image"),
    ("video/", "video"),
    ("audio/", "audio"),
    ("font/", "font"),
)
# A few non-prefix types in the same "boring large binary" class.
_PLACEHOLDER_EXACT = {
    "application/mp4": "video",
    "application/x-font-ttf": "font",
    "application/font-woff": "font",
    "application/font-woff2": "font",
    "application/vnd.ms-fontobject": "font",
}


def placeholder_kind(content_type: str) -> Optional[str]:
    """Return 'image'/'video'/'audio'/'font' if this type should be a placeholder, else None."""
    ct = (content_type or "").lower().split(";", 1)[0].strip()
    for prefix, kind in _PLACEHOLDER_PREFIXES:
        if ct.startswith(prefix):
            return kind
    return _PLACEHOLDER_EXACT.get(ct)


def hexdump(data: bytes, indent: str = "   ") -> str:
    """Classic offset | hex (8+8 grouped) | ASCII-gutter dump of ``data``."""
    out = []
    for off in range(0, len(data), 16):
        chunk = data[off:off + 16]
        cells = [f"{b:02x}" for b in chunk]
        left = " ".join(cells[:8])
        right = " ".join(cells[8:])
        hexcol = f"{left:<23}  {right:<23}"
        ascii_col = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        out.append(f"{indent}{off:04x}  {hexcol}  |{ascii_col}|")
    return "\n".join(out)


def summarize_undecoded(body: bytes, content_type: str,
                        opts: BodyDisplayOptions = BodyDisplayOptions()) -> str:
    """One self-contained block describing a body no decoder handled.

    Image/video/audio/font types collapse to a single ``<kind: ct, N bytes>`` line.
    Otherwise: a header line plus a byte preview (repr or hexdump), truncated to
    ``opts.preview_bytes`` unless ``opts.full``, with an explicit truncation note.
    """
    kind = placeholder_kind(content_type)
    if kind is not None:
        return f"<{kind}: {content_type}, {len(body)} bytes>"

    ct = content_type or "no content-type"
    lines = [f"(not decoded: {ct}, {len(body)} bytes)"]
    data = body if opts.full else body[:opts.preview_bytes]
    lines.append(hexdump(data) if opts.hexdump else "   " + repr(data))
    if not opts.full and len(body) > len(data):
        lines.append(f"   … (first {len(data)} of {len(body)} bytes; "
                     f"--full-bodies for all)")
    return "\n".join(lines)
