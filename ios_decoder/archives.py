"""Other heavy binary container types: zip, CBOR, and Apple Image4 (img4).

All ``bytes`` in / ``str`` out.  Optional external pieces degrade gracefully and visibly:
CBOR needs the ``cbor2`` package, img4 needs the ``ipsw`` CLI — if either is absent the
decoder says so (with the body size) rather than failing.
"""

from __future__ import annotations

import io
import os
import re
import shutil
import subprocess
import tempfile
import zipfile
from typing import Optional

from . import nested
from .httputil import indent

__all__ = ["decode_zip", "decode_cbor", "decode_img4", "looks_like_img4"]


# How deep to follow zip-within-zip.  Apple's own .c3h/.c3b nesting is one level, so
# 4 is already generous; the cap exists because `data` is untrusted capture bytes and a
# self-referential or deeply-nested archive would otherwise recurse without bound (and
# each level re-reads every member, so the cost compounds).
_MAX_ZIP_DEPTH = 4


def decode_zip(data: bytes, depth: int = 0) -> str:
    """List a zip archive's entries; decode plist/JSON/nested-zip/text members recursively.

    Apple's ``.c3h``/``.c3b`` (3D Flyover) archives nest zip-within-zip, and carry plain
    (non-plist) XML members alongside the plist ones — so a member is decoded via, in order:
    a nested zip (recurse), a plist/JSON container (the ``nested`` decoder), else — if it's
    clean text (covers generic XML and anything else readable) — shown verbatim. Only bytes
    that are none of these are left as ``(not decoded)``, never dropped silently.

    *depth* is the current nesting level, bounded by :data:`_MAX_ZIP_DEPTH`.
    """
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as e:
        return f"// ERROR: not a valid zip archive: {e}"
    with zf:
        names = zf.namelist()
        lines = [f"zip archive: {len(names)} file(s)"]
        for name in names:
            try:
                content = zf.read(name)
            except Exception as e:  # noqa: BLE001 - per-entry, keep going
                lines.append(f"  {name}: // ERROR reading entry: {e}")
                continue
            lines.append(f"  {name} ({len(content)} bytes)")
            if not content:
                lines[-1] += "  (empty)"
                continue
            rendered = _decode_member(content, depth)
            if rendered is not None:
                lines.append(indent(rendered, 4))
            else:                            # member read OK but not structurally-decodable
                lines[-1] += "  (not decoded)"
    return "\n".join(lines)


def _is_zip(content: bytes) -> bool:
    """True if *content* really is a zip archive.

    Tested structurally (``zipfile.is_zipfile`` locates the End of Central Directory
    record) rather than by a magic prefix.  A prefix check gets this wrong in both
    directions: ``PK\\x07\\x08`` is a mid-stream data-descriptor signature and never
    starts a file, while ``PK\\x03\\x04`` is only a *local file header* -- present in a
    truncated fragment that has no central directory and so cannot be listed.  Guessing
    from the prefix also commits the caller to the zip branch, where a failure surfaces
    as "not a valid zip archive" instead of falling through to the plist/JSON/text
    decoders that would have handled the bytes.
    """
    try:
        return zipfile.is_zipfile(io.BytesIO(content))
    except Exception:                        # noqa: BLE001 - malformed input is a "no"
        return False


def _decode_member(content: bytes, depth: int = 0) -> Optional[str]:
    """Best-effort decode of one zip member's bytes; None if nothing recognized it."""
    if _is_zip(content):                     # nested archive (e.g. .c3h within .c3h)
        if depth >= _MAX_ZIP_DEPTH:
            return f"// nested zip not decoded: nesting deeper than {_MAX_ZIP_DEPTH} levels"
        return decode_zip(content, depth + 1)
    parsed = nested.parse_container(content, "")
    if parsed is not None:
        _, tree = parsed
        return nested.render(tree)
    if nested.is_mostly_printable(content):  # generic XML / text: show it, don't hide it
        return content.decode("utf-8", "replace")
    return None


def decode_cbor(data: bytes) -> str:
    """Decode a CBOR body and render it; notes if ``cbor2`` isn't installed."""
    try:
        import cbor2
    except ImportError:
        return f"// CBOR: cbor2 not installed ({len(data)} bytes)"
    try:
        obj = cbor2.loads(data)
    except Exception as e:  # noqa: BLE001 - cbor2 raises various decode errors
        return f"// ERROR: CBOR decode failed: {type(e).__name__}: {e}"
    return nested.render(obj)


_IMG4_MAGICS = {b"IM4M": "im4m", b"IM4P": "im4p", b"IMG4": ""}
_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def looks_like_img4(data: bytes) -> bool:
    """True if ``data`` carries an Image4 magic (IM4M / IM4P / IMG4) at offset 6."""
    return data[6:10] in _IMG4_MAGICS


def decode_img4(data: bytes) -> str:
    """Decode an Apple Image4 blob via the ``ipsw`` CLI; notes if ipsw is unavailable."""
    sub = _IMG4_MAGICS.get(data[6:10])
    if sub is None:
        return f"// img4: unrecognised magic {data[6:10]!r}"
    if shutil.which("ipsw") is None:
        return f"// img4 ({data[6:10].decode()}): ipsw CLI not installed ({len(data)} bytes)"
    cmd = ["ipsw", "img4"] + ([sub] if sub else []) + ["info", "--no-color"]
    fd, path = tempfile.mkstemp(prefix="ios_decoder_img4_")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        out = subprocess.run(cmd + [path], capture_output=True, timeout=30)
        text = _ANSI.sub("", (out.stdout or out.stderr).decode("utf-8", "replace")).rstrip("\n")
        if out.returncode != 0:        # don't pass off an ipsw error (on stderr) as the decode
            return (f"// WARNING: ipsw img4 exited {out.returncode}:\n"
                    + (text or "(no output)"))
        return text or "// img4: no output"
    except (subprocess.SubprocessError, OSError) as e:
        return f"// ERROR: img4 decode failed: {type(e).__name__}: {e}"
    finally:
        os.unlink(path)
