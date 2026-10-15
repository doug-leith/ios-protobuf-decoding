"""macho/export_trie.py -- decode a Mach-O dyld export trie (name -> image offset).

The export trie (``LC_DYLD_EXPORTS_TRIE``, or the export range of ``LC_DYLD_INFO``) is how
dyld names the symbols an image exports.  Each node is ``uleb(terminal size)``, then -- when
the node ends a name -- ``uleb(flags)`` and, for an ordinary export, ``uleb(image offset)``;
then a child count and, per child, a NUL-terminated edge label and ``uleb(child offset)``.

Re-exports (``EXPORT_SYMBOL_FLAGS_REEXPORT``) name a symbol of ANOTHER image and carry no
address, so they are skipped.  A stub-and-resolver export carries the stub's offset first,
which is where callers branch to.
"""
from __future__ import annotations

from typing import Dict, Tuple

EXPORT_SYMBOL_FLAGS_REEXPORT = 0x08
EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER = 0x10

# [cap:INPUT-SANITY] runaway backstop for a malformed trie, far above any real image's
# node count (libobjc ~400 exports, the largest frameworks a few tens of thousands).
_MAX_NODES = 2_000_000


def decode_export_trie(data: bytes) -> Dict[str, Tuple[int, int]]:
    """``{symbol name: (flags, image offset)}`` for every non-re-export symbol in *data*.

    *data* is the trie's bytes (offset 0 = root).  Malformed nodes are skipped rather than
    raising, so a damaged trie yields the symbols it can still name."""
    end = len(data)
    out: Dict[str, Tuple[int, int]] = {}

    def uleb(p: int) -> Tuple[int, int]:
        res = shift = 0
        while p < end:
            b = data[p]
            p += 1
            res |= (b & 0x7F) << shift
            if not b & 0x80:
                return res, p
            shift += 7
            if shift > 63:
                break
        return res, end

    stack = [(0, "")]
    seen = set()
    while stack and len(seen) < _MAX_NODES:
        node, prefix = stack.pop()
        if node >= end or node in seen:
            continue
        seen.add(node)
        term_size, p = uleb(node)
        if term_size:
            flags, q = uleb(p)
            if not flags & EXPORT_SYMBOL_FLAGS_REEXPORT:
                offset, _q = uleb(q)
                out[prefix] = (flags, offset)
        p += term_size
        if p >= end:
            continue
        nchild = data[p]
        p += 1
        for _ in range(nchild):
            z = data.find(b"\x00", p)
            if z < 0:
                break
            edge = data[p:z].decode("utf-8", errors="replace")
            child, p = uleb(z + 1)
            stack.append((child, prefix + edge))
    return out
