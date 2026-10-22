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

from typing import Dict, Iterator, Optional, Tuple

from .leb import read_uleb

EXPORT_SYMBOL_FLAGS_REEXPORT = 0x08
EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER = 0x10

def iter_export_trie(data: bytes) -> Iterator[Tuple[str, int, Optional[int]]]:
    """``(symbol name, flags, image offset or None)`` for every terminal node of the trie in
    *data* (offset 0 = root), depth-first; a re-export has no offset of its own (None).
    A node that cannot be read whole -- its terminal's flags and offset inside the size it
    declares, inside *data* -- names nothing, and an edge that cannot be read ends its node's
    children: a damaged trie yields only symbols it states in full."""
    end = len(data)
    stack = [(0, "")]
    seen = set()
    while stack:                    # each node is visited once (seen) and lies inside data
        node, prefix = stack.pop()
        if node >= end or node in seen:
            continue
        seen.add(node)
        try:
            term_size, p = read_uleb(data, node, end)
            terminal = None
            if term_size:
                t_end = p + term_size
                if t_end > end:
                    continue
                flags, q = read_uleb(data, p, t_end)
                offset = (None if flags & EXPORT_SYMBOL_FLAGS_REEXPORT
                          else read_uleb(data, q, t_end)[0])
                terminal = (prefix, flags, offset)
        except ValueError:
            continue
        if terminal is not None:
            yield terminal
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
            try:
                child, p = read_uleb(data, z + 1, end)
            except ValueError:
                break
            stack.append((child, prefix + edge))


def decode_export_trie(data: bytes) -> Dict[str, Tuple[int, int]]:
    """``{symbol name: (flags, image offset)}`` for every non-re-export symbol in *data*."""
    return {name: (flags, off) for name, flags, off in iter_export_trie(data) if off is not None}
