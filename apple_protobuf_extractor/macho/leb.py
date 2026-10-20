"""macho/leb.py -- unsigned LEB128 integers, as Mach-O linkedit data stores them (the dyld
export trie, ``LC_FUNCTION_STARTS``)."""
from __future__ import annotations

from typing import Optional, Tuple


def read_uleb(data: bytes, p: int, end: Optional[int] = None) -> Tuple[int, int]:
    """``(value, offset after it)`` of the unsigned LEB128 at ``data[p]``.  An encoding still
    open at *end* (default: the end of *data*), or wider than 64 bits, ends there:
    ``(the bits read, end)``."""
    end = len(data) if end is None else end
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
