"""
macho/nlist.py
==============
The ``nlist_64`` symbol table: a binary's ``LC_SYMTAB`` and a dyld cache's ``.symbols`` file
hold the same entries (``n_strx`` u32, ``n_type`` u8, ``n_sect`` u8, ``n_desc`` u16, ``n_value``
u64), each naming a string in a string table.
"""
from __future__ import annotations

import struct
from typing import Iterator, NamedTuple

_NLIST = struct.Struct('<IBBHQ')
NLIST_SIZE = _NLIST.size                 # 16


class Nlist(NamedTuple):
    name: bytes                          # (empty: no name -- its string is not in the table)
    n_type: int
    n_sect: int
    n_value: int


def iter_nlist(buf, nlist_base: int, first: int, last: int,
               strings_base: int, strings_end: int) -> Iterator[Nlist]:
    """The entries ``first`` .. ``last - 1`` of the table at *nlist_base* in *buf* (those that
    lie in it), each with its name: the string at ``strings_base + n_strx``, which must end
    before *strings_end*."""
    end = min(strings_end, len(buf))
    for i in range(first, last):
        off = nlist_base + i * NLIST_SIZE
        if off + NLIST_SIZE > len(buf):
            break
        n_strx, n_type, n_sect, _desc, n_value = _NLIST.unpack_from(buf, off)
        sp = strings_base + n_strx
        stop = buf.find(b'\x00', sp, end) if n_strx and sp < end else -1
        yield Nlist(bytes(buf[sp:stop]) if stop >= 0 else b'', n_type, n_sect, n_value)
