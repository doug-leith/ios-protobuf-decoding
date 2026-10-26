"""macho.nlist -- the nlist_64 symbol table, shared by a binary's LC_SYMTAB
(BinaryContext.iter_symbols) and a dyld cache's .symbols file (macho.local_symbols)."""
import os
import struct
import sys
import unittest
from types import SimpleNamespace

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

from macho.memory import BinaryContext
from macho.nlist import iter_nlist

# strings: "\0_a\0" -- offset 1 names "_a", offset 0 (and 3) the empty string
STRINGS = b"\x00_a\x00"


def _table(*entries):
    return b"".join(struct.pack('<IBBHQ', strx, 0x0e, sect, 0, value)
                    for strx, sect, value in entries)


class TestIterNlist(unittest.TestCase):

    def test_each_entry_with_its_name(self):
        buf = _table((1, 1, 0x1000), (0, 1, 0x2000), (3, 1, 0x3000)) + STRINGS
        got = [(e.name, e.n_value) for e in iter_nlist(buf, 0, 0, 3, 48, 48 + len(STRINGS))]
        self.assertEqual(got, [(b"_a", 0x1000), (b"", 0x2000), (b"", 0x3000)])

    def test_a_string_past_the_table_or_unterminated_has_no_name(self):
        buf = _table((9, 1, 0x1000), (1, 1, 0x2000)) + b"\x00_ab"
        got = [e.name for e in iter_nlist(buf, 0, 0, 2, 32, 32 + 4)]
        self.assertEqual(got, [b"", b""])

    def test_entries_past_the_buffer_are_not_read(self):
        buf = _table((1, 1, 0x1000))
        self.assertEqual(len(list(iter_nlist(buf, 0, 0, 5, 16, 16))), 1)


class TestIterSymbols(unittest.TestCase):

    def test_a_stripped_entry_is_no_symbol(self):
        # an entry whose string is empty (a stripped local) names nothing: not a symbol ''
        data = _table((1, 1, 0x1000), (3, 1, 0x2000)) + STRINGS
        fake = SimpleNamespace(_data=data, _symtab=(1, 2, 33, len(STRINGS)), _export_trie=None)
        fake._data = b"\x00" + data              # (symoff and stroff must be > 0)
        self.assertEqual(list(BinaryContext.iter_symbols(fake)), [("_a", 0x1000)])


if __name__ == "__main__":
    unittest.main()
