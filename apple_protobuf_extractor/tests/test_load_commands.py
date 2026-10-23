"""macho/load_commands.py: one parser of a Mach-O image's load commands, for a file and a
dyld cache image alike; a malformed command is a ValueError, not a shorter list."""
import struct
import unittest

from macho.load_commands import (LC_DYLD_CHAINED_FIXUPS, LC_DYLD_EXPORTS_TRIE, LC_DYLD_INFO_ONLY,
                                 LC_FUNCTION_STARTS, LC_SYMTAB, parse_load_commands)
from tests.conftest import _pack_section64, _pack_segment64


def _linkedit(cmd, a, b):
    return struct.pack('<IIII', cmd, 16, a, b)


def _dylib(name):
    raw = name.encode() + b'\x00'
    return struct.pack('<IIIIII', 0x0C, 24 + len(raw), 24, 0, 0, 0) + raw


class TestParse(unittest.TestCase):

    def test_what_the_commands_say(self):
        text = _pack_segment64('__TEXT', vmaddr=0x1000, vmsize=0x2000, fileoff=0, filesize=0x2000,
                               sections=[_pack_section64('__text', '__TEXT', 0x1100, 0x10, 0x100),
                                         _pack_section64('__bss', '__TEXT', 0x1200, 0x10, 0x200,
                                                         flags=0x1)])
        info = struct.pack('<12I', LC_DYLD_INFO_ONLY, 48, 0, 0, 0, 0, 0, 0, 0, 0, 0x50, 0x60)
        cmds = [text, struct.pack('<6I', LC_SYMTAB, 24, 1, 2, 3, 4),
                _linkedit(LC_FUNCTION_STARTS, 0x10, 0x20), info,
                _linkedit(LC_DYLD_CHAINED_FIXUPS, 0x30, 0x40), _dylib('/usr/lib/libobjc.A.dylib')]
        lc = parse_load_commands(b''.join(cmds), len(cmds))
        [seg] = lc.segments
        self.assertEqual((seg.name, seg.vmaddr, seg.vmsize), ('__TEXT', 0x1000, 0x2000))
        self.assertEqual([(s.name, s.file_off, s.has_file_content) for s in seg.sections],
                         [('__text', 0x100, True), ('__bss', 0, False)])
        self.assertIs(lc.segment('__TEXT'), seg)
        self.assertIsNone(lc.segment('__DATA'))
        self.assertEqual(lc.symtab, (1, 2, 3, 4))
        self.assertEqual(lc.function_starts, (0x10, 0x20))
        self.assertEqual(lc.export_trie, (0x50, 0x60))           # LC_DYLD_INFO's export range
        self.assertEqual(lc.chained_fixups, (0x30, 0x40))
        self.assertEqual(lc.dylibs, ['/usr/lib/libobjc.A.dylib'])

    def test_the_exports_trie_command_wins_over_dyld_info(self):
        info = struct.pack('<12I', LC_DYLD_INFO_ONLY, 48, 0, 0, 0, 0, 0, 0, 0, 0, 0x50, 0x60)
        for cmds in ([info, _linkedit(LC_DYLD_EXPORTS_TRIE, 0x70, 0x80)],
                     [_linkedit(LC_DYLD_EXPORTS_TRIE, 0x70, 0x80), info]):
            self.assertEqual(parse_load_commands(b''.join(cmds), 2).export_trie, (0x70, 0x80))

    def test_no_commands(self):
        lc = parse_load_commands(b'', 0)
        self.assertEqual((lc.segments, lc.symtab, lc.export_trie, lc.dylibs), ([], None, None, []))


class TestMalformed(unittest.TestCase):

    def _raises(self, cmds, ncmds, pattern):
        with self.assertRaisesRegex(ValueError, pattern):
            parse_load_commands(cmds, ncmds)

    def test_cmdsize_under_8(self):
        self._raises(struct.pack('<II', LC_SYMTAB, 4) + bytes(20), 1, "cmdsize=4")

    def test_a_command_overrunning_sizeofcmds(self):
        self._raises(struct.pack('<6I', LC_SYMTAB, 32, 0, 0, 0, 0), 1, "overruns sizeofcmds")

    def test_more_commands_than_sizeofcmds_holds(self):
        self._raises(_linkedit(LC_FUNCTION_STARTS, 0, 0), 2, "past sizeofcmds")

    def test_a_command_shorter_than_its_struct(self):
        self._raises(struct.pack('<IIII', LC_SYMTAB, 16, 0, 0), 1, "shorter than its struct")

    def test_sections_past_cmdsize(self):
        seg = bytearray(_pack_segment64('__TEXT', vmaddr=0, vmsize=0x1000, fileoff=0,
                                        filesize=0x1000,
                                        sections=[_pack_section64('__text', '__TEXT', 0, 4, 0)]))
        struct.pack_into('<I', seg, 64, 100)                      # nsects 100, room for 1
        self._raises(bytes(seg), 1, "100 sections do not fit")

    def test_a_dylib_name_outside_its_command(self):
        cmd = bytearray(_dylib('/usr/lib/x'))
        struct.pack_into('<I', cmd, 8, len(cmd))
        self._raises(bytes(cmd), 1, "name offset")


if __name__ == "__main__":
    unittest.main()
