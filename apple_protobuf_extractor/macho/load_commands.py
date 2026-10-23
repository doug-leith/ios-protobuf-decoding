"""
macho/load_commands.py — the load commands of a 64-bit Mach-O image.

One parser for an image read from a file (:class:`macho.memory.BinaryContext`) and one read
from a dyld shared cache (:meth:`macho.dyld_cache.DyldCacheReader.image_load_commands`): its
segments and sections, where its linkedit tables lie, the dylibs it links.  A malformed
command is a ValueError, not a shorter list.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

LC_SYMTAB              = 0x00000002
LC_SEGMENT_64          = 0x00000019
LC_DYLD_INFO           = 0x00000022
LC_DYLD_INFO_ONLY      = 0x80000022
LC_DYLD_CHAINED_FIXUPS = 0x80000034
LC_DYLD_EXPORTS_TRIE   = 0x80000033
LC_FUNCTION_STARTS     = 0x00000026
#: The commands naming a dylib the image links (dylib_command: the name's offset at +8).
LC_LINKED_DYLIBS = frozenset((
    0x0000000C,    # LC_LOAD_DYLIB
    0x80000018,    # LC_LOAD_WEAK_DYLIB
    0x8000001F,    # LC_REEXPORT_DYLIB
    0x80000023,    # LC_LOAD_UPWARD_DYLIB
))

# The section types with no file content (loader.h): S_ZEROFILL, S_GB_ZEROFILL,
# S_THREAD_LOCAL_ZEROFILL
ZEROFILL_TYPES = frozenset((0x1, 0xc, 0x12))

_SEGMENT_64_SIZE = 72         # segment_command_64
_SECTION_64_SIZE = 80         # section_64
#: The size of each command read here: one shorter is malformed.
_COMMAND_SIZES = {LC_SEGMENT_64: _SEGMENT_64_SIZE, LC_SYMTAB: 24, LC_DYLD_INFO: 48,
                  LC_DYLD_INFO_ONLY: 48, LC_DYLD_CHAINED_FIXUPS: 16, LC_DYLD_EXPORTS_TRIE: 16,
                  LC_FUNCTION_STARTS: 16, **{c: 24 for c in LC_LINKED_DYLIBS}}


@dataclass
class Section:
    name:     str
    segname:  str
    vmaddr:   int
    vmsize:   int
    file_off: int   # 0 for zerofill sections (no on-disk content)
    flags:    int

    @property
    def size(self) -> int:
        return self.vmsize

    @property
    def has_file_content(self) -> bool:
        """False for BSS / zerofill sections."""
        return (self.flags & 0xFF) not in ZEROFILL_TYPES


@dataclass
class Segment:
    name:     str
    vmaddr:   int
    vmsize:   int
    fileoff:  int
    filesize: int
    sections: List[Section] = field(default_factory=list)


@dataclass
class LoadCommands:
    """What an image's load commands say, in command order."""
    segments: List[Segment] = field(default_factory=list)
    #: LC_SYMTAB: (symoff, nsyms, stroff, strsize)
    symtab: Optional[Tuple[int, int, int, int]] = None
    #: LC_FUNCTION_STARTS: (dataoff, datasize)
    function_starts: Optional[Tuple[int, int]] = None
    #: The export trie (offset, size): LC_DYLD_EXPORTS_TRIE's, else the export range of
    #: LC_DYLD_INFO(_ONLY) when it has one
    export_trie: Optional[Tuple[int, int]] = None
    #: LC_DYLD_CHAINED_FIXUPS: (dataoff, datasize)
    chained_fixups: Optional[Tuple[int, int]] = None
    #: Install names of the dylibs the image links (:data:`LC_LINKED_DYLIBS`)
    dylibs: List[str] = field(default_factory=list)

    def segment(self, name: str) -> Optional[Segment]:
        """The first segment called *name*, or None."""
        return next((s for s in self.segments if s.name == name), None)


def _name(raw: bytes) -> str:
    return raw.rstrip(b'\x00').decode('ascii', errors='replace')


def _parse_segment(cmds: bytes, off: int, cmdsize: int) -> Segment:
    (_, _, segname_b, vmaddr, vmsize, fileoff, filesize,
     _maxprot, _initprot, nsects, _flags) = struct.unpack_from('<II16sQQQQiiII', cmds, off)
    segname = _name(segname_b)
    if _SEGMENT_64_SIZE + nsects * _SECTION_64_SIZE > cmdsize:
        raise ValueError(f"segment {segname} at {off + 32:#x}: {nsects} sections do not fit "
                         f"its cmdsize {cmdsize}")
    seg = Segment(name=segname, vmaddr=vmaddr, vmsize=vmsize, fileoff=fileoff,
                  filesize=filesize)
    for i in range(nsects):
        (sname_b, sgname_b, addr, size, foff, _align, _reloff, _nreloc, s_flags,
         _r1, _r2, _r3) = struct.unpack_from(
            '<16s16sQQIIIIIIII', cmds, off + _SEGMENT_64_SIZE + i * _SECTION_64_SIZE)
        has_content = (s_flags & 0xFF) not in ZEROFILL_TYPES
        seg.sections.append(Section(name=_name(sname_b), segname=_name(sgname_b),
                                    vmaddr=addr, vmsize=size,
                                    file_off=foff if has_content else 0, flags=s_flags))
    return seg


def parse_load_commands(cmds: bytes, ncmds: int) -> LoadCommands:
    """The *ncmds* load commands in *cmds* (the ``sizeofcmds`` bytes after the 32-byte
    ``mach_header_64``).  ValueError for a command with ``cmdsize`` under 8, one that runs past
    the end of *cmds*, one shorter than its struct, or a segment whose sections do not fit in
    it.  Offsets in messages are from the image's header."""
    out = LoadCommands()
    off, end = 0, len(cmds)
    info_exports: Optional[Tuple[int, int]] = None
    for _ in range(ncmds):
        if off + 8 > end:
            raise ValueError(f"load command at {off + 32:#x} past sizeofcmds ({end})")
        cmd, cmdsize = struct.unpack_from('<II', cmds, off)
        if cmdsize < 8:
            raise ValueError(f"bad load command at {off + 32:#x}: cmdsize={cmdsize}")
        if off + cmdsize > end:
            raise ValueError(f"load command at {off + 32:#x} (cmdsize={cmdsize}) overruns "
                             f"sizeofcmds ({end})")
        if cmdsize < _COMMAND_SIZES.get(cmd, 8):
            raise ValueError(f"load command {cmd:#x} at {off + 32:#x}: cmdsize {cmdsize} is "
                             f"shorter than its struct ({_COMMAND_SIZES[cmd]})")
        if cmd == LC_SEGMENT_64:
            out.segments.append(_parse_segment(cmds, off, cmdsize))
        elif cmd == LC_SYMTAB:
            out.symtab = struct.unpack_from('<IIII', cmds, off + 8)
        elif cmd == LC_FUNCTION_STARTS:
            out.function_starts = struct.unpack_from('<II', cmds, off + 8)
        elif cmd == LC_DYLD_EXPORTS_TRIE:
            out.export_trie = struct.unpack_from('<II', cmds, off + 8)
        elif cmd in (LC_DYLD_INFO, LC_DYLD_INFO_ONLY):
            exports = struct.unpack_from('<II', cmds, off + 40)    # dyld_info's last two u32
            if all(exports) and info_exports is None:
                info_exports = exports
        elif cmd == LC_DYLD_CHAINED_FIXUPS:
            out.chained_fixups = struct.unpack_from('<II', cmds, off + 8)
        elif cmd in LC_LINKED_DYLIBS:
            name_off = struct.unpack_from('<I', cmds, off + 8)[0]
            if not 0 < name_off < cmdsize:
                raise ValueError(f"dylib command at {off + 32:#x}: name offset {name_off} "
                                 f"outside its cmdsize {cmdsize}")
            name = cmds[off + name_off:off + cmdsize].split(b'\x00', 1)[0]
            if name:
                out.dylibs.append(name.decode('utf-8', errors='replace'))
        off += cmdsize
    if out.export_trie is None:
        out.export_trie = info_exports
    return out
