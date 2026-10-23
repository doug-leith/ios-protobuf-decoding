"""tests/test_memory.py — tests for macho/memory.py BinaryContext."""

from __future__ import annotations

import struct
import pytest

from macho.memory import (
    BinaryContext,
    FAT_MAGIC, MH_CIGAM_64, MH_MAGIC_64,
    CPU_TYPE_ARM64,
)
from tests.conftest import (
    build_text_binary,
    NOP_BYTES, RET_BYTES,
    ptr64,
)

TEXT_VA = 0x1000


def ctx(code: bytes, vmaddr: int = TEXT_VA) -> BinaryContext:
    return BinaryContext(build_text_binary(code, vmaddr=vmaddr))


# Two segments whose file bytes are adjacent, the first holding two sections: a section that
# is not its segment's start or whole, and a read or a string that runs on past its segment
# into the next one's bytes, rather than to the end of the file.
TWO_TEXT, TWO_CSTR, TWO_DATA = 0x1000, 0x1010, 0x2000
TWO_FILEOFF = 32 + (72 + 2 * 80) + (72 + 80)
TWO_CODE = NOP_BYTES * 4
TWO_CSTR_BYTES = b"abcdefghijklmnop"            # no terminator inside __TEXT
TWO_DATA_BYTES = b"\x00" * 8 + b"\xaa" * 8


def two_segments() -> BinaryContext:
    import tests.conftest as cf
    text = cf._pack_segment64('__TEXT', vmaddr=TWO_TEXT, vmsize=0x20, fileoff=TWO_FILEOFF,
                              filesize=0x20, sections=[
        cf._pack_section64('__text', '__TEXT', TWO_TEXT, 0x10, TWO_FILEOFF),
        cf._pack_section64('__cstring', '__TEXT', TWO_CSTR, 0x10, TWO_FILEOFF + 0x10)])
    data = cf._pack_segment64('__DATA', vmaddr=TWO_DATA, vmsize=0x10,
                              fileoff=TWO_FILEOFF + 0x20, filesize=0x10, sections=[
        cf._pack_section64('__data', '__DATA', TWO_DATA, 0x10, TWO_FILEOFF + 0x20)])
    hdr = cf._pack_header(ncmds=2, sizeofcmds=len(text) + len(data))
    assert len(hdr + text + data) == TWO_FILEOFF
    return BinaryContext(hdr + text + data + TWO_CODE + TWO_CSTR_BYTES + TWO_DATA_BYTES)


# ─── Header validation ────────────────────────────────────────────────────────

class TestHeaderValidation:
    def test_too_short(self):
        # Isolate the `len(data) < 32` length guard specifically.  Use a VALID
        # MH_MAGIC_64 magic followed by a too-short body: the fixture reaches the
        # length guard regardless of whether the length check or the magic check
        # runs first (an all-zeros fixture would be ambiguous — magic==0 also
        # raises ValueError, so a bare `raises(ValueError)` couldn't tell which
        # guard fired).  Assert the length-guard message so it can't pass on the
        # bad-magic path.
        data = struct.pack('<I', MH_MAGIC_64) + b'\x00' * 16   # 20 bytes < 32
        with pytest.raises(ValueError, match="too short"):
            BinaryContext(data)
        with pytest.raises(ValueError, match="too short"):     # one byte under the header
            BinaryContext(struct.pack('<I', MH_MAGIC_64) + b'\x00' * 27)

    def test_bad_magic(self):
        # An arm64 CPU type, so only the magic is wrong (a 32-bit Mach-O's among them)
        for magic in (0xDEADBEEF, 0xFEEDFACE):
            data = struct.pack('<IIIIIIII', magic, CPU_TYPE_ARM64, 0, 2, 0, 0, 0, 0) \
                + b'\x00' * 200
            with pytest.raises(ValueError, match="Not a 64-bit LE Mach-O"):
                BinaryContext(data)

    def test_fat_magic_rejected(self):
        data = struct.pack('<IIIIIIII', FAT_MAGIC, 0,0,0,0,0,0,0) + b'\x00' * 200
        with pytest.raises(ValueError, match="[Ff]at"):
            BinaryContext(data)
        # a fat file's own first bytes (fat.h: FAT_MAGIC 0xcafebabe, stored big-endian)
        with pytest.raises(ValueError, match="[Ff]at"):
            BinaryContext(b'\xca\xfe\xba\xbe' + b'\x00' * 228)

    def test_be_magic_rejected(self):
        data = struct.pack('<IIIIIIII', MH_CIGAM_64, 0,0,0,0,0,0,0) + b'\x00' * 200
        with pytest.raises(ValueError, match="[Bb]ig"):
            BinaryContext(data)
        # a big-endian 64-bit header's own first bytes (MH_MAGIC_64 0xfeedfacf, big-endian)
        with pytest.raises(ValueError, match="[Bb]ig"):
            BinaryContext(b'\xfe\xed\xfa\xcf' + b'\x00' * 228)

    def test_truncated_load_commands(self):
        # ncmds=1, sizeofcmds=1000, but binary only has 100 bytes after header; the command
        # there is well formed, so only the truncation can reject it
        import tests.conftest as cf
        seg = cf._pack_segment64('__TEXT', vmaddr=0x1000, vmsize=0, fileoff=0, filesize=0)
        data = struct.pack('<IIIIIIII',
            MH_MAGIC_64, CPU_TYPE_ARM64, 0, 2,
            1,    # ncmds
            1000, # sizeofcmds
            0, 0
        ) + seg + b'\x00' * (100 - len(seg))
        with pytest.raises(ValueError, match="truncated: need 1032 bytes"):
            BinaryContext(data)

    def test_valid_arm64_binary(self):
        c = ctx(NOP_BYTES)
        assert c is not None


# ─── CPU properties ───────────────────────────────────────────────────────────

class TestCpuProperties:
    def test_cpu_type(self):
        c = ctx(NOP_BYTES)
        assert c.cpu_type == CPU_TYPE_ARM64

    def test_is_not_arm64e_by_default(self):
        c = ctx(NOP_BYTES)
        assert not c.is_arm64e

    def test_is_arm64e_subtype(self):
        # Build a binary with cpu_subtype = 0x80000002 (arm64e)
        code   = NOP_BYTES
        binary = build_text_binary(code, vmaddr=TEXT_VA)
        # Patch cpusubtype at offset 8
        patched = binary[:8] + struct.pack('<I', 0x80000002) + binary[12:]
        c = BinaryContext(patched)
        assert c.is_arm64e
        # arm64e is the subtype's low byte, with or without the capability bits above it
        for subtype, arm64e in ((0x00000002, True), (0x81000002, True), (0x80000000, False),
                                (0x80000001, False)):
            patched = binary[:8] + struct.pack('<I', subtype) + binary[12:]
            assert BinaryContext(patched).is_arm64e is arm64e, hex(subtype)

    def test_image_base(self):
        c = ctx(NOP_BYTES, vmaddr=0x1000)
        # Segment vmaddr = 0x1000 (not PAGEZERO)
        assert c.image_base == 0x1000


# ─── Filetype (executable vs dylib) ───────────────────────────────────────────

class TestFiletype:
    # Mach-O header: magic(0) cputype(4) cpusubtype(8) filetype(12) …
    _FILETYPE_OFF = 12

    def _with_filetype(self, ft: int) -> BinaryContext:
        b = build_text_binary(NOP_BYTES, vmaddr=TEXT_VA)
        patched = b[:self._FILETYPE_OFF] + struct.pack('<I', ft) + b[self._FILETYPE_OFF + 4:]
        return BinaryContext(patched)

    def test_executable_is_executable(self):
        import tests.conftest as cf
        c = self._with_filetype(cf.MH_EXECUTE)
        assert c.filetype == cf.MH_EXECUTE
        assert c.is_executable
        assert not c.is_dylib

    def test_dylib_is_dylib(self):
        import tests.conftest as cf
        c = self._with_filetype(cf.MH_DYLIB)
        assert c.filetype == cf.MH_DYLIB
        assert c.is_dylib
        assert not c.is_executable


# ─── Section access ───────────────────────────────────────────────────────────

class TestSectionAccess:
    def test_has_section_true(self):
        c = ctx(NOP_BYTES)
        assert c.has_section('__TEXT', '__text')

    def test_has_section_false(self):
        c = ctx(NOP_BYTES)
        assert not c.has_section('__DATA', '__data')
        # A section is named by its segment and its own name together
        c = two_segments()
        assert not c.has_section('__DATA', '__text')
        assert not c.has_section('__TEXT', '__data')

    def test_section_vmaddr(self):
        c = ctx(NOP_BYTES, vmaddr=TEXT_VA)
        sect = c.section('__TEXT', '__text')
        assert sect.vmaddr == TEXT_VA
        assert two_segments().section('__TEXT', '__cstring').vmaddr == TWO_CSTR

    def test_section_size(self):
        code = NOP_BYTES * 5
        c    = ctx(code)
        sect = c.section('__TEXT', '__text')
        assert sect.size == len(code)
        assert two_segments().section('__TEXT', '__text').size == 0x10     # (segment: 0x20)

    def test_section_missing_raises(self):
        c = ctx(NOP_BYTES)
        with pytest.raises(KeyError):
            c.section('__DATA', '__data')
        with pytest.raises(KeyError):                  # (the name in another segment)
            two_segments().section('__DATA', '__text')

    def test_section_has_file_content(self):
        c    = ctx(NOP_BYTES)
        sect = c.section('__TEXT', '__text')
        assert sect.has_file_content


# ─── vmaddr_to_offset / read_bytes ───────────────────────────────────────────

class TestReadBytes:
    def test_read_first_instruction(self):
        c    = ctx(NOP_BYTES + RET_BYTES)
        data = c.read_bytes(TEXT_VA, 4)
        assert data == NOP_BYTES

    def test_read_second_instruction(self):
        c    = ctx(NOP_BYTES + RET_BYTES)
        data = c.read_bytes(TEXT_VA + 4, 4)
        assert data == RET_BYTES

    def test_unmapped_raises(self):
        c = ctx(NOP_BYTES)
        for va in (0xDEAD0000, 0, TEXT_VA - 4, TEXT_VA + 4):     # above, below, just outside
            with pytest.raises(ValueError):
                c.read_bytes(va, 4)

    def test_overrun_raises(self):
        c = ctx(NOP_BYTES)   # only 4 bytes of code
        with pytest.raises(ValueError):
            c.read_bytes(TEXT_VA, 8)   # ask for 8 bytes
        # The segment's end, not the file's: __DATA's bytes follow __TEXT's
        c = two_segments()
        assert c.read_bytes(TWO_CSTR, 0x10) == TWO_CSTR_BYTES
        with pytest.raises(ValueError, match="overruns segment"):
            c.read_bytes(TWO_CSTR, 0x14)

    def test_zero_length_no_error(self):
        c = ctx(NOP_BYTES * 4)
        # Reading 0 bytes at a valid address is pathological but must not crash
        assert c.read_bytes(TEXT_VA + 4, 0) == b''
        assert c.vmaddr_to_offset(TEXT_VA + 4, 1) == 32 + 72 + 80 + 4      # the file offset


# ─── Primitive readers ────────────────────────────────────────────────────────

class TestPrimitiveReaders:
    def test_read_u32(self):
        word = 0xABCD1234
        code = struct.pack('<I', word)
        c    = ctx(code)
        assert c.read_u32(TEXT_VA) == word

    def test_read_u64(self):
        val  = 0x0102030405060708
        code = struct.pack('<Q', val)
        c    = ctx(code)
        assert c.read_u64(TEXT_VA) == val
        # Unsigned: bit 63 (a bind or authentication bit) is part of the value
        assert ctx(struct.pack('<Q', 0x8010000000000001)).read_u64(TEXT_VA) \
            == 0x8010000000000001

    def test_read_s32_negative(self):
        code = struct.pack('<i', -42)
        c    = ctx(code)
        assert c.read_s32(TEXT_VA) == -42

    def test_read_s64_negative(self):
        code = struct.pack('<q', -1)
        c    = ctx(code)
        assert c.read_s64(TEXT_VA) == -1
        # All eight bytes, in order (-1 reads as -1 at any signed width and either order)
        assert ctx(struct.pack('<q', -0x123456789)).read_s64(TEXT_VA) == -0x123456789


# ─── read_cstring ─────────────────────────────────────────────────────────────

class TestReadCstring:
    def test_simple(self):
        code = b'hello\x00' + b'\x00' * 2
        c    = ctx(code)
        assert c.read_cstring(TEXT_VA) == 'hello'

    def test_empty_string(self):
        code = b'\x00' + NOP_BYTES
        c    = ctx(code)
        assert c.read_cstring(TEXT_VA) == ''

    def test_no_null_raises(self):
        code = b'abcdefghijklmnopq'   # 17 bytes, no null within max_len=4
        c    = ctx(code)
        with pytest.raises(ValueError):
            c.read_cstring(TEXT_VA, max_len=4)
        c = ctx(b'abcdefgh\x00')       # a null past max_len
        with pytest.raises(ValueError):
            c.read_cstring(TEXT_VA, max_len=4)
        assert c.read_cstring(TEXT_VA, max_len=9) == 'abcdefgh'


# ─── find_cstring_in_section ─────────────────────────────────────────────────

class TestFindCstring:
    def test_finds_string(self):
        code = b'one\x00two\x00three\x00'
        c    = ctx(code)
        va   = c.find_cstring_in_section('__TEXT', '__text', 'two')
        assert va == TEXT_VA + 4    # 'two' starts at offset 4
        # a whole C string, not a prefix of an earlier one
        c = ctx(b'twofold\x00two\x00')
        assert c.find_cstring_in_section('__TEXT', '__text', 'two') == TEXT_VA + 8

    def test_missing_string_returns_none(self):
        code = b'hello\x00'
        c    = ctx(code)
        assert c.find_cstring_in_section('__TEXT', '__text', 'world') is None
        assert c.find_cstring_in_section('__TEXT', '__text', 'hell') is None   # (a prefix)

    def test_missing_section_returns_none(self):
        c = ctx(NOP_BYTES)
        assert c.find_cstring_in_section('__DATA', '__data', 'hello') is None


# ─── iter_ptrs ────────────────────────────────────────────────────────────────

class TestIterPtrs:
    def test_three_pointers(self):
        # (above 2**32: all 8 bytes of each slot)
        code = ptr64(0x1_0000_0AAA) + ptr64(0x1_0000_0BBB) + ptr64(0x1_0000_0CCC)
        c    = ctx(code)
        vals = list(c.iter_ptrs(TEXT_VA, 3))
        assert vals == [0x1_0000_0AAA, 0x1_0000_0BBB, 0x1_0000_0CCC]

    def test_single_pointer(self):
        code = ptr64(0x1_2345_6780)
        c    = ctx(code)
        assert list(c.iter_ptrs(TEXT_VA, 1)) == [0x1_2345_6780]


# ─── Zerofill / BSS sections ─────────────────────────────────────────────────

class TestZerofillSections:
    def _bss_binary(self):
        """Binary with a zerofill (BSS) section — S_ZEROFILL = flags & 0xFF == 1."""
        VA      = 0x1000
        BSS_SZ  = 4096

        import tests.conftest as cf
        # flags=1 → S_ZEROFILL
        sect = cf._pack_section64('__bss', '__DATA', VA, BSS_SZ, 0, flags=1)
        seg  = cf._pack_segment64('__DATA', vmaddr=VA, vmsize=BSS_SZ,
                                   fileoff=0, filesize=0, sections=[sect])
        hdr  = cf._pack_header(ncmds=1, sizeofcmds=len(seg))
        return BinaryContext(hdr + seg)

    def test_has_file_content_false(self):
        ctx  = self._bss_binary()
        sect = ctx.section('__DATA', '__bss')
        assert not sect.has_file_content

    def test_the_zerofill_types_are_loader_h_s(self):
        """S_ZEROFILL (0x1), S_GB_ZEROFILL (0xc) and S_THREAD_LOCAL_ZEROFILL (0x12) have no
        file content; S_MOD_INIT_FUNC_POINTERS (0x9) has, as a plain section (0x0) has (#141)."""
        import tests.conftest as cf
        for stype, content in ((0x0, True), (0x1, False), (0x9, True), (0xc, False),
                               (0x12, False)):
            sect = cf._pack_section64('__s', '__DATA', 0x1000, 16, 0x40,
                                      flags=0x80000000 | stype)
            seg  = cf._pack_segment64('__DATA', vmaddr=0x1000, vmsize=16, fileoff=0x40,
                                       filesize=16, sections=[sect])
            hdr  = cf._pack_header(ncmds=1, sizeofcmds=len(seg))
            s = BinaryContext(hdr + seg + bytes(0x40)).section('__DATA', '__s')
            assert (s.has_file_content, s.file_off) == (content, 0x40 if content else 0), stype

    def test_read_bytes_zerofill_raises(self):
        ctx = self._bss_binary()
        with pytest.raises(ValueError):
            ctx.read_bytes(0x1000, 4)

    def test_vmaddr_to_offset_zerofill_raises(self):
        ctx = self._bss_binary()
        with pytest.raises(ValueError):
            ctx.vmaddr_to_offset(0x1000, 1)


# ─── PAGEZERO / image_base ───────────────────────────────────────────────────

class TestImageBase:
    def _binary_with_pagezero(self):
        import tests.conftest as cf
        import struct
        """Binary with a PAGEZERO (vmaddr=0, vmsize=0x100000000) and a real TEXT segment."""
        HDR    = 32
        # Two segments: __PAGEZERO (no sections, no file content) + __TEXT (one section)
        LC1_SZ = 72        # PAGEZERO has 0 sections
        LC2_SZ = 72 + 80   # __TEXT has 1 section
        DATA_OFF = HDR + LC1_SZ + LC2_SZ
        TEXT_VA  = 0x100004000
        CODE     = struct.pack('<I', 0xD65F03C0)   # ret

        pg_seg = cf._pack_segment64('__PAGEZERO', vmaddr=0, vmsize=0x100000000,
                                     fileoff=0, filesize=0, sections=[])
        txt_sect = cf._pack_section64('__text', '__TEXT', TEXT_VA, len(CODE), DATA_OFF)
        txt_seg  = cf._pack_segment64('__TEXT', vmaddr=TEXT_VA, vmsize=len(CODE),
                                       fileoff=DATA_OFF, filesize=len(CODE),
                                       sections=[txt_sect])
        hdr = cf._pack_header(ncmds=2, sizeofcmds=len(pg_seg) + len(txt_seg))
        return BinaryContext(hdr + pg_seg + txt_seg + CODE)

    def test_image_base_excludes_pagezero(self):
        ctx = self._binary_with_pagezero()
        assert ctx.image_base == 0x100004000

    def test_image_base_cached(self):
        """image_base is found once, when the load commands are read, not on each access."""
        ctx = self._binary_with_pagezero()
        ctx._segments = []                  # (a recomputed base would be 0 now)
        assert ctx.image_base == 0x100004000
        assert ctx.image_base == 0x100004000


# ─── Bad load command ────────────────────────────────────────────────────────

class TestBadLoadCommand:
    def test_cmdsize_too_small_raises(self):
        """A load command with cmdsize < 8 is malformed and must raise."""
        import struct as st, tests.conftest as cf
        # sizeofcmds >= 8 so the loop reads the load command header;
        # cmdsize=4 inside the command is what triggers the raise.
        sizeofcmds = 8
        hdr = st.pack('<IIIIIIII',
            cf.MH_MAGIC_64, cf.CPU_ARM64, 0, cf.MH_EXECUTE,
            1, sizeofcmds, 0, 0)
        bad_lc = st.pack('<II', cf.LC_SEGMENT_64, 4)   # cmdsize=4 < 8 → invalid
        with pytest.raises(ValueError):
            BinaryContext(hdr + bad_lc + b'\x00' * 200)


# ─── read_cstring segment-boundary clamping ──────────────────────────────────

class TestReadCstringBoundary:
    def test_cstring_at_last_byte_of_segment(self):
        """Null terminator at the very last byte of the segment must succeed."""
        # Build: 'hello\0' where \0 is the LAST byte in the segment.
        # Pass vmaddr=TEXT_VA so the segment is mapped where the test reads from.
        code = b'hello\x00'
        ctx  = BinaryContext(build_text_binary(code, vmaddr=TEXT_VA))
        s    = ctx.read_cstring(TEXT_VA)
        assert s == 'hello'

    def test_uncapped_read_goes_to_the_terminator(self):
        """max_len=None: clamped by the segment only (a Swift name is read so)."""
        name = b'n' * 5000
        ctx  = BinaryContext(build_text_binary(name + b'\x00', vmaddr=TEXT_VA))
        assert ctx.read_cstring(TEXT_VA, None) == name.decode()
        with pytest.raises(ValueError):
            ctx.read_cstring(TEXT_VA)
        with pytest.raises(ValueError):     # the segment's end, not the file's
            two_segments().read_cstring(TWO_CSTR, None)

    def test_no_null_within_segment_raises(self):
        """If there's no null within the segment, read_cstring must raise."""
        code = b'abcde'   # no null terminator anywhere
        ctx  = BinaryContext(build_text_binary(code, vmaddr=TEXT_VA))
        with pytest.raises(ValueError):
            ctx.read_cstring(TEXT_VA, max_len=10)
        # ... even when the next segment's bytes, right after it in the file, hold one
        with pytest.raises(ValueError):
            two_segments().read_cstring(TWO_CSTR, max_len=40)


# ─── Section cmdsize validation ──────────────────────────────────────────────

class TestSectionCmdsizeValidation:
    def test_inflated_nsects_clamped_to_cmdsize(self):
        """A segment claiming nsects=100 but cmdsize only fitting 1 section
        must parse exactly 1 section, not overflow."""
        import struct as st, tests.conftest as cf

        code = b'\x00' * 4
        HDR  = 32
        # Build a segment with nsects=100 but cmdsize only covering 1 section
        real_nsects  = 1
        lie_nsects   = 100
        cmdsize      = 72 + real_nsects * 80  # only space for 1 section

        sect_b = cf._pack_section64('__text', '__TEXT', 0x1000, 4, HDR + cmdsize)
        seg_hdr = st.pack('<II16sQQQQiiii',
            cf.LC_SEGMENT_64, cmdsize,
            b'__TEXT\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
            0x1000, 4, HDR + cmdsize, 4,
            7, 5, lie_nsects, 0)
        seg_b = seg_hdr + sect_b
        assert len(seg_b) == cmdsize

        hdr = cf._pack_header(ncmds=1, sizeofcmds=cmdsize)
        ctx = BinaryContext(hdr + seg_b + code)
        # Must have parsed exactly 1 section, not 100
        assert ctx.has_section('__TEXT', '__text')
        # No additional garbage sections should exist
        sect = ctx.section('__TEXT', '__text')
        assert sect.vmaddr == 0x1000


# ─── TestBinaryContextFromCache ───────────────────────────────────────────────

import os as _os, shutil as _shutil, struct as _struct, tempfile as _tempfile

_CACHE_MAGIC = b'dyld_v1   arm64\x00'


def _build_from_cache_fixture(base: int = 0x100000000):
    """
    Build a synthetic single-mapping cache and return
    ``(cache_path_str, base, content_bytes)``.

    The mapping starts 0x1000 below *base* (the cache's base is not the image's).
    Content layout (all offsets relative to *base*):
      +0x0000  mach-o header + one LC_SEGMENT_64 (__TEXT, 0x5000 bytes)
      +0x1000  class name cstring  "CacheClass\\0"
      +0x2000  class_ro_t stub     name ptr at +24
      +0x3000  class_t stub        data ptr at +32
      +0x4000  classlist           one entry → class_t
    """
    content = bytearray(0x5000)

    # mach-o header + minimal LC_SEGMENT_64
    lc_size = 72
    _struct.pack_into('<I', content,  0, 0xFEEDFACF)
    _struct.pack_into('<I', content,  4, CPU_TYPE_ARM64)
    _struct.pack_into('<I', content,  8, 0)
    _struct.pack_into('<I', content, 12, 6)          # MH_DYLIB
    _struct.pack_into('<I', content, 16, 1)
    _struct.pack_into('<I', content, 20, lc_size)
    _struct.pack_into('<I', content, 32, 0x19)
    _struct.pack_into('<I', content, 36, lc_size)
    content[40:56] = b'__TEXT\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    _struct.pack_into('<Q', content, 56, base)
    _struct.pack_into('<Q', content, 64, 0x5000)
    _struct.pack_into('<I', content, 80, 0)   # nsects

    name_va  = base + 0x1000
    ro_va    = base + 0x2000
    cls_va   = base + 0x3000

    content[0x1000 : 0x1000 + 11] = b'CacheClass\x00'
    _struct.pack_into('<Q', content, 0x2000 + 24, name_va)
    _struct.pack_into('<Q', content, 0x3000 + 32, ro_va)
    _struct.pack_into('<Q', content, 0x4000, cls_va)
    # Two encoded pointers (DyldCacheReader.decode_ptr): an arm64e authenticated rebase,
    # its low 32 bits the offset from the cache base, and a plain-arm64 cache's, its low
    # 36 bits the address under metadata bits
    _struct.pack_into('<Q', content, 0x4800, (1 << 63) | (0x1000 + 0x2000))
    _struct.pack_into('<Q', content, 0x4808, (0x5 << 48) | name_va)

    # Pack into a minimal cache file
    mapped   = bytes(0x1000) + content
    MAP_OFF  = 0x200
    cont_off = (MAP_OFF + 32 + 0xfff) & ~0xfff
    total    = cont_off + len(mapped)
    buf      = bytearray(total)
    buf[0:16] = _CACHE_MAGIC
    _struct.pack_into('<I', buf, 0x10, MAP_OFF)
    _struct.pack_into('<I', buf, 0x14, 1)
    _struct.pack_into('<QQQ', buf, MAP_OFF, base - 0x1000, len(mapped), cont_off)
    _struct.pack_into('<I',   buf, MAP_OFF + 24, 5)
    _struct.pack_into('<I',   buf, MAP_OFF + 28, 5)
    buf[cont_off : cont_off + len(mapped)] = mapped

    tmpdir   = _tempfile.mkdtemp()
    path     = _os.path.join(tmpdir, 'dyld_shared_cache_arm64')
    with open(path, 'wb') as f:
        f.write(buf)
    return tmpdir, path, base, bytes(content)


class TestBinaryContextFromCache:
    """Unit tests for BinaryContext.from_cache()."""

    _SEC_MAP = {
        '__TEXT':                        (0x100000000, 0x100005000),
        '__TEXT/__objc_classname':       (0x100001000, 0x100001100),
        '__DATA_CONST':                  (0x100004000, 0x100004008),
        '__DATA_CONST/__objc_classlist': (0x100004000, 0x100004008),
    }

    # pytest xunit-style fixtures (this file is pytest-native — plain classes, not
    # unittest.TestCase — so `setUp`/`tearDown` are NOT honoured; pytest 8+ dropped
    # nose-style support.  Use `setup_method`/`teardown_method`, which pytest calls
    # for plain test classes).
    def setup_method(self, method):
        self._tmpdir, path, self._base, _ = _build_from_cache_fixture(0x100000000)
        from macho.dyld_cache import DyldCacheReader
        self._reader = DyldCacheReader(path)
        self._reader.image_sections = lambda va: self._SEC_MAP
        self._ctx = BinaryContext.from_cache(self._reader, self._base)

    def teardown_method(self, method):
        self._reader.close()
        _shutil.rmtree(self._tmpdir, ignore_errors=True)

    # ── construction ─────────────────────────────────────────────────────────

    def test_creates_instance(self):
        assert isinstance(self._ctx, BinaryContext)

    def test_image_base_equals_mach_header_va(self):
        assert self._ctx.image_base == self._base

    def test_cpu_type_is_arm64(self):
        assert self._ctx.cpu_type == CPU_TYPE_ARM64

    def test_is_arm64e_false(self):
        assert not self._ctx.is_arm64e

    # ── section access ────────────────────────────────────────────────────────

    def test_has_section_present(self):
        assert self._ctx.has_section('__DATA_CONST', '__objc_classlist')

    def test_has_section_absent(self):
        assert not self._ctx.has_section('__EXTRA_OBJC', '__objc_selrefs')
        assert not self._ctx.has_section('__TEXT', '__objc_classlist')   # (__DATA_CONST's)

    def test_section_vmaddr_and_size(self):
        sec = self._ctx.section('__DATA_CONST', '__objc_classlist')
        assert sec.vmaddr == self._base + 0x4000
        assert sec.vmsize == 8
        sec = self._ctx.section('__TEXT', '__objc_classname')            # (not its segment's)
        assert (sec.vmaddr, sec.vmsize) == (self._base + 0x1000, 0x100)

    # ── read primitives ───────────────────────────────────────────────────────

    def test_read_u64(self):
        # class_t.data at offset 32 → class_ro_t VA
        assert self._ctx.read_u64(self._base + 0x3000 + 32) == self._base + 0x2000
        # the word as stored, not decoded
        assert self._ctx.read_u64(self._base + 0x4800) == (1 << 63) | 0x3000

    def test_read_u32_magic(self):
        assert self._ctx.read_u32(self._base) == 0xFEEDFACF

    def test_read_cstring(self):
        assert self._ctx.read_cstring(self._base + 0x1000) == 'CacheClass'

    def test_read_bytes(self):
        assert self._ctx.read_bytes(self._base, 4) == _struct.pack('<I', 0xFEEDFACF)
        assert self._ctx.read_bytes(self._base + 0x1000, 11) == b'CacheClass\x00'

    def test_read_ptr_decodes(self):
        # class_ro_t VA is in the mapping → returned unchanged
        assert self._ctx.read_ptr(self._base + 0x3000 + 32) == self._base + 0x2000
        # encoded pointers -> their targets
        assert self._ctx.read_ptr(self._base + 0x4800) == self._base + 0x2000
        assert self._ctx.read_ptr(self._base + 0x4808) == self._base + 0x1000

    def test_iter_ptrs_classlist(self):
        ptrs = list(self._ctx.iter_ptrs(self._base + 0x4000, 1))
        assert len(ptrs) == 1
        assert ptrs[0] == self._base + 0x3000
        # consecutive 8-byte slots, each decoded
        assert list(self._ctx.iter_ptrs(self._base + 0x4800, 2)) \
            == [self._base + 0x2000, self._base + 0x1000]

    def test_read_unmapped_raises(self):
        with pytest.raises(ValueError):
            self._ctx.read_u64(0xDEAD000000000000)

    # ── another image's class in cache mode ───────────────────────────────────

    def test_a_cache_binds_nothing_by_name(self):
        """A dyld cache was bound when it was built: a class slot is read through, to the
        class it points at (ptr→class_t→class_ro_t→name), not named by a bind."""
        from macho.classlist import class_name_at
        assert self._ctx.bind_name_for(self._base + 0x4000) is None
        assert class_name_at(self._ctx, self._ctx.read_ptr(self._base + 0x4000)) == 'CacheClass'

    def test_bind_name_for_unmapped_returns_none(self):
        assert self._ctx.bind_name_for(0xDEAD000000000000) is None


# ─── chained-fixup binds: named by their slot (binary mode) ──────────────────

class TestBindSlots:
    """A chained-fixup bind is named by the slot the chain walk found it at
    (``bind_name_for``); ``read_ptr`` gives its raw value, which is no address of the file
    -- even where its low bits, the import ordinal, fall inside a segment (a dylib whose
    ``__TEXT`` is at vmaddr 0)."""

    def _base0_ctx(self):
        raw = 0x8010000000000002            # ptr64 bind, ordinal 2: inside __TEXT at 0
        c = BinaryContext(build_text_binary(struct.pack('<Q', raw) + NOP_BYTES * 2, vmaddr=0))
        return c, raw

    def test_a_bind_slot_reads_as_its_raw_value(self):
        c, raw = self._base0_ctx()
        assert c.read_ptr(0) == 2           # (not a bind: the packed-pointer reading)
        c._bind_slots.add(0)
        c._bind_name_map[0] = '_OBJC_CLASS_$_NSObject'
        assert c.read_ptr(0) == raw
        assert list(c.iter_ptrs(0, 1)) == [raw]
        assert c.bind_name_for(0) == '_OBJC_CLASS_$_NSObject'
        assert c.bind_name_for(8) is None

    def test_a_bound_superclass_is_named(self):
        from macho.classlist import ClassList, ObjcClass, superclass_chain
        c, raw = self._base0_ctx()
        c._bind_slots.add(8)
        c._bind_name_map[8] = '_OBJC_CLASS_$_PBCodable'
        cls = ObjcClass(vmaddr=0, name="AReq", is_meta=False, superclass_vmaddr=raw,
                        superclass_name=None, ro_flags=0, instance_size=0, methods=[], ivars=[])
        chain = superclass_chain(c, 0, ClassList([cls]))
        assert (chain.names, chain.end) == (("PBCodable",), "import")


class TestChainedFixupImports:
    """The imports table of LC_DYLD_CHAINED_FIXUPS, each format by its own layout
    (fixup-chains.h), the symbol pool as it is or zlib-compressed."""
    NAMES = [b"_first", b"_OBJC_CLASS_$_PBCodable", b"_objc_msgSend"]

    def _imports(self, imp_fmt, sym_fmt=0):
        import zlib
        pool = b"".join(n + b"\x00" for n in self.NAMES)
        offs = [pool.index(n + b"\x00") for n in self.NAMES]
        if imp_fmt == 3:        # u64 lib_ordinal:16 weak:1 reserved:15 name_offset:32, u64 addend
            entries = b"".join(struct.pack('<QQ', (o << 32) | 1, 0) for o in offs)
        else:                   # u32 lib_ordinal:8 weak:1 name_offset:23 (+ int32 addend)
            entries = b"".join(struct.pack('<I', (o << 9) | 1) + (b"\x00" * 4 if imp_fmt == 2 else b"")
                               for o in offs)
        if sym_fmt == 1:
            pool = zlib.compress(pool)
        blob = struct.pack('<IIIIIII', 0, 0xFFFF, 28, 28 + len(entries), len(offs), imp_fmt,
                           sym_fmt) + entries + pool
        c = BinaryContext.__new__(BinaryContext)
        c._data = struct.pack('<IIII', 0x80000034, 16, 16, len(blob)) + blob
        c._parse_chained_fixups_lc(0)
        return c._imports

    def test_every_format(self):
        want = [n.decode() for n in self.NAMES]
        for imp_fmt in (1, 2, 3):
            assert self._imports(imp_fmt) == want, imp_fmt

    def test_a_compressed_symbol_pool(self):
        assert self._imports(3, sym_fmt=1) == [n.decode() for n in self.NAMES]


def _uleb(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F; n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def _export_trie_bytes():
    """A 3-node export trie exporting '_A' (terminal) and '_AB' (terminal)."""
    # node2 (terminal '_AB'): term_size=2 [flags=0, addr=0x10], 0 children
    node2 = b"\x02" + b"\x00" + b"\x10" + b"\x00"
    # node1 (terminal '_A'): term_size=2 [flags=0, addr=0x20], 1 child 'B'->node2
    # layout offsets: root=0 (6 bytes), node1=6 (7 bytes), node2=13
    node1 = b"\x02" + b"\x00" + b"\x20" + b"\x01" + b"B\x00" + _uleb(13)
    root = b"\x00" + b"\x01" + b"_A\x00" + _uleb(6)
    blob = root + node1 + node2
    assert len(root) == 6 and len(node1) == 7, (len(root), len(node1))
    return blob


def _bare_ctx(data, symtab=None, export_trie=None, image_base=0):
    c = BinaryContext.__new__(BinaryContext)
    c._data = data
    c._symtab = symtab
    c._export_trie = export_trie
    c._image_base = image_base
    return c


class TestIterSymbolNames:
    # real linkedit offsets are always > 0; place tables after a pad so the
    # parser's `stroff > 0` / `base > 0` guards are satisfied (and exercised).
    PAD = b"\x00\x00\x00\x00"

    def _build(self):
        strtab = b"\x00_sym1\x00_sym2\x00"          # n_strx 0 (empty), 1, 7
        # 3 nlist entries: n_strx=1, 7, and 0 (the 0 entry is skipped)
        nlist = b"".join(struct.pack("<I", x) + b"\x00" * 12 for x in (1, 7, 0))
        trie = _export_trie_bytes()
        data = self.PAD + strtab + nlist + trie
        stroff = len(self.PAD)
        symoff = stroff + len(strtab)
        trie_off = symoff + len(nlist)
        return _bare_ctx(data,
                         symtab=(symoff, 3, stroff, len(strtab)),
                         export_trie=(trie_off, len(trie)))

    def test_nlist_plus_export_trie(self):
        names = list(self._build().iter_symbol_names())
        # nlist names (n_strx=0 entry skipped) then export-trie names
        assert names == ["_sym1", "_sym2", "_A", "_AB"]

    def test_no_data_yields_nothing(self):
        assert list(_bare_ctx(b"", symtab=(4, 1, 4, 1)).iter_symbol_names()) == []

    def test_symtab_none_only_trie(self):
        trie = _export_trie_bytes()
        c = _bare_ctx(self.PAD + trie, symtab=None,
                      export_trie=(len(self.PAD), len(trie)))
        assert list(c.iter_symbol_names()) == ["_A", "_AB"]

    def test_export_trie_none_only_nlist(self):
        strtab = b"\x00sym\x00"
        nlist = struct.pack("<I", 1) + b"\x00" * 12
        data = self.PAD + strtab + nlist
        c = _bare_ctx(data, symtab=(len(self.PAD) + len(strtab), 1,
                                    len(self.PAD), len(strtab)),
                      export_trie=None)
        assert list(c.iter_symbol_names()) == ["sym"]

    def test_out_of_range_offsets_are_safe(self):
        # symoff past EOF and export-trie base past EOF -> no crash, no names (a string
        # table in range, so the symoff bound is what stops the nlist read)
        c = _bare_ctx(b"\x00abc", symtab=(999, 5, 1, 3), export_trie=(999, 10))
        assert list(c.iter_symbol_names()) == []

    def test_nlist_out_of_range_symoff_is_safe_in_isolation(self):
        # The fixture above uses stroff=0, which independently short-circuits the
        # nlist branch via `stroff > 0` -- regardless of whether the out-of-range
        # `symoff` clamp (and its `nsyms = min(nsyms, (n - symoff) // 16)` sibling)
        # does anything at all. Disable the export trie and use a REAL, in-range
        # stroff so the only thing standing between `symoff=999` and a
        # `struct.unpack_from` buffer-overrun is the nlist clamp itself.
        strtab = b"\x00sym\x00"
        data = self.PAD + strtab
        c = _bare_ctx(data, symtab=(999, 5, len(self.PAD), len(strtab)),
                     export_trie=None)
        assert list(c.iter_symbol_names()) == []

    def test_export_trie_out_of_range_base_is_safe_in_isolation(self):
        # Isolate the export-trie entry clamp from the nlist side entirely (no
        # symtab at all). NOTE: `base=999` (as in the fixture above) can't
        # discriminate the `base >= len(data)` HALF of this guard on its own --
        # the DFS loop's very first iteration re-checks `node >= end` on that same
        # starting node (node initially equals base) and that inner check is
        # mathematically guaranteed to agree whenever base >= len(data), so it's
        # provably redundant with the entry check for that half, not just
        # untested. The `base <= 0` half is NOT redundant, though: `base=0` slips
        # past both the leading `if not self._export_trie` (a (0, size) tuple is
        # still truthy) and the inner `node >= end` check (0 < end), so only this
        # clamp's `base <= 0` arm stops the walk from starting at file offset 0
        # and yielding a bogus empty-string symbol.
        c = _bare_ctx(b"abcd", symtab=None, export_trie=(0, 10))
        assert list(c.iter_symbol_names()) == []


class TestIterSymbols:
    """``(name, address)``: an nlist symbol's value when it is defined in a section, the export
    trie's image offset from the image base; a debug stab (no section, its value an mtime) or
    an undefined symbol has none."""
    PAD = b"\x00\x00\x00\x00"

    def test_addresses(self):
        strtab = b"\x00_def\x00/path/obj.o\x00_undef\x00"
        entries = ((1, 1, 0x1000), (6, 0, 0x6a608d3b), (18, 0, 0))   # (n_strx, n_sect, n_value)
        nlist = b"".join(struct.pack("<IBBHQ", x, 0, s, 0, v) for x, s, v in entries)
        trie = _export_trie_bytes()
        data = self.PAD + strtab + nlist + trie
        stroff, symoff = len(self.PAD), len(self.PAD) + len(strtab)
        ctx = _bare_ctx(data, symtab=(symoff, 3, stroff, len(strtab)),
                        export_trie=(symoff + len(nlist), len(trie)), image_base=0x100000000)
        assert list(ctx.iter_symbols()) == [
            ("_def", 0x1000), ("/path/obj.o", None), ("_undef", None),
            ("_A", 0x100000020), ("_AB", 0x100000010)]


class TestReadUleb:

    def test_multi_byte(self):
        from macho.leb import read_uleb
        assert read_uleb(b"\x80\x01\x05", 0) == (128, 2)
        assert read_uleb(b"\x80\x01\x05", 2) == (5, 3)

    def test_an_encoding_open_at_the_end_is_an_error(self):
        # Its bits so far are no value (#141): a truncated table read them as one.
        from macho.leb import read_uleb
        with pytest.raises(ValueError):
            read_uleb(b"\xff\xff", 0)
        with pytest.raises(ValueError):
            read_uleb(b"\x81\x01\x05", 0, end=1)
        assert read_uleb(b"\x81\x01\x05", 0, end=2) == (0x81, 2)

    def test_wider_than_64_bits_is_an_error(self):
        from macho.leb import read_uleb
        assert read_uleb(b"\xff" * 9 + b"\x01", 0) == ((1 << 64) - 1, 10)
        with pytest.raises(ValueError):
            read_uleb(b"\xff" * 10 + b"\x01", 0)


class TestExportTrieDamage:
    """A damaged trie names only symbols it states in full (#141): a terminal is read inside
    the size it declares, inside the data."""

    def test_an_offset_outside_its_terminal_names_nothing(self):
        from macho.export_trie import iter_export_trie
        # root: term_size=1 [flags=0], the offset would be the child count byte; 0 children
        assert list(iter_export_trie(b"\x01\x00\x05\x00")) == []
        assert list(iter_export_trie(b"\x02\x00\x05\x00")) == [("", 0, 5)]

    def test_a_terminal_past_the_end_names_nothing(self):
        from macho.export_trie import iter_export_trie
        good = _export_trie_bytes()
        assert list(iter_export_trie(good)) == [("_A", 0, 0x20), ("_AB", 0, 0x10)]
        # _AB's terminal cut short: its offset ULEB left open, then its flags missing
        cut = good[:15] + b"\x90"
        assert list(iter_export_trie(cut)) == [("_A", 0, 0x20)]
        assert list(iter_export_trie(good[:14])) == [("_A", 0, 0x20)]

    def test_an_open_edge_ends_its_node_s_children(self):
        from macho.export_trie import iter_export_trie
        # root: 2 children, '_A' -> node at 0x80 | 0x80.. (open at the end)
        assert list(iter_export_trie(b"\x00\x02_A\x00\x80")) == []


class TestFunctionStarts:

    def test_deltas_from_text_until_a_zero(self):
        from macho.memory import decode_function_starts
        assert decode_function_starts(_uleb(0x10) + _uleb(0x208) + b"\x00" + _uleb(4), 0x1000) \
            == [0x1010, 0x1218]

    def test_a_delta_open_at_the_end_is_unread_input(self):
        from macho.memory import decode_function_starts, unread_input
        from types import SimpleNamespace as NS
        with pytest.raises(ValueError):
            decode_function_starts(_uleb(0x10) + b"\x88", 0x1000)
        blob = b"\x00" * 8 + _uleb(0x10) + b"\x88"
        c = _bare_ctx(blob)
        c._segments = [NS(name="__TEXT", vmaddr=0x1000)]
        c._cache_reader = None
        c._function_starts_lc, c._function_starts = (8, len(blob) - 8), None
        assert c.function_starts() == []
        assert [e[:2] for e in unread_input(c)] == [("function starts", "0x8")]

    def test_without_the_command_there_are_none(self):
        from types import SimpleNamespace as NS
        c = _bare_ctx(_uleb(0x10) + _uleb(0x20) + b"\x00" + b"\x01" * 16)
        c._segments, c._cache_reader = [NS(name="__TEXT", vmaddr=0x1000)], None
        c._function_starts_lc = c._function_starts = None
        assert c.function_starts() == []



class TestDecodeChainPtrUnknownFormat:
    """_decode_chain_ptr's unknown-format-passthrough branch: no test (live or
    synthetic) previously called it with an fmt outside the three recognised
    chained-fixup pointer formats. It is a pure function, so this is cheap
    direct coverage of what "correctness depends on this branch never actually
    firing" (per its scope_note) actually does when it does fire."""

    def test_unrecognized_format_returns_raw_unchanged(self):
        from macho.memory import _decode_chain_ptr
        raw = 0x1234_5678_9ABC_DEF0
        # fmt=99 is not ARM64E(1)/64(2)/64_OFFSET(6) -> verbatim passthrough.
        assert _decode_chain_ptr(raw, 99, image_base=0x100000000) == raw

    def test_recognized_formats_do_not_passthrough_unchanged(self):
        # Sanity check the contrast: a recognized format (plain arm64e rebase,
        # bind bit clear) DOES transform the raw value (strips PAC high bits),
        # so the unknown-format branch's "verbatim" behavior is a real,
        # distinguishable code path and not just the general-case fallthrough.
        from macho.memory import _decode_chain_ptr
        raw = (0x1234_5678_9ABC_DEF0) & 0x0000_007F_FFFF_FFFF | (0x7F << 40)
        decoded = _decode_chain_ptr(raw, 1, image_base=0x100000000)
        assert decoded != raw


class TestImageBaseIsTheHeaderSegment:
    """The image's base is the segment holding its header: a dylib's __TEXT at vmaddr 0 (it
    was skipped for the next segment), an executable's after __PAGEZERO (#133)."""

    def _ctx(self, segs):
        from types import SimpleNamespace as NS
        c = BinaryContext.__new__(BinaryContext)
        c._segments = [NS(name=n, vmaddr=v, fileoff=o, filesize=f) for n, v, o, f in segs]
        return c

    def test_a_dylib(self):
        c = self._ctx([('__TEXT', 0, 0, 0x4000), ('__DATA', 0x4000, 0x4000, 0x1000)])
        assert c._local_image_base() == 0

    def test_an_executable(self):
        c = self._ctx([('__PAGEZERO', 0, 0, 0), ('__TEXT', 0x100000000, 0, 0x4000)])
        assert c._local_image_base() == 0x100000000
