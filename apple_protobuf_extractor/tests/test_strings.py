"""tests/test_strings.py — tests for macho/strings.py."""

from __future__ import annotations

import pytest

from macho.memory import BinaryContext
from macho.strings import build_string_table
from tests.conftest import _pack_header, _pack_segment64, _pack_section64


def _build_cstring_binary(strings: list, sectname: str = '__cstring',
                           segname: str = '__TEXT') -> BinaryContext:
    """Build a minimal Mach-O with a cstring section containing the given strings."""
    payload = b''
    for s in strings:
        payload += s.encode('utf-8') + b'\x00'

    HDR      = 32
    LC_SIZE  = 72 + 80
    DATA_OFF = HDR + LC_SIZE
    VMADDR   = 0x1000

    sect = _pack_section64(sectname, segname,
                           vmaddr=VMADDR, vmsize=len(payload),
                           fileoff=DATA_OFF)
    seg  = _pack_segment64(segname,
                           vmaddr=VMADDR, vmsize=len(payload),
                           fileoff=DATA_OFF, filesize=len(payload),
                           sections=[sect])
    hdr  = _pack_header(ncmds=1, sizeofcmds=len(seg))
    data = hdr + seg + payload
    return BinaryContext(data)


class TestStringTableBasic:
    def test_get_existing(self):
        ctx = _build_cstring_binary(['hello', 'world'])
        tbl = build_string_table(ctx)
        # vmaddr 0x1000 → 'hello', 0x1006 → 'world'
        assert tbl.get(0x1000) == 'hello'
        assert tbl.get(0x1006) == 'world'

    def test_get_missing_returns_none(self):
        ctx = _build_cstring_binary(['hello'])
        tbl = build_string_table(ctx)
        assert tbl.get(0xDEAD) is None

    def test_getitem_existing(self):
        ctx = _build_cstring_binary(['abc'])
        tbl = build_string_table(ctx)
        assert tbl[0x1000] == 'abc'

    def test_getitem_missing_raises(self):
        ctx = _build_cstring_binary(['abc'])
        tbl = build_string_table(ctx)
        with pytest.raises(KeyError):
            _ = tbl[0x9999]

    def test_find_single_occurrence(self):
        ctx = _build_cstring_binary(['alpha', 'beta', 'gamma'])
        tbl = build_string_table(ctx)
        results = tbl.find('beta')
        assert len(results) == 1
        assert tbl.get(results[0]) == 'beta'

    def test_find_missing_returns_empty(self):
        ctx = _build_cstring_binary(['alpha'])
        tbl = build_string_table(ctx)
        assert tbl.find('zzz') == []

    def test_len(self):
        ctx = _build_cstring_binary(['a', 'bb', 'ccc'])
        tbl = build_string_table(ctx)
        assert len(tbl) == 3

    def test_iter(self):
        ctx = _build_cstring_binary(['x', 'y'])
        tbl = build_string_table(ctx)
        values = {e.value for e in tbl}
        assert 'x' in values and 'y' in values

    def test_section_names(self):
        ctx = _build_cstring_binary(['hello'])
        tbl = build_string_table(ctx)
        assert '__cstring' in tbl.section_names()

    def test_all_in_section(self):
        ctx = _build_cstring_binary(['one', 'two', 'three'])
        tbl = build_string_table(ctx)
        entries = tbl.all_in_section('__cstring')
        values  = {e.value for e in entries}
        assert values == {'one', 'two', 'three'}

    def test_all_in_section_wrong_name(self):
        ctx = _build_cstring_binary(['hello'])
        tbl = build_string_table(ctx)
        assert tbl.all_in_section('__nosection') == []


class TestStringTableMultipleSections:
    def _build_two_section_binary(self) -> BinaryContext:
        """Binary with both __cstring and __objc_classname (note: 16 chars, no trailing s)."""
        cstr     = b'hello\x00world\x00'
        clsnames = b'NSObject\x00MyClass\x00'
        HDR      = 32
        VA1      = 0x1000
        VA2      = VA1 + len(cstr)

        # '__objc_classname' = 16 chars (fits in Mach-O sectname field without truncation)
        LC_SZ    = 72 + 2 * 80   # one segment, two sections
        DATA_OFF = HDR + LC_SZ

        s1 = _pack_section64('__cstring',        '__TEXT', VA1, len(cstr),     DATA_OFF)
        s2 = _pack_section64('__objc_classname', '__TEXT', VA2, len(clsnames), DATA_OFF + len(cstr))
        seg = _pack_segment64('__TEXT',
                              vmaddr=VA1, vmsize=len(cstr) + len(clsnames),
                              fileoff=DATA_OFF, filesize=len(cstr) + len(clsnames),
                              sections=[s1, s2])
        hdr  = _pack_header(ncmds=1, sizeofcmds=len(seg))
        data = hdr + seg + cstr + clsnames
        return BinaryContext(data)

    def test_entries_from_both_sections(self):
        ctx = self._build_two_section_binary()
        tbl = build_string_table(ctx)
        assert tbl.find('hello') != []
        assert tbl.find('NSObject') != []

    def test_section_segregation(self):
        ctx = self._build_two_section_binary()
        tbl = build_string_table(ctx)
        cstr_vals  = {e.value for e in tbl.all_in_section('__cstring')}
        cls_vals   = {e.value for e in tbl.all_in_section('__objc_classname')}
        assert 'hello' in cstr_vals  and 'NSObject' not in cstr_vals
        assert 'NSObject' in cls_vals and 'hello' not in cls_vals

    def test_section_names_both_present(self):
        ctx = self._build_two_section_binary()
        tbl = build_string_table(ctx)
        names = tbl.section_names()
        assert '__cstring' in names
        assert '__objc_classname' in names   # 16-char form in Mach-O field


class TestStringTableEmpty:
    def test_empty_binary(self):
        from tests.conftest import build_text_binary
        from macho.memory import BinaryContext
        import struct as st
        ctx = BinaryContext(build_text_binary(st.pack('<I', 0xD65F03C0)))
        tbl = build_string_table(ctx)
        assert len(tbl) == 0
        assert tbl.section_names() == []


# ─── __objc_selrefs NOT scanned ───────────────────────────────────────────────

class TestSelrefsNotScanned:
    def _selrefs_binary(self) -> BinaryContext:
        """Binary whose only string-like section is __objc_selrefs (pointer array)."""
        import struct as st
        # Pack two 8-byte 'pointer' values — NOT null-terminated strings.
        selrefs = st.pack('<QQ', 0x0000000100012345, 0x0000000100067890)
        HDR     = 32
        LC_SZ   = 72 + 80
        DATA_OFF = HDR + LC_SZ
        VA      = 0x1000
        s = _pack_section64('__objc_selrefs', '__DATA', VA, len(selrefs), DATA_OFF)
        seg = _pack_segment64('__DATA', vmaddr=VA, vmsize=len(selrefs),
                               fileoff=DATA_OFF, filesize=len(selrefs),
                               sections=[s])
        hdr = _pack_header(ncmds=1, sizeofcmds=len(seg))
        return BinaryContext(hdr + seg + selrefs)

    def test_selrefs_produces_no_entries(self):
        """Pointer bytes in __objc_selrefs must not appear as string entries."""
        ctx = self._selrefs_binary()
        tbl = build_string_table(ctx)
        assert len(tbl) == 0

    def test_selrefs_section_not_in_table(self):
        ctx = self._selrefs_binary()
        tbl = build_string_table(ctx)
        assert '__objc_selrefs' not in tbl.section_names()


# ─── Section size guard ───────────────────────────────────────────────────────

class TestSectionSizeGuard:
    def test_oversized_section_skipped(self):
        """A section claiming vmsize > _MAX_SECTION_SIZE must be silently skipped."""
        from macho.strings import _MAX_SECTION_SIZE

        # Build a section header claiming an enormous vmsize but only 6 bytes data
        small_payload = b'hello\x00'
        HDR     = 32
        LC_SZ   = 72 + 80
        DATA_OFF = HDR + LC_SZ
        VA      = 0x1000

        s = _pack_section64('__cstring', '__TEXT', VA,
                             _MAX_SECTION_SIZE + 1,   # lie about vmsize
                             DATA_OFF)
        seg = _pack_segment64('__TEXT', vmaddr=VA,
                               vmsize=len(small_payload),  # real segment size
                               fileoff=DATA_OFF,
                               filesize=len(small_payload),
                               sections=[s])
        hdr = _pack_header(ncmds=1, sizeofcmds=len(seg))
        ctx = BinaryContext(hdr + seg + small_payload)
        tbl = build_string_table(ctx)
        # The section claims huge size → must be skipped
        assert tbl.find('hello') == []


# ─── Section name correctness ─────────────────────────────────────────────────

class TestSectionNaming:
    """Regression tests for the __objc_methname section name spelling.

    The Mach-O section name field is 16 bytes.  '__objc_methname' (15 chars + null)
    is the actual name used by Apple's toolchain.  '__objc_methnames' (16 chars,
    no null) is NOT what the binary stores, so using it as a lookup key would
    always miss, silently leaving selectors out of the string table.
    """

    def test_methname_section_is_scanned(self):
        """build_string_table must pick up strings in __TEXT/__objc_methname."""
        ctx = _build_cstring_binary(['readFrom:', 'writeTo:', 'mergeFrom:'],
                                    sectname='__objc_methname')
        tbl = build_string_table(ctx)
        assert tbl.find('readFrom:') != [], \
            "__objc_methname strings not in table — check _SCAN_SECTIONS spelling"

    def test_methnames_16char_would_miss(self):
        """The 16-char spelling '__objc_methnames' would produce a cache miss."""
        ctx = _build_cstring_binary(['readFrom:', 'writeTo:'],
                                    sectname='__objc_methname')
        # Confirm the section is stored WITHOUT a trailing 's'
        assert ctx.has_section('__TEXT', '__objc_methname'), \
            "Binary should have __objc_methname section"
        assert not ctx.has_section('__TEXT', '__objc_methnames'), \
            "__objc_methnames (with 's') should NOT exist — would silently miss strings"

    def test_scan_sections_spelling(self):
        """The _SCAN_SECTIONS constant must use the 15-char spelling."""
        from macho.strings import _SCAN_SECTIONS
        section_names = [sec for _, sec in _SCAN_SECTIONS]
        assert '__objc_methname' in section_names, \
            "'__objc_methname' missing from _SCAN_SECTIONS"
        assert '__objc_methnames' not in section_names, \
            "Typo '__objc_methnames' found in _SCAN_SECTIONS — remove the trailing 's'"

    def test_classname_section_still_scanned(self):
        """Fixing methname must not break __objc_classname scanning."""
        ctx = _build_cstring_binary(['GEORoute', 'GEOPlaceRequest'],
                                    sectname='__objc_classname')
        tbl = build_string_table(ctx)
        assert tbl.find('GEORoute') != []
