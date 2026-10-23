"""tests/test_classlist.py — tests for macho/classlist.py."""

from __future__ import annotations

import struct

from macho.memory import BinaryContext
from macho.strings import StringTable, build_string_table
from macho.classlist import ObjcClass, ObjcMethod, ClassList, build_class_list, _parse_class
from tests.conftest import _pack_header, _pack_segment64, _pack_section64, ptr64, build_text_binary


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _null_strings() -> StringTable:
    return StringTable()


def _strings_from(*name_pairs) -> StringTable:
    """Build a StringTable from (vmaddr, value) pairs."""
    st = StringTable()
    from macho.strings import StringEntry
    for va, val in name_pairs:
        st._add(StringEntry(vmaddr=va, section='__objc_classnames', value=val))
    return st


# ── Synthetic class_t builder ─────────────────────────────────────────────────

BASE_VA = 0x10000   # vmaddr of our data section

def _encode_class(
    class_va: int,
    ro_va: int,
    superclass_va: int = 0,
) -> bytes:
    """Pack a class_t struct (40 bytes): isa, super, cache, vtable, data."""
    return struct.pack('<QQQQQ',
        0,               # isa (don't care for tests)
        superclass_va,   # superclass
        0,               # cache
        0,               # vtable
        ro_va,           # data → class_ro_t*
    )


def _encode_ro(
    name_va: int,
    flags: int = 0,
    inst_size: int = 8,
    methods_va: int = 0,
    ivars_va: int = 0,
) -> bytes:
    """Pack a class_ro_t struct (72 bytes)."""
    return struct.pack('<IIIIQQQQQQQi',
        flags,
        0,            # instanceStart
        inst_size,
        0,            # reserved
        0,            # ivarLayout
        name_va,
        methods_va,
        0,            # baseProtocols
        ivars_va,
        0,            # weakIvarLayout
        0,            # baseProperties
        0,            # padding to 72 bytes
    )


def _build_single_class_binary(class_name: str) -> tuple:
    """
    Build a minimal Mach-O with one ObjC class in __DATA_CONST/__objc_classlist.
    Returns (ctx, classlist_vmaddr).
    """
    # Layout (all relative to DATA_VA):
    #   [0]    class name cstring (len+1 bytes, padded to 8)
    #   [8]    class_ro_t (72 bytes)
    #   [80]   class_t (40 bytes)
    #   [120]  classlist (8 bytes, one pointer)

    HDR      = 32
    name_b   = class_name.encode() + b'\x00'
    name_pad = name_b.ljust((len(name_b) + 7) & ~7, b'\x00')

    DATA_VA  = 0x1000
    name_va  = DATA_VA
    ro_va    = DATA_VA + len(name_pad)
    class_va = ro_va + 72
    list_va  = class_va + 40

    # Classnames section in __TEXT
    classnames_data = name_pad

    # __objc_classlist section (one pointer)
    classlist_data  = ptr64(class_va)

    # Inline data: ro + class (no methods/ivars)
    inline = (
        _encode_ro(name_va=name_va)[:72] +   # class_ro_t
        _encode_class(class_va, ro_va)        # class_t
    )

    # We need all this in one contiguous section so vmaddrs work.
    # Use __DATA as the segment for everything except classnames.
    # Two segments: __TEXT (classnames), __DATA_CONST (classlist + class data)

    all_data = classnames_data + inline + classlist_data

    # Work out file positions
    # Segment 1 (__TEXT): classnames only
    seg1_vmaddr   = DATA_VA
    seg1_vmsize   = len(classnames_data)
    # Segment 2 (__DATA_CONST): ro + class_t + classlist
    seg2_vmaddr   = DATA_VA + len(classnames_data)
    seg2_vmsize   = len(inline) + len(classlist_data)

    # Build sections
    # LC = 32 (hdr) + (72+80)*2 (two segment commands)
    LC_SZ    = 2 * (72 + 80)
    DATA_OFF = HDR + LC_SZ

    s1 = _pack_section64('__objc_classnames',  '__TEXT',
                         seg1_vmaddr, seg1_vmsize, DATA_OFF)
    sg1 = _pack_segment64('__TEXT',
                          vmaddr=seg1_vmaddr, vmsize=seg1_vmsize,
                          fileoff=DATA_OFF, filesize=seg1_vmsize,
                          sections=[s1])

    s2 = _pack_section64('__objc_classlist', '__DATA_CONST',
                         seg2_vmaddr, seg2_vmsize,
                         DATA_OFF + seg1_vmsize)
    sg2 = _pack_segment64('__DATA_CONST',
                          vmaddr=seg2_vmaddr, vmsize=seg2_vmsize,
                          fileoff=DATA_OFF + seg1_vmsize,
                          filesize=seg2_vmsize,
                          sections=[s2])

    hdr  = _pack_header(ncmds=2, sizeofcmds=len(sg1) + len(sg2))
    binary = hdr + sg1 + sg2 + all_data
    ctx = BinaryContext(binary)
    return ctx, list_va


# ─── ClassList collection tests ───────────────────────────────────────────────

class TestClassListEmpty:
    def test_empty_classlist(self):
        # Binary with no objc_classlist section
        from tests.conftest import build_text_binary
        import struct as st
        ctx = BinaryContext(build_text_binary(st.pack('<I', 0xD65F03C0)))
        cl = build_class_list(ctx, StringTable())
        assert len(cl) == 0

    def test_find_on_empty(self):
        ctx = BinaryContext(build_text_binary(struct.pack('<I', 0xD65F03C0)))
        cl  = build_class_list(ctx, StringTable())
        assert cl.find('NSObject') is None


class TestClassListSingleClass:
    def test_class_found_by_name(self):
        ctx, _ = _build_single_class_binary('MyClass')
        strings = build_string_table(ctx)
        cl      = build_class_list(ctx, strings)
        assert cl.find('MyClass') is not None

    def test_class_name_correct(self):
        ctx, _ = _build_single_class_binary('FooMessage')
        strings = build_string_table(ctx)
        cl      = build_class_list(ctx, strings)
        cls     = cl.find('FooMessage')
        assert cls is not None
        assert cls.name == 'FooMessage'

    def test_class_not_meta(self):
        ctx, _ = _build_single_class_binary('BarClass')
        strings = build_string_table(ctx)
        cl      = build_class_list(ctx, strings)
        cls     = cl.find('BarClass')
        assert not cls.is_meta

    def test_len(self):
        ctx, _ = _build_single_class_binary('OnlyClass')
        strings = build_string_table(ctx)
        cl      = build_class_list(ctx, strings)
        assert len(cl) == 1

    def test_contains(self):
        ctx, _ = _build_single_class_binary('ContainsMe')
        strings = build_string_table(ctx)
        cl      = build_class_list(ctx, strings)
        assert 'ContainsMe' in cl
        assert 'Missing'    not in cl


# ─── find_subclasses ──────────────────────────────────────────────────────────

class TestFindSubclasses:
    def _make_hierarchy(self) -> ClassList:
        """
        Simple hierarchy: Root → Child1, Root → Child2 → GrandChild
        All classes constructed directly as ObjcClass objects.
        """
        root  = ObjcClass(vmaddr=1, name='Root',       is_meta=False,
                          superclass_vmaddr=0, superclass_name=None,
                          ro_flags=0, instance_size=8)
        c1    = ObjcClass(vmaddr=2, name='Child1',     is_meta=False,
                          superclass_vmaddr=1, superclass_name='Root',
                          ro_flags=0, instance_size=8)
        c2    = ObjcClass(vmaddr=3, name='Child2',     is_meta=False,
                          superclass_vmaddr=1, superclass_name='Root',
                          ro_flags=0, instance_size=8)
        gc    = ObjcClass(vmaddr=4, name='GrandChild', is_meta=False,
                          superclass_vmaddr=3, superclass_name='Child2',
                          ro_flags=0, instance_size=8)
        return ClassList([root, c1, c2, gc])

    def test_direct_children(self):
        cl = self._make_hierarchy()
        subs = {c.name for c in cl.find_subclasses('Root', transitive=False)}
        assert subs == {'Child1', 'Child2'}

    def test_transitive_all_descendants(self):
        cl = self._make_hierarchy()
        subs = {c.name for c in cl.find_subclasses('Root', transitive=True)}
        assert subs == {'Child1', 'Child2', 'GrandChild'}

    def test_no_subclasses(self):
        cl = self._make_hierarchy()
        assert cl.find_subclasses('Child1') == []

    def test_unknown_class(self):
        cl = self._make_hierarchy()
        assert cl.find_subclasses('DoesNotExist') == []

    def test_gpb_pattern(self):
        """GPBMessage → [MsgA, MsgB] → [MsgA_Sub]."""
        gpb  = ObjcClass(vmaddr=1, name='GPBMessage',  is_meta=False,
                         superclass_vmaddr=0, superclass_name=None,
                         ro_flags=0, instance_size=8)
        msgA = ObjcClass(vmaddr=2, name='MsgA',        is_meta=False,
                         superclass_vmaddr=1, superclass_name='GPBMessage',
                         ro_flags=0, instance_size=16)
        msgB = ObjcClass(vmaddr=3, name='MsgB',        is_meta=False,
                         superclass_vmaddr=1, superclass_name='GPBMessage',
                         ro_flags=0, instance_size=16)
        sub  = ObjcClass(vmaddr=4, name='MsgA_Sub',    is_meta=False,
                         superclass_vmaddr=2, superclass_name='MsgA',
                         ro_flags=0, instance_size=24)
        cl = ClassList([gpb, msgA, msgB, sub])
        subs = {c.name for c in cl.find_subclasses('GPBMessage')}
        assert subs == {'MsgA', 'MsgB', 'MsgA_Sub'}


# ─── ObjcClass method helpers ─────────────────────────────────────────────────

class TestObjcClassHelpers:
    def _cls_with_methods(self, sels: list) -> ObjcClass:
        methods = [ObjcMethod(name=s, types='', imp=0x1000 + i * 4)
                   for i, s in enumerate(sels)]
        return ObjcClass(vmaddr=1, name='Foo', is_meta=False,
                         superclass_vmaddr=0, superclass_name=None,
                         ro_flags=0, instance_size=8, methods=methods)

    def test_has_method_true(self):
        cls = self._cls_with_methods(['+initialize', '-dealloc'])
        assert cls.has_method('+initialize')

    def test_has_method_false(self):
        cls = self._cls_with_methods(['+initialize'])
        assert not cls.has_method('-dealloc')

    def test_get_method_found(self):
        cls = self._cls_with_methods(['+initialize', '-foo'])
        m   = cls.get_method('+initialize')
        assert m is not None
        assert m.name == '+initialize'

    def test_get_method_not_found(self):
        cls = self._cls_with_methods(['+initialize'])
        assert cls.get_method('-bar') is None


# ─── by_vmaddr ───────────────────────────────────────────────────────────────

class TestByVmaddr:
    def test_by_vmaddr_found(self):
        ctx, _ = _build_single_class_binary('FindMe')
        strings = build_string_table(ctx)
        cl  = build_class_list(ctx, strings)
        cls = cl.find('FindMe')
        assert cls is not None
        assert cl.by_vmaddr(cls.vmaddr) is cls

    def test_by_vmaddr_not_found(self):
        ctx, _ = _build_single_class_binary('FindMe')
        strings = build_string_table(ctx)
        cl  = build_class_list(ctx, strings)
        assert cl.by_vmaddr(0xDEADDEAD) is None


# ─── Meta class detection ────────────────────────────────────────────────────

class TestMetaClass:
    def test_meta_flag_set(self):
        """A class_ro_t with RO_META flag must produce is_meta=True."""
        from macho.classlist import RO_META

        # Build a class with flags=RO_META directly via ObjcClass
        meta = ObjcClass(vmaddr=1, name='FooMeta', is_meta=True,
                         superclass_vmaddr=0, superclass_name=None,
                         ro_flags=RO_META, instance_size=8)
        normal = ObjcClass(vmaddr=2, name='Foo', is_meta=False,
                           superclass_vmaddr=0, superclass_name=None,
                           ro_flags=0, instance_size=8)
        cl = ClassList([meta, normal])
        assert cl.find('FooMeta').is_meta is True
        assert cl.find('Foo').is_meta is False

    def test_find_subclasses_excludes_meta(self):
        """find_subclasses must return only instance classes.
        Metaclasses are no longer added to _children so they cannot
        appear in subclass queries even if they have the same superclass_name."""
        root  = ObjcClass(vmaddr=1, name='Root', is_meta=False,
                          superclass_vmaddr=0, superclass_name=None,
                          ro_flags=0, instance_size=8)
        child = ObjcClass(vmaddr=2, name='Child', is_meta=False,
                          superclass_vmaddr=1, superclass_name='Root',
                          ro_flags=0, instance_size=8)
        meta  = ObjcClass(vmaddr=3, name='ChildMeta', is_meta=True,
                          superclass_vmaddr=1, superclass_name='Root',
                          ro_flags=1, instance_size=8)
        cl = ClassList([root, child, meta])
        names = {c.name for c in cl.find_subclasses('Root')}
        assert 'Child' in names
        assert 'ChildMeta' not in names, \
            "metaclasses must not appear in find_subclasses results"


# ─── Duplicate class name handling ───────────────────────────────────────────

class TestDuplicateClassNames:
    """ClassList._by_name is a dict keyed by class name.  When two instance
    classes share a name the first one wins (it is already in _by_name and the
    second is not a metaclass so the precedence rule keeps the first).
    __len__ still counts all entries including the shadowed duplicate, and
    both are accessible via by_vmaddr."""

    def _dup_classlist(self):
        a = ObjcClass(vmaddr=1, name='Shared', is_meta=False,
                      superclass_vmaddr=0, superclass_name=None,
                      ro_flags=0, instance_size=8)
        b = ObjcClass(vmaddr=2, name='Shared', is_meta=False,
                      superclass_vmaddr=0, superclass_name=None,
                      ro_flags=0, instance_size=8)
        return ClassList([a, b]), a, b

    def test_find_returns_first_class_when_names_collide(self):
        cl, a, b = self._dup_classlist()
        # First write wins: the first class (vmaddr=1) is kept
        assert cl.find('Shared').vmaddr == a.vmaddr

    def test_len_counts_both_entries(self):
        cl, _, _ = self._dup_classlist()
        assert len(cl) == 2   # both are in _classes even if only one is in _by_name

    def test_by_vmaddr_finds_both(self):
        cl, a, b = self._dup_classlist()
        assert cl.by_vmaddr(a.vmaddr) is a
        assert cl.by_vmaddr(b.vmaddr) is b

    def test_iter_yields_both(self):
        cl, a, b = self._dup_classlist()
        all_names = [c.name for c in cl]
        assert all_names.count('Shared') == 2


# ─── isa-following: metaclasses added to ClassList ───────────────────────────

class TestMetaclassNamePrecedence:
    """
    Regression tests for the ClassList._by_name precedence fix.

    Root cause: In ObjC, a metaclass shares the same name string as its
    instance class (class_ro_t.name is the same for both).
    build_class_list appends metaclasses AFTER instance classes in
    raw_classes (via isa-following), so without a precedence rule the
    metaclass overwrites the instance class in _by_name.

    Symptom: cl.find('GEODirectionsRequestFeedback') returned the
    metaclass (is_meta=True, 1 method) instead of the instance class
    (is_meta=False, 50+ methods), causing:
      * test_not_metaclass        — assertFalse(target.is_meta) failed
      * test_method_count_reasonable — only 1 method
      * test_init_found_by_imp   — init IMP missing from metaclass methods
      * extract_proto_message     — _is_proto_class failed on metaclass →
                                    returned None

    Fix: when building _by_name, an existing instance-class entry is never
    overwritten by a metaclass; a metaclass entry IS overwritten by an
    instance class (in case the metaclass happened to appear first).
    """

    def _make_pair(self, name: str):
        """Return (instance_class, metaclass) with the same name."""
        inst = ObjcClass(vmaddr=0x1000, name=name, is_meta=False,
                         superclass_vmaddr=0, superclass_name=None,
                         ro_flags=0, instance_size=64)
        meta = ObjcClass(vmaddr=0x2000, name=name, is_meta=True,
                         superclass_vmaddr=0, superclass_name=None,
                         ro_flags=1, instance_size=8)
        return inst, meta

    def test_find_returns_instance_class_when_instance_added_first(self):
        """Instance class first → metaclass appended after must not overwrite."""
        inst, meta = self._make_pair('GEODirectionsRequestFeedback')
        cl = ClassList([inst, meta])   # real isa-following order
        found = cl.find('GEODirectionsRequestFeedback')
        assert found is inst, \
            "find() must return the instance class, not the metaclass"
        assert found.is_meta is False

    def test_find_returns_instance_class_when_metaclass_added_first(self):
        """Even if the metaclass happens to be first, instance class wins."""
        inst, meta = self._make_pair('GEOPDComponent')
        cl = ClassList([meta, inst])
        found = cl.find('GEOPDComponent')
        assert found is inst
        assert found.is_meta is False

    def test_by_vmaddr_finds_both_regardless_of_name(self):
        """by_vmaddr is always correct — both entries accessible by address."""
        inst, meta = self._make_pair('GEOPDPlace')
        cl = ClassList([inst, meta])
        assert cl.by_vmaddr(inst.vmaddr) is inst
        assert cl.by_vmaddr(meta.vmaddr) is meta

    def test_find_returns_nonnone_for_class_with_metaclass(self):
        """find() must be non-None and not a metaclass after isa-following."""
        from macho.classlist import build_class_list
        from macho.strings import build_string_table
        # _build_binary_with_metaclass default: meta_name == class_name
        ctx, class_va, meta_va = _build_binary_with_metaclass(
            'GEODirectionsRequestFeedback'
        )
        strings = build_string_table(ctx)
        cl = build_class_list(ctx, strings)
        found = cl.find('GEODirectionsRequestFeedback')
        assert found is not None, \
            "find() must return non-None after isa-following adds metaclass"
        assert found.is_meta is False, \
            "find() must return the instance class, not the metaclass"
        assert found.vmaddr == class_va, \
            f"expected vmaddr {class_va:#x}, got {found.vmaddr:#x}"

    def test_metaclass_still_accessible_by_vmaddr_after_fix(self):
        """by_vmaddr must still resolve the metaclass after the precedence fix."""
        from macho.classlist import build_class_list
        from macho.strings import build_string_table
        ctx, class_va, meta_va = _build_binary_with_metaclass('GEOPDFoo2')
        strings = build_string_table(ctx)
        cl = build_class_list(ctx, strings)
        meta = cl.by_vmaddr(meta_va)
        assert meta is not None
        assert meta.is_meta is True




def _build_binary_with_metaclass(
    class_name: str,
    meta_name: str = None,
    isa_self_loop: bool = False,
    isa_zero: bool = False,
) -> tuple:
    """
    Build a Mach-O where one class_t in __objc_classlist has its ``isa``
    pointing to a metaclass that lives in the same binary but is NOT listed
    in the classlist itself.  This mimics the real GeoServices layout where
    metaclasses live in __DATA_DIRTY.

    Layout (single __DATA_CONST segment):
        [DATA_VA +   0]  meta_ro_t  (72 bytes, RO_META flag)
        [DATA_VA +  72]  meta_t     (40 bytes)  <- metaclass, NOT in classlist
        [DATA_VA + 112]  class_ro_t (72 bytes)
        [DATA_VA + 184]  class_t    (40 bytes, isa = meta_t_va)
        [DATA_VA + 224]  classlist  (8 bytes)   -> class_t only

    Returns (ctx, class_t_va, meta_t_va).
    """
    from macho.classlist import RO_META

    if meta_name is None:
        meta_name = class_name

    TEXT_VA = 0x1_0000
    DATA_VA = 0x2_0000

    # Name cstrings
    meta_name_b  = meta_name.encode()  + b'\x00'
    class_name_b = class_name.encode() + b'\x00'
    names_b = meta_name_b + class_name_b
    if len(names_b) % 8:
        names_b += b'\x00' * (8 - len(names_b) % 8)

    meta_name_va  = TEXT_VA
    class_name_va = TEXT_VA + len(meta_name_b)

    meta_ro_va   = DATA_VA
    meta_t_va    = DATA_VA + 72
    class_ro_va  = DATA_VA + 112
    class_t_va   = DATA_VA + 184
    classlist_va = DATA_VA + 224

    # Metaclass ro_t: flags=RO_META, name=meta_name_va, rest zero
    # Layout: flags(u32) instStart(u32) instSize(u32) reserved(u32)
    #         ivarLayout(u64) name(u64) baseMethods(u64) baseProtocols(u64)
    #         ivars(u64) weakIvarLayout(u64) baseProperties(u64)
    meta_ro = struct.pack('<IIII', RO_META, 0, 0, 0)
    meta_ro += struct.pack('<QQQQQQQ', 0, meta_name_va, 0, 0, 0, 0, 0)
    assert len(meta_ro) == 72

    # Metaclass t: isa→self (canonical root-metaclass pattern)
    meta_t = struct.pack('<QQQQQ', meta_t_va, 0, 0, 0, meta_ro_va)
    assert len(meta_t) == 40

    # Regular class ro_t: flags=0, name=class_name_va
    class_ro = struct.pack('<IIII', 0, 0, 8, 0)
    class_ro += struct.pack('<QQQQQQQ', 0, class_name_va, 0, 0, 0, 0, 0)
    assert len(class_ro) == 72

    # Regular class t
    if isa_self_loop:
        isa_val = class_t_va
    elif isa_zero:
        isa_val = 0
    else:
        isa_val = meta_t_va
    class_t = struct.pack('<QQQQQ', isa_val, 0, 0, 0, class_ro_va)
    assert len(class_t) == 40

    classlist_data = struct.pack('<Q', class_t_va)
    data_block = meta_ro + meta_t + class_ro + class_t + classlist_data
    assert len(data_block) == 232

    # Pack binary
    HDR    = 32
    lc_sz  = 2 * 72 + 2 * 80      # two segment LCs + two section headers
    data_off = HDR + lc_sz

    s_text = _pack_section64('__objc_classnames', '__TEXT',
                              TEXT_VA, len(names_b), data_off)
    sg_text = _pack_segment64('__TEXT',
                               vmaddr=TEXT_VA, vmsize=len(names_b),
                               fileoff=data_off, filesize=len(names_b),
                               sections=[s_text])

    classlist_off = data_off + len(names_b) + (classlist_va - DATA_VA)
    s_data = _pack_section64('__objc_classlist', '__DATA_CONST',
                              classlist_va, 8, classlist_off)
    sg_data = _pack_segment64('__DATA_CONST',
                               vmaddr=DATA_VA, vmsize=len(data_block),
                               fileoff=data_off + len(names_b),
                               filesize=len(data_block),
                               sections=[s_data])

    hdr    = _pack_header(ncmds=2, sizeofcmds=len(sg_text) + len(sg_data))
    binary = hdr + sg_text + sg_data + names_b + data_block
    ctx = BinaryContext(binary)
    return ctx, class_t_va, meta_t_va


class TestIsaFollowing:
    """
    Regression tests for the build_class_list isa-following fix.

    Before the fix, metaclasses lived in __DATA_DIRTY at vmaddrs pointed to by
    class_t.isa but were never added to the ClassList.  _find_metaclass()
    therefore always returned None for shared-cache-extracted binaries, forcing
    downstream heuristics (Strategy 2 name-suffix matching) that could return
    the wrong element type for repeated fields when the suffix was generic
    (e.g. "Value" matching GEODefaultsDBValue instead of GEOPDComponentValue).

    After the fix, build_class_list follows each class_t.isa pointer and parses
    the metaclass into raw_classes, so cl.by_vmaddr() resolves it and
    _find_metaclass() returns the correct object.
    """

    def test_metaclass_present_in_classlist(self):
        """Metaclass reached via isa must appear in the ClassList."""
        ctx, _, meta_va = _build_binary_with_metaclass('GEOPDFoo')
        strings = build_string_table(ctx)
        cl = build_class_list(ctx, strings)
        assert cl.by_vmaddr(meta_va) is not None, \
            "metaclass must be findable by vmaddr after isa-following"

    def test_metaclass_is_meta_true(self):
        """The metaclass entry must have is_meta=True (from RO_META flag)."""
        ctx, _, meta_va = _build_binary_with_metaclass('GEOPDBar')
        strings = build_string_table(ctx)
        cl = build_class_list(ctx, strings)
        meta = cl.by_vmaddr(meta_va)
        assert meta is not None
        assert meta.is_meta is True, \
            "isa-followed entry must carry RO_META → is_meta=True"

    def test_regular_class_still_present(self):
        """The regular class must still be parsed and present."""
        ctx, class_va, _ = _build_binary_with_metaclass('GEOPDBaz')
        strings = build_string_table(ctx)
        cl = build_class_list(ctx, strings)
        cls = cl.by_vmaddr(class_va)
        assert cls is not None
        assert cls.is_meta is False
        assert cls.name == 'GEOPDBaz'

    def test_total_len_is_two(self):
        """One classlist entry + one isa-followed metaclass = len 2."""
        ctx, _, _ = _build_binary_with_metaclass('GEOPDQux')
        strings = build_string_table(ctx)
        cl = build_class_list(ctx, strings)
        assert len(cl) == 2, \
            f"expected class + metaclass = 2 entries, got {len(cl)}"

    def test_find_metaclass_returns_nonnone(self):
        """_find_metaclass must return non-None after the fix."""
        from proto.extractor import _find_metaclass as _fm
        ctx, class_va, meta_va = _build_binary_with_metaclass('GEOPDMsg')
        strings = build_string_table(ctx)
        cl = build_class_list(ctx, strings)
        regular_cls = cl.by_vmaddr(class_va)
        assert regular_cls is not None
        found = _fm(ctx, regular_cls, cl)
        assert found is not None, \
            "_find_metaclass must resolve after isa-following fix"
        assert found.vmaddr == meta_va
        assert found.is_meta is True

    def test_isa_self_loop_no_duplicate(self):
        """isa == class_va (root-class pattern) must not produce a duplicate."""
        ctx, class_va, _ = _build_binary_with_metaclass(
            'NSObject', isa_self_loop=True
        )
        strings = build_string_table(ctx)
        cl = build_class_list(ctx, strings)
        # The isa points back to class_va which is already in seen_vas, so it
        # is skipped.  Only one entry should exist.
        assert len(cl) == 1, \
            f"self-loop isa must not add a duplicate; got {len(cl)}"
        assert cl.by_vmaddr(class_va) is not None

    def test_isa_zero_no_crash_and_class_present(self):
        """isa == 0 must be silently skipped; the regular class is still parsed."""
        ctx, class_va, _ = _build_binary_with_metaclass('GEOPDZero', isa_zero=True)
        strings = build_string_table(ctx)
        cl = build_class_list(ctx, strings)
        assert len(cl) == 1
        assert cl.by_vmaddr(class_va) is not None

    def test_isa_unmapped_no_crash(self):
        """An isa read that raises ValueError must be silently skipped."""
        from macho.strings import build_string_table as bst

        ctx, class_va, _ = _build_binary_with_metaclass('GEOPDRemote')
        strings = bst(ctx)

        # Patch read_ptr so that reading class_t.isa raises ValueError
        original_read_ptr = ctx.read_ptr

        def patched_read_ptr(va):
            if va == class_va:
                raise ValueError(f"simulated unmapped isa at {va:#x}")
            return original_read_ptr(va)

        ctx.read_ptr = patched_read_ptr

        cl = build_class_list(ctx, strings)
        assert cl.by_vmaddr(class_va) is not None, \
            "regular class must still be present when its isa read fails"


# ─── Method list robustness (bad name pointer must not truncate the list) ────

class TestMethodListRobustness:
    """Regression test for _parse_traditional_method: a method with an unmapped
    name_ptr used to propagate a ValueError that broke out of the entire method
    loop, silently discarding all subsequent methods.

    The fix wraps read_cstring in try/except so only THAT method gets name=None;
    the loop continues and later methods are still parsed.
    """

    def test_bad_name_ptr_sets_name_none_does_not_truncate(self):
        """A method with an unmapped name pointer must be parsed with name=None
        and must NOT truncate subsequent methods in the same list."""
        from macho.classlist import _parse_traditional_method
        from macho.strings import StringTable

        UNMAPPED_VA = 0xDEAD0000   # guaranteed outside any segment

        # Build a fake ctx where the name pointer for one method is unmapped
        class _FakeCtx:
            """Minimal ctx stub: normal reads work except for UNMAPPED_VA."""
            _data = b'\x00' * 64   # enough for the method struct itself

            def is_variable(self, vmaddr):        # no program data, no binds
                return False

            def read_ptr(self, va):
                # method_t layout: name_ptr @0, types_ptr @8, imp @16
                # For our test method VA=0: name=UNMAPPED_VA, types=0, imp=0xCAFE
                field = va - 0
                if field == 0:   return UNMAPPED_VA
                if field == 8:   return 0
                if field == 16:  return 0xCAFE0000
                raise ValueError(f"unmapped {va:#x}")

            def read_cstring(self, va, max_len=4096):
                if va == UNMAPPED_VA:
                    raise ValueError(f"unmapped cstring at {va:#x}")
                return ''

        st  = StringTable()
        ctx = _FakeCtx()

        method = _parse_traditional_method(ctx, va=0, strings=st)
        assert method is not None,  "method must still be returned even with bad name_ptr"
        assert method.name is None,  "name must be None (not raise) for unmapped pointer"
        assert method.imp == 0xCAFE0000, "imp must still be parsed correctly"


# ─── class_t.data dual-tag-bit regression (mechanism_claims_data id=tagstrip) ──
#
# _parse_class used to strip the FAST_DATA_MASK low ObjC/Swift tag bits from
# class_t.data ONLY when ctx.read_ptr()'s decoded value equalled the raw u64
# (i.e. it assumed any change meant the fixup walk had already "cleaned" the
# slot).  But the cache/binary pointer decoders only ever strip HIGH
# chain/cache-metadata bits (>= bit 36); they never touch the low 3 tag bits.
# When a class_t.data value carries a high fixup bit AND a low tag bit at the
# same time, read_ptr() changes the raw value (due to the high-bit strip)
# while leaving the low tag bits in place — so the old conditional wrongly
# treated the value as "already clean" and skipped the mask, producing a
# ro_va off by the tag value and silently dropping the class.

class TestParseClassDualTagBits:
    def test_high_chain_bit_and_low_tag_bit_both_set(self):
        """
        class_t.data raw = 0x4000000100000104:
          - high bit 0x4000000000000000 = chain/cache fixup metadata
          - low 3 bits 0x4                = ObjC/Swift FAST_DATA_MASK tag
        Correct decode (mask FAST_DATA_MASK, then strip the high bit) is
        0x100000100.  The old code took ctx.read_ptr()'s output (which only
        strips the high bit, yielding 0x100000104) unchanged because it
        differed from the raw value -- an off-by-4 ro_va that reads garbage
        and causes _parse_class to return None, silently dropping the class.
        """
        import tempfile
        from macho.dyld_cache import DyldCacheReader
        from tests.test_dyld_cache import _pack_cache

        BASE     = 0x100000000
        NAME_VA  = BASE + 0x000
        RO_VA    = BASE + 0x100          # correct, masked class_ro_t address
        CLASS_VA = BASE + 0x200

        TAG_BITS  = 0x4                  # low ObjC/Swift tag bit
        CHAIN_BIT = 0x4000000000000000   # high chain-fixup metadata bit
        raw_data  = CHAIN_BIT | RO_VA | TAG_BITS
        assert raw_data == 0x4000000100000104

        content = bytearray(0x300)
        name_b  = b'TagBitClass\x00'
        content[0:len(name_b)] = name_b
        content[0x100:0x100 + 72] = _encode_ro(name_va=NAME_VA)
        content[0x200:0x200 + 40] = struct.pack('<QQQQQ', 0, 0, 0, 0, raw_data)

        cache_bytes = _pack_cache(BASE, bytes(content))

        with tempfile.TemporaryDirectory() as tmpdir:
            import os
            cache_path = os.path.join(tmpdir, 'dyld_shared_cache_arm64')
            with open(cache_path, 'wb') as f:
                f.write(cache_bytes)

            with DyldCacheReader(cache_path) as reader:
                ctx = BinaryContext.from_cache(reader, BASE)
                cls = _parse_class(ctx, CLASS_VA, StringTable())

        assert cls is not None, (
            "class must be parsed, not silently dropped, when class_t.data "
            "carries both a high chain-fixup bit and a low ObjC tag bit"
        )
        assert cls.name == 'TagBitClass'


class TestAnIvarOffsetTheRuntimeSets:
    """A Swift class's ivar offset variable lives in zero-fill program data (``__common``):
    the runtime sets it, the file holds no bytes there.  The ivar is kept with no offset
    (None), not read as unreadable -- which had cut every such list short (the sweep of
    2026-10-22: 23 lists in 7 images, TODO #138)."""

    def test_kept_with_no_offset(self):
        import struct as _s
        from macho.classlist import _parse_ivars
        from macho.memory import unread_input
        VAR, NAME, TYPE = 0x9000, 0x5000, 0x5010

        class Ctx:
            def read_u32(self, va):
                return _s.unpack_from("<I", self.list, va - 0x4000)[0]

            def read_ptr(self, va):
                return _s.unpack_from("<Q", self.list, va - 0x4000)[0]

            def read_cstring(self, va, max_len=4096):
                return {NAME: "count", TYPE: "q"}[va]

            def is_variable(self, va):
                return va == VAR
        ctx = Ctx()
        ctx.list = _s.pack("<II", 32, 1) + _s.pack("<QQQII", VAR, NAME, TYPE, 3, 8)
        ivars = _parse_ivars(ctx, 0x4000, StringTable())
        assert [(i.name, i.offset, i.offset_slot) for i in ivars] == [("count", None, VAR)]
        assert unread_input(ctx) == []


class TestSuperclassChain:
    """macho.classlist.superclass_chain: a class of the image read from the class list,
    another image's through its class_t (+8 its superclass), a bound slot by its import."""

    @staticmethod
    def _cls(va, name, super_va):
        return ObjcClass(vmaddr=va, name=name, is_meta=False, superclass_vmaddr=super_va,
                         superclass_name=None, ro_flags=0, instance_size=0, methods=[], ivars=[])

    @staticmethod
    def _ctx(supers=(), names=(), binds=(), mapped=(), cache=False):
        """A stand-in: *supers* {class_t: superclass} and *names* {class_t: name} of other
        images' classes, *binds* {slot: symbol}, *mapped* the file's addresses."""
        import macho.classlist as CL
        from tests._fakes import NoImage

        class Ctx(NoImage):
            is_cache_backed = cache

            def read_ptr(self, va):
                if va - 8 in dict(supers):
                    return dict(supers)[va - 8]
                raise ValueError("unmapped")

            def bind_name_for(self, vmaddr):
                return dict(binds).get(vmaddr)

            def vmaddr_to_offset(self, vmaddr, length=1):
                if vmaddr in mapped:
                    return vmaddr
                raise ValueError("unmapped")
        table = dict(names)
        return Ctx(), (lambda ctx, va: table.get(va)), CL

    def _chain(self, cl, va, **kw):
        from unittest import mock
        ctx, name_at, CL = self._ctx(**kw)
        with mock.patch.object(CL, "class_name_at", name_at):
            return CL.superclass_chain(ctx, va, cl)

    def test_across_images_to_the_root(self):
        cl = ClassList([self._cls(0x1000, "A", 0x2000), self._cls(0x2000, "B", 0x8000)])
        ch = self._chain(cl, 0x1000, supers={0x8000: 0x9000, 0x9000: 0}, cache=True,
                         names={0x8000: "Shared", 0x9000: "PBCodable"})
        assert (ch.names, ch.end) == (("B", "Shared", "PBCodable"), "root")
        assert ch.links[0] == (0x2000, "B")

    def test_a_bound_slot_ends_at_its_import(self):
        cl = ClassList([self._cls(0x1000, "A", 0x8010000000000002)])
        ch = self._chain(cl, 0x1000, binds={0x1008: "_OBJC_CLASS_$_NSObject"})
        assert (ch.links, ch.end) == (((None, "NSObject"),), "import")

    def test_a_cycle_ends_it(self):
        cl = ClassList([self._cls(0x1000, "A", 0x2000), self._cls(0x2000, "B", 0x1000)])
        ch = self._chain(cl, 0x1000)
        assert (ch.names, ch.end) == (("B",), "cycle")

    def test_where_it_leaves_the_file(self):
        # a pointer the file does not map: outside; one it maps but cannot name: inside
        cl = ClassList([self._cls(0x1000, "A", 0x201e1d7c688)])
        ch = self._chain(cl, 0x1000)
        assert (ch.end, ch.end_va, ch.left_file) == ("unnamed", 0x201e1d7c688, True)
        cl = ClassList([self._cls(0x1000, "A", 0x3000)])
        ch = self._chain(cl, 0x1000, mapped={0x3000})
        assert (ch.end, ch.left_file) == ("unnamed", False)
        # a cache reads every image: nothing is outside it
        cl = ClassList([self._cls(0x1000, "A", 0x201e1d7c688)])
        assert self._chain(cl, 0x1000, cache=True).left_file is False


class TestAncestors:

    def test_the_image_s_classes_then_a_stop(self):
        cl = ClassList([TestSuperclassChain._cls(0x1000, "A", 0x2000),
                        TestSuperclassChain._cls(0x2000, "B", 0x8000)])
        assert [c.name for c in cl.ancestors(cl.find("A"))] == ["A", "B"]

    def test_a_cycle_ends_it(self):
        cl = ClassList([TestSuperclassChain._cls(0x1000, "A", 0x2000),
                        TestSuperclassChain._cls(0x2000, "B", 0x1000)])
        assert [c.name for c in cl.ancestors(cl.find("A"))] == ["A", "B"]
