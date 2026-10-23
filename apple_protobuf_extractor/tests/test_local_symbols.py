"""
tests/test_local_symbols.py
===========================
Tests for macho/local_symbols.py — recovering ObjC method names from the
dyld shared cache's ``.symbols`` local-symbol table.

Two tiers:

* Synthetic tests for :func:`apply_to_classes` need no cache file: they build
  ObjcClass/ObjcMethod objects directly and assert the rename / add / skip-meta
  behaviour.
* Live tests load the real GeoServices image and assert known IMP→selector
  mappings (verified against the iPhone 8 iOS cache), gated by ``_HAS_CACHE``.
"""

import os
import artifacts
import unittest

import struct
import tempfile

from macho.classlist import ObjcClass, ObjcMethod
from macho.local_symbols import (
    ImageLocalSymbols,
    apply_to_classes,
    load_image_symbol_addrs,
    symbols_path_for,
)


def _method(name, imp, types=''):
    return ObjcMethod(name=name, types=types, imp=imp, is_relative=True)


def _class(name, methods, *, is_meta=False):
    return ObjcClass(
        vmaddr=0x1000,
        name=name,
        is_meta=is_meta,
        superclass_vmaddr=0,
        superclass_name=None,
        ro_flags=0,
        instance_size=0,
        methods=list(methods),
        ivars=[],
    )


# ─── Synthetic apply_to_classes tests (no cache required) ──────────────────────

class TestApplyToClasses(unittest.TestCase):

    def _syms(self):
        # Foo: readFrom: @0x10 (currently mis-named), writeTo: @0x20 (null),
        #      plus territoryTypeAsString: @0x30 that's absent from the class.
        return ImageLocalSymbols(
            imp_to_sel={0x10: 'readFrom:', 0x20: 'writeTo:',
                        0x30: 'territoryTypeAsString:'},
            class_to_sels={'Foo': {'readFrom:': 0x10, 'writeTo:': 0x20,
                                   'territoryTypeAsString:': 0x30}},
        )

    def test_corrects_false_positive_name(self):
        cls = _class('Foo', [_method('COMBO', 0x10)])
        counts = apply_to_classes([cls], self._syms())
        self.assertEqual(cls.methods[0].name, 'readFrom:')
        self.assertEqual(counts['corrected'], 1)

    def test_fills_null_name(self):
        cls = _class('Foo', [_method(None, 0x20)])
        counts = apply_to_classes([cls], self._syms())
        self.assertEqual(cls.methods[0].name, 'writeTo:')
        self.assertEqual(counts['renamed'], 1)

    def test_adds_method_absent_from_list(self):
        # The class has only readFrom:; the AsString: selector exists as a
        # symbol but not in the optimised method list → it must be added.
        cls = _class('Foo', [_method('readFrom:', 0x10)])
        counts = apply_to_classes([cls], self._syms())
        names = {m.name for m in cls.methods}
        self.assertIn('territoryTypeAsString:', names)
        self.assertIn('writeTo:', names)
        self.assertEqual(counts['added'], 2)

    def test_no_duplicate_when_imp_already_present(self):
        cls = _class('Foo', [_method('readFrom:', 0x10)])
        apply_to_classes([cls], self._syms())
        imps = [m.imp for m in cls.methods if m.imp == 0x10]
        self.assertEqual(len(imps), 1)

    def test_metaclass_gets_no_instance_selectors(self):
        # A metaclass shares its instance class's name; instance selectors
        # (from class_to_sels / imp_to_sel) must NOT be grafted onto it.  With
        # no meta_to_sels entry for 'Foo' it is left completely untouched.
        meta = _class('Foo', [_method(None, 0x99)], is_meta=True)
        counts = apply_to_classes([meta], self._syms())
        self.assertEqual(len(meta.methods), 1)          # nothing added
        self.assertIsNone(meta.methods[0].name)         # nothing renamed
        self.assertEqual(
            counts,
            {'renamed': 0, 'corrected': 0, 'added': 0, 'meta_added': 0},
        )

    def test_metaclass_gets_class_methods_grafted(self):
        # +[Foo valueType] exists only as a symbol; it must be grafted onto the
        # metaclass (and an existing meta method renamed by IMP), while the
        # instance class with the same name is unaffected by meta_to_sels.
        syms = ImageLocalSymbols(
            meta_imp_to_sel={0x40: 'valueType'},
            meta_to_sels={'Foo': {'valueType': 0x40, 'itemType': 0x50}},
        )
        meta = _class('Foo', [_method(None, 0x40)], is_meta=True)
        counts = apply_to_classes([meta], syms)
        names = {m.name for m in meta.methods}
        self.assertEqual(names, {'valueType', 'itemType'})  # renamed + added
        self.assertEqual(counts['renamed'], 1)
        self.assertEqual(counts['meta_added'], 1)

    def test_unknown_class_untouched(self):
        cls = _class('Bar', [_method(None, 0xABC)])
        counts = apply_to_classes([cls], self._syms())
        self.assertIsNone(cls.methods[0].name)
        self.assertEqual(
            counts,
            {'renamed': 0, 'corrected': 0, 'added': 0, 'meta_added': 0},
        )


# ─── Offline: synthetic .symbols file for load_image_symbol_addrs ──────────────

def _build_symbols_file(path, image_off, syms):
    """Write a minimal dyld ``.symbols`` file holding ONE image's local symbols.

    *syms* is a list of ``(name, n_value)``; an ``n_value`` of 0 must be skipped
    by the parser.  ``image_off`` is the per-image ``dylibOffset``
    (``mach_header_va - cache_base``).  Mirrors the on-disk layout the production
    parser reads (header @0x48/0x50 → local_symbols_info → entries → nlist +
    strings)."""
    strings = b"\x00"                                  # index 0 = empty string
    nlist = b""
    str_off = {}
    for name, value in syms:
        b = name.encode()
        if b not in str_off:
            str_off[b] = len(strings)
            strings += b + b"\x00"
        nlist += struct.pack("<IBBHQ", str_off[b], 0, 1, 0, value)

    lso = 0x1000                                       # local-symbols region start
    info_size = 6 * 4
    entries_off = info_size
    nlist_off = entries_off + 16                       # one 16-byte entry
    strings_off = nlist_off + len(nlist)
    info = struct.pack("<6I", nlist_off, len(syms), strings_off, len(strings),
                       entries_off, 1)
    entry = struct.pack("<QII", image_off, 0, len(syms))
    region = info + entry + nlist + strings

    buf = bytearray(lso + len(region))
    struct.pack_into("<Q", buf, 0x48, lso)             # localSymbolsOffset
    struct.pack_into("<Q", buf, 0x50, len(region))     # localSymbolsSize
    buf[lso:lso + len(region)] = region
    with open(path, "wb") as fh:
        fh.write(buf)


class TestLoadImageSymbolAddrsOffline(unittest.TestCase):
    """Deterministic parse coverage (no cache needed) for the raw name→vmaddr
    reader, including the n_value-skip and substring-filter branches."""
    def _write(self, syms, image_off=0x1000):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "test.symbols")
        _build_symbols_file(p, image_off, syms)
        return p

    def test_all_symbols_and_nvalue_skip(self):
        p = self._write([("_proto_a", 0x4000), ("_skip_me", 0),       # 0 -> skipped
                         ("_proto_b", 0x4010)])
        got = load_image_symbol_addrs(p, cache_base=0, mach_header_va=0x1000)
        self.assertEqual(got, {"_proto_a": 0x4000, "_proto_b": 0x4010})

    def test_substring_filter(self):
        p = self._write([("Foo_protobuf_nameMap_WZ", 0x8000),
                         ("Foo13decodeMessageF", 0x8100),
                         ("unrelated_symbol", 0x8200)])
        got = load_image_symbol_addrs(p, 0, 0x1000,
                                      substrs=["_protobuf_nameMap", "13decodeMessage"])
        self.assertEqual(set(got), {"Foo_protobuf_nameMap_WZ", "Foo13decodeMessageF"})

    def test_image_not_listed_returns_empty(self):
        p = self._write([("_x", 0x4000)], image_off=0x1000)
        # ask for a different image offset than the one in the file
        self.assertEqual(load_image_symbol_addrs(p, 0, 0x9999), {})

    def test_a_file_that_cannot_be_opened_raises(self):
        # (an absent .symbols is no path at all; one that cannot be read is the caller's to
        # record: TODO #137)
        with self.assertRaises(OSError):
            load_image_symbol_addrs("/no/such/file.symbols", 0, 0x1000)


# ─── Live tests against the real GeoServices cache ─────────────────────────────

_CACHE_MAIN = artifacts.cache_file()
_HAS_SYMBOLS = _CACHE_MAIN is not None and symbols_path_for(_CACHE_MAIN) is not None
_SKIP_MSG = ('dyld shared cache .symbols file not found — place full cache '
             '(including dyld_shared_cache_arm64.symbols) in the data dir (see the artifacts module / MACHO_DATA_DIR)')


@unittest.skipUnless(_HAS_SYMBOLS, _SKIP_MSG)
class TestLocalSymbolsLive(unittest.TestCase):
    """Resolve GeoServices method names from the real ``.symbols`` table.

    IMP→selector pairs verified against the iPhone 8 cache
    (GEOCoarseLocationTerritoryInfo instance methods).
    """

    # Verified IMP (impOffset target) → selector for GEOCoarseLocationTerritoryInfo.
    _KNOWN = {
        0x18c50e080: 'init',
        0x18c50fe88: 'readFrom:',
        0x18c50fe90: 'writeTo:',
        0x18c510908: 'hash',
        0x18c510264: 'copyWithZone:',
    }

    @classmethod
    def setUpClass(cls):
        from macho.dyld_cache import DyldCacheReader
        cls.reader = DyldCacheReader(_CACHE_MAIN)
        cls.mach_va = cls.reader.find_image_header('GeoServices')
        cls.syms = (cls.reader.image_local_symbols(cls.mach_va)
                    if cls.mach_va is not None else None)

    @classmethod
    def tearDownClass(cls):
        cls.reader.close()

    def setUp(self):
        if self.mach_va is None:
            self.skipTest('GeoServices not present in this cache')
        if not self.syms:
            self.skipTest('GeoServices local symbols not accessible')

    def test_known_imp_to_selector(self):
        for imp, sel in self._KNOWN.items():
            self.assertEqual(self.syms.imp_to_sel.get(imp), sel,
                             f'IMP 0x{imp:x} should resolve to {sel!r}')

    def test_class_to_sels_has_proto_boilerplate(self):
        sels = self.syms.class_to_sels.get('GEOCoarseLocationTerritoryInfo', {})
        self.assertIn('readFrom:', sels)
        self.assertIn('writeTo:', sels)

    def test_apply_fixes_false_positive_on_real_class(self):
        from macho.memory import BinaryContext
        from macho.strings import build_string_table
        from macho import classlist as CL
        ctx = BinaryContext.from_cache(self.reader, self.mach_va)
        st = build_string_table(ctx)
        cl = CL.build_class_list(ctx, st)
        unnamed = sum(1 for c in cl for m in c.methods if m.name is None)
        counts = apply_to_classes(cl, self.syms)
        # The method lists name nearly every method themselves (the relative-selector base,
        # .cxx_destruct accepted, #122): before, 383 were unnamed (347 of them .cxx_destruct)
        # and over 1000 renamed or corrected by .symbols; now 36 unnamed, 41 fixed.
        self.assertLess(unnamed, 100)
        self.assertLess(counts['renamed'] + counts['corrected'], 100)
        # The method at the readFrom: IMP must now be named readFrom: (it parses
        # as a false-positive selector from the stripped method list otherwise).
        klass = cl.find('GEOCoarseLocationTerritoryInfo')
        self.assertIsNotNone(klass)
        by_imp = {m.imp: m.name for m in klass.methods}
        self.assertEqual(by_imp.get(0x18c50fe88), 'readFrom:')

    def test_class_methods_captured_in_meta_to_sels(self):
        # The +[GEOBusiness categoryType] element-type method must be recovered
        # into the separate metaclass map (verified IMP from Hopper).
        sels = self.syms.meta_to_sels.get('GEOBusiness', {})
        self.assertIn('categoryType', sels)
        self.assertEqual(sels['categoryType'], 0x18cfb9ba4)
        # It must NOT leak into the instance-method map (same class name).
        self.assertNotIn('categoryType',
                         self.syms.class_to_sels.get('GEOBusiness', {}))

    def test_metaclass_type_methods_grafted_and_resolved(self):
        # End-to-end: the metaclass's preoptimised +xyzType element-type methods
        # drive repeated-field resolution.  Their selector names now decode
        # DIRECTLY from the cache's relative-method-selector base (the '🤯'
        # anchor), so they are present even before .symbols grafting; grafting
        # still adds any methods entirely absent from the optimised list
        # (meta_added) and corrects the rest.  GEOBusiness is a good witness: two
        # adjacent "category" fields resolve to *different* element types
        # declared by their respective +xyzType methods.
        from macho.memory import BinaryContext
        from macho.strings import build_string_table
        from macho import classlist as CL
        from proto.extractor import extract_proto_message

        ctx = BinaryContext.from_cache(self.reader, self.mach_va)
        st = build_string_table(ctx)
        cl = CL.build_class_list(ctx, st)

        biz = cl.find('GEOBusiness')
        self.assertIsNotNone(biz)
        meta = cl.by_vmaddr(ctx.read_ptr(biz.vmaddr))
        self.assertIsNotNone(meta)
        self.assertTrue(meta.is_meta)
        # The relative-selector-base decode resolves the metaclass +xyzType
        # names directly from the binary — no .symbols required.
        self.assertIn('categoryType', {m.name for m in meta.methods})

        counts = apply_to_classes(cl, self.syms)
        self.assertGreater(counts['meta_added'], 0)
        meta_sels = {m.name for m in meta.methods}
        self.assertIn('categoryType', meta_sels)
        self.assertIn('localizedCategoriesType', meta_sels)

        msg = extract_proto_message(ctx, st, cl, biz)
        by_name = {f.name: f.type_name for f in msg.fields}
        # categoryType → NSString → repeated string (must NOT be promoted to a
        # message type by the name-suffix pool refinement).
        self.assertEqual(by_name.get('categorys'), 'string')
        # localizedCategoriesType → GEOCategory → repeated message.
        self.assertEqual(by_name.get('localizedCategories'), 'GEOCategory')
        # A plain bytes→message recovery that depends on the grafted pool.
        self.assertEqual(by_name.get('photos'), 'GEOPhoto')

    def test_wide_oneof_field_numbers_not_truncated(self):
        # GEOPDComponentValue is an 81-field oneof whose writeTo: serialises its
        # highest-tag fields (89–96) in out-of-line blocks past the old fixed
        # 600-instruction cap.  The field-count-aware budget must capture them so
        # every ivar gets its real protobuf tag, instead of falling to the
        # next_unconfirmed fallback (which assigned the lowest-free numbers and
        # both dropped tags 89–96 and invented spurious fields in the type gaps).
        from macho.memory import BinaryContext
        from macho.strings import build_string_table
        from macho import classlist as CL
        from proto.extractor import extract_proto_message

        ctx = BinaryContext.from_cache(self.reader, self.mach_va)
        st = build_string_table(ctx)
        cl = CL.build_class_list(ctx, st)
        apply_to_classes(cl, self.syms)

        cv = cl.find('GEOPDComponentValue')
        self.assertIsNotNone(cv)
        msg = extract_proto_message(ctx, st, cl, cv)
        by_num = {f.number: f.type_name for f in msg.fields}
        nums = set(by_num)

        # High-tag oneof members must resolve to their real classes (these are
        # the fields the old cap dropped entirely).
        self.assertEqual(by_num.get(91), 'GEOPDTransitPaymentMethodInfo')
        self.assertEqual(by_num.get(92), 'GEOPDBusinessAssets')
        self.assertEqual(by_num.get(96), 'GEOPDPOIClaim')
        self.assertTrue({89, 91, 92, 93, 94, 95, 96} <= nums)

        # The ComponentType gap tags (no oneof member) must NOT appear — they
        # only showed up as spurious next_unconfirmed filler before the fix.
        for gap in (17, 18, 19, 21, 28, 35):
            self.assertNotIn(gap, nums, f"tag {gap} is a type gap; must be absent")

        # Every field must carry a binary-confirmed number (no filler guesses).
        self.assertTrue(all(f.number_confirmed for f in msg.fields))


@unittest.skipUnless(_HAS_SYMBOLS, _SKIP_MSG)
class TestImageSymbolAddrsLive(unittest.TestCase):
    """``image_symbol_addrs`` exposes the RAW name→vmaddr table (not just ObjC
    methods) — the source swift-protobuf recovery uses cache-native.  Checked on
    CopresenceCore, a cache framework whose swift-protobuf types carry
    ``_protobuf_nameMap`` static-init symbols in the ``.symbols`` sub-cache."""
    @classmethod
    def setUpClass(cls):
        from macho.dyld_cache import DyldCacheReader
        cls.reader = DyldCacheReader(_CACHE_MAIN)
        cls.mach_va = cls.reader.find_image_header('CopresenceCore')

    @classmethod
    def tearDownClass(cls):
        cls.reader.close()

    def setUp(self):
        if self.mach_va is None:
            self.skipTest('CopresenceCore not present in this cache')

    def test_substr_filter_finds_namemap_symbols(self):
        addrs = self.reader.image_symbol_addrs(self.mach_va, '_protobuf_nameMap')
        self.assertTrue(addrs, 'expected nameMap symbols for CopresenceCore')
        # every returned name matches the filter and every addr is a real vmaddr
        self.assertTrue(all('_protobuf_nameMap' in n for n in addrs))
        self.assertTrue(all(v > 0 for v in addrs.values()))
        # CP_KeyValue's nameMap static-init symbol is present
        self.assertTrue(any('CP_KeyValue' in n and '_protobuf_nameMap' in n
                            for n in addrs))

    def test_filter_narrows_result(self):
        wide = self.reader.image_symbol_addrs(self.mach_va)               # all
        narrow = self.reader.image_symbol_addrs(self.mach_va, 'decodeMessage')
        self.assertGreater(len(wide), len(narrow))
        self.assertTrue(all('decodeMessage' in n for n in narrow))

    def test_unknown_image_offset_empty(self):
        # an address that maps to no image entry yields an empty table, not error
        self.assertEqual(self.reader.image_symbol_addrs(0xDEAD0000, 'x'), {})


if __name__ == '__main__':
    unittest.main()
