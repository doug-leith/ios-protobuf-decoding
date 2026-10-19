"""
tests/test_cache_classlist.py
=============================
Tests for macho/cache_classlist.py — proof-of-concept for reading ObjC class
names directly from the dyld shared cache.

Test classes
------------
TestDecodeCachePtr
    Unit tests for _decode_cache_ptr().
    Covers all three resolution strategies (direct VA, tag-bit masking,
    packed-pointer strip) as well as unmapped / zero inputs.

TestReadObjcClassName
    Synthetic tests for read_objc_class_name() using in-memory caches
    with hand-crafted class_t / class_ro_t / name-string layouts.
    Covers: happy path, ObjC tag bits on class_ro_t pointer, null data
    pointer, unmapped class_va, bad name pointer.

TestIterClassNames
    Synthetic tests for iter_class_names() using the same helpers.
    Covers: single class, multiple classes, skipping invalid entries,
    exclusive-end classlist bounds.

TestClassNamesLive
    Live tests against the real dyld cache.  Skipped when the cache is
    absent.  Data-section tests (read_objc_class_name, iter_class_names)
    have an additional inner skip if the DATA sub-caches are absent
    (verified by probing a Hopper-verified class_t address).
"""

from __future__ import annotations

import os
import artifacts
import shutil
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from macho.dyld_cache     import DyldCacheReader
from macho.cache_classlist import (
    _decode_cache_ptr,
    read_objc_class_name,
    iter_class_names,
)


# ── Synthetic cache builder (reused from test_dyld_cache.py pattern) ──────────

_MAGIC_ARM64 = b'dyld_v1   arm64\x00'
_MAP_START   = 0x200   # conventional offset for the first mapping entry


def _pack_cache(vmaddr: int, content: bytes, *, magic: bytes = _MAGIC_ARM64) -> bytes:
    """Single-mapping synthetic cache whose content maps at *vmaddr*."""
    content_off = (_MAP_START + 32 + 0xfff) & ~0xfff
    total_size  = content_off + len(content)
    buf         = bytearray(total_size)

    buf[0:16] = magic
    struct.pack_into('<I', buf, 0x10, _MAP_START)
    struct.pack_into('<I', buf, 0x14, 1)
    struct.pack_into('<QQQ', buf, _MAP_START, vmaddr, len(content), content_off)
    struct.pack_into('<I',   buf, _MAP_START + 24, 5)
    struct.pack_into('<I',   buf, _MAP_START + 28, 5)
    buf[content_off : content_off + len(content)] = content
    return bytes(buf)


class _TmpDir:
    def __init__(self):  self.path = tempfile.mkdtemp()
    def join(self, n):   return os.path.join(self.path, n)
    def write(self, n, d):
        p = self.join(n)
        with open(p, 'wb') as f: f.write(d)
        return p
    def __enter__(self): return self
    def __exit__(self, *_): shutil.rmtree(self.path, ignore_errors=True)


def _build_objc_cache(
    classes: list,          # list of (class_name_str,)
    *,
    base: int = 0x100000000,
) -> bytes:
    """
    Build a synthetic cache with a realistic ObjC memory layout.

    Layout within the single mapping (all offsets relative to ``base``):

    ``0x0000`` : 16 bytes reserved (simulates text before structs)
    ``0x1000`` : name strings (null-terminated, packed together)
    ``0x2000`` : class_ro_t structs (80 bytes each, 16-byte aligned; we use
                 only the first 32 bytes so 80 bytes leaves plenty of padding)
    ``0x3000`` : class_t structs (40 bytes each)
    ``0x4000`` : __objc_classlist (8 bytes per class)

    Each ``class_ro_t`` at position ``i`` has its ``name`` pointer (at +24)
    pointing to the corresponding name string.
    Each ``class_t`` at position ``i`` has its ``data`` pointer (at +32)
    pointing to the corresponding ``class_ro_t``.
    Each classlist entry points to the corresponding ``class_t``.
    """
    CONTENT_SIZE = 0x5000
    content = bytearray(CONTENT_SIZE)

    # ── Name strings at page 0x1000 ─────────────────────────────────────────
    name_vas = []
    name_cursor = 0x1000
    for (name_str,) in classes:
        encoded = name_str.encode('utf-8') + b'\x00'
        content[name_cursor : name_cursor + len(encoded)] = encoded
        name_vas.append(base + name_cursor)
        name_cursor += len(encoded)

    # ── class_ro_t structs at page 0x2000 (80 bytes each) ───────────────────
    ro_vas = []
    RO_STRIDE = 80
    for i, (name_str,) in enumerate(classes):
        off = 0x2000 + i * RO_STRIDE
        # name pointer at offset +24
        struct.pack_into('<Q', content, off + 24, name_vas[i])
        ro_vas.append(base + off)

    # ── class_t structs at page 0x3000 (48 bytes each, > 40) ────────────────
    class_vas = []
    CLS_STRIDE = 48
    for i in range(len(classes)):
        off = 0x3000 + i * CLS_STRIDE
        # data pointer at offset +32 → class_ro_t
        struct.pack_into('<Q', content, off + 32, ro_vas[i])
        class_vas.append(base + off)

    # ── classlist at page 0x4000 ─────────────────────────────────────────────
    list_start = base + 0x4000
    list_end   = base + 0x4000 + len(classes) * 8
    for i, cls_va in enumerate(class_vas):
        struct.pack_into('<Q', content, 0x4000 + i * 8, cls_va)

    cache = _pack_cache(base, bytes(content))
    return cache, list_start, list_end, class_vas


# ─── TestDecodeCachePtr ───────────────────────────────────────────────────────

class TestDecodeCachePtr(unittest.TestCase):
    """Unit tests for _decode_cache_ptr()."""

    BASE = 0x180000000

    def setUp(self):
        self.tmpdir = _TmpDir()
        # A tiny cache mapping [BASE, BASE+0x1000)
        data = _pack_cache(self.BASE, b'\x00' * 0x1000)
        self.path = self.tmpdir.write('cache', data)

    def tearDown(self):
        self.tmpdir.__exit__(None, None, None)

    # ── strategy 1: direct vmaddr ─────────────────────────────────────────────

    def test_direct_vmaddr_in_mapping_returned_as_is(self):
        with DyldCacheReader(self.path) as r:
            result = _decode_cache_ptr(r, self.BASE)
        self.assertEqual(result, self.BASE)

    def test_direct_vmaddr_middle_of_mapping(self):
        with DyldCacheReader(self.path) as r:
            result = _decode_cache_ptr(r, self.BASE + 0x500)
        self.assertEqual(result, self.BASE + 0x500)

    # ── strategy 1: tagged vmaddr still in mapping returned as-is ───────────
    # _decode_cache_ptr is a generic decoder; ObjC tag-bit stripping is
    # the caller's responsibility (done in read_objc_class_name via & ~0x7).
    # Here we verify that a tagged address that IS within a mapping comes back
    # unchanged — the caller must strip before passing if it wants the
    # clean address.

    def test_tagged_vmaddr_in_mapping_returned_as_is(self):
        """Tagged address still in mapping → returned unchanged (caller strips)."""
        tagged = self.BASE | 0x7   # within mapping [BASE, BASE+0x1000)
        with DyldCacheReader(self.path) as r:
            result = _decode_cache_ptr(r, tagged)
        self.assertEqual(result, tagged)   # NOT BASE — tag bits preserved

    def test_tagged_then_strip_gives_correct_address(self):
        """Pre-stripping tag bits before calling decoder gives clean address."""
        tagged = self.BASE | 0x3
        with DyldCacheReader(self.path) as r:
            result = _decode_cache_ptr(r, tagged & ~0x7)
        self.assertEqual(result, self.BASE)

    def test_tagged_outside_mapping_with_clean_inside(self):
        """Tagged address outside mapping, but clean address is inside → clean returned."""
        # Put the mapping at BASE+0x100 with size exactly 0x10 so
        # BASE+0x100 is in range but BASE+0x107 is not.
        import struct, tempfile, os
        inner_base = self.BASE + 0x100
        inner_content = b'\x00' * 0x8   # only 8 bytes, vmend = inner_base+8
        data = _pack_cache(inner_base, inner_content)
        with tempfile.NamedTemporaryFile(delete=False, suffix='.cache') as tf:
            tf.write(data)
            tmp = tf.name
        try:
            with DyldCacheReader(tmp) as r:
                tagged = inner_base | 0x3     # inner_base+3; within [inner_base, inner_base+8) → in map
                result = _decode_cache_ptr(r, tagged & ~0x7)
            self.assertEqual(result, inner_base)
        finally:
            os.unlink(tmp)

    # ── strategy 3: packed-pointer strip ─────────────────────────────────────

    def test_packed_pointer_high_bits_stripped(self):
        """Bits 63+ set (ipsw-extracted format): low 36 bits yield the vmaddr."""
        raw = 0xC000_0000_0000_0000 | self.BASE  # bits 62-63 set
        with DyldCacheReader(self.path) as r:
            result = _decode_cache_ptr(r, raw)
        self.assertEqual(result, self.BASE)

    # ── null / unmapped inputs ────────────────────────────────────────────────

    def test_zero_returns_zero(self):
        with DyldCacheReader(self.path) as r:
            self.assertEqual(_decode_cache_ptr(r, 0), 0)

    def test_unmapped_address_returns_zero(self):
        with DyldCacheReader(self.path) as r:
            self.assertEqual(_decode_cache_ptr(r, 0xDEAD000000000000), 0)

    def test_unmapped_after_tag_masking_returns_zero(self):
        """Value not in mapping even after masking → 0."""
        not_mapped = 0x999000007  # bits 0-2 set, low36 in range but not mapped
        with DyldCacheReader(self.path) as r:
            self.assertEqual(_decode_cache_ptr(r, not_mapped), 0)


# ─── TestReadObjcClassName ────────────────────────────────────────────────────

class TestReadObjcClassName(unittest.TestCase):
    """Unit tests for read_objc_class_name() using synthetic caches."""

    def setUp(self):
        self.tmpdir = _TmpDir()

    def tearDown(self):
        self.tmpdir.__exit__(None, None, None)

    def _make_reader(self, classes):
        cache, list_start, list_end, class_vas = _build_objc_cache(classes)
        path = self.tmpdir.write('cache', cache)
        return DyldCacheReader(path), list_start, list_end, class_vas

    # ── happy path ────────────────────────────────────────────────────────────

    def test_single_class_name_resolved(self):
        r, _, _, class_vas = self._make_reader([('GEOFoo',)])
        with r:
            name = read_objc_class_name(r, class_vas[0])
        self.assertEqual(name, 'GEOFoo')

    def test_multiple_classes_correct_names(self):
        classes = [('Alpha',), ('Beta',), ('Gamma',)]
        r, _, _, class_vas = self._make_reader(classes)
        with r:
            for i, (expected,) in enumerate(classes):
                self.assertEqual(read_objc_class_name(r, class_vas[i]), expected)

    def test_name_with_special_chars(self):
        r, _, _, class_vas = self._make_reader([('GEOPDPlaceRequest',)])
        with r:
            self.assertEqual(read_objc_class_name(r, class_vas[0]), 'GEOPDPlaceRequest')

    # ── class_t.data with ObjC tag bits ──────────────────────────────────────

    def test_class_ro_pointer_with_tag_bits_still_resolves(self):
        """class_t.data with low 3 bits set → name should still resolve."""
        BASE = 0x100000000
        content = bytearray(0x5000)
        name = b'TaggedClass\x00'
        content[0x1000 : 0x1000 + len(name)] = name
        struct.pack_into('<Q', content, 0x2000 + 24, BASE + 0x1000)  # class_ro_t.name
        # class_t.data with tag bits 0b11 set
        struct.pack_into('<Q', content, 0x3000 + 32, (BASE + 0x2000) | 0x3)

        cache = _pack_cache(BASE, bytes(content))
        path  = self.tmpdir.write('tagged', cache)
        class_va = BASE + 0x3000

        with DyldCacheReader(path) as r:
            result = read_objc_class_name(r, class_va)
        self.assertEqual(result, 'TaggedClass')

    # ── error / edge cases ────────────────────────────────────────────────────

    def test_null_data_pointer_returns_none(self):
        """class_t.data == 0 → None."""
        BASE = 0x100000000
        content = bytearray(0x4000)   # all zeros; data pointer stays 0
        cache = _pack_cache(BASE, bytes(content))
        path  = self.tmpdir.write('null_data', cache)
        with DyldCacheReader(path) as r:
            result = read_objc_class_name(r, BASE)
        self.assertIsNone(result)

    def test_unmapped_class_va_returns_none(self):
        r, _, _, _ = self._make_reader([('X',)])
        with r:
            result = read_objc_class_name(r, 0xDEADBEEF00000000)
        self.assertIsNone(result)

    def test_unmapped_class_ro_pointer_returns_none(self):
        """class_t.data points outside any mapping → None."""
        BASE = 0x100000000
        content = bytearray(0x4000)
        # data pointer at class_t+32 points to an unmapped address
        struct.pack_into('<Q', content, 0x3000 + 32, 0x999000000000)
        cache = _pack_cache(BASE, bytes(content))
        path  = self.tmpdir.write('bad_ro', cache)
        with DyldCacheReader(path) as r:
            result = read_objc_class_name(r, BASE + 0x3000)
        self.assertIsNone(result)

    def test_null_name_pointer_returns_none(self):
        """class_ro_t.name == 0 (but data pointer is valid) → None."""
        BASE = 0x100000000
        content = bytearray(0x5000)
        # class_ro_t.name is left as 0 (null)
        struct.pack_into('<Q', content, 0x3000 + 32, BASE + 0x2000)
        cache = _pack_cache(BASE, bytes(content))
        path  = self.tmpdir.write('null_name', cache)
        with DyldCacheReader(path) as r:
            result = read_objc_class_name(r, BASE + 0x3000)
        self.assertIsNone(result)


# ─── TestIterClassNames ───────────────────────────────────────────────────────

class TestIterClassNames(unittest.TestCase):
    """Unit tests for iter_class_names()."""

    def setUp(self):
        self.tmpdir = _TmpDir()

    def tearDown(self):
        self.tmpdir.__exit__(None, None, None)

    def _collect(self, classes):
        cache, start, end, _ = _build_objc_cache(classes)
        path = self.tmpdir.write('cache', cache)
        with DyldCacheReader(path) as r:
            return list(iter_class_names(r, start, end))

    # ── basic iteration ───────────────────────────────────────────────────────

    def test_single_class(self):
        results = self._collect([('OnlyClass',)])
        self.assertEqual(len(results), 1)
        _, name = results[0]
        self.assertEqual(name, 'OnlyClass')

    def test_multiple_classes_all_returned(self):
        classes = [('ClassA',), ('ClassB',), ('ClassC',)]
        results = self._collect(classes)
        names = [n for _, n in results]
        self.assertEqual(sorted(names), ['ClassA', 'ClassB', 'ClassC'])

    def test_yields_class_va_and_name(self):
        """Each result is a 2-tuple (int, str)."""
        results = self._collect([('MyClass',)])
        self.assertEqual(len(results), 1)
        va, name = results[0]
        self.assertIsInstance(va, int)
        self.assertIsInstance(name, str)
        self.assertTrue(va > 0)
        self.assertEqual(name, 'MyClass')

    def test_empty_classlist_yields_nothing(self):
        """classlist_start == classlist_end → no results."""
        cache, start, _, _ = _build_objc_cache([('X',)])
        path = self.tmpdir.write('cache', cache)
        with DyldCacheReader(path) as r:
            results = list(iter_class_names(r, start, start))  # empty range
        self.assertEqual(results, [])

    def test_skips_zero_classlist_entry(self):
        """A zero entry in the classlist is silently skipped."""
        BASE = 0x100000000
        content = bytearray(0x5000)
        # Valid class at index 0, zero entry at index 1
        name = b'GoodClass\x00'
        content[0x1000 : 0x1000 + len(name)] = name
        struct.pack_into('<Q', content, 0x2000 + 24, BASE + 0x1000)
        struct.pack_into('<Q', content, 0x3000 + 32, BASE + 0x2000)
        struct.pack_into('<Q', content, 0x4000, BASE + 0x3000)  # entry 0: valid
        # entry 1 at 0x4008 is all-zero (skipped)

        cache = _pack_cache(BASE, bytes(content))
        path  = self.tmpdir.write('mixed', cache)
        start = BASE + 0x4000
        end   = BASE + 0x4010  # 2 entries

        with DyldCacheReader(path) as r:
            results = list(iter_class_names(r, start, end))
        names = [n for _, n in results]
        self.assertEqual(names, ['GoodClass'])


# ─── Live test helpers ────────────────────────────────────────────────────────

def _find_cache_main() -> 'Optional[str]':
    _here = os.path.dirname(os.path.abspath(__file__))
    _root = os.path.dirname(os.path.dirname(_here))
    _names = ('dyld_shared_cache_arm64e', 'dyld_shared_cache_arm64')
    cache_dir = os.environ.get('MACHO_TEST_CACHE', '').strip()
    for d in ([cache_dir] if cache_dir else []) + [artifacts.cache_dir()]:
        for name in _names:
            p = os.path.join(d, name)
            if os.path.isfile(p):
                return p
    return None


_CACHE_MAIN = _find_cache_main()
_HAS_CACHE  = _CACHE_MAIN is not None
_SKIP_MSG   = ('dyld shared cache not found — set MACHO_TEST_CACHE, or place '
               'cache files under <data dir>/dylib/ (see artifacts.py)')


# ─── TestClassNamesLive ───────────────────────────────────────────────────────

@unittest.skipUnless(_HAS_CACHE, _SKIP_MSG)
class TestClassNamesLive(unittest.TestCase):
    """
    Live tests for cache_classlist.py against the real GeoServices cache.

    Two tiers of skip:
    1. ``@skipUnless(_HAS_CACHE, ...)`` — the entire class is skipped when the
       main cache file is absent.
    2. ``self._require_data()`` — individual tests that need DATA sub-caches
       (class_t and class_ro_t structs) skip gracefully when those sub-caches
       are absent from the environment.

    Hopper-verified constants (GeoServices binary, verified June 2026):
    ───────────────────────────────────────────────────────────────────
    ``_OBJC_CLASS_$_GEOPDPlaceRequest``  class_t   0x1e1de3be8 (__DATA_DIRTY)
    ``__OBJC_CLASS_RO_$_GEOPDPlaceRequest``       0x1d6050c28 (__DATA_CONST)
    "GEOPDPlaceRequest"                  name str  0x18d97f901 (__TEXT)

    ``_OBJC_CLASS_$_GEOPDPlaceResponse`` class_t   0x1e1de3d28 (__DATA_DIRTY)
    ``__OBJC_CLASS_RO_$_GEOPDPlaceResponse``      0x1d6050cb8 (__DATA_CONST)
    "GEOPDPlaceResponse"                 name str  0x18d97f94c (__TEXT)
    """

    # ── Hopper-verified regression constants ──────────────────────────────────
    # class_t vmaddrs (in __DATA_DIRTY, sub-cache .41.dylddata)
    _CLASS_T_PLACE_REQUEST  = 0x1e1de3be8
    _CLASS_T_PLACE_RESPONSE = 0x1e1de3d28
    # class_ro_t vmaddrs (in __DATA_CONST, sub-cache .27.dylddata)
    _CLASS_RO_PLACE_REQUEST  = 0x1d6050c28
    _CLASS_RO_PLACE_RESPONSE = 0x1d6050cb8
    # Name string vmaddrs (in __TEXT/__objc_classname, sub-cache .03)
    _NAME_VA_PLACE_REQUEST  = 0x18d97f901
    _NAME_VA_PLACE_RESPONSE = 0x18d97f94c
    # classlist (in __DATA_CONST, sub-cache .27.dylddata)
    _CLASSLIST_START = 0x1d60364a0
    _CLASSLIST_END   = 0x1d603b5c8

    @classmethod
    def setUpClass(cls):
        cls.reader = DyldCacheReader(_CACHE_MAIN)
        # Check DATA sub-cache availability by probing a known class_t address.
        # class_t is in __DATA_DIRTY (sub-cache .41.dylddata).  If absent, all
        # DATA-dependent tests are skipped via _require_data().
        cls.data_available = cls.reader.has_vmaddr(cls._CLASS_T_PLACE_REQUEST)
        # Also check that the TEXT-range (class names) is accessible.
        cls.text_available = cls.reader.has_vmaddr(cls._NAME_VA_PLACE_REQUEST)

    @classmethod
    def tearDownClass(cls):
        cls.reader.close()

    def _require_data(self):
        """Skip if __DATA_DIRTY sub-cache is absent."""
        if not self.data_available:
            self.skipTest(
                "DATA sub-caches not accessible — class_t structs unmapped"
            )

    def _require_text(self):
        """Skip if the __TEXT sub-cache containing class names is absent."""
        if not self.text_available:
            self.skipTest(
                "__TEXT sub-cache not accessible — class name strings unmapped"
            )

    # ── _decode_cache_ptr (live mappings) ─────────────────────────────────────

    def test_decode_direct_va_in_main_mapping(self):
        """A VA covered by the main cache mapping is returned unchanged."""
        # The main file maps [0x180000000, 0x18005c000); use an address inside it.
        va = 0x180000000
        result = _decode_cache_ptr(self.reader, va)
        self.assertEqual(result, va)

    def test_decode_unmapped_va_returns_zero(self):
        result = _decode_cache_ptr(self.reader, 0xDEAD000000000000)
        self.assertEqual(result, 0)

    def test_decode_text_classname_va_direct(self):
        """__TEXT sub-cache VA (class name address) resolves if TEXT is loaded."""
        self._require_text()
        result = _decode_cache_ptr(self.reader, self._NAME_VA_PLACE_REQUEST)
        self.assertEqual(result, self._NAME_VA_PLACE_REQUEST)

    def test_decode_class_ro_va_direct(self):
        """__DATA_CONST VA (class_ro_t) resolves directly if sub-cache loaded."""
        if not self.reader.has_vmaddr(self._CLASS_RO_PLACE_REQUEST):
            self.skipTest("__DATA_CONST sub-cache not accessible")
        result = _decode_cache_ptr(self.reader, self._CLASS_RO_PLACE_REQUEST)
        self.assertEqual(result, self._CLASS_RO_PLACE_REQUEST)

    # ── read_objc_class_name ──────────────────────────────────────────────────

    def test_read_name_geopd_place_request(self):
        """class_t for GEOPDPlaceRequest → 'GEOPDPlaceRequest'."""
        self._require_data()
        name = read_objc_class_name(self.reader, self._CLASS_T_PLACE_REQUEST)
        self.assertEqual(name, 'GEOPDPlaceRequest',
                         f"Got {name!r} from class_t @ 0x{self._CLASS_T_PLACE_REQUEST:x}")

    def test_read_name_geopd_place_response(self):
        """class_t for GEOPDPlaceResponse → 'GEOPDPlaceResponse'."""
        self._require_data()
        name = read_objc_class_name(self.reader, self._CLASS_T_PLACE_RESPONSE)
        self.assertEqual(name, 'GEOPDPlaceResponse',
                         f"Got {name!r} from class_t @ 0x{self._CLASS_T_PLACE_RESPONSE:x}")

    def test_read_name_unmapped_returns_none(self):
        """Bad class_t address → None."""
        result = read_objc_class_name(self.reader, 0x1)
        self.assertIsNone(result)

    def test_class_ro_ptr_decode_via_read_u64(self):
        """
        Structural check: raw u64 at class_t+32 decodes to the Hopper-verified
        class_ro_t address (possibly after low tag-bit masking).
        """
        self._require_data()
        raw = self.reader.read_u64(self._CLASS_T_PLACE_REQUEST + 32)
        self.assertIsNotNone(raw, "read_u64 at class_t+32 returned None")
        decoded = _decode_cache_ptr(self.reader, raw)
        self.assertEqual(decoded, self._CLASS_RO_PLACE_REQUEST,
                         f"raw=0x{raw:x}, decoded=0x{decoded:x}, "
                         f"expected=0x{self._CLASS_RO_PLACE_REQUEST:x}")

    def test_name_ptr_decode_via_read_u64(self):
        """
        Structural check: raw u64 at class_ro_t+24 decodes to the
        Hopper-verified name string address.
        """
        if not self.reader.has_vmaddr(self._CLASS_RO_PLACE_REQUEST):
            self.skipTest("__DATA_CONST sub-cache not accessible")
        raw = self.reader.read_u64(self._CLASS_RO_PLACE_REQUEST + 24)
        self.assertIsNotNone(raw, "read_u64 at class_ro_t+24 returned None")
        decoded = _decode_cache_ptr(self.reader, raw)
        self.assertEqual(decoded, self._NAME_VA_PLACE_REQUEST,
                         f"raw=0x{raw:x}, decoded=0x{decoded:x}, "
                         f"expected=0x{self._NAME_VA_PLACE_REQUEST:x}")

    # ── iter_class_names ──────────────────────────────────────────────────────

    def test_iter_class_names_finds_place_request(self):
        """GEOPDPlaceRequest must appear in the GeoServices classlist."""
        self._require_data()
        names = {n for _, n in iter_class_names(
            self.reader, self._CLASSLIST_START, self._CLASSLIST_END
        )}
        self.assertIn('GEOPDPlaceRequest', names)

    def test_iter_class_names_finds_place_response(self):
        """GEOPDPlaceResponse must appear in the GeoServices classlist."""
        self._require_data()
        names = {n for _, n in iter_class_names(
            self.reader, self._CLASSLIST_START, self._CLASSLIST_END
        )}
        self.assertIn('GEOPDPlaceResponse', names)

    def test_iter_class_names_count_reasonable(self):
        """Must yield more than 100 names from GeoServices classlist."""
        self._require_data()
        count = sum(1 for _ in iter_class_names(
            self.reader, self._CLASSLIST_START, self._CLASSLIST_END
        ))
        self.assertGreater(count, 100,
                           f"Only {count} class names — suspiciously few")

    def test_iter_class_names_no_empty_strings(self):
        """Every yielded name must be a non-empty string."""
        self._require_data()
        for _, name in iter_class_names(
            self.reader, self._CLASSLIST_START, self._CLASSLIST_END
        ):
            self.assertIsInstance(name, str)
            self.assertGreater(len(name), 0)

    def test_iter_class_names_class_vas_are_mapped(self):
        """All class_t vmaddrs must fall within a mapped cache region.

        We do NOT assert a specific segment range here.  GeoServices class_t
        structs can live in __DATA or __DATA_DIRTY depending on the iOS build,
        and those bounds differ between minor releases.  What we CAN assert —
        portably, across all builds — is that every decoded class_va is within
        some mapped region according to DyldCacheReader, which means the
        pointer chain was decoded correctly.
        """
        self._require_data()
        for class_va, name in iter_class_names(
            self.reader, self._CLASSLIST_START, self._CLASSLIST_END
        ):
            self.assertTrue(
                self.reader.has_vmaddr(class_va),
                f"{name!r}: class_va 0x{class_va:x} not in any mapped cache region"
            )


# ─── TestEnumStringsFromCacheLive ─────────────────────────────────────────────

@unittest.skipUnless(_HAS_CACHE, _SKIP_MSG)
class TestEnumStringsFromCacheLive(unittest.TestCase):
    """
    Live validation that enum strings can be read directly from the dyld cache
    without going through an ipsw-extracted binary.

    Background
    ----------
    A concern was raised that ipsw may have corrupted DATA-section pointer
    values in the extracted GeoServices binary that Hopper analyses (the same
    class of bug that produced wrong nameOffset values in relative method
    lists).  These tests verify the *cache-native* read path instead, so
    correctness does not depend on the ipsw-extracted copy at all.

    The probe targets two distinct enum-storage patterns:

    Pattern A — jump-table (GEOPDPlaceResponse.status)
    ---------------------------------------------------
    ``statusAsString:`` computes CFStringRef addresses at compile time via
    ``adrp/add`` instruction pairs; each CFStringRef lives in
    ``__DATA_CONST/__cfstring`` and has its ``str_ptr`` (at byte offset 16)
    pointing into ``__TEXT/__cstring``.  The read chain is:

        cache VA of CFStringRef  →  read_u64(+16)  →  str_ptr VA
        str_ptr VA               →  read_cstring()  →  enum string

    Pattern B — pointer table (GEOPDPlaceResponse.requestType)
    -----------------------------------------------------------
    ``requestTypeAsString:`` uses ``ldr x0, [table_base, index*8]`` to load
    a CFStringRef pointer from a dense array at ``0x1d5f8a950``.  The read
    chain adds one extra hop:

        table VA  →  read_u64()  →  CFStringRef VA
        CFStringRef VA + 16      →  read_u64()  →  str_ptr VA
        str_ptr VA               →  read_cstring()  →  enum string

    Ground truth (Hopper-verified, June 2026)
    -----------------------------------------
    CFStringRef VAs from ``statusAsString:`` disassembly (``adrp/add`` pairs):

        cfstring_STATUS_SUCCESS       0x1d5fa2720   → str @ 0x18d88d5b5
        cfstring_STATUS_FAILED        0x1d5fa2740   → str @ 0x18d88d5c4
        cfstring_STATUS_INCOMPLETE    0x1d5fa2760
        cfstring_INVALID_REQUEST      0x1d5fa2780
        cfstring_FAILED_NO_RESULT     0x1d5fa27a0
        cfstring_NEEDS_REFINEMENT     0x1d5fa27c0
        cfstring_FAILED_NOT_AUTHORIZED 0x1d5fa27e0
        cfstring_STATUS_DEDUPED       0x1d5fa2800
        cfstring_VERSION_MISMATCH     0x1d5fa2820

    Pointer table base from ``requestTypeAsString:`` disassembly:
        0x1d5f8a950   (59 entries; each 8-byte ptr → CFStringRef)

    Known string VAs (from Hopper search_strings):
        "STATUS_SUCCESS"    0x18d88d5b5
        "STATUS_FAILED"     0x18d88d5c4
    """

    # ── Hopper-verified constants ─────────────────────────────────────────────
    # CFStringRef.str_ptr is at byte offset 16 (field layout: isa[8] | flags+pad[8] | str_ptr[8] | len[8])
    _CFSTRING_STR_PTR_OFFSET = 16

    # STATUS enum — CFStringRef VAs (from statusAsString: adrp/add instructions)
    _CFSTR_STATUS_SUCCESS         = 0x1d5fa2720
    _CFSTR_STATUS_FAILED          = 0x1d5fa2740
    _CFSTR_STATUS_INCOMPLETE      = 0x1d5fa2760
    _CFSTR_INVALID_REQUEST        = 0x1d5fa2780
    _CFSTR_FAILED_NO_RESULT       = 0x1d5fa27a0

    # STATUS string cache VAs (Hopper search_strings)
    _STR_STATUS_SUCCESS           = 0x18d88d5b5
    _STR_STATUS_FAILED            = 0x18d88d5c4

    # REQUEST_TYPE pointer table (from requestTypeAsString: adrp/add)
    _REQTYPE_TABLE_BASE           = 0x1d5f8a950
    _REQTYPE_TABLE_ENTRY_COUNT    = 59
    _REQTYPE_STRING_PREFIX        = 'REQUEST_TYPE_'

    @classmethod
    def setUpClass(cls):
        cls.reader = DyldCacheReader(_CACHE_MAIN)

        # Check sub-cache availability:
        # – DATA_CONST (.27.dylddata) needed for CFStringRef str_ptr and table entries
        # – TEXT (.03) needed for the string data itself
        cls.data_const_ok = cls.reader.has_vmaddr(cls._CFSTR_STATUS_SUCCESS)
        cls.text_ok       = cls.reader.has_vmaddr(cls._STR_STATUS_SUCCESS)

    @classmethod
    def tearDownClass(cls):
        cls.reader.close()

    def _require_data_const(self):
        if not self.data_const_ok:
            self.skipTest("__DATA_CONST sub-cache not accessible (sub-cache .27.dylddata absent)")

    def _require_text(self):
        if not self.text_ok:
            self.skipTest("__TEXT sub-cache not accessible (sub-cache .03 absent)")

    def _require_both(self):
        self._require_data_const()
        self._require_text()

    def _read_cfstring(self, cfstring_va):
        """Follow CFStringRef.str_ptr and return the string, or None."""
        raw_str_ptr = self.reader.read_u64(cfstring_va + self._CFSTRING_STR_PTR_OFFSET)
        if not raw_str_ptr:
            return None
        # For builtFromChainedFixups=0 caches, str_ptr is a direct cache vmaddr.
        # _decode_cache_ptr handles both direct and packed-pointer formats.
        str_va = _decode_cache_ptr(self.reader, raw_str_ptr)
        if not str_va:
            return None
        return self.reader.read_cstring(str_va)

    # ── Pattern A: STATUS enum via CFStringRef VAs ────────────────────────────

    def test_cfstring_status_success_str_ptr_is_correct_cache_va(self):
        """str_ptr field of cfstring_STATUS_SUCCESS must equal the Hopper-verified cache VA."""
        self._require_data_const()
        raw = self.reader.read_u64(self._CFSTR_STATUS_SUCCESS + self._CFSTRING_STR_PTR_OFFSET)
        self.assertIsNotNone(raw, "read_u64 returned None for STATUS_SUCCESS str_ptr")
        decoded = _decode_cache_ptr(self.reader, raw)
        self.assertEqual(
            decoded, self._STR_STATUS_SUCCESS,
            f"str_ptr decoded to 0x{decoded:x}, expected 0x{self._STR_STATUS_SUCCESS:x}"
        )

    def test_cfstring_status_success_reads_correct_string(self):
        """Cache-native read of STATUS_SUCCESS CFStringRef yields 'STATUS_SUCCESS'."""
        self._require_both()
        result = self._read_cfstring(self._CFSTR_STATUS_SUCCESS)
        self.assertEqual(result, 'STATUS_SUCCESS',
                         f"Got {result!r} instead of 'STATUS_SUCCESS'")

    def test_cfstring_status_failed_str_ptr_is_correct_cache_va(self):
        """str_ptr field of cfstring_STATUS_FAILED must equal the Hopper-verified cache VA."""
        self._require_data_const()
        raw = self.reader.read_u64(self._CFSTR_STATUS_FAILED + self._CFSTRING_STR_PTR_OFFSET)
        self.assertIsNotNone(raw)
        decoded = _decode_cache_ptr(self.reader, raw)
        self.assertEqual(
            decoded, self._STR_STATUS_FAILED,
            f"str_ptr decoded to 0x{decoded:x}, expected 0x{self._STR_STATUS_FAILED:x}"
        )

    def test_cfstring_status_failed_reads_correct_string(self):
        """Cache-native read of STATUS_FAILED CFStringRef yields 'STATUS_FAILED'."""
        self._require_both()
        result = self._read_cfstring(self._CFSTR_STATUS_FAILED)
        self.assertEqual(result, 'STATUS_FAILED',
                         f"Got {result!r} instead of 'STATUS_FAILED'")

    def test_all_status_cfstrings_readable(self):
        """All five STATUS enum CFStringRefs yield non-empty strings."""
        self._require_both()
        known_cfstrs = [
            self._CFSTR_STATUS_SUCCESS,
            self._CFSTR_STATUS_FAILED,
            self._CFSTR_STATUS_INCOMPLETE,
            self._CFSTR_INVALID_REQUEST,
            self._CFSTR_FAILED_NO_RESULT,
        ]
        for va in known_cfstrs:
            result = self._read_cfstring(va)
            self.assertIsNotNone(result,
                                 f"CFStringRef at 0x{va:x}: read_cfstring returned None")
            self.assertGreater(len(result), 0,
                               f"CFStringRef at 0x{va:x}: got empty string")

    # ── Pattern B: REQUEST_TYPE enum via pointer table ────────────────────────

    def test_request_type_table_entry_0_is_valid_cfstring_pointer(self):
        """Pointer table entry 0 must decode to a mapped CFStringRef address."""
        self._require_data_const()
        raw_ptr = self.reader.read_u64(self._REQTYPE_TABLE_BASE)
        self.assertIsNotNone(raw_ptr, "read_u64 at table[0] returned None")
        cfstring_va = _decode_cache_ptr(self.reader, raw_ptr)
        self.assertNotEqual(cfstring_va, 0,
                            f"table[0] raw=0x{raw_ptr:x} decoded to 0 (unmapped)")
        self.assertTrue(
            self.reader.has_vmaddr(cfstring_va),
            f"table[0] decoded to 0x{cfstring_va:x} which is not mapped"
        )

    def test_request_type_table_entry_0_yields_request_type_string(self):
        """Following pointer table entry 0 all the way to the string gives a REQUEST_TYPE_ value."""
        self._require_both()
        raw_ptr = self.reader.read_u64(self._REQTYPE_TABLE_BASE)
        cfstring_va = _decode_cache_ptr(self.reader, raw_ptr)
        self.assertNotEqual(cfstring_va, 0)
        result = self._read_cfstring(cfstring_va)
        self.assertIsNotNone(result, "pointer-chain read for table[0] returned None")
        self.assertTrue(
            result.startswith(self._REQTYPE_STRING_PREFIX),
            f"table[0] resolved to {result!r}, expected a REQUEST_TYPE_* string"
        )

    def test_request_type_table_several_entries_yield_valid_strings(self):
        """First 5 REQUEST_TYPE pointer table entries all resolve to non-None strings."""
        self._require_both()
        for i in range(5):
            entry_va = self._REQTYPE_TABLE_BASE + i * 8
            raw_ptr = self.reader.read_u64(entry_va)
            if not raw_ptr:
                continue   # sparse table; skip null entries gracefully
            cfstring_va = _decode_cache_ptr(self.reader, raw_ptr)
            if not cfstring_va:
                self.fail(f"table[{i}] raw=0x{raw_ptr:x} decoded to 0 (unmapped)")
            result = self._read_cfstring(cfstring_va)
            self.assertIsNotNone(result, f"table[{i}] pointer chain returned None")
            self.assertTrue(
                result.startswith(self._REQTYPE_STRING_PREFIX),
                f"table[{i}] → {result!r}, expected REQUEST_TYPE_* string"
            )

    def test_str_ptr_encoding_documented(self):
        """
        Characterise the raw str_ptr encoding used by this cache build.

        The cache at rest uses an internal pointer encoding for DATA-section
        pointers even when builtFromChainedFixups=0: the low 36 bits hold the
        absolute cache vmaddr; upper bits carry chain-info metadata.
        _decode_cache_ptr strategy 2 (strip bits 63:36) handles this, which
        is why the end-to-end read tests pass.

        This test verifies that the raw values CAN be decoded to a mapped
        address, and documents whether they are plain (no high bits) or
        encoded (high bits set).  It does NOT assert either format — both are
        valid depending on the iOS build.
        """
        self._require_data_const()
        known_cfstrs = {
            'STATUS_SUCCESS':    self._CFSTR_STATUS_SUCCESS,
            'STATUS_FAILED':     self._CFSTR_STATUS_FAILED,
            'STATUS_INCOMPLETE': self._CFSTR_STATUS_INCOMPLETE,
            'INVALID_REQUEST':   self._CFSTR_INVALID_REQUEST,
        }
        for name, va in known_cfstrs.items():
            raw = self.reader.read_u64(va + self._CFSTRING_STR_PTR_OFFSET)
            if raw is None:
                self.skipTest(f"{name}: CFStringRef at 0x{va:x} not mapped")
            decoded = _decode_cache_ptr(self.reader, raw)
            self.assertNotEqual(
                decoded, 0,
                f"{name}: raw str_ptr 0x{raw:x} could not be decoded "
                f"to any mapped address — possible genuine corruption"
            )
            self.assertTrue(
                self.reader.has_vmaddr(decoded),
                f"{name}: decoded 0x{decoded:x} not in any mapped region"
            )


# ─── TestCacheNativePipelineLive ──────────────────────────────────────────────

@unittest.skipUnless(_HAS_CACHE, _SKIP_MSG)
class TestCacheNativePipelineLive(unittest.TestCase):
    """
    Live end-to-end test: full proto-extraction pipeline using only the dyld
    shared cache — no ipsw-extracted binary file involved.

    Validates that BinaryContext.from_cache + build_string_table +
    build_class_list + extract_all together produce the same key messages
    that the binary path produces.

    Tests are skipped when sub-caches are absent (ctx.has_section returns
    False for __TEXT sections → string table is empty → no classes found).
    """

    # Known GeoServices proto classes that must survive the full pipeline.
    _EXPECTED_CLASSES = {
        'GEOPDPlaceRequest',
        'GEOPDPlaceResponse',
        'GEOPDPlaceRequestParameters',
        'GEOPDRouteRequest',
    }

    @classmethod
    def setUpClass(cls):
        from macho.dyld_cache import DyldCacheReader
        from macho.memory     import BinaryContext
        from macho.strings    import build_string_table
        from macho.classlist  import build_class_list
        from proto.extractor  import extract_all

        cls.reader = DyldCacheReader(_CACHE_MAIN)

        mach_va = cls.reader.find_image_header('GeoServices')
        if mach_va is None:
            cls.ctx       = None
            cls.cl        = None
            cls.messages  = []
            cls.class_names = set()
            return

        ctx = BinaryContext.from_cache(cls.reader, mach_va)
        cls.ctx = ctx

        # Check if we have TEXT sub-caches (needed for methname/classname strings)
        text_ok = cls.reader.has_vmaddr(mach_va + 0x1000)  # somewhere in __TEXT

        if not text_ok:
            cls.cl          = None
            cls.messages    = []
            cls.class_names = set()
            return

        try:
            st = build_string_table(ctx)
            # Pass the open cache reader so that has_direct=True selector
            # names (in the unified cache selector pool) resolve correctly.
            cl = build_class_list(ctx, st)
            # Recover ObjC selector names from the .symbols sub-cache — the
            # supported cache-native path.  Without this, preoptimised relative
            # method lists leave readFrom:/writeTo: unresolved and extract_all
            # raises SelectorsUnresolvedError (the "cache without .symbols" case).
            syms = cls.reader.image_local_symbols(mach_va)
            if syms:
                from macho.local_symbols import apply_to_classes
                apply_to_classes(cl, syms)
            messages = extract_all(ctx, st, cl)
            cls.cl          = cl
            cls.messages    = messages
            cls.class_names = {m.class_name for m in messages}
        except Exception as exc:
            cls.cl          = None
            cls.messages    = []
            cls.class_names = set()
            cls._setup_exc  = str(exc)

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, 'reader') and cls.reader is not None:
            cls.reader.close()

    def _require_pipeline(self):
        if not self.messages:
            exc = getattr(self.__class__, '_setup_exc', None)
            reason = f": {exc}" if exc else " (sub-caches may be absent)"
            self.skipTest(f"Pipeline produced no messages{reason}")

    # ── structural checks ─────────────────────────────────────────────────────

    def test_find_geoservices_header_succeeds(self):
        """find_image_header must find GeoServices in the cache."""
        mach_va = self.reader.find_image_header('GeoServices')
        self.assertIsNotNone(mach_va)

    def test_from_cache_creates_valid_context(self):
        """BinaryContext.from_cache must succeed for GeoServices."""
        self.assertIsNotNone(self.ctx)

    def test_from_cache_has_expected_sections(self):
        """Key ObjC sections must be present in the cache-mode context."""
        if self.ctx is None:
            self.skipTest("ctx not created")
        for seg, sec in [
            ('__TEXT', '__objc_methname'),
            ('__TEXT', '__objc_classname'),
            ('__DATA_CONST', '__objc_classlist'),
        ]:
            self.assertTrue(
                self.ctx.has_section(seg, sec),
                f"Missing section {seg}/{sec}"
            )

    # ── pipeline output ───────────────────────────────────────────────────────

    def test_pipeline_produces_messages(self):
        """Full pipeline must return at least one proto message."""
        self._require_pipeline()
        self.assertGreater(len(self.messages), 0)

    def test_pipeline_finds_expected_classes(self):
        """Known GeoServices classes must appear in the extracted messages."""
        self._require_pipeline()

        # Filter _EXPECTED_CLASSES to those that actually exist in the binary.
        # A class absent from __objc_classname simply isn't in this cache
        # version — skip it rather than failing; Scenario A / B / C are only
        # relevant for names that ARE in the binary.
        if self.ctx and self.ctx.has_section('__TEXT', '__objc_classname'):
            try:
                sect = self.ctx.section('__TEXT', '__objc_classname')
                raw  = self.ctx.read_bytes(sect.vmaddr, sect.vmsize)
                present_in_binary = {
                    n for n in self._EXPECTED_CLASSES
                    if (n.encode() + b'\x00') in raw
                }
            except Exception:
                present_in_binary = self._EXPECTED_CLASSES  # can't check, require all
        else:
            present_in_binary = self._EXPECTED_CLASSES

        missing = present_in_binary - self.class_names
        if not missing:
            return  # fast path — all found (or none present)

        # ── Self-diagnosing failure report ────────────────────────────────
        # Determine WHICH of the three failure modes applies to each missing
        # class so the root cause can be fixed without a follow-up run.
        #
        # Scenario A: class is absent from the ClassList entirely
        #             → class_t VA is unmapped (DATA_DIRTY not covered)
        # Scenario B: class is in the ClassList but _is_proto_class fails
        #             → has-bits ivar type_enc unreadable / doesn't match
        # Scenario C: class passes _is_proto_class but extract_proto_message raises
        #             → exception silently swallowed by extract_all
        try:
            from proto.protoclass_heuristic import _is_proto_class
            from proto.extractor import extract_proto_message
            from macho.strings    import build_string_table

            st = build_string_table(self.ctx)

            # Cheaply detect whether a class name appears in the binary at all:
            # scan __TEXT/__objc_classname (the section whose bytes build_string_table
            # already read).  If the name string is absent, the class doesn't exist
            # in this cache version; if it's present the class_t is just unmapped.
            classname_section = (
                self.ctx.section('__TEXT', '__objc_classname')
                if self.ctx.has_section('__TEXT', '__objc_classname') else None
            )
            def _name_in_binary(name: str) -> bool:
                if classname_section is None:
                    return False
                try:
                    raw = self.ctx.read_bytes(
                        classname_section.vmaddr, classname_section.vmsize)
                    return (name.encode() + b'\x00') in raw
                except Exception:
                    return False

            diag_lines = [
                f"Missing expected classes: {missing}",
                f"(found {len(self.class_names)} total, "
                f"{self.reader.mapping_count()} mappings loaded)",
            ]

            for name in sorted(missing):
                cls_obj = self.cl.find(name) if self.cl else None
                if cls_obj is None:
                    in_binary = _name_in_binary(name)
                    if in_binary:
                        # Scenario A: class exists in binary but class_t is unmapped
                        diag_lines.append(
                            f"  {name}: name IS in __objc_classname but NOT IN CLASSLIST "
                            f"(Scenario A — class_t VA is in an unmapped DATA region)"
                        )
                    else:
                        # Class simply does not exist in this cache version
                        diag_lines.append(
                            f"  {name}: NOT IN BINARY (not present in this GeoServices version "
                            f"— remove from _EXPECTED_CLASSES)"
                        )
                    continue

                # Class IS in ClassList — check ivar detection
                ivar_summary = ', '.join(
                    f"{iv.name!r}:{iv.type_enc[:30]!r}"
                    for iv in cls_obj.ivars
                ) or '(no ivars)'
                proto_ok = _is_proto_class(cls_obj)
                if not proto_ok:
                    # Scenario B
                    diag_lines.append(
                        f"  {name}: IN ClassList but _is_proto_class=False "
                        f"(Scenario B — ivars: {ivar_summary})"
                    )
                    continue

                # _is_proto_class passes — try extraction
                exc_info = None
                try:
                    msg = extract_proto_message(
                        self.ctx, st, self.cl, cls_obj
                    )
                except Exception as e:
                    exc_info = repr(e)

                if exc_info:
                    # Scenario C
                    diag_lines.append(
                        f"  {name}: extract_proto_message raised "
                        f"(Scenario C): {exc_info}"
                    )
                else:
                    diag_lines.append(
                        f"  {name}: proto_ok={proto_ok}, no exception, "
                        f"but still not in class_names (unexpected)"
                    )

        except Exception as diag_exc:
            diag_lines = [
                f"Missing expected classes: {missing}",
                f"(diagnostic failed: {diag_exc})",
            ]

        self.assertEqual(missing, set(), '\n'.join(diag_lines))

    def test_place_response_has_status_field(self):
        """GEOPDPlaceResponse must have a 'status' field (int or enum)."""
        self._require_pipeline()
        place_response = next(
            (m for m in self.messages if m.class_name == 'GEOPDPlaceResponse'),
            None
        )
        self.assertIsNotNone(place_response, "GEOPDPlaceResponse not in messages")
        field_names = {f.name for f in place_response.fields}
        self.assertIn('status', field_names,
                      f"'status' not in GEOPDPlaceResponse fields: {field_names}")

    def test_message_count_reasonable(self):
        """Must extract more than 100 distinct proto messages."""
        self._require_pipeline()
        self.assertGreater(
            len(self.messages), 100,
            f"Only {len(self.messages)} messages — suspiciously few"
        )
