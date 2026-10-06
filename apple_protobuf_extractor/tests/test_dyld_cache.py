"""
tests/test_dyld_cache.py — Tests for macho/dyld_cache.py and its integration
with _parse_relative_method in macho/classlist.py.

Test classes
------------
TestDyldCacheReaderSynthetic
    Unit tests using in-memory / temp-file cache files.  No real cache needed.
    Covers: magic validation, mapping arithmetic, cstring reads, boundary
    conditions, error handling, has_vmaddr, mapping_count, context manager.

TestDyldCacheSplitCache
    Tests with actual on-disk temp files for the split-cache code path.
    Covers: sub-cache entry parsing, sub-cache mapping loading, graceful skip
    of missing sub-caches, read_cstring spanning the sub-cache.

TestDyldCacheClasslistIntegration
    Unit-level integration tests for _parse_relative_method name resolution.
    Uses synthetic Mach-O binaries (via conftest helpers) and temp cache files.
    Covers: binary-only resolution (Step 1 local methname, unmapped → None) and
    Step 1b cache-native has_direct selector resolution through a from_cache ctx.

TestDyldCacheReaderLive
    Live smoke-tests against the real cache files in /mnt/user-data/uploads/.
    Skipped automatically when files are absent.
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

from macho.dyld_cache import (
    AmbiguousImageError,
    DyldCacheReader,
    ImageNotFoundError,
)
from macho.memory     import BinaryContext
from macho.strings    import StringTable
from macho.classlist  import _parse_relative_method, build_class_list

from tests.conftest import build_binary, ptr64


# ─── Synthetic cache builder ──────────────────────────────────────────────────

_MAGIC_ARM64  = b'dyld_v1   arm64\x00'
_MAGIC_ARM64E = b'dyld_v1  arm64e\x00'

# Offsets in dyld_cache_header used by DyldCacheReader
_HDR_MAPPING_OFF  = 0x10
_HDR_MAPPING_CNT  = 0x14
_HDR_SUBCACHE_OFF = 0x188
_HDR_SUBCACHE_CNT = 0x18c
_HDR_SIZE         = 0x1a0   # bytes we write (rest are zero-padded)
_MAP_START        = 0x200   # conventional offset for first mapping entry


def _pack_cache(
    vmaddr:    int,
    content:   bytes,
    *,
    magic:     bytes = _MAGIC_ARM64,
    subcaches: list  = (),   # list of (ext_str, vm_offset) → for main-file entries only
) -> bytes:
    """
    Build a minimal dyld shared cache binary suitable for DyldCacheReader.

    One mapping: vmaddr → content (fileOffset placed right after the header).

    subcaches: sequence of (ext_str, vm_offset) tuples written into the
        subCacheArray.  These make the main-file reader aware that sub-cache
        files exist, but the caller must actually write those files separately.
    """
    map_count  = 1
    sub_count  = len(subcaches)

    # Sub-cache entries start right after the mapping entry
    sub_start  = _MAP_START + map_count * 32         # 32 bytes per mapping entry
    # Content starts after sub-cache entries (with 4 KiB alignment)
    raw_after  = sub_start + sub_count * 56          # 56 bytes per sub-cache entry
    content_off = (raw_after + 0xfff) & ~0xfff       # page-align

    total_size = content_off + len(content)
    buf        = bytearray(total_size)

    # Header
    buf[0:16] = magic
    struct.pack_into('<I', buf, _HDR_MAPPING_OFF, _MAP_START)
    struct.pack_into('<I', buf, _HDR_MAPPING_CNT, map_count)
    if subcaches:
        struct.pack_into('<I', buf, _HDR_SUBCACHE_OFF, sub_start)
        struct.pack_into('<I', buf, _HDR_SUBCACHE_CNT, sub_count)

    # Mapping entry: vmaddr, size, fileOffset, maxProt, initProt
    struct.pack_into('<QQQ', buf, _MAP_START, vmaddr, len(content), content_off)
    struct.pack_into('<I',   buf, _MAP_START + 24, 5)   # R+X
    struct.pack_into('<I',   buf, _MAP_START + 28, 5)

    # Sub-cache entries
    for i, (ext, vm_off) in enumerate(subcaches):
        off = sub_start + i * 56
        # uuid[16]: fill with index bytes for distinctiveness
        buf[off:off+16] = bytes([i & 0xff] * 16)
        struct.pack_into('<Q', buf, off + 16, vm_off)
        ext_b = ext.encode('ascii')[:32]
        buf[off + 24: off + 24 + len(ext_b)] = ext_b

    # Content
    buf[content_off: content_off + len(content)] = content

    return bytes(buf)


class _TmpDir:
    """Context manager: temp directory that cleans itself up."""

    def __init__(self):
        self.path = tempfile.mkdtemp()

    def join(self, name: str) -> str:
        return os.path.join(self.path, name)

    def write(self, name: str, data: bytes) -> str:
        p = self.join(name)
        with open(p, 'wb') as f:
            f.write(data)
        return p

    def __enter__(self):
        return self

    def __exit__(self, *_):
        shutil.rmtree(self.path, ignore_errors=True)


# ─── TestDyldCacheReaderSynthetic ─────────────────────────────────────────────

class TestDyldCacheReaderSynthetic(unittest.TestCase):
    """Unit tests using temp-file caches.  No real device cache needed."""

    # ── helpers ──────────────────────────────────────────────────────────────

    def _single(self, vmaddr: int, content: bytes) -> str:
        """Write a single-file cache to a temp dir; return the main path."""
        data = _pack_cache(vmaddr, content)
        self._tmpdir = _TmpDir()
        path = self._tmpdir.write('dyld_shared_cache_arm64', data)
        return path

    def tearDown(self):
        if hasattr(self, '_tmpdir'):
            self._tmpdir.__exit__(None, None, None)

    # ── magic validation ─────────────────────────────────────────────────────

    def test_invalid_magic_raises(self):
        with _TmpDir() as d:
            p = d.write('not_a_cache', b'not_dyld_data_here_at_all_xxxxx')
            with self.assertRaises(ValueError):
                DyldCacheReader(p)

    def test_arm64e_magic_accepted(self):
        content = b'selector\x00'
        data    = _pack_cache(0x180000000, content, magic=_MAGIC_ARM64E)
        with _TmpDir() as d:
            p = d.write('dyld_shared_cache_arm64e', data)
            with DyldCacheReader(p) as r:
                self.assertEqual(r.mapping_count(), 1)

    def test_truncated_file_raises(self):
        # A file whose 7-byte 'dyld_v1' prefix matches but whose header is too
        # short (< 16 bytes) hits _check_magic's `len(hdr) < 16` guard, which
        # raises ValueError("Not a dyld shared cache: ...").  Assert that exact
        # type + message rather than a bare Exception, so this cannot pass on an
        # unrelated crash (e.g. a struct.error from some later half-read field).
        with _TmpDir() as d:
            p = d.write('short', b'dyld_v1')   # magic prefix but too short for any fields
            with self.assertRaisesRegex(ValueError, r'Not a dyld shared cache'):
                DyldCacheReader(p)

    # ── basic cstring reads ──────────────────────────────────────────────────

    def test_single_mapping_cstring(self):
        vmaddr = 0x180000000
        path   = self._single(vmaddr, b'hello\x00world\x00')
        with DyldCacheReader(path) as r:
            self.assertEqual(r.read_cstring(vmaddr),         'hello')
            self.assertEqual(r.read_cstring(vmaddr + 6),     'world')

    def test_cstring_adjacent_strings(self):
        vmaddr  = 0x200000000
        content = b'alloc\x00init\x00dealloc\x00'
        path    = self._single(vmaddr, content)
        with DyldCacheReader(path) as r:
            self.assertEqual(r.read_cstring(vmaddr),      'alloc')
            self.assertEqual(r.read_cstring(vmaddr + 6),  'init')
            self.assertEqual(r.read_cstring(vmaddr + 11), 'dealloc')

    def test_empty_cstring(self):
        vmaddr  = 0x100000000
        content = b'\x00next\x00'    # empty string at base, then 'next'
        path    = self._single(vmaddr, content)
        with DyldCacheReader(path) as r:
            self.assertEqual(r.read_cstring(vmaddr),     '')
            self.assertEqual(r.read_cstring(vmaddr + 1), 'next')

    def test_vmaddr_at_mapping_start(self):
        vmaddr  = 0x100000000
        content = b'start\x00'
        path    = self._single(vmaddr, content)
        with DyldCacheReader(path) as r:
            self.assertEqual(r.read_cstring(vmaddr), 'start')

    def test_vmaddr_one_before_end_single_byte_string(self):
        """Last byte of a mapping that is a null terminator → empty string."""
        vmaddr  = 0x100000000
        content = b'\x00'           # single null — empty string
        path    = self._single(vmaddr, content)
        with DyldCacheReader(path) as r:
            self.assertEqual(r.read_cstring(vmaddr), '')

    # ── None / error cases ───────────────────────────────────────────────────

    def test_unmapped_address_returns_none(self):
        vmaddr = 0x180000000
        path   = self._single(vmaddr, b'data\x00')
        with DyldCacheReader(path) as r:
            self.assertIsNone(r.read_cstring(0x200000000))

    def test_address_just_past_end_returns_none(self):
        vmaddr  = 0x180000000
        content = b'hi\x00'
        path    = self._single(vmaddr, content)
        with DyldCacheReader(path) as r:
            self.assertIsNone(r.read_cstring(vmaddr + len(content)))

    def test_max_len_guard_returns_none(self):
        """A string longer than max_len has no null within the window → None."""
        vmaddr  = 0x100000000
        content = b'a' * 200 + b'\x00'
        path    = self._single(vmaddr, content)
        with DyldCacheReader(path) as r:
            self.assertIsNone(r.read_cstring(vmaddr, max_len=10))

    def test_exact_max_len_string_returned(self):
        """A string of exactly max_len characters (then null) is returned."""
        vmaddr  = 0x100000000
        content = b'x' * 50 + b'\x00'
        path    = self._single(vmaddr, content)
        with DyldCacheReader(path) as r:
            result = r.read_cstring(vmaddr, max_len=50)
            self.assertEqual(result, 'x' * 50)

    def test_no_null_within_mapping_returns_none(self):
        """Mapping contains no null terminator at all → None."""
        vmaddr  = 0x100000000
        content = b'AAAAAAAAAA'   # no null
        path    = self._single(vmaddr, content)
        with DyldCacheReader(path) as r:
            self.assertIsNone(r.read_cstring(vmaddr))

    def test_non_utf8_returns_none(self):
        vmaddr  = 0x100000000
        content = b'\x80\x81\x82\x00'   # invalid UTF-8 leading bytes
        path    = self._single(vmaddr, content)
        with DyldCacheReader(path) as r:
            self.assertIsNone(r.read_cstring(vmaddr))

    # ── has_vmaddr ───────────────────────────────────────────────────────────

    def test_has_vmaddr_in_range(self):
        vmaddr  = 0x180000000
        content = b'\x00' * 0x1000
        path    = self._single(vmaddr, content)
        with DyldCacheReader(path) as r:
            self.assertTrue(r.has_vmaddr(vmaddr))
            self.assertTrue(r.has_vmaddr(vmaddr + 0x800))
            self.assertTrue(r.has_vmaddr(vmaddr + 0xfff))

    def test_has_vmaddr_at_exact_end_is_false(self):
        vmaddr  = 0x180000000
        content = b'\x00' * 0x100
        path    = self._single(vmaddr, content)
        with DyldCacheReader(path) as r:
            self.assertFalse(r.has_vmaddr(vmaddr + 0x100))

    def test_has_vmaddr_false_for_unmapped(self):
        vmaddr = 0x180000000
        path   = self._single(vmaddr, b'\x00' * 16)
        with DyldCacheReader(path) as r:
            self.assertFalse(r.has_vmaddr(0x300000000))

    # ── mapping_count ────────────────────────────────────────────────────────

    def test_mapping_count_single_file(self):
        path = self._single(0x100000000, b'\x00' * 4)
        with DyldCacheReader(path) as r:
            self.assertEqual(r.mapping_count(), 1)

    # ── context manager ──────────────────────────────────────────────────────

    def test_context_manager_closes_handles(self):
        path = self._single(0x100000000, b'test\x00')
        r = DyldCacheReader(path)
        r.__enter__()
        self.assertEqual(r.read_cstring(0x100000000), 'test')
        r.__exit__(None, None, None)
        # After close, _fhs should be empty
        self.assertEqual(len(r._fhs), 0)

    def test_with_statement_works(self):
        path = self._single(0x100000000, b'ok\x00')
        with DyldCacheReader(path) as r:
            self.assertEqual(r.read_cstring(0x100000000), 'ok')


# ─── TestDyldCacheSplitCache ──────────────────────────────────────────────────

class TestDyldCacheSplitCache(unittest.TestCase):
    """Tests with actual on-disk temp files for the split-cache code path."""

    def setUp(self):
        self.tmpdir = _TmpDir()

    def tearDown(self):
        self.tmpdir.__exit__(None, None, None)

    def _write_split(self, main_vm, main_content, sub_entries):
        """
        Write a main cache + sub-cache files.

        sub_entries: list of (ext, vm_offset, sub_content) tuples.
            vm_offset is relative to main_vm (used in sub-cache entry) and
            sub_content is placed at the sub-cache file's own vmaddr.
        """
        subcache_refs = [(ext, vm_off) for ext, vm_off, _ in sub_entries]
        main_data = _pack_cache(main_vm, main_content, subcaches=subcache_refs)
        main_path = self.tmpdir.write('dyld_shared_cache_arm64', main_data)

        for ext, vm_off, sub_content in sub_entries:
            sub_vmaddr = main_vm + vm_off
            sub_data   = _pack_cache(sub_vmaddr, sub_content)
            self.tmpdir.write('dyld_shared_cache_arm64' + ext, sub_data)

        return main_path

    # ── loading ──────────────────────────────────────────────────────────────

    def test_subcache_mappings_loaded(self):
        path = self._write_split(
            main_vm      = 0x180000000,
            main_content = b'main\x00',
            sub_entries  = [('.01', 0x1000, b'sub01\x00')],
        )
        with DyldCacheReader(path) as r:
            self.assertEqual(r.mapping_count(), 2)

    def test_two_subcaches_loaded(self):
        path = self._write_split(
            main_vm      = 0x180000000,
            main_content = b'main\x00',
            sub_entries  = [
                ('.01', 0x10000,  b'sub01\x00'),
                ('.02', 0x20000,  b'sub02\x00'),
            ],
        )
        with DyldCacheReader(path) as r:
            self.assertEqual(r.mapping_count(), 3)

    def test_missing_subcache_skipped_gracefully(self):
        """If a sub-cache file is absent, no exception is raised."""
        # Write main that references '.01' but don't write .01 file
        main_data = _pack_cache(
            0x180000000, b'main\x00',
            subcaches=[('.01', 0x1000)],
        )
        path = self.tmpdir.write('dyld_shared_cache_arm64', main_data)
        import warnings as _w
        with _w.catch_warnings(record=True) as caught:
            _w.simplefilter('always')
            with DyldCacheReader(path) as r:
                # Only main mapping loaded; no crash
                self.assertEqual(r.mapping_count(), 1)
                self.assertEqual(r.read_cstring(0x180000000), 'main')
                # New API: missing count / paths are tracked
                self.assertEqual(r.missing_subcache_count(), 1)
                missing = r.missing_subcache_paths()
                self.assertEqual(len(missing), 1)
                self.assertTrue(missing[0].endswith('.01'),
                                f"expected .01 suffix, got {missing[0]!r}")
        # A UserWarning should have been emitted for the missing file
        user_warns = [w for w in caught if issubclass(w.category, UserWarning)]
        self.assertEqual(len(user_warns), 1,
                         f"expected 1 UserWarning, got {len(user_warns)}: {caught}")
        self.assertIn('1/1', str(user_warns[0].message))
        self.assertIn('.01', str(user_warns[0].message))

    def test_all_subcaches_found_no_warning(self):
        """When all sub-caches are present, no UserWarning is emitted."""
        path = self._write_split(
            main_vm      = 0x180000000,
            main_content = b'main\x00',
            sub_entries  = [('.01', 0x10000, b'sub\x00')],
        )
        import warnings as _w
        with _w.catch_warnings(record=True) as caught:
            _w.simplefilter('always')
            with DyldCacheReader(path) as r:
                self.assertEqual(r.missing_subcache_count(), 0)
                self.assertEqual(r.missing_subcache_paths(), [])
        user_warns = [w for w in caught if issubclass(w.category, UserWarning)]
        self.assertEqual(len(user_warns), 0,
                         f"unexpected warning(s): {user_warns}")

    def test_verbose_prints_to_stderr(self):
        """verbose=True prints diagnostic lines to stderr without crashing."""
        import io
        main_data = _pack_cache(
            0x180000000, b'main\x00',
            subcaches=[('.01', 0x1000)],
        )
        path = self.tmpdir.write('dyld_shared_cache_arm64', main_data)
        import warnings as _w
        captured = io.StringIO()
        real_stderr = sys.stderr
        try:
            sys.stderr = captured
            with _w.catch_warnings(record=True):
                _w.simplefilter('always')
                with DyldCacheReader(path, verbose=True):
                    pass
        finally:
            sys.stderr = real_stderr
        output = captured.getvalue()
        # Should mention the header fields and the missing file
        self.assertIn('sub_off=', output)
        self.assertIn('sub_cnt=', output)
        self.assertIn('.01', output)
        self.assertIn('MISSING', output)

    # ── reads spanning main and sub-cache ────────────────────────────────────

    def test_read_from_main(self):
        path = self._write_split(
            main_vm      = 0x180000000,
            main_content = b'fromMain\x00',
            sub_entries  = [('.01', 0x10000, b'fromSub\x00')],
        )
        with DyldCacheReader(path) as r:
            self.assertEqual(r.read_cstring(0x180000000), 'fromMain')

    def test_read_from_subcache(self):
        path = self._write_split(
            main_vm      = 0x180000000,
            main_content = b'main\x00',
            sub_entries  = [('.01', 0x10000, b'subSelector:\x00')],
        )
        with DyldCacheReader(path) as r:
            # Sub-cache .01 maps to 0x180000000 + 0x10000 = 0x180010000
            self.assertEqual(r.read_cstring(0x180010000), 'subSelector:')

    def test_unmapped_between_main_and_sub(self):
        """Gap between main and sub-cache mapping should return None."""
        path = self._write_split(
            main_vm      = 0x180000000,
            main_content = b'\x00' * 0x100,         # ends at 0x180000100
            sub_entries  = [('.01', 0x10000, b'\x00')],  # starts at 0x180010000
        )
        with DyldCacheReader(path) as r:
            # Address in gap: 0x180001000 → not mapped
            self.assertIsNone(r.read_cstring(0x180001000))

    def test_read_multiple_strings_from_subcache(self):
        content = b'alpha\x00beta\x00gamma\x00'
        path = self._write_split(
            main_vm      = 0x180000000,
            main_content = b'\x00',
            sub_entries  = [('.01', 0x1000, content)],
        )
        base = 0x180001000
        with DyldCacheReader(path) as r:
            self.assertEqual(r.read_cstring(base),      'alpha')
            self.assertEqual(r.read_cstring(base + 6),  'beta')
            self.assertEqual(r.read_cstring(base + 11), 'gamma')


# ─── TestDyldCacheClasslistIntegration ───────────────────────────────────────

class TestDyldCacheClasslistIntegration(unittest.TestCase):
    """
    Integration tests for _parse_relative_method name resolution.

    After hybrid (binary+cache) mode was removed, _parse_relative_method no
    longer takes a cache argument: selector cstrings are read entirely through
    ``ctx`` (which routes to the cache reader for a from_cache context).  These
    tests cover the two surviving paths — binary-only resolution and Step 1b
    cache-native has_direct resolution.

    Binary layout for the relative-method tests:
      __TEXT at 0x18c000000 (holds method entry — 12 bytes of s32 fields)

    The method entry:
      name_rel  = (sel_va - method_va) masked to s32  → sel_ref_va unmapped
      types_rel = 0  → types = ''
      imp_rel   = 0  → imp = method_va + 8
    """

    # Binary method vmaddr
    METHOD_VA   = 0x18c000000
    # NEGATIVE offset so sel_ref_va < METHOD_VA → clearly outside the binary.
    SEL_REL     = -(0x01000000)          # -16 MiB → sel_ref_va = METHOD_VA - 0x01000000
    SEL_VA      = METHOD_VA + SEL_REL    # = 0x18b000000

    def setUp(self):
        self.tmpdir = _TmpDir()

        # ── Binary: __TEXT at METHOD_VA with 12-byte method entry ──
        method_bytes = struct.pack('<iii', self.SEL_REL, 0, 0)
        binary_data  = build_binary([{
            'name':    '__TEXT',
            'vmaddr':  self.METHOD_VA,
            'sections': [{'name': '__text', 'content': method_bytes}],
        }])
        self.ctx     = BinaryContext(binary_data)
        self.strings = StringTable()

    def tearDown(self):
        self.tmpdir.__exit__(None, None, None)

    # ── binary-only resolution ───────────────────────────────────────────────

    def test_unmapped_selref_stays_none(self):
        """
        Binary-only: when sel_ref_va is unmapped (Format A pointer deref fails),
        the method object is still returned but its name is None.
        """
        m = _parse_relative_method(self.ctx, self.METHOD_VA, self.strings)
        self.assertIsNotNone(m)      # method object is still returned
        self.assertIsNone(m.name)    # but name is None (unmapped)
        self.assertTrue(m.is_relative)

    def test_local_methname_resolves(self):
        """
        When sel_ref_va is inside the binary's own __objc_methname, Step 1
        resolves the selector from the binary itself.
        """
        # Binary:
        #   __TEXT at 0x10000000  (contains __objc_methname with 'localSel')
        #   __DATA at 0x10002000  (contains the 12-byte method entry)
        #
        # name_rel = methname_va - method_va = 0x10000000 - 0x10002000 = -0x2000
        # sel_ref_va = 0x10002000 + (-0x2000) = 0x10000000  ← in __objc_methname ✓
        METHNAME_VA  = 0x10000000
        METHOD_VA    = 0x10002000
        sel_str      = b'localSel\x00'
        name_rel     = METHNAME_VA - METHOD_VA   # = -0x2000, fits in s32

        method_bytes = struct.pack('<iii', name_rel, 0, 0)

        binary_data = build_binary([
            {
                'name':    '__TEXT',
                'vmaddr':  METHNAME_VA,
                'sections': [{'name': '__objc_methname', 'content': sel_str}],
            },
            {
                'name':    '__DATA',
                'vmaddr':  METHOD_VA,
                'sections': [{'name': '__data', 'content': method_bytes}],
            },
        ])
        ctx = BinaryContext(binary_data)

        m = _parse_relative_method(ctx, METHOD_VA, self.strings)
        self.assertEqual(m.name, 'localSel',
                         "Step 1 must resolve a selector inside __objc_methname")

    def test_imp_computed_correctly(self):
        """IMP is pure arithmetic regardless of whether the name resolved."""
        m = _parse_relative_method(self.ctx, self.METHOD_VA, self.strings)
        # imp_rel=0 → imp = (METHOD_VA + 8) + 0
        self.assertEqual(m.imp, self.METHOD_VA + 8)

    def test_format_a_unmapped_name_va_stays_none(self):
        """
        Format A (non-direct): sel_ref_va lands in __objc_selrefs (mapped); the
        8-byte pointer there (name_va) points at a cstring address that is not
        mapped in this binary.  Binary-only resolution leaves name=None.
        """
        METHOD_VA = 0x10000000
        SELREF_VA = 0x10010000
        NAME_VA   = 0x20000000

        name_rel     = SELREF_VA - METHOD_VA
        selref_bytes = struct.pack('<Q', NAME_VA)
        method_bytes = struct.pack('<iii', name_rel, 0, 0)

        binary_data = build_binary([
            {
                'name':    '__DATA',
                'vmaddr':  SELREF_VA,
                'sections': [{'name': '__objc_selrefs', 'content': selref_bytes}],
            },
            {
                'name':    '__TEXT',
                'vmaddr':  METHOD_VA,
                'sections': [{'name': '__text', 'content': method_bytes}],
            },
        ])
        ctx = BinaryContext(binary_data)
        m = _parse_relative_method(ctx, METHOD_VA, self.strings)

        self.assertIsNotNone(m)
        self.assertIsNone(m.name,
            "Format A with unmapped name_va must leave name=None in binary-only mode")

    # ── Step 1b: has_direct=True via cache-native context ────────────────────

    def test_step1b_cache_native_ctx_resolves_has_direct_selector(self):
        """
        Step 1b: a cache-native BinaryContext (from_cache) resolves has_direct
        selectors from the unified cache selector pool through ctx.read_cstring.

        In cache-native mode, sel_ref_va for shared selectors (readFrom:,
        writeTo:, …) points into the unified cache pool, OUTSIDE the local
        __objc_methname section, so Step 1 fails.  Step 1b then calls
        ctx.read_cstring(sel_ref_va); for a cache-backed context this reads from
        the cache and succeeds.

        Layout
        ------
        Cache has content over BASE+0x0000..BASE+0x2FFF:
          BASE+0x0000  method entry (12 bytes): name_rel=0x2000, types=0, imp=0
          BASE+0x2000  selector string 'readFrom:\\0'
        (no __objc_methname section — sel_ref_va is outside any local section)
        """
        from macho.memory import BinaryContext

        BASE = 0x100000000
        METHOD_VA  = BASE + 0x0000
        SEL_VA     = BASE + 0x2000   # sel_ref_va = METHOD_VA + 0x2000
        name_rel   = SEL_VA - METHOD_VA   # = 0x2000, fits in s32

        content = bytearray(0x3000)
        # Method entry at BASE+0x0000
        struct.pack_into('<iii', content, 0x0000, name_rel, 0, 0)
        # Selector string at BASE+0x2000
        content[0x2000 : 0x2000 + 10] = b'readFrom:\x00'

        # Build a minimal cache containing this content
        MAP_OFF  = 0x200
        cont_off = (MAP_OFF + 32 + 0xfff) & ~0xfff
        total    = cont_off + len(content)
        buf      = bytearray(total)
        buf[0:16] = b'dyld_v1   arm64\x00'
        struct.pack_into('<I', buf, 0x10, MAP_OFF)   # mappingOffset
        struct.pack_into('<I', buf, 0x14, 1)          # mappingCount
        struct.pack_into('<QQQ', buf, MAP_OFF, BASE, len(content), cont_off)
        struct.pack_into('<I',   buf, MAP_OFF + 24, 5)
        struct.pack_into('<I',   buf, MAP_OFF + 28, 5)
        buf[cont_off : cont_off + len(content)] = content

        cache_path = self.tmpdir.write('dyld_shared_cache_arm64', bytes(buf))

        sec_map = {
            '__TEXT':             (BASE, BASE + 0x3000),
            '__TEXT/__text':      (METHOD_VA, METHOD_VA + 0x10),
            # NOTE: no __objc_methname section — Step 1 cannot resolve the name
        }

        with DyldCacheReader(cache_path) as reader:
            reader.image_sections = lambda va: sec_map
            ctx = BinaryContext.from_cache(reader, BASE)

            m = _parse_relative_method(ctx, METHOD_VA, self.strings,
                                       has_direct=True)

        self.assertIsNotNone(m)
        self.assertEqual(m.name, 'readFrom:',
            "Step 1b must resolve has_direct selectors via cache-native ctx")

    def test_step1b_binary_ctx_raises_gracefully_for_has_direct(self):
        """
        Step 1b: for a plain binary context (non-cache-native), sel_ref_va
        that is outside the binary's own segments raises ValueError, which
        must be caught and leave name=None (no regression).
        """
        # Plain binary with method entry; sel_ref_va is well outside the binary.
        m = _parse_relative_method(
            self.ctx, self.METHOD_VA, self.strings, has_direct=True
        )
        self.assertIsNotNone(m)
        self.assertIsNone(m.name,
            "Plain binary ctx: out-of-segment sel_ref_va must leave name=None")

    def test_step1b_cache_native_still_respects_local_methname(self):
        """
        Step 1b: when sel_ref_va IS in the local __objc_methname, Step 1
        already resolves the name; Step 1b is correctly skipped.
        """
        # Build a cache-native ctx where sel_ref_va is INSIDE __objc_methname.
        BASE = 0x100000000
        SEL_VA     = BASE + 0x0100   # inside methname section
        METHOD_VA  = BASE + 0x1000
        name_rel   = SEL_VA - METHOD_VA  # negative, fits in s32

        content = bytearray(0x2000)
        struct.pack_into('<iii', content, 0x1000, name_rel, 0, 0)  # method entry
        sel_str = b'writeTo:\x00'
        content[0x0100 : 0x0100 + len(sel_str)] = sel_str  # selector string

        MAP_OFF  = 0x200
        cont_off = (MAP_OFF + 32 + 0xfff) & ~0xfff
        total    = cont_off + len(content)
        buf      = bytearray(total)
        buf[0:16] = b'dyld_v1   arm64\x00'
        struct.pack_into('<I', buf, 0x10, MAP_OFF)
        struct.pack_into('<I', buf, 0x14, 1)
        struct.pack_into('<QQQ', buf, MAP_OFF, BASE, len(content), cont_off)
        struct.pack_into('<I',   buf, MAP_OFF + 24, 5)
        struct.pack_into('<I',   buf, MAP_OFF + 28, 5)
        buf[cont_off : cont_off + len(content)] = content

        cache_path = self.tmpdir.write('cache_step1b_methname', bytes(buf))

        sec_map = {
            '__TEXT':                  (BASE, BASE + 0x2000),
            '__TEXT/__objc_methname':  (BASE + 0x0000, BASE + 0x0800),
        }
        with DyldCacheReader(cache_path) as reader:
            reader.image_sections = lambda va: sec_map
            ctx = BinaryContext.from_cache(reader, BASE)
            # has_direct=True: Step 1 should fire since SEL_VA is in methname
            m = _parse_relative_method(ctx, METHOD_VA, self.strings,
                                       has_direct=True)

        self.assertEqual(m.name, 'writeTo:',
            "Step 1 (local methname) must resolve before Step 1b is attempted")

    # ── build_class_list API ─────────────────────────────────────────────────

    def test_build_class_list_binary_only(self):
        """build_class_list(ctx, st) resolves classes from a plain binary."""
        from tests.conftest import build_objc_binary
        binary_data = build_objc_binary([{'name': 'MyClass'}])
        ctx         = BinaryContext(binary_data)
        strings     = StringTable()

        cl = build_class_list(ctx, strings)
        self.assertIn('MyClass', cl)


# ─── TestDyldCacheReaderLive ──────────────────────────────────────────────────

def _find_cache_main() -> 'Optional[str]':
    """
    Locate the main dyld shared cache file.  Search order:

    1. MACHO_TEST_CACHE env var (see artifacts.py) — treated as a directory;
       the first of dyld_shared_cache_arm64{e} found inside it is used.
    2. The ``dylib/`` subdirectory of the data dir (see artifacts.data_dir()).

    Returns the path string if found, None otherwise.
    """
    _here = os.path.dirname(os.path.abspath(__file__))
    _root = os.path.dirname(os.path.dirname(_here))
    _names = ('dyld_shared_cache_arm64e', 'dyld_shared_cache_arm64')

    cache_dir = os.environ.get('MACHO_TEST_CACHE', '').strip()
    search_dirs = []
    if cache_dir:
        search_dirs.append(cache_dir)
    search_dirs.append(artifacts.cache_dir())

    for d in search_dirs:
        for name in _names:
            p = os.path.join(d, name)
            if os.path.isfile(p):
                return p
    return None


_CACHE_MAIN = _find_cache_main()
_HAS_CACHE  = _CACHE_MAIN is not None

_SKIP_MSG   = ('dyld shared cache not found — set MACHO_TEST_CACHE, or place '
               'cache files under <data dir>/dylib/ (see artifacts.py)')


# ── Structural discovery helpers ──────────────────────────────────────────────
# These functions derive vmaddrs from the cache's own data structures rather
# than using any hardcoded addresses, making the live tests portable across
# different iOS versions and cache builds.

_IMG_TEXT_OFF_FIELD = 0x88   # imagesTextOffset u64 in dyld_cache_header
_IMG_TEXT_CNT_FIELD = 0x90   # imagesTextCount  u64 in dyld_cache_header
_SHARED_START_FIELD = 0xe0   # sharedRegionStart u64
_SHARED_SIZE_FIELD  = 0xe8   # sharedRegionSize  u64
_IMG_TEXT_STRIDE    = 32     # sizeof(dyld_cache_image_text_info)
_LC_SEGMENT_64      = 0x19


def _parse_images_text(main_data: bytes) -> list:
    """
    Parse the dyld_cache_image_text_info array from the main cache header.
    Returns list of (load_vmaddr, path_str) for all embedded images.
    """
    img_off = struct.unpack_from('<Q', main_data, _IMG_TEXT_OFF_FIELD)[0]
    img_cnt = struct.unpack_from('<Q', main_data, _IMG_TEXT_CNT_FIELD)[0]
    if img_off == 0 or img_cnt == 0:
        return []
    results = []
    for i in range(min(int(img_cnt), 5000)):
        off = img_off + i * _IMG_TEXT_STRIDE
        if off + _IMG_TEXT_STRIDE > len(main_data):
            break
        # dyld_cache_image_text_info: uuid[16], loadAddress u64,
        #   textSegmentSize u32, pathOffset u32
        load_va  = struct.unpack_from('<Q', main_data, off + 16)[0]
        path_off = struct.unpack_from('<I', main_data, off + 28)[0]
        try:
            end  = main_data.index(b'\x00', path_off)
            path = main_data[path_off:end].decode('ascii', errors='replace')
        except (ValueError, UnicodeDecodeError):
            path = ''
        results.append((load_va, path))
    return results


def _find_macho_section(reader: DyldCacheReader,
                         macho_va: int,
                         seg: str, sec: str) -> tuple:
    """
    Read a Mach-O header from the cache at *macho_va*, walk its load
    commands and return (section_vmaddr, section_vmsize) for the named
    segment/section.  Returns (None, None) if not found.
    """
    mapping = reader._find_mapping(macho_va)
    if mapping is None:
        return None, None
    fh = reader._fh(mapping.path)
    fh.seek(mapping.translate(macho_va))
    hdr = fh.read(32768)   # header + load commands fit comfortably
    if len(hdr) < 32:
        return None, None
    ncmds = struct.unpack_from('<I', hdr, 16)[0]
    lc_off = 32
    seg_b, sec_b = seg.encode(), sec.encode()
    for _ in range(min(ncmds, 256)):
        if lc_off + 8 > len(hdr):
            break
        cmd, cmdsize = struct.unpack_from('<II', hdr, lc_off)
        if cmdsize < 8:
            break
        if cmd == _LC_SEGMENT_64 and lc_off + 72 <= len(hdr):
            segname = hdr[lc_off+8 : lc_off+24].rstrip(b'\x00')
            if segname == seg_b:
                nsects = struct.unpack_from('<I', hdr, lc_off+64)[0]
                so = lc_off + 72
                for _ in range(min(nsects, 256)):
                    if so + 80 > len(hdr):
                        break
                    sname = hdr[so : so+16].rstrip(b'\x00')
                    if sname == sec_b:
                        s_va   = struct.unpack_from('<Q', hdr, so+32)[0]
                        s_size = struct.unpack_from('<Q', hdr, so+40)[0]
                        return s_va, s_size
                    so += 80
        lc_off += cmdsize
    return None, None


def _scan_section_for_selectors(reader: DyldCacheReader,
                                  sec_va: int, sec_size: int,
                                  targets: set) -> dict:
    """
    Scan a cstring section in the cache for *targets*.
    Returns {selector_str: vmaddr}.
    """
    mapping = reader._find_mapping(sec_va)
    if mapping is None:
        return {}
    fh = reader._fh(mapping.path)
    fh.seek(mapping.translate(sec_va))
    data = fh.read(min(int(sec_size), mapping.vmend - sec_va))
    found = {}
    pos = 0
    while pos < len(data) and len(found) < len(targets):
        nul = data.find(b'\x00', pos)
        if nul == -1:
            break
        s = data[pos:nul].decode('ascii', errors='replace')
        if s in targets:
            found[s] = sec_va + pos
        pos = nul + 1
    return found


def _search_all_mappings(reader: DyldCacheReader, needle_bytes: bytes) -> 'Optional[int]':
    """
    Scan all mapped regions for *needle_bytes*.  Returns vmaddr of the first
    occurrence, or None.  Used to find selectors outside libobjc's own section.
    """
    CHUNK = 2 * 1024 * 1024   # 2 MB chunks to avoid large in-memory reads
    overlap = len(needle_bytes) - 1
    for mapping in reader._mappings:
        fh    = reader._fh(mapping.path)
        msize = mapping.vmend - mapping.vmaddr
        pos   = 0
        while pos < msize:
            read_size = min(CHUNK + overlap, msize - pos)
            fh.seek(mapping.file_offset + pos)
            chunk = fh.read(read_size)
            if not chunk:
                break
            idx = chunk.find(needle_bytes)
            if idx != -1:
                return mapping.vmaddr + pos + idx
            pos += CHUNK   # advance by CHUNK (overlap keeps boundary coverage)
    return None


@unittest.skipUnless(_HAS_CACHE, _SKIP_MSG)
class TestDyldCacheReaderLive(unittest.TestCase):
    """
    Live smoke-tests against the real cache files.

    All vmaddrs are derived structurally from the cache's own imagesText
    array and embedded Mach-O headers — no addresses are hardcoded.  The
    tests therefore work correctly with any version of the cache files.
    """

    # Selector names we verify can be resolved from the cache.
    # These are fundamental ObjC/proto runtime selectors present in every
    # iOS release; their specific vmaddrs are discovered at setUp time.
    _LIBOBJC_SELECTORS = {
        '_isDeallocating', 'alloc', 'allocWithZone:', 'autorelease',
        'class', 'dealloc', 'release', 'init',
    }
    _PROTO_SELECTOR = 'readFrom:'   # proto-runtime; lives outside libobjc

    @classmethod
    def setUpClass(cls):
        cls.reader = DyldCacheReader(_CACHE_MAIN)

        # ── Discover selector vmaddrs structurally ────────────────────────
        # 1. Parse imagesText from main cache header to find libobjc
        main_data  = open(_CACHE_MAIN, 'rb').read()
        images     = _parse_images_text(main_data)
        libobjc_va = next(
            (va for va, path in images if path == '/usr/lib/libobjc.A.dylib'),
            None,
        )

        # 2. Parse libobjc's Mach-O to find __TEXT.__objc_methname
        cls.methname_va   = None
        cls.methname_size = None
        cls.selector_vas  = {}      # {name: vmaddr} — populated below
        cls.proto_sel_va  = None

        if libobjc_va is not None:
            cls.libobjc_va = libobjc_va
            va, sz = _find_macho_section(
                cls.reader, libobjc_va, '__TEXT', '__objc_methname'
            )
            if va is not None:
                cls.methname_va   = va
                cls.methname_size = sz
                cls.selector_vas  = _scan_section_for_selectors(
                    cls.reader, va, sz, cls._LIBOBJC_SELECTORS
                )

        # 3. Locate the proto-runtime selector anywhere in the cache
        needle = cls._PROTO_SELECTOR.encode() + b'\x00'
        cls.proto_sel_va = _search_all_mappings(cls.reader, needle)

        # 4. Derive the "definitely beyond cache" address from the header
        shared_start = struct.unpack_from('<Q', main_data, _SHARED_START_FIELD)[0]
        shared_size  = struct.unpack_from('<Q', main_data, _SHARED_SIZE_FIELD)[0]
        cls.beyond_cache_va = shared_start + shared_size + 0x1000

    @classmethod
    def tearDownClass(cls):
        cls.reader.close()

    # ── structural / coverage tests ──────────────────────────────────────────

    def test_mapping_count_at_least_one(self):
        """Must have at least one mapping (the main cache file's own region)."""
        self.assertGreaterEqual(self.reader.mapping_count(), 1)

    def test_libobjc_vmaddr_is_covered(self):
        """libobjc load address (from imagesText) must be within a mapped region."""
        self.assertIsNotNone(self.libobjc_va,
                             "Could not find libobjc in cache imagesText")
        self.assertTrue(self.reader.has_vmaddr(self.libobjc_va),
                        f"libobjc vmaddr 0x{self.libobjc_va:x} not mapped")

    def test_methname_section_is_covered(self):
        """__TEXT.__objc_methname (from libobjc Mach-O header) must be mapped."""
        self.assertIsNotNone(self.methname_va,
                             "Could not locate __objc_methname in libobjc")
        self.assertTrue(self.reader.has_vmaddr(self.methname_va))

    def test_beyond_cache_not_covered(self):
        """An address beyond sharedRegionStart+sharedRegionSize must not be mapped."""
        self.assertFalse(self.reader.has_vmaddr(self.beyond_cache_va),
                         f"0x{self.beyond_cache_va:x} should be outside mapped range")

    def test_unmapped_zero_returns_none(self):
        self.assertIsNone(self.reader.read_cstring(0x1))

    # ── selector reads ───────────────────────────────────────────────────────
    # Each selector vmaddr is derived from libobjc's __objc_methname section,
    # not hardcoded.  If setUpClass could not locate a selector, the test is
    # skipped rather than failing with a misleading assertion error.

    def _va(self, sel: str) -> int:
        """Return the discovered vmaddr for *sel*, or skip the test."""
        va = self.selector_vas.get(sel)
        if va is None:
            self.skipTest(f"'{sel}' not found in libobjc __objc_methname")
        return va

    def test_read_is_deallocating(self):
        self.assertEqual(self.reader.read_cstring(self._va('_isDeallocating')),
                         '_isDeallocating')

    def test_read_alloc(self):
        self.assertEqual(self.reader.read_cstring(self._va('alloc')), 'alloc')

    def test_read_alloc_with_zone(self):
        self.assertEqual(self.reader.read_cstring(self._va('allocWithZone:')),
                         'allocWithZone:')

    def test_read_autorelease(self):
        self.assertEqual(self.reader.read_cstring(self._va('autorelease')),
                         'autorelease')

    def test_read_class(self):
        self.assertEqual(self.reader.read_cstring(self._va('class')), 'class')

    def test_read_dealloc(self):
        self.assertEqual(self.reader.read_cstring(self._va('dealloc')), 'dealloc')

    def test_read_release(self):
        self.assertEqual(self.reader.read_cstring(self._va('release')), 'release')

    def test_read_init(self):
        self.assertEqual(self.reader.read_cstring(self._va('init')), 'init')

    def test_all_libobjc_selectors_found(self):
        """All target selectors must be discoverable in libobjc's methname section."""
        missing = self._LIBOBJC_SELECTORS - set(self.selector_vas)
        self.assertEqual(missing, set(),
                         f"Selectors not found in __objc_methname: {missing}")

    # ── proto-runtime selector ───────────────────────────────────────────────

    def test_read_proto_selector(self):
        """readFrom: must be findable anywhere in the cache and readable back."""
        if self.proto_sel_va is None:
            self.skipTest(f"'{self._PROTO_SELECTOR}' not found in any mapped region")
        self.assertEqual(self.reader.read_cstring(self.proto_sel_va),
                         self._PROTO_SELECTOR)

    # ── consistency ──────────────────────────────────────────────────────────

    def test_repeated_reads_are_idempotent(self):
        """Reading the same vmaddr multiple times must return the same result."""
        va = self._va('alloc')
        for _ in range(5):
            self.assertEqual(self.reader.read_cstring(va), 'alloc')


# ─── Helpers shared by synthetic image-discovery tests ───────────────────────

def _pack_images_cache(
    entries,          # list of (load_va: int, path_str: str)
    *,
    vmaddr  = 0x100000000,
    content = b'\x00' * 16,
    magic   = _MAGIC_ARM64,
) -> bytes:
    """
    Build a minimal dyld shared cache that has a valid ``imagesText`` array.

    Layout (all in one file, no sub-caches):

    * ``0x000``: header (``0x200`` bytes, zero-padded except the key fields)
    * ``0x200``: one mapping entry (32 bytes; maps *vmaddr* to *content*)
    * ``0x220``: imagesText entries (32 bytes each)
    * immediately after entries: null-terminated path strings
    * (page-aligned): *content* bytes for the mapped region

    dyld_cache_image_text_info layout::

        uuid[16]  loadAddress u64  textSegmentSize u32  pathOffset u32
    """
    MAP_OFF      = 0x200
    IMG_TEXT_OFF = MAP_OFF + 32         # immediately after the single mapping entry

    # ── Lay out path strings ─────────────────────────────────────────────────
    paths_start  = IMG_TEXT_OFF + len(entries) * 32
    path_offsets = []
    path_blobs   = []
    cur = paths_start
    for _, path_str in entries:
        path_offsets.append(cur)
        blob = path_str.encode('utf-8') + b'\x00'
        path_blobs.append(blob)
        cur += len(blob)
    paths_data = b''.join(path_blobs)

    # ── Page-align content ───────────────────────────────────────────────────
    content_off = (cur + 0xfff) & ~0xfff
    total       = content_off + len(content)
    buf         = bytearray(total)

    # ── Header ───────────────────────────────────────────────────────────────
    buf[0:16] = magic
    struct.pack_into('<I', buf, 0x10, MAP_OFF)           # mappingOffset
    struct.pack_into('<I', buf, 0x14, 1)                 # mappingCount
    struct.pack_into('<Q', buf, 0x88, IMG_TEXT_OFF)      # imagesTextOffset
    struct.pack_into('<Q', buf, 0x90, len(entries))      # imagesTextCount

    # ── Mapping entry: vmaddr, size, fileOffset ──────────────────────────────
    struct.pack_into('<QQQ', buf, MAP_OFF, vmaddr, len(content), content_off)
    struct.pack_into('<I',   buf, MAP_OFF + 24, 5)       # maxProt  (R+X)
    struct.pack_into('<I',   buf, MAP_OFF + 28, 5)       # initProt

    # ── imagesText entries ────────────────────────────────────────────────────
    for i, ((load_va, _), path_off) in enumerate(zip(entries, path_offsets)):
        o = IMG_TEXT_OFF + i * 32
        struct.pack_into('<Q', buf, o + 16, load_va)    # loadAddress
        struct.pack_into('<I', buf, o + 24, 0x1000)     # textSegmentSize (nominal)
        struct.pack_into('<I', buf, o + 28, path_off)   # pathOffset

    # ── Path strings ─────────────────────────────────────────────────────────
    buf[paths_start : paths_start + len(paths_data)] = paths_data

    # ── Content ──────────────────────────────────────────────────────────────
    buf[content_off : content_off + len(content)] = content

    return bytes(buf)


def _build_lc_segment64(segname, vmaddr, vmsize, sections=()) -> bytes:
    """
    Build one ``LC_SEGMENT_64`` load-command blob.

    *sections* is a list of ``(sectname, addr, size)`` triples.
    The ``section_64`` struct is 80 bytes; ``segment_command_64`` header is 72 bytes.
    """
    nsects  = len(sections)
    cmdsize = 72 + nsects * 80
    buf     = bytearray(cmdsize)

    # cmd u32, cmdsize u32, segname char[16],
    # vmaddr u64, vmsize u64, fileoff u64, filesize u64,
    # maxprot i32, initprot i32, nsects u32, flags u32
    struct.pack_into('<I', buf,  0, 0x19)           # cmd = LC_SEGMENT_64
    struct.pack_into('<I', buf,  4, cmdsize)
    buf[8 : 8 + len(segname)] = segname.encode()[:16]
    struct.pack_into('<Q', buf, 24, vmaddr)
    struct.pack_into('<Q', buf, 32, vmsize)
    struct.pack_into('<I', buf, 56, 5)              # maxprot
    struct.pack_into('<I', buf, 60, 5)              # initprot
    struct.pack_into('<I', buf, 64, nsects)

    # section_64: sectname[16], segname[16], addr u64, size u64, ...
    for i, (sname, addr, sz) in enumerate(sections):
        so = 72 + i * 80
        buf[so      : so + 16] = sname.encode()[:16].ljust(16, b'\x00')
        buf[so + 16 : so + 32] = segname.encode()[:16].ljust(16, b'\x00')
        struct.pack_into('<Q', buf, so + 32, addr)
        struct.pack_into('<Q', buf, so + 40, sz)

    return bytes(buf)


def _build_macho(segments) -> bytes:
    """
    Build a minimal 64-bit Mach-O header + LC_SEGMENT_64 load commands.

    *segments*: list of ``(segname, vmaddr, vmsize, sections)`` where *sections*
    is a list of ``(sectname, addr, size)`` triples.

    Returns the raw header + load-command bytes (no __TEXT data follows).
    """
    lcs = [_build_lc_segment64(seg, va, sz, sects)
           for seg, va, sz, sects in segments]
    lc_data = b''.join(lcs)

    hdr = bytearray(32)
    struct.pack_into('<I', hdr,  0, 0xFEEDFACF)        # magic = MH_MAGIC_64
    struct.pack_into('<I', hdr,  4, 12)                 # cputype  = ARM
    struct.pack_into('<I', hdr,  8, 0)                  # cpusubtype
    struct.pack_into('<I', hdr, 12, 8)                  # filetype = MH_DYLIB
    struct.pack_into('<I', hdr, 16, len(lcs))           # ncmds
    struct.pack_into('<I', hdr, 20, len(lc_data))       # sizeofcmds
    return bytes(hdr) + lc_data


# ─── TestFindImageHeader ──────────────────────────────────────────────────────

class TestFindImageHeader(unittest.TestCase):
    """
    Unit tests for DyldCacheReader.find_image_header().

    All tests use in-memory / temp-file caches built from *_pack_images_cache*.
    No real cache file is required.
    """

    def setUp(self):
        self.tmpdir = _TmpDir()

    def tearDown(self):
        self.tmpdir.__exit__(None, None, None)

    def _make_cache(self, entries, **kwargs):
        data = _pack_images_cache(entries, **kwargs)
        path = self.tmpdir.write('dyld_shared_cache_arm64', data)
        return path

    # ── basic lookups ─────────────────────────────────────────────────────────

    def test_finds_single_image_by_name(self):
        """Single-entry cache: find by framework name."""
        path = self._make_cache([(0x18c000000, '/path/to/GeoServices.framework/GeoServices')])
        with DyldCacheReader(path) as r:
            va = r.find_image_header('GeoServices')
        self.assertEqual(va, 0x18c000000)

    def test_finds_image_by_full_path_substring(self):
        """Full-path substring lookup works as well as a short name."""
        entries = [
            (0x180100000, '/usr/lib/libsystem.dylib'),
            (0x181200000, '/System/Library/Frameworks/Foundation.framework/Foundation'),
        ]
        path = self._make_cache(entries)
        with DyldCacheReader(path) as r:
            va = r.find_image_header('/Foundation.framework/Foundation')
        self.assertEqual(va, 0x181200000)

    def test_framework_principal_preferred_over_substring_shadow(self):
        """A bare name resolves to the framework principal binary, NOT a
        substring shadow that merely contains the name.

        Replaces the old test_first_match_returned_for_ambiguous_name, which
        asserted the now-removed substring-first-wins behaviour (it returned
        the GeoServices_helper.dylib shadow).  The principal-identity tier
        picks the real framework regardless of array order, so this is NOT
        ambiguous.
        """
        entries = [
            (0x181000000, '/usr/lib/GeoServices_helper.dylib'),     # shadow, listed first
            (0x182000000, '/GeoServices.framework/GeoServices'),    # principal
        ]
        path = self._make_cache(entries)
        with DyldCacheReader(path) as r:
            self.assertEqual(r.find_image_header('GeoServices'), 0x182000000)
            self.assertEqual(r.resolve_image('GeoServices'), 0x182000000)

    def test_substring_shadow_not_matched(self):
        """'GeoServices' must not resolve to 'GeoServicesCore' (real cache shadow)."""
        entries = [
            (0x181000000, '/System/Library/PrivateFrameworks/GeoServices.framework/GeoServices'),
            (0x182000000, '/System/Library/PrivateFrameworks/GeoServicesCore.framework/GeoServicesCore'),
        ]
        path = self._make_cache(entries)
        with DyldCacheReader(path) as r:
            self.assertEqual(r.resolve_image('GeoServices'), 0x181000000)
            self.assertEqual(r.resolve_image('GeoServicesCore'), 0x182000000)

    def test_substring_shadow_not_matched_when_shadow_listed_first(self):
        # The fixture above happens to list the correct entry FIRST, so the old
        # substring-first-wins policy (`name in img_path`, first array match)
        # coincidentally returns the right answer too -- reorder so the shadow
        # is first, forcing that old policy to pick the wrong entry.
        entries = [
            (0x182000000, '/System/Library/PrivateFrameworks/GeoServicesCore.framework/GeoServicesCore'),
            (0x181000000, '/System/Library/PrivateFrameworks/GeoServices.framework/GeoServices'),
        ]
        path = self._make_cache(entries)
        with DyldCacheReader(path) as r:
            self.assertEqual(r.resolve_image('GeoServices'), 0x181000000)
            self.assertEqual(r.resolve_image('GeoServicesCore'), 0x182000000)

    def test_genuine_ambiguity_raises_and_lists_candidates(self):
        """Two framework principals with the same name → AmbiguousImageError
        carrying both full paths; find_image_header returns None (no silent pick)."""
        entries = [
            (0x181000000, '/System/Library/PrivateFrameworks/A.framework/Frameworks/IMAP.framework/IMAP'),
            (0x182000000, '/System/Library/PrivateFrameworks/B.framework/Frameworks/IMAP.framework/IMAP'),
        ]
        path = self._make_cache(entries)
        with DyldCacheReader(path) as r:
            with self.assertRaises(AmbiguousImageError) as cm:
                r.resolve_image('IMAP')
            self.assertEqual(len(cm.exception.candidates), 2)
            self.assertEqual(cm.exception.name, 'IMAP')
            self.assertIsNone(r.find_image_header('IMAP'))

    def test_resolve_image_exact_full_path(self):
        """An exact full path resolves via tier 1 even when a shorter name would too."""
        full = '/System/Library/Frameworks/Foundation.framework/Foundation'
        path = self._make_cache([(0x181200000, full)])
        with DyldCacheReader(path) as r:
            self.assertEqual(r.resolve_image(full), 0x181200000)

    def test_resolve_image_exact_full_path_disambiguates_substring_shadow(self):
        """Tier 1 must win even when a SECOND image's path merely contains the
        queried full path as a substring.

        The single-entry fixture in test_resolve_image_exact_full_path is not
        enough to prove tier 1 is load-bearing: with only one image, tier 3
        (unique substring) resolves it identically, so that test still passes
        even if tier 1 were deleted entirely. Here a second image nests the
        queried path inside a longer one, which makes tier 3 alone ambiguous
        (both images contain the queried string) -- only tier 1's `==` check
        picks the exact match unambiguously.
        """
        inner = '/System/Library/Frameworks/Foo.framework/Foo'
        outer = '/somewhere/nested' + inner  # contains `inner` as a substring
        entries = [
            (0x182000000, outer),
            (0x181000000, inner),
        ]
        path = self._make_cache(entries)
        with DyldCacheReader(path) as r:
            self.assertEqual(r.resolve_image(inner), 0x181000000)

    def test_resolve_image_not_found_raises(self):
        """resolve_image raises ImageNotFoundError; find_image_header returns None."""
        path = self._make_cache([(0x18c000000, '/Framework/GeoServices')])
        with DyldCacheReader(path) as r:
            with self.assertRaises(ImageNotFoundError):
                r.resolve_image('DoesNotExist')
            self.assertIsNone(r.find_image_header('DoesNotExist'))

    def test_returns_none_for_unknown_image(self):
        """Searching for a name not in the cache returns None."""
        path = self._make_cache([(0x18c000000, '/Framework/GeoServices')])
        with DyldCacheReader(path) as r:
            va = r.find_image_header('DoesNotExist')
        self.assertIsNone(va)

    def test_returns_none_when_no_images_text(self):
        """A cache without imagesText fields returns None (single-mapping cache)."""
        data = _pack_cache(0x180000000, b'hello\x00')
        path = self.tmpdir.write('cache_no_images', data)
        with DyldCacheReader(path) as r:
            # _pack_cache does NOT write imagesTextOffset/Count
            va = r.find_image_header('anything')
        self.assertIsNone(va)

    # ── case sensitivity ──────────────────────────────────────────────────────

    def test_match_is_case_sensitive(self):
        """Lowercase query does not match a differently-cased path."""
        path = self._make_cache([(0x18c000000, '/GeoServices.framework/GeoServices')])
        with DyldCacheReader(path) as r:
            self.assertIsNone(r.find_image_header('geoservices'))
            self.assertEqual(r.find_image_header('GeoServices'), 0x18c000000)

    # ── load-address accuracy ─────────────────────────────────────────────────

    def test_correct_va_returned_for_middle_entry(self):
        """Load address for a non-first entry in the array is correct."""
        entries = [
            (0x100000000, '/usr/lib/libA.dylib'),
            (0x200000000, '/usr/lib/libB.dylib'),
            (0x300000000, '/usr/lib/libC.dylib'),
        ]
        path = self._make_cache(entries)
        with DyldCacheReader(path) as r:
            self.assertEqual(r.find_image_header('libB'), 0x200000000)
            self.assertEqual(r.find_image_header('libC'), 0x300000000)

    def test_many_images_correct_lookup(self):
        """Lookup works correctly among 100 entries."""
        entries = [(0x100000000 + i * 0x100000,
                    f'/usr/lib/lib{i:03d}.dylib') for i in range(100)]
        path = self._make_cache(entries)
        with DyldCacheReader(path) as r:
            for i in (0, 1, 49, 98, 99):
                va = r.find_image_header(f'lib{i:03d}')
                self.assertEqual(va, 0x100000000 + i * 0x100000,
                                 f"Wrong VA for entry {i}")



# ─── TestListImages ───────────────────────────────────────────────────────────

class TestListImages(unittest.TestCase):
    """
    Unit tests for DyldCacheReader.list_images().

    Uses the same synthetic cache builder as TestFindImageHeader.
    """

    def setUp(self):
        self.tmpdir = _TmpDir()

    def tearDown(self):
        self.tmpdir.__exit__(None, None, None)

    def _make_cache(self, entries):
        data = _pack_images_cache(entries)
        return self.tmpdir.write('dyld_shared_cache_arm64', data)

    # ── basic behaviour ───────────────────────────────────────────────────────

    def test_returns_all_entries(self):
        entries = [
            (0x100000000, '/System/Library/Frameworks/Foundation.framework/Foundation'),
            (0x200000000, '/usr/lib/libobjc.A.dylib'),
            (0x300000000, '/System/Library/PrivateFrameworks/GeoServices.framework/GeoServices'),
        ]
        path = self._make_cache(entries)
        with DyldCacheReader(path) as r:
            images = r.list_images()
        self.assertEqual(len(images), 3)

    def test_paths_match_input(self):
        entries = [
            (0x100000000, '/Framework/A'),
            (0x200000000, '/Framework/B'),
        ]
        path = self._make_cache(entries)
        with DyldCacheReader(path) as r:
            images = r.list_images()
        paths = [p for _, p in images]
        self.assertIn('/Framework/A', paths)
        self.assertIn('/Framework/B', paths)

    def test_load_addresses_match_input(self):
        entries = [
            (0x111000000, '/lib/one.dylib'),
            (0x222000000, '/lib/two.dylib'),
        ]
        path = self._make_cache(entries)
        with DyldCacheReader(path) as r:
            images = r.list_images()
        vas = {p: va for va, p in images}
        self.assertEqual(vas['/lib/one.dylib'], 0x111000000)
        self.assertEqual(vas['/lib/two.dylib'], 0x222000000)

    def test_order_preserved(self):
        """Entries come back in the same order as the imagesText array."""
        entries = [(0x100000000 + i * 0x100000, f'/lib/lib{i}.dylib')
                   for i in range(10)]
        path = self._make_cache(entries)
        with DyldCacheReader(path) as r:
            images = r.list_images()
        for idx, (va, img_path) in enumerate(images):
            self.assertIn(f'lib{idx}.dylib', img_path)

    def test_single_image(self):
        path = self._make_cache([(0x18c000000, '/GeoServices.framework/GeoServices')])
        with DyldCacheReader(path) as r:
            images = r.list_images()
        self.assertEqual(len(images), 1)
        self.assertEqual(images[0][0], 0x18c000000)
        self.assertIn('GeoServices', images[0][1])

    def test_empty_when_no_images_text(self):
        """A cache without imagesTextOffset returns an empty list."""
        data = _pack_cache(0x180000000, b'hello\x00')
        path = self.tmpdir.write('no_images_cache', data)
        with DyldCacheReader(path) as r:
            images = r.list_images()
        self.assertEqual(images, [])

    def test_large_image_list(self):
        """list_images handles a 200-entry table without truncation."""
        entries = [(0x100000000 + i * 0x100000, f'/usr/lib/lib{i:03d}.dylib')
                   for i in range(200)]
        path = self._make_cache(entries)
        with DyldCacheReader(path) as r:
            images = r.list_images()
        self.assertEqual(len(images), 200)

    # ── result type ───────────────────────────────────────────────────────────

    def test_result_is_list_of_tuples(self):
        path = self._make_cache([(0x100000000, '/lib/foo.dylib')])
        with DyldCacheReader(path) as r:
            images = r.list_images()
        self.assertIsInstance(images, list)
        self.assertIsInstance(images[0], tuple)
        va, img_path = images[0]
        self.assertIsInstance(va, int)
        self.assertIsInstance(img_path, str)


# ─── TestImageSections ────────────────────────────────────────────────────────

class TestImageSections(unittest.TestCase):
    """
    Unit tests for DyldCacheReader.image_sections().

    Synthetic caches are built whose mapped content is a complete Mach-O header
    (magic + load commands).  The reader can then parse those load commands via
    read_raw() and image_sections() returns the expected section/segment dict.
    """

    def setUp(self):
        self.tmpdir = _TmpDir()

    def tearDown(self):
        self.tmpdir.__exit__(None, None, None)

    def _make_cache_with_macho(self, macho_bytes, macho_va=0x180000000):
        """Write a single-mapping cache whose content IS a mach-o header blob."""
        data = _pack_cache(macho_va, macho_bytes)
        path = self.tmpdir.write('dyld_shared_cache_arm64', data)
        return path, macho_va

    # ── happy-path parsing ────────────────────────────────────────────────────

    def test_single_segment_no_sections(self):
        """One LC_SEGMENT_64 with no sections → segment key only."""
        macho = _build_macho([
            ('__TEXT', 0x100000000, 0x10000, []),
        ])
        path, va = self._make_cache_with_macho(macho)
        with DyldCacheReader(path) as r:
            secs = r.image_sections(va)
        self.assertIn('__TEXT', secs)
        self.assertEqual(secs['__TEXT'], (0x100000000, 0x100010000))

    def test_segment_with_sections(self):
        """Sections are returned under segname/sectname keys."""
        macho = _build_macho([
            ('__TEXT', 0x100000000, 0x50000, [
                ('__text',          0x100001000, 0x30000),
                ('__objc_methname', 0x100031000, 0x10000),
            ]),
        ])
        path, va = self._make_cache_with_macho(macho)
        with DyldCacheReader(path) as r:
            secs = r.image_sections(va)
        self.assertIn('__TEXT/__text',          secs)
        self.assertIn('__TEXT/__objc_methname', secs)
        self.assertEqual(secs['__TEXT/__text'],          (0x100001000, 0x100031000))
        self.assertEqual(secs['__TEXT/__objc_methname'], (0x100031000, 0x100041000))

    def test_multiple_segments_both_present(self):
        """Two segments are both returned in the dict."""
        macho = _build_macho([
            ('__TEXT',       0x100000000, 0x10000, [('__text', 0x100001000, 0x8000)]),
            ('__DATA_CONST', 0x200000000, 0x5000,  [('__objc_classlist', 0x200001000, 0x800)]),
        ])
        path, va = self._make_cache_with_macho(macho)
        with DyldCacheReader(path) as r:
            secs = r.image_sections(va)
        self.assertIn('__TEXT',       secs)
        self.assertIn('__DATA_CONST', secs)
        self.assertIn('__TEXT/__text',                 secs)
        self.assertIn('__DATA_CONST/__objc_classlist', secs)

    def test_zero_vmsize_section_excluded(self):
        """A section with vmsize == 0 must not appear in the result."""
        macho = _build_macho([
            ('__TEXT', 0x100000000, 0x10000, [
                ('__real',  0x100001000, 0x1000),
                ('__empty', 0x100002000, 0),         # vmsize = 0
            ]),
        ])
        path, va = self._make_cache_with_macho(macho)
        with DyldCacheReader(path) as r:
            secs = r.image_sections(va)
        self.assertIn('__TEXT/__real',  secs)
        self.assertNotIn('__TEXT/__empty', secs)

    def test_zero_vmaddr_section_excluded(self):
        """A section with vmaddr == 0 must not appear in the result."""
        macho = _build_macho([
            ('__TEXT', 0x100000000, 0x10000, [
                ('__real',     0x100001000, 0x1000),
                ('__nulladdr', 0,           0x1000),  # vmaddr = 0
            ]),
        ])
        path, va = self._make_cache_with_macho(macho)
        with DyldCacheReader(path) as r:
            secs = r.image_sections(va)
        self.assertIn('__TEXT/__real', secs)
        self.assertNotIn('__TEXT/__nulladdr', secs)

    def test_section_bounds_are_exclusive_end(self):
        """vm_end == vm_start + vm_size (exclusive upper bound)."""
        macho = _build_macho([
            ('__TEXT', 0x180000000, 0x100000, [
                ('__objc_methname', 0x180010000, 0x40000),
            ]),
        ])
        path, va = self._make_cache_with_macho(macho)
        with DyldCacheReader(path) as r:
            secs = r.image_sections(va)
        start, end = secs['__TEXT/__objc_methname']
        self.assertEqual(start, 0x180010000)
        self.assertEqual(end,   0x180050000)   # start + 0x40000

    # ── error / edge cases ────────────────────────────────────────────────────

    def test_bad_magic_returns_empty_dict(self):
        """Content that does not begin with MH_MAGIC_64 → empty dict."""
        bad_content = b'\xDE\xAD\xBE\xEF' + b'\x00' * 28
        path, va = self._make_cache_with_macho(bad_content)
        with DyldCacheReader(path) as r:
            secs = r.image_sections(va)
        self.assertEqual(secs, {})

    def test_unmapped_va_returns_empty_dict(self):
        """Address not covered by any mapping → empty dict."""
        macho = _build_macho([('__TEXT', 0x180000000, 0x1000, [])])
        path, va = self._make_cache_with_macho(macho)
        with DyldCacheReader(path) as r:
            secs = r.image_sections(0xDEAD000000000000)
        self.assertEqual(secs, {})

    def test_truncated_content_returns_partial_or_empty(self):
        """A 4-byte blob (too short for a mach-o header) → empty dict."""
        path, va = self._make_cache_with_macho(b'\xcf\xfa\xed\xfe')  # magic only
        with DyldCacheReader(path) as r:
            secs = r.image_sections(va)
        self.assertEqual(secs, {})

    def test_no_load_commands_returns_segment_only(self):
        """ncmds=0 / sizeofcmds=0 → empty dict (guard fires before walk)."""
        hdr = bytearray(32)
        struct.pack_into('<I', hdr,  0, 0xFEEDFACF)   # magic
        struct.pack_into('<I', hdr, 16, 0)             # ncmds = 0
        struct.pack_into('<I', hdr, 20, 0)             # sizeofcmds = 0
        path, va = self._make_cache_with_macho(bytes(hdr))
        with DyldCacheReader(path) as r:
            secs = r.image_sections(va)
        self.assertEqual(secs, {})


# ─── TestImageDiscoveryLive ───────────────────────────────────────────────────

@unittest.skipUnless(_HAS_CACHE, _SKIP_MSG)
class TestImageDiscoveryLive(unittest.TestCase):
    """
    Live tests for find_image_header() and image_sections() against the real
    dyld shared cache.

    All addresses are derived structurally or verified against the binary
    loaded in Hopper.  Hopper-verified regression constants are clearly
    labelled in each test that uses them.

    The image_sections() tests are skipped when the cache sub-files are not
    accessible (i.e. DyldCacheReader was loaded from a directory that has only
    the main file).  In that case cls.sections is set to {} and individual
    tests call self._require_sections() to skip gracefully.
    """

    # ── Hopper-verified constants (GeoServices, verified June 2026) ──────────
    # These exact values are regression guards; changing them means the binary
    # or test infrastructure changed and the constants need re-verification.
    _HOPPER_GEO_VA              = 0x18c1a7000
    _HOPPER_TEXT_START          = 0x18c1a7000   # == mach_header VA
    _HOPPER_TEXT_END            = 0x18db30000
    _HOPPER_DATA_CONST_START    = 0x1d5f796d0
    _HOPPER_DATA_CONST_END      = 0x1d61be6d0
    _HOPPER_CLASSLIST_START     = 0x1d60364a0
    _HOPPER_CLASSLIST_END       = 0x1d603b5c8
    _HOPPER_SELREFS_START       = 0x1d6187b50
    _HOPPER_SELREFS_END         = 0x1d61b7618
    _HOPPER_METHNAME_START      = 0x18d98e846
    _HOPPER_METHNAME_END        = 0x18da577c7

    # Expected sections present in GeoServices
    _EXPECTED_SEGMENTS = {'__TEXT', '__DATA_CONST', '__DATA'}
    _EXPECTED_SECTIONS = {
        '__TEXT/__objc_methname',
        '__TEXT/__objc_classname',
        '__DATA_CONST/__objc_classlist',
        '__DATA_CONST/__objc_selrefs',
        '__DATA_CONST/__objc_const',
    }

    @classmethod
    def setUpClass(cls):
        cls.reader   = DyldCacheReader(_CACHE_MAIN)
        cls.geo_va   = cls.reader.find_image_header('GeoServices')
        cls.sections = (
            cls.reader.image_sections(cls.geo_va) if cls.geo_va else {}
        )

    @classmethod
    def tearDownClass(cls):
        cls.reader.close()

    def _require_sections(self):
        """Skip the calling test if sub-caches were not available."""
        if not self.sections:
            self.skipTest(
                "image_sections() returned {} — GeoServices mach-o header "
                "not accessible (sub-cache files may be absent from this environment)"
            )

    # ── find_image_header ─────────────────────────────────────────────────────

    def test_find_geoservices_not_none(self):
        """GeoServices must be found in the imagesText array."""
        self.assertIsNotNone(self.geo_va,
                             "find_image_header('GeoServices') returned None")

    def test_find_geoservices_va_hopper_verified(self):
        """GeoServices load address matches Hopper-verified value."""
        if self.geo_va is None:
            self.skipTest("GeoServices not found")
        self.assertEqual(
            self.geo_va, self._HOPPER_GEO_VA,
            f"Expected 0x{self._HOPPER_GEO_VA:x}, got 0x{self.geo_va:x}"
        )

    def test_find_libobjc_not_none(self):
        """libobjc must be findable by filename."""
        va = self.reader.find_image_header('libobjc.A.dylib')
        self.assertIsNotNone(va, "libobjc not found in cache imagesText")

    def test_find_foundation_not_none(self):
        """Foundation must be findable by framework name."""
        va = self.reader.find_image_header('Foundation.framework/Foundation')
        self.assertIsNotNone(va, "Foundation not found in cache imagesText")

    def test_find_unknown_returns_none(self):
        """A name not present in the cache must return None."""
        va = self.reader.find_image_header('ZZZNonexistentFramework_XYZ')
        self.assertIsNone(va)

    def test_find_by_full_path_substring(self):
        """GeoServices is findable by the trailing path component."""
        va = self.reader.find_image_header(
            'GeoServices.framework/GeoServices'
        )
        self.assertIsNotNone(va)
        if self.geo_va:
            self.assertEqual(va, self.geo_va)

    # ── image_sections — segment coverage ────────────────────────────────────

    def test_geoservices_expected_segments_present(self):
        """All core segments must appear in image_sections() output."""
        self._require_sections()
        missing = self._EXPECTED_SEGMENTS - set(self.sections)
        self.assertEqual(missing, set(),
                         f"Missing segments: {missing}")

    def test_geoservices_text_segment_start_equals_header_va(self):
        """__TEXT start must equal the mach_header VA returned by find_image_header."""
        self._require_sections()
        text_start, _ = self.sections['__TEXT']
        self.assertEqual(
            text_start, self.geo_va,
            "__TEXT segment start should equal the mach_header_va"
        )

    def test_geoservices_text_bounds_hopper_verified(self):
        """__TEXT segment bounds match Hopper-verified values."""
        self._require_sections()
        self.assertEqual(
            self.sections['__TEXT'],
            (self._HOPPER_TEXT_START, self._HOPPER_TEXT_END),
        )

    def test_geoservices_data_const_segment_structural(self):
        """__DATA_CONST must be present, non-empty, and contain the classlist section.

        We do not assert exact bounds because DATA segment layouts differ between
        iOS builds.  The Hopper constants _HOPPER_DATA_CONST_START/_END were
        verified against one specific build; other builds place the segment at
        slightly different vmaddrs.  What is portable across all builds:
          - the segment exists and is non-empty
          - __DATA_CONST/__objc_classlist is present and lies inside it
        """
        self._require_sections()
        self.assertIn('__DATA_CONST', self.sections,
                      "__DATA_CONST segment absent from image_sections() output")
        seg_start, seg_end = self.sections['__DATA_CONST']
        self.assertLess(seg_start, seg_end,
                        f"__DATA_CONST is empty: start=0x{seg_start:x} end=0x{seg_end:x}")
        # classlist must be nested inside DATA_CONST
        if '__DATA_CONST/__objc_classlist' in self.sections:
            cl_start, cl_end = self.sections['__DATA_CONST/__objc_classlist']
            self.assertGreaterEqual(cl_start, seg_start,
                "classlist start is below __DATA_CONST start")
            self.assertLessEqual(cl_end, seg_end,
                "classlist end exceeds __DATA_CONST end")

    # ── image_sections — section presence ────────────────────────────────────

    def test_geoservices_expected_sections_present(self):
        """All key ObjC/proto sections must appear in image_sections() output."""
        self._require_sections()
        missing = self._EXPECTED_SECTIONS - set(self.sections)
        self.assertEqual(missing, set(),
                         f"Missing sections: {missing}")

    def test_geoservices_classlist_bounds_hopper_verified(self):
        """__objc_classlist bounds match Hopper-verified values."""
        self._require_sections()
        self.assertEqual(
            self.sections['__DATA_CONST/__objc_classlist'],
            (self._HOPPER_CLASSLIST_START, self._HOPPER_CLASSLIST_END),
        )

    def test_geoservices_methname_bounds_hopper_verified(self):
        """__objc_methname bounds match Hopper-verified values."""
        self._require_sections()
        self.assertEqual(
            self.sections['__TEXT/__objc_methname'],
            (self._HOPPER_METHNAME_START, self._HOPPER_METHNAME_END),
        )

    def test_geoservices_selrefs_bounds_hopper_verified(self):
        """__objc_selrefs bounds match Hopper-verified values."""
        self._require_sections()
        self.assertEqual(
            self.sections['__DATA_CONST/__objc_selrefs'],
            (self._HOPPER_SELREFS_START, self._HOPPER_SELREFS_END),
        )

    # ── image_sections — structural sanity ───────────────────────────────────

    def test_geoservices_classlist_size_multiple_of_8(self):
        """__objc_classlist size is a positive multiple of 8 (pointer array)."""
        self._require_sections()
        start, end = self.sections['__DATA_CONST/__objc_classlist']
        size = end - start
        self.assertGreater(size, 0)
        self.assertEqual(size % 8, 0,
                         f"classlist size 0x{size:x} is not a multiple of 8")

    def test_geoservices_classlist_entry_count_reasonable(self):
        """__objc_classlist must contain a plausible number of class pointers."""
        self._require_sections()
        start, end = self.sections['__DATA_CONST/__objc_classlist']
        count = (end - start) // 8
        self.assertGreater(count, 100,
                           f"Only {count} class pointers — suspiciously few")

    def test_geoservices_text_sections_within_text_segment(self):
        """All __TEXT/* section VAs must lie within the __TEXT segment bounds."""
        self._require_sections()
        seg_start, seg_end = self.sections['__TEXT']
        for key, (s, e) in self.sections.items():
            if not key.startswith('__TEXT/'):
                continue
            self.assertGreaterEqual(s, seg_start,
                                    f"{key} start 0x{s:x} < __TEXT start 0x{seg_start:x}")
            self.assertLessEqual(e, seg_end,
                                 f"{key} end 0x{e:x} > __TEXT end 0x{seg_end:x}")

    def test_geoservices_section_count_reasonable(self):
        """image_sections() must return a plausible number of keys."""
        self._require_sections()
        # GeoServices has 5 segments and ~40+ sections; combined keys > 20
        self.assertGreater(len(self.sections), 20,
                           f"Only {len(self.sections)} keys — suspiciously few")


# ─── TestSubcacheDiagnostics ─────────────────────────────────────────────────

class TestSubcacheDiagnostics(unittest.TestCase):
    """The verbose _dump_subcache_* helpers (extracted from _load_subcaches) print
    to stderr only and never affect parsing.  The missing/dir-listing branch of
    _dump_subcache_result is NOT reached by the live tests (all sub-caches are
    present in the corpus), so its flattened control flow is covered here by
    calling the helpers directly on a minimal stand-in (they read only
    ``self._mappings``)."""

    def _emit(self, method, *args):
        import io
        import contextlib
        import types
        from macho.dyld_cache import DyldCacheReader
        fake = types.SimpleNamespace(_mappings=[0, 0, 0])   # len → "3 total mapping(s)"
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            getattr(DyldCacheReader, method)(fake, *args)
        return buf.getvalue()

    def test_entry_line_format(self):
        out = self._emit('_dump_subcache_entry', 4, '.05', '/c/x.05', '[MISSING]')
        self.assertIn("[04] ext='.05'", out)
        self.assertIn('/c/x.05', out)
        self.assertIn('[MISSING]', out)

    def test_result_no_missing_summary_only(self):
        out = self._emit('_dump_subcache_result', '/c/cache', 3, [])
        self.assertIn('3/3 sub-cache(s) loaded, 0 missing', out)
        self.assertNotIn('directory listing', out)

    def test_result_missing_lists_matching_files(self):
        with _TmpDir() as d:
            d.write('cache', b'')
            d.write('cache.01', b'')
            d.write('cache.02', b'')
            out = self._emit('_dump_subcache_result',
                             d.join('cache'), 3, [d.join('cache.03')])
        self.assertIn('1 missing', out)
        self.assertIn('directory listing', out)
        self.assertIn('cache.01', out)
        self.assertIn('cache.02', out)

    def test_result_missing_no_matches_falls_back_to_dir_listing(self):
        with _TmpDir() as d:
            d.write('unrelated.bin', b'')
            out = self._emit('_dump_subcache_result',
                             d.join('nomatch'), 1, [d.join('nomatch.01')])
        self.assertIn('no files start with', out)
        self.assertIn('unrelated.bin', out)

    def test_result_missing_unreadable_dir_handled(self):
        out = self._emit('_dump_subcache_result',
                         '/no_such_dir_xyz/cache', 1, ['/no_such_dir_xyz/cache.01'])
        self.assertIn('could not list directory', out)


class TestDetectSubcacheStride(unittest.TestCase):
    """_detect_subcache_stride is a pure function of raw entry bytes; no cache in
    this project's corpus is known to be v1 (per its own docstring), so this
    branch has never been exercised by any live or synthetic test. Cheap direct
    coverage of both the v2 (56-byte, '.NN' extension) and v1/indeterminate
    (24-byte, no extension) shapes."""

    def test_v2_stride_detected_by_dot_extension(self):
        from macho.dyld_cache import _detect_subcache_stride, _SUBCACHE_STRIDE_V2
        raw = bytearray(_SUBCACHE_STRIDE_V2)
        raw[24:27] = b'.01'
        self.assertEqual(_detect_subcache_stride(bytes(raw)), _SUBCACHE_STRIDE_V2)

    def test_v1_fallback_when_byte24_is_not_dot(self):
        from macho.dyld_cache import _detect_subcache_stride, _SUBCACHE_STRIDE_V1, _SUBCACHE_STRIDE_V2
        raw = bytearray(_SUBCACHE_STRIDE_V2)
        raw[24] = ord('X')   # next entry's uuid byte, not '.'
        self.assertEqual(_detect_subcache_stride(bytes(raw)), _SUBCACHE_STRIDE_V1)

    def test_v1_fallback_when_buffer_too_short_to_probe(self):
        from macho.dyld_cache import _detect_subcache_stride, _SUBCACHE_STRIDE_V1
        raw = b'\x00' * 24   # shorter than the v2 probe offset (24)
        self.assertEqual(_detect_subcache_stride(raw), _SUBCACHE_STRIDE_V1)


class TestSlideInfoVersionGate(unittest.TestCase):
    """decode_ptr reads the runtime offset of an arm64e DATA pointer as the low 34 bits
    for slide-info v5 caches (iOS 26+/macOS 26+, > 4 GB, ``dyld_cache_slide_pointer5``)
    and as the low 32 bits otherwise (v3 keeps PAC diversity in bits 32-47).  A cache
    whose data lies past ``cache_base + 4 GB`` was silently mis-decoded (the 32-bit
    result lands on a *different mapped* address): MessageProtection/TrustedPeers on
    iOS 27 lost every ObjC class."""

    BASE   = 0x180000000
    OFFSET = 0x14e7735c0            # 33 bits: past the 4 GB mark

    def _reader(self, tmp, *, slide_version, legacy=False, with_target=True):
        data = bytearray(_pack_cache(self.BASE, b'\x00' * 0x1000, magic=_MAGIC_ARM64E))
        slide_off = 0x500
        struct.pack_into('<I', data, slide_off, slide_version)
        if legacy:
            # old header: mappingOffset below the mappingWithSlide fields
            struct.pack_into('<I', data, _HDR_MAPPING_OFF, 0x100)
            struct.pack_into('<Q', data, 0x100, self.BASE)
            struct.pack_into('<Q', data, 0x108, 0x1000)
            struct.pack_into('<Q', data, 0x110, 0x1000)
            struct.pack_into('<Q', data, 0x28, slide_off)       # slideInfoOffsetUnused
        else:
            struct.pack_into('<II', data, 0x138, 0x300, 1)      # mappingWithSlide off/cnt
            struct.pack_into('<QQQQQ', data, 0x300, self.BASE, 0x1000, 0x1000, slide_off, 0x20)
        path = tmp.write('cache', bytes(data))
        rd = DyldCacheReader(path)
        if with_target:
            # a mapping at base+OFFSET (past 4 GB) and one at base+(OFFSET & 0xFFFFFFFF)
            for off in (self.OFFSET, self.OFFSET & 0xFFFFFFFF):
                rd._mappings.append(type(rd._mappings[0])(self.BASE + off - 0x1000, 0x2000, path, 0x1000))
            rd._mappings.sort(key=lambda m: m.vmaddr)
            rd._vmaddr_keys = [m.vmaddr for m in rd._mappings]
        return rd

    def _raw(self):
        return (1 << 52) | self.OFFSET          # next=1 (v5 plain rebase), low 34 bits = offset

    def test_v5_slide_version_detected(self):
        with _TmpDir() as tmp:
            rd = self._reader(tmp, slide_version=5)
            self.assertEqual(rd._slide_versions, {5})
            self.assertEqual(rd._runtime_offset_mask, (1 << 34) - 1)
            rd.close()

    def test_v5_pointer_past_4gb_decodes_to_the_real_target(self):
        with _TmpDir() as tmp:
            rd = self._reader(tmp, slide_version=5)
            self.assertEqual(rd.decode_ptr(self._raw()), self.BASE + self.OFFSET)
            rd.close()

    def test_v3_pointer_keeps_the_32_bit_mask(self):
        # v3 auth pointer: offset in bits 0-31, PAC diversity in bits 32-47.  The same bits
        # that v5 treats as offset must NOT be taken as offset here.
        with _TmpDir() as tmp:
            rd = self._reader(tmp, slide_version=3)
            self.assertEqual(rd._slide_versions, {3})
            self.assertEqual(rd._runtime_offset_mask, 0xFFFFFFFF)
            self.assertEqual(rd.decode_ptr(self._raw()),
                             self.BASE + (self.OFFSET & 0xFFFFFFFF))
            rd.close()

    def test_legacy_header_slide_info_is_read(self):
        with _TmpDir() as tmp:
            rd = self._reader(tmp, slide_version=2, legacy=True, with_target=False)
            self.assertEqual(rd._slide_versions, {2})
            self.assertEqual(rd._runtime_offset_mask, 0xFFFFFFFF)
            rd.close()

    def test_cache_without_slide_info_keeps_the_32_bit_mask(self):
        with _TmpDir() as tmp:
            path = tmp.write('cache', _pack_cache(self.BASE, b'\x00' * 0x1000))
            rd = DyldCacheReader(path)
            self.assertEqual(rd._slide_versions, set())
            self.assertEqual(rd._runtime_offset_mask, 0xFFFFFFFF)
            rd.close()
