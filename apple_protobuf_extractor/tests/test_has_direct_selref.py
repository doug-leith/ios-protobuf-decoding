"""
Tests for the has_direct=True selector recovery building blocks:
  1. _is_valid_selector accepts single-char ObjC selectors, rejects garbage
  2. _decode_packed_ptr decodes packed pointers only when the target is inside
     the binary's own segments (the below-image_base "Mode 3" was removed with
     hybrid mode)
  3. Live test: with a standalone binary, single-char selectors are present in
     __objc_methname and validate

Selector-name resolution for cache-native frameworks (has_direct=True direct
selectors) is handled by Step 1b of _parse_relative_method reading through
ctx.read_cstring, plus .symbols local-symbol recovery; both are covered by the
cache-native suites (test_cache_classlist, test_local_symbols).  The old ipsw
binary+cache "selref pool / C-calibration" path has been removed along with
hybrid mode, so its unit tests are gone.

Tests are split into unit (no binary required) and live (binary present).
"""
from __future__ import annotations

import os
import artifacts
import struct
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from macho.classlist import _is_valid_selector
from macho.memory import BinaryContext


# ── helpers ───────────────────────────────────────────────────────────────────

def _minimal_macho(
    *,
    text_vmaddr: int = 0x18c000000,
    text_data: bytes = b'',
    extra_load_cmds: bytes = b'',
) -> bytes:
    """Build a minimal arm64 Mach-O with one __TEXT segment."""
    # Build segment command
    seg_name  = b'__TEXT\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    nsects    = 0
    seg_cmd   = struct.pack(
        '<II16sQQQQiiii',
        0x19, 72 + nsects * 80,   # cmd, cmdsize
        seg_name,
        text_vmaddr, len(text_data),
        0, len(text_data),         # fileoff, filesize
        7, 5, nsects, 0,
    )
    all_cmds  = seg_cmd + extra_load_cmds
    hdr = struct.pack(
        '<IIIIIIII',
        0xFEEDFACF,            # magic arm64 LE
        0x0100000C, 0,         # cpu_type, cpu_subtype
        0x6,                   # MH_DYLIB
        1 + (1 if extra_load_cmds else 0),  # ncmds
        len(all_cmds),
        0, 0,
    )
    return hdr + all_cmds + text_data


def _ctx_with_image_base(image_base: int) -> BinaryContext:
    """Return a BinaryContext whose image_base == *image_base*."""
    data = _minimal_macho(text_vmaddr=image_base, text_data=b'\x00' * 64)
    return BinaryContext(data)


# ── 1. _is_valid_selector ─────────────────────────────────────────────────────

class TestSelectorValidation(unittest.TestCase):
    """_is_valid_selector rejects binary garbage, accepts real selectors."""

    def test_simple_getter(self):
        self.assertTrue(_is_valid_selector('status'))

    def test_with_colon(self):
        self.assertTrue(_is_valid_selector('setStatus:'))
        self.assertTrue(_is_valid_selector('statusAsString:'))

    def test_proto_selectors(self):
        for sel in ('readFrom:', 'writeTo:', 'mergeFrom:', 'copyTo:',
                    'isEqual:', 'hash', 'description'):
            self.assertTrue(_is_valid_selector(sel), f'Expected valid: {sel!r}')

    def test_empty_rejected(self):
        self.assertFalse(_is_valid_selector(''))
        self.assertFalse(_is_valid_selector(None))

    def test_single_char_accepted(self):
        # Single-char property getters like x, y, z are valid ObjC selectors.
        # Previous code incorrectly required len > 1.
        for sel in ('x', 'y', 'z', 'n', 'X', '_'):
            self.assertTrue(_is_valid_selector(sel),
                            f'Single-char selector should be valid: {sel!r}')

    def test_control_chars_rejected(self):
        self.assertFalse(_is_valid_selector('\x01\\'))
        self.assertFalse(_is_valid_selector('\x00abc'))

    def test_binary_garbage_rejected(self):
        self.assertFalse(_is_valid_selector('spatch_queue>",R,N,V_serverQueue'))
        self.assertFalse(_is_valid_selector('some thing'))
        self.assertFalse(_is_valid_selector('foo{bar}'))
        self.assertFalse(_is_valid_selector('%@"'))   # oslogstring content

    def test_long_selectors_accepted(self):
        # a many-argument initialiser: iPhone 8 GeoServices' -[GEOPDPlaceRequest
        # initWithMerchantCode:...] is over 600 characters (a length cap left it unnamed, or
        # named by a fragment of another string)
        self.assertTrue(_is_valid_selector('initWithMerchantCode:' + 'arg:' * 160))

    def test_empty_keywords_accepted(self):
        # ObjC allows an empty keyword: UIKitCore's -[_IntArray2D ::newValue:]
        self.assertTrue(_is_valid_selector('::newValue:'))
        self.assertTrue(_is_valid_selector(':'))

    def test_starts_with_digit_rejected(self):
        self.assertFalse(_is_valid_selector('2bad'))

    def test_underscore_start_ok(self):
        self.assertTrue(_is_valid_selector('_privateMethod'))
        self.assertTrue(_is_valid_selector('_internal:with:args:'))


# ── 2. _decode_packed_ptr: binary-local segment decode ────────────────────────

class TestDecodePackedPtr(unittest.TestCase):
    """_decode_packed_ptr (binary mode) decodes packed pointers ONLY when the
    low-36-bit target lands inside the binary's own mapped segments.

    The old "Mode 3" that accepted any address below image_base (the dyld
    shared-cache selector pool) was removed with hybrid binary+cache mode: a
    standalone binary cannot resolve an address that lives only in the cache,
    so such pointers are left raw rather than decoded to an unmappable vmaddr.
    Cache-native contexts never reach this method (they decode through
    DyldCacheReader.decode_ptr)."""

    def _raw_ptr(self, low36: int, metadata: int = 0x000002) -> int:
        """Build a packed pointer with chain/auth metadata in the upper bits."""
        return (metadata << 36) | (low36 & 0xFFFFFFFFF)

    def test_below_image_base_not_decoded(self):
        """Addresses below image_base (cache pool range) are NOT decoded now —
        they return raw, since a standalone binary cannot resolve them."""
        image_base = 0x18c000000
        ctx = _ctx_with_image_base(image_base)

        pool_va = 0x18251984f   # below image_base, only valid inside the cache
        self.assertLess(pool_va, image_base)
        raw = self._raw_ptr(pool_va)
        self.assertEqual(ctx._decode_packed_ptr(raw), raw,
                         'Below-image_base targets must be left raw (Mode 3 removed)')

    def test_various_pool_addrs_below_base_not_decoded(self):
        """Several representative below-base pool addresses all return raw."""
        image_base = 0x18c000000
        ctx = _ctx_with_image_base(image_base)
        pool_addrs = [
            0x1823b874f, 0x18243a6cf, 0x18251984f, 0x1827c65cf,
            0x1828da8cf, 0x182a53acf, 0x182a90bcf, 0x182e120cf,
        ]
        for pva in pool_addrs:
            self.assertLess(pva, image_base)
            raw = self._raw_ptr(pva)
            self.assertEqual(ctx._decode_packed_ptr(raw), raw,
                             f'Below-base pool_va=0x{pva:x} must be left raw')

    def test_above_image_base_not_in_segment_returns_raw(self):
        """Addresses above image_base but not in any segment return raw."""
        image_base = 0x18c000000
        ctx = _ctx_with_image_base(image_base)
        high_addr = image_base + 0x10000000  # well above, not in segments
        raw = self._raw_ptr(high_addr)
        self.assertEqual(ctx._decode_packed_ptr(raw), raw)

    def test_zero_low36_not_decoded(self):
        """low36=0 must not be decoded to avoid spurious zero pointers."""
        image_base = 0x18c000000
        ctx = _ctx_with_image_base(image_base)
        raw = self._raw_ptr(0)  # zero address
        self.assertEqual(ctx._decode_packed_ptr(raw), raw)

    def test_address_in_binary_segment_decodes(self):
        """Addresses in the binary's own segments must still decode (Mode 2)."""
        image_base = 0x18c000000
        ctx = _ctx_with_image_base(image_base)
        # The TEXT segment has vmaddr=image_base with 64 bytes.
        in_seg = image_base + 4
        raw = self._raw_ptr(in_seg)
        self.assertEqual(ctx._decode_packed_ptr(raw), in_seg)


# ── 3. Live test ──────────────────────────────────────────────────────────────

def _find_binary() -> str:
    from_env = os.environ.get('MACHO_TEST_BINARY', '').strip()
    if from_env:
        return from_env
    return artifacts.geoservices_path()


BINARY       = _find_binary()
SKIP_BIN     = not os.path.isfile(BINARY)
SKIP_MSG_BIN = 'GeoServices binary not available'


@unittest.skipIf(SKIP_BIN, SKIP_MSG_BIN)
class TestSingleCharSelectorLive(unittest.TestCase):
    """Single-char selectors resolve from __objc_methname once validator is fixed."""

    @classmethod
    def setUpClass(cls):
        from macho.memory import BinaryContext
        from macho.strings import build_string_table
        with open(BINARY, 'rb') as f:
            cls.ctx = BinaryContext(f.read())
        cls.strings = build_string_table(cls.ctx)

    def test_single_char_x_appears_in_methname(self):
        """'x' must be present in the binary's __objc_methname scan."""
        ctx = self.ctx
        self.assertTrue(ctx.has_section('__TEXT', '__objc_methname'))
        mn = ctx.section('__TEXT', '__objc_methname')
        # Read the methname section and scan for 'x\0'
        data = ctx.read_bytes(mn.vmaddr, mn.vmsize)
        self.assertIn(b'x\x00', data, "'x' should be in __objc_methname")

    def test_x_selector_is_now_valid(self):
        """_is_valid_selector('x') must return True after the validator fix."""
        self.assertTrue(_is_valid_selector('x'))
        self.assertTrue(_is_valid_selector('y'))
        self.assertTrue(_is_valid_selector('z'))


if __name__ == '__main__':
    unittest.main(verbosity=2)


class TestDirectSelectorReadFromTheBaseOnly(unittest.TestCase):
    """A preoptimised direct selector is read at the cache's selector base + nameOffset only:
    va + nameOffset is no selector address, and a string there is a fragment of another."""

    def test_no_fallback_read_once_the_base_is_known(self):
        from macho.classlist import _parse_relative_method
        from tests._fakes import NoImage

        class Ctx(NoImage):
            _rel_sel_base = 0x100000
            strings = {0x100040: "%@ not a selector", 0x1040: "te"}   # base+0x40, va+0x40

            def read_s32(self, va):
                return {0x1000: 0x40, 0x1004: 0, 0x1008: 0x10}[va]

            def read_cstring(self, va):
                return self.strings[va]

        m = _parse_relative_method(Ctx(), 0x1000, None, has_direct=True)
        self.assertIsNone(m.name)                 # left for .symbols, not named 'te'
