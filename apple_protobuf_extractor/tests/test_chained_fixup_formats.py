"""Chained-fixup pointer-format decoding (macho/memory.py).

Two layers:

* Unit tests of ``_decode_chain_ptr`` / ``_chain_next_stride`` for the arm64e
  "userland" formats (9 and 12) on hand-packed values built from the layouts in
  <mach-o/fixup-chains.h>, including the one thing the binary fixture cannot
  reach: a bind ordinal above 16 bits, which is what distinguishes
  USERLAND24 (12) from USERLAND (9).
* A real arm64e binary (synthetic_fixtures/f26_arm64e_fixups) whose every
  fixup is checked against Apple's own ``dyld_info -fixups`` output, recorded
  in that fixture's expected.py.  Before format 12 was supported the decoder
  saw 2 of the 16 fixups and no classes at all.
"""
import importlib.util
import os
import unittest

from macho.memory import (
    BinaryContext, _decode_chain_ptr, _chain_next_stride,
    _DYLD_PTR_ARM64E, _DYLD_PTR_ARM64E_USERLAND, _DYLD_PTR_ARM64E_USERLAND24,
)
from macho.strings import build_string_table
from macho.classlist import build_class_list
from serializers.swift_descriptor_extract import load_macho_slice

_DIR = os.path.join(os.path.dirname(__file__), "synthetic_fixtures",
                    "f26_arm64e_fixups")
_BINARY = os.path.join(_DIR, "testfx_e")

_BASE = 0x1_0000_0000


def _rebase(target, high8=0, nxt=0):
    """dyld_chained_ptr_arm64e_rebase: target:43 high8:8 next:11 bind:1 auth:1"""
    return target | (high8 << 43) | (nxt << 51)


def _auth_rebase(target, diversity=0, addr_div=0, key=0, nxt=0):
    """dyld_chained_ptr_arm64e_auth_rebase: target:32 diversity:16 addrDiv:1
    key:2 next:11 bind:1 auth:1"""
    return (target | (diversity << 32) | (addr_div << 48) | (key << 49)
            | (nxt << 51) | (1 << 63))


class TestArm64eUserlandFormatDecode(unittest.TestCase):

    def test_plain_rebase_is_offset_from_image_base(self):
        for fmt in (_DYLD_PTR_ARM64E_USERLAND, _DYLD_PTR_ARM64E_USERLAND24):
            self.assertEqual(
                _decode_chain_ptr(_rebase(0x4058), fmt, _BASE), _BASE + 0x4058)

    def test_plain_rebase_uses_the_full_43_bit_target(self):
        # Bits above the classic arm64e format's 39-bit mask must survive.
        target = 0x7_FFFF_FFFF_F   # 43 bits set
        self.assertEqual(
            _decode_chain_ptr(_rebase(target), _DYLD_PTR_ARM64E_USERLAND24, 0),
            target)

    def test_plain_rebase_drops_high8_and_chain_metadata(self):
        raw = _rebase(0x4058, high8=0xAB, nxt=0x123)
        self.assertEqual(
            _decode_chain_ptr(raw, _DYLD_PTR_ARM64E_USERLAND24, _BASE),
            _BASE + 0x4058)

    def test_auth_rebase_ignores_diversity_key_and_next(self):
        raw = _auth_rebase(0xC0A0, diversity=0x6AE1, addr_div=1, key=3, nxt=9)
        self.assertEqual(
            _decode_chain_ptr(raw, _DYLD_PTR_ARM64E_USERLAND24, _BASE),
            _BASE + 0xC0A0)

    def test_bind_is_not_a_rebase(self):
        bind = (1 << 62) | 5
        self.assertEqual(
            _decode_chain_ptr(bind, _DYLD_PTR_ARM64E_USERLAND24, _BASE), 0)
        self.assertEqual(
            _decode_chain_ptr(bind | (1 << 63), _DYLD_PTR_ARM64E_USERLAND24,
                              _BASE), 0)

    def test_next_stride_is_11_bits_of_8_bytes(self):
        for fmt in (_DYLD_PTR_ARM64E, _DYLD_PTR_ARM64E_USERLAND,
                    _DYLD_PTR_ARM64E_USERLAND24):
            self.assertEqual(_chain_next_stride(_rebase(0, nxt=0), fmt), 0)
            self.assertEqual(_chain_next_stride(_rebase(0, nxt=3), fmt), 24)
            self.assertEqual(
                _chain_next_stride(_auth_rebase(0, nxt=0x7FF), fmt), 0x7FF * 8)

    def test_classic_arm64e_format_still_reads_targets_as_vmaddrs(self):
        # Format 1's targets are absolute; only 9/12 add the image base.
        self.assertEqual(
            _decode_chain_ptr(_rebase(0x1_0000_4058), _DYLD_PTR_ARM64E, _BASE),
            0x1_0000_4058)

    def test_bind_ordinal_width_distinguishes_userland24(self):
        """Feed a chain of one bind with a 20-bit ordinal through the walker
        for both formats: USERLAND24 must read all 24 bits, USERLAND only the low 16
        (0x12345 -> 0x2345)."""
        ordinal = 0x12345                  # > 16 bits
        raw = (1 << 62) | ordinal

        class _Ctx(BinaryContext):
            def __init__(self):            # no Mach-O: drive _walk_chain only
                self._fixup_map = {}
                self._bind_name_map = {}
                self._segments = []
                self._data = b""

            def vmaddr_to_offset(self, va, n):
                if va != 0x1000:
                    raise ValueError("unmapped")
                return 0

            def _local_image_base(self):
                return _BASE

        import struct as _st
        for fmt, want in ((_DYLD_PTR_ARM64E_USERLAND24, "sym_0x12345"),
                          (_DYLD_PTR_ARM64E_USERLAND, "sym_0x2345")):
            c = _Ctx()
            c._data = _st.pack("<Q", raw)
            imports = [f"sym_{hex(i)}" for i in range(0x12346)]
            c._walk_chain(0x1000, fmt, imports)
            self.assertEqual(c._bind_name_map.get(0x1000), want, fmt)


def _load_expected():
    spec = importlib.util.spec_from_file_location(
        "f26_expected", os.path.join(_DIR, "expected.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@unittest.skipUnless(os.path.exists(_BINARY),
                     "f26 binary not built — run tests/synthetic_fixtures/"
                     "build_fixtures.sh f26_arm64e_fixups")
class TestArm64eBinaryAgainstDyldInfo(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        with open(_BINARY, "rb") as fh:
            cls.ctx = BinaryContext(load_macho_slice(fh.read()))
        cls.exp = _load_expected()

    def test_image_base(self):
        self.assertEqual(self.ctx.image_base, self.exp.IMAGE_BASE)

    def test_every_fixup_matches_dyld_info(self):
        wrong = []
        for slot, kind, target in self.exp.FIXUPS:
            if kind == "rebase":
                got = self.ctx._fixup_map.get(slot)
                want = self.exp.IMAGE_BASE + target
            else:
                got = self.ctx._bind_name_map.get(slot)
                want = target
            if got != want:
                wrong.append((hex(slot), kind, want, got))
        self.assertEqual(wrong, [])

    def test_no_fixups_beyond_dyld_infos(self):
        rebases = {s for s, k, _ in self.exp.FIXUPS if k == "rebase"}
        binds = {s for s, k, _ in self.exp.FIXUPS if k == "bind"}
        self.assertEqual(set(self.ctx._fixup_map), rebases)
        self.assertEqual(set(self.ctx._bind_name_map), binds)

    def test_class_list_recovered(self):
        cl = build_class_list(self.ctx, build_string_table(self.ctx))
        self.assertEqual(sorted(c.name for c in cl),
                         sorted(self.exp.CLASSES * 2))   # class + metaclass
        cls = cl.find("TestFixupClass")
        self.assertEqual([m.name for m in cls.methods], ["make"])


if __name__ == "__main__":
    unittest.main()
