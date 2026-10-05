"""
tests/test_coverage_gaps.py — Unit tests filling coverage gaps identified in
the code-review session (June 2026).

Functions covered here (all previously at 0 test references):
  proto/extractor.py:
    _decode_bcond
    _read_raw_word
    _is_in_section
    _is_in_any_section
    _identify_string_write_helpers

  Additional cases for partially-covered functions:
    _decode_cmp_imm  (shift field not previously exercised)
    _find_string_write_helper  (NSMutableString + missing-helper paths)

All tests are pure-logic / synthetic-binary; no GeoServices binary required.
"""

from __future__ import annotations

import struct
import sys
import os
import unittest
from typing import List, Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from macho.memory import BinaryContext, Section
from macho.classlist import ClassList, ObjcClass, ObjcIvar, ObjcMethod
from macho.arm64decode import (_decode_bcond, _decode_cmp_imm,
                                range_from_unsigned_gate,
                                _COND_EQ, _COND_NE, _COND_LO, _COND_LS)
from proto.dispatch import _COND_HI, _COND_HS, _find_field_count, _read_raw_word
from proto.write_helpers import _find_string_write_helper, _identify_string_write_helpers
from macho.memory import _is_in_section, _is_in_any_section
from tests.conftest import (
    build_text_binary,
    encode_bl,
    encode_b,
    NOP_BYTES,
    RET_BYTES,
)


# ── Tiny helpers ──────────────────────────────────────────────────────────────

def _encode_cmp_w(rn: int, imm12: int, shift: int = 0) -> int:
    """Encode CMP wN, #(imm12 << (shift*12)) as a 32-bit instruction word."""
    return 0x7100001F | (shift << 22) | (imm12 << 10) | (rn << 5)


def _encode_bcond(cond: int, imm19: int = 0) -> int:
    """Encode B.cond #(PC + imm19*4) as a 32-bit instruction word."""
    return 0x54000000 | ((imm19 & 0x7FFFF) << 5) | (cond & 0xF)


def _encode_movz_w32(rd: int, imm16: int) -> bytes:
    """Encode MOVZ w{rd}, #imm16 (32-bit form used for field-number args)."""
    return struct.pack('<I', 0x52800000 | ((imm16 & 0xFFFF) << 5) | (rd & 0x1F))


def _make_section(vmaddr: int = 0x1000, vmsize: int = 0x100) -> Section:
    return Section(
        name='__text', segname='__TEXT',
        vmaddr=vmaddr, vmsize=vmsize,
        file_off=0x200, flags=0,
    )


def _proto_class(name: str, ivars: Optional[List[ObjcIvar]] = None,
                 methods: Optional[List[ObjcMethod]] = None) -> ObjcClass:
    """Minimal proto-detected ObjcClass (method-name detection path)."""
    base_sels = [
        'readFrom:', 'writeTo:', 'mergeFrom:',
        'copyTo:', 'copyWithZone:', 'isEqual:',
        'hash', 'description', 'dictionaryRepresentation',
    ]
    all_methods = [ObjcMethod(name=s, types='', imp=0, is_relative=False)
                   for s in base_sels]
    if methods:
        all_methods.extend(methods)
    return ObjcClass(
        vmaddr=0x8000, name=name, is_meta=False,
        superclass_vmaddr=0, superclass_name=None,
        ro_flags=0, instance_size=32,
        methods=all_methods,
        ivars=ivars or [],
    )


# ══════════════════════════════════════════════════════════════════════════════
# _decode_cmp_imm — shift field (existing tests cover shift=0 only)
# ══════════════════════════════════════════════════════════════════════════════

class TestDecodeCmpImmShift(unittest.TestCase):
    """Exercise the imm12 << (shift*12) path not covered by existing tests."""

    def test_shift1_doubles_immediate_by_4096(self):
        # CMP w8, #2, lsl #12 → effective immediate = 2 * 4096 = 8192
        word = _encode_cmp_w(rn=8, imm12=2, shift=1)
        result = _decode_cmp_imm(word)
        self.assertIsNotNone(result)
        rn, imm = result
        self.assertEqual(rn, 8)
        self.assertEqual(imm, 2 << 12)

    def test_shift2_multiplies_immediate_by_4096_squared(self):
        # CMP w5, #1, lsl #24 → effective immediate = 1 * (4096^2) = 16777216
        word = _encode_cmp_w(rn=5, imm12=1, shift=2)
        result = _decode_cmp_imm(word)
        self.assertIsNotNone(result)
        _, imm = result
        self.assertEqual(imm, 1 << 24)

    def test_rn_field_decoded_correctly_with_nonzero_shift(self):
        word = _encode_cmp_w(rn=3, imm12=4, shift=1)
        result = _decode_cmp_imm(word)
        self.assertIsNotNone(result)
        rn, imm = result
        self.assertEqual(rn, 3)
        self.assertEqual(imm, 4 << 12)

    def test_maximum_rn_field(self):
        # rn=30 (x30 / lr) is a valid register operand for a CMP
        word = _encode_cmp_w(rn=30, imm12=1, shift=0)
        result = _decode_cmp_imm(word)
        self.assertIsNotNone(result)
        rn, imm = result
        self.assertEqual(rn, 30)
        self.assertEqual(imm, 1)


# ══════════════════════════════════════════════════════════════════════════════
# _decode_bcond
# ══════════════════════════════════════════════════════════════════════════════

class TestDecodeBcond(unittest.TestCase):
    """_decode_bcond returns the 4-bit condition code or None for non-B.cond words."""

    def test_b_hi_returns_cond_hi(self):
        word = _encode_bcond(_COND_HI)
        self.assertEqual(_decode_bcond(word), _COND_HI)

    def test_b_hs_returns_cond_hs(self):
        word = _encode_bcond(_COND_HS)
        self.assertEqual(_decode_bcond(word), _COND_HS)

    def test_b_eq_returns_zero(self):
        # Condition code 0x0 = EQ
        word = _encode_bcond(0x0)
        self.assertEqual(_decode_bcond(word), 0x0)

    def test_b_ne_returns_one(self):
        word = _encode_bcond(0x1)
        self.assertEqual(_decode_bcond(word), 0x1)

    def test_b_lt_returns_correct_cond(self):
        # LT = cond 0xB
        word = _encode_bcond(0xB)
        self.assertEqual(_decode_bcond(word), 0xB)

    def test_nonzero_offset_preserves_cond(self):
        # Offset should not affect the returned cond bits
        word = _encode_bcond(_COND_HI, imm19=42)
        self.assertEqual(_decode_bcond(word), _COND_HI)

    def test_cmp_word_returns_none(self):
        # CMP instruction shares no bits with B.cond base pattern
        cmp_word = _encode_cmp_w(rn=8, imm12=5)
        self.assertIsNone(_decode_bcond(cmp_word))

    def test_nop_returns_none(self):
        self.assertIsNone(_decode_bcond(0xD503201F))

    def test_cbz_returns_none(self):
        # CBZ x0, #0 = 0xB4000000 — similar opcode space but different pattern
        self.assertIsNone(_decode_bcond(0xB4000000))

    def test_bc_cond_bit4_set_returns_none(self):
        # BC.cond (ARMv8.8) has bit 4 set — the mask 0xFF000010 excludes these
        bc_hi = 0x54000010 | _COND_HI   # BC.HI
        self.assertIsNone(_decode_bcond(bc_hi),
                          "BC.cond (bit4=1) must not match B.cond")

    def test_all_condition_codes_in_range(self):
        # Every 4-bit condition code must round-trip correctly
        for cond in range(16):
            word = _encode_bcond(cond)
            self.assertEqual(_decode_bcond(word), cond,
                             f"cond=0x{cond:x} did not round-trip")


# ══════════════════════════════════════════════════════════════════════════════
# _read_raw_word
# ══════════════════════════════════════════════════════════════════════════════

class TestReadRawWord(unittest.TestCase):
    """_read_raw_word reads a 4-byte LE word; returns None for unmapped addresses."""

    TEXT_VA = 0x4000

    @classmethod
    def setUpClass(cls):
        # Build a binary with 4 known words followed by RET
        words = [0xDEADBEEF, 0xCAFEBABE, 0x12345678, 0x00000001]
        code = b''.join(struct.pack('<I', w) for w in words) + RET_BYTES
        cls.ctx = BinaryContext(build_text_binary(code, vmaddr=cls.TEXT_VA))
        cls.words = words

    def test_reads_first_word(self):
        self.assertEqual(_read_raw_word(self.ctx, self.TEXT_VA), self.words[0])

    def test_reads_second_word(self):
        self.assertEqual(_read_raw_word(self.ctx, self.TEXT_VA + 4), self.words[1])

    def test_reads_third_word(self):
        self.assertEqual(_read_raw_word(self.ctx, self.TEXT_VA + 8), self.words[2])

    def test_reads_fourth_word(self):
        self.assertEqual(_read_raw_word(self.ctx, self.TEXT_VA + 12), self.words[3])

    def test_unmapped_address_returns_none(self):
        self.assertIsNone(_read_raw_word(self.ctx, 0xDEAD0000))

    def test_zero_address_returns_none(self):
        self.assertIsNone(_read_raw_word(self.ctx, 0x0))

    def test_returns_none_rather_than_raising(self):
        # Must not propagate ValueError for unmapped addresses
        try:
            result = _read_raw_word(self.ctx, 0xFFFFFFFF00000000)
        except Exception as exc:
            self.fail(f"_read_raw_word raised unexpectedly: {exc}")
        self.assertIsNone(result)


# ══════════════════════════════════════════════════════════════════════════════
# _is_in_section
# ══════════════════════════════════════════════════════════════════════════════

class TestIsInSection(unittest.TestCase):
    """_is_in_section: half-open interval [vmaddr, vmaddr+vmsize)."""

    def setUp(self):
        self.sect = _make_section(vmaddr=0x1000, vmsize=0x100)

    def test_address_inside_range(self):
        self.assertTrue(_is_in_section(0x1050, self.sect))

    def test_address_at_start(self):
        self.assertTrue(_is_in_section(0x1000, self.sect))

    def test_address_at_last_byte(self):
        self.assertTrue(_is_in_section(0x10FF, self.sect))

    def test_address_one_past_end_is_false(self):
        self.assertFalse(_is_in_section(0x1100, self.sect))

    def test_address_well_past_end_is_false(self):
        self.assertFalse(_is_in_section(0x2000, self.sect))

    def test_address_before_start_is_false(self):
        self.assertFalse(_is_in_section(0x0FFF, self.sect))

    def test_none_section_always_false(self):
        self.assertFalse(_is_in_section(0x1050, None))

    def test_zero_vmsize_section_always_false(self):
        empty = _make_section(vmaddr=0x1000, vmsize=0)
        self.assertFalse(_is_in_section(0x1000, empty))


# ══════════════════════════════════════════════════════════════════════════════
# _is_in_any_section
# ══════════════════════════════════════════════════════════════════════════════

class TestIsInAnySection(unittest.TestCase):

    def setUp(self):
        self.s1 = _make_section(vmaddr=0x1000, vmsize=0x100)
        self.s2 = _make_section(vmaddr=0x2000, vmsize=0x200)

    def test_address_in_first_section(self):
        self.assertTrue(_is_in_any_section(0x1050, [self.s1, self.s2]))

    def test_address_in_second_section(self):
        self.assertTrue(_is_in_any_section(0x2100, [self.s1, self.s2]))

    def test_address_between_sections_is_false(self):
        self.assertFalse(_is_in_any_section(0x1200, [self.s1, self.s2]))

    def test_address_past_both_sections_is_false(self):
        self.assertFalse(_is_in_any_section(0x5000, [self.s1, self.s2]))

    def test_empty_list_always_false(self):
        self.assertFalse(_is_in_any_section(0x1050, []))

    def test_single_section_list(self):
        self.assertTrue(_is_in_any_section(0x1000, [self.s1]))
        self.assertFalse(_is_in_any_section(0x2000, [self.s1]))

    def test_with_none_entry_in_list(self):
        # _is_in_section handles None gracefully; the any() should too
        self.assertTrue(_is_in_any_section(0x1050, [None, self.s1]))


# ══════════════════════════════════════════════════════════════════════════════
# Field-count gate removal regression
# ══════════════════════════════════════════════════════════════════════════════

class TestFieldCountGateRemoval(unittest.TestCase):
    """
    Regression tests ensuring the field_count gate is gone.

    The gate was:
        if field_count > 0 and not confirmed and ordinal > field_count:
            continue

    This incorrectly truncated unconfirmed proto fields whenever:
      (a) the readFrom: discovery matched the wrong function and returned a
          spuriously small field_count, OR
      (b) the proto schema had been extended beyond the original dispatch
          table (legitimate field_count < len(field_ivars)).

    Both failure modes are tested here by forcing _confirm_field_numbers to
    return a small field_count and verifying that extract_proto_message still
    emits all field ivars.
    """

    def _run(self, cls):
        """
        Call extract_proto_message with _confirm_field_numbers patched to return
        EMPTY confirmed_numbers — proving every field ivar is still emitted (no
        field-count truncation gate exists).  ``field_count`` itself was removed
        from _FieldNumberResult 2026-06-15 along with the inert pointer-table path,
        so the gate it once fed is now structurally impossible; this guards against
        any truncation regression returning.
        """
        from unittest.mock import patch
        from proto.extractor import extract_proto_message, _FieldNumberResult
        from macho.strings import StringTable
        from macho.classlist import ClassList

        class _MinCtx:
            is_cache_backed = False
            def has_section(self, *a): return False
            def section(self, *a): raise ValueError
            def read_ptr(self, va): raise ValueError
            def read_u32(self, va): raise ValueError
            def read_bytes(self, va, n): raise ValueError

        class _NullST:
            def get(self, va): return ''
            def find(self, s): return []
            def all_in_section(self, s): return []

        class _NullCL:
            def __iter__(self): return iter([])
            def by_vmaddr(self, va): return None
            def find(self, n): return None
            def find_subclasses(self, n, transitive=True): return []
            def __len__(self): return 0
            def __contains__(self, n): return False

        fake_result = _FieldNumberResult(
            confirmed_numbers={},
            wt_helpers={},
            string_helper=None,
        )
        with patch('proto.extractor._confirm_field_numbers',
                   return_value=fake_result):
            return extract_proto_message(
                _MinCtx(), _NullST(), _NullCL(), cls
            )

    def _make_proto_cls(self, n_fields: int) -> ObjcClass:
        """Proto class with n_fields scalar ivars detected via ivar heuristic."""
        # Use has-bits ivar for proto detection (cache-native path)
        has_bits_enc = '{?=' + ''.join(
            f'"has_field{i}"b1' for i in range(1, n_fields + 1)
        ) + '}'
        ivars = [ObjcIvar(name='_flags', type_enc=has_bits_enc,
                          offset=0, size=8)]
        ivars += [
            ObjcIvar(name=f'_field{i}', type_enc='i', offset=i * 8, size=4)
            for i in range(1, n_fields + 1)
        ]
        return ObjcClass(
            vmaddr=0x8000, name='GEOMockProto', is_meta=False,
            superclass_vmaddr=0, superclass_name=None,
            ro_flags=0, instance_size=n_fields * 8 + 8,
            methods=[],
            ivars=ivars,
        )

    def test_all_fields_emitted_with_no_confirmed_numbers(self):
        """
        Core regression: 10 field ivars with empty confirmed_numbers must all be
        emitted.  The old field_count gate would have cut fields at ordinal > N.
        """
        N = 10
        cls = self._make_proto_cls(N)
        msg = self._run(cls)
        self.assertIsNotNone(msg, "extract_proto_message must not return None")
        self.assertEqual(
            len(msg.fields), N,
            f"Expected {N} fields but got {len(msg.fields)} — "
            f"a field-count truncation gate may have been re-introduced"
        )

    def test_five_field_class_all_emitted(self):
        N = 5
        cls = self._make_proto_cls(N)
        msg = self._run(cls)
        self.assertIsNotNone(msg)
        self.assertEqual(len(msg.fields), N)

    def test_single_field_class_emitted(self):
        """Edge: a one-field class must survive."""
        cls = self._make_proto_cls(1)
        msg = self._run(cls)
        self.assertIsNotNone(msg)
        self.assertEqual(len(msg.fields), 1)
    """
    Boundary-condition unit tests for _identify_string_write_helpers.

    The "returns a VA when a string ivar has a confirmed helper" case requires
    a binary with ADRP+LDRSW patterns into __DATA/__objc_ivar sections, which
    is already covered by the live GeoServices integration tests
    (TestRepeatedStringReclassification in test_proto.py).
    """

    @classmethod
    def setUpClass(cls):
        cls.ctx = BinaryContext(build_text_binary(RET_BYTES, vmaddr=0x4000))

    def test_empty_classlist_returns_empty_set(self):
        cl = ClassList([])
        result = _identify_string_write_helpers(self.ctx, cl)
        self.assertIsInstance(result, set)
        self.assertEqual(len(result), 0)

    def test_non_proto_class_skipped(self):
        # Class with no proto methods or ivar patterns → not detected as proto
        non_proto = ObjcClass(
            vmaddr=0x1000, name='GEOFoo', is_meta=False,
            superclass_vmaddr=0, superclass_name=None, ro_flags=0, instance_size=16,
            methods=[ObjcMethod(name='init', types='', imp=0, is_relative=False)],
        )
        cl = ClassList([non_proto])
        result = _identify_string_write_helpers(self.ctx, cl)
        self.assertEqual(len(result), 0)

    def test_proto_class_with_no_string_ivars_returns_empty_set(self):
        # A genuine proto class but all ivars are scalar — no NSString ivar present
        proto_cls = _proto_class(
            'GEOScalarMsg',
            ivars=[
                ObjcIvar(name='_count', type_enc='i', offset=8, size=4),
                ObjcIvar(name='_flags', type_enc='{?="has_count"b1}', offset=0, size=4),
            ],
        )
        cl = ClassList([proto_cls])
        result = _identify_string_write_helpers(self.ctx, cl)
        self.assertEqual(len(result), 0)

    def test_metaclass_skipped(self):
        meta = ObjcClass(
            vmaddr=0x2000, name='GEOMeta', is_meta=True,
            superclass_vmaddr=0, superclass_name=None, ro_flags=0, instance_size=16,
            ivars=[ObjcIvar(name='_name', type_enc='@"NSString"', offset=8, size=8)],
        )
        cl = ClassList([meta])
        result = _identify_string_write_helpers(self.ctx, cl)
        self.assertEqual(len(result), 0, "Metaclasses must be skipped")

    def test_returns_set_type(self):
        result = _identify_string_write_helpers(self.ctx, ClassList([]))
        self.assertIsInstance(result, set)


# ══════════════════════════════════════════════════════════════════════════════
# _find_string_write_helper — additional cases
# ══════════════════════════════════════════════════════════════════════════════

class TestFindStringWriteHelperAdditional(unittest.TestCase):
    """
    Complements the existing tests in test_proto.py with edge cases not
    previously covered: NSMutableString ivar and helper absent from dict.
    """

    def test_nsmutablestring_ivar_counts_as_string(self):
        # @"NSMutableString" must be treated identically to @"NSString"
        ivars = [
            ObjcIvar(name='_tag', type_enc='i', offset=8, size=4),
            ObjcIvar(name='_label', type_enc='@"NSMutableString"', offset=16, size=8),
        ]
        helpers = {'_tag': 0x1000, '_label': 0x2000}
        result = _find_string_write_helper(helpers, ivars, set())
        self.assertEqual(result, 0x2000,
                         "@NSMutableString ivar must identify string helper")

    def test_string_ivar_with_no_helper_entry_returns_none(self):
        # The NSString ivar is present but its key is absent from helpers
        ivars = [
            ObjcIvar(name='_name', type_enc='@"NSString"', offset=8, size=8),
        ]
        helpers = {}   # no entry for _name
        result = _find_string_write_helper(helpers, ivars, set())
        self.assertIsNone(result,
                          "Missing helper entry for NSString ivar must return None")

    def test_first_string_ivar_helper_returned_when_multiple_present(self):
        # When multiple NSString ivars are present, the first one with
        # a confirmed helper determines the string-helper VA
        ivars = [
            ObjcIvar(name='_a', type_enc='@"NSString"', offset=8, size=8),
            ObjcIvar(name='_b', type_enc='@"NSString"', offset=16, size=8),
        ]
        helpers = {'_a': 0xAAAA, '_b': 0xBBBB}
        result = _find_string_write_helper(helpers, ivars, set())
        self.assertEqual(result, 0xAAAA,
                         "First matching string ivar determines the helper VA")

    def test_empty_ivars_list_returns_none(self):
        result = _find_string_write_helper({'_x': 0x1000}, [], set())
        self.assertIsNone(result)

    def test_empty_helpers_dict_returns_none(self):
        ivars = [ObjcIvar(name='_name', type_enc='@"NSString"', offset=8, size=8)]
        result = _find_string_write_helper({}, ivars, set())
        self.assertIsNone(result)


class TestRangeFromUnsignedGate(unittest.TestCase):
    """The shared jump-table count-from-gate convention (range_from_unsigned_gate),
    extracted from the 4 sites that inlined it (`_find_dispatch_cluster`, the
    jump-table enum harvester Idiom A, `_harvest_dictrep_enums`, and
    `_dictrep_cmp_range`).  A divergence in this off-by-one silently drops the
    last enum value / dispatch arm, so it is pinned here."""

    def test_hi_covers_imm_plus_one(self):
        # b.hi (index > imm → default) ⇒ valid indices 0..imm ⇒ imm+1 entries.
        self.assertEqual(range_from_unsigned_gate(_COND_HI, 7), 8)
        self.assertEqual(range_from_unsigned_gate(_COND_HI, 0), 1)

    def test_hs_covers_imm(self):
        # b.hs (index >= imm → default) ⇒ valid indices 0..imm-1 ⇒ imm entries.
        self.assertEqual(range_from_unsigned_gate(_COND_HS, 7), 7)
        self.assertEqual(range_from_unsigned_gate(_COND_HS, 1), 1)

    def test_non_range_conditions_yield_zero(self):
        # Only the unsigned default-branch conditions are range gates; anything
        # else (incl. the routing-sense b.lo/b.ls and None) is "no gate".
        for cond in (_COND_EQ, _COND_NE, _COND_LO, _COND_LS, None):
            self.assertEqual(range_from_unsigned_gate(cond, 7), 0)

    def test_matches_legacy_inline_convention(self):
        # Exhaustive equivalence to the pre-refactor inline expression at every
        # site: `imm+1 if HI elif imm if HS else 0`.
        for imm in range(0, 64):
            for cond in (_COND_HI, _COND_HS, _COND_EQ, _COND_NE,
                         _COND_LO, _COND_LS, None):
                expected = (imm + 1 if cond == _COND_HI
                            else imm if cond == _COND_HS else 0)
                self.assertEqual(range_from_unsigned_gate(cond, imm), expected)


class TestEmbeddedStructNote(unittest.TestCase):
    """`_embedded_struct_note` flags a SINGULAR by-value embedded C-struct field
    (@encode `{Name=...}`) that resolved to bytes, so the degradation is visible
    (transparency principle / LIMITATIONS.md (2)).  Genuine NSData bytes and the
    anonymous `{?=...}` shapes (has-bits / packed-list) must NOT be flagged."""

    def setUp(self):
        from proto.extractor import _embedded_struct_note
        self.fn = _embedded_struct_note

    def _iv(self, enc):
        return ObjcIvar(name='_x', type_enc=enc, offset=8, size=8)

    def test_named_struct_resolved_to_bytes_is_flagged(self):
        note = self.fn(self._iv('{GEOSessionID="_high"Q"_low"Q}'), 'bytes', None)
        self.assertIsNotNone(note)
        self.assertIn('GEOSessionID', note)
        self.assertIn('LIMITATIONS.md (2)', note)

    def test_genuine_nsdata_bytes_not_flagged(self):
        # @"NSData" → ("bytes", None) but enc starts with '@', not '{' → real bytes.
        self.assertIsNone(self.fn(self._iv('@"NSData"'), 'bytes', None))

    def test_anonymous_hasbits_struct_not_flagged(self):
        self.assertIsNone(self.fn(self._iv('{?="has_a"b1"has_b"b1}'), 'bytes', None))

    def test_packed_list_struct_not_flagged(self):
        self.assertIsNone(
            self.fn(self._iv('{?="list"^i"count"Q"size"Q}'), 'bytes', None))

    def test_resolved_message_type_not_flagged(self):
        # A struct that DID resolve to a concrete type (type_class set) is not bytes.
        self.assertIsNone(
            self.fn(self._iv('{GEOThing=QQ}'), 'GEOThing', 'GEOThing'))

    def test_scalar_not_flagged(self):
        self.assertIsNone(self.fn(self._iv('i'), 'int32', None))


# ── Runner ────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    unittest.main(verbosity=2)
