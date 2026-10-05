"""
tests/test_confirm_field_numbers.py — Tests for the _confirm_field_numbers helper
extracted from extract_proto_message (Phase 3).

Written BEFORE extraction; all tests must fail until the function and
_FieldNumberResult dataclass exist in proto.extractor.
"""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from macho.memory import BinaryContext
from macho.strings import StringTable
from macho.classlist import ClassList, ObjcClass, ObjcIvar, ObjcMethod
from tests.conftest import build_text_binary, RET_BYTES


# ── Tiny builders ─────────────────────────────────────────────────────────────

def _ctx() -> BinaryContext:
    return BinaryContext(build_text_binary(RET_BYTES, vmaddr=0x4000))


def _ivar(name: str, type_enc: str = 'i', offset: int = 8) -> ObjcIvar:
    return ObjcIvar(name=name, type_enc=type_enc, offset=offset, size=4)


def _make_cls(name: str = 'GEOMock', methods=None, ivars=None) -> ObjcClass:
    return ObjcClass(
        vmaddr=0x8000, name=name, is_meta=False,
        superclass_vmaddr=0, superclass_name=None,
        ro_flags=0, instance_size=32,
        methods=methods or [],
        ivars=ivars or [],
    )


def _import():
    from proto.extractor import _confirm_field_numbers, _FieldNumberResult
    return _confirm_field_numbers, _FieldNumberResult


# ══════════════════════════════════════════════════════════════════════════════
# _FieldNumberResult dataclass shape
# ══════════════════════════════════════════════════════════════════════════════

class TestFieldNumberResultShape(unittest.TestCase):
    """_FieldNumberResult must be a dataclass with exactly four named fields."""

    def setUp(self):
        _, self.RR = _import()

    def test_has_confirmed_numbers_field(self):
        r = self.RR(confirmed_numbers={}, wt_helpers={},
                    string_helper=None)
        self.assertIsInstance(r.confirmed_numbers, dict)

    def test_has_wt_helpers_field(self):
        r = self.RR(confirmed_numbers={}, wt_helpers={'_x': 0x1000},
                    string_helper=None)
        self.assertEqual(r.wt_helpers, {'_x': 0x1000})

    def test_has_string_helper_field(self):
        r = self.RR(confirmed_numbers={}, wt_helpers={},
                    string_helper=0x5000)
        self.assertEqual(r.string_helper, 0x5000)

    def test_none_string_helper_allowed(self):
        r = self.RR(confirmed_numbers={}, wt_helpers={},
                    string_helper=None)
        self.assertIsNone(r.string_helper)


# ══════════════════════════════════════════════════════════════════════════════
# _confirm_field_numbers — boundary conditions (no real binary needed)
# ══════════════════════════════════════════════════════════════════════════════

class TestConfirmFieldNumbersBoundary(unittest.TestCase):
    """Boundary tests that don't require a GeoServices binary."""

    def setUp(self):
        self._fn, self.RR = _import()
        self.ctx = _ctx()

    def _call(self, field_ivars=None, instance_method_names=None,
              string_write_helpers=frozenset(), cls=None):
        return self._fn(
            self.ctx,
            cls or _make_cls(),
            field_ivars or [],
            instance_method_names or set(),
            string_write_helpers=string_write_helpers,
        )

    # ── Return type ──────────────────────────────────────────────────────────

    def test_returns_field_number_result(self):
        r = self._call()
        self.assertIsInstance(r, self.RR)

    def test_result_fields_exist(self):
        r = self._call()
        for attr in ('confirmed_numbers', 'wt_helpers', 'string_helper'):
            self.assertTrue(hasattr(r, attr), f"Missing attribute: {attr}")

    # ── Empty inputs → empty outputs ─────────────────────────────────────────

    def test_no_ivars_returns_empty_confirmed_numbers(self):
        r = self._call(field_ivars=[])
        self.assertEqual(r.confirmed_numbers, {})

    def test_no_ivars_returns_empty_wt_helpers(self):
        r = self._call(field_ivars=[])
        self.assertEqual(r.wt_helpers, {})

    def test_cls_without_readfrom_returns_empty_confirmed(self):
        # No writeTo: field numbers for a bare class → confirmed_numbers empty.
        ivars = [_ivar('_count', 'i', 8), _ivar('_name', '@', 16)]
        r = self._call(field_ivars=ivars)
        self.assertEqual(r.confirmed_numbers, {})

    # ── string_write_helpers fallback ────────────────────────────────────────

    def test_string_helper_set_from_binary_wide_fallback(self):
        # When local NSString detection fails but binary-wide set is provided,
        # string_helper is taken from the binary-wide set.
        ivars = [_ivar('_count', 'i', 8)]   # no @"NSString" ivar
        r = self._call(
            field_ivars=ivars,
            string_write_helpers=frozenset({0xDEAD}),
        )
        self.assertEqual(r.string_helper, 0xDEAD,
                         "Binary-wide fallback helper must be used when no local one found")

    def test_string_helper_none_when_no_binary_wide_set(self):
        ivars = [_ivar('_count', 'i', 8)]
        r = self._call(field_ivars=ivars, string_write_helpers=frozenset())
        self.assertIsNone(r.string_helper)

    def test_confirmed_numbers_type_is_dict(self):
        r = self._call()
        self.assertIsInstance(r.confirmed_numbers, dict)

    def test_wt_helpers_type_is_dict(self):
        r = self._call()
        self.assertIsInstance(r.wt_helpers, dict)

    # ── Multiple binary-wide helpers — any one is fine ────────────────────────

    def test_one_helper_chosen_from_binary_wide_set(self):
        ivars = [_ivar('_count', 'i', 8)]
        helpers = frozenset({0x1000, 0x2000, 0x3000})
        r = self._call(field_ivars=ivars, string_write_helpers=helpers)
        self.assertIn(r.string_helper, helpers)


# NOTE: the field-count-aware writeTo: disassembly budget (_writeto_insn_budget /
# _WRITETO_MAX_INSNS / _WRITETO_INSNS_PER_FIELD) and its TestWriteToInsnBudget cover
# were deleted in Phase B8 with the forward-scan decoder.  The sole decoder is now
# the CFG walk, which is reachability-bounded (no instruction budget).


# ══════════════════════════════════════════════════════════════════════════════
# _writeto_field_number_before — tail-call write detection
# ══════════════════════════════════════════════════════════════════════════════

class TestWriteToFieldNumberBefore(unittest.TestCase):
    """The field number for a write call is the `mov w2,#N` before it — directly
    for a `bl`, or past the hoisted epilogue (`ldp`/`stp`/`unk`) for a tail-call
    `b`.  Regression cover for locationd ALSCellTower.psc / ALSLocation.infoMask
    (last field, tail-call `b _PBDataWriterWrite…Field`)."""

    def setUp(self):
        from proto.writeto import _writeto_field_number_before
        from macho.disasm import Insn
        self.fn = _writeto_field_number_before
        self.Insn = Insn

    def _i(self, mnem, op=''):
        return self.Insn(addr=0, mnemonic=mnem, op_str=op, size=4, raw=b'\x00\x00\x00\x00')

    def test_bl_field_number_immediately_before(self):
        insns = [self._i('mov', 'x0, x19'),
                 self._i('movz', 'w2, #0x3'),
                 self._i('bl', '#0x1000')]
        self.assertEqual(self.fn(insns, 2), 3)

    def test_tailcall_b_with_epilogue_between(self):
        # mov w2,#0xc ; ldp ; ldp ; <unk post-indexed ldp> ; b helper
        insns = [self._i('movz', 'w2, #0xc'),
                 self._i('ldp', 'x29, x30, [sp, #0x20]'),
                 self._i('ldp', 'x20, x19, [sp, #0x10]'),
                 self._i('unk', '#0xa8c357f6'),
                 self._i('b', '#0x10138dacc')]
        self.assertEqual(self.fn(insns, 4), 12)

    def test_double_field_uses_w1(self):
        # A double field's number is in w1 and its VALUE in d0, so the call has an FP
        # argument (without one `mov w1,#N` is just a constant argument — see
        # test_newer_toolchain_ios27.TestFieldNumberInW1NeedsAnFpValue).
        insns = [self._i('ldr', 'd0, [x8]'),
                 self._i('movz', 'w1, #0x7'),
                 self._i('ldp', 'x29, x30, [sp, #0x20]'),
                 self._i('b', '#0x2000')]
        self.assertEqual(self.fn(insns, 3), 7)

    def test_w1_constant_without_an_fp_value_is_not_a_field_number(self):
        insns = [self._i('movz', 'w1, #0x7'),
                 self._i('ldp', 'x29, x30, [sp, #0x20]'),
                 self._i('b', '#0x2000')]
        self.assertIsNone(self.fn(insns, 2))

    def test_control_flow_branch_returns_none(self):
        # A `b` with no field-number setup before it (after skipping non-epilogue
        # instructions) must yield None — not a spurious field write.
        insns = [self._i('ldr', 'w1, [x20, x8]'),
                 self._i('b', '#0x3000')]
        self.assertIsNone(self.fn(insns, 1))

    def test_skip_bounded_does_not_run_off(self):
        # More than the skip bound of epilogue insns before any mov → None.
        insns = [self._i('movz', 'w2, #0x5')] + \
                [self._i('ldp', f'x{n}, x{n+1}, [sp]') for n in range(8)] + \
                [self._i('b', '#0x4000')]
        self.assertIsNone(self.fn(insns, len(insns) - 1))


# ── Runner ────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    unittest.main(verbosity=2)
