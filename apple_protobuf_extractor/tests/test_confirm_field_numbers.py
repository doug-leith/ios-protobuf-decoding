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
from macho.classlist import ObjcClass, ObjcIvar
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


# ── Runner ────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    unittest.main(verbosity=2)
