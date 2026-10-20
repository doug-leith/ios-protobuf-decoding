"""
tests/test_coverage_gaps.py — Unit tests filling coverage gaps identified in
the code-review session (June 2026).

Functions covered here (all previously at 0 test references):
  proto/extractor.py:
    _identify_string_write_helpers

  Additional cases for partially-covered functions:
    _find_string_write_helper  (NSMutableString + missing-helper paths)

All tests are pure-logic / synthetic-binary; no GeoServices binary required.
"""

from __future__ import annotations

import sys
import os
import unittest
from typing import List, Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from macho.memory import BinaryContext
from macho.classlist import ClassList, ObjcClass, ObjcIvar, ObjcMethod
from proto.write_helpers import _find_string_write_helper, _identify_string_write_helpers
from tests.conftest import build_text_binary, RET_BYTES


# ── Tiny helpers ──────────────────────────────────────────────────────────────

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

        from tests._fakes import NoImage

        class _MinCtx(NoImage):
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
