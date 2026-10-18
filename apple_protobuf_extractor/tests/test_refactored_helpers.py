"""
tests/test_refactored_helpers.py — Tests for the four helpers extracted from
the extract_proto_message god function (June 2026 refactor).

Written BEFORE the extraction so that:
  • Failing imports confirm the functions don't yet exist.
  • Once extracted, all tests must pass with zero changes to this file.

Functions under test (all new, all in proto.extractor):
    _RepeatedTypeResult / _resolve_repeated_field_type
    _collect_enum_definitions

(The former _apply_pass_b / Pass-A / Pass-B name-overlap fallbacks were removed
2026-06-08 — a census across GeoServices / locationd / CoreLocationProtobuf
showed they resolved zero fields; unresolved repeated fields now fall back to
the safe `repeated bytes`.)
"""

from __future__ import annotations

import sys
import os
import unittest
from typing import List, Optional
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from macho.memory import BinaryContext
from macho.strings import StringTable, build_string_table
from macho.classlist import ClassList, ObjcClass, ObjcIvar, ObjcMethod
from proto.models import FieldLabel, ProtoField, ProtoEnum
from tests.conftest import build_text_binary, RET_BYTES


# ── Lazy imports (functions don't exist until after extraction) ───────────────

def _import_helpers():
    from proto.repeated import _RepeatedTypeResult, _resolve_repeated_field_type
    from proto.enums import _collect_enum_definitions
    return (_RepeatedTypeResult,
            _resolve_repeated_field_type,
            _collect_enum_definitions)


# ── Tiny builders ─────────────────────────────────────────────────────────────

def _ctx() -> BinaryContext:
    return BinaryContext(build_text_binary(RET_BYTES, vmaddr=0x4000))


def _st() -> StringTable:
    return StringTable()


def _empty_cl() -> ClassList:
    return ClassList([])


def _make_method(name: Optional[str] = None, imp: int = 0,
                 types: str = '') -> ObjcMethod:
    return ObjcMethod(name=name, types=types, imp=imp, is_relative=False)


def _make_cls(name: str = 'GEOMock', methods: Optional[List[ObjcMethod]] = None,
              ivars: Optional[List[ObjcIvar]] = None) -> ObjcClass:
    return ObjcClass(
        vmaddr=0x8000, name=name, is_meta=False,
        superclass_vmaddr=0, superclass_name=None,
        ro_flags=0, instance_size=32,
        methods=methods or [],
        ivars=ivars or [],
    )


def _scalar_field(name: str, type_name: str = 'int32',
                  type_class: Optional[str] = None,
                  number: int = 1) -> ProtoField:
    return ProtoField(name=name, number=number, type_name=type_name,
                      label=FieldLabel.OPTIONAL, type_class=type_class)


def _enum_field(name: str, enum_name: str, number: int = 1) -> ProtoField:
    return ProtoField(name=name, number=number, type_name=enum_name,
                      label=FieldLabel.OPTIONAL, type_class=f'ENUM:{enum_name}')


# ══════════════════════════════════════════════════════════════════════════════
# _resolve_repeated_field_type
# ══════════════════════════════════════════════════════════════════════════════

class TestResolveRepeatedFieldType(unittest.TestCase):
    """
    _resolve_repeated_field_type determines the concrete element type for one
    repeated NSArray field.  Returns _RepeatedTypeResult(type_name, type_class).

    Resolution order: write-helper string check → +xyzType metaclass method → safe
    `bytes` fallback.  The Pass-A / Pass-B name-overlap fallbacks were removed
    2026-06-08, the name-suffix class guess ("Strategy 2") and the pool-suffix
    refinement on 2026-10-13.
    """

    def setUp(self):
        (self.RR, self._fn, *_) = _import_helpers()
        self.ctx = _ctx()

    def _call(self, ivar_name: str, pname: str,
              string_helper: Optional[int] = None,
              wt_helpers: Optional[dict] = None,
              resolved_type: str = 'bytes',
              element_sel: str = '_sel_',
              element_unresolved: bool = False):
        # element_sel mimics _repeated_element_type's return: a +xyzType SELECTOR.
        # _resolve_repeated_type now returns (type_name, element_unresolved).
        ivar = ObjcIvar(name=ivar_name, type_enc='@', offset=8, size=8)
        with patch('proto.repeated._repeated_element_type', return_value=element_sel), \
             patch('proto.repeated._resolve_repeated_type',
                   return_value=(resolved_type, element_unresolved)):
            return self._fn(
                ivar, pname,
                metaclass=None, cl=_empty_cl(), ctx=self.ctx,
                string_helper=string_helper,
                wt_helpers=wt_helpers or {},
            )

    # ── resolved != "bytes" ───────────────────────────────────────────────────

    def test_resolved_class_returned_directly(self):
        r = self._call('_places', 'places', resolved_type='GEOPDPlace')
        self.assertEqual(r.type_name, 'GEOPDPlace')
        self.assertEqual(r.type_class, 'GEOPDPlace')

    def test_resolved_string_type_class_is_none(self):
        r = self._call('_names', 'names', resolved_type='string')
        self.assertEqual(r.type_name, 'string')
        self.assertIsNone(r.type_class)

    def test_string_outcome_is_abi_confirmed(self):
        # A `string` outcome is ABI-confirmed (NSString mapping), not a guess.
        r = self._call('_names', 'names',
                       resolved_type='string', element_sel='nameType')
        self.assertEqual(r.type_name, 'string')
        self.assertTrue(r.abi_confirmed)

    def test_resolved_class_is_not_abi_confirmed(self):
        r = self._call('_widgets', 'widgets',
                       resolved_type='GEOWidget', element_sel='widgetType')
        self.assertEqual(r.type_class, 'GEOWidget')
        self.assertFalse(r.abi_confirmed)

    def test_result_has_no_name_guess_flag(self):
        # via_name_suffix was the Strategy-2 provenance flag; the strategy is gone.
        self.assertFalse(hasattr(self._call('_items', 'items'), 'via_name_suffix'))

    def test_resolved_class_is_never_rewritten_by_name(self):
        # The pool-suffix refinement used to replace the IMP-confirmed +xyzType class
        # with a pool class sharing the field-name suffix (iOS 27: the resolver's
        # correct GEOFormattedString became GEOCompositeAnnouncement; only the
        # structural lever masked it).  The signature has no pool any more, and the
        # class read out of the method stands.
        import inspect
        self.assertNotIn('meta_type_pool', inspect.signature(self._fn).parameters)
        r = self._call('_announcements', 'announcements', resolved_type='GEOFormattedString',
                       element_sel='announcementType')
        self.assertEqual((r.type_name, r.type_class),
                         ('GEOFormattedString', 'GEOFormattedString'))

    def test_genuine_bytes_not_element_unresolved(self):
        # A resolved NSData element → ("bytes", False): genuine repeated bytes,
        # must NOT be flagged element_unresolved.
        r = self._call('_blobs', 'blobs', resolved_type='bytes',
                       element_unresolved=False)
        self.assertEqual(r.type_name, 'bytes')
        self.assertFalse(r.element_unresolved)
        # On its own this only exercises the (already trivially-False)
        # element_unresolved=False branch -- both before and after the
        # element_unresolved-propagation fix, a "bytes"/False input yields
        # False.  Also check the True case here so this test alone would have
        # caught a regression in the propagation (the sibling
        # test_unresolved_bytes_propagates_element_unresolved below covers the
        # same thing, but this test must not depend on that one running too).
        r2 = self._call('_blobs', 'blobs', resolved_type='bytes',
                        element_unresolved=True)
        self.assertEqual(r2.type_name, 'bytes')
        self.assertTrue(r2.element_unresolved)

    def test_unresolved_bytes_propagates_element_unresolved(self):
        # A give-up ("bytes", True) → element_unresolved must propagate so the
        # caller can attach the degraded-bytes note.
        r = self._call('_items', 'items', resolved_type='bytes',
                       element_unresolved=True)
        self.assertEqual(r.type_name, 'bytes')
        self.assertTrue(r.element_unresolved)

    # ── string write helper is checked FIRST (ABI evidence outranks any class) ─

    def test_string_helper_beats_a_resolved_message_class(self):
        # GEOPDSSearchEvChargingParameters.networks: a name guess used to pick the unique
        # class ending in "Network" (GEOLogMsgEventNetwork) but writeTo: writes the
        # field with the binary-wide NSString helper -> it is a repeated string.
        r = self._call('_networks', 'networks',
                       string_helper=0xAAAA, wt_helpers={'_networks': 0xAAAA},
                       resolved_type='GEOLogMsgEventNetwork',
                       element_sel='networkType')
        self.assertEqual(r.type_name, 'string')
        self.assertIsNone(r.type_class)
        self.assertTrue(r.abi_confirmed)

    def test_non_string_helper_does_not_override_resolved_class(self):
        # The field's writer is a different helper (the message writer): the
        # resolved class stands.
        r = self._call('_places', 'places',
                       string_helper=0xAAAA, wt_helpers={'_places': 0xBBBB},
                       resolved_type='GEOPDPlace', element_sel='placeType')
        self.assertEqual(r.type_class, 'GEOPDPlace')
        self.assertFalse(r.abi_confirmed)

    def test_no_string_helper_known_does_not_override_resolved_class(self):
        r = self._call('_places', 'places', string_helper=None,
                       wt_helpers={'_places': 0xAAAA},
                       resolved_type='GEOPDPlace', element_sel='placeType')
        self.assertEqual(r.type_class, 'GEOPDPlace')

    # ── resolved == "bytes", string helper matches ────────────────────────────

    def test_string_helper_match_reclassifies_to_string(self):
        r = self._call('_labels', 'labels',
                       string_helper=0xAAAA, wt_helpers={'_labels': 0xAAAA})
        self.assertEqual(r.type_name, 'string')
        self.assertIsNone(r.type_class)

    # ── resolved == "bytes" → safe bytes fallback (no Pass A/B) ────────────────

    def test_result_has_all_required_attributes(self):
        r = self._call('_places', 'places')
        for attr in ('type_name', 'type_class'):
            self.assertTrue(hasattr(r, attr), f"Missing attribute: {attr}")


# ══════════════════════════════════════════════════════════════════════════════
# _collect_enum_definitions
# ══════════════════════════════════════════════════════════════════════════════

class TestCollectEnumDefinitions(unittest.TestCase):
    """
    _collect_enum_definitions runs both the shared-cache methname scan
    (which may mutate fields by adding ENUM: tags) and the enum extraction
    loop (which may mutate fields by reverting ENUM: → int32 and returns
    List[ProtoEnum]).
    """

    def setUp(self):
        (*_, self._fn) = _import_helpers()
        self.ctx = _ctx()
        self.st  = _st()

    # ── No ENUM: fields ───────────────────────────────────────────────────────

    def test_empty_fields_returns_empty(self):
        self.assertEqual(
            self._fn(self.ctx, _make_cls(), [], self.st, set(), None), [])

    def test_non_enum_fields_ignored(self):
        fields = [_scalar_field('count'), _scalar_field('name', 'string')]
        result = self._fn(self.ctx, _make_cls(), fields, self.st, set(), None)
        self.assertEqual(result, [])

    # ── ENUM: field with imp=0 (method found by name but no IMP) ─────────────

    def test_method_found_by_name_imp_zero_creates_empty_protoneum(self):
        cls = _make_cls(methods=[_make_method('statusAsString:', imp=0)])
        fld = _enum_field('status', 'Status')
        result = self._fn(self.ctx, cls, [fld], self.st,
                          instance_method_names={'statusAsString:'},
                          metaclass=None)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].name, 'Status')
        self.assertEqual(result[0].values, [])

    # ── ENUM: field, method absent, instance names non-empty → revert ─────────

    def test_method_not_found_instance_names_nonempty_reverts_field(self):
        # No 'feedbackTypeAsString:' method on class, instance_method_names non-empty
        # → method_exists=False → revert to int32
        fld = _enum_field('feedbackType', 'FeedbackType')
        self._fn(self.ctx, _make_cls(), [fld], self.st,
                 instance_method_names={'readFrom:'},
                 metaclass=None)
        self.assertEqual(fld.type_name, 'int32')
        self.assertIsNone(fld.type_class)

    def test_revert_returns_no_enum(self):
        fld = _enum_field('feedbackType', 'FeedbackType')
        result = self._fn(self.ctx, _make_cls(), [fld], self.st,
                          instance_method_names={'readFrom:'},
                          metaclass=None)
        self.assertEqual(result, [])

    def test_revert_flags_field_with_disambiguation_comment(self):
        # Transparency (Gap A Option 1): a field flagged as an enum whose values
        # cannot be recovered is reverted to int32 AND carries a comment so the
        # degradation is visible, not silent.  Drives the mode-aware header
        # severity via n_ambiguous.
        from proto.enums import _ENUM_UNRESOLVED_COMMENT
        fld = _enum_field('feedbackType', 'FeedbackType')
        self._fn(self.ctx, _make_cls(), [fld], self.st,
                 instance_method_names={'readFrom:'},
                 metaclass=None)
        self.assertEqual(fld.type_name, 'int32')
        self.assertIsNone(fld.type_class)
        self.assertEqual(fld.disambiguation_comment, _ENUM_UNRESOLVED_COMMENT)

    def test_revert_clears_all_fields_sharing_same_enum_name(self):
        # Two fields both tagged with the same enum name → both reverted
        fld1 = _enum_field('status', 'Status')
        fld2 = _enum_field('defaultStatus', 'Status')
        self._fn(self.ctx, _make_cls(), [fld1, fld2], self.st,
                 instance_method_names={'readFrom:'},
                 metaclass=None)
        self.assertEqual(fld1.type_name, 'int32')
        self.assertEqual(fld2.type_name, 'int32')

    def test_duplicate_enum_name_produces_one_protoneum(self):
        # Two fields with same enum name → only one ProtoEnum entry
        cls = _make_cls(methods=[_make_method('statusAsString:', imp=0)])
        fld1 = _enum_field('status', 'Status')
        fld2 = _enum_field('defaultStatus', 'Status')
        result = self._fn(self.ctx, cls, [fld1, fld2], self.st,
                          instance_method_names={'statusAsString:'},
                          metaclass=None)
        self.assertEqual(len(result), 1)

    # ── Shared-cache path: instance_method_names empty ────────────────────────

    def test_shared_cache_methname_found_tags_then_reverts(self):
        # Methname scan adds an ENUM: tag, but with no resolvable xAsString:
        # method (instance_method_names empty, class has no such method) the field
        # reverts to scalar.  Final state: type_class=None, type_name='int32'.
        fld = _scalar_field('status', 'int32')
        with patch('proto.enums._enum_name_from_methname', return_value='Status'):
            self._fn(self.ctx, _make_cls(), [fld], self.st,
                     instance_method_names=set(), metaclass=None)
        self.assertIsNone(fld.type_class)

    def test_shared_cache_methname_not_found_field_unchanged(self):
        fld = _scalar_field('count', 'int32')
        with patch('proto.enums._enum_name_from_methname', return_value=None):
            result = self._fn(self.ctx, _make_cls(), [fld], self.st,
                              instance_method_names=set(), metaclass=None)
        self.assertEqual(fld.type_name, 'int32')
        self.assertIsNone(fld.type_class)
        self.assertEqual(result, [])

    def test_string_field_skipped_in_shared_cache_scan(self):
        # 'string' is not in ("int32", "uint32") → methname scan must skip it
        fld = _scalar_field('name', 'string')
        with patch('proto.enums._enum_name_from_methname',
                   return_value='NameEnum') as mock_mn:
            self._fn(self.ctx, _make_cls(), [fld], self.st,
                     instance_method_names=set(), metaclass=None)
        # The function should not have been called for a 'string' field
        # (it's gated on type_name in ("int32","uint32"))
        self.assertEqual(fld.type_name, 'string',
                         "Non-scalar field must not be re-tagged as enum")


# ── Runner ────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    unittest.main(verbosity=2)
