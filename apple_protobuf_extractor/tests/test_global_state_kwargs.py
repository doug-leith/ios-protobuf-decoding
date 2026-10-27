"""
tests/test_global_state_kwargs.py — Tests for the global-state kwargs refactor.

Written BEFORE implementation; all tests must fail until the changes are made,
then pass without modification.

Changes under test:
  • _class_to_proto_name(name, prefixes=None)   — explicit prefix override
  • _collect_enum_definitions(..., *, prefixes=None, enum_debug_writer=None)
  • extract_proto_message(..., *, prefixes=None, enum_debug_writer=None)
  • extract_all(..., *, prefixes=None, enum_debug_writer=None)
"""

from __future__ import annotations

import sys
import os
import unittest
from typing import Dict, List, Optional, Any

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from macho.memory import BinaryContext
from macho.strings import StringTable
from macho.classlist import ClassList, ObjcClass, ObjcIvar, ObjcMethod
from proto.models import FieldLabel, ProtoField
from tests.conftest import build_text_binary, RET_BYTES


# ── Tiny builders ─────────────────────────────────────────────────────────────

def _ctx() -> BinaryContext:
    return BinaryContext(build_text_binary(RET_BYTES, vmaddr=0x4000))


def _st() -> StringTable:
    return StringTable()


def _make_cls(name: str = 'GEOMock',
              methods: Optional[List[ObjcMethod]] = None) -> ObjcClass:
    return ObjcClass(
        vmaddr=0x8000, name=name, is_meta=False,
        superclass_vmaddr=0, superclass_name=None,
        ro_flags=0, instance_size=32,
        methods=methods or [],
        ivars=[],
    )


def _enum_field(name: str, enum_name: str) -> ProtoField:
    return ProtoField(name=name, number=1, type_name=enum_name,
                      label=FieldLabel.OPTIONAL, type_class=f'ENUM:{enum_name}')


# ══════════════════════════════════════════════════════════════════════════════
# _class_to_proto_name(name, prefixes=None)
# ══════════════════════════════════════════════════════════════════════════════

class TestClassToProtoNamePrefixKwarg(unittest.TestCase):
    """_class_to_proto_name must accept an explicit prefixes override."""

    def setUp(self):
        from proto.config import _class_to_proto_name
        self._fn = _class_to_proto_name

    def test_explicit_prefix_strips_correctly(self):
        self.assertEqual(self._fn('FOOBar', ('FOO',)), 'Bar')

    def test_explicit_prefix_overrides_default(self):
        # 'GEOPD' is not in the default set (GEO is); with ('GEOPD',) it strips 'GEOPD'
        self.assertEqual(self._fn('GEOPDPlace', ('GEOPD',)), 'Place')

    def test_no_kwarg_uses_default_prefixes(self):
        # GEO is in the canonical DEFAULT_PREFIXES, used when no prefixes= passed.
        # NOTE: this never mutates/touches the (now-removed) module-level global,
        # so old and new semantics coincide by construction -- see
        # test_prefix_consolidation.py::TestSingleCanonicalSource::
        # test_no_module_level_prefix_global_and_no_cross_call_leakage for a test
        # that actually exercises 1ec059a's global-removal.
        self.assertEqual(self._fn('GEOPDPlace'), 'PDPlace')

    def test_explicit_prefix_not_matching_returns_full_name(self):
        self.assertEqual(self._fn('GEOPDPlace', ('FOO',)), 'GEOPDPlace')

    def test_empty_prefix_tuple_returns_full_name(self):
        # No prefixes match → return as-is
        self.assertEqual(self._fn('GEOPDPlace', ()), 'GEOPDPlace')

    def test_multiple_prefixes_correct_one_chosen(self):
        self.assertEqual(self._fn('CLPLocation', ('GEO', 'CLP')), 'Location')


# ══════════════════════════════════════════════════════════════════════════════
# _collect_enum_definitions — enum_debug_writer kwarg
# ══════════════════════════════════════════════════════════════════════════════

class TestCollectEnumDefinitionsDebugWriterKwarg(unittest.TestCase):
    """_collect_enum_definitions must use the passed enum_debug_writer."""

    def setUp(self):
        from proto.enums import _collect_enum_definitions
        self._fn = _collect_enum_definitions
        self.ctx = _ctx()
        self.st  = _st()

    def _scalar(self, name: str, type_name: str = 'int32') -> ProtoField:
        return ProtoField(name=name, number=1, type_name=type_name,
                          label=FieldLabel.OPTIONAL, type_class=None)

    def test_no_writer_kwarg_returns_without_error(self):
        """Backward compat: no enum_debug_writer kwarg → no error, same behavior."""
        result = self._fn(self.ctx, _make_cls(), [], self.st, set(), None)
        self.assertEqual(result.enums, [])

    def test_writer_kwarg_accepted_without_error(self):
        records: List[Dict[str, Any]] = []
        result = self._fn(self.ctx, _make_cls(), [], self.st, set(), None,
                          enum_debug_writer=records.append)
        self.assertEqual(result.enums, [])

    def test_writer_kwarg_receives_mode_c_record_on_revert(self):
        # ENUM: field, no method → revert → Mode C → debug record emitted to kwarg writer
        records: List[Dict[str, Any]] = []
        cls = _make_cls(methods=[])
        fld = _enum_field('feedbackType', 'FeedbackType')
        self._fn(self.ctx, cls, [fld], self.st,
                 instance_method_names={'readFrom:'},
                 metaclass=None,
                 enum_debug_writer=records.append)
        self.assertGreater(len(records), 0,
                           "Mode C record must be emitted to the kwarg writer")
        self.assertEqual(records[0]['mode'], 'C_revert_to_scalar')

    def test_no_writer_kwarg_emits_nothing_and_does_not_raise(self):
        # There is no global debug sink: with no enum_debug_writer the diagnostic
        # is simply absent (a no-op).  A Mode-C revert must still proceed silently.
        cls = _make_cls(methods=[])
        fld = _enum_field('feedbackType', 'FeedbackType')
        self._fn(self.ctx, cls, [fld], self.st,
                 instance_method_names={'readFrom:'},
                 metaclass=None)   # no enum_debug_writer → must not raise

    def test_dbg_enum_no_writer_never_falls_back_to_a_prior_calls_writer(self):
        # The tests above can't observe proto/config.py's actual change (dropping
        # the module-level `current_debug_writer` global in favour of an explicit
        # `writer=` param): _collect_enum_definitions's own `if _dbg_w is not None`
        # guard already skips the call whenever enum_debug_writer is omitted, so
        # config.py's internals are never reached either way.  Call
        # proto.config._dbg_enum directly (bypassing that outer guard) with an
        # explicit writer, then again with NO writer, and confirm the second call
        # is a true no-op rather than silently reusing the first call's writer --
        # which the old module-global design would have done.
        from proto.config import _dbg_enum
        seen_first: List[Dict[str, Any]] = []
        _dbg_enum({"mode": "first"}, writer=seen_first.append)
        self.assertEqual(len(seen_first), 1)
        _dbg_enum({"mode": "second"})   # no writer= this time
        self.assertEqual(len(seen_first), 1,
                         "must not fall back to a previous call's writer")


# ══════════════════════════════════════════════════════════════════════════════
# extract_proto_message — prefixes and enum_debug_writer kwargs
# ══════════════════════════════════════════════════════════════════════════════

class TestExtractProtoMessageKwargs(unittest.TestCase):
    """extract_proto_message must accept prefixes and enum_debug_writer kwargs."""

    def setUp(self):
        from proto.extractor import extract_proto_message
        self._fn = extract_proto_message

    def _cls_with_ivar(self, cls_name: str, ivar_name: str = '_count',
                       type_enc: str = 'i') -> ObjcClass:
        ivar = ObjcIvar(name=ivar_name, type_enc=type_enc, offset=8, size=4)
        # Minimal proto-like class: needs readFrom: and writeTo: in method list
        methods = [
            ObjcMethod(name='readFrom:', types='', imp=0, is_relative=False),
            ObjcMethod(name='writeTo:', types='', imp=0, is_relative=False),
        ]
        return ObjcClass(
            vmaddr=0x8000, name=cls_name, is_meta=False,
            superclass_vmaddr=0, superclass_name=None,
            ro_flags=0, instance_size=32,
            methods=methods, ivars=[ivar],
        )

    def test_custom_prefix_strips_class_name_for_message_name(self):
        # 'FOOBaz._count' with prefix ('FOO',) → message name should be 'Baz'
        ctx = _ctx()
        st  = _st()
        cl  = ClassList([])
        cls = self._cls_with_ivar('FOOBaz')
        msg = self._fn(ctx, st, cl, cls, prefixes=('FOO',))
        if msg is not None:
            self.assertEqual(msg.name, 'Baz',
                             "Custom prefix must be used for message name")

    def test_no_prefix_kwarg_uses_default_global(self):
        # 'GEOBaz._count' with no prefix kwarg → message name uses GEO default
        ctx = _ctx()
        st  = _st()
        cl  = ClassList([])
        cls = self._cls_with_ivar('GEOBaz')
        msg = self._fn(ctx, st, cl, cls)
        if msg is not None:
            self.assertEqual(msg.name, 'Baz')

    def test_enum_debug_writer_kwarg_accepted(self):
        ctx = _ctx()
        st  = _st()
        cl  = ClassList([])
        cls = self._cls_with_ivar('GEOBaz')
        records: List[dict] = []
        # Must not raise
        self._fn(ctx, st, cl, cls, enum_debug_writer=records.append)   # (None or a message)


# ══════════════════════════════════════════════════════════════════════════════
# extract_all — prefixes and enum_debug_writer kwargs
# ══════════════════════════════════════════════════════════════════════════════

class TestExtractAllKwargs(unittest.TestCase):
    """extract_all must accept and forward prefixes and enum_debug_writer."""

    def setUp(self):
        from proto.extractor import extract_all
        self._fn = extract_all
        self.ctx = _ctx()
        self.st  = _st()
        self.cl  = ClassList([])

    def test_accepts_prefixes_kwarg_without_error(self):
        result = self._fn(self.ctx, self.st, self.cl, prefixes=('GEO', 'CLP'))
        self.assertIsInstance(result, list)

    def test_accepts_enum_debug_writer_kwarg_without_error(self):
        result = self._fn(self.ctx, self.st, self.cl, enum_debug_writer=lambda r: None)
        self.assertIsInstance(result, list)

    def test_both_kwargs_together_without_error(self):
        result = self._fn(self.ctx, self.st, self.cl,
                          prefixes=('GEO',), enum_debug_writer=lambda r: None)
        self.assertIsInstance(result, list)

    def test_no_kwargs_backward_compat(self):
        result = self._fn(self.ctx, self.st, self.cl)
        self.assertIsInstance(result, list)


if __name__ == '__main__':
    unittest.main(verbosity=2)
