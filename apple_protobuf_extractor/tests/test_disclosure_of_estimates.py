"""Estimates the output must flag, and failures the run must report.

* An int field's encoding (int / sint / fixed) comes from its writeTo: writer: by the
  writer's code (cache), by the import stub's bound name (a standalone binary calls
  ProtocolBuffer.framework through stubs), else it is "unknown" and the field is flagged.
* A field whose ivar type names no wire type (bare ``@``, NSNumber / NSValue / NSObject)
  emits as bytes with a note.
* An image-wide pre-pass that raises, and a per-class analysis that raises or does not
  settle, are recorded in the run diagnostics and printed, not only debug-logged.
"""
import io
import os
import sys
import unittest
from contextlib import redirect_stderr
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

import proto.extractor as E
import proto.write_helpers as WH
from macho.classlist import ObjcIvar
from proto import emitter
from proto.models import (ExtractionDiagnostics, FieldLabel, ProtoField, ProtoMessage,
                          get_diagnostics, record_analysis_failure, record_failed_pass)


class _Ctx:
    """A context with nothing mapped: every helper read fails."""


def _ivar(name="_count", enc="i"):
    return ObjcIvar(name=name, type_enc=enc, offset=8, size=4)


class TestWriterFamilyFromImportName(unittest.TestCase):
    """A standalone binary's helper is a stub into ProtocolBuffer.framework: its name decides."""

    def _family(self, bound):
        with mock.patch.object(WH, "_helper_real_target", lambda ctx, va: va), \
                mock.patch.object(WH, "import_name", lambda ctx, va: bound):
            return WH._classify_write_helper(_Ctx(), 0x1000)

    def test_each_int_writer_names_its_family(self):
        for bound, fam in (("_PBDataWriterWriteInt32Field", "int32"),
                           ("_PBDataWriterWriteUint32Field", "uint32"),
                           ("_PBDataWriterWriteSint32Field", "sint32"),
                           ("_PBDataWriterWriteSint64Field", "sint64"),
                           ("_PBDataWriterWriteSfixed32Field", "fixed32"),
                           ("_PBDataWriterWriteFixed64Field", "fixed64"),
                           ("_PBDataWriterWriteInt64Field", "plain"),
                           ("_PBDataWriterWriteBOOLField", "plain")):
            self.assertEqual(self._family(bound), fam, bound)

    def test_an_unrelated_import_falls_back_to_reading_the_code(self):
        # not a PBDataWriter stub, and no readable code: nothing shows the encoding
        self.assertEqual(self._family("_objc_msgSend"), "unknown")


class TestUnknownEncodingIsFlagged(unittest.TestCase):

    def test_no_helper_or_an_unreadable_one_is_unknown_not_plain(self):
        self.assertEqual(WH._classify_write_helper(_Ctx(), None), "unknown")
        self.assertEqual(WH._classify_write_helper(_Ctx(), 0x1000), "unknown")

    def test_refine_reports_an_undecided_int(self):
        with mock.patch.object(E, "_classify_write_helper", lambda ctx, va: "unknown"):
            self.assertEqual(E._refine_int_wire_form(_Ctx(), "int32", None, _ivar(),
                                                     {"_count": 0x10}), ("int32", False))
        with mock.patch.object(E, "_classify_write_helper", lambda ctx, va: "sint32"):
            self.assertEqual(E._refine_int_wire_form(_Ctx(), "int32", None, _ivar(),
                                                     {"_count": 0x10}), ("sint32", True))
        # not an int: nothing to decide
        self.assertEqual(E._refine_int_wire_form(_Ctx(), "string", None, _ivar(enc='@"NSString"'),
                                                 {}), ("string", True))

    def test_packed_element_writers_that_disagree_are_undecided(self):
        fams = iter(("sint32", "int32"))
        walk = {"_count": {"bracket": True, "elem_helper_vas": (0x10, 0x20)}}
        with mock.patch.object(E, "_classify_write_helper", lambda ctx, va: next(fams)):
            self.assertEqual(E._refine_int_wire_form(_Ctx(), "int32", None, _ivar(), {}, walk),
                             ("int32", False))


class TestOpaqueObjectNote(unittest.TestCase):

    def test_types_that_name_no_wire_type_are_noted(self):
        self.assertIn("names no wire type", E._opaque_object_note(_ivar(enc="@"), None))
        self.assertIn('@"NSNumber"', E._opaque_object_note(_ivar(enc='@"NSNumber"'), "NSNumber"))

    def test_foundation_types_with_a_wire_type_are_not(self):
        self.assertIsNone(E._opaque_object_note(_ivar(enc='@"NSString"'), None))
        self.assertIsNone(E._opaque_object_note(_ivar(enc='@"NSData"'), None))
        self.assertIsNone(E._opaque_object_note(_ivar(enc='@"GEOPlace"'), "GEOPlace"))


class TestRunDiagnosticsOfFailures(unittest.TestCase):

    def _msg(self):
        return ProtoMessage(name="M", class_name="M", fields=[ProtoField(
            name="a", number=1, type_name="int32", label=FieldLabel.OPTIONAL,
            number_confirmed=True)])

    def test_a_failed_pre_pass_is_an_error_and_is_printed(self):
        ctx = _Ctx()
        with self.assertLogs("proto.models", "WARNING"):
            record_failed_pass(ctx, "writeTo indegree", RuntimeError("boom"), "numbers estimated")
        d = get_diagnostics(ctx)
        self.assertEqual(d.n_errors, 1)
        err, out = io.StringIO(), io.StringIO()
        msgs = [self._msg()]
        with redirect_stderr(err):
            emitter.print_summary(msgs, emitter.build_proto_files(msgs), diagnostics=d, file=out)
        self.assertIn("pre-passes FAILED", out.getvalue())
        self.assertIn("writeTo indegree pre-pass failed (RuntimeError: boom); numbers estimated",
                      err.getvalue())

    def test_a_failed_class_analysis_is_recorded_once_and_warned(self):
        ctx = _Ctx()
        for _ in range(2):
            record_analysis_failure(ctx, "GEOX", "readFrom: dispatch", "core 0x10: ValueError: x")
        d = get_diagnostics(ctx)
        self.assertEqual(d.analysis_failures, [("GEOX", "readFrom: dispatch", "core 0x10: ValueError: x")])
        self.assertEqual(d.n_errors, 0)            # its fields are flagged, nothing is missing
        err = io.StringIO()
        msgs = [self._msg()]
        with redirect_stderr(err):
            emitter.print_summary(msgs, emitter.build_proto_files(msgs), diagnostics=d,
                                  file=io.StringIO())
        self.assertIn("GEOX: readFrom: dispatch: core 0x10: ValueError: x", err.getvalue())

    def test_a_dispatch_evaluation_that_raises_reaches_the_diagnostics(self):
        ctx = _Ctx()
        cls = mock.Mock(name="cls")
        cls.name = "GEOX"
        boom = mock.Mock(side_effect=ValueError("bad bytes"))
        with mock.patch.object(E, "_resolve_repeated_via_dispatch", boom), \
                mock.patch.object(E, "_resolve_repeated_via_dispatch_ivars", boom):
            E._resolve_dispatch_context(ctx, cls, {0x10: "GEOY"}, [])
        self.assertEqual([a for _c, a, _d in get_diagnostics(ctx).analysis_failures],
                         ["readFrom: dispatch (element classes)", "readFrom: dispatch (element ivars)"])

    def test_a_coding_error_in_the_evaluator_is_not_swallowed(self):
        cls = mock.Mock(name="cls")
        cls.name = "GEOX"
        with mock.patch.object(E, "_resolve_repeated_via_dispatch",
                               mock.Mock(side_effect=NameError("typo"))):
            with self.assertRaises(NameError):
                E._resolve_dispatch_context(_Ctx(), cls, {0x10: "GEOY"}, [])


if __name__ == "__main__":
    unittest.main()
