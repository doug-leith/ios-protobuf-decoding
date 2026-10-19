"""The extractor must say so when output is missing, estimated or uncertain.

Covers the run-level disclosures: per-run diagnostics (failed classes, foreign-runtime
errors, enum switches that could not be evaluated), the summary rows, the header's
estimated-field count, the CLI exit status, rejection of input that cannot be decoded
(wrong architecture, truncated Mach-O), partial enums, renamed duplicate value names, the
C++ duplicate-message resolution and the native-decoder notice.  Everything runs on the
compiled synthetic fixtures or on tiny hand-built inputs (no dyld cache needed).
"""
import io
import logging
import os
import struct
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

import cli
from macho.classlist import build_class_list
from macho.memory import BinaryContext, CPU_TYPE_ARM64
from macho.strings import build_string_table
from proto import emitter
from proto.extractor import extract_all
from proto.models import (ExtractionDiagnostics, FieldLabel, ProtoEnum, ProtoEnumValue,
                          ProtoField, ProtoMessage, get_diagnostics)
from tests.test_synthetic_fixtures import _FIXTURES_DIR, load_macho_slice

_FIXTURE = os.path.join(_FIXTURES_DIR, 'f1_writeto_fieldnum', 'testmsg')
_HAVE_FIXTURE = os.path.exists(_FIXTURE)


def _load(path=_FIXTURE):
    with open(path, 'rb') as fh:
        data = load_macho_slice(fh.read())
    ctx = BinaryContext(data)
    st = build_string_table(ctx)
    return ctx, st, build_class_list(ctx, st)


class TestDiagnosticsObject(unittest.TestCase):

    def test_is_created_lazily_and_shared_per_ctx(self):
        class Ctx:
            pass
        ctx = Ctx()
        d = get_diagnostics(ctx)
        self.assertIsInstance(d, ExtractionDiagnostics)
        self.assertIs(get_diagnostics(ctx), d)
        self.assertEqual(d.n_errors, 0)

    def test_only_dropped_output_counts_as_an_error(self):
        d = ExtractionDiagnostics()
        d.unevaluated_switches.append(('C', 'f', 'why'))
        self.assertEqual(d.n_errors, 0)            # an undecided field is flagged, not an error
        d.failed_classes.append(('C', 'boom'))
        d.foreign_errors.append(('swift', 'boom'))
        self.assertEqual(d.n_errors, 2)


@unittest.skipUnless(_HAVE_FIXTURE, 'synthetic fixture binary not built')
class TestFailedClassesAreReported(unittest.TestCase):

    def _run_with_one_class_failing(self):
        import proto.extractor as E
        ctx, st, cl = _load()
        real = E.extract_proto_message
        victim = {}

        def flaky(ctx_, st_, cl_, cls, **kw):
            if not victim:
                victim['name'] = cls.name
                raise RuntimeError('boom')
            return real(ctx_, st_, cl_, cls, **kw)

        with mock.patch.object(E, 'extract_proto_message', flaky), \
                self.assertLogs('proto.extractor', 'WARNING') as logs:
            messages = extract_all(ctx, st, cl)
        return ctx, messages, victim['name'], logs.output

    def test_failed_class_is_recorded_warned_and_named(self):
        ctx, messages, victim, logs = self._run_with_one_class_failing()
        diag = get_diagnostics(ctx)
        self.assertEqual([n for n, _ in diag.failed_classes], [victim])
        self.assertIn('RuntimeError: boom', diag.failed_classes[0][1])
        self.assertTrue(any('MISSING' in line and victim in line for line in logs), logs)
        self.assertNotIn(victim, {m.class_name for m in messages})

    def test_a_second_run_starts_with_clean_diagnostics(self):
        ctx, st, cl = _load()
        get_diagnostics(ctx).failed_classes.append(('Stale', 'from an earlier run'))
        extract_all(ctx, st, cl)
        self.assertEqual(get_diagnostics(ctx).failed_classes, [])

    def test_summary_and_exit_status_report_it(self):
        ctx, messages, victim, _ = self._run_with_one_class_failing()
        files = emitter.build_proto_files(messages)
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(sys, 'stderr', err):
            emitter.print_summary(messages, files, diagnostics=get_diagnostics(ctx), file=out)
        self.assertIn('classes FAILED (missing)', out.getvalue())
        self.assertIn(victim, err.getvalue())


@unittest.skipUnless(_HAVE_FIXTURE, 'synthetic fixture binary not built')
class TestCliEndToEnd(unittest.TestCase):

    def test_clean_run_writes_protos_that_protoc_accepts_and_exits_zero(self):
        import shutil
        import subprocess
        with tempfile.TemporaryDirectory() as out:
            rc = cli.main(['--binary', _FIXTURE, '-o', out])
            self.assertEqual(rc, 0)
            files = sorted(f for f in os.listdir(out) if f.endswith('.proto'))
            self.assertTrue(files)
            text = open(os.path.join(out, files[0])).read()
            self.assertIn('confirmed field numbers', text.split('\n\n')[0])
            if shutil.which('protoc'):
                r = subprocess.run(['protoc', f'--proto_path={out}', '--descriptor_set_out=/dev/null',
                                    files[0]], capture_output=True, text=True)
                self.assertEqual(r.returncode, 0, r.stderr)

    def test_run_that_dropped_a_class_exits_non_zero(self):
        import proto.extractor as E
        real = E.extract_proto_message
        seen = []

        def flaky(ctx_, st_, cl_, cls, **kw):
            if not seen:
                seen.append(cls.name)
                raise RuntimeError('boom')
            return real(ctx_, st_, cl_, cls, **kw)

        with mock.patch.object(E, 'extract_proto_message', flaky), \
                mock.patch.object(sys, 'stderr', io.StringIO()), \
                mock.patch.object(sys, 'stdout', io.StringIO()):
            rc = cli.main(['--binary', _FIXTURE, '--dry-run'])
        self.assertEqual(rc, cli.EXIT_INCOMPLETE)


class TestInputThatCannotBeDecodedIsRejected(unittest.TestCase):

    @staticmethod
    def _header(cputype, ncmds=0, sizeofcmds=0):
        return struct.pack('<IIIIIIII', 0xFEEDFACF, cputype, 0, 6, ncmds, sizeofcmds, 0, 0)

    def test_wrong_architecture_is_an_error_not_an_empty_extraction(self):
        with self.assertRaisesRegex(ValueError, 'unsupported CPU type 0x1000007'):
            BinaryContext(self._header(0x01000007))      # x86_64

    def test_arm64_header_is_accepted(self):
        BinaryContext(self._header(CPU_TYPE_ARM64))

    @unittest.skipUnless(_HAVE_FIXTURE, 'synthetic fixture binary not built')
    def test_truncated_file_is_an_error(self):
        with open(_FIXTURE, 'rb') as fh:
            data = load_macho_slice(fh.read())
        with self.assertRaisesRegex(ValueError, 'truncated'):
            BinaryContext(data[:len(data) // 2])


class TestSummaryAndHeaderDoNotHideEstimates(unittest.TestCase):

    @staticmethod
    def _msg(n_confirmed, n_estimated, enums=()):
        fields = [ProtoField(f'c{i}', i + 1, 'int32', FieldLabel.OPTIONAL, number_confirmed=True)
                  for i in range(n_confirmed)]
        fields += [ProtoField(f'e{i}', 100 + i, 'int32', FieldLabel.OPTIONAL, number_confirmed=False)
                   for i in range(n_estimated)]
        return ProtoMessage(name='M', class_name='GEOM', fields=fields, enums=list(enums))

    def test_header_never_rounds_up_to_100_percent_and_counts_the_estimates(self):
        msgs = [self._msg(8221, 28)]
        pf = emitter.build_proto_files(msgs)[0]
        header = pf.emit().split('\n\n')[0]
        self.assertIn('8221 confirmed field numbers (99.6%)', header)
        self.assertIn('28 ESTIMATED', header)
        self.assertNotIn('(100', header)

    def test_all_confirmed_header_says_100(self):
        header = emitter.build_proto_files([self._msg(10, 0)])[0].emit().split('\n\n')[0]
        self.assertIn('10 confirmed field numbers (100.0%)', header)
        self.assertNotIn('ESTIMATED', header)

    def test_incomplete_enums_are_counted_in_header_and_summary(self):
        e = ProtoEnum('E', [ProtoEnumValue('E_A', 1)], values_truncated=True,
                      incomplete_reason='value 3: loop at 0x10')
        msgs = [self._msg(1, 0, enums=[e])]
        files = emitter.build_proto_files(msgs)
        self.assertIn('1 enum(s) may have missing values', files[0].emit())
        out = io.StringIO()
        emitter.print_summary(msgs, files, file=out)
        self.assertIn('enums possibly incomplete', out.getvalue())

    def test_enum_with_a_reason_shows_the_reason(self):
        e = ProtoEnum('E', [ProtoEnumValue('E_A', 1)], values_truncated=True,
                      incomplete_reason='value 3: loop at 0x10')
        self.assertIn('INCOMPLETE — value 3: loop at 0x10', e.to_proto())

    def test_unevaluated_switch_rows_appear_in_the_summary(self):
        d = ExtractionDiagnostics()
        d.unevaluated_switches.append(('GEOX', 'kind', 'value 1: tbz untracked'))
        out = io.StringIO()
        msgs = [self._msg(1, 0)]
        emitter.print_summary(msgs, emitter.build_proto_files(msgs), diagnostics=d, file=out)
        self.assertIn('enum switches not evaluated', out.getvalue())


class TestEnumValueNameDisclosure(unittest.TestCase):

    def test_duplicate_binary_names_are_suffixed_and_say_so(self):
        from proto.enums import _enum_values_from_pairs
        vals = _enum_values_from_pairs('ArtworkUse', [
            (0, 'ARTWORK_USE_UNKNOWN'), (1, 'ARTWORK_USE_LIST'), (2, 'ARTWORK_USE_UNKNOWN')])
        by = {v.number: v for v in vals}
        self.assertEqual(by[0].name, 'ARTWORK_USE_UNKNOWN')
        self.assertIsNone(by[0].comment)
        self.assertEqual(by[2].name, 'ARTWORK_USE_UNKNOWN_2')
        self.assertIn('identically', by[2].comment)


@unittest.skipUnless(_HAVE_FIXTURE, 'synthetic fixture binary not built')
class TestWriterFlowFailureIsRecorded(unittest.TestCase):

    def test_write_sites_that_raise_are_an_analysis_failure(self):
        from proto.writer_flow import WriterFlow
        ctx, st, cl = _load()
        with mock.patch.object(WriterFlow, 'write_sites', side_effect=RuntimeError('boom')):
            extract_all(ctx, st, cl)
        failures = get_diagnostics(ctx).analysis_failures
        self.assertTrue(failures)
        self.assertTrue(all(a == 'writeTo: flow' and d == 'RuntimeError: boom'
                            for _c, a, d in failures), failures)


class TestForeignRuntimeFailuresAreNotSilent(unittest.TestCase):

    def test_cpp_collection_failure_is_recorded_and_warned(self):
        from proto import foreign

        class Ctx:
            pass
        ctx = Ctx()
        with mock.patch.object(foreign, 'cpp_messages_from_ctx', side_effect=OSError('nope')), \
                mock.patch.object(foreign, 'swift_messages', return_value=[]), \
                self.assertLogs('proto.foreign', 'WARNING') as logs:
            foreign.collect_foreign_messages(ctx, None)
        self.assertEqual(get_diagnostics(ctx).foreign_errors[0][0], 'C++ libprotobuf')
        self.assertIn('FAILED', logs.output[0])

    def test_duplicate_cpp_message_keeps_the_larger_field_set_and_says_so(self):
        from proto.foreign import _dedupe_cpp_messages

        def m(n):
            return ProtoMessage(name='FileOptions', class_name='x', package='google.protobuf',
                                fields=[ProtoField(f'f{i}', i + 1, 'int32', FieldLabel.OPTIONAL)
                                        for i in range(n)])
        small, big = m(10), m(21)
        for order in ((small, big), (big, small)):
            with self.assertLogs('proto.foreign', 'WARNING'):
                out = _dedupe_cpp_messages(list(order))
            self.assertEqual(len(out), 1)
            self.assertEqual(len(out[0].fields), 21, 'discovery order must not decide')
            self.assertIn('differing field counts', out[0].message_note)


class TestNativeDecoderNotice(unittest.TestCase):

    def test_warns_once_per_process(self):
        from macho import disasm
        disasm._native_decoder_warned = False
        with self.assertLogs('macho.disasm', 'WARNING') as logs:
            disasm._warn_native_decoder_once()
            disasm._warn_native_decoder_once()
        self.assertEqual(len(logs.output), 1)
        self.assertIn('capstone is not installed', logs.output[0])


if __name__ == '__main__':
    unittest.main()
