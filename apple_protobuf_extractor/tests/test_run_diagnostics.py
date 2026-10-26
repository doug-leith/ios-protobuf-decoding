"""The extractor must say so when output is missing, estimated or uncertain.

Covers the run-level disclosures: per-run diagnostics (failed classes, foreign-runtime
errors, enum switches that could not be evaluated), the summary rows, the header's
estimated-field count, the CLI exit status, rejection of input that cannot be decoded
(wrong architecture, truncated Mach-O), partial enums, renamed duplicate value names, the
C++ duplicate-message resolution and the native-decoder notice.  Everything runs on the
compiled synthetic fixtures or on tiny hand-built inputs (no dyld cache needed).
"""
import contextlib
import io
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
_FIXTURE_MANY = os.path.join(_FIXTURES_DIR, 'f10_geo_log_message', 'testlm')    # eight classes


def _load(path=_FIXTURE):
    with open(path, 'rb') as fh:
        data = load_macho_slice(fh.read())
    ctx = BinaryContext(data)
    st = build_string_table(ctx)
    return ctx, st, build_class_list(ctx, st)


@contextlib.contextmanager
def _first_class_failing():
    """extract_proto_message raises for the first class; yields the list of its name."""
    import proto.extractor as E
    real = E.extract_proto_message
    seen = []

    def flaky(ctx_, st_, cl_, cls, **kw):
        if not seen:
            seen.append(cls.name)
            raise RuntimeError('boom')
        return real(ctx_, st_, cl_, cls, **kw)
    with mock.patch.object(E, 'extract_proto_message', flaky):
        yield seen


class TestDiagnosticsObject(unittest.TestCase):

    def test_is_created_lazily_and_shared_per_ctx(self):
        class Ctx:
            pass
        ctx = Ctx()
        d = get_diagnostics(ctx)
        self.assertIsInstance(d, ExtractionDiagnostics)
        self.assertIs(get_diagnostics(ctx), d)
        self.assertIsNot(get_diagnostics(Ctx()), d)          # another ctx: its own
        self.assertEqual(d.n_errors, 0)

    def test_only_dropped_output_counts_as_an_error(self):
        d = ExtractionDiagnostics()
        d.unevaluated_switches.append(('C', 'f', 'why'))
        d.analysis_failures.append(('C', 'readFrom: dispatch', 'why'))
        d.heuristics_hit.append(('_CAP', 'at 1'))
        self.assertEqual(d.n_errors, 0)            # an undecided field is flagged, not an error
        for n, (name, entry) in enumerate((('failed_classes', ('C', 'boom')),
                                           ('foreign_errors', ('swift', 'boom')),
                                           ('failed_passes', ('pass', 'boom', 'skipped')),
                                           ('unread', ('class', '0x10', 'boom'))), 1):
            getattr(d, name).append(entry)
            self.assertEqual(d.n_errors, n, name)


    def test_another_images_entries_are_merged_under_its_name(self):
        d, other = ExtractionDiagnostics(), ExtractionDiagnostics()
        other.failed_passes.append(('pass', 'ValueError: x', 'skipped'))
        other.analysis_failures.append(('C', 'readFrom: dispatch', 'why'))
        d.merge(other, 'Foo.framework/Foo')
        self.assertEqual(d.failed_passes, [('Foo.framework/Foo: pass', 'ValueError: x', 'skipped')])
        self.assertEqual(d.analysis_failures, [('Foo.framework/Foo: C', 'readFrom: dispatch', 'why')])
        self.assertEqual(d.n_errors, 1)


@unittest.skipUnless(_HAVE_FIXTURE, 'synthetic fixture binary not built')
class TestTheChecksBeforeExtractionAreKept(unittest.TestCase):
    """extract_all resets its caches first: what the checks it runs first record (here a
    failed pass in the foreign-protobuf notice) reaches the run's diagnostics (TODO #134)."""

    def test_kept(self):
        import proto.extractor as E
        from proto.models import record_failed_pass
        ctx, st, cl = _load()

        def failing(ctx_, cl_):
            record_failed_pass(ctx_, 'foreign-protobuf detection', ValueError('x'), 'no notice')
        with mock.patch.object(E, '_warn_if_foreign_protobuf', failing), \
                self.assertLogs('proto.models', 'WARNING'):
            extract_all(ctx, st, cl)
        self.assertEqual([p[0] for p in get_diagnostics(ctx).failed_passes],
                         ['foreign-protobuf detection'])


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
        # the CLI's status of the same run (a dylib: no enum escalation)
        args = cli._build_parser().parse_args(['--binary', _FIXTURE, '--dry-run'])
        with mock.patch.object(sys, 'stderr', io.StringIO()), \
                mock.patch.object(sys, 'stdout', io.StringIO()):
            status = cli._build_and_write_output(messages, args, 'testmsg', ctx,
                                                 emitter.InputKind.DYLIB)
        self.assertEqual(status, cli.EXIT_INCOMPLETE)


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
            if not shutil.which('protoc'):
                self.skipTest('protoc not on PATH: its acceptance not checked')
            r = subprocess.run(['protoc', f'--proto_path={out}', '--descriptor_set_out=/dev/null',
                                files[0]], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)

    @unittest.skipUnless(os.path.exists(_FIXTURE_MANY), 'synthetic fixture binary not built')
    def test_run_that_dropped_a_class_exits_non_zero(self):
        # the other classes written; and the one class of f1 dropped, nothing written
        for fixture in (_FIXTURE_MANY, _FIXTURE):
            with self.subTest(fixture=os.path.basename(fixture)), _first_class_failing(), \
                    mock.patch.object(sys, 'stderr', io.StringIO()), \
                    mock.patch.object(sys, 'stdout', io.StringIO()):
                rc = cli.main(['--binary', fixture, '--dry-run'])
                self.assertEqual(rc, cli.EXIT_INCOMPLETE)


class TestCliRejectsUnconfirmedClasses(unittest.TestCase):

    @unittest.skipUnless(_HAVE_FIXTURE, 'synthetic fixture binary not built')
    def test_an_error_and_a_status_not_a_traceback(self):
        import proto.extractor as E
        from proto.protoclass_heuristic import ProtoClassDetectionError

        def unconfirmed(*a, **kw):
            raise ProtoClassDetectionError('proto-class detection FAILED STRUCTURALLY')
        err = io.StringIO()
        with mock.patch.object(E, 'extract_all', unconfirmed), \
                mock.patch.object(sys, 'stderr', err), \
                mock.patch.object(sys, 'stdout', io.StringIO()):
            rc = cli.main(['--binary', _FIXTURE, '--dry-run'])
        self.assertEqual(rc, 1)
        self.assertIn('error: proto-class detection FAILED STRUCTURALLY', err.getvalue())


class TestUnreadInputIsAnError(unittest.TestCase):
    """Structural input that could not be read is recorded with the context (TODO #137): it
    counts as an error, survives the reset at the start of a run (the class list is read
    before it), and is listed once per place."""

    def test_recorded_once_and_counted(self):
        from macho.memory import record_unread
        class Ctx:
            pass
        ctx = Ctx()
        diag = get_diagnostics(ctx)                 # fetched first: the context's own list
        with self.assertLogs('macho.memory', 'WARNING') as logs:
            record_unread(ctx, 'ivar list', '0x10', ValueError('unmapped'))
            record_unread(ctx, 'ivar list', '0x20', ValueError('unmapped'))    # another place
        self.assertEqual(len(logs.output), 1)       # warned once per kind
        record_unread(ctx, 'ivar list', '0x10', ValueError('unmapped'))        # the same place
        self.assertEqual(diag.unread, [('ivar list', '0x10', 'ValueError: unmapped'),
                                       ('ivar list', '0x20', 'ValueError: unmapped')])
        self.assertEqual(diag.n_errors, 2)
        self.assertEqual(diag.as_dict()['unread'], [['ivar list', '0x10', 'ValueError: unmapped'],
                                                    ['ivar list', '0x20', 'ValueError: unmapped']])

    @unittest.skipUnless(_HAVE_FIXTURE, 'synthetic fixture binary not built')
    def test_an_unreadable_class_reaches_the_run(self):
        """A class_t that cannot be read is no longer just absent: the run that follows (its
        caches reset first) still sees it, and exits incomplete."""
        import macho.classlist as C
        ctx, st, _cl = _load()
        real = C._parse_class
        hit = []

        def unreadable_first(ctx_, va, strings):
            if not hit:
                hit.append(va)
                C.record_unread(ctx_, "class", f"{va:#x}", ValueError("unmapped"))
                return None
            return real(ctx_, va, strings)
        with mock.patch.object(C, '_parse_class', unreadable_first), \
                self.assertLogs('macho.memory', 'WARNING'):
            cl = build_class_list(ctx, st)
        extract_all(ctx, st, cl)
        self.assertEqual([u[0] for u in get_diagnostics(ctx).unread], ['class'])
        self.assertGreaterEqual(get_diagnostics(ctx).n_errors, 1)

    def test_a_class_t_read_failure_is_recorded(self):
        import macho.classlist as C
        class Ctx:
            def read_ptr(self, va):
                raise ValueError(f"{va:#x} unmapped")
        ctx = Ctx()
        with self.assertLogs('macho.memory', 'WARNING'):
            self.assertIsNone(C._parse_class(ctx, 0x1000, None))
        self.assertEqual(get_diagnostics(ctx).unread[0][:2], ('class', '0x1000'))

    def test_a_logic_error_is_not_a_read_error(self):
        from macho.memory import READ_ERRORS
        for exc in (KeyError, IndexError, AttributeError):
            self.assertFalse(issubclass(exc, READ_ERRORS), exc)

    @unittest.skipUnless(_HAVE_FIXTURE, 'synthetic fixture binary not built')
    def test_the_cli_writes_its_diagnostics(self):
        import json
        with tempfile.TemporaryDirectory() as out, _first_class_failing() as failed, \
                mock.patch.object(sys, 'stderr', io.StringIO()), \
                mock.patch.object(sys, 'stdout', io.StringIO()):
            rc = cli.main(['--binary', _FIXTURE, '--dry-run',
                           '--diagnostics-json', os.path.join(out, 'd.json')])
            got = json.load(open(os.path.join(out, 'd.json')))
        self.assertEqual(rc, cli.EXIT_INCOMPLETE)
        # this run's entries, every list by name
        self.assertEqual(got, {'failed_classes': [[failed[0], 'RuntimeError: boom']],
                               'foreign_errors': [], 'unevaluated_switches': [],
                               'failed_passes': [], 'analysis_failures': [],
                               'heuristics_hit': [], 'unread': []})


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
        # whole segments past the end; one byte short (inside the last segment); inside the
        # load commands
        for cut in (len(data) // 2, len(data) - 1, 40):
            with self.subTest(cut=cut), self.assertRaisesRegex(ValueError, 'truncated'):
                BinaryContext(data[:cut])


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
        whole = ProtoEnum('F', [ProtoEnumValue('F_A', 1)])            # not counted
        msgs = [self._msg(1, 0, enums=[e, whole])]
        files = emitter.build_proto_files(msgs)
        self.assertIn('// Note: 1 enum(s) may have missing values', files[0].emit())
        out = io.StringIO()
        emitter.print_summary(msgs, files, file=out)
        self.assertRegex(out.getvalue(), r'enums possibly incomplete +1 ')

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
            (0, 'ARTWORK_USE_UNKNOWN'), (1, 'ARTWORK_USE_LIST'), (2, 'ARTWORK_USE_UNKNOWN'),
            (8, 'ARTWORK_USE_UNKNOWN')])
        by = {v.number: v for v in vals}
        self.assertEqual(by[0].name, 'ARTWORK_USE_UNKNOWN')
        self.assertIsNone(by[0].comment)
        self.assertEqual(by[2].name, 'ARTWORK_USE_UNKNOWN_2')
        self.assertEqual(by[8].name, 'ARTWORK_USE_UNKNOWN_8')      # by number, not position
        self.assertIn('identically', by[2].comment)
        self.assertIn('identically', by[8].comment)
        # unprefixed in the binary: the duplicate is found by its normalised name
        bare = _enum_values_from_pairs('ArtworkUse', [(0, 'UNKNOWN'), (1, 'LIST'), (2, 'UNKNOWN')])
        self.assertEqual([v.name for v in bare],
                         ['ARTWORK_USE_UNKNOWN', 'ARTWORK_USE_LIST', 'ARTWORK_USE_UNKNOWN_2'])


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

        from tests._fakes import NoImage
        ctx = NoImage()
        with mock.patch.object(foreign, 'cpp_file_protos', side_effect=OSError('nope')), \
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
            self.assertIn('different fields', out[0].message_note)

    def test_duplicate_cpp_messages_with_as_many_different_fields_are_reported_too(self):
        from proto.foreign import _dedupe_cpp_messages

        def m(name):
            return ProtoMessage(name='M', class_name='x', package='p',
                                fields=[ProtoField(name, 1, 'int32', FieldLabel.OPTIONAL)])
        with self.assertLogs('proto.foreign', 'WARNING'):
            out = _dedupe_cpp_messages([m('a'), m('b')])
        self.assertEqual(len(out), 1)
        self.assertIn('1 of the other copy', out[0].message_note)
        same = _dedupe_cpp_messages([m('a'), m('a')])       # identical copies: one, quietly
        self.assertEqual((len(same), same[0].message_note), (1, None))


class TestCapstoneRequired(unittest.TestCase):

    def test_without_capstone_disassembly_fails_loudly(self):
        # a partial built-in decoder used to stand in, silently changing what the analysis saw
        import sys
        from unittest import mock
        from macho.disasm import disasm
        from macho.memory import BinaryContext
        from tests.conftest import build_text_binary, RET_BYTES
        ctx = BinaryContext(build_text_binary(RET_BYTES, vmaddr=0x4000))
        with mock.patch.dict(sys.modules, {'capstone': None}), \
                mock.patch('macho.disasm._CS', None):
            with self.assertRaisesRegex(ImportError, 'capstone is required'):
                disasm(ctx, 0x4000)


if __name__ == '__main__':
    unittest.main()


class TestHeuristicHits(unittest.TestCase):
    """models.record_heuristic_hit: one warning per bound or heuristic, every place listed once,
    and the run summary says so."""

    def test_warned_once_listed_once_each(self):
        import io
        from proto.models import record_heuristic_hit
        from proto.emitter import print_summary
        from tests._fakes import NoImage
        ctx = NoImage()
        with self.assertLogs('proto.models', 'WARNING') as logs:
            record_heuristic_hit(ctx, "_CAP", "at 1")
            record_heuristic_hit(ctx, "_CAP", "at 2")
            record_heuristic_hit(ctx, "_CAP", "at 1")          # the same place again
            record_heuristic_hit(ctx, "_OTHER", "at 3")
        self.assertEqual(len(logs.output), 2)
        diag = get_diagnostics(ctx)
        self.assertEqual(diag.heuristics_hit, [("_CAP", "at 1"), ("_CAP", "at 2"), ("_OTHER", "at 3")])
        out, err = io.StringIO(), io.StringIO()
        with mock.patch('sys.stderr', err):
            print_summary([], [], source_name="x", file=out, diagnostics=diag)
        self.assertIn("bounds / heuristics hit", out.getvalue())
        self.assertIn("_CAP: at 2", err.getvalue())
