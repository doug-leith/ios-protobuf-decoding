"""
proto/dispatch_eval.py -- readFrom: field dispatch decoded by evaluation -- and the parts of
proto/arm64_eval.Flow it is built on (``run_from``, opaque values, the object-escape stack rule,
per-``br`` arm edges, tail targets, the rejoin stop, the gate intervals ``candidates()`` lists).

Three layers:

* listings (``Insn`` text, no binary) pin each Flow mechanism down on its own;
* every compiled synthetic fixture: the evaluator's element / ivar bindings must equal the
  hand-authored ground truth for every message-typed field, with nothing extra;
* the real caches (skipped when absent): the shapes the evaluator was built against -- the
  macOS 27 objc_direct adders and ownership-gate engines (LIMITATIONS 11), an element spilled
  across a call, a control ``br`` ahead of the field-number extraction, map-entry readers,
  a fall-through into the next function past a noreturn call, inline readers.
"""
import importlib.util
import os
import sys
import unittest
from tests._listing import text_listing

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, '..'))

from proto.arm64_eval import Flow, Objects
from proto import dispatch_eval as E
from proto import eval_tokens as T

CALL, CALL2 = '#0x9000', '#0x9100'           # callees outside the listing
SELF = T.SELF
_RETURNS = Objects(opaque=T.opaque, call_result=lambda k, target, x0: T.ret_value(k))


listing = text_listing


def calls_by_target(region):
    return {c.target: c for c in region.calls}


class TestRunFromThroughCalls(unittest.TestCase):

    def test_calls_are_recorded_with_their_arguments_and_results_followed(self):
        insns, _ = listing(
            'mov x19, x0',
            f'bl {CALL}',                 # x0 = SELF here; afterwards x0 = its result token
            'mov x1, x0',
            'mov x0, x19',
            f'bl {CALL2}',
            'ret')
        r = Flow(None, insns).run_from(0, {'x0': SELF}, objects=_RETURNS)
        got = calls_by_target(r)
        self.assertEqual(got[0x9000].args['x0'], SELF)
        self.assertEqual(got[0x9100].args['x0'], SELF)            # callee-saved copy survived
        self.assertEqual(got[0x9100].args['x1'], T.ret_value(1))   # the first call's result

    def test_a_call_clobbers_the_caller_saved_registers(self):
        insns, _ = listing('mov x3, #7', 'mov x20, #9', f'bl {CALL}', f'bl {CALL2}', 'ret')
        r = Flow(None, insns).run_from(0, {})
        second = calls_by_target(r)[0x9100]
        self.assertNotIn('x3', second.args)
        self.assertEqual(Flow(None, insns).propagate({}, [3])[3].get('x20'), 9)

    def test_a_known_branch_is_followed_one_way_an_unknown_one_both(self):
        insns, _ = listing(
            'mov w8, #1', 'cbz w8, @skip', f'bl {CALL}',
            'skip:', 'cbz x0, @other', f'bl {CALL2}', 'other:', 'ret')
        r = Flow(None, insns).run_from(0, {'x0': SELF}, objects=T.OPAQUE)
        self.assertEqual(set(calls_by_target(r)), {0x9000, 0x9100})   # x0 opaque: both sides
        insns2, _ = listing('mov w8, #0', 'cbz w8, @skip', f'bl {CALL}', 'skip:', 'ret')
        self.assertEqual(calls_by_target(Flow(None, insns2).run_from(0, {})), {})


class TestOpaqueValues(unittest.TestCase):
    """SELF / call results are objects: a copy carries them, nothing else may compute with them."""

    def run_x1(self, *body):
        insns, _ = listing(*body, f'bl {CALL}', 'ret')
        r = Flow(None, insns).run_from(0, {'x0': SELF}, objects=T.OPAQUE)
        return calls_by_target(r)[0x9000].args.get('x1')

    def test_a_64_bit_copy_carries_it(self):
        self.assertEqual(self.run_x1('mov x1, x0'), SELF)

    def test_a_32_bit_copy_does_not(self):
        self.assertIsNone(self.run_x1('mov w1, w0'))

    def test_arithmetic_and_loads_through_it_are_unknown(self):
        self.assertIsNone(self.run_x1('add x1, x0, #8'))
        self.assertIsNone(self.run_x1('ldr x1, [x0, #8]'))

    def test_without_the_predicate_a_token_is_no_number(self):
        """A token lives above the 64-bit value space (like a frame address): a run that is not
        told what it stands for knows nothing of it, rather than taking it for a number."""
        insns, _ = listing('mov x2, x0', 'add x1, x0, #8', f'bl {CALL}', 'ret')
        r = Flow(None, insns).run_from(0, {'x0': SELF})
        args = calls_by_target(r)[0x9000].args
        self.assertEqual((args.get('x1'), args.get('x2')), (None, None))


class TestObjectEscape(unittest.TestCase):
    """An element spilled across a call that is handed a HIGHER frame address (the iPhone 8
    GEOTFCompactRoadSpeeds shape: ``str x0,[sp,#8]`` ... ``add x1,sp,#0x60; bl`` ...
    ``ldr x1,[sp,#8]; bl adder``)."""

    BODY = ('sub sp, sp, #0x80', f'bl {CALL}', 'str x0, [sp, #8]', 'add x1, sp, #0x60',
            f'bl {CALL}', 'ldr x1, [sp, #8]', f'bl {CALL2}', 'add sp, sp, #0x80', 'ret')

    def x1_at_adder(self, object_escape):
        insns, _ = listing(*self.BODY)
        r = Flow(None, insns).run_from(
            0, {}, objects=Objects(opaque=T.opaque, call_result=_RETURNS.call_result,
                                   object_escape=object_escape))
        return calls_by_target(r)[0x9100].args.get('x1')

    def args_after_a_spill_at(self, off):
        # x8 = 5 stored at sp+off, a call handed sp+0x60, the slot reloaded into x1
        insns, _ = listing('sub sp, sp, #0x80', 'mov x8, #5', f'str x8, [sp, #{off:#x}]',
                           'add x1, sp, #0x60', f'bl {CALL}', f'ldr x1, [sp, #{off:#x}]',
                           f'bl {CALL2}', 'ret')
        r = Flow(None, insns).run_from(0, {}, objects=Objects(object_escape=True))
        return calls_by_target(r)[0x9100].args

    def test_a_slot_below_the_escaped_address_survives(self):
        self.assertEqual(self.x1_at_adder(True), T.ret_value(1))
        self.assertEqual(self.args_after_a_spill_at(0x58).get('x1'), 5)   # ends at sp+0x60

    def test_the_default_rule_clears_every_slot(self):
        self.assertIsNone(self.x1_at_adder(False))

    def test_a_slot_at_or_above_the_escaped_address_is_cleared(self):
        for off in (0x60, 0x68):
            with self.subTest(off=hex(off)):
                self.assertNotIn('x1', self.args_after_a_spill_at(off))


class TestPerBrArms(unittest.TestCase):
    """Each ``br`` reaches only ITS table's arms (``jump_table_arms`` makes every arm an edge of
    every br, so an unknown index fanned out to the other table's handlers too)."""

    LINES = ('cbz x0, @second',
             'br x16',                       # table A, index unknown
             'a1:', f'bl {CALL}', 'ret',
             'second:', 'br x17',            # table B
             'b1:', f'bl {CALL2}', 'ret')

    def test_an_unknown_index_reaches_only_its_own_arms(self):
        insns, lab = listing(*self.LINES)
        br_a, br_b = insns[1].addr, lab['second']
        f = Flow(None, insns, br_arms={br_a: {lab['a1']}, br_b: {lab['b1']}})
        r = f.run_from(1, {})                 # start at table A's br
        self.assertEqual(set(calls_by_target(r)), {0x9000})
        f2 = Flow(None, insns, jump_table_arms={lab['a1'], lab['b1']})   # every br, every arm
        self.assertEqual(set(calls_by_target(f2.run_from(1, {}))), {0x9000, 0x9100})

    def test_a_known_index_takes_one_arm_and_reports_the_target(self):
        insns, lab = listing(*self.LINES)
        f = Flow(None, insns, br_arms={insns[1].addr: {lab['a1'], lab['b1']}})
        r = f.run_from(1, {'x16': lab['b1']})
        self.assertEqual(set(calls_by_target(r)), {0x9100})
        self.assertIn((insns[1].addr, lab['b1']), r.br_targets)

    def test_an_arm_mid_block_becomes_a_block_leader(self):
        insns, lab = listing('br x16', 'nop', 'mid:', f'bl {CALL}', 'ret')
        f = Flow(None, insns, br_arms={insns[0].addr: {lab['mid']}})
        self.assertEqual(f.cfg.addr_to_block[lab['mid']], lab['mid'])


class TestTailTargetsAndRejoin(unittest.TestCase):

    def test_a_branch_to_a_known_function_entry_is_a_tail_call(self):
        insns, lab = listing('mov x1, x2', 'b @next', 'next:', f'bl {CALL}', 'ret')
        r = Flow(None, insns).run_from(0, {'x2': SELF}, objects=T.OPAQUE,
                                       tail_targets=frozenset({lab['next']}))
        (c,) = r.calls
        self.assertTrue(c.tail)
        self.assertEqual((c.target, c.args['x1']), (lab['next'], SELF))

    def test_a_path_that_leaves_the_rejoin_set_stops_when_it_reenters(self):
        insns, lab = listing('cbz x0, @handler', 'common:', f'bl {CALL}', 'ret',
                             'handler:', f'bl {CALL2}', 'b @common')
        f = Flow(None, insns)
        common = frozenset({f.cfg.addr_to_block[0x1000], lab['common']})
        r = f.run_from(0, {'x0': 0}, rejoin=common)
        self.assertEqual(set(calls_by_target(r)), {0x9100})
        # x0 unknown: entry -> common never leaves the set, so it runs on
        r = f.run_from(0, {}, rejoin=common)
        self.assertEqual(set(calls_by_target(r)), {0x9000, 0x9100})


class TestCandidateIntervals(unittest.TestCase):

    def test_a_gate_clamped_before_the_table_load_still_yields_its_interval(self):
        # the macOS 27 engine shape: sub; cmp; b.hi; cmp; csel (clamp); ldrsw [table, x16]
        insns, lab = listing('lsr x1, x22, #3', 'sub w16, w1, #1', 'cmp w16, #9', 'b.hi @out',
                             'cmp x16, #9', 'csel x16, x16, xzr, ls',
                             'ldrsw x16, [x17, x16, lsl #2]', 'out:', 'ret')
        scan = Flow(None, insns).candidates(0, 'x1', (1, 1 << 29))
        self.assertIn((1, 10), scan.intervals)
        self.assertNotIn(5, scan.values)      # the values hold only the gate's end points


class TestSelectorStubForms(unittest.TestCase):
    """proto.callees.stub_selector, which the evaluator's adder / init tracking reads
    selectors with: the per-selector ``adrp x1; ldr x1,[x1,#o]`` stub, and the shared stub
    newer caches use (iOS 27 / macOS 27), ``adrp x1; add x1,x1,#o; b _objc_msgSend``."""

    STUB, SEL_PAGE, SEL_OFF, TARGET = 0x10000, 0x20000, 0x48, 0x30000

    def _ctx(self):
        import struct
        from tests.conftest import WordCtx, encode_adrp, encode_add_imm64, encode_b
        words = [struct.unpack('<I', w)[0] for w in (
            encode_adrp(1, (self.SEL_PAGE - self.STUB) >> 12),
            encode_add_imm64(1, 1, self.SEL_OFF),
            encode_b(self.TARGET - (self.STUB + 8)))]
        sel_va = self.SEL_PAGE + self.SEL_OFF

        class Ctx(WordCtx):
            def read_cstring(self, va, max_len=4096):
                if va != sel_va:
                    raise ValueError(va)
                return 'addPredictedSpeed:'
        return Ctx(self.STUB, words)

    def _sel(self, target_name):
        from unittest.mock import patch
        from proto.callees import stub_selector
        with patch('proto.callees.callee_name', lambda ctx, va: target_name if va == self.TARGET else None):
            return stub_selector(self._ctx(), self.STUB)

    def test_shared_stub_names_its_selector(self):
        self.assertEqual(self._sel('_objc_msgSend'), 'addPredictedSpeed:')

    def test_the_same_shape_branching_elsewhere_is_not_a_send(self):
        self.assertIsNone(self._sel('_objc_retain'))


# ── the compiled synthetic fixtures ───────────────────────────────────────────

_FIXTURES_DIR = os.path.join(_HERE, 'synthetic_fixtures')
# Fixtures whose adder call is an argument-less inline-asm ``bl`` to the accessor's IMP (README
# gotcha 10: the binary is never run, only the call target was ever meant to be read).  Data
# flow cannot -- and must not -- bind an ivar to a call that is handed no element; their element
# bindings are still checked.
_ARGLESS_ADDER = frozenset(('f17_repeated_adder_ivar_lever', 'f20_dispatch_wrapper_core_picker'))
_SCALARS = frozenset('double float int32 int64 uint32 uint64 sint32 sint64 fixed32 fixed64 '
                     'sfixed32 sfixed64 bool string bytes'.split())
# Singular message fields whose fixture core hands the case to PBHandleUnknownField (fixture.m):
# no handler builds the element (its type is the ivar's @encode), so nothing binds them.
_UNDISPATCHED = {('f8_geo_companion_drive_step', 'CompanionDriveStep'): {13, 15, 16, 17},
                 ('f10_geo_log_message', 'LogMsgEvent'): {2, 101, 102, 106, 117}}


def _fixtures():
    import test_synthetic_fixtures as T
    return T._FIXTURES


def _load(binary_path):
    from macho.memory import BinaryContext
    from macho.strings import build_string_table
    from macho.classlist import build_class_list
    from serializers.swift_descriptor_extract import load_macho_slice
    from proto.dispatch import _build_readfrom_core_index
    with open(binary_path, 'rb') as fh:
        ctx = BinaryContext(load_macho_slice(fh.read()))
    cl = build_class_list(ctx, build_string_table(ctx))
    return ctx, cl, _build_readfrom_core_index(ctx, cl)


def _class_named(by_name, msg):
    """The class of expected.py's message *msg*: its name, or the name with the class prefix
    extraction strips (proto.defaults.DEFAULT_PREFIXES: f6-f10 key GEOLogMessage as LogMessage)."""
    from proto.defaults import DEFAULT_PREFIXES
    return next((by_name[n] for n in (msg, *(p + msg for p in DEFAULT_PREFIXES)) if n in by_name),
                None)


def _expected(fixture_dir):
    path = os.path.join(_FIXTURES_DIR, fixture_dir, 'expected.py')
    spec = importlib.util.spec_from_file_location(f'_de_expected_{fixture_dir}', path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.EXPECTED


class TestSyntheticFixtures(unittest.TestCase):
    """For every message-typed field of every fixture message: the evaluator binds its number
    to its element class; a repeated one also binds its ivar (``_<field name>``).  No other
    number or ivar is bound, and every reader of every fixture is compared."""

    def test_every_fixture(self):
        sys.path.insert(0, _HERE)
        checked = 0
        for fixture_dir, binary in _fixtures():
            path = os.path.join(_FIXTURES_DIR, fixture_dir, binary)
            if not os.path.exists(path):
                continue
            ctx, cl, core_index = _load(path)
            expected = _expected(fixture_dir)
            by_name = {c.name: c for c in cl if not c.is_meta}
            classes = {msg: _class_named(by_name, msg) for msg in expected}
            known = {c.name for c in classes.values() if c is not None}
            compared = set()
            for msg, spec in expected.items():
                cls = classes[msg]
                if cls is None or cls.get_method('readFrom:') is None:
                    continue
                skip = _UNDISPATCHED.get((fixture_dir, msg), set())
                want = {f['number']: f for f in spec['fields'] if f['number'] not in skip
                        and f['type_name'] not in _SCALARS and f['type_name'] in known}
                got = E.evaluate_class(ctx, cls, core_index)
                with self.subTest(fixture=f'{fixture_dir}/{binary}', message=msg):
                    self.assertEqual(got.elements(),
                                     {n: f['type_name'] for n, f in want.items()},
                                     f'notes: {got.notes}')
                    self.assertEqual(got.ivars(), {} if fixture_dir in _ARGLESS_ADDER else {
                        '_' + f['name']: (f['type_name'], n)
                        for n, f in want.items() if f['label'] == 'repeated'})
                compared.add(cls.name)
                checked += 1
            with self.subTest(fixture=f'{fixture_dir}/{binary}'):
                self.assertEqual(compared, {n for n, c in by_name.items()
                                            if c.get_method('readFrom:') is not None})
        self.assertGreater(checked, 20)


# ── the real caches ───────────────────────────────────────────────────────────

def _cache_dir(env, *rel):
    d = os.environ.get(env, '').strip() or os.path.join(_HERE, '..', '..', *rel)
    for name in ('dyld_shared_cache_arm64e', 'dyld_shared_cache_arm64'):
        if os.path.isfile(os.path.join(d, name)):
            return os.path.join(d, name)
    return None


_IPHONE8 = _cache_dir('MACHO_TEST_CACHE', 'iphone8_data', 'dylib')
_MACOS27 = _cache_dir('MACHO_TEST_MACOS27_CACHE', 'macos27_data', 'dylib')


class _Live(unittest.TestCase):
    CACHE = None
    IMAGE = 'GeoServices'

    @classmethod
    def setUpClass(cls):
        from macho.dyld_cache import DyldCacheReader
        from macho.memory import BinaryContext
        from macho.strings import build_string_table
        from macho.classlist import build_class_list
        from macho.local_symbols import apply_to_classes
        from proto.dispatch import _build_readfrom_core_index
        cls.reader = DyldCacheReader(cls.CACHE)
        mva = cls.reader.resolve_image(cls.IMAGE)
        cls.ctx = BinaryContext.from_cache(cls.reader, mva)
        cl = build_class_list(cls.ctx, build_string_table(cls.ctx))
        syms = cls.reader.image_local_symbols(mva)
        if syms:
            apply_to_classes(cl, syms)
        cls.core_index = _build_readfrom_core_index(cls.ctx, cl)
        cls.by_name = {c.name: c for c in cl if not c.is_meta}

    @classmethod
    def tearDownClass(cls):
        cls.reader.close()

    def ev(self, name):
        return E.evaluate_class(self.ctx, self.by_name[name], self.core_index)


@unittest.skipUnless(_MACOS27, 'macOS 27 cache not present (macos27_data/dylib or MACHO_TEST_MACOS27_CACHE)')
class TestMacOS27(_Live):
    """LIMITATIONS 11: jump-table engines the ownership gate rejected, objc_direct adders."""
    CACHE = _MACOS27

    def test_tf_engines_and_their_objc_direct_adders(self):
        for cls, n, elem, ivar, handler in (
                ('GEOTFCompactRoadSpeeds', 5, 'GEOTFCompactPredictedSpeed', '_predictedSpeeds', 0x1987469ec),
                ('GEOTFRoadSpeed', 6, 'GEOTFPredictedSpeed', '_predictedSpeeds', 0x198750098),
                ('GEOTFIncident', 3, 'GEOTFInfo', '_infos', 0x198749a50)):
            with self.subTest(cls=cls):
                got = self.ev(cls)
                self.assertEqual(got.elements(), {n: elem})
                self.assertEqual(got.ivars(), {ivar: (elem, n)})
                self.assertEqual(got.fields[n].handler, handler)     # the jump-table arm

    def test_inline_reader_whose_adder_is_objc_direct(self):
        self.assertEqual(self.ev('GEOPDTileList').ivars(), {'_tiles': ('GEOTileCoordinate', 1)})

    def test_engine_laid_out_after_its_wrapper(self):
        # the -readFrom: wrapper's tail b runs into the engine that follows it in memory
        self.assertEqual(self.ev('GEORegionalResourceTileData').elements(), {2: 'GEOAttribution'})

    def test_readers_that_hand_only_the_reader_on_have_no_core(self):
        # -[GEOPDStorefrontFilter readFrom:] is `mov x0,x2; b <skip-everything helper>`
        # (shared by three field-less filters): never handed self, so not this class's core.
        self.assertNotIn('GEOPDStorefrontFilter', self.core_index.values())

    def test_self_held_in_a_stack_slot(self):
        self.assertEqual(self.ev('GEODirectionsFeedbackLogMessage').elements(),
                         {1: 'GEODirectionsFeedback', 2: 'GEOLocation'})


@unittest.skipUnless(_IPHONE8, 'iPhone 8 cache not present (iphone8_data/dylib or MACHO_TEST_CACHE)')
class TestIPhone8(_Live):
    CACHE = _IPHONE8

    def test_element_spilled_across_a_call(self):
        self.assertEqual(self.ev('GEOTFCompactRoadSpeeds').ivars(),
                         {'_predictedSpeeds': ('GEOTFCompactPredictedSpeed', 5)})

    def test_control_br_ahead_of_the_field_number(self):
        self.assertEqual(self.ev('GEOPhoto').ivars(), {'_photoInfos': ('GEOPhotoInfo', 2)})

    def test_map_fields_bind_at_the_outer_number(self):
        # the map entry's own key/value dispatch (fields 1/2) is not LPRRoot's
        self.assertEqual(self.ev('GEOLPRRoot').elements(),
                         {1: 'GEOLPRRegion', 3: 'GEOLPRPowerType', 4: 'GEOLPRVehicleType'})

    def test_next_function_past_a_noreturn_call_is_not_ours(self):
        # The core ends in a call that never returns (the stack-guard failure).  The function
        # laid out after it is no method IMP or core, but LC_FUNCTION_STARTS starts one there,
        # so the core's body ends before it and its lsr is never read (it used to be read, and
        # refused for not holding self).
        from proto.function_body import function_end
        got = self.ev('GEOPDPlaceCollection')
        self.assertNotIn(29, got.elements())
        self.assertEqual(got.elements()[1], 'GEOLocalizedString')
        self.assertFalse(any('self not held' in n for n in got.notes))
        core = got.cores[0]
        entries = E._known_entries(self.ctx, self.by_name['GEOPDPlaceCollection'], self.core_index)
        end = function_end(self.ctx, core)
        self.assertLess(end, entries.next_after(core))
        self.assertLess(E._function_insns(self.ctx, core, entries)[-1].addr, end)

    def test_an_inline_reader_has_no_c_core(self):
        # -[GEOPDTileList readFrom:] holds the dispatch itself; its first call retains the
        # reader.  The runtime stub it calls must not be indexed (it used to be, named after
        # the first inline reader, GEOFlyoverRegionVersions).
        self.assertNotIn('GEOPDTileList', self.core_index.values())
        self.assertNotIn('GEOFlyoverRegionVersions', self.core_index.values())
        self.assertEqual(self.ev('GEOPDTileList').ivars(), {'_tiles': ('GEOTileCoordinate', 1)})

    def test_a_thin_wrapper_core_is_indexed(self):
        # -[GEOPDComponentValue readFrom:] is `mov x1, x2 ; mov w2, #0 ; b <core>`
        from macho.disasm import disasm, _parse_imm
        from proto.dispatch import _find_readfrom_c_func
        cls = self.by_name['GEOPDComponentValue']
        wrapper = disasm(self.ctx, cls.get_method('readFrom:').imp, 3, stop_at_ret=False)
        self.assertEqual([i.mnemonic for i in wrapper], ['mov', 'mov', 'b'])
        core = _parse_imm(wrapper[2].op_str)
        self.assertEqual(_find_readfrom_c_func(self.ctx, cls), core)
        self.assertEqual(self.core_index.get(core), 'GEOPDComponentValue')

    def test_a_preamble_lsr_that_dispatches_nothing_does_not_hide_the_real_one(self):
        self.assertEqual(self.ev('GEOMapServiceTraits').elements()[39], 'GEOAutomobileOptions')


@unittest.skipUnless(_IPHONE8, 'iPhone 8 cache not present (iphone8_data/dylib or MACHO_TEST_CACHE)')
class TestIPhone8CoreParsec(_Live):
    """CoreParsec's ``_CP...`` classes are proto classes only through the PBCodable superclass
    closure; the core index used to gate on the name heuristic alone and came out empty."""
    CACHE = _IPHONE8
    IMAGE = 'CoreParsec'

    def test_the_core_index_holds_the_closure_classes(self):
        self.assertIn('_CPValue', self.core_index.values())
        self.assertGreater(len(self.core_index), 50)

    def test_a_singular_setter_ending_in_a_tail_branch_is_not_an_adder(self):
        # Field 4 is the singular goTakeoverResult: [self setGoTakeoverResult:e].  The setter
        # ends in a tail branch, and the next method (setUniqueIdsOfVisibleButtons:) loads an
        # array ivar's offset; reading past the setter's own end bound field 4 to that array.
        ev = self.ev('_CPVisibleResultsFeedback')
        self.assertEqual(ev.elements().get(4), '_CPSearchResultForFeedback')
        self.assertEqual(ev.ivars(), {'_results': ('_CPSearchResultForFeedback', 2)})


class TestEvaluateClassMemo(unittest.TestCase):
    """The evaluation depends on the core index, so it is memoised only for the image's own
    index (cached on ctx as _readfrom_core_index) and for an empty one (code review
    2026-10-18: it used to be keyed by class alone, so a {} call could serve a later call
    with the real index)."""

    class _Ctx:
        pass

    class _Cls:
        name, vmaddr, methods = 'GEOX', 0x1000, []

    def setUp(self):
        self.calls = []
        self._saved = E._known_entries, E.find_cores
        E._known_entries = lambda ctx, cls, idx: self.calls.append(len(idx)) or []
        E.find_cores = lambda ctx, cls, entries, flows=None: ([], [])

    def tearDown(self):
        E._known_entries, E.find_cores = self._saved

    def test_empty_index_is_memoised(self):
        ctx = self._Ctx()
        a, b = E.evaluate_class(ctx, self._Cls, {}), E.evaluate_class(ctx, self._Cls, {})
        self.assertIs(a, b)
        self.assertEqual(self.calls, [0])

    def test_image_index_is_memoised_separately_from_empty(self):
        ctx = self._Ctx()
        ctx._readfrom_core_index = {0x2000: 'GEOY'}
        empty = E.evaluate_class(ctx, self._Cls, {})
        image = E.evaluate_class(ctx, self._Cls, ctx._readfrom_core_index)
        self.assertIsNot(empty, image)
        self.assertIs(E.evaluate_class(ctx, self._Cls, ctx._readfrom_core_index), image)
        self.assertEqual(self.calls, [0, 1])

    def test_other_index_is_not_memoised(self):
        ctx = self._Ctx()
        other = {0x2000: 'GEOY'}
        E.evaluate_class(ctx, self._Cls, other)
        E.evaluate_class(ctx, self._Cls, {0x3000: 'GEOZ'})
        E.evaluate_class(ctx, self._Cls, other)          # the same index again: afresh too
        self.assertEqual(self.calls, [1, 1, 1])



class TestAppendedIvar(unittest.TestCase):
    """A function handed self and the element is read with what it is handed: the array ivar is
    the ``self->ivar`` it sends the element to (f25's PBAppendMessageAtOffset(self, 8, e)), not
    an argument that equals an array ivar's offset."""
    ELEM = T.ret_value(99)
    OBJECTS = Objects(opaque=T.opaque, field_value=T.field_value,
                      call_result=lambda k, target, x0: T.ret_value(k))

    def appended(self, *body):
        from unittest import mock
        insns, _ = listing(*body)
        with mock.patch.object(E, "_function_insns", lambda ctx, va, entries=None: insns), \
                mock.patch.object(E.D, "decoded_flow", lambda ctx, ins: Flow(None, ins)):
            return E._appended_ivar(None, 0x1000, {'x0': SELF, 'x1': 8, 'x2': self.ELEM},
                                    {self.ELEM}, frozenset({8, 16}), self.OBJECTS, None)

    def test_the_ivar_at_the_offset_it_is_handed(self):
        self.assertEqual(self.appended('ldr x0, [x0, x1]', f'bl {CALL}', 'ret'), 8)

    def test_a_function_that_appends_to_no_ivar_of_self_names_none(self):
        # handed (self, 8, element) as well, but it sends the element elsewhere
        self.assertIsNone(self.appended('mov x0, x2', 'mov x2, x1', f'bl {CALL}', 'ret'))


class TestInitFamily(unittest.TestCase):
    """An element is the result of an init-family method sent to one (it returns its receiver):
    clang's ARC family, ``init`` then anything but a lowercase letter."""

    def test_family(self):
        for sel in ("init", "initWithData:", "init:", "initWithDictionary:error:"):
            self.assertTrue(E._init_family(sel), sel)
        for sel in ("initialize", "initiate", "_init", "copy", None):
            self.assertFalse(E._init_family(sel), sel)


if __name__ == '__main__':
    unittest.main()
