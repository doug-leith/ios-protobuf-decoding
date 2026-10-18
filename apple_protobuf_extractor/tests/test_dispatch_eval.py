"""
proto/dispatch_eval.py -- readFrom: field dispatch decoded by evaluation -- and the parts of
proto/arm64_eval.Flow it is built on (``run_from``, opaque values, the object-escape stack rule,
per-``br`` arm edges, tail targets, the rejoin stop, ``candidates(intervals=)``).

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

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, '..'))

from macho.disasm import Insn
from proto.arm64_eval import Flow, _STACK_TOP
from proto import dispatch_eval as E

CALL, CALL2 = '#0x9000', '#0x9100'           # callees outside the listing
SELF = E.SELF


def listing(*lines, base=0x1000):
    """``(insns, labels)`` for *lines* (``'mnemonic ops'`` or ``'label:'``) placed at *base*;
    ``@label`` operands become addresses."""
    labels, code, pc = {}, [], base
    for ln in lines:
        if ln.endswith(':'):
            labels[ln[:-1]] = pc
        else:
            code.append((pc, ln))
            pc += 4
    out = []
    for a, ln in code:
        mn, _, ops = ln.partition(' ')
        for name, addr in labels.items():
            ops = ops.replace('@' + name, hex(addr).replace('0x', '#0x'))
        out.append(Insn(addr=a, mnemonic=mn, op_str=ops, size=4, raw=b'\0' * 4))
    return out, labels


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
        r = Flow(None, insns).run_from(0, {'x0': SELF}, call_result=lambda k, target, x0: E._ret_value(k), opaque=E._opaque)
        got = calls_by_target(r)
        self.assertEqual(got[0x9000].args['x0'], SELF)
        self.assertEqual(got[0x9100].args['x0'], SELF)            # callee-saved copy survived
        self.assertEqual(got[0x9100].args['x1'], E._ret_value(1))   # the first call's result

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
        r = Flow(None, insns).run_from(0, {'x0': SELF}, opaque=E._opaque)
        self.assertEqual(set(calls_by_target(r)), {0x9000, 0x9100})   # x0 opaque: both sides
        insns2, _ = listing('mov w8, #0', 'cbz w8, @skip', f'bl {CALL}', 'skip:', 'ret')
        self.assertEqual(calls_by_target(Flow(None, insns2).run_from(0, {})), {})


class TestOpaqueValues(unittest.TestCase):
    """SELF / call results are objects: a copy carries them, nothing else may compute with them."""

    def run_x1(self, *body):
        insns, _ = listing(*body, f'bl {CALL}', 'ret')
        r = Flow(None, insns).run_from(0, {'x0': SELF}, opaque=E._opaque)
        return calls_by_target(r)[0x9000].args.get('x1')

    def test_a_64_bit_copy_carries_it(self):
        self.assertEqual(self.run_x1('mov x1, x0'), SELF)

    def test_a_32_bit_copy_does_not(self):
        self.assertIsNone(self.run_x1('mov w1, w0'))

    def test_arithmetic_and_loads_through_it_are_unknown(self):
        self.assertIsNone(self.run_x1('add x1, x0, #8'))
        self.assertIsNone(self.run_x1('ldr x1, [x0, #8]'))

    def test_without_the_predicate_a_token_is_an_ordinary_number(self):
        insns, _ = listing('add x1, x0, #8', f'bl {CALL}', 'ret')
        r = Flow(None, insns).run_from(0, {'x0': SELF})
        self.assertEqual(calls_by_target(r)[0x9000].args.get('x1'), SELF + 8)


class TestObjectEscape(unittest.TestCase):
    """An element spilled across a call that is handed a HIGHER frame address (the iPhone 8
    GEOTFCompactRoadSpeeds shape: ``str x0,[sp,#8]`` ... ``add x1,sp,#0x60; bl`` ...
    ``ldr x1,[sp,#8]; bl adder``)."""

    BODY = ('sub sp, sp, #0x80', f'bl {CALL}', 'str x0, [sp, #8]', 'add x1, sp, #0x60',
            f'bl {CALL}', 'ldr x1, [sp, #8]', f'bl {CALL2}', 'add sp, sp, #0x80', 'ret')

    def x1_at_adder(self, object_escape):
        insns, _ = listing(*self.BODY)
        r = Flow(None, insns).run_from(0, {}, call_result=lambda k, target, x0: E._ret_value(k), opaque=E._opaque,
                                       object_escape=object_escape)
        return calls_by_target(r)[0x9100].args.get('x1')

    def test_a_slot_below_the_escaped_address_survives(self):
        self.assertEqual(self.x1_at_adder(True), E._ret_value(1))

    def test_the_default_rule_clears_every_slot(self):
        self.assertIsNone(self.x1_at_adder(False))

    def test_a_slot_at_or_above_the_escaped_address_is_cleared(self):
        insns, _ = listing('sub sp, sp, #0x80', 'mov x8, #5', 'str x8, [sp, #0x68]',
                           'add x1, sp, #0x60', f'bl {CALL}', 'ldr x1, [sp, #0x68]',
                           f'bl {CALL2}', 'ret')
        r = Flow(None, insns).run_from(0, {}, object_escape=True)
        self.assertNotIn('x1', calls_by_target(r)[0x9100].args)


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
        r = Flow(None, insns).run_from(0, {'x2': SELF}, opaque=E._opaque,
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


class TestCandidateIntervals(unittest.TestCase):

    def test_a_gate_clamped_before_the_table_load_still_yields_its_interval(self):
        # the macOS 27 engine shape: sub; cmp; b.hi; cmp; csel (clamp); ldrsw [table, x16]
        insns, lab = listing('lsr x1, x22, #3', 'sub w16, w1, #1', 'cmp w16, #9', 'b.hi @out',
                             'cmp x16, #9', 'csel x16, x16, xzr, ls',
                             'ldrsw x16, [x17, x16, lsl #2]', 'out:', 'ret')
        ivs = []
        cands = Flow(None, insns).candidates(0, 'x1', (1, 1 << 29), intervals=ivs)
        self.assertIn((1, 10), ivs)
        self.assertNotIn(5, cands)            # without the sink only the gate's end points


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


def _expected(fixture_dir):
    path = os.path.join(_FIXTURES_DIR, fixture_dir, 'expected.py')
    spec = importlib.util.spec_from_file_location(f'_de_expected_{fixture_dir}', path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.EXPECTED


class TestSyntheticFixtures(unittest.TestCase):
    """For every message-typed field of every fixture message: the evaluator binds its number
    to its element class; a repeated one also binds its ivar.  No other number is bound."""

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
            known = set(expected)
            for msg, spec in expected.items():
                cls = by_name.get(msg)
                if cls is None or cls.get_method('readFrom:') is None:
                    continue
                want = {f['number']: f for f in spec['fields']
                        if f['type_name'] not in _SCALARS and f['type_name'] in known}
                got = E.evaluate_class(ctx, cls, core_index)
                with self.subTest(fixture=f'{fixture_dir}/{binary}', message=msg):
                    self.assertEqual(got.elements(),
                                     {n: f['type_name'] for n, f in want.items()},
                                     f'notes: {got.notes}')
                    for n, f in want.items():
                        if f['label'] == 'repeated' and fixture_dir not in _ARGLESS_ADDER:
                            ivar = next((iv for iv, (_c, num) in got.ivars().items() if num == n), None)
                            self.assertIsNotNone(ivar, f'field {n}: no adder->ivar binding')
                checked += 1
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
        got = self.ev('GEOPDPlaceCollection')
        self.assertNotIn(29, got.elements())
        self.assertEqual(got.elements()[1], 'GEOLocalizedString')
        self.assertTrue(any('self not held' in n for n in got.notes))

    def test_an_inline_reader_has_no_c_core(self):
        # -[GEOPDTileList readFrom:] holds the dispatch itself; its first call retains the
        # reader.  The runtime stub it calls must not be indexed (it used to be, named after
        # the first inline reader, GEOFlyoverRegionVersions).
        self.assertNotIn('GEOPDTileList', self.core_index.values())
        self.assertNotIn('GEOFlyoverRegionVersions', self.core_index.values())
        self.assertEqual(self.ev('GEOPDTileList').ivars(), {'_tiles': ('GEOTileCoordinate', 1)})

    def test_a_thin_wrapper_core_is_indexed(self):
        from proto.dispatch import _find_readfrom_c_func
        core = _find_readfrom_c_func(self.ctx, self.by_name['GEOPDComponentValue'])
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
        E.evaluate_class(ctx, self._Cls, {0x2000: 'GEOY'})
        E.evaluate_class(ctx, self._Cls, {0x3000: 'GEOZ'})
        self.assertEqual(self.calls, [1, 1])


if __name__ == '__main__':
    unittest.main()
