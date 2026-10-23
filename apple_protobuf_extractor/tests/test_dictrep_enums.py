"""
Tests for ``_dictionaryRepresentation:`` switch-table enum recovery (Gap 2).

Some Apple proto enums have no ``xAsString:``/``StringAsX:`` companion selector
(e.g. ``GEOComponentType`` / ``ComponentStatus`` on ``GEOPDComponent``).  Their
int→name map lives in the class's ``-[Class _dictionaryRepresentation:]`` method
as one LLVM switch per field.  ``_harvest_dictrep`` disassembles that
method, locates each switch by the ivar offset it reads, and recovers the
per-value ``cfstring`` names.

Two layers are tested:

* **Synthetic** — assembled bodies (tests/_a64asm.py) that have no binary
  dependency.
* **Live** — the full harvester against the real GeoServices cache, gated on the
  cache being present (``dylib/dyld_shared_cache_arm64``).  Ground truth: the
  ``GEOComponentType`` switch at ``0x18d85bb7c`` (97 entries, 8 gaps) and its
  value→name mapping cross-checked against the confirmed ``GEOPDComponentValue``
  field numbers (field# == ComponentType value).
"""

import os
import artifacts
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

from tests._a64asm import assemble, FlowCtx
from macho.disasm import disasm


class _FakeMethod:
    def __init__(self, imp):
        self.imp = imp


class _FakeIvar:
    def __init__(self, name, offset):
        self.name = name
        self.offset = offset


class _FakeCls:
    name = 'GEOFakeResult'

    def __init__(self, dictrep_imp, ivars):
        self._dictrep_imp = dictrep_imp
        self.ivars = ivars

    def get_method(self, sel):
        if sel == '_dictionaryRepresentation:':
            return _FakeMethod(self._dictrep_imp)
        return None


_UNKNOWN_FMT = '(unknown: %i)'


class TestHarvestDictrepEnumsCompareChain(unittest.TestCase):
    """``_harvest_dictrep`` recovers an inlined compare chain: the field's value is
    loaded from its ivar (``ldr w1, [x19, x8]`` with x8 from the ivar-offset slot), a ``cbz``
    names value 0, ``cmp #1; b.ne`` names value 1, every other value reaches the converter's
    ``"(unknown: %i)"`` fallback, and the chosen name reaches the call as its first argument.
    Modelled on GEOBatchPlaceResult.statusCode (assembled by ``tests/_a64asm.py``)."""

    BASE = 0x1000
    IVAR_OFFSET_TABLE = 0x5040   # holds the field's own ivar byte offset (16)
    IVAR_OFFSET = 16
    STR0_ADDR, STR1_ADDR, UNKNOWN_ADDR = 0x6080, 0x7010, 0x8020

    CODE = [
        'tbz w0, #0, end',                    # has-bits gate
        'adrp x8, #0x5000', 'ldrsw x8, [x8, #0x40]',   # this field's ivar-offset lookup
        'ldr w1, [x19, x8]',                  # the value
        'cbz w1, l0',                         # value 0
        'cmp w1, #1', 'b.ne unk',             # value 1, else unknown
        'adrp x21, #0x7000', 'add x21, x21, #0x10', 'b merge',
        'l0:', 'adrp x21, #0x6000', 'add x21, x21, #0x80', 'b merge',
        'unk:', 'adrp x2, #0x8000', 'add x2, x2, #0x20', 'bl helper', 'b end',
        'merge:', 'mov x2, x21', 'bl helper',
        'end:', 'b helper',                   # tail-call epilogue, as in the real code
        'helper:', 'ret',
    ]

    def _build_ctx(self):
        words, _ = assemble(self.BASE, self.CODE)
        ctx = FlowCtx(self.BASE, words)
        ctx._m[self.IVAR_OFFSET_TABLE] = self.IVAR_OFFSET
        ctx._strings = {
            self.STR0_ADDR: 'MY_VALUE_ZERO', self.STR1_ADDR: 'MY_VALUE_ONE',
            self.UNKNOWN_ADDR: _UNKNOWN_FMT,
        }
        return ctx

    def test_recovers_both_values_from_the_compare_chain(self):
        from proto.enums import _harvest_dictrep
        ctx = self._build_ctx()
        cls = _FakeCls(self.BASE, [_FakeIvar('_myField', self.IVAR_OFFSET)])
        result = _harvest_dictrep(ctx, cls)[0]
        self.assertEqual(result, {
            self.IVAR_OFFSET: [(0, 'MY_VALUE_ZERO'), (1, 'MY_VALUE_ONE')],
        })

    def test_not_attributed_to_an_unrelated_ivar_offset(self):
        # If the field's REAL offset isn't in the class's own ivar list, the chain must
        # not be attributed to it -- valid_offsets is exactly cls.ivars's own offsets.
        from proto.enums import _harvest_dictrep
        ctx = self._build_ctx()
        cls = _FakeCls(self.BASE, [_FakeIvar('_otherField', 999)])
        self.assertEqual(_harvest_dictrep(ctx, cls)[0], {})

    def _ctx_without(self, drop_prefixes, strings):
        code = [c for c in self.CODE if not c.startswith(drop_prefixes)]
        words, _ = assemble(self.BASE, code)
        ctx = FlowCtx(self.BASE, words)
        ctx._m[self.IVAR_OFFSET_TABLE] = self.IVAR_OFFSET
        ctx._strings = strings
        return ctx

    def test_two_names_without_the_unknown_fallback_are_still_an_enum(self):
        # The default path is an unrelated call (no "(unknown: %i)"): the string handed to
        # the call still takes two different values (0 -> ZERO, 1 -> ONE), i.e. it depends
        # on the field's value, which is all an enum is.
        from proto.enums import _harvest_dictrep
        ctx = self._ctx_without(('adrp x2,', 'add x2, x2,'),
                                {self.STR0_ADDR: 'MY_VALUE_ZERO', self.STR1_ADDR: 'MY_VALUE_ONE'})
        cls = _FakeCls(self.BASE, [_FakeIvar('_myField', self.IVAR_OFFSET)])
        self.assertEqual(_harvest_dictrep(ctx, cls)[0], {
            self.IVAR_OFFSET: [(0, 'MY_VALUE_ZERO'), (1, 'MY_VALUE_ONE')]})

    def test_a_single_name_with_nothing_to_vary_against_is_not_an_enum(self):
        # Only value 0 is named and every other value just skips the call: a name that
        # does not vary with the value could be any constant string.
        from proto.enums import _harvest_dictrep
        code = [c for c in self.CODE if c not in ('cmp w1, #1', 'b.ne unk')
                and not c.startswith(('adrp x2,', 'add x2, x2,'))]
        code = [c.replace('adrp x21, #0x7000', 'nop').replace('add x21, x21, #0x10', 'nop')
                for c in code]
        words, _ = assemble(self.BASE, code)
        ctx = FlowCtx(self.BASE, words)
        ctx._m[self.IVAR_OFFSET_TABLE] = self.IVAR_OFFSET
        ctx._strings = {self.STR0_ADDR: 'MY_VALUE_ZERO'}
        cls = _FakeCls(self.BASE, [_FakeIvar('_myField', self.IVAR_OFFSET)])
        self.assertNotIn(self.IVAR_OFFSET, _harvest_dictrep(ctx, cls)[0])

    def test_values_without_a_name_may_simply_skip_the_dictionary_call(self):
        # Older compilers emit no "(unknown: %i)": a value with no name jumps over the call.
        from proto.enums import _harvest_dictrep
        code = [c.replace('b.ne unk', 'b.ne end') for c in self.CODE]
        ctx = self._ctx_without(('adrp x2,', 'add x2, x2,'),
                                {self.STR0_ADDR: 'MY_VALUE_ZERO', self.STR1_ADDR: 'MY_VALUE_ONE'})
        words, _ = assemble(self.BASE, [c for c in code if not c.startswith(('adrp x2,', 'add x2, x2,'))])
        ctx = FlowCtx(self.BASE, words)
        ctx._m[self.IVAR_OFFSET_TABLE] = self.IVAR_OFFSET
        ctx._strings = {self.STR0_ADDR: 'MY_VALUE_ZERO', self.STR1_ADDR: 'MY_VALUE_ONE'}
        cls = _FakeCls(self.BASE, [_FakeIvar('_myField', self.IVAR_OFFSET)])
        self.assertEqual(_harvest_dictrep(ctx, cls)[0], {
            self.IVAR_OFFSET: [(0, 'MY_VALUE_ZERO'), (1, 'MY_VALUE_ONE')]})


class TestHarvestDictrepEnumsOutOfLineChains(unittest.TestCase):
    """Each chain must be attributed to ITS OWN field even when the compiler lays the gated
    blocks out of line (found by the compiled f24 fixture).  The has-bits byte is loaded
    ONCE, a tbnz cascade branches on each field's bit straight to that field's block, and
    those blocks sit AFTER the epilogue.  Field A (statusCode, values 1/5/60) is a cmp+b.eq
    chain, field B (mode, values 0/1) a cbz-0 + cmp chain; ``count`` is a plain int that goes
    straight to ``+numberWithInt:`` (must not become an enum), as does the has-bits byte."""

    BASE = 0x1000
    SLOT_FLAGS, SLOT_STATUS, SLOT_MODE, SLOT_COUNT = 0x5010, 0x5020, 0x5024, 0x5028
    OFF_FLAGS, OFF_STATUS, OFF_MODE, OFF_COUNT = 8, 16, 20, 24
    STRINGS = {
        0x6040: 'TEST_STATUS_FAILED', 0x6080: 'TEST_STATUS_INVALID',
        0x60c0: 'TEST_STATUS_MISMATCH',
        0x7000: 'TEST_MODE_OFF', 0x7040: 'TEST_MODE_ON',
        0x8020: _UNKNOWN_FMT,
    }

    CODE = [
        'adrp x22, #0x5000', 'ldrsw x8, [x22, #0x10]', 'ldrb w8, [x19, x8]',
        'tbnz w8, #0, chainA', 'tbnz w8, #1, chainB',
        'adrp x8, #0x5000', 'ldrsw x8, [x8, #0x28]', 'ldr w2, [x19, x8]', 'bl helper',
        'epilogue:', 'b helper',                                     # tail branch
        'chainA:', 'adrp x8, #0x5000', 'ldrsw x8, [x8, #0x20]', 'ldr w8, [x19, x8]',
        'cmp w8, #1', 'b.eq a1', 'cmp w8, #0x3c', 'b.eq a60', 'cmp w8, #5', 'b.ne adflt',
        'adrp x21, #0x6000', 'add x21, x21, #0x80', 'b amerge',
        'a1:', 'adrp x21, #0x6000', 'add x21, x21, #0x40', 'b amerge',
        'a60:', 'adrp x21, #0x6000', 'add x21, x21, #0xc0', 'b amerge',
        'adflt:', 'adrp x2, #0x8000', 'add x2, x2, #0x20', 'bl helper',
        'amerge:', 'mov x2, x21', 'bl helper', 'b epilogue',
        'chainB:', 'adrp x8, #0x5000', 'ldrsw x8, [x8, #0x24]', 'ldr w8, [x19, x8]',
        'cbz w8, b0', 'cmp w8, #1', 'b.ne bdflt',
        'adrp x21, #0x7000', 'add x21, x21, #0x40', 'b bmerge',
        'b0:', 'adrp x21, #0x7000', 'add x21, x21, #0', 'b bmerge',
        'bdflt:', 'adrp x2, #0x8000', 'add x2, x2, #0x20', 'bl helper',
        'bmerge:', 'mov x2, x21', 'bl helper', 'b epilogue',
        'helper:', 'ret',
    ]

    def _ctx(self):
        words, _ = assemble(self.BASE, self.CODE)
        ctx = FlowCtx(self.BASE, words)
        ctx._m[self.SLOT_FLAGS] = self.OFF_FLAGS
        ctx._m[self.SLOT_STATUS] = self.OFF_STATUS
        ctx._m[self.SLOT_MODE] = self.OFF_MODE
        ctx._m[self.SLOT_COUNT] = self.OFF_COUNT
        ctx._strings = dict(self.STRINGS)
        return ctx

    def _cls(self):
        return _FakeCls(self.BASE, [
            _FakeIvar('_has', self.OFF_FLAGS), _FakeIvar('_statusCode', self.OFF_STATUS),
            _FakeIvar('_mode', self.OFF_MODE), _FakeIvar('_count', self.OFF_COUNT)])

    def test_each_out_of_line_chain_goes_to_its_own_field(self):
        from proto.enums import _harvest_dictrep
        result = _harvest_dictrep(self._ctx(), self._cls())[0]
        self.assertEqual(result, {
            self.OFF_STATUS: [(1, 'TEST_STATUS_FAILED'),
                              (5, 'TEST_STATUS_INVALID'),
                              (60, 'TEST_STATUS_MISMATCH')],
            self.OFF_MODE: [(0, 'TEST_MODE_OFF'), (1, 'TEST_MODE_ON')],
        })

    def test_plain_int_field_in_the_same_function_is_not_an_enum(self):
        from proto.enums import _harvest_dictrep
        result = _harvest_dictrep(self._ctx(), self._cls())[0]
        self.assertNotIn(self.OFF_COUNT, result)
        self.assertNotIn(self.OFF_FLAGS, result)

    def test_value_loads_found_by_use_def_chain_in_instruction_order(self):
        """Every load whose address derives from an ivar-offset slot (the has-bits byte via
        the hoisted x22 page, the plain int, and the two out-of-line chains)."""
        from proto.dictrep_flow import Flow
        ctx = self._ctx()
        insns = disasm(ctx, self.BASE, max_insns=200, stop_at_ret=False)
        flow = Flow(ctx, insns)
        got = [(insns[k].addr, off) for k, off in flow.value_loads()]
        self.assertEqual(got, [
            (0x1008, self.OFF_FLAGS),    # ldrb w8, [x19, x8]
            (0x101c, self.OFF_COUNT),    # ldr w2, [x19, x8]
            (0x1030, self.OFF_STATUS),   # out of line (after the epilogue)
            (0x1090, self.OFF_MODE),     # out of line
        ])


# ══════════════════════════════════════════════════════════════════════════════
# Live tests against the real GeoServices cache
# ══════════════════════════════════════════════════════════════════════════════

_CACHE_MAIN = artifacts.cache_file()
_SKIP_MSG = ('dyld shared cache not found — place the full cache in '
             '<repo>/iphone8_data/dylib/ (or set MACHO_DATA_DIR)')


@unittest.skipUnless(_CACHE_MAIN is not None, _SKIP_MSG)
class TestDictRepEnumsLive(unittest.TestCase):
    """Recover GEOComponentType / ComponentStatus from the real cache."""

    @classmethod
    def setUpClass(cls):
        from macho.dyld_cache import DyldCacheReader
        from macho.memory import BinaryContext
        from macho.strings import build_string_table
        from macho.classlist import build_class_list
        from macho.local_symbols import apply_to_classes
        from proto.protocore import _proto_name
        from proto.enums import _harvest_dictrep

        cls.reader = DyldCacheReader(_CACHE_MAIN)
        cls.mach_va = cls.reader.find_image_header('GeoServices')
        if cls.mach_va is None:
            return
        ctx = BinaryContext.from_cache(cls.reader, cls.mach_va)
        st = build_string_table(ctx)
        clist = build_class_list(ctx, st)
        syms = cls.reader.image_local_symbols(cls.mach_va)
        if syms:
            apply_to_classes(clist, syms)
        cls.ctx = ctx
        cls.st = st
        cls.clist = clist
        comp = next((c for c in clist
                     if c.name == 'GEOPDComponent' and not c.is_meta), None)
        cls.comp = comp
        cls.harvest = _harvest_dictrep(ctx, comp)[0] if comp else {}
        cls._off = {_proto_name(iv.name): iv.offset
                    for iv in comp.ivars if iv.name} if comp else {}

    @classmethod
    def tearDownClass(cls):
        cls.reader.close()

    def setUp(self):
        if self.mach_va is None:
            self.skipTest('GeoServices not present in this cache')
        if not getattr(self, 'comp', None):
            self.skipTest('GEOPDComponent not found')

    def _type_enum(self):
        off = self._off.get('type')
        self.assertIn(off, self.harvest, 'type switch should be recovered')
        return dict(self.harvest[off])

    def test_component_type_known_values(self):
        """Cross-check against confirmed GEOPDComponentValue field numbers."""
        d = self._type_enum()
        expect = {
            0:  'COMPONENT_TYPE_UNKNOWN',
            1:  'COMPONENT_TYPE_ENTITY',
            2:  'COMPONENT_TYPE_PLACE_INFO',
            4:  'COMPONENT_TYPE_BOUNDS',
            20: 'COMPONENT_TYPE_TRANSIT_INCIDENT',
            31: 'COMPONENT_TYPE_ADDRESS_OBJECT',
            36: 'COMPONENT_TYPE_TIP',
            41: 'COMPONENT_TYPE_RAP',
            48: 'COMPONENT_TYPE_VENUE_INFO',
            88: 'COMPONENT_TYPE_ENHANCED_PLACEMENT',
            96: 'COMPONENT_TYPE_POI_CLAIM',
        }
        for val, name in expect.items():
            self.assertEqual(d.get(val), name,
                             f'ComponentType[{val}] should be {name}')

    def test_component_type_gaps_absent(self):
        """The 8 in-range gap values route to UNKNOWN and must not be emitted."""
        d = self._type_enum()
        for gap in (17, 18, 19, 21, 28, 35, 75, 80):
            self.assertNotIn(gap, d, f'value {gap} is a gap — must be absent')

    def test_component_type_no_key_contamination(self):
        """No value name should be a stray dictionary key (lowercase field name)."""
        d = self._type_enum()
        for val, name in d.items():
            self.assertTrue(name.startswith('COMPONENT_TYPE'),
                            f'value {val} got non-enum string {name!r}')
        # 89 = 88 named component types + COMPONENT_TYPE_UNKNOWN(0)
        self.assertEqual(len(d), 89)

    def test_status_recovered_without_contamination(self):
        """The status switch yields the status values, not the 'status' key."""
        off = self._off.get('status')
        d = dict(self.harvest.get(off, []))
        self.assertGreaterEqual(len(d), 2)
        self.assertEqual(d.get(1), 'STATUS_FAILED')
        self.assertEqual(d.get(2), 'STATUS_INCOMPLETE')
        for name in d.values():
            self.assertEqual(name, name.upper(),
                             f'status value {name!r} looks like a dict key')

    def test_status_full_hybrid_switch(self):
        """ComponentStatus is a hybrid: a dense jump table (0,1,2,5) plus
        isolated cmp+b.eq/b.ne comparisons for the sparse high values
        (20,30,40,50,60).  All 9 must be recovered (cross-checked against the
        hand-decoded GEOPDPlaceResponse.proto reference)."""
        off = self._off.get('status')
        d = dict(self.harvest.get(off, []))
        self.assertEqual(d, {
            0:  'STATUS_SUCCESS',          # pre-loaded default (value 0)
            1:  'STATUS_FAILED',
            2:  'STATUS_INCOMPLETE',
            5:  'INVALID_REQUEST',         # dense jump table
            20: 'FAILED_NO_RESULT',        # isolated cmp #0x14
            30: 'NEEDS_REFINEMENT',        # isolated cmp #0x1e
            40: 'FAILED_NOT_AUTHORIZED',   # isolated cmp #0x28
            50: 'STATUS_DEDUPED',          # isolated cmp #0x32
            60: 'VERSION_MISMATCH',        # isolated cmp #0x3c
        })

    def test_cache_control_pointer_table(self):
        """cacheControl uses the pointer-table form (ldr [table, v, lsl#3])."""
        off = self._off.get('cacheControl')
        d = dict(self.harvest.get(off, []))
        self.assertEqual(d, {
            0: 'UNKNOWN_CACHEABILITY',
            1: 'UNCACHEABLE',
            2: 'CACHEABLE',
        })

    def test_dictrep_extent_bound_not_truncated(self):
        """TODO #40: a class whose _dictionaryRepresentation: overruns the 8000-insn
        PROBE no longer flags as truncated — the function-extent bound recomputes the
        whole contiguous body, which closes on its own `ret` below the safety ceiling.
        (Was test_dictrep_truncation_fails_loud, which asserted the OPPOSITE under the
        old magic-count budget; the cap was proven to lose zero enums — dictrep_probe3.)"""
        from proto.enums import _harvest_dictrep
        target = next((c for c in self.clist
                       if c.name == 'GEOPDSearchQueryIntentMetadata'
                       and not c.is_meta), None)
        if target is None:
            self.skipTest('GEOPDSearchQueryIntentMetadata not in this cache')
        self.ctx._dictrep_truncated_classes = None
        _harvest_dictrep(self.ctx, target)[0]
        self.assertNotIn('GEOPDSearchQueryIntentMetadata',
                         self.ctx._dictrep_truncated_classes or set())

    def _harvest_field(self, class_name, field_name):
        """{value: name} for class_name.field_name's dictRep enum, or None."""
        from proto.protocore import _proto_name
        from proto.enums import _harvest_dictrep
        cls = next((c for c in self.clist
                    if c.name == class_name and not c.is_meta), None)
        if cls is None:
            return None
        off = next((iv.offset for iv in cls.ivars
                    if iv.name and _proto_name(iv.name) == field_name), None)
        if off is None:
            return None
        return dict(_harvest_dictrep(self.ctx, cls)[0].get(off, []))

    def test_pointer_table_1based_enums_biased(self):
        """TODO #54: the 3 Hopper-confirmed 1-based dictRep-only enums (pointer-table
        idiom) recover their real values, not the 0-based raw table index."""
        # _harvest_dictrep returns the RAW value-string names; the emitter
        # later qualifies them (RELATIONSHIP_OWNER -> PD_QUICK_LINK_ITEM_…_OWNER).
        rel = self._harvest_field('GEOPDQuickLinkItem', 'relationship')
        if rel is None:
            self.skipTest('GEOPDQuickLinkItem not in this cache')
        self.assertEqual(rel.get(1), 'RELATIONSHIP_OWNER')
        self.assertEqual(rel.get(3), 'RELATIONSHIP_OTHER')
        self.assertNotIn(0, rel, '1-based enum must not start at 0')

        tag = self._harvest_field('GEOPDSearchGeoParsingResult', 'tagSource')
        if tag is not None:
            self.assertEqual(tag.get(1), 'CRF')
            self.assertNotIn(0, tag)

        chain = self._harvest_field('GEOPDSearchChainInfo', 'relationshipTypes')
        if chain is not None:
            self.assertEqual(chain.get(1), 'DIFFERENT_FROM')
            self.assertNotIn(0, chain)

    # (Removed test_xasstring_routed_field_not_rebiased: it asserted GEOTFIncident.
    # laneClosureType stays 0-based because "it has an xAsString: selector".  It has
    # none -- the image-wide selector pool hit that suggested it was another class's --
    # and its dictRep is `sub w9,w8,#1 ; cmp w9,#9`, i.e. 1..9.  That is now pinned by
    # TestBiasedDictRepEnumsLive; the genuine xAsString-owned side (no double bias) by
    # the f28 TestKind fixture and TestFieldRoutesThroughXAsString.)

    def test_dictrep_body_is_its_whole_extent(self):
        """The dictRep body of the classes whose bodies are longest is read whole: the linear
        listing of its extent, up to the next function entry, nothing left unread."""
        from proto.enums import _dictrep_body
        from proto.function_body import function_end
        names = ('GEOPDSearchQueryIntentMetadata', 'GEOAnalyticsPipelineStateData',
                 'GEOLogMsgStateCuratedCollection')
        seen = 0
        for cls in self.clist:
            if cls.is_meta or cls.name not in names:
                continue
            m = cls.get_method('_dictionaryRepresentation:')
            if m is None or m.imp == 0:
                continue
            body = _dictrep_body(self.ctx, m.imp)
            self.assertTrue(body, f'{cls.name}: empty body')
            self.assertFalse(body.truncated, f'{cls.name}: body read only in part')
            self.assertEqual(body[-1].addr + 4, function_end(self.ctx, m.imp),
                             f'{cls.name}: body does not reach its extent')
            seen += 1
        if seen == 0:
            self.skipTest('longest-body classes not in this cache')


class TestEnumRecoveryTruncatedRendering(unittest.TestCase):
    """The class-level enum_recovery_truncated flag renders a WARNING comment
    (offline — no cache needed)."""

    def _msg(self, truncated):
        from proto.models import ProtoMessage, ProtoField, FieldLabel
        f = ProtoField(name='kind', number=1, type_name='int32',
                       label=FieldLabel.OPTIONAL, type_class=None)
        return ProtoMessage(name='Foo', class_name='GEOFoo', fields=[f],
                            enum_recovery_truncated=truncated)

    # (test_model_to_proto_emits_comment_when_truncated /
    # test_model_to_proto_no_comment_by_default removed 2026-07-22:  they
    # called the now-deleted ProtoMessage.to_proto, a dead-code twin of
    # _emit_message below that nothing in production ever called --
    # test_emitter_emits_comment_when_
    # truncated / test_emitter_no_comment_by_default already cover the exact
    # same behavior against the real renderer, so no coverage was lost.)

    def _emit(self, truncated):
        from proto.emitter import ProtoFile
        pf = ProtoFile(package='geo', filename='geo.proto',
                       messages=[self._msg(truncated)], imports=[])
        return pf.emit()

    def test_emitter_emits_comment_when_truncated(self):
        self.assertIn('enum recovery may be INCOMPLETE', self._emit(True))

    def test_emitter_no_comment_by_default(self):
        self.assertNotIn('enum recovery may be INCOMPLETE', self._emit(False))

    def test_snapshot_records_flag_only_when_true(self):
        from snapshot_output import _snap_messages
        snap_t = _snap_messages([self._msg(True)])
        snap_f = _snap_messages([self._msg(False)])
        self.assertIn('GEOFoo.<enum_recovery_truncated>', snap_t)
        self.assertNotIn('GEOFoo.<enum_recovery_truncated>', snap_f)


@unittest.skipUnless(_CACHE_MAIN is not None, _SKIP_MSG)
class TestHalfwordJumpTableEnumLive(unittest.TestCase):
    """Regression for the **halfword** (``ldrh``) jump-table value-string reader.

    ``-[GEOTileSet styleAsString:]`` dispatches its ~100 cases through a HALFWORD
    jump table (the case-block region exceeds 1 KB, so each offset needs 2 bytes —
    ``ldrh w11, [x9, x8, lsl #1]``).  The jump-table reader formerly
    hardcoded a 1-byte / stride-1 read and discarded the width it had already
    decoded, mis-striding every entry: it smeared value 1's ``VECTOR_STANDARD``
    across 9, 11, 13, … and dropped the wire-observed values 18 and 20 entirely.
    Honouring the detected entry width (``ldrb``→1, ``ldrh``→2) fixes it.

    Surfaced by mitm traffic (``Resources f3 style=18/20 not in TileSetStyle``);
    ground truth is the published ``GEOTileStyle`` enum (values 0-8 match exactly,
    confirming no decoder off-by-one) plus the halfword-decoded case blocks."""

    @classmethod
    def setUpClass(cls):
        from macho.dyld_cache import DyldCacheReader
        from macho.memory import BinaryContext
        from macho.strings import build_string_table
        from macho.classlist import build_class_list
        from macho.local_symbols import apply_to_classes
        from proto.enums import _extract_enum_values

        cls.reader = DyldCacheReader(_CACHE_MAIN)
        mv = cls.reader.find_image_header('GeoServices')
        if mv is None:
            cls.pairs = None
            return
        ctx = BinaryContext.from_cache(cls.reader, mv)
        st = build_string_table(ctx)
        clist = build_class_list(ctx, st)
        syms = cls.reader.image_local_symbols(mv)
        if syms:
            apply_to_classes(clist, syms)
        # Resolve the IMP by class+selector (NOT a hardcoded VA — survives a cache
        # rev) and decode its value→string pairs through the production path.
        imp = next((m.imp for c in clist if c.name == 'GEOTileSet' and not c.is_meta
                    for m in c.methods if m.name == 'styleAsString:'), None)
        cls.imp = imp
        cls.pairs = (_extract_enum_values(ctx, imp)[0] if imp else None)
        cls.d = dict(cls.pairs) if cls.pairs else {}

    @classmethod
    def tearDownClass(cls):
        cls.reader.close()

    def setUp(self):
        if not self.pairs:
            self.skipTest('GEOTileSet styleAsString: not found in cache')

    def test_low_range_matches_published_geotilestyle(self):
        # 0-8 are the dense, stable head of the enum; matching the published
        # GEOTileStyle exactly proves there is no decoder off-by-one.
        self.assertEqual(self.d.get(0), 'RASTER_STANDARD')
        self.assertEqual(self.d.get(1), 'VECTOR_STANDARD')
        self.assertEqual(self.d.get(5), 'RASTER_STANDARD_BACKGROUND')
        self.assertEqual(self.d.get(8), 'RASTER_TERRAIN')

    def test_wire_observed_values_recovered(self):
        # The exact values mitm traffic flagged as "not in enum" pre-fix — both
        # are real, distinct case blocks the byte-stride read had dropped.
        self.assertEqual(self.d.get(18), 'VECTOR_REALISTIC')
        self.assertEqual(self.d.get(20), 'VECTOR_ROADS')

    def test_no_byte_misread_smear(self):
        # Corruption signature: reading the halfword table as bytes mapped many
        # distinct values to VECTOR_STANDARD.  A correct read assigns it once.
        smear = sorted(v for v, s in self.pairs if s == 'VECTOR_STANDARD')
        self.assertEqual(smear, [1])

    def test_recovers_substantially_more_than_a_byte_read(self):
        # BREADTH-ONLY sanity check: the byte-stride corruption this class guards
        # against SMEARS values (many distinct cases collapse onto the same wrong
        # string) rather than dropping the pair count below 90, so this assertion
        # alone can't catch that corruption -- it's a coarse "did the read run at
        # all" sanity, not a mutation-testing target. Precision is covered by
        # test_wire_observed_values_recovered (specific dropped values 18/20) and
        # test_no_byte_misread_smear (the exact smear signature) above, which DO
        # catch a revert.
        self.assertGreaterEqual(len(self.pairs), 90)


@unittest.skipUnless(_CACHE_MAIN is not None, _SKIP_MSG)
class TestChainedSegmentEnumLive(unittest.TestCase):
    """Regression for **idiom-B** (comparison-tree) jump-table segment gating.

    A sparse xAsString: method splits its value space with a binary search whose
    leaves are reached by ``[sub #bias]; cmp wN,#K; b.ls/b.lo <segment>``.  The
    harvester used to attribute each segment only via the linear-preceding
    ``cmp; b.hi default`` gate, so a branch-routed segment grabbed the
    NEIGHBOURING fall-through gate, mis-biased, and its values collided with
    another segment's → dedup-dropped silently.

    Ground truth: ``-[GEOLogMsgState stateTypeAsString:]`` routes stateType
    401-407 (the DEVICE_* cluster) through ``sub w8,w2,#401; cmp w8,#6; b.ls``.
    mitm traffic flagged 402/403/404/407 as "not in enum LogMsgStateType"."""

    @classmethod
    def setUpClass(cls):
        from macho.dyld_cache import DyldCacheReader
        from macho.memory import BinaryContext
        from macho.strings import build_string_table
        from macho.classlist import build_class_list
        from macho.local_symbols import apply_to_classes
        from proto.enums import _extract_enum_values

        cls.reader = DyldCacheReader(_CACHE_MAIN)
        mv = cls.reader.find_image_header('GeoServices')
        if mv is None:
            cls.d = None
            return
        ctx = BinaryContext.from_cache(cls.reader, mv)
        st = build_string_table(ctx)
        clist = build_class_list(ctx, st)
        syms = cls.reader.image_local_symbols(mv)
        if syms:
            apply_to_classes(clist, syms)
        imp = next((m.imp for c in clist if c.name == 'GEOLogMsgState'
                    and not c.is_meta
                    for m in c.methods if m.name == 'stateTypeAsString:'), None)
        cls.d = dict(_extract_enum_values(ctx, imp)[0]) if imp else None

    @classmethod
    def tearDownClass(cls):
        cls.reader.close()

    def setUp(self):
        if not self.d:
            self.skipTest('GEOLogMsgState stateTypeAsString: not found in cache')

    def test_branch_routed_4xx_cluster_recovered(self):
        # The exact mitm-flagged values, plus the rest of the b.ls-routed leaf.
        # _extract_enum_values returns the RAW value-string names (the emitter
        # later qualifies them to LOG_MSG_STATE_TYPE_*).
        self.assertEqual(self.d.get(401), 'DEVICE_BASE')
        self.assertEqual(self.d.get(402), 'DEVICE_LOCALE')
        self.assertEqual(self.d.get(404), 'CAR_PLAY')
        self.assertEqual(self.d.get(407), 'DEVICE_SETTINGS')

    def test_purely_additive_idiomA_segments_undisturbed_by_idiomB_fix(self):
        # NOT a positive test of the idiom-B (comparison-tree) fix itself -- 501/702
        # are idiom-A (fall-through) values the commit's own message calls "purely
        # additive" and never touches; test_branch_routed_4xx_cluster_recovered
        # (above) is what actually regression-guards the idiom-B fix.  This is a
        # no-regression guard: confirms the idiom-B addition didn't disturb the
        # pre-existing idiom-A segments around it.
        self.assertEqual(self.d.get(501), 'MAP_VIEW')
        self.assertEqual(self.d.get(702), 'PLACE_CARD')


@unittest.skipUnless(_CACHE_MAIN is not None, _SKIP_MSG)
class TestUnattributedSegmentWarnsLive(unittest.TestCase):
    """Negative-add-biased jump-table segments are recovered (TODO #53), and a
    cleanly-recovered enum is NOT flagged INCOMPLETE.

    GEOLogMessage logMessageTypeAsString: has a segment biased by the negative-add
    idiom (`mov w8,#-50000; add w8,w2,w8; cmp w8,#3`); the data-flow evaluator
    (proto/dictrep_flow.py) now models it, so the 50000-base values ARE recovered and the enum is no longer
    flagged truncated.  (The seg_incomplete → truncated=True safety net still exists
    for a genuinely-unattributable segment, but no current GeoServices enum hits it.)
    GEOTileSet styleAsString: is a cleanly-recovered halfword-table enum that must
    likewise NOT be flagged."""

    @classmethod
    def setUpClass(cls):
        from macho.dyld_cache import DyldCacheReader
        from macho.memory import BinaryContext
        from macho.strings import build_string_table
        from macho.classlist import build_class_list
        from macho.local_symbols import apply_to_classes
        from proto.enums import _extract_enum_values

        cls.reader = DyldCacheReader(_CACHE_MAIN)
        mv = cls.reader.find_image_header('GeoServices')
        if mv is None:
            cls.ok = False
            return
        ctx = BinaryContext.from_cache(cls.reader, mv)
        st = build_string_table(ctx)
        clist = build_class_list(ctx, st)
        syms = cls.reader.image_local_symbols(mv)
        if syms:
            apply_to_classes(clist, syms)

        def _imp(cn, sel):
            return next((m.imp for c in clist if c.name == cn and not c.is_meta
                         for m in c.methods if m.name == sel), None)
        i_log = _imp('GEOLogMessage', 'logMessageTypeAsString:')
        i_tile = _imp('GEOTileSet', 'styleAsString:')
        i_telem = _imp('GEOTelemetricEntity', 'eventKeyAsString:')
        cls.ok = bool(i_log and i_tile and i_telem)
        if cls.ok:
            log_pairs, _, cls.log_trunc = _extract_enum_values(ctx, i_log)
            cls.log_vals = {v for v, _ in log_pairs}
            cls.tile_trunc = _extract_enum_values(ctx, i_tile)[2]
            telem_pairs, _, cls.telem_trunc = _extract_enum_values(ctx, i_telem)
            cls.telem_vals = {v for v, _ in telem_pairs}

    @classmethod
    def tearDownClass(cls):
        cls.reader.close()

    def setUp(self):
        if not getattr(self, 'ok', False):
            self.skipTest('required methods not found in cache')

    def test_negadd_segment_recovered_not_flagged(self):
        # TODO #53: the negative-add-biased 50000-class segment is now recovered,
        # so LogMessageType is complete and must NOT be flagged truncated.
        self.assertIn(50000, self.log_vals,
                      'LogMessageType 50000-class (negadd-biased) segment not recovered')
        self.assertFalse(self.log_trunc,
                         'LogMessageType is fully recovered → must NOT be flagged '
                         'values_truncated')

    def test_cleanly_recovered_enum_not_flagged(self):
        # GEOTileSet was never flagged truncated, before or after the seg_incomplete
        # fix -- pure negative control. A live positive sibling for the DETECTOR
        # (an enum whose seg_incomplete jump-table segment genuinely fails to bind)
        # is not available: a census over the current GeoServices corpus finds 0
        # enums with values_truncated=True (the negadd/idiomB bias fixes recovered
        # every segment that used to hit this flag -- see the two sibling tests
        # below). The EMITTED-comment side of values_truncated=True is covered at
        # the model level by test_enum.py::TestEnumClassMethods::
        # test_truncated_enum_emits_incomplete_warning; a genuine DETECTOR-level
        # positive would need a hand-built synthetic unattributable jump-table
        # segment (not yet constructed).
        self.assertFalse(self.tile_trunc,
                         'a fully-recovered enum must NOT be flagged incomplete')

    def test_idiomB_materialized_bias_segment_recovered_not_flagged(self):
        # seg_incomplete bias-gap fix: GEOTelemetricEntity.eventKeyAsString: routes
        # two high-value segments through a comparison-tree (Idiom B) whose bias is
        # materialised (mov #-K; add) rather than a literal `sub #imm12`.  The evaluator
        # applies the materialised bias on every path, so those segments (52020-base and 60500-base) ARE recovered and the enum is
        # no longer flagged truncated.
        self.assertIn(60500, self.telem_vals,
                      'Idiom-B 60500-base materialized-bias segment not recovered')
        self.assertIn(52020, self.telem_vals,
                      'Idiom-B 52020-base materialized-bias segment not recovered')
        self.assertFalse(self.telem_trunc,
                         'TelemetricEntityEventKey is fully recovered → must NOT be '
                         'flagged values_truncated')


@unittest.skipUnless(_CACHE_MAIN is not None, _SKIP_MSG)
class TestLongMethodNotFalselyTruncatedLive(unittest.TestCase):
    """TODO #58: a long-but-complete xAsString: method must NOT be flagged
    `values_truncated`.

    The LogMsg-family methods are ~12k instructions; a 1000-insn probe used to run out of
    budget before their `ret`.  The body is now the linear listing of its extent
    (proto.function_body.function_listing), read whole, so nothing flags these enums.  Ground truth: `-[GEOLogMsgEventUserAction userActionEventActionAsString:]`
    (1171 values) and `-[GEORPFeedbackFieldOption keyAsString:]` (124) — both fully
    recovered (incl. the #53 negadd-biased ranges) and therefore complete."""

    @classmethod
    def setUpClass(cls):
        from macho.dyld_cache import DyldCacheReader
        from macho.memory import BinaryContext
        from macho.strings import build_string_table
        from macho.classlist import build_class_list
        from macho.local_symbols import apply_to_classes
        from proto.enums import _extract_enum_values

        cls.reader = DyldCacheReader(_CACHE_MAIN)
        mv = cls.reader.find_image_header('GeoServices')
        if mv is None:
            cls.res = None
            return
        ctx = BinaryContext.from_cache(cls.reader, mv)
        st = build_string_table(ctx)
        clist = build_class_list(ctx, st)
        syms = cls.reader.image_local_symbols(mv)
        if syms:
            apply_to_classes(clist, syms)

        def _imp(cn, sel):
            return next((m.imp for c in clist if c.name == cn and not c.is_meta
                         for m in c.methods if m.name == sel), None)
        cls.res = {}
        for cn, sel in (('GEOLogMsgEventUserAction', 'userActionEventActionAsString:'),
                        ('GEORPFeedbackFieldOption', 'keyAsString:')):
            imp = _imp(cn, sel)
            if imp:
                pairs, _conf, trunc = _extract_enum_values(ctx, imp)
                cls.res[cn] = (len(pairs), trunc)

    @classmethod
    def tearDownClass(cls):
        cls.reader.close()

    def setUp(self):
        if not getattr(self, 'res', None):
            self.skipTest('required xAsString: methods not found in cache')

    def test_long_useraction_method_not_truncated(self):
        n, trunc = self.res.get('GEOLogMsgEventUserAction', (0, None))
        if not n:
            self.skipTest('userActionEventActionAsString: not found')
        self.assertGreater(n, 1000, 'expected the full ~1171-value enum')
        self.assertFalse(trunc, 'long-but-complete enum must NOT be flagged truncated')

    def test_long_feedbackkey_method_not_truncated(self):
        n, trunc = self.res.get('GEORPFeedbackFieldOption', (0, None))
        if not n:
            self.skipTest('keyAsString: not found')
        self.assertGreaterEqual(n, 100)
        self.assertFalse(trunc, 'long-but-complete enum must NOT be flagged truncated')


@unittest.skipUnless(_CACHE_MAIN is not None, _SKIP_MSG)
class TestBiasedDictRepEnumsLive(unittest.TestCase):
    """1-based dictRep-only enums on the real iOS 16 GeoServices image.

    Each of these fields is serialised by ``sub w9,w8,#1 ; cmp w9,#N ; b.hs ;
    ldr x,[table,w9,sxtw #3]`` in ``-[Class _dictionaryRepresentation:]`` and has
    NO ``xAsString:`` selector on its own class -- but the same selector spelling
    (``typeAsString:``, ``resultStatusAsString:``, ``laneClosureTypeAsString:``)
    exists on OTHER classes, which used to make the image-wide selector pool read as
    "routes through xAsString:" and drop the bias (values came out 0-based).
    Ground truth: the ``sub #1`` / ``cmp #N`` at the cited addresses
    (GEOPDGroundDataBuild 0x18d1173c0 N=3, GEOPDSearchQuerySpellCorrectionMetadata
    0x18cbf20c8 N=6, GEOTFIncident 0x18c55e374 N=9) and the iOS 27 extraction."""

    @classmethod
    def setUpClass(cls):
        from macho.dyld_cache import DyldCacheReader
        from macho.memory import BinaryContext
        from macho.strings import build_string_table
        from macho.classlist import build_class_list
        from macho.local_symbols import apply_to_classes
        from proto.protocore import _proto_name
        from proto.enums import _harvest_dictrep

        cls.reader = DyldCacheReader(_CACHE_MAIN)
        mv = cls.reader.find_image_header('GeoServices')
        cls.res = {}
        if mv is None:
            return
        ctx = BinaryContext.from_cache(cls.reader, mv)
        st = build_string_table(ctx)
        clist = build_class_list(ctx, st)
        syms = cls.reader.image_local_symbols(mv)
        if syms:
            apply_to_classes(clist, syms)
        cls.st = st
        for cn, field in (('GEOPDGroundDataBuild', 'type'),
                          ('GEOPDSearchQuerySpellCorrectionMetadata', 'resultStatus'),
                          ('GEOTFIncident', 'laneClosureType')):
            c = next((c for c in clist if c.name == cn and not c.is_meta), None)
            if c is None:
                continue
            off = {_proto_name(iv.name): iv.offset for iv in c.ivars if iv.name}.get(field)
            cls.res[cn] = dict(_harvest_dictrep(ctx, c)[0].get(off, []))

    @classmethod
    def tearDownClass(cls):
        cls.reader.close()

    def _get(self, cn):
        if not self.res.get(cn):
            self.skipTest(f'{cn} enum not recovered / class absent')
        return self.res[cn]

    def test_selector_pool_holds_the_colliding_selectors(self):
        # The precondition that made the old gate misfire: the pool has the selector
        # (from other classes) although GEOPDGroundDataBuild itself has none.
        self.assertTrue(self.st.find('typeAsString:'))

    def test_ground_data_build_type_is_one_based(self):
        d = self._get('GEOPDGroundDataBuild')
        self.assertEqual(d, {1: 'T300', 2: 'T400', 3: 'T392C'})

    def test_spell_correction_result_status_is_one_based(self):
        d = self._get('GEOPDSearchQuerySpellCorrectionMetadata')
        self.assertEqual(sorted(d), [1, 2, 3, 4, 5, 6])
        self.assertEqual(d[1], 'NOT_IN_WHITE_LIST')
        self.assertEqual(d[6], 'NOT_PROCESSED')

    def test_lane_closure_type_is_one_based(self):
        d = self._get('GEOTFIncident')
        self.assertEqual(sorted(d), list(range(1, 10)))
        self.assertEqual(d[1], 'LEFT_LANE')
        self.assertEqual(d[9], 'OFF_RAMP')


@unittest.skipUnless(_CACHE_MAIN is not None, _SKIP_MSG)
class TestDictRepBodyLive(unittest.TestCase):
    """_dictrep_body bounds -[cls _dictionaryRepresentation:] by structure: the linear range
    from its IMP to the next function entry (LC_FUNCTION_STARTS).  iPhone 8 iOS 16
    GeoServices, checked against the cache's .symbols (the next symbol after the IMP):

      GEOPDSearchQueryIntentMetadata   0x18cbe0068..0x18cbe1b90 (jsonRepresentation next)
      GEOLogMsgStateCuratedCollection  0x18d4ca87c..0x18d4d2084
      GEOPDPlace                       0x18c1e2cc0..0x18c1e33c8
      GEOLatLng                        0x18c1c1688..0x18c1c18a8: its C reader starts there,
                                       before the next method (0x18c1c21b4), which the
                                       next-method-IMP bound used to read up to

    A read to the first `ret` ran past every one of these (to 11,296 / 24,647 / 508 / 704
    insns) because a dictRep leaves by a tail call, not a `ret`."""

    CASES = {
        'GEOPDSearchQueryIntentMetadata': (0x18cbe0068, 0x18cbe1b90),
        'GEOLogMsgStateCuratedCollection': (0x18d4ca87c, 0x18d4d2084),
        'GEOPDPlace': (0x18c1e2cc0, 0x18c1e33c8),
        'GEOLatLng': (0x18c1c1688, 0x18c1c18a8),
    }

    @classmethod
    def setUpClass(cls):
        from macho.dyld_cache import DyldCacheReader
        from macho.memory import BinaryContext
        from macho.strings import build_string_table
        from macho.classlist import build_class_list
        from macho.local_symbols import apply_to_classes
        from proto.enums import _dictrep_body

        cls.reader = DyldCacheReader(_CACHE_MAIN)
        cls.bodies = {}
        mv = cls.reader.find_image_header('GeoServices')
        if mv is None:
            return
        ctx = BinaryContext.from_cache(cls.reader, mv)
        st = build_string_table(ctx)
        clist = build_class_list(ctx, st)
        syms = cls.reader.image_local_symbols(mv)
        if syms:
            apply_to_classes(clist, syms)
        ctx._function_entries = {m.imp for c in clist for m in c.methods if m.imp}
        for c in clist:
            if c.is_meta or c.name not in cls.CASES:
                continue
            m = c.get_method('_dictionaryRepresentation:')
            if m is not None and m.imp == cls.CASES[c.name][0]:
                cls.bodies[c.name] = _dictrep_body(ctx, m.imp)

    @classmethod
    def tearDownClass(cls):
        cls.reader.close()

    def test_body_is_the_range_to_the_next_function(self):
        if len(self.bodies) != len(self.CASES):
            self.skipTest('GeoServices classes not at the pinned addresses in this cache')
        for name, (imp, end) in self.CASES.items():
            body = self.bodies[name]
            self.assertEqual(body[0].addr, imp, name)
            self.assertEqual(body[-1].addr + 4, end, name)
            self.assertEqual(len(body), (end - imp) // 4, name)


def _ios27_cache():
    d = os.environ.get('MACHO_TEST_IOS27_CACHE', '').strip() or \
        os.path.join(artifacts.REPO_ROOT, 'ios27_data', 'dylib')
    p = os.path.join(d, 'dyld_shared_cache_arm64e')
    return p if os.path.isfile(p) else None


@unittest.skipUnless(_ios27_cache() is not None, 'iOS 27 cache not present')
class TestDictRepBodyKeepsEvaluatedArmsIOS27(unittest.TestCase):
    """iOS 27 GEOPDSUserActionMetadataElement's dictRep switches through `br` jump tables
    some of whose arms only Flow's evaluation resolves.  Pruning the body to a static CFG
    lost 6 uiAction values (1065 TAP_GEO, 2200, 3088, 5039, 7030, 11029) and 2 uiTarget
    values (1313, 1810); the whole range to the next method keeps all 46 / 31."""

    @classmethod
    def setUpClass(cls):
        from macho.dyld_cache import DyldCacheReader
        from macho.memory import BinaryContext
        from macho.strings import build_string_table
        from macho.classlist import build_class_list
        from macho.local_symbols import apply_to_classes
        from proto.protocore import _proto_name
        from proto.enums import _harvest_dictrep

        cls.reader = DyldCacheReader(_ios27_cache())
        cls.res = None
        mv = cls.reader.find_image_header('/GeoServices.framework/GeoServices')
        if mv is None:
            return
        ctx = BinaryContext.from_cache(cls.reader, mv)
        st = build_string_table(ctx)
        clist = build_class_list(ctx, st)
        syms = cls.reader.image_local_symbols(mv)
        if syms:
            apply_to_classes(clist, syms)
        ctx._function_entries = {m.imp for c in clist for m in c.methods if m.imp}
        c = next((c for c in clist
                  if c.name == 'GEOPDSUserActionMetadataElement' and not c.is_meta), None)
        if c is None:
            return
        off = {_proto_name(iv.name): iv.offset for iv in c.ivars if iv.name}
        enums, incomplete, _ = _harvest_dictrep(ctx, c)
        cls.res = ({k: dict(enums.get(off.get(k), [])) for k in ('uiAction', 'uiTarget')},
                   incomplete)

    @classmethod
    def tearDownClass(cls):
        cls.reader.close()

    def test_every_value_is_recovered(self):
        if self.res is None:
            self.skipTest('GEOPDSUserActionMetadataElement not in this cache')
        values, incomplete = self.res
        self.assertEqual(len(values['uiAction']), 46)
        self.assertEqual(len(values['uiTarget']), 31)
        for v in (1065, 2200, 3088, 5039, 7030, 11029):
            self.assertIn(v, values['uiAction'])
        for v in (1313, 1810):
            self.assertIn(v, values['uiTarget'])
        self.assertFalse(incomplete)

@unittest.skipUnless(_CACHE_MAIN is not None, _SKIP_MSG)
class TestNoArgDictRepLive(unittest.TestCase):
    """Classes whose only dictRep is a self-contained no-arg ``dictionaryRepresentation``
    (no ``_dictionaryRepresentation:``), which leaves by a tail call, not a ``ret``.

    _DKPRValueType (iOS 16 CoreDuet, 0x190beb400): ``cmp w8,#5 ; b.hs`` then a CFString
    pointer table from "INTEGER", exit ``b`` at 0x190beb4d4; Apple's iOS 13
    knowledge.proto gives the same five values.  AWDProactiveAppPredictionSubscores
    (AppPredictionInternal, 0x1bfec6464): ~15.5k insns whose last is a backward ``b``
    (0x1bfed565c) -- the body must close there, not run on to the 40000 safety ceiling."""

    @classmethod
    def setUpClass(cls):
        from macho.dyld_cache import DyldCacheReader
        from macho.memory import BinaryContext
        from macho.strings import build_string_table
        from macho.classlist import build_class_list
        from macho.local_symbols import apply_to_classes
        from proto.protocore import _proto_name
        from proto.enums import _harvest_dictrep

        cls.reader = DyldCacheReader(_CACHE_MAIN)
        cls.res = {}
        for image, cn, field in (('/CoreDuet.framework/CoreDuet', '_DKPRValueType', 'type'),
                                 ('/AppPredictionInternal.framework/AppPredictionInternal',
                                  'AWDProactiveAppPredictionSubscores', None)):
            mv = cls.reader.find_image_header(image)
            if mv is None:
                continue
            ctx = BinaryContext.from_cache(cls.reader, mv)
            st = build_string_table(ctx)
            clist = build_class_list(ctx, st)
            syms = cls.reader.image_local_symbols(mv)
            if syms:
                apply_to_classes(clist, syms)
            # the method-IMP set extract_all threads onto ctx bounds the body
            ctx._function_entries = {m.imp for c in clist for m in c.methods if m.imp}
            c = next((c for c in clist if c.name == cn and not c.is_meta), None)
            if c is None or c.get_method('_dictionaryRepresentation:') is not None:
                continue
            enums = _harvest_dictrep(ctx, c)[0]
            off = {_proto_name(iv.name): iv.offset for iv in c.ivars if iv.name}.get(field)
            cls.res[cn] = (dict(enums.get(off, [])),
                           cn in (getattr(ctx, '_dictrep_truncated_classes', None) or set()))

    @classmethod
    def tearDownClass(cls):
        cls.reader.close()

    def _get(self, cn):
        if cn not in self.res:
            self.skipTest(f'{cn} absent or not a no-arg-only dictRep in this cache')
        return self.res[cn]

    def test_value_type_enum_recovered(self):
        values, _ = self._get('_DKPRValueType')
        self.assertEqual(values, {0: 'INTEGER', 1: 'DOUBLE', 2: 'STRING', 3: 'BLOB', 4: 'DATE'})

    def test_long_body_closes_on_its_own_exit(self):
        _, truncated = self._get('AWDProactiveAppPredictionSubscores')
        self.assertFalse(truncated)


if __name__ == '__main__':
    unittest.main()
