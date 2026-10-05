"""
Tests for ``_dictionaryRepresentation:`` switch-table enum recovery (Gap 2).

Some Apple proto enums have no ``xAsString:``/``StringAsX:`` companion selector
(e.g. ``GEOComponentType`` / ``ComponentStatus`` on ``GEOPDComponent``).  Their
int→name map lives in the class's ``-[Class _dictionaryRepresentation:]`` method
as one LLVM switch per field.  ``_harvest_dictrep_enums`` disassembles that
method, locates each switch by the ivar offset it reads, and recovers the
per-value ``cfstring`` names.

Two layers are tested:

* **Synthetic** — the raw-word decoders (`_decode_ldr_reg_off`,
  `_longest_common_prefix`) that have no binary dependency.
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

from macho.arm64decode import _decode_ldr_reg_off
from proto.enums import _longest_common_prefix
from tests.conftest import WordCtx as _WordCtx
from macho.disasm import disasm


# ══════════════════════════════════════════════════════════════════════════════
# Synthetic decoder tests (no binary needed)
# ══════════════════════════════════════════════════════════════════════════════

class TestDictRepBiasHelpers(unittest.TestCase):
    """TODO #54: the dictRep off-by-bias fix.  A biased (e.g. 1-based) enum
    re-bases the value into the table-index register with ``sub w<idx>,w<val>,#N``
    before the pointer-table read; the harvester adds ``N`` back.  Both guards are
    exercised here so the window-bleed false positive (#54's ``spellerRankerModelType``)
    stays fixed without a live cache."""

    @staticmethod
    def _ins(words, base=0x1000):
        from types import SimpleNamespace
        insns = [SimpleNamespace(addr=base + 4 * k) for k in range(len(words))]
        wmap = {insns[k].addr: words[k] for k in range(len(words))}
        return insns, wmap

    # proven encodings (rd in low 5 bits, imm in [21:10], shift in [23:22])
    SUB_W8_W1_1 = 0x51000428   # sub w8, w1, #1   (bias 1, dest w8)
    SUB_W9_W1_1 = 0x51000429   # sub w9, w1, #1   (bias 1, dest w9 — a NEIGHBOUR)
    SUB_W8_W1_2 = 0x51000828   # sub w8, w1, #2   (bias 2, dest w8)
    SUB_W8_LSL12 = 0x51400428  # sub w8, w1, #1, lsl #12  (shifted — not a small bias)
    NOP = 0xD503201F

    def test_bias_recovered_when_dest_is_index_reg(self):
        from proto.enums import _sub_imm_bias
        insns, words = self._ins([self.NOP, self.SUB_W8_W1_1, self.NOP])
        self.assertEqual(_sub_imm_bias(insns, words, 0, len(insns), dest_reg=8), 1)

    def test_window_bleed_rejected_when_dest_is_other_reg(self):
        # The neighbour's `sub w9,...` must NOT bias a table indexed by w8.
        from proto.enums import _sub_imm_bias
        insns, words = self._ins([self.SUB_W9_W1_1, self.NOP])
        self.assertEqual(_sub_imm_bias(insns, words, 0, len(insns), dest_reg=8), 0)

    def test_shifted_sub_is_not_a_small_bias(self):
        from proto.enums import _sub_imm_bias
        insns, words = self._ins([self.SUB_W8_LSL12])
        self.assertEqual(_sub_imm_bias(insns, words, 0, len(insns), dest_reg=8), 0)

    def test_last_match_wins(self):
        from proto.enums import _sub_imm_bias
        insns, words = self._ins([self.SUB_W8_W1_1, self.NOP, self.SUB_W8_W1_2])
        self.assertEqual(_sub_imm_bias(insns, words, 0, len(insns), dest_reg=8), 2)

    def test_no_sub_returns_zero(self):
        from proto.enums import _sub_imm_bias
        insns, words = self._ins([self.NOP, self.NOP])
        self.assertEqual(_sub_imm_bias(insns, words, 0, len(insns), dest_reg=8), 0)


class TestFieldRoutesThroughXAsString(unittest.TestCase):
    """The dictRep→xAsString discriminator: a field with an ``xAsString:``/
    ``StringAsX:`` selector has its bias handled by the xAsString path, so the
    dictRep harvester must NOT re-bias it (else double-/mis-bias)."""

    class _FakeCls:
        def __init__(self, sels):
            self._sels = set(sels)
        def get_method(self, sel):
            return object() if sel in self._sels else None

    class _FakeSt:
        def __init__(self, sels):
            self._sels = set(sels)
        def find(self, sel):
            return 1 if sel in self._sels else 0

    def test_method_list_hit(self):
        from proto.enums import _field_routes_through_xasstring
        cls = self._FakeCls({'relationshipAsString:'})
        self.assertTrue(_field_routes_through_xasstring(cls, self._FakeSt(set()),
                                                        '_relationship'))

    def test_stringas_form_hit(self):
        from proto.enums import _field_routes_through_xasstring
        cls = self._FakeCls({'StringAsResultStatus:'})
        self.assertTrue(_field_routes_through_xasstring(cls, self._FakeSt(set()),
                                                        '_resultStatus'))

    def test_selector_pool_fallback(self):
        # cache-native: method not name-resolved, selector still in __objc_methname.
        from proto.enums import _field_routes_through_xasstring
        cls = self._FakeCls(set())
        st = self._FakeSt({'laneClosureTypeAsString:'})
        self.assertTrue(_field_routes_through_xasstring(cls, st, '_laneClosureType'))

    def test_dictrep_only_field_is_not_routed(self):
        # Only covers the trivial default-False branch (no method-list hit, no
        # selector-pool hit) of _field_routes_through_xasstring; the three True-
        # case siblings above (same class) are what actually catch a revert of
        # this detector.
        from proto.enums import _field_routes_through_xasstring
        cls = self._FakeCls(set())
        self.assertFalse(_field_routes_through_xasstring(cls, self._FakeSt(set()),
                                                         '_tagSource'))


# ══════════════════════════════════════════════════════════════════════════════
# Synthetic decoder tests (no binary needed)
# ══════════════════════════════════════════════════════════════════════════════

class TestDecodeLdrRegOff(unittest.TestCase):
    """Decode of the integer register-offset load used by the jump tables."""

    def test_ldrh_table_load(self):
        # 0x7868792b = `ldrh w11, [x9, x8, lsl #1]` (16-bit jump table read)
        self.assertEqual(_decode_ldr_reg_off(0x7868792b), (2, 9, 8, 11))

    def test_ldr_word_ivar_load(self):
        # 0xb8686aa8 = `ldr w8, [x21, x8]` (32-bit ivar value load)
        self.assertEqual(_decode_ldr_reg_off(0xb8686aa8), (4, 21, 8, 8))

    def test_ldr_doubleword_pointer_table_load(self):
        # 0xf8687936 = `ldr x22, [x9, x8, lsl #3]` (8-byte pointer-table read)
        self.assertEqual(_decode_ldr_reg_off(0xf8687936), (8, 9, 8, 22))

    def test_entry_size_from_size_field(self):
        # entry_size is 1<<size: byte (size=00) → 1, half (size=01) → 2.
        esz, _rn, _rm, _rt = _decode_ldr_reg_off(0x7868792b)
        self.assertEqual(esz, 2)

    def test_non_load_returns_none(self):
        self.assertIsNone(_decode_ldr_reg_off(0xd61f0000))   # br x0
        self.assertIsNone(_decode_ldr_reg_off(0x91000021))   # add x1, x1, #0
        self.assertIsNone(_decode_ldr_reg_off(0x00000000))


class TestLongestCommonPrefix(unittest.TestCase):
    def test_common(self):
        self.assertEqual(
            _longest_common_prefix(
                ['COMPONENT_TYPE_ENTITY', 'COMPONENT_TYPE_PLACE_INFO']),
            'COMPONENT_TYPE_')

    def test_no_common(self):
        self.assertEqual(_longest_common_prefix(['STATUS_FAILED', 'INVALID']), '')

    def test_single(self):
        self.assertEqual(_longest_common_prefix(['ABC']), 'ABC')

    def test_empty(self):
        self.assertEqual(_longest_common_prefix([]), '')


class TestHarvestDictrepEnumsCompareChain(unittest.TestCase):
    """``_harvest_dictrep_enums``'s third pass recovers an enum's int->name map
    from an inlined BINARY-SEARCH TREE of `cmp`/range-branch comparisons inside
    `dictionaryRepresentation`, on a newer toolchain that has no separate
    `xAsString:` method and no `_dictionaryRepresentation:` jump table either
    (both already handled) for this field.

    Regression test for the compare-chain harvester (commit 9d07d15): built
    from real, capstone-verified instruction words modelling the exact shape
    found on GEOBatchPlaceResult.statusCode -- a has-bits `tbz` gate, the
    field's own `adrp+ldrsw` ivar-offset lookup, a `cbz` for value 0, and a
    `cmp+b.ne` for value 1, bounded by the first `bl` (the chain itself proven
    to contain none)."""

    BASE = 0x1000
    IVAR_OFFSET_TABLE = 0x5040   # holds the field's own ivar byte offset (16)
    IVAR_OFFSET = 16
    STR0_ADDR = 0x6080           # direct C-string address for value 0's name
    STR1_ADDR = 0x7010           # direct C-string address for value 1's name

    # Hand-built, capstone-verified (see commit 9d07d15's dev notes): a
    # has-bits gate, this field's own adrp+ldrsw ivar-offset lookup, a `cbz`
    # leaf for value 0, a `cmp+b.ne` leaf for value 1, then a `bl` (unrelated
    # merge-point helper -- must NOT be reached by the harvester) and `ret`.
    WORDS = [
        0x360001a0,   # tbz  w0, #0, #0x1034            (has-bits gate)
        0x90000028,   # adrp x8, #0x5000
        0xb9804108,   # ldrsw x8, [x8, #0x40]            -> IVAR_OFFSET_TABLE
        0x340000c1,   # cbz  w1, #0x1024                 (value 0 -> label0)
        0x7100043f,   # cmp  w1, #1
        0x540000e1,   # b.ne #0x1030                     (value 1 falls through)
        0xd0000020,   # adrp x0, #0x7000                 (value 1's string)
        0x91004000,   # add  x0, x0, #0x10               -> STR1_ADDR
        0x14000005,   # b    #0x1034
        0xb0000020,   # adrp x0, #0x6000                 (value 0's string, label0)
        0x91020000,   # add  x0, x0, #0x80               -> STR0_ADDR
        0x14000002,   # b    #0x1034
        0x94000000,   # bl   #0x1030 (self)              -- chain must stop here
        0xd65f03c0,   # ret
    ]

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
                return TestHarvestDictrepEnumsCompareChain._FakeMethod(self._dictrep_imp)
            return None

    def _build_ctx(self):
        ctx = _WordCtx(self.BASE, self.WORDS)
        ctx._m[self.IVAR_OFFSET_TABLE] = self.IVAR_OFFSET
        ctx._strings = {
            self.STR0_ADDR: 'MY_VALUE_ZERO',
            self.STR1_ADDR: 'MY_VALUE_ONE',
        }
        return ctx

    def test_recovers_both_values_from_the_compare_chain(self):
        from proto.enums import _harvest_dictrep_enums
        ctx = self._build_ctx()
        cls = self._FakeCls(self.BASE, [self._FakeIvar('_myField', self.IVAR_OFFSET)])
        result = _harvest_dictrep_enums(ctx, cls, None)
        self.assertEqual(result, {
            self.IVAR_OFFSET: [(0, 'MY_VALUE_ZERO'), (1, 'MY_VALUE_ONE')],
        })

    def test_not_attributed_to_an_unrelated_ivar_offset(self):
        # If the field's REAL offset isn't in the class's own ivar list (e.g.
        # the class under test doesn't actually declare this field), the
        # chain must not be attributed to it -- valid_offsets is exactly
        # cls.ivars's own offsets.
        from proto.enums import _harvest_dictrep_enums
        ctx = self._build_ctx()
        cls = self._FakeCls(self.BASE, [self._FakeIvar('_otherField', 999)])
        result = _harvest_dictrep_enums(ctx, cls, None)
        self.assertEqual(result, {})


class TestHarvestDictrepEnumsOutOfLineChains(unittest.TestCase):
    """_harvest_dictrep_enums's compare-chain pass must attribute each chain
    to ITS OWN field even when the compiler lays the gated blocks out of line.

    Regression test for the ivar-lookup anchor (found by the compiled f24
    fixture; the earlier has-bits-gate anchor lost the first field's chain
    here).  The shape is the one clang emits for a dictionaryRepresentation
    with several gated fields: the has-bits byte is loaded ONCE, a tbnz
    cascade branches on each field's bit straight to that field's block, and
    those blocks sit AFTER the epilogue -- so a chain is not adjacent to (nor
    after) its own gate in linear order.  Field A (statusCode, values 1/5/60)
    is a cmp+b.eq chain, field B (mode, values 0/1) a cbz-0 + cmp
    chain, and count is a plain int with an ivar-offset lookup but no
    compares at all (must not become an enum).  The epilogue is a TAIL branch,
    as in the real code, so a linear scan carries on into the out-of-line
    blocks.  Every word is capstone-verified; the trailing comment on each is
    its disassembly."""

    BASE = 0x1000
    # ivar-offset slots (the data words the adrp+ldrsw lookups read):
    SLOT_FLAGS, SLOT_STATUS, SLOT_MODE, SLOT_COUNT = 0x5010, 0x5020, 0x5024, 0x5028
    OFF_FLAGS, OFF_STATUS, OFF_MODE, OFF_COUNT = 8, 16, 20, 24
    STRINGS = {
        0x6040: 'TEST_STATUS_FAILED', 0x6080: 'TEST_STATUS_INVALID',
        0x60c0: 'TEST_STATUS_MISMATCH',
        0x7000: 'TEST_MODE_OFF', 0x7040: 'TEST_MODE_ON',
    }

    WORDS = [
    0x90000036,   # 0x1000 top      adrp x22, #0x5000
    0xb98012c8,   # 0x1004          ldrsw x8, [x22, #0x10]
    0x38686a68,   # 0x1008          ldrb w8, [x19, x8]
    0x370000e8,   # 0x100c          tbnz w8, #0, #0x1028
    0x37080368,   # 0x1010          tbnz w8, #1, #0x107c
    0x90000028,   # 0x1014 cnt      adrp x8, #0x5000
    0xb9802908,   # 0x1018          ldrsw x8, [x8, #0x28]
    0xb9400262,   # 0x101c          ldr w2, [x19]
    0x94000026,   # 0x1020          bl #0x10b8
    0x14000025,   # 0x1024 ret      b #0x10b8
    0x90000028,   # 0x1028 chainA   adrp x8, #0x5000
    0xb9802108,   # 0x102c          ldrsw x8, [x8, #0x20]
    0xb8686a68,   # 0x1030          ldr w8, [x19, x8]
    0x7100051f,   # 0x1034          cmp w8, #1
    0x54000100,   # 0x1038          b.eq #0x1058
    0x7100f11f,   # 0x103c          cmp w8, #0x3c
    0x54000120,   # 0x1040          b.eq #0x1064
    0x7100151f,   # 0x1044          cmp w8, #5
    0x54000141,   # 0x1048          b.ne #0x1070
    0xb0000035,   # 0x104c leaf5    adrp x21, #0x6000
    0x910202b5,   # 0x1050          add x21, x21, #0x80
    0x14000008,   # 0x1054          b #0x1074
    0xb0000035,   # 0x1058 leaf1    adrp x21, #0x6000
    0x910102b5,   # 0x105c          add x21, x21, #0x40
    0x14000005,   # 0x1060          b #0x1074
    0xb0000035,   # 0x1064 leaf60   adrp x21, #0x6000
    0x910302b5,   # 0x1068          add x21, x21, #0xc0
    0x14000002,   # 0x106c          b #0x1074
    0x94000012,   # 0x1070 dflt     bl #0x10b8
    0x94000011,   # 0x1074 merge    bl #0x10b8
    0x17ffffeb,   # 0x1078          b #0x1024
    0x90000028,   # 0x107c chainB   adrp x8, #0x5000
    0xb9802508,   # 0x1080          ldrsw x8, [x8, #0x24]
    0xb8686a68,   # 0x1084          ldr w8, [x19, x8]
    0x340000c8,   # 0x1088          cbz w8, #0x10a0
    0x7100051f,   # 0x108c          cmp w8, #1
    0x540000e1,   # 0x1090          b.ne #0x10ac
    0xd0000035,   # 0x1094 m1       adrp x21, #0x7000
    0x910102b5,   # 0x1098          add x21, x21, #0x40
    0x14000005,   # 0x109c          b #0x10b0
    0xd0000035,   # 0x10a0 m0       adrp x21, #0x7000
    0x910002b5,   # 0x10a4          add x21, x21, #0
    0x14000002,   # 0x10a8          b #0x10b0
    0x94000003,   # 0x10ac mdflt    bl #0x10b8
    0x94000002,   # 0x10b0 mmerge   bl #0x10b8
    0x17ffffdc,   # 0x10b4          b #0x1024
    0xd65f03c0,   # 0x10b8 helper   ret 
    ]

    def _ctx(self):
        ctx = _WordCtx(self.BASE, self.WORDS)
        ctx._m[self.SLOT_FLAGS] = self.OFF_FLAGS
        ctx._m[self.SLOT_STATUS] = self.OFF_STATUS
        ctx._m[self.SLOT_MODE] = self.OFF_MODE
        ctx._m[self.SLOT_COUNT] = self.OFF_COUNT
        ctx._strings = dict(self.STRINGS)
        return ctx

    def _cls(self):
        Ivar = TestHarvestDictrepEnumsCompareChain._FakeIvar
        return TestHarvestDictrepEnumsCompareChain._FakeCls(self.BASE, [
            Ivar('_has', self.OFF_FLAGS), Ivar('_statusCode', self.OFF_STATUS),
            Ivar('_mode', self.OFF_MODE), Ivar('_count', self.OFF_COUNT)])

    def test_each_out_of_line_chain_goes_to_its_own_field(self):
        from proto.enums import _harvest_dictrep_enums
        result = _harvest_dictrep_enums(self._ctx(), self._cls(), None)
        self.assertEqual(result, {
            self.OFF_STATUS: [(1, 'TEST_STATUS_FAILED'),
                              (5, 'TEST_STATUS_INVALID'),
                              (60, 'TEST_STATUS_MISMATCH')],
            self.OFF_MODE: [(0, 'TEST_MODE_OFF'), (1, 'TEST_MODE_ON')],
        })

    def test_plain_int_field_in_the_same_function_is_not_an_enum(self):
        from proto.enums import _harvest_dictrep_enums
        result = _harvest_dictrep_enums(self._ctx(), self._cls(), None)
        self.assertNotIn(self.OFF_COUNT, result)
        self.assertNotIn(self.OFF_FLAGS, result)

    def test_ivar_offset_lookups_in_instruction_order(self):
        """Every adrp+ldrsw ivar-offset lookup, in order — including the
        has-bits one, whose page register (x22) is loaded once at the top and
        reused, and the two out-of-line ones that come after the epilogue."""
        from proto.enums import _ivar_offset_lookups
        ctx = self._ctx()
        insns = disasm(ctx, self.BASE, max_insns=200, stop_at_ret=False)
        got = [(insns[i].addr, off) for i, off in _ivar_offset_lookups(ctx, insns)]
        self.assertEqual(got, [
            (0x1004, self.OFF_FLAGS),    # has-bits, via the hoisted adrp x22
            (0x1018, self.OFF_COUNT),    # inline block
            (0x102c, self.OFF_STATUS),   # out of line (after the epilogue)
            (0x1080, self.OFF_MODE),     # out of line
        ])


class TestDirectBranchTarget(unittest.TestCase):
    """TODO #40: _direct_branch_target extracts the PC-relative target of a DIRECT
    branch and returns None for calls (bl/blr) and indirect jumps (br), so a tail
    call or jump-table dispatch never extends the function extent."""

    def _t(self, mnemonic, op_str):
        from proto.enums import _direct_branch_target
        from types import SimpleNamespace
        return _direct_branch_target(SimpleNamespace(mnemonic=mnemonic, op_str=op_str))

    def test_b_and_cond(self):
        self.assertEqual(self._t('b', '#0x18d001000'), 0x18d001000)
        self.assertEqual(self._t('b.eq', '#0x2000'), 0x2000)
        self.assertEqual(self._t('b.hi', '#0x2abc'), 0x2abc)

    def test_compare_and_test_branches(self):
        self.assertEqual(self._t('cbz', 'w8, #0x3000'), 0x3000)
        self.assertEqual(self._t('cbnz', 'x0, #0x3010'), 0x3010)
        self.assertEqual(self._t('tbz', 'w8, #5, #0x4000'), 0x4000)   # target is LAST tok
        self.assertEqual(self._t('tbnz', 'x9, #0x3f, #0x4010'), 0x4010)

    def test_calls_and_indirect_are_none(self):
        self.assertIsNone(self._t('bl', '#0x5000'))   # call — not a body branch
        self.assertIsNone(self._t('blr', 'x8'))
        self.assertIsNone(self._t('br', 'x8'))        # indirect jump-table dispatch
        self.assertIsNone(self._t('add', 'x0, x1, #0x10'))
        self.assertIsNone(self._t('ret', ''))


# ══════════════════════════════════════════════════════════════════════════════
# Live tests against the real GeoServices cache
# ══════════════════════════════════════════════════════════════════════════════

def _find_cache_main():
    _here = os.path.dirname(os.path.abspath(__file__))
    _root = os.path.dirname(os.path.dirname(_here))
    cache_dir = os.environ.get('MACHO_TEST_CACHE', '').strip()
    for d in ([cache_dir] if cache_dir else []) + [artifacts.cache_dir()]:
        for name in ('dyld_shared_cache_arm64e', 'dyld_shared_cache_arm64'):
            p = os.path.join(d, name)
            if os.path.isfile(p):
                return p
    return None


_CACHE_MAIN = _find_cache_main()
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
        from proto.enums import _harvest_dictrep_enums

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
        cls.harvest = _harvest_dictrep_enums(ctx, comp, st) if comp else {}
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
        from proto.enums import _harvest_dictrep_enums
        target = next((c for c in self.clist
                       if c.name == 'GEOPDSearchQueryIntentMetadata'
                       and not c.is_meta), None)
        if target is None:
            self.skipTest('GEOPDSearchQueryIntentMetadata not in this cache')
        self.ctx._dictrep_truncated_classes = None
        _harvest_dictrep_enums(self.ctx, target, self.st)
        self.assertNotIn('GEOPDSearchQueryIntentMetadata',
                         self.ctx._dictrep_truncated_classes or set())

    def _harvest_field(self, class_name, field_name):
        """{value: name} for class_name.field_name's dictRep enum, or None."""
        from proto.protocore import _proto_name
        from proto.enums import _harvest_dictrep_enums
        cls = next((c for c in self.clist
                    if c.name == class_name and not c.is_meta), None)
        if cls is None:
            return None
        off = next((iv.offset for iv in cls.ivars
                    if iv.name and _proto_name(iv.name) == field_name), None)
        if off is None:
            return None
        return dict(_harvest_dictrep_enums(self.ctx, cls, self.st).get(off, []))

    def test_pointer_table_1based_enums_biased(self):
        """TODO #54: the 3 Hopper-confirmed 1-based dictRep-only enums (pointer-table
        idiom) recover their real values, not the 0-based raw table index."""
        # _harvest_dictrep_enums returns the RAW value-string names; the emitter
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

    def test_xasstring_routed_field_not_rebiased(self):
        """A field WITH an xAsString: selector keeps its bias handled by that path —
        the dictRep harvester must not shift it (guards the resultStatus/laneClosureType
        false positives the unconditional bias produced)."""
        d = self._harvest_field('GEOTFIncident', 'laneClosureType')
        if not d:
            self.skipTest('GEOTFIncident.laneClosureType dictRep enum not recovered')
        # left at the raw 0-based table index (xAsString path owns any real bias).
        self.assertIn(0, d, 'xAsString-routed field was wrongly re-biased off 0')

    def test_function_body_extent_closes_on_terminal(self):
        """The extent finder returns a contiguous body ending in a terminal (the
        function's own `ret`), well under the hard-cap, for the overrunning classes."""
        from proto.enums import _function_body_extent, _DICTREP_HARD_CAP, _TERMINAL_MNEMONICS
        names = ('GEOPDSearchQueryIntentMetadata', 'GEOAnalyticsPipelineStateData',
                 'GEOLogMsgStateCuratedCollection')
        seen = 0
        for cls in self.clist:
            if cls.is_meta or cls.name not in names:
                continue
            m = cls.get_method('_dictionaryRepresentation:')
            if m is None or m.imp == 0:
                continue
            body = _function_body_extent(self.ctx, m.imp, _DICTREP_HARD_CAP)
            self.assertTrue(body, f'{cls.name}: empty extent')
            self.assertIn(body[-1].mnemonic, _TERMINAL_MNEMONICS,
                          f'{cls.name}: extent did not close on a terminal')
            self.assertLess(len(body), _DICTREP_HARD_CAP,
                            f'{cls.name}: body hit the safety ceiling')
            seen += 1
        if seen == 0:
            self.skipTest('overrunning classes not in this cache')


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
    ``ldrh w11, [x9, x8, lsl #1]``).  ``_extract_jumptable_enum_values`` formerly
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
        cls.pairs = (_extract_enum_values(ctx, imp, st)[0] if imp else None)
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
        cls.d = dict(_extract_enum_values(ctx, imp, st)[0]) if imp else None

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
    idiom (`mov w8,#-50000; add w8,w2,w8; cmp w8,#3`); _leading_materialized_bias
    now models it, so the 50000-base values ARE recovered and the enum is no longer
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
            log_pairs, _, cls.log_trunc = _extract_enum_values(ctx, i_log, st)
            cls.log_vals = {v for v, _ in log_pairs}
            cls.tile_trunc = _extract_enum_values(ctx, i_tile, st)[2]
            telem_pairs, _, cls.telem_trunc = _extract_enum_values(ctx, i_telem, st)
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
        # materialised (mov #-K; add) rather than a literal `sub #imm12`.  Idiom B's
        # branch_gates now apply _leading_materialized_bias (mirroring Idiom A), so
        # those segments (52020-base and 60500-base) ARE recovered and the enum is
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

    The LogMsg-family methods are ~12k instructions, so the cheap 1000-insn probe
    runs out of budget before their `ret` — but every enum value lives in the first
    ~1000 insns.  The function-extent fallback recomputes the contiguous body and
    closes on the method's own `ret`, so `_disasm_truncated` no longer false-flags
    these enums.  Ground truth: `-[GEOLogMsgEventUserAction userActionEventActionAsString:]`
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
                pairs, _conf, trunc = _extract_enum_values(ctx, imp, st)
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


if __name__ == '__main__':
    unittest.main()
