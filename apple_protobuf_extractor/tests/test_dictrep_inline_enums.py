"""
Enums whose number->name map is INLINED into -_dictionaryRepresentation: (no xAsString:/
StringAsX: converter method), recovered by proto/dictrep_flow.py.

The recovery used to read the function through look-back windows and missed nearly all
*repeated* enums and several scalar ones (37 ObjC-class fields of the "more specific than the
Extractor schema" list of the private repo's descriptor-recovery eval).  It is now data-flow: the field is found by use-def chain from the
ivar-offset slot, candidate values come from the comparisons the value takes part in, and
each is driven through the CFG to the name that reaches the dictionary call.  Covered here:

* synthetic code (assembled by tests/_a64asm.py, encodings checked against capstone):
  a repeated field's pointer-table loop with every constant HOISTED out of the loop; a
  biased multi-segment sparse switch with a hoisted value-0 name; 1-based tables; a
  single-valued enum; plain ints that must stay ints;
* the real iPhone 8 GeoServices image: all 37 fields with names and numbers, the negatives
  (labelType, operatingHoursCount), and the extracted schema.

Each live row is (class, field, n_values, first, middle, last) with (number, raw CFString
name); the numbers were cross-checked against the Claude/Codex enum definitions that exist
for these fields (every field with one agrees on every number).
"""
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

from macho.disasm import disasm
from proto.dictrep_flow import Flow, UNKNOWN_ENUM_FORMAT
from tests._a64asm import assemble, FlowCtx
from tests.test_dictrep_enums import _CACHE_MAIN, _SKIP_MSG, _FakeCls, _FakeIvar


class TestAssemblerMatchesCapstone(unittest.TestCase):
    """The fixtures are only as good as the assembler: every instruction it emits must decode
    (capstone, via macho.disasm) to the mnemonic and registers it was written with."""

    LINES = [
        'adrp x8, #0x5000', 'add x8, x8, #0x40', 'sub w9, w8, #0x23', 'ldrsw x8, [x8, #0x40]',
        'ldr w8, [x19, x8]', 'ldrb w11, [x26, x9]', 'ldr x24, [x28, x8, lsl #3]',
        'ldr x23, [x26, w9, sxtw #3]', 'ldrsw x8, [x8, x27, lsl #2]', 'ldr x9, [x8, #8]',
        'ldr w2, [x19]', 'cmp w8, #4', 'cmp x27, x9', 'b.hs L', 'b.ne L', 'cbz w1, L',
        'tbnz w8, #1, L', 'b L', 'bl L', 'mov x24, x28', 'mov x28, #0', 'adr x10, L',
        'add x10, x10, x11, lsl #2', 'br x10', 'nop', 'lsr w9, w9, w8', 'mov w9, #-50000',
        'sub w9, w8, w10', 'add w9, w8, w10', 'eor x16, x30, x30, lsl #1', 'brk #0xc471', 'ret', 'L:', 'ret',
    ]

    def test_every_form_round_trips(self):
        base = 0x1000
        words, labels = assemble(base, self.LINES)
        code = [ln for ln in self.LINES if not ln.endswith(':')]
        ctx = FlowCtx(base, words)
        insns = disasm(ctx, base, max_insns=len(words), stop_at_ret=False)
        self.assertEqual(len(insns), len(code))
        for ins, ln in zip(insns, code):
            mn = ln.split()[0]
            self.assertEqual(ins.mnemonic, mn, ln)
            regs = lambda t: re.findall(r'\b[xw]\d+\b', t.split(';')[0])
            self.assertEqual(regs(ins.op_str), regs(ln.partition(' ')[2]), ln)
        # label-resolved branch / adr targets
        by = {i.addr: i for i in insns}
        self.assertIn(f'#{labels["L"]:#x}', by[base + 4 * 13].op_str)       # b.hs L


def _enum_ctx(code, *, strings=None, slots=None, ptrs=None, tables=None, base=0x1000):
    words, labels = assemble(base, code)
    ctx = FlowCtx(base, words)
    for addr, v in (slots or {}).items():
        ctx._m[addr] = v
    for addr, v in (ptrs or {}).items():
        ctx.put_ptr(addr, v)
    for addr, data in (tables or {}).items():
        ctx.put_bytes(addr, data)
    ctx._strings = dict(strings or {})
    return ctx, labels


def _harvest(ctx, base, ivars):
    from proto.enums import _harvest_dictrep_enums
    return _harvest_dictrep_enums(
        ctx, _FakeCls(base, [_FakeIvar(n, o) for n, o in ivars]), None)


# CFString / table addresses used by the synthetic code below
UNK = 0x8020


class TestRepeatedFieldPointerTableLoop(unittest.TestCase):
    """The shape that defeated the look-back windows: a repeated field walks its array; the
    ivar-offset page register, the pointer-table base and the "(unknown: %i)" format are all
    hoisted out of the loop; the element is loaded through a container deref; and the field
    before it left ITS dictionary key in the same scratch register as the table base."""

    CODE = [
        # previous (scalar) field: its key goes through x9 -- the register the table uses later
        'adrp x9, #0x7000', 'add x9, x9, #0x740', 'mov x3, x9',
        'adrp x26, #0x5000', 'ldrsw x8, [x26, #0x40]', 'add x8, x21, x8', 'ldr x9, [x8, #8]',
        'cbz x9, done', 'mov x27, #0',
        'adrp x28, #0x6000', 'add x28, x28, #0x100',          # table base, hoisted
        'adrp x23, #0x8000', 'add x23, x23, #0x20',           # "(unknown: %i)", hoisted
        'loop:',
        'ldr x8, [x8]', 'ldrsw x8, [x8, x27, lsl #2]',        # array data, element
        'cmp w8, #4', 'b.hs unk', 'ldr x24, [x28, x8, lsl #3]', 'b merge',
        'unk:', 'mov x2, x23', 'bl helper', 'mov x24, x0',
        'merge:', 'mov x2, x24', 'bl helper',
        'add x27, x27, #1', 'ldrsw x8, [x26, #0x40]', 'add x8, x21, x8', 'ldr x9, [x8, #8]',
        'cmp x27, x9', 'b.lo loop',
        'done:', 'b helper', 'helper:', 'ret',
    ]
    NAMES = {0x9000: 'LINK_UNKNOWN', 0x9020: 'LINK_QUICK', 0x9040: 'LINK_CLIP', 0x9060: 'LINK_EXT'}

    def _ctx(self):
        return _enum_ctx(self.CODE, strings={**self.NAMES, UNK: UNKNOWN_ENUM_FORMAT},
                         slots={0x5040: 16},
                         ptrs={0x6100 + 8 * i: a for i, a in enumerate(sorted(self.NAMES))})[0]

    def test_repeated_enum_recovered_with_numbers_from_the_table_index(self):
        r = _harvest(self._ctx(), 0x1000, [('_linkTypes', 16)])
        self.assertEqual(r, {16: [(0, 'LINK_UNKNOWN'), (1, 'LINK_QUICK'),
                                  (2, 'LINK_CLIP'), (3, 'LINK_EXT')]})

    def test_field_is_attributed_by_use_def_chain_through_the_container_deref(self):
        ctx = self._ctx()
        insns = disasm(ctx, 0x1000, max_insns=200, stop_at_ret=False)
        flow = Flow(ctx, insns)
        offs = {insns[k].addr: off for k, off in flow.value_loads()}
        self.assertEqual(set(offs.values()), {16})
        element = next(i for i in insns if i.mnemonic == 'ldrsw' and 'x27' in i.op_str)
        self.assertIn(element.addr, offs)

    def test_hoisted_table_base_is_not_the_neighbouring_fields_key(self):
        ctx = self._ctx()
        insns = disasm(ctx, 0x1000, max_insns=200, stop_at_ret=False)
        flow = Flow(ctx, insns)
        ldr = next(k for k, i in enumerate(insns) if i.mnemonic == 'ldr' and 'x28, x8' in i.op_str)
        self.assertEqual(flow.const_before(ldr, 'x28'), 0x6100)
        # x9 holds the neighbour's key (adrp+add at the top) -- a definition reaches here too
        self.assertEqual(flow.const_before(ldr, 'x9'), None)


class TestBiasedMultiSegmentSwitch(unittest.TestCase):
    """A sparse enum compiled as value 0 (cbz) + a jump table indexed by ``value - 35`` + an
    isolated compare (16); the value-0 name is hoisted into a register.  One value load, three
    dispatch sites: the numbers are the wire values and no segment hides another."""

    CODE = [
        'adrp x25, #0x5000', 'ldrsw x8, [x25, #0x40]', 'ldr w8, [x21, x8]',
        'adrp x28, #0x6000', 'add x28, x28, #0x200',           # value 0's name, hoisted
        'adrp x26, #0x6000', 'add x26, x26, #0x400',            # byte index table
        'cbz w8, zero',
        'sub w9, w8, #0x23', 'cmp w9, #2', 'b.hi seg2',
        'adr x10, cases', 'ldrb w11, [x26, x9]', 'add x10, x10, x11, lsl #2', 'br x10',
        'cases:',
        'adrp x24, #0x6000', 'add x24, x24, #0x300', 'b merge',      # 35
        'adrp x24, #0x6000', 'add x24, x24, #0x320', 'b merge',      # 36
        'adrp x24, #0x6000', 'add x24, x24, #0x340', 'b merge',      # 37
        'seg2:', 'cmp w8, #0x10', 'b.ne unk',
        'adrp x24, #0x6000', 'add x24, x24, #0x360', 'b merge',      # 16
        'zero:', 'mov x24, x28', 'b merge',
        'unk:', 'adrp x2, #0x8000', 'add x2, x2, #0x20', 'bl helper', 'mov x24, x0',
        'merge:', 'mov x2, x24', 'bl helper', 'b helper', 'helper:', 'ret',
    ]
    STR = {0x6200: 'UNKNOWN_KIND', 0x6300: 'KIND_A', 0x6320: 'KIND_B', 0x6340: 'KIND_C',
           0x6360: 'KIND_SIXTEEN', UNK: UNKNOWN_ENUM_FORMAT}

    def _ctx(self):
        return _enum_ctx(self.CODE, strings=self.STR, slots={0x5040: 24},
                         tables={0x6400: bytes([0, 3, 6])})[0]

    def test_numbers_are_wire_values_and_segments_are_merged(self):
        r = _harvest(self._ctx(), 0x1000, [('_kind', 24)])
        self.assertEqual(r, {24: [(0, 'UNKNOWN_KIND'), (16, 'KIND_SIXTEEN'), (35, 'KIND_A'),
                                  (36, 'KIND_B'), (37, 'KIND_C')]})

    def test_candidate_values_come_from_the_gate_interval_and_the_compares(self):
        ctx = self._ctx()
        insns = disasm(ctx, 0x1000, max_insns=200, stop_at_ret=False)
        flow = Flow(ctx, insns)
        (k, off), = [(k, o) for k, o in flow.value_loads()]
        self.assertEqual(sorted(flow.candidates(k, 'x8', 1 << 31).values), [0, 16, 35, 36, 37])


class TestScalarShapes(unittest.TestCase):

    BIASED = [
        'adrp x25, #0x5000', 'ldrsw x8, [x25, #0x40]', 'ldrsw x8, [x21, x8]',
        'adrp x28, #0x6000', 'add x28, x28, #0x100',
        'sub w9, w8, #1', 'cmp w9, #3', 'b.hs unk',
        'ldr x24, [x28, w9, sxtw #3]', 'b merge',
        'unk:', 'adrp x2, #0x8000', 'add x2, x2, #0x20', 'bl helper', 'mov x24, x0',
        'merge:', 'mov x2, x24', 'bl helper', 'b helper', 'helper:', 'ret',
    ]

    def test_one_based_pointer_table_yields_one_based_numbers(self):
        names = {0x9000: 'T300', 0x9020: 'T400', 0x9040: 'T392C'}
        ctx = _enum_ctx(self.BIASED, strings={**names, UNK: UNKNOWN_ENUM_FORMAT},
                        slots={0x5040: 16},
                        ptrs={0x6100 + 8 * i: a for i, a in enumerate(sorted(names))})[0]
        self.assertEqual(_harvest(ctx, 0x1000, [('_type', 16)]),
                         {16: [(1, 'T300'), (2, 'T400'), (3, 'T392C')]})

    def test_value_names_up_to_128_characters_are_read_in_full(self):
        # PLACECARD_ENRICHMENT_SUPPRESSION_REASON_APP_EXTENSION_UNAVAILABLE is 65 characters;
        # a 64-character read truncated it and the value was dropped.
        long_name = 'PLACECARD_ENRICHMENT_SUPPRESSION_REASON_APP_EXTENSION_UNAVAILABLE'
        self.assertEqual(len(long_name), 65)
        names = {0x9000: 'SHORT_A', 0x9020: long_name, 0x9040: 'SHORT_C'}
        ctx = _enum_ctx(self.BIASED, strings={**names, UNK: UNKNOWN_ENUM_FORMAT},
                        slots={0x5040: 16},
                        ptrs={0x6100 + 8 * i: a for i, a in enumerate(sorted(names))})[0]
        self.assertEqual(_harvest(ctx, 0x1000, [('_type', 16)]),
                         {16: [(1, 'SHORT_A'), (2, long_name), (3, 'SHORT_C')]})

    SINGLE = [
        'adrp x25, #0x5000', 'ldrsw x8, [x25, #0x40]', 'ldr w8, [x21, x8]',
        'cbz w8, zero', 'adrp x2, #0x8000', 'add x2, x2, #0x20', 'bl helper', 'mov x22, x0',
        'b merge', 'zero:', 'adrp x22, #0x6000', 'add x22, x22, #0x80',
        'merge:', 'mov x2, x22', 'bl helper', 'b helper', 'helper:', 'ret',
    ]

    def test_single_valued_enum_is_recognised_by_the_unknown_fallback(self):
        ctx = _enum_ctx(self.SINGLE, strings={0x6080: 'TYPE_GENERIC', UNK: UNKNOWN_ENUM_FORMAT},
                        slots={0x5040: 24})[0]
        self.assertEqual(_harvest(ctx, 0x1000, [('_type', 24)]),
                         {24: [(0, 'TYPE_GENERIC')]})

    PLAIN = [
        'adrp x25, #0x5000', 'ldrsw x8, [x25, #0x40]', 'ldr w2, [x21, x8]',
        'bl helper', 'mov x2, x0', 'bl helper', 'b helper', 'helper:', 'ret',
    ]

    def test_plain_int_through_nsnumber_is_not_an_enum(self):
        ctx = _enum_ctx(self.PLAIN, strings={UNK: UNKNOWN_ENUM_FORMAT}, slots={0x5040: 24})[0]
        self.assertEqual(_harvest(ctx, 0x1000, [('_count', 24)]), {})

    def test_a_single_name_that_does_not_vary_is_not_enough(self):
        # value 0 -> a name, every other value reaches an unrelated call: nothing shows the
        # string depends on the value (it could be any constant), so not an enum.
        code = [c for c in TestScalarShapes.SINGLE if not c.startswith(('adrp x2,', 'add x2, x2'))]
        ctx = _enum_ctx(code, strings={0x6080: 'TYPE_GENERIC'}, slots={0x5040: 24})[0]
        self.assertEqual(_harvest(ctx, 0x1000, [('_type', 24)]), {})

    def test_retained_name_in_x0_is_found_by_value_dependence(self):
        # older compilers hand the name to a retain call in x0 (not the dictionary call's x2)
        code = [
            'adrp x25, #0x5000', 'ldrsw x8, [x25, #0x40]', 'ldr w8, [x21, x8]',
            'sub w9, w8, #1', 'cmp w9, #2', 'b.hi skip',
            'adrp x8, #0x6000', 'add x8, x8, #0x40', 'ldr x0, [x8, w9, uxtw #3]',
            'bl helper', 'skip:', 'b helper', 'helper:', 'ret',
        ]
        names = {0x9000: 'A_ONE', 0x9020: 'A_TWO', 0x9040: 'A_THREE'}
        ctx = _enum_ctx(code, strings=names, slots={0x5040: 16},
                        ptrs={0x6040 + 8 * i: a for i, a in enumerate(sorted(names))})[0]
        self.assertEqual(_harvest(ctx, 0x1000, [('_type', 16)]),
                         {16: [(1, 'A_ONE'), (2, 'A_TWO'), (3, 'A_THREE')]})


class TestWhatCouldNotBeEvaluatedIsReported(unittest.TestCase):
    """An evaluation that cannot be completed must not turn into a quiet int32."""

    CHAIN = [
        'adrp x25, #0x5000', 'ldrsw x8, [x25, #0x40]', 'ldr w8, [x21, x8]',
        '{guard}',
        'cbz w8, zero', 'cmp w8, #1', 'b.eq one', 'cmp w8, #2', 'b.eq two',
        'adrp x2, #0x8000', 'add x2, x2, #0x20', 'bl helper', 'b end',
        'zero:', 'adrp x2, #0x6000', 'add x2, x2, #0x40', 'b merge',
        'one:', 'adrp x2, #0x6000', 'add x2, x2, #0x80', 'b merge',
        'two:', '{two_guard}', 'adrp x2, #0x6000', 'add x2, x2, #0xc0',
        'merge:', 'bl helper', 'end:', 'b helper', 'helper:', 'ret',
    ]
    NAMES = {0x6040: 'K_ZERO', 0x6080: 'K_ONE', 0x60c0: 'K_TWO', UNK: UNKNOWN_ENUM_FORMAT}

    def _flow(self, guard='nop', two_guard='nop'):
        code = [c.replace('{guard}', guard).replace('{two_guard}', two_guard) for c in self.CHAIN]
        ctx, _ = _enum_ctx(code, strings=self.NAMES, slots={0x5040: 24})
        insns = disasm(ctx, 0x1000, max_insns=200, stop_at_ret=False)
        return Flow(ctx, insns), ctx

    def test_one_value_that_cannot_be_evaluated_makes_the_enum_incomplete_not_absent(self):
        flow, _ = self._flow(two_guard='cbz x5, merge')          # x5: not tracked
        out = flow.enum_maps({24})
        self.assertEqual(out, {24: [(0, 'K_ZERO'), (1, 'K_ONE')]})
        self.assertIn('value 2', flow.incomplete[24])
        self.assertEqual(flow.unevaluated, {})

    def test_a_switch_nothing_could_be_evaluated_for_is_listed_as_unevaluated(self):
        flow, _ = self._flow(guard='cbz x5, merge')              # every path aborts
        out = flow.enum_maps({24})
        self.assertEqual(out, {})
        self.assertIn('untracked', flow.unevaluated[24])

    def test_harvest_reports_all_three_results(self):
        from proto.enums import _harvest_dictrep
        code = [c.replace('{guard}', 'nop').replace('{two_guard}', 'cbz x5, merge')
                for c in self.CHAIN]
        ctx, _ = _enum_ctx(code, strings=self.NAMES, slots={0x5040: 24})
        enums, incomplete, unevaluated = _harvest_dictrep(
            ctx, _FakeCls(0x1000, [_FakeIvar('_kind', 24)]), None)
        self.assertEqual(sorted(enums), [24])
        self.assertEqual(list(incomplete), [24])
        self.assertEqual(unevaluated, {})

    def test_clean_enum_is_not_flagged(self):
        flow, _ = self._flow()
        flow.enum_maps({24})
        self.assertEqual((flow.incomplete, flow.unevaluated), ({}, {}))


class TestBitmaskGatedTable(unittest.TestCase):
    """``mov w9,#mask; lsr w9,w9,w8; tbz w9,#0`` -- a table whose valid indices are the set
    bits of a constant (the evaluator follows ``tbz``/``tbnz`` on the shifted constant)."""

    CODE = [
        'adrp x25, #0x5000', 'ldrsw x8, [x25, #0x40]', 'ldr w8, [x21, x8]',
        'cmp w8, #2', 'b.hi unk',
        'mov w9, #5', 'lsr w9, w9, w8', 'tbz w9, #0, unk',
        'adrp x28, #0x6000', 'add x28, x28, #0x100',
        'ldr x2, [x28, x8, lsl #3]', 'bl helper', 'b end',
        'unk:', 'adrp x2, #0x8000', 'add x2, x2, #0x20', 'bl helper',
        'end:', 'b helper', 'helper:', 'ret',
    ]

    TBNZ_CODE = [
        'adrp x25, #0x5000', 'ldrsw x8, [x25, #0x40]', 'ldr w8, [x21, x8]',
        'cmp w8, #2', 'b.hi unk',
        'mov w9, #5', 'lsr w9, w9, w8', 'tbnz w9, #0, table', 'b unk',
        'table:', 'adrp x28, #0x6000', 'add x28, x28, #0x100',
        'ldr x2, [x28, x8, lsl #3]', 'bl helper', 'b end',
        'unk:', 'adrp x2, #0x8000', 'add x2, x2, #0x20', 'bl helper',
        'end:', 'b helper', 'helper:', 'ret',
    ]

    def test_the_branch_polarity_is_followed_not_assumed(self):
        # tbnz jumps to the table when the bit is SET: same values as the tbz form
        names = {0x9000: 'M_ZERO', 0x9020: 'M_ONE_UNUSED', 0x9040: 'M_TWO'}
        ctx, _ = _enum_ctx(self.TBNZ_CODE, strings={**names, UNK: UNKNOWN_ENUM_FORMAT},
                           slots={0x5040: 16},
                           ptrs={0x6100 + 8 * i: a for i, a in enumerate(sorted(names))})
        self.assertEqual(_harvest(ctx, 0x1000, [('_m', 16)]), {16: [(0, 'M_ZERO'), (2, 'M_TWO')]})

    def test_only_the_values_whose_mask_bit_is_set_are_named(self):
        names = {0x9000: 'M_ZERO', 0x9020: 'M_ONE_UNUSED', 0x9040: 'M_TWO'}
        ctx, _ = _enum_ctx(self.CODE, strings={**names, UNK: UNKNOWN_ENUM_FORMAT},
                           slots={0x5040: 16},
                           ptrs={0x6100 + 8 * i: a for i, a in enumerate(sorted(names))})
        self.assertEqual(_harvest(ctx, 0x1000, [('_m', 16)]), {16: [(0, 'M_ZERO'), (2, 'M_TWO')]})


class TestReachingDefinitions(unittest.TestCase):

    CODE = [
        'mov x8, #1', 'cbz x0, other', 'mov x8, #2', 'b join', 'other:', 'mov x9, #7',
        'join:', 'adrp x10, #0x5000', 'add x10, x10, #0x10', 'ret',
    ]

    def _flow(self):
        ctx, _ = _enum_ctx(self.CODE)
        insns = disasm(ctx, 0x1000, max_insns=50, stop_at_ret=False)
        return Flow(ctx, insns), insns

    def test_two_definitions_reach_a_join_so_the_register_is_not_constant(self):
        flow, insns = self._flow()
        join = next(k for k, i in enumerate(insns) if i.mnemonic == 'adrp')
        self.assertEqual(len(flow.defs_before(join, 'x8')), 2)
        self.assertIsNone(flow.const_before(join, 'x8'))

    def test_single_definition_is_a_constant(self):
        flow, insns = self._flow()
        ret = next(k for k, i in enumerate(insns) if i.mnemonic == 'ret')
        self.assertEqual(flow.const_before(ret, 'x10'), 0x5010)

    def test_function_entry_value_is_not_a_constant(self):
        flow, _ = self._flow()
        self.assertIsNone(flow.const_before(1, 'x0'))


# (class, field, n_values, first, middle, last) -- (number, raw value-name CFString)
EXPECTED = [
    ('GEOPDActionDataFilter', 'linkTypes', 4, (0, 'LINK_TYPE_UNKNOWN'), (2, 'LINK_TYPE_APP_CLIP'), (3, 'LINK_TYPE_EXTENSION')),
    ('GEOPDAutocompletePlaceContextMetadata', 'clientizationFeatures', 5, (0, 'CLIENTIZATION_FEATURE_UNKNOWN'), (2, 'CLIENTIZATION_FEATURE_IS_LANDMARK'), (4, 'CLIENTIZATION_FEATURE_SUMMARY_EXPERIENCE')),
    ('GEOPDBatchReverseGeocodingParameters', 'additionalPlaceTypes', 22, (0, 'UNKNOWN_PLACE_TYPE'), (48, 'ISLAND'), (65, 'PHYSICAL_FEATURE')),
    ('GEOPDCategorySearchParameters', 'supportedRelatedEntitySectionTypes', 2, (0, 'RELATED_ENTITY_SECTION_TYPE_UNKNOWN'), (1, 'RELATED_ENTITY_SECTION_TYPE_COLLECTION'), (1, 'RELATED_ENTITY_SECTION_TYPE_COLLECTION')),
    ('GEOPDCategorySearchParameters', 'supportedSearchTierTypes', 3, (0, 'SEARCH_TIER_METADATA_UNKNOWN'), (1, 'SEARCH_TIER_METADATA_PRIMARY'), (2, 'SEARCH_TIER_METADATA_AUXILIARY')),
    ('GEOPDCategorySearchParameters', 'knownRefinementTypes', 6, (0, 'RESULT_REFINEMENT_TYPE_UNKNOWN'), (3, 'RESULT_REFINEMENT_TYPE_MULTI_SELECT'), (5, 'RESULT_REFINEMENT_GUIDES_HOME')),
    ('GEOPDCategorySearchParameters', 'supportedPlaceSummaryFormatTypes', 5, (0, 'PLACE_SUMMARY_FORMAT_TYPE_UNKNOWN'), (2, 'PLACE_SUMMARY_FORMAT_TYPE_ITALICS'), (4, 'PLACE_SUMMARY_FORMAT_TYPE_TAPPABLE_ENTITY')),
    ('GEOPDCategorySearchParameters', 'supportedSearchSectionTypes', 3, (0, 'SEARCH_SECTION_TYPE_UNKNOWN'), (1, 'SEARCH_SECTION_TYPE_PLACE'), (2, 'SEARCH_SECTION_TYPE_GUIDE')),
    ('GEOPDETAFilter', 'transportTypes', 7, (0, 'AUTOMOBILE'), (3, 'BICYCLE'), (6, 'RIDESHARE')),
    ('GEOPDExtendedGeoLookupResult', 'status', 3, (0, 'EXTENDED_GEO_LOOKUP_RESULTS_STATUS_UNDEFINED'), (1, 'EXTENDED_GEO_LOOKUP_RESULTS_STATUS_SUCCESS'), (2, 'EXTENDED_GEO_LOOKUP_RESULTS_STATUS_NO_CACHE_MATCH')),
    ('GEOPDExtensionParams', 'extensionTypes', 3, (0, 'EXTENSION_TYPE_UNKNOWN'), (1, 'EXTENSION_TYPE_RESERVATION'), (2, 'EXTENSION_TYPE_QUEUING')),
    ('GEOPDExternalActionFilter', 'componentTypes', 89, (0, 'COMPONENT_TYPE_UNKNOWN'), (50, 'COMPONENT_TYPE_CONTAINED_PLACE'), (96, 'COMPONENT_TYPE_POI_CLAIM')),
    ('GEOPDGroundDataBuild', 'capabilitys', 2, (1, 'PANORAMIC'), (2, 'WOBBLY'), (2, 'WOBBLY')),
    ('GEOPDGuidesHomeParameters', 'supportedFixedSectionTypes', 4, (0, 'GUIDES_HOME_FIXED_SECTION_TYPE_UNKNOWN'), (2, 'GUIDES_HOME_FIXED_SECTION_TYPE_FILTERS'), (3, 'GUIDES_HOME_FIXED_SECTION_TYPE_FILTERED_GUIDES')),
    ('GEOPDGuidesHomeParameters', 'supportedRepeatableSectionTypes', 5, (0, 'GUIDES_HOME_REPEATABLE_SECTION_TYPE_UNKNOWN'), (2, 'GUIDES_HOME_REPEATABLE_SECTION_TYPE_PUBLISHER'), (4, 'GUIDES_HOME_REPEATABLE_SECTION_TYPE_LOCATIONS')),
    ('GEOPDMapsSearchHomeParameters', 'supportedSectionTypes', 6, (0, 'UNKNOWN'), (3, 'PUBLISHER_SUGGESTION_RESULT'), (5, 'GUIDE_LOCATION_SUGGESTION_RESULT')),
    ('GEOPDResultSnippetFilter', 'supportedChildActions', 8, (0, 'CHILD_ACTION_TYPE_UNKNOWN'), (4, 'CHILD_ACTION_TYPE_LOOK_AROUND'), (7, 'CHILD_ACTION_TYPE_GUIDES')),
    ('GEOPDSearchBrowseCategorySuggestionParameters', 'engineTypes', 5, (0, 'CAR_ENGINE_TYPE_UNKNOWN'), (2, 'CAR_ENGINE_TYPE_DIESEL'), (4, 'CAR_ENGINE_TYPE_CNG')),
    ('GEOPDSearchParameters', 'supportedRelatedEntitySectionTypes', 2, (0, 'RELATED_ENTITY_SECTION_TYPE_UNKNOWN'), (1, 'RELATED_ENTITY_SECTION_TYPE_COLLECTION'), (1, 'RELATED_ENTITY_SECTION_TYPE_COLLECTION')),
    ('GEOPDSearchParameters', 'supportedSearchTierTypes', 3, (0, 'SEARCH_TIER_METADATA_UNKNOWN'), (1, 'SEARCH_TIER_METADATA_PRIMARY'), (2, 'SEARCH_TIER_METADATA_AUXILIARY')),
    ('GEOPDSearchParameters', 'knownRefinementTypes', 6, (0, 'RESULT_REFINEMENT_TYPE_UNKNOWN'), (3, 'RESULT_REFINEMENT_TYPE_MULTI_SELECT'), (5, 'RESULT_REFINEMENT_GUIDES_HOME')),
    ('GEOPDSearchParameters', 'supportedPlaceSummaryFormatTypes', 5, (0, 'PLACE_SUMMARY_FORMAT_TYPE_UNKNOWN'), (2, 'PLACE_SUMMARY_FORMAT_TYPE_ITALICS'), (4, 'PLACE_SUMMARY_FORMAT_TYPE_TAPPABLE_ENTITY')),
    ('GEOPDSearchParameters', 'supportedSearchSectionTypes', 3, (0, 'SEARCH_SECTION_TYPE_UNKNOWN'), (1, 'SEARCH_SECTION_TYPE_PLACE'), (2, 'SEARCH_SECTION_TYPE_GUIDE')),
    ('GEOPDSearchQueryCompletionMetadata', 'completionSourceTypes', 14, (0, 'COMPLETION_SOURCE_TYPE_DEFAULT'), (7, 'COMPLETION_SOURCE_TYPE_EMBEDDING'), (13, 'COMPLETION_SOURCE_TYPE_TRANSLATION')),
    ('GEOPDSearchQueryFuzzyMatchV2Metadata', 'rewriteTypes', 3, (0, 'LAZY_REWRITE_NONE'), (1, 'FV2'), (2, 'TOK')),
    ('GEOPDSearchQueryGeoNormalizerMetadata', 'normalizers', 5, (1, 'NORMALIZE'), (3, 'SEGMENTATION'), (5, 'RBO')),
    ('GEOPDSearchQueryGeoTagMetadata', 'tagSources', 27, (1, 'CRF'), (14, 'ALTER_BELOW_STREET_ONLY'), (27, 'POSTAL_AND_DOOR_NUMBER_ONLY')),
    ('GEOPDSearchQueryGeoTagMetadata', 'geoRewriteTypes', 6, (1, 'PREFIX_TO_FIRST_DIGIT'), (4, 'IE_COUNTY_STRICT'), (6, 'TR_MAHALLESI')),
    ('GEOPDSearchQueryIntentMetadata', 'intentSources', 7, (0, 'NONE'), (3, 'QIS'), (6, 'GEO')),
    ('GEOPDSearchQueryIntentMetadata', 'rewrittenQueryTypes', 22, (0, 'NONE_REWRITTEN_QUERY_TYPE'), (11, 'POI_SEARCH_SPELL_CORRECTION'), (21, 'NEURAL_REWRITE')),
    ('GEOPDSearchRewrittenQueryNonPayloadField', 'pipelineType', 4, (0, 'NONE'), (2, 'GEO_ONLY'), (3, 'COMMON')),
    ('GEOPDSearchTriggerFeature', 'completionSourceTypes', 14, (0, 'COMPLETION_SOURCE_TYPE_DEFAULT'), (7, 'COMPLETION_SOURCE_TYPE_EMBEDDING'), (13, 'COMPLETION_SOURCE_TYPE_TRANSLATION')),
    ('GEOPDSpatialEventLookupParameters', 'categoryFilters', 14, (0, 'SPATIAL_EVENT_LOOKUP_CATEGORY_UNKNOWN'), (7, 'SPATIAL_EVENT_LOOKUP_CATEGORY_FESTIVALSANDFAIRS'), (13, 'SPATIAL_EVENT_LOOKUP_CATEGORY_APPLEEVENT')),
    ('GEOPDSpatialLookupResult', 'mappedCategorys', 23, (0, 'SPATIAL_LOOKUP_CATEGORY_UNKNOWN'), (11, 'SPATIAL_LOOKUP_CATEGORY_NIGHTLIFE'), (22, 'SPATIAL_LOOKUP_CATEGORY_HOSPITAL')),
    ('GEOPDSpatialPlaceLookupParameters', 'categoryFilters', 24, (0, 'SPATIAL_PLACE_LOOKUP_CATEGORY_UNKNOWN'), (12, 'SPATIAL_PLACE_LOOKUP_CATEGORY_PARK'), (23, 'SPATIAL_PLACE_LOOKUP_CATEGORY_AMUSEMENTPARK_RIDE')),
    ('GEOPDVendorIDLink', 'reservationTypes', 3, (0, 'RESTAURANT_RESERVATION_TYPE_UNKNOWN'), (1, 'RESTAURANT_RESERVATION_TYPE_RESERVATION'), (2, 'RESTAURANT_RESERVATION_TYPE_QUEUING')),
    ('GEOPDWebModuleConfiguration', 'type', 1, (0, 'WEB_MODULE_TYPE_GENERIC'), (0, 'WEB_MODULE_TYPE_GENERIC'), (0, 'WEB_MODULE_TYPE_GENERIC')),
]

# Fields that must NOT become enums: dictRep emits them through +[NSNumber numberWithInt:]
# with no "(unknown: %i)" branch (labelType), or they are not enums at all (the repeated
# 12-byte inline struct whose COUNT ivar is operatingHoursCount).
NOT_ENUMS = [
    ('GEOPDSearchAddressLabeledToken', 'labelType'),
    ('GEOPDDepartureSequence', 'operatingHoursCount'),
]


@unittest.skipUnless(_CACHE_MAIN is not None, _SKIP_MSG)
class TestInlinedDictRepEnumsLive(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        from macho.dyld_cache import DyldCacheReader
        from macho.memory import BinaryContext
        from macho.strings import build_string_table
        from macho.classlist import build_class_list
        from macho.local_symbols import apply_to_classes

        cls.reader = DyldCacheReader(_CACHE_MAIN)
        mv = cls.reader.find_image_header('GeoServices')
        cls.ok = mv is not None
        if not cls.ok:
            return
        cls.ctx = BinaryContext.from_cache(cls.reader, mv)
        cls.st = build_string_table(cls.ctx)
        cls.clist = build_class_list(cls.ctx, cls.st)
        syms = cls.reader.image_local_symbols(mv)
        if syms:
            apply_to_classes(cls.clist, syms)
        cls.by_name = {c.name: c for c in cls.clist if not c.is_meta}
        cls._harvest_cache = {}

    @classmethod
    def tearDownClass(cls):
        cls.reader.close()

    def setUp(self):
        if not self.ok:
            self.skipTest('GeoServices not present in this cache')

    def _pairs(self, class_name, field):
        from proto.enums import _harvest_dictrep_enums
        from proto.protocore import _proto_name
        c = self.by_name[class_name]
        if class_name not in self._harvest_cache:
            self._harvest_cache[class_name] = _harvest_dictrep_enums(self.ctx, c, self.st)
        off = {_proto_name(iv.name): iv.offset for iv in c.ivars if iv.name}[field]
        return self._harvest_cache[class_name].get(off, [])

    def test_all_37_fields_recovered_with_names_and_numbers(self):
        self.assertEqual(len(EXPECTED), 37)
        for cn, field, n, first, mid, last in EXPECTED:
            with self.subTest(field=f'{cn}.{field}'):
                pairs = self._pairs(cn, field)
                self.assertEqual(len(pairs), n)
                self.assertEqual(pairs[0], first)
                self.assertEqual(pairs[len(pairs) // 2], mid)
                self.assertEqual(pairs[-1], last)
                self.assertEqual([v for v, _ in pairs], sorted({v for v, _ in pairs}))

    def test_plain_int_and_non_enum_fields_stay_unrecovered(self):
        for cn, field in NOT_ENUMS:
            with self.subTest(field=f'{cn}.{field}'):
                self.assertEqual(self._pairs(cn, field), [])

    def test_biased_multi_segment_sparse_enum_numbers(self):
        # GEOPlaceType-shaped: values {0,1,2,4} + {16} + {35,43..51,54,55,57,61,63..65}, three
        # dispatch sites (the third indexed by value - 35).  Numbers must be the wire
        # values, not table indices, and the first segment must not hide the others.
        pairs = dict(self._pairs('GEOPDBatchReverseGeocodingParameters', 'additionalPlaceTypes'))
        self.assertEqual(sorted(pairs), [0, 1, 2, 4, 16, 35] + list(range(43, 52))
                         + [54, 55, 57, 61, 63, 64, 65])
        self.assertEqual(pairs[0], 'UNKNOWN_PLACE_TYPE')       # value-0 name hoisted via mov
        self.assertEqual(pairs[16], 'LOCALITY')                # isolated cmp+b.ne
        self.assertEqual(pairs[35], 'TIME_ZONE')               # first entry of the biased table
        self.assertEqual(pairs[65], 'PHYSICAL_FEATURE')

    def test_existing_biased_enums_no_longer_unbiased(self):
        # PlaceTypeHint/PlaceTypeLimit used the same switch but kept only the first, unbiased
        # segment (TIME_ZONE=0 ... PHYSICAL_FEATURE=30).
        pairs = dict(self._pairs('GEOPDPlaceRefinementParameters', 'placeTypeHint'))
        self.assertEqual(pairs[35], 'TIME_ZONE')
        self.assertEqual(pairs[65], 'PHYSICAL_FEATURE')
        self.assertEqual(pairs[1], 'COUNTRY')
        self.assertNotIn(8, pairs)

    def test_single_valued_enum_needs_the_unknown_format_signature(self):
        self.assertEqual(self._pairs('GEOPDWebModuleConfiguration', 'type'),
                         [(0, 'WEB_MODULE_TYPE_GENERIC')])

    def test_repeated_enum_values_are_not_one_based_shifted(self):
        # pointer table in a loop with sub w9,w8,#1 -> values 1..5, not 0..4
        pairs = self._pairs('GEOPDSearchQueryGeoNormalizerMetadata', 'normalizers')
        self.assertEqual([v for v, _ in pairs], [1, 2, 3, 4, 5])
        self.assertEqual(pairs[0][1], 'NORMALIZE')

    def test_extracted_schema_types_the_fields_as_enums(self):
        import proto.extractor as E
        m = E.extract_proto_message(self.ctx, self.st, self.clist, self.clist.find('GEOPDGroundDataBuild'))
        f = {x.name: x for x in m.fields}
        self.assertTrue(f['capabilitys'].type_class.startswith('ENUM:'))
        self.assertEqual(f['capabilitys'].label.name, 'REPEATED')
        enum = next(e for e in m.enums if f['capabilitys'].type_class == f'ENUM:{e.name}')
        self.assertEqual([(v.number, v.name.rsplit('_', 1)[-1]) for v in enum.values],
                         [(1, 'PANORAMIC'), (2, 'WOBBLY')])
        m = E.extract_proto_message(self.ctx, self.st, self.clist, self.clist.find('GEOPDSearchAddressLabeledToken'))
        label = next(x for x in m.fields if x.name == 'labelType')
        self.assertEqual((label.type_name, label.type_class), ('int32', None))


if __name__ == '__main__':
    unittest.main()
