"""Synthetic unit tests for proto/dispatch.py's jump-table CFG completion — NO real binary.

(The ownership check _arm_calls_own_method and the wrapper-core hop these tests also
covered were retired 2026-10-15 with the rest of the readFrom: shape decoders; the dispatch
is decoded by evaluation now -- tests/test_dispatch_eval.py.)
"""
import os
import sys
import unittest
from types import SimpleNamespace

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

from proto.arm64cfg import build_blocks, inject_arm_edges
from proto.dispatch import _jump_table_arm_addrs


class TestJumpTableArmAddrsRangeGuardRedundant(unittest.TestCase):
    """_jump_table_arm_addrs's `lo <= arm < hi` guard (dispatch.py) can never be
    independently load-bearing through inject_arm_edges(): arm64cfg.build_blocks
    builds cfg.addr_to_block from the SAME insns list, with the SAME lo/hi bounds
    (both computed as `ins[0].addr, ins[-1].addr + 4` over one shared sorted list),
    so addr_to_block.keys() is always a subset of [lo, hi). Any arm address that
    fails the range check is, by construction, also absent from addr_to_block --
    inject_arm_edges's `- {None}` filter already drops it on its own. Proves this
    on one fixture: a real adr/ldrb/add/br jump table with a 3-byte table whose
    third entry decodes to an address far outside the function (0x1354 vs an
    8-instruction span ending at 0x1020)."""

    def _ins(self, addr, mn, op=''):
        return SimpleNamespace(addr=addr, mnemonic=mn, op_str=op)

    def _fixture(self):
        # adr x13,#0x1034; ldrb w9,[x10,w9]; add x13,x13,w9,lsl#2; br x13
        # table @0x2100 (x10 = adrp x10,#0x2000 + add x10,x10,#0x100), 3 one-byte
        # entries [0, 1, 200] -> arm_base + {0,4,800} = {0x1034, 0x1038, 0x1354}.
        # The first two land on real instructions (the two `ret` arms below);
        # the third (200) lands far past the function -- out of [lo, hi).
        return [
            self._ins(0x1000, 'adrp', 'x10, #0x2000'),
            self._ins(0x1004, 'add',  'x10, x10, #0x100'),
            self._ins(0x1008, 'cmp',  'w9, #3'),
            self._ins(0x100c, 'b.hs', '#0x1040'),
            self._ins(0x1010, 'ldrb', 'w9, [x10, w9]'),
            self._ins(0x1014, 'adr',  'x13, #0x1034'),
            self._ins(0x1018, 'add',  'x13, x13, w9, lsl #2'),
            self._ins(0x101c, 'br',   'x13'),
            self._ins(0x1034, 'ret',  ''),
            self._ins(0x1038, 'ret',  ''),
        ]

    class _TableCtx:
        _TABLE = bytes([0, 1, 200])

        def is_variable(self, vmaddr):        # no program data, no binds
            return False

        def read_bytes(self, va, n):
            assert 0x2100 <= va and va + n <= 0x2100 + len(self._TABLE)
            return self._TABLE[va - 0x2100:va - 0x2100 + n]

    def test_out_of_range_entry_dropped_by_guard(self):
        # Documents the guard's own claim: it filters 0x1354 out of the arm set.
        arms = _jump_table_arm_addrs(self._TableCtx(), self._fixture())
        self.assertEqual(arms, {0x1034, 0x1038})

    def test_out_of_range_entry_also_absent_from_downstream_cfg(self):
        # And independently: even without the guard, inject_arm_edges would
        # never have picked 0x1354 up -- it isn't a key of addr_to_block,
        # because addr_to_block is built from this same insns list.
        insns = self._fixture()
        cfg = build_blocks(insns)
        self.assertIsNone(cfg.addr_to_block.get(0x1354))

    def test_guard_removal_does_not_change_injected_edges(self):
        # The two facts above combine: simulate the UNGUARDED function's output
        # (the guarded arms plus the address the range check alone would have
        # suppressed) and confirm inject_arm_edges produces IDENTICAL edges
        # either way -- the range check is fully subsumed downstream.
        insns = self._fixture()
        guarded_arms = _jump_table_arm_addrs(self._TableCtx(), insns)
        unguarded_arms = guarded_arms | {0x1354}

        cfg_guarded = build_blocks(insns)
        inject_arm_edges(cfg_guarded, guarded_arms)
        cfg_unguarded = build_blocks(insns)
        inject_arm_edges(cfg_unguarded, unguarded_arms)

        br_block = cfg_guarded.order[1]
        self.assertEqual(cfg_guarded.succ[br_block], cfg_unguarded.succ[br_block])



class TestJumpTablesDecodedByEvaluation(unittest.TestCase):
    """Each index value the bound lets through is run to the ``br``: the table's entry width,
    signedness and scaling, a bias or clamp of the index and the anchor are whatever the code
    computes."""

    class _Mem:
        def __init__(self, base, data):
            self.base, self.data = base, data

        def read_bytes(self, va, n):
            if not self.base <= va <= va + n <= self.base + len(self.data):
                raise ValueError(va)
            return self.data[va - self.base:va - self.base + n]

        def is_variable(self, vmaddr):        # no program data, no binds
            return False

        def read_ptr(self, va):
            return int.from_bytes(self.read_bytes(va, 8), 'little')

    @staticmethod
    def _listing(lines, base=0x1000):
        from macho.disasm import Insn
        return [Insn(addr=base + 4 * k, mnemonic=ln.partition(' ')[0], op_str=ln.partition(' ')[2],
                     size=4, raw=b'\0' * 4) for k, ln in enumerate(lines)]

    @staticmethod
    def _deltas(*ds):
        return b''.join(d.to_bytes(4, 'little', signed=True) for d in ds)

    def test_difference_table_with_a_bare_extend_is_not_scaled(self):
        # add x16, x17, w16, sxtw: the extend carries no shift, so each entry IS the byte delta
        # (a decoder that took an unparsed shift for lsl #2 would put the arms 4x too far).
        insns = self._listing([
            'cmp w1, #2', 'b.hi #0x1028', 'adrp x17, #0x2000', 'add x17, x17, #0x0',
            'ldrsw x16, [x17, x1, lsl #2]', 'adr x17, #0x1024', 'add x16, x17, w16, sxtw',
            'br x16', 'ret', 'ret', 'ret', 'ret', 'ret'])
        mem = self._Mem(0x2000, self._deltas(4, 8, 12))
        self.assertEqual(_jump_table_arm_addrs(mem, insns), {0x1028, 0x102c, 0x1030})

    def test_an_index_clamped_after_its_gate(self):
        # the macOS 27 engine: sub; cmp; b.hi; cmp; csel (clamp); ldrsw [table, x16, lsl #2]
        insns = self._listing([
            'sub w16, w1, #1', 'cmp w16, #2', 'b.hi #0x1034', 'cmp x16, #2',
            'csel x16, x16, xzr, ls', 'adrp x17, #0x2000', 'add x17, x17, #0x0',
            'ldrsw x16, [x17, x16, lsl #2]', 'adr x17, #0x1024', 'add x16, x17, x16',
            'br x16', 'ret', 'ret', 'ret', 'ret', 'ret'])
        mem = self._Mem(0x2000, self._deltas(0x10, 0x14, -0x18))
        self.assertEqual(_jump_table_arm_addrs(mem, insns, per_br=True),
                         {0x1028: {0x1034, 0x1038, 0x100c}})

    def test_an_index_copied_from_the_gated_register(self):
        # locationd 0x100ed2d68: the gate compares w2, the table is indexed by its copy w21
        insns = self._listing([
            'mov x21, x2', 'cmp w2, #2', 'b.hi #0x1030', 'mov w8, w21', 'adr x9, #0x1020',
            'add x9, x9, x8, lsl #3', 'br x9', 'nop', 'ret', 'nop', 'ret', 'nop', 'ret'])
        self.assertEqual(_jump_table_arm_addrs(self._Mem(0, b''), insns, per_br=True),
                         {0x1018: {0x1020, 0x1028, 0x1030}})

    def test_an_ungated_index_set_on_each_path(self):
        # locationd 0x100dc8a98: no gate; the index is 0 or 2 by the path in, then maybe one
        # more (cinc) -- each of its values is run to the br
        insns = self._listing([
            'cbz w0, #0x100c', 'mov w22, #0', 'b #0x1010', 'mov w22, #2', 'cmp w1, #5',
            'cinc w22, w22, ge', 'mov w8, w22', 'adr x9, #0x1030', 'add x9, x9, x8, lsl #3',
            'br x9', 'nop', 'nop', 'ret', 'nop', 'ret', 'nop', 'ret', 'nop', 'ret'])
        self.assertEqual(_jump_table_arm_addrs(self._Mem(0, b''), insns, per_br=True),
                         {0x1024: {0x1030, 0x1038, 0x1040, 0x1048}})

    def test_an_ungated_value_set_is_all_or_nothing(self):
        # the index is 0 or 9 on the paths in; 9 lands past the function: no arms at all
        insns = self._listing([
            'cbz w0, #0x100c', 'mov w22, #0', 'b #0x1010', 'mov w22, #9', 'mov w8, w22',
            'adr x9, #0x1024', 'add x9, x9, x8, lsl #3', 'br x9', 'nop', 'ret', 'nop', 'ret'])
        self.assertEqual(_jump_table_arm_addrs(self._Mem(0, b''), insns), set())

    def test_an_index_from_a_load_is_not_guessed(self):
        insns = self._listing([
            'ldr w22, [x0]', 'mov w8, w22', 'adr x9, #0x1018', 'add x9, x9, x8, lsl #3',
            'br x9', 'nop', 'ret'])
        self.assertEqual(_jump_table_arm_addrs(self._Mem(0, bytes(8)), insns), set())

    def test_a_mask_bounded_index(self):
        # and w8, w0, #3 on a wire type: no compare, every value the mask lets through
        insns = self._listing([
            'and w8, w0, #3', 'adr x9, #0x1010', 'add x9, x9, x8, lsl #3', 'br x9',
            'ret', 'nop', 'ret', 'nop', 'ret', 'nop', 'ret'])
        self.assertEqual(_jump_table_arm_addrs(self._Mem(0, b''), insns),
                         {0x1010, 0x1018, 0x1020, 0x1028})

    def test_a_mask_wider_than_the_gate_span_is_reported(self):
        # and w8, w0, #0x1fff: 8,192 values, each a run -- not enumerated, and in the summary
        from proto.models import get_diagnostics
        insns = self._listing([
            'and w8, w0, #0x1fff', 'adr x9, #0x1010', 'add x9, x9, x8, lsl #3', 'br x9',
            'ret', 'nop', 'ret'])
        mem = self._Mem(0, b'')
        self.assertEqual(_jump_table_arm_addrs(mem, insns), set())
        self.assertIn(("_MAX_GATE_SPAN", "0x1000"), get_diagnostics(mem).heuristics_hit)

    def test_a_shift_bounded_index(self):
        # lsr x8, x1, #62: a value's two tag bits (Foundation.Data's representation in
        # swift-protobuf's BytesValue.traverse), every value 0..3 an entry of a byte table
        insns = self._listing([
            'lsr x8, x1, #0x3e', 'adrp x9, #0x2000', 'add x9, x9, #0x0', 'adr x10, #0x101c',
            'ldrb w11, [x9, x8]', 'add x10, x10, x11, lsl #2', 'br x10',
            'ret', 'ret', 'ret', 'ret'])
        mem = self._Mem(0x2000, bytes((0, 1, 2, 3)))
        self.assertEqual(_jump_table_arm_addrs(mem, insns), {0x101c, 0x1020, 0x1024, 0x1028})

    def test_a_ubfx_bounded_index(self):
        insns = self._listing([
            'ubfx w8, w0, #3, #1', 'adr x9, #0x1010', 'add x9, x9, x8, lsl #3', 'br x9',
            'ret', 'nop', 'ret'])
        self.assertEqual(_jump_table_arm_addrs(self._Mem(0, b''), insns), {0x1010, 0x1018})

    def test_arms_past_a_partial_listing_within_bounds(self):
        # a listing read only up to its br: the arms lie past its last instruction, so they are
        # found only within the function's extent passed as bounds
        insns = self._listing(['and w8, w0, #1', 'adr x9, #0x1010', 'add x9, x9, x8, lsl #3',
                               'br x9'])
        mem = self._Mem(0, b'')
        self.assertEqual(_jump_table_arm_addrs(mem, insns), set())
        self.assertEqual(_jump_table_arm_addrs(mem, insns, bounds=(0x1000, 0x1020)),
                         {0x1010, 0x1018})

    def test_a_table_reached_only_through_another_tables_arm(self):
        # the second br is behind the first table's arm 0x101c: decoded once that arm is an edge
        insns = self._listing([
            'and w8, w0, #1', 'adr x9, #0x1014', 'add x9, x9, x8, lsl #3', 'br x9',
            'ret', 'ret', 'nop', 'and w10, w2, #1', 'adr x11, #0x1030', 'add x11, x11, x10, lsl #2',
            'br x11', 'ret', 'ret', 'ret'])
        self.assertEqual(_jump_table_arm_addrs(self._Mem(0, b''), insns, per_br=True),
                         {0x100c: {0x1014, 0x101c}, 0x1028: {0x1030, 0x1034}})



class TestProvisionalDecodes(unittest.TestCase):
    """A jump table decoded while call_reads was still solving a cycle (its evaluation used a
    provisional answer) is decoded again once the cycle settles, and a different result is
    warned of (TODO #119) rather than kept silently."""

    def test_a_table_that_decodes_differently_once_settled_is_warned_of(self):
        from unittest import mock
        import proto.dispatch as D
        from tests._fakes import NoImage
        from tests._listing import insns
        listing = insns([('cmp', 'w8, #1'), ('b.hi', '#0x1010'), ('adr', 'x9, #0x1010'),
                         ('br', 'x9'), ('ret', '')])
        ctx = NoImage()
        answers = [{0x1010}, {0x100c}]             # in the cycle, then once it has settled

        def evaluated(flow, idom, kb, lo, hi):
            if len(answers) == 2:
                D.note_provisional_answer(ctx)     # it consulted a function still being read
            return answers.pop(0)

        with mock.patch.object(D, '_evaluated_arms', evaluated), \
                mock.patch('proto.liveness.solving', lambda ctx: True):   # a cycle open
            self.assertEqual(D._jump_table_arm_addrs(ctx, listing), {0x1010})
        with mock.patch.object(D, '_evaluated_arms', evaluated):
            with self.assertLogs('proto.models', 'WARNING') as logs:
                D.recheck_provisional_decodes(ctx)
        self.assertIn('decodes differently', logs.output[0])
        self.assertEqual(D._jump_table_arm_addrs(ctx, listing), {0x100c})

    def test_a_table_that_decodes_the_same_is_not_remarked(self):
        from unittest import mock
        import proto.dispatch as D
        from proto.models import get_diagnostics
        from tests._fakes import NoImage
        from tests._listing import insns
        listing = insns([('cmp', 'w8, #1'), ('b.hi', '#0x1010'), ('adr', 'x9, #0x1010'),
                         ('br', 'x9'), ('ret', '')])
        ctx = NoImage()
        calls = []

        def evaluated(flow, idom, kb, lo, hi):
            if not calls:
                D.note_provisional_answer(ctx)
            calls.append(kb)
            return {0x1010}

        with mock.patch.object(D, '_evaluated_arms', evaluated):
            with mock.patch('proto.liveness.solving', lambda ctx: True):
                D._jump_table_arm_addrs(ctx, listing)
            D.recheck_provisional_decodes(ctx)
        self.assertEqual(len(calls), 2)                 # decoded again once settled
        self.assertEqual(get_diagnostics(ctx).heuristics_hit, [])


class TestProvisionalDecodeSettledWhileDecoded(unittest.TestCase):
    """A decode that used a provisional answer, the cycle settling before the decode returned,
    is decoded again at once: it was queued after the recheck had run (review 2026-10-27)."""

    def test_decoded_again_at_once(self):
        from unittest import mock
        import proto.dispatch as D
        from tests._fakes import NoImage
        from tests._listing import insns
        listing = insns([('cmp', 'w8, #1'), ('b.hi', '#0x1010'), ('adr', 'x9, #0x1010'),
                         ('br', 'x9'), ('ret', '')])
        ctx = NoImage()
        answers = [{0x1010}, {0x100c}]

        def evaluated(flow, idom, kb, lo, hi):
            if len(answers) == 2:
                D.note_provisional_answer(ctx)
            return answers.pop(0)

        with mock.patch.object(D, '_evaluated_arms', evaluated), \
                self.assertLogs('proto.models', 'WARNING'):
            self.assertEqual(D._jump_table_arm_addrs(ctx, listing), {0x100c})
        self.assertEqual(getattr(ctx, "_provisional_decodes", []), [])


class TestTableBaseParkedAcrossACall(unittest.TestCase):
    """#121, locationd's readFrom core (0x100bdbcf0): the table base x30 is parked in x20 around
    a call (which clobbers x30) and copied back.  By reaching definitions that is a copy cycle
    (unknown); the decoder starts from the forward evaluation, where it is the constant."""

    def _arms(self):
        from unittest import mock
        import proto.callees as C
        import proto.dispatch as D
        from tests._fakes import NoImage
        from tests._listing import insns

        class Image(NoImage):
            def read_bytes(self, va, n):
                table = {0x5070: 0, 0x5071: 1, 0x5072: 2}
                if all(va + i in table for i in range(n)):
                    return bytes(table[va + i] for i in range(n))
                raise ValueError(va)

            def is_variable(self, vmaddr):        # no program data, no binds
                return False

            def read_ptr(self, va):
                raise ValueError(va)

        listing = insns([('adrp', 'x30, #0x5000'), ('add', 'x30, x30, #0x70'),
                         ('mov', 'x20, x30'), ('bl', '#0x9000'), ('mov', 'x30, x20'),   # 0x1008
                         ('cmp', 'w8, #2'), ('b.hi', '#0x1034'), ('adr', 'x9, #0x102c'),
                         ('ldrb', 'w10, [x30, x8]'), ('add', 'x9, x9, x10, lsl #2'),
                         ('br', 'x9'),                                                   # 0x1028
                         ('b', '#0x1008'), ('b', '#0x1008'),                             # arms
                         ('cbnz', 'x0, #0x1008'), ('ret', '')])   # 0x1034: the loop's own edge
        import proto.liveness as L
        with mock.patch.object(C, 'callee_name', lambda ctx, va: None), \
                mock.patch.object(L, 'callee_name', lambda ctx, va: None), \
                mock.patch.object(L, 'stub_selector', lambda ctx, va: None):
            return D._jump_table_arm_addrs(Image(), listing, per_br=True).get(0x1028, set())

    def test_the_table_decodes(self):
        self.assertEqual(self._arms(), {0x102c, 0x1030, 0x1034})

    def test_by_reaching_definitions_alone_it_would_not(self):
        from unittest import mock
        from proto.arm64_eval import Flow
        with mock.patch.object(Flow, 'known_before', lambda self, k: {}):
            self.assertEqual(self._arms(), set())


if __name__ == "__main__":
    unittest.main()
