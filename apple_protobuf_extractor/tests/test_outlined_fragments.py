"""Calls to machine-outlined code: run as part of the caller, not as an AAPCS64 call.

The outliner moves a repeated straight-line sequence into a fragment the function ``bl``s
(``ldrsw x9, [x23, #0x30] ; add x0, x8, x9 ; ret``): it has no calling convention, so the
caller's registers survive it except the ones it writes, and its stores are the caller's
(PegasusAPI's name-map builders, TODO #97).  A fragment may set up the caller's frame (``sub
sp, sp, #0x80 ; stp ... ; ret``), and a thunk ends in a tail call instead of a return (``stp
x2, x3, [sp, #0x10] ; ... ; b T``): its prefix runs in the caller, then the ``bl`` is a call to T
(iOS 27 PromptKit's name-map builders), or through a register (``mov x19, x0 ; mov x0, #0 ; br
x1``, Swift's outlined metadata-accessor call).  :func:`proto.callees.outlined_code` recognises them;
:class:`proto.arm64_eval.Flow` runs them in place of the call.
"""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

from proto import callees
from proto.arm64_eval import Flow, Objects, _STACK_TOP
from tests._listing import insns, layout
from tests._fakes import NoImage

FRAG, TAIL = 0x2000, 0x5000


def _flow(frag_lines, *caller, tail=None, tail_reg=None):
    """Flow over *caller* (at 0x1000) where ``bl #0x2000`` runs *frag_lines* (with *tail*: a
    thunk's prefix, then a call to *tail*; with *tail_reg*, through that register)."""
    frag = tuple(insns(frag_lines, FRAG))
    with mock.patch('proto.arm64_eval.outlined_fragment',
                    lambda ctx, t: frag if t == FRAG else None), \
            mock.patch('proto.arm64_eval.outlined_tail',
                       lambda ctx, t: tail if t == FRAG else None), \
            mock.patch('proto.arm64_eval.outlined_tail_reg',
                       lambda ctx, t: tail_reg if t == FRAG else None):
        flow = Flow(NoImage(), insns(caller))
        k = next(k for k, i in enumerate(flow.insns) if i.mnemonic == 'bl')
        flow.fragment(k)
        flow.fragment_tail(k)
        flow.fragment_tail_reg(k)
    return flow


class TestFlowThroughAFragment(unittest.TestCase):

    def test_registers_it_does_not_write_survive(self):
        flow = _flow([('add', 'x0, x8, #0x10')],
                     ('mov', 'x8, #0x100'), ('mov', 'x19, #3'), ('bl', '#0x2000'),
                     ('mov', 'x1, x0'), ('ret', ''))
        self.assertEqual(flow.const_before(3, 'x0'), 0x110)
        self.assertEqual(flow.const_before(3, 'x8'), 0x100)     # an ABI call would take x8
        self.assertEqual(flow.defs_before(3, 'x8'), frozenset((0,)))
        self.assertEqual(flow.defs_before(3, 'x0'), frozenset((2,)))
        regs = flow.propagate({}, [3])[3]
        self.assertEqual((regs.get('x0'), regs.get('x8')), (0x110, 0x100))

    def test_its_stores_are_the_callers(self):
        flow = _flow([('str', 'x10, [x8]')],
                     ('add', 'x8, sp, #0x10'), ('mov', 'x10, #7'), ('bl', '#0x2000'),
                     ('ldr', 'x1, [sp, #0x10]'), ('ret', ''))
        self.assertEqual(flow.propagate({}, [4])[4].get('x1'), 7)

    def test_the_registers_inside_it(self):
        flow = _flow([('mov', 'x9, #4'), ('add', 'x0, x8, x9')],
                     ('mov', 'x8, #0x100'), ('bl', '#0x2000'), ('ret', ''))
        inside = {}
        flow.propagate({}, [2], fragments_out=inside)
        self.assertEqual([r.get('x9') for r in inside[1]], [None, 4])
        self.assertEqual(inside[1][0].get('x8'), 0x100)
        self.assertEqual(inside[1][0].get('sp'), _STACK_TOP)

    def test_a_call_that_is_not_a_fragment_takes_the_caller_saved_registers(self):
        flow = _flow([('add', 'x0, x8, #0x10')],
                     ('mov', 'x8, #0x100'), ('bl', '#0x3000'), ('mov', 'x1, x8'), ('ret', ''))
        self.assertIsNone(flow.const_before(2, 'x8'))

    def test_a_spill_in_an_outlined_prologue_is_reloaded_after_it(self):
        # the prologue moves sp: the caller's frame is the one it set up
        flow = _flow([('sub', 'sp, sp, #0x80'), ('stp', 'x28, x27, [sp, #0x20]')],
                     ('mov', 'x28, #7'), ('mov', 'x27, #8'), ('bl', '#0x2000'),
                     ('ldp', 'x1, x2, [sp, #0x20]'), ('ret', ''))
        regs = flow.propagate({}, [4])[4]
        self.assertEqual((regs.get('x1'), regs.get('x2')), (7, 8))
        self.assertEqual(regs.get('sp'), _STACK_TOP - 0x80)
        self.assertEqual(flow.const_before(3, 'x28'), 7)        # callee-saved, kept


class TestFlowThroughAThunk(unittest.TestCase):
    """``bl`` to ``stp x2, x3, [sp, #0x10] ; mov x21, x1 ; mov x0, #0 ; <LR check> ; b T``."""

    PREFIX = [('stp', 'x2, x3, [sp, #0x10]'), ('mov', 'x21, x1'), ('mov', 'x0, #0')]
    CALLER = [('sub', 'sp, sp, #0x40'), ('mov', 'x1, #9'), ('mov', 'x2, #5'), ('mov', 'x3, #6'),
              ('bl', '#0x2000'), ('ldp', 'x9, x10, [sp, #0x10]'), ('mov', 'x11, x21'),
              ('ret', '')]
    BL, AFTER = 4, 5

    def _flow(self):
        return _flow(self.PREFIX, *self.CALLER, tail=TAIL)

    def test_its_prefix_stores_are_reloaded_after_it(self):
        regs = self._flow().propagate({}, [self.AFTER + 1])[self.AFTER + 1]
        self.assertEqual((regs.get('x9'), regs.get('x10')), (5, 6))

    def test_a_callee_saved_register_it_sets_survives_its_tail_call(self):
        flow = self._flow()
        self.assertEqual(flow.propagate({}, [self.AFTER])[self.AFTER].get('x21'), 9)
        self.assertEqual(flow.const_before(self.AFTER, 'x21'), 9)
        self.assertEqual(flow.defs_before(self.AFTER, 'x21'), frozenset((self.BL,)))

    def test_its_tail_call_takes_the_caller_saved_registers(self):
        flow = self._flow()
        regs = flow.propagate({}, [self.AFTER])[self.AFTER]
        self.assertIsNone(regs.get('x0'))               # the prefix's 0 is the call's argument
        self.assertIsNone(regs.get('x1'))
        self.assertIsNone(flow.const_before(self.AFTER, 'x0'))
        self.assertIsNone(flow.const_before(self.AFTER, 'x1'))
        self.assertIn('x0', flow.call_writes(self.BL))
        self.assertIn('x21', flow.call_writes(self.BL))

    def test_the_call_site_is_the_bl_with_the_registers_there(self):
        calls = self._flow().run_from(0, {}).calls
        self.assertEqual([(c.k, c.target) for c in calls], [(self.BL, FRAG)])
        self.assertEqual(calls[0].args.get('x1'), 9)
        self.assertNotIn('x0', calls[0].args)           # set to 0 by the prefix, not before

    def test_its_result_is_the_bl_calls(self):
        # call_result is told the bl's target and x0, not the tail callee's (a named function
        # of this shape, a metadata accessor, is known by its own name)
        told = []
        objects = Objects(call_result=lambda addr, t, x0: told.append((addr, t, x0)) or 0x99)
        flow = self._flow()
        regs = flow.propagate({'x0': 0x77}, [self.AFTER], objects)[self.AFTER]
        self.assertEqual(set(told), {(flow.insns[self.BL].addr, FRAG, 0x77)})   # (fixpoint, then replay)
        self.assertEqual(regs.get('x0'), 0x99)

    def test_the_registers_inside_it_and_at_its_tail_call(self):
        inside = {}
        self._flow().propagate({}, [self.AFTER], fragments_out=inside)
        trace = inside[self.BL]
        self.assertEqual(len(trace), len(self.PREFIX) + 1)
        self.assertEqual((trace[-1].get('x0'), trace[-1].get('x21')), (0, 9))

    def test_evaluate_stops_at_its_tail_call(self):
        where = []
        with mock.patch('proto.arm64_eval.read_cfstring_text', lambda ctx, va: f"S{va:#x}"):
            got = self._flow().evaluate(-1, 'x8', 0, where=where)
        self.assertEqual(where, [self.BL])
        self.assertEqual((got.get('x0'), got.get('x1')), ('S0x0', 'S0x9'))


class TestFlowThroughARegisterThunk(unittest.TestCase):
    """``bl`` to ``mov x19, x0 ; mov x0, #0 ; br x1``: the caller's x19 is the prefix's, then a
    call through x1."""

    PREFIX = [('mov', 'x19, x0'), ('mov', 'x0, #0')]
    CALLER = [('add', 'x19, sp, #0x10'), ('mov', 'x0, #0x40'), ('mov', 'x1, #0x7000'),
              ('bl', '#0x2000'), ('mov', 'x2, x19'), ('ret', '')]
    BL, AFTER = 3, 4

    def _flow(self):
        return _flow(self.PREFIX, *self.CALLER, tail_reg='x1')

    def test_the_callee_saved_register_it_sets_is_its_value_not_the_callers(self):
        flow = self._flow()
        self.assertEqual(flow.propagate({}, [self.AFTER])[self.AFTER].get('x19'), 0x40)
        self.assertEqual(flow.const_before(self.AFTER, 'x19'), 0x40)

    def test_its_tail_call_takes_the_caller_saved_registers(self):
        flow = self._flow()
        self.assertTrue(flow.fragment_calls(self.BL))
        self.assertIsNone(flow.propagate({}, [self.AFTER])[self.AFTER].get('x0'))
        self.assertIn('x0', flow.call_writes(self.BL))

    def test_its_tail_call_goes_where_the_register_points(self):
        flow = self._flow()
        self.assertEqual(flow.thunk_target(self.BL, {'x1': 0x7000}), 0x7000)
        self.assertIsNone(flow.thunk_target(self.BL, {}))


class _TextCtx:
    """A ctx with a ``__text`` section and a function index."""
    class _Sec:
        vmaddr, vmsize = 0x1000, 0x4000

    def __init__(self, starts):
        self._starts = starts

    def has_section(self, seg, sect):
        return (seg, sect) == ('__TEXT', '__text')

    def section(self, seg, sect):
        return self._Sec()

    def function_starts(self):
        return self._starts


class TestRecognise(unittest.TestCase):

    def _frag(self, lines, starts=(0x1000, FRAG, 0x2100), target=FRAG):
        _order, fake = layout((FRAG, lines))
        with mock.patch('proto.callees.disasm', fake):
            return callees.outlined_fragment(_TextCtx(list(starts)), target)

    def test_a_straight_line_ending_in_ret(self):
        got = self._frag([('ldrsw', 'x9, [x23, #0x30]'), ('add', 'x0, x8, x9'), ('ret', '')])
        self.assertEqual([i.mnemonic for i in got], ['ldrsw', 'add'])

    def test_a_tail_call_through_a_register_ends_a_thunk(self):
        _order, fake = layout((FRAG, [('mov', 'x1, x25'), ('br', 'x21')]))
        with mock.patch('proto.callees.disasm', fake):
            got = callees.outlined_code(_TextCtx([0x1000, FRAG, 0x2100]), FRAG)
        self.assertEqual(([i.mnemonic for i in got.body], got.tail, got.tail_reg),
                         (['mov'], None, 'x21'))

    def test_a_call_or_a_branch_inside_is_not_a_fragment(self):
        self.assertIsNone(self._frag([('bl', '#0x3000'), ('ret', '')]))
        self.assertIsNone(self._frag([('cbz', 'x0, #0x2008'), ('mov', 'x0, #1'), ('ret', '')]))

    def test_a_frame_that_moves_sp_by_an_immediate_is_a_fragment(self):
        # the outlined prologue: the caller's state tracks sp
        got = self._frag([('sub', 'sp, sp, #0x80'), ('stp', 'x28, x27, [sp, #0x20]'), ('ret', '')])
        self.assertEqual([i.mnemonic for i in got], ['sub', 'stp'])
        got = self._frag([('stp', 'x20, x19, [sp, #-0x10]!'), ('ret', '')])
        self.assertEqual([i.mnemonic for i in got], ['stp'])

    def test_sp_moved_by_a_register_or_a_link_register_write_is_not_a_fragment(self):
        self.assertIsNone(self._frag([('sub', 'sp, sp, x9'), ('ret', '')]))
        self.assertIsNone(self._frag([('mov', 'sp, x29'), ('ret', '')]))
        self.assertIsNone(self._frag([('ldr', 'x30, [x0]'), ('ret', '')]))
        self.assertIsNone(self._frag([('ldp', 'x29, x30, [sp], #0x10'), ('ret', '')]))

    def _code(self, lines, starts=(0x1000, FRAG, 0x2100), target=FRAG):
        _order, fake = layout((FRAG, lines))
        with mock.patch('proto.callees.disasm', fake):
            return callees.outlined_code(_TextCtx(list(starts)), target)

    def test_a_thunk(self):
        check = [('eor', 'x16, x30, x30, lsl #1'), ('tbz', f'x16, #62, #{FRAG + 0x18:#x}'),
                 ('brk', '#0xc471')]
        got = self._code([('stp', 'x2, x3, [sp, #0x10]'), ('mov', 'x21, x1'), ('mov', 'x0, #0'),
                          *check, ('b', '#0x5000')], starts=(0x1000, FRAG, FRAG + 0x1c))
        self.assertEqual([i.mnemonic for i in got.body], ['stp', 'mov', 'mov'])
        self.assertEqual(got.tail, 0x5000)
        got = self._code([('mov', 'x1, x25'), ('b', '#0x5000')], starts=(0x1000, FRAG, FRAG + 8))
        self.assertEqual(([i.mnemonic for i in got.body], got.tail), (['mov'], 0x5000))
        self.assertEqual(callees.outlined_tail(None, FRAG), None)

    def test_a_branch_inside_its_extent_or_not_at_its_end_is_not_a_thunk(self):
        self.assertIsNone(self._code([('mov', 'x1, x25'), ('b', '#0x2000')],
                                     starts=(0x1000, FRAG, FRAG + 8)))
        self.assertIsNone(self._code([('mov', 'x1, x25'), ('b', '#0x5000'), ('nop', '')],
                                     starts=(0x1000, FRAG, FRAG + 12)))
        # a test other than the return-address check is a branch
        self.assertIsNone(self._code([('eor', 'x16, x30, x30, lsl #1'),
                                      ('tbz', f'x16, #61, #{FRAG + 0xc:#x}'), ('brk', '#0xc471'),
                                      ('b', '#0x5000')], starts=(0x1000, FRAG, FRAG + 0x10)))

    def test_it_returns_inside_its_own_extent(self):
        lines = [('mov', 'x0, #1'), ('mov', 'x1, #2'), ('ret', '')]
        self.assertIsNone(self._frag(lines, starts=(0x1000, FRAG, FRAG + 8)))

    def test_outside_text_or_without_a_function_index_it_is_a_call(self):
        lines = [('mov', 'x0, #1'), ('ret', '')]
        self.assertIsNone(self._frag(lines, target=0x9000))
        self.assertIsNone(self._frag(lines, starts=()))


if __name__ == '__main__':
    unittest.main()
