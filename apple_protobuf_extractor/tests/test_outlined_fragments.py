"""Calls to machine-outlined fragments: run as part of the caller, not as an AAPCS64 call.

The outliner moves a repeated straight-line sequence into a fragment the function ``bl``s
(``ldrsw x9, [x23, #0x30] ; add x0, x8, x9 ; ret``): it has no calling convention, so the
caller's registers survive it except the ones it writes, and its stores are the caller's
(PegasusAPI's name-map builders, TODO #97).  :func:`proto.callees.outlined_fragment` recognises
one; :class:`proto.arm64_eval.Flow` runs it in place of the call.
"""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

from proto import callees
from proto.arm64_eval import Flow, _STACK_TOP
from tests._listing import insns, layout
from tests._fakes import NoImage

FRAG = 0x2000


def _flow(frag_lines, *caller):
    """Flow over *caller* (at 0x1000) where ``bl #0x2000`` runs *frag_lines*."""
    frag = tuple(insns(frag_lines, FRAG))
    with mock.patch('proto.arm64_eval.outlined_fragment',
                    lambda ctx, t: frag if t == FRAG else None):
        flow = Flow(NoImage(), insns(caller))
        flow.fragment(next(k for k, i in enumerate(flow.insns) if i.mnemonic == 'bl'))
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

    def test_a_tail_call_through_a_register_is_a_call(self):
        self.assertIsNone(self._frag([('mov', 'x1, x25'), ('br', 'x21')]))

    def test_a_call_or_a_branch_inside_is_not_a_fragment(self):
        self.assertIsNone(self._frag([('bl', '#0x3000'), ('ret', '')]))
        self.assertIsNone(self._frag([('cbz', 'x0, #0x2008'), ('mov', 'x0, #1'), ('ret', '')]))

    def test_a_frame_of_its_own_is_not_a_fragment(self):
        self.assertIsNone(self._frag([('sub', 'sp, sp, #0x10'), ('ret', '')]))
        self.assertIsNone(self._frag([('stp', 'x29, x30, [sp, #-0x10]!'), ('ret', '')]))
        self.assertIsNone(self._frag([('ldr', 'x30, [x0]'), ('ret', '')]))

    def test_it_returns_inside_its_own_extent(self):
        lines = [('mov', 'x0, #1'), ('mov', 'x1, #2'), ('ret', '')]
        self.assertIsNone(self._frag(lines, starts=(0x1000, FRAG, FRAG + 8)))

    def test_outside_text_or_without_a_function_index_it_is_a_call(self):
        lines = [('mov', 'x0, #1'), ('ret', '')]
        self.assertIsNone(self._frag(lines, target=0x9000))
        self.assertIsNone(self._frag(lines, starts=()))


if __name__ == '__main__':
    unittest.main()
