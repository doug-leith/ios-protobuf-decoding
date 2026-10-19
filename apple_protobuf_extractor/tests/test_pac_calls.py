"""arm64e calls and branches through an authenticated register (``blraa`` / ``braa`` ...).

A ``blraa`` is a call like ``bl`` / ``blr``: the caller-saved registers are the callee's.  The
exception is a callee whose contract changes fewer (:data:`proto.callees.CALL_CLOBBERS`): the
stack probe a frame over a page calls first, through its GOT slot, keeps x0 (self).  A ``braa``
is an indirect branch: no successor in the CFG.
"""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

from proto.arm64_eval import Flow
from proto.arm64_operands import CALLER_SAVED, writes
from tests._listing import insns

PROBE = 0x9000             # ____chkstk_darwin
SLOT = 0x6010              # its GOT slot


class _Ctx:
    is_cache_backed = False

    def read_ptr(self, va):
        if va == SLOT:
            return PROBE
        raise ValueError(va)

    def read_bytes(self, va, n):
        raise ValueError(va)


def _probe_named(ctx, va):
    return '____chkstk_darwin' if va == PROBE else None


def _unnamed(ctx, va):
    return None


def _probe_call(*after):
    """x0 = 5, then the stack probe through its GOT slot, then *after*."""
    return insns([('mov', 'x0, #5'), ('mov', 'w9, #0x1270'), ('adrp', 'x17, #0x6000'),
                  ('add', 'x17, x17, #0x10'), ('ldr', 'x16, [x17]'), ('blraa', 'x16, x17'),
                  *after])


CALL = 5                   # index of the blraa in _probe_call


class TestWrites(unittest.TestCase):

    def test_an_authenticated_call_writes_every_caller_saved_register(self):
        for mn in ('blraa', 'blrab'):
            self.assertEqual(writes(insns([(mn, 'x16, x17')])[0]), list(CALLER_SAVED))
        self.assertEqual(writes(insns([('blraaz', 'x8')])[0]), list(CALLER_SAVED))

    def test_an_authenticated_branch_writes_nothing(self):
        self.assertEqual(writes(insns([('braa', 'x16, x17')])[0]), [])


class TestStackProbe(unittest.TestCase):

    def _flow(self):
        return Flow(_Ctx(), _probe_call(('mov', 'x1, x0'), ('ret', '')))

    def test_an_unknown_callee_takes_x0(self):
        with mock.patch('proto.callees.callee_name', _unnamed):
            flow = self._flow()
            self.assertIsNone(flow.const_before(CALL + 1, 'x0'))
            self.assertIsNone(flow.propagate({}, [CALL + 1])[CALL + 1].get('x0'))

    def test_the_stack_probe_keeps_x0_and_changes_its_scratch(self):
        with mock.patch('proto.callees.callee_name', _probe_named):
            flow = self._flow()
            self.assertEqual(flow.const_before(CALL + 1, 'x0'), 5)
            regs = flow.propagate({}, [CALL + 1])[CALL + 1]
            self.assertEqual(regs.get('x0'), 5)
            self.assertIsNone(regs.get('x16'))
            self.assertEqual(flow.defs_before(CALL + 1, 'x16'), frozenset((CALL,)))

    def test_the_candidate_scan_runs_through_the_probe(self):
        code = _probe_call(('cmp', 'w2, #3'), ('b.hi', '#0x1028'), ('mov', 'x0, #1'), ('ret', ''),
                           ('mov', 'x0, #0'), ('ret', ''))
        domain = (-(1 << 31), 1 << 31)
        with mock.patch('proto.callees.callee_name', _probe_named):
            self.assertEqual(Flow(_Ctx(), code).candidates(-1, 'x2', domain).intervals, [(0, 3)])
        with mock.patch('proto.callees.callee_name', _unnamed):     # a call ends the scan
            self.assertEqual(Flow(_Ctx(), code).candidates(-1, 'x2', domain).intervals, [])


class TestIndirectBranch(unittest.TestCase):

    def test_an_authenticated_branch_has_no_successor(self):
        flow = Flow(None, insns([('braa', 'x16, x17'), ('mov', 'x0, #1'), ('ret', '')]))
        self.assertNotIn(1, flow.propagate({}, [1]))      # the next instruction is not reached

    def test_an_authenticated_call_falls_through(self):
        flow = Flow(None, insns([('blraa', 'x16, x17'), ('mov', 'x0, #1'), ('ret', '')]))
        self.assertIsNotNone(flow.propagate({}, [2]).get(2))


if __name__ == '__main__':
    unittest.main()
