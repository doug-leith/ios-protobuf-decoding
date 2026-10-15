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

from macho.memory import BinaryContext
from proto.arm64cfg import build_blocks, inject_arm_edges
from proto.dispatch import _jump_table_arm_addrs
from tests.conftest import build_text_binary, encode_bl, RET_BYTES


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
        def read_bytes(self, va, n):
            assert va == 0x2100 and n == 3
            return bytes([0, 1, 200])

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


if __name__ == "__main__":
    unittest.main()
