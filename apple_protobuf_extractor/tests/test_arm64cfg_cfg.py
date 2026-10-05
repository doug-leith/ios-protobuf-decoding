"""Synthetic unit tests for the arm64 basic-block CFG + dominators (TODO #42).

No binary needed — hand-built Insn streams exercise build_blocks / dominators /
dominates, the engine the readFrom dispatch resolver uses to attribute each element
`bl` to the field whose handler block DOMINATES it.
"""
import os
import sys
import unittest
from types import SimpleNamespace

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

from proto.arm64cfg import (build_blocks, dominators, dominates, inject_arm_edges,
                            _resolve_offset_addr, _succ_addrs)


def _ins(addr, mn, op=''):
    return SimpleNamespace(addr=addr, mnemonic=mn, op_str=op)


class TestBuildBlocks(unittest.TestCase):
    def test_straightline_single_block(self):
        b = 0x1000
        cfg = build_blocks([_ins(b, 'mov', 'x0, x1'), _ins(b + 4, 'add', 'x0, x0, #1'),
                            _ins(b + 8, 'ret', '')])
        self.assertEqual(cfg.order, [b])
        self.assertEqual(cfg.succ[b], [])

    def test_conditional_splits_two_successors(self):
        b = 0x2000
        cfg = build_blocks([
            _ins(b + 0x0, 'cmp', 'w8, #1'),
            _ins(b + 0x4, 'b.eq', f'#{b + 0x10}'),
            _ins(b + 0x8, 'mov', 'w0, #0'),
            _ins(b + 0xc, 'ret', ''),
            _ins(b + 0x10, 'ret', ''),
        ])
        self.assertEqual(cfg.order, [b, b + 0x8, b + 0x10])
        self.assertEqual(set(cfg.succ[b]), {b + 0x8, b + 0x10})

    def test_unconditional_b_edge_and_tailcall_dropped(self):
        b = 0x3000
        cfg = build_blocks([
            _ins(b + 0x0, 'b', f'#{b + 0x8}'),
            _ins(b + 0x4, 'ret', ''),
            _ins(b + 0x8, 'b', '#0x9999999'),
            _ins(b + 0xc, 'ret', ''),
        ])
        self.assertEqual(cfg.succ[b], [b + 0x8])
        self.assertEqual(cfg.succ[b + 0x8], [])

    def test_succ_addrs_range_guard_drops_out_of_range_b_target(self):
        # test_unconditional_b_edge_and_tailcall_dropped (above) can't discriminate
        # the `lo <= t < hi` range guard on its own: build_blocks's downstream
        # `by_addr`/`addr_to_block` membership check is, by construction, always a
        # subset of [lo, hi) (both are derived from the very same instruction list),
        # so any target that fails the range check ALSO fails that membership check
        # regardless — the range guard can never be independently load-bearing
        # through build_blocks().  Call `_succ_addrs` directly (no build_blocks
        # membership filter downstream) so the range guard alone is what's tested.
        b = 0x3000
        lo, hi = b, b + 0x10
        out_of_range = _ins(b + 0x8, 'b', f'#{hi + 0x1000}')   # tail call, past hi
        self.assertEqual(_succ_addrs(out_of_range, b + 0xc, lo, hi), [])
        in_range = _ins(b + 0x8, 'b', f'#{b + 0xc}')
        self.assertEqual(_succ_addrs(in_range, b + 0xc, lo, hi), [b + 0xc])


class TestDominators(unittest.TestCase):
    def test_diamond_merge_not_dominated_by_arms(self):
        b = 0x4000
        E, L, R, M = b, b + 0x8, b + 0x10, b + 0x18
        cfg = build_blocks([
            _ins(E + 0x0, 'cmp', 'w8, #1'),
            _ins(E + 0x4, 'b.eq', f'#{R}'),
            _ins(L + 0x0, 'mov', 'w0, #1'),
            _ins(L + 0x4, 'b', f'#{M}'),
            _ins(R + 0x0, 'mov', 'w0, #2'),
            _ins(R + 0x4, 'b', f'#{M}'),
            _ins(M + 0x0, 'ret', ''),
        ])
        idom = dominators(cfg)
        self.assertTrue(dominates(idom, E, M))
        self.assertFalse(dominates(idom, L, M))
        self.assertFalse(dominates(idom, R, M))

    def test_forward_branch_handler_dominance(self):
        b = 0x5000
        cfg = build_blocks([
            _ins(b + 0x00, 'cmp', 'w1, #102'),
            _ins(b + 0x04, 'b.ne', f'#{b + 0x20}'),
            _ins(b + 0x08, 'bl', '#0xAAAA'),
            _ins(b + 0x0c, 'b', f'#{b + 0x30}'),
            _ins(b + 0x20, 'bl', '#0xBBBB'),
            _ins(b + 0x24, 'b', f'#{b + 0x30}'),
            _ins(b + 0x30, 'ret', ''),
        ])
        idom = dominators(cfg)
        h102 = cfg.addr_to_block[b + 0x08]
        self.assertTrue(dominates(idom, h102, b + 0x08))
        self.assertFalse(dominates(idom, h102, b + 0x20))


class TestInjectArmEdges(unittest.TestCase):
    def test_br_block_gets_arm_edges(self):
        b = 0x6000
        cfg = build_blocks([
            _ins(b + 0x0, 'br', 'x13'),
            _ins(b + 0x8, 'bl', '#0xAAAA'),
            _ins(b + 0xc, 'ret', ''),
            _ins(b + 0x10, 'bl', '#0xBBBB'),
            _ins(b + 0x14, 'ret', ''),
        ])
        self.assertEqual(cfg.succ[b], [])
        inject_arm_edges(cfg, [b + 0x8, b + 0x10])
        self.assertEqual(set(cfg.succ[b]), {b + 0x8, b + 0x10})
        idom = dominators(cfg)
        self.assertTrue(dominates(idom, cfg.addr_to_block[b + 0x8], b + 0x8))


class TestResolveOffsetAddr(unittest.TestCase):
    """The ivar-offset-variable address held in an offset register, across the
    cache form (`adrp+ldrsw[base,#G]`) and the binary-mode PC-relative LITERAL
    form (`ldrsw x8, #ADDR`)."""

    def test_cache_form_adrp_ldrsw(self):
        # adrp x8,#0x1000; ldrsw x8,[x8,#0x400]  -> 0x1000 + 0x400
        pre = [_ins(0x0, 'adrp', 'x8, #0x1000'),
               _ins(0x4, 'ldrsw', 'x8, [x8, #0x400]')]
        self.assertEqual(_resolve_offset_addr(pre, 'x8', {}), 0x1000 + 0x400)

    def test_binary_literal_form(self):
        # ldrsw x8, #0x1000b7160  -> the immediate IS the offset-var address.
        pre = [_ins(0x0, 'ldrsw', 'x8, #0x1000b7160')]
        self.assertEqual(_resolve_offset_addr(pre, 'x8', {}), 0x1000b7160)

    def test_literal_form_only_matches_target_reg(self):
        # a literal load into a DIFFERENT reg must not resolve x8.
        pre = [_ins(0x0, 'ldrsw', 'x9, #0x1000b7160')]
        self.assertIsNone(_resolve_offset_addr(pre, 'x8', {}))


if __name__ == '__main__':
    unittest.main()
