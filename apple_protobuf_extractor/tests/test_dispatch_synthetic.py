"""Synthetic unit tests for readFrom dispatch helpers — NO real binary.

#2 (post-#11 split): proto/dispatch.py's raw-word decoders (_find_dispatch_cluster,
_find_field_number_register, …) already have synthetic cover in test_readfrom_dispatch.
This adds cover for _arm_calls_own_method, which had ZERO non-live references — the
check that confirms a candidate readFrom core belongs to THIS class because its
jump-table arm bl's into one of the class's own method IMPs.
"""
import os
import sys
import unittest
from types import SimpleNamespace

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

from macho.memory import BinaryContext
from proto.arm64cfg import build_blocks, inject_arm_edges
from proto.dispatch import _arm_calls_own_method, _jump_table_arm_addrs
from tests.conftest import build_text_binary, encode_bl, RET_BYTES


class TestArmCallsOwnMethod(unittest.TestCase):
    V = 0x4000

    def _ctx(self, code):
        return BinaryContext(build_text_binary(code, vmaddr=self.V))

    def test_bl_into_own_imp_is_true(self):
        # arm: `bl +8` (absolute target V+8) ; ret  — and V+8 is an own IMP.
        ctx = self._ctx(encode_bl(8) + RET_BYTES)
        self.assertTrue(_arm_calls_own_method(ctx, self.V, frozenset({self.V + 8})))

    def test_bl_into_foreign_target_is_false(self):
        # The bl target is NOT among own_imps -> the core belongs to a nested message.
        ctx = self._ctx(encode_bl(8) + RET_BYTES)
        self.assertFalse(
            _arm_calls_own_method(ctx, self.V, frozenset({self.V + 0x9999})))

    def test_no_bl_is_false(self):
        ctx = self._ctx(RET_BYTES)
        self.assertFalse(_arm_calls_own_method(ctx, self.V, frozenset({self.V + 8})))

    def test_empty_own_imps_is_false(self):
        ctx = self._ctx(encode_bl(8) + RET_BYTES)
        self.assertFalse(_arm_calls_own_method(ctx, self.V, frozenset()))


class TestWiringBugGuard(unittest.TestCase):
    """#3 robustness: a wiring/refactor bug (NameError/ImportError) inside a guarded
    decoder must PROPAGATE — not be swallowed as a graceful "decode failed" (that's how
    the enums-carve missing-import bug could have hidden). Data-driven failures
    (ValueError) still degrade gracefully."""

    V = 0x4000

    def _ctx_with_bl(self):
        # _find_field_count(ctx, V) == 0 for this synthetic ctx, so _readspecified_and_count
        # falls through to the GUARDED ReadAllFrom hop (iter_bl_targets is hop-only).
        from macho.memory import BinaryContext
        return BinaryContext(build_text_binary(encode_bl(8) + RET_BYTES, vmaddr=self.V))

    def test_nameerror_in_guarded_hop_propagates(self):
        from proto import dispatch as D
        ctx = self._ctx_with_bl()
        orig = D.iter_bl_targets
        D.iter_bl_targets = lambda *a, **k: (_ for _ in ()).throw(NameError("carve bug"))
        try:
            with self.assertRaises(NameError):       # guard re-raises wiring bugs
                D._readspecified_and_count(ctx, self.V)
        finally:
            D.iter_bl_targets = orig

    def test_value_error_in_guarded_hop_swallowed(self):
        # NOTE: this documents the PRE-EXISTING broad `except Exception` (which
        # predates d0c95f4 and would swallow ValueError regardless), not d0c95f4's
        # actual addition -- the NEW `except (NameError, ImportError): raise` clause
        # that must re-raise WIRING bugs instead of masking them as "hop failed".
        # test_nameerror_in_guarded_hop_propagates (above) is what actually
        # regression-guards that addition. Kept here as a pre-existing-behavior
        # guard: a data-driven ValueError must still degrade gracefully.
        from proto import dispatch as D
        ctx = self._ctx_with_bl()
        orig = D.iter_bl_targets
        D.iter_bl_targets = lambda *a, **k: (_ for _ in ()).throw(ValueError("bad data"))
        try:
            # data-driven failure still degrades gracefully
            self.assertEqual(D._readspecified_and_count(ctx, self.V), (None, 0))
        finally:
            D.iter_bl_targets = orig


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
