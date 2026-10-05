"""Synthetic unit tests for the dense enum decode/naming heuristics — NO real binary.

#2 (post-#11 split): the enum harvesters in proto/enums.py previously had only
*live*, skip-if-absent coverage. These hand-build the exact inputs (value-string
pairs, raw ARM64 words) so the decode logic is exercised in every CI run, not only
when a GeoServices cache is present. This is where decode bugs have historically hid.

Targets (each had ZERO non-live test references before this file):
  * _enum_name_from_pairs         — pure: SCREAMING_SNAKE value prefix -> CamelCase type name
  * _dictrep_cmp_range            — the cmp+b.hi/b.hs entry-count gate
  * _find_index_bias              — the leading `sub wN,wM,#bias` (1-based enum adjust)
  * _detect_unrecovered_csel_chain — the branchless if-converted `cmp+csel` chain
                                     idiom none of the three branch-based harvesters
                                     decode (see tests/synthetic_fixtures/README.md's
                                     "isolated-compares" finding — confirmed real via
                                     locationd, just not reachable via any C source on
                                     this repo's installed clang)
  * _detect_unreached_branch_gate — a `cmp+b.ls`/`b.lo` gate whose target lies past
                                     a window that stopped on `ret` — catches a
                                     jump-table segment the window never reached
                                     (confirmed synthetic-toolchain-only, not observed
                                     on real GeoServices/locationd binaries — see the
                                     same README section)
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

from macho.disasm import Insn
from proto.enums import (_enum_name_from_pairs, _dictrep_cmp_range, _find_index_bias,
    _detect_unrecovered_csel_chain, _detect_unreached_branch_gate)


# ── proven ARM64 instruction words (same encodings used by test_readfrom_dispatch) ──
CMP_W8_0xD   = 0x7100351F   # cmp  w8, #0xd
B_HI         = 0x54000048   # b.hi  (cond = HI)
B_HS         = 0x54000042   # b.hs  (cond = HS)
SUB_W8_W1_1  = 0x51000428   # sub  w8, w1, #1     (bias 1)
NOP          = 0xD503201F   # nop
RET          = 0xD65F03C0   # ret
B_PLAIN      = 0x14000010   # b  #+64  (unconditional; NOT a terminal mnemonic)


def _cmp_w2(imm: int) -> int:
    """`cmp w2, #imm` — same _CMP_PATTERN family as CMP_W8_0xD, register 2, imm12."""
    return 0x7100001F | (2 << 5) | ((imm & 0xFFF) << 10)


def _bcond(cond: int, insns_forward: int) -> int:
    """`b.<cond>` targeting `insns_forward` instructions ahead of this one."""
    return 0x54000000 | ((insns_forward & 0x7FFFF) << 5) | cond


_COND_LS = 0x9   # unsigned <=
_COND_LO = 0x3   # unsigned <  (a.k.a. CC)


from tests.conftest import WordCtx as _WordCtx


# ══════════════════════════════════════════════════════════════════════════════
# _enum_name_from_pairs — value-string prefix -> CamelCase enum type name (pure)
# ══════════════════════════════════════════════════════════════════════════════

class TestEnumNameFromPairs(unittest.TestCase):
    def test_multiword_prefix_becomes_camelcase(self):
        # The documented case: MAPS_RESULT_TYPE_* -> "MapsResultType" (better than the
        # ivar-derived fallback "ResultType").
        pairs = [(0, "MAPS_RESULT_TYPE_UNKNOWN"), (1, "MAPS_RESULT_TYPE_PLACE"),
                 (2, "MAPS_RESULT_TYPE_TRANSIT")]
        self.assertEqual(_enum_name_from_pairs(pairs, "ResultType"), "MapsResultType")

    def test_fewer_than_two_pairs_returns_fallback(self):
        self.assertEqual(_enum_name_from_pairs([(0, "FOO_BAR_BAZ")], "Fallback"),
                         "Fallback")

    def test_empty_pairs_returns_fallback(self):
        self.assertEqual(_enum_name_from_pairs([], "Fallback"), "Fallback")

    def test_single_word_common_prefix_returns_fallback(self):
        # common prefix "STATUS" is one word -> no benefit over ivar-derived "Status".
        # NOTE: using fallback="Status" here can't tell the guard's early-return
        # apart from just falling through and capitalizing "STATUS" -- both give
        # "Status" coincidentally. Use an unrelated fallback so the guard's
        # absence would visibly produce the wrong (capitalized-common) name.
        self.assertEqual(
            _enum_name_from_pairs([(0, "STATUS_OK"), (1, "STATUS_FAILED")], "Status"),
            "Status")
        self.assertEqual(
            _enum_name_from_pairs([(0, "STATUS_OK"), (1, "STATUS_FAILED")],
                                  "SomeOtherIvarDerivedName"),
            "SomeOtherIvarDerivedName")

    def test_no_common_prefix_returns_fallback(self):
        self.assertEqual(
            _enum_name_from_pairs([(0, "ALPHA_ONE"), (1, "BETA_TWO")], "Fallback"),
            "Fallback")


# ══════════════════════════════════════════════════════════════════════════════
# _dictrep_cmp_range — entry count from the `cmp wN,#K` + `b.hi`/`b.hs` gate
# ══════════════════════════════════════════════════════════════════════════════

class TestDictrepCmpRange(unittest.TestCase):
    BASE = 0x1000

    def _io(self, gate_word):
        # insns[0]=cmp, insns[1]=gate, insns[2]=dispatch; words keyed by insn addr.
        insns = [Insn(self.BASE + 4 * i, 'unk', '', 4, b'\x00\x00\x00\x00')
                 for i in range(3)]
        words = {self.BASE: CMP_W8_0xD, self.BASE + 4: gate_word}
        return insns, words

    def test_hi_gate_count_is_imm_plus_one(self):
        insns, words = self._io(B_HI)
        self.assertEqual(_dictrep_cmp_range(insns, words, 2), 0xD + 1)   # 14

    def test_hs_gate_count_is_imm(self):
        insns, words = self._io(B_HS)
        self.assertEqual(_dictrep_cmp_range(insns, words, 2), 0xD)

    def test_no_conditional_gate_returns_zero(self):
        insns, words = self._io(NOP)
        self.assertEqual(_dictrep_cmp_range(insns, words, 2), 0)

    def test_no_cmp_in_window_returns_zero(self):
        insns = [Insn(self.BASE + 4 * i, 'unk', '', 4, b'\x00\x00\x00\x00')
                 for i in range(3)]
        words = {self.BASE: NOP, self.BASE + 4: B_HI}   # no cmp
        self.assertEqual(_dictrep_cmp_range(insns, words, 2), 0)


# ══════════════════════════════════════════════════════════════════════════════
# _find_index_bias — leading `sub wN,wM,#bias` before the first CMP
# ══════════════════════════════════════════════════════════════════════════════

class TestFindIndexBias(unittest.TestCase):
    BASE = 0x2000

    def test_sub_before_cmp_returns_bias(self):
        ctx = _WordCtx(self.BASE, [SUB_W8_W1_1, CMP_W8_0xD, RET])
        self.assertEqual(_find_index_bias(ctx, self.BASE), 1)

    def test_no_sub_before_cmp_returns_zero(self):
        ctx = _WordCtx(self.BASE, [NOP, CMP_W8_0xD, RET])
        self.assertEqual(_find_index_bias(ctx, self.BASE), 0)

    def test_cmp_first_stops_scan_zero_bias(self):
        # A sub AFTER the cmp gate must not count (the scan stops at the cmp).
        ctx = _WordCtx(self.BASE, [CMP_W8_0xD, SUB_W8_W1_1, RET])
        self.assertEqual(_find_index_bias(ctx, self.BASE), 0)


# ══════════════════════════════════════════════════════════════════════════════
# _detect_unrecovered_csel_chain — cmp+csel chain (>=2 links) with no branch harvest
# ══════════════════════════════════════════════════════════════════════════════

class TestDetectUnrecoveredCselChain(unittest.TestCase):
    BASE = 0x3000

    def _insns(self, n, csel_at):
        """n plain instructions, with insns[i].mnemonic = 'csel' for i in csel_at."""
        return [Insn(self.BASE + 4 * i,
                     'csel' if i in csel_at else 'cmp',
                     '', 4, b'\x00\x00\x00\x00')
                for i in range(n)]

    def test_two_link_chain_detected(self):
        # cmp #5; csel ...; cmp #9; csel ... -- a real 2-link chain.
        insns = self._insns(4, csel_at={1, 3})
        words = {insns[0].addr: _cmp_w2(5), insns[2].addr: _cmp_w2(9)}
        self.assertTrue(_detect_unrecovered_csel_chain(insns, words))

    def test_single_link_not_a_chain(self):
        # Only one cmp+csel pair -- not enough to call it a CHAIN (the >=2 gate
        # keeps this conservative against an isolated, unrelated csel).
        insns = self._insns(2, csel_at={1})
        words = {insns[0].addr: _cmp_w2(5)}
        self.assertFalse(_detect_unrecovered_csel_chain(insns, words))

    def test_cmp_not_followed_by_csel_ignored(self):
        insns = self._insns(4, csel_at=set())   # no csel anywhere
        words = {insns[0].addr: _cmp_w2(5), insns[2].addr: _cmp_w2(9)}
        self.assertFalse(_detect_unrecovered_csel_chain(insns, words))

    def test_zero_immediate_link_does_not_count(self):
        # cmp #0 is excluded (mirrors _harvest_isolated_compares' own `imm == 0`
        # guard) -- so a zero-imm link plus one real link is still only 1 link.
        insns = self._insns(4, csel_at={1, 3})
        words = {insns[0].addr: _cmp_w2(0), insns[2].addr: _cmp_w2(9)}
        self.assertFalse(_detect_unrecovered_csel_chain(insns, words))

    def test_no_cmp_at_all_returns_false(self):
        insns = self._insns(2, csel_at={1})
        words = {}   # no raw word recorded for the "cmp" instruction
        self.assertFalse(_detect_unrecovered_csel_chain(insns, words))


# ══════════════════════════════════════════════════════════════════════════════
# _detect_unreached_branch_gate — cmp+b.ls/b.lo gate targeting past the window
# ══════════════════════════════════════════════════════════════════════════════

class TestDetectUnreachedBranchGate(unittest.TestCase):
    BASE = 0x4000

    def _insns(self, n, last_mnemonic='ret'):
        insns = [Insn(self.BASE + 4 * i, 'unk', '', 4, b'\x00\x00\x00\x00')
                 for i in range(n)]
        insns[-1] = Insn(insns[-1].addr, last_mnemonic, '', 4, b'\x00\x00\x00\x00')
        return insns

    def test_gate_target_past_window_end_detected(self):
        # cmp w2,#5; b.ls +100 (way past this 4-insn window); ...; ret
        insns = self._insns(4)
        words = {insns[0].addr: _cmp_w2(5),
                 insns[1].addr: _bcond(_COND_LS, 100)}
        self.assertTrue(_detect_unreached_branch_gate(insns, words))

    def test_gate_target_within_window_not_flagged(self):
        # b.ls targets insns[2], which IS inside the disassembled window.
        insns = self._insns(4)
        words = {insns[0].addr: _cmp_w2(5),
                 insns[1].addr: _bcond(_COND_LS, 1)}
        self.assertFalse(_detect_unreached_branch_gate(insns, words))

    def test_lo_condition_also_detected(self):
        insns = self._insns(4)
        words = {insns[0].addr: _cmp_w2(5),
                 insns[1].addr: _bcond(_COND_LO, 100)}
        self.assertTrue(_detect_unreached_branch_gate(insns, words))

    def test_window_not_ending_in_ret_not_flagged(self):
        # Real Apple codegen funnels every case to a SHARED epilogue via a
        # plain `b`, not its own `ret` -- confirmed against
        # GEOTelemetricEntity.eventKeyAsString: (see README). A window ending
        # in a non-terminal (e.g. `b`) means the probe simply hasn't hit the
        # function's real end yet, which is not this detector's concern.
        insns = self._insns(4, last_mnemonic='b')
        words = {insns[0].addr: _cmp_w2(5),
                 insns[1].addr: _bcond(_COND_LS, 100)}
        self.assertFalse(_detect_unreached_branch_gate(insns, words))

    def test_no_ls_lo_gate_not_flagged(self):
        # b.hi (not LS/LO) is the "fall-through gate" idiom, not a
        # comparison-tree ROUTING branch -- out of scope for this detector.
        insns = self._insns(4)
        words = {insns[0].addr: _cmp_w2(5), insns[1].addr: B_HI}
        self.assertFalse(_detect_unreached_branch_gate(insns, words))

    def test_empty_insns_returns_false(self):
        self.assertFalse(_detect_unreached_branch_gate([], {}))


if __name__ == "__main__":
    unittest.main()
