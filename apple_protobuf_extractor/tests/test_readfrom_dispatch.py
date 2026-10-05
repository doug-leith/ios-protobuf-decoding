"""
Tests for the principled ``repeated <message>`` element-type resolver
(``proto/extractor.py``): the readFrom: field-dispatch jump-table walk that names
each repeated field's element class by the ReadAllFrom callee address its
dispatch arm invokes.

Two layers:

* **Synthetic** — the raw-word dispatch-cluster decoder
  (``_find_dispatch_cluster``), which the native arm64 mini-decoder cannot reach
  because ``adr`` and the register-offset ``ldrh`` render as ``unk``.
* **Live** — the full resolver against the real GeoServices cache, gated on the
  cache being present.  Ground truth (cross-checked against the hand-decoded
  ``GEOPDPlaceResponse.proto``): ``GEOPDComponent.values`` (field 8) ->
  ``GEOPDComponentValue`` and ``GEOPDComponent.commingledAttributions``
  (field 14) -> ``GEOPDAttribution`` — both of which the name-suffix heuristics
  mis-resolve to ``repeated bytes``.
"""

import os
import artifacts
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

import struct

from macho.arm64decode import _decode_bcond_target, _decode_lsr_imm
from proto.dispatch import (_core_resolves_compare_chain, _dominance_field_of,
    _decode_readfrom_jumptable, _find_dispatch_cluster,
    _find_field_number_register, _func_end, _walk_jumptable_arms,
    _classref_class_name, _core_insns, _core_loads_own_ivar_slot)


# ══════════════════════════════════════════════════════════════════════════════
# Synthetic dispatch-cluster decoder (no binary needed)
# ══════════════════════════════════════════════════════════════════════════════

from tests.conftest import (WordCtx as _WordCtx, build_text_binary, encode_bl,
    encode_b, encode_adrp, encode_add_imm64, encode_ldr_imm64, RET_BYTES, NOP_BYTES,
    put_ptr)
from macho.memory import BinaryContext


def _int_word(encoded_bytes: bytes) -> int:
    """Unpack a conftest ``encode_*`` helper's 4-byte little-endian result back
    to a raw instruction word, for use in a `WordCtx` word list."""
    return struct.unpack('<I', encoded_bytes)[0]


class TestFindDispatchCluster(unittest.TestCase):
    """Recover (ARM_BASE, count, table_reg, entry_size, bias, br_va) from raw words."""

    BASE = 0x1000

    # The canonical cluster, one 4-byte word per instruction:
    #   sub  w8, w1, #1        ; bias = 1 (table entry i serves field 1 + i)
    #   cmp  w8, #0xd          ; field-count gate => count = 0xd + 1 = 14
    #   b.hi <oob>             ; HI condition
    #   adr  x9, #+0x10        ; ARM_BASE = va(adr) + 0x10
    #   ldrh w10,[x15,x8,lsl#1]; table reg x15, 2-byte entries
    #   nop                    ; stand-in for `add x9,x9,x10,lsl#2` (decoded as unk)
    #   br   x9
    WORDS = [
        0x51000428,   # sub  w8, w1, #1
        0x7100351f,   # cmp  w8, #0xd
        0x54000048,   # b.hi #+8   (cond = HI)
        0x10000089,   # adr  x9, #+0x10
        0x786879ea,   # ldrh w10, [x15, x8, lsl #1]
        0xd503201f,   # nop  (placeholder for the shifted-register add)
        0xd61f0120,   # br   x9
    ]

    def test_cluster_fields_recovered(self):
        ctx = _WordCtx(self.BASE, self.WORDS)
        result = _find_dispatch_cluster(ctx, self.BASE)
        self.assertIsNotNone(result)
        arm_base, count, table_reg, entry_size, bias, _br_va = result
        # adr is word index 3 -> va = BASE + 12; target = va + 0x10.
        self.assertEqual(arm_base, self.BASE + 12 + 0x10)
        self.assertEqual(count, 14)            # 0xd + 1 (b.hi)
        self.assertEqual(table_reg, 15)        # x15
        self.assertEqual(entry_size, 2)        # ldrh -> 2 bytes
        self.assertEqual(bias, 1)              # sub w8, w1, #1

    def test_high_bias_recovered(self):
        # ALSLocationResponse-style: the table covers a high contiguous range,
        # so the feeding sub subtracts a large bias (0x15 = 21).
        words = list(self.WORDS)
        words[0] = 0x51005428            # sub w8, w1, #0x15
        ctx = _WordCtx(self.BASE, words)
        _arm, _count, _reg, _esz, bias, _br_va = _find_dispatch_cluster(ctx, self.BASE)
        self.assertEqual(bias, 0x15)

    def test_missing_sub_yields_zero_bias(self):
        # No feeding sub -> bias 0 (caller bails rather than risk a wrong join).
        words = list(self.WORDS)
        words[0] = 0xd503201f            # nop in place of the sub
        ctx = _WordCtx(self.BASE, words)
        _arm, _count, _reg, _esz, bias, _br_va = _find_dispatch_cluster(ctx, self.BASE)
        self.assertEqual(bias, 0)

    def test_hs_condition_uses_imm_directly(self):
        # b.hs (cond = 0x2) means count = imm (not imm + 1).
        words = list(self.WORDS)
        words[2] = 0x54000042            # b.hs #+8  (low nibble = 0x2 = HS)
        ctx = _WordCtx(self.BASE, words)
        _arm, count, _reg, _esz, _bias, _br_va = _find_dispatch_cluster(ctx, self.BASE)
        self.assertEqual(count, 0xd)

    def test_no_br_returns_none(self):
        ctx = _WordCtx(self.BASE, self.WORDS[:-1])   # drop the br
        self.assertIsNone(_find_dispatch_cluster(ctx, self.BASE))

    def test_br_without_preceding_adr_skipped(self):
        # A br with no adr in the preceding window is not a dispatch cluster.
        words = [0xd503201f, 0xd503201f, 0xd61f0120]   # nop; nop; br x9
        ctx = _WordCtx(self.BASE, words)
        self.assertIsNone(_find_dispatch_cluster(ctx, self.BASE))


class TestFindDispatchClusterFunctionBoundary(unittest.TestCase):
    """_find_dispatch_cluster's raw-word scan must stop at the function's own
    boundary (a `ret` followed by the next function's prologue), not keep
    scanning into whatever unrelated code follows in memory.

    Regression test for the function-boundary fix (commit 3fe1f1d): found by
    direct disassembly when a recursive candidate search on GEOLPRWorld's
    engine reached a ~40-instruction function ending in a `ret`, and the
    (then-unbounded) scan continued ~300 more instructions past it into an
    unrelated function that happened to contain a fully-formed, valid-looking
    dispatch cluster -- returning that unrelated cluster as if it belonged to
    the short function, rather than correctly finding nothing."""

    BASE = 0x1000

    # A short function: one filler instruction, then `ret`.
    SHORT_FUNC = [
        0xd503201f,   # nop
        0xd65f03c0,   # ret
    ]

    # An unrelated function immediately following in memory: a real prologue
    # opener, then the exact canonical cluster from TestFindDispatchCluster
    # (proven independently, above, to be recognized correctly on its own).
    NEXT_FUNC = [
        0xd503237f,   # pacibsp             -- function-prologue opener
        0x51000428,   # sub  w8, w1, #1
        0x7100351f,   # cmp  w8, #0xd
        0x54000048,   # b.hi #+8
        0x10000089,   # adr  x9, #+0x10
        0x786879ea,   # ldrh w10, [x15, x8, lsl #1]
        0xd503201f,   # nop  (placeholder for the shifted-register add)
        0xd61f0120,   # br   x9
    ]

    def test_scan_stops_at_ret_and_does_not_adopt_next_functions_cluster(self):
        words = self.SHORT_FUNC + self.NEXT_FUNC
        ctx = _WordCtx(self.BASE, words)
        self.assertIsNone(_find_dispatch_cluster(ctx, self.BASE))

    def test_next_functions_own_cluster_is_still_found_from_its_own_start(self):
        # Sanity check: the NEXT_FUNC words are themselves a valid cluster --
        # the fix must stop the scan at the boundary, not break recognition
        # of a genuine cluster reached from its own function's start.
        words = self.SHORT_FUNC + self.NEXT_FUNC
        ctx = _WordCtx(self.BASE, words)
        next_func_va = self.BASE + len(self.SHORT_FUNC) * 4
        result = _find_dispatch_cluster(ctx, next_func_va)
        self.assertIsNotNone(result)
        self.assertEqual(result[4], 1)   # bias, from `sub w8, w1, #1`


class TestDecodeReadfromJumptableTableBaseAliasing(unittest.TestCase):
    """_decode_readfrom_jumptable must resolve a cluster's table-base
    adrp+add as the LAST such pair at or before its OWN `br` -- not the first
    one anywhere in the function.

    Regression test for the reaching-definition fix (commit a2d12f6): a
    ReadSpecified engine holding two separate br-based jump-table clusters
    that both compute their table base via adrp+add into the SAME scratch
    register (x17, the ARM64 IP1 intra-procedure-call scratch register
    conventionally reused for this) previously always resolved to the FIRST
    cluster's table address, silently misreading every arm of any LATER
    cluster reusing that register (observed live on GEORPFeedbackDetails)."""

    BASE = 0x1000
    TABLE_A = 0x5100   # cluster A's own table -- must NEVER be read for cluster B
    TABLE_B = 0x6200   # cluster B's own table -- the one under test

    def _build_ctx(self):
        words = [
            _int_word(encode_adrp(17, 4)),               # 0x1000: adrp x17, #0x5000
            _int_word(encode_add_imm64(17, 17, 0x100)),  # 0x1004: add  x17,x17,#0x100 -> 0x5100
        ]
        words += [0xd503201f] * 28                       # 0x1008..0x1074: filler (cluster A's body)
        words += [
            _int_word(encode_adrp(17, 5)),                # 0x1078: adrp x17, #0x6000
            _int_word(encode_add_imm64(17, 17, 0x200)),   # 0x107c: add  x17,x17,#0x200 -> 0x6200
            0xd65f03c0,                                    # 0x1080: ret
        ]
        ctx = _WordCtx(self.BASE, words)
        # Cluster A's table: deltas that would produce a plausible-looking but
        # WRONG result if the table-base search weren't scoped to cluster B.
        ctx._m[self.TABLE_A + 0] = 0x30
        ctx._m[self.TABLE_A + 4] = 0x40
        # Cluster B's own table -- the correct answer.
        ctx._m[self.TABLE_B + 0] = 0x10
        ctx._m[self.TABLE_B + 4] = 0x20
        return ctx

    def test_resolves_own_table_not_an_earlier_clusters(self):
        ctx = self._build_ctx()
        br_va = self.BASE + 32 * 4   # the `ret`'s address: both adrp+add pairs precede it
        cluster_b = (self.BASE, 2, 17, 4, 1, br_va)
        arms = _decode_readfrom_jumptable(ctx, self.BASE, 2, cluster=cluster_b)
        self.assertEqual(arms, {1: self.BASE + 0x10, 2: self.BASE + 0x20})


class TestWalkJumptableArmsClassrefFallback(unittest.TestCase):
    """``_walk_jumptable_arms`` must resolve a field's element class from an
    explicit classref load (``adrp+ldr`` resolving via ``ctx.bind_name_for``)
    when the arm's ``bl`` target isn't in ``core_index`` -- the newer
    toolchain's shape where an arm calls a GENERIC, ivar-offset-parameterized
    helper (``[ElementClass alloc]`` reached indirectly) instead of the
    element class's own ReadAllFrom core directly.

    Regression test for the classref fallback (commit 4e28a64): the arm loads
    a classref for its element class right before a `bl` to a shared helper
    whose OWN address means nothing in `core_index` (it may even collide with
    an unrelated class, per _build_readfrom_core_index's "first wins" note) --
    only the classref itself names the real element class."""

    ARM_VA = 0x9000                    # page-aligned, so pages_delta below is exact
    CLASSREF_SLOT = 0xA018             # holds the [ElementClass alloc] classref
    _CLASSREF_PAGES_DELTA = (0xA000 - 0x9000) // 0x1000   # == 1

    def _build_ctx(self):
        words = [
            # adrp x0, #0xa000
            _int_word(encode_adrp(0, self._CLASSREF_PAGES_DELTA)),
            # ldr x1, [x0, #0x18]  -- the classref itself
            _int_word(encode_ldr_imm64(1, 0, self.CLASSREF_SLOT & 0xFFF)),
            0x9413dbfe,   # bl #0x500000 -- a generic helper, NOT in core_index
            0xd65f03c0,   # ret
        ]
        ctx = _WordCtx(self.ARM_VA, words)
        ctx._binds = {self.CLASSREF_SLOT: 'GEOSomeClass'}
        return ctx

    def test_resolves_element_class_from_classref_not_bl_target(self):
        ctx = self._build_ctx()
        arms = {1: self.ARM_VA}
        core_index = {0x77777: 'GEOSomeClass'}   # 'GEOSomeClass' is a KNOWN proto class,
                                                  # at some unrelated address -- the bl's
                                                  # own target (0x500000) is deliberately
                                                  # absent from core_index.
        result = _walk_jumptable_arms(ctx, arms, core_index)
        self.assertEqual(result, {1: 'GEOSomeClass'})

    def test_classref_to_unknown_class_is_not_resolved(self):
        # The classref itself doesn't make a name trustworthy -- it must also
        # be a name core_index already recognizes as a real proto class in
        # this binary (rules out an unrelated classref cached for another
        # purpose in the same arm).
        ctx = self._build_ctx()
        arms = {1: self.ARM_VA}
        core_index = {0x77777: 'GEOSomeOtherClass'}   # 'GEOSomeClass' NOT among the
                                                       # known classes this time.
        result = _walk_jumptable_arms(ctx, arms, core_index)
        self.assertEqual(result, {})


class TestClassrefClassName(unittest.TestCase):
    """``_classref_class_name`` names the class a classref slot points at, for
    both shapes a real image has: an EXTERNAL/bound class (``bind_name_for``,
    with binary mode's ``_OBJC_CLASS_$_`` prefix) and, in binary mode, a class
    defined in the SAME image, whose slot is a plain rebase to a ``class_t``
    (``bind_name_for`` knows nothing of it, so the name is read through
    ``class_t.data -> class_ro_t.name``).

    Regression test for the binary-mode local-class path (found by the
    compiled f25 fixture; before it the classref fallback silently never fired
    for a standalone binary/dylib whose element classes are its own)."""

    SLOT = 0xA018            # the __objc_classrefs entry
    CLASS_T = 0xB000         # the class_t it points at
    RO = 0xC000              # class_ro_t
    NAME = 0xD000            # the name C string

    def _ctx(self):
        ctx = _WordCtx(0x1000, [0xd65f03c0])
        ctx._binds = {}
        ctx._strings = {self.NAME: 'GEOLocalClass'}
        return ctx

    def _link_local_class(self, ctx, data_tag_bits=0):
        put_ptr(ctx, self.SLOT, self.CLASS_T)
        # class_t.data (+32) carries the low tag bits the runtime ORs in
        # (FAST_IS_SWIFT etc.); they must be masked off to reach class_ro_t.
        put_ptr(ctx, self.CLASS_T + 32, self.RO | data_tag_bits)
        put_ptr(ctx, self.RO + 24, self.NAME)             # class_ro_t.name

    def test_bound_class_has_binary_mode_prefix_stripped(self):
        ctx = self._ctx()
        ctx._binds[self.SLOT] = '_OBJC_CLASS_$_GEOExternal'
        self.assertEqual(_classref_class_name(ctx, self.SLOT), 'GEOExternal')

    def test_bound_class_without_prefix_is_returned_as_is(self):
        # cache mode's bind_name_for already returns a bare class name
        ctx = self._ctx()
        ctx._binds[self.SLOT] = 'GEOExternal'
        self.assertEqual(_classref_class_name(ctx, self.SLOT), 'GEOExternal')

    def test_local_class_named_via_class_ro(self):
        ctx = self._ctx()
        self._link_local_class(ctx)
        self.assertEqual(_classref_class_name(ctx, self.SLOT), 'GEOLocalClass')

    def test_local_class_data_tag_bits_are_masked(self):
        ctx = self._ctx()
        self._link_local_class(ctx, data_tag_bits=0x3)
        self.assertEqual(_classref_class_name(ctx, self.SLOT), 'GEOLocalClass')

    def test_bind_wins_over_a_local_chain(self):
        ctx = self._ctx()
        self._link_local_class(ctx)
        ctx._binds[self.SLOT] = '_OBJC_CLASS_$_GEOExternal'
        self.assertEqual(_classref_class_name(ctx, self.SLOT), 'GEOExternal')

    def test_null_or_unmapped_slot_is_none(self):
        ctx = self._ctx()
        self.assertIsNone(_classref_class_name(ctx, self.SLOT))   # unmapped
        put_ptr(ctx, self.SLOT, 0)
        self.assertIsNone(_classref_class_name(ctx, self.SLOT))   # null pointer

    def test_broken_chain_is_none(self):
        # slot -> class_t exists but class_t.data was never mapped
        ctx = self._ctx()
        put_ptr(ctx, self.SLOT, self.CLASS_T)
        self.assertIsNone(_classref_class_name(ctx, self.SLOT))

    def test_walk_jumptable_arms_resolves_a_local_class_classref(self):
        """End to end through the arm walker: the arm's classref is a LOCAL
        class (no bind entry at all) and only the class_t chain names it."""
        arm_va = 0x9000
        ctx = _WordCtx(arm_va, [
            _int_word(encode_adrp(0, 1)),                  # adrp x0, #0xa000
            _int_word(encode_ldr_imm64(1, 0, self.SLOT & 0xFFF)),  # ldr x1,[x0,#0x18]
            0x9413dbfe,                                    # bl #0x500000 (generic helper)
            0xd65f03c0,                                    # ret
        ])
        ctx._binds = {}
        ctx._strings = {self.NAME: 'GEOLocalClass'}
        self._link_local_class(ctx)
        core_index = {0x77777: 'GEOLocalClass'}
        self.assertEqual(
            _walk_jumptable_arms(ctx, {1: arm_va}, core_index),
            {1: 'GEOLocalClass'})


class TestCoreInsnsExtent(unittest.TestCase):
    """``_core_insns`` bounds a function TIGHTLY: it ends at the first
    ``ret``/unconditional branch at or beyond every forward CONDITIONAL branch
    target seen so far.  Every word is capstone-verified (trailing comment).

    Regression tests for the extent the ownership check
    (``_core_loads_own_ivar_slot``) relies on.  The looser CFG-reachability
    ``_func_end`` credits a plain-arm64 function that ends in a tail call
    (``b <stub>``) with the stub island and every function in between — found
    when the f27 fixture's engine appeared to load the ivars of the classes laid
    out after it."""

    BASE = 0x1000

    def _addrs(self, words):
        ctx = _WordCtx(self.BASE, words)
        return [i.addr for i in _core_insns(ctx, self.BASE)]

    def test_out_of_line_block_after_a_tail_branch_is_kept(self):
        # The layout the compiler produces for hoisted-has-bits gating: a
        # conditional branch jumps to a block placed after the epilogue's tail
        # `b`, which therefore must NOT end the function.
        addrs = self._addrs([
            0x37000088,   # 0x1000 tbnz w8, #0, #0x1010   (frontier -> 0x1010)
            0xaa0103e0,   # 0x1004 mov  x0, x1
            0x14001ffe,   # 0x1008 b    #0x9000           (tail call; before frontier)
            0xd503201f,   # 0x100c nop
            0xaa0203e0,   # 0x1010 mov  x0, x2            (the out-of-line block)
            0xd65f03c0,   # 0x1014 ret                    <- ends here
            0xaa0903e9,   # 0x1018 mov  x9, x9            (next function)
        ])
        self.assertEqual(addrs[-1], 0x1014)
        self.assertNotIn(0x1018, addrs)

    def test_plain_tail_call_ends_the_function(self):
        addrs = self._addrs([
            0xaa0103e0,   # 0x1000 mov x0, x1
            0x14001fff,   # 0x1004 b   #0x9000            (tail call: ends here)
            0xaa0903e9,   # 0x1008 mov x9, x9             (next function)
            0xaa0a03ea,   # 0x100c mov x10, x10
        ])
        self.assertEqual(addrs, [0x1000, 0x1004])

    def test_ret_before_a_pending_branch_target_does_not_end_it(self):
        addrs = self._addrs([
            0x37000088,   # 0x1000 tbnz w8, #0, #0x1010
            0xd65f03c0,   # 0x1004 ret                    (early exit path)
            0xd503201f,   # 0x1008 nop
            0xd503201f,   # 0x100c nop
            0xaa0203e0,   # 0x1010 mov x0, x2
            0xd65f03c0,   # 0x1014 ret                    <- the real end
            0xaa0903e9,   # 0x1018 mov x9, x9
        ])
        self.assertEqual(addrs[-1], 0x1014)

    def test_unconditional_forward_branch_is_not_a_frontier(self):
        # `b #0x1010` might be a merge jump or a tail call; either way it must
        # not extend the function — the cost is an under-run, the safe direction.
        addrs = self._addrs([
            0xaa0103e0,   # 0x1000 mov x0, x1
            0x14000003,   # 0x1004 b   #0x1010            <- ends here (under-run)
            0xd65f03c0,   # 0x1008 ret
            0xd503201f,   # 0x100c nop
            0xaa0203e0,   # 0x1010 mov x0, x2
            0xd65f03c0,   # 0x1014 ret
        ])
        self.assertEqual(addrs, [0x1000, 0x1004])


class TestCoreLoadsOwnIvarSlot(unittest.TestCase):
    """``_core_loads_own_ivar_slot``: does the function load one of THIS class's
    own ivar-offset variables?  Identity is by slot ADDRESS, and it fails
    closed.  Regression test for the ownership corroboration that lets the
    compare-chain tier accept a guard-less engine (newest arm64e builds)."""

    BASE = 0x1000
    OWN_SLOT = 0x5020
    WORDS = [
        0x90000028,   # 0x1000 adrp  x8, #0x5000
        0xb9802108,   # 0x1004 ldrsw x8, [x8, #0x20]    -> slot 0x5020
        0xd65f03c0,   # 0x1008 ret
    ]

    def _ctx(self, slot_value=8):
        ctx = _WordCtx(self.BASE, self.WORDS)
        ctx._m[self.OWN_SLOT] = slot_value       # the ivar's OFFSET, e.g. 8
        return ctx

    def test_loading_an_own_slot_confirms(self):
        self.assertTrue(_core_loads_own_ivar_slot(
            self._ctx(), self.BASE, frozenset({self.OWN_SLOT})))

    def test_identity_is_by_address_not_by_offset_value(self):
        # Another class's ivar-offset variable at a DIFFERENT address that holds
        # the SAME offset value (8) must not confirm — small offsets collide
        # across classes constantly.
        self.assertFalse(_core_loads_own_ivar_slot(
            self._ctx(slot_value=8), self.BASE, frozenset({0x5024})))

    def test_fails_closed_when_own_slots_unknown(self):
        self.assertFalse(_core_loads_own_ivar_slot(
            self._ctx(), self.BASE, frozenset()))

    def test_slot_load_after_the_functions_end_does_not_count(self):
        # A tail-called neighbour's slot load must not be credited to this
        # function: the scan stops at the `ret`.
        ctx = _WordCtx(self.BASE, self.WORDS + [
            0x90000028,   # 0x100c adrp  x8, #0x5000        (the NEXT function)
            0xb9802908,   # 0x1010 ldrsw x8, [x8, #0x28]    -> slot 0x5028
            0xd65f03c0,   # 0x1014 ret
        ])
        self.assertFalse(_core_loads_own_ivar_slot(
            ctx, self.BASE, frozenset({0x5028})))


# ══════════════════════════════════════════════════════════════════════════════
# Compare-chain dispatch decoders (the few-field / hybrid encoding)
# ══════════════════════════════════════════════════════════════════════════════

class TestDecodeLsrImm(unittest.TestCase):
    """`_decode_lsr_imm` decodes the `field# = tag >> 3` derivation."""

    def test_decode_64bit_lsr_x23_x8_3(self):
        # lsr x23, x8, #3  (UBFM 64-bit, immr=3, imms=63) — the real GeoServices
        # GEOPDPlaceGlobalCommonResult field-number derivation word.
        self.assertEqual(_decode_lsr_imm(0xD343FD17), (23, 8, 3))

    def test_decode_32bit_lsr_w0_w1_3(self):
        # lsr w0, w1, #3  (UBFM 32-bit, immr=3, imms=31)
        self.assertEqual(_decode_lsr_imm(0x53037C20), (0, 1, 3))

    def test_non_lsr_returns_none(self):
        self.assertIsNone(_decode_lsr_imm(0xD503201F))   # nop
        self.assertIsNone(_decode_lsr_imm(0x7100351F))   # cmp w8,#0xd

    def test_ubfm_that_is_not_an_lsr_alias_rejected(self):
        # 64-bit UBFM with imms != 63 is a bitfield extract, not lsr → None.
        self.assertIsNone(_decode_lsr_imm(0xD3400000 | (3 << 16) | (10 << 10)))


class TestFindFieldNumberRegister(unittest.TestCase):
    """`_find_field_number_register` locates the unique `tag >> 3` destination."""

    BASE = 0x2000

    def _ctx(self, words):
        return _WordCtx(self.BASE, words)

    def test_unique_lsr3_destination_returned(self):
        words = [0xD503201F, 0xD343FD17, 0xD503201F]   # nop; lsr x23,x8,#3; nop
        ctx = self._ctx(words)
        self.assertEqual(
            _find_field_number_register(ctx, self.BASE, self.BASE + 4 * 3), 23)

    def test_no_lsr3_returns_none(self):
        words = [0xD503201F, 0x7100351F, 0xD503201F]   # no shift-by-3
        ctx = self._ctx(words)
        self.assertIsNone(
            _find_field_number_register(ctx, self.BASE, self.BASE + 4 * 3))

    def test_ambiguous_multiple_destinations_returns_none(self):
        # lsr x23,x8,#3  and  lsr x9,x8,#3 → two distinct field# regs → ambiguous.
        lsr_x9 = (0xD3400000 | (3 << 16) | (63 << 10) | (8 << 5) | 9)
        words = [0xD343FD17, lsr_x9]
        ctx = self._ctx(words)
        self.assertIsNone(
            _find_field_number_register(ctx, self.BASE, self.BASE + 4 * 2))

    def test_lsr_by_other_shift_ignored(self):
        # lsr x23,x8,#4 is not the tag>>3 idiom → not counted.
        lsr4 = (0xD3400000 | (4 << 16) | (63 << 10) | (8 << 5) | 23)
        ctx = self._ctx([lsr4])
        self.assertIsNone(
            _find_field_number_register(ctx, self.BASE, self.BASE + 4))


class TestWrapperRawWordDecoders(unittest.TestCase):
    """Raw-word decoders used to bound and scan a ReadAllFrom wrapper for the
    call to its separate dispatch core (no binary needed)."""

    def test_decode_bl_forward(self):
        from macho.arm64decode import _decode_b_bl_target
        # bl #+0x10 : imm26 = 4
        word = 0x94000000 | 0x4
        self.assertEqual(_decode_b_bl_target(word, 0x1000), 0x1010)

    def test_decode_b_backward(self):
        from macho.arm64decode import _decode_b_bl_target
        # b #-0x10 : imm26 = -4 (0x03FFFFFC)
        word = 0x14000000 | 0x03FFFFFC
        self.assertEqual(_decode_b_bl_target(word, 0x1000), 0x0FF0)

    def test_decode_non_branch_is_none(self):
        from macho.arm64decode import _decode_b_bl_target
        self.assertIsNone(_decode_b_bl_target(0xD503201F, 0x1000))   # nop

    def test_ret_words(self):
        from macho.arm64decode import _is_ret_word
        self.assertTrue(_is_ret_word(0xD65F03C0))   # ret
        self.assertTrue(_is_ret_word(0xD65F0BFF))   # retaa
        self.assertTrue(_is_ret_word(0xD65F0FFF))   # retab
        self.assertFalse(_is_ret_word(0xD61F0000))  # br (indirect, not ret)

    def test_func_prologue_words(self):
        from macho.arm64decode import _is_func_prologue_word
        self.assertTrue(_is_func_prologue_word(0xD10143FF))   # sub sp, sp, #0x50
        self.assertTrue(_is_func_prologue_word(0xA9BF7BFD))   # stp x29,x30,[sp,#-0x10]!
        self.assertTrue(_is_func_prologue_word(0xD503237F))   # pacibsp
        self.assertTrue(_is_func_prologue_word(0xD503233F))   # paciasp
        self.assertFalse(_is_func_prologue_word(0xD503201F))  # nop
        self.assertFalse(_is_func_prologue_word(0x94000004))  # bl
        self.assertFalse(_is_func_prologue_word(0xD50323FF))  # autibsp (epilogue, not prologue)


class TestCompareChainBlocks(unittest.TestCase):
    """Control-flow block attribution for the compare-chain dispatch decoder
    (no binary needed).  Guards against the linear-adjacency regression where a
    forward-branched handler was mis-tagged with the textually-preceding field."""

    @staticmethod
    def _cmp(rn, imm):                       # cmp wRn, #imm  (SUBS WZR,Wn,#imm)
        return 0x7100001F | ((imm & 0xFFF) << 10) | ((rn & 0x1F) << 5)

    @staticmethod
    def _bcond(cond, va, target):            # b.cond target
        imm19 = ((target - va) // 4) & 0x7FFFF
        return 0x54000000 | (imm19 << 5) | (cond & 0xF)

    def test_decode_bcond_target_forward(self):
        # b.eq +0x1C from 0x1000
        word = self._bcond(0x0, 0x1000, 0x101C)
        self.assertEqual(_decode_bcond_target(word, 0x1000), 0x101C)

    def test_decode_bcond_target_backward(self):
        word = self._bcond(0x1, 0x1000, 0x0FF0)   # b.ne -0x10
        self.assertEqual(_decode_bcond_target(word, 0x1000), 0x0FF0)

    def test_decode_bcond_target_rejects_non_bcond(self):
        self.assertIsNone(_decode_bcond_target(0x94000004, 0x1000))  # bl


# ══════════════════════════════════════════════════════════════════════════════
# Dominance-based field attribution (_dominance_field_of / _core_resolves_compare_chain)
#
# Replaces the old address-range decoder (_compare_chain_blocks / _field_for_addr,
# retired) as the sole compare-chain field-attribution mechanism — the same one
# proto/repeated.py's element/ivar resolvers already used.  Built on REAL compiled
# arm64 machine code (via tests.conftest.build_text_binary + a real BinaryContext),
# not raw words, since _dominance_field_of disassembles through capstone (it needs
# real Insn objects to build the CFG), unlike the old raw-word scanner.
# ══════════════════════════════════════════════════════════════════════════════

def _enc_lsr_x(rd, rn):
    """lsr xRd, xRn, #3 (UBFM 64-bit, immr=3, imms=63) — the field# = tag>>3 idiom."""
    import struct
    return struct.pack('<I', 0xD3400000 | (3 << 16) | (63 << 10)
                       | ((rn & 0x1F) << 5) | (rd & 0x1F))


def _enc_cmp(rn, imm):
    """cmp wRn, #imm (SUBS WZR, Wn, #imm)."""
    import struct
    return struct.pack('<I', 0x7100001F | ((imm & 0xFFF) << 10) | ((rn & 0x1F) << 5))


def _enc_bcond(cond, pc, target):
    """b.cond target, encoded relative to *pc* (this instruction's own address)."""
    import struct
    imm19 = ((target - pc) // 4) & 0x7FFFF
    return struct.pack('<I', 0x54000000 | (imm19 << 5) | (cond & 0xF))


_COND_EQ, _COND_NE = 0x0, 0x1


class TestDominanceFieldAttribution(unittest.TestCase):
    """Mirror GEOPDExternalAction: field 2 is a FORWARD b.eq block placed at a
    higher address than the field-1 b.ne fall-through.  Dominance attribution must
    map field 2 -> the forward target, field 1 -> the fall-through — NOT bind the
    field-2 block to the textually-nearer `cmp #1` (the bug the whole compare-chain
    field-attribution mechanism exists to avoid)."""

    VMADDR = 0x4000

    @classmethod
    def setUpClass(cls):
        base = cls.VMADDR
        cls.core1 = base + 0x1000    # arbitrary "known ReadAllFrom" addresses,
        cls.core2 = base + 0x2000    # far enough away to not overlap the body

        code = b''
        code += _enc_lsr_x(23, 8)                                    # 0x00  field_reg = 23
        code += _enc_cmp(23, 2)                                      # 0x04  cmp w23,#2
        code += _enc_bcond(_COND_EQ, base + 0x08, base + 0x24)       # 0x08  b.eq FWD (field 2)
        code += _enc_cmp(23, 1)                                      # 0x0c  cmp w23,#1
        code += _enc_bcond(_COND_NE, base + 0x10, base + 0x2c)       # 0x10  b.ne ELSE (field 1 = fall-through)
        code += encode_bl(cls.core1 - (base + 0x14))                 # 0x14  bl CORE1 (field 1's element)
        code += encode_b((base + 0x30) - (base + 0x18))              # 0x18  b MERGE
        code += NOP_BYTES                                             # 0x1c  (padding)
        code += NOP_BYTES                                             # 0x20  (padding)
        code += encode_bl(cls.core2 - (base + 0x24))                 # 0x24  FWD: bl CORE2 (field 2's element)
        code += encode_b((base + 0x30) - (base + 0x28))              # 0x28  b MERGE
        code += NOP_BYTES                                             # 0x2c  ELSE
        code += RET_BYTES                                             # 0x30  MERGE: ret

        cls.bl1_addr = base + 0x14   # field 1's element call (fall-through handler)
        cls.bl2_addr = base + 0x24   # field 2's element call (forward handler)
        cls.ctx = BinaryContext(build_text_binary(code, vmaddr=base))
        cls.func_end = _func_end(cls.ctx, base)
        cls.field_reg = _find_field_number_register(cls.ctx, base, cls.func_end)

    def test_field_reg_recovered(self):
        # RE-ATTRIBUTION NOTE: this class (and its fixture) was added by
        # 284e018d, but this specific test only calls _find_field_number_register
        # -- a pre-existing, unrelated function that is byte-identical before
        # and after that commit (confirmed via `git show 284e018d`, which only
        # touches _core_resolves_compare_chain/_dominance_field_of and deletes
        # _compare_chain_blocks/_field_for_addr). This is really a sanity check
        # that the synthetic fixture's LSR-derived field register is what the
        # OTHER tests in this class assume -- test_forward_branch_handler_
        # attributed_correctly and test_core_resolves_compare_chain_end_to_end
        # below are what actually regression-guard 284e018d's migration.
        self.assertEqual(self.field_reg, 23)

    def test_forward_branch_handler_attributed_correctly(self):
        field_of = _dominance_field_of(
            self.ctx, self.VMADDR, self.func_end, self.field_reg)
        # The forward (b.eq) block resolves to field 2, the fall-through to field 1
        # — not the textually-nearer `cmp w23,#1` a linear/address-range scan would
        # wrongly associate with the forward block.
        self.assertEqual(field_of(self.bl2_addr), 2)
        self.assertEqual(field_of(self.bl1_addr), 1)

    def test_addr_before_any_handler_is_unattributed(self):
        field_of = _dominance_field_of(
            self.ctx, self.VMADDR, self.func_end, self.field_reg)
        self.assertIsNone(field_of(self.VMADDR))   # the lsr/dispatch preamble itself

    def test_core_resolves_compare_chain_end_to_end(self):
        # The migrated production gate: both element calls resolve to distinct
        # known cores under distinct fields -> non-degenerate -> True.
        core_index = {self.core1: 'ElementOne', self.core2: 'ElementTwo'}
        self.assertTrue(_core_resolves_compare_chain(
            self.ctx, self.VMADDR, core_index))

    def test_core_resolves_compare_chain_no_known_cores(self):
        # Neither bl target is in core_index -> nothing to bind -> False.
        # NOTE (TAUTOLOGICAL against 284e018d's migration): `field_of =
        # _dominance_field_of(...)` is constructed eagerly but only ever
        # CALLED inside `if target in core_index:` -- with core_index={} that
        # guard is False for every bl in the body, so the migrated dominance
        # closure is never actually invoked here, only built. No fixture using
        # THIS body's real bl targets (core1/core2) can invoke field_of while
        # still returning False for "no known cores": including either target
        # in core_index makes it a KNOWN core, flipping the scenario (and the
        # expected result) to the one test_core_resolves_compare_chain_end_to_end
        # above already covers -- that sibling is what actually exercises
        # _dominance_field_of's internals for this migration.
        self.assertFalse(_core_resolves_compare_chain(self.ctx, self.VMADDR, {}))


class TestDegeneratePartitionRejected(unittest.TestCase):
    """A field whose OWN handler block calls two DISTINCT known ReadAllFrom cores
    is not a real per-field compare chain (a collapsed/mis-decoded dispatch would
    look like this) -- _core_resolves_compare_chain must reject it so the caller
    prefers the wrapper-found core instead."""

    VMADDR = 0x8000

    @classmethod
    def setUpClass(cls):
        base = cls.VMADDR
        cls.core_a = base + 0x1000
        cls.core_b = base + 0x2000

        code = b''
        code += _enc_lsr_x(23, 8)                                   # 0x00  field_reg = 23
        code += _enc_cmp(23, 1)                                     # 0x04  cmp w23,#1
        code += _enc_bcond(_COND_NE, base + 0x08, base + 0x18)      # 0x08  b.ne ELSE
        code += encode_bl(cls.core_a - (base + 0x0c))               # 0x0c  field 1: bl CORE_A
        code += encode_bl(cls.core_b - (base + 0x10))               # 0x10  field 1 (SAME block!): bl CORE_B
        code += encode_b((base + 0x1c) - (base + 0x14))             # 0x14  b MERGE
        code += NOP_BYTES                                            # 0x18  ELSE
        code += RET_BYTES                                            # 0x1c  MERGE: ret

        cls.ctx = BinaryContext(build_text_binary(code, vmaddr=base))

    def test_degenerate_partition_rejected(self):
        core_index = {self.core_a: 'A', self.core_b: 'B'}
        self.assertFalse(_core_resolves_compare_chain(
            self.ctx, self.VMADDR, core_index))


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
class TestReadFromDispatchLive(unittest.TestCase):
    """Resolve GEOPDComponent's repeated-message element types from the cache."""

    @classmethod
    def setUpClass(cls):
        from macho.dyld_cache import DyldCacheReader
        from macho.memory import BinaryContext
        from macho.strings import build_string_table
        from macho.classlist import build_class_list
        from macho.local_symbols import apply_to_classes
        from proto.dispatch import _build_readfrom_core_index, _find_readfrom_c_func

        cls.reader = DyldCacheReader(_CACHE_MAIN)
        cls.mach_va = cls.reader.find_image_header('GeoServices')
        if cls.mach_va is None:
            raise unittest.SkipTest('GeoServices image not in cache')
        cls.ctx = BinaryContext.from_cache(cls.reader, cls.mach_va)
        cls.st = build_string_table(cls.ctx)
        cls.cl = build_class_list(cls.ctx, cls.st)
        syms = cls.reader.image_local_symbols(cls.mach_va)
        if syms:
            apply_to_classes(cls.cl, syms)
        cls.core_index = _build_readfrom_core_index(cls.ctx, cls.cl)
        cls._find_readfrom_c_func = staticmethod(_find_readfrom_c_func)

    def test_core_index_non_trivial(self):
        # Hundreds of proto classes -> hundreds of ReadAllFrom cores indexed.
        self.assertGreater(len(self.core_index), 100)

    def test_core_index_keys_are_addresses(self):
        self.assertTrue(all(isinstance(k, int) and k > 0
                            for k in self.core_index))

    def test_component_value_core_indexed_by_address(self):
        gv = self.cl.find('GEOPDComponentValue')
        self.assertIsNotNone(gv)
        core = self._find_readfrom_c_func(self.ctx, gv)
        self.assertIsNotNone(core)
        self.assertEqual(self.core_index.get(core), 'GEOPDComponentValue')

    def test_dispatch_resolves_known_message_fields(self):
        from proto.repeated import _resolve_repeated_via_dispatch
        comp = self.cl.find('GEOPDComponent')
        self.assertIsNotNone(comp)
        elems = _resolve_repeated_via_dispatch(self.ctx, comp, self.core_index)
        # Ground truth from the hand-decoded reference.
        self.assertEqual(elems.get(8),  'GEOPDComponentValue')   # values
        self.assertEqual(elems.get(14), 'GEOPDAttribution')      # commingledAttributions
        self.assertEqual(elems.get(7),  'GEOPDAttribution')      # attribution
        self.assertEqual(elems.get(11), 'GEOPDSource')           # source

    def test_end_to_end_values_field_is_message_not_bytes(self):
        from proto.extractor import extract_proto_message
        from proto.write_helpers import _identify_string_write_helpers
        from proto.models import FieldLabel
        comp = self.cl.find('GEOPDComponent')
        helpers = frozenset(_identify_string_write_helpers(self.ctx, self.cl))
        msg = extract_proto_message(self.ctx, self.st, self.cl, comp,
                                    string_write_helpers=helpers,
                                    readfrom_core_index=self.core_index)
        by_num = {f.number: f for f in msg.fields}
        values = by_num.get(8)
        self.assertIsNotNone(values)
        self.assertEqual(str(values.label).split('.')[-1], 'REPEATED')
        self.assertEqual(values.type_class, 'GEOPDComponentValue')
        self.assertNotEqual(values.type_name, 'bytes')

    def test_end_to_end_without_index_falls_back_to_heuristics(self):
        # With an EXPLICIT opt-out (readfrom_core_index=None) the dispatch resolver
        # never fires — behaviour is the pre-existing heuristic path (values stays
        # `repeated bytes`), proving the resolver is additive. NOTE: the kwarg now
        # auto-builds when omitted, so the degraded path must be requested explicitly
        # (see extract_proto_message _AUTO sentinel); passing None is that opt-out.
        from proto.extractor import extract_proto_message
        comp = self.cl.find('GEOPDComponent')
        msg = extract_proto_message(self.ctx, self.st, self.cl, comp,
                                    readfrom_core_index=None)
        values = {f.number: f for f in msg.fields}.get(8)
        self.assertIsNotNone(values)
        self.assertEqual(values.type_name, 'bytes')

    # ── Compare-chain dispatch (no jump table) ────────────────────────────────

    def test_compare_chain_resolves_single_field_message(self):
        # GEOPDPlaceGlobalCommonResult has ONE repeated field whose readFrom: is a
        # flat tag-decode loop (no jump table).  The compare-chain tier reads the
        # element class from the `cmp w23,#1`-guarded element bl — and must NOT
        # pick up the field-0-guarded runtime-helper call.
        from proto.repeated import _resolve_repeated_via_dispatch
        cls = self.cl.find('GEOPDPlaceGlobalCommonResult')
        self.assertIsNotNone(cls)
        elems = _resolve_repeated_via_dispatch(self.ctx, cls, self.core_index)
        self.assertEqual(elems.get(1), 'GEOPDPlaceContextMetadata')
        # field 0 is not a legal protobuf field number → never present.
        self.assertNotIn(0, elems)

    def test_end_to_end_compare_chain_field_is_message_not_bytes(self):
        from proto.extractor import extract_proto_message
        from proto.write_helpers import _identify_string_write_helpers
        cls = self.cl.find('GEOPDPlaceGlobalCommonResult')
        helpers = frozenset(_identify_string_write_helpers(self.ctx, self.cl))
        msg = extract_proto_message(self.ctx, self.st, self.cl, cls,
                                    string_write_helpers=helpers,
                                    readfrom_core_index=self.core_index)
        fld = {f.name: f for f in msg.fields}.get('placeContextMetadatas')
        self.assertIsNotNone(fld)
        self.assertEqual(fld.type_class, 'GEOPDPlaceContextMetadata')
        self.assertNotEqual(fld.type_name, 'bytes')
        # Principled (dispatch), so NOT flagged as a name-suffix guess.
        self.assertIsNone(fld.type_inference_note)

    # ── Wrapper→separate-core dispatch (ReadAllFrom wrapper calls a core) ──────

    def test_wrapper_core_finder_locates_separate_core(self):
        # GEOPDDepartureSequence's readFrom: anchor is a thin ReadAllFrom wrapper
        # that only *calls* a separate ReadSpecified core past an early ret; the
        # finder must locate that core and decode its arms.
        from proto.dispatch import _find_dispatch_core_via_wrapper, _find_readfrom_c_func
        cls = self.cl.find('GEOPDDepartureSequence')
        self.assertIsNotNone(cls)
        rf = _find_readfrom_c_func(self.ctx, cls)
        self.assertIsNotNone(rf)
        own = frozenset(m.imp for m in cls.methods if m.imp)
        core_va, arms = _find_dispatch_core_via_wrapper(self.ctx, rf, own)
        self.assertIsNotNone(core_va)
        self.assertTrue(arms)

    def test_wrapper_core_resolves_repeated_message_fields(self):
        # The wrapper→core fallback lets the dispatch resolver reach the table, so
        # the repeated-message fields resolve to their real element classes.
        from proto.repeated import _resolve_repeated_via_dispatch
        cls = self.cl.find('GEOPDDepartureSequence')
        elems = _resolve_repeated_via_dispatch(self.ctx, cls, self.core_index)
        self.assertEqual(elems.get(5), 'GEOPDDeparture')             # departures
        self.assertEqual(elems.get(6), 'GEOPDDepartureFrequency')    # departureFrequencys

    def test_wrapper_core_end_to_end_field_is_message_not_bytes(self):
        # End-to-end: GEOPDDepartureSequence's wrapper also calls nested message
        # readers, but the own-IMP identity check picks THIS class's core, so
        # `departures` resolves to its real element class via principled dispatch
        # (not the name-suffix guess, and not a nested type).
        from proto.extractor import extract_proto_message
        from proto.write_helpers import _identify_string_write_helpers
        cls = self.cl.find('GEOPDDepartureSequence')
        helpers = frozenset(_identify_string_write_helpers(self.ctx, self.cl))
        msg = extract_proto_message(self.ctx, self.st, self.cl, cls,
                                    string_write_helpers=helpers,
                                    readfrom_core_index=self.core_index)
        by_name = {f.name: f for f in msg.fields}
        dep = by_name.get('departures')
        self.assertIsNotNone(dep)
        self.assertEqual(dep.type_class, 'GEOPDDeparture')
        self.assertNotEqual(dep.type_name, 'bytes')
        # Principled dispatch result → not a name-suffix guess.
        self.assertIsNone(dep.type_inference_note)

    # ── Adder→ivar lever (binds element type to the exact ivar) ───────────────

    def test_adder_array_ivar_pins_exact_offset(self):
        # The _addNoFlagsDeparture: accessor loads the _departures ivar-offset
        # variable; the lever reads that slot and returns the backing array
        # ivar's byte offset — even though the accessor also touches the _flags
        # struct ivar (which is excluded by the array-encoding filter).
        from proto.repeated import _adder_array_ivar
        cls = self.cl.find('GEOPDDepartureSequence')
        adder = next((m.imp for m in cls.methods
                      if m.name == '_addNoFlagsDeparture:'), None)
        self.assertIsNotNone(adder)
        dep_off = next(iv.offset for iv in cls.ivars if iv.name == '_departures')
        array_offs = frozenset(
            iv.offset for iv in cls.ivars
            if iv.type_enc in ('@"NSArray"', '@"NSMutableArray"'))
        self.assertEqual(_adder_array_ivar(self.ctx, adder, array_offs), dep_off)

    def test_adder_array_ivar_rejects_singular_message_ivar_offset(self):
        # test_lever_never_binds_singular_message_field (below) can't discriminate
        # the array_offsets type-check on its own: GEOETARequest's singular
        # `_origin` (GEOWaypoint) field has no _addNoFlags<X>: adder at all, so the
        # jump-table arm walk's OTHER gate (the arm's second `bl` must land in
        # `own_imps` AND be treated as an adder) already excludes it before
        # `_adder_array_ivar` is ever called — reverting the type-check alone
        # would not move that test.  Here we call `_adder_array_ivar` directly on
        # `setOrigin:`, which IS in `own_imps` and loads the ivar-offset-table slot
        # with the exact same `adrp+add+ldrsw` pattern a real adder uses — so the
        # "found via own_imps" gate is satisfied and only the array_offsets
        # type-check can still reject binding to this singular, non-array ivar.
        from proto.repeated import _adder_array_ivar
        cls = self.cl.find('GEOETARequest')
        self.assertIsNotNone(cls)
        setter = next((m.imp for m in cls.methods if m.name == 'setOrigin:'), None)
        self.assertIsNotNone(setter)
        origin_off = next(iv.offset for iv in cls.ivars if iv.name == '_origin')
        array_offs = frozenset(
            iv.offset for iv in cls.ivars
            if iv.type_enc in ('@"NSArray"', '@"NSMutableArray"'))
        self.assertNotIn(origin_off, array_offs)   # _origin is GEOWaypoint, not an array
        self.assertIsNone(_adder_array_ivar(self.ctx, setter, array_offs))

    def test_dispatch_ivars_jumptable_binds_by_ivar_with_number(self):
        # The jump-table lever returns {ivar_name: (element_class, field_number)}.
        from proto.repeated import _resolve_repeated_via_dispatch_ivars
        cls = self.cl.find('GEOPDDepartureSequence')
        ivmap = _resolve_repeated_via_dispatch_ivars(
            self.ctx, cls, self.core_index)
        self.assertEqual(ivmap.get('_departures'), ('GEOPDDeparture', 5))
        self.assertEqual(ivmap.get('_departureFrequencys'),
                         ('GEOPDDepartureFrequency', 6))

    def test_dispatch_ivars_compare_chain_binds_unconfirmed_field(self):
        # GEOPDExternalAction uses the compare-chain reader; its repeated
        # externalActionDetails field is bound by ivar via the adder.  Its
        # handler is a FORWARD-branch block (cmp w23,#2; b.eq <later addr>),
        # placed at a higher address than the field-1 fall-through — so the
        # control-flow block attribution must report field 2 (matching writeTo:,
        # verified by hand-decoding readFrom:), not the address-adjacent 1.
        from proto.repeated import _resolve_repeated_via_dispatch_ivars
        cls = self.cl.find('GEOPDExternalAction')
        if cls is None:
            self.skipTest('GEOPDExternalAction not in this cache')
        ivmap = _resolve_repeated_via_dispatch_ivars(
            self.ctx, cls, self.core_index)
        self.assertEqual(ivmap.get('_externalActionDetails'),
                         ('GEOPDExternalActionDetail', 2))

    def test_direct_core_preferred_over_wrong_wrapper_sibling(self):
        # GEOPDExternalAction has a real direct compare-chain core
        # (read_specified_va) AND its readFrom: body calls sibling cores the wrapper
        # scan can mistake for the dispatch core.  _locate_dispatch_arms must keep
        # the direct core (it resolves a clean compare chain) rather than adopt the
        # wrong sibling — else externalActionDetails would silently drop to bytes.
        from proto.dispatch import _locate_dispatch_arms
        from proto.repeated import _resolve_repeated_via_dispatch
        cls = self.cl.find('GEOPDExternalAction')
        if cls is None:
            self.skipTest('GEOPDExternalAction not in this cache')
        _arms, core_va, _rf = _locate_dispatch_arms(
            self.ctx, cls, self.core_index)
        # The kept core resolves field 2 to the real element class.
        elems = _resolve_repeated_via_dispatch(self.ctx, cls, self.core_index)
        self.assertEqual(elems.get(2), 'GEOPDExternalActionDetail')

    def test_degenerate_jumptable_collapse_yields_no_mis_binding(self):
        # GEORPFeedbackFieldValue is a large JUMP-TABLE reader (21 feedback-type fields).
        # TODO #42: the compare-chain tier now attributes element bls by DOMINANCE over a
        # COMPLETE CFG (br arms injected) — so a field is credited only with the cores its
        # match edge dominates; it can't lump 21 distinct cores under one field.  The old
        # _degenerate_block_partition guard (deleted in #42) is unnecessary by construction.
        # At the time this test was written, no mechanism could yet resolve
        # _hoursFields at all, so it asserted the conservative "not bound rather
        # than mis-bound" outcome: _hoursFields must not be mis-bound to the
        # first-scanned element (GEORPFeedbackFieldAnnotations).
        # Since then, _walk_jumptable_arms gained two structural guards (reject
        # an arm address shared by >=2 different field numbers; bound each arm's
        # scan by the next arm's own start) that let it correctly resolve this
        # class's jump table without that ambiguity.  _hoursFields (field 16)
        # now resolves to GEORPFeedbackBusinessHours -- matching golden exactly
        # (tests/golden/GeoServices.json) -- so the guard is updated to assert
        # the verified-correct value instead of "not bound", while keeping the
        # original regression check (never GEORPFeedbackFieldAnnotations).
        from proto.repeated import _resolve_repeated_via_dispatch_ivars
        cls = self.cl.find('GEORPFeedbackFieldValue')
        if cls is None:
            self.skipTest('GEORPFeedbackFieldValue not in this cache')
        ivmap = _resolve_repeated_via_dispatch_ivars(
            self.ctx, cls, self.core_index)
        self.assertEqual(ivmap.get('_hoursFields'), ('GEORPFeedbackBusinessHours', 16))
        self.assertNotEqual(
            ivmap.get('_hoursFields', (None, None))[0],
            'GEORPFeedbackFieldAnnotations')

    def test_thick_wrapper_compare_chain_core_resolves(self):
        # GEOLPRWorld's readFrom: is a thick wrapper: _readspecified_and_count finds
        # no direct core (read_specified_va is None), and the dispatch core is a
        # COMPARE CHAIN (not a jump table).  The wrapper→core finder must surface
        # that compare-chain core so the elements resolve from the binary's own
        # parse code (replacing the old name-suffix guesses that dropped the "Map"
        # suffix, e.g. GEOLPRPowerType -> the real GEOLPRPowerTypeMap).
        from proto.repeated import _resolve_repeated_via_dispatch_ivars
        cls = self.cl.find('GEOLPRWorld')
        if cls is None:
            self.skipTest('GEOLPRWorld not in this cache')
        ivmap = _resolve_repeated_via_dispatch_ivars(
            self.ctx, cls, self.core_index)
        self.assertEqual(ivmap.get('_powerTypes'), ('GEOLPRPowerTypeMap', 3))
        self.assertEqual(ivmap.get('_vehicleTypes'), ('GEOLPRVehicleTypeMap', 4))
        self.assertEqual(ivmap.get('_regions'), ('GEOLPRRegion', 1))

    def test_lever_promotes_bytes_field_to_message(self):
        # GEOPDEventCategory.localizedCategorys had no confirmed number and fell
        # to `repeated bytes`; the adder→ivar lever now types it as GEOPDCategory.
        from proto.extractor import extract_proto_message
        from proto.write_helpers import _identify_string_write_helpers
        cls = self.cl.find('GEOPDEventCategory')
        if cls is None:
            self.skipTest('GEOPDEventCategory not in this cache')
        helpers = frozenset(_identify_string_write_helpers(self.ctx, self.cl))
        msg = extract_proto_message(self.ctx, self.st, self.cl, cls,
                                    string_write_helpers=helpers,
                                    readfrom_core_index=self.core_index)
        fld = next((f for f in msg.fields
                    if f.name == 'localizedCategorys'), None)
        self.assertIsNotNone(fld)
        self.assertEqual(fld.type_class, 'GEOPDCategory')
        self.assertNotEqual(fld.type_name, 'bytes')
        self.assertIsNone(fld.type_inference_note)   # principled, not a guess

    def test_lever_drops_guess_without_touching_the_number(self):
        # GEOPDExternalAction.externalActionDetails was a Strategy-2 GUESS.  The
        # compare-chain lever binds its element type by ivar, dropping the warning
        # note.  The lever NEVER adopts the dispatch field number (the dispatch
        # index is not reliable as a confirmation), so the number is left exactly
        # as the writeTo:/pointer-table pass set it.
        from proto.protocore import _is_real_field_ivar
        from proto.extractor import _confirm_field_numbers, extract_proto_message
        from proto.write_helpers import _identify_string_write_helpers
        cls = self.cl.find('GEOPDExternalAction')
        if cls is None:
            self.skipTest('GEOPDExternalAction not in this cache')
        helpers = frozenset(_identify_string_write_helpers(self.ctx, self.cl))
        msg = extract_proto_message(self.ctx, self.st, self.cl, cls,
                                    string_write_helpers=helpers,
                                    readfrom_core_index=self.core_index)
        fld = next((f for f in msg.fields
                    if f.name == 'externalActionDetails'), None)
        self.assertIsNotNone(fld)
        # Type fixed to principled dispatch ground truth, guess note removed.
        self.assertEqual(fld.type_class, 'GEOPDExternalActionDetail')
        self.assertIsNone(fld.type_inference_note)
        # Number is whatever the confirmation pass decided — the lever did not
        # override it with the dispatch index.
        imn = {m.name for m in cls.methods if m.name}
        fivars = [iv for iv in cls.ivars if _is_real_field_ivar(iv, imn)]
        conf = _confirm_field_numbers(self.ctx, cls, fivars, imn).confirmed_numbers
        self.assertEqual(fld.number, conf['_externalActionDetails'])

    def test_lever_never_binds_singular_message_field(self):
        # GEOETARequest has a singular GEOWaypoint field (no adder) alongside a
        # repeated `destinations` GEOWaypoint field (has _addNoFlagsDestination:).
        # The lever must bind ONLY the repeated ivar — the singular field has no
        # adder, so the ordinal-mis-binding hazard cannot occur.
        from proto.repeated import _resolve_repeated_via_dispatch_ivars
        cls = self.cl.find('GEOETARequest')
        if cls is None:
            self.skipTest('GEOETARequest not in this cache')
        ivmap = _resolve_repeated_via_dispatch_ivars(
            self.ctx, cls, self.core_index)
        self.assertEqual(ivmap.get('_destinations'), ('GEOWaypoint', 4))
        # The singular waypoint ivars are NOT array-typed, so never bound here.
        for ivn, (_el, _fn) in ivmap.items():
            iv = next(iv for iv in cls.ivars if iv.name == ivn)
            self.assertIn(iv.type_enc, ('@"NSArray"', '@"NSMutableArray"'))


if __name__ == '__main__':
    unittest.main(verbosity=2)
