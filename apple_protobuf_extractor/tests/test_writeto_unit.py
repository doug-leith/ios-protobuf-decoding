#!/usr/bin/env python3
"""Deterministic synthetic-CFG unit tests for the production writeTo: walk
(``proto.writeto.writeto_walk`` + the binding/parsing helpers it uses).  No binary
needed — a fake instruction memory is built from tuples and ``proto.writeto.disasm``
is monkeypatched to slice it.

Locks the numbers-only walk's contract: sound (no foreign over-read), complete
across guard edges into outlined blocks past foreign IMPs, correct unconditional-b
discrimination (write / foreign / thunk / follow), and set-correct under Apple's
out-of-tag-order emission — plus the operand-parse / offset-resolve / container
and binding helpers.

(Formerly tested the standalone ``wt_reader.py`` prototype; repointed to the
production module when that fork was deleted.)
"""
import unittest

import proto.writeto as W       # walk, detect_context, _forward_self_load_off, bind_write
import proto.arm64cfg as CFG    # _parse_load, _resolve_offset_addr (their canonical home)
from macho.disasm import Insn


def asm(*blocks):
    """Build {addr: Insn} from blocks of (base, [(mnemonic, op_str), ...]).
    Returns (mem, fake_disasm)."""
    mem = {}
    for base, lines in blocks:
        a = base
        for mn, op in lines:
            mem[a] = Insn(addr=a, mnemonic=mn, op_str=op, size=4, raw=b'\x00\x00\x00\x00')
            a += 4

    def fake_disasm(ctx, addr, max_insns=400, stop_at_ret=False):
        out = []
        a = addr
        while len(out) < max_insns and a in mem:
            out.append(mem[a])
            a += 4
        return out

    return mem, fake_disasm


def walk(fake_disasm, imp, foreign=frozenset(), indeg=None, **kw):
    orig = W.disasm
    W.disasm = fake_disasm
    try:
        writes, flags = W.writeto_walk(None, imp, set(foreign), indeg or {}, **kw)
    finally:
        W.disasm = orig
    return {w['n'] for w in writes}, writes


class TestWriteToWalk(unittest.TestCase):

    def test_linear_inline_writes(self):
        _, fd = asm((0x1000, [
            ('mov', 'w2, #1'), ('bl', '#0x9000'),
            ('mov', 'w2, #2'), ('bl', '#0x9000'),
            ('mov', 'w2, #3'), ('bl', '#0x9000'),
            ('ret', ''),
        ]))
        got, _ = walk(fd, 0x1000)
        self.assertEqual(got, {1, 2, 3})

    def test_outlined_block_past_foreign_imp(self):
        # field #1's block is OUTLINED at 0x5000, past a foreign method IMP 0x2000;
        # reached only via the explicit guard target.  Must still be recovered.
        _, fd = asm(
            (0x1000, [
                ('tbnz', 'w8, #0, #0x5000'),   # guard -> outlined block
                ('mov', 'w2, #2'), ('bl', '#0x9000'),  # #2 inline
                ('ret', ''),
            ]),
            (0x5000, [
                ('mov', 'w2, #1'), ('bl', '#0x9000'),  # #1 outlined
                ('ret', ''),
            ]),
        )
        got, _ = walk(fd, 0x1000, foreign={0x2000})
        self.assertEqual(got, {1, 2})

    def test_thunk_not_followed(self):
        # unconditional b to a high in-degree shared thunk must NOT be followed,
        # so its bogus field write is never collected.
        _, fd = asm(
            (0x1000, [
                ('mov', 'w2, #1'), ('bl', '#0x9000'),
                ('b', '#0x8000'),              # thunk
            ]),
            (0x8000, [
                ('mov', 'w2, #99'), ('bl', '#0x9000'),  # must NOT be collected
                ('ret', ''),
            ]),
        )
        got, _ = walk(fd, 0x1000, indeg={0x8000: {0xAAA, 0xBBB}})
        self.assertEqual(got, {1})

    def test_tail_call_write(self):
        # mov w2,#5 ; b helper  -> a tail-call FIELD WRITE, recorded.
        _, fd = asm((0x1000, [
            ('mov', 'w2, #5'), ('b', '#0x9000'),
        ]))
        got, _ = walk(fd, 0x1000)
        self.assertEqual(got, {5})

    def test_foreign_b_not_followed(self):
        # b to a foreign method IMP (no field-number before) terminates the path;
        # the foreign block's write is not collected.
        _, fd = asm(
            (0x1000, [
                ('mov', 'w2, #1'), ('bl', '#0x9000'),
                ('b', '#0x2000'),              # foreign imp tail-call
            ]),
            (0x2000, [
                ('mov', 'w2, #42'), ('bl', '#0x9000'),  # must NOT be collected
                ('ret', ''),
            ]),
        )
        got, _ = walk(fd, 0x1000, foreign={0x2000})
        self.assertEqual(got, {1})

    def test_follow_own_outlined_b(self):
        # unconditional b to a NON-foreign, low in-degree target = our own outlined
        # block -> follow it and collect its write.
        _, fd = asm(
            (0x1000, [
                ('mov', 'w2, #1'), ('bl', '#0x9000'),
                ('b', '#0x1500'),
            ]),
            (0x1500, [
                ('mov', 'w2, #2'), ('bl', '#0x9000'),
                ('ret', ''),
            ]),
        )
        got, _ = walk(fd, 0x1000, indeg={})   # 0x1500 not a known thunk
        self.assertEqual(got, {1, 2})

    def test_set_correct_under_out_of_order_emission(self):
        # Apple reorders: field #2's block emitted AFTER #3 (GEOFormatArgument
        # pattern).  The SET must still be complete; monotonic() may be False.
        _, fd = asm(
            (0x1000, [
                ('tbnz', 'w8, #1, #0x1100'),   # bit1 -> #3 (early)
                ('tbz',  'w8, #0, #0x1200'),   # bit0 -> #2 (late block)
                ('ret', ''),
            ]),
            (0x1100, [
                ('mov', 'w2, #3'), ('bl', '#0x9000'), ('ret', ''),
            ]),
            (0x1200, [
                ('mov', 'w2, #2'), ('bl', '#0x9000'), ('ret', ''),
            ]),
        )
        got, writes = walk(fd, 0x1000)
        self.assertEqual(got, {2, 3})

    def test_no_writes_stub(self):
        # 4-insn stub that only tail-calls a thunk (unknownFields) -> no fields.
        _, fd = asm((0x1000, [
            ('adrp', 'x8, #0x1000'),
            ('ldrsw', 'x8, [x8, #0x10]'),
            ('ldr', 'x0, [x0, x8]'),
            ('b', '#0x8000'),
        ]))
        got, _ = walk(fd, 0x1000, indeg={0x8000: {0x1, 0x2, 0x3}})
        self.assertEqual(got, set())

    def test_issueB_begin_submsg_cont_off_is_array_not_count(self):
        # Inline-repeated MESSAGE (begin/end-bracketed) field #1: the COUNT ivar
        # offset is loaded in the preheader (loop bound) BEFORE the begin; the ARRAY
        # ivar offset is loaded in the loop body AFTER it.  The container offset
        # recorded for the write must be the ARRAY (post-begin) load, not the count
        # (Issue B: count-vs-array).  Offset vars: count @0x4000, array @0x4008.
        _, fd = asm((0x1000, [
            ('adrp',  'x8, #0x4000'),
            ('ldrsw', 'x21, [x8, #0x0]'),    # x21 = &count offset var  -> 0x4000
            ('ldr',   'x9, [x20, x21]'),     # count load (self=x20): cur_off=count
            ('cbz',   'x9, #0x1080'),
            ('adrp',  'x8, #0x4000'),
            ('ldrsw', 'x24, [x8, #0x8]'),    # x24 = &array offset var  -> 0x4008
            ('str',   'xzr, [sp, #8]'),
            ('add',   'x1, sp, #8'),         # stack scratch -> begin-submessage
            ('mov',   'w2, #1'),
            ('bl',    '#0x9000'),            # BEGIN field #1
            ('ldr',   'x8, [x20, x24]'),     # ARRAY load (after begin)
            ('ret',   ''),
        ]))
        _, writes = walk(fd, 0x1000, self_reg='x20')
        w1 = [w for w in writes if w['n'] == 1][0]
        self.assertEqual(w1['cont_off'], 0x4008,
                         "begin-submessage must bind the array offset, not the count")

    def test_loop_first_wins_dedup(self):
        # a repeated field's per-element write loops back; the same #N appears
        # twice but is collected once.
        _, fd = asm((0x1000, [
            ('mov', 'w2, #4'), ('bl', '#0x9000'),
            ('mov', 'w2, #4'), ('bl', '#0x9000'),
            ('ret', ''),
        ]))
        got, writes = walk(fd, 0x1000)
        self.assertEqual(got, {4})
        self.assertEqual(len([w for w in writes if w['n'] == 4]), 1)


class TestPackedElementWriter(unittest.TestCase):
    """A packed repeated scalar is written as begin-mark(field#) .. element writer with
    the no-tag field# -1 per element .. recall-mark.  The walk records the begin-mark as
    the field write (``bracket``) and the no-tag call inside it as ``elem_helper_vas``
    — the writer whose wire family types the elements (CLPSatelliteInfo.cnos: sint32)."""

    BEGIN, END, SINT32, INT32 = 0x9000, 0x9100, 0x9200, 0x9300

    def _packed(self, elem_writer, after_end=()):
        # Shape of -[CLPSatelliteInfo writeTo:]: the element loop is its own block (the
        # b.lo back-edge target), so the bracket must be threaded across the block edge.
        return asm((0x1000, [
            ('str',  'xzr, [sp, #8]'),
            ('add',  'x1, sp, #8'),          # stack scratch -> begin-mark
            ('mov',  'x0, x19'),
            ('mov',  'w2, #2'),
            ('bl',   f'#{self.BEGIN:#x}'),   # BEGIN field #2
            ('mov',  'x22, #0'),
            # loop @0x1018
            ('ldr',  'w1, [x8, x22, lsl #2]'),
            ('mov',  'x0, x19'),
            ('mov',  'w2, #-1'),             # no tag: packed element
            ('bl',   f'#{elem_writer:#x}'),
            ('add',  'x22, x22, #1'),
            ('cmp',  'x22, x8'),
            ('b.lo', '#0x1018'),
            ('add',  'x1, sp, #8'),
            ('mov',  'x0, x19'),
            ('bl',   f'#{self.END:#x}'),     # recall-mark (END)
            *after_end,
            ('ret',  ''),
        ]))[1]

    def test_element_writer_in_separate_loop_block(self):
        _, writes = walk(self._packed(self.SINT32), 0x1000)
        w = [w for w in writes if w['n'] == 2][0]
        self.assertTrue(w['bracket'])
        self.assertEqual(w['helper_va'], self.BEGIN)
        self.assertEqual(w['elem_helper_vas'], [self.SINT32])

    def test_no_tag_write_after_recall_mark_not_attributed(self):
        # a no-tag call after the bracket closed belongs to no field
        _, writes = walk(self._packed(self.SINT32, after_end=(
            ('mov', 'w2, #-1'), ('bl', f'#{self.INT32:#x}'))), 0x1000)
        w = [w for w in writes if w['n'] == 2][0]
        self.assertEqual(w['elem_helper_vas'], [self.SINT32])

    def test_unpacked_list_is_not_a_bracket(self):
        # unpacked repeated: the element writer is called per element WITH the field#,
        # so it is the field's own helper and there is no bracket
        _, fd = asm((0x1000, [
            ('ldr', 'w1, [x8, x22, lsl #2]'),
            ('mov', 'w2, #0x17'),
            ('bl',  f'#{self.INT32:#x}'),
            ('ret', ''),
        ]))
        _, writes = walk(fd, 0x1000)
        w = writes[0]
        self.assertFalse(w['bracket'])
        self.assertEqual(w['helper_va'], self.INT32)
        self.assertEqual(w['elem_helper_vas'], [])

    def test_packed_list_nested_in_inline_submessage_not_attributed_to_outer(self):
        # inline sub-message field #3 containing a packed list (nested bracket, not
        # recorded as a top-level field): its no-tag elements must not type field #3
        _, fd = asm((0x1000, [
            ('add', 'x1, sp, #8'), ('mov', 'w2, #3'), ('bl', f'#{self.BEGIN:#x}'),
            ('add', 'x1, sp, #16'), ('mov', 'w2, #1'), ('bl', f'#{self.BEGIN:#x}'),
            ('mov', 'w2, #-1'), ('bl', f'#{self.SINT32:#x}'),
            ('add', 'x1, sp, #16'), ('bl', f'#{self.END:#x}'),
            ('add', 'x1, sp, #8'), ('bl', f'#{self.END:#x}'),
            ('ret', ''),
        ]))
        _, writes = walk(fd, 0x1000)
        w3 = [w for w in writes if w['n'] == 3][0]
        self.assertTrue(w3['bracket'])
        self.assertEqual(w3['elem_helper_vas'], [])


def ins_list(*pairs, base=0x2000):
    """Build a list of Insn from (mnemonic, op_str) pairs at sequential addresses."""
    return [Insn(addr=base + 4 * i, mnemonic=mn, op_str=op, size=4,
                 raw=b'\x00\x00\x00\x00') for i, (mn, op) in enumerate(pairs)]


class FakeCtx:
    """Minimal ctx exposing read_u32 over a {addr: value} map (the main ctx call
    the binding layer makes).  Optional ``ptrs``/``cstrs`` maps back read_ptr /
    read_cstring for the accessor-binding tier (selector-stub resolution).  Lets
    every binder be unit-tested with NO binary."""
    def __init__(self, mem, ptrs=None, cstrs=None):
        self._mem = dict(mem)
        self._ptrs = dict(ptrs or {})
        self._cstrs = dict(cstrs or {})

    def read_u32(self, addr):
        if addr not in self._mem:
            raise ValueError(f"unmapped {addr:#x}")
        return self._mem[addr]

    def read_ptr(self, addr):
        if addr not in self._ptrs:
            raise ValueError(f"unmapped ptr {addr:#x}")
        return self._ptrs[addr]

    def read_cstring(self, addr):
        if addr not in self._cstrs:
            raise ValueError(f"unmapped cstr {addr:#x}")
        return self._cstrs[addr]


class TestParseLoad(unittest.TestCase):
    def test_reg_indexed(self):
        self.assertEqual(CFG._parse_load('x1, [x20, x8]'), ('x1', 'x20', 'x8'))

    def test_imm_offset_has_no_off_reg(self):
        self.assertEqual(CFG._parse_load('w1, [x20, #0x10]'), ('w1', 'x20', None))

    def test_shifted_index(self):
        self.assertEqual(CFG._parse_load('x1, [x8, x24, lsl #3]'),
                         ('x1', 'x8', 'x24'))

    def test_fp_value_reg_preserved(self):
        self.assertEqual(CFG._parse_load('d0, [x20, x8]'), ('d0', 'x20', 'x8'))

    def test_non_memory_is_none(self):
        self.assertIsNone(CFG._parse_load('x0, x1'))


class TestResolveOffsetAddr(unittest.TestCase):
    def test_direct_adrp_ldrsw(self):
        # adrp x8,page ; ldrsw x9,[x8,#0x40]  -> resolve x9 = page + 0x40
        pre = ins_list(('adrp', 'x8, #0x10000'), ('ldrsw', 'x9, [x8, #0x40]'))
        self.assertEqual(CFG._resolve_offset_addr(pre, 'x9', {}), 0x10040)

    def test_adrp_add_base(self):
        # adrp x8,page ; add x8,x8,#0x200 ; ldrsw x9,[x8,#0x40] -> page+0x200+0x40
        pre = ins_list(('adrp', 'x8, #0x10000'), ('add', 'x8, x8, #0x200'),
                       ('ldrsw', 'x9, [x8, #0x40]'))
        self.assertEqual(CFG._resolve_offset_addr(pre, 'x9', {}), 0x10240)

    def test_base_regs_fallback(self):
        # offset reg defined from a callee-saved base captured in base_regs
        pre = ins_list(('ldrsw', 'x9, [x21, #0x40]'))
        self.assertEqual(
            CFG._resolve_offset_addr(pre, 'x9', {'x21': 0x30000}), 0x30040)

    def test_unresolvable_base_returns_none(self):
        pre = ins_list(('ldrsw', 'x9, [x21, #0x40]'))   # x21 not local, not in base_regs
        self.assertIsNone(CFG._resolve_offset_addr(pre, 'x9', {}))


class TestForwardSelfLoadOff(unittest.TestCase):
    def test_repeated_message_array_ldr(self):
        # begin@0 ; adrp ; ldrsw x24,[x8,#8] ; ldr x8,[self,x24]  -> page+8 (array)
        blk = ins_list(('bl', '#0x9000'), ('adrp', 'x8, #0x10000'),
                       ('ldrsw', 'x24, [x8, #0x8]'), ('ldr', 'x8, [x20, x24]'))
        self.assertEqual(W._forward_self_load_off(blk, 0, 'x20', {}), 0x10008)

    def test_packed_scalar_add_container(self):
        # begin@0 ; adrp ; ldrsw x8,[x8,#0x10] ; add x22,self,x8  -> page+0x10
        blk = ins_list(('bl', '#0x9000'), ('adrp', 'x8, #0x10000'),
                       ('ldrsw', 'x8, [x8, #0x10]'), ('add', 'x22, x20, x8'))
        self.assertEqual(W._forward_self_load_off(blk, 0, 'x20', {}), 0x10010)

    def test_stops_at_next_bl(self):
        # a second bl before any self-load -> nothing found (don't cross into next write)
        blk = ins_list(('bl', '#0x9000'), ('bl', '#0x9100'),
                       ('adrp', 'x8, #0x10000'), ('ldrsw', 'x24, [x8, #0x8]'),
                       ('ldr', 'x8, [x20, x24]'))
        self.assertIsNone(W._forward_self_load_off(blk, 0, 'x20', {}))


class TestDetectContext(unittest.TestCase):
    def _run(self, *pairs):
        orig = W.disasm
        W.disasm = lambda ctx, addr, max_insns=40, stop_at_ret=False: \
            ins_list(*pairs)
        try:
            return W.detect_context(None, 0x2000)
        finally:
            W.disasm = orig

    def test_self_from_mov(self):
        self_reg, _ = self._run(('mov', 'x20, x0'), ('bl', '#0x9000'))
        self.assertEqual(self_reg, 'x20')

    def test_self_defaults_to_x0(self):
        # no `mov xR, x0` before the first bl -> self stays x0 (ABI arg reg).
        self_reg, _ = self._run(('stp', 'x22, x21, [sp, #-0x30]!'), ('bl', '#0x9000'))
        self.assertEqual(self_reg, 'x0')

    def test_base_regs_always_empty(self):
        # TODO #59: the prologue base-register seed was removed (redundant with the
        # walk's live cur_base tracking).  detect_context returns NO bases even when
        # an adrp+add into a callee-saved reg is present in the prologue.
        _, base = self._run(('mov', 'x20, x0'), ('adrp', 'x21, #0x10000'),
                            ('add', 'x21, x21, #0x200'), ('bl', '#0x9000'))
        self.assertEqual(base, {})


class TestBindWrite(unittest.TestCase):
    SELF = 'x20'

    def _w(self, pre, cont_off=None):
        return dict(n=1, write_addr=0x2000, block=0x2000, guard=0x2000,
                    cont_off=cont_off, pre=pre)

    def test_2a_scalar_self_load(self):
        # value loaded from self[ivar_off]; offset var @page+0x40 holds byte-off 0x18
        ctx = FakeCtx({0x10040: 0x18})
        pre = ins_list(('adrp', 'x8, #0x10000'), ('ldrsw', 'x8, [x8, #0x40]'),
                       ('ldr', 'w1, [x20, x8]'), ('mov', 'x0, x19'),
                       ('mov', 'w2, #3'), ('bl', '#0x9000'))
        name, st = W.bind_write(ctx, self._w(pre), self.SELF, {}, {0x18: '_foo'})
        self.assertEqual((name, st), ('_foo', 'ok'))

    def test_2b_container_stack_scratch(self):
        # begin-submessage: value is a stack scratch (no self-load) -> bind cont_off
        ctx = FakeCtx({0x10040: 0x18})
        pre = ins_list(('str', 'xzr, [sp, #8]'), ('add', 'x1, sp, #8'),
                       ('mov', 'x0, x19'), ('mov', 'w2, #1'), ('bl', '#0x9000'))
        name, st = W.bind_write(ctx, self._w(pre, cont_off=0x10040),
                                self.SELF, {}, {0x18: '_foo'})
        self.assertEqual((name, st), ('_foo', 'ok-repeated'))

    def test_guard_blocks_cont_off_for_unresolved_scalar(self):
        # value IS a self-load but its offset reg is undefined -> 2a fails; the guard
        # must NOT fall through to cont_off (would mis-bind to a stale internal ivar).
        ctx = FakeCtx({0x10040: 0x18})
        pre = ins_list(('ldr', 'w1, [x20, x8]'), ('mov', 'w2, #3'), ('bl', '#0x9000'))
        name, st = W.bind_write(ctx, self._w(pre, cont_off=0x10040),
                                self.SELF, {}, {0x18: '_foo'})
        self.assertEqual((name, st), (None, 'unresolved-offset'))

    def test_value_search_stops_at_prev_bl(self):
        # a begin-submessage whose pre still contains the PREVIOUS field's self-load
        # must not adopt it: the value-load search stops at the intervening bl, so the
        # write is correctly judged a container write and binds cont_off.
        ctx = FakeCtx({0x10040: 0x18})
        pre = ins_list(('ldr', 'w1, [x20, x8]'), ('bl', '#0x9000'),       # prev field
                       ('str', 'xzr, [sp, #8]'), ('add', 'x1, sp, #8'),
                       ('mov', 'w2, #1'), ('bl', '#0x9100'))               # this begin
        name, st = W.bind_write(ctx, self._w(pre, cont_off=0x10040),
                                self.SELF, {}, {0x18: '_foo'})
        self.assertEqual((name, st), ('_foo', 'ok-repeated'))


class TestAccessorBinding(unittest.TestCase):
    """Tier 2d: message/object fields whose value comes from a property GETTER
    call (objc selector stub) rather than a direct self-load.  Locks (a) the
    selector-stub resolver, and (b) that the accessor tier front-runs the cont_off
    container tier so a STALE threaded cont_off can't mis-bind a getter-sourced
    message (the _CPUsageEnvelope.context = 14 vs estimated-6 bug)."""
    SELF = 'x20'

    # getter selector stub @0x9000  and an ARC retain thunk @0x9100 (not a stub).
    _STUB = (0x9000, [('adrp', 'x1, #0x40000'), ('ldr', 'x1, [x1, #0x28]'),
                      ('adrp', 'x16, #0x50000'), ('ldr', 'x16, [x16, #0x570]'),
                      ('br', 'x16')])
    _RETAIN = (0x9100, [('ret', '')])

    def _ctx(self):
        # selref @0x40028 -> SEL ptr 0x5000 -> cstring 'context'
        return FakeCtx({0x10040: 0x40}, ptrs={0x40028: 0x5000},
                       cstrs={0x5000: 'context'})

    def _patch_disasm(self):
        mem, fd = asm(self._STUB, self._RETAIN)
        orig = W.disasm
        W.disasm = fd
        return orig

    def test_selector_stub_name(self):
        ctx = self._ctx()
        orig = self._patch_disasm()
        try:
            self.assertEqual(W._selector_stub_name(ctx, 0x9000), 'context')
            self.assertIsNone(W._selector_stub_name(ctx, 0x9100))   # plain thunk
        finally:
            W.disasm = orig

    def test_accessor_beats_stale_cont_off(self):
        # the message-write idiom: getter -> retain -> mov chain -> write.  cont_off
        # is STALE (points at a different ivar _stale); the accessor tier must win.
        ctx = self._ctx()
        srcblk = ins_list(
            ('mov', 'x0, x19'), ('bl', '#0x9000'),      # getter (selector stub)
            ('bl', '#0x9100'),                          # ARC retain (passthrough)
            ('mov', 'x20, x0'), ('ldr', 'x0, [sp, #8]'),
            ('mov', 'x1, x20'), ('mov', 'w2, #14'), ('bl', '#0xa000'))
        srck = len(srcblk) - 1                          # the write bl
        pre = srcblk[3:]                                # since the retain bl
        w = dict(n=14, write_addr=0x2020, block=0x2000, guard=0x2000,
                 cont_off=0x10040, pre=pre, srcblk=srcblk, srck=srck)
        orig = self._patch_disasm()
        try:
            name, st = W.bind_write(ctx, w, self.SELF, {},
                                    {0x40: '_stale', 0x18: '_context'},
                                    {'context': '_context'})
        finally:
            W.disasm = orig
        self.assertEqual((name, st), ('_context', 'ok-accessor'))

    def test_no_accessor_map_falls_through_to_cont_off(self):
        # with no sel_to_ivar, the same getter-sourced write degrades to the cont_off
        # container binding (the pre-fix behaviour) — proves 2d is purely additive.
        ctx = self._ctx()
        srcblk = ins_list(
            ('mov', 'x0, x19'), ('bl', '#0x9000'), ('bl', '#0x9100'),
            ('mov', 'x20, x0'), ('ldr', 'x0, [sp, #8]'),
            ('mov', 'x1, x20'), ('mov', 'w2, #14'), ('bl', '#0xa000'))
        w = dict(n=14, write_addr=0x2020, block=0x2000, guard=0x2000,
                 cont_off=0x10040, pre=srcblk[3:], srcblk=srcblk, srck=len(srcblk) - 1)
        orig = self._patch_disasm()
        try:
            name, st = W.bind_write(ctx, w, self.SELF, {}, {0x40: '_stale'}, None)
        finally:
            W.disasm = orig
        self.assertEqual((name, st), ('_stale', 'ok-repeated'))


class TestOperandToolkit(unittest.TestCase):
    """The shared op_str parser primitives in proto.arm64cfg."""

    def test_split_ops_keeps_brackets_intact(self):
        self.assertEqual(CFG.split_ops('w1, [x20, x8]'), ['w1', '[x20, x8]'])
        self.assertEqual(CFG.split_ops('x8, x8, #0x200'), ['x8', 'x8', '#0x200'])
        self.assertEqual(CFG.split_ops('x1, [x8, x24, lsl #3]'),
                         ['x1', '[x8, x24, lsl #3]'])

    def test_split_ops_strips_lowercases_and_handles_empty(self):
        self.assertEqual(CFG.split_ops('X20, X0'), ['x20', 'x0'])
        self.assertEqual(CFG.split_ops(''), [])
        self.assertEqual(CFG.split_ops('x0'), ['x0'])

    def test_dst_reg(self):
        self.assertEqual(CFG.dst_reg('x20, x0'), 'x20')
        # _norm_reg normalises the w-view to the x-view (what clobber detection needs)
        self.assertEqual(CFG.dst_reg('w1, [x20, x8]'), 'x1')
        # ldp: first operand is the destination
        self.assertEqual(CFG.dst_reg('x22, x21, [sp], #0x30'), 'x22')
        self.assertIsNone(CFG.dst_reg(''))

    def test_parse_adrp(self):
        self.assertEqual(CFG.parse_adrp('x21, #0x10000'), ('x21', 0x10000))
        self.assertIsNone(CFG.parse_adrp('x21'))             # malformed (one operand)

    def test_mem_operand_forms(self):
        self.assertEqual(CFG.mem_operand('x1, [x20, x8]'),   ('x1', 'x20', 'x8', 0, 0))
        self.assertEqual(CFG.mem_operand('w1, [x20, #0x10]'), ('w1', 'x20', None, 0x10, 0))
        self.assertEqual(CFG.mem_operand('x8, [x20]'),        ('x8', 'x20', None, 0, 0))
        self.assertEqual(CFG.mem_operand('x1, [x8, x24, lsl #3]'),
                         ('x1', 'x8', 'x24', 0, 3))
        self.assertEqual(CFG.mem_operand('d0, [x20, x8]'),    ('d0', 'x20', 'x8', 0, 0))
        self.assertIsNone(CFG.mem_operand('x0, x1'))         # not a memory operand

    def test_parse_load_is_mem_operand_shim(self):
        # the back-compat shim returns (value, base, index) — the first three
        self.assertEqual(CFG._parse_load('x1, [x8, x24, lsl #3]'), ('x1', 'x8', 'x24'))
        self.assertIsNone(CFG._parse_load('x0, x1'))


if __name__ == '__main__':
    unittest.main()
