#!/usr/bin/env python3
"""Tests for protobuf ``map<K, V>`` recovery (TODO #41, ``proto/mapfields.py``).

Synthetic tests use instruction listings copied from real arm64 disassembly (a stack
block's invoke function, the parent ``writeTo:`` that builds the block, an inline
enumeration loop) with ``disasm`` monkeypatched to read them — no binary needed.  One
live-gated test runs the whole extractor on CoreParsec (4 inline-loop maps) and
protoc-compiles the emitted files.  The GeoServices block-shape maps are covered by the
golden snapshot (``test_golden_output``, ``<map>`` keys).
"""
import copy
import os
import shutil
import subprocess
import tempfile
import unittest
from tests._listing import layout
from tests._fakes import NoImage, name_marks
from pathlib import Path

import proto.mapfields as M
import proto.callees as C
import proto.function_body as FB
import proto.extractor as E
from proto.dispatch import FunctionEntries, listing_flow
from proto.submessage_marks import scratch_slot_of
from proto.emitter import build_proto_files, write_from_messages
from proto.models import FieldLabel, ProtoField, ProtoMessage


# ── fake instruction memory + context ─────────────────────────────────────────


def _held(table, addr):
    if addr not in table:
        raise ValueError(f"{addr:#x} not mapped")
    return table[addr]


class FakeCtx(NoImage):
    """Just enough BinaryContext for the helpers under test."""

    def __init__(self, u32=None, ptrs=None, cstrs=None):
        self.u32, self.ptrs, self.cstrs = u32 or {}, ptrs or {}, cstrs or {}

    # an address nothing holds raises ValueError, as BinaryContext's reads do
    def read_u32(self, addr):
        return _held(self.u32, addr)

    def bind_name_for(self, addr):                   # no imports bound by name
        return None

    def read_bytes(self, addr, size):                # the image, for the evaluator's loads
        if size == 4 and addr in self.u32:
            return self.u32[addr].to_bytes(4, 'little', signed=self.u32[addr] < 0)
        raise ValueError(f"unmapped {addr:#x}")

    def is_variable(self, vmaddr):        # no program data, no binds
        return False

    def read_ptr(self, addr):
        return _held(self.ptrs, addr)

    def read_cstring(self, addr):
        return _held(self.cstrs, addr)


asm = layout


def selector_stub(base, sel_slot):
    """The 5-insn objc selector-stub shape ``proto.callees.stub_selector`` recognises."""
    return (base, [('adrp', f'x1, #{sel_slot & ~0xfff:#x}'),
                   ('ldr', f'x1, [x1, #{sel_slot & 0xfff:#x}]'),
                   ('adrp', 'x16, #0x1000'), ('ldr', 'x16, [x16, #0x10]'),
                   ('br', 'x16')])


class _Patched(unittest.TestCase):
    """Route ``disasm`` in the modules that read memory to a fake (the marks named)."""

    def setUp(self):
        name_marks(self)

    def patch(self, fake):
        for mod in (FB, C):
            orig = mod.disasm
            mod.disasm = fake
            self.addCleanup(setattr, mod, 'disasm', orig)


# Real listings (iPhone8 GeoServices) -------------------------------------------------

# Block invoke fn of -[GEOPublisherAttributionManifest writeTo:]: begin(F=1), key via the
# 0x...ac18 helper (w2=1), value via 0x...ac24 (w2=2), end.  Key/value pass straight
# through (string key, message value) — no unboxing selector.
_MANIFEST_INVOKE = (0x18ce4175c, [
    ('sub', 'sp, sp, #0x40'), ('stp', 'x22, x21, [sp, #0x10]'),
    ('stp', 'x20, x19, [sp, #0x20]'), ('stp', 'x29, x30, [sp, #0x30]'),
    ('add', 'x29, sp, #0x30'), ('mov', 'x19, x1'), ('mov', 'x20, x0'),
    ('str', 'xzr, [sp, #8]'), ('ldr', 'x21, [x0, #0x20]'),
    ('bl', '#0x18dbdbf74'), ('mov', 'x22, x0'), ('bl', '#0x18dbdbf68'),
    ('mov', 'x19, x0'), ('add', 'x1, sp, #8'), ('mov', 'x0, x21'),
    ('mov', 'w2, #1'), ('bl', '#0x18dbdab88'),                      # begin F=1
    ('ldr', 'x0, [x20, #0x20]'), ('mov', 'x1, x19'), ('mov', 'w2, #1'),
    ('bl', '#0x18dbdac18'),                                         # key
    ('bl', '#0x18dbdbe54'),
    ('ldr', 'x0, [x20, #0x20]'), ('mov', 'x1, x22'), ('mov', 'w2, #2'),
    ('bl', '#0x18dbdac24'),                                         # value
    ('bl', '#0x18dbdbe84'),
    ('ldr', 'x0, [x20, #0x20]'), ('add', 'x1, sp, #8'),
    ('bl', '#0x18dbdab94'),                                         # end
    ('ldp', 'x29, x30, [sp, #0x30]'), ('ldp', 'x20, x19, [sp, #0x20]'),
    ('ldp', 'x22, x21, [sp, #0x10]'), ('add', 'sp, sp, #0x40'), ('ret', ''),
])

# -[GEOPublisherAttributionManifest writeTo:] — builds the stack block and calls
# enumerateKeysAndObjectsUsingBlock:.  ivar offset variable at 0x1dcfb30e4 (value 8).
_MANIFEST_WRITETO = (0x18ce416d8, [
    ('sub', 'sp, sp, #0x50'), ('stp', 'x20, x19, [sp, #0x30]'),
    ('stp', 'x29, x30, [sp, #0x40]'), ('add', 'x29, sp, #0x40'),
    ('mov', 'x19, x0'), ('bl', '#0x18dbdbf74'),
    ('adrp', 'x8, #0x1dcfb3000'), ('ldrsw', 'x8, [x8, #0xe4]'),
    ('ldr', 'x19, [x19, x8]'),
    ('adrp', 'x8, #0x1dac91000'), ('ldr', 'x8, [x8, #0xec0]'),
    ('str', 'x8, [sp, #8]'),
    ('adrp', 'x8, #0x18d84c000'), ('ldr', 'd0, [x8, #0x288]'),
    ('adrp', 'x8, #0x18ce41000'), ('add', 'x8, x8, #0x75c'),            # invoke addr
    ('str', 'd0, [sp, #0x10]'),
    ('adrp', 'x9, #0x1d5f93000'), ('add', 'x9, x9, #0xaa8'),
    ('stp', 'x8, x9, [sp, #0x18]'),                                     # block+0x10
    ('str', 'x0, [sp, #0x28]'), ('bl', '#0x18dbdbefc'), ('str', 'x0, [sp]'),
    ('add', 'x2, sp, #8'), ('mov', 'x0, x19'),
    ('bl', '#0x18dae11e0'),                                             # enumerate stub
    ('ldr', 'x8, [sp, #0x28]'), ('bl', '#0x18dbdbee4'), ('ldr', 'x0, [sp]'),
    ('ldp', 'x29, x30, [sp, #0x40]'), ('ldp', 'x20, x19, [sp, #0x30]'),
    ('add', 'sp, sp, #0x50'), ('b', '#0x18dbdbe30'),
])

# Block invoke fn of GEOPublisherAttributionManifestIndex's map (F=2): the value is an
# NSNumber unboxed via a selector stub (here 0x18db2ce60 = unsignedIntValue) and written
# by the uint32 helper 0x...ac30.
_INDEX_INVOKE = (0x18ce434dc, [
    ('sub', 'sp, sp, #0x40'), ('stp', 'x22, x21, [sp, #0x10]'),
    ('stp', 'x20, x19, [sp, #0x20]'), ('stp', 'x29, x30, [sp, #0x30]'),
    ('add', 'x29, sp, #0x30'), ('mov', 'x19, x1'), ('mov', 'x20, x0'),
    ('str', 'xzr, [sp, #8]'), ('ldr', 'x21, [x0, #0x20]'),
    ('bl', '#0x18dbdbf74'), ('mov', 'x22, x0'), ('bl', '#0x18dbdbf68'),
    ('mov', 'x19, x0'), ('add', 'x1, sp, #8'), ('mov', 'x0, x21'),
    ('mov', 'w2, #2'), ('bl', '#0x18dbdab88'),
    ('ldr', 'x0, [x20, #0x20]'), ('mov', 'x1, x19'), ('mov', 'w2, #1'),
    ('bl', '#0x18dbdac18'), ('bl', '#0x18dbdbe54'),
    ('ldr', 'x19, [x20, #0x20]'), ('mov', 'x0, x22'),
    ('bl', '#0x18db2ce60'),                                            # unbox
    ('mov', 'x21, x0'), ('bl', '#0x18dbdbe84'),
    ('mov', 'x0, x19'), ('mov', 'x1, x21'), ('mov', 'w2, #2'),
    ('bl', '#0x18dbdac30'),                                            # uint32 value
    ('ldr', 'x0, [x20, #0x20]'), ('add', 'x1, sp, #8'),
    ('bl', '#0x18dbdab94'),
    ('ldp', 'x29, x30, [sp, #0x30]'), ('ldp', 'x20, x19, [sp, #0x20]'),
    ('ldp', 'x22, x21, [sp, #0x10]'), ('add', 'sp, sp, #0x40'), ('ret', ''),
])

# The inline enumeration loop body of CoreParsec -[_CPStruct writeTo:] (intKeyFields,
# F=2): the key is unboxed via a selector stub BETWEEN the begin mark and the key write.
# Regression: that stub `bl` still sees the begin's stale `add x1, sp` as the reaching
# x1 definition, so a naive "x1 is a stack scratch" test mistook it for the END mark.
_INLINE_LOOP = (0x19ba893e0, [
    ('str', 'xzr, [sp, #0x48]'), ('add', 'x1, sp, #0x48'), ('mov', 'x0, x19'),
    ('mov', 'w2, #2'), ('bl', '#0x1a2582db4'),                         # begin F=2
    ('mov', 'x0, x23'), ('bl', '#0x19bae49e0'),                        # [key intValue]
    ('mov', 'x1, x0'), ('mov', 'x0, x19'), ('mov', 'w2, #1'),
    ('bl', '#0x1a2582dfc'),                                            # key (int32)
    ('ldr', 'x0, [x20, x24]'), ('mov', 'x2, x23'),
    ('bl', '#0x19bae5480'),                                            # dict[key]
    ('bl', '#0x1a25830b4'), ('mov', 'x23, x0'),
    ('mov', 'x0, x19'), ('mov', 'x1, x23'), ('mov', 'w2, #2'),
    ('bl', '#0x1a2582e20'),                                            # value
    ('bl', '#0x1a2583198'),
    ('add', 'x1, sp, #0x48'), ('mov', 'x0, x19'), ('bl', '#0x1a2582dc0'),  # end
    ('add', 'x26, x26, #1'),
])


def _ctx_with_selectors(**sels):
    """FakeCtx whose selector slots resolve to the given names: ``{slot_page_addr: name}``."""
    ctx = FakeCtx()
    for slot, name in sels.items():
        addr = int(slot.lstrip('s'), 16)
        ctx.ptrs[addr] = 0xA000 + len(ctx.cstrs)
        ctx.cstrs[ctx.ptrs[addr]] = name
    return ctx


class TestAnalyzeEntry(_Patched):

    def _begin(self, insns):
        return next(i for i, x in enumerate(insns) if x.mnemonic == 'bl'
                    and scratch_slot_of(listing_flow(None, insns), i) is not None)

    def test_block_invoke_string_key_message_value(self):
        insns, fd = asm(_MANIFEST_INVOKE)
        self.patch(fd)
        e = M.analyze_entry(FakeCtx(), insns, self._begin(insns))
        self.assertEqual(e.number, 1)
        self.assertEqual((e.key_helper, e.value_helper), (0x18dbdac18, 0x18dbdac24))
        self.assertEqual((e.key_sel, e.value_sel), (None, None))

    def test_unboxing_selector_is_traced_to_the_value(self):
        insns, fd = asm(_INDEX_INVOKE, selector_stub(0x18db2ce60, 0x18d000000))
        self.patch(fd)
        ctx = _ctx_with_selectors(s18d000000='unsignedIntValue')
        e = M.analyze_entry(ctx, insns, self._begin(insns))
        self.assertEqual(e.number, 2)
        self.assertEqual(e.value_helper, 0x18dbdac30)
        self.assertEqual((e.key_sel, e.value_sel), (None, 'unsignedIntValue'))

    def test_selector_stub_call_after_begin_is_not_the_end_mark(self):
        insns, fd = asm(_INLINE_LOOP, selector_stub(0x19bae49e0, 0x19c000000))
        self.patch(fd)
        ctx = _ctx_with_selectors(s19c000000='intValue')
        e = M.analyze_entry(ctx, insns, self._begin(insns))
        self.assertEqual(e.number, 2)
        self.assertEqual((e.key_helper, e.value_helper), (0x1a2582dfc, 0x1a2582e20))
        self.assertEqual((e.key_sel, e.value_sel), ('intValue', None))

    def _mutate(self, edit):
        lines = list(_MANIFEST_INVOKE[1])
        edit(lines)
        insns, fd = asm((_MANIFEST_INVOKE[0], lines))
        self.patch(fd)
        return M.analyze_entry(FakeCtx(), insns, self._begin(insns))

    def test_no_end_mark_is_rejected(self):
        self.assertIsNone(self._mutate(lambda L: L.__delitem__(slice(-7, -4))))

    def test_second_write_of_a_subfield_is_rejected(self):
        def dup(L):
            i = L.index(('bl', '#0x18dbdac18'))
            L[i + 1:i + 1] = [('mov', 'w2, #1'), ('bl', '#0x18dbdac18')]
        self.assertIsNone(self._mutate(dup))

    def test_foreign_subfield_number_is_rejected(self):
        def third(L):
            i = L.index(('bl', '#0x18dbdac24'))
            L[i - 1] = ('mov', 'w2, #3')
        self.assertIsNone(self._mutate(third))

    def test_a_value_written_out_of_line_is_read(self):
        # the value's write past the ret, branched to and back (where a has-bit test puts it)
        def ool(L):
            base = _MANIFEST_INVOKE[0]
            i = L.index(('ldr', 'x0, [x20, #0x20]'), L.index(('bl', '#0x18dbdac18')))
            value = L[i:i + 5]
            del L[i:i + 5]
            L.insert(i, ('b', f'#{base + 4 * (len(L) + 1):#x}'))
            L.extend(value + [('b', f'#{base + 4 * (i + 1):#x}')])
        e = self._mutate(ool)
        self.assertEqual((e.number, e.key_helper, e.value_helper), (1, 0x18dbdac18, 0x18dbdac24))

    def test_a_path_that_returns_before_the_end_mark_is_rejected(self):
        def early(L):
            i = L.index(('bl', '#0x18dbdac18'))
            L.insert(i + 1, None)
            L[i + 1] = ('cbz', f'x0, #{_MANIFEST_INVOKE[0] + 4 * (len(L) - 1):#x}')   # to the ret
        self.assertIsNone(self._mutate(early))

    def test_not_a_begin_mark_is_rejected(self):
        insns, fd = asm(_MANIFEST_INVOKE)
        self.patch(fd)
        key_call = next(i for i, x in enumerate(insns) if x.op_str == '#0x18dbdac18')
        self.assertIsNone(M.analyze_entry(FakeCtx(), insns, key_call))


class TestScanBlockEnumeratedMaps(_Patched):

    def _scan(self, writeto=_MANIFEST_WRITETO, offset_to_name=None):
        insns, fd = asm(writeto, _MANIFEST_INVOKE,
                        selector_stub(0x18dae11e0, 0x18d100000))
        self.patch(fd)
        ctx = _ctx_with_selectors(s18d100000=M._ENUMERATE_SELECTOR)
        ctx.u32[0x1dcfb30e4] = 8                      # ivar-offset variable -> offset 8
        name = {8: '_publisherAttributionSources'} if offset_to_name is None else offset_to_name
        return M.scan_block_enumerated_maps(ctx, writeto[0], FunctionEntries([0x18ce417e8]), name)

    def test_block_map_is_found_and_bound_to_its_ivar(self):
        got = self._scan()
        self.assertEqual(list(got), ['_publisherAttributionSources'])
        e = got['_publisherAttributionSources']
        self.assertEqual((e.number, e.key_helper, e.value_helper, e.shape),
                         (1, 0x18dbdac18, 0x18dbdac24, 'block'))

    def test_block_at_stack_bottom_uses_mov_x2_sp(self):
        # GEOLPRRoot's second block sits at sp+0: `mov x2, sp` and the invoke pointer
        # at [sp,#0x10] — the same recovery must hold.
        lines = list(_MANIFEST_WRITETO[1])
        i = lines.index(('add', 'x2, sp, #8'))
        lines[i] = ('mov', 'x2, sp')
        lines[lines.index(('stp', 'x8, x9, [sp, #0x18]'))] = ('stp', 'x8, x9, [sp, #0x10]')
        got = self._scan((_MANIFEST_WRITETO[0], lines))
        self.assertEqual(got['_publisherAttributionSources'].number, 1)

    def test_unknown_ivar_offset_is_not_bound(self):
        self.assertEqual(self._scan(offset_to_name={999: '_other'}), {})

    def test_other_selector_is_not_a_map_write(self):
        insns, fd = asm(_MANIFEST_WRITETO, _MANIFEST_INVOKE,
                        selector_stub(0x18dae11e0, 0x18d100000))
        self.patch(fd)
        ctx = _ctx_with_selectors(s18d100000='enumerateObjectsUsingBlock:')
        ctx.u32[0x1dcfb30e4] = 8
        self.assertEqual(M.scan_block_enumerated_maps(
            ctx, _MANIFEST_WRITETO[0], FunctionEntries([0x18ce417e8]), {8: '_x'}), {})

    def test_invoke_without_ret_is_never_analysed(self):
        lines = [x for x in _MANIFEST_INVOKE[1] if x[0] != 'ret']
        insns, fd = asm(_MANIFEST_WRITETO, (_MANIFEST_INVOKE[0], lines),
                        selector_stub(0x18dae11e0, 0x18d100000))
        self.patch(fd)
        ctx = _ctx_with_selectors(s18d100000=M._ENUMERATE_SELECTOR)
        ctx.u32[0x1dcfb30e4] = 8
        self.assertEqual(M.scan_block_enumerated_maps(
            ctx, _MANIFEST_WRITETO[0], FunctionEntries([0x18ce417e8]), {8: '_x'}), {})


# Newer (arm64e, macOS 27) toolchain: the invoke pointer is PAC-signed in place, the
# dictionary ivar is reached by ``add xT,xSelf,xOff ; ldr xD,[xT]``, and the enumerate
# stub is ``adrp x1 ; add x1,x1,#o ; b objc_msgSend`` (x1 = the selector string itself).
_ARM64E_WRITETO = (0x199a2ef00, [
    ('pacibsp', ''), ('sub', 'sp, sp, #0x50'), ('stp', 'x20, x19, [sp, #0x30]'),
    ('stp', 'x29, x30, [sp, #0x40]'), ('add', 'x29, sp, #0x40'), ('mov', 'x19, x0'),
    ('mov', 'x0, x2'), ('bl', '#0x1a01057e0'),
    ('adrp', 'x8, #0x1e4941000'), ('ldrsw', 'x8, [x8, #0xdcc]'),
    ('add', 'x8, x19, x8'), ('ldr', 'x19, [x8]'),                       # the dictionary ivar
    ('add', 'x8, sp, #8'),
    ('adrp', 'x16, #0x1e0220000'), ('ldr', 'x16, [x16, #0x5a0]'),
    ('mov', 'x17, x8'), ('movk', 'x17, #0x6ae1, lsl #48'), ('pacda', 'x16, x17'),
    ('str', 'x16, [sp, #8]'),
    ('adrp', 'x9, #0x19b234000'), ('ldr', 'd0, [x9, #0xec8]'), ('str', 'd0, [sp, #0x10]'),
    ('add', 'x8, x8, #0x10'),
    ('adrp', 'x16, #0x199a2e000'), ('add', 'x16, x16, #0xfac'),         # invoke address
    ('pacia', 'x16, x8'),                                               # ... signed in place
    ('adrp', 'x8, #0x1e9d14000'), ('add', 'x8, x8, #0xfd8'),
    ('stp', 'x16, x8, [sp, #0x18]'), ('str', 'x0, [sp, #0x28]'),
    ('bl', '#0x1a01057e0'), ('mov', 'x20, x0'),
    ('add', 'x2, sp, #8'), ('mov', 'x0, x19'),
    ('bl', '#0x1a0013400'),                                             # enumerate stub
    ('ldr', 'x0, [sp, #0x28]'), ('bl', '#0x1a01057d0'),
    ('ldp', 'x29, x30, [sp, #0x40]'), ('ldp', 'x20, x19, [sp, #0x30]'),
    ('add', 'sp, sp, #0x50'), ('retab', ''),
])
_ARM64E_INVOKE = (0x199a2efac, [
    ('pacibsp', ''), ('sub', 'sp, sp, #0x40'), ('stp', 'x22, x21, [sp, #0x10]'),
    ('stp', 'x20, x19, [sp, #0x20]'), ('stp', 'x29, x30, [sp, #0x30]'),
    ('add', 'x29, sp, #0x30'), ('mov', 'x19, x1'), ('mov', 'x20, x0'),
    ('str', 'xzr, [sp, #8]'), ('ldr', 'x21, [x0, #0x20]'),
    ('mov', 'x0, x2'), ('bl', '#0x1a01057e0'), ('mov', 'x22, x0'),
    ('mov', 'x0, x19'), ('bl', '#0x1a01057e0'), ('mov', 'x19, x0'),
    ('add', 'x1, sp, #8'), ('mov', 'x0, x21'), ('mov', 'w2, #1'),
    ('bl', '#0x1a0103d00'),                                             # begin F=1
    ('ldr', 'x0, [x20, #0x20]'), ('mov', 'x1, x19'), ('mov', 'w2, #1'),
    ('bl', '#0x1a0103dc0'),                                             # key
    ('mov', 'x0, x19'), ('bl', '#0x1a01057d0'),
    ('ldr', 'x0, [x20, #0x20]'), ('mov', 'x1, x22'), ('mov', 'w2, #2'),
    ('bl', '#0x1a0103dd0'),                                             # value
    ('mov', 'x0, x22'), ('bl', '#0x1a01057d0'),
    ('ldr', 'x0, [x20, #0x20]'), ('add', 'x1, sp, #8'),
    ('bl', '#0x1a0103d10'),                                             # end
    ('ldp', 'x29, x30, [sp, #0x30]'), ('ldp', 'x20, x19, [sp, #0x20]'),
    ('ldp', 'x22, x21, [sp, #0x10]'), ('add', 'sp, sp, #0x40'), ('retab', ''),
])


class TestNewerToolchainBlockShape(_Patched):

    def _ctx(self):
        ctx = FakeCtx(u32={0x1e4941dcc: 8},
                      cstrs={0x1f57cb020: M._ENUMERATE_SELECTOR})
        return ctx

    MSGSEND = 0x1a0000800                  # _objc_msgSend in the cache

    def _stub(self):
        return (0x1a0013400, [('adrp', 'x1, #0x1f57cb000'), ('add', 'x1, x1, #0x20'),
                              ('b', f'#{self.MSGSEND:#x}')])

    def patch(self, fake):
        super().patch(fake)
        orig = C.callee_name                 # the shared stub is a send only to a named objc_msgSend
        C.callee_name = lambda ctx, va: '_objc_msgSend' if va == self.MSGSEND else orig(ctx, va)
        self.addCleanup(setattr, C, 'callee_name', orig)

    def test_pac_signed_invoke_and_add_ldr_ivar_load_are_recovered(self):
        insns, fd = asm(_ARM64E_WRITETO, _ARM64E_INVOKE, self._stub())
        self.patch(fd)
        got = M.scan_block_enumerated_maps(self._ctx(), _ARM64E_WRITETO[0], FunctionEntries([0x199a3000]),
                                           {8: '_vehicles'})
        e = got['_vehicles']
        self.assertEqual((e.number, e.key_helper, e.value_helper),
                         (1, 0x1a0103dc0, 0x1a0103dd0))

    def test_new_shape_stub_selector_is_read_from_the_literal(self):
        insns, fd = asm(self._stub())
        self.patch(fd)
        self.assertEqual(C.stub_selector(self._ctx(), 0x1a0013400), M._ENUMERATE_SELECTOR)
        self.assertIsNone(C.stub_selector(self._ctx(), 0x1a0013410))   # unmapped target

    def test_offset_variable_ignores_an_earlier_unrelated_adrp_add_on_the_same_register(self):
        # A function-wide prefix holds an UNRELATED `adrp x8 ; add x8,x8,#o` (a block
        # descriptor); the ivar's offset variable is the LATER `adrp x8 ; ldrsw x8,[x8,#k]`.
        # Scanning the prefix for the first adrp+add pair would resolve the wrong address.
        insns, fd = asm((0x1000, [
            ('adrp', 'x8, #0x1e9d0f000'), ('add', 'x8, x8, #0x798'),
            ('stp', 'x16, x8, [sp, #0x38]'),
            ('adrp', 'x8, #0x1e493e000'), ('ldrsw', 'x8, [x8, #0xfa8]'),
            ('add', 'x8, x20, x8'), ('ldr', 'x20, [x8]'), ('mov', 'x0, x20'),
            ('bl', '#0x9000')]))
        ctx = FakeCtx(u32={0x1e493efa8: 32})
        self.assertEqual(M._trace_ivar(ctx, listing_flow(ctx, insns), len(insns) - 1, 'x0',
                                       {32: '_vehicleTypes'}),
                         '_vehicleTypes')


class TestFindMapWriters(_Patched):

    def test_number_collision_drops_the_writer(self):
        insns, fd = asm(_MANIFEST_WRITETO, _MANIFEST_INVOKE,
                        selector_stub(0x18dae11e0, 0x18d100000))
        self.patch(fd)
        ctx = _ctx_with_selectors(s18d100000=M._ENUMERATE_SELECTOR)
        ctx.u32[0x1dcfb30e4] = 8
        ctx._function_entries = {0x18ce417e8}

        class _Method:
            imp = _MANIFEST_WRITETO[0]

        class _Cls:
            name = 'GEOFake'
            def get_method(self, sel):
                return _Method() if sel == 'writeTo:' else None

        class _Iv:
            name, offset, type_enc = '_publisherAttributionSources', 8, '@"NSMutableDictionary"'

        ok = M.find_map_writers(ctx, _Cls(), [_Iv()], {}, {8: _Iv.name}, {})
        self.assertEqual(ok[_Iv.name].number, 1)
        clash = M.find_map_writers(ctx, _Cls(), [_Iv()], {}, {8: _Iv.name}, {'_other': 1})
        self.assertEqual(clash, {})


# ── write-helper types ────────────────────────────────────────────────────────


class TestHelperVotes(unittest.TestCase):

    def setUp(self):
        # Canonicalisation = identity, family = plain, so votes test the table itself.
        for name, repl in (('real_target', lambda ctx, va: va),
                           ('_classify_write_helper', lambda ctx, va: 'plain')):
            orig = getattr(M, name)
            setattr(M, name, repl)
            self.addCleanup(setattr, M, name, orig)
        self.ctx = FakeCtx()

    class _Iv:
        def __init__(self, name, enc):
            self.name, self.type_enc = name, enc

    def _vote(self, ivars, helpers, protos=frozenset({'GEOMsg'})):
        M.record_helper_votes(self.ctx, ivars, helpers, protos)

    def test_unanimous_kinds(self):
        I = self._Iv
        self._vote([I('_a', '@"NSString"'), I('_b', '@"NSString"'), I('_c', '@"GEOMsg"'),
                    I('_d', 'I'), I('_e', '@"NSData"'), I('_f', 'B')],
                   {'_a': 0x10, '_b': 0x10, '_c': 0x20, '_d': 0x30, '_e': 0x40, '_f': 0x50})
        self.assertEqual([M.helper_kind(self.ctx, h) for h in (0x10, 0x20, 0x30, 0x40, 0x50)],
                         ['string', 'message', 'uint32', 'bytes', 'bool'])

    def test_conflicting_votes_are_not_guessed(self):
        I = self._Iv
        self._vote([I('_a', 'i'), I('_b', 'I')], {'_a': 0x10, '_b': 0x10})
        self.assertIsNone(M.helper_kind(self.ctx, 0x10))

    def test_unseen_helper_is_unknown(self):
        self.assertIsNone(M.helper_kind(self.ctx, 0x99))

    def test_arrays_dictionaries_and_unknown_objects_do_not_vote(self):
        I = self._Iv
        self._vote([I('_a', '@"NSMutableArray"'), I('_b', '@"NSMutableDictionary"'),
                    I('_c', '@"NSObject"'), I('_d', '{?="list"^i"count"Q"size"Q}')],
                   {'_a': 0x10, '_b': 0x20, '_c': 0x30, '_d': 0x40})
        self.assertEqual(getattr(self.ctx, '_helper_votes', {}), {})

    def test_int_votes_are_refined_by_wire_family(self):
        M._classify_write_helper = lambda ctx, va: 'sint32'
        I = self._Iv
        self._vote([I('_a', 'i')], {'_a': 0x10})
        self.assertEqual(M.helper_kind(self.ctx, 0x10), 'sint32')


class TestResolveMapTypes(unittest.TestCase):

    def setUp(self):
        self.kinds = {1: 'string', 2: 'message', 3: 'uint32', 4: 'bytes', 5: 'string', 6: 'int32'}
        self.classes = {'GEOVal'}
        for name, repl in (('helper_kind', lambda ctx, va: self.kinds.get(va)),
                           ('readfrom_value_classes',
                            lambda ctx, cls, n, ci, known: set(self.classes))):
            orig = getattr(M, name)
            setattr(M, name, repl)
            self.addCleanup(setattr, M, name, orig)

    def resolve(self, key=1, value=2, **kw):
        w = M.MapEntryWriter(number=1, key_helper=key, value_helper=value, **kw)
        return M.resolve_map_types(None, None, w, {}, frozenset({'GEOVal'}))

    def test_string_to_message(self):
        t = self.resolve()
        self.assertEqual((t.key_type, t.value_type, t.value_class, t.reason),
                         ('string', 'message', 'GEOVal', None))

    def test_string_to_scalar_requires_readfrom_to_allocate_nothing(self):
        self.classes = set()
        t = self.resolve(value=3)
        self.assertEqual((t.key_type, t.value_type, t.value_class, t.reason),
                         ('string', 'uint32', None, None))

    def test_scalar_value_but_readfrom_allocates_a_class_is_not_resolved(self):
        t = self.resolve(value=3)                   # classes still {'GEOVal'}
        self.assertIsNone(t.value_type)
        self.assertIn('readFrom: allocates GEOVal', t.reason)

    def test_message_value_with_ambiguous_classes_keeps_the_proof_but_no_class(self):
        self.classes = {'GEOVal', 'GEOOther'}
        t = self.resolve()
        self.assertEqual((t.key_type, t.value_type, t.value_class), ('string', 'message', None))
        self.assertIn('no single value class', t.reason)

    def test_int_key_and_illegal_key_kinds(self):
        self.classes = set()
        self.assertEqual(self.resolve(key=6, value=1).key_type, 'int32')
        for bad in (4, 2, None):                     # bytes / message / unseen helper
            self.assertIsNone(self.resolve(key=bad, value=1).key_type)

    def test_unboxing_selector_must_agree_with_the_helper_type(self):
        self.classes = set()
        ok = self.resolve(key=6, value=3, key_sel='intValue', value_sel='unsignedIntValue')
        self.assertEqual((ok.key_type, ok.value_type, ok.reason), ('int32', 'uint32', None))
        bad = self.resolve(key=6, value=3, key_sel='longLongValue')
        self.assertIsNone(bad.key_type)
        self.assertIn('longLongValue', bad.reason)
        unknown_sel = self.resolve(key=6, value=3, key_sel='someOtherSelector')
        self.assertEqual(unknown_sel.key_type, 'int32')


# ── field application + emission ──────────────────────────────────────────────


def _field(**kw):
    base = dict(name='m', number=1, type_name='NSMutableDictionary', label=FieldLabel.OPTIONAL,
                type_class='NSMutableDictionary', number_confirmed=True,
                type_inference_note=M._MAP_FIELD_NOTE)
    base.update(kw)
    return ProtoField(**base)


class TestApplyMapTypes(unittest.TestCase):

    def test_full_recovery_clears_the_note_and_stays_singular(self):
        f = _field()
        M._apply_map_types(f, M.MapTypes('string', 'message', 'GEOVal'))
        self.assertEqual((f.map_key_type, f.map_value_class, f.map_value_type), ('string', 'GEOVal', None))
        self.assertIsNone(f.type_inference_note)
        self.assertIs(f.label, FieldLabel.OPTIONAL)

    def test_scalar_value(self):
        f = _field()
        M._apply_map_types(f, M.MapTypes('string', 'uint32'))
        self.assertEqual((f.map_key_type, f.map_value_type), ('string', 'uint32'))

    def test_message_value_of_unknown_class_degrades_to_bytes_with_a_note(self):
        f = _field()
        M._apply_map_types(f, M.MapTypes('string', 'message', None, 'why'))
        self.assertEqual((f.map_key_type, f.map_value_type), ('string', 'bytes'))
        self.assertIn('why', f.type_inference_note)

    def test_unrecovered_types_become_repeated_bytes_of_entries(self):
        f = _field()
        M._apply_map_types(f, M.MapTypes(None, 'string', None, 'key write helper not identified'))
        self.assertIsNone(f.map_key_type)
        self.assertIs(f.label, FieldLabel.REPEATED)
        self.assertIn('map-entry message', f.type_inference_note)
        self.assertIn('key write helper not identified', f.type_inference_note)


def _msg(class_name, *fields):
    return ProtoMessage(name=class_name.replace('GEO', '', 1), class_name=class_name,
                        fields=list(fields))


def _emit(*messages):
    return {pf.filename: pf.emit({m.class_name: m.package or E_pkg(m.class_name)
                                  for m in messages})
            for pf in build_proto_files(list(messages))}


def E_pkg(class_name):
    from proto.emitter import package_for_class
    return package_for_class(class_name)


class TestMapEmission(unittest.TestCase):

    def test_scalar_map_renders_without_an_estimate_comment(self):
        f = _field(name='fileIndex', number=2, map_key_type='string', map_value_type='uint32',
                   type_inference_note=None)
        out = _emit(_msg('GEOIndex', f))['geo.proto']
        self.assertIn('  map<string, uint32> fileIndex = 2;\n', out)

    def test_message_value_resolves_to_the_proto_message_name(self):
        f = _field(name='sources', number=1, map_key_type='string', map_value_class='GEOSource',
                   type_inference_note=None)
        out = _emit(_msg('GEOManifest', f), _msg('GEOSource'))['geo.proto']
        self.assertIn('  map<string, Source> sources = 1;\n', out)

    def test_unextracted_value_class_degrades_to_bytes_and_is_flagged(self):
        f = _field(name='sources', number=1, map_key_type='string', map_value_class='GEOGone',
                   type_inference_note=None)
        out = _emit(_msg('GEOManifest', f))['geo.proto']
        self.assertIn('map<string, bytes> sources = 1;  // unresolved: GEOGone', out)

    def test_cross_package_value_is_qualified_and_imported(self):
        f = _field(name='fields', number=1, map_key_type='string', map_value_class='CLPValue',
                   type_inference_note=None)
        files = _emit(_msg('GEOStruct', f), _msg('CLPValue'))
        self.assertIn('map<string, clp.CLPValue> fields = 1;', files['geo.proto'])
        self.assertIn('import "clp.proto";', files['geo.proto'])

    def _cyclic_pair(self):
        # GEOStruct holds map<string, CLPValue>; CLPValue holds a GEOStruct (the
        # CoreParsec _CPStruct <-> _CPValue shape) -> geo.proto and clp.proto would
        # import each other.
        m = _field(name='fields', number=1, map_key_type='string', map_value_class='CLPValue',
                   type_inference_note=None)
        back = _field(name='structValue', number=5, type_name='GEOStruct',
                      type_class='GEOStruct', type_inference_note=None)
        return [_msg('GEOStruct', m), _msg('CLPValue', back)], m

    def test_map_value_that_would_close_an_import_cycle_degrades_to_bytes(self):
        msgs, m = self._cyclic_pair()
        files = {pf.filename: pf.emit({x.class_name: E_pkg(x.class_name) for x in msgs})
                 for pf in build_proto_files(msgs)}
        self.assertIn('map<string, bytes> fields = 1;  // map value is message CLPValue',
                      files['geo.proto'])
        self.assertIn('import each other', files['geo.proto'])
        self.assertNotIn('import "clp.proto"', files['geo.proto'])
        self.assertIn('import "geo.proto";', files['clp.proto'])   # the other edge is kept
        self.assertIsNone(m.map_value_class)

    def test_cycle_breaking_is_stable_across_rebuilds(self):
        msgs, m = self._cyclic_pair()
        build_proto_files(msgs)
        again = {pf.filename: pf.emit({x.class_name: E_pkg(x.class_name) for x in msgs})
                 for pf in build_proto_files(msgs)}
        self.assertIn('map<string, bytes> fields = 1;', again['geo.proto'])

    def test_acyclic_map_value_is_left_typed(self):
        m = _field(name='fields', number=1, map_key_type='string', map_value_class='CLPValue',
                   type_inference_note=None)
        files = _emit(_msg('GEOStruct', m), _msg('CLPValue'))
        self.assertIn('map<string, clp.CLPValue> fields = 1;', files['geo.proto'])

    @unittest.skipUnless(shutil.which('protoc'), 'protoc not on PATH')
    def test_cycle_broken_output_compiles_with_protoc(self):
        msgs, _m = self._cyclic_pair()
        files = {pf.filename: pf.emit({x.class_name: E_pkg(x.class_name) for x in msgs})
                 for pf in build_proto_files(msgs)}
        with tempfile.TemporaryDirectory() as d:
            for name, text in files.items():
                with open(os.path.join(d, name), 'w') as fh:
                    fh.write(text)
            r = subprocess.run(['protoc', f'--proto_path={d}', '--descriptor_set_out=/dev/null']
                               + [os.path.join(d, n) for n in files], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_repeated_bytes_fallback_keeps_its_note(self):
        f = _field(name='m', number=3, label=FieldLabel.REPEATED,
                   type_inference_note=M._MAP_UNRESOLVED_NOTE.format(reason='r'))
        out = _emit(_msg('GEOX', f))['geo.proto']
        self.assertIn('repeated bytes m = 3;', out)
        self.assertIn('map-entry message', out)

    def test_resolve_type_refs_is_idempotent_for_maps(self):
        f = _field(map_key_type='string', map_value_class='GEOSource', type_inference_note=None)
        msgs = [_msg('GEOManifest', f), _msg('GEOSource')]
        build_proto_files(msgs)
        first = (f.map_value_type, f.unresolved_type_class)
        build_proto_files(msgs)
        self.assertEqual((f.map_value_type, f.unresolved_type_class), first)
        self.assertEqual(first, ('Source', None))

    @unittest.skipUnless(shutil.which('protoc'), 'protoc not on PATH')
    def test_emitted_map_fields_compile_with_protoc(self):
        fs = [_field(name='a', number=1, map_key_type='string', map_value_class='GEOSource',
                     type_inference_note=None),
              _field(name='b', number=2, map_key_type='int32', map_value_type='bytes',
                     type_inference_note=None),
              _field(name='c', number=3, map_key_type='string', map_value_type='string',
                     type_inference_note=None)]
        files = _emit(_msg('GEOManifest', *fs), _msg('GEOSource'))
        with tempfile.TemporaryDirectory() as d:
            for name, text in files.items():
                with open(os.path.join(d, name), 'w') as fh:
                    fh.write(text)
            r = subprocess.run(['protoc', f'--proto_path={d}', '--descriptor_set_out=/dev/null']
                               + [os.path.join(d, n) for n in files], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)


# ── live: CoreParsec inline-loop maps (+ PET, which has no entry writer) ──────


class TestLiveCoreParsec(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        import live_artifacts as V
        loaded = V.load_cache("CoreParsec")
        if loaded is None:
            raise unittest.SkipTest("CoreParsec dyld cache not available")
        ctx, st, cl = loaded
        msgs = E.extract_all(ctx, st, cl)
        # Snapshot the extractor's own state BEFORE any emission (resolve_type_refs /
        # cycle breaking legitimately rewrite map value fields); emit from a copy.
        cls.recovered = {(m.class_name, f.name): (f.number, f.number_confirmed, f.map_key_type,
                                                  f.map_value_type, f.map_value_class,
                                                  f.type_inference_note, f.label)
                         for m in msgs for f in m.fields if f.map_key_type or
                         f.type_class in E._MAP_OBJC_CLASSES}
        cls.msgs = copy.deepcopy(msgs)

    def test_recovered_shapes(self):
        want = {
            ('_CPStruct', 'stringKeyFields'): (1, 'string', None, '_CPValue'),
            ('_CPStruct', 'intKeyFields'): (2, 'int32', None, '_CPValue'),
            ('_CPClientSession', 'resourceVersions'): (3, 'string', 'string', None),
            ('_CPStartNetworkSearchFeedback', 'headers'): (6, 'string', 'string', None),
        }
        for key, (num, kt, vt, vc) in want.items():
            n, conf, mk, mv, mc, note, label = self.recovered[key]
            self.assertEqual((n, conf, mk, mv, mc), (num, True, kt, vt, vc), key)
            self.assertIsNone(note, key)
            self.assertIs(label, FieldLabel.OPTIONAL, key)

    @unittest.skipUnless(shutil.which('protoc'), 'protoc not on PATH')
    def test_emitted_files_with_maps_compile_together(self):
        with tempfile.TemporaryDirectory() as d:
            paths, _pfs = write_from_messages(copy.deepcopy(self.msgs), Path(d))
            read = lambda name: Path(d, name).read_text()
            self.assertIn('map<string, string> resourceVersions = 3;',
                          read('_cpclientsession.proto'))
            # _CPStruct <-> _CPValue are mutually recursive across per-class files: typing
            # the map values would be an import cycle, so they are degraded (flagged).
            text = read('_cpstruct.proto')
            self.assertIn('map<string, bytes> stringKeyFields = 1;  // map value is message '
                          '_CPValue', text)
            self.assertIn('map<int32, bytes> intKeyFields = 2;  // map value is message '
                          '_CPValue', text)
            r = subprocess.run(['protoc', f'--proto_path={d}', '--descriptor_set_out=/dev/null']
                               + [str(p) for p in paths], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)


if __name__ == '__main__':
    unittest.main()
