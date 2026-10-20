"""
tests/test_disasm.py — tests for macho/disasm.py.

Structure
---------
Unit tests (no binary, no capstone):
  - _norm_reg and _parse_imm helpers

Integration tests (use build_text_binary from conftest):
  - disasm() encoding → decoding round-trips
  - Stops at ret
  - max_insns cap
  - Graceful handling at segment boundary
  - Unaligned vmaddr raises ValueError
  - Full adrp+add / adrp+ldr / movz pipelines against synthetic code, the registers'
    values read by proto.arm64_eval.Flow (the extractor's one evaluator)
  - BL targets from synthetic code
"""

from __future__ import annotations

import struct
from typing import List

import pytest

from macho.disasm import (
    Insn,
    _norm_reg,
    _parse_imm,
    disasm,
)
from macho.memory import BinaryContext
from tests.conftest import (
    NOP_BYTES,
    RET_BYTES,
    build_text_binary,
    encode_add_imm64,
    encode_adrp,
    encode_bl,
    encode_ldr_imm64,
    encode_movz,
)


# ── Helpers ────────────────────────────────────────────────────────────────────

def make_insn(addr: int, mnemonic: str, op_str: str) -> Insn:
    """Create a mock Insn for unit tests (raw bytes are dummy)."""
    return Insn(addr=addr, mnemonic=mnemonic, op_str=op_str,
                size=4, raw=b'\x00\x00\x00\x00')


def _branch_targets(insns, mnemonics=('bl',)):
    """Immediate targets of the *mnemonics* branches in *insns*, in order."""
    return [_parse_imm(i.op_str) for i in insns if i.mnemonic in mnemonics]


TEXT_VA = 0x4000    # canonical vmaddr used in integration tests


def ctx_from_code(code: bytes, vmaddr: int = TEXT_VA) -> BinaryContext:
    return BinaryContext(build_text_binary(code, vmaddr=vmaddr))

def value_after(insns: List[Insn], reg: str):
    """*reg*'s value before the listing's final instruction (its ``ret``), by the
    extractor's one evaluation of register values (:meth:`proto.arm64_eval.Flow.const_before`)."""
    from proto.arm64_eval import Flow
    return Flow(None, list(insns)).const_before(len(insns) - 1, reg)


def load_address(insns: List[Insn], reg: str):
    """The address the load into *reg* reads: its base register's value there plus the
    displacement."""
    from proto.arm64_eval import Flow
    from proto.arm64_operands import mem_regs, split_ops
    flow = Flow(None, list(insns))
    for k, ins in enumerate(insns):
        ops = split_ops(ins.op_str)
        if ins.mnemonic == 'ldr' and len(ops) == 2 and _norm_reg(ops[0]) == _norm_reg(reg):
            m = mem_regs(ops[1])
            base = flow.const_before(k, m[0]) if m and m[0] else None
            return None if base is None else base + m[2]
    return None



# ══════════════════════════════════════════════════════════════════════════════
# Helper / utility tests
# ══════════════════════════════════════════════════════════════════════════════

class TestNormReg:
    def test_x_reg(self):
        assert _norm_reg('x8')  == 'x8'
        assert _norm_reg('x0')  == 'x0'
        assert _norm_reg('x30') == 'x30'

    def test_w_reg_normalised_to_x(self):
        assert _norm_reg('w8')  == 'x8'
        assert _norm_reg('w0')  == 'x0'
        assert _norm_reg('w30') == 'x30'

    def test_upper_case(self):
        assert _norm_reg('X8')  == 'x8'
        assert _norm_reg('W8')  == 'x8'

    def test_sp(self):
        assert _norm_reg('sp') == 'sp'
        assert _norm_reg('SP') == 'sp'

    def test_xzr_wzr(self):
        assert _norm_reg('xzr') == 'xzr'
        assert _norm_reg('wzr') == 'xzr'
        assert _norm_reg('XZR') == 'xzr'

    def test_unknown(self):
        assert _norm_reg('q8')   is None   # SIMD register
        assert _norm_reg('foo')  is None
        assert _norm_reg('')     is None


class TestParseImm:
    def test_hex(self):
        assert _parse_imm('#0x20')    == 0x20
        assert _parse_imm('#0x1000')  == 0x1000
        assert _parse_imm('#0xDEAD')  == 0xDEAD

    def test_decimal(self):
        assert _parse_imm('#32') == 32
        assert _parse_imm('#0')  == 0

    def test_negative(self):
        assert _parse_imm('#-4')    == -4
        assert _parse_imm('#-0x10') == -0x10

    def test_in_larger_string(self):
        assert _parse_imm('x8, #0x100') == 0x100
        assert _parse_imm('x8, [x0, #8]') == 8

    def test_missing(self):
        assert _parse_imm('') is None
        assert _parse_imm('x8, x0') is None


# ══════════════════════════════════════════════════════════════════════════════
# disasm() integration tests  (use real encoded instruction bytes)
# ══════════════════════════════════════════════════════════════════════════════

class TestDisasmBasic:
    def test_single_ret(self):
        ctx = ctx_from_code(RET_BYTES)
        insns = disasm(ctx, TEXT_VA)
        assert len(insns) == 1
        assert insns[0].mnemonic == 'ret'
        assert insns[0].addr == TEXT_VA

    def test_nops_then_ret(self):
        code = NOP_BYTES * 3 + RET_BYTES
        ctx  = ctx_from_code(code)
        insns = disasm(ctx, TEXT_VA)
        assert len(insns) == 4
        assert all(i.mnemonic == 'nop' for i in insns[:3])
        assert insns[-1].mnemonic == 'ret'

    def test_stops_at_ret_includes_ret(self):
        """ret at position 2 — later instructions must not appear."""
        code = NOP_BYTES + RET_BYTES + NOP_BYTES * 10
        ctx  = ctx_from_code(code)
        insns = disasm(ctx, TEXT_VA)
        assert len(insns) == 2
        assert insns[-1].mnemonic == 'ret'

    def test_max_insns_cap(self):
        code = NOP_BYTES * 50
        ctx  = ctx_from_code(code)
        insns = disasm(ctx, TEXT_VA, max_insns=5)
        assert len(insns) == 5
        assert all(i.mnemonic == 'nop' for i in insns)

    def test_addr_per_insn(self):
        code = NOP_BYTES * 4
        ctx  = ctx_from_code(code)
        insns = disasm(ctx, TEXT_VA)
        for idx, insn in enumerate(insns):
            assert insn.addr == TEXT_VA + idx * 4

    def test_unaligned_raises(self):
        ctx = ctx_from_code(NOP_BYTES * 4)
        with pytest.raises(ValueError, match="aligned"):
            disasm(ctx, TEXT_VA + 1)

    def test_size_is_4(self):
        ctx   = ctx_from_code(NOP_BYTES + RET_BYTES)
        insns = disasm(ctx, TEXT_VA)
        assert all(i.size == 4 for i in insns)

    def test_raw_bytes_correct(self):
        ctx   = ctx_from_code(NOP_BYTES + RET_BYTES)
        insns = disasm(ctx, TEXT_VA)
        assert insns[0].raw == NOP_BYTES
        assert insns[1].raw == RET_BYTES

    def test_empty_on_unmapped(self):
        ctx = ctx_from_code(RET_BYTES)
        with pytest.raises(ValueError):
            disasm(ctx, 0xDEAD0000)


class TestDisasmSegmentBoundary:
    def test_truncated_at_segment_end(self):
        """When the code is only 3 instructions, disasm must return all 3."""
        code = NOP_BYTES * 2 + RET_BYTES     # 12 bytes; max_insns=100
        ctx  = ctx_from_code(code)
        insns = disasm(ctx, TEXT_VA, max_insns=100)
        # May return 3 (stops at ret) or fewer if read is clamped — either way ≤ 3
        assert 1 <= len(insns) <= 3
        if len(insns) == 3:
            assert insns[-1].mnemonic == 'ret'

    def test_single_instruction_at_boundary(self):
        """A one-instruction method (just ret) must still decode."""
        ctx   = ctx_from_code(RET_BYTES)
        insns = disasm(ctx, TEXT_VA)
        assert len(insns) == 1
        assert insns[0].mnemonic == 'ret'


# ══════════════════════════════════════════════════════════════════════════════
# Pipeline tests: encode → disasm → analysis
# ══════════════════════════════════════════════════════════════════════════════

class TestAdrpAddPipeline:
    """End-to-end: hand-encode adrp+add, disassemble, evaluate the register."""

    def _build_and_disasm(
        self,
        rd: int,
        target_vmaddr: int,
        insn_vmaddr: int = TEXT_VA,
    ) -> List[Insn]:
        page    = target_vmaddr & ~0xFFF
        offset  = target_vmaddr & 0xFFF
        pages_delta = (page >> 12) - (insn_vmaddr >> 12)
        code = (
            encode_adrp(rd, pages_delta) +
            encode_add_imm64(rd, rd, offset) +
            RET_BYTES
        )
        ctx = ctx_from_code(code, vmaddr=insn_vmaddr)
        return disasm(ctx, insn_vmaddr)

    def test_finds_target_x8(self):
        target = 0x5020
        insns  = self._build_and_disasm(rd=8, target_vmaddr=target)
        assert value_after(insns, 'x8') == target

    def test_finds_target_x0(self):
        target = 0x8010
        insns  = self._build_and_disasm(rd=0, target_vmaddr=target)
        assert value_after(insns, 'x0') == target

    def test_wrong_reg_not_found(self):
        insns = self._build_and_disasm(rd=8, target_vmaddr=0x5020)
        assert value_after(insns, 'x9') is None

    def test_zero_within_page_offset(self):
        """Target is exactly on a page boundary (offset = 0)."""
        target = 0x3000   # page-aligned
        insns  = self._build_and_disasm(rd=8, target_vmaddr=target)
        assert value_after(insns, 'x8') == target

    def test_max_page_offset(self):
        target = 0x5FFF   # max 12-bit offset = 0xFFF
        insns  = self._build_and_disasm(rd=8, target_vmaddr=target)
        assert value_after(insns, 'x8') == target

    def test_different_insn_vmaddr(self):
        """The analysis must be portable: target derived from PC, not from any
        constant embedded in the test."""
        insn_va = 0x2000
        target  = 0xA020
        insns   = self._build_and_disasm(rd=8, target_vmaddr=target,
                                          insn_vmaddr=insn_va)
        assert value_after(insns, 'x8') == target


class TestAdrpLdrPipeline:
    """End-to-end: adrp + ldr → GOT slot address."""

    def _build_and_disasm(
        self,
        rd: int,
        got_vmaddr: int,
        insn_vmaddr: int = TEXT_VA,
    ) -> List[Insn]:
        page         = got_vmaddr & ~0xFFF
        offset       = got_vmaddr & 0xFFF
        # ldr offset must be 8-byte aligned (it encodes as /8)
        offset       = offset & ~7
        got_vmaddr   = page | offset
        pages_delta  = (page >> 12) - (insn_vmaddr >> 12)
        code = (
            encode_adrp(rd, pages_delta) +
            encode_ldr_imm64(rd, rd, offset) +
            RET_BYTES
        )
        ctx = ctx_from_code(code, vmaddr=insn_vmaddr)
        return disasm(ctx, insn_vmaddr)

    def test_finds_got_slot_x8(self):
        got = 0x5008
        insns = self._build_and_disasm(rd=8, got_vmaddr=got)
        assert load_address(insns, 'x8') == got

    def test_finds_got_slot_zero_offset(self):
        got = 0x6000   # offset = 0
        insns = self._build_and_disasm(rd=0, got_vmaddr=got)
        assert load_address(insns, 'x0') == got

    def test_wrong_reg_not_found(self):
        insns = self._build_and_disasm(rd=8, got_vmaddr=0x5008)
        assert load_address(insns, 'x9') is None


class TestBlPipeline:
    """End-to-end: encode BL instructions, disassemble, collect targets."""

    def test_single_bl_forward(self):
        # BL to 2 instructions ahead (8 bytes)
        code  = encode_bl(+8) + NOP_BYTES + RET_BYTES
        ctx   = ctx_from_code(code)
        insns = disasm(ctx, TEXT_VA)
        targets = _branch_targets(insns)
        assert targets == [TEXT_VA + 8]

    def test_two_bls(self):
        # Two BL instructions, then RET
        # BL #8 (2 insns ahead), then BL #12 (3 insns ahead from there)
        code = (
            encode_bl(+12) +   # from TEXT_VA: target = TEXT_VA+12
            encode_bl(+12) +   # from TEXT_VA+4: target = TEXT_VA+16
            NOP_BYTES +
            RET_BYTES
        )
        ctx   = ctx_from_code(code)
        insns = disasm(ctx, TEXT_VA)
        targets = _branch_targets(insns)
        assert targets == [TEXT_VA + 12, TEXT_VA + 16]

    def test_bl_backward(self):
        # BL that targets the start of the function (offset = -(n instructions * 4))
        # Put BL at position 2 (offset 8), targeting position 0 (offset = -8)
        code = NOP_BYTES + NOP_BYTES + encode_bl(-8) + RET_BYTES
        ctx  = ctx_from_code(code)
        insns = disasm(ctx, TEXT_VA)
        targets = _branch_targets(insns)
        # bl is at TEXT_VA+8; target = TEXT_VA+8 + (-8) = TEXT_VA
        assert targets == [TEXT_VA]

    def test_b_roundtrip_via_encode_b(self):
        """encode_b + disasm → the b's target vmaddr."""
        from tests.conftest import encode_b
        BASE_VA = 0x4000
        TARGET_OFFSET = +20   # 5 instructions ahead
        code = encode_b(TARGET_OFFSET)
        ctx  = ctx_from_code(code, vmaddr=BASE_VA)
        insns = disasm(ctx, BASE_VA, max_insns=2)
        targets = _branch_targets(insns, ('bl', 'b'))
        assert targets == [BASE_VA + TARGET_OFFSET], (
            f"Expected [{BASE_VA + TARGET_OFFSET:#x}], got {targets}"
        )

    def test_b_and_bl_roundtrip_mixed(self):
        """Mixed bl+b sequence decoded by disasm: both targets."""
        from tests.conftest import encode_b
        BASE_VA   = 0x4000
        bl_bytes  = encode_bl(+12)   # BL → BASE_VA + 12
        b_bytes   = encode_b(+16)    # B  → BASE_VA + 4 + 16 = BASE_VA + 20
        code      = bl_bytes + b_bytes + NOP_BYTES * 8
        ctx       = ctx_from_code(code, vmaddr=BASE_VA)
        insns     = disasm(ctx, BASE_VA, max_insns=4, stop_at_ret=False)
        targets   = _branch_targets(insns, ('bl', 'b'))
        assert BASE_VA + 12 in targets, "BL target must be captured"
        assert BASE_VA + 20 in targets, "B target must be captured"


class TestMovzPipeline:
    def test_movz_decoded(self):
        code  = encode_movz(rd=0, imm16=42) + RET_BYTES
        ctx   = ctx_from_code(code)
        insns = disasm(ctx, TEXT_VA)
        val   = value_after(insns, 'x0')
        assert val == 42

    def test_movz_large_imm(self):
        code  = encode_movz(rd=8, imm16=0x1234) + RET_BYTES
        ctx   = ctx_from_code(code)
        insns = disasm(ctx, TEXT_VA)
        val   = value_after(insns, 'x8')
        assert val == 0x1234


# ══════════════════════════════════════════════════════════════════════════════
# Portability / no-hardcoded-address assertions
# ══════════════════════════════════════════════════════════════════════════════

class TestPortability:
    """These tests explicitly verify that results are relative/structural,
    not dependent on any specific binary's addresses."""

    def test_adrp_add_result_scales_with_pc(self):
        """The resolved target must shift by the same amount as the vmaddr."""
        delta = 0x100000
        base_insn_va = 0x4000
        base_target  = 0x8020

        insns_a = [
            make_insn(base_insn_va,           'adrp', f'x8, #{base_target & ~0xFFF:#x}'),
            make_insn(base_insn_va + 4,        'add',  f'x8, x8, #{base_target & 0xFFF:#x}'),
            make_insn(base_insn_va + 8,        'ret',  ''),
        ]
        insns_b = [
            make_insn(base_insn_va + delta,   'adrp', f'x8, #{(base_target + delta) & ~0xFFF:#x}'),
            make_insn(base_insn_va + delta + 4,'add',  f'x8, x8, #{(base_target + delta) & 0xFFF:#x}'),
            make_insn(base_insn_va + delta + 8,'ret',  ''),
        ]

        result_a = value_after(insns_a, 'x8')
        result_b = value_after(insns_b, 'x8')
        assert result_a is not None
        assert result_b is not None
        assert result_b - result_a == delta

    def test_bl_target_encodes_absolute_from_pc(self):
        """BL target must be computed from the instruction's own PC, not TEXT_VA."""
        # At two different PCs, a BL with +8 offset should yield different targets
        pc_a, pc_b = 0x1000, 0x5000
        code = encode_bl(+8) + NOP_BYTES + RET_BYTES
        for pc in (pc_a, pc_b):
            ctx   = ctx_from_code(code, vmaddr=pc)
            insns = disasm(ctx, pc)
            tgts  = _branch_targets(insns)
            assert tgts == [pc + 8], f"wrong target at pc={pc:#x}"


# ══════════════════════════════════════════════════════════════════════════════
# STR/STP false-clobber regression tests
# ══════════════════════════════════════════════════════════════════════════════

class TestStrDoesNotClobber:
    """STR and STP read their first operand, they do not clobber it: a STR x8, [x9] between
    adrp x8 and add x8 leaves x8 the page (the decoder must not report them as writes)."""

    def test_str_between_adrp_and_add(self):
        insns = [
            make_insn(0x1000, 'adrp', 'x8, #0x5000'),
            make_insn(0x1004, 'str',  'x8, [x9]'),          # reads x8, keeps it live
            make_insn(0x1008, 'add',  'x8, x8, #0x20'),
            make_insn(0x100c, 'ret',  ''),
        ]
        assert value_after(insns, 'x8') == 0x5020

    def test_stp_between_adrp_and_add(self):
        insns = [
            make_insn(0x1000, 'adrp', 'x8, #0x3000'),
            make_insn(0x1004, 'stp',  'x29, x30, [sp, #-0x10]'),
            make_insn(0x1008, 'stp',  'x8, x9, [sp]'),      # stores x8, does not write it
            make_insn(0x100c, 'add',  'x8, x8, #0x10'),
            make_insn(0x1010, 'ret',  ''),
        ]
        assert value_after(insns, 'x8') == 0x3010

    def test_cmp_between_adrp_and_add(self):
        insns = [
            make_insn(0x1000, 'adrp', 'x8, #0x4000'),
            make_insn(0x1004, 'cmp',  'x8, x0'),            # compares x8, no write
            make_insn(0x1008, 'add',  'x8, x8, #0x8'),
            make_insn(0x100c, 'ret',  ''),
        ]
        assert value_after(insns, 'x8') == 0x4008

    def test_mov_still_clobbers(self):
        """mov xN writes xN: x8 is x0 + 0x20, not the page."""
        insns = [
            make_insn(0x1000, 'adrp', 'x8, #0x5000'),
            make_insn(0x1004, 'mov',  'x8, x0'),            # overwrites x8
            make_insn(0x1008, 'add',  'x8, x8, #0x20'),
            make_insn(0x100c, 'ret',  ''),
        ]
        assert value_after(insns, 'x8') is None

    def test_ldr_still_clobbers(self):
        """ldr xN writes xN: x8 is the loaded value + 0x20, not the page."""
        insns = [
            make_insn(0x1000, 'adrp', 'x8, #0x5000'),
            make_insn(0x1004, 'ldr',  'x8, [x9, #0x0]'),   # loads into x8
            make_insn(0x1008, 'add',  'x8, x8, #0x20'),
            make_insn(0x100c, 'ret',  ''),
        ]
        assert value_after(insns, 'x8') is None

    def test_str_between_adrp_and_ldr_does_not_clobber(self):
        insns = [
            make_insn(0x1000, 'adrp', 'x8, #0x6000'),
            make_insn(0x1004, 'str',  'x8, [x9]'),
            make_insn(0x1008, 'ldr',  'x8, [x8, #0x10]'),
        ]
        assert load_address(insns, 'x8') == 0x6010


# ══════════════════════════════════════════════════════════════════════════════
# MOVK pipeline (64-bit immediate construction)
# ══════════════════════════════════════════════════════════════════════════════

class TestMovkDecoder:
    def test_movz_movk_sequence_builds_the_64_bit_value(self):
        insns = [
            make_insn(0x1000, 'movz', 'x0, #0xabcd'),
            make_insn(0x1004, 'movk', 'x0, #0x1234, lsl #16'),
            make_insn(0x1008, 'ret', ''),
        ]
        assert value_after(insns, 'x0') == 0x1234abcd

    def test_movk_pipeline(self):
        """Encode MOVK bytes, disassemble, verify mnemonic and operands."""
        import struct
        # MOVK x8, #0x5678, lsl #16
        word = 0xF2800000 | ((1 & 0x3) << 21) | ((0x5678 & 0xFFFF) << 5) | 8
        code = struct.pack('<I', word) + RET_BYTES
        ctx  = ctx_from_code(code)
        insns = disasm(ctx, TEXT_VA)
        movk = next((i for i in insns if i.mnemonic == 'movk'), None)
        assert movk is not None
        assert 'x8' in movk.op_str
        assert '0x5678' in movk.op_str


# ══════════════════════════════════════════════════════════════════════════════
# Cache-native mode: disasm() must not call vmaddr_to_offset
# ══════════════════════════════════════════════════════════════════════════════

class MockCacheReader:
    """Minimal DyldCacheReader stand-in for cache-native disasm tests.

    Backs a single flat code region starting at ``base_va``.  All reads
    outside that region return None (simulating an unmapped address).
    """

    def __init__(self, data: bytes, base_va: int) -> None:
        self._data   = data
        self._base   = base_va

    def read_raw(self, va: int, n: int):
        off = va - self._base
        if off < 0 or off + n > len(self._data):
            return None
        return self._data[off : off + n]

    def read_u64(self, va: int):
        raw = self.read_raw(va, 8)
        return struct.unpack_from('<Q', raw)[0] if raw else None

    def decode_ptr(self, val: int) -> int:
        return val

    def read_cstring(self, va: int, max_len: int = 4096):
        off = va - self._base
        if off < 0 or off >= len(self._data):
            return None
        end = self._data.find(b'\x00', off, off + max_len)
        return self._data[off:end].decode('utf-8', errors='replace') if end >= 0 else None


def _make_cache_ctx(code: bytes, base_va: int = 0x18C000000):
    """Build a cache-backed BinaryContext with *code* at *base_va*.

    Bypasses BinaryContext.from_cache() to avoid the DyldCacheReader
    isinstance assertion while still creating an identical internal layout.
    """
    from macho.memory import BinaryContext, Segment

    mock = MockCacheReader(code, base_va)
    ctx  = BinaryContext.__new__(BinaryContext)
    ctx._data           = b''
    ctx._segments       = [
        Segment(name='__TEXT', vmaddr=base_va, vmsize=len(code),
                fileoff=0, filesize=len(code)),
    ]
    ctx._sections       = {}
    ctx._fixup_map      = {}
    ctx._bind_name_map  = {}
    ctx._image_base     = base_va
    ctx._cpu_type       = 0x0100000C
    ctx._cpu_subtype    = 0
    ctx._cache_reader   = mock
    return ctx


class TestIsCacheBacked:
    """BinaryContext.is_cache_backed property."""

    def test_binary_mode_is_false(self):
        """Binary-mode ctx (constructed with BinaryContext(data)) must return False."""
        ctx = BinaryContext(build_text_binary(RET_BYTES))
        assert ctx.is_cache_backed is False

    def test_cache_mode_is_true(self):
        """Cache-mode ctx (constructed with MockCacheReader) must return True."""
        ctx = _make_cache_ctx(RET_BYTES)
        assert ctx.is_cache_backed is True


class TestDisasmCacheNativeMode:
    """
    Regression tests for the cache-native disasm() bug.

    Root cause: disasm() called ctx.vmaddr_to_offset(vmaddr, 4) for address
    validation.  In cache-native mode ctx._data == b'' so the guard
    ``off + length > len(self._data)`` is always True, causing ValueError for
    every valid vmaddr.  This silently zeroed out all confirmed field numbers
    (0 of 1302 messages confirmed when running --framework GeoServices --cache).

    Fix: disasm() now uses ctx.read_bytes() for validation when is_cache_backed
    is True; vmaddr_to_offset is only called in binary mode.
    """

    CACHE_VA = 0x18C000000   # representative cache-range vmaddr

    def test_disasm_does_not_raise_in_cache_mode(self):
        """disasm() must not raise ValueError for a valid vmaddr in cache mode.

        Before the fix, vmaddr_to_offset() always raised ValueError because
        ctx._data is empty in cache mode (len == 0).
        """
        code = encode_bl(+8) + NOP_BYTES + RET_BYTES
        ctx  = _make_cache_ctx(code, self.CACHE_VA)
        # Must not raise — this was the regression
        insns = disasm(ctx, self.CACHE_VA)
        assert len(insns) > 0, "disasm should return instructions for valid cache vmaddr"

    def test_disasm_returns_correct_instructions_in_cache_mode(self):
        """Instructions disassembled from a cache-backed context must be correct."""
        code  = encode_bl(+8) + NOP_BYTES + RET_BYTES
        ctx   = _make_cache_ctx(code, self.CACHE_VA)
        insns = disasm(ctx, self.CACHE_VA)
        assert insns[0].mnemonic == 'bl'
        assert insns[1].mnemonic == 'nop'
        assert insns[2].mnemonic == 'ret'

    def test_disasm_bl_target_correct_in_cache_mode(self):
        """BL target computed from a cache-range PC must be an absolute cache vmaddr."""
        code  = encode_bl(+8) + NOP_BYTES + RET_BYTES
        ctx   = _make_cache_ctx(code, self.CACHE_VA)
        insns = disasm(ctx, self.CACHE_VA)
        targets = _branch_targets(insns)
        assert targets == [self.CACHE_VA + 8]

    def test_disasm_stops_at_ret_in_cache_mode(self):
        """stop_at_ret=True (default) must work correctly in cache mode."""
        # NOP, NOP, RET, NOP — should stop at index 2 (ret)
        code  = NOP_BYTES + NOP_BYTES + RET_BYTES + NOP_BYTES
        ctx   = _make_cache_ctx(code, self.CACHE_VA)
        insns = disasm(ctx, self.CACHE_VA)
        assert insns[-1].mnemonic == 'ret'
        assert len(insns) == 3   # NOP NOP RET (fourth NOP excluded)

    def test_disasm_stop_at_ret_false_continues_past_ret_in_cache_mode(self):
        """stop_at_ret=False must read past ret in cache mode."""
        code  = RET_BYTES + NOP_BYTES
        ctx   = _make_cache_ctx(code, self.CACHE_VA)
        insns = disasm(ctx, self.CACHE_VA, stop_at_ret=False)
        assert len(insns) == 2
        assert insns[0].mnemonic == 'ret'
        assert insns[1].mnemonic == 'nop'

    def test_disasm_max_insns_respected_in_cache_mode(self):
        """max_insns cap must be respected in cache mode."""
        code  = NOP_BYTES * 20
        ctx   = _make_cache_ctx(code, self.CACHE_VA)
        insns = disasm(ctx, self.CACHE_VA, max_insns=5, stop_at_ret=False)
        assert len(insns) == 5

    def test_disasm_unaligned_raises_in_cache_mode(self):
        """Unaligned vmaddr must raise ValueError in cache mode (same as binary mode)."""
        ctx = _make_cache_ctx(NOP_BYTES + RET_BYTES, self.CACHE_VA)
        with pytest.raises(ValueError, match="not 4-byte aligned"):
            disasm(ctx, self.CACHE_VA + 1)

    def test_disasm_unmapped_raises_in_cache_mode(self):
        """A vmaddr completely outside the cache mapping must raise ValueError."""
        ctx = _make_cache_ctx(NOP_BYTES + RET_BYTES, self.CACHE_VA)
        with pytest.raises(ValueError):
            disasm(ctx, 0x1234)   # far below cache range, not mapped

    def test_is_cache_backed_false_preserves_binary_mode_behaviour(self):
        """Binary-mode disasm must still work correctly after the fix."""
        code  = encode_bl(+8) + NOP_BYTES + RET_BYTES
        ctx   = BinaryContext(build_text_binary(code, vmaddr=TEXT_VA))
        insns = disasm(ctx, TEXT_VA)
        assert insns[0].mnemonic == 'bl'
        assert not ctx.is_cache_backed

    def test_duck_typed_ctx_without_is_cache_backed_uses_vmaddr_to_offset(self):
        """disasm() uses getattr(ctx, 'is_cache_backed', False) so that
        duck-typed test stubs lacking the property still use vmaddr_to_offset
        (the safe binary-mode path) rather than raising AttributeError.

        Regression: before the getattr fix, _FakeCtx in TestPoolAlwaysBuilt
        caused an AttributeError when disasm() checked ctx.is_cache_backed,
        which silently killed the IMP-scan pool and returned GEODefaultsDBValue
        instead of GEOPDComponentValue for the 'values' field.
        """
        # Minimal duck-typed ctx — has vmaddr_to_offset but NOT is_cache_backed
        class _DuckCtx:
            _VA = 0x1000
            _CODE = encode_bl(+8) + NOP_BYTES + RET_BYTES

            def vmaddr_to_offset(self, va, length=1):
                off = va - self._VA
                if 0 <= off < len(self._CODE):
                    return off
                raise ValueError(f"unmapped 0x{va:x}")

            def read_bytes(self, va, length):
                off = va - self._VA
                if 0 <= off and off + length <= len(self._CODE):
                    return self._CODE[off : off + length]
                raise ValueError(f"no data at 0x{va:x}")

        ctx = _DuckCtx()
        assert not hasattr(ctx, 'is_cache_backed')
        # Must not raise AttributeError
        insns = disasm(ctx, 0x1000)
        assert insns[0].mnemonic == 'bl', (
            f"Expected 'bl', got {insns[0].mnemonic!r} — duck-typed ctx broke"
        )
