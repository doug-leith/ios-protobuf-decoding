"""
tests/test_disasm.py — tests for macho/disasm.py.

Structure
---------
Unit tests (no binary, no capstone):
  - iter_bl_targets / iter_branch_targets
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
    iter_bl_targets,
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
# iter_bl_targets
# ══════════════════════════════════════════════════════════════════════════════

class TestIterBlTargets:
    def test_single_bl(self):
        insns = [
            make_insn(0x1000, 'mov', 'x0, #0x1'),
            make_insn(0x1004, 'bl',  '#0xdeadbeef'),
            make_insn(0x1008, 'ret', ''),
        ]
        assert list(iter_bl_targets(insns)) == [0xdeadbeef]

    def test_multiple_bls(self):
        insns = [
            make_insn(0x1000, 'bl', '#0x1234'),
            make_insn(0x1004, 'nop', ''),
            make_insn(0x1008, 'bl', '#0x5678'),
            make_insn(0x100c, 'bl', '#0xabcd'),
        ]
        assert list(iter_bl_targets(insns)) == [0x1234, 0x5678, 0xabcd]

    def test_no_bl(self):
        insns = [make_insn(0x1000, 'ret', '')]
        assert list(iter_bl_targets(insns)) == []

    def test_empty(self):
        assert list(iter_bl_targets([])) == []

    def test_blr_not_included(self):
        """blr (indirect branch) has no immediate target; must not appear."""
        insns = [
            make_insn(0x1000, 'blr', 'x8'),
            make_insn(0x1004, 'bl',  '#0x2000'),
        ]
        assert list(iter_bl_targets(insns)) == [0x2000]

    def test_order_preserved(self):
        targets = [0x100, 0x200, 0x300]
        insns = [make_insn(i * 4, 'bl', f'#{t:#x}') for i, t in enumerate(targets)]
        assert list(iter_bl_targets(insns)) == targets

    def test_unconditional_b_not_included(self):
        """iter_bl_targets must NOT yield unconditional 'b' targets (only 'bl')."""
        insns = [
            make_insn(0x1000, 'mov', 'x1, x2'),
            make_insn(0x1004, 'b',   '#0x5000'),   # tail-call branch
        ]
        assert list(iter_bl_targets(insns)) == [], (
            "iter_bl_targets must exclude 'b' — use iter_branch_targets for that"
        )


# ══════════════════════════════════════════════════════════════════════════════
# iter_branch_targets
# ══════════════════════════════════════════════════════════════════════════════

class TestIterBranchTargets:
    """iter_branch_targets captures both 'bl' (call) and 'b' (tail call)."""

    def _targets(self, insns):
        from macho.disasm import iter_branch_targets
        return list(iter_branch_targets(insns))

    def test_bl_captured(self):
        insns = [make_insn(0x1000, 'bl', '#0x5000')]
        assert self._targets(insns) == [0x5000]

    def test_b_captured(self):
        """Unconditional 'b' (tail call) must be yielded."""
        insns = [
            make_insn(0x1000, 'mov', 'x1, x2'),
            make_insn(0x1004, 'b',   '#0x6000'),
        ]
        assert self._targets(insns) == [0x6000]

    def test_both_bl_and_b_in_sequence(self):
        insns = [
            make_insn(0x1000, 'bl',  '#0x1111'),
            make_insn(0x1004, 'nop', ''),
            make_insn(0x1008, 'b',   '#0x2222'),
        ]
        assert self._targets(insns) == [0x1111, 0x2222]

    def test_conditional_branch_not_captured(self):
        """b.cond mnemonics (b.hi, b.ne, etc.) are never 'b' or 'bl'."""
        insns = [
            make_insn(0x1000, 'b.hi', '#0x9000'),
            make_insn(0x1004, 'b.ne', '#0x9004'),
            make_insn(0x1008, 'bl',   '#0xAAAA'),
        ]
        assert self._targets(insns) == [0xAAAA]

    def test_blr_not_captured(self):
        """blr (indirect) has no imm target; must not appear."""
        insns = [
            make_insn(0x1000, 'blr', 'x8'),
            make_insn(0x1004, 'b',   '#0x3000'),
        ]
        assert self._targets(insns) == [0x3000]

    def test_empty_input(self):
        assert self._targets([]) == []

    def test_no_branches(self):
        insns = [
            make_insn(0x1000, 'mov', 'x1, x2'),
            make_insn(0x1004, 'ret', ''),
        ]
        assert self._targets(insns) == []

    def test_order_preserved(self):
        insns = [
            make_insn(0x1000, 'b',  '#0xAAA'),
            make_insn(0x1004, 'bl', '#0xBBB'),
            make_insn(0x1008, 'b',  '#0xCCC'),
        ]
        assert self._targets(insns) == [0xAAA, 0xBBB, 0xCCC]

    def test_b_roundtrip_via_encode_b(self):
        """encode_b + disasm + iter_branch_targets → correct target vmaddr."""
        from tests.conftest import encode_b
        BASE_VA = 0x4000
        TARGET_OFFSET = +20   # 5 instructions ahead
        code = encode_b(TARGET_OFFSET)
        ctx  = ctx_from_code(code, vmaddr=BASE_VA)
        insns = disasm(ctx, BASE_VA, max_insns=2)
        targets = self._targets(insns)
        assert targets == [BASE_VA + TARGET_OFFSET], (
            f"Expected [{BASE_VA + TARGET_OFFSET:#x}], got {targets}"
        )

    def test_b_and_bl_roundtrip_mixed(self):
        """Mixed bl+b sequence decoded by disasm and collected by iter_branch_targets."""
        from tests.conftest import encode_b
        BASE_VA   = 0x4000
        bl_bytes  = encode_bl(+12)   # BL → BASE_VA + 12
        b_bytes   = encode_b(+16)    # B  → BASE_VA + 4 + 16 = BASE_VA + 20
        code      = bl_bytes + b_bytes + NOP_BYTES * 8
        ctx       = ctx_from_code(code, vmaddr=BASE_VA)
        insns     = disasm(ctx, BASE_VA, max_insns=4, stop_at_ret=False)
        targets   = self._targets(insns)
        assert BASE_VA + 12 in targets, "BL target must be captured"
        assert BASE_VA + 20 in targets, "B target must be captured"


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
        targets = list(iter_bl_targets(insns))
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
        targets = list(iter_bl_targets(insns))
        assert targets == [TEXT_VA + 12, TEXT_VA + 16]

    def test_bl_backward(self):
        # BL that targets the start of the function (offset = -(n instructions * 4))
        # Put BL at position 2 (offset 8), targeting position 0 (offset = -8)
        code = NOP_BYTES + NOP_BYTES + encode_bl(-8) + RET_BYTES
        ctx  = ctx_from_code(code)
        insns = disasm(ctx, TEXT_VA)
        targets = list(iter_bl_targets(insns))
        # bl is at TEXT_VA+8; target = TEXT_VA+8 + (-8) = TEXT_VA
        assert targets == [TEXT_VA]


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
# Native decoder unit tests  (bypass disasm(), call _native_decode directly)
# ══════════════════════════════════════════════════════════════════════════════

class TestNativeDecoder:
    """Test _native_decode in isolation for all opcode families."""

    from macho.disasm import _native_decode as _dec   # class-level import

    def _dec(self, word: int, pc: int = 0x1000):
        from macho.disasm import _native_decode
        return _native_decode(word, pc)

    def test_ret(self):
        assert self._dec(0xD65F03C0) == ('ret', '')

    def test_retaa(self):
        assert self._dec(0xD65F0BFF) == ('retaa', '')

    def test_retab(self):
        assert self._dec(0xD65F0FFF) == ('retab', '')

    def test_nop(self):
        assert self._dec(0xD503201F) == ('nop', '')

    def test_adrp_forward(self):
        """ADRP x8, +1 page at PC=0x1000 → page 0x2000."""
        word = struct.unpack('<I', encode_adrp(8, 1))[0]
        mnem, ops = self._dec(word, pc=0x1000)
        assert mnem == 'adrp'
        # page = (0x1000 & ~0xFFF) + 1*0x1000 = 0x2000
        assert '#0x2000' in ops
        assert 'x8' in ops

    def test_adrp_reg_zero(self):
        word = struct.unpack('<I', encode_adrp(0, 2))[0]
        mnem, ops = self._dec(word, pc=0x0)
        assert mnem == 'adrp'
        assert 'x0' in ops
        assert '#0x2000' in ops

    def test_add_imm64(self):
        word = struct.unpack('<I', encode_add_imm64(8, 8, 0x20))[0]
        mnem, ops = self._dec(word)
        assert mnem == 'add'
        assert 'x8' in ops
        assert '0x20' in ops

    def test_add_imm64_shift1(self):
        """ADD with shift=1 (imm << 12)."""
        # Encode ADD x8, x8, #1, LSL#12 → imm = 0x1000
        word = 0x91400000 | (1 << 10) | (8 << 5) | 8   # shift=01, imm12=1
        mnem, ops = self._dec(word)
        assert mnem == 'add'
        assert '0x1000' in ops

    def test_ldr_imm64(self):
        word = struct.unpack('<I', encode_ldr_imm64(8, 9, 16))[0]
        mnem, ops = self._dec(word)
        assert mnem == 'ldr'
        assert 'x8' in ops
        assert 'x9' in ops
        assert '0x10' in ops

    def test_ldrsw_imm(self):
        """LDRSW x8, [x23, #0xfb4] — the dominant ivar-offset load in GeoServices.

        This was previously decoded as 'unk', silently breaking pointer-table
        analysis when capstone is not installed.
        """
        rn, rt, offset = 23, 8, 0xfb4
        imm12 = offset // 4
        word  = 0xB9800000 | (imm12 << 10) | (rn << 5) | rt
        mnem, ops = self._dec(word)
        assert mnem == 'ldrsw', f"expected 'ldrsw', got {mnem!r} {ops!r}"
        assert f'x{rt}' in ops
        assert f'x{rn}' in ops
        assert f'#{offset:#x}' in ops

    def test_bl_forward(self):
        word = struct.unpack('<I', encode_bl(+20))[0]
        mnem, ops = self._dec(word, pc=0x1000)
        assert mnem == 'bl'
        target = _parse_imm(ops)
        assert target == 0x1014    # 0x1000 + 20

    def test_bl_backward(self):
        word = struct.unpack('<I', encode_bl(-8))[0]
        mnem, ops = self._dec(word, pc=0x1000)
        assert mnem == 'bl'
        target = _parse_imm(ops)
        assert target == 0x1000 - 8

    def test_movz_hw0(self):
        word = struct.unpack('<I', encode_movz(0, 0x1234))[0]
        mnem, ops = self._dec(word)
        assert mnem == 'movz'
        assert 'x0' in ops
        val = _parse_imm(ops)
        assert val == 0x1234

    def test_unknown_returns_unk(self):
        mnem, ops = self._dec(0x00000000)
        assert mnem == 'unk'
        assert '0x' in ops

    # ── Additional opcode families with no prior _native_decode coverage ──────
    # (trigger_group audit rows 9-18:
    # each of these branches previously had zero test coverage, live or
    # synthetic — the pure-Python fallback decoder is only exercised when
    # capstone is unavailable, which never happens in this project's venv, so
    # these branches were reachable ONLY through direct unit tests like this.)

    def test_b_plain_branch(self):
        """Plain 'b' (not 'bl') — distinct opcode from BL, must decode as 'b'."""
        word = 0x14000000 | 4   # b #(pc+16)
        mnem, ops = self._dec(word, pc=0x1000)
        assert mnem == 'b'
        assert _parse_imm(ops) == 0x1010

    def test_ldr_32bit_unsigned_offset(self):
        """'ldr wN, [xM, #off]' (32-bit, base 0xB9400000) — distinct from the
        64-bit ldr (0xF9400000) and from ldrsw (0xB9800000), both already
        covered above."""
        word = 0xB9400000 | (4 << 10) | (9 << 5) | 8   # ldr w8, [x9, #0x10]
        mnem, ops = self._dec(word)
        assert mnem == 'ldr'
        assert 'w8' in ops and 'x9' in ops and '0x10' in ops

    def test_movz_32bit(self):
        """MOVZ 32-bit (sf=0, base 0x52800000) — the actual field-number-argument
        form the module docstring credits to Apple's writeTo: methods.  The
        existing test_movz_hw0 above (via conftest.encode_movz) only builds the
        64-bit form (base 0xD2800000); this is a genuinely different branch."""
        word = 0x52800000 | (0x14 << 5) | 2   # movz w2, #0x14
        mnem, ops = self._dec(word)
        assert mnem == 'movz'
        assert 'w2' in ops
        assert _parse_imm(ops) == 0x14

    def test_movk_32bit(self):
        """MOVK 32-bit (sf=0, base 0x72800000) — distinct from the 64-bit MOVK
        (base 0xF2800000) covered by TestMovkDecoder.test_movk_native_decode."""
        word = 0x72800000 | (0x1234 << 5) | 0   # movk w0, #0x1234
        mnem, ops = self._dec(word)
        assert mnem == 'movk'
        assert 'w0' in ops
        assert _parse_imm(ops) == 0x1234

    def test_movn_64bit(self):
        word = 0x92800000 | (5 << 5) | 0   # movn x0, #0x5
        mnem, ops = self._dec(word)
        assert mnem == 'movn'
        assert 'x0' in ops
        assert _parse_imm(ops) == 0x5

    def test_mov_canonical_vs_orr_general(self):
        """ORR shifted-register 64-bit with Rn=XZR (31) is the canonical 'MOV'
        alias; the same encoding with Rn != 31 is a genuine 3-operand 'orr'."""
        mov_word = 0xAA000000 | (2 << 16) | (31 << 5) | 1   # mov x1, x2
        mnem, ops = self._dec(mov_word)
        assert mnem == 'mov'
        assert ops == 'x1, x2'

        orr_word = 0xAA000000 | (2 << 16) | (3 << 5) | 1    # orr x1, x3, x2
        mnem, ops = self._dec(orr_word)
        assert mnem == 'orr'
        assert ops == 'x1, x3, x2'

    def test_add_imm_reserved_shift_returns_unk(self):
        """ADD-immediate with shift encoded 2 or 3 is an architecturally-reserved
        encoding; _native_decode must return 'unk' rather than silently
        misinterpreting the shift field (shift is only defined for 0 or 1)."""
        for shift in (2, 3):
            word = 0x91000000 | (shift << 22) | (5 << 10) | (9 << 5) | 8
            mnem, ops = self._dec(word)
            assert mnem == 'unk', f'shift={shift} should be unk, got {mnem!r}'


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
            tgts  = list(iter_bl_targets(insns))
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
    def test_movk_native_decode(self):
        from macho.disasm import _native_decode
        from tests.conftest import encode_movz  # noqa: F401 (not used here)
        # MOVK X0, #0x1234, LSL #16 — hw=1
        word = 0xF2A24680   # movk x0, #0x1234, lsl #16
        # Compute: 0xF2800000 | (1 << 21) | (0x1234 << 5) | 0
        import struct
        expected_word = struct.unpack('<I', bytes([
            0x80 | 0,   # rd=0, low bit of imm16
            0x46,       # imm16 bits
            0xA2,       # hw=1 in bits 22-21, imm16 bits
            0xF2,       # top: MOVK 64-bit
        ]))[0]
        # Build MOVK x0, #0x1234, lsl #16 properly
        built = 0xF2800000 | ((1 & 0x3) << 21) | ((0x1234 & 0xFFFF) << 5) | 0
        mnem, ops = _native_decode(built, 0x1000)
        assert mnem == 'movk'
        assert 'x0' in ops
        assert '0x1234' in ops
        assert 'lsl #16' in ops or 'lsl' in ops

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
# Native decoder completeness for common prologue/epilogue patterns
# ══════════════════════════════════════════════════════════════════════════════

class TestNativeDecoderCompleteness:
    def _dec(self, word, pc=0x1000):
        from macho.disasm import _native_decode
        return _native_decode(word, pc)

    def test_stp_x29_x30(self):
        """Standard prologue: stp x29, x30, [sp, #-0x10]"""
        # stp x29, x30, [sp, #-0x10]
        # 0xA9BF7BFD: size=10, V=0, L=0, imm7=-1 (signed), Rt2=30, Rn=31, Rt=29
        import struct
        # Build: STP 64-bit signed-offset: base=0xA9000000, imm7=-1 << 15
        imm7 = (-1) & 0x7F  # = 0x7F
        word = 0xA9000000 | (imm7 << 15) | (30 << 10) | (31 << 5) | 29
        mnem, ops = self._dec(word)
        assert mnem == 'stp'
        assert 'x29' in ops and 'x30' in ops

    def test_ldp_x29_x30(self):
        """Standard epilogue: ldp x29, x30, [sp, #0x10]"""
        # LDP 64-bit: base=0xA9400000, imm7=1 (positive)
        word = 0xA9400000 | (1 << 15) | (30 << 10) | (31 << 5) | 29
        mnem, ops = self._dec(word)
        assert mnem == 'ldp'
        assert 'x29' in ops and 'x30' in ops

    def test_cbz(self):
        import struct
        word = struct.unpack('<I', encode_bl(0))[0]   # just to show encoding works
        # Build CBZ x8, #0x1010 (offset +4 instructions from 0x1000 = 0x1010)
        imm19 = 4   # 4 instructions forward
        word  = 0x34000000 | (0 << 31) | (imm19 << 5) | 8   # sf=0 (32-bit), nz=0
        mnem, ops = self._dec(word, pc=0x1000)
        assert mnem == 'cbz'
        assert 'w8' in ops
        target = _parse_imm(ops)
        assert target == 0x1010

    def test_cbnz(self):
        imm19 = 2
        word  = 0x34000000 | (1 << 31) | (1 << 24) | (imm19 << 5) | 0   # sf=1, nz=1
        mnem, ops = self._dec(word, pc=0x1000)
        assert mnem == 'cbnz'

    def test_sub_imm(self):
        import struct
        # SUB x29, sp, #0x20
        word = 0xD1000000 | (0x20 << 10) | (31 << 5) | 29
        mnem, ops = self._dec(word)
        assert mnem == 'sub'
        assert 'x29' in ops

    def test_str_imm64(self):
        # STR x8, [sp, #0x10] → 0xF9000000 | ((0x10>>3) << 10) | (31 << 5) | 8
        import struct
        word = 0xF9000000 | ((0x10 >> 3) << 10) | (31 << 5) | 8
        mnem, ops = self._dec(word)
        assert mnem == 'str'
        assert 'x8' in ops

    def test_blr(self):
        # BLR x8: base=0xD63F0000 | (8 << 5)
        word = 0xD63F0000 | (8 << 5)
        mnem, ops = self._dec(word)
        assert mnem == 'blr'
        assert 'x8' in ops

    def test_br(self):
        word = 0xD61F0000 | (16 << 5)
        mnem, ops = self._dec(word)
        assert mnem == 'br'
        assert 'x16' in ops

    def test_ldrsw(self):
        """LDRSW Xt, [Xn, #off] — sign-extending 32→64 load, encoding 0xB98xxxxx."""
        # ldrsw x0, [x1, #0x10]
        rn, rt, offset = 1, 0, 0x10
        imm12 = offset // 4
        word  = 0xB9800000 | (imm12 << 10) | (rn << 5) | rt
        mnem, ops = self._dec(word)
        assert mnem == 'ldrsw'
        assert 'x0' in ops
        assert 'x1' in ops
        assert '#0x10' in ops

    def test_ldrsw_zero_offset(self):
        """LDRSW with zero offset: ldrsw x8, [x23]."""
        rn, rt = 23, 8
        word = 0xB9800000 | (0 << 10) | (rn << 5) | rt
        mnem, ops = self._dec(word)
        assert mnem == 'ldrsw'
        assert f'x{rt}' in ops
        assert f'x{rn}' in ops


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
        targets = list(iter_bl_targets(insns))
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
