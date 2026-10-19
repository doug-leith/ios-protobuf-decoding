"""
macho/disasm.py — arm64 disassembler and instruction-stream analysis.

Architecture
------------
* disasm(ctx, vmaddr, max_insns, stop_at_ret) → List[Insn]
  Disassembles arm64 code starting at vmaddr.  Uses capstone when available;
  falls back to a pure-Python mini-decoder that handles the dozen opcodes
  needed for GPB analysis (adrp, add, ldr, bl, movz, mov, b, ret, nop, …).
  By default stops at the first ret-family instruction or after max_insns
  instructions.  Pass stop_at_ret=False to continue past ret (needed when
  scanning writeTo: methods whose out-of-line field blocks follow the main
  function epilogue).

* Analysis primitives operate on List[Insn] — no BinaryContext needed.
  All pattern matching is structural (mnemonic + op_str regex); no hardcoded
  addresses are ever used.  The same code works across any arm64 binary.

Public API
----------
    disasm(ctx, vmaddr, max_insns=512, stop_at_ret=True) → List[Insn]
    iter_bl_targets(insns)             → Iterator[int]   # all BL call targets
    iter_branch_targets(insns)         → Iterator[int]   # BL and B targets

Register values (an adrp+add address, a loaded slot, a movz constant) are read by
:class:`proto.arm64_eval.Flow`, not here.
"""

from __future__ import annotations

import logging
import re
import struct
from dataclasses import dataclass
from typing import Iterator, List, Optional, Sequence, Tuple

from .memory import BinaryContext

# ─── Public types ─────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Insn:
    """One decoded arm64 instruction."""
    addr:     int    # vmaddr
    mnemonic: str    # lower-case, e.g. "adrp", "bl", "ret"
    op_str:   str    # operand string, e.g. "x8, #0x5000"
    size:     int    # always 4 on arm64
    raw:      bytes  # 4 raw bytes (little-endian)

    def __str__(self) -> str:
        return f"0x{self.addr:x}:  {self.mnemonic:<8} {self.op_str}"


# ─── Constants ────────────────────────────────────────────────────────────────

_STOP_MNEMONICS  = frozenset(('ret', 'retaa', 'retab', 'eret'))
# [cap:INPUT-SANITY — leave as-is] Only the *default* max_insns for callers that don't
# pass one.  Every decode-critical disassembly in the extractor passes an EXPLICIT cap
# (the proto/extractor.py Tier-1/2 constants), so this default governs only don't-care
# / early-terminating reads and is never the binding limit for any field/enum/number.
_DEFAULT_MAX     = 512

# Mnemonics whose first register operand is a SOURCE (read), not a destination
# ('str x8, [x9]' reads x8; 'cmp x8, #0' reads x8): proto.arm64_operands.writes.
_SOURCE_FIRST_MNEMONICS = frozenset({
    'str',  'strb',  'strh',  'stur',  'sturb',  'sturh',
    'sttr', 'sttrb', 'sttrh',
    'stp',  'stnp',
    'stxr', 'stxrb', 'stxrh', 'stlxr', 'stlxrb', 'stlxrh',
    'stlr', 'stlrb', 'stlrh',
    'cmp',  'cmn',   'tst',
    'cbz',  'cbnz',
    'tbz',  'tbnz',
    'blr',  'br',
    'ret',  'retaa', 'retab',
})

# ─── Register helpers ─────────────────────────────────────────────────────────

_REG_RE  = re.compile(r'^[xwXW](\d+)$')
_IMM_RE  = re.compile(r'#(-?0x[0-9a-fA-F]+|-?\d+)')

def _norm_reg(name: str) -> Optional[str]:
    """Normalise an arm64 register name to 'xN' form.

    'x8' → 'x8', 'w8' → 'x8', 'sp' → 'sp', 'xzr'/'wzr' → 'xzr'.
    Returns None for unrecognised names.
    """
    name = name.strip().lower()
    if name == 'sp':
        return 'sp'
    if name in ('xzr', 'wzr'):
        return 'xzr'
    m = _REG_RE.match(name)
    return f'x{m.group(1)}' if m else None


def _parse_imm(s: str) -> Optional[int]:
    """Extract the first immediate value from an op_str fragment."""
    m = _IMM_RE.search(s)
    if not m:
        return None
    val = m.group(1)
    try:
        return int(val, 16) if '0x' in val.lower() else int(val)
    except ValueError:
        return None


def iter_bl_targets(insns: Sequence[Insn]) -> Iterator[int]:
    """Yield the vmaddr targets of every ``bl`` (branch-and-link) instruction."""
    for insn in insns:
        if insn.mnemonic == 'bl':
            t = _parse_imm(insn.op_str)
            if t is not None:
                yield t


def iter_branch_targets(insns: Sequence[Insn]) -> Iterator[int]:
    """Yield the vmaddr targets of every ``bl`` or ``b`` instruction.

    Extends :func:`iter_bl_targets` to also capture unconditional branch
    (``b``) instructions.  Apple's ObjC proto runtime readFrom: wrappers
    commonly use a tail-call ``b _ClsReadFrom`` rather than ``bl``, so
    analysing only ``bl`` misses them.  Conditional branches (``b.hi``,
    ``b.ne``, etc.) are excluded — their mnemonics never equal ``'b'``.
    """
    for insn in insns:
        if insn.mnemonic in ('bl', 'b'):
            t = _parse_imm(insn.op_str)
            if t is not None:
                yield t


def disasm(
    ctx: BinaryContext,
    vmaddr: int,
    max_insns: int = _DEFAULT_MAX,
    stop_at_ret: bool = True,
) -> List[Insn]:
    """
    Disassemble arm64 instructions starting at *vmaddr* in *ctx*.

    Uses capstone when available; otherwise uses the built-in pure-Python
    mini-decoder which covers the opcodes needed for GPB analysis.

    When *stop_at_ret* is True (the default) the scan halts at the first
    ret-family instruction and includes it in the result.  Pass
    ``stop_at_ret=False`` when you need to read past a function epilogue —
    for example, when analysing writeTo: methods that place some field-write
    blocks in out-of-line sections *after* the main ``ret``.

    Raises ValueError if *vmaddr* is not 4-byte aligned or cannot be read.
    """
    if vmaddr & 3:
        raise ValueError(
            f"vmaddr 0x{vmaddr:x} is not 4-byte aligned (arm64 requires 4-byte)"
        )

    # Validate that vmaddr is readable — raises ValueError for unmapped addresses.
    # This is intentional: callers should not silently proceed with bad IMPs.
    #
    # Binary mode: vmaddr_to_offset validates against segment bounds and the
    #   in-memory binary data.  Cheap (no data copy).
    #
    # Cache-native mode: ctx._data is empty (b'') so vmaddr_to_offset's final
    #   guard ("off + length > len(self._data)") fires for EVERY non-zero
    #   vmaddr — even fully valid ones — because len(b'') == 0.  In cache mode
    #   we validate by attempting an actual 4-byte read through the cache
    #   reader, which raises ValueError for truly unmapped addresses.
    #
    # getattr with a default of False makes this duck-type-safe: test stubs
    # that implement the BinaryContext interface without inheriting from it
    # (e.g. _FakeCtx in test_proto.py) fall through to vmaddr_to_offset as
    # normal and continue working without needing to add is_cache_backed.
    if getattr(ctx, "is_cache_backed", False):
        try:
            ctx.read_bytes(vmaddr, 4)
        except ValueError:
            raise ValueError(
                f"vmaddr 0x{vmaddr:x} not readable in cache"
            )
    else:
        ctx.vmaddr_to_offset(vmaddr, 4)

    data = _read_available(ctx, vmaddr, max_insns * 4)
    if not data:
        return []

    try:
        import capstone
    except ImportError:
        capstone = None
    if capstone is None:
        _warn_native_decoder_once()
        return _disasm_native(data, vmaddr, max_insns, stop_at_ret)
    # (outside the try: an ImportError raised INSIDE the capstone path is a real bug)
    return _disasm_capstone(data, vmaddr, max_insns, capstone, stop_at_ret)


_native_decoder_warned = False


def _warn_native_decoder_once() -> None:
    """capstone is absent: the built-in decoder is used, which does not decode every load /
    store form (register-offset loads come out as ``unk``), so enum and field recovery can
    silently be less complete.  Say so once per process."""
    global _native_decoder_warned
    if not _native_decoder_warned:
        _native_decoder_warned = True
        logging.getLogger(__name__).warning(
            "capstone is not installed: using the built-in arm64 decoder, which does not "
            "decode every instruction form; enum and field recovery may be incomplete "
            "(install capstone: pip install capstone)")


def _read_available(ctx: BinaryContext, vmaddr: int, want: int) -> bytes:
    """
    Read up to *want* bytes from *vmaddr*, gracefully shrinking the request
    when the read window extends past the segment boundary.

    Returns empty bytes if even a single instruction cannot be read.
    """
    # Fast path: the common case where the method is far from the segment end
    try:
        return ctx.read_bytes(vmaddr, want)
    except ValueError:
        pass
    # Binary-search for the largest 4-byte-aligned read that succeeds
    lo, hi = 4, want - 4
    best   = b''
    while lo <= hi:
        mid = ((lo + hi) // 2) & ~3   # keep 4-byte aligned
        if mid < 4:
            break
        try:
            best = ctx.read_bytes(vmaddr, mid)
            lo   = mid + 4
        except ValueError:
            hi  = mid - 4
    return best


# ── capstone backend ──────────────────────────────────────────────────────────

def _disasm_capstone(
    data: bytes, vmaddr: int, max_insns: int, capstone,  # type: ignore[type-arg]
    stop_at_ret: bool = True,
) -> List[Insn]:
    cs = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    result: List[Insn] = []
    for ci in cs.disasm(data, vmaddr):
        insn = Insn(
            addr     = ci.address,
            mnemonic = ci.mnemonic,
            op_str   = ci.op_str,
            size     = ci.size,
            raw      = bytes(ci.bytes),
        )
        result.append(insn)
        if stop_at_ret and ci.mnemonic in _STOP_MNEMONICS:
            break
        if len(result) >= max_insns:
            break
    return result


# ── Pure-Python mini-decoder (fallback) ───────────────────────────────────────

def _disasm_native(data: bytes, vmaddr: int, max_insns: int,
                   stop_at_ret: bool = True) -> List[Insn]:
    """
    Decode arm64 instructions using pure Python.

    Covers: adrp, add (imm), ldr (unsigned-offset 64-bit), bl, b,
            movz (64-bit hw=0..3), ret/retaa/retab, nop, and a handful of
            other common mnemonics needed to recognise clobbers.
    Unknown encodings produce mnemonic='unk', op_str='#0x<hex>'.
    """
    result: List[Insn] = []
    off    = 0
    pc     = vmaddr
    while off + 4 <= len(data) and len(result) < max_insns:
        word, = struct.unpack_from('<I', data, off)
        mnem, ops = _native_decode(word, pc)
        insn = Insn(addr=pc, mnemonic=mnem, op_str=ops, size=4,
                    raw=data[off:off + 4])
        result.append(insn)
        if stop_at_ret and mnem in _STOP_MNEMONICS:
            break
        off += 4
        pc  += 4
    return result


def _xreg(n: int) -> str:
    return 'sp' if n == 31 else f'x{n}'


def _native_decode(word: int, pc: int) -> Tuple[str, str]:
    """Decode one 32-bit arm64 word → (mnemonic, op_str)."""

    # ── Exact matches ─────────────────────────────────────────────────────
    if word == 0xD65F03C0:
        return ('ret',   '')
    if word == 0xD65F0BFF:
        return ('retaa', '')
    if word == 0xD65F0FFF:
        return ('retab', '')
    if word == 0xD503201F:
        return ('nop',   '')
    if word == 0xD503233F:
        return ('paciasp', '')
    if word == 0xD503237F:
        return ('pacibsp', '')
    if word == 0xD50323FF:
        return ('autibsp', '')
    if word == 0xD5033FDF:
        return ('isb',   '')

    rd = word & 0x1F
    rn = (word >> 5) & 0x1F

    # ── ADRP  (bit31=1, bits28-24=10000) ──────────────────────────────────
    # Mask: check bit31=1 and bits28-24=10000 without constraining immlo
    if (word & 0x9F000000) == 0x90000000:
        immlo = (word >> 29) & 0x3
        immhi = (word >> 5)  & 0x7FFFF
        imm   = (immhi << 2) | immlo
        if imm & 0x100000:       # sign-extend 21-bit
            imm -= 0x200000
        page = (pc & ~0xFFF) + (imm << 12)
        return ('adrp', f'x{rd}, #{page:#x}')

    # ── ADD immediate (64-bit, bits31-24=0x91, shift in bits23-22) ────────
    if (word >> 24) == 0x91:
        rn_   = (word >> 5) & 0x1F
        imm12 = (word >> 10) & 0xFFF
        shift = (word >> 22) & 0x3
        if shift == 0:
            imm = imm12
        elif shift == 1:
            imm = imm12 << 12
        else:
            return ('unk', f'#{word:#010x}')
        return ('add', f'{_xreg(rd)}, {_xreg(rn_)}, #{imm:#x}')

    # ── SUB immediate (64-bit, bits31-24=0xD1) ────────────────────────────
    if (word >> 24) == 0xD1:
        rn_   = (word >> 5) & 0x1F
        imm12 = (word >> 10) & 0xFFF
        shift = (word >> 22) & 0x3
        imm   = imm12 << (12 if shift == 1 else 0)
        return ('sub', f'{_xreg(rd)}, {_xreg(rn_)}, #{imm:#x}')

    # ── LDR 64-bit unsigned-offset (bits31-22=1111100101) ─────────────────
    # Encoding: size=11, V=0, opc=01 → base = 0xF9400000
    if (word & 0xFFC00000) == 0xF9400000:
        rt_   = word & 0x1F
        rn_   = (word >> 5) & 0x1F
        imm12 = (word >> 10) & 0xFFF
        off   = imm12 * 8
        return ('ldr', f'{_xreg(rt_)}, [{_xreg(rn_)}, #{off:#x}]')

    # ── STR 64-bit unsigned-offset (bits31-22=1111100100, base=0xF9000000) ─
    if (word & 0xFFC00000) == 0xF9000000:
        rt_   = word & 0x1F
        rn_   = (word >> 5) & 0x1F
        imm12 = (word >> 10) & 0xFFF
        off   = imm12 * 8
        return ('str', f'{_xreg(rt_)}, [{_xreg(rn_)}, #{off:#x}]')

    # ── LDR 32-bit unsigned-offset (base=0xB9400000) ──────────────────────
    if (word & 0xFFC00000) == 0xB9400000:
        rt_   = word & 0x1F
        rn_   = (word >> 5) & 0x1F
        imm12 = (word >> 10) & 0xFFF
        off   = imm12 * 4
        return ('ldr', f'w{rt_}, [{_xreg(rn_)}, #{off:#x}]')

    # ── LDRSW unsigned-offset (sign-extend 32→64, base=0xB9800000) ────────
    # Encoding: size=10, V=0, opc=10.  The dominant ivar-offset load in
    # GeoServices is "ldrsw x8, [x23, #0xfb4]".  Without this case every
    # ldrsw falls through to 'unk', silently breaking pointer-table analysis
    # when capstone is not installed.
    if (word & 0xFFC00000) == 0xB9800000:
        rt_   = word & 0x1F
        rn_   = (word >> 5) & 0x1F
        imm12 = (word >> 10) & 0xFFF
        off   = imm12 * 4
        return ('ldrsw', f'{_xreg(rt_)}, [{_xreg(rn_)}, #{off:#x}]')

    # ── BL (bits31-26=100101, base=0x94000000) ────────────────────────────
    if (word & 0xFC000000) == 0x94000000:
        imm26 = word & 0x3FFFFFF
        if imm26 & 0x2000000:
            imm26 -= 0x4000000
        target = pc + imm26 * 4
        return ('bl', f'#{target:#x}')

    # ── B  (bits31-26=000101, base=0x14000000) ────────────────────────────
    if (word & 0xFC000000) == 0x14000000:
        imm26 = word & 0x3FFFFFF
        if imm26 & 0x2000000:
            imm26 -= 0x4000000
        target = pc + imm26 * 4
        return ('b', f'#{target:#x}')

    # ── CBZ / CBNZ (bits31-25=x011010) ────────────────────────────────────
    if (word & 0x7E000000) == 0x34000000:
        sf    = (word >> 31) & 1
        nz    = (word >> 24) & 1
        imm19 = (word >> 5) & 0x7FFFF
        if imm19 & 0x40000:
            imm19 -= 0x80000
        target = pc + imm19 * 4
        reg    = f'x{rd}' if sf else f'w{rd}'
        return (('cbnz' if nz else 'cbz'), f'{reg}, #{target:#x}')

    # ── MOVZ 32-bit (sf=0, opc=10 → bits28-23=100101, base=0x52800000) ────
    # Used when field numbers are passed in 32-bit w-registers (movz w2, #N).
    # Apple's proto writeTo: always uses movz wN for field-number arguments.
    if (word & 0xFF800000) == 0x52800000:
        hw    = (word >> 21) & 0x3
        imm16 = (word >> 5) & 0xFFFF
        shift = hw * 16
        if shift:
            return ('movz', f'w{rd}, #{imm16:#x}, lsl #{shift}')
        return ('movz', f'w{rd}, #{imm16:#x}')

    # ── MOVZ 64-bit (sf=1, opc=10 → bit30=1 bit29=0, bits28-23=100101) ────
    # Full 9-bit opcode check via mask 0xFF800000 (bits 31–23)
    if (word & 0xFF800000) == 0xD2800000:
        hw    = (word >> 21) & 0x3
        imm16 = (word >> 5) & 0xFFFF
        shift = hw * 16
        if shift:
            return ('movz', f'x{rd}, #{imm16:#x}, lsl #{shift}')
        return ('movz', f'x{rd}, #{imm16:#x}')

    # ── MOVK 32-bit (sf=0, opc=11, base=0x72800000) ───────────────────────
    if (word & 0xFF800000) == 0x72800000:
        hw    = (word >> 21) & 0x3
        imm16 = (word >> 5) & 0xFFFF
        shift = hw * 16
        if shift:
            return ('movk', f'w{rd}, #{imm16:#x}, lsl #{shift}')
        return ('movk', f'w{rd}, #{imm16:#x}')

    # ── MOVK 64-bit (sf=1, opc=11 → bit30=1 bit29=1, bits28-23=100101) ────
    if (word & 0xFF800000) == 0xF2800000:
        hw    = (word >> 21) & 0x3
        imm16 = (word >> 5) & 0xFFFF
        shift = hw * 16
        if shift:
            return ('movk', f'x{rd}, #{imm16:#x}, lsl #{shift}')
        return ('movk', f'x{rd}, #{imm16:#x}')

    # ── MOVN 64-bit (sf=1, opc=00 → bit30=0 bit29=0, bits28-23=100101) ────
    if (word & 0xFF800000) == 0x92800000:
        hw    = (word >> 21) & 0x3
        imm16 = (word >> 5) & 0xFFFF
        return ('movn', f'x{rd}, #{imm16:#x}')

    # ── MOV (register, via ORR Xd, XZR, Xm) ──────────────────────────────
    # ORR shifted reg 64-bit: bits31-29=101, bits28-24=01010, shift=00, N=0
    # base=0xAA000000; "MOV Xd, Xm" is canonical form when Rn=XZR
    if (word & 0xFF200000) == 0xAA000000:
        rm  = (word >> 16) & 0x1F
        rn_ = (word >>  5) & 0x1F
        if rn_ == 31:   # XZR source → canonical MOV
            return ('mov', f'{_xreg(rd)}, {_xreg(rm)}')
        return ('orr', f'{_xreg(rd)}, {_xreg(rn_)}, {_xreg(rm)}')

    # ── STP / LDP (signed-offset, 64-bit, base patterns) ──────────────────
    if (word & 0xFFC00000) == 0xA9000000:   # STP 64-bit
        rt2 = (word >> 10) & 0x1F
        rn_ = (word >> 5) & 0x1F
        imm7 = ((word >> 15) & 0x7F)
        if imm7 & 0x40:
            imm7 -= 0x80
        return ('stp', f'{_xreg(rd)}, {_xreg(rt2)}, [{_xreg(rn_)}, #{imm7*8:#x}]')
    if (word & 0xFFC00000) == 0xA9400000:   # LDP 64-bit
        rt2 = (word >> 10) & 0x1F
        rn_ = (word >> 5) & 0x1F
        imm7 = ((word >> 15) & 0x7F)
        if imm7 & 0x40:
            imm7 -= 0x80
        return ('ldp', f'{_xreg(rd)}, {_xreg(rt2)}, [{_xreg(rn_)}, #{imm7*8:#x}]')

    # ── BLR (branch-link to register, base=0xD63F0000) ────────────────────
    if (word & 0xFFFFFC1F) == 0xD63F0000:
        rn_ = (word >> 5) & 0x1F
        return ('blr', _xreg(rn_))

    # ── BR  (branch to register, base=0xD61F0000) ─────────────────────────
    if (word & 0xFFFFFC1F) == 0xD61F0000:
        rn_ = (word >> 5) & 0x1F
        return ('br', _xreg(rn_))

    # ── Unknown ───────────────────────────────────────────────────────────
    return ('unk', f'#{word:#010x}')
