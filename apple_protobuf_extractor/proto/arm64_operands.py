"""proto/arm64_operands.py -- ARM64 operands as capstone prints them: register names and widths,
memory operands, the flexible second operand (shifted / extended register or immediate), which
registers an instruction writes, and the AAPCS64 caller-saved sets.

These carry no protobuf meaning.  They are shared by the evaluator (:mod:`proto.arm64_eval`),
the writer-provenance flow (:mod:`proto.writer_flow`), the struct and map decoders and the
readFrom: dispatch."""
from __future__ import annotations

import re
from typing import List, NamedTuple, Optional

from macho.disasm import Insn, _norm_reg, _parse_imm, _SOURCE_FIRST_MNEMONICS


def split_ops(op_str):
    """Split an operand string on TOP-LEVEL commas (commas inside ``[...]`` stay
    put), returning stripped, lowercased operand tokens.

        'w1, [x20, x8]'   -> ['w1', '[x20, x8]']
        'x8, x8, #0x200'  -> ['x8', 'x8', '#0x200']
        'ret' / ''        -> []
    """
    out, depth, start = [], 0, 0
    for i, ch in enumerate(op_str):
        if ch == '[':
            depth += 1
        elif ch == ']':
            depth -= 1
        elif ch == ',' and depth == 0:
            out.append(op_str[start:i].strip().lower())
            start = i + 1
    tail = op_str[start:].strip().lower()
    if out or tail:
        out.append(tail)
    return out


REG_BYTES = {'x': 8, 'w': 4, 'd': 8, 's': 4, 'q': 16, 'h': 2, 'b': 1}


def reg_bytes(tok: str) -> int:
    return REG_BYTES.get(tok.strip()[:1].lower(), 8)


def reg_mask(tok: str) -> int:
    return 0xFFFFFFFF if tok.strip().lower().startswith('w') else 0xFFFFFFFFFFFFFFFF


def reg_bits(tok: str) -> int:
    """Width of register operand *tok*: 32 for a w register, else 64."""
    return 32 if tok.strip().lower().startswith('w') else 64


_FP_REG = re.compile(r'^[bhsdqv](\d+)(\.\w+)?$')


def reg_name(tok: str) -> Optional[str]:
    """A register operand's name for the reaching definitions: ``xN`` for x/w registers (as
    :func:`macho.disasm._norm_reg`), ``vN`` for an SIMD/FP register of any width."""
    r = _norm_reg(tok)
    if r is not None:
        return r
    m = _FP_REG.match(tok.strip().lower())
    return f"v{m.group(1)}" if m and int(m.group(1)) < 32 else None


CALLER_SAVED_GPRS = tuple(f"x{n}" for n in range(0, 19)) + ("x30",)


# The SIMD/FP registers, named vN whatever the width (b/h/s/d/q/vN.T): tracked by the reaching
# definitions only (a float/double argument rides in v0), never by value.  AAPCS64 preserves
# v8-v15 (their low 64 bits, all a scalar uses) across a call.
CALLER_SAVED_FPRS = tuple(f"v{n}" for n in range(0, 8)) + tuple(f"v{n}" for n in range(16, 32))


# Mnemonics whose first operand is NOT a destination (and calls, handled separately).
NO_DEST = _SOURCE_FIRST_MNEMONICS | {
    'b', 'bl', 'blr', 'br', 'nop', 'ccmp', 'ccmn', 'cbz', 'cbnz', 'tbz', 'tbnz', 'cmp', 'cmn', 'tst',
    'prfm', 'dmb', 'dsb', 'isb', 'fcmp', 'fcmpe', 'fccmp', 'fccmpe',
}


# The evaluator's loads and stores: bytes moved (None: the register's width) and whether a
# load sign-extends.
LOAD_BYTES = {'ldr': None, 'ldrb': 1, 'ldrh': 2, 'ldrsw': 4, 'ldrsb': 1, 'ldrsh': 2,
               'ldur': None, 'ldurb': 1, 'ldurh': 2, 'ldursw': 4, 'ldursb': 1, 'ldursh': 2}


SIGNED_LOADS = frozenset(('ldrsw', 'ldrsb', 'ldrsh', 'ldursw', 'ldursb', 'ldursh', 'ldpsw'))


STORE_BYTES = {'str': None, 'stur': None, 'strb': 1, 'sturb': 1, 'strh': 2, 'sturh': 2}


def is_cond_branch(mn: str) -> bool:
    return mn.startswith('b.')


class MemOperand(NamedTuple):
    """A ``[Rn, Rm{, ext #s}]`` / ``[Rn, #imm]`` memory operand."""
    base: Optional[str]
    index: Optional[str]
    disp: int
    ext: Optional[str]
    shift: int
    index_w: bool


def parse_mem(op: str):
    """``[Rn, Rm{, ext #s}]`` / ``[Rn, #imm]`` -> (base, index, disp, ext, shift, index is w-reg)."""
    if '[' not in op or ']' not in op:
        return None
    parts = [p.strip() for p in op[op.index('[') + 1: op.index(']')].split(',')]
    base = _norm_reg(parts[0])
    index, disp, ext, shift, idx_w = None, 0, None, 0, False
    if len(parts) >= 2:
        if parts[1].startswith('#'):
            disp = _parse_imm(parts[1]) or 0
        else:
            index, idx_w = _norm_reg(parts[1]), parts[1].startswith('w')
    if len(parts) >= 3:
        ext = parts[2].split()[0]
        shift = (_parse_imm(parts[2]) or 0) if '#' in parts[2] else 0
    return MemOperand(base, index, disp, ext, shift, idx_w)


def mem_regs(op: str):
    """(base, index or None, displacement) of a memory operand, or None."""
    pm = parse_mem(op)
    return None if pm is None else (pm[0], pm[1], pm[2])


def writeback_base(ops: List[str]) -> Optional[str]:
    """Base register a pre-index (``[Rn, #imm]!``) or post-index (``[Rn], #imm``) memory
    operand updates, else None."""
    i = next((j for j, o in enumerate(ops) if o.startswith('[')), None)
    if i is None:
        return None
    if ops[i].endswith('!') or (len(ops) > i + 1 and ops[i + 1].startswith('#')):
        pm = parse_mem(ops[i])
        return pm[0] if pm else None
    return None


def writes(ins: Insn) -> List[str]:
    """Registers (xN / vN form) *ins* overwrites."""
    mn = ins.mnemonic
    if mn in ('bl', 'blr'):
        return list(CALLER_SAVED_GPRS + CALLER_SAVED_FPRS)
    if is_cond_branch(mn):
        return []
    ops = split_ops(ins.op_str)
    out = []
    wb = writeback_base(ops)
    if wb is not None and wb not in ('xzr', 'sp'):
        out.append(wb)
    if mn in NO_DEST:
        return out
    if ops:
        r = reg_name(ops[0])
        if r is not None and r != 'xzr' and r != 'sp':
            out.append(r)
    if mn in ('ldp', 'ldnp', 'ldpsw') and len(ops) > 1:
        r = reg_name(ops[1])
        if r is not None and r != 'xzr' and r != 'sp':
            out.append(r)
    return out


SHIFT_MNEMONICS = ('lsr', 'lsl', 'asr')


def shift_value(mn: str, a: int, n: int, dest_tok: str) -> int:
    """``lsr`` / ``lsl`` / ``asr`` of *a* by *n*, in the destination's width."""
    bits = 32 if dest_tok.strip().lower().startswith('w') else 64
    n %= bits
    a &= (1 << bits) - 1
    if mn == 'lsl':
        return a << n
    if mn == 'lsr':
        return a >> n
    sa = a - (1 << bits) if a >> (bits - 1) else a
    return sa >> n


def as_signed(v: Optional[int], tok: str) -> Optional[int]:
    """*v*, a register's unsigned content, as the signed number it stands for (a bias
    materialised as ``mov w9, #-0x3bc4`` reads back as 0xFFFFC43C)."""
    if v is None:
        return None
    bits = 32 if tok.strip().lower().startswith('w') else 64
    return v - (1 << bits) if v >> (bits - 1) else v


def imm_operand(ops: List[str], i: int) -> Optional[int]:
    """The immediate at ``ops[i]`` including an optional ``lsl #12`` shift operand after it
    (``sub w8, w2, #0x11, lsl #12`` is 0x11000)."""
    v = _parse_imm(ops[i])
    if v is None:
        return None
    if len(ops) > i + 1 and ops[i + 1].startswith('lsl'):
        v <<= _parse_imm(ops[i + 1]) or 0
    return v


#: Extended-register operand forms: (source bits, sign-extends).
_EXTENDS = {'uxtb': (8, False), 'uxth': (16, False), 'uxtw': (32, False), 'uxtx': (64, False),
            'sxtb': (8, True), 'sxth': (16, True), 'sxtw': (32, True), 'sxtx': (64, True)}


def apply_shift(v: int, reg_tok: str, mod: str) -> Optional[int]:
    """*v* (register *reg_tok*'s content) under a second-operand modifier: a shifted register
    (``lsl``/``lsr``/``asr``/``ror #n``) or an extended register (``uxtb`` .. ``sxtx [#n]``).
    None for a modifier this does not know, so the result is unknown rather than wrong."""
    toks = mod.strip().lower().split(None, 1)
    if not toks:
        return v
    kind = toks[0]
    amt = 0
    if len(toks) > 1:
        amt = _parse_imm(toks[1].strip())
        if amt is None:
            return None
    bits = reg_bits(reg_tok)
    mask = (1 << bits) - 1
    v &= mask
    if kind == 'lsl':
        return v << amt
    if kind == 'lsr':
        return v >> amt
    if kind == 'asr':
        return (v - (1 << bits) if v >> (bits - 1) else v) >> amt
    if kind == 'ror':
        amt %= bits
        return ((v >> amt) | (v << (bits - amt))) & mask if amt else v
    if kind in _EXTENDS:
        width, signed = _EXTENDS[kind]
        x = v & ((1 << width) - 1)
        if signed and x >> (width - 1):
            x -= 1 << width
        return x << amt
    return None


def operand2(ops: List[str], i: int, get) -> Optional[int]:
    """Value of the flexible second operand at ``ops[i]``: an immediate (with an optional
    ``lsl #12``) or a register read with *get*, shifted / extended by ``ops[i + 1]``."""
    if ops[i].startswith('#'):
        return imm_operand(ops, i)
    v = get(ops[i])
    if v is None or len(ops) <= i + 1:
        return v
    return apply_shift(v, ops[i], ops[i + 1])
