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
    """Split an operand string on TOP-LEVEL commas (commas inside ``[...]`` or a register list
    ``{...}`` stay put), returning stripped, lowercased operand tokens.

        'w1, [x20, x8]'             -> ['w1', '[x20, x8]']
        'x8, x8, #0x200'            -> ['x8', 'x8', '#0x200']
        '{v0.16b, v1.16b}, [x0]'    -> ['{v0.16b, v1.16b}', '[x0]']
        'ret' / ''                  -> []
    """
    out, depth, start = [], 0, 0
    for i, ch in enumerate(op_str):
        if ch in '[{':
            depth += 1
        elif ch in ']}':
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
    t = tok.strip().lower()
    return 8 if t == 'sp' else REG_BYTES.get(t[:1], 8)


def reg_mask(tok: str) -> int:
    return 0xFFFFFFFF if tok.strip().lower().startswith('w') else 0xFFFFFFFFFFFFFFFF


def reg_bits(tok: str) -> int:
    """Width of register operand *tok*: 32 for a w register, else 64."""
    return 32 if tok.strip().lower().startswith('w') else 64


_FP_REG = re.compile(r'^[bhsdqv](\d+)(\.\w+)?(\[(?:0x[0-9a-f]+|\d+)\])?$')    # a lane: v0.s[1], v0.b[0xa]


def reg_name(tok: str) -> Optional[str]:
    """A register operand's name for the reaching definitions: ``xN`` for x/w registers (as
    :func:`macho.disasm._norm_reg`), ``vN`` for an SIMD/FP register of any width."""
    r = _norm_reg(tok)
    if r is not None:
        return r
    m = _FP_REG.match(tok.strip().lower())
    return f"v{m.group(1)}" if m and int(m.group(1)) < 32 else None


CALLER_SAVED_GPRS = tuple(f"x{n}" for n in range(0, 19)) + ("x30",)


# The AAPCS64 argument registers; a call also reads x8, an indirect result's address.
ARG_GPRS = tuple(f"x{n}" for n in range(8))
ARG_FPRS = tuple(f"v{n}" for n in range(8))
CALL_ARG_GPRS = ARG_GPRS + ("x8",)


# The SIMD/FP registers, named vN whatever the width (b/h/s/d/q/vN.T): tracked by the reaching
# definitions only (a float/double argument rides in v0), never by value.  AAPCS64 preserves
# v8-v15 (their low 64 bits, all a scalar uses) across a call.
CALLER_SAVED_FPRS = tuple(f"v{n}" for n in range(0, 8)) + tuple(f"v{n}" for n in range(16, 32))


CALLER_SAVED = CALLER_SAVED_GPRS + CALLER_SAVED_FPRS


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


PAIR_LOADS = frozenset(('ldp', 'ldpsw', 'ldnp'))


PAIR_STORES = frozenset(('stp', 'stnp'))


RETURNS = frozenset(('ret', 'retaa', 'retab'))


COMPARE_BRANCHES = frozenset(('cbz', 'cbnz', 'tbz', 'tbnz'))


# Calls: ``bl``, and through a register (arm64e: authenticating it first).
CALLS = frozenset(('bl', 'blr', 'blraa', 'blrab', 'blraaz', 'blrabz'))


# Branches through a register (arm64e: authenticating it first).  A jump table's is a plain ``br``.
INDIRECT_BRANCHES = frozenset(('br', 'braa', 'brab', 'braaz', 'brabz'))


# Traps: a path that reaches one ends there.
TRAPS = frozenset(('brk', 'udf', 'hlt'))


# Every branch but ``b.cond`` (:func:`is_cond_branch`): what ends a straight-line run.
BLOCK_ENDS = frozenset(('b',)) | CALLS | INDIRECT_BRANCHES | RETURNS | COMPARE_BRANCHES


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


def _list_regs(tok: str) -> List[str]:
    """The registers of a vector register list ``{v0.16b, v1.16b}`` or one lane of them
    ``{v0.s, v1.s}[1]`` (``vN`` form)."""
    inner = tok[tok.index('{') + 1:tok.index('}')] if '{' in tok and '}' in tok else tok
    return [r for r in (reg_name(t) for t in inner.split(',')) if r]


def operand_regs(tokens) -> List[str]:
    """The registers (``xN`` / ``vN`` form) named by operand tokens -- memory operands'
    bases and indices included -- other than ``xzr`` / ``sp``."""
    out = []
    for t in tokens:
        t = t.strip()
        if t.startswith('['):
            pm = parse_mem(t)
            names = [n for n in (pm[0], pm[1]) if n] if pm else []
        elif t.startswith('{'):
            names = _list_regs(t)
        else:
            names = t.split()[:1]
        for n in names:
            r = reg_name(n)
            if r and r not in ('xzr', 'sp'):
                out.append(r)
    return out


def mem_regs(op: str):
    """(base, index or None, displacement) of a memory operand, or None."""
    pm = parse_mem(op)
    return None if pm is None else (pm[0], pm[1], pm[2])


def writeback_base(ops: List[str]) -> Optional[str]:
    """Base register a pre-index (``[Rn, #imm]!``) or post-index memory operand updates (an
    operand after it: ``[Rn], #imm``, or a register, ``[x26], x19`` in a vector load / store),
    else None."""
    i = next((j for j, o in enumerate(ops) if o.startswith('[')), None)
    if i is None:
        return None
    if ops[i].endswith('!') or len(ops) > i + 1:
        pm = parse_mem(ops[i])
        return pm[0] if pm else None
    return None


# Exclusive stores: the first operand is the status register they write.
STORE_EXCLUSIVE = frozenset(('stxr', 'stxrb', 'stxrh', 'stlxr', 'stlxrb', 'stlxrh', 'stxp', 'stlxp'))
# LSE atomics that return the old value in their SECOND operand (``ldadd ws, wt, [xn]``);
# ``cas`` writes its first, ``casp`` its first pair.
_LSE_LOAD = re.compile(r'(ldadd|ldclr|ldeor|ldset|ldsmax|ldsmin|ldumax|ldumin|swp)(a|l|al)?[bh]?$')
_CASP = re.compile(r'casp(a|l|al)?$')


def _is_store(mn: str) -> bool:
    """*mn* stores and writes no register but a writeback base: every ``st...`` (``str``,
    ``stlur``, ``st1``, an LSE store alias ``stadd``, an MTE tag store ``stz2g`` ...) except
    an exclusive store's status (:data:`STORE_EXCLUSIVE`)."""
    return mn.startswith('st') and mn not in STORE_EXCLUSIVE


def writes_memory(mn: str) -> bool:
    """*mn* writes memory: a store (an exclusive one included), an LSE atomic, a compare-and-swap."""
    return mn.startswith('st') or bool(_LSE_LOAD.match(mn)) or mn.startswith('cas')
# Instructions that read their destination too: they change only some of its bits (movk, the
# bitfield inserts, a shift-insert), accumulate into it (multiply-add, shift-right-accumulate,
# the bitwise selects, a table lookup's extension) or authenticate / sign / strip the pointer
# it holds.
_READS_DEST = frozenset((
    'movk', 'bfi', 'bfxil', 'bfm', 'bfc', 'sli', 'sri',
    'mla', 'mls', 'fmla', 'fmls', 'usra', 'ssra', 'ursra', 'srsra', 'bsl', 'bit', 'bif', 'tbx',
    'smlal', 'smlal2', 'umlal', 'umlal2', 'smlsl', 'smlsl2', 'umlsl', 'umlsl2', 'sqdmlal',
    'sqdmlal2', 'sqdmlsl', 'sqdmlsl2', 'sdot', 'udot', 'fmlal', 'fmlsl', 'sadalp', 'uadalp',
    'autia', 'autib', 'autda', 'autdb', 'autiza', 'autizb', 'autdza', 'autdzb',
    'pacia', 'pacib', 'pacda', 'pacdb', 'paciza', 'pacizb', 'pacdza', 'pacdzb',
    'xpaci', 'xpacd'))
# Pointer authentication with implicit operands: (registers read, registers written).  The
# return-address forms sign / authenticate / strip x30 in place (with sp or zero as the
# modifier); the 1716 forms sign x17 with x16.
_IMPLICIT = {mn: (('x30',), ('x30',)) for mn in (
    'paciasp', 'pacibsp', 'autiasp', 'autibsp', 'paciaz', 'pacibz', 'autiaz', 'autibz', 'xpaclri')}
_IMPLICIT.update({mn: (('x16', 'x17'), ('x17',)) for mn in (
    'pacia1716', 'pacib1716', 'autia1716', 'autib1716')})
# Loads that write two registers.
_PAIR_DESTS = PAIR_LOADS | frozenset(('ldxp', 'ldaxp'))


def writes(ins: Insn) -> List[str]:
    """Registers (xN / vN form) *ins* overwrites."""
    mn = ins.mnemonic
    if mn in CALLS:
        return list(CALLER_SAVED)
    if is_cond_branch(mn):
        return []
    if mn in _IMPLICIT:
        return list(_IMPLICIT[mn][1])
    ops = split_ops(ins.op_str)
    out = []
    wb = writeback_base(ops)
    if wb is not None and wb not in ('xzr', 'sp'):
        out.append(wb)
    if (mn in NO_DEST or _is_store(mn)) and mn not in STORE_EXCLUSIVE:
        return out
    if ops and ops[0].startswith('{'):
        dests = _list_regs(ops[0]) if mn.startswith('ld') else []      # a lane load: the list
    elif _LSE_LOAD.match(mn):
        dests = ops[1:2]
    elif mn in _PAIR_DESTS or _CASP.match(mn):
        dests = ops[:2]
    else:
        dests = ops[:1]
    for d in dests:
        r = reg_name(d)
        if r is not None and r != 'xzr' and r != 'sp':
            out.append(r)
    return out



def reads(ins: Insn) -> List[str]:
    """Registers (xN / vN form) *ins* reads, as :func:`writes` sees its operands: a load its
    address registers (an LSE atomic also the value it adds / swaps in); a store, compare or
    test every register; an exclusive store all but its status; a call through a register
    that register (what the callee reads is :func:`proto.callees.call_reads`'); ``movk`` /
    ``bfi`` / a lane write also the destination they change only part of; anything else every
    register but the destination(s)."""
    mn = ins.mnemonic
    ops = split_ops(ins.op_str)
    if mn == 'bl' or mn == 'b' or is_cond_branch(mn):
        return []
    if mn in _IMPLICIT:
        return list(_IMPLICIT[mn][0])
    if mn in RETURNS and not ops:
        return ['x30']                          # the return address
    mem = [o for o in ops if o.startswith('[')]
    if mn in CALLS or mn in INDIRECT_BRANCHES:
        srcs = ops
    elif mn in STORE_EXCLUSIVE:
        srcs = ops[1:]
    elif _LSE_LOAD.match(mn):
        srcs = ops[:1] + mem
    elif mn.startswith('cas'):
        srcs = ops
    elif (mn in NO_DEST or _is_store(mn) or mn in _READS_DEST
          or (ops and '[' in ops[0] and not ops[0].startswith('['))
          or (mn in ('orr', 'bic') and len(ops) > 1 and ops[0].startswith('v')
              and ops[1].startswith('#'))):    # ``orr v0.4s, #0xff``: Vd = Vd | imm
        srcs = ops
    elif mem and mn.startswith('ld'):
        srcs = mem
    else:
        srcs = ops[1:] if writes(ins) else ops
    return operand_regs(srcs)

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
