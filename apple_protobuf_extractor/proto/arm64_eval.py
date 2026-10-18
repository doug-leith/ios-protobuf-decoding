"""proto/arm64_eval.py -- a small ARM64 evaluator over one function body: its CFG (jump-table
arms per ``br``), reaching definitions over the x and SIMD/FP registers, and concrete
evaluation with a model of the registers, the NZCV flags and the stack slots.

* :meth:`Flow.const_before` / :meth:`Flow.defs_before` -- a register's constant / definitions at
  an instruction (a constant iff exactly one definition reaches and it is constant).
* :meth:`Flow.candidates` -- the values worth evaluating for a loaded integer, read off the
  comparisons it takes part in (``V + b`` affine form, ordered gates expanded to intervals).
* :meth:`Flow.evaluate` -- run one value to the first call; :meth:`Flow.propagate` -- whole-
  function constant propagation (per flag value: :meth:`Flow.flag_runs`); :meth:`Flow.run_from`
  -- a run that continues through calls, recording each call site.

It knows nothing of protobufs.  Its users: the enum recovery (:mod:`proto.dictrep_flow`), the
struct decoder (:mod:`proto.structfields`), the readFrom: dispatch evaluator
(:mod:`proto.dispatch_eval`).  Split out of proto/dictrep_flow.py (code review 2026-10-18).
"""
from __future__ import annotations

import logging
import re
from collections import deque
from itertools import product
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, Iterable, List, Optional, Set, Tuple

from macho.disasm import Insn, _norm_reg, _parse_imm
from proto.arm64cfg import build_blocks, inject_arm_edges, parse_adrp, split_ops
from macho.strings import read_cfstring_text
from proto.arm64_operands import (
    CALLER_SAVED_GPRS, LOAD_BYTES, SIGNED_LOADS, STORE_BYTES,
    reg_bytes, reg_mask, reg_bits, is_cond_branch, writes,
    parse_mem, mem_regs, SHIFT_MNEMONICS, shift_value, as_signed, imm_operand,
    operand2,
)

log = logging.getLogger(__name__)


_ENTRY = -1                                   # pseudo-definition: value on function entry
_REGS = tuple(f"x{n}" for n in range(0, 31)) + tuple(f"v{n}" for n in range(0, 32))
_LOADS = {'ldr': None, 'ldrb': 1, 'ldrh': 2, 'ldrsw': 4, 'ldrsb': 1, 'ldrsh': 2}
_ORDERED_CONDS = ('hi', 'hs', 'cs', 'lo', 'cc', 'ls', 'gt', 'ge', 'lt', 'le')

# [cap:INPUT-SANITY] An ordered gate (`cmp w, #imm12; b.hi`) spans at most 2^12 values by the
# encoding of the immediate; a wider span cannot come from one unshifted compare.  Only a gate
# whose register then indexes a table is expanded to the whole interval.
_MAX_GATE_SPAN = 1 << 12


# sp on entry to an evaluated function.  A stack address is then an ordinary integer that
# arithmetic carries through ``sub sp`` / ``add x29, sp, #k`` / writeback, told apart from image
# and heap addresses (below 2^48 on arm64) by where it lives; a frame is far smaller than the
# 2^32 bytes either side of the entry sp this partition gives the stack.
_STACK_TOP = 1 << 62
_STACK_SPAN = 1 << 32
_FRAME_REGS = ('sp', 'x29')
# Registers that may carry a flag argument into a function: x0 holds the object / struct.
_FLAG_ARG_REGS = tuple(f"x{n}" for n in range(1, 8))


def _is_stack(v: Optional[int]) -> bool:
    return v is not None and _STACK_TOP - _STACK_SPAN <= v < _STACK_TOP + _STACK_SPAN


#: The condition flags N, Z, C, V (each 0 or 1), exactly as the instruction that set them left
#: them.  A literal ``#nzcv`` (``ccmp``) and the C = V = 0 of ``tst``/``ands`` are expressible.
Nzcv = Tuple[int, int, int, int]


def _nzcv_sub(a: int, b: int, bits: int) -> Nzcv:
    """Flags of ``a - b`` (``cmp``, ``subs``, ``ccmp``)."""
    m = (1 << bits) - 1
    ua, ub = a & m, b & m
    r = (ua - ub) & m
    return (r >> (bits - 1), int(r == 0), int(ua >= ub), ((ua ^ ub) & (ua ^ r)) >> (bits - 1) & 1)


def _nzcv_add(a: int, b: int, bits: int) -> Nzcv:
    """Flags of ``a + b`` (``cmn``, ``adds``, ``ccmn``)."""
    m = (1 << bits) - 1
    ua, ub = a & m, b & m
    r = (ua + ub) & m
    return (r >> (bits - 1), int(r == 0), int(ua + ub > m), (~(ua ^ ub) & (ua ^ r)) >> (bits - 1) & 1)


def _nzcv_logic(r: int, bits: int) -> Nzcv:
    """Flags of a logical result (``tst``, ``ands``, ``bics``): C = V = 0."""
    r &= (1 << bits) - 1
    return (r >> (bits - 1), int(r == 0), 0, 0)


def _eval_cond(cond: str, flags: Nzcv) -> Optional[bool]:
    """Truth of condition code *cond* under *flags*; None for an unknown code."""
    n, z, c, v = flags
    table = {
        'eq': z, 'ne': not z, 'hs': c, 'cs': c, 'lo': not c, 'cc': not c,
        'mi': n, 'pl': not n, 'vs': v, 'vc': not v,
        'hi': c and not z, 'ls': not c or z,
        'ge': n == v, 'lt': n != v, 'gt': not z and n == v, 'le': z or n != v,
        'al': True, 'nv': True,
    }
    r = table.get(cond)
    return None if r is None else bool(r)


#: Instructions that set the condition flags.  Any of them the evaluator does not model (or
#: models only in some operand forms) makes the flags unknown, so a later branch on them is
#: undecided rather than decided on an earlier comparison's flags.
_FLAG_SETTERS = frozenset((
    'cmp', 'cmn', 'tst', 'ccmp', 'ccmn', 'adds', 'subs', 'ands', 'bics', 'adcs', 'sbcs',
    'negs', 'ngcs', 'fcmp', 'fcmpe', 'fccmp', 'fccmpe', 'setf8', 'setf16', 'rmif', 'cfinv',
    'axflag', 'xaflag', 'msr'))


class _Abort(Exception):
    """The evaluation reached something it cannot decide (a branch on a value the analysis
    does not track, an unbounded jump, a revisited instruction); the message says which."""


class _Machine:
    """What an evaluation knows: register values, stack slots and the condition flags.

    A register absent from *regs* is asked of *fallback* (the reaching-definition constant at
    the evaluation's root) unless it was since overwritten with something unknown (*top*).
    *slots* maps a stack address to ``(size, value)``.  *escaped* records that a stack address
    has been put in a register other than sp / x29: from then on a callee, or a store through
    a pointer the evaluation does not know, may write any slot, so either clears them all.
    Until then the frame is the function's own and a call leaves its slots alone.

    *opaque*, when given, marks values that stand for an object the analysis cannot see into
    (``self``, a call's result): a register copy carries one, every other use of it (arithmetic,
    an address, a compare or test) sees an unknown value.

    *field_value(object, offset)*, when given, is the value a 64-bit load from an opaque object
    at a known offset produces (e.g. a token for ``self->ivar``); otherwise such a load is unknown.

    *object_escape* narrows what an escaped stack address exposes: a callee (or a store through
    an unknown pointer) is handed a pointer to an object and may write from it upward, never
    below it, so only the slots at or above the LOWEST escaped address are cleared
    (*escape_lo*).  Off by default: then every slot is cleared, as before."""

    def __init__(self, regs: Dict[str, int], fallback=None, opaque=None,
                 object_escape: bool = False, field_value=None):
        self.regs: Dict[str, int] = dict(regs)
        self.top: Set[str] = set()
        self.fallback = fallback
        self.opaque = opaque
        self.object_escape = object_escape
        self.field_value = field_value
        self.slots: Dict[int, Tuple[int, int]] = {}
        self.escaped = False
        self.escape_lo: Optional[int] = None
        self.flags: Optional[Nzcv] = None

    def copy(self) -> "_Machine":
        m = _Machine(self.regs, self.fallback, self.opaque, self.object_escape, self.field_value)
        m.top, m.slots, m.escaped, m.flags = set(self.top), dict(self.slots), self.escaped, self.flags
        m.escape_lo = self.escape_lo
        return m

    def _clobber_slots(self) -> None:
        """What a callee / a store through an unknown pointer may have written."""
        if not self.escaped:
            return
        if self.object_escape and self.escape_lo is not None:
            self.slots = {a: v for a, v in self.slots.items() if a + v[0] <= self.escape_lo}
        else:
            self.slots.clear()

    def join(self, other: "_Machine") -> "_Machine":
        """What holds on both paths (for :meth:`Flow.propagate`, whose machines have no
        fallback: an absent register is unknown)."""
        m = _Machine({r: v for r, v in self.regs.items() if other.regs.get(r) == v},
                     opaque=self.opaque, object_escape=self.object_escape,
                     field_value=self.field_value)
        m.slots = {a: s for a, s in self.slots.items() if other.slots.get(a) == s}
        m.escaped = self.escaped or other.escaped
        los = [x for x in (self.escape_lo, other.escape_lo) if x is not None]
        m.escape_lo = min(los) if los else None
        m.flags = self.flags if self.flags == other.flags else None
        return m

    def same(self, other: "_Machine") -> bool:
        return (self.regs == other.regs and self.slots == other.slots
                and self.escaped == other.escaped and self.flags == other.flags
                and self.escape_lo == other.escape_lo)

    def get(self, tok: str) -> Optional[int]:
        r = _norm_reg(tok)
        if r is None:
            return None
        if r == 'xzr':
            return 0
        if r in self.regs:
            v = self.regs[r]
        elif r in self.top or self.fallback is None:
            return None
        else:
            v = self.fallback(r)
            if v is None:
                return None
        if self.opaque is not None and self.opaque(v):
            return None
        return v & reg_mask(tok)

    def copy_of(self, tok: str) -> Optional[int]:
        """The value a register copy (``mov Rd, Rn``) moves: as :meth:`get`, except that an
        opaque value is carried by a 64-bit copy (a 32-bit one cannot hold it)."""
        r = _norm_reg(tok)
        if self.opaque is not None and r in self.regs and self.opaque(self.regs[r]):
            return self.regs[r] if tok.strip().lower().startswith('x') else None
        return self.get(tok)

    def put(self, tok: str, v: Optional[int]) -> None:
        r = _norm_reg(tok)
        if r is None or r == 'xzr':
            return
        if v is None:
            self.regs.pop(r, None)
            self.top.add(r)
            return
        v &= reg_mask(tok)
        self.regs[r] = v
        self.top.discard(r)
        if r not in _FRAME_REGS and _is_stack(v):
            self.escaped = True
            self.escape_lo = v if self.escape_lo is None else min(self.escape_lo, v)

    def call(self) -> None:
        """A call: the caller-saved registers and the flags are the callee's."""
        regs, top = self.regs, self.top
        for r in CALLER_SAVED_GPRS:                 # canonical names: no _norm_reg round trip
            regs.pop(r, None)
        top.update(CALLER_SAVED_GPRS)
        self.flags = None
        self._clobber_slots()

    def store(self, addr: Optional[int], size: int, v: Optional[int]) -> None:
        if not _is_stack(addr):
            if addr is None:
                self._clobber_slots()
            return                              # memory outside the frame is not modelled
        for a in [a for a, (s, _v) in self.slots.items() if a < addr + size and addr < a + s]:
            del self.slots[a]
        if v is not None:
            self.slots[addr] = (size, v & ((1 << (8 * size)) - 1))


@dataclass
class CallSite:
    """One call met by :meth:`Flow.run_from`: its instruction index and address, its target
    (None for a ``blr`` through an unknown register), the argument registers known at it, and
    whether it is a tail call (``b`` out of the function)."""
    k: int
    addr: int
    target: Optional[int]
    args: Dict[str, int]
    tail: bool = False


@dataclass
class Region:
    """What :meth:`Flow.run_from` reached: blocks in first-visit order, the calls, the known
    target of every ``br`` met (a caller can add the ones that are not yet CFG edges and run
    again), and the ``br`` instructions whose target was not known."""
    order: List[int] = field(default_factory=list)
    blocks: Set[int] = field(default_factory=set)
    calls: List[CallSite] = field(default_factory=list)
    br_targets: Set[Tuple[int, int]] = field(default_factory=set)     # (br address, target)
    unresolved_br: List[int] = field(default_factory=list)


class _Worklist:
    """The forward fixpoint's work list: the state at a block is the join of every state pushed
    to it; a block is (re)queued when that changes; *order* lists blocks by first visit."""

    def __init__(self, order: Optional[List[int]] = None):
        self.states: Dict[int, "_Machine"] = {}
        self.order: List[int] = order if order is not None else []
        self._work: deque = deque()
        self._queued: Set[int] = set()

    def push(self, blk: int, st: "_Machine") -> None:
        cur = self.states.get(blk)
        if cur is None:
            self.order.append(blk)
            self.states[blk] = st.copy()
        else:
            merged = cur.join(st)
            if merged.same(cur):
                return
            self.states[blk] = merged
        if blk not in self._queued:
            self._queued.add(blk)
            self._work.append(blk)

    def pop(self) -> int:
        blk = self._work.popleft()
        self._queued.discard(blk)
        return blk

    def __bool__(self) -> bool:
        return bool(self._work)


class Flow:
    """CFG + reaching definitions + concrete evaluation for ONE function body."""

    def __init__(self, ctx, insns: List[Insn], jump_table_arms: Iterable[int] = (),
                 br_arms: Optional[Dict[int, Iterable[int]]] = None):
        """The jump-table arms complete the CFG in one of two ways.

        * *br_arms* ``{br address: its arms}``: each arm starts a block and is an edge of ITS
          ``br`` only, so a ``br`` whose index is unknown reaches its own table's arms, not
          every table's (the readFrom: dispatch and the writer flow).
        * *jump_table_arms*: every arm is an edge of every ``br``.  The enum recovery needs this
          over-approximation: its candidate scan must reach the gates of the nested tables of a
          segmented switch, which hang off arms the per-``br`` decoding does not attribute
          (per-``br`` arms there lose cases such as iPhone 8
          AnalyticsPipelineStateData restoreUiTarget 1501-1504; measured 2026-10-18)."""
        self.ctx = ctx
        self.insns = insns
        self.addr_idx = {ins.addr: k for k, ins in enumerate(insns)}
        if br_arms is not None:
            leaders = {a for arms in br_arms.values() for a in arms}
            self.cfg = build_blocks(insns, leaders)
            for b in self.cfg.order:
                last = self.cfg.blocks[b][-1]
                if last.mnemonic == 'br':
                    for a in sorted(br_arms.get(last.addr, ())):
                        ab = self.cfg.addr_to_block.get(a)
                        if ab is not None and ab not in self.cfg.succ[b]:
                            self.cfg.succ[b].append(ab)
        else:
            self.cfg = build_blocks(insns, ())
            inject_arm_edges(self.cfg, tuple(jump_table_arms))
        self._block_of: Dict[int, int] = {}          # insn index -> block leader address
        self._first_in_block: Dict[int, int] = {}    # block leader -> index of its first insn
        for b in self.cfg.order:
            body = self.cfg.blocks[b]
            self._first_in_block[b] = self.addr_idx[body[0].addr]
            for ins in body:
                self._block_of[self.addr_idx[ins.addr]] = b
        self._wr: List[List[str]] = [writes(i) for i in insns]       # registers each insn writes
        self._gen: Dict[int, Dict[str, FrozenSet[int]]] = {}          # block -> last def of each reg
        for b in self.cfg.order:
            first = self._first_in_block[b]
            gen: Dict[str, FrozenSet[int]] = {}
            for k in range(first, first + len(self.cfg.blocks[b])):
                for r in self._wr[k]:
                    gen[r] = frozenset((k,))
            self._gen[b] = gen
        self._in: Dict[int, Dict[str, FrozenSet[int]]] = {}
        self._solve()
        self._const_memo: Dict[Tuple[int, str], Optional[int]] = {}
        self._ivar_memo: Dict[int, Optional[int]] = {}
        self._interval_sink: Optional[List[Tuple[int, int]]] = None

    # ── reaching definitions ────────────────────────────────────────────────

    def _solve(self) -> None:
        """Forward reaching-definitions fixpoint: sweep the blocks in reverse postorder, joining
        the predecessors' OUT sets, until nothing changes (a few sweeps for a reducible CFG)."""
        cfg = self.cfg
        if cfg.entry is None:
            return
        preds: Dict[int, List[int]] = {b: [] for b in cfg.order}
        for b in cfg.order:
            for s in cfg.succ.get(b, []):
                preds.setdefault(s, []).append(b)
        post: List[int] = []
        seen = {cfg.entry}
        stack = [(cfg.entry, iter(cfg.succ.get(cfg.entry, [])))]
        while stack:
            node, it = stack[-1]
            nxt = next((s for s in it if s not in seen), None)
            if nxt is None:
                post.append(node)
                stack.pop()
            else:
                seen.add(nxt)
                stack.append((nxt, iter(cfg.succ.get(nxt, []))))
        rpo = list(reversed(post))
        entry_state = {r: frozenset((_ENTRY,)) for r in _REGS}
        out: Dict[int, Dict[str, FrozenSet[int]]] = {}
        changed = True
        while changed:
            changed = False
            for b in rpo:
                if b == cfg.entry:
                    inn = entry_state
                else:
                    ps = [out[p] for p in preds[b] if p in out]
                    if not ps:
                        continue
                    if len(ps) == 1:
                        inn = ps[0]
                    else:
                        inn = {}
                        for r in _REGS:
                            first = ps[0][r]
                            inn[r] = first if all(o[r] is first or o[r] == first for o in ps[1:]) \
                                else frozenset().union(*(o[r] for o in ps))
                self._in[b] = inn
                state = dict(inn)
                state.update(self._gen[b])
                if out.get(b) != state:
                    out[b] = state
                    changed = True

    def defs_before(self, k: int, reg: str) -> FrozenSet[int]:
        """Indices of the definitions of *reg* that reach ``insns[k]`` (``-1`` = function
        entry); empty if the instruction is unreachable."""
        if k < 0:                                   # the function's entry (a root of -1)
            return frozenset((_ENTRY,)) if reg in _REGS else frozenset()
        b = self._block_of.get(k)
        if b is None or b not in self._in or reg not in _REGS:
            return frozenset()
        state = self._in[b][reg]
        for j in range(self._first_in_block[b], k):
            if reg in self._wr[j]:
                state = frozenset((j,))
        return state

    def _only_def(self, k: int, reg: str) -> Optional[int]:
        d = self.defs_before(k, reg)
        if len(d) != 1:
            return None
        (x,) = d
        return x if x >= 0 else None

    # ── constants ───────────────────────────────────────────────────────────

    def const_before(self, k: int, reg: str) -> Optional[int]:
        """Value of *reg* before ``insns[k]`` if exactly one constant definition reaches it."""
        if reg == 'xzr':
            return 0
        key = (k, reg)
        if key in self._const_memo:
            return self._const_memo[key]
        self._const_memo[key] = None                     # break cycles (loops)
        d = self._only_def(k, reg)
        val = self._const_of_def(d) if d is not None else None
        self._const_memo[key] = val
        return val

    def _const_of_def(self, d: int) -> Optional[int]:
        ins = self.insns[d]
        mn, ops = ins.mnemonic, split_ops(ins.op_str)
        if mn == 'adrp':
            pa = parse_adrp(ins.op_str)
            return pa[1] if pa else None
        if mn == 'adr' and len(ops) == 2:
            return _parse_imm(ops[1])
        if mn in ('mov', 'movz') and len(ops) == 2:
            if ops[1].startswith('#'):
                v = _parse_imm(ops[1])
                return None if v is None else v & reg_mask(ops[0])
            r = _norm_reg(ops[1])
            return self.const_before(d, r) if r else None
        if mn == 'movn' and len(ops) >= 2:
            v = _parse_imm(ops[1])
            sh = _parse_imm(ops[2]) if len(ops) > 2 else 0
            return None if v is None else (~(v << (sh or 0))) & reg_mask(ops[0])
        if mn == 'movk' and len(ops) >= 2:
            base = self.const_before(d, _norm_reg(ops[0]))
            v = _parse_imm(ops[1])
            sh = (_parse_imm(ops[2]) or 0) if len(ops) > 2 else 0
            if base is None or v is None:
                return None
            return ((base & ~(0xFFFF << sh)) | ((v & 0xFFFF) << sh)) & reg_mask(ops[0])
        if mn in ('add', 'sub') and len(ops) in (3, 4):
            def getc(tok: str) -> Optional[int]:
                r = _norm_reg(tok)
                v = self.const_before(d, r) if r else None
                return None if v is None else v & reg_mask(tok)
            a, b = getc(ops[1]), operand2(ops, 2, getc)
            if a is None or b is None:
                return None
            return (a + b if mn == 'add' else a - b) & reg_mask(ops[0])
        return None

    # ── which ivar a load reads ─────────────────────────────────────────────

    def ivar_of_reg(self, k: int, reg: str) -> Optional[int]:
        """Ivar byte offset that the ADDRESS held in *reg* before ``insns[k]`` was computed
        from, by use-def chain; None if it is not derived from exactly one ivar-offset slot."""
        found: Set[int] = set()
        for d in self.defs_before(k, reg):
            if d < 0:
                continue
            off = self._ivar_of_def(d)
            if off is not None:
                found.add(off)
        return next(iter(found)) if len(found) == 1 else None

    def _ivar_of_def(self, d: int) -> Optional[int]:
        if d in self._ivar_memo:
            return self._ivar_memo[d]
        self._ivar_memo[d] = None                        # break cycles (loop counters)
        ins = self.insns[d]
        mn, ops = ins.mnemonic, split_ops(ins.op_str)
        res: Optional[int] = None
        if mn == 'ldrsw' and len(ops) == 2:              # the ivar-offset slot itself
            addr = self._mem_const_addr(d, ops[1])
            if addr is not None:
                try:
                    res = self.ctx.read_s32(addr)
                except (ValueError, KeyError, IndexError):
                    res = None
        elif mn == 'add' and len(ops) >= 3:              # obj + offset  /  array + index
            cands = {self.ivar_of_reg(d, r) for r in (_norm_reg(ops[1]),
                     _norm_reg(ops[2]) if not ops[2].startswith('#') else None) if r}
            cands.discard(None)
            res = next(iter(cands)) if len(cands) == 1 else None
        elif mn == 'mov' and len(ops) == 2 and not ops[1].startswith('#'):
            r = _norm_reg(ops[1])
            res = self.ivar_of_reg(d, r) if r else None
        elif mn == 'ldr' and len(ops) == 2 and ops[0].startswith('x'):
            # container deref (PBRepeated.list): a POINTER loaded from the ivar's own
            # storage, no index -- a value read out of an array is not an address
            m = mem_regs(ops[1])
            res = self.ivar_of_reg(d, m[0]) if m and m[0] and m[1] is None else None
        self._ivar_memo[d] = res
        return res

    def _mem_const_addr(self, k: int, mem: str) -> Optional[int]:
        """Address of ``[Rn, #imm]`` / ``[Rn]`` when Rn is a constant, else None."""
        m = mem_regs(mem)
        if not m or m[0] is None or m[1] is not None:
            return None
        base = self.const_before(k, m[0])
        return None if base is None else base + m[2]


    # ── candidate values: the constants V is compared / indexed against ─────

    def candidates(self, root: int, dest: str, domain,
                   intervals: Optional[List[Tuple[int, int]]] = None) -> Set[int]:
        """Values of the loaded integer worth evaluating, from the comparisons it takes part
        in.  Registers are tracked as ``V + b`` through ``mov`` / ``add|sub`` of an immediate
        or of a constant register; comparing such a register with *c* gives the point
        ``c - b``, and an ordered gate (``b.hi`` / ``b.hs`` / ...) gives the whole interval it
        guards (``sub w9,w8,#35; cmp w9,#30; b.hi`` -> V in 35..65).  The scan follows the CFG
        from the load and stops each path at its first call (where the name is consumed).
        *domain* is ``hi`` (values ``0 <= v < hi``) or ``(lo, hi)``: a 4-byte value is a signed
        int32, so an enum may start below zero (``add w8, w2, #1; cmp w8, #10`` is -1..8).
        *intervals*, when given, receives the ``(lo, hi)`` of EVERY ordered gate met, whether or
        not a table load then uses it (a gate whose index is clamped by a ``csel`` before the
        load is not followed to the load)."""
        cands: Set[int] = {0}
        self._gate_capped = False        # set when a table gate was wider than _MAX_GATE_SPAN
        self._interval_sink = intervals
        root_blk = self._block_of.get(root) if root >= 0 else self.cfg.entry
        if root_blk is None:
            return cands
        entry: Dict[int, Dict[str, int]] = {}
        work: deque = deque()

        def push(blk: int, st: Dict[str, int]) -> None:
            cur = entry.get(blk)
            if cur is None:
                entry[blk] = dict(st)
            else:
                merged = {r: b for r, b in cur.items() if st.get(r) == b}
                if merged == cur:
                    return
                entry[blk] = merged
            work.append(blk)

        def run(blk: int, st: Dict[str, int], lo: int) -> bool:
            hi = self._first_in_block[blk] + len(self.cfg.blocks[blk])
            for k in range(lo, hi):
                if self.insns[k].mnemonic in ('bl', 'blr'):
                    return False
                self._candidate_step(cands, st, k)
            for succ in self.cfg.succ.get(blk, []):
                push(succ, st)
            return True

        run(root_blk, {dest: 0}, root + 1)
        while work:
            blk = work.popleft()
            run(blk, dict(entry[blk]), self._first_in_block[blk])
        lo, hi = domain if isinstance(domain, tuple) else (0, domain)
        return {v for v in cands if lo <= v < hi}

    def _candidate_step(self, cands: Set[int], st: Dict[str, int], k: int) -> None:
        """One instruction of the candidate scan.  *st* maps a register to its offset ``b`` in
        ``V + b``; it ALSO carries, per path, the interval of the last ordered gate on each
        offset (keys ``gate_lo:<b>`` / ``gate_hi:<b>``), so a table is expanded by ITS OWN
        gate and not by an unrelated compare of the same value met on another path."""
        ins = self.insns[k]
        mn, ops = ins.mnemonic, split_ops(ins.op_str)
        if mn in ('cmp', 'cmn') and len(ops) in (2, 3):
            r = _norm_reg(ops[0])
            if r in st:
                c = imm_operand(ops, 1) if ops[1].startswith('#') else self._const_reg(k, ops[1])
                if c is not None and mn == 'cmn':     # `cmn w2, #1` compares with -1
                    c = -c
                if c is not None:
                    nxt = self.insns[k + 1].mnemonic if k + 1 < len(self.insns) else ''
                    cond = nxt[2:] if nxt.startswith('b.') else ''
                    point = c - st[r]
                    cands.add(point)
                    if cond in _ORDERED_CONDS:
                        lo, hi = sorted((-st[r], point))
                        st[f"gate_lo:{st[r]}"], st[f"gate_hi:{st[r]}"] = lo, hi   # keyed by the VALUE's offset: a register copy keeps it
                        if self._interval_sink is not None:
                            self._interval_sink.append((lo, hi))
        elif mn in ('cbz', 'cbnz') and ops:
            r = _norm_reg(ops[0])
            if r in st:
                cands.add(-st[r])
        elif mn in _LOADS and len(ops) == 2:
            # A table indexed by a gated register: every index the gate lets through is a
            # distinct case, so the whole interval (not just its end point) is a candidate.
            pm = parse_mem(ops[1])
            if pm and pm[1] in st and f"gate_lo:{st[pm[1]]}" in st:
                lo, hi = st[f"gate_lo:{st[pm[1]]}"], st[f"gate_hi:{st[pm[1]]}"]
                if hi - lo <= _MAX_GATE_SPAN:
                    cands.update(range(lo, hi + 1))
                else:
                    self._gate_capped = True
        new: Optional[Tuple[str, int]] = None
        if mn == 'mov' and len(ops) == 2 and not ops[1].startswith('#'):
            rs, rd = _norm_reg(ops[1]), _norm_reg(ops[0])
            if rs in st and rd:
                new = (rd, st[rs])
        elif mn in ('add', 'sub') and len(ops) >= 3:      # 4th operand: ``lsl #12`` of an immediate
            rs, rd = _norm_reg(ops[1]), _norm_reg(ops[0])
            if rs in st and rd:
                raw = operand2(ops, 2, lambda tok: self._const_reg(k, tok))
                c = raw if ops[2].startswith('#') or raw is None else \
                    as_signed(raw & reg_mask(ops[0]), ops[0])
                if c is not None:
                    new = (rd, st[rs] + (c if mn == 'add' else -c))
        for r in writes(ins):
            st.pop(r, None)
        if new is not None:
            st[new[0]] = new[1]

    def _const_reg(self, k: int, tok: str) -> Optional[int]:
        r = _norm_reg(tok)
        return self.const_before(k, r) if r else None

    def _skip_trap_branch(self, k: int, target: Optional[int], mn: str, ins: Insn) -> int:
        """Index to continue at after a test of a register the analysis does not track, when one
        side of the branch is a trap (``brk``/``udf``).  Such a test is a runtime check that
        passes on every execution that returns -- the arm64e pointer-authentication return
        check ``eor x16,x30,x30,lsl #1; tbz x16,#62,ok; brk`` -- so the evaluation follows the
        other side.  Any other untracked test cannot be decided and aborts the value."""
        def traps(i: Optional[int]) -> bool:
            return i is not None and 0 <= i < len(self.insns) \
                and self.insns[i].mnemonic in ('brk', 'udf')
        t = self.addr_idx.get(target) if target is not None else None
        if traps(t) and not traps(k + 1):
            return k + 1
        if traps(k + 1) and t is not None and not traps(t):
            return t
        raise _Abort(f"{mn} at {ins.addr:#x} tests an untracked register")

    # ── concrete evaluation of the switch for one value ─────────────────────

    def evaluate(self, root: int, dest: str, value: int,
                 stop: FrozenSet[int] = frozenset(), direct: bool = False,
                 where: Optional[List[int]] = None) -> Dict[str, str]:
        """Run the code from just after the field-value load *root* (the function's entry for
        ``root == -1``) with ``dest = value`` to the first call -- or to the return / tail call
        out of the function, where a converter hands back its result -- and return
        ``{argument register: text}`` for every argument register (x0-x7) that then holds a
        string constant: the dictionary key, the name chosen for the value, the converter's
        ``"(unknown: %i)"`` fallback...  Empty when the value never reaches one (it reaches
        another field's value load listed in *stop* first -- an older compiler simply omits the
        entry for a value with no name).  *direct* also accepts plain C strings from
        ``__TEXT,__cstring`` (standalone binaries' name tables).  Which register carries the
        NAME is decided by the caller: the one whose text varies with the value.  *where*, when
        given, receives the index of the call / return the run stopped at."""
        m = _Machine({dest: value & 0xFFFFFFFF if value < 0 else value},
                     fallback=lambda r: self.const_before(root, r))
        if root < 0:
            m.put('sp', _STACK_TOP)               # from the entry the frame is the function's
        seen: Set[int] = set()

        def jump(target: Optional[int]) -> int:
            if target is None or target not in self.addr_idx:
                raise _Abort(f"indirect/unresolvable jump at {self.insns[k].addr:#x}")
            return self.addr_idx[target]

        k = root + 1
        while k < len(self.insns):
            if k in seen:
                raise _Abort(f"loop at {self.insns[k].addr:#x}")
            if k in stop:
                return {}
            seen.add(k)
            ins = self.insns[k]
            mn, ops = ins.mnemonic, split_ops(ins.op_str)
            nxt = k + 1
            if mn in ('bl', 'blr', 'ret', 'retaa', 'retab'):
                if where is not None:
                    where.append(k)
                return self._string_args(m.get, direct)
            if mn == 'b' and len(ops) == 1:
                target = _parse_imm(ops[0])
                if target is not None and target not in self.addr_idx:
                    if where is not None:
                        where.append(k)
                    return self._string_args(m.get, direct)   # a tail call out of the function
                nxt = jump(target)
            elif mn == 'br' and len(ops) == 1:
                nxt = jump(m.get(ops[0]))
            elif is_cond_branch(mn) or mn in ('cbz', 'cbnz', 'tbz', 'tbnz'):
                taken, target = self._branch(m, ins)
                if taken is None:
                    if is_cond_branch(mn):
                        raise _Abort(f"{mn} at {ins.addr:#x} tests flags the analysis cannot compute"
                                     if m.flags is None else f"unmodelled condition {mn} at {ins.addr:#x}")
                    nxt = self._skip_trap_branch(k, target, mn, ins)
                elif taken:
                    nxt = jump(target)
            else:
                self._exec(m, ins)
            k = nxt
        return {}

    def _branch(self, m: "_Machine", ins: Insn) -> Tuple[Optional[bool], Optional[int]]:
        """``(taken, target)`` of a conditional branch under *m*; ``taken`` is None when the
        condition is not known."""
        mn, ops = ins.mnemonic, split_ops(ins.op_str)
        if is_cond_branch(mn):
            target = _parse_imm(ops[0]) if ops else None
            return (None if m.flags is None else _eval_cond(mn[2:], m.flags)), target
        if mn in ('cbz', 'cbnz') and len(ops) == 2:
            v = m.get(ops[0])
            return (None if v is None else (v == 0) == (mn == 'cbz')), _parse_imm(ops[1])
        if mn in ('tbz', 'tbnz') and len(ops) == 3:
            v = m.get(ops[0])
            bit = _parse_imm(ops[1]) or 0
            return (None if v is None else (((v >> bit) & 1) == 0) == (mn == 'tbz')), _parse_imm(ops[2])
        return None, None

    def _exec(self, m: "_Machine", ins: Insn) -> None:
        """One non-branching instruction's effect on *m* (registers, flags, stack slots).
        Anything not modelled makes the registers it writes unknown."""
        mn, ops = ins.mnemonic, split_ops(ins.op_str)
        get, put = m.get, m.put
        if mn in ('cmp', 'cmn') and len(ops) in (2, 3):   # 3: ``cmp w2, #4, lsl #12`` / ``w9, lsl #2``
            a, b = get(ops[0]), operand2(ops, 1, get)
            m.flags = None if a is None or b is None else \
                (_nzcv_sub if mn == 'cmp' else _nzcv_add)(a, b, reg_bits(ops[0]))
        elif mn in ('ccmp', 'ccmn') and len(ops) == 4:     # ccmp a, b, #nzcv, cond
            c = None if m.flags is None else _eval_cond(ops[3], m.flags)
            if c is None:
                m.flags = None
            elif c:
                a = get(ops[0])
                b = _parse_imm(ops[1]) if ops[1].startswith('#') else get(ops[1])
                m.flags = None if a is None or b is None else \
                    (_nzcv_sub if mn == 'ccmp' else _nzcv_add)(a, b, reg_bits(ops[0]))
            else:
                lit = _parse_imm(ops[2])
                m.flags = None if lit is None else \
                    ((lit >> 3) & 1, (lit >> 2) & 1, (lit >> 1) & 1, lit & 1)
        elif mn in ('mov', 'movz') and len(ops) == 2:
            put(ops[0], _parse_imm(ops[1]) if ops[1].startswith('#') else m.copy_of(ops[1]))
        elif mn == 'movn' and len(ops) >= 2:
            v = _parse_imm(ops[1])
            put(ops[0], None if v is None else ~(v << ((_parse_imm(ops[2]) or 0) if len(ops) > 2 else 0)))
        elif mn == 'movk' and len(ops) >= 2:
            base, v = get(ops[0]), _parse_imm(ops[1])
            sh = (_parse_imm(ops[2]) or 0) if len(ops) > 2 else 0
            put(ops[0], None if base is None or v is None
                else (base & ~(0xFFFF << sh)) | ((v & 0xFFFF) << sh))
        elif mn in ('adrp', 'adr') and len(ops) == 2:
            v = (parse_adrp(ins.op_str) or (None, None))[1] if mn == 'adrp' else _parse_imm(ops[1])
            put(ops[0], v)
        elif mn in ('add', 'sub') and len(ops) in (3, 4):
            a, b = get(ops[1]), operand2(ops, 2, get)
            put(ops[0], None if a is None or b is None else (a + b if mn == 'add' else a - b))
        elif mn == 'csel' and len(ops) == 4:
            if m.flags is None:
                put(ops[0], None)
            else:
                c = _eval_cond(ops[3], m.flags)
                put(ops[0], None if c is None else get(ops[1] if c else ops[2]))
        elif mn in SHIFT_MNEMONICS and len(ops) == 3:
            a = get(ops[1])
            n = _parse_imm(ops[2]) if ops[2].startswith('#') else get(ops[2])
            put(ops[0], None if a is None or n is None else shift_value(mn, a, n, ops[0]))
        elif mn in ('and', 'orr', 'eor', 'ands') and len(ops) in (3, 4):
            a = get(ops[1])
            b = _parse_imm(ops[2]) if ops[2].startswith('#') else operand2(ops, 2, get)
            r = None if a is None or b is None else \
                {'and': a & b, 'ands': a & b, 'orr': a | b, 'eor': a ^ b}[mn]
            put(ops[0], r)
            if mn == 'ands':
                m.flags = None if r is None else _nzcv_logic(r, reg_bits(ops[0]))
        elif mn == 'ubfx' and len(ops) == 4:
            a, lsb, width = get(ops[1]), _parse_imm(ops[2]), _parse_imm(ops[3])
            put(ops[0], None if a is None or lsb is None or not width
                else (a >> lsb) & ((1 << width) - 1))
        elif mn == 'tst' and len(ops) in (2, 3):     # tst a, b [, shift]: flags of a & b
            a = get(ops[0])
            b = _parse_imm(ops[1]) if ops[1].startswith('#') else operand2(ops, 1, get)
            m.flags = None if a is None or b is None else _nzcv_logic(a & b, reg_bits(ops[0]))
        elif mn in ('subs', 'adds') and len(ops) in (3, 4):
            a, b = get(ops[1]), operand2(ops, 2, get)
            if a is not None and b is not None:
                bits = reg_bits(ops[0])
                m.flags = (_nzcv_sub if mn == 'subs' else _nzcv_add)(a, b, bits)
                put(ops[0], a - b if mn == 'subs' else a + b)
            else:
                m.flags = None
                put(ops[0], None)
        elif mn in LOAD_BYTES and len(ops) in (2, 3):
            ft = (self._field_load(m, ops[1])
                  if len(ops) == 2 and mn == 'ldr' and ops[0].strip().lower().startswith('x')
                  else None)
            if ft is not None:
                put(ops[0], ft)
                return
            addr = self._access(m, ops[1], ops[2] if len(ops) == 3 else None)
            size = LOAD_BYTES[mn] or reg_bytes(ops[0])
            put(ops[0], self._read(m, addr, size, mn in SIGNED_LOADS))
        elif mn in ('ldp', 'ldpsw') and len(ops) in (3, 4):
            addr = self._access(m, ops[2], ops[3] if len(ops) == 4 else None)
            size = 4 if mn == 'ldpsw' else reg_bytes(ops[0])
            put(ops[0], self._read(m, addr, size, mn == 'ldpsw'))
            put(ops[1], self._read(m, None if addr is None else addr + size, size, mn == 'ldpsw'))
        elif mn in STORE_BYTES and len(ops) in (2, 3):
            v = m.copy_of(ops[0])                   # a spill is a copy (opaque values survive)
            addr = self._access(m, ops[1], ops[2] if len(ops) == 3 else None)
            m.store(addr, STORE_BYTES[mn] or reg_bytes(ops[0]), v)
        elif mn == 'stp' and len(ops) in (3, 4):
            v0, v1 = m.copy_of(ops[0]), m.copy_of(ops[1])
            addr = self._access(m, ops[2], ops[3] if len(ops) == 4 else None)
            size = reg_bytes(ops[0])
            m.store(addr, size, v0)
            m.store(None if addr is None else addr + size, size, v1)
        else:
            for r in writes(ins):
                put(r, None)
            if mn in _FLAG_SETTERS:                 # an unmodelled flag-setter, or form of one
                m.flags = None

    def _field_load(self, m: "_Machine", mem: str) -> Optional[int]:
        """``m.field_value(object, offset)`` for a 64-bit load from an opaque object at a known
        offset (``ldr x0, [x19, x8]`` with x19 = self and x8 an ivar offset), else None."""
        if m.field_value is None:
            return None
        pm = parse_mem(mem)
        if pm is None or mem.endswith('!'):
            return None
        base, index, disp, ext, shift, idx_w = pm
        r = _norm_reg(base) if base else None
        obj = m.regs.get(r) if r else None
        if obj is None or m.opaque is None or not m.opaque(obj):
            return None
        off = disp
        if index:
            iv = m.get(index)
            if iv is None:
                return None
            if idx_w or ext in ('sxtw', 'uxtw'):
                iv &= 0xFFFFFFFF
                if ext == 'sxtw' and iv & 0x80000000:
                    iv -= 1 << 32
            off += iv << shift
        return m.field_value(obj, off)

    def _access(self, m: "_Machine", mem: str, post: Optional[str]) -> Optional[int]:
        """Address a memory operand accesses under *m* (None if unknown), applying a pre-index
        (``[Rn, #imm]!``) or post-index (``[Rn], #imm``) base update to *m*."""
        pm = parse_mem(mem)
        if pm is None:
            return None
        base, index, disp, ext, shift, idx_w = pm
        b = m.get(base) if base else None
        addr = b
        if addr is not None and index:
            iv = m.get(index)
            if iv is None:
                addr = None
            else:
                if idx_w or ext in ('sxtw', 'uxtw'):
                    iv &= 0xFFFFFFFF
                    if ext == 'sxtw' and iv & 0x80000000:
                        iv -= 1 << 32
                addr += iv << shift
        if mem.endswith('!'):
            addr = None if addr is None else addr + disp
            m.put(base, addr)
        elif post is not None and post.startswith('#'):
            imm = _parse_imm(post)
            m.put(base, None if b is None or imm is None else b + imm)
        elif addr is not None:
            addr += disp
        return None if addr is None else addr & 0xFFFFFFFFFFFFFFFF

    def _read(self, m: "_Machine", addr: Optional[int], size: int, signed: bool) -> Optional[int]:
        """The *size*-byte value at *addr*: a stack slot stored with that width, or the image."""
        if addr is None:
            return None
        if _is_stack(addr):
            slot = m.slots.get(addr)
            if slot is None or slot[0] != size:
                return None
            raw = slot[1]
        else:
            try:
                if size == 8:
                    return self.ctx.read_ptr(addr)
                raw = int.from_bytes(self.ctx.read_bytes(addr, size), 'little')
            except (ValueError, KeyError, IndexError):
                return None
        if signed and size < 8 and raw & (1 << (size * 8 - 1)):
            raw -= 1 << (size * 8)
        return raw

    # ── constant propagation over the whole function ────────────────────────

    def propagate(self, entry: Dict[str, int], at: Iterable[int], opaque=None,
                  object_escape: bool = False,
                  slots_out: Optional[Dict[int, Dict[int, Tuple[int, int]]]] = None,
                  call_result=None, field_value=None) -> Dict[int, Dict[str, int]]:
        """``{k: {register: value}}``: the registers known before each ``insns[k]`` in *at*
        when the function is entered with *entry* (say a flag argument's value) and sp at
        the frame's top; an index missing from the result is unreachable under *entry*.

        Unlike :meth:`evaluate` this runs through calls (which clobber the caller-saved
        registers) and over the whole CFG: a forward fixpoint in which a register, stack slot
        or the flags is known at a block iff every path into it that can execute agrees.  A
        branch whose condition is known follows only the side taken, so code that depends on
        *entry* is resolved the same way whether it was compiled to a ``csel`` or a branch.
        *opaque*, *object_escape*: see :class:`_Machine`; *slots_out*, when given, receives the
        stack slots known before each ``insns[k]`` in *at*; *call_result*: see :meth:`run_from`."""
        cfg = self.cfg
        want = set(at)
        if cfg.entry is None:
            return {}
        start = _Machine(entry, opaque=opaque, object_escape=object_escape, field_value=field_value)
        start.put('sp', _STACK_TOP)
        wl = _Worklist()
        wl.push(cfg.entry, start)
        while wl:
            blk = wl.pop()
            st = wl.states[blk].copy()
            first = self._first_in_block[blk]
            for k in range(first, first + len(cfg.blocks[blk])):
                self._propagate_step(st, k, call_result)
            for succ in self._live_successors(blk, st):
                wl.push(succ, st)
        out: Dict[int, Dict[str, int]] = {}
        for blk, st0 in wl.states.items():
            st = st0.copy()
            first = self._first_in_block[blk]
            for k in range(first, first + len(cfg.blocks[blk])):
                if k in want:
                    out[k] = dict(st.regs)
                    if slots_out is not None:
                        slots_out[k] = dict(st.slots)
                self._propagate_step(st, k, call_result)
        return out

    def _propagate_step(self, m: "_Machine", k: int, call_result=None) -> None:
        ins = self.insns[k]
        mn = ins.mnemonic
        if mn in ('bl', 'blr'):
            if call_result is None:
                m.call()
                return
            x0 = m.copy_of('x0')
            ops = split_ops(ins.op_str)
            target = _parse_imm(ins.op_str) if mn == 'bl' else (m.get(ops[0]) if ops else None)
            m.call()
            v = call_result(k, target, x0)
            if v is not None:
                m.put('x0', v)
        elif mn in ('b', 'br', 'ret', 'retaa', 'retab', 'cbz', 'cbnz', 'tbz', 'tbnz') \
                or is_cond_branch(mn):
            return
        else:
            self._exec(m, ins)

    def _live_successors(self, blk: int, m: "_Machine") -> List[int]:
        """The successors of *blk* that can execute under *m*: one side of a branch whose
        condition is known (or the known target of a ``br``), else all of them."""
        succ = self.cfg.succ.get(blk, [])
        last = self.cfg.blocks[blk][-1]
        if last.mnemonic == 'br':
            v = m.get(split_ops(last.op_str)[0]) if last.op_str else None
            b = self.cfg.addr_to_block.get(v) if v is not None else None
            return [b] if b in succ else list(succ)
        taken, target = self._branch(m, last)
        if taken is None:
            return list(succ)
        k = self.addr_idx[last.addr]
        dest = target if taken else (self.insns[k + 1].addr if k + 1 < len(self.insns) else None)
        b = self.cfg.addr_to_block.get(dest) if dest is not None else None
        return [b] if b in succ else []

    def run_from(self, k0: int, regs: Dict[str, int], stop: FrozenSet[int] = frozenset(),
                 opaque=None, object_escape: bool = False,
                 slots: Optional[Dict[int, Tuple[int, int]]] = None,
                 tail_targets: FrozenSet[int] = frozenset(),
                 rejoin: FrozenSet[int] = frozenset(), call_result=None,
                 field_value=None) -> "Region":
        """Run from ``insns[k0]`` with *regs* known (nothing else is) to every block it can
        reach without entering a block in *stop*, through calls, and record each call.

        The same forward fixpoint as :meth:`propagate` -- a value is known at a block iff every
        path into it that can execute agrees, and a branch whose condition is known follows only
        the side taken -- but started mid-function and bounded by *stop* (e.g. the blocks that
        dominate a reader's ``lsr Wf, Wtag, #3``, so one loop iteration is evaluated).  A call
        clobbers the caller-saved registers, flags and (once a stack address has escaped) the
        slots.
        The result lists every call (``bl`` / ``blr`` / a ``b`` out of the function) with the
        argument registers x0-x7 known at it (opaque values included, see :class:`_Machine`),
        and the blocks reached in first-visit order.  *object_escape*: see :class:`_Machine`;
        *slots*: stack slots known at ``insns[k0]``.  A ``b`` to an address in *tail_targets*
        (known function entries) is a tail call even when that address lies in the window.
        *call_result(k, target, x0_before)*, when given, is the value of x0 after the call at
        ``insns[k]`` (None: unknown) -- e.g. *x0_before* for a runtime function that returns its
        argument (``objc_retain``), or an opaque token naming that call's result, so it can be
        followed to later arguments.
        *rejoin*: a path that has left this set of blocks stops when it enters it again (e.g. the
        blocks an unknown field number reaches: after a field's own handler, everything from
        there on is common to every field)."""
        cfg = self.cfg
        start_blk = self._block_of.get(k0)
        region = Region()
        if start_blk is None:
            return region
        wl = _Worklist(region.order)

        def push(blk: int, st: _Machine, frm: Optional[int] = None) -> None:
            if blk in stop or (frm is not None and blk in rejoin and frm not in rejoin):
                return
            wl.push(blk, st)

        def step(st: _Machine, k: int, record: bool) -> None:
            ins = self.insns[k]
            mn = ins.mnemonic
            tgt = _parse_imm(ins.op_str) if mn == 'b' else None
            tail = tgt is not None and (tgt not in self.addr_idx or tgt in tail_targets)
            if mn in ('bl', 'blr') or tail:
                if record:
                    target = (m_get_target(st, ins) if mn == 'blr' else _parse_imm(ins.op_str))
                    args = {f"x{n}": v for n in range(8) if (v := st.copy_of(f"x{n}")) is not None}
                    region.calls.append(CallSite(k, ins.addr, target, args, tail))
                if mn != 'b':
                    x0 = st.copy_of('x0')
                    target = (m_get_target(st, ins) if mn == 'blr' else _parse_imm(ins.op_str))
                    st.call()
                    v = call_result(k, target, x0) if call_result is not None else None
                    if v is not None:
                        st.put('x0', v)
            else:
                self._propagate_step(st, k)

        def m_get_target(st: _Machine, ins: Insn) -> Optional[int]:
            ops = split_ops(ins.op_str)
            return st.get(ops[0]) if ops else None

        def successors(blk: int, st: _Machine) -> List[int]:
            last = cfg.blocks[blk][-1]
            if last.mnemonic == 'b' and _parse_imm(last.op_str) in tail_targets:
                return []
            return self._live_successors(blk, st)

        def run_block(blk: int, st: _Machine, lo: int, record: bool) -> None:
            first = self._first_in_block[blk]
            for k in range(lo, first + len(cfg.blocks[blk])):
                step(st, k, record)
            last = cfg.blocks[blk][-1]
            if record and last.mnemonic == 'br':
                v = m_get_target(st, last)
                if v is None:
                    region.unresolved_br.append(last.addr)
                else:
                    region.br_targets.add((last.addr, v))

        # The partial first block runs once; its successors seed the fixpoint.
        st0 = _Machine(regs, opaque=opaque, object_escape=object_escape, field_value=field_value)
        if 'sp' not in regs:
            st0.put('sp', _STACK_TOP)
        if slots:
            st0.slots = dict(slots)
        first_st = st0.copy()
        run_block(start_blk, st0, k0, False)
        for succ in successors(start_blk, st0):
            push(succ, st0, start_blk)
        while wl:
            blk = wl.pop()
            st = wl.states[blk].copy()
            run_block(blk, st, self._first_in_block[blk], False)
            for succ in successors(blk, st):
                push(succ, st, blk)
        # Record the calls from the final (fixpoint) state of each block.
        run_block(start_blk, first_st, k0, True)
        for blk in region.order:
            run_block(blk, wl.states[blk].copy(), self._first_in_block[blk], True)
        region.blocks = set(region.order) | {start_blk}
        return region

    def flag_arguments(self) -> Tuple[str, ...]:
        """Argument registers (x1-x7) whose value on entry is tested: a compare, test or
        test-and-branch reads it, directly or through ``mov`` copies, by reaching definitions.
        A generated ``_dictionaryRepresentation:`` takes its JSON-or-not flag this way."""
        out: Set[str] = set()
        for k, ins in enumerate(self.insns):
            if k not in self._block_of:
                continue
            mn, ops = ins.mnemonic, split_ops(ins.op_str)
            if mn not in ('cmp', 'cmn', 'tst', 'ccmp', 'ccmn', 'cbz', 'cbnz', 'tbz', 'tbnz') or not ops:
                continue
            r = self._entry_arg(k, _norm_reg(ops[0]), set())
            if r in _FLAG_ARG_REGS:
                out.add(r)
        return tuple(sorted(out))

    def entry_arg(self, k: int, reg: Optional[str]) -> Optional[str]:
        """The argument register whose value on ENTRY *reg* holds before ``insns[k]`` (by
        reaching definitions, through ``mov`` copies), else None."""
        return self._entry_arg(k, reg, set())

    def _entry_arg(self, k: int, reg: Optional[str], seen: Set[int]) -> Optional[str]:
        """The register whose ENTRY value *reg* holds before ``insns[k]``, through copies."""
        if reg is None:
            return None
        defs = self.defs_before(k, reg)
        if defs == frozenset((_ENTRY,)):
            return reg
        if len(defs) != 1:
            return None
        (d,) = defs
        if d < 0 or d in seen:
            return None
        seen.add(d)
        ins = self.insns[d]
        ops = split_ops(ins.op_str)
        if ins.mnemonic == 'mov' and len(ops) == 2 and not ops[1].startswith('#'):
            return self._entry_arg(d, _norm_reg(ops[1]), seen)
        return None

    def flag_runs(self, at: Iterable[int]) -> List[Dict[int, Dict[str, int]]]:
        """:meth:`propagate` once per assignment of 0 / 1 to the :meth:`flag_arguments` (one
        run with nothing fixed when there are none) -- e.g. the JSON and the plain
        dictionary representation of one ``_dictionaryRepresentation:``."""
        at = list(at)
        flags = self.flag_arguments()
        return [self.propagate(dict(zip(flags, bits)), at)
                for bits in product((0, 1), repeat=len(flags))]

    def _string_args(self, get, direct: bool = False) -> Dict[str, str]:
        out: Dict[str, str] = {}
        for n in range(8):
            reg = f"x{n}"
            va = get(reg)
            if va is None:
                continue
            text = self._text_at(va, direct)
            if text:
                out[reg] = text
        return out

    def _text_at(self, va: int, direct: bool) -> Optional[str]:
        """The string constant at *va*: a CFString; with *direct*, also a plain C string in
        ``__TEXT,__cstring`` (not a selector name or any other pointer into the image)."""
        text = read_cfstring_text(self.ctx, va)
        if text is not None or not direct:
            return text
        try:
            if not self.ctx.has_section("__TEXT", "__cstring"):
                return None
            sec = self.ctx.section("__TEXT", "__cstring")
            if not sec.vmaddr <= va < sec.vmaddr + sec.vmsize:
                return None
            return self.ctx.read_cstring(va, max_len=128)
        except (ValueError, KeyError, UnicodeDecodeError, AttributeError):
            return None

    # ── the enum maps of the function ───────────────────────────────────────


# ── operand helpers ────────────────────────────────────────────────────────


