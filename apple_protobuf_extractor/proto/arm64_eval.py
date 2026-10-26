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
(:mod:`proto.dispatch_eval`).
"""
from __future__ import annotations

import logging
from collections import deque
from itertools import product
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, FrozenSet, Iterable, List, Optional, Set, Tuple

from macho.disasm import Insn, _norm_reg, _parse_imm
from macho.memory import READ_ERRORS
from proto.arm64cfg import (build_blocks, build_blocks_with_br_arms, inject_arm_edges, parse_adrp,
                            predecessors, reverse_postorder)
from macho.strings import read_cfstring_text
from proto.callees import (call_reads, call_clobbers as callee_clobbers, outlined_fragment,
                           outlined_tail)
from proto.arm64_operands import (
    ARG_GPRS, AUTHENTICATED_BRANCHES, CALL_ARG_GPRS, CALLER_SAVED, CALLER_SAVED_GPRS, CALLS,
    INDIRECT_BRANCHES, POINTER_AUTH, RETURNS, LOAD_BYTES, SIGNED_LOADS, STORE_BYTES, TRAPS,
    split_ops, writes_memory, reg_bytes, reg_mask, reg_bits, branch_target, is_cond_branch,
    is_conditional, writes,
    parse_mem, index_offset, mem_regs, SHIFT_MNEMONICS, shift_value, as_signed, imm_operand,
    operand2,
)

log = logging.getLogger(__name__)


_ENTRY = -1                                   # pseudo-definition: value on function entry
_REGS = tuple(f"x{n}" for n in range(0, 31)) + tuple(f"v{n}" for n in range(0, 32))
_ORDERED_CONDS = ('hi', 'hs', 'cs', 'lo', 'cc', 'ls', 'gt', 'ge', 'lt', 'le')
# The ordered conditions whose bound belongs to the upper side (``cmp w8, #3 ; b.hs`` admits 0..2).
_STRICT_CONDS = frozenset(('hs', 'cs', 'lo', 'cc', 'ge', 'lt'))
#: The ordered conditions that hold when ``cmp V, #c`` finds V in ``0..c`` (``csel``'s first
#: source is then the in-range one).
_IN_RANGE_CONDS = frozenset(('ls', 'lo', 'cc', 'le', 'lt'))

# [cap:COSMETIC — ×8 changes none of the 19 gate targets, 2026-10-26] the widest ordered gate
# (`cmp w, #imm; b.hi`), mask or value set whose values are evaluated one by one (each a run):
# an unshifted immediate spans at most 2^12 values, a register or `lsl #12` compare more, and
# nothing else in the code bounds a table it indexes.  A wider one is not enumerated, and is
# reported (Candidates.gate_capped; record_heuristic_hit).
_MAX_GATE_SPAN = 1 << 12


@dataclass(frozen=True)
class Sym:
    """A value that is not a number: a frame address (*kind* ``"frame"``: the entry sp plus
    *off*), an address into an object the analysis cannot see into (``"pointer"``: object
    *ident* plus *off*, :class:`Objects` *pointer*), or an object itself (``"token"``:
    :mod:`proto.eval_tokens`).  The machine carries one through what keeps its meaning
    (:meth:`_Machine.put`) and takes any other use of it as unknown.

    Defined on it: a frame address or a pointer plus or minus a number (another one), the
    difference of two frame addresses (a number: it does not depend on where the stack is),
    and the order of frame addresses.  Anything else -- its bits, a shift, a token plus a
    number -- raises TypeError: an operation the machine does not take as unknown is a bug,
    not a value (as an integer it would make a plausible number)."""
    kind: str
    ident: Any = None
    off: int = 0

    def __add__(self, n):
        if type(n) is int and self.kind != "token":
            return Sym(self.kind, self.ident, self.off + n)
        return NotImplemented

    __radd__ = __add__

    def __sub__(self, o):
        if type(o) is int and self.kind != "token":
            return Sym(self.kind, self.ident, self.off - o)
        if isinstance(o, Sym) and self.kind == o.kind == "frame":
            return self.off - o.off
        return NotImplemented

    def __lt__(self, o):
        if isinstance(o, Sym) and self.kind == o.kind == "frame":
            return self.off < o.off
        return NotImplemented

    def __le__(self, o):
        if isinstance(o, Sym) and self.kind == o.kind == "frame":
            return self.off <= o.off
        return NotImplemented


def frame(off: int = 0) -> Sym:
    """The frame address *off* bytes from the entry sp."""
    return Sym("frame", None, off)


# sp on entry to an evaluated function.  A frame address is the entry sp plus an offset: copies,
# loads and stores of all 64 bits carry it, adding or subtracting a number moves it, the
# difference of two is that number, and clearing the low four bits aligns it (the entry sp is
# 16-byte aligned, AAPCS64).  Any other use of one is unknown: its 32-bit half, a shift, a
# compare with a number -- what they give depends on where the stack really is.
_STACK_TOP = frame(0)
# A frame is far smaller than the 2^32 bytes either side of the entry sp: a frame address
# further off (a frame address plus a 64-bit constant) is unknown (_Machine.put).
_STACK_SPAN = 1 << 32
_MASK64 = (1 << 64) - 1
# Where flags comparing two frame addresses are computed: an sp far from wrapping either way.
_REPRESENTATIVE_SP = 1 << 62
_FRAME_REGS = ('sp', 'x29')
# Registers that may carry a flag argument into a function: x0 holds the object / struct.
_FLAG_ARG_REGS = ARG_GPRS[1:]


def _is_stack(v) -> bool:
    return isinstance(v, Sym) and v.kind == "frame"


def _is_symbolic(v) -> bool:
    return isinstance(v, Sym)


def _wide(tok: str) -> bool:
    """*tok* names all 64 bits of a general register (``xN`` / ``sp``), not a ``w`` half."""
    t = tok.strip().lower()
    return t.startswith('x') or t == 'sp'


def _signed64(v: int) -> int:
    return v - (1 << 64) if v >= 1 << 63 else v


def _add_sub(add: bool, a: Optional[int], b: Optional[int]) -> Optional[int]:
    """``a + b`` / ``a - b`` where either may be a frame address or a pointer into an object:
    one plus or minus a number (read as signed 64-bit) is one too, the difference of two frame
    addresses is a number; a number minus one, two objects' addresses, or the sum of two
    frame addresses are unknown."""
    if a is None or b is None:
        return None
    sa, sb = _is_stack(a), _is_stack(b)
    if sa and sb:
        return None if add else a - b
    syma, symb = _is_symbolic(a), _is_symbolic(b)
    if syma and symb:
        return None
    if symb:
        return b + _signed64(a) if add and b.kind != "token" else None
    if syma:
        return None if a.kind == "token" else a + _signed64(b) if add else a - _signed64(b)
    return a + b if add else a - b


def _frame_based(m: "_Machine", mem: str) -> bool:
    """A memory operand whose base register holds a frame address."""
    pm = parse_mem(mem)
    return pm is not None and pm.base is not None and _is_stack(m.get(pm.base))


def _flag_operands(a: Optional[int], b: Optional[int], subtract: bool = True
                   ) -> Tuple[Optional[int], Optional[int]]:
    """The operands a compare's flags are computed from: two numbers as they are; for a
    subtraction (``cmp`` / ``subs``), two frame addresses as offsets from one sp (their
    difference does not depend on where the stack is, their sum does); a frame address against
    a number, unknown."""
    if a is None or b is None:
        return None, None
    sa, sb = _is_stack(a), _is_stack(b)
    if sa and sb and subtract:
        return a.off + _REPRESENTATIVE_SP, b.off + _REPRESENTATIVE_SP
    if sa or sb or _is_symbolic(a) or _is_symbolic(b):
        return None, None
    return a, b


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


_SIGN_EXTENDS = {'sxtb': 8, 'sxth': 16, 'sxtw': 32}    # the bits each sign-extends

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
    has been put in a register other than sp / x29: from then on a store through a pointer
    the evaluation does not know may write any slot, so it clears them.  *handed* records that
    a callee can reach the frame: a stack address was in an argument register (x0-x8) at a
    call, or was stored outside the frame; from then on every call may write any slot.
    Until then the frame is the function's own and a call leaves its slots alone.

    *opaque*, when given, marks values that stand for an object the analysis cannot see into
    (``self``, a call's result): a register copy carries one, every other use of it (arithmetic,
    an address, a compare or test) sees an unknown value.

    *field_value(object, offset)*, when given, is the value a 64-bit load from an opaque object
    at a known offset produces (e.g. a token for ``self->ivar``); otherwise such a load is unknown.

    *pointer*, when given, marks values that are addresses into an object the analysis cannot
    see into (a Swift ``&self.field``, where self is a struct): unlike an opaque value, one plus
    or minus a number is still one (as a frame address is), and a load from one at a known
    offset is ``field_value(pointer, offset)``.

    *bound(slot)*, when given, is the value an 8-byte load from a slot dyld binds to an import
    produces (a value naming the import); otherwise such a load is unknown.

    *object_escape* narrows what an escaped stack address exposes: a callee (or a store through
    an unknown pointer) is handed a pointer to an object and may write from it upward, never
    below it, so only the slots at or above the LOWEST escaped (*escape_lo*) or handed
    (*handed_lo*) address are cleared.  Off by default: then every slot is cleared."""

    def __init__(self, regs: Dict[str, int], fallback=None, opaque=None,
                 object_escape: bool = False, field_value=None, pointer=None, bound=None):
        self.regs: Dict[str, int] = dict(regs)
        self.top: Set[str] = set()
        self.fallback = fallback
        self.opaque = opaque
        self.object_escape = object_escape
        self.field_value = field_value
        self.pointer = pointer
        self.bound = bound
        self.slots: Dict[int, Tuple[int, int]] = {}
        self.escaped = False
        self.escape_lo: Optional[int] = None
        self.handed = False
        self.handed_lo: Optional[int] = None
        self.flags: Optional[Nzcv] = None

    def copy(self) -> "_Machine":
        m = _Machine(self.regs, self.fallback, self.opaque, self.object_escape, self.field_value,
                     self.pointer, self.bound)
        m.top, m.slots, m.escaped, m.flags = set(self.top), dict(self.slots), self.escaped, self.flags
        m.escape_lo = self.escape_lo
        m.handed, m.handed_lo = self.handed, self.handed_lo
        return m

    def _clobber_slots(self, reached: bool, lo: Optional[int]) -> None:
        """What a callee / a store through an unknown pointer may have written: nothing
        unless it can *reach* the frame; with *object_escape*, the slots from *lo* up."""
        if not reached:
            return
        if self.object_escape and lo is not None:
            self.slots = {a: v for a, v in self.slots.items() if a + v[0] <= lo}
        else:
            self.slots.clear()

    def _hand(self, v: int) -> None:
        self.handed = True
        self.handed_lo = v if self.handed_lo is None else min(self.handed_lo, v)

    def _reach(self, lo: int) -> int:
        """The lowest frame address a callee handed the object at *lo* can reach: *lo*, or a
        frame address stored in a slot it can read (at or above *lo*), transitively."""
        changed = True
        while changed:
            changed = False
            for a, (s, v) in self.slots.items():
                if a + s > lo and _is_stack(v) and v < lo:
                    lo, changed = v, True
        return lo

    def join(self, other: "_Machine") -> "_Machine":
        """What holds on both paths (for :meth:`Flow.propagate`, whose machines have no
        fallback: an absent register is unknown)."""
        m = _Machine({r: v for r, v in self.regs.items() if other.regs.get(r) == v},
                     opaque=self.opaque, object_escape=self.object_escape,
                     field_value=self.field_value, pointer=self.pointer, bound=self.bound)
        m.slots = {a: s for a, s in self.slots.items() if other.slots.get(a) == s}
        m.escaped = self.escaped or other.escaped
        los = [x for x in (self.escape_lo, other.escape_lo) if x is not None]
        m.escape_lo = min(los) if los else None
        m.handed = self.handed or other.handed
        los = [x for x in (self.handed_lo, other.handed_lo) if x is not None]
        m.handed_lo = min(los) if los else None
        m.flags = self.flags if self.flags == other.flags else None
        return m

    def same(self, other: "_Machine") -> bool:
        return (self.regs == other.regs and self.slots == other.slots
                and self.escaped == other.escaped and self.flags == other.flags
                and self.escape_lo == other.escape_lo and self.handed == other.handed
                and self.handed_lo == other.handed_lo)

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
        if _is_symbolic(v):
            return v if _wide(tok) else None
        return v & reg_mask(tok)

    def number(self, tok: str) -> Optional[int]:
        """*tok*'s value when it is a number (not a frame address)."""
        v = self.get(tok)
        return None if _is_symbolic(v) else v

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
        if _is_symbolic(v):
            symbol = (_is_stack(v) and -_STACK_SPAN <= v.off < _STACK_SPAN) or \
                (self.opaque is not None and self.opaque(v)) or \
                (self.pointer is not None and self.pointer(v))
            if not symbol or not _wide(tok):        # stack-derived arithmetic, or half of one
                self.regs.pop(r, None)
                self.top.add(r)
                return
        else:
            v &= reg_mask(tok)
        self.regs[r] = v
        self.top.discard(r)
        if r not in _FRAME_REGS and _is_stack(v):
            self.escaped = True
            self.escape_lo = v if self.escape_lo is None else min(self.escape_lo, v)

    def call(self, args: Tuple[str, ...] = None, clobbers: Optional[Tuple[str, ...]] = None
             ) -> None:
        """A call: the caller-saved registers and the flags are the callee's, and the frame
        slots too once a callee can reach them (*handed*: a stack address in a register it
        reads -- *args*, default x0-x8 -- now, or handed out before).  A callee that changes
        fewer (*clobbers*: :data:`proto.callees.CALL_CLOBBERS`) changes only those and the
        flags."""
        if clobbers is not None:
            for r in clobbers:
                self.regs.pop(r, None)
            self.top.update(clobbers)
            self.flags = None
            return
        for r in (CALL_ARG_GPRS if args is None else args):
            v = self.regs.get(r)
            if v is None and r not in self.top and self.fallback is not None:
                v = self.fallback(r)
            if _is_stack(v):
                self._hand(v)
        regs, top = self.regs, self.top
        for r in CALLER_SAVED_GPRS:                 # canonical names: no _norm_reg round trip
            regs.pop(r, None)
        top.update(CALLER_SAVED_GPRS)
        self.flags = None
        if self.handed and self.object_escape:
            self.handed_lo = self._reach(self.handed_lo)
        self._clobber_slots(self.handed, self.handed_lo)

    def store(self, addr: Optional[int], size: int, v: Optional[int],
              in_frame: bool = False) -> None:
        """A store of *v* at *addr*; *in_frame*: its base is a frame address (an unknown index
        or an unmodelled form leaves *addr* None: any slot may be written)."""
        if not _is_stack(addr):
            if _is_stack(v):
                self._hand(v)                   # stored where a callee may find it
            if addr is None and in_frame:
                self.slots.clear()
            elif addr is None:
                if self.escaped and self.object_escape:
                    self.escape_lo = self._reach(self.escape_lo)
                self._clobber_slots(self.escaped, self.escape_lo)
            return                              # memory outside the frame is not modelled
        for a in [a for a, (s, _v) in self.slots.items() if a < addr + size and addr < a + s]:
            del self.slots[a]
        if v is not None and (size == 8 or not _is_symbolic(v)):
            self.slots[addr] = (size, v if _is_symbolic(v) else v & ((1 << (8 * size)) - 1))


@dataclass(frozen=True)
class Objects:
    """How a run (:meth:`Flow.run_from`, :meth:`Flow.propagate`) treats the objects it cannot
    see into -- all optional: *opaque*, *field_value*, *pointer* and *object_escape* as in
    :class:`_Machine`; *call_result(addr, target, x0_before)*, the value of x0 after the call
    at address *addr* (None: unknown) -- e.g. *x0_before* for a runtime function that returns its
    argument (``objc_retain``), or an opaque token naming that call's result, so it can be
    followed to later arguments; *bound* as in :class:`_Machine`."""
    opaque: Optional[Callable[[Optional[int]], bool]] = None
    field_value: Optional[Callable[[int, int], Optional[int]]] = None
    call_result: Optional[Callable[[int, Optional[int], Optional[int]], Optional[int]]] = None
    object_escape: bool = False
    pointer: Optional[Callable[[Optional[int]], bool]] = None
    bound: Optional[Callable[[int], Optional[int]]] = None

    def machine(self, regs: Dict[str, int]) -> "_Machine":
        return _Machine(regs, opaque=self.opaque, object_escape=self.object_escape,
                        field_value=self.field_value, pointer=self.pointer, bound=self.bound)


NO_OBJECTS = Objects()
_ALL_GPRS = tuple(f"x{n}" for n in range(29))


@dataclass
class CallSite:
    """One call met by :meth:`Flow.run_from`: its instruction index and address, its target
    (None for a ``blr`` through an unknown register), the argument registers known at it, and
    whether it is a tail call (``b`` out of the function).  In a run with *pointer* objects
    (:class:`Objects`: Swift) *args* holds every register known at it (self, the error and the
    async context are x20-x22, and an outlined thunk reads the caller's callee-saved ones) and
    *via* is the value a ``blr`` goes through, a token included."""
    k: int
    addr: int
    target: Optional[int]
    args: Dict[str, int]
    tail: bool = False
    via: Optional[int] = None


@dataclass
class Region:
    """What :meth:`Flow.run_from` reached: blocks in first-visit order, the calls, the known
    target of every ``br`` met (a caller can add the ones that are not yet CFG edges and run
    again)."""
    order: List[int] = field(default_factory=list)
    blocks: Set[int] = field(default_factory=set)
    calls: List[CallSite] = field(default_factory=list)
    br_targets: Set[Tuple[int, int]] = field(default_factory=set)     # (br address, target)


class RegMap(dict):
    """A :meth:`Flow.forward` state that is a plain map (register -> value, or any key): an
    entry holds at a join iff it holds, with the same value, on both sides."""

    def copy(self) -> "RegMap":
        return RegMap(self)

    def join(self, other: Dict) -> "RegMap":
        return RegMap((r, v) for r, v in self.items() if other.get(r) == v)

    def same(self, other: Dict) -> bool:
        return self == other


class _Worklist:
    """The forward fixpoint's work list (:meth:`Flow.forward`): the state at a block is the join
    of every state pushed to it; a block is (re)queued when that changes; *order* lists blocks
    by first visit."""

    def __init__(self, order: Optional[List[int]] = None):
        self.states: Dict[int, Any] = {}
        self.order: List[int] = order if order is not None else []
        self._work: deque = deque()
        self._queued: Set[int] = set()

    def push(self, blk: int, st: Any) -> None:
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


@dataclass
class Candidates:
    """What :meth:`Flow.candidates` read off the comparisons a loaded integer takes part in."""
    values: Set[int]                                    # within the domain
    intervals: List[Tuple[int, int]] = field(default_factory=list)   # every ordered gate met
    gate_capped: bool = False          # a table gate was wider than _MAX_GATE_SPAN values


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
          AnalyticsPipelineStateData restoreUiTarget 1501-1504)."""
        self.ctx = ctx
        self.insns = insns
        self.addr_idx = {ins.addr: k for k, ins in enumerate(insns)}
        if br_arms is not None:
            self.cfg = build_blocks_with_br_arms(insns, br_arms)
        else:
            self.cfg = build_blocks(insns, tuple(jump_table_arms))   # an arm enters at itself
            inject_arm_edges(self.cfg, tuple(jump_table_arms))
        self._block_of: Dict[int, int] = {}          # insn index -> block leader address
        self._first_in_block: Dict[int, int] = {}    # block leader -> index of its first insn
        for b in self.cfg.order:
            body = self.cfg.blocks[b]
            self._first_in_block[b] = self.addr_idx[body[0].addr]
            for ins in body:
                self._block_of[self.addr_idx[ins.addr]] = b
        # reaching definitions, solved on first use (:meth:`defs_before`): a run that only
        # evaluates (propagate / run_from) never needs them
        self._wr: Optional[List[List[str]]] = None    # registers each insn writes
        self._in: Optional[Dict[int, Dict[str, FrozenSet[int]]]] = None
        self._const_memo: Dict[Tuple[int, str], Optional[int]] = {}
        self._ivar_memo: Dict[int, Optional[int]] = {}
        self._reg_targets: Optional[Dict[int, int]] = None   # :meth:`_register_call_targets`
        self._fragments: Dict[int, Optional[Tuple[Insn, ...]]] = {}   # :meth:`fragment`
        self._tails: Dict[int, Optional[int]] = {}                    # :meth:`fragment_tail`
        self._known: Dict[int, Dict[str, int]] = {}                   # :meth:`known_before`
        self._entry_states: Optional[Dict[int, "_Machine"]] = None    # :meth:`known_before`

    # ── reaching definitions ────────────────────────────────────────────────

    def _solve(self) -> None:
        """Forward reaching-definitions fixpoint: sweep the blocks in reverse postorder, joining
        the predecessors' OUT sets, until nothing changes (a few sweeps for a reducible CFG)."""
        cfg = self.cfg
        self._wr = [writes(i) for i in self.insns]
        for k, ins in enumerate(self.insns):
            if ins.mnemonic in CALLS:
                clobbers = self.call_writes(k)
                if clobbers is not None:
                    self._wr[k] = list(clobbers)
        self._in = {}
        if cfg.entry is None:
            return
        gens: Dict[int, Dict[str, FrozenSet[int]]] = {}  # block -> last def of each reg
        for b in cfg.order:
            first = self._first_in_block[b]
            gen: Dict[str, FrozenSet[int]] = {}
            for k in range(first, first + len(cfg.blocks[b])):
                for r in self._wr[k]:
                    gen[r] = frozenset((k,))
            gens[b] = gen
        preds = predecessors(cfg)
        rpo = reverse_postorder(cfg)
        entry_state = {r: frozenset((_ENTRY,)) for r in _REGS}
        out: Dict[int, Dict[str, FrozenSet[int]]] = {}
        changed = True
        while changed:
            changed = False
            for b in rpo:
                # the entry block is also a loop head when a branch comes back to it
                ps = ([entry_state] if b == cfg.entry else []) + \
                    [out[p] for p in preds[b] if p in out]
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
                state.update(gens[b])
                if out.get(b) != state:
                    out[b] = state
                    changed = True

    def defs_before(self, k: int, reg: str) -> FrozenSet[int]:
        """Indices of the definitions of *reg* that reach ``insns[k]`` (``-1`` = function
        entry); empty if the instruction is unreachable."""
        if k < 0:                                   # the function's entry (a root of -1)
            return frozenset((_ENTRY,)) if reg in _REGS else frozenset()
        if self._in is None:
            self._solve()
        b = self._block_of.get(k)
        if b is None or b not in self._in or reg not in _REGS:
            return frozenset()
        state = self._in[b][reg]
        for j in range(self._first_in_block[b], k):
            if reg in self._wr[j]:
                state = frozenset((j,))
        return state

    def from_entry(self, k: int, reg: str) -> bool:
        """Whether *reg* before ``insns[k]`` still holds its value on entry, on every path."""
        return self.defs_before(k, reg) == frozenset((_ENTRY,))

    def only_def(self, k: int, reg: str) -> Optional[int]:
        """Index of the one definition of *reg* reaching ``insns[k]``; None for a live-in,
        several reaching definitions, or an unreachable ``insns[k]``."""
        d = self.defs_before(k, reg)
        if len(d) != 1:
            return None
        (x,) = d
        return x if x >= 0 else None

    # ── constants ───────────────────────────────────────────────────────────

    def const_before(self, k: int, reg: str) -> Optional[int]:
        """Value of *reg* before ``insns[k]`` if every definition reaching it is that constant
        (e.g. a table base set the same way on each path into a loop)."""
        if reg == 'xzr':
            return 0
        key = (k, reg)
        if key in self._const_memo:
            return self._const_memo[key]
        self._const_memo[key] = None                     # break cycles (loops)
        defs = self.defs_before(k, reg)
        vals = ({None} if not defs or _ENTRY in defs
                else {self._const_of_def(d, reg) for d in defs})
        val = vals.pop() if len(vals) == 1 else None
        self._const_memo[key] = val
        return val

    def _const_of_def(self, d: int, reg: str) -> Optional[int]:
        frag = self.fragment(d)
        if frag is not None:                             # *reg* as the fragment leaves it
            if self.fragment_tail(d) is not None and reg in self.tail_writes(d):
                return None                              # set by a thunk's tail call
            m = _Machine({}, fallback=lambda r: self.const_before(d, r))
            for fi in frag:
                self._exec(m, fi)
            v = m.get(reg)
            return None if v is None or _is_symbolic(v) else v
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
            v = self.const_before(d, r) if r else None
            return None if v is None else v & reg_mask(ops[0])
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
        if mn == 'ldrsw':                                # the ivar-offset slot itself
            addr = self.slot_load_address(d)
            if addr is not None:
                try:
                    res = self.ctx.read_s32(addr)
                except READ_ERRORS:
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

    def slot_load_address(self, k: int) -> Optional[int]:
        """Address of the ivar-offset variable the 4-byte load ``insns[k]`` reads (an
        ``ldrsw``, :meth:`load_address`); None for any other instruction."""
        return self.load_address(k) if self.insns[k].mnemonic == 'ldrsw' else None

    def slot_loads(self, ks: Iterable[int]) -> Set[int]:
        """The ivar-offset variables the loads at *ks* read (:meth:`slot_load_address`)."""
        return {a for k in ks if (a := self.slot_load_address(k)) is not None}

    def load_address(self, k: int) -> Optional[int]:
        """Address the single-register load ``insns[k]`` reads: ``[Xb, #o]`` / ``[Xb]``, the
        base taken from its reaching definitions (:meth:`const_before`: the ``adrp`` of a page
        is often hoisted), or a PC-relative literal ``#ADDR``; None for any other instruction,
        an indexed or writeback form, or a base that is not a constant."""
        ins = self.insns[k]
        ops = split_ops(ins.op_str)
        if ins.mnemonic not in LOAD_BYTES or len(ops) != 2 or ops[1].endswith('!'):
            return None
        if ops[1].startswith('#'):
            return _parse_imm(ops[1])
        m = mem_regs(ops[1])
        if not m or m[0] is None or m[1] is not None:
            return None
        base = self.const_before(k, m[0])
        return None if base is None else base + m[2]


    # ── candidate values: the constants V is compared / indexed against ─────

    def candidates(self, root: int, dest: str, domain) -> Candidates:
        """Values of the loaded integer worth evaluating, from the comparisons it takes part
        in.  Registers are tracked as ``V + b`` through ``mov`` / ``add|sub`` of an immediate
        or of a constant register; comparing such a register with *c* gives the point
        ``c - b``, and an ordered gate (``b.hi`` / ``b.hs`` / ...) gives the whole interval it
        guards (``sub w9,w8,#35; cmp w9,#30; b.hi`` -> V in 35..65), wherever the instruction
        that reads the flags is (:meth:`_candidate_step`).  The scan follows the CFG
        from the load and stops each path at its first call (where the name is consumed).
        *domain* is ``hi`` (values ``0 <= v < hi``) or ``(lo, hi)``: a 4-byte value is a signed
        int32, so an enum may start below zero (``add w8, w2, #1; cmp w8, #10`` is -1..8).
        The result also lists the ``(lo, hi)`` of EVERY ordered gate met, whether or not a
        table load then uses it, and whether a table gate was too wide to expand."""
        scan = Candidates({0})
        cands = scan.values
        root_blk = self._block_of.get(root) if root >= 0 else self.cfg.entry
        if root_blk is None:
            return scan
        def run(blk: int, st: RegMap, lo: int):
            for k in range(lo, self.block_range(blk).stop):
                if self.insns[k].mnemonic in CALLS:
                    clobbers = self.call_writes(k)
                    if clobbers is None or self.fragment_tail(k) is not None:
                        return []                      # the path ends at its first call
                    for r in clobbers:
                        st.pop(r, None)
                    continue
                self._candidate_step(scan, st, k)
            return [(succ, st) for succ in self.cfg.succ.get(blk, [])]

        self.forward(run(root_blk, RegMap({dest: 0}), root + 1),
                     lambda blk, st: run(blk, st, self._first_in_block[blk]))
        lo, hi = domain if isinstance(domain, tuple) else (0, domain)
        scan.values = {v for v in cands if lo <= v < hi}
        return scan

    def _candidate_step(self, scan: Candidates, st: Dict[str, int], k: int) -> None:
        """One instruction of the candidate scan.  *st* maps a register to its offset ``b`` in
        ``V + b``; it ALSO carries, per path, the interval of the last ordered gate on each
        offset (keys ``gate_lo:<b>`` / ``gate_hi:<b>``), so a table is expanded by ITS OWN
        gate and not by an unrelated compare of the same value met on another path, and the
        comparison the flags hold (keys ``flags_b`` / ``flags_point``) until the instruction
        that reads them: an ordered ``b.cond`` gates the value; a ``csel`` that keeps it on the
        side the gate admits and zero on the other (an index clamped for a table) gates its
        destination."""
        cands = scan.values
        ins = self.insns[k]
        mn, ops = ins.mnemonic, split_ops(ins.op_str)
        new: Optional[Tuple[str, int]] = None
        cond = mn[2:] if mn.startswith('b.') else (ops[3] if mn == 'csel' and len(ops) == 4 else '')
        if cond in _ORDERED_CONDS and "flags_b" in st:
            b, point = st["flags_b"], st["flags_point"]
            lo, hi = sorted((-b, point))
            if cond in _STRICT_CONDS and hi == point:
                hi -= 1
            if mn == 'csel':
                # the side the gate admits: the first source when the condition holds in range
                kept, other = (ops[1], ops[2]) if cond in _IN_RANGE_CONDS else (ops[2], ops[1])
                if not (st.get(_norm_reg(kept)) == b and _norm_reg(other) in ('xzr', 'wzr')):
                    lo = None
                else:
                    new = (_norm_reg(ops[0]), b)
            if lo is not None:
                st[f"gate_lo:{b}"], st[f"gate_hi:{b}"] = lo, hi   # keyed by the VALUE's offset: a register copy keeps it
                scan.intervals.append((lo, hi))
        if mn in _FLAG_SETTERS:
            st.pop("flags_b", None)
            st.pop("flags_point", None)
        if mn in ('cmp', 'cmn') and len(ops) in (2, 3):
            r = _norm_reg(ops[0])
            if r in st:
                if ops[1].startswith('#'):
                    c = imm_operand(ops, 1)
                else:                                 # a register, shifted / extended
                    raw = operand2(ops, 1, lambda tok: self._const_reg(k, tok))
                    c = None if raw is None else as_signed(raw & reg_mask(ops[0]), ops[0])
                if c is not None and mn == 'cmn':     # `cmn w2, #1` compares with -1
                    c = -c
                if c is not None:
                    point = c - st[r]
                    cands.add(point)
                    st["flags_b"], st["flags_point"] = st[r], point
        elif mn in ('cbz', 'cbnz') and ops:
            r = _norm_reg(ops[0])
            if r in st:
                cands.add(-st[r])
        elif mn in LOAD_BYTES and len(ops) == 2:
            # A table indexed by a gated register: every index the gate lets through is a
            # distinct case, so the whole interval (not just its end point) is a candidate.
            pm = parse_mem(ops[1])
            if pm and pm[1] in st and f"gate_lo:{st[pm[1]]}" in st:
                lo, hi = st[f"gate_lo:{st[pm[1]]}"], st[f"gate_hi:{st[pm[1]]}"]
                if hi - lo <= _MAX_GATE_SPAN:
                    cands.update(range(lo, hi + 1))
                else:
                    scan.gate_capped = True
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
                and self.insns[i].mnemonic in TRAPS
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
        # a negative value as the register holds it: the root load's width (ldrsw x8: 64 bits)
        width = split_ops(self.insns[root].op_str)[0] if root >= 0 and self.insns[root].op_str \
            else 'x0'
        m = _Machine({dest: value & reg_mask(width)},
                     fallback=lambda r: self.const_before(root, r))
        if root < 0:
            m.put('sp', _STACK_TOP)               # from the entry the frame is the function's
        end, k = self._single_path(m, root + 1, stop.__contains__, follow_indirect=True)
        if end not in ('call', 'return', 'tail'):
            return {}                             # at a stop, a trap: no string reaches a call
        if where is not None:
            where.append(k)
        return self._string_args(m.get, direct)

    def _single_path(self, m: "_Machine", k: int, until: Callable[[int], bool],
                     follow_indirect: bool) -> Tuple[str, int]:
        """Run *m* from ``insns[k]`` along the one path its values decide, to ``(end, index)``:
        *end* ``'until'`` (``until(index)`` holds), ``'call'``, ``'return'``, ``'tail'`` (a ``b``
        out of the listing, or an authenticated branch: through a signed function pointer),
        ``'indirect'`` (a ``br`` when not *follow_indirect*; else it jumps to its register's
        value), ``'trap'``, or ``'end'`` (past the listing).  An outlined fragment runs in
        place and a call with a contract (:meth:`call_clobbers`) changes what it clobbers;
        neither ends the path.  A thunk runs its prefix, then is a call (``'call'``).  Raises
        _Abort at a loop, a branch it cannot decide, a jump to an address it does not know."""
        seen: Set[int] = set()

        def jump(target: Optional[int]) -> int:
            if target is None or target not in self.addr_idx:
                raise _Abort(f"indirect/unresolvable jump at {self.insns[k].addr:#x}")
            return self.addr_idx[target]

        while k < len(self.insns):
            if k in seen:
                raise _Abort(f"loop at {self.insns[k].addr:#x}")
            if until(k):
                return 'until', k
            seen.add(k)
            ins = self.insns[k]
            mn, ops = ins.mnemonic, split_ops(ins.op_str)
            nxt = k + 1
            if self.fragment(k) is not None:
                self._run_fragment(m, k)
                if self.fragment_tail(k) is not None:
                    return 'call', k              # a thunk's tail call, after its prefix
            elif mn in CALLS and (clobbers := self.call_clobbers(
                    k, self._call_target(m, ins), evaluated=True)) is not None:
                m.call((), clobbers)
            elif mn in CALLS:
                return 'call', k
            elif mn in RETURNS:
                return 'return', k
            elif mn == 'b':
                target = branch_target(ins)
                if target is not None and target not in self.addr_idx:
                    return 'tail', k              # a tail call out of the function
                nxt = jump(target)
            elif mn in AUTHENTICATED_BRANCHES:
                return 'tail', k                  # through a signed function pointer
            elif mn in INDIRECT_BRANCHES:
                if not follow_indirect:
                    return 'indirect', k
                nxt = jump(m.get(ops[0]) if ops else None)
            elif mn in TRAPS:
                return 'trap', k
            elif is_conditional(mn):
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
        return 'end', k

    def known_before(self, k: int) -> Dict[str, int]:
        """The registers known before ``insns[k]`` whatever the listing was entered with: what
        :meth:`propagate` (entered with nothing known) finds every path there agrees on --
        through loops and calls, so a table base the compiler parks in a callee-saved register
        across a call and copies back is still that constant.  One fixpoint per Flow (its
        blocks' entry states, :meth:`_fixpoint`), *k*'s block replayed; memoised per index."""
        if k not in self._known:
            if self._entry_states is None:
                self._entry_states = self._fixpoint({}, NO_OBJECTS)
            self._known[k] = self._replay(self._entry_states, [k], NO_OBJECTS).get(k, {})
        return self._known[k]

    def value_at(self, k0: int, regs: Dict[str, int], kt: int, reg: str) -> Optional[int]:
        """*reg*'s value on reaching ``insns[kt]`` when the code is run from ``insns[k0]`` with
        *regs* known (any other register: what :meth:`known_before` knows at ``insns[k0]``, else
        its reaching-definition constant there), following the branches the run decides.  None
        when the run does not reach *kt* -- a call, a return, a jump out of the listing, a branch
        it cannot decide, a loop -- or the value there is unknown."""
        if k0 < 0:
            return None
        m = _Machine({}, fallback=lambda r: self.const_before(k0, r))
        for r, v in {**self.known_before(k0), **regs}.items():
            m.put(r, v)                         # put: a stack address marks the frame escaped
        try:
            end, _ = self._single_path(m, k0, lambda k: k == kt, follow_indirect=False)
        except _Abort:
            return None
        return m.get(reg) if end == 'until' else None

    def _branch(self, m: "_Machine", ins: Insn) -> Tuple[Optional[bool], Optional[int]]:
        """``(taken, target)`` of a conditional branch under *m*; ``taken`` is None when the
        condition is not known."""
        mn, ops = ins.mnemonic, split_ops(ins.op_str)
        target = branch_target(ins)
        if is_cond_branch(mn):
            return (None if m.flags is None else _eval_cond(mn[2:], m.flags)), target
        if mn in ('cbz', 'cbnz') and len(ops) == 2:
            v = m.get(ops[0])
            if v is not None and _is_symbolic(v) and not _is_stack(v):
                v = None                            # a pointer into an object may be nil
            return (None if v is None else (v == 0) == (mn == 'cbz')), target
        if mn in ('tbz', 'tbnz') and len(ops) == 3:
            v = m.get(ops[0])
            bit = _parse_imm(ops[1]) or 0
            if _is_stack(v):                        # only the alignment bits are the frame's
                v = v.off if bit < 4 else None
            elif v is not None and _is_symbolic(v):
                v = None                            # (a pointer's bits are its encoding's)
            return (None if v is None else (((v >> bit) & 1) == 0) == (mn == 'tbz')), target
        return None, None

    def _exec(self, m: "_Machine", ins: Insn) -> None:
        """One non-branching instruction's effect on *m* (registers, flags, stack slots).
        Anything not modelled makes the registers it writes unknown."""
        mn, ops = ins.mnemonic, split_ops(ins.op_str)
        get, put = m.number, m.put                 # a frame address only where it keeps its meaning
        if mn in ('cmp', 'cmn') and len(ops) in (2, 3):   # 3: ``cmp w2, #4, lsl #12`` / ``w9, lsl #2``
            a, b = _flag_operands(m.get(ops[0]), operand2(ops, 1, m.get if len(ops) == 2 else get),
                                  mn == 'cmp')
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
        elif mn in POINTER_AUTH:
            pass            # signs / authenticates / strips a pointer in place: same address
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
            a, b = m.get(ops[1]), operand2(ops, 2, m.get if len(ops) == 3 else get)
            put(ops[0], _add_sub(mn == 'add', a, b))
        elif mn == 'csel' and len(ops) == 4:
            if m.flags is None:
                put(ops[0], None)
            else:
                c = _eval_cond(ops[3], m.flags)
                put(ops[0], None if c is None else m.get(ops[1] if c else ops[2]))
        elif mn in SHIFT_MNEMONICS and len(ops) == 3:
            a = get(ops[1])
            n = _parse_imm(ops[2]) if ops[2].startswith('#') else get(ops[2])
            put(ops[0], None if a is None or n is None else shift_value(mn, a, n, ops[0]))
        elif mn in ('and', 'orr', 'eor', 'ands') and len(ops) in (3, 4):
            a = m.get(ops[1])
            b = _parse_imm(ops[2]) if ops[2].startswith('#') else operand2(ops, 2, get)
            if _is_stack(a):                       # aligning a frame address (and sp, x9, #-16)
                b = None if b is None else b & _MASK64
                r = (frame(a.off & _signed64(b))
                     if mn == 'and' and b is not None and b | 0xF == _MASK64 else None)
                put(ops[0], r)
                if mn == 'ands':
                    m.flags = None
                return
            if _is_symbolic(a):                    # a pointer's bits are not a number's
                a = None
            r = None if a is None or b is None else \
                {'and': a & b, 'ands': a & b, 'orr': a | b, 'eor': a ^ b}[mn]
            put(ops[0], r)
            if mn == 'ands':
                m.flags = None if r is None else _nzcv_logic(r, reg_bits(ops[0]))
        elif mn == 'ubfx' and len(ops) == 4:
            a, lsb, width = get(ops[1]), _parse_imm(ops[2]), _parse_imm(ops[3])
            put(ops[0], None if a is None or lsb is None or not width
                else (a >> lsb) & ((1 << width) - 1))
        elif mn in _SIGN_EXTENDS and len(ops) == 2:     # sxtw xd, wn: the low bits, signed
            a, bits = get(ops[1]), _SIGN_EXTENDS[mn]
            put(ops[0], None if a is None else
                (a & ((1 << bits) - 1)) - ((a >> (bits - 1) & 1) << bits))
        elif mn == 'bfi' and len(ops) == 4:     # bfi d, n, #lsb, #width: n's low bits into d at lsb
            d, a, lsb, width = get(ops[0]), get(ops[1]), _parse_imm(ops[2]), _parse_imm(ops[3])
            mask = (1 << width) - 1 if width else 0
            put(ops[0], None if d is None or a is None or lsb is None or not width
                else (d & ~(mask << lsb)) | ((a & mask) << lsb))
        elif mn == 'tst' and len(ops) in (2, 3):     # tst a, b [, shift]: flags of a & b
            a = get(ops[0])
            b = _parse_imm(ops[1]) if ops[1].startswith('#') else operand2(ops, 1, get)
            m.flags = None if a is None or b is None else _nzcv_logic(a & b, reg_bits(ops[0]))
        elif mn in ('subs', 'adds') and len(ops) in (3, 4):
            a, b = m.get(ops[1]), operand2(ops, 2, m.get if len(ops) == 3 else get)
            fa, fb = _flag_operands(a, b, mn == 'subs')
            m.flags = None if fa is None or fb is None else \
                (_nzcv_sub if mn == 'subs' else _nzcv_add)(fa, fb, reg_bits(ops[0]))
            put(ops[0], _add_sub(mn == 'adds', a, b))
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
            in_frame = _frame_based(m, ops[1])
            addr = self._access(m, ops[1], ops[2] if len(ops) == 3 else None)
            m.store(addr, STORE_BYTES[mn] or reg_bytes(ops[0]), v, in_frame)
        elif mn == 'stp' and len(ops) in (3, 4):
            v0, v1 = m.copy_of(ops[0]), m.copy_of(ops[1])
            in_frame = _frame_based(m, ops[2])
            addr = self._access(m, ops[2], ops[3] if len(ops) == 4 else None)
            size = reg_bytes(ops[0])
            m.store(addr, size, v0, in_frame)
            m.store(None if addr is None else addr + size, size, v1, in_frame)
        else:
            if writes_memory(mn):                   # an unmodelled store (stnp, st1, stlr, an
                mem = next((o for o in ops if o.startswith('[')), None)   # LSE atomic ...)
                m.store(None, 16, None, mem is not None and _frame_based(m, mem))
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
        base, index, disp = pm.base, pm.index, pm.disp
        r = _norm_reg(base) if base else None
        obj = m.regs.get(r) if r else None
        if obj is None or not ((m.opaque is not None and m.opaque(obj)) or
                               (m.pointer is not None and m.pointer(obj))):
            return None
        off = disp
        if index:
            iv = m.number(index)                    # (a frame address or a pointer: no offset)
            if iv is None:
                return None
            off += index_offset(iv, pm)
        return m.field_value(obj, off)

    def _access(self, m: "_Machine", mem: str, post: Optional[str]) -> Optional[int]:
        """Address a memory operand accesses under *m* (None if unknown), applying a pre-index
        (``[Rn, #imm]!``) or post-index (``[Rn], #imm``) base update to *m*."""
        pm = parse_mem(mem)
        if pm is None:
            return None
        base, index, disp = pm.base, pm.index, pm.disp
        b = m.get(base) if base else None
        if isinstance(b, Sym) and b.kind == "token":
            b = None                            # (an object's own address is not known)
        addr = b
        if addr is not None and index:
            iv = m.number(index)
            addr = None if iv is None else addr + index_offset(iv, pm)
        if mem.endswith('!'):
            addr = None if addr is None else addr + disp
            m.put(base, addr)
        elif post is not None and post.startswith('#'):
            imm = _parse_imm(post)
            m.put(base, None if b is None or imm is None else b + imm)
        elif addr is not None:
            addr += disp
        if addr is None or _is_stack(addr):
            return addr
        return None if _is_symbolic(addr) else addr & _MASK64

    def _read(self, m: "_Machine", addr: Optional[int], size: int, signed: bool) -> Optional[int]:
        """The *size*-byte value at *addr*: a stack slot stored with that width, or the image's
        -- unless the file does not give its run-time value (:meth:`BinaryContext.is_variable`:
        a variable the program writes, a slot bound to an import)."""
        if addr is None:
            return None
        if _is_stack(addr):
            slot = m.slots.get(addr)
            if slot is None or slot[0] != size:
                return None
            raw = slot[1]
        else:
            if self.ctx is None:
                return None
            if self.ctx.is_variable(addr):
                return m.bound(addr) if m.bound is not None and size == 8 else None
            try:
                if size == 8:
                    return self.ctx.read_ptr(addr)
                raw = int.from_bytes(self.ctx.read_bytes(addr, size), 'little')
            except READ_ERRORS:
                return None
        if signed and size < 8 and raw & (1 << (size * 8 - 1)):
            raw -= 1 << (size * 8)
        return raw

    # ── constant propagation over the whole function ────────────────────────

    def block_range(self, blk: int) -> range:
        """Indices of the instructions of the block led by *blk*."""
        first = self._first_in_block[blk]
        return range(first, first + len(self.cfg.blocks[blk]))

    def forward(self, seeds: Iterable[Tuple[int, Any]], run_block: Callable[[int, Any], Iterable],
                order: Optional[List[int]] = None, max_visits: Optional[int] = None
                ) -> Optional[Dict[int, Any]]:
        """The forward fixpoint over the CFG, in any state domain (a state has ``copy``,
        ``join`` and ``same``): the state at a block is the join of every state pushed to it,
        from *seeds* ``(block, state)`` and from ``run_block(block, state)``, which runs the
        block on its own copy of the state and returns the ``(successor, state)`` edges it
        leaves by.  ``{block: state}`` of every block reached, or None when it has not settled
        after *max_visits* block runs; *order* receives the blocks by first visit."""
        wl = _Worklist(order)
        for blk, st in seeds:
            wl.push(blk, st)
        visits = 0
        while wl:
            visits += 1
            if max_visits is not None and visits > max_visits:
                return None
            blk = wl.pop()
            for succ, st in run_block(blk, wl.states[blk].copy()):
                wl.push(succ, st)
        return wl.states

    def propagate(self, entry: Dict[str, int], at: Iterable[int], objects: Objects = NO_OBJECTS,
                  slots_out: Optional[Dict[int, Dict[int, Tuple[int, int]]]] = None,
                  fragments_out: Optional[Dict[int, List[Dict[str, int]]]] = None
                  ) -> Dict[int, Dict[str, int]]:
        """``{k: {register: value}}``: the registers known before each ``insns[k]`` in *at*
        when the function is entered with *entry* (say a flag argument's value) and sp at
        the frame's top; an index missing from the result is unreachable under *entry*.

        Unlike :meth:`evaluate` this runs through calls (which clobber the caller-saved
        registers) and over the whole CFG: a forward fixpoint in which a register, stack slot
        or the flags is known at a block iff every path into it that can execute agrees.  A
        branch whose condition is known follows only the side taken, so code that depends on
        *entry* is resolved the same way whether it was compiled to a ``csel`` or a branch.
        *objects*: see :class:`Objects`; *fragments_out*, when given, receives for each outlined
        fragment a ``bl`` runs (:meth:`fragment`) the registers before each of its instructions
        (and, for a thunk, before its tail call);
        *slots_out*, when given, receives the stack slots known
        before each ``insns[k]`` in *at*."""
        return self._replay(self._fixpoint(entry, objects), at, objects, slots_out, fragments_out)

    def _fixpoint(self, entry: Dict[str, int], objects: Objects) -> Dict[int, "_Machine"]:
        """``{block: state on entry to it}`` of every block :meth:`propagate` reaches from
        *entry* (sp at the frame's top)."""
        if self.cfg.entry is None:
            return {}
        start = objects.machine(entry)
        start.put('sp', _STACK_TOP)

        def run_block(blk: int, st: _Machine):
            for k in self.block_range(blk):
                self._propagate_step(st, k, objects.call_result)
            return [(succ, st) for succ in self._live_successors(blk, st)]
        return self.forward([(self.cfg.entry, start)], run_block)

    def _replay(self, states: Dict[int, "_Machine"], at: Iterable[int], objects: Objects,
                slots_out: Optional[Dict[int, Dict[int, Tuple[int, int]]]] = None,
                fragments_out: Optional[Dict[int, List[Dict[str, int]]]] = None
                ) -> Dict[int, Dict[str, int]]:
        """:meth:`propagate`'s answer from the blocks' entry *states* (:meth:`_fixpoint`): each
        block holding an index of *at* -- with *fragments_out*, every block -- run again from
        its entry state, recording the registers before each index of *at*."""
        want = set(at)
        blocks = {self._block_of.get(k) for k in want}
        out: Dict[int, Dict[str, int]] = {}
        for blk, st0 in states.items():
            if blk not in blocks and fragments_out is None:
                continue
            st = st0.copy()
            for k in self.block_range(blk):
                if k in want:
                    out[k] = dict(st.regs)
                    if slots_out is not None:
                        slots_out[k] = dict(st.slots)
                trace = [] if fragments_out is not None and self.fragment(k) is not None else None
                self._propagate_step(st, k, objects.call_result, trace)
                if trace is not None:
                    fragments_out[k] = trace
        return out

    @staticmethod
    def _call_target(m: "_Machine", ins: Insn) -> Optional[int]:
        """The address the call ``ins`` reaches under *m*: a ``bl`` immediate, or its register
        (not a frame address, which is no code)."""
        if ins.mnemonic == 'bl':
            return _parse_imm(ins.op_str)
        ops = split_ops(ins.op_str)
        v = m.get(ops[0]) if ops else None
        return None if _is_symbolic(v) else v

    def call_clobbers(self, k: int, target: Optional[int] = None, evaluated: bool = False
                      ) -> Optional[Tuple[str, ...]]:
        """The registers the call ``insns[k]`` changes when its callee changes fewer than a call
        may (:func:`proto.callees.call_clobbers`: the stack probe), else None.  A call through a
        register reaches *target* when *evaluated* (an evaluator's value there), else the value
        :meth:`propagate` gives that register (a pointer loaded from a GOT slot)."""
        if self.ctx is None:
            return None
        ins = self.insns[k]
        if ins.mnemonic == 'bl':
            target = _parse_imm(ins.op_str)
        elif not evaluated:
            target = self._register_call_targets().get(k)
        return callee_clobbers(self.ctx, target)

    def fragment(self, k: int) -> Optional[Tuple[Insn, ...]]:
        """The instructions the ``bl`` ``insns[k]`` runs as part of this function (an outlined
        fragment, or a thunk's prefix: :func:`proto.callees.outlined_code`), else None."""
        if k not in self._fragments:
            ins = self.insns[k]
            self._fragments[k] = (outlined_fragment(self.ctx, _parse_imm(ins.op_str))
                                  if ins.mnemonic == 'bl' and self.ctx is not None else None)
        return self._fragments[k]

    def fragment_tail(self, k: int) -> Optional[int]:
        """The target of the tail call the thunk the ``bl`` ``insns[k]`` runs ends in: after
        its prefix (:meth:`fragment`) the ``bl`` is a call to it.  None for a fragment or a
        call."""
        if k not in self._tails:
            self._tails[k] = (outlined_tail(self.ctx, _parse_imm(self.insns[k].op_str))
                              if self.fragment(k) is not None else None)
        return self._tails[k]

    def tail_clobbers(self, k: int) -> Optional[Tuple[str, ...]]:
        """The registers the tail call of the thunk at ``insns[k]`` (:meth:`fragment_tail`)
        changes when its callee changes fewer than a call may
        (:func:`proto.callees.call_clobbers`), else None."""
        return callee_clobbers(self.ctx, self.fragment_tail(k))

    def tail_writes(self, k: int) -> Tuple[str, ...]:
        """The registers the tail call of the thunk at ``insns[k]`` changes:
        :meth:`tail_clobbers`, else every caller-saved one."""
        clobbers = self.tail_clobbers(k)
        return clobbers if clobbers is not None else CALLER_SAVED

    def call_writes(self, k: int) -> Optional[Tuple[str, ...]]:
        """The registers the call ``insns[k]`` writes when not a call's caller-saved set: an
        outlined fragment's own (and the link register; a thunk's tail call adds
        :meth:`tail_writes`), a contract's (:meth:`call_clobbers`); else None (every
        caller-saved register)."""
        frag = self.fragment(k)
        if frag is not None:
            w = {r for fi in frag for r in writes(fi)} | {'x30'}
            if self.fragment_tail(k) is not None:
                w.update(self.tail_writes(k))
            return tuple(sorted(w))
        return self.call_clobbers(k)

    def _run_fragment(self, m: "_Machine", k: int,
                      trace: Optional[List[Dict[str, int]]] = None) -> None:
        """Run the outlined fragment (or thunk prefix) the ``bl`` ``insns[k]`` calls in *m*, its
        stores included; *trace* receives the registers before each of its instructions, and
        before a thunk's tail call."""
        m.put('x30', None)
        for fi in self.fragment(k):
            if trace is not None:
                trace.append(dict(m.regs))
            self._exec(m, fi)
        if trace is not None and self.fragment_tail(k) is not None:
            trace.append(dict(m.regs))

    def _register_call_targets(self) -> Dict[int, int]:
        """``{index: target}`` of the calls through a register whose register the forward
        evaluation knows (:meth:`known_before`; it reads no reaching definitions)."""
        if self._reg_targets is None:
            ks = [k for k, i in enumerate(self.insns) if i.mnemonic in CALLS and i.mnemonic != 'bl']
            self._reg_targets = {}
            for k in ks:
                ops = split_ops(self.insns[k].op_str)
                v = self.known_before(k).get(_norm_reg(ops[0])) if ops else None
                if v is not None and not _is_symbolic(v):
                    self._reg_targets[k] = v
        return self._reg_targets

    def _call_reads(self, target: Optional[int]) -> Optional[Tuple[str, ...]]:
        """The registers a call to *target* reads (:func:`proto.callees.call_reads`: e.g.
        ``objc_retain_x19`` reads x19 only); None (x0-x8) without an image to name it by."""
        if target is None or self.ctx is None:
            return None
        return call_reads(self.ctx, target)

    def _propagate_step(self, m: "_Machine", k: int, call_result=None,
                        trace: Optional[List[Dict[str, int]]] = None,
                        on_call: Optional[Callable[[Optional[int]], None]] = None) -> None:
        """Run ``insns[k]`` in *m*: an outlined fragment's instructions; a thunk's prefix, then
        its tail call; a call with a contract (:meth:`call_clobbers`); any other call as one
        that reads what its target reads (:meth:`_call_reads`), clobbers the caller-saved
        registers and returns *call_result*'s x0; a branch changes nothing.  *on_call(target)*,
        when given, is told of each of those other calls before it runs.  A thunk's ``bl`` is
        the call site, with the registers at it (a consumer that follows the call runs the
        prefix itself), and its result is that call's: *call_result* is told the ``bl``'s
        target and x0 (a named function of this shape, a metadata accessor say, is known by
        its own name, not its tail callee's)."""
        ins = self.insns[k]
        mn = ins.mnemonic
        if self.fragment(k) is not None:
            tail = self.fragment_tail(k)
            if tail is None:
                self._run_fragment(m, k, trace)
                return
            site = (self._call_target(m, ins), m.copy_of('x0'))
            if on_call is not None:
                on_call(site[0])
            self._run_fragment(m, k, trace)
            self._call(m, k, tail, self.tail_clobbers(k), call_result, site)
            return
        if mn in CALLS:
            target = self._call_target(m, ins)
            clobbers = self.call_clobbers(k, target, evaluated=True)
            if clobbers is None and on_call is not None:
                on_call(target)
            self._call(m, k, target, clobbers, call_result)
        elif mn == 'b' or mn in INDIRECT_BRANCHES or mn in RETURNS or is_conditional(mn):
            return
        else:
            self._exec(m, ins)

    def _call(self, m: "_Machine", k: int, target: Optional[int],
              clobbers: Optional[Tuple[str, ...]], call_result=None,
              site: Optional[Tuple[Optional[int], Optional[int]]] = None) -> None:
        """The call to *target* at ``insns[k]`` in *m*: with a contract, the *clobbers* only;
        else it reads what *target* reads, clobbers the caller-saved registers and returns
        *call_result*'s x0, told *site* ``(target, x0)`` (default: *target* and x0 now)."""
        if clobbers is not None:
            m.call((), clobbers)
            return
        target_of, x0 = site if site is not None else (target, m.copy_of('x0'))
        m.call(self._call_reads(target))
        v = call_result(self.insns[k].addr, target_of, x0) if call_result is not None else None
        if v is not None:
            m.put('x0', v)

    def _live_successors(self, blk: int, m: "_Machine") -> List[int]:
        """The successors of *blk* that can execute under *m*: one side of a branch whose
        condition is known (or the known target of a ``br``), else all of them."""
        succ = self.cfg.succ.get(blk, [])
        last = self.cfg.blocks[blk][-1]
        if last.mnemonic == 'br':
            v = m.get(split_ops(last.op_str)[0]) if last.op_str else None
            if v is None or _is_symbolic(v):
                return list(succ)
            b = self.cfg.addr_to_block.get(v)      # a known target the CFG lacks: no edge here
            return [b] if b in succ else []        # (run_from reports it in br_targets)
        taken, target = self._branch(m, last)
        if taken is None:
            return list(succ)
        k = self.addr_idx[last.addr]
        dest = target if taken else (self.insns[k + 1].addr if k + 1 < len(self.insns) else None)
        b = self.cfg.addr_to_block.get(dest) if dest is not None else None
        return [b] if b in succ else []

    def run_from(self, k0: int, regs: Dict[str, int], stop: FrozenSet[int] = frozenset(),
                 objects: Objects = NO_OBJECTS,
                 slots: Optional[Dict[int, Tuple[int, int]]] = None,
                 tail_targets: FrozenSet[int] = frozenset(),
                 rejoin: FrozenSet[int] = frozenset()) -> "Region":
        """Run from ``insns[k0]`` with *regs* known (nothing else is) to every block it can
        reach without entering a block in *stop*, through calls, and record each call.

        The same forward fixpoint as :meth:`propagate` -- a value is known at a block iff every
        path into it that can execute agrees, and a branch whose condition is known follows only
        the side taken -- but started mid-function and bounded by *stop* (e.g. the blocks that
        dominate a reader's ``lsr Wf, Wtag, #3``, so one loop iteration is evaluated).  A call
        clobbers the caller-saved registers, flags and the slots a callee may reach (a stack
        address handed to one, or stored where one may find it: :class:`_Machine`).
        The result lists every call (``bl`` / ``blr`` / a ``b`` out of the function) with the
        argument registers x0-x7 known at it (opaque values included, see :class:`_Machine`),
        and the blocks reached in first-visit order.  *objects*: see :class:`Objects`;
        *slots*: stack slots known at ``insns[k0]``.  A ``b`` to an address in *tail_targets*
        (known function entries) is a tail call even when that address lies in the window.
        *rejoin*: a path that has left this set of blocks stops when it enters it again (e.g. the
        blocks an unknown field number reaches: after a field's own handler, everything from
        there on is common to every field)."""
        cfg = self.cfg
        start_blk = self._block_of.get(k0)
        region = Region()
        if start_blk is None:
            return region

        regs_recorded = _ALL_GPRS if objects.pointer is not None else ARG_GPRS

        def record_call(st: _Machine, k: int, target: Optional[int], tail: bool) -> None:
            args = {r: v for r in regs_recorded if (v := st.copy_of(r)) is not None}
            ins = self.insns[k]
            via = st.get(split_ops(ins.op_str)[0]) if objects.pointer is not None and \
                ins.mnemonic not in ('bl', 'b') and ins.op_str else None
            region.calls.append(CallSite(k, ins.addr, target, args, tail, via))

        def step(st: _Machine, k: int, record: bool) -> None:
            ins = self.insns[k]
            if ins.mnemonic == 'b':
                tgt = branch_target(ins)
                if record and tgt is not None and (tgt not in self.addr_idx or tgt in tail_targets):
                    record_call(st, k, tgt, True)
                return
            self._propagate_step(st, k, objects.call_result, on_call=(
                (lambda target: record_call(st, k, target, False)) if record else None))

        def successors(blk: int, st: _Machine) -> List[int]:
            last = cfg.blocks[blk][-1]
            if last.mnemonic == 'b' and branch_target(last) in tail_targets:
                return []
            return self._live_successors(blk, st)

        def run_block(blk: int, st: _Machine, lo: int, record: bool) -> None:
            for k in range(lo, self.block_range(blk).stop):
                step(st, k, record)
            last = cfg.blocks[blk][-1]
            if record and last.mnemonic == 'br':
                v = self._call_target(st, last)
                if v is not None:
                    region.br_targets.add((last.addr, v))

        # The partial first block runs once; its successors seed the fixpoint.
        st0 = objects.machine(regs)
        if 'sp' not in regs:
            st0.put('sp', _STACK_TOP)
        if slots:
            st0.slots = dict(slots)

        def edges(blk: int, st: _Machine):
            return [(succ, st) for succ in successors(blk, st)
                    if succ not in stop and not (succ in rejoin and blk not in rejoin)]

        def run_whole(blk: int, st: _Machine):
            run_block(blk, st, self._first_in_block[blk], False)
            return edges(blk, st)

        first_st = st0.copy()
        run_block(start_blk, st0, k0, False)
        states = self.forward(edges(start_blk, st0), run_whole, order=region.order)
        # Record the calls from the final (fixpoint) state of each block.
        run_block(start_blk, first_st, k0, True)
        for blk in region.order:
            run_block(blk, states[blk].copy(), self._first_in_block[blk], True)
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
        if self.from_entry(k, reg):
            return reg
        d = self.only_def(k, reg)
        if d is None or d in seen:
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
        for reg in ARG_GPRS:
            va = get(reg)
            if type(va) is not int:                 # (a frame address or an object: no string)
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
            return self.ctx.read_cstring(va, max_len=sec.vmaddr + sec.vmsize - va)
        except READ_ERRORS:
            return None
