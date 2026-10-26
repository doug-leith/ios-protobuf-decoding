"""proto/writer_flow.py -- which ivars can reach the wire through ``-[Cls writeTo:]``.

The only way a value reaches the wire is through the ``PBDataWriter`` that ``writeTo:`` is
handed (``x2``).  This module follows every value in ``writeTo:`` by a forward *may*-dataflow
over its CFG and collects what can arrive at a call that receives the writer.  An ivar that
can never get there is not a wire field, whatever its storage looks like.

Each register and stack slot carries the set of origins its value may derive from:

  ``W``          the writer (or a value the analysis must treat as possibly the writer)
  ``S``          ``self`` itself
  ``('I', iv)``  a value read from ivar *iv* (or derived from one: arithmetic, a pointer the
                 ivar holds, the address ``self + offset(iv)``)
  ``('O', iv)``  the byte offset of ivar *iv* (loaded from its offset variable)
  ``T``          an unknown part of ``self`` (a load from ``self`` at an unresolved offset, or
                 the result of a call handed ``self`` that is not summarised)

A call's inputs are what its callee reads.  Calls into the Objective-C runtime and the
ProtocolBuffer runtime are named by their exported / imported ABI symbol
(:func:`proto.callees.callee_name`) and have fixed contracts (:data:`proto.callees.RUNTIME_CONTRACTS`, :data:`_PB_WRITE`):
``objc_retain_x2`` reads x2 and returns it; ``PBDataWriterWriteInt32Field(writer, value,
field)`` serialises x1.  Any other callee reads what :func:`proto.callees.call_reads` says
(the AAPCS64 argument registers, or for a function of the image itself, with or without a
calling convention, the registers it reads before writing them) and returns a value derived
from all of them.

A call that receives the writer serialises its contract's value argument, or -- with no
contract -- everything it reads.  The writer handed to a call with no contract may be kept
by it, so from then on every call counts as a writer call.

The answer is *undecided* (None) when the proof does not go through: ``self`` or an unknown
part of it can reach the writer, the writer is stored outside the frame, control leaves the
function window other than by a call, an indirect jump is unresolved, or the fixpoint does
not settle.  Undecided never drops anything: callers keep their fallback.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

from macho.classlist import ClassList, ObjcClass
from macho.disasm import _parse_imm, _norm_reg
from macho.memory import BinaryContext, _ctx_store, PROGRAM_ERRORS
from proto.arm64_eval import Flow, Objects, _STACK_TOP, _is_stack
from proto.dispatch import (_jump_table_arm_addrs, build_function_index, decoded_flow,
                            function_entries)
from proto.dispatch_eval import _function_insns
from proto.function_body import is_function_entry
from proto.callees import (PB_FIELD_WRITERS, callee_name, sent_selector, stub_selector, call_reads, text_holding,
                           RUNTIME_CONTRACTS as _ARC, NORETURN as _NORETURN)
from proto.arm64_operands import (reads, writes, reg_name, parse_mem, reg_bytes, LOAD_BYTES, STORE_BYTES,
                                  PAIR_LOADS, PAIR_STORES, RETURNS, CALLER_SAVED, CALLS,
                                  AUTHENTICATED_BRANCHES, ARG_GPRS, branch_target, is_conditional,
                                  imm_operand, split_ops)

from proto.models import record_heuristic_hit
from proto.submessage_marks import PLACE_MARK, RECALL_MARK

log = logging.getLogger(__name__)

E: FrozenSet = frozenset()
_W, _S, _T = 'W', 'S', 'T'
_P = 'P'                     # (_P, reg): a self-method summary's argument register on entry


# [cap:COSMETIC — ×8 changes none of the 19 gate targets, 2026-10-26] runaway backstops (a writeTo: settles in a few sweeps of its
# blocks; the largest, 1,745 blocks in iOS 27 GeoServices, in 32,644 visits).  Each reports
# when it binds (record_heuristic_hit).
_MAX_BLOCK_VISITS = 50_000
_MAX_SUMMARY_DEPTH = 3


# ── ABI contracts ─────────────────────────────────────────────────────────────
# The Objective-C runtime's are proto.callees.RUNTIME_CONTRACTS (imported as _ARC) and
# NORETURN: (reads, returns) by exported symbol name, fixed by the runtime ABI.

# PBDataWriter functions (ProtocolBuffer runtime ABI): (reads, serialised value register), the
# field writers' by :data:`proto.callees.PB_FIELD_WRITERS`.  Marks are length bookkeeping: they
# serialise nothing of ours.
_PB_WRITE: Dict[str, Tuple[Tuple[str, ...], Optional[str]]] = {
    "_PBDataWriterWriteBareVarint": (("x0", "x1"), "x1"),
    PLACE_MARK: (("x0", "x1", "x2"), None),
    RECALL_MARK: (("x0", "x1"), None),
}
for _t, _ptype in PB_FIELD_WRITERS.items():
    _PB_WRITE[f"_PBDataWriterWrite{_t}Field"] = ((("x0", "v0", "x1"), "v0")
                                                 if _ptype in ("float", "double")
                                                 else (("x0", "x1", "x2"), "x1"))
for _t in ("Submessage", "Subgroup"):
    _PB_WRITE[f"_PBDataWriterWrite{_t}"] = (("x0", "x1", "x2"), "x1")

# Message sends with a fixed contract (the PB protocol this tool decodes): ``[m writeTo:w]``
# serialises the receiver into the writer it is handed; ``[w writeData:d]`` appends d.
_SEND_SERIALISES = {"writeTo:": "x0", "writeData:": "x2"}

# NSFastEnumeration (Foundation ABI): ``[c countByEnumeratingWithState:&state objects:buf
# count:n]`` sets the 64-byte NSFastEnumerationState at x2 -- ``itemsPtr`` among it -- to point
# at objects of the receiver ``c`` and returns their count.  The loop reads its elements
# through ``itemsPtr``, so they derive from the receiver alone, whatever an earlier loop left
# in the reused state.
_FAST_ENUMERATION = "countByEnumeratingWithState:objects:count:"
_FAST_ENUMERATION_STATE_BYTES = 64

# The Flow run the register values come from: a callee handed a pointer into the frame may
# write from it upward, never below (as this analysis's own frame origins assume).
_FRAME_OBJECTS = Objects(object_escape=True)


def _is_object(o) -> bool:
    """*o* names an object: a call's result or an ivar's value."""
    return isinstance(o, tuple) and o[0] in ('R', 'I')


class _St:
    """May-state at a program point: origin sets per register / stack slot, whether the writer
    has escaped into a call with no contract, the length-delimited marks open at the point
    (``om``: every stack of ``(frame slot, begin-mark address)`` a path into it can have), and
    whether every path sets v0 by an instruction other than a call since its last call (``fv``:
    a floating-point argument is being passed).  The values registers hold -- frame
    addresses, constant addresses, immediates -- are not here: they are the function's
    :meth:`proto.arm64_eval.Flow.propagate` run (:class:`_Run`); nor is what was put into an
    object (:class:`_Result`)."""
    __slots__ = ('r', 'sl', 'esc', 'fl', 'om', 'fv')

    def __init__(self, r=None, sl=None, esc=False, fl=None, om=frozenset({()}), fv=False):
        self.r = dict(r or {})
        self.sl = dict(sl or {})      # 8-byte frame granule (offset from entry sp) -> origins
        self.esc = esc
        self.fl = dict(fl or {})      # a callee was handed the frame from here up: origins
        self.om = om
        self.fv = fv

    def copy(self) -> "_St":
        return _St(self.r, self.sl, self.esc, self.fl, self.om, self.fv)

    def join(self, o: "_St") -> "_St":
        return _St({k: self.r.get(k, E) | o.r.get(k, E) for k in set(self.r) | set(o.r)},
                   {k: self.sl.get(k, E) | o.sl.get(k, E) for k in set(self.sl) | set(o.sl)},
                   self.esc or o.esc,
                   {k: self.fl.get(k, E) | o.fl.get(k, E) for k in set(self.fl) | set(o.fl)},
                   self.om | o.om, self.fv and o.fv)

    def same(self, o: "_St") -> bool:
        return (self.r == o.r and self.sl == o.sl and self.esc == o.esc and self.fl == o.fl
                and self.om == o.om and self.fv == o.fv)

    def frame_read(self, a: int, size: int) -> FrozenSet:
        """Origins of *size* bytes at frame address *a*: every granule they touch, plus what
        any callee handed the frame at or below *a* may have written there."""
        out: Set = set()
        g = a - (a % 8)
        while g < a + size:
            out |= self.sl.get(g, E)
            g += 8
        for lo, v in self.fl.items():
            if lo <= a + size - 1:
                out |= v
        return frozenset(out)

    def frame_write(self, a: int, size: int, v: FrozenSet) -> None:
        g = a - (a % 8)
        while g < a + size:
            whole = g >= a and g + 8 <= a + size
            self.sl[g] = v if whole else (self.sl.get(g, E) | v)
            g += 8

    def frame_from(self, lo: int) -> FrozenSet:
        """Origins of everything in the frame at or above *lo* (what a callee handed a
        pointer to *lo* can read)."""
        out: Set = set()
        for g, v in self.sl.items():
            if g + 8 > lo:
                out |= v
        for flo, v in self.fl.items():
            out |= v
        return frozenset(out)

    def p(self, reg: str) -> FrozenSet:
        return self.r.get(reg, E)

    def kill(self, reg: str, prov: FrozenSet = E) -> None:
        self.r[reg] = prov


@dataclass(frozen=True)
class WriteSite:
    """A call in ``writeTo:`` that may be handed the writer (a field write, a begin / end
    mark, a struct serialiser ``f(&struct, writer)``, ...), as the fixpoint leaves it: the
    callee, the register holding the writer, the immediates x1 / x2 hold on every path into
    the call, where the values in the argument registers and v0 come from
    (:class:`WriterFlow`'s origins), and the length-delimited marks open at it."""
    addr: int
    target: Optional[int]
    name: Optional[str]                 # the callee's ABI symbol, when it has one
    writer_reg: str                     # the first argument register that may hold the writer
    x1: Optional[int]
    x2: Optional[int]
    args: Tuple[Tuple[str, FrozenSet], ...]   # (x0..x7, origins), non-empty ones
    v0_origins: FrozenSet
    slot: Optional[int]                 # x1 as a frame address (a mark's scratch), else None
    open_marks: FrozenSet = frozenset({()})   # stacks of (slot, begin-mark addr) open here
    fp_value: bool = False              # every path sets v0 for this call (an FP argument)

    def origins(self, reg: str) -> FrozenSet:
        return dict(self.args).get(reg, frozenset())

    @property
    def _value_reg(self) -> Optional[str]:
        """Where the serialised value travels: the writer contract's register; for a callee
        without one, the AAPCS64 positions -- ``(writer, value, field)`` in x0 / x1 / w2, or,
        with a float / double value set up in v0, ``(writer, value, field)`` in x0 / v0 / w1."""
        pb = _PB_WRITE.get(self.name) if self.name else None
        if pb is not None:
            return pb[1]
        return "v0" if self.x2 is None and self.fp_value and self.x1 is not None else "x1"

    @property
    def number(self) -> Optional[int]:
        """The field number the call is handed: a PB writer's third argument, if it takes one
        (w1 after a value in v0, else w2; a recall mark and a bare varint take none); for a
        callee without a contract, w1 when the value travels in v0, else w2."""
        pb = _PB_WRITE.get(self.name) if self.name else None
        if pb is not None:
            reads = pb[0]
            return None if len(reads) < 3 else self.x1 if reads[2] == "x1" else self.x2
        return self.x1 if self._value_reg == "v0" else self.x2

    @property
    def is_mark(self) -> bool:
        """A begin / end mark."""
        return self.name in (PLACE_MARK, RECALL_MARK)

    @property
    def value_origins(self) -> FrozenSet:
        """Origins of the data the call serialises: a writer-in-x0 call's contract value
        register (x1 without a contract), else every argument but the writer (``f(&struct,
        writer)``)."""
        if self.writer_reg != "x0":
            return frozenset().union(*(o for r, o in self.args if r != self.writer_reg))
        reg = self._value_reg
        return self.v0_origins if reg == "v0" else self.origins(reg) if reg else frozenset()


class _Result:
    """What a function body serialises, returns and calls, read from its settled states.  What
    may be put into an object (an object being a call's result ``('R', addr)`` or an ivar
    ``('I', name)``) is not part of a state, which it does not change: ``puts`` holds
    ``(where, objects, origins)`` for each call handed them all and each store through one, and
    ``ser_in`` each serialisation's ``(where, origins)``; :meth:`expand` adds to what a
    serialisation reaches what was put, at a place with a path to it, into an object among its
    origins.  ``where`` is the index of the function's instruction being run (``at``)."""
    __slots__ = ('ser', 'ser_in', 'puts', 'at', 'ret', 'complete', 'why', 'sites', 'sends',
                 'indirect_calls')

    def __init__(self):
        self.ser: Set = set()
        self.ser_in: List[Tuple[int, FrozenSet]] = []
        self.puts: List[Tuple[int, FrozenSet, FrozenSet]] = []
        self.at = -1
        self.ret: Set = set()
        self.sites: Dict[int, WriteSite] = {}
        self.sends: Set[str] = set()         # selectors the body's own calls send
        self.indirect_calls = 0              # its ``blr`` calls (target unknown)
        self.complete = True
        self.why: List[str] = []

    def fail(self, why: str) -> None:
        self.complete = False
        if len(self.why) < 8:                # [cap:COSMETIC] reasons kept: they only explain
            self.why.append(why)

    def serialise(self, v) -> None:
        """*v*'s origins reach the writer here."""
        self.ser |= v
        self.ser_in.append((self.at, frozenset(v)))

    def put_into(self, objs, v: FrozenSet) -> None:
        """What *v* derives from may be inside every object among the origins *objs* from here."""
        objs = frozenset(o for o in objs if _is_object(o))
        if objs and v:
            self.puts.append((self.at, objs, v))

    def expand(self, flow: Flow) -> None:
        if not self.puts:
            return
        cfg = flow.cfg
        block = [cfg.addr_to_block[i.addr] for i in flow.insns]
        preds: Dict[int, Set[int]] = {}
        for b, ss in cfg.succ.items():
            for t in ss:
                preds.setdefault(t, set()).add(b)
        before: Dict[int, Set[int]] = {}             # block -> the blocks with a path to it
        for k, v in self.ser_in:
            if not any(_is_object(o) for o in v):
                continue
            b = block[k]
            if b not in before:
                seen, work = set(), list(preds.get(b, ()))
                while work:
                    x = work.pop()
                    if x not in seen:
                        seen.add(x)
                        work.extend(preds.get(x, ()))
                before[b] = seen
            self.ser |= _contents(_held((objs, put) for pk, objs, put in self.puts
                                        if block[pk] in before[b]
                                        or (block[pk] == b and pk < k)), v)


def _held(puts) -> Dict:
    """Object -> the origin sets put into it, from ``(objects, origins)`` pairs."""
    into: Dict = {}
    for objs, put in puts:
        for t in objs:
            into.setdefault(t, set()).add(put)
    return into


def _contents(into: Dict, v: FrozenSet) -> FrozenSet:
    """*v*'s origins and, transitively, those of what was put into an object among them
    (:func:`_held`; the writer excepted: it is never inside an object)."""
    out = set(v)
    work = [t for t in out if t in into]
    seen, done = set(work), set()
    while work:
        for put in into[work.pop()]:
            if put in done:
                continue
            done.add(put)
            for o in put:
                if o == _W or o in out:
                    continue
                out.add(o)
                if o in into and o not in seen:
                    seen.add(o)
                    work.append(o)
    return frozenset(out)


@dataclass(frozen=True)
class _Run:
    """One function body being analysed: its :class:`proto.arm64_eval.Flow`, the registers
    before each instruction of its ``propagate`` run (``values``: an index missing is not
    reached) and before each instruction of the outlined fragments it calls, and a thunk's tail
    call (``fragments``),
    its jump-table arms, the summary depth, the function whose summary it is (``top``) and
    its address window ``[lo, hi)``."""
    flow: Flow
    values: Dict[int, Dict[str, int]]
    fragments: Dict[int, List[Dict[str, int]]]
    arms: Dict
    depth: int
    top: int
    lo: int
    hi: int


class WriterFlow:
    """One analysis context per image: the function index, and each class's analysis
    (:class:`_ClassFlow`), memoised."""

    def __init__(self, ctx: BinaryContext, cl: ClassList):
        self.ctx, self.cl = ctx, cl
        build_function_index(ctx, cl)
        self.entries = function_entries(ctx)
        self._analysed: Dict[int, tuple] = {}

    # ── public entry ─────────────────────────────────────────────────────────
    def reachable_ivars(self, cls: ObjcClass) -> Tuple[Optional[FrozenSet[str]], List[str]]:
        """``(ivars whose values can reach the writer, reasons)``; the set is None when
        undecided (the reasons say why)."""
        reach, why = self.analyse(cls)[:2]
        return reach, why

    def write_sites(self, cls: ObjcClass) -> Optional[List[WriteSite]]:
        """The calls of *cls*'s own ``writeTo:`` that may be handed the writer, in address
        order; None when the body is not decoded or the fixpoint does not go through (control
        leaves the function window, an indirect jump is unresolved, ...)."""
        return self.analyse(cls)[2]

    def sent_selectors(self, cls: ObjcClass) -> Optional[FrozenSet[str]]:
        """Every selector *cls*'s own ``writeTo:`` sends: through a selector stub, or a plain
        ``objc_msgSend`` with the selector in x1.  None when that cannot be told: the body
        is not decoded, the fixpoint does not go through, or it makes an indirect call."""
        return self.analyse(cls)[3]

    def analyse(self, cls: ObjcClass):
        """``(reachable ivars, reasons, write sites, sent selectors)`` of *cls*'s
        ``writeTo:`` (see :meth:`reachable_ivars` / :meth:`write_sites` /
        :meth:`sent_selectors`), memoised per class."""
        hit = self._analysed.get(cls.vmaddr)
        if hit is None:
            hit = self._analysed[cls.vmaddr] = self._analyse(cls)
        return hit

    def _analyse(self, cls: ObjcClass):
        m = cls.get_method("writeTo:")
        if m is None or not m.imp:
            return None, ["no writeTo:"], None, None
        res = _ClassFlow(self, cls)._run(m.imp, {'x0': frozenset({_S}), 'x2': frozenset({_W})},
                                         0, m.imp)
        if res is None:
            return None, ["writeTo: body not decoded"], None, None
        if not res.complete:
            return None, res.why, None, None
        sites = [res.sites[a] for a in sorted(res.sites)]
        sends = None if res.indirect_calls else frozenset(res.sends)
        bad = sorted(str(x) for x in res.ser if not isinstance(x, tuple) or x[0] != 'I')
        if any(x in (_S, _T) for x in res.ser):
            return None, [f"self reaches the writer ({', '.join(bad)})"], sites, sends
        return (frozenset(x[1] for x in res.ser if isinstance(x, tuple) and x[0] == 'I'), [],
                sites, sends)


class _ClassFlow:
    """One class's ``writeTo:`` analysis: its methods and ivars (through its ancestors) and the
    summaries of the methods it calls, over the image's :class:`WriterFlow`."""

    def __init__(self, wf: WriterFlow, cls: Optional[ObjcClass] = None):
        self.ctx, self.cl, self.entries = wf.ctx, wf.cl, wf.entries
        self.cls = cls
        chain = self._chain(cls) if cls is not None else []
        self.own_imps: Dict[int, str] = {mm.imp: mm.name for c in chain for mm in c.methods
                                         if mm.imp and mm.name}
        self.slot_to_ivar: Dict[int, str] = {iv.offset_slot: iv.name for c in chain
                                             for iv in c.ivars if iv.offset_slot}
        self.off_to_ivar: Dict[int, str] = {iv.offset: iv.name for iv in cls.ivars
                                            if iv.offset} if cls is not None else {}
        self._summary_memo: Dict[int, FrozenSet] = {}
        self._summary_cuts = 0               # summaries cut at _MAX_SUMMARY_DEPTH so far

    def _chain(self, cls: ObjcClass) -> List[ObjcClass]:
        return list(self.cl.ancestors(cls))

    # ── function body ────────────────────────────────────────────────────────
    def _insns(self, va: int):
        return _function_insns(self.ctx, va, entries=self.entries)

    def _run(self, imp: int, entry: Dict[str, FrozenSet], depth: int, top: int
             ) -> Optional[_Result]:
        insns = self._insns(imp)
        if not insns:
            return None
        arms = _jump_table_arm_addrs(self.ctx, insns, per_br=True)
        flow = decoded_flow(self.ctx, insns)            # its CFG is built with those arms
        fragments: Dict[int, List[Dict[str, int]]] = {}
        values = flow.propagate({}, range(len(flow.insns)), _FRAME_OBJECTS,
                                fragments_out=fragments)
        return self._fixpoint(_Run(flow, values, fragments, arms, depth, top, insns[0].addr,
                                   insns[-1].addr + 4), entry)

    def _fixpoint(self, run: _Run, entry: Dict[str, FrozenSet]) -> _Result:
        """The origins at every block (:meth:`proto.arm64_eval.Flow.forward`), then what
        the body serialises, returns and calls, read from those states."""
        flow = run.flow
        cfg = flow.cfg

        def run_block(b: int, st: _St):
            if self._block(st, b, _Result(), run):
                return []
            zero_edge = self._zero_edge(cfg.blocks[b][-1])
            edges = []
            for s in cfg.succ.get(b, []):
                if flow.block_range(s)[0] not in run.values:
                    continue                         # no path into it can execute
                out = st
                if zero_edge is not None and cfg.blocks[s][0].addr == zero_edge[1]:
                    out = st.copy()                  # on this edge the register is 0
                    out.kill(zero_edge[0])
                edges.append((s, out))
            return edges

        res = _Result()
        states = flow.forward([(cfg.entry, _St(entry))], run_block,
                              max_visits=_MAX_BLOCK_VISITS)
        if states is None:
            res.fail("fixpoint did not settle")
            record_heuristic_hit(self.ctx, "_MAX_BLOCK_VISITS", f"writer flow of {run.lo:#x}")
            return res
        for b, st in states.items():
            self._block(st.copy(), b, res, run)
        res.expand(flow)
        return res

    def _block(self, st: _St, b: int, res: _Result, run: _Run) -> bool:
        """Run block *b*; True when the path ends (return, tail call, no-return call)."""
        flow = run.flow
        for k in flow.block_range(b):
            res.at = k
            ins = flow.insns[k]
            vals = run.values.get(k, {})
            mn = ins.mnemonic
            ops = split_ops(ins.op_str)
            if mn in RETURNS:
                res.ret |= st.p('x0') | st.p('v0')
                return True
            tgt = branch_target(ins) if mn in ('b', 'bl') else None
            frag = flow.fragment(k)
            if frag is not None:
                frag_vals = run.fragments.get(k, ())
                self._run_in_place(st, frag, frag_vals, tgt, res, run.depth, ins.addr, vals)
                if flow.fragment_calls(k) and self._tail_call(
                        st, k, res, run, frag_vals[-1] if len(frag_vals) > len(frag) else {}):
                    return True                      # no-return callee
                continue
            if mn in CALLS:
                callee = (tgt if mn == 'bl'
                          else self._const(vals, _norm_reg(ops[0]) if ops else None))
                clobbers = flow.call_clobbers(k, callee, evaluated=True)
                if clobbers is not None:             # changes only these (the stack probe)
                    for r in clobbers:
                        st.r.pop(r, None)
                    continue
            lo, hi = run.lo, run.hi
            out_of_window = mn == 'b' and tgt is not None and not (lo <= tgt < hi)
            if mn in CALLS or out_of_window or mn in AUTHENTICATED_BRANCHES:
                if out_of_window and not self._is_function(tgt):
                    res.fail(f"branch out of the function window at {ins.addr:#x}")
                    return True
                if self._call(st, callee if mn in CALLS else tgt, res, run.depth, run.top,
                              ins.addr, vals):      # (a blr: the target its register holds)
                    return True                      # no-return callee
                if mn not in CALLS:                  # a tail call
                    res.ret |= st.p('x0') | st.p('v0')
                    return True
                continue
            if mn == 'br':
                if not run.arms.get(ins.addr):
                    res.fail(f"unresolved indirect jump at {ins.addr:#x}")
                return False
            if mn == 'b' or is_conditional(mn):
                t = branch_target(ins)
                if t is not None and not (lo <= t < hi):
                    res.fail(f"branch out of the function window at {ins.addr:#x}")
                    return True
                if mn == 'b':
                    return False
                continue
            self._exec(st, ins, mn, ops, vals, res)
        return False

    @staticmethod
    def _zero_edge(ins) -> Optional[Tuple[str, int]]:
        """``(register, successor address)`` of the edge on which a ``cbz`` / ``cbnz``
        register is 0, else None: the value there is the constant 0 and carries nothing."""
        if ins.mnemonic not in ('cbz', 'cbnz'):
            return None
        ops = split_ops(ins.op_str)
        r = _norm_reg(ops[0]) if ops else None
        t = branch_target(ins)
        if r is None or t is None:
            return None
        return (r, t) if ins.mnemonic == 'cbz' else (r, ins.addr + 4)

    def _is_function(self, va: int) -> bool:
        return (is_function_entry(self.ctx, va, self.entries) or callee_name(self.ctx, va) is not None
                or stub_selector(self.ctx, va) is not None)

    # ── calls ────────────────────────────────────────────────────────────────
    def _run_in_place(self, st: _St, frag, frag_vals, tgt: int, res: _Result, depth: int,
                      addr: int, vals: Dict[str, int]) -> None:
        """The ``bl`` at *addr* to code that runs as part of this function
        (:meth:`proto.arm64_eval.Flow.fragment`): an outlined fragment, a thunk's prefix (its
        tail call: :meth:`_tail_call`), or a leaf function its shape cannot be told from.  Its
        effect on the state is its instructions' (run
        with *frag_vals*, the registers before each); as a call it is a write site when handed
        the writer, and may serialise what it reads (:func:`proto.callees.call_reads`)."""
        self._site(st, tgt, None, res, depth, addr, vals)
        argp = self._read_origins(st, call_reads(self.ctx, tgt), vals)[0]
        if _W in argp or st.esc:
            res.serialise(frozenset(argp) - {_W})
        for fi, fv in zip(frag, frag_vals):
            self._exec(st, fi, fi.mnemonic, split_ops(fi.op_str), fv, res)
        st.kill('x30')

    def _tail_call(self, st: _St, k: int, res: _Result, run: _Run,
                   vals: Dict[str, int]) -> bool:
        """The tail call the thunk the ``bl`` ``insns[k]`` runs makes after its prefix
        (:meth:`proto.arm64_eval.Flow.thunk_target`), the registers there *vals*: a call
        whose site is the ``bl``'s (:meth:`_run_in_place` records it); True when it does not
        return."""
        clobbers = run.flow.tail_clobbers(k)
        if clobbers is not None:                     # changes only these (the stack probe)
            for r in clobbers:
                st.r.pop(r, None)
            return False
        return self._call(st, run.flow.thunk_target(k, vals), res, run.depth, run.top,
                          run.flow.insns[k].addr, vals, site=False)

    def _read_origins(self, st: _St, reads, vals: Dict[str, int]):
        """``(origins, frame addresses)`` of what a callee reading the registers *reads* can
        reach: their origins, and what lies in the frame above any frame address among them."""
        argp: Set = set()
        frames = {r: f for r in reads if (f := self._frame(vals, r)) is not None}
        for r in reads:
            argp |= st.p(r)
            if r in frames:                          # a frame address: callee reads upward
                argp |= st.frame_from(frames[r])
        return argp, frames

    def _site(self, st: _St, tgt: Optional[int], name: Optional[str], res: _Result,
              depth: int, addr: int, vals: Dict[str, int]) -> None:
        """Record the call at *addr* as a :class:`WriteSite` when it is handed the writer, and
        the length-delimited marks it opens or closes."""
        wreg = next((r for r in ARG_GPRS if _W in st.p(r)), None) if depth == 0 else None
        if wreg is not None:
            slot = self._frame(vals, 'x1')
            res.sites[addr] = WriteSite(
                addr, tgt, name, wreg, self._int32(vals, 'x1'), self._int32(vals, 'x2'),
                tuple((r, st.p(r)) for r in ARG_GPRS if st.p(r)), st.p('v0'), slot, st.om,
                st.fv)
        if wreg == 'x0' and name in (PLACE_MARK, RECALL_MARK):
            # A length-delimited mark, handed the writer and a frame scratch: the begin mark
            # opens one, the end mark closes the one open on that scratch.
            slot = self._frame(vals, 'x1')
            if slot is not None:
                if name == PLACE_MARK:
                    st.om = frozenset(stk + ((slot, addr),) for stk in st.om)
                else:
                    st.om = frozenset(stk[:-1] if stk and stk[-1][0] == slot else stk
                                      for stk in st.om)

    def _call(self, st: _St, tgt: Optional[int], res: _Result, depth: int, top: int,
              addr: int, vals: Dict[str, int], site: bool = True) -> bool:
        """The call at *addr* to *tgt* (None: unknown), the registers before it *vals*;
        True when it does not return.  *site*: record it as a write site (:meth:`_site`)."""
        name = callee_name(self.ctx, tgt) if tgt is not None else None
        sel = sent_selector(self.ctx, tgt, self._const(vals, 'x1'))
        if depth == 0:
            if tgt is None:
                res.indirect_calls += 1
            elif sel is not None:
                res.sends.add(sel)
        if site:
            self._site(st, tgt, name, res, depth, addr, vals)
        if name in _NORETURN:
            return True
        state = self._frame(vals, 'x2')
        if sel == _FAST_ENUMERATION and state is not None and _W not in st.p('x0'):
            recv = st.p('x0')
            for r in CALLER_SAVED:
                st.r.pop(r, None)
            st.frame_write(state, _FAST_ENUMERATION_STATE_BYTES, recv)
            st.r['x0'] = recv
            st.r['v0'] = E
            st.fv = False
            return False
        contract = _ARC.get(name) if name else None
        pb = _PB_WRITE.get(name) if name else None
        if pb is not None:
            reads, value = pb
        elif contract is not None:
            reads, value = contract[0], None
        else:
            reads, value = call_reads(self.ctx, tgt), None
        argp, frames = self._read_origins(st, reads, vals)
        has_w = _W in argp or st.esc
        if has_w:
            if pb is not None:
                if value is not None:
                    res.serialise(st.p(value))
            elif contract is not None:
                pass                                 # ARC: reads it, writes nothing out
            elif sel in _SEND_SERIALISES and _W in (st.p('x2') if sel == 'writeTo:' else st.p('x0')):
                res.serialise(st.p(_SEND_SERIALISES[sel]) - {_W})
            else:
                res.serialise(frozenset(argp) - {_W})
                if _W in argp:
                    st.esc = True                    # the callee may keep the writer
        # result
        if contract is not None:
            rp = st.p(contract[1]) if contract[1] else E
        elif pb is not None:
            rp = E
        else:
            rp = self._call_result(st, tgt, sel, argp, depth, top, addr)
            # a callee may put what it is handed into any object it is handed
            handed = frozenset(argp)
            res.put_into(handed, handed)
            own = ('R', addr)
            objs = frozenset(o for o in handed if _is_object(o))
            if own in rp and objs:
                # and its result may be one of those objects: it holds what they hold, and
                # what is put into it they hold
                res.put_into({own}, objs)
                res.put_into(objs, frozenset({own}))
        if frames and contract is None and pb is None:
            m = min(frames.values())                 # the callee may write the frame upward
            st.fl[m] = st.fl.get(m, E) | frozenset(argp)
        for r in CALLER_SAVED:
            st.r.pop(r, None)
        st.r['x0'] = frozenset(rp)
        st.r['v0'] = frozenset(rp - {_W, _S})        # an object is never returned in v0
        st.fv = False
        return False

    def _call_result(self, st: _St, tgt, sel, argp, depth, top, addr: int) -> FrozenSet:
        imp = None
        if st.p('x0') == frozenset({_S}):
            if sel is not None and self.cls is not None:
                m = self.cls.get_method(sel)
                if m is None:
                    for c in self._chain(self.cls)[1:]:
                        m = c.get_method(sel)
                        if m is not None:
                            break
                imp = m.imp if m is not None else None
            elif tgt in self.own_imps:
                imp = tgt
            elif text_holding(self.ctx, tgt) is not None:
                imp = tgt                            # a C function of this image handed self
        if imp is not None and imp != top:
            out = set()                              # its return: the caller's origins for
            for o in self._summary(imp, depth):     # each argument it is derived from
                out |= st.p(o[1]) if isinstance(o, tuple) and o[0] == _P else {o}
            return frozenset(out)
        # an object of its own; the objects it was handed are not carried (what they hold and
        # what it holds are the same, through the caller's heap), so a chain of calls does not
        # pile up the objects of every call before it
        r = {o for o in argp if not (isinstance(o, tuple) and o[0] == 'R')}
        if _S in r:
            r.discard(_S)
            r.add(_T)
        r.add(('R', addr))
        return frozenset(r)

    def _summary(self, imp: int, depth: int) -> FrozenSet:
        """Origins of the value a method of self returns, called with x0 = self and each other
        argument register its own marker (``(_P, reg)``: the caller substitutes its origins)."""
        if imp in self._summary_memo:
            return self._summary_memo[imp]
        self._summary_memo[imp] = frozenset({_T})    # recursion guard
        cuts = self._summary_cuts
        out = frozenset({_T})
        if depth < _MAX_SUMMARY_DEPTH:
            entry = {'x0': frozenset({_S}),
                     **{r: frozenset({(_P, r)}) for r in ARG_GPRS if r != 'x0'}}
            res = self._run(imp, entry, depth + 1, imp)
            if res is not None and res.complete:
                # (the objects of its own calls are no objects of the caller's: the call that
                # returns one is, ``('R', addr)``)
                out = frozenset(o for o in res.ret if not (isinstance(o, tuple) and o[0] == 'R'))
        else:
            self._summary_cuts += 1
            record_heuristic_hit(self.ctx, "_MAX_SUMMARY_DEPTH",
                               f"{self.cls.name if self.cls else '?'}: the method at {imp:#x}")
        if self._summary_cuts == cuts:
            self._summary_memo[imp] = out
        else:                                    # it depends on how deep it was asked for
            del self._summary_memo[imp]
        return out

    # ── one instruction ──────────────────────────────────────────────────────
    # *vals*: the registers known before an instruction on every path into it (:class:`_Run`)
    @staticmethod
    def _frame(vals: Dict[str, int], reg: Optional[str]) -> Optional[int]:
        """*reg* as a frame address (offset from the entry sp), or None when it is not one."""
        v = vals.get(reg)
        return v - _STACK_TOP if _is_stack(v) else None

    @staticmethod
    def _const(vals: Dict[str, int], reg: Optional[str]) -> Optional[int]:
        """*reg* when it is a constant other than a frame address (a page, an address, an
        immediate)."""
        v = vals.get(reg)
        return v if type(v) is int else None

    @classmethod
    def _int32(cls, vals: Dict[str, int], reg: str) -> Optional[int]:
        """*reg*'s constant as the signed 32-bit argument a ``w`` register passes (a field
        number; the no-tag number is -1)."""
        v = cls._const(vals, reg)
        if v is None:
            return None
        v &= 0xFFFFFFFF
        return v - (1 << 32) if v & 0x80000000 else v

    @staticmethod
    def _access(mem: str, ops: List[str], fa: int, disp: int) -> int:
        """The address a frame access reads or writes: pre-index ``[b, #d]!`` and offset
        ``[b, #d]`` use b+d, post-index ``[b], #d`` uses b (the base's new value is the
        Flow run's)."""
        tail = ops[-1].strip() if ops else ''
        if (not mem.rstrip().endswith('!') and tail.startswith('#') and '[' not in tail
                and ops.index(mem) == len(ops) - 2):
            return fa
        return fa + disp

    def _exec(self, st: _St, ins, mn: str, ops: List[str], vals: Dict[str, int],
              res: _Result) -> None:
        dsts = [d for d in writes(ins) if d != 'sp']
        if 'v0' in dsts:
            st.fv = True
        if (mn in ('add', 'sub') and len(ops) in (3, 4) and ops[2].strip().startswith('#')
                and self._frame(vals, 'sp' if ops[1].strip() == 'sp' else _norm_reg(ops[1]))
                is not None) or (mn == 'mov' and len(ops) == 2 and ops[1].strip() == 'sp'):
            for d in dsts:                           # a frame address
                st.kill(d, frozenset({'STK'}))
            return
        if mn in LOAD_BYTES or mn in PAIR_LOADS:
            self._load(st, mn, ops, dsts, vals)
            return
        if mn in STORE_BYTES or mn in PAIR_STORES:
            self._store(st, ins, mn, ops, vals, res)
            return
        # anything else: each destination derives from every source register
        src: Set = set()
        for r in reads(ins):
            src |= st.p(r)
            if self._frame(vals, r) is not None:
                src.add('STK')
        if mn == 'add' and _S in src:
            # self + an ivar's offset = the address of that ivar (C pointer provenance)
            names = [x[1] for x in src if isinstance(x, tuple) and x[0] == 'O']
            if names:
                src = {x for x in src if x != _S and not (isinstance(x, tuple) and x[0] == 'O')}
                src |= {('I', n) for n in names}
        if mn in ('add', 'sub') and _S in src and len(ops) in (3, 4) \
                and ops[2].strip().startswith('#'):
            # self plus a constant: a load through it reads the ivar at that offset plus its own
            c = imm_operand(ops, 2)
            offs = {x[1] for x in src if isinstance(x, tuple) and x[0] == 'OFF'}
            src = {x for x in src if not (isinstance(x, tuple) and x[0] == 'OFF')}
            if c is not None and len(offs) <= 1:
                src.add(('OFF', (offs.pop() if offs else 0) + (c if mn == 'add' else -c)))
        for d in dsts:
            st.kill(d, frozenset(src))

    def _load(self, st: _St, mn: str, ops: List[str], dsts: List[str],
              vals: Dict[str, int]) -> None:
        mem = next((o for o in ops if '[' in o), None)
        pm = parse_mem(mem) if mem else None
        regs_out = [reg_name(o) for o in ops if '[' not in o and not o.strip().startswith('#')]
        regs_out = [r for r in regs_out if r]
        if pm is None:                               # PC-relative literal: ldr x, #addr
            iv = self.slot_to_ivar.get(_parse_imm(ops[-1]) if ops else None)
            for d in dsts:
                st.kill(d, frozenset({('O', iv)}) if iv else E)
            return
        base, idx, disp = pm[0], pm[1], pm[2]
        width = reg_bytes(ops[0]) if ops else 8
        outs = regs_out[:2] if mn in PAIR_LOADS else regs_out[:1]
        fa = self._frame(vals, base) if base else None
        if fa is not None and idx is None:
            a0 = self._access(mem, ops, fa, disp)
            vals = [st.frame_read(a0 + width * i, width) for i in range(len(outs))]
            for d in dsts:
                st.kill(d)
            for d, v in zip(outs, vals):
                st.kill(d, v)
            return
        if fa is not None:                           # an element of a frame array: any of it
            v = st.frame_from(fa + disp) | st.p(idx)
            for d in dsts:
                st.kill(d)
            for d in outs:
                st.kill(d, v)
            return
        cb = self._const(vals, base) if base else None
        if cb is not None and idx is None:
            esize = 4 if mn == 'ldpsw' else width   # ldpsw: two 32-bit offset variables
            addr = cb + disp
            ivs = [self.slot_to_ivar.get(addr + esize * i) for i in range(len(outs))]
            for d in dsts:
                st.kill(d)
            for d, iv in zip(outs, ivs):
                st.kill(d, frozenset({('O', iv)}) if iv else E)
            return
        bp = st.p(base) | (st.p(idx) if idx else E)
        out: Set = set()
        if _S in bp:
            names = [x[1] for x in bp if isinstance(x, tuple) and x[0] == 'O']
            offs = [x[1] for x in bp if isinstance(x, tuple) and x[0] == 'OFF']
            at = disp + (offs[0] if offs else 0) if len(offs) <= 1 else None
            if names:
                out |= {('I', n) for n in names}
            elif idx is None and at in self.off_to_ivar:
                out.add(('I', self.off_to_ivar[at]))
            else:
                out.add(_T)
        out |= {x for x in bp if x != _S and x != 'STK'
                and not (isinstance(x, tuple) and x[0] in ('O', 'OFF'))}
        for d in dsts:
            st.kill(d)
        for d in outs:
            st.kill(d, frozenset(out))

    def _store(self, st: _St, ins, mn: str, ops: List[str], vals: Dict[str, int],
               res: _Result) -> None:
        mem = next((o for o in ops if '[' in o), None)
        pm = parse_mem(mem) if mem else None
        srcs = [o for o in ops if '[' not in o and not o.strip().startswith('#')]
        if mn in PAIR_STORES:
            srcs = srcs[:2]
        else:
            srcs = srcs[:1]
        if pm is None:
            return
        base = pm[0]
        fa = self._frame(vals, base) if base else None
        if fa is not None and pm[1] is None:
            a = self._access(mem, ops, fa, pm[2])
            for tok in srcs:
                w = reg_bytes(tok)
                r = reg_name(tok.strip())
                stk = r is not None and self._frame(vals, r) is not None
                v = (st.p(r) | (frozenset({'STK'}) if stk else E)) if r else E
                st.frame_write(a, w, frozenset(v))
                a += w
            return
        if fa is not None:                           # an element of a frame array, from fa up
            v = set()
            for tok in srcs:
                r = reg_name(tok.strip())
                if r:
                    v |= st.p(r) | ({'STK'} if self._frame(vals, r) is not None else set())
            st.fl[fa + pm[2]] = st.fl.get(fa + pm[2], E) | frozenset(v)
            return
        v: Set = set()
        for tok in srcs:
            r = reg_name(tok.strip())
            if r and _W in st.p(r):
                res.fail(f"writer stored outside the frame at {ins.addr:#x}")
            if r:
                v |= st.p(r)
        if base:
            res.put_into(st.p(base), frozenset(v))


def writer_flow_for(ctx: BinaryContext, cl: ClassList) -> "WriterFlow":
    """The image's :class:`WriterFlow`, cached on *ctx* (built again for another class list)."""
    wf = getattr(ctx, "_writer_flow", None)
    if wf is None or wf.cl is not cl:
        wf = WriterFlow(ctx, cl)
        _ctx_store(ctx, "_writer_flow", wf)
    return wf


def writer_reachable_ivars(ctx: BinaryContext, cl: ClassList, cls: ObjcClass
                           ) -> Tuple[Optional[FrozenSet[str]], List[str]]:
    """``(ivars whose values can reach -[cls writeTo:]'s writer, reasons)``: the set is None
    when undecided.  One :class:`WriterFlow` per image is cached on *ctx*."""
    wf = writer_flow_for(ctx, cl)
    try:
        return wf.reachable_ivars(cls)
    except PROGRAM_ERRORS:
        raise
    except Exception as exc:                         # bad input: undecided, never a drop
        log.debug("writer flow failed for %s: %s", cls.name, exc)
        return None, [f"analysis error: {exc}"]
