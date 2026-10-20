"""proto/dispatch -- the readFrom: anchors the dispatch evaluator (:mod:`proto.dispatch_eval`)
starts from:

* :func:`_find_readfrom_c_func` / :func:`_build_readfrom_core_index` -- the ReadAllFrom core
  each proto class's ``-readFrom:`` tail-calls, indexed by address (an element core a parent's
  handler calls names the element class);
* :func:`_jump_table_arm_addrs` -- decoded ``br`` jump tables, the CFG completion every
  :class:`proto.arm64_eval.Flow` user seeds its graph with.

Never imports proto.extractor or proto.dispatch_eval (which imports this module); the
evaluator (:mod:`proto.arm64_eval`) is imported inside the functions that run it.
"""
from __future__ import annotations
import bisect
import logging
import re
from typing import Dict, List, Optional

from macho.memory    import READ_ERRORS, BinaryContext, _ctx_cache, _ctx_store
from macho.classlist import ObjcClass
from macho.disasm   import disasm, Insn, _norm_reg, _parse_imm
from proto.arm64cfg import dominators
from proto.eval_tokens import SELF, READER, OPAQUE
from proto.arm64_operands import (NO_DEST, PAIR_LOADS, INDIRECT_BRANCHES, RETURNS, imm_operand,
                                  is_cond_branch, split_ops)
from proto.protoclass_set import _proto_class_set

log = logging.getLogger(__name__)

# [cap:COSMETIC — verified] the readFrom: wrapper's call is in its first two instructions (x8 changed nothing).
_READFROM_MAX_INSNS = 12


def _find_readfrom_c_func(
    ctx: BinaryContext, cls: ObjcClass
) -> Optional[int]:
    """
    The C ReadFrom core ``-[Cls readFrom:]`` is a thin wrapper around, or None.

    The thin wrapper hands its object and its reader straight on::

        mov x1, x2              ; (mov w2, #0)
        b   _ClsReadFrom        ; or: bl _ClsReadFrom ... ret

    Decided by data flow, not by "the first branch": the wrapper (up to its first
    unconditional terminator) is run with x0 = self and x2 = the reader as opaque tokens
    (:mod:`proto.dispatch_eval`), and its first call must be handed both (x0 = self, x1 =
    reader).  So an inline reader -- ``-readFrom:`` holding the dispatch itself, whose first
    call retains the reader -- has no C core (a parent cannot ``bl`` one; it messages
    ``readFrom:``), and a ``-readFrom:`` that hands only the reader to a shared function
    (a field-less filter's skip-everything helper) has none either.
    """
    from proto.arm64_eval import Flow
    method = cls.get_method("readFrom:")
    if method is None or method.imp == 0:
        return None

    try:
        insns = disasm(ctx, method.imp, max_insns=_READFROM_MAX_INSNS, stop_at_ret=False)
    except READ_ERRORS:
        return None
    end = next((k for k, i in enumerate(insns)
                if i.mnemonic in ('b', 'udf') or i.mnemonic in INDIRECT_BRANCHES
                or i.mnemonic in RETURNS), None)
    insns = insns[:end + 1] if end is not None else insns
    if not insns:
        return None
    region = Flow(ctx, insns).run_from(0, {'x0': SELF, 'x2': READER}, objects=OPAQUE)
    if not region.calls:
        return None
    first = region.calls[0]
    if first.args.get('x0') == SELF and first.args.get('x1') == READER:
        return first.target
    return None


def _section_name(ctx: BinaryContext, va: int) -> Optional[str]:
    """Name of the section containing *va*, or ``None`` if unmapped."""
    for seg in ctx.segments:
        if seg.vmaddr <= va < seg.vmaddr + seg.vmsize:
            for sec in seg.sections:
                if sec.vmaddr <= va < sec.vmaddr + sec.vmsize:
                    return sec.name
            return None
    return None


# An unsigned range check: the branch that guards a table (a signed compare or an equality
# test is not an index bound).
_RANGE_CONDS = frozenset(('hi', 'hs', 'cs', 'lo', 'cc', 'ls'))


def _guarding_cond(flow, k: int) -> Optional[str]:
    """The condition of the conditional branch that reads the flags ``insns[k]`` sets: the
    first flag reader after it in its block, when that is a ``b.<cond>``; else None."""
    from proto.arm64_eval import _FLAG_SETTERS
    b = flow._block_of.get(k)
    end = flow._first_in_block[b] + len(flow.cfg.blocks[b])
    for j in range(k + 1, end):
        mn = flow.insns[j].mnemonic
        if is_cond_branch(mn):
            return mn[2:]
        if mn in _FLAG_SETTERS or mn in ('csel', 'csinc', 'csinv', 'csneg', 'cset', 'csetm',
                                         'cinc', 'cinv', 'cneg', 'ccmp', 'ccmn', 'adc', 'sbc'):
            return None
    return None


def _index_bound(flow, k: int):
    """``(start, register, values)`` when ``insns[k]`` bounds a register a jump table may be
    indexed by: a compare with an immediate whose flags an unsigned range branch reads
    (``cmp w8, #N ; b.hi`` -- or ``b.hs`` / ``b.ls`` / ``b.lo`` -- guarding the table),
    evaluated from the compare itself with values 0 .. N+1, the gate deciding which reach the
    ``br``; or a low-bit mask (``and w8, w0, #2^k-1``), evaluated from just after it with
    every value the mask lets through.  None for anything else."""
    from proto.arm64_eval import _MAX_GATE_SPAN
    ins = flow.insns[k]
    ops = split_ops(ins.op_str)
    if ins.mnemonic == 'cmp' and len(ops) in (2, 3) and ops[1].startswith('#'):
        n = imm_operand(ops, 1)
        r = _norm_reg(ops[0])
        if n is None or r is None or n > _MAX_GATE_SPAN or _guarding_cond(flow, k) not in _RANGE_CONDS:
            return None
        return k, r, n + 2
    if ins.mnemonic == 'and' and len(ops) == 3 and ops[2].startswith('#'):
        mask = _parse_imm(ops[2])
        r = _norm_reg(ops[0])
        if mask is None or r is None or mask <= 0 or mask & (mask + 1) or mask >= _MAX_GATE_SPAN:
            return None
        return k + 1, r, mask + 1
    return None


_GPR = re.compile(r'\b[xw](\d+)\b')


def _reads(ins) -> set:
    """The general registers (``xN`` form) *ins* reads: every register operand but the
    destination(s)."""
    ops = split_ops(ins.op_str)
    mn = ins.mnemonic
    if mn in NO_DEST or mn == 'movk' or is_cond_branch(mn):
        src = ops
    elif mn in PAIR_LOADS:
        src = ops[2:]
    else:
        src = ops[1:]
    return {f"x{m}" for o in src for m in _GPR.findall(o)}


def _sources(flow, kb: int, reg: str) -> set:
    """The definitions *reg*'s value at ``insns[kb]`` is computed from, transitively by
    reaching definitions: instruction indices, and ``('entry', r)`` for a register's value on
    entry."""
    out: set = set()
    work = [(kb, _norm_reg(reg))]
    while work:
        k, r = work.pop()
        for d in flow.defs_before(k, r):
            node = ('entry', r) if d < 0 else d
            if node in out:
                continue
            out.add(node)
            if d >= 0:
                work.extend((d, s) for s in _reads(flow.insns[d]))
    return out


def _evaluated_arms(flow, idom, kb: int, lo: int, hi: int) -> set:
    """The targets the ``br`` at ``insns[kb]`` takes, by evaluation from its index bound: the
    nearest bound (:func:`_index_bound`) in the code that dominates the ``br`` and whose value
    the target is computed from (:func:`_sources`).  Each value the bound lets through is run
    to the ``br`` (:meth:`proto.arm64_eval.Flow.value_at`) and its register read there, so the
    table's shape -- entry width and signedness, scaling, a bias or clamp of the index, the
    base -- is whatever the code computes, not a pattern.  Every path to the ``br`` passes
    that bound, so a bound further up (a range check of the same value before a bias) lets
    through no value it does not; one further up is tried only when the nearest gives no
    target."""
    reg = flow.insns[kb].op_str.strip()
    blk = flow._block_of[kb]
    sources = _sources(flow, kb, reg)
    d = blk
    while True:
        first = flow._first_in_block[d]
        end = kb if d == blk else first + len(flow.cfg.blocks[d])
        for k in range(end - 1, first - 1, -1):
            bound = _index_bound(flow, k)
            if bound is None:
                continue
            start, r, count = bound
            bounded = {k} if start != k else \
                {('entry', r) if x < 0 else x for x in flow.defs_before(k, r)}
            if not bounded & sources:
                continue                     # the target is not computed from this value
            arms = set()
            for v in range(count):
                t = flow.value_at(start, {r: v}, kb, reg)
                if t is not None and lo <= t < hi:
                    arms.add(t)
            if arms:
                return arms
        up = idom.get(d)
        if up is None or up == d:
            return set()
        d = up


def _jump_table_arm_addrs(ctx: BinaryContext, insns: List["Insn"], per_br: bool = False):
    """Arm-target addresses of every ``br Xn`` jump table in *insns*, decided by evaluation
    (:func:`_evaluated_arms`): each value the index's bound lets through is run to the ``br``.
    That covers every compiler idiom alike -- an index table (``ldrb``/``ldrh`` entry scaled by
    the final ``add``'s shift), a difference table (signed ``ldrsw`` byte deltas from an
    ``adr`` anchor inside the dispatch), a mask-bounded index (``and w8, w0, #7`` on a wire
    type) -- with no look-back window.

    A GENERAL CFG-completion decoder: it recovers arm targets for any such ``br`` so a CFG
    (and :func:`proto.arm64cfg.dominators`) reaches the blocks behind it.  Without it a
    reader whose field dispatch shares its function with a control ``br`` ahead of the
    field-number extraction (e.g. GEOHours) has that extraction unreachable.  A ``br`` reached
    only through another table's arms (a segmented switch) is decoded once those arms are CFG
    edges; a ``br`` the entry never reaches is not decoded.
    Read-only; returns in-range arm addresses -- with *per_br*, as ``{br address: its arms}``.
    Memoised on *ctx* per instruction listing."""
    if ctx is None or not insns:
        return {} if per_br else set()
    by_br = _decoded(ctx, insns)[0]
    if per_br:
        return {b: set(a) for b, a in by_br.items()}
    return set().union(*by_br.values())


def _decoded(ctx: BinaryContext, insns: List["Insn"]) -> list:
    """``[{br address: arms}, Flow or None, sorted listing]`` for *insns*, memoised on *ctx* per
    listing: the decoder's last Flow is kept when it was built with the final arms."""
    from proto.arm64_eval import Flow
    ins = sorted(insns, key=lambda i: i.addr)
    key = tuple(i.addr for i in ins)
    memo = _ctx_cache(ctx, "_jump_table_arms", dict)
    hit = memo.get(key)
    if hit is None:
        by_br: Dict[int, frozenset] = {}
        final = None
        lo, hi = ins[0].addr, ins[-1].addr + 4
        todo = {k for k, i in enumerate(ins) if i.mnemonic == 'br'}
        while todo:
            flow = Flow(ctx, ins, br_arms=by_br)
            idom = dominators(flow.cfg)
            reached = sorted(k for k in todo if flow._block_of.get(k) in idom)
            todo.difference_update(reached)
            new = {}
            for kb in reached:
                arms = _evaluated_arms(flow, idom, kb, lo, hi)
                if arms:
                    new[ins[kb].addr] = frozenset(arms)
            if not new:
                final = flow
                break
            by_br = {**by_br, **new}
        hit = memo[key] = [by_br, final, ins]
    return hit


def decoded_flow(ctx: BinaryContext, insns: List["Insn"]):
    """The :class:`proto.arm64_eval.Flow` of *insns* (in address order) with each ``br``
    reaching its own decoded table (:func:`_jump_table_arm_addrs`): the decoder's own when it
    built one with the final arms.  Memoised on *ctx* per listing."""
    from proto.arm64_eval import Flow
    hit = _decoded(ctx, insns)
    if hit[1] is None:
        hit[1] = Flow(ctx, hit[2], br_arms=hit[0])
    return hit[1]


def listing_flow(ctx: BinaryContext, insns: List["Insn"]):
    """The :class:`proto.arm64_eval.Flow` of an instruction listing, each ``br`` reaching its
    own decoded table (:func:`decoded_flow` for a listing in address order); with no tables,
    which need the image, when *ctx* is None."""
    from proto.arm64_eval import Flow
    if ctx is None or any(a.addr >= b.addr for a, b in zip(insns, insns[1:])):
        return Flow(ctx, list(insns), br_arms=_jump_table_arm_addrs(ctx, insns, per_br=True))
    return decoded_flow(ctx, insns)


def build_function_index(ctx: BinaryContext, cl: 'ClassList') -> None:
    """Record on *ctx* every method IMP of the image (``_function_entries``) and every ivar's
    offset-variable address (``_ivar_offset_slots``).  The readFrom: evaluator
    (:mod:`proto.dispatch_eval`) uses the IMPs, with the ReadAllFrom cores, as function
    boundaries and tail-call targets, and the slots to tell this class's ivars from others'.
    Built once per extraction; :func:`_build_readfrom_core_index` calls it."""
    entries = _ctx_cache(ctx, "_function_entries", set)
    ivar_slots = _ctx_cache(ctx, "_ivar_offset_slots", set)
    for cls in cl:
        entries.update(m.imp for m in cls.methods if m.imp)
        ivar_slots.update(iv.offset_slot for iv in cls.ivars if iv.offset_slot)


class FunctionEntries(list):
    """Sorted function-entry addresses with set membership (``members``) and the next entry
    after an address (:meth:`next_after`): a function ends where the next one starts, and a
    ``b`` to an entry is a tail call."""
    __slots__ = ("members",)

    def __init__(self, addrs=()):
        super().__init__(sorted(set(addrs)))
        self.members = frozenset(self)

    def next_after(self, va: int) -> Optional[int]:
        """The first entry above *va*, or None."""
        i = bisect.bisect_right(self, va)
        return self[i] if i < len(self) else None


def function_entries(ctx: BinaryContext) -> FunctionEntries:
    """The image's function index (:func:`build_function_index`) as :class:`FunctionEntries`,
    sorted once per extraction rather than by every caller (empty when the index is not built).
    Rebuilt if the index has grown since."""
    es = getattr(ctx, "_function_entries", None) or set()
    memo = getattr(ctx, "_function_entries_sorted", None)
    if memo is None or memo[0] is not es or memo[1] != len(es):
        memo = _ctx_store(ctx, "_function_entries_sorted", (es, len(es), FunctionEntries(es)))
    return memo[2]


def _build_readfrom_core_index(
    ctx: BinaryContext,
    cl: 'ClassList',
) -> Dict[int, str]:
    """
    Binary-wide pre-pass: map every proto class's ReadAllFrom C-core address to
    its class name — ``{ReadAllFrom_vmaddr: class_name}``.

    The ReadAllFrom core is the tail target of ``-[Cls readFrom:]`` (recovered by
    :func:`_find_readfrom_c_func`) — exactly the address a *parent* class's
    readFrom: dispatch handler calls on a new object when parsing an embedded ``<Cls>``
    element.  The dispatch evaluator (:mod:`proto.dispatch_eval`) names an element class
    **by that call target**, which works in cache-native mode where symbol names are
    stripped.  Also builds the function index (:func:`build_function_index`).

    One pass over the classlist, threaded through to every :func:`extract_proto_message`
    call.  Two classes sharing one core would make the index name only the first; none do
    (GeoServices: 1598 cores, all distinct).
    """
    index: Dict[int, str] = {}
    build_function_index(ctx, cl)
    proto_classes = _proto_class_set(ctx, cl)
    for cls in cl:
        if cls.is_meta or cls.name not in proto_classes:
            continue
        core = _find_readfrom_c_func(ctx, cls)
        if core is None:
            continue
        prev = index.get(core)
        if prev is None:
            index[core] = cls.name
        elif prev != cls.name:
            log.debug("readFrom core 0x%x maps to both %s and %s; keeping %s",
                      core, prev, cls.name, prev)
    return index
