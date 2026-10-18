"""proto/dispatch_eval.py -- PROTOTYPE: decode a class's readFrom: field dispatch by evaluation.

Not used by the extraction path.  It runs alongside :mod:`proto.dispatch` / :mod:`proto.repeated`
so their results can be compared (``scripts`` drivers report the disagreements).

The question the dispatch idioms answer by shape -- "for field N, which handler runs, which
element class does it build, and which ivar does it append to" -- is answered here by running
the reader:

1. **Which function dispatches** (replaces the wrapper scan and every ownership signal).
   ``-[Cls readFrom:]`` is entered with x0 = SELF and x2 = READER, two opaque tokens.  A call is
   followed only when it is handed THIS object (x0 = SELF; ``objc_retain`` and the ARC
   return-value handshake return their argument), so a nested element's reader -- handed a
   freshly allocated object -- is never mistaken for ours, whatever the toolchain's call-site
   shape.  (The reader itself is not required: readers retain it first and use the
   retain's result, which the analysis cannot equate with READER without the runtime's names.)  The first function so
   reached that extracts a field number (``lsr Wf, Wtag, #3``) is the dispatch core; the
   constants it was handed (a data table chosen by a ``csel``) come along as values.
2. **What runs for field N.**  The core is propagated from its entry to the ``lsr`` (the state
   there: self, reader, table, in whatever registers the core keeps them), then from just after
   the ``lsr`` with Wf = N through calls (:meth:`proto.arm64_eval.Flow.run_from`) until control
   re-enters a block that dominates the ``lsr`` -- the next tag read.  Branches the analysis
   cannot decide (has-bits, wire type, error checks) are followed both ways; a jump-table
   ``br`` is decided by N itself.  Only the outermost ``lsr`` counts: one dominated by another
   is a nested message's or a map entry's reader inlined into an outer field's handler.  N's handler is what N reaches and an unknown field number
   (one past every value the code compares with) does not.
3. **What the handler does**, read off call arguments, not idioms: the element core is a call
   into a known ``ReadAllFrom`` core handed an object other than self / the reader (its x0 is
   the element object); the element class is any known proto class whose ``class_t`` address is an argument
   (``objc_alloc`` / ``objc_opt_new``, however the address was formed -- classref ``ldr`` or
   direct ``adrp+add``); the adder is a call handed x0 = SELF and that element object (in x2 for a
   method IMP called directly, x1 = ``_cmd``; in x1 for an ``objc_direct`` C function), and its ivar is the array ivar whose offset
   variable it loads (:func:`proto.repeated._adder_array_ivar`).

Stack slots use the object-escape rule (:class:`proto.arm64_eval._Machine`): a callee handed a
frame address may write from it upward only, and does not keep it past its return.  An older
toolchain spills the element object across such a call (``str x0,[sp,#8]`` ... ``add x1,sp,#0x60;
bl`` ... ``ldr x1,[sp,#8]; bl adder``), which clearing every slot would lose.

Candidate field numbers come from :meth:`Flow.candidates` (every compare point and every ordered
gate's interval).  Jump-table arms the CFG lacks are found by evaluating the ``br`` under each N;
the CFG is rebuilt with them and the run repeated.  The CFG is still SEEDED with the decoded
jump tables (:func:`proto.dispatch._jump_table_arm_addrs`, as every Flow user): a control ``br``
ahead of the ``lsr`` (has-bits bookkeeping) has an index the fixpoint cannot know, and without
its arms the ``lsr`` is unreachable.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

from macho.disasm import disasm, _parse_imm
from proto.arm64cfg import dominators, dominates, ivar_slot_loads, split_ops
from macho.disasm import _norm_reg
from proto.arm64_eval import Flow
from proto.arm64_operands import parse_mem
from proto.callees import callee_name, stub_selector, RETURNS_ARGUMENT
from proto import dispatch as D

log = logging.getLogger(__name__)

# Opaque tokens: above every image address, below 2^48, and outside the stack partition.
_TOKEN_BASE = 0xE000_0000_0000
SELF = _TOKEN_BASE
READER = _TOKEN_BASE + 0x1000_0000
_RET_BASE = _TOKEN_BASE + 0x2000_0000          # + 16 * insn index: x0 after that call
_FIELD_BASE = _TOKEN_BASE + 0x3000_0000        # + offset: self->ivar at that byte offset

_MAX_FIELD = 1 << 29                            # protobuf field numbers are 1 .. 2^29 - 1
_MAX_SPAN = 1 << 12                             # a gate interval wider than this is not expanded
_DESCEND_DEPTH = 4
_ARM_ROUNDS = 4
# [cap:INPUT-SANITY] a br target further than this past the core's entry is not taken as one of
# its arms (the largest GeoServices reader is ~5 KB; this is a runaway guard, not a window).
_ARM_REACH = 0x40000

_ARRAY_ENCS = ('@"NSMutableArray"', '@"NSArray"')


def _is_ret_token(v: Optional[int]) -> bool:
    return v is not None and _RET_BASE <= v < _RET_BASE + (1 << 28)


def _opaque(v: Optional[int]) -> bool:
    """SELF, READER, call results and self's ivar values are objects, not numbers."""
    return v is not None and _TOKEN_BASE <= v < _FIELD_BASE + (1 << 28)


def _field_value(obj: int, off: int) -> Optional[int]:
    """``self->ivar`` at byte offset *off* (the array a reader appends to with addObject:)."""
    return _FIELD_BASE + off if obj == SELF and 0 <= off < (1 << 24) else None


def _ret_value(k: int) -> int:
    return _RET_BASE + 16 * k


def _selector_of(ctx, call) -> Optional[str]:
    """Selector a call sends: a ``_objc_msgSend$<sel>`` stub's, or -- for a call to the
    generic ``objc_msgSend`` a standalone binary imports by name -- the selector string x1
    points at."""
    if call.target is None:
        return None
    sel = stub_selector(ctx, call.target)
    if sel is not None:
        return sel
    x1 = call.args.get('x1')
    if x1 is not None and not _opaque(x1) and callee_name(ctx, call.target) == '_objc_msgSend':
        try:
            return ctx.read_cstring(x1)
        except (ValueError, KeyError, IndexError, UnicodeDecodeError):
            return None
    return None


def _call_result(ctx):
    """``call_result`` for :meth:`Flow.run_from` / :meth:`Flow.propagate`: a call to a runtime
    function that returns its argument keeps x0; any other call's result is a fresh token."""
    def result(k: int, target: Optional[int], x0: Optional[int]) -> Optional[int]:
        if x0 is not None and _opaque(x0) and callee_name(ctx, target) in RETURNS_ARGUMENT:
            return x0
        return _ret_value(k)
    return result


@dataclass
class FieldDispatch:
    number: int
    handler: Optional[int] = None              # first handler-only block reached
    element_core: Optional[str] = None         # class of the ReadAllFrom core handed the reader
    element_classes: Tuple[str, ...] = ()      # proto classes whose class_t is an argument
    adder: Optional[int] = None                # call handed (SELF, element object)
    adder_ivar: Optional[str] = None
    calls: List[Tuple[int, Optional[int]]] = field(default_factory=list)   # (call addr, target)

    @property
    def element(self) -> Optional[str]:
        if self.element_core:
            return self.element_core
        return self.element_classes[0] if len(self.element_classes) == 1 else None


@dataclass
class ClassDispatch:
    cls: str
    cores: List[int] = field(default_factory=list)
    fields: Dict[int, FieldDispatch] = field(default_factory=dict)
    notes: List[str] = field(default_factory=list)

    def elements(self) -> Dict[int, str]:
        return {n: f.element for n, f in sorted(self.fields.items()) if f.element}

    def ivars(self) -> Dict[str, Tuple[str, int]]:
        out: Dict[str, Tuple[str, int]] = {}
        for n, f in sorted(self.fields.items()):
            if f.adder_ivar and f.element:
                out.setdefault(f.adder_ivar, (f.element, n))
        return out


# ── function bodies ─────────────────────────────────────────────────────────

def _known_entries(ctx, cls, core_index: Dict[int, str]) -> List[int]:
    """Sorted addresses known to start a function: every method IMP (recorded on *ctx* by
    :func:`proto.dispatch.build_function_index`), every ReadAllFrom core and *cls*'s own
    methods.  Functions do not overlap, so a function ends at the next one (the CFG-reachable
    end alone runs a tail ``b`` into the function it jumps to, e.g. a ``-readFrom:`` wrapper into
    the engine laid out after it)."""
    es = set(getattr(ctx, "_function_entries", None) or ())
    es.update(core_index)
    es.update(m.imp for m in cls.methods if m.imp)
    return sorted(es)


def _class_name_at(ctx, va: Optional[int]) -> Optional[str]:
    """Name of the ObjC class whose ``class_t`` is at *va* (``class_t.data -> class_ro_t.name``),
    or None.  Callers accept it only when it is a known proto class."""
    from macho.objc_abi import CLASS_T_DATA, CLASS_RO_NAME, FAST_DATA_MASK
    if va is None or not 0 < va < _TOKEN_BASE:
        return None
    try:
        ro = ctx.read_ptr(va + CLASS_T_DATA) & FAST_DATA_MASK
        name_va = ctx.read_ptr(ro + CLASS_RO_NAME) if ro else 0
        return ctx.read_cstring(name_va) if name_va else None
    except (ValueError, KeyError, IndexError, UnicodeDecodeError, TypeError):
        return None


# [cap:INPUT-SANITY] a masked jump-table index (``and Wi, Wn, #2^k-1``) is enumerated only up to
# this many values (a byte-wide index is the widest seen).
_MAX_MASKED_INDEX = 256


def _seed_br_arms(ctx, insns) -> Dict[int, Set[int]]:
    """``{br address: arms}`` to complete a CFG with before any evaluation: each ``br``'s decoded
    table (:func:`proto.dispatch._jump_table_arm_addrs`), plus -- for a ``br`` whose index is
    bounded by an ``and`` mask rather than a ``cmp`` gate (``and w8, w0, #7`` on the wire type)
    -- the targets the ``br`` takes for every value the mask lets through, found by running the
    straight-line code from the ``and`` to the ``br``."""
    from proto.arm64_eval import _Machine
    per_br = {b: set(a) for b, a in D._jump_table_arm_addrs(ctx, insns, per_br=True).items()}
    flow = None
    for kb, br in enumerate(insns):
        if br.mnemonic != 'br' or br.addr in per_br:
            continue
        for ka in range(kb - 1, max(-1, kb - 16), -1):
            a = insns[ka]
            if a.mnemonic in ('b', 'bl', 'blr', 'br', 'ret', 'retab', 'cbz', 'cbnz', 'tbz', 'tbnz') \
                    or a.mnemonic.startswith('b.'):
                break
            ops = split_ops(a.op_str)
            if a.mnemonic != 'and' or len(ops) != 3 or not ops[2].startswith('#'):
                continue
            try:
                mask = int(ops[2].lstrip('#'), 0)
            except ValueError:
                continue
            if mask <= 0 or mask >= _MAX_MASKED_INDEX or mask & (mask + 1):
                continue
            if flow is None:
                flow = Flow(ctx, insns)
            arms = set()
            for v in range(mask + 1):
                m = _Machine({_norm_reg(ops[0]): v}, fallback=lambda r, k=ka: flow.const_before(k, r))
                for k in range(ka + 1, kb):
                    flow._exec(m, insns[k])
                t = m.get(split_ops(br.op_str)[0])
                if t is not None and insns[0].addr <= t <= insns[-1].addr:
                    arms.add(t)
            if arms:
                per_br[br.addr] = arms
            break
    return per_br


# [cap:INPUT-SANITY] how far past its entry a function is looked for when no later function
# entry is known (the largest GeoServices reader is ~5 KB; a runaway guard, not a window).
_MAX_FUNC_BYTES = 0x10000


def _function_insns(ctx, va: int, upto: int = 0, entries: Optional[List[int]] = None):
    """The instructions of the function at *va*: those reachable from its entry over a CFG
    whose ``br`` instructions reach their own decoded jump-table arms (a control ``br`` ahead of
    the dispatch would otherwise end the function), where a ``b`` to a known function entry is
    a tail call, and never past the next known function entry (*entries*).  *upto* extends it
    to cover arms found by evaluation."""
    import bisect
    from proto.arm64cfg import build_blocks
    hard_end = va + _MAX_FUNC_BYTES
    tails: Set[int] = set()
    if entries:
        i = bisect.bisect_right(entries, va)
        if i < len(entries):
            hard_end = min(hard_end, entries[i])
        tails = set(entries)
    try:
        insns = [i for i in disasm(ctx, va, max_insns=max(1, (hard_end - va) // 4),
                                   stop_at_ret=False) if va <= i.addr < hard_end]
    except Exception:
        return []
    if not insns:
        return []
    per_br = _seed_br_arms(ctx, insns)
    cfg = build_blocks(insns, {a for arms in per_br.values() for a in arms})
    reached, work = set(), [cfg.entry]
    while work:
        b = work.pop()
        if b is None or b in reached:
            continue
        reached.add(b)
        last = cfg.blocks[b][-1]
        succ = list(cfg.succ.get(b, []))
        if last.mnemonic == 'b' and _parse_imm(last.op_str) in tails:
            succ = []                                      # a tail call into another function
        if last.mnemonic == 'br':
            succ += [cfg.addr_to_block[a] for a in per_br.get(last.addr, ()) if a in cfg.addr_to_block]
        work.extend(succ)
    end = max(cfg.blocks[b][-1].addr for b in reached) + 4
    end = min(max(end, upto), hard_end)
    return [i for i in insns if i.addr < end]


def _lsr3_sites(flow: Flow) -> List[Tuple[int, str]]:
    """``(index, destination)`` of every field-number extraction ``tag >> 3``: ``lsr Rd, Rn, #3``,
    or ``ubfx Rd, Rn, #3, #width`` (an older compiler keeps only the field bits, e.g. 16)."""
    out = []
    for k, ins in enumerate(flow.insns):
        if ins.mnemonic not in ('lsr', 'ubfx'):
            continue
        ops = split_ops(ins.op_str)
        if (ins.mnemonic == 'lsr' and len(ops) == 3 and ops[2].strip() == '#3') or \
                (ins.mnemonic == 'ubfx' and len(ops) == 4 and ops[2].strip() == '#3'):
            r = _norm_reg(ops[0])
            if r:
                out.append((k, r))
    return out


def _outermost(flow: Flow, idom, sites: List[int]) -> Set[int]:
    """Of the DISPATCHING field-number extractions (*sites*: insn indices whose run gave at
    least one field a handler), those not reached only through another one: an ``lsr`` whose
    block is strictly dominated by another dispatching ``lsr``'s block belongs to a reader
    inlined into one of the outer fields' handlers (a nested message, a map entry's key/value),
    not to us.  (An ``lsr #3`` that dispatches nothing -- byte arithmetic in the preamble --
    does not count, even when it dominates the real one.)"""
    blocks = {k: flow._block_of.get(k) for k in sites}
    out = set()
    for k in sites:
        b = blocks[k]
        if b is None or b not in idom:
            continue
        if any(o != k and blocks[o] in idom and blocks[o] != b and dominates(idom, blocks[o], b)
               for o in sites):
            continue
        out.add(k)
    return out


def _in_image_text(ctx, va: Optional[int]) -> bool:
    return va is not None and D._section_name(ctx, va) == '__text'


# ── 1. which function dispatches ────────────────────────────────────────────

def find_cores(ctx, cls, entries: Optional[List[int]] = None
               ) -> Tuple[List[Tuple[int, Dict[str, int]]], List[str]]:
    """``([(core_va, entry_registers)], notes)``: the functions reached from ``-readFrom:`` by
    calls handed this object and this reader that extract a field number."""
    m = cls.get_method("readFrom:")
    notes: List[str] = []
    if m is None or not m.imp:
        return [], ["no readFrom:"]
    found: List[Tuple[int, Dict[str, int]]] = []
    seen: Set[int] = set()
    tails = frozenset(entries or ())

    def descend(va: int, regs: Dict[str, int], depth: int) -> None:
        if va in seen or depth > _DESCEND_DEPTH:
            return
        seen.add(va)
        insns = _function_insns(ctx, va, entries=entries)
        if not insns:
            return
        flow = Flow(ctx, insns, br_arms=_seed_br_arms(ctx, insns))
        region = flow.run_from(0, regs, call_result=_call_result(ctx), field_value=_field_value, opaque=_opaque,
                               object_escape=True, tail_targets=tails)
        # A core extracts a field number on a path from ITS OWN entry (the window can hold
        # the function laid out after it).
        if any(flow._block_of.get(k) in region.blocks for k, _d in _lsr3_sites(flow)):
            found.append((va, regs))
            return
        for c in region.calls:
            if c.args.get('x0') == SELF and _in_image_text(ctx, c.target):
                descend(c.target, dict(c.args), depth + 1)

    descend(m.imp, {'x0': SELF, 'x2': READER}, 0)
    if not found:
        notes.append("no function handed (self, reader) extracts a field number")
    return found, notes


# ── 2./3. what runs for each field number ──────────────────────────────────

def _decode_core(ctx, core_va: int, entry: Dict[str, int], cls, core_index: Dict[int, str],
                 out: ClassDispatch, entries: Optional[List[int]] = None) -> None:
    from proto.repeated import _adder_array_ivar
    array_offsets = frozenset(iv.offset for iv in cls.ivars if iv.type_enc in _ARRAY_ENCS)
    own_slots = frozenset(iv.offset_slot for iv in cls.ivars if iv.offset_slot)
    own_imps = frozenset(mm.imp for mm in cls.methods if mm.imp)
    off_to_ivar = {iv.offset: iv.name for iv in cls.ivars}
    sel_to_imp = {mm.name: mm.imp for mm in cls.methods if mm.name and mm.imp}
    # Known proto classes: every class with a ReadAllFrom core, plus the image's whole proto
    # class set when extraction has computed it (proto.protoclass_set caches it on ctx); a
    # message class whose readFrom: does not resolve to a core of its own is still one.
    known = set(core_index.values()) | set(getattr(ctx, "_proto_class_names_cache", None) or ())

    arms: Dict[int, Set[int]] = {}             # br address -> targets found by evaluation
    upto = 0
    for _round in range(_ARM_ROUNDS):
        insns = _function_insns(ctx, core_va, upto, entries)
        # CFG completion, per br: its decoded table (as every Flow user), so a control ``br``
        # ahead of the lsr (has-bits bookkeeping, whose index the fixpoint cannot know) does
        # not cut the lsr off; targets found by evaluating a ``br`` under N are added on top.
        br_arms: Dict[int, Set[int]] = _seed_br_arms(ctx, insns)
        for b, a in arms.items():
            br_arms.setdefault(b, set()).update(a)
        flow = Flow(ctx, insns, br_arms=br_arms)
        idom = dominators(flow.cfg)
        sites = _lsr3_sites(flow)
        results: List[Tuple[int, str, Dict[int, object], object]] = []
        new_arms: Dict[int, Set[int]] = {}
        for k, dest in sites:
            lsr_blk = flow._block_of.get(k)
            if lsr_blk is None or lsr_blk not in idom:
                continue
            slots_at: Dict[int, Dict[int, Tuple[int, int]]] = {}
            base = flow.propagate(entry, [k], opaque=_opaque, object_escape=True,
                                  slots_out=slots_at, call_result=_call_result(ctx),
                                  field_value=_field_value).get(k)
            if base is None:
                continue                       # this lsr is unreachable from the entry
            base_slots = slots_at.get(k, {})
            if SELF not in base.values() and SELF not in (v for _sz, v in base_slots.values()):
                # The loop that stores into THIS object holds it (in a register or a stack
                # slot -- a newer toolchain's engine spills it).  An lsr reached without
                # self is not our dispatch: e.g. the next function in memory, reached by
                # falling through a call that never returns (the stack-guard failure).
                out.notes.append(f"lsr {flow.insns[k].addr:#x}: self not held, skipped")
                continue
            stop = frozenset(b for b in flow.cfg.order if b in idom and dominates(idom, b, lsr_blk))
            ivs: List[Tuple[int, int]] = []
            cands = flow.candidates(k, dest, (1, _MAX_FIELD), intervals=ivs)
            for lo, hi in ivs:
                if hi - lo <= _MAX_SPAN:
                    cands.update(v for v in range(max(lo, 1), hi + 1) if v < _MAX_FIELD)
            if not cands:
                continue
            default_n = max(cands) + 1
            run = lambda n, rejoin=frozenset(): flow.run_from(
                k + 1, {**base, dest: n}, stop, call_result=_call_result(ctx), field_value=_field_value, opaque=_opaque,
                object_escape=True, slots=base_slots, rejoin=rejoin)
            regions = {default_n: run(default_n)}
            # A field's run stops where it rejoins the unknown-field region: from there on the
            # code is every field's (and is subtracted below anyway).
            dflt_blocks = frozenset(regions[default_n].blocks)
            for n in sorted(cands):
                r = run(n, dflt_blocks)
                regions[n] = r
                for b, t in r.br_targets:
                    if t not in br_arms.get(b, ()) and core_va <= t < core_va + _ARM_REACH:
                        new_arms.setdefault(b, set()).add(t)
            results.append((k, dest, regions, default_n))
        if not new_arms:
            break
        end = insns[-1].addr + 4 if insns else 0
        for b, ts in new_arms.items():
            arms.setdefault(b, set()).update(ts)
            upto = max([upto] + [t + 4 for t in ts if t >= end])
    else:
        out.notes.append(f"core {core_va:#x}: arms still being discovered after {_ARM_ROUNDS} rounds")

    def dispatches(regions, default_n) -> bool:
        d = regions[default_n].blocks
        return any(r.blocks - d for n, r in regions.items() if n != default_n)
    keep = _outermost(flow, idom, [k for k, _d, rg, dn in results if dispatches(rg, dn)])
    for k, dest, regions, default_n in results:
        if k not in keep:
            if dispatches(regions, default_n):
                out.notes.append(f"lsr {flow.insns[k].addr:#x}: inside another field's handler, skipped")
            continue
        dflt = regions[default_n]
        onlys = {n: r.blocks - dflt.blocks for n, r in regions.items() if n != default_n}
        onlys = {n: o for n, o in onlys.items() if o}
        # blocks every field reaches but an unknown one does not (the in-range side of a
        # gate) are not any one field's handler
        shared = set.intersection(*onlys.values()) if len(onlys) > 1 else set()
        for n, r in regions.items():
            if n not in onlys:
                continue
            only = onlys[n]
            calls = [c for c in r.calls if flow._block_of.get(c.k) in only]
            if own_slots and _writes_foreign_object(ctx, flow, only, calls, own_slots, own_imps):
                # Handed self, but this field's handler fills ANOTHER class's ivars: a class can
                # pass itself to another class's engine (f27 TestGrForeignEngine), whose stores
                # go through that class's ivar-offset variables.
                out.notes.append(f"field {n}: handler uses another class's ivars, skipped")
                continue
            fd = out.fields.get(n) or FieldDispatch(n)
            fd.handler = fd.handler or next((b for b in r.order if b in only and b not in shared),
                                            next((b for b in r.order if b in only), None))
            classes: List[str] = list(fd.element_classes)
            elem_obj = None
            for c in calls:
                fd.calls.append((c.addr, c.target))
                if (fd.element_core is None and c.target in core_index
                        and c.args.get('x0') not in (SELF, READER)):
                    fd.element_core = core_index[c.target]
                    elem_obj = c.args.get('x0')
                for v in c.args.values():
                    name = _class_name_at(ctx, v)
                    if name in known and name not in classes:
                        classes.append(name)
            fd.element_classes = tuple(classes)
            # The element object(s): the one handed to the ReadAllFrom core, the result of a
            # call handed the element class (objc_alloc / objc_opt_new / [Cls alloc]), and the
            # result of an init... sent to one of those (by convention -init returns it).
            elems: Set[int] = {elem_obj} if elem_obj is not None else set()
            for _pass in range(2):
                for c in calls:
                    x0 = c.args.get('x0')
                    if _class_name_at(ctx, x0) in known:
                        elems.add(_ret_value(c.k))
                    elif x0 in elems and (_selector_of(ctx, c) or '').startswith('init'):
                        elems.add(_ret_value(c.k))
            if elems and fd.adder_ivar is None:
                for c in calls:
                    recv = c.args.get('x0')
                    if not elems & {c.args.get('x1'), c.args.get('x2'), c.args.get('x3')}:
                        continue
                    if recv is not None and _FIELD_BASE <= recv < _FIELD_BASE + (1 << 24):
                        # [self->_array addObject:element]: the array IS the ivar
                        off = recv - _FIELD_BASE
                        if off in array_offsets:
                            fd.adder, fd.adder_ivar = c.target, off_to_ivar.get(off)
                            break
                        continue
                    if recv != SELF:
                        continue
                    # x1 for an objc_direct C function, x2 for a method IMP or a message send
                    # (x1 = _cmd)
                    lit = [v for a, v in c.args.items() if a != 'x0' and v in array_offsets]
                    if len(lit) == 1:
                        # a generic helper handed (self, offset, element): the array ivar
                        # at that byte offset (f25's PBAppendMessageAtOffset)
                        fd.adder, fd.adder_ivar = c.target, off_to_ivar.get(lit[0])
                        break
                    sel = _selector_of(ctx, c)
                    tgt = sel_to_imp.get(sel, c.target) if sel is not None else c.target
                    off = _adder_array_ivar(ctx, tgt, array_offsets) if tgt else None
                    if fd.adder is None:
                        fd.adder = c.target
                    if off is not None:
                        fd.adder, fd.adder_ivar = c.target, off_to_ivar.get(off)
                        break
            out.fields[n] = fd


def _slots_loaded(ctx, va: Optional[int]) -> FrozenSet[int]:
    """The ivar-offset-variable addresses the function at *va* loads (``adrp`` + ``ldrsw``)."""
    from macho.memory import _ctx_cache
    if va is None:
        return frozenset()
    memo = _ctx_cache(ctx, "_dispatch_eval_slot_loads", dict)
    if va not in memo:
        try:
            ins = disasm(ctx, va, max_insns=256, stop_at_ret=True)
        except Exception:
            ins = []
        memo[va] = frozenset(sl for _i, sl in ivar_slot_loads(ins))
    return memo[va]


def _block_slot_loads(flow: Flow, blocks: Set[int]) -> Set[int]:
    """Addresses of the 4-byte ivar-offset loads (``ldrsw Xd, [Xb, #o]``) in *blocks*, the base
    register's value taken from its reaching definition -- the ``adrp`` of the offset page is
    usually hoisted out of the handler into the preamble."""
    out: Set[int] = set()
    for b in blocks:
        first = flow._first_in_block[b]
        for k in range(first, first + len(flow.cfg.blocks[b])):
            ins = flow.insns[k]
            if ins.mnemonic != 'ldrsw':
                continue
            ops = split_ops(ins.op_str)
            pm = parse_mem(ops[1]) if len(ops) == 2 else None
            if pm is None or pm.index is not None:
                continue
            page = flow.const_before(k, pm.base)
            if page is not None:
                out.add(page + pm.disp)
    return out


def _writes_foreign_object(ctx, flow: Flow, blocks: Set[int], calls, own_slots: FrozenSet[int],
                           own_imps: FrozenSet[int]) -> bool:
    """Positive evidence that a field handler fills ANOTHER class's object: it (or a function it
    hands self to) uses ivar-offset variables, none of them this class's, and it calls none of
    this class's methods.  A handler that touches no ivar-offset variable at all (a generic
    helper handed a literal offset) is not evidence either way."""
    all_slots = frozenset(getattr(ctx, "_ivar_offset_slots", None) or ())
    used = _block_slot_loads(flow, blocks) & all_slots
    for c in calls:
        if c.target in own_imps:
            return False
        used |= {v for v in c.args.values() if v in all_slots}     # handed an offset variable
        if c.args.get('x0') == SELF and _in_image_text(ctx, c.target):
            used |= _slots_loaded(ctx, c.target) & all_slots
    return bool(used) and not (used & own_slots)


def evaluate_class(ctx, cls, core_index: Dict[int, str]) -> ClassDispatch:
    """Decode *cls*'s readFrom: dispatch (see the module docstring).  Memoised per class on
    *ctx*: the element-by-number and element-by-ivar consumers share one evaluation.  The
    result depends on *core_index*, so it is memoised only for the image's own index (the
    one cached on *ctx* as ``_readfrom_core_index``) and for an empty one; any other index
    is evaluated afresh."""
    from macho.memory import _ctx_cache
    if not core_index:
        key = (cls.vmaddr, "empty")
    elif core_index is getattr(ctx, "_readfrom_core_index", None):
        key = (cls.vmaddr, "image")
    else:
        key = None
    memo = _ctx_cache(ctx, "_dispatch_eval_cache", dict)
    if key is not None and key in memo:
        return memo[key]
    out = ClassDispatch(cls.name)
    if key is not None:
        memo[key] = out
    if getattr(ctx, "_function_entries", None) is None:
        out.notes.append("function index not built (proto.dispatch.build_function_index): "
                         "function boundaries from the core index and the class's own methods only")
    entries = _known_entries(ctx, cls, core_index)
    cores, notes = find_cores(ctx, cls, entries)
    out.notes.extend(notes)
    for core_va, entry in cores:
        out.cores.append(core_va)
        try:
            _decode_core(ctx, core_va, entry, cls, core_index, out, entries)
        except Exception as exc:                # prototype: report, don't hide
            out.notes.append(f"core {core_va:#x}: {type(exc).__name__}: {exc}")
    return out
