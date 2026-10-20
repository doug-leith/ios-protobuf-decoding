"""proto/dispatch_eval.py -- decode a class's readFrom: field dispatch by evaluation.

The extraction path's readFrom: reader: :mod:`proto.repeated` takes repeated-message element
classes and their array ivars from it, :mod:`proto.mapfields` a map's value classes.

For field N: which handler runs, which element class it builds, and which ivar it appends
to.  Answered by running the reader:

1. **Which function dispatches.**  ``-[Cls readFrom:]`` is entered with x0 = SELF and x2 =
   READER, two opaque tokens.  A call is followed only when it is handed THIS object (x0 =
   SELF; ``objc_retain`` and the ARC return-value handshake return their argument), so a
   nested element's reader -- handed a freshly allocated object -- is never mistaken for
   ours.  (The reader itself is not required: readers retain it and use the retain's result,
   which cannot be equated with READER without the runtime's names.)  The first function so
   reached that extracts a field number (``lsr Wf, Wtag, #3``) is the dispatch core; the
   constants it was handed (a data table chosen by a ``csel``) come along as values.
2. **What runs for field N.**  The core is propagated from its entry to the ``lsr``, then run
   from just after it with Wf = N, through calls (:meth:`proto.arm64_eval.Flow.run_from`),
   until control re-enters a block that dominates the ``lsr`` -- the next tag read.  Branches
   the analysis cannot decide (has-bits, wire type, error checks) are followed both ways; a
   jump-table ``br`` is decided by N.  Only the outermost ``lsr`` counts: one dominated by
   another is a nested message's or a map entry's reader inlined into a handler.  N's handler
   is what N reaches and an unknown field number (one past every compared value) does not.
3. **What the handler does**, read off call arguments: the element core is a call into a
   known ``ReadAllFrom`` core handed an object other than self / the reader; the element
   class is any known proto class whose ``class_t`` address is an argument (``objc_alloc`` /
   ``objc_opt_new``, however the address was formed); the adder is a call handed x0 = SELF
   and that element object (in x2 for a method IMP, x1 = ``_cmd``; in x1 for an
   ``objc_direct`` C function), and its ivar is the array ivar whose offset variable it loads
   (:func:`proto.repeated._adder_array_ivar`).

Stack slots use the object-escape rule (:class:`proto.arm64_eval._Machine`): a callee handed
a frame address may write from it upward only, and does not keep it past its return.  An
older toolchain spills the element object across such a call (``str x0,[sp,#8]`` ... ``add
x1,sp,#0x60; bl`` ... ``ldr x1,[sp,#8]; bl adder``), which clearing every slot would lose.

Candidate field numbers come from :meth:`Flow.candidates` (every compare point and every
ordered gate's interval).  Jump-table arms the CFG lacks are found by evaluating the ``br``
under each N; the CFG is rebuilt with them and the run repeated.  The CFG is seeded with the
decoded jump tables (:func:`proto.dispatch._jump_table_arm_addrs`): a control ``br`` ahead of
the ``lsr`` (has-bits bookkeeping) has an index the fixpoint cannot know, and without its arms
the ``lsr`` is unreachable.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

from macho.disasm import _norm_reg
from macho.memory import READ_ERRORS, _ctx_cache, _ctx_store
from macho.classlist import class_name_at
from proto.arm64cfg import dominators, dominates
from proto.arm64_operands import split_ops
from proto.arm64_eval import Flow, _MAX_GATE_SPAN
from proto.repeated import _adder_array_ivar
from proto.callees import callee_name, stub_selector
from proto.function_body import function_body
from proto.eval_tokens import (SELF, READER, TOKEN_BASE, FIELD_BASE, opaque, ret_value,
                               object_model)
from proto import dispatch as D
from proto.models import record_analysis_failure

log = logging.getLogger(__name__)

_MAX_FIELD = 1 << 29                            # protobuf field numbers are 1 .. 2^29 - 1
# [cap:INPUT-SANITY — verified 2026-10-18] how many calls deep from -readFrom: a dispatch core
# is looked for, and how many rounds of evaluated jump-table arms extend a core (a round that
# finds none ends the loop; the last round leaves a note).  Raising both 4 -> 16 changed no
# output on any of the 12 ios_decoder/protos targets or iOS 27 / macOS 27 GeoServices.
_DESCEND_DEPTH = 4
_ARM_ROUNDS = 4
# [cap:INPUT-SANITY] a br target further than this past the core's entry is not taken as one of
# its arms (the largest GeoServices reader is ~5 KB; this is a runaway guard, not a window).
_ARM_REACH = 0x40000

_ARRAY_ENCS = ('@"NSMutableArray"', '@"NSArray"')


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
    if x1 is not None and not opaque(x1) and callee_name(ctx, call.target) == '_objc_msgSend':
        try:
            return ctx.read_cstring(x1)
        except (ValueError, KeyError, IndexError, UnicodeDecodeError):
            return None
    return None


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

def _known_entries(ctx, cls, core_index: Dict[int, str]) -> "D.FunctionEntries":
    """Addresses known to start a function: every method IMP (recorded on *ctx* by
    :func:`proto.dispatch.build_function_index`), every ReadAllFrom core and *cls*'s own
    methods.  Functions do not overlap, so a function ends at the next one (the CFG-reachable
    end alone runs a tail ``b`` into the function it jumps to, e.g. a ``-readFrom:`` wrapper into
    the engine laid out after it).  The image-wide part (index and core index) is built once
    and reused while both are unchanged; a class adds only methods the index does not hold."""
    index = D.function_entries(ctx)
    key = (id(index), id(core_index), len(core_index))
    memo = getattr(ctx, "_known_entries_base", None)
    if memo is None or memo[0] != key:
        base = D.FunctionEntries(index.members.union(core_index)) if core_index else index
        memo = _ctx_store(ctx, "_known_entries_base", (key, index, core_index, base))
    base = memo[3]
    extra = [m.imp for m in cls.methods if m.imp and m.imp not in base.members]
    return D.FunctionEntries(base.members.union(extra)) if extra else base


def _class_name_at(ctx, va: Optional[int]) -> Optional[str]:
    """Name of the ObjC class whose ``class_t`` is at *va* (an argument value: None for an
    opaque token or an unknown value).  Callers accept it only when it is a known proto
    class."""
    if va is None or not 0 < va < TOKEN_BASE:
        return None
    return class_name_at(ctx, va)


def _seed_br_arms(ctx, insns) -> Dict[int, Set[int]]:
    """``{br address: arms}`` to complete a CFG with before any evaluation: each ``br``'s decoded
    table (:func:`proto.dispatch._jump_table_arm_addrs`, which also covers an index bounded by
    an ``and`` mask rather than a ``cmp`` gate -- ``and w8, w0, #7`` on the wire type)."""
    return D._jump_table_arm_addrs(ctx, insns, per_br=True)


def _as_entries(entries) -> "D.FunctionEntries":
    """*entries* (any iterable of addresses, or None) as :class:`proto.dispatch.FunctionEntries`."""
    return entries if isinstance(entries, D.FunctionEntries) else D.FunctionEntries(entries or ())


def _function_insns(ctx, va: int, entries: Optional[List[int]] = None,
                    arms: Optional[Dict[int, Set[int]]] = None):
    """The instructions of the function at *va* (:func:`proto.function_body.function_body`):
    what its entry reaches inside its extent, which also ends at the next known function entry
    (*entries*: method IMPs, ReadAllFrom cores), following each ``br``'s decoded table and the
    *arms* found by evaluation.  [] when *va* cannot be read."""
    try:
        return function_body(ctx, va, _as_entries(entries), arms)
    except READ_ERRORS:
        return []


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

def find_cores(ctx, cls, entries: Optional[List[int]] = None, flows: Optional[Dict[int, tuple]] = None
               ) -> Tuple[List[Tuple[int, Dict[str, int]]], List[str]]:
    """``([(core_va, entry_registers)], notes)``: the functions reached from ``-readFrom:`` by
    calls handed this object and this reader that extract a field number.  *flows*, when
    given, receives ``{core_va: (insns, br_arms, Flow)}``: the core's first-round evaluation
    setup, which :func:`_decode_core` would otherwise rebuild."""
    m = cls.get_method("readFrom:")
    notes: List[str] = []
    if m is None or not m.imp:
        return [], ["no readFrom:"]
    found: List[Tuple[int, Dict[str, int]]] = []
    seen: Set[int] = set()
    entries = _as_entries(entries)
    tails = entries.members
    objs = object_model(ctx)

    def descend(va: int, regs: Dict[str, int], depth: int) -> None:
        if va in seen or depth > _DESCEND_DEPTH:
            return
        seen.add(va)
        insns = _function_insns(ctx, va, entries=entries)
        if not insns:
            return
        per_br = _seed_br_arms(ctx, insns)
        flow = D.decoded_flow(ctx, insns)
        region = flow.run_from(0, regs, objects=objs, tail_targets=tails)
        # A core extracts a field number on a path from ITS OWN entry.
        if any(flow._block_of.get(k) in region.blocks for k, _d in _lsr3_sites(flow)):
            found.append((va, regs))
            if flows is not None:
                flows[va] = (insns, per_br, flow)
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
                 out: ClassDispatch, entries: Optional[List[int]] = None,
                 first: Optional[tuple] = None) -> None:
    """Run *cls*'s dispatch core at *core_va* for each field number into *out*.  *first* is
    :func:`find_cores`' ``(insns, br_arms, Flow)`` for the core (round 0 needs exactly that)."""
    array_offsets = frozenset(iv.offset for iv in cls.ivars if iv.type_enc in _ARRAY_ENCS)
    own_slots = frozenset(iv.offset_slot for iv in cls.ivars if iv.offset_slot)
    own_imps = frozenset(mm.imp for mm in cls.methods if mm.imp)
    off_to_ivar = {iv.offset: iv.name for iv in cls.ivars}
    sel_to_imp = {mm.name: mm.imp for mm in cls.methods if mm.name and mm.imp}
    # Known proto classes: every class with a ReadAllFrom core, plus the image's whole proto
    # class set when extraction has computed it (proto.protoclass_set caches it on ctx); a
    # message class whose readFrom: does not resolve to a core of its own is still one.
    known = set(core_index.values()) | set(getattr(ctx, "_proto_class_names_cache", None) or ())
    objs = object_model(ctx)

    arms: Dict[int, Set[int]] = {}             # br address -> targets found by evaluation
    for _round in range(_ARM_ROUNDS):
        # CFG completion, per br: its decoded table (as every Flow user), so a control ``br``
        # ahead of the lsr (has-bits bookkeeping, whose index the fixpoint cannot know) does
        # not cut the lsr off; targets found by evaluating a ``br`` under N are added on top.
        if _round == 0 and first is not None:
            insns, br_arms, flow = first
        else:
            insns = _function_insns(ctx, core_va, entries, arms)
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
            base = flow.propagate(entry, [k], objects=objs, slots_out=slots_at).get(k)
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
            scan = flow.candidates(k, dest, (1, _MAX_FIELD))
            cands = scan.values
            for lo, hi in scan.intervals:
                if hi - lo <= _MAX_GATE_SPAN:      # one imm12 gate's reach
                    cands.update(v for v in range(max(lo, 1), hi + 1) if v < _MAX_FIELD)
            if not cands:
                continue
            default_n = max(cands) + 1
            run = lambda n, rejoin=frozenset(): flow.run_from(
                k + 1, {**base, dest: n}, stop, objects=objs, slots=base_slots, rejoin=rejoin)
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
        for b, ts in new_arms.items():
            arms.setdefault(b, set()).update(ts)
    else:
        detail = f"core {core_va:#x}: arms still being discovered after {_ARM_ROUNDS} rounds"
        out.notes.append(detail)
        record_analysis_failure(ctx, cls.name, "readFrom: dispatch", detail)

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
                        elems.add(ret_value(c.k))
                    elif x0 in elems and (_selector_of(ctx, c) or '').startswith('init'):
                        elems.add(ret_value(c.k))
            if elems and fd.adder_ivar is None:
                for c in calls:
                    recv = c.args.get('x0')
                    if not elems & {c.args.get('x1'), c.args.get('x2'), c.args.get('x3')}:
                        continue
                    if recv is not None and FIELD_BASE <= recv < FIELD_BASE + (1 << 24):
                        # [self->_array addObject:element]: the array IS the ivar
                        off = recv - FIELD_BASE
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
    """The ivar-offset-variable addresses the function at *va* loads (``ldrsw`` from a base
    whose reaching definition is a constant page, :meth:`Flow.slot_load_address`), over its
    whole body (:func:`_function_insns`, bounded by the image's function index)."""
    if va is None:
        return frozenset()
    memo = _ctx_cache(ctx, "_dispatch_eval_slot_loads", dict)
    if va not in memo:
        ins = _function_insns(ctx, va, entries=D.function_entries(ctx))
        flow = D.decoded_flow(ctx, ins) if ins else None
        memo[va] = frozenset(sl for k in range(len(ins)) if flow is not None
                             and (sl := flow.slot_load_address(k)) is not None)
    return memo[va]


def _block_slot_loads(flow: Flow, blocks: Set[int]) -> Set[int]:
    """Addresses of the 4-byte ivar-offset loads (``ldrsw Xd, [Xb, #o]``) in *blocks*, the base
    register's value taken from its reaching definition -- the ``adrp`` of the offset page is
    usually hoisted out of the handler into the preamble."""
    out: Set[int] = set()
    for b in blocks:
        first = flow._first_in_block[b]
        for k in range(first, first + len(flow.cfg.blocks[b])):
            addr = flow.slot_load_address(k)
            if addr is not None:
                out.add(addr)
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
    flows: Dict[int, tuple] = {}
    cores, notes = find_cores(ctx, cls, entries, flows)
    out.notes.extend(notes)
    for core_va, entry in cores:
        out.cores.append(core_va)
        try:
            _decode_core(ctx, core_va, entry, cls, core_index, out, entries, flows.get(core_va))
        except (NameError, ImportError):
            raise
        except Exception as exc:
            detail = f"core {core_va:#x}: {type(exc).__name__}: {exc}"
            out.notes.append(detail)
            record_analysis_failure(ctx, cls.name, "readFrom: dispatch", detail)
    return out
