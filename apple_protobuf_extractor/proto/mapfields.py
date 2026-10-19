"""proto/mapfields.py — protobuf ``map<K, V>`` field recovery (TODO #41).

A protobuf map field compiles to an ObjC ``NSMutableDictionary`` ivar whose
``@encode`` string carries no key/value type, and on the wire it is a *repeated*
length-delimited field whose entries are messages ``{key = 1, value = 2}``.  The
ivar alone therefore says "dictionary" and nothing else; this module recovers the
rest from the two serializers:

* **writeTo:** emits each entry as ``PlaceMark(writer, &scratch, F)`` — the begin
  of a length-delimited sub-message with the MAP field's number ``F`` — then the
  key through the write helper called with field ``1``, the value through the one
  called with field ``2``, then ``RecallMark``.  Two code shapes wrap that body:

  - **block** — ``[self->_dict enumerateKeysAndObjectsUsingBlock:&block]``: the entry
    code lives in the block's *invoke* function (the function pointer at
    ``block+0x10``), not ``writeTo:`` itself.  Found by
    :func:`scan_block_enumerated_maps`.
  - **inline loop** — a ``countByEnumeratingWithState:`` loop in ``writeTo:`` itself;
    the write sites already bind the begin-mark to the ivar, so the entry body is the
    code after that write (:func:`entry_from_bound_write`).

  Both feed :func:`analyze_entry`, which reads the field number and the key/value
  *write helpers* (plus, as a cross-check, the NSNumber unboxing selector feeding
  each).  A helper's meaning is NOT hard-coded: every write helper is shared by all
  fields of one wire type, so its type is the unanimous type of the ivars that use it
  binary-wide (:func:`record_helper_votes` / :func:`helper_kind` — the same ground-truth
  mechanism as ``write_helpers._identify_string_write_helpers``).

* **readFrom:** must *create* a message value, so the handler for field ``F`` allocates the
  value class or calls its ``ClsReadAllFrom`` core.  :func:`readfrom_value_classes` returns
  those classes from the dispatch evaluator (:mod:`proto.dispatch_eval`), which runs the
  outermost field-number dispatch with ``F`` (so a map entry's own nested ``value = 2`` is
  not mistaken for top-level field 2).

``writeTo:`` alone names no value class (``writeSubmessage`` dispatches on the object's
runtime type), which is why the reader side is needed for message values.

Imports only ``macho.*`` plus sibling ``proto`` modules (never ``proto.extractor``).
Every function degrades to "not recovered" (``None``) rather than guessing; the
extractor then keeps the flagged ``bytes`` fallback.  See LIMITATIONS.md (1).
"""
from __future__ import annotations

import logging
from collections import Counter
from dataclasses import dataclass
from typing import Dict, FrozenSet, List, Optional, Sequence, Set, Tuple

from macho.memory import BinaryContext, _ctx_cache
from macho.classlist import ClassList, ObjcClass, ObjcIvar
from macho.disasm import disasm, _parse_imm, _norm_reg
from proto.callees import real_target, stub_selector

from proto.arm64cfg import (
    split_ops, mem_operand, _next_imp,
)
from proto.writeto import _writeto_field_number_before
from proto.write_helpers import _classify_write_helper, _refine_scalar_by_family
from proto.models import FieldLabel, ProtoField, ProtoMessage
from proto.protocore import _SCALAR_ENC, _CLASS_TO_PROTO
from proto.protoclass_set import _proto_class_set
from proto.dispatch import listing_flow
from proto.arm64_eval import Objects
from proto.dispatch_eval import evaluate_class

log = logging.getLogger(__name__)


def _addr_to_name(ctx, addr, offset_to_name):
    """Read the u32 ivar byte-offset at *addr* and map to an ivar name.  The
    map-membership check IS the validator (a stray read almost never equals a byte
    offset this class declares), so no hard section gate is needed."""
    if addr is None:
        return None
    try:
        return offset_to_name.get(ctx.read_u32(addr))
    except (NameError, ImportError):
        raise
    except Exception:
        return None

#: ObjC ivar classes a protobuf ``map<>`` field compiles to.
MAP_OBJC_CLASSES = frozenset({"NSDictionary", "NSMutableDictionary"})

#: ivar ``@encode`` strings of those classes (what the field loop tests against).
MAP_IVAR_ENCS = frozenset(f'@"{c}"' for c in MAP_OBJC_CLASSES)

#: proto scalar types legal as a ``map<>`` KEY (proto3: integral/bool/string only —
#: never float/double/bytes/message/enum).
MAP_KEY_TYPES = frozenset({
    "string", "bool", "int32", "int64", "uint32", "uint64",
    "sint32", "sint64", "fixed32", "fixed64", "sfixed32", "sfixed64",
})

# A map entry has exactly two sub-fields.
_KEY_FIELD, _VALUE_FIELD = 1, 2

# The ObjC runtime call that drives a block-based map write.
_ENUMERATE_SELECTOR = "enumerateKeysAndObjectsUsingBlock:"

# Stack-block layout (clang Block ABI): isa @+0, flags/reserved @+8, invoke @+0x10.
_BLOCK_INVOKE_OFFSET = 0x10

# [cap:INPUT-SANITY] a runaway backstop for the block-invoke disassembly, NOT a tuned
# bound: the invoke function ends at its own ``ret`` (the scan stops there), and the
# entry writer is ~40 instructions.  A body with no ``ret`` inside the window is
# rejected (never truncated-and-guessed).
_BLOCK_INVOKE_MAX_INSNS = 1024

# NSNumber unboxing selector → proto types that storage is consistent with.  Used only
# as an INDEPENDENT CROSS-CHECK of the helper-derived type (the helper decides the type).
_UNBOX_TYPES: Dict[str, FrozenSet[str]] = {
    "intValue":              frozenset({"int32", "sint32", "sfixed32", "bool"}),
    "unsignedIntValue":      frozenset({"uint32", "fixed32"}),
    "integerValue":          frozenset({"int64", "sint64", "sfixed64", "int32"}),
    "longLongValue":         frozenset({"int64", "sint64", "sfixed64"}),
    "unsignedLongLongValue": frozenset({"uint64", "fixed64"}),
    "unsignedLongValue":     frozenset({"uint64", "fixed64"}),
    "longValue":             frozenset({"int64", "sint64", "sfixed64"}),
    "boolValue":             frozenset({"bool"}),
    "doubleValue":           frozenset({"double"}),
    "floatValue":            frozenset({"float"}),
}


@dataclass(frozen=True)
class MapEntryWriter:
    """What ``writeTo:`` says about one map field's entries (types still unresolved —
    helper VAs, not type names; see :func:`resolve_map_types`)."""
    number: int                       # the MAP field number (PlaceMark's field arg)
    key_helper: int                   # write helper called with field# 1
    value_helper: int                 # write helper called with field# 2
    key_sel: Optional[str] = None     # NSNumber unboxing selector feeding the key, if any
    value_sel: Optional[str] = None   # ... feeding the value, if any
    shape: str = "block"              # 'block' | 'inline-loop' (diagnostic only)


@dataclass(frozen=True)
class MapTypes:
    """Resolved map types.  ``key_type`` / ``value_type`` are proto type names; a
    message value has ``value_type == "message"`` and carries its ObjC class in
    ``value_class`` (resolved to the proto message name by the emitter; ``None`` when
    the write helper proved a message but its class could not be named).  ``None`` =
    not recovered, with ``reason`` saying which part and why."""
    key_type: Optional[str]
    value_type: Optional[str]
    value_class: Optional[str] = None
    reason: Optional[str] = None


# ── Register / def-use helpers ────────────────────────────────────────────────
#
# Every helper reads a listing through its :class:`proto.arm64_eval.Flow`
# (:func:`proto.dispatch.listing_flow`): ``flow.insns`` is the listing, and a register's
# definition is its reaching definition over the listing's CFG.


def _reaching_def(flow, i: int, reg: str) -> Optional[int]:
    """Index of the one instruction whose definition of register *reg* (normalised ``xN``)
    reaches ``flow.insns[i]``, by reaching definitions over the listing's CFG.  A call
    defines every caller-saved register (it clobbers them), so a value held across a call in
    a caller-saved register is not traced through it.  ``None`` when the register is a
    live-in, when more than one definition reaches (the value depends on the path), or when
    ``insns[i]`` is unreachable."""
    defs = flow.defs_before(i, reg)
    if len(defs) != 1:
        return None
    (d,) = defs
    return d if d >= 0 else None


def _sp_offset(ins) -> Optional[int]:
    """``K`` of ``add xD, sp, #K`` (``0`` for the ``mov xD, sp`` a block at the very
    bottom of the frame compiles to); else None — i.e. the stack offset *xD* points at."""
    ops = split_ops(ins.op_str)
    if ins.mnemonic == 'add' and len(ops) == 3 and ops[1] == 'sp' and ops[2].startswith('#'):
        return _parse_imm(ops[2])
    if ins.mnemonic == 'mov' and len(ops) == 2 and ops[1] == 'sp':
        return 0
    return None


def _pc_relative_address(flow, i: int, reg: str) -> Optional[int]:
    """Address materialised into *reg* at ``insns[i]`` by ``adrp reg,#page ;
    add reg,reg,#imm`` (the reaching pair — a body re-uses its scratch register for
    many unrelated pages).  None for any other defining form."""
    insns = flow.insns
    d = _reaching_def(flow, i, reg)
    if d is None:
        return None
    add = insns[d]
    ops = split_ops(add.op_str)
    if (add.mnemonic != 'add' or len(ops) != 3 or _norm_reg(ops[0]) != reg
            or _norm_reg(ops[1]) != reg or not ops[2].startswith('#')):
        return None
    imm = _parse_imm(ops[2])
    p = _reaching_def(flow, d, reg)
    if imm is None or p is None or insns[p].mnemonic != 'adrp':
        return None
    pops = split_ops(insns[p].op_str)
    page = _parse_imm(pops[1]) if len(pops) == 2 else None
    return None if page is None else page + imm


def _offset_var_address(flow, i: int, offreg: str) -> Optional[int]:
    """Address of the ivar-offset variable whose value is in *offreg* at ``insns[i]``:
    the reaching ``ldrsw offreg,[base,#k]`` with ``base`` the reaching ``adrp`` page
    (``+ add``) — or the PC-relative literal ``ldrsw offreg, #ADDR`` a standalone image
    uses.  Reaching definitions only: unlike :func:`proto.arm64cfg._resolve_offset_addr`
    (which scans a block prefix for the FIRST matching ``adrp+add``) this is safe over a
    whole function, where an earlier unrelated ``adrp x8 ; add x8,x8,#o`` would shadow the
    page actually feeding this load."""
    insns = flow.insns
    d = _reaching_def(flow, i, offreg)
    if d is None or insns[d].mnemonic not in ('ldrsw', 'ldr'):
        return None
    mem = mem_operand(insns[d].op_str)
    if mem is None:
        ops = split_ops(insns[d].op_str)
        return _parse_imm(ops[1]) if len(ops) == 2 and ops[1].startswith('#') else None
    if mem[2] is not None:
        return None
    b = _reaching_def(flow, d, mem[1])
    if b is None:
        return None
    if insns[b].mnemonic == 'adrp':
        ops = split_ops(insns[b].op_str)
        page = _parse_imm(ops[1]) if len(ops) == 2 else None
        return None if page is None else page + mem[3]
    base = _pc_relative_address(flow, d, mem[1])
    return None if base is None else base + mem[3]


def _trace_ivar(ctx: BinaryContext, flow, i: int, reg: str,
                offset_to_name: Dict[int, str]) -> Optional[str]:
    """Name of the ivar whose value is in *reg* at ``insns[i]``: follow ``mov`` chains
    back to the defining ``ldr xD,[Xself, Xoff]`` (``Xoff`` = a loaded ivar-offset
    variable → resolved to the ivar by :func:`_addr_to_name`) or the
    immediate-offset form.  The declared-offset membership test IS the validator."""
    insns, seen = flow.insns, set()
    while (i, reg) not in seen:
        seen.add((i, reg))
        d = _reaching_def(flow, i, reg)
        if d is None:
            return None
        ins = insns[d]
        ops = split_ops(ins.op_str)
        if ins.mnemonic == 'mov' and len(ops) == 2 and _norm_reg(ops[1]):
            reg, i = _norm_reg(ops[1]), d
            continue
        if ins.mnemonic == 'ldr':
            mem = mem_operand(ins.op_str)
            if mem is None:
                return None
            if mem[2] is not None:                      # [base, Xoff]
                return _addr_to_name(
                    ctx, _offset_var_address(flow, d, mem[2]), offset_to_name)
            if mem[3] == 0:                             # [Xb] with Xb = add Xself, Xoff
                a = _reaching_def(flow, d, mem[1])
                aops = split_ops(insns[a].op_str) if a is not None else []
                if (a is not None and insns[a].mnemonic == 'add' and len(aops) == 3
                        and not aops[2].startswith('#') and _norm_reg(aops[2])):
                    return _addr_to_name(
                        ctx, _offset_var_address(flow, a, _norm_reg(aops[2])),
                        offset_to_name)
                return None
            return offset_to_name.get(mem[3])           # [base, #off]
        return None
    return None


def _trace_unbox_selector(ctx: BinaryContext, flow, i: int) -> Optional[str]:
    """Selector of the objc call that produced the value passed in ``x1`` at the
    write-helper call ``insns[i]`` — the NSNumber unboxing step (``[v longLongValue]``)
    for a scalar key/value, or ``None`` when the object is passed straight through
    (string / message / bytes) or the chain can't be followed."""
    reg, j, seen = 'x1', i, set()
    while (j, reg) not in seen:
        seen.add((j, reg))
        d = _reaching_def(flow, j, reg)
        if d is None:
            return None
        ins = flow.insns[d]
        if ins.mnemonic == 'bl':
            return stub_selector(ctx, _parse_imm(ins.op_str)) if reg == 'x0' else None
        ops = split_ops(ins.op_str)
        if ins.mnemonic == 'mov' and len(ops) == 2 and _norm_reg(ops[1]):
            reg, j = _norm_reg(ops[1]), d
            continue
        return None
    return None


# ── Entry-body analysis (shared by both writeTo: shapes) ──────────────────────


def analyze_entry(ctx: BinaryContext, insns: Sequence, begin_idx: int) -> Optional[MapEntryWriter]:
    """Analyse one map-entry body in the linear instruction list *insns*, whose
    BEGIN-submessage ``bl`` (stack-scratch ``x1``, literal field number ``F``) is at
    ``begin_idx``.  Returns the :class:`MapEntryWriter` or ``None`` unless the body is
    exactly ``begin(F) … write(1) … write(2) … end`` with ONE helper call per sub-field
    and a matching END mark (same scratch slot, no field number) — anything else
    (nested sub-messages, a second write of a sub-field, an unterminated body, a
    sub-field other than 1/2) is not a recognisable map entry."""
    flow = listing_flow(ctx, insns)
    begin = insns[begin_idx]
    slot = _scratch_slot_of(flow, begin_idx)       # shared by the begin and end marks
    if begin.mnemonic != 'bl' or slot is None:
        return None
    number = _writeto_field_number_before(insns, begin_idx)
    if number is None or number < 1:
        return None

    writes: Dict[int, Tuple[int, int]] = {}            # sub-field -> (helper_va, insn index)
    for j in range(begin_idx + 1, len(insns)):
        ins = insns[j]
        if ins.mnemonic != 'bl':
            continue
        target = _parse_imm(ins.op_str)
        fn = _writeto_field_number_before(insns, j)
        j_slot = _scratch_slot_of(flow, j)
        if j_slot is not None:
            if fn is None and j_slot == slot:                         # END mark
                break
            return None                                               # nested begin / foreign scratch
        if fn in (_KEY_FIELD, _VALUE_FIELD):
            if fn in writes or target is None:
                return None
            writes[fn] = (target, j)
        elif fn is not None:
            return None                                               # not a {key, value} entry
    else:
        return None                                                   # no END mark
    if _KEY_FIELD not in writes or _VALUE_FIELD not in writes:
        return None
    (kh, kj), (vh, vj) = writes[_KEY_FIELD], writes[_VALUE_FIELD]
    return MapEntryWriter(
        number=number, key_helper=kh, value_helper=vh,
        key_sel=_trace_unbox_selector(ctx, flow, kj),
        value_sel=_trace_unbox_selector(ctx, flow, vj))


def _scratch_slot_of(flow, k: int) -> Optional[int]:
    """Stack offset K of the ``add x1, sp, #K`` that defines ``x1`` as the argument of
    the call at ``insns[k]`` (the begin/end-mark idiom), else None.  A function that
    addresses its locals from the frame pointer says ``sub x1, x29, #K`` instead; that
    slot is reported as ``-K`` (never equal to an sp-relative one), which is all the
    begin/end pairing needs.  A call between the definition and *k* redefines ``x1``,
    so a stale scratch is never reported."""
    d = _reaching_def(flow, k, 'x1')
    if d is None:
        return None
    ins = flow.insns[d]
    ops = split_ops(ins.op_str)
    if ins.mnemonic == 'sub' and len(ops) == 3 and ops[1] == 'x29' and ops[2].startswith('#'):
        k_off = _parse_imm(ops[2])
        return None if k_off is None else -k_off
    return _sp_offset(ins)


# ── Shape A: enumerateKeysAndObjectsUsingBlock: ───────────────────────────────


def scan_block_enumerated_maps(
    ctx: BinaryContext, imp: int, imps_sorted: List[int],
    offset_to_name: Dict[int, str],
) -> Dict[str, MapEntryWriter]:
    """``{ivar_name: MapEntryWriter}`` for every ``[self->_dict
    enumerateKeysAndObjectsUsingBlock:&block]`` in the ``writeTo:`` at *imp*.

    The parent is its structural extent (``imp`` .. next method IMP — a hard upper bound
    that includes its out-of-line tail blocks), evaluated over its CFG
    (:meth:`proto.arm64_eval.Flow.propagate`, which models the stack frame).  For each
    enumerate call: the receiver (``x0``) traces to the dictionary ivar; ``x2`` is the stack
    block, whose invoke pointer is the 8-byte slot at ``x2 + 0x10`` as every path into the
    call leaves it; the invoke function's own body (to its ``ret``) is then analysed by
    :func:`analyze_entry`.  Unrecognised shapes are simply absent (the field keeps its
    flagged fallback)."""
    out: Dict[str, MapEntryWriter] = {}
    end = _next_imp(imps_sorted, imp)
    try:
        insns = disasm(ctx, imp, max_insns=max(64, (end - imp) // 4), stop_at_ret=False)
    except (NameError, ImportError):
        raise
    except Exception:
        return out
    calls = [i for i, ins in enumerate(insns) if ins.mnemonic == 'bl'
             and stub_selector(ctx, _parse_imm(ins.op_str)) == _ENUMERATE_SELECTOR]
    if not calls:
        return out
    flow = listing_flow(ctx, insns)
    slots: Dict[int, Dict[int, Tuple[int, int]]] = {}
    # a callee handed a pointer into the frame (a fast-enumeration state, say) may write
    # that object and upward, never the slots below it (Objects.object_escape)
    regs = flow.propagate({}, calls, Objects(object_escape=True), slots_out=slots)
    for i in calls:
        ivar = _trace_ivar(ctx, flow, i, 'x0', offset_to_name)
        blk = regs.get(i, {}).get('x2')
        slot = slots.get(i, {}).get(blk + _BLOCK_INVOKE_OFFSET) if blk is not None else None
        invoke = slot[1] if slot is not None and slot[0] == 8 else None
        if ivar is None or invoke is None or ivar in out:
            continue
        try:
            body = disasm(ctx, invoke, max_insns=_BLOCK_INVOKE_MAX_INSNS, stop_at_ret=True)
        except (NameError, ImportError):
            raise
        except Exception:
            continue
        if not body or body[-1].mnemonic not in ('ret', 'retaa', 'retab'):
            continue                                    # never analyse a truncated body
        body_flow = listing_flow(ctx, body)
        for k, b in enumerate(body):
            if b.mnemonic == 'bl' and _scratch_slot_of(body_flow, k) is not None:
                entry = analyze_entry(ctx, body, k)
                if entry is not None:
                    out[ivar] = entry
                break                                   # first begin only
    return out


# ── Shape B: inline enumeration loop (bound begin-mark) ──────────────────────


def entry_from_bound_write(ctx: BinaryContext, imp: int, imps_sorted: List[int],
                          w: dict) -> Optional[MapEntryWriter]:
    """The :class:`MapEntryWriter` for a bound ``writeTo:`` write *w* (at *imp*) that is a
    begin-submessage mark (already bound to the dictionary ivar, with its field number).
    The entry body is the code after it in the method's linear listing (``imp`` .. the next
    method IMP)."""
    if not w.get('bracket'):
        return None
    end = _next_imp(imps_sorted, imp)
    try:
        insns = disasm(ctx, imp, max_insns=max(64, (end - imp) // 4), stop_at_ret=False)
    except (NameError, ImportError):
        raise
    except Exception:
        return None
    k = next((i for i, x in enumerate(insns) if x.addr == w['write_addr']), None)
    if k is None:
        return None
    entry = analyze_entry(ctx, insns, k)
    if entry is None or entry.number != w.get('n'):
        return None
    return MapEntryWriter(**{**entry.__dict__, 'shape': 'inline-loop'})


def find_map_writers(
    ctx: BinaryContext, cls: ObjcClass, map_ivars: Sequence[ObjcIvar],
    bound_writes: Dict[str, dict], offset_to_name: Dict[int, str],
    confirmed_numbers: Dict[str, int],
) -> Dict[str, MapEntryWriter]:
    """Map-entry writers for *cls*'s dictionary ivars: the inline-loop shape from the
    binding writes (*bound_writes* = ``{ivar: write}``), else the block shape from
    :func:`scan_block_enumerated_maps`.  A writer is dropped if its number collides with
    another ivar's confirmed number (inconsistent evidence is never trusted)."""
    m = cls.get_method("writeTo:")
    if m is None or not m.imp or not map_ivars:
        return {}
    writers: Dict[str, MapEntryWriter] = {}
    imps_sorted = sorted(getattr(ctx, "_writeto_foreign_imps", None) or ())
    for iv in map_ivars:
        w = bound_writes.get(iv.name)
        if w is not None:
            e = entry_from_bound_write(ctx, m.imp, imps_sorted, w)
            if e is not None:
                writers[iv.name] = e
    pending = [iv for iv in map_ivars if iv.name not in writers]
    if pending:
        for name, e in scan_block_enumerated_maps(
                ctx, m.imp, imps_sorted, offset_to_name).items():
            if any(iv.name == name for iv in pending):
                writers[name] = e
    taken: Dict[int, str] = {}
    for name, n in confirmed_numbers.items():
        taken[n] = name
    out: Dict[str, MapEntryWriter] = {}
    for name, e in writers.items():
        owner = taken.get(e.number)
        if owner is not None and owner != name:
            log.debug("%s.%s: map field number %d collides with %s; ignored",
                      cls.name, name, e.number, owner)
            continue
        taken[e.number] = name
        out[name] = e
    return out


# ── Write-helper types (binary-wide ground truth) ─────────────────────────────


def _ivar_wire_kind(enc: str, proto_classes: FrozenSet[str]) -> Optional[str]:
    """Wire kind an ivar of encoding *enc* proves for its write helper: a proto scalar
    type, ``string``, ``bytes`` or ``message``; ``None`` for storage that does not pin
    the helper's kind (arrays/dictionaries/packed lists/pointers/unknown objects)."""
    if enc in _SCALAR_ENC:
        return _SCALAR_ENC[enc]
    if enc.startswith('@"') and enc.endswith('"'):
        cls = enc[2:-1]
        if cls in _CLASS_TO_PROTO:
            return _CLASS_TO_PROTO[cls]
        if cls in proto_classes:
            return "message"
    return None


def record_helper_votes(
    ctx: BinaryContext, field_ivars: Sequence[ObjcIvar], helpers: Dict[str, int],
    proto_classes: FrozenSet[str],
) -> None:
    """Accumulate, on *ctx*, one vote per field ``{canonical write helper → wire kind of
    the ivar that uses it}``.  Called per class by ``extract_proto_message`` with the write
    helpers the write sites already bound (``WriteBindings.helpers``; no extra analysis), so by
    the end of ``extract_all`` the table covers every class in the binary."""
    votes = _ctx_cache(ctx, "_helper_votes", dict)
    for iv in field_ivars:
        va = helpers.get(iv.name)
        kind = _ivar_wire_kind(iv.type_enc or "", proto_classes) if va else None
        if kind is None:
            continue
        if kind in ("int32", "int64", "uint32", "uint64"):
            fam = _classify_write_helper(ctx, va)
            if fam == "unknown":
                continue                    # the writer shows no encoding: no vote
            kind = _refine_scalar_by_family(kind, fam)
        votes.setdefault(real_target(ctx, va), Counter())[kind] += 1


def helper_kind(ctx: BinaryContext, helper_va: int) -> Optional[str]:
    """Wire kind of a write helper: the UNANIMOUS kind of the ivars that use it
    binary-wide, else ``None`` (never seen, or conflicting votes — not guessed)."""
    votes = (getattr(ctx, "_helper_votes", None) or {}).get(real_target(ctx, helper_va))
    if not votes or len(votes) != 1:
        return None
    return next(iter(votes))


# ── readFrom: value class ─────────────────────────────────────────────────────


def readfrom_value_classes(
    ctx: BinaryContext, cls: ObjcClass, number: int,
    core_index: Dict[int, str], known_classes: FrozenSet[str],
) -> Optional[Set[str]]:
    """Proto classes field *number*'s ``readFrom:`` handler builds -- the map entry's whole
    parse, its own key/value dispatch included: the ReadAllFrom core it calls on a new object
    and every proto class it allocates (:mod:`proto.dispatch_eval`, which runs the dispatch
    with the field number set to *number*).  ``None`` when the dispatch, or a handler for that
    number, can't be found (the caller then reports the value class as unrecovered)."""
    ev = evaluate_class(ctx, cls, core_index or {})   # an empty index still names allocated classes
    fd = ev.fields.get(number)
    if fd is None:
        return None
    names = set(fd.element_classes)
    if fd.element_core:
        names.add(fd.element_core)
    return {n for n in names if n in known_classes}


# ── Type resolution ───────────────────────────────────────────────────────────


def resolve_map_types(
    ctx: BinaryContext, cls: ObjcClass, writer: MapEntryWriter,
    core_index: Dict[int, str], known_classes: FrozenSet[str],
) -> MapTypes:
    """Resolve a map field's key/value types from its :class:`MapEntryWriter`.

    Key = the key helper's wire kind (must be a legal map-key type).  Value = the value
    helper's wire kind; for ``message`` the class is the single proto class the
    ``readFrom:`` arm of this field references, and for a non-message kind the arm must
    reference NONE (the two serializers are cross-checked — disagreement is reported,
    not resolved).  The NSNumber unboxing selector, where present, must be consistent
    with the helper-derived scalar type."""
    kt = helper_kind(ctx, writer.key_helper)
    vt = helper_kind(ctx, writer.value_helper)
    reasons: List[str] = []

    key_type: Optional[str] = kt if kt in MAP_KEY_TYPES else None
    if key_type is None:
        reasons.append("key write helper not identified as a map-key type"
                       if kt is None else f"key kind {kt} is not a legal map key")
    value_type: Optional[str] = vt
    value_class: Optional[str] = None
    if vt is None:
        reasons.append("value write helper not identified")
    else:
        classes = readfrom_value_classes(ctx, cls, writer.number, core_index, known_classes)
        if vt == "message":
            if classes is not None and len(classes) == 1:
                value_class = next(iter(classes))
            else:
                reasons.append("value is a message but readFrom: names no single value class")
        elif classes:
            value_type = None
            reasons.append("writeTo: says scalar/string value but readFrom: allocates "
                           + "/".join(sorted(classes)))
    for what, sel, typ in (("key", writer.key_sel, key_type),
                           ("value", writer.value_sel, value_type)):
        ok = _UNBOX_TYPES.get(sel) if sel else None
        if typ and ok is not None and typ not in ok:
            reasons.append(f"{what} unboxed via {sel} but helper says {typ}")
            if what == "key":
                key_type = None
            else:
                value_type = None
    return MapTypes(key_type, value_type, value_class, "; ".join(reasons) or None)


# ── Post-extraction finalisation (moved from proto.extractor) ───────────────

_MAP_FIELD_NOTE = (
    "map<> field (ObjC NSMutableDictionary) emitted as bytes; no map-entry writer "
    "found in writeTo: so key/value types not recovered — see LIMITATIONS.md (1)"
)


_MAP_UNRESOLVED_NOTE = (
    "map<> field: each element is a map-entry message {{key = 1, value = 2}}; "
    "key/value types not recovered ({reason}) — see LIMITATIONS.md (1)"
)


_MAP_VALUE_CLASS_NOTE = (
    "map value is a message whose class could not be determined ({reason}); value "
    "emitted as bytes — see LIMITATIONS.md (1)"
)


def _apply_map_types(fld: ProtoField, types: MapTypes) -> None:
    """Apply resolved :class:`MapTypes` to a map field (see :func:`_finalize_map_fields`).

    * key + value known  -> ``map<K, V>`` (singular; a message value is named by its ObjC
      class and resolved by the emitter), no note — nothing is uncertain.
    * key known, value a message of unknown class -> ``map<K, bytes>`` + note (a message is
      length-delimited like bytes, so every entry still decodes).
    * anything else -> ``repeated bytes`` of entry messages + note (the entries are all
      visible, unlike a singular ``bytes`` which keeps only the last)."""
    if types.key_type and types.value_type == "message" and types.value_class:
        fld.map_key_type, fld.map_value_class = types.key_type, types.value_class
        fld.type_inference_note = None
    elif types.key_type and types.value_type not in (None, "message"):
        fld.map_key_type, fld.map_value_type = types.key_type, types.value_type
        fld.type_inference_note = None
    elif types.key_type and types.value_type == "message":
        fld.map_key_type, fld.map_value_type = types.key_type, "bytes"
        fld.type_inference_note = _MAP_VALUE_CLASS_NOTE.format(reason=types.reason)
    else:
        fld.label = FieldLabel.REPEATED
        fld.type_inference_note = _MAP_UNRESOLVED_NOTE.format(reason=types.reason)


def _finalize_map_fields(
    ctx: BinaryContext, cl: ClassList, messages: List[ProtoMessage],
    core_index: Dict[int, str],
) -> None:
    """Post-extraction pass (#41): type every map field whose entry writer was recovered.

    Runs after the whole image is extracted because a map key/value helper's type is the
    unanimous type of the ivars that use it binary-wide (``ctx._helper_votes``, filled by
    :func:`record_helper_votes` as each class was extracted).  A field with no entry
    writer is left untouched (flagged ``bytes``)."""
    writers = getattr(ctx, "_map_writers", None) or {}
    if not writers:
        return
    known = _proto_class_set(ctx, cl)
    by_name = {c.name: c for c in cl if not c.is_meta}
    for msg in messages:
        cls = by_name.get(msg.class_name)
        for fld in msg.fields:
            writer = writers.get((msg.class_name, fld.name))
            if writer is None or cls is None:
                continue
            try:
                types = resolve_map_types(ctx, cls, writer, core_index, known)
            except (NameError, ImportError):
                raise
            except Exception as exc:
                log.debug("map type resolution failed for %s.%s: %s",
                          msg.class_name, fld.name, exc)
                types = MapTypes(None, None, None, f"analysis failed: {type(exc).__name__}")
            _apply_map_types(fld, types)
