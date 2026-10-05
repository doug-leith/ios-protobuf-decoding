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
    ``block+0x10``), which the field-number CFG walk never enters.  Found by
    :func:`scan_block_enumerated_maps`.
  - **inline loop** — a ``countByEnumeratingWithState:`` loop in ``writeTo:`` itself;
    the CFG walk already binds the begin-mark to the ivar, so the entry body is the
    straight-line code after that write (:func:`entry_from_walk_write`).

  Both feed :func:`analyze_entry`, which reads the field number and the key/value
  *write helpers* (plus, as a cross-check, the NSNumber unboxing selector feeding
  each).  A helper's meaning is NOT hard-coded: every write helper is shared by all
  fields of one wire type, so its type is the unanimous type of the ivars that use it
  binary-wide (:func:`record_helper_votes` / :func:`helper_kind` — the same ground-truth
  mechanism as ``write_helpers._identify_string_write_helpers``).

* **readFrom:** must *create* a message value, so it statically references the value
  class (``[Cls alloc]`` / ``ClsReadAllFrom``) inside the arm that handles field ``F``.
  :func:`readfrom_value_classes` returns every proto class referenced in the OUTERMOST
  ``cmp Wf,#F`` handler's dominance region (so a map entry's own nested ``value = 2``
  tag compare is not mistaken for top-level field 2).

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
from macho.classlist import ObjcClass, ObjcIvar
from macho.disasm import disasm, _parse_imm, _norm_reg

from proto.arm64cfg import (
    split_ops, dst_reg, mem_operand, _next_imp, dominates,
)
from proto.writeto import (
    _writeto_field_number_before, _selector_stub_name,
    _addr_to_name, _NON_DEF_MNEMONICS,
)
from proto.write_helpers import (
    _helper_real_target, _classify_write_helper, _refine_scalar_by_family,
)
from proto.protocore import _SCALAR_ENC, _CLASS_TO_PROTO
from proto.dispatch import (
    _locate_dispatch_arms, _func_end, _find_field_number_register,
    _compare_handlers, _classref_class_name,
)

log = logging.getLogger(__name__)

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

_CALLER_SAVED = frozenset(f"x{i}" for i in range(0, 19))


def _reaching_def(insns: Sequence, i: int, reg: str) -> Optional[int]:
    """Index of the instruction that defines GPR *reg* (normalised ``xN``) as seen at
    ``insns[i]``: the closest earlier writer.  A ``bl`` counts as a definition of every
    caller-saved register (it clobbers them), so a value held across a call in a
    caller-saved register is correctly NOT traced through it.  ``None`` when no
    writer precedes (the register is a live-in)."""
    for j in range(i - 1, -1, -1):
        ins = insns[j]
        mn = ins.mnemonic
        if mn == 'bl':
            if reg in _CALLER_SAVED:
                return j
            continue
        if mn.startswith('st') or mn in _NON_DEF_MNEMONICS:
            continue
        ops = split_ops(ins.op_str)
        if not ops:
            continue
        if mn in ('ldp', 'ldpsw') and len(ops) >= 3:
            if _norm_reg(ops[0]) == reg or _norm_reg(ops[1]) == reg:
                return j
            continue
        if dst_reg(ins.op_str) == reg:
            return j
    return None


def _sp_offset(ins) -> Optional[int]:
    """``K`` of ``add xD, sp, #K`` (``0`` for the ``mov xD, sp`` a block at the very
    bottom of the frame compiles to); else None — i.e. the stack offset *xD* points at."""
    ops = split_ops(ins.op_str)
    if ins.mnemonic == 'add' and len(ops) == 3 and ops[1] == 'sp' and ops[2].startswith('#'):
        return _parse_imm(ops[2])
    if ins.mnemonic == 'mov' and len(ops) == 2 and ops[1] == 'sp':
        return 0
    return None


def _pc_relative_address(insns: Sequence, i: int, reg: str) -> Optional[int]:
    """Address materialised into *reg* at ``insns[i]`` by ``adrp reg,#page ;
    add reg,reg,#imm`` (the LAST such pair — a body re-uses its scratch register for
    many unrelated pages).  None for any other defining form."""
    d = _reaching_def(insns, i, reg)
    # arm64e signs a code pointer in place (``pacia reg, disc``) before storing it: the
    # address is unchanged, so look through the signing to the adrp+add that built it.
    while d is not None and insns[d].mnemonic.startswith('pac'):
        d = _reaching_def(insns, d, reg)
    if d is None:
        return None
    add = insns[d]
    ops = split_ops(add.op_str)
    if (add.mnemonic != 'add' or len(ops) != 3 or _norm_reg(ops[0]) != reg
            or _norm_reg(ops[1]) != reg or not ops[2].startswith('#')):
        return None
    imm = _parse_imm(ops[2])
    p = _reaching_def(insns, d, reg)
    if imm is None or p is None or insns[p].mnemonic != 'adrp':
        return None
    pops = split_ops(insns[p].op_str)
    page = _parse_imm(pops[1]) if len(pops) == 2 else None
    return None if page is None else page + imm


def _stack_store_source(insns: Sequence, i: int, disp: int) -> Optional[Tuple[int, str]]:
    """``(index, source_reg)`` of the closest store before ``insns[i]`` that writes the
    8 bytes at ``[sp, #disp]`` (``str xA,[sp,#d]`` or either half of ``stp``)."""
    for j in range(i - 1, -1, -1):
        ins = insns[j]
        if ins.mnemonic not in ('str', 'stp'):
            continue
        ops = split_ops(ins.op_str)
        mem = mem_operand(f"{ops[0]}, {ops[-1]}") if ops else None
        if mem is None or mem[1] != 'sp' or mem[2] is not None:
            continue
        if ins.mnemonic == 'str' and mem[3] == disp:
            return j, _norm_reg(ops[0])
        if ins.mnemonic == 'stp' and len(ops) == 3:
            if mem[3] == disp:
                return j, _norm_reg(ops[0])
            if mem[3] + 8 == disp:
                return j, _norm_reg(ops[1])
    return None


def _offset_var_address(insns: Sequence, i: int, offreg: str) -> Optional[int]:
    """Address of the ivar-offset variable whose value is in *offreg* at ``insns[i]``:
    the reaching ``ldrsw offreg,[base,#k]`` with ``base`` the reaching ``adrp`` page
    (``+ add``) — or the PC-relative literal ``ldrsw offreg, #ADDR`` a standalone image
    uses.  Reaching definitions only: unlike :func:`proto.arm64cfg._resolve_offset_addr`
    (which scans a block prefix for the FIRST matching ``adrp+add``) this is safe over a
    whole function, where an earlier unrelated ``adrp x8 ; add x8,x8,#o`` would shadow the
    page actually feeding this load."""
    d = _reaching_def(insns, i, offreg)
    if d is None or insns[d].mnemonic not in ('ldrsw', 'ldr'):
        return None
    mem = mem_operand(insns[d].op_str)
    if mem is None:
        ops = split_ops(insns[d].op_str)
        return _parse_imm(ops[1]) if len(ops) == 2 and ops[1].startswith('#') else None
    if mem[2] is not None:
        return None
    b = _reaching_def(insns, d, mem[1])
    if b is None:
        return None
    if insns[b].mnemonic == 'adrp':
        ops = split_ops(insns[b].op_str)
        page = _parse_imm(ops[1]) if len(ops) == 2 else None
        return None if page is None else page + mem[3]
    base = _pc_relative_address(insns, d, mem[1])
    return None if base is None else base + mem[3]


def _trace_ivar(ctx: BinaryContext, insns: Sequence, i: int, reg: str,
                offset_to_name: Dict[int, str]) -> Optional[str]:
    """Name of the ivar whose value is in *reg* at ``insns[i]``: follow ``mov`` chains
    back to the defining ``ldr xD,[Xself, Xoff]`` (``Xoff`` = a loaded ivar-offset
    variable → resolved to the ivar by :func:`proto.writeto._addr_to_name`) or the
    immediate-offset form.  The declared-offset membership test IS the validator."""
    for _ in range(8):                                  # mov-chain depth guard
        d = _reaching_def(insns, i, reg)
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
                    ctx, _offset_var_address(insns, d, mem[2]), offset_to_name)
            if mem[3] == 0:                             # [Xb] with Xb = add Xself, Xoff
                a = _reaching_def(insns, d, mem[1])
                aops = split_ops(insns[a].op_str) if a is not None else []
                if (a is not None and insns[a].mnemonic == 'add' and len(aops) == 3
                        and not aops[2].startswith('#') and _norm_reg(aops[2])):
                    return _addr_to_name(
                        ctx, _offset_var_address(insns, a, _norm_reg(aops[2])),
                        offset_to_name)
                return None
            return offset_to_name.get(mem[3])           # [base, #off]
        return None
    return None


def _stub_selector(ctx: BinaryContext, target: Optional[int]) -> Optional[str]:
    """Selector an objc-message stub at *target* sends: the classic ``adrp x1 ; ldr x1,[x1,#o]
    ; … ; br`` selector-reference stub (:func:`proto.writeto._selector_stub_name`), or the
    newer toolchain's ``adrp x1 ; add x1,x1,#o ; b objc_msgSend`` form whose ``x1`` is the
    selector string's own address."""
    sel = _selector_stub_name(ctx, target)
    if sel is not None or target is None:
        return sel
    try:
        ins = disasm(ctx, target, 3, stop_at_ret=False)
    except Exception:
        return None
    if len(ins) < 3 or ins[0].mnemonic != 'adrp' or ins[1].mnemonic != 'add' \
            or ins[2].mnemonic != 'b':
        return None
    a, d = split_ops(ins[0].op_str), split_ops(ins[1].op_str)
    if (len(a) != 2 or len(d) != 3 or a[0] != 'x1' or d[0] != 'x1' or d[1] != 'x1'
            or not d[2].startswith('#')):
        return None
    page, imm = _parse_imm(a[1]), _parse_imm(d[2])
    try:
        return ctx.read_cstring(page + imm) if page is not None and imm is not None else None
    except Exception:
        return None


def _trace_unbox_selector(ctx: BinaryContext, insns: Sequence, i: int) -> Optional[str]:
    """Selector of the objc call that produced the value passed in ``x1`` at the
    write-helper call ``insns[i]`` — the NSNumber unboxing step (``[v longLongValue]``)
    for a scalar key/value, or ``None`` when the object is passed straight through
    (string / message / bytes) or the chain can't be followed."""
    reg, j = 'x1', i
    for _ in range(8):
        d = _reaching_def(insns, j, reg)
        if d is None:
            return None
        ins = insns[d]
        if ins.mnemonic == 'bl':
            return _stub_selector(ctx, _parse_imm(ins.op_str)) if reg == 'x0' else None
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
    begin = insns[begin_idx]
    slot = _scratch_slot_of(insns, begin_idx)       # shared by the begin and end marks
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
        j_slot = _scratch_slot_of(insns, j)
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
        key_sel=_trace_unbox_selector(ctx, insns, kj),
        value_sel=_trace_unbox_selector(ctx, insns, vj))


def _scratch_slot_of(insns: Sequence, k: int) -> Optional[int]:
    """Stack offset K of the ``add x1, sp, #K`` that defines ``x1`` as the argument of
    the call at ``insns[k]`` (the begin/end-mark idiom), else None.  Unlike
    :func:`proto.writeto._value_is_stack_scratch` this honours call clobbers: a ``bl``
    between the ``add`` and *k* redefines ``x1``, so a stale scratch is never reported."""
    d = _reaching_def(insns, k, 'x1')
    return None if d is None else _sp_offset(insns[d])


# ── Shape A: enumerateKeysAndObjectsUsingBlock: ───────────────────────────────


def scan_block_enumerated_maps(
    ctx: BinaryContext, imp: int, imps_sorted: List[int],
    offset_to_name: Dict[int, str],
) -> Dict[str, MapEntryWriter]:
    """``{ivar_name: MapEntryWriter}`` for every ``[self->_dict
    enumerateKeysAndObjectsUsingBlock:&block]`` in the ``writeTo:`` at *imp*.

    The parent is scanned linearly over its structural extent (``imp`` .. next method
    IMP — a hard upper bound that includes its out-of-line tail blocks); the match is a
    LOCAL pattern, so no control-flow reachability is needed.  For each enumerate call:
    the receiver (``x0``) traces to the dictionary ivar; the block (``x2 = add x2,sp,#B``)
    has its invoke pointer stored at ``[sp,#B+0x10]`` as an ``adrp+add`` address; the
    invoke function's own body (to its ``ret``) is then analysed by :func:`analyze_entry`.
    Unrecognised shapes are simply absent (the field keeps its flagged fallback)."""
    out: Dict[str, MapEntryWriter] = {}
    end = _next_imp(imps_sorted, imp)
    try:
        insns = disasm(ctx, imp, max_insns=max(64, (end - imp) // 4), stop_at_ret=False)
    except Exception:
        return out
    for i, ins in enumerate(insns):
        if ins.mnemonic != 'bl':
            continue
        if _stub_selector(ctx, _parse_imm(ins.op_str)) != _ENUMERATE_SELECTOR:
            continue
        ivar = _trace_ivar(ctx, insns, i, 'x0', offset_to_name)
        d = _reaching_def(insns, i, 'x2')
        blk = _sp_offset(insns[d]) if d is not None else None
        if ivar is None or blk is None or ivar in out:
            continue
        store = _stack_store_source(insns, i, blk + _BLOCK_INVOKE_OFFSET)
        invoke = (None if store is None
                  else _pc_relative_address(insns, store[0] + 1, store[1]))
        if invoke is None:
            continue
        try:
            body = disasm(ctx, invoke, max_insns=_BLOCK_INVOKE_MAX_INSNS, stop_at_ret=True)
        except Exception:
            continue
        if not body or body[-1].mnemonic not in ('ret', 'retaa', 'retab'):
            continue                                    # never analyse a truncated body
        for k, b in enumerate(body):
            if b.mnemonic == 'bl' and _scratch_slot_of(body, k) is not None:
                entry = analyze_entry(ctx, body, k)
                if entry is not None:
                    out[ivar] = entry
                break                                   # first begin only
    return out


# ── Shape B: inline enumeration loop (walk-bound begin-mark) ──────────────────


def entry_from_walk_write(ctx: BinaryContext, w: dict) -> Optional[MapEntryWriter]:
    """The :class:`MapEntryWriter` for a ``writeTo:`` CFG-walk write event *w* that is a
    begin-submessage mark (the walk already bound it to the dictionary ivar and read
    its field number).  The entry body is the straight-line code after it in the same
    basic block; a loop body that spans several blocks is not analysed (``None``)."""
    blk, k = w.get('srcblk'), w.get('srck')
    if blk is None or k is None:
        return None
    entry = analyze_entry(ctx, blk, k)
    if entry is None or entry.number != w.get('n'):
        return None
    return MapEntryWriter(**{**entry.__dict__, 'shape': 'inline-loop'})


def find_map_writers(
    ctx: BinaryContext, cls: ObjcClass, map_ivars: Sequence[ObjcIvar],
    walk_writes: Dict[str, dict], offset_to_name: Dict[int, str],
    confirmed_numbers: Dict[str, int],
) -> Dict[str, MapEntryWriter]:
    """Map-entry writers for *cls*'s dictionary ivars: the inline-loop shape from the
    CFG-walk write events (*walk_writes* = ``{ivar: write}``), else the block shape from
    :func:`scan_block_enumerated_maps`.  A writer is dropped if its number collides with
    another ivar's confirmed number (inconsistent evidence is never trusted)."""
    m = cls.get_method("writeTo:")
    if m is None or not m.imp or not map_ivars:
        return {}
    writers: Dict[str, MapEntryWriter] = {}
    for iv in map_ivars:
        w = walk_writes.get(iv.name)
        if w is not None:
            e = entry_from_walk_write(ctx, w)
            if e is not None:
                writers[iv.name] = e
    pending = [iv for iv in map_ivars if iv.name not in writers]
    if pending:
        foreign = getattr(ctx, "_writeto_foreign_imps", None) or ()
        for name, e in scan_block_enumerated_maps(
                ctx, m.imp, sorted(foreign), offset_to_name).items():
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


def _canonical_helper(ctx: BinaryContext, helper_va: int) -> int:
    """Real target of a write helper (see :func:`proto.write_helpers._helper_real_target`),
    memoised — a per-callsite stub island has a different VA at every call site but one
    shared target."""
    memo = _ctx_cache(ctx, "_helper_canon", dict)
    if helper_va not in memo:
        try:
            memo[helper_va] = _helper_real_target(ctx, helper_va)
        except Exception:
            memo[helper_va] = helper_va
    return memo[helper_va]


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
    the ivar that uses it}``.  Called per class by ``extract_proto_message`` with the
    ``_out_helpers`` the CFG walk already produced (no extra analysis), so by the end of
    ``extract_all`` the table covers every class in the binary."""
    votes = _ctx_cache(ctx, "_helper_votes", dict)
    for iv in field_ivars:
        va = helpers.get(iv.name)
        kind = _ivar_wire_kind(iv.type_enc or "", proto_classes) if va else None
        if kind is None:
            continue
        if kind in ("int32", "int64", "uint32", "uint64"):
            kind = _refine_scalar_by_family(kind, _classify_write_helper(ctx, va))
        votes.setdefault(_canonical_helper(ctx, va), Counter())[kind] += 1


def helper_kind(ctx: BinaryContext, helper_va: int) -> Optional[str]:
    """Wire kind of a write helper: the UNANIMOUS kind of the ivars that use it
    binary-wide, else ``None`` (never seen, or conflicting votes — not guessed)."""
    votes = (getattr(ctx, "_helper_votes", None) or {}).get(_canonical_helper(ctx, helper_va))
    if not votes or len(votes) != 1:
        return None
    return next(iter(votes))


# ── readFrom: value class ─────────────────────────────────────────────────────


def readfrom_value_classes(
    ctx: BinaryContext, cls: ObjcClass, number: int,
    core_index: Dict[int, str], known_classes: FrozenSet[str],
) -> Optional[Set[str]]:
    """Proto classes referenced (``[Cls alloc]`` classref, or a ``bl`` into a known
    ReadAllFrom core) anywhere in the region dominated by the OUTERMOST handler of
    field *number* in *cls*'s ``readFrom:`` — i.e. the map entry's whole parse, nested
    key/value tag compares included.  ``None`` when the reader/handler can't be
    located unambiguously (the caller then reports the value class as unrecovered)."""
    arms, core_va, readfrom_va = _locate_dispatch_arms(ctx, cls, core_index)
    if readfrom_va is None:
        return None
    core = core_va if core_va is not None else readfrom_va
    func_end = _func_end(ctx, core)
    if func_end is None:
        return None
    field_reg = _find_field_number_register(ctx, core, func_end)
    if field_reg is None:
        return None
    built = _compare_handlers(ctx, core, func_end, field_reg)
    if built is None:
        return None
    cfg, idom, handlers = built

    tops = []
    for n, h in handlers:
        if n != number:
            continue
        # outermost = not dominated by any OTHER handler (a nested tag compare inside
        # another field's arm is dominated by that arm's handler).
        if not any(h2 != h and dominates(idom, h2, h) for _n2, h2 in handlers):
            tops.append(h)
    if len(set(tops)) != 1:
        return None
    top = tops[0]

    # Classref page registers are often hoisted far from the load (``adrp x27,#pg`` in
    # the prologue, ``ldr x0,[x27,#off]`` in the arm), so collect every page ever
    # assigned to each register function-wide; a candidate only counts if it resolves
    # to a KNOWN proto class (the validator — an unrelated slot can't pass it).
    pages: Dict[str, Set[int]] = {}
    for b in cfg.order:
        for ins in cfg.blocks[b]:
            if ins.mnemonic == 'adrp':
                ops = split_ops(ins.op_str)
                page = _parse_imm(ops[1]) if len(ops) == 2 else None
                if page is not None and _norm_reg(ops[0]):
                    pages.setdefault(_norm_reg(ops[0]), set()).add(page)
    names: Set[str] = set()
    for b in cfg.order:
        if not dominates(idom, top, b):
            continue
        for ins in cfg.blocks[b]:
            if ins.mnemonic == 'ldr':
                mem = mem_operand(ins.op_str)
                if mem is not None and mem[2] is None:
                    for page in pages.get(mem[1], ()):
                        name = _classref_class_name(ctx, page + mem[3])
                        if name in known_classes:
                            names.add(name)
            elif ins.mnemonic == 'bl':
                t = _parse_imm(ins.op_str)
                if t in core_index:
                    names.add(core_index[t])
    return names


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
