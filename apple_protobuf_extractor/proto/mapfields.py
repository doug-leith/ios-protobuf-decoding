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
    the write sites already bind the begin-mark to the ivar, so the entry is the
    sub-message it opens (:func:`entry_from_bound_write`).

  Both feed :func:`analyze_entry`, which reads off the writer flow's calls of the function
  (:mod:`proto.writer_flow`; the block's with the writer among what it captured) the field
  number and the key/value
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

from collections import Counter
from dataclasses import dataclass
from typing import Dict, FrozenSet, List, Optional, Sequence, Set, Tuple

from macho.memory import READ_ERRORS, BinaryContext, record_unread, PROGRAM_ERRORS
from macho.classlist import ClassList, ObjcClass, ObjcIvar
from macho.disasm import _parse_imm, _norm_reg
from proto.callees import real_target, sent_selector

from proto.arm64cfg import mem_operand
from proto.arm64_operands import reg_name, split_ops
from proto.dispatch import FunctionEntries, function_entries
from proto.function_body import function_body, function_listing
from proto.writeto import BoundWrite, writer_calls
from proto.submessage_marks import NO_OPEN_MARK, PLACE_MARK, submessage
from proto.write_helpers import _classify_write_helper, _refine_scalar_by_family
from proto.models import (FieldLabel, ImageEvidence, ProtoField, ProtoMessage,
                          record_analysis_failure)
from proto.protocore import _SCALAR_ENC, _CLASS_TO_PROTO
from proto.protoclass_set import _proto_class_set
from proto.dispatch import listing_flow
from proto.arm64_eval import Objects
from proto.dispatch_eval import evaluate_class


@dataclass(frozen=True)
class _IvarNames:
    """A class's field ivars by the address of their offset variable (an ivar_t's ``offset``:
    the code loads it to reach the ivar; another class's ivar at the same offset has its own
    variable), and by the offset itself (a literal displacement, with no variable)."""
    by_slot: Dict[int, str]
    by_offset: Dict[int, str]

    @staticmethod
    def of(ivars: Sequence[ObjcIvar]) -> "_IvarNames":
        return _IvarNames({iv.offset_slot: iv.name for iv in ivars if iv.offset_slot and iv.name},
                          {iv.offset: iv.name for iv in ivars if iv.offset and iv.name})

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


def _offset_var_address(flow, i: int, offreg: str) -> Optional[int]:
    """Address of the ivar-offset variable whose value is in *offreg* at ``insns[i]``: the
    one load reaching it (:meth:`Flow.slot_load_address`).  Reaching definitions only, so
    over a whole function an earlier unrelated ``adrp x8 ; add x8,x8,#o`` cannot shadow the
    page actually feeding this load."""
    d = flow.only_def(i, offreg)
    return None if d is None else flow.slot_load_address(d)


def _trace_ivar(flow, i: int, reg: str, names: _IvarNames) -> Optional[str]:
    """Name of the ivar whose value is in *reg* at ``insns[i]``: follow ``mov`` chains
    back to the defining ``ldr xD,[Xself, Xoff]`` (``Xoff`` = a loaded ivar-offset
    variable, the ivar by its address) or the immediate-offset form."""
    insns, seen = flow.insns, set()
    while (i, reg) not in seen:
        seen.add((i, reg))
        d = flow.only_def(i, reg)
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
                return names.by_slot.get(_offset_var_address(flow, d, mem[2]))
            if mem[3] == 0:                             # [Xb] with Xb = add Xself, Xoff
                a = flow.only_def(d, mem[1])
                aops = split_ops(insns[a].op_str) if a is not None else []
                if (a is not None and insns[a].mnemonic == 'add' and len(aops) == 3
                        and not aops[2].startswith('#') and _norm_reg(aops[2])):
                    return names.by_slot.get(_offset_var_address(flow, a, _norm_reg(aops[2])))
                return None
            return names.by_offset.get(mem[3])          # [base, #off]
        return None
    return None


def _send_at(ctx: BinaryContext, flow, k: int) -> Optional[str]:
    """The selector the ``bl`` ``flow.insns[k]`` sends (:func:`proto.callees.sent_selector`: a
    selector stub's, or a plain ``objc_msgSend``'s selector string in x1), else None."""
    return sent_selector(ctx, _parse_imm(flow.insns[k].op_str), flow.known_before(k).get('x1'))


def _trace_unbox_selector(ctx: BinaryContext, flow, i: int, reg: str) -> Optional[str]:
    """Selector of the objc call that produced the value the write-helper call ``insns[i]`` is
    handed in *reg* (its writer's value register: x1, or v0 for a float / double) -- the
    NSNumber unboxing step (``[v longLongValue]``, ``[v doubleValue]``) for a scalar key / value,
    or ``None`` when the object is passed straight through (string / message / bytes) or the
    chain can't be followed."""
    j, seen = i, set()
    while (j, reg) not in seen:
        seen.add((j, reg))
        d = flow.only_def(j, reg)
        if d is None:
            return None
        ins = flow.insns[d]
        if ins.mnemonic == 'bl':
            return _send_at(ctx, flow, d) if reg in ('x0', 'v0') else None
        ops = split_ops(ins.op_str)
        src = reg_name(ops[1]) if ins.mnemonic in ('mov', 'fmov') and len(ops) == 2 else None
        if src:
            reg, j = src, d
            continue
        return None
    return None


# ── Entry-body analysis (shared by both writeTo: shapes) ──────────────────────


def analyze_entry(ctx: BinaryContext, insns: Sequence, calls,
                  begin) -> Optional[MapEntryWriter]:
    """Analyse one map-entry body: the sub-message the begin mark *begin* opens among the
    writer flow's *calls* of the function *insns* lists
    (:func:`proto.submessage_marks.submessage`).  Returns the :class:`MapEntryWriter` or
    ``None`` unless the body writes exactly sub-fields 1 and 2, ONE helper call each --
    anything else (nested sub-messages, a second write of a sub-field, a path with no end
    mark, a sub-field other than 1/2) is not a recognisable map entry."""
    sub = submessage(calls, begin)
    if sub is None or sub.nested:
        return None
    writes = {}                                        # sub-field -> its write call
    for t in sub.writes:
        if t.number not in (_KEY_FIELD, _VALUE_FIELD) or t.number in writes:
            return None                                # not a {key, value} entry
        writes[t.number] = t
    if len(writes) != 2:
        return None
    at = {ins.addr: k for k, ins in enumerate(insns)}
    key, value = writes[_KEY_FIELD], writes[_VALUE_FIELD]
    if key.addr not in at or value.addr not in at:
        return None
    flow = listing_flow(ctx, insns)
    return MapEntryWriter(
        number=sub.number, key_helper=key.target, value_helper=value.target,
        key_sel=_trace_unbox_selector(ctx, flow, at[key.addr], key.value_reg),
        value_sel=_trace_unbox_selector(ctx, flow, at[value.addr], value.value_reg))


# ── Shape A: enumerateKeysAndObjectsUsingBlock: ───────────────────────────────


def scan_block_enumerated_maps(
    ctx: BinaryContext, cls: ObjcClass, imp: int, entries: FunctionEntries,
    names: _IvarNames,
) -> Dict[str, MapEntryWriter]:
    """``{ivar_name: MapEntryWriter}`` for every ``[self->_dict
    enumerateKeysAndObjectsUsingBlock:&block]`` in *cls*'s ``writeTo:`` at *imp*.

    The parent is its extent (:func:`proto.function_body.function_listing`: ``imp`` .. the
    next function entry, *entries* among them; its out-of-line tail blocks included),
    evaluated over its CFG
    (:meth:`proto.arm64_eval.Flow.propagate`, which models the stack frame).  For each
    enumerate call: the receiver (``x0``) traces to the dictionary ivar; ``x2`` is the stack
    block, whose invoke pointer is the 8-byte slot at ``x2 + 0x10`` as every path into the
    call leaves it; the invoke function's own body (:func:`proto.function_body.function_body`)
    is then analysed by :func:`analyze_entry`, its one begin mark outside every other the
    entry's (:meth:`proto.writer_flow.WriterFlow.block_calls`).  Unrecognised shapes are
    simply absent (the field keeps its flagged fallback)."""
    out: Dict[str, MapEntryWriter] = {}
    try:
        insns = function_listing(ctx, imp, entries)
    except READ_ERRORS as exc:
        record_unread(ctx, "method body", f"writeTo: {imp:#x}", exc)
        return out
    flow = listing_flow(ctx, insns)
    enumerates = [i for i, ins in enumerate(insns) if ins.mnemonic == 'bl'
                  and _send_at(ctx, flow, i) == _ENUMERATE_SELECTOR]
    if not enumerates:
        return out
    slots: Dict[int, Dict[int, Tuple[int, int]]] = {}
    # a callee handed a pointer into the frame (a fast-enumeration state, say) may write
    # that object and upward, never the slots below it (Objects.object_escape)
    regs = flow.propagate({}, enumerates, Objects(object_escape=True), slots_out=slots)
    for i in enumerates:
        ivar = _trace_ivar(flow, i, 'x0', names)
        blk = regs.get(i, {}).get('x2')
        slot = slots.get(i, {}).get(blk + _BLOCK_INVOKE_OFFSET) if blk is not None else None
        invoke = slot[1] if slot is not None and slot[0] == 8 else None
        if ivar is None or invoke is None or ivar in out:
            continue
        try:
            body = function_body(ctx, invoke, entries)
        except READ_ERRORS as exc:
            record_unread(ctx, "function", f"{invoke:#x}", exc)
            continue
        if not body or body.truncated:                  # never analyse a truncated body
            record_unread(ctx, "map entry block", f"{invoke:#x}",
                          ValueError("its body was read only in part"))
            continue
        calls = writer_calls(ctx, cls, invoke)              # (undecided: recorded there)
        if calls is None:
            continue
        begins = [s for s in calls.sites if s.name == PLACE_MARK and s.open_marks == NO_OPEN_MARK]
        entry = analyze_entry(ctx, body, calls, begins[0]) if len(begins) == 1 else None
        if entry is None:
            record_analysis_failure(ctx, cls.name, "map fields",
                                    f"{ivar}: the entry block at {invoke:#x} writes "
                                    f"{len(begins)} sub-messages, not one map entry"
                                    if len(begins) != 1 else
                                    f"{ivar}: the entry block at {invoke:#x} writes no "
                                    "{key = 1, value = 2} entry")
        else:
            out[ivar] = entry
    return out


# ── Shape B: inline enumeration loop (bound begin-mark) ──────────────────────


def entry_from_bound_write(ctx: BinaryContext, cls: ObjcClass, imp: int,
                          entries: FunctionEntries, w: BoundWrite) -> Optional[MapEntryWriter]:
    """The :class:`MapEntryWriter` for a bound write *w* of *cls*'s ``writeTo:`` (at *imp*)
    that is a begin-submessage mark (already bound to the dictionary ivar, with its field
    number): the sub-message it opens among the ``writeTo:``'s writer calls."""
    if not w.bracket:
        return None
    calls = writer_calls(ctx, cls)
    begin = next((s for s in calls.sites if s.addr == w.addr), None) if calls else None
    if begin is None:
        return None
    try:
        insns = function_listing(ctx, imp, entries)
    except READ_ERRORS:
        return None
    return analyze_entry(ctx, insns, calls, begin)


def find_map_writers(
    ctx: BinaryContext, cls: ObjcClass, map_ivars: Sequence[ObjcIvar],
    bound_writes: Dict[str, BoundWrite], field_ivars: Sequence[ObjcIvar],
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
    entries = function_entries(ctx)
    for iv in map_ivars:
        w = bound_writes.get(iv.name)
        if w is not None:
            e = entry_from_bound_write(ctx, cls, m.imp, entries, w)
            if e is not None:
                writers[iv.name] = e
    pending = [iv for iv in map_ivars if iv.name not in writers]
    if pending:
        for name, e in scan_block_enumerated_maps(
                ctx, cls, m.imp, entries, _IvarNames.of(field_ivars)).items():
            if any(iv.name == name for iv in pending):
                writers[name] = e
    taken: Dict[int, str] = {}
    for name, n in confirmed_numbers.items():
        taken[n] = name
    out: Dict[str, MapEntryWriter] = {}
    for name, e in writers.items():
        owner = taken.get(e.number)
        if owner is not None and owner != name:
            record_analysis_failure(ctx, cls.name, "map fields",
                                    f"{name}: its entry writer's field number {e.number} is "
                                    f"{owner}'s; not taken for a map")
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
    ctx: BinaryContext, votes: Dict[int, Counter], field_ivars: Sequence[ObjcIvar],
    helpers: Dict[str, int], proto_classes: FrozenSet[str],
) -> None:
    """Add to *votes* (:attr:`proto.models.ImageEvidence.helper_votes`) one vote per field
    ``{canonical write helper → wire kind of the ivar that uses it}``.  Called per class by
    ``extract_proto_message`` with the write helpers the write sites already bound
    (``WriteBindings.helpers``; no extra analysis), so by the end of ``extract_all`` the table
    covers every class in the binary."""
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


def helper_kind(ctx: BinaryContext, votes: Dict[int, Counter], helper_va: int) -> Optional[str]:
    """Wire kind of a write helper: the UNANIMOUS kind of the ivars that use it
    binary-wide (*votes*), else ``None`` (never seen, or conflicting votes — not guessed)."""
    got = votes.get(real_target(ctx, helper_va))
    if not got or len(got) != 1:
        return None
    return next(iter(got))


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
    ev = evaluate_class(ctx, cls, core_index or {}, known_classes)  # an empty index still names
                                                                    # the classes allocated
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
    core_index: Dict[int, str], known_classes: FrozenSet[str], votes: Dict[int, Counter],
) -> MapTypes:
    """Resolve a map field's key/value types from its :class:`MapEntryWriter` and the image's
    write-helper *votes*.

    Key = the key helper's wire kind (must be a legal map-key type).  Value = the value
    helper's wire kind; for ``message`` the class is the single proto class the
    ``readFrom:`` arm of this field references, and for a non-message kind the arm must
    reference NONE (the two serializers are cross-checked — disagreement is reported,
    not resolved).  The NSNumber unboxing selector, where present, must be consistent
    with the helper-derived scalar type."""
    kt = helper_kind(ctx, votes, writer.key_helper)
    vt = helper_kind(ctx, votes, writer.value_helper)
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


# ── Post-extraction finalisation ─────────────────────────────────────────────

_MAP_FIELD_NOTE = (
    "map<> field (ObjC NSMutableDictionary) emitted as bytes; no map-entry writer "
    "found in writeTo: so key/value types not recovered — see LIMITATIONS.md (1)"
)
#: A map field of a single-class extraction whose entry writer was found: its key and value are
#: typed by the write-helper votes of the whole image, which only extract_all collects.
_MAP_WHOLE_IMAGE_NOTE = (
    "map<> field (ObjC NSMutableDictionary) emitted as bytes: its key/value types are read over "
    "the whole image (extract_all), not by a single-class extraction"
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
    core_index: Dict[int, str], evidence: ImageEvidence,
) -> None:
    """Post-extraction pass (#41): type every map field whose entry writer was recovered.

    Runs after the whole image is extracted because a map key/value helper's type is the
    unanimous type of the ivars that use it binary-wide (*evidence*'s ``helper_votes``, filled
    by :func:`record_helper_votes` as each class was extracted).  A field with no entry
    writer is left untouched (flagged ``bytes``)."""
    writers = evidence.map_writers
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
                types = resolve_map_types(ctx, cls, writer, core_index, known,
                                          evidence.helper_votes)
            except PROGRAM_ERRORS:
                raise
            except Exception as exc:
                record_analysis_failure(ctx, msg.class_name, "map types",
                                        f"{fld.name}: {type(exc).__name__}: {exc}")
                types = MapTypes(None, None, None, f"analysis failed: {type(exc).__name__}")
            _apply_map_types(fld, types)
