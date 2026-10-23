"""proto/structfields.py — inline C-struct field recovery (TODO #37).

Apple's protobuf compiler stores a sub-message whose fields are all scalars as a plain C
struct instead of an ObjC object: a *singular* one by value (``@encode`` ``{Tag="a"I"b"I
"_has"{?=…}}``) and a *repeated* one as an array of them (``^{Tag=II{?=b1b1}}`` plus the
``_xCount`` / ``_xSpace`` ivars).  On the wire the field is a length-delimited sub-message,
but no ObjC class stands behind it, so there is no ``writeTo:`` to read and the element type
used to degrade to ``bytes`` (LIMITATIONS.md (2)).

Everything needed is nevertheless in the binary, and none of it is a heuristic:

* **the struct's name and member layout** — the ivar ``@encode`` names the struct (``Tag``)
  and gives each member's C type, hence its size and (by natural alignment) its offset
  (:func:`parse_struct_encoding`);
* **each member's field number and wire type** — the owner's ``writeTo:`` serialises the
  struct through a small C function (or, when the compiler inlined it, the same code between
  the begin/end marks): per member ``has-bit test ; load [struct+offset] ; write(field#)``.
  :func:`decode_struct_writer` reads ``(offset, field#, write helper, load width)`` triples
  from it; the helper's wire family (sint/fixed) is the same one :mod:`proto.write_helpers`
  already classifies;
* **enum members** — a member that is an enum is emitted by the struct's dictionary
  representation through the compiler-inlined ``xAsString:`` (a value-name switch ending in
  the CFString ``"(unknown: %i)"``) into the ``setObject:forKey:`` call that files it; a plain
  number goes through ``NSNumber``.  :func:`decode_dictrep_members` reads each call's key and
  the member its value comes from (:func:`_pair_members`), and an enum's value names from the
  same data-flow evaluation the class-level recovery uses (:mod:`proto.dictrep_flow`);
* **validation** — the writer's member offsets and load widths must match the encoding's
  layout exactly (:func:`match_layout`): every member written once, no write at an unknown
  offset.  A struct that does not match is left as the flagged ``bytes`` fallback, never
  guessed.

The owner-side entry point mirrors :mod:`proto.mapfields`: ``extract_proto_message`` records
the ``writeTo:`` write that binds the begin-mark to the struct ivar
(:func:`record_struct_site`); once the whole image has been extracted,
:func:`finalize_struct_fields` decodes each site, groups the sites by struct tag (every owner
of one tag must agree), synthesises one :class:`ProtoMessage` per tag and retypes the owner
fields.

Imports only ``macho.*`` plus sibling ``proto`` modules (never ``proto.extractor``).
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple

from macho.disasm import _parse_imm, _norm_reg
from macho.memory import READ_ERRORS, _ctx_cache, record_unread

from proto.arm64cfg import mem_operand
from proto.arm64_operands import (CALLER_SAVED_GPRS, CALLS, LOAD_BYTES, NO_DEST, BLOCK_ENDS,
                                  reg_name, split_ops)
from proto import arm64_eval, dictrep_flow
from proto.callees import stub_selector, text_holding
from macho.strings import read_cfstring_text
from proto.config import _class_to_proto_name
from proto.dispatch import FunctionEntries, _jump_table_arm_addrs, function_entries, listing_flow
from proto.function_body import function_body, function_listing
from proto.enums import _ENUM_UNRESOLVED_COMMENT, _find_dictrep_c_func, _enum_values_from_pairs, _enum_name_from_pairs, _qualify_enum_name
from proto.submessage_marks import Bracket, analyze_bracket
from proto.models import FieldLabel, ProtoEnum, ProtoField, ProtoMessage
from proto.writeto import BoundWrite
from proto.write_helpers import _classify_write_helper, _refine_scalar_by_family, INT_ENCODING_NOTE
from proto.eval_tokens import SELF, READER, OPAQUE
from proto.protocore import _SCALAR_ENC

log = logging.getLogger(__name__)

# ── @encode parsing ───────────────────────────────────────────────────────────

# C scalar @encode char -> size in bytes (also its natural alignment).
_SCALAR_SIZE = {'c': 1, 'C': 1, 'B': 1, 's': 2, 'S': 2, 'i': 4, 'I': 4, 'l': 4, 'L': 4,
                'f': 4, 'q': 8, 'Q': 8, 'd': 8}


@dataclass(frozen=True)
class StructMember:
    offset: int
    code: str                    # scalar @encode char ('I', 'd', …)
    name: Optional[str]          # the encoding's member name ('_duration'), when it has one

    @property
    def size(self) -> int:
        return _SCALAR_SIZE[self.code]


@dataclass(frozen=True)
class StructLayout:
    tag: str                     # the C struct tag ('GEOPDTimeRange')
    members: Tuple[StructMember, ...]   # data members in memory order (has-bits excluded)
    is_array: bool               # True for ``^{Tag=…}`` (a repeated field), False by value


class _Unsupported(Exception):
    """An @encode shape that is not a flat struct of scalars (+ has-bits)."""


def _parse_struct(s: str, i: int) -> Tuple[str, list, int]:
    """Parse ``{Tag=members}`` starting at ``s[i] == '{'``; returns ``(tag, items, next_i)``
    where *items* are ``(name|None, kind, payload)`` with kind 'scalar' / 'bits' / 'struct'."""
    j = s.index('=', i)
    tag = s[i + 1:j]
    i = j + 1
    items: list = []
    while s[i] != '}':
        name = None
        if s[i] == '"':
            k = s.index('"', i + 1)
            name, i = s[i + 1:k], k + 1
        c = s[i]
        if c == '{':
            sub_tag, sub_items, i = _parse_struct(s, i)
            items.append((name, 'struct', (sub_tag, sub_items)))
        elif c == 'b':
            m = re.match(r'b(\d+)', s[i:])
            if m is None:
                raise _Unsupported(s)
            items.append((name, 'bits', int(m.group(1))))
            i += m.end()
        elif c in _SCALAR_SIZE:
            items.append((name, 'scalar', c))
            i += 1
        else:
            raise _Unsupported(s)               # pointers, objects, arrays, unions…
    return tag, items, i + 1


def parse_struct_encoding(enc: Optional[str]) -> Optional[StructLayout]:
    """The :class:`StructLayout` of an ivar ``@encode`` that is a (pointer to a) flat struct
    of scalars with an optional trailing has-bits struct — i.e. what Apple's PB compiler emits
    for an all-scalar sub-message — else ``None`` (a lock, an NSRange, a struct holding
    pointers/objects/nested structs: none of those is a wire message).

    Offsets follow C natural alignment; the has-bits struct only ever follows the data."""
    if not enc:
        return None
    is_array = enc.startswith('^')
    body = enc[1:] if is_array else enc
    if not body.startswith('{') or body.startswith('{?'):
        return None
    try:
        tag, items, end = _parse_struct(body, 0)
    except (_Unsupported, ValueError, IndexError):
        return None
    if end != len(body):
        return None
    members: List[StructMember] = []
    off = 0
    seen_bits = False
    for name, kind, payload in items:
        if kind == 'scalar':
            if seen_bits:
                return None                      # data after the has-bits: not the PB shape
            size = _SCALAR_SIZE[payload]
            off = (off + size - 1) // size * size
            members.append(StructMember(off, payload, name))
            off += size
        elif kind == 'struct' and payload[0] == '?' and all(k == 'bits' for _n, k, _p in payload[1]):
            seen_bits = True                     # the has-bits group
        else:
            return None                          # nested struct / bare bitfield: not modelled
    if not members:
        return None
    return StructLayout(tag, tuple(members), is_array)


# ── the struct's own C serialiser ─────────────────────────────────────────────

_LOAD_WIDTH_MNEMONICS = {mn: n for mn, n in LOAD_BYTES.items() if n}    # fixed-width loads


@dataclass(frozen=True)
class MemberWrite:
    """One member serialisation read from a struct writer."""
    offset: int          # byte offset of the member in the struct
    number: int          # the proto field number it is written with
    helper: int          # the write helper called (VA; a stub is followed when classifying)
    width: int           # bytes loaded from the struct for the value


def _writer_insns(ctx, entry: int) -> List:
    """The struct serialiser at *entry*: the instructions its entry reaches
    (:func:`proto.function_body.function_body`), [] when *entry* cannot be read (recorded when
    it is in this image's ``__text``).  A ``b`` out of its extent -- to a write helper, another
    serialiser, the runtime -- is a tail call."""
    try:
        return function_body(ctx, entry, function_entries(ctx))
    except READ_ERRORS as exc:
        if text_holding(ctx, entry) is not None:
            record_unread(ctx, "function", f"{entry:#x}", exc)
        return []


# The serialiser's two arguments as opaque tokens for the evaluation (any two values the
# evaluator treats as objects: register copies carry them, arithmetic does not).
_STRUCT_ARG, _WRITER_ARG = SELF, READER


def decode_struct_writer(ctx, entry: int) -> List[MemberWrite]:
    """The member writes of the struct serialiser at *entry* — ``f(struct *x0, writer x1)`` —
    in address order; ``[]`` when it writes no member (not a struct writer).

    Decided by data flow, not by instruction windows.  The function is evaluated
    (:meth:`proto.arm64_eval.Flow.run_from`) with the struct and the writer as opaque
    tokens; a write is a call (or tail call) handed the writer in x0.  The AAPCS64 argument
    positions of ``PBDataWriterWrite*Field(writer, value, field#)`` then say where the rest
    is: an integer value in x1 with the field number in w2, a float/double value in v0 with
    the field number in w1.  The field number must be a constant at the call and the value
    must trace, by reaching definitions through copies (:func:`_member_in`), to one load
    from ``[struct + offset]`` (a register holding x0's entry value).  So a tail call behind
    the arm64e return-address check (``autibsp ; eor x16,x30,x30,lsl #1 ; tbz x16,#62 ;
    brk``), or setup instructions in any order, read the same.  A write whose value does not
    trace to a struct member is skipped here and the layout match (:func:`match_layout`)
    then rejects the struct as incomplete."""
    insns = _writer_insns(ctx, entry)
    if not insns:
        return []
    try:
        flow = arm64_eval.Flow(ctx, list(insns))
        region = flow.run_from(0, {'x0': _STRUCT_ARG, 'x1': _WRITER_ARG}, objects=OPAQUE)
    except READ_ERRORS:
        return []

    def member_at(d: int) -> Optional[Tuple[int, int]]:
        ins = insns[d]
        if not (ins.mnemonic.startswith('ldr') or ins.mnemonic.startswith('ldur')):
            return None
        mem = mem_operand(ins.op_str)
        if mem is None or mem[2] is not None or flow.entry_arg(d, mem[1]) != 'x0':
            return None
        return mem[3], _load_width(ins, mem)

    calls = {c.k: c for c in region.calls}          # the fixpoint's last (final) state per call
    writes: List[MemberWrite] = []
    for k in sorted(calls):
        c = calls[k]
        if c.args.get('x0') != _WRITER_ARG or c.target is None:
            continue
        got = []
        for number_reg, value_reg in (('x2', 'x1'), ('x1', 'v0')):
            n = c.args.get(number_reg)
            if type(n) is int:
                member = _member_in(flow, insns, k, value_reg, member_at)
                if member is not None:
                    got.append((member, n))
        if len(got) != 1:
            continue
        (offset, width), n = got[0]
        writes.append(MemberWrite(offset, n, c.target, width))
    return writes


def match_layout(layout: StructLayout, writes: Sequence[MemberWrite]) -> Optional[Dict[int, int]]:
    """``{member offset: field number}`` when *writes* serialise exactly the members of
    *layout* — each offset once, the load width equal to the member's size, field numbers
    positive and distinct — else ``None``."""
    by_off = {m.offset: m for m in layout.members}
    got: Dict[int, int] = {}
    for w in writes:
        m = by_off.get(w.offset)
        if m is None or w.offset in got or w.width != m.size or w.number < 1:
            return None
        got[w.offset] = w.number
    if set(got) != set(by_off) or len(set(got.values())) != len(got):
        return None
    return got


# ── the owner's begin/end-marked sub-message write ────────────────────────────


# ── inlined struct members: a symbolic base-register data flow ─────────────────


def _load_width(ins, mem) -> int:
    """Bytes a load instruction reads (from its mnemonic / destination register width)."""
    if ins.mnemonic in _LOAD_WIDTH_MNEMONICS:
        return _LOAD_WIDTH_MNEMONICS[ins.mnemonic]
    return 4 if mem[0][0] in 'wsf' else 8


def _struct_load_step(flow, ins, k: int, state: Dict[str, tuple],
                      is_ivar_offset, is_array: bool) -> Optional[Tuple[int, int]]:
    """One instruction (``flow.insns[k]``) of the struct-addressing state (see
    :func:`track_struct_loads`); returns ``(member offset, width)`` when *ins* loads a member."""
    mn, ops = ins.mnemonic, split_ops(ins.op_str)
    if mn in CALLS:
        for r in flow.call_writes(k) or CALLER_SAVED_GPRS:
            state.pop(r, None)
        return None
    if not ops or mn in NO_DEST:
        return None
    dst = _norm_reg(ops[0])
    new, member = None, None
    if mn in LOAD_BYTES:
        mem = mem_operand(ins.op_str)
        slot = flow.slot_load_address(k)
        if slot is not None and is_ivar_offset(slot):
            new = ('ivoff',)                                        # the offset variable itself
        elif mem is not None:
            base_st = state.get(mem[1])
            idx_st = state.get(mem[2]) if mem[2] else None
            if idx_st == ('ivoff',):
                if is_array:
                    new = ('base', 0)                               # the element array
                else:
                    member = (0, _load_width(ins, mem))             # by value: member 0
            elif base_st == ('slot',) and mem[2] is None and mem[3] == 0:
                new = ('base', 0)                                   # the element array
            elif base_st is not None and base_st[0] == 'base':
                member = (base_st[1] + (mem[3] if mem[2] is None else 0), _load_width(ins, mem))
    elif mn == 'add' and len(ops) in (3, 4):                        # 4: ``add xE, xA, xI, lsl #s``
        a = state.get(_norm_reg(ops[1]))
        if ops[2].startswith('#'):
            if a and a[0] == 'base' and len(ops) == 3:
                new = ('base', a[1] + (_parse_imm(ops[2]) or 0))
        elif state.get(_norm_reg(ops[2])) == ('ivoff',) and len(ops) == 3:
            # &self->ivar: the struct itself (by value), or the slot holding the array pointer
            new = ('slot',) if is_array else ('base', 0)
        elif a and a[0] == 'base':
            new = ('base', a[1])                                    # array element
    elif mn == 'mov' and len(ops) == 2 and _norm_reg(ops[1]) in state:
        new = state[_norm_reg(ops[1])]
    if dst is not None:
        if new is not None:
            state[dst] = new
        else:
            state.pop(dst, None)
    return member


def track_struct_loads(ctx, insns: Sequence, last: int, is_ivar_offset, is_array: bool,
                       window=None) -> Dict[int, Tuple[int, int]]:
    """``{instruction index: (member offset, width)}`` for every load, among ``insns[:last+1]``
    (restricted to the indices in *window*, when given), that reads a member of the struct held
    in one particular ivar — found by following how the code addresses it:

    * the ivar's **offset variable** is loaded (``ldrsw xOff,[xPage, #k]``, its address by
      :meth:`Flow.slot_load_address`; *is_ivar_offset* says whether that address holds this
      ivar's offset);
    * **by value**: ``add xB, xSelf, xOff`` is the struct, members ``[xB, #k]`` (member 0 may
      be the load ``ldr xV,[xSelf, xOff]`` itself);
    * **array** (*is_array*): ``ldr xA,[xSelf, xOff]`` -- or ``add xS, xSelf, xOff`` (the
      address of the ivar, which holds the array pointer) then ``ldr xA,[xS]`` -- is the element
      array, ``add xE, xA, xI`` (``xI`` possibly scaled: ``, lsl #s``) an element, members
      ``[xE, #k]`` (member 0 may be ``[xA, xI]``).

    A forward data flow over the listing's CFG (:func:`proto.dispatch.listing_flow`): a
    register holds one of these roles at an instruction when every path into it agrees, so
    an offset load hoisted above a loop reaches the loop body, and a role set on one branch
    only does not.  A register written by anything not modelled -- and every caller-saved
    one across a call -- loses its role, so only a genuine chain from the offset variable
    yields a member."""
    flow = listing_flow(ctx, list(insns))
    cfg = flow.cfg
    if cfg.entry is None:
        return {}

    def run_block(b: int, state: arm64_eval.RegMap):
        for k in flow.block_range(b):
            _struct_load_step(flow, flow.insns[k], k, state, is_ivar_offset, is_array)
        return [(s, state) for s in cfg.succ.get(b, [])]

    out: Dict[int, Tuple[int, int]] = {}
    for b, st0 in flow.forward([(cfg.entry, arm64_eval.RegMap())], run_block).items():
        state = st0.copy()
        for k in flow.block_range(b):
            member = _struct_load_step(flow, flow.insns[k], k, state, is_ivar_offset, is_array)
            if member is not None and k <= last and (window is None or k in window):
                out[k] = member
    return out


def decode_inline_writes(ctx, insns: Sequence, bracket: Bracket, is_ivar_offset,
                         layout: StructLayout) -> List[MemberWrite]:
    """The member writes of a struct the compiler serialised INLINE in the owner's ``writeTo:``
    (no struct-writer function): between the begin/end marks each member is
    ``load [struct + offset] ; write(field#)``, the struct located through the ivar's offset
    variable (:func:`track_struct_loads`).  As in :func:`decode_struct_writer`, the AAPCS64
    argument positions say where the value is -- x1 with the field number in w2, or v0 with it
    in w1 -- and it must trace, by reaching definitions through copies (:func:`_member_in`), to
    one member load.  A write fed by anything else is skipped and the layout match
    (:func:`match_layout`) rejects an incomplete struct."""
    loads = track_struct_loads(ctx, insns, max(bracket.region), is_ivar_offset, layout.is_array,
                               window=set(bracket.region))
    flow = listing_flow(ctx, insns)
    out: List[MemberWrite] = []
    for k, n, helper in bracket.writes:
        got = [m for number_reg, value_reg in (('x2', 'x1'), ('x1', 'v0'))
               if flow.const_before(k, number_reg) == n
               and (m := _member_in(flow, insns, k, value_reg, loads.get)) is not None]
        if len(got) == 1:
            (offset, width), = got
            out.append(MemberWrite(offset, n, helper, width))
    return out


# ── member names: the struct's dictionary-representation function ─────────────

_IDENTIFIER = re.compile(r'^[A-Za-z_][A-Za-z0-9_]{0,63}$')
_DICTREP_SELECTOR = "_dictionaryRepresentation:"


def _cfstring(ctx, va: int) -> Optional[str]:
    """The text of the ``CFString`` constant at *va* when it reads as an identifier — the only
    kind of key a generated dictionary representation uses — else ``None``."""
    text = read_cfstring_text(ctx, va)
    return text if text is not None and _IDENTIFIER.match(text) else None


@dataclass(frozen=True)
class MemberDict:
    """What a struct's dictionary representation says about one member."""
    key: Optional[str]                                # the dictionary key (the member's name);
    # None when the key is chosen between two spellings that differ only in case -- the member
    # is still filed (its code is the member's), only its name is left to the @encode
    enum: Optional[Tuple[Tuple[int, str], ...]] = None
    # None: emitted as a plain number.  A tuple: the member's value is driven through an
    # enum-name switch (proto.dictrep_flow decides: the string handed to the call varies
    # with the value) -- the ``(value, name)`` pairs recovered from it, empty when two calls
    # filing the member show different pairs.


def _flow_for(ctx, insns: Sequence):
    """The :class:`Flow` of *insns* (memoised per list: one owner's members share it)."""
    cache = _ctx_cache(ctx, "_member_flows", dict)
    key = id(insns)
    hit = cache.get(key)
    if hit is None or hit[0] is not insns:
        try:
            arms = _jump_table_arm_addrs(ctx, list(insns))
        except READ_ERRORS:                      # CFG completion only; the evaluation itself
            arms = ()                          # follows `br` targets and does not need it
        hit = (insns, dictrep_flow.Flow(ctx, list(insns), jump_table_arms=arms))
        cache[key] = hit
    return hit[1]


def _key_spelling(cands: Sequence[str]) -> Tuple[Optional[str], bool]:
    """``(key, case_twins)`` for a key chosen between two spellings by the JSON flag
    (``isJSON ? @"camelCase" : @"snake_case"``): the camelCase one, the ivar/field naming
    convention; ``None`` when neither or both lack ``_`` -- *case_twins* when they are two
    spellings that differ only in case (``bTHFPx`` / ``BTHFPx``), whose member is still filed."""
    plain = [c for c in cands if '_' not in c]
    key = plain[0] if len(plain) == 1 else None
    return key, len(plain) == 2 and plain[0].lower() == plain[1].lower()


_SET_FOR_KEY = "setObject:forKey:"
_BOX_PREFIX = "numberWith"                 # +[NSNumber numberWithInt: / …Bool: / …UnsignedLongLong:]
_FP_BOXES = ("numberWithDouble:", "numberWithFloat:")
_COPIES = ('mov', 'fmov', 'fcvt')


def _boxed_member(ctx, flow, insns: Sequence, k: int, member_at) -> Optional[int]:
    """The member whose value the ``setObject:forKey:`` call at ``insns[k]`` files as a number,
    by use-def chain from its object argument x2: through ``mov`` copies to the result of a
    ``numberWith*`` send, whose value argument (x2; v0 for ``numberWithDouble:`` /
    ``numberWithFloat:``, the AAPCS64 float register) must come from a member load.  Between
    the two, a call that is not a message send is followed into its x0 argument only when that
    argument is the result of the call right before it -- the ARC return-value handshake
    (``bl numberWith… ; bl objc_retainAutoreleasedReturnValue``), whose callee returns its
    argument.  ``None`` for anything else."""
    reg, at, seen = 'x2', k, set()
    while (reg, at) not in seen:
        seen.add((reg, at))
        defs = flow.defs_before(at, reg)
        if len(defs) != 1:
            return None
        (d,) = defs
        if d < 0:
            return None
        ins, ops = insns[d], split_ops(insns[d].op_str)
        if ins.mnemonic == 'mov' and len(ops) == 2 and not ops[1].startswith('#'):
            reg, at = _norm_reg(ops[1]), d
            if reg is None or reg == 'xzr':
                return None
            continue
        if ins.mnemonic != 'bl' or reg != 'x0':
            return None
        sel = stub_selector(ctx, _parse_imm(ins.op_str))
        if sel is not None:
            if not sel.startswith(_BOX_PREFIX):
                return None
            return _member_in(flow, insns, d, 'v0' if sel in _FP_BOXES else 'x2', member_at)
        if flow.defs_before(d, 'x0') != frozenset((d - 1,)) or insns[d - 1].mnemonic != 'bl':
            return None
        at = d                                   # the handshake: x0 is the previous call's result
    return None


def _member_in(flow, insns: Sequence, k: int, reg: str, member_at) -> Optional[int]:
    """The member offset *reg* holds before ``insns[k]``: every definition reaching it is a
    member load, directly or through value-preserving copies (``mov`` / ``fmov`` / ``fcvt``:
    a float member boxed as a double), of the same member."""
    found = set()
    work, seen = [(k, reg)], set()
    while work:
        at, r = work.pop()
        if (at, r) in seen:
            continue
        seen.add((at, r))
        for d in flow.defs_before(at, r):
            if d < 0:
                return None
            off = member_at(d)
            if off is not None:
                found.add(off)
                continue
            ops = split_ops(insns[d].op_str)
            src = reg_name(ops[1]) if insns[d].mnemonic in _COPIES and len(ops) == 2 \
                and not ops[1].startswith('#') else None
            if src is None or src == 'xzr':
                return None
            work.append((d, src))
    return next(iter(found)) if len(found) == 1 else None


def _enum_calls(flow, insns: Sequence, calls, member_at) -> Dict[int, Dict[int, tuple]]:
    """``{call index: {member offset: (value, name) pairs}}``: the ``setObject:forKey:`` calls
    an enum member's name reaches.  Each member load is driven through the code by
    :meth:`proto.dictrep_flow.Flow.enum_of_load` (the class-level recovery's analysis; the
    other members' loads bound its code); a member is an enum there iff the string handed on
    varies with its value, and the call a named value's run stops at, with the name in x2,
    is the call that files it."""
    loads = frozenset(k for k in range(len(insns)) if member_at(k) is not None)
    out: Dict[int, Dict[int, tuple]] = {}
    for root in sorted(loads):
        res = flow.enum_of_load(root, loads - {root})
        if res is None or not res.pairs or res.name_reg != 'x2':
            continue
        pairs = tuple(sorted(res.pairs.items()))
        for v in res.pairs:
            c = res.stops.get(v)
            if c in calls:
                out.setdefault(c, {})[member_at(root)] = pairs
    return out


_NO_KEY = object()


def _call_key(ctx, runs, k: int):
    """The dictionary key of the ``setObject:forKey:`` call at ``insns[k]``: x3's value on every
    flag run that reaches it (:meth:`proto.arm64_eval.Flow.flag_runs`), a CFString
    identifier.  Two spellings across the flag values are resolved by :func:`_key_spelling`.
    Returns the key, ``None`` (an unresolvable spelling pair -- :data:`_CASE_TWINS` when the
    two differ only in case), or :data:`_NO_KEY` when x3 is not a constant identifier on some
    run (or no run reaches the call)."""
    texts = set()
    for run in runs:
        if k not in run:
            continue                                  # not reached with this flag value
        va = run[k].get('x3')
        text = _cfstring(ctx, va) if va is not None else None
        if text is None:
            return _NO_KEY
        texts.add(text)
    if not texts or len(texts) > 2:
        return _NO_KEY
    if len(texts) == 1:
        return next(iter(texts))
    key, twins = _key_spelling(sorted(texts))
    return _CASE_TWINS if key is None and twins else key


_CASE_TWINS = object()


def _pair_members(ctx, insns: Sequence, member_at) -> Tuple[Dict[int, MemberDict], int]:
    """Pair the dictionary keys of a dictionary-representation listing with the struct members
    they file: ``(members, unpaired)`` — ``{member offset: MemberDict}`` and how many keyed
    calls file no member.

    Every pairing is read at the ``setObject:forKey:`` call itself: the key is x3's value there
    (:func:`_call_key`: by constant propagation over the whole function, so a key hoisted out
    of a loop, chosen by the JSON flag or spilled to the stack is read as well as one built
    in place), the member is the one whose value x2 carries -- a number boxed from it
    (:func:`_boxed_member`), or an enum's name chosen by a switch on it (:func:`_enum_calls`).
    *member_at(k)* gives the member offset loaded by ``insns[k]`` (``None`` for any other
    instruction).  A member filed under two different keys keeps no name (nothing is guessed);
    a keyed call whose object traces to no member counts as unpaired."""
    calls = [k for k, ins in enumerate(insns) if ins.mnemonic == 'bl'
             and stub_selector(ctx, _parse_imm(ins.op_str)) == _SET_FOR_KEY]
    if not calls:
        return {}, 0
    flow = _flow_for(ctx, insns)
    runs = flow.flag_runs(calls)
    by_enum = _enum_calls(flow, insns, set(calls), member_at)
    keys: Dict[int, set] = {}
    enums: Dict[int, tuple] = {}
    unpaired = 0
    for k in calls:
        key = _call_key(ctx, runs, k)
        if key is _NO_KEY:
            continue
        if key is None:                               # two spellings, neither the camelCase one
            unpaired += 1
            continue
        if k in by_enum:
            if len(by_enum[k]) != 1:
                unpaired += 1                         # two members' names reach one call
                continue
            ((member, pairs),) = by_enum[k].items()
            if enums.setdefault(member, pairs) != pairs:
                enums[member] = ()
        else:
            member = _boxed_member(ctx, flow, insns, k, member_at)
            if member is None:
                unpaired += 1
                continue
        keys.setdefault(member, set()).add(None if key is _CASE_TWINS else key)
    members: Dict[int, MemberDict] = {}
    for off, ks in keys.items():
        if len(ks) != 1:
            log.debug("struct member +%#x filed under keys %r; name left unrecovered",
                      off, sorted(ks, key=str))
        members[off] = MemberDict(next(iter(ks)) if len(ks) == 1 else None, enums.get(off))
    return members, unpaired


def decode_dictrep_members(ctx, entry: int, offsets) -> Dict[int, MemberDict]:
    """``{member offset: MemberDict}`` read from a struct's dictionary-representation
    function at *entry* — ``NSDictionary *f(struct *x0)`` — or ``{}`` when it is not one (no
    key, or a key that files no member at one of the layout's *offsets*: e.g. the function of
    a LARGER struct that merely shares the first few offsets — :func:`_pair_members`)."""
    insns = _writer_insns(ctx, entry)
    base = {'x0'}
    for ins in insns:
        if ins.mnemonic in BLOCK_ENDS:
            break
        ops = split_ops(ins.op_str)
        if ins.mnemonic == 'mov' and len(ops) == 2 and _norm_reg(ops[1]) == 'x0' and _norm_reg(ops[0]):
            base.add(_norm_reg(ops[0]))

    def member_at(k):
        ins = insns[k]
        if ins.mnemonic in LOAD_BYTES:
            mem = mem_operand(ins.op_str)
            if mem is not None and mem[2] is None and mem[1] in base and mem[3] in offsets:
                return mem[3]
        return None

    members, unpaired = _pair_members(ctx, insns, member_at)
    return members if not unpaired else {}


def decode_inline_dictrep_members(ctx, insns: Sequence, is_ivar_offset,
                                  layout: StructLayout) -> Dict[int, MemberDict]:
    """``{member offset: MemberDict}`` for a struct whose dictionary representation the
    compiler inlined into the owner's ``_dictionaryRepresentation:`` (*insns*): the struct's
    members are located through the ivar's offset variable exactly as in the inline
    ``writeTo:`` (:func:`track_struct_loads`), so only this ivar's keys are paired."""
    want = {m.offset for m in layout.members}
    loads = track_struct_loads(ctx, insns, len(insns) - 1, is_ivar_offset, layout.is_array)
    members, _unpaired = _pair_members(
        ctx, insns, lambda k: loads[k][0] if k in loads and loads[k][0] in want else None)
    return members


# ── recording sites during extraction, resolving them afterwards ──────────────


@dataclass(frozen=True)
class StructSite:
    """A struct-typed field of one class and the ``writeTo:`` begin-mark bound
    to it: enough to analyse the write once the whole image is extracted."""
    ivar: str
    write_addr: int              # address of the begin-mark ``bl``
    ivar_offset: int             # the ivar's declared byte offset in the object
    number: int
    enc: str                     # the ivar's @encode


def record_struct_site(ctx, class_name: str, field_name: str, ivar_name: str,
                       ivar_offset: int, enc: Optional[str], write: Optional[BoundWrite]) -> None:
    """Remember a struct-typed field's bound begin-mark for :func:`finalize_struct_fields`.
    A no-op unless the ivar is a flat scalar struct and a write binds it."""
    if write is None:
        return
    if parse_struct_encoding(enc) is None:
        return
    _ctx_cache(ctx, "_struct_sites", dict)[(class_name, field_name)] = StructSite(
        ivar_name, write.addr, ivar_offset, write.number, enc)


_MEMBER_NAME_MISSING = ("member name not recovered (the struct's @encode names no members); "
                        "see LIMITATIONS.md (2)")
_STRUCT_COMMENT = ("inline C struct '{tag}' (no ObjC class): member layout from its @encode, "
                   "field numbers from the owner's writeTo: serialiser, member names from the "
                   "@encode or the owner's _dictionaryRepresentation:")


def _method_body(ctx, cls, selector: str) -> Optional[int]:
    """Where the class's *selector* method's code starts: its IMP, except that a
    ``_dictionaryRepresentation:`` a build leaves out of the method list is found through the
    public wrappers that tail-branch into it (:func:`proto.enums._find_dictrep_c_func`)."""
    if selector == _DICTREP_SELECTOR:
        return _find_dictrep_c_func(ctx, cls)
    m = cls.get_method(selector)
    return m.imp if m is not None and m.imp else None


def _linear_method(ctx, cls, selector: str, entries: FunctionEntries, memo: dict):
    """The class's *selector* method as one linear instruction list (its extent, out-of-line
    tail blocks included: :func:`proto.function_body.function_listing`), memoised per
    class."""
    key = (cls.name, selector)
    if key not in memo:
        imp = _method_body(ctx, cls, selector)
        insns = None
        if imp:
            try:
                insns = function_listing(ctx, imp, entries)
            except READ_ERRORS:
                insns = None
        memo[key] = insns
    return memo[key]


def _ivar_offset_test(ctx, site: StructSite):
    """Predicate "does the 4-byte word at this address hold the ivar's offset?".  The code
    reaches an ivar through a variable that holds its offset; the compiler keeps separate copies
    of that variable for different methods, so the VALUE (unique per ivar) identifies it."""
    def test(addr) -> bool:
        try:
            return addr is not None and ctx.read_s32(addr) == site.ivar_offset
        except READ_ERRORS:
            return False
    return test


def _decode_site(ctx, cls, site: StructSite, layout: StructLayout, entries, memo):
    """``({offset: field#}, {offset: helper})`` for one site, or ``None`` if its begin-mark
    body does not hold a struct serialiser matching *layout*."""
    insns = _linear_method(ctx, cls, "writeTo:", entries, memo)
    if not insns:
        return None
    idx = next((i for i, x in enumerate(insns) if x.addr == site.write_addr), None)
    if idx is None:
        return None
    br = analyze_bracket(ctx, insns, idx)
    if br is None or br.number != site.number:
        return None
    for callee in br.callees:
        writes = decode_struct_writer(ctx, callee)
        numbers = match_layout(layout, writes) if writes else None
        if numbers is not None:
            return numbers, {w.offset: w.helper for w in writes}
    if br.writes:                                                       # serialised inline
        writes = decode_inline_writes(ctx, insns, br, _ivar_offset_test(ctx, site), layout)
        numbers = match_layout(layout, writes) if writes else None
        if numbers is not None:
            return numbers, {w.offset: w.helper for w in writes}
    return None


def _unique_keys(members: Dict[int, MemberDict]) -> bool:
    keys = [md.key for md in members.values() if md.key]
    return len(set(keys)) == len(keys)


def _dictrep_members(ctx, cls, site: StructSite, layout: StructLayout, entries,
                     memo) -> Optional[Dict[int, MemberDict]]:
    """What this owner's ``_dictionaryRepresentation:`` says about *layout*'s members (key and
    enum-ness).

    Either the struct's own dictionary-representation function is CALLED (the unique
    ``{offset: member}`` among the callees whose members are exactly the layout's — several
    different ones mean the owner cannot say which is which), or the compiler inlined it, in
    which case the members are paired through the ivar's offset variable.  ``None`` if neither
    names every member."""
    insns = _linear_method(ctx, cls, _DICTREP_SELECTOR, entries, memo)
    if not insns:
        return None
    want = {m.offset for m in layout.members}
    found = set()
    cache = _ctx_cache(ctx, "_dictrep_names", dict)
    for ins in insns:
        if ins.mnemonic != 'bl':
            continue
        target = _parse_imm(ins.op_str)
        if target is None:
            continue
        key = (target, frozenset(want))
        if key not in cache:
            cache[key] = decode_dictrep_members(ctx, target, want)
        members = cache[key]
        if members and set(members) == want \
                and _unique_keys(members):
            found.add(tuple(sorted(members.items())))
    if len(found) == 1:
        return dict(next(iter(found)))
    if not found:
        members = decode_inline_dictrep_members(ctx, insns, _ivar_offset_test(ctx, site), layout)
        if members and _unique_keys(members):
            return members                   # possibly partial: unnamed members keep a placeholder
    return None


def _merge_names(per_owner) -> Optional[Dict[int, str]]:
    """The dictionary-representation names merged over the owners that could give any — or
    ``None`` when two owners name one member differently or two members share a name."""
    merged: Dict[int, str] = {}
    for d in per_owner:
        for off, key in (d or {}).items():
            if merged.setdefault(off, key) != key:
                return None
    return merged if len(set(merged.values())) == len(merged) else None


def _struct_member_names(items) -> Optional[Dict[int, str]]:
    """``{member offset: name}`` over the owners of one struct tag: the names the @encodes give
    (agreeing across the owners that give any), the dictionary representations' keys for the
    members no @encode names; ``None`` on a disagreement or a name two members share."""
    enc = _merge_names([{m.offset: m.name.lstrip('_') for m in l.members if m.name}
                        for _f, l, _n, _h, _d in items])
    if enc is None:
        return None
    rest = _merge_names([{off: md.key for off, md in (d or {}).items()
                          if md.key and off not in enc}
                         for _f, _l, _n, _h, d in items])
    if rest is None:
        return None
    merged = {**rest, **enc}
    return merged if len(set(merged.values())) == len(merged) else None


def _merge_enums(per_owner: Sequence[Optional[Dict[int, MemberDict]]]
                 ) -> Dict[int, Tuple[Tuple[int, str], ...]]:
    """``{member offset: (value, name) pairs}`` for the members that are enums, merged over the
    owners that could read their dictionary representation.

    An owner either shows a member's name switch or shows the member emitted as a plain
    number; owners that disagree on that leave the member a plain integer (nothing is
    guessed).  The pairs of several owners are united when no value gets two names, else the
    values are dropped (an enum whose values are not recovered: ``()``)."""
    seen: Dict[int, list] = {}
    for members in per_owner:
        for off, md in (members or {}).items():
            seen.setdefault(off, []).append(md.enum)
    out: Dict[int, Tuple[Tuple[int, str], ...]] = {}
    for off, enums in seen.items():
        if any(e is None for e in enums):
            if any(e is not None for e in enums):
                log.debug("struct member +%#x: owners disagree on enum-ness; left a number", off)
            continue
        merged: Dict[int, str] = {}
        clash = False
        for e in enums:
            for v, name in e:
                clash = clash or merged.setdefault(v, name) != name
        out[off] = () if clash else tuple(sorted(merged.items()))
    return out


def _make_enum(base_name: str, pairs: Sequence[Tuple[int, str]]) -> ProtoEnum:
    """The :class:`ProtoEnum` for a struct member's recovered *pairs*: the type name is
    reconstructed from the value names' common prefix (the binary stores no enum type names;
    see :func:`proto.enums._enum_name_from_pairs`), the value names normalised as the
    class-level recovery does."""
    name = _enum_name_from_pairs(list(pairs), base_name)
    if name == base_name:
        # value names spelled ``TypeName_VALUE`` (not SCREAMING_SNAKE, so the prefix rule above
        # passed on them) carry the C enum's own name
        heads = {raw.split('_', 1)[0] for _v, raw in pairs}
        if len(pairs) >= 2 and len(heads) == 1 and all('_' in raw for _v, raw in pairs):
            head = next(iter(heads))
            if re.match(r'^[A-Z][A-Za-z0-9]*[a-z][A-Za-z0-9]*$', head):
                name = head
    values = _enum_values_from_pairs(name, pairs)
    return ProtoEnum(name=name, values=values)


def finalize_struct_fields(ctx, cl, messages: List[ProtoMessage], prefixes=None) -> None:
    """Post-extraction pass (TODO #37): turn every ``bytes``-typed struct field whose
    serialiser was decoded into a message-typed field, synthesising one :class:`ProtoMessage`
    per struct tag (appended to *messages*).

    Sites are grouped by tag and every owner of a tag must agree on the member numbers and
    wire families — a disagreement leaves the whole tag as the flagged ``bytes`` fallback.
    A tag that collides with a real ObjC class or an existing message name is skipped."""
    sites = getattr(ctx, "_struct_sites", None) or {}
    if not sites:
        return
    entries = function_entries(ctx)
    by_class = {c.name: c for c in cl if not c.is_meta}
    taken_names = {m.name for m in messages}
    taken_classes = {m.class_name for m in messages} | set(by_class)
    memo: dict = {}

    groups: Dict[str, List[tuple]] = {}
    for msg in messages:
        cls = by_class.get(msg.class_name)
        for fld in msg.fields:
            site = sites.get((msg.class_name, fld.name))
            if site is None or cls is None or fld.type_name != "bytes":
                continue
            layout = parse_struct_encoding(site.enc)
            got = _decode_site(ctx, cls, site, layout, entries, memo) if layout else None
            if got is not None:
                dmembers = _dictrep_members(ctx, cls, site, layout, entries, memo)
                groups.setdefault(layout.tag, []).append((fld, layout, got[0], got[1], dmembers))

    for tag, items in sorted(groups.items()):
        numbers = {tuple(sorted(n.items())) for _f, _l, n, _h, _d in items}
        shapes = {tuple((m.offset, m.code) for m in l.members) for _f, l, _n, _h, _d in items}
        # member names: an @encode that names its members (``"_duration"I``) says so, and the
        # unnamed form of the same struct (an array's ``^{Tag=II…}``) leaves them to the
        # dictionary representation; every source that names a member must agree
        keyed = _struct_member_names(items)
        enum_pairs = _merge_enums([d for _f, _l, _n, _h, d in items])
        families: Dict[int, set] = {}
        for _f, _l, _n, helpers, _d in items:
            for off, h in helpers.items():
                families.setdefault(off, set()).add(_classify_write_helper(ctx, h))
        if len(numbers) != 1 or len(shapes) != 1 or keyed is None \
                or any(len(v) != 1 for v in families.values()):
            log.debug("struct %s: owners disagree on layout; left as bytes", tag)
            continue
        pname = _class_to_proto_name(tag, prefixes)
        if tag in taken_classes or pname in taken_names:
            log.debug("struct %s: name collides with an existing message; left as bytes", tag)
            continue
        layout, number_of = items[0][1], dict(items[0][2])
        fields, enums = [], []
        for m in layout.members:
            base = _SCALAR_ENC[m.code]
            fam = next(iter(families[m.offset]))
            ptype = _refine_scalar_by_family(base, fam)
            fname = keyed.get(m.offset)
            note = None if fname else _MEMBER_NAME_MISSING
            if note is None and fam == "unknown" and base in ("int32", "int64", "uint32", "uint64"):
                note = INT_ENCODING_NOTE
            fld = ProtoField(
                name=fname or f"field{number_of[m.offset]}", number=number_of[m.offset],
                type_name=ptype, label=FieldLabel.OPTIONAL, number_confirmed=True,
                type_inference_note=note)
            if m.offset in enum_pairs and ptype in ("int32", "uint32"):
                pairs = enum_pairs[m.offset]
                if pairs:
                    enum = _make_enum(_qualify_enum_name(pname, fld.name[:1].upper() + fld.name[1:]),
                                      pairs)
                    fld.type_name, fld.type_class = enum.name, f"ENUM:{enum.name}"
                    enums.append(enum)
                else:
                    fld.disambiguation_comment = _ENUM_UNRESOLVED_COMMENT
            fields.append(fld)
        messages.append(ProtoMessage(
            name=pname, class_name=tag, fields=fields, enums=enums,
            inline_struct=_STRUCT_COMMENT.format(tag=tag)))
        taken_names.add(pname)
        taken_classes.add(tag)
        for fld, _l, _n, _h, _d in items:
            fld.type_name, fld.type_class, fld.type_inference_note = tag, tag, None
