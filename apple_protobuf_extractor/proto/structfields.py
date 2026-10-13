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
  the CFString ``"(unknown: %i)"``) before its key; a plain number goes through ``NSNumber``.
  :func:`decode_dictrep_members` reads that per member and, from the same compare chain or
  pointer table the class-level enum recovery reads (:mod:`proto.enums`), the value names;
* **validation** — the writer's member offsets and load widths must match the encoding's
  layout exactly (:func:`match_layout`): every member written once, no write at an unknown
  offset.  A struct that does not match is left as the flagged ``bytes`` fallback, never
  guessed.

The owner-side entry point mirrors :mod:`proto.mapfields`: ``extract_proto_message`` records
the ``writeTo:`` CFG-walk event that bound the begin-mark to the struct ivar
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

from macho.arm64decode import (_decode_bcond, _decode_cmp_imm, _decode_ldr_reg_off,
                               range_from_unsigned_gate)
from macho.disasm import disasm, find_adrp_add_target, _parse_imm, _norm_reg
from macho.memory import _ctx_cache

from proto.arm64cfg import split_ops, mem_operand, _next_imp
from proto.config import _class_to_proto_name
from proto.dispatch import _read_raw_word
from proto.enums import (_ENUM_UNRESOLVED_COMMENT, _enum_name_from_pairs, _harvest_cbz_value0,
                         _harvest_isolated_compares, _normalize_enum_value_name,
                         _qualify_enum_name, _read_dictrep_pointer_pairs, _sub_imm_bias)
from proto.mapfields import _scratch_slot_of
from proto.models import FieldLabel, ProtoEnum, ProtoEnumValue, ProtoField, ProtoMessage
from proto.writeto import _writeto_field_number_before
from proto.write_helpers import _classify_write_helper, _refine_scalar_by_family
from proto.protocore import _SCALAR_ENC

log = logging.getLogger(__name__)

# ── @encode parsing ───────────────────────────────────────────────────────────

# C scalar @encode char -> size in bytes (also its natural alignment).
_SCALAR_SIZE = {'c': 1, 'C': 1, 'B': 1, 's': 2, 'S': 2, 'i': 4, 'I': 4, 'l': 4, 'L': 4,
                'f': 4, 'q': 8, 'Q': 8, 'd': 8}

# The anonymous has-bits struct ``{?=b1b1…}`` (and its named form ``"_has"{?="x"b1…}``) is
# presence bookkeeping, not data.  Clang packs it as an ``unsigned int`` bitfield group.
_HAS_BITS_SIZE = 4


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

# [cap:INPUT-SANITY] runaway backstops for the writer walk, not tuned bounds: a struct writer
# is a handful of straight-line blocks of ~10 instructions, one per member.
_WRITER_MAX_BLOCKS = 64
_WRITER_BLOCK_INSNS = 128
# How far (bytes) a local branch may reach from the writer's entry and still be a block of
# the same function rather than a tail call into another one.
_WRITER_LOCAL_SPAN = 0x800
# How many instructions back from a write call the value load may sit.
_VALUE_LOAD_WINDOW = 12

_LOAD_WIDTH_MNEMONICS = {'ldrb': 1, 'ldrh': 2, 'ldursb': 1, 'ldursh': 2, 'ldurb': 1, 'ldurh': 2,
                         'ldrsb': 1, 'ldrsh': 2, 'ldrsw': 4, 'ldursw': 4}
_BRANCH_MNEMONICS = frozenset(('b', 'bl', 'br', 'blr', 'braa', 'brab', 'blraa', 'blrab',
                               'ret', 'retaa', 'retab', 'cbz', 'cbnz', 'tbz', 'tbnz'))


@dataclass(frozen=True)
class MemberWrite:
    """One member serialisation read from a struct writer."""
    offset: int          # byte offset of the member in the struct
    number: int          # the proto field number it is written with
    helper: int          # the write helper called (VA; a stub is followed when classifying)
    width: int           # bytes loaded from the struct for the value


def _branch_target(ins) -> Optional[int]:
    ops = split_ops(ins.op_str)
    return _parse_imm(ops[-1]) if ops and ops[-1].startswith('#') else None


def _writer_insns(ctx, entry: int) -> List:
    """The instructions reachable from *entry* in address order: conditional branches and
    in-function jumps are followed, ``ret`` and a tail-called write helper end a path."""
    seen_blocks, work, out = set(), [entry], {}
    while work and len(seen_blocks) < _WRITER_MAX_BLOCKS:
        a = work.pop()
        if a in seen_blocks or a in out:
            continue
        seen_blocks.add(a)
        try:
            block = disasm(ctx, a, max_insns=_WRITER_BLOCK_INSNS, stop_at_ret=True)
        except Exception:
            continue
        for k, ins in enumerate(block):
            if ins.addr in out:
                break
            out[ins.addr] = ins
            mn = ins.mnemonic
            if mn in ('cbz', 'cbnz', 'tbz', 'tbnz') or mn.startswith('b.'):
                t = _branch_target(ins)
                if t is not None:
                    work.append(t)
            elif mn == 'b':
                if _writeto_field_number_before(block, k) is not None:
                    break                                   # tail-called write helper
                t = _branch_target(ins)
                if t is not None and abs(t - entry) < _WRITER_LOCAL_SPAN:
                    work.append(t)
                break
    return [out[a] for a in sorted(out)]


def _dest_kind(ins) -> Optional[str]:
    """Which argument register an instruction defines: ``'int'`` for x1/w1, ``'fp'`` for
    d0/s0 (a floating-point value argument), else None."""
    ops = split_ops(ins.op_str)
    if not ops or ins.mnemonic.startswith('st') or ins.mnemonic in ('cmp', 'cmn', 'tst'):
        return None
    d = ops[0]
    if d in ('x1', 'w1'):
        return 'int'
    if d in ('d0', 's0') or d.startswith('v0.'):
        return 'fp'
    return None


def _value_load(insns: Sequence, j: int, base_regs, fp_hint: bool) -> Optional[Tuple[int, int]]:
    """``(member_offset, width)`` of the ``ldr`` that produced the value argument of the write
    call at ``insns[j]``: the closest earlier definition of x1/w1 (or d0/s0 for a float/double
    field, whose field number is the one in w1) within the same straight-line run, which must
    be a load from ``[struct_base + offset]``.  ``None`` for any other source."""
    want = 'fp' if fp_hint else 'int'
    for k in range(j - 1, max(j - _VALUE_LOAD_WINDOW, -1), -1):
        ins = insns[k]
        if ins.mnemonic in _BRANCH_MNEMONICS and ins.mnemonic not in ('tbz', 'tbnz', 'cbz', 'cbnz'):
            return None
        if _dest_kind(ins) != want:
            continue
        mem = mem_operand(ins.op_str)
        if (mem is None or mem[2] is not None or mem[1] not in base_regs
                or not (ins.mnemonic.startswith('ldr') or ins.mnemonic.startswith('ldur'))):
            return None
        vreg = mem[0]
        if ins.mnemonic in _LOAD_WIDTH_MNEMONICS:
            width = _LOAD_WIDTH_MNEMONICS[ins.mnemonic]
        elif vreg[0] in 'wsf':
            width = 4
        elif vreg[0] in 'xd':
            width = 8
        else:
            return None
        return mem[3], width
    return None


def decode_struct_writer(ctx, entry: int) -> List[MemberWrite]:
    """The member writes of the struct serialiser at *entry* — ``f(struct *x0, writer x1)`` —
    in address order; ``[]`` when it writes no member (not a struct writer).

    A write is any call/tail-call that sets a field number (``mov w2,#N``; ``w1`` for a
    float/double, whose value rides in d0/s0 — :func:`proto.writeto._writeto_field_number_before`)
    and whose value argument is loaded straight from ``[struct + offset]``.  A write whose
    value does not trace to a struct member is skipped here and the layout match
    (:func:`match_layout`) then rejects the struct as incomplete."""
    insns = _writer_insns(ctx, entry)
    # The struct pointer arrives in x0; the prologue copies it into a callee-saved register
    # (``mov x20, x0``) that every member load then uses.  Aliases are read from the entry run
    # only (up to its first call/branch), so an epilogue ``ldp x20,…`` restore on one path
    # cannot be mistaken for a redefinition on another.
    base = {'x0'}
    for ins in insns:
        if ins.mnemonic in _BRANCH_MNEMONICS:
            break
        ops = split_ops(ins.op_str)
        if ins.mnemonic == 'mov' and len(ops) == 2 and _norm_reg(ops[1]) == 'x0' and _norm_reg(ops[0]):
            base.add(_norm_reg(ops[0]))
    writes: List[MemberWrite] = []
    for j, ins in enumerate(insns):
        mn = ins.mnemonic
        if mn not in ('bl', 'b'):
            continue
        n = _writeto_field_number_before(insns, j)
        target = _branch_target(ins)
        if n is None or target is None:
            continue
        # the field number sits in w1 exactly when the value is a float/double in d0/s0
        fp = any(i2.mnemonic in ('mov', 'movz') and i2.op_str.startswith('w1,')
                 for i2 in insns[max(j - 6, 0):j])
        got = _value_load(insns, j, base, fp)
        if got is None:
            continue
        writes.append(MemberWrite(got[0], n, target, got[1]))
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


@dataclass(frozen=True)
class Bracket:
    """What one ``begin(F) … end`` sub-message write in an owner's ``writeTo:`` contains."""
    number: int                  # the field number the begin mark carries
    callees: Tuple[int, ...]     # calls with no field number — candidate struct writers
    region: Tuple[int, ...]      # indices (into the listing) of every instruction between the marks
    writes: Tuple[Tuple[int, int, int], ...]   # inline member writes: (index, field#, helper)


# [cap:INPUT-SANITY] runaway backstop for the bracket walk, not a tuned bound: a sub-message
# body is a few dozen instructions (an inlined struct with has-bit jump tables a few hundred).
_BRACKET_MAX_INSNS = 4096


def analyze_bracket(insns: Sequence, begin_idx: int) -> Optional[Bracket]:
    """Analyse the sub-message write whose BEGIN mark (``bl`` with a stack-scratch ``x1`` and a
    literal field number) is at ``insns[begin_idx]`` in the owner's linear ``writeTo:``
    listing.  The body is every instruction reachable from the mark WITHOUT passing the
    matching END mark (same scratch slot, no field number): the branches an inlined struct's
    has-bit tests compile to put some members out of line, past the loop's back-edge, so a
    straight read to the end mark would miss them.

    Returns the field number, the calls inside that carry NO field number (candidate struct
    serialisers ``f(&struct, writer)``) and the calls that DO carry one (members written
    inline), or ``None`` if there is no begin mark here, a path leaves the listing or reaches
    ``ret`` before an end mark, or a nested/foreign mark appears (an unmodelled shape)."""
    begin = insns[begin_idx]
    slot = _scratch_slot_of(insns, begin_idx)
    if begin.mnemonic != 'bl' or slot is None:
        return None
    number = _writeto_field_number_before(insns, begin_idx)
    if number is None or number < 1:
        return None
    at = {ins.addr: k for k, ins in enumerate(insns)}
    seen, work = set(), [begin_idx + 1]
    callees: List[int] = []
    writes: List[Tuple[int, int, int]] = []
    ended = False
    while work:
        k = work.pop()
        while k is not None and 0 <= k < len(insns) and k not in seen:
            if len(seen) > _BRACKET_MAX_INSNS:
                return None
            seen.add(k)
            ins, mn, nxt = insns[k], insns[k].mnemonic, k + 1
            if mn in ('ret', 'retaa', 'retab'):
                return None                          # a path with no end mark
            if mn in ('bl', 'b'):
                j_slot = _scratch_slot_of(insns, k) if mn == 'bl' else None
                fn = _writeto_field_number_before(insns, k)
                target = _branch_target(ins)
                if j_slot is not None:
                    if fn is None and j_slot == slot:
                        ended = True
                        break                        # END mark: this path is complete
                    return None                      # nested begin / foreign scratch
                if fn is not None and target is not None:
                    writes.append((k, fn, target))
                elif mn == 'bl' and target is not None:
                    callees.append(target)
                if mn == 'b':
                    if fn is not None:
                        return None                  # a tail-called write ends the function: no end mark
                    t = at.get(target)
                    if t is None:
                        return None
                    nxt = t                          # in-function jump
            elif mn in ('cbz', 'cbnz', 'tbz', 'tbnz') or mn.startswith('b.'):
                t = at.get(_branch_target(ins))
                if t is None:
                    return None
                work.append(t)
            k = nxt
    if not ended:
        return None
    return Bracket(number, tuple(dict.fromkeys(callees)), tuple(sorted(seen)), tuple(writes))


# ── inlined struct members: a symbolic base-register tracker ──────────────────


def _load_width(ins, mem) -> int:
    """Bytes a load instruction reads (from its mnemonic / destination register width)."""
    if ins.mnemonic in _LOAD_WIDTH_MNEMONICS:
        return _LOAD_WIDTH_MNEMONICS[ins.mnemonic]
    return 4 if mem[0][0] in 'wsf' else 8


_CALLER_SAVED = [f'x{i}' for i in range(18)]
_LOAD_MNEMONICS = ('ldrsw', 'ldr', 'ldrb', 'ldrh', 'ldur')
_NO_DEST_MNEMONICS = ('cmp', 'cmn', 'tst', 'tbz', 'tbnz', 'cbz', 'cbnz', 'b')


def track_struct_loads(insns: Sequence, last: int, is_ivar_offset, is_array: bool,
                       window=None) -> Dict[int, Tuple[int, int]]:
    """``{instruction index: (member offset, width)}`` for every load, among ``insns[:last+1]``
    (restricted to the indices in *window*, when given), that reads a member of the struct held
    in one particular ivar — found by following how the code addresses it:

    * the ivar's **offset variable** is loaded (``ldrsw xOff,[xPage, #k]``; *is_ivar_offset*
      says whether that address holds this ivar's offset);
    * **by value**: ``add xB, xSelf, xOff`` is the struct, members ``[xB, #k]`` (member 0 may
      be the load ``ldr xV,[xSelf, xOff]`` itself);
    * **array** (*is_array*): ``ldr xA,[xSelf, xOff]`` is the element array, ``add xE, xA, xI``
      an element, members ``[xE, #k]`` (member 0 may be ``[xA, xI]``).

    Registers are tracked in address order from the start of the listing (the offset load is
    often hoisted above the loop); a register written by anything not modelled — and every
    caller-saved one across a call — is forgotten, so only a genuine chain from the offset
    variable yields a member."""
    pages: Dict[str, int] = {}
    state: Dict[str, tuple] = {}                    # reg -> ('ivoff',) | ('base', offset)
    out: Dict[int, Tuple[int, int]] = {}
    for k in range(last + 1):
        ins = insns[k]
        mn, ops = ins.mnemonic, split_ops(ins.op_str)
        if mn == 'bl':
            for r in _CALLER_SAVED:
                state.pop(r, None)
                pages.pop(r, None)
            continue
        if not ops or mn.startswith('st') or mn in _NO_DEST_MNEMONICS:
            continue
        dst = _norm_reg(ops[0])
        new = None
        if mn == 'adrp' and len(ops) == 2:
            pages[dst] = _parse_imm(ops[1])
            state.pop(dst, None)
            continue
        if mn in _LOAD_MNEMONICS or mn.startswith('ldrs'):
            mem = mem_operand(ins.op_str)
            if mem is None:                                         # PC-relative literal
                if mn == 'ldrsw' and len(ops) == 2 and is_ivar_offset(_parse_imm(ops[1])):
                    new = ('ivoff',)
            else:
                base_st = state.get(mem[1])
                idx_st = state.get(mem[2]) if mem[2] else None
                if mn == 'ldrsw' and mem[2] is None and mem[1] in pages \
                        and is_ivar_offset(pages[mem[1]] + mem[3]):
                    new = ('ivoff',)                                # the offset variable itself
                elif idx_st == ('ivoff',):
                    if is_array:
                        new = ('base', 0)                           # the element array
                    elif window is None or k in window:
                        out[k] = (0, _load_width(ins, mem))         # by value: member 0
                elif base_st is not None and base_st[0] == 'base' and (window is None or k in window):
                    out[k] = (base_st[1] + (mem[3] if mem[2] is None else 0), _load_width(ins, mem))
        elif mn == 'add' and len(ops) == 3:
            a = state.get(_norm_reg(ops[1]))
            if ops[2].startswith('#'):
                if a and a[0] == 'base':
                    new = ('base', a[1] + (_parse_imm(ops[2]) or 0))
            elif state.get(_norm_reg(ops[2])) == ('ivoff',):
                new = ('base', 0)                                   # &self->ivar (by value)
            elif a and a[0] == 'base':
                new = ('base', a[1])                                # array element
        elif mn == 'mov' and len(ops) == 2 and _norm_reg(ops[1]) in state:
            new = state[_norm_reg(ops[1])]
        if dst is not None:
            if new is not None:
                state[dst] = new
            else:
                state.pop(dst, None)
            if mn != 'adrp':
                pages.pop(dst, None)
    return out


def decode_inline_writes(ctx, insns: Sequence, bracket: Bracket, is_ivar_offset,
                         layout: StructLayout) -> List[MemberWrite]:
    """The member writes of a struct the compiler serialised INLINE in the owner's ``writeTo:``
    (no struct-writer function): between the begin/end marks each member is
    ``load [struct + offset] ; write(field#)``, the struct located through the ivar's offset
    variable (:func:`track_struct_loads`).  Only loads that resolve to a struct member count;
    a write fed by anything else is skipped and the layout match (:func:`match_layout`)
    rejects an incomplete struct."""
    loads = track_struct_loads(insns, max(bracket.region), is_ivar_offset, layout.is_array,
                               window=set(bracket.region))
    out: List[MemberWrite] = []
    for k, n, helper in bracket.writes:
        fp = any(i2.mnemonic in ('mov', 'movz') and i2.op_str.startswith('w1,')
                 for i2 in insns[max(k - 6, 0):k])
        want = 'fp' if fp else 'int'
        for j in range(k - 1, max(k - _VALUE_LOAD_WINDOW, -1), -1):
            if _dest_kind(insns[j]) == want:
                if j in loads:
                    out.append(MemberWrite(loads[j][0], n, helper, loads[j][1]))
                break
    return out


# ── member names: the struct's dictionary-representation function ─────────────

_IDENTIFIER = re.compile(r'^[A-Za-z_][A-Za-z0-9_]{0,63}$')
_DICTREP_SELECTOR = "_dictionaryRepresentation:"


def _cfstring_text(ctx, va: int) -> Optional[str]:
    """The ASCII text of the ``CFString`` constant at *va* (``isa, flags, chars*, length``),
    else ``None``."""
    try:
        chars, length = ctx.read_ptr(va + 16), ctx.read_u64(va + 24)
        if not chars or not 0 < length <= 64:
            return None
        return ctx.read_bytes(chars, length).decode('ascii')
    except Exception:
        return None


def _cfstring(ctx, va: int) -> Optional[str]:
    """The text of the ``CFString`` constant at *va* when it reads as an identifier — the only
    kind of key a generated dictionary representation uses — else ``None``."""
    text = _cfstring_text(ctx, va)
    return text if text is not None and _IDENTIFIER.match(text) else None


# The CFString a generated ``xAsString:`` falls back to for a value it has no name for.
_UNKNOWN_FORMAT = "(unknown: %i)"


@dataclass(frozen=True)
class MemberDict:
    """What a struct's dictionary representation says about one member."""
    key: Optional[str]                                # the dictionary key (the member's name);
    # None when the key is chosen between two spellings that differ only in case -- the member
    # is still filed (its code is the member's), only its name is left to the @encode
    enum: Optional[Tuple[Tuple[int, str], ...]] = None
    # None: emitted as a plain number.  A tuple: emitted through an enum-name switch
    # (``"(unknown: %i)"``) — the ``(value, name)`` pairs recovered from it, empty when the
    # switch is of a shape this pass does not read.


def _references_unknown_format(ctx, span: Sequence) -> bool:
    """True if *span* builds the address of the ``"(unknown: %i)"`` CFString (``adrp rP ;
    add rD, rP, #imm``)."""
    pages: Dict[str, int] = {}
    for ins in span:
        ops = split_ops(ins.op_str)
        if ins.mnemonic == 'adrp' and len(ops) == 2 and _parse_imm(ops[1]) is not None:
            pages[ops[0]] = _parse_imm(ops[1])
        elif ins.mnemonic == 'add' and len(ops) == 3 and ops[1] in pages \
                and _parse_imm(ops[2]) is not None \
                and _cfstring_text(ctx, pages[ops[1]] + _parse_imm(ops[2])) == _UNKNOWN_FORMAT:
            return True
    return False


def _table_base(span: Sequence, upto: int, reg: str) -> Optional[int]:
    """Address built into *reg* by the NEAREST ``adrp``/``add`` pair before ``span[upto]`` (a
    span re-uses its scratch registers; the live pair is the closest one)."""
    for j in range(upto - 1, -1, -1):
        if span[j].mnemonic == 'adrp':
            t = find_adrp_add_target(span[j:upto + 1], reg)
            if t is not None:
                return t
    return None


def _gate_range(span: Sequence, words: Dict[int, int], upto: int) -> int:
    """Number of table entries the NEAREST ``cmp wN,#imm ; b.hs|b.hi`` range gate before
    ``span[upto]`` admits (0 if none).  The span is one member's code, so the whole of it is
    searched: a sparse table's validity-bitmask test (``mov/movk ; lsr ; tbnz``) sits between
    the gate and the table load."""
    for j in range(upto - 1, -1, -1):
        cmp = _decode_cmp_imm(words.get(span[j].addr, 0))
        if cmp is None:
            continue
        nxt = _decode_bcond(words.get(span[j + 1].addr, 0)) if j + 1 < len(span) else None
        n = range_from_unsigned_gate(nxt, cmp[1])
        if n:
            return n
    return 0


def _span_valid_mask(span: Sequence) -> Optional[int]:
    """The validity bitmask of a sparse-enum pointer table in *span*, or ``None``.

    A table with holes (values the enum does not declare) is gated by a constant mask::

        mov w10,#0xff9f ; movk w10,#3,lsl #16 ; lsr w10,w10,w9 ; tbnz w10,#0,<table load>

    — bit v of the mask set = value v is declared; the holes' table slots hold a filler name
    that must not be read as a value.  The gate branches either way round (``tbnz`` to the
    load, or ``tbz`` to the unknown branch); the mask means the same.  (Same shape as
    :func:`proto.enums._valid_value_bitmask`, which reads only the ``tbz`` form.)"""
    consts: Dict[str, int] = {}
    for i, ins in enumerate(span):
        ops, mn = split_ops(ins.op_str), ins.mnemonic
        if mn in ('mov', 'movz') and len(ops) == 2 and ops[1].startswith('#'):
            if _norm_reg(ops[0]) and _parse_imm(ops[1]) is not None:
                consts[_norm_reg(ops[0])] = _parse_imm(ops[1])
        elif mn == 'movk' and len(ops) == 3 and ops[2].startswith('lsl'):
            r, v, sh = _norm_reg(ops[0]), _parse_imm(ops[1]), _parse_imm(ops[2].split()[-1])
            if r in consts and v is not None and sh is not None:
                consts[r] = (consts[r] & ~(0xFFFF << sh)) | (v << sh)
        elif mn == 'lsr' and len(ops) == 3 and i + 1 < len(span):
            nxt, nops = span[i + 1], split_ops(span[i + 1].op_str)
            if _norm_reg(ops[1]) in consts and nxt.mnemonic in ('tbz', 'tbnz') and len(nops) == 3 \
                    and _norm_reg(nops[0]) == _norm_reg(ops[0]) and _parse_imm(nops[1]) == 0:
                return consts[_norm_reg(ops[1])]
    return None


def _span_enum_pairs(ctx, span: Sequence) -> Tuple[Tuple[int, str], ...]:
    """The ``(value, name)`` pairs of the enum-name switch inside *span* (one member's code in a
    dictionary representation), by the two shapes the class-level recovery reads: a compare
    chain (``cbz`` / ``cmp ; b.eq|b.ne``, each arm loading its CFString) and a pointer table
    (``cmp #n ; b.hs unknown ; ldr x,[table, idx, lsl #3]``).  Empty if neither is present."""
    words = {}
    for ins in span:
        w = _read_raw_word(ctx, ins.addr)
        if w is not None:
            words[ins.addr] = w
    found: Dict[int, str] = {}
    _harvest_isolated_compares(ctx, span, words, lambda v, n: found.setdefault(v, n))
    _harvest_cbz_value0(ctx, span, words, lambda v, n: found.setdefault(v, n))
    for i, ins in enumerate(span):
        d = _decode_ldr_reg_off(words.get(ins.addr, 0))
        if d is None or d[0] != 8:                                  # 64-bit pointer-table load
            continue
        _esz, base_rn, idx_reg, _rt = d
        n = _gate_range(span, words, i)
        table = _table_base(span, i, f"x{base_rn}")
        if n < 2 or table is None:
            continue
        bias = _sub_imm_bias(span, words, 0, i, dest_reg=idx_reg) or 0
        mask = _span_valid_mask(span[:i])               # a sparse table: bit v set = v declared
        for v, name in _read_dictrep_pointer_pairs(ctx, table, n):
            if mask is None or (mask >> v) & 1:
                found.setdefault(v + bias, name)
    return tuple(sorted(found.items()))


def _pair_members(ctx, insns: Sequence, member_at) -> Tuple[Dict[int, MemberDict], int]:
    """Pair each dictionary key in a dictionary-representation listing with the struct member
    it files: ``(members, unpaired)`` — ``{member offset: MemberDict}`` and how many keys found
    no member.

    *member_at(k)* gives the member offset loaded by ``insns[k]`` (``None`` for any other
    instruction).  A key is a ``CFString`` constant built into x3 (``adrp x3 ; add x3,x3,#imm``)
    — or chosen by ``csel x3`` between two of them (``isJSON ? @"camelCase" : @"snake_case"``,
    of which the camelCase spelling, the ivar/field naming convention, is taken) — and belongs
    to the closest preceding member load.  The code between that member's first load and its
    key is the member's own: an enum member's holds the name switch (:class:`MemberDict`)."""
    members: Dict[int, MemberDict] = {}
    unpaired = 0
    member: Optional[int] = None
    first_load = 0                          # index of the current member's first load
    pages: Dict[str, int] = {}              # reg -> page set by the last ``adrp``
    consts: Dict[str, int] = {}             # reg -> address built by ``adrp`` + ``add``
    for k, ins in enumerate(insns):
        m = member_at(k)
        if m is not None:
            if m != member:
                first_load = k
            member = m
            continue
        mn, ops = ins.mnemonic, split_ops(ins.op_str)
        if mn == 'adrp' and len(ops) == 2 and _parse_imm(ops[1]) is not None:
            pages[ops[0]] = _parse_imm(ops[1])
            consts.pop(ops[0], None)
            continue
        if mn == 'add' and len(ops) == 3 and ops[1] == ops[0] and ops[0] in pages \
                and _parse_imm(ops[2]) is not None:
            consts[ops[0]] = pages[ops[0]] + _parse_imm(ops[2])
        key, is_key, case_twins = None, False, False
        if mn == 'add' and ops and ops[0] == 'x3' and 'x3' in consts:
            key = _cfstring(ctx, consts['x3'])
            is_key = key is not None
        elif mn == 'csel' and len(ops) == 4 and ops[0] == 'x3':
            cands = [_cfstring(ctx, consts[r]) for r in ops[1:3] if r in consts]
            is_key = len(cands) == 2 and None not in cands
            plain = [c for c in cands if c and '_' not in c]
            key = plain[0] if is_key and len(plain) == 1 else None
            case_twins = (is_key and len(plain) == 2 and plain[0].lower() == plain[1].lower())
        if not is_key:
            continue
        if (key is None and not case_twins) or member is None or member in members:
            unpaired += 1
        else:
            span = insns[first_load:k + 1]
            members[member] = MemberDict(
                key, _span_enum_pairs(ctx, span) if _references_unknown_format(ctx, span) else None)
        member = None
    return members, unpaired


def _pair_keys(ctx, insns: Sequence, member_at) -> Tuple[Dict[int, str], int]:
    """:func:`_pair_members` reduced to the keys: ``({member offset: key}, unpaired)``."""
    members, unpaired = _pair_members(ctx, insns, member_at)
    return {off: md.key for off, md in members.items() if md.key}, unpaired


def decode_dictrep_members(ctx, entry: int, offsets) -> Dict[int, MemberDict]:
    """``{member offset: MemberDict}`` read from a struct's dictionary-representation
    function at *entry* — ``NSDictionary *f(struct *x0)`` — or ``{}`` when it is not one (no
    key, or a key that files no member at one of the layout's *offsets*: e.g. the function of
    a LARGER struct that merely shares the first few offsets — :func:`_pair_members`)."""
    insns = _writer_insns(ctx, entry)
    base = {'x0'}
    for ins in insns:
        if ins.mnemonic in _BRANCH_MNEMONICS:
            break
        ops = split_ops(ins.op_str)
        if ins.mnemonic == 'mov' and len(ops) == 2 and _norm_reg(ops[1]) == 'x0' and _norm_reg(ops[0]):
            base.add(_norm_reg(ops[0]))

    def member_at(k):
        ins = insns[k]
        if ins.mnemonic in _LOAD_MNEMONICS:
            mem = mem_operand(ins.op_str)
            if mem is not None and mem[2] is None and mem[1] in base and mem[3] in offsets:
                return mem[3]
        return None

    members, unpaired = _pair_members(ctx, insns, member_at)
    return members if not unpaired else {}


def decode_dictrep_names(ctx, entry: int, offsets) -> Dict[int, str]:
    """``{member offset: dictionary key}`` — :func:`decode_dictrep_members` reduced to the keys."""
    return {off: md.key for off, md in decode_dictrep_members(ctx, entry, offsets).items()
            if md.key}


def decode_inline_dictrep_members(ctx, insns: Sequence, is_ivar_offset,
                                  layout: StructLayout) -> Dict[int, MemberDict]:
    """``{member offset: MemberDict}`` for a struct whose dictionary representation the
    compiler inlined into the owner's ``_dictionaryRepresentation:`` (*insns*): the struct's
    members are located through the ivar's offset variable exactly as in the inline
    ``writeTo:`` (:func:`track_struct_loads`), so only this ivar's keys are paired."""
    want = {m.offset for m in layout.members}
    loads = track_struct_loads(insns, len(insns) - 1, is_ivar_offset, layout.is_array)
    members, _unpaired = _pair_members(
        ctx, insns, lambda k: loads[k][0] if k in loads and loads[k][0] in want else None)
    return members


def decode_inline_dictrep_names(ctx, insns: Sequence, is_ivar_offset,
                                layout: StructLayout) -> Dict[int, str]:
    """:func:`decode_inline_dictrep_members` reduced to the keys."""
    return {off: md.key for off, md in
            decode_inline_dictrep_members(ctx, insns, is_ivar_offset, layout).items() if md.key}


# ── recording sites during extraction, resolving them afterwards ──────────────


@dataclass(frozen=True)
class StructSite:
    """A struct-typed field of one class and the ``writeTo:`` begin-mark the CFG walk bound
    to it: enough to analyse the write once the whole image is extracted."""
    ivar: str
    write_addr: int              # address of the begin-mark ``bl``
    ivar_offset: int             # the ivar's declared byte offset in the object
    number: int
    enc: str                     # the ivar's @encode


def record_struct_site(ctx, class_name: str, field_name: str, ivar_name: str,
                       ivar_offset: int, enc: Optional[str], write: Optional[dict]) -> None:
    """Remember a struct-typed field's walk-bound begin-mark for :func:`finalize_struct_fields`.
    A no-op unless the ivar is a flat scalar struct and the walk bound a write to it."""
    if write is None or write.get('write_addr') is None or write.get('n') is None:
        return
    if parse_struct_encoding(enc) is None:
        return
    _ctx_cache(ctx, "_struct_sites", dict)[(class_name, field_name)] = StructSite(
        ivar_name, write['write_addr'], ivar_offset, write['n'], enc)


_MEMBER_NAME_MISSING = ("member name not recovered (the struct's @encode names no members); "
                        "see LIMITATIONS.md (2)")
_STRUCT_COMMENT = ("inline C struct '{tag}' (no ObjC class): member layout from its @encode, "
                   "field numbers from the owner's writeTo: serialiser, member names from the "
                   "@encode or the owner's _dictionaryRepresentation:")


def _linear_method(ctx, cls, selector: str, foreign_sorted: List[int], memo: dict):
    """The class's *selector* method as one linear instruction list (``imp`` .. next method
    IMP — its structural extent, including out-of-line tail blocks), memoised per class."""
    key = (cls.name, selector)
    if key not in memo:
        m = cls.get_method(selector)
        insns = None
        if m is not None and m.imp:
            end = _next_imp(foreign_sorted, m.imp)
            try:
                insns = disasm(ctx, m.imp, max_insns=max(64, (end - m.imp) // 4),
                               stop_at_ret=False)
            except Exception:
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
        except Exception:
            return False
    return test


def _decode_site(ctx, cls, site: StructSite, layout: StructLayout, foreign_sorted, memo):
    """``({offset: field#}, {offset: helper})`` for one site, or ``None`` if its begin-mark
    body does not hold a struct serialiser matching *layout*."""
    insns = _linear_method(ctx, cls, "writeTo:", foreign_sorted, memo)
    if not insns:
        return None
    idx = next((i for i, x in enumerate(insns) if x.addr == site.write_addr), None)
    if idx is None:
        return None
    br = analyze_bracket(insns, idx)
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


def _dictrep_members(ctx, cls, site: StructSite, layout: StructLayout, foreign_sorted,
                     memo) -> Optional[Dict[int, MemberDict]]:
    """What this owner's ``_dictionaryRepresentation:`` says about *layout*'s members (key and
    enum-ness).

    Either the struct's own dictionary-representation function is CALLED (the unique
    ``{offset: member}`` among the callees whose members are exactly the layout's — several
    different ones mean the owner cannot say which is which), or the compiler inlined it, in
    which case the members are paired through the ivar's offset variable.  ``None`` if neither
    names every member."""
    insns = _linear_method(ctx, cls, _DICTREP_SELECTOR, foreign_sorted, memo)
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
    values, used = [], set()
    for value, raw in pairs:
        vname = _normalize_enum_value_name(name, raw)
        if vname in used:
            vname = f"{vname}_{value}"
        used.add(vname)
        values.append(ProtoEnumValue(name=vname, number=value))
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
    foreign_sorted = sorted(getattr(ctx, "_writeto_foreign_imps", None) or ())
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
            got = _decode_site(ctx, cls, site, layout, foreign_sorted, memo) if layout else None
            if got is not None:
                dmembers = _dictrep_members(ctx, cls, site, layout, foreign_sorted, memo)
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
            ptype = _refine_scalar_by_family(base, next(iter(families[m.offset])))
            fname = keyed.get(m.offset)
            fld = ProtoField(
                name=fname or f"field{number_of[m.offset]}", number=number_of[m.offset],
                type_name=ptype, label=FieldLabel.OPTIONAL, number_confirmed=True,
                type_inference_note=None if fname else _MEMBER_NAME_MISSING)
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
