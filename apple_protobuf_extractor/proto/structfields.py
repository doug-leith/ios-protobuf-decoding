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

from macho.disasm import disasm, _parse_imm, _norm_reg
from macho.memory import _ctx_cache

from proto.arm64cfg import split_ops, mem_operand, _next_imp
from proto.config import _class_to_proto_name
from proto.mapfields import _scratch_slot_of
from proto.models import FieldLabel, ProtoField, ProtoMessage
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


def _cfstring(ctx, va: int) -> Optional[str]:
    """The text of the ``CFString`` constant at *va* (``isa, flags, chars*, length``) when it
    reads as an identifier — the only kind of key a generated dictionary representation uses
    — else ``None``."""
    try:
        chars, length = ctx.read_ptr(va + 16), ctx.read_u64(va + 24)
        if not chars or not 0 < length <= 64:
            return None
        text = ctx.read_bytes(chars, length).decode('ascii')
    except Exception:
        return None
    return text if _IDENTIFIER.match(text) else None


def _pair_keys(ctx, insns: Sequence, member_at) -> Tuple[Dict[int, str], int]:
    """Pair each dictionary key in a dictionary-representation listing with the struct member
    it files: ``(names, unpaired)`` — ``{member offset: key}`` and how many keys found no member.

    *member_at(k)* gives the member offset loaded by ``insns[k]`` (``None`` for any other
    instruction).  A key is a ``CFString`` constant built into x3 (``adrp x3 ; add x3,x3,#imm``)
    — or chosen by ``csel x3`` between two of them (``isJSON ? @"camelCase" : @"snake_case"``,
    of which the camelCase spelling, the ivar/field naming convention, is taken) — and belongs
    to the closest preceding member load."""
    names: Dict[int, str] = {}
    unpaired = 0
    member: Optional[int] = None
    pages: Dict[str, int] = {}              # reg -> page set by the last ``adrp``
    consts: Dict[str, int] = {}             # reg -> address built by ``adrp`` + ``add``
    for k, ins in enumerate(insns):
        m = member_at(k)
        if m is not None:
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
        key, is_key = None, False
        if mn == 'add' and ops and ops[0] == 'x3' and 'x3' in consts:
            key = _cfstring(ctx, consts['x3'])
            is_key = key is not None
        elif mn == 'csel' and len(ops) == 4 and ops[0] == 'x3':
            cands = [_cfstring(ctx, consts[r]) for r in ops[1:3] if r in consts]
            is_key = len(cands) == 2 and None not in cands
            plain = [c for c in cands if c and '_' not in c]
            key = plain[0] if is_key and len(plain) == 1 else None
        if not is_key:
            continue
        if key is None or member is None or member in names:
            unpaired += 1
        else:
            names[member] = key
        member = None
    return names, unpaired


def decode_dictrep_names(ctx, entry: int, offsets) -> Dict[int, str]:
    """``{member offset: dictionary key}`` read from a struct's dictionary-representation
    function at *entry* — ``NSDictionary *f(struct *x0)`` — or ``{}`` when it is not one (no
    key, or a key that files no member at one of the layout's *offsets*: e.g. the function of
    a LARGER struct that merely shares the first few offsets — :func:`_pair_keys`)."""
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

    names, unpaired = _pair_keys(ctx, insns, member_at)
    return names if not unpaired else {}


def decode_inline_dictrep_names(ctx, insns: Sequence, is_ivar_offset,
                                layout: StructLayout) -> Dict[int, str]:
    """``{member offset: key}`` for a struct whose dictionary representation the compiler
    inlined into the owner's ``_dictionaryRepresentation:`` (*insns*): the struct's members
    are located through the ivar's offset variable exactly as in the inline ``writeTo:``
    (:func:`track_struct_loads`), so only this ivar's keys are paired."""
    want = {m.offset for m in layout.members}
    loads = track_struct_loads(insns, len(insns) - 1, is_ivar_offset, layout.is_array)
    names, _unpaired = _pair_keys(
        ctx, insns, lambda k: loads[k][0] if k in loads and loads[k][0] in want else None)
    return names


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


def _dictrep_names(ctx, cls, site: StructSite, layout: StructLayout, foreign_sorted,
                   memo) -> Optional[Dict[int, str]]:
    """The member names this owner's ``_dictionaryRepresentation:`` gives *layout*.

    Either the struct's own dictionary-representation function is CALLED (the unique
    ``{offset: key}`` among the callees whose members are exactly the layout's — several
    different ones mean the owner cannot say which is which), or the compiler inlined it, in
    which case the keys are paired through the ivar's offset variable.  ``None`` if neither
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
            cache[key] = decode_dictrep_names(ctx, target, want)
        names = cache[key]
        if names and set(names) == want and len(set(names.values())) == len(names):
            found.add(tuple(sorted(names.items())))
    if len(found) == 1:
        return dict(next(iter(found)))
    if not found:
        names = decode_inline_dictrep_names(ctx, insns, _ivar_offset_test(ctx, site), layout)
        if names and len(set(names.values())) == len(names):
            return names                     # possibly partial: unnamed members keep a placeholder
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
                dnames = (None if all(m.name for m in layout.members)
                          else _dictrep_names(ctx, cls, site, layout, foreign_sorted, memo))
                groups.setdefault(layout.tag, []).append((fld, layout, got[0], got[1], dnames))

    for tag, items in sorted(groups.items()):
        numbers = {tuple(sorted(n.items())) for _f, _l, n, _h, _d in items}
        names = {tuple(m.name for m in l.members) for _f, l, _n, _h, _d in items}
        keyed = _merge_names(d for _f, _l, _n, _h, d in items)
        families: Dict[int, set] = {}
        for _f, _l, _n, helpers, _d in items:
            for off, h in helpers.items():
                families.setdefault(off, set()).add(_classify_write_helper(ctx, h))
        if len(numbers) != 1 or len(names) != 1 or keyed is None \
                or any(len(v) != 1 for v in families.values()):
            log.debug("struct %s: owners disagree on layout; left as bytes", tag)
            continue
        pname = _class_to_proto_name(tag, prefixes)
        if tag in taken_classes or pname in taken_names:
            log.debug("struct %s: name collides with an existing message; left as bytes", tag)
            continue
        layout, number_of = items[0][1], dict(items[0][2])
        fields = []
        for m in layout.members:
            base = _SCALAR_ENC[m.code]
            ptype = _refine_scalar_by_family(base, next(iter(families[m.offset])))
            fname = m.name.lstrip('_') if m.name else keyed.get(m.offset)
            fields.append(ProtoField(
                name=fname or f"field{number_of[m.offset]}", number=number_of[m.offset],
                type_name=ptype, label=FieldLabel.OPTIONAL, number_confirmed=True,
                type_inference_note=None if fname else _MEMBER_NAME_MISSING))
        messages.append(ProtoMessage(
            name=pname, class_name=tag, fields=fields,
            inline_struct=_STRUCT_COMMENT.format(tag=tag)))
        taken_names.add(pname)
        taken_classes.add(tag)
        for fld, _l, _n, _h, _d in items:
            fld.type_name, fld.type_class, fld.type_inference_note = tag, tag, None
