"""swift_namemap_bytecode.py — decoder for the packed-bytecode ``_NameMap`` used by
newer swift-protobuf / InternalSwiftProtobuf toolchains (iOS 27 and later).

Wired into :func:`swift_descriptor_extract._extract_namemap` as shape E (a fallback
reached only when no other shape recovered fields).  Strictly self-validating:
:func:`decode_namemap_bytecode` returns ``None`` unless the literal has the header,
only known opcodes, NUL-terminated names and is consumed exactly, so a non-bytecode
literal (e.g. the bare-name literal of a single-field message) can never be misread
as fields.

Format (swift-protobuf ``NameMap.swift``, ``ProtoNameInstruction``).  The
generator emits ``_NameMap(bytecode: "<string literal>")`` instead of a runtime
dictionary literal, so the (number, name) table is a plain byte string in
``__TEXT,__cstring``::

    00                      header byte
    <op> [delta] name 00 …  one instruction per field

    op 1 sameNext     proto name == JSON name, number = prev + 1
    op 2 sameDelta    same, number = prev + <delta>
    op 3 standardNext JSON name derived from proto name, number = prev + 1
    op 4 standardDelta  "                                 number = prev + <delta>
    op 5/6 uniqueNext/Delta   proto name, then JSON name (two NUL-terminated strings)
    op 7/8 groupNext/Delta    group type name
    op 9/10 aliasNext/Delta   enum value: primary name, then <count> and that many alias
                              names (all share the primary's number)
    op 11 reservedName        reserved name (no field)
    op 12 reservedNumbers     reserved range (no field)

Integers (deltas, reserved numbers) use the 6-bit/0x40-continuation form of
:func:`_varint` and are SIGNED 32-bit (two's complement): an enum with a negative or
zero first value is encoded with an explicit delta (``T_NEG = -5`` is
``02 {\x7f\x7f\x7f\x7f\x03`` = -5).  Field numbers are >= 1; enum values may be any
int32.

Only the structure the extractor needs is returned: ``(number, proto_name)``.

How the literal is found (iOS 27 / arm64e): the type's ``_protobuf_nameMap`` getter
either tail-calls a shared template (``adrp/add x1,<storage>; adrp/add x2,<literal>;
mov w3,#<len>; b <template>``) or calls ``_NameMap.init(bytecode:)`` inline with
``StaticString(x0=ptr, w1=len, w2=2)`` — see :func:`bytecode_literal_from_getter`.
"""
from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from macho.disasm import _parse_imm
from macho.memory import READ_ERRORS
from proto.arm64_eval import Flow
from proto.arm64_operands import CALLS, INDIRECT_BRANCHES, split_ops

_SAME_NEXT, _SAME_DELTA = 1, 2
_STD_NEXT, _STD_DELTA = 3, 4
_UNIQUE_NEXT, _UNIQUE_DELTA = 5, 6
_GROUP_NEXT, _GROUP_DELTA = 7, 8
_ALIAS_NEXT, _ALIAS_DELTA = 9, 10
_RESERVED_NAME, _RESERVED_NUMBERS = 11, 12
_MAX_FIELD_NUMBER = 0x1FFFFFFF


def _varint(buf: bytes, i: int) -> Tuple[int, int]:
    """The bytecode's integer encoding; returns (value, next_i).

    The literal is a Swift *string*, so every byte must stay valid UTF-8 (<0x80):
    no LEB128 high-bit continuation.  Instead each byte carries 6 payload bits and
    bit 6 (0x40) is the continuation flag, least-significant group first
    (``'Y' 0x01`` = 0x19 | 1<<6 = 89).  Inferred from the data and validated
    against independent ``traverse`` numbers -- see the unit tests.  Raises
    ValueError on truncation."""
    val = shift = 0
    while True:
        if i >= len(buf) or shift > 30:
            raise ValueError("truncated integer")
        b = buf[i]
        i += 1
        val |= (b & 0x3F) << shift
        if not b & 0x40:
            return val, i
        shift += 6


def _int32(v: int) -> int:
    """Reinterpret an unsigned 32-bit group-assembled value as signed."""
    v &= 0xFFFFFFFF
    return v - (1 << 32) if v & 0x80000000 else v


def _cstr(buf: bytes, i: int) -> Tuple[str, int]:
    end = buf.find(b"\x00", i)
    if end < 0:
        raise ValueError("unterminated name")
    return buf[i:end].decode("utf-8", "replace"), end + 1


def decode_namemap_bytecode(raw: bytes, enum: bool = False) -> Optional[List[Tuple[int, str]]]:
    """Decode a ``_NameMap`` bytecode literal to ``[(number, proto_name), …]``.

    Returns ``None`` when *raw* is not a well-formed bytecode (so a caller can
    fall through to another shape instead of fabricating fields).  Reserved
    names/ranges are skipped.  An enum alias list yields the primary entry and then
    one entry per alias with the SAME number, in source order.  *enum* admits any
    int32 value (zero and negative included); otherwise numbers must be valid
    field numbers (>= 1)."""
    if not raw or raw[0] != 0:
        return None
    out: List[Tuple[int, str]] = []
    i, prev = 1, 0
    try:
        while i < len(raw):
            op = raw[i]
            i += 1
            if op == _RESERVED_NAME:
                _, i = _cstr(raw, i)
                continue
            if op == _RESERVED_NUMBERS:
                _, i = _varint(raw, i)
                _, i = _varint(raw, i)
                continue
            if not _SAME_NEXT <= op <= _ALIAS_DELTA:
                return None
            if op % 2 == 0:                     # *Delta form: explicit (signed) delta first
                delta, i = _varint(raw, i)
                num = prev + _int32(delta)
            else:
                num = prev + 1
            name, i = _cstr(raw, i)
            names = [name]
            if op in (_UNIQUE_NEXT, _UNIQUE_DELTA):
                _, i = _cstr(raw, i)            # JSON name
            elif op in (_ALIAS_NEXT, _ALIAS_DELTA):
                count, i = _varint(raw, i)
                if count > 64:
                    return None
                for _ in range(count):
                    alias, i = _cstr(raw, i)
                    names.append(alias)
            lo = -(1 << 31) if enum else 1
            hi = (1 << 31) - 1 if enum else _MAX_FIELD_NUMBER
            if not lo <= num <= hi or not all(names):
                return None
            prev = num
            out.extend((num, nm) for nm in names)
    except ValueError:
        return None
    return out


_MAX_LITERAL_LEN = 4096
_W = 0xFFFFFFFF


def call_site_registers(ctx, insns,
                        flow: Optional[Flow] = None) -> List[Tuple[int, Dict[str, int]]]:
    """``(k, registers known before insns[k])`` at each call in the listing *insns* -- a
    ``bl`` / ``blr``, and a tail call: a ``b`` to an address outside the listing or a ``br``
    -- in address order, by :meth:`proto.arm64_eval.Flow.propagate` from its entry (calls
    clobber the caller-saved registers).  *flow*: the listing's Flow, when already built."""
    inside = {i.addr for i in insns}
    ks = []
    for k, ins in enumerate(insns):
        mn = ins.mnemonic
        ops = split_ops(ins.op_str)
        tail = ((mn == "b" and ops and _parse_imm(ops[-1]) not in inside)
                or mn in INDIRECT_BRANCHES)
        if tail or mn in CALLS:
            ks.append(k)
    regs = (flow or Flow(ctx, list(insns))).propagate({}, at=ks)
    return [(k, regs[k]) for k in ks if k in regs]


def bytecode_literal_from_getter(ctx, insns, enum: bool = False,
                                 flow: Optional[Flow] = None) -> Optional[bytes]:
    """Locate the bytecode string literal passed to ``_NameMap.init(bytecode:)``
    from a getter's listing (the instructions its entry reaches).  Two lowerings:

    * **tail-call**: ``adrp/add x1,<slot>; adrp/add x2,<literal>; mov w3,#len;
      b <shared-template>`` -- literal in ``x2``, length in ``w3``;
    * **inline**: the getter itself calls the initialiser, ``adrp/add x9,<literal>;
      mov x0,x9; mov w1,#len; mov w2,#2; bl <_NameMap.init(bytecode:)>`` -- the
      ``StaticString`` is (``x0`` ptr, ``w1`` len, ``w2`` flags=2 utf8-pointer).

    The registers are read at each call (:func:`call_site_registers`), in address order,
    up to the first tail call.  The tail-call candidate is only a CANDIDATE: callers must
    validate it with :func:`decode_namemap_bytecode`, which declines anything that is not a
    well-formed bytecode."""
    for k, regs in call_site_registers(ctx, insns, flow):
        if insns[k].mnemonic not in CALLS:                   # tail-call form
            if regs.get("x2") is not None and regs.get("x3", 0) & _W:
                return _read(ctx, regs["x2"], regs["x3"] & _W)
            return None
        if (regs.get("x0") is not None and regs.get("x1", 0) & _W     # inline form
                and regs.get("x2", 0) & _W == 2):
            lit = _read(ctx, regs["x0"], regs["x1"] & _W)
            if lit is not None and decode_namemap_bytecode(lit, enum=enum):
                return lit
    return None


def _in_cstrings(ctx, va) -> bool:
    """*va* lies in the image's ``__TEXT,__cstring`` (where a literal lives: a length read off
    a pair of registers that hold something else is not one)."""
    if not ctx.has_section("__TEXT", "__cstring"):
        return False
    sec = ctx.section("__TEXT", "__cstring")
    return sec.vmaddr <= va < sec.vmaddr + sec.vmsize


def _read(ctx, va, length) -> Optional[bytes]:
    if length > _MAX_LITERAL_LEN and _in_cstrings(ctx, va):
        from proto.models import record_heuristic_hit
        record_heuristic_hit(ctx, "_MAX_LITERAL_LEN",
                             f"the name-map literal at {va:#x} ({length} bytes) is refused")
    if not 1 <= length <= _MAX_LITERAL_LEN:
        return None
    try:
        return ctx.read_bytes(va, length)
    except READ_ERRORS:
        return None

