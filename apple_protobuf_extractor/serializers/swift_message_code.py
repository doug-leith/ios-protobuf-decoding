"""serializers/swift_message_code.py -- a swift-protobuf message's fields read off its own code:
which ``Decoder`` method its ``decodeMessage`` calls for each field number and the property it
hands it, and which ``Visitor`` method its ``traverse`` calls (TODO #129).

**Where the code is.**  Each conformance to swift-protobuf's ``Message`` (a ``__swift5_proto``
record) names the conforming type and its witnesses: as resilient witnesses (requirement, then
implementation; the conformance to a protocol of another module), or as a witness table whose
slots follow the protocol's requirements.  A requirement is named by its method descriptor's
symbol (``...7MessageP8traverse...Tq``).  A witness that only forwards its arguments to one
function of the image (the ``TW`` thunk) is that function.  No symbol of the message's own is
needed: a public type's ``traverse`` is an export, not a local symbol, and an image may have
neither.

**What decodeMessage decodes.**  The body runs with self (x20), the decoder (x0), its type (x1)
and its ``Decoder`` witness table (x2) as pointers into objects (:class:`proto.arm64_eval.Objects`
*pointer*): ``&self.field`` is self plus the field's offset, a value loaded from an object is an
object of its own (a copy-on-write message's ``_storage``), a call's result another.  Each call
is named by its target's symbol (a dispatch thunk ``...7DecoderP...Tj``) or, through a ``blr``,
by the Decoder requirement at the witness-table slot its target was loaded from.  From the
``nextFieldNumber`` call the body is run once per field number N (x0 = N, the optional's tag
x1 = 0) until it comes back round the loop (:meth:`Flow.run_from`); the functions an arm calls
(the generated ``try { try decoder.decode...(value: &self._x) }()`` closures) are run with the
arguments the arm hands them.  N's ``decode<Singular|Repeated><Kind>Field`` / ``decodeMapField``
call, less what an unknown number also reaches, is its field: the method gives the kind, the
metadata it is handed the type (a message's or an enum's in x1; a map's key and value type in x1,
x2 -- its thin ``fieldType`` takes no register), and the pointer in x0 the property's object and
offset where they are static (a library-evolution build reads its offsets from the metadata).
"""
from __future__ import annotations

import re
import struct
from dataclasses import dataclass
from typing import Dict, List, NamedTuple, Optional, Tuple

from macho.memory import READ_ERRORS, BinaryContext, _ctx_cache
from proto.arm64_eval import Flow, Objects
from proto.arm64_operands import CALLS, CALLER_SAVED
from proto.callees import callee_name
from proto.function_body import function_body

# addresses into the objects a run cannot see into: object k's window, from POINTER_BASE
POINTER_BASE = 1 << 82
_WINDOW = 1 << 36
SELF, DECODER, DECODER_TYPE, DECODER_WITNESSES = range(4)
# the Swift runtime's retains return their argument
_RETURNS_ARGUMENT = frozenset(("_swift_retain", "_swift_bridgeObjectRetain", "_swift_unknownObjectRetain"))
# A run decodes a message no one else holds: a copy-on-write message's storage is its own (the
# copy that a shared one takes first fills the same fields), so `_uniqueStorage()` returns the
# storage self holds and the run keeps one object for it.
_UNIQUELY_REFERENCED = frozenset(("_swift_isUniquelyReferenced_nonNull_native",
                                  "_swift_isUniquelyReferenced_native",
                                  "_swift_isUniquelyReferencedNonObjC_nonNull"))
# a Decoder requirement, by its descriptor's, dispatch thunk's or a witness's symbol, or a
# decoder type's method that implements one (``BinaryDecoder.decodeSingularDoubleField``: ``V``)
_DECODE_RE = re.compile(r"[PV]\d+(?:decode(Singular|Repeated)(\w+?)Field5value|"
                        r"(decodeMapField)9fieldType5value|(nextFieldNumber)S)")
_MAX_DEPTH = 3                       # [cap:INPUT-SANITY] arm -> closure -> helper
_MAX_FIELD_NUMBER = 0x1FFFFFFF


def pointer(k: int, off: int = 0) -> int:
    return POINTER_BASE + k * _WINDOW + off


def is_pointer(v: Optional[int]) -> bool:
    return v is not None and POINTER_BASE <= v < POINTER_BASE + (1 << 20) * _WINDOW


def split(v: int) -> Tuple[int, int]:
    """``(object, offset)`` of a pointer."""
    return (v - POINTER_BASE) // _WINDOW, (v - POINTER_BASE) % _WINDOW


class _Objects:
    """The objects of one message's runs: self, the decoder, its type and witness table, then
    each value loaded from one (*origin*: ``("load", object, offset)``) and each call's result
    (``("call", function, index)``)."""

    def __init__(self, ctx: BinaryContext):
        self.ctx = ctx
        self.origin: Dict[int, tuple] = {SELF: ("self",), DECODER: ("decoder",),
                                         DECODER_TYPE: ("decoder type",),
                                         DECODER_WITNESSES: ("decoder witnesses",)}
        self._ids: Dict[tuple, int] = {}

    def _object(self, key: tuple) -> int:
        if key not in self._ids:
            self._ids[key] = len(self.origin)
            self.origin[self._ids[key]] = key
        return pointer(self._ids[key])

    def objects(self, function: int) -> Objects:
        def field_value(v, disp):
            k, off = split(v)
            return self._object(("load", k, off + disp))

        def call_result(k, target, x0):
            name = callee_name(self.ctx, target)
            if is_pointer(x0) and name in _RETURNS_ARGUMENT:
                return x0
            if name in _UNIQUELY_REFERENCED:
                return 1
            return self._object(("call", function, k, target, x0))
        return Objects(pointer=is_pointer, field_value=field_value, call_result=call_result,
                       object_escape=True)


@dataclass
class Decoded:
    """What field N's code does with one ``Decoder`` call: the method's label (Singular /
    Repeated / Map) and kind (Double, Message, ...); the type it is handed (a message's or an
    enum's, by its metadata: :func:`metadata_type`; a map's key and value); and, when the
    pointer it decodes through is known, the property's object (``("self",)``, or ``("load",
    object, offset)`` for one held by another: a ``_storage``) and byte offset in it."""
    label: str
    kind: str
    type: Optional[str] = None
    origin: Optional[tuple] = None
    offset: Optional[int] = None


# ── conformances ──────────────────────────────────────────────────────────────

def _i32(ctx, va):
    return struct.unpack("<i", ctx.read_bytes(va, 4))[0]


def _u32(ctx, va):
    return struct.unpack("<I", ctx.read_bytes(va, 4))[0]


def _rel(ctx, va):
    return va + _i32(ctx, va)


def _rel_indirect(ctx, va) -> Tuple[int, bool]:
    """A relative indirectable pointer: ``(target, through a slot)``; for an indirect one the
    slot's address (its value read by :func:`_slot_name` / ``read_ptr``)."""
    v = _i32(ctx, va)
    return (va + (v & ~1), True) if v & 1 else (va + v, False)


def _symbols(ctx) -> Dict[int, str]:
    """address -> name of the symbols that can name a swift-protobuf requirement or protocol."""
    from serializers.swift_descriptor_extract import _visitor_symbols

    def build():
        out: Dict[int, str] = {}
        for n, a in _visitor_symbols(ctx).items():
            out.setdefault(a, n)
        return out
    return _ctx_cache(ctx, "_swift_requirement_symbols", build)


def _named(ctx, va: int, indirect: bool) -> Optional[str]:
    """The symbol a (possibly indirect) reference names: an indirect one's slot holds the
    address (bound: the import's name)."""
    if indirect:
        raw = ctx.read_ptr(va)
        name = ctx.import_name_for_bind(raw) if hasattr(ctx, "import_name_for_bind") else None
        if name:
            return name
        va = raw
    return _symbols(ctx).get(va)


# traverse(visitor:) / decodeMessage(decoder:), as a requirement's or a witness's symbol spells
# them ("Message" a word substitution: ``06decodeD07decoder``, ``06decodeF07decoder``)
_TRAVERSE_RE = re.compile(r"8traverse7visitor")
_DECODE_MESSAGE_RE = re.compile(r"(?:13decodeMessage|06decode[A-Z]\d?)7decoder")


class Code(NamedTuple):
    """A function, and the constants the forwarders on the way to it hand it in x3-x8 (a
    ``merged`` body's per-type parts: identical-code folding passes them as arguments)."""
    va: int
    args: Tuple[Tuple[str, int], ...] = ()


def message_witnesses(ctx) -> Dict[int, Dict[str, Code]]:
    """``{type descriptor: {"traverse": Code, "decodeMessage": Code}}`` for each conformance of
    the image to swift-protobuf's ``Message`` (SwiftProtobuf or InternalSwiftProtobuf).
    Memoised."""
    return _ctx_cache(ctx, "_swift_message_witnesses", lambda: _message_witnesses(ctx))


def _message_witnesses(ctx) -> Dict[int, Dict[str, Code]]:
    try:
        sec = ctx.section("__TEXT", "__swift5_proto")
    except READ_ERRORS:
        return {}
    out: Dict[int, Dict[str, Code]] = {}
    for rec in range(sec.vmaddr, sec.vmaddr + sec.vmsize, 4):
        try:
            cd = _rel(ctx, rec)
            proto, ind = _rel_indirect(ctx, cd)
            pname = _named(ctx, proto, ind) or ""
            if not pname.endswith("7MessageMp"):
                continue
            flags = _u32(ctx, cd + 12)
            kind = (flags >> 3) & 7
            tref = _rel(ctx, cd + 4)
            tdesc = tref if kind == 0 else ctx.read_ptr(tref) if kind == 1 else None
            if not tdesc:
                continue
            found: Dict[str, Code] = {}
            at = cd + 16 + (4 if flags & (1 << 6) else 0) + 12 * ((flags >> 8) & 0xFF)
            if flags & (1 << 16):                  # resilient witnesses: requirement, impl
                for i in range(_u32(ctx, at)):
                    w = at + 4 + 8 * i
                    req, rind = _rel_indirect(ctx, w)
                    _note(ctx, found, _named(ctx, req, rind), _rel(ctx, w + 4))
            else:                                  # a witness table, in requirement order
                names = _slot_names(ctx, pname)
                wt = _rel(ctx, cd + 8)
                for i, req in names.items():
                    for name in req:
                        _note(ctx, found, name, ctx.read_ptr(wt + 8 + 8 * i))
            if found:
                out[tdesc] = found
        except READ_ERRORS:
            continue
    return out


def _note(ctx, found: Dict[str, Code], requirement: Optional[str], impl: Optional[int]) -> None:
    if not requirement or not impl:
        return
    if _TRAVERSE_RE.search(requirement):
        found["traverse"] = implementation(ctx, impl)
    elif _DECODE_MESSAGE_RE.search(requirement):
        found["decodeMessage"] = implementation(ctx, impl)


def implementation(ctx, witness: int) -> Code:
    """The function a witness is: one whose only call into the image is a ``bl`` handed its own
    entry arguments (x0-x2, self in x20) is that callee -- the ``TW`` thunk, and a body that
    identical-code folding made a call of a ``merged`` one, with the constants it adds in
    x3-x8 -- followed to the first that is not."""
    code = Code(witness)
    for _ in range(_MAX_DEPTH + 1):
        nxt = _forwarded_to(ctx, code.va)
        if nxt is None:
            return code
        code = Code(nxt[0], tuple(sorted({**dict(code.args), **nxt[1]}.items())))
    return code


def _forwarded_to(ctx, va: int) -> Optional[Tuple[int, Dict[str, int]]]:
    from macho.disasm import _parse_imm
    try:
        insns = list(function_body(ctx, va))
    except READ_ERRORS:
        return None
    calls = [k for k, ins in enumerate(insns) if ins.mnemonic in CALLS]
    if len(calls) != 1 or insns[calls[0]].mnemonic != "bl":
        return None
    k = calls[0]
    flow = Flow(ctx, insns)
    if not all(flow.entry_arg(k, r) == r for r in ("x0", "x1", "x2", "x20")):
        return None
    target = _parse_imm(insns[k].op_str)
    if target is None or not _in_image_text(ctx, target):
        return None
    known = flow.propagate({}, [k]).get(k, {})
    return target, {r: known[r] for r in ("x3", "x4", "x5", "x6", "x7", "x8")
                    if r in known and not flow.entry_arg(k, r)}


def _in_image_text(ctx, va: int) -> bool:
    try:
        text = ctx.section("__TEXT", "__text")
    except READ_ERRORS:
        return False
    return text.vmaddr <= va < text.vmaddr + text.vmsize


# ── decodeMessage ─────────────────────────────────────────────────────────────

def _decoder_slots(ctx) -> Dict[int, str]:
    """``{witness-table offset: Decoder requirement}``: by the requirements' descriptors
    (:func:`serializers.swift_descriptor_extract._protocol_slots`), else -- an image that links
    swift-protobuf in, without those symbols -- by what its decoders' witnesses are named."""
    from serializers.swift_descriptor_extract import _protocol_slots

    def build():
        out = dict(_protocol_slots(ctx, "7DecoderMp"))
        protos = [n for n in _symbols(ctx).values() if n.endswith("7DecoderMp")]
        for pname in protos:
            for i, names in _slot_names(ctx, pname).items():
                hit = next((n for n in names if _DECODE_RE.search(n)), None)
                if hit:
                    out.setdefault(8 + 8 * i, hit)
        return out
    return _ctx_cache(ctx, "_swift_decoder_slots", build)


def _static_tables(ctx) -> List[Tuple[str, int]]:
    """``(protocol symbol, witness table)`` of each conformance in the image with a static
    witness table (not resilient witnesses)."""
    def build():
        out = []
        try:
            sec = ctx.section("__TEXT", "__swift5_proto")
        except READ_ERRORS:
            return out
        for rec in range(sec.vmaddr, sec.vmaddr + sec.vmsize, 4):
            try:
                cd = _rel(ctx, rec)
                proto, ind = _rel_indirect(ctx, cd)
                if not _u32(ctx, cd + 12) & (1 << 16):
                    out.append((_named(ctx, proto, ind) or "", _rel(ctx, cd + 8)))
            except READ_ERRORS:
                continue
        return out
    return _ctx_cache(ctx, "_swift_static_tables", build)


def _slot_names(ctx, protocol: str) -> Dict[int, List[str]]:
    """``{requirement index: [names]}`` of *protocol* (its descriptor's symbol): each
    requirement's method-descriptor symbol (``…Tq``), and the symbols of what the image's static
    witness tables for it hold at that slot and of the function that forwards to
    (``…P8traverse7visitor…TW``, a body ``…V8traverse7visitor…F``) -- an image that links
    swift-protobuf in may have only those."""
    def build():
        out: Dict[int, List[str]] = {}
        va = next((a for a, n in _symbols(ctx).items() if n == protocol), None)
        if va is None:
            return out
        try:
            _f, _p, _n, nsig, nreq, _a = struct.unpack("<IiiIIi", ctx.read_bytes(va, 24))
        except READ_ERRORS:
            return out
        start = va + 24 + 12 * nsig
        impl_names = _impl_symbols(ctx)
        for i in range(nreq):
            names = [n for n in (_symbols(ctx).get(start + 8 * i),) if n]
            for pname, wt in _static_tables(ctx):
                if pname != protocol:
                    continue
                try:
                    impl = ctx.read_ptr(wt + 8 + 8 * i)
                except READ_ERRORS:
                    continue
                if impl:                           # the witness, and the body it forwards to
                    names.extend(impl_names.get(impl, ()))
                    names.extend(impl_names.get(implementation(ctx, impl).va, ()))
            out[i] = list(dict.fromkeys(names))
        return out
    return _ctx_cache(ctx, "_swift_slot_names_" + protocol, build)


def _impl_symbols(ctx) -> Dict[int, List[str]]:
    """address -> every symbol of the image there (a witness may carry several)."""
    def build():
        out: Dict[int, List[str]] = {}
        try:
            for n, a in ctx.iter_symbols():
                if a:
                    out.setdefault(a, []).append(n)
        except READ_ERRORS:
            pass
        return out
    return _ctx_cache(ctx, "_swift_impl_symbols", build)


def _call_name(ctx, objs: _Objects, target: Optional[int], via: Optional[int],
               thunks: bool = False) -> str:
    """The symbol a call reaches: its target's (with *thunks*, an outlined thunk's tail
    callee's), or -- through a ``blr`` -- the Decoder requirement at the slot of the decoder's
    witness table its target was loaded from."""
    from serializers.swift_descriptor_extract import _symbol_at
    if target is not None:
        return _symbol_at(ctx, (_tail_called(ctx, target) if thunks else None) or target)
    if is_pointer(via):
        origin = objs.origin.get(split(via)[0], ())
        if origin[:2] == ("load", DECODER_WITNESSES):
            return _decoder_slots(ctx).get(origin[2], "")
    return ""


def _tail_called(ctx, va: int) -> Optional[int]:
    """The function an outlined thunk of the image tail-calls (``mov x0, x24 ; ... ; b <T>``: no
    call of its own, a ``b`` out of itself), else None."""
    from macho.disasm import _parse_imm
    if not _in_image_text(ctx, va):
        return None

    def build():
        try:
            insns = list(function_body(ctx, va))
        except READ_ERRORS:
            return None
        if not insns or any(i.mnemonic in CALLS for i in insns) or insns[-1].mnemonic != "b":
            return None
        t = _parse_imm(insns[-1].op_str)
        inside = insns[0].addr <= (t or 0) <= insns[-1].addr
        return None if t is None or inside else t
    memo = _ctx_cache(ctx, "_swift_tail_called", dict)
    if va not in memo:
        memo[va] = build()
    return memo[va]


def _flow(ctx, va: int) -> Optional[Flow]:
    from serializers.swift_descriptor_extract import _flow_of
    try:
        return _flow_of(ctx, list(function_body(ctx, va)))
    except READ_ERRORS:
        return None


def _decodes(ctx, objs: _Objects, calls, depth: int, seen) -> List[Decoded]:
    """The Decoder field calls among *calls* (a run's), and in the image's functions they reach
    (run with the arguments handed them)."""
    out: List[Decoded] = []
    for c in calls:
        name = _call_name(ctx, objs, c.target, c.via)
        m = _DECODE_RE.search(name)
        if m:
            if m.group(4):
                continue                           # nextFieldNumber
            label, kind = ("Map", "Map") if m.group(3) else (m.group(1), m.group(2))
            d = Decoded(label, kind)
            if kind in _GENERIC_KINDS:              # <M: Message> / <E: Enum>: M's metadata in x1
                d.type = metadata_type(ctx, objs, c.args.get("x1"))
            elif kind == "Map":                     # <KeyType, ValueType>: x1, x2 (the
                key = metadata_type(ctx, objs, c.args.get("x1"))   # thin fieldType: none)
                val = metadata_type(ctx, objs, c.args.get("x2"))
                if key and val:
                    d.type = "map<%s, %s>" % (_MAP_MARKERS.get(key, key), _MAP_MARKERS.get(val, val))
            v = c.args.get("x0")
            if is_pointer(v):
                d.origin, d.offset = objs.origin[split(v)[0]], split(v)[1]
            out.append(d)
            continue
        if c.target is None or depth >= _MAX_DEPTH or not _in_image_text(ctx, c.target) \
                or c.target in seen:
            continue
        flow = _flow(ctx, c.target)
        if flow is None:
            continue
        region = flow.run_from(0, dict(c.args), objects=objs.objects(c.target))
        out.extend(_decodes(ctx, objs, region.calls, depth + 1, seen | {c.target}))
    return out


def decoded_fields(ctx, decode, numbers) -> Dict[int, List[Decoded]]:
    """``{N: [Decoded]}`` for each field number in *numbers* a ``decodeMessage`` (a
    :class:`Code`, or its address) decodes (see the module docstring); {} when no
    ``nextFieldNumber`` call is found -- in it, or in a function it calls (a copy-on-write
    message's loop, in the closure it hands its storage)."""
    code = decode if isinstance(decode, Code) else Code(decode)
    objs = _Objects(ctx)
    entry = {"x0": pointer(DECODER), "x1": pointer(DECODER_TYPE),
             "x2": pointer(DECODER_WITNESSES), "x20": pointer(SELF), **dict(code.args)}
    numbers = sorted(n for n in set(numbers) if 1 <= n <= _MAX_FIELD_NUMBER)
    return _fields(ctx, objs, code.va, entry, numbers, 1)


def _fields(ctx, objs: _Objects, va: int, entry: Dict[str, int], numbers, depth: int
            ) -> Dict[int, List[Decoded]]:
    from macho.disasm import _parse_imm
    flow = _flow(ctx, va)
    if flow is None:
        return {}
    model = objs.objects(va)
    calls = [k for k, ins in enumerate(flow.insns) if ins.mnemonic in CALLS]
    slots: Dict[int, Dict[int, Tuple[int, int]]] = {}
    states = flow.propagate(entry, calls, objects=model, slots_out=slots)
    nexts, inner = [], []
    for k in calls:
        st = states.get(k)
        if st is None:
            continue
        ins = flow.insns[k]
        target = _parse_imm(ins.op_str) if ins.mnemonic == "bl" else None
        reg = ins.op_str.split(",")[0].strip()
        if target is None:
            target = st.get(reg) if not is_pointer(st.get(reg)) else None
        via = None if target is not None else st.get(reg)
        m = _DECODE_RE.search(_call_name(ctx, objs, target, via, thunks=True))
        if m and m.group(4):
            nexts.append(k)
        elif target is not None and _in_image_text(ctx, target):
            inner.append((target, st))
    if not nexts:
        # the loop is in a function this one calls, handed what it holds
        if depth >= _MAX_DEPTH:
            return {}
        for target, st in inner:
            got = _fields(ctx, objs, target, dict(st), numbers, depth + 1)
            if got:
                return got
        return {}
    # an iteration ends where a nextFieldNumber call is: the loop's head, or (a rotated loop:
    # one call ahead of it, one at its end) the next one
    stop = frozenset(flow._block_of[k] for k in nexts)
    out: Dict[int, List[Decoded]] = {}
    for k in nexts:
        base = {r: v for r, v in states[k].items() if r not in CALLER_SAVED}

        def run(n, rejoin=frozenset()):
            regs = {**base, "x0": n, "x1": 0, "x21": 0}
            return flow.run_from(k + 1, regs, stop, objects=model, slots=slots.get(k, {}),
                                 rejoin=rejoin)
        unknown = run((max(numbers) if numbers else 0) + 1)
        common = {_key(d) for d in _decodes(ctx, objs, unknown.calls, depth, frozenset())}
        for n in numbers:
            r = run(n, frozenset(unknown.blocks))
            for d in _decodes(ctx, objs, r.calls, depth, frozenset()):
                if _key(d) not in common and _key(d) not in {_key(x) for x in out.get(n, ())}:
                    out.setdefault(n, []).append(d)
    return out


def _key(d: Decoded) -> tuple:
    return d.label, d.kind, d.type, d.origin, d.offset


# ── the types a call is handed ────────────────────────────────────────────────

_GENERIC_KINDS = frozenset(("Message", "Enum", "Group"))
# a map's key / value type marker -> the proto scalar it stands for
_MAP_MARKERS = {"Protobuf" + k: v for k, v in (
    ("String", "string"), ("Bytes", "bytes"), ("Bool", "bool"), ("Float", "float"),
    ("Double", "double"), ("Int32", "int32"), ("Int64", "int64"), ("UInt32", "uint32"),
    ("UInt64", "uint64"), ("SInt32", "sint32"), ("SInt64", "sint64"), ("Fixed32", "fixed32"),
    ("Fixed64", "fixed64"), ("SFixed32", "sfixed32"), ("SFixed64", "sfixed64"))}
_INSTANTIATE = ("___swift_instantiateConcreteTypeFromMangledName",
                "___swift_instantiateConcreteTypeFromMangledNameV2")


def _accessors(ctx) -> Dict[int, int]:
    """``{metadata access function: type descriptor}`` of the image's nominal types (each
    descriptor's AccessFunction, a relative pointer at +0x0C)."""
    import serializers.swift_type_recovery as TR

    def build():
        out: Dict[int, int] = {}
        try:
            sec = ctx.section("__TEXT", "__swift5_types")
        except READ_ERRORS:
            return out
        for rec in range(sec.vmaddr, sec.vmaddr + sec.vmsize, 4):
            try:
                desc = TR._type_record(ctx, rec)
                if desc and TR._desc_kind(ctx, desc) in (16, 17, 18) and _i32(ctx, desc + 0x0C):
                    out.setdefault(_rel(ctx, desc + 0x0C), desc)
            except READ_ERRORS:
                continue
        return out
    return _ctx_cache(ctx, "_swift_metadata_accessors", build)


_KIND_LETTERS = "VOC"


def _type_of_accessor_symbol(name: str) -> Optional[str]:
    """``$s<module><Outer>V<Inner>VMa`` -> ``Outer.Inner``: another image's type, by the
    symbol of its metadata accessor (one run of identifiers: a word substitution refers back
    across them, ``21InternalSwiftProtobuf06Google_C10_TimestampV`` -> Google_Protobuf_Timestamp)."""
    import serializers.swift_type_recovery as TR
    body = name[3:-2] if name.startswith("_$s") and name.endswith("Ma") else ""
    if not body or body[-1] not in _KIND_LETTERS:
        return None
    ids = TR.demangle_idents(body)
    return ".".join(ids[1:]) if len(ids) > 1 else None


def metadata_type(ctx, objs: _Objects, v: Optional[int]) -> Optional[str]:
    """The type a metadata value stands for: the result of the image's metadata accessor for a
    type (by its descriptor), of another image's (by its symbol), or of instantiating a mangled
    name (``__swift_instantiateConcreteTypeFromMangledName`` handed its cache, whose first word
    is a relative reference to the name); or a static metadata record (its descriptor at +8)."""
    import serializers.swift_type_recovery as TR
    from serializers.swift_descriptor_extract import _symbol_at
    if v is None:
        return None
    if is_pointer(v):
        origin = objs.origin.get(split(v)[0], ())
        if origin[:1] != ("call",) or split(v)[1]:
            return None
        _c, _fn, _k, target, x0 = origin
        if target is None:
            return None
        desc = _accessors(ctx).get(target)
        if desc:
            return TR._qualified_name(ctx, desc)
        name = _symbol_at(ctx, target)
        if name in _INSTANTIATE and x0 is not None and not is_pointer(x0):
            try:
                ptype, label = TR.decode_mangled(ctx, _rel(ctx, x0))
            except READ_ERRORS:
                return None
            return ("repeated " + ptype if label == "repeated" else ptype) if ptype else None
        return _type_of_accessor_symbol(name)
    try:
        desc = ctx.read_ptr(v + 8)
        return TR._qualified_name(ctx, desc) if TR._desc_kind(ctx, desc) in (17, 18) else None
    except READ_ERRORS:
        return None
