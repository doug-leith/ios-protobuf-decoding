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
from dataclasses import dataclass
from typing import Dict, List, NamedTuple, Optional, Tuple

from macho.memory import READ_ERRORS, BinaryContext, _ctx_cache
from proto.arm64_eval import Flow, Objects, Sym
from proto.arm64_operands import CALLS, CALLER_SAVED
from proto.callees import callee_name, text_holding
from proto.function_body import function_body
from proto.models import MAX_FIELD_NUMBER
from serializers import swift_symbols as SY
from serializers.swift_symbols import read_i32, rel

# self; the decoder (or visitor) argument, its type and its witness table
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


def pointer(k: int, off: int = 0) -> Sym:
    """An address *off* bytes into object *k* (a run cannot see into it)."""
    return Sym("pointer", k, off)


def is_pointer(v) -> bool:
    return isinstance(v, Sym) and v.kind == "pointer"


def split(v: Sym) -> Tuple[int, int]:
    """``(object, offset)`` of a pointer."""
    return v.ident, v.off


class _Objects:
    """The objects of one message's runs: self, the decoder, its type and witness table, then
    each value loaded from one (*origin*: ``("load", object, offset)``), each call's result
    (``("call", address, target, x0)``) and each import loaded from the slot dyld binds to it
    (``("import", slot)``: a standalone binary's)."""

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

        def call_result(addr, target, x0):
            name = callee_name(self.ctx, target)
            if is_pointer(x0) and name in _RETURNS_ARGUMENT:
                return x0
            if name in _UNIQUELY_REFERENCED:
                return 1
            return self._object(("call", addr, target, x0))
        return Objects(pointer=is_pointer, field_value=field_value, call_result=call_result,
                       object_escape=True, bound=self.imported)

    def imported(self, slot: int) -> Optional[int]:
        if getattr(self.ctx, "is_cache_backed", False) or not self.ctx.bind_name_for(slot):
            return None                            # (a dyld cache's slots are bound)
        return self._object(("import", slot))

    def entry(self, code: "Code") -> Dict[str, int]:
        """A run's entry registers: the method's arguments (x0-x2, self in x20) as these
        objects, and what *code*'s forwarders hand it."""
        return {"x0": pointer(DECODER), "x1": pointer(DECODER_TYPE),
                "x2": pointer(DECODER_WITNESSES), "x20": pointer(SELF), **dict(code.args),
                **{r: self.imported(slot) for r, slot in code.imports}}


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

# traverse(visitor:) / decodeMessage(decoder:), as a requirement's or a witness's symbol spells
# them ("Message" a word substitution: ``06decodeD07decoder``, ``06decodeF07decoder``)
_TRAVERSE_RE = re.compile(r"8traverse7visitor")
_DECODE_MESSAGE_RE = re.compile(r"(?:13decodeMessage|06decode[A-Z]\d?)7decoder")


class Code(NamedTuple):
    """A function, and what the forwarders on the way to it hand it in x3-x8 (a ``merged``
    body's per-type parts: identical-code folding passes them as arguments): constants
    (*args*), and imports loaded from the slots dyld binds (*imports*: register, slot)."""
    va: int
    args: Tuple[Tuple[str, int], ...] = ()
    imports: Tuple[Tuple[str, int], ...] = ()


def message_witnesses(ctx) -> Dict[int, Dict[str, Code]]:
    """``{type descriptor: {"traverse": Code, "decodeMessage": Code}}`` for each conformance of
    the image to swift-protobuf's ``Message`` (SwiftProtobuf or InternalSwiftProtobuf).
    Memoised."""
    return _ctx_cache(ctx, "_swift_message_witnesses", lambda: _message_witnesses(ctx))


def _message_witnesses(ctx) -> Dict[int, Dict[str, Code]]:
    out: Dict[int, Dict[str, Code]] = {}
    for c in SY.conformances(ctx):
        protocol = next((n for n in c.protocol if n.endswith("7MessageMp")), None)
        if protocol is None or not c.type_descriptor:
            continue
        found: Dict[str, Code] = {}
        if c.witness_table is None:                # resilient witnesses: requirement, impl
            for names, impl in c.resilient:
                _note(ctx, found, names, impl)
        else:                                      # a witness table, in requirement order
            for off, names in requirement_slots(ctx, protocol).items():
                try:
                    impl = ctx.read_ptr(c.witness_table + off)
                except READ_ERRORS:
                    continue
                _note(ctx, found, names, impl)
        if found:
            out[c.type_descriptor] = found
    return out


def _note(ctx, found: Dict[str, Code], requirement: Tuple[str, ...], impl: Optional[int]) -> None:
    if not impl:
        return
    if any(_TRAVERSE_RE.search(n) for n in requirement):
        found["traverse"] = implementation(ctx, impl)
    elif any(_DECODE_MESSAGE_RE.search(n) for n in requirement):
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
        code = Code(nxt[0], tuple(sorted({**dict(code.args), **nxt[1]}.items())),
                    tuple(sorted({**dict(code.imports), **nxt[2]}.items())))
    return code


def _forwarded_to(ctx, va: int) -> Optional[Tuple[int, Dict[str, int], Dict[str, int]]]:
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
    if text_holding(ctx, target) is None:
        return None
    objs = _Objects(ctx)
    known = flow.propagate({}, [k], objects=objs.objects(va)).get(k, {})
    args, imports = {}, {}
    for r in ("x3", "x4", "x5", "x6", "x7", "x8"):
        v = known.get(r)
        if v is None or flow.entry_arg(k, r):
            continue
        if not isinstance(v, Sym):
            args[r] = v
        elif is_pointer(v) and objs.origin[split(v)[0]][0] == "import":
            imports[r] = objs.origin[split(v)[0]][1]
    return target, args, imports


# ── protocol requirements, and the calls they name ────────────────────────────

def requirement_slots(ctx, protocol: str) -> Dict[int, Tuple[str, ...]]:
    """``{witness-table offset: names}`` of each requirement of *protocol* (its descriptor's
    symbol): its descriptor's symbols (:func:`serializers.swift_symbols.protocol_requirements`),
    and those of what the image's static witness tables for it hold at that slot and of the
    function that forwards to (``…P8traverse7visitor…TW``, a body ``…V8traverse7visitor…F``) --
    an image that links swift-protobuf in may have only those.  Memoised."""
    memo = _ctx_cache(ctx, "_swift_requirement_slots", dict)
    if protocol not in memo:
        memo[protocol] = _requirement_slots(ctx, protocol)
    return memo[protocol]


def _requirement_slots(ctx, protocol: str) -> Dict[int, Tuple[str, ...]]:
    tables = [c.witness_table for c in SY.conformances(ctx)
              if protocol in c.protocol and c.witness_table is not None]
    out: Dict[int, Tuple[str, ...]] = {}
    for i, required in enumerate(SY.protocol_requirements(ctx, protocol)):
        names = list(required)
        for wt in tables:
            try:
                impl = ctx.read_ptr(wt + 8 + 8 * i)
            except READ_ERRORS:
                continue
            if impl:                               # the witness, and the body it forwards to
                names.extend(SY.names_at(ctx, impl))
                names.extend(SY.names_at(ctx, implementation(ctx, impl).va))
        out[8 + 8 * i] = tuple(dict.fromkeys(names))
    return out


def _slots(ctx, suffix: str, pattern) -> Dict[int, str]:
    """``{witness-table offset: requirement}`` of the swift-protobuf protocols whose descriptor's
    symbol ends in *suffix*: the first of a slot's :func:`requirement_slots` names *pattern*
    matches."""
    def build():
        out: Dict[int, str] = {}
        for protocol in SY.names_ending(ctx, suffix):
            for off, names in requirement_slots(ctx, protocol).items():
                hit = next((n for n in names if pattern.search(n)), None)
                if hit:
                    out.setdefault(off, hit)
        return out
    return _ctx_cache(ctx, "_swift_slots_" + suffix, build)


def _decoder_slots(ctx) -> Dict[int, str]:
    """The ``Decoder`` requirements by witness-table offset (:func:`_slots`)."""
    return _slots(ctx, "7DecoderMp", _DECODE_RE)


def _visitor_slots(ctx) -> Dict[int, str]:
    """The ``Visitor`` requirements by witness-table offset (:func:`_slots`)."""
    return _slots(ctx, "7VisitorMp", _VISIT_RE)


def _match(pattern, names: Tuple[str, ...]):
    """The first match of *pattern* in *names*, or None."""
    return next((m for m in map(pattern.search, names) if m), None)


def _call_names(ctx, objs: _Objects, target: Optional[int], via: Optional[int],
                thunks: bool = False, slots=_decoder_slots) -> Tuple[str, ...]:
    """The symbols a call reaches: its target's (with *thunks*, an outlined thunk's tail
    callee's), or -- through a ``blr`` -- the requirement at the slot of the argument's witness
    table (the decoder's, or with *slots* = :func:`_visitor_slots` the visitor's) its target was
    loaded from."""
    if target is not None:
        return SY.function_names(ctx, (_tail_called(ctx, target) if thunks else None) or target)
    if is_pointer(via):
        origin = objs.origin.get(split(via)[0], ())
        if origin[:2] == ("load", DECODER_WITNESSES):
            hit = slots(ctx).get(origin[2])
            return (hit,) if hit else ()
        if origin[:1] == ("import",):
            name = ctx.bind_name_for(origin[1])
            return (name,) if name else ()
    return ()


def _tail_called(ctx, va: int) -> Optional[int]:
    """The function an outlined thunk of the image tail-calls (``mov x0, x24 ; ... ; b <T>``: no
    call of its own, a ``b`` out of itself), else None."""
    from macho.disasm import _parse_imm
    if text_holding(ctx, va) is None:
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


def _decodes(ctx, objs: _Objects, calls, depth: int, seen) -> List[Decoded]:
    """The Decoder field calls among *calls* (a run's), and in the image's functions they reach
    (run with the arguments handed them)."""
    out: List[Decoded] = []
    for c in calls:
        m = _match(_DECODE_RE, _call_names(ctx, objs, c.target, c.via))
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
        if c.target is None or depth >= _MAX_DEPTH or text_holding(ctx, c.target) is None \
                or c.target in seen:
            continue
        flow = SY.function_flow(ctx, c.target)
        if flow is None:
            continue
        region = flow.run_from(0, dict(c.args), objects=objs.objects(c.target))
        out.extend(_decodes(ctx, objs, region.calls, depth + 1, seen | {c.target}))
    return out


def decoded_fields(ctx, decode, numbers) -> Optional[Dict[int, List[Decoded]]]:
    """``{N: [Decoded]}`` for each field number in *numbers* a ``decodeMessage`` (a
    :class:`Code`, or its address) decodes (see the module docstring); None when no
    ``nextFieldNumber`` call is found -- in it, or in a function it calls (a copy-on-write
    message's loop, in the closure it hands its storage) -- so what it decodes is not known."""
    code = decode if isinstance(decode, Code) else Code(decode)
    objs = _Objects(ctx)
    entry = objs.entry(code)
    numbers = sorted(n for n in set(numbers) if 1 <= n <= MAX_FIELD_NUMBER)
    return _fields(ctx, objs, code.va, entry, numbers, 1)


def _fields(ctx, objs: _Objects, va: int, entry: Dict[str, int], numbers, depth: int
            ) -> Optional[Dict[int, List[Decoded]]]:
    from macho.disasm import _parse_imm
    flow = SY.function_flow(ctx, va)
    if flow is None:
        return None
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
            target = st.get(reg) if not isinstance(st.get(reg), Sym) else None
        via = None if target is not None else st.get(reg)
        m = _match(_DECODE_RE, _call_names(ctx, objs, target, via, thunks=True))
        if m and m.group(4):
            nexts.append(k)
        elif text_holding(ctx, target) is not None:
            inner.append((target, st))
    if not nexts:
        # the loop is in a function this one calls, handed what it holds
        if depth >= _MAX_DEPTH:
            return None
        for target, st in inner:
            got = _fields(ctx, objs, target, dict(st), numbers, depth + 1)
            if got is not None:
                return got
        return None
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
        # the arms' closures have their own budget, however deep the loop was found
        common = {_key(d) for d in _decodes(ctx, objs, unknown.calls, 1, frozenset())}
        for n in numbers:
            r = run(n, frozenset(unknown.blocks))
            for d in _decodes(ctx, objs, r.calls, 1, frozenset()):
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
        if not ctx.has_section("__TEXT", "__swift5_types"):
            return out
        sec = ctx.section("__TEXT", "__swift5_types")
        for rec in range(sec.vmaddr, sec.vmaddr + sec.vmsize, 4):
            try:
                desc = TR._type_record(ctx, rec)
                if desc and TR._desc_kind(ctx, desc) in (16, 17, 18) and read_i32(ctx, desc + 0x0C):
                    out.setdefault(rel(ctx, desc + 0x0C), desc)
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
    if v is None:
        return None
    if is_pointer(v):
        origin = objs.origin.get(split(v)[0], ())
        if origin[:1] != ("call",) or split(v)[1]:
            return None
        _c, _addr, target, x0 = origin
        if target is None:
            return None
        desc = _accessors(ctx).get(target)
        if desc:
            return TR._qualified_name(ctx, desc)
        names = SY.function_names(ctx, target)
        if any(n in _INSTANTIATE for n in names) and x0 is not None and not isinstance(x0, Sym):
            try:
                ptype, label = TR.decode_mangled(ctx, rel(ctx, x0))
            except READ_ERRORS:
                return None
            return ("repeated " + ptype if label == "repeated" else ptype) if ptype else None
        return next(filter(None, map(_type_of_accessor_symbol, names)), None)
    if isinstance(v, Sym):                       # (a frame address)
        return None
    try:
        desc = ctx.read_ptr(v + 8)
        return TR._qualified_name(ctx, desc) if TR._desc_kind(ctx, desc) in (17, 18) else None
    except READ_ERRORS:
        return None


# ── traverse ──────────────────────────────────────────────────────────────────

_VISIT_RE = re.compile(r"[PV]\d+visit(Singular|Repeated|Packed)?(\w*?)Field")


@dataclass
class Visited:
    """One ``Visitor`` call of a traverse: label (Singular / Repeated / Packed / Map), kind, and
    the type it is handed (a message's or an enum's metadata after the number; a map's key and
    value type)."""
    label: str
    kind: str
    type: Optional[str] = None


def visit_number_register(label: str, kind: str) -> str:
    """Where a Visitor method takes its field number.  swift-protobuf's Visitor methods take
    ``(value, fieldNumber: Int, …)``: in the Swift calling convention the number is the integer
    argument after the value's registers -- none for a Float / Double (it travels in an FP
    register), two for a String / Data (two words), one for everything else (an integer, a Bool,
    an Array, a Dictionary, an enum or message by reference)."""
    if label == "Singular" and kind in ("Float", "Double"):
        return "x0"
    if label == "Singular" and kind in ("String", "Bytes"):
        return "x2"
    return "x1"


def _visitor_method(ctx, objs: _Objects, c) -> Optional[Tuple[str, str]]:
    """``(label, kind)`` of the Visitor method call *c* goes to, or None."""
    m = _match(_VISIT_RE, _call_names(ctx, objs, c.target, c.via, slots=_visitor_slots))
    return ((m.group(1) or "Map"), (m.group(2) or "Map")) if m else None


def _visits_a_field(visit: Tuple[str, str]) -> bool:
    """Not an extension's or the unknown fields' visit."""
    return visit[1] != "Extension" and not visit[1].startswith("Unknown")


def _code(traverse) -> "Code":
    return traverse if isinstance(traverse, Code) else Code(traverse)


def visit_methods(ctx, traverse) -> Dict[int, Tuple[str, str]]:
    """``{k: (label, kind)}``: the Visitor method of each call ``insns[k]`` of a
    ``traverse(visitor:)`` body itself (a :class:`Code` or its address; *insns* those of its
    :func:`serializers.swift_symbols.function_flow`) that visits a field, named as
    :func:`visited_fields` names them."""
    code = _code(traverse)
    flow = SY.function_flow(ctx, code.va)
    if flow is None:
        return {}
    objs = _Objects(ctx)
    region = flow.run_from(0, objs.entry(code), objects=objs.objects(code.va))
    out: Dict[int, Tuple[str, str]] = {}
    for c in region.calls:
        visit = _visitor_method(ctx, objs, c)
        if visit is not None and _visits_a_field(visit):
            out[c.k] = visit
    return out


def visited_fields(ctx, traverse) -> Dict[int, List[Visited]]:
    """``{N: [Visited]}``: the Visitor calls a ``traverse(visitor:)`` (a :class:`Code` or its
    address) makes, by the field number it hands each -- run with self (x20), the visitor (x0),
    its type (x1) and witness table (x2) as :func:`decoded_fields` runs decodeMessage, and the
    functions it calls (a oneof's cases, the generated closures) run with what they are
    handed.  Memoised per code."""
    code = _code(traverse)
    memo = _ctx_cache(ctx, "_swift_visited_fields", dict)
    if code not in memo:
        objs = _Objects(ctx)
        out: Dict[int, List[Visited]] = {}
        _visits(ctx, objs, code.va, objs.entry(code), 1, frozenset(), out)
        memo[code] = out
    return memo[code]


def _visits(ctx, objs: _Objects, va: int, entry, depth: int, seen, out) -> None:
    flow = SY.function_flow(ctx, va)
    if flow is None:
        return
    region = flow.run_from(0, dict(entry), objects=objs.objects(va))
    for c in region.calls:
        visit = _visitor_method(ctx, objs, c)
        if visit is not None:
            label, kind = visit
            n = c.args.get(visit_number_register(label, kind))
            if not _visits_a_field(visit) or n is None or isinstance(n, Sym) \
                    or not 1 <= n <= MAX_FIELD_NUMBER:
                continue
            v = Visited(label, kind)
            if kind in _GENERIC_KINDS:
                v.type = metadata_type(ctx, objs, c.args.get("x2"))
            elif kind == "Map":
                key = metadata_type(ctx, objs, c.args.get("x2"))
                val = metadata_type(ctx, objs, c.args.get("x3"))
                if key and val:
                    v.type = "map<%s, %s>" % (_MAP_MARKERS.get(key, key), _MAP_MARKERS.get(val, val))
            if (v.label, v.kind, v.type) not in {(x.label, x.kind, x.type) for x in out.get(n, ())}:
                out.setdefault(n, []).append(v)
            continue
        if c.target is None or depth >= _MAX_DEPTH or text_holding(ctx, c.target) is None \
                or c.target in seen:
            continue
        _visits(ctx, objs, c.target, c.args, depth + 1, seen | {c.target}, out)


# ── the proto type a call stands for ──────────────────────────────────────────

# a Decoder / Visitor method's scalar kind -> its proto type
SCALARS = {
    "Int32": "int32", "Int64": "int64", "UInt32": "uint32", "UInt64": "uint64",
    "SInt32": "sint32", "SInt64": "sint64", "Fixed32": "fixed32", "Fixed64": "fixed64",
    "SFixed32": "sfixed32", "SFixed64": "sfixed64", "Bool": "bool", "Float": "float",
    "Double": "double", "String": "string", "Bytes": "bytes",
}


def decoded_type(d) -> Optional[str]:
    """The proto type a :class:`Decoded` (or :class:`Visited`) call stands for."""
    if d.kind == "Map":
        return d.type
    base = d.type if d.kind in _GENERIC_KINDS else SCALARS.get(d.kind)
    if base is None:
        return None
    return f"repeated {base}" if d.label in ("Repeated", "Packed") else base
