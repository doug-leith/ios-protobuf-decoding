"""swift_descriptor_extract.py — recover swift-protobuf message field NAMES and
NUMBERS from a Mach-O binary (and enum case names/numbers).

Swift-protobuf messages (types conforming to ``SwiftProtobuf.Message``) carry a
static ``_protobuf_nameMap`` that maps each field number to its proto name,
emitted by ``protoc-gen-swift``.  Unlike Apple ``PBCodable`` (no descriptor — we
reverse-engineer ``writeTo:``/``readFrom:``), the nameMap is a structured table,
so names+numbers are recoverable directly.  The compiler lowers the *same*
generated dictionary-literal source several ways across iOS versions / toolchains
/ optimisation levels; this module handles all of them:

* **A — inline closure** (device / iOS 16 frameworks): a ``swift_once``-guarded
  init closure builds each entry inline with ``mov w,#<num>; str x,[base]`` plus
  ``adr x,<name-cstring>; mov w,#<len>; stp x,x,[entry]``.
* **B — compact single-field tail-call**: the closure passes ``x2=<name>``,
  ``w3=<len>`` (and the number) to a shared single-entry template, which stores them; it is
  read as the template with the closure's registers (:func:`_tail_callee`), like A and D.
* **C — static object** (newer toolchains): the dictionary literal is
  const-folded into a static ``Array<(Int, _NameDescription)>`` handed to
  ``_swift_initStaticObject(metadata, object)``; the object the getter passes is read as
  ``(number, name-ptr, len, …)`` elements, the stride (version-dependent) taken from the
  first two and every element required to parse (:func:`_parse_static_blob`).
* **D — shared once-init template** (another newer-toolchain lowering, e.g.
  DPSubmissionService): the getter is just ``adr x0,<once-token>; adr
  x1,<storage-slot>; adr x2,<builder>; b <shared-lazy-init-template>`` — the
  branch target is a generic memoized-value-getter TEMPLATE shared across many
  unrelated types (it carries no type information), but the ``adr x2`` value is
  the type's own builder, which stores each entry as ``mov w,#<num>;
  str x,[base]`` + ``adr x,<name>; mov w,#<len>; stp x,x,[entry]`` — the same
  literal shape as A, just reached by chasing the ``adr`` instead of walking
  the getter inline (:func:`_shared_once_init_targets`).  Some builders are
  themselves only a further arg-setup stub for a *second*, arity-specific
  shared template (:func:`_builder_entries` reads that template with the
  registers the stub hands it).

* **E — packed bytecode** (newer swift-protobuf / iOS 27 InternalSwiftProtobuf):
  ``_NameMap(bytecode: "<literal>")`` -- the whole (number, name) table is one
  NUL-delimited string literal, reached from a getter of the form ``adrp/add
  x1,<slot>; adrp/add x2,<literal>; mov w3,#<len>; b <template>``.  Decoded by
  :mod:`serializers.swift_namemap_bytecode` (structure-validated: header, opcodes,
  terminators and full consumption, else it declines).  A single-field message's
  bare-name literal (no header) is declined and read through its template, as B.

TYPES come from Swift reflection (:mod:`serializers.swift_type_recovery`), joined by name.
``traverse`` adds the integer encoding (``sint32``, ``fixed64`` …) and types the scalars
reflection leaves untyped: each of its Visitor calls is named by its dispatch thunk or its
visitor witness-table slot (:func:`_traverse_visits`).

Works in BOTH modes: from a standalone binary the per-type ``_protobuf_nameMap``
static-init symbols come from ``LC_SYMTAB`` / the dyld export trie; cache-native
they come from the cache's ``.symbols`` sub-cache (same nlist, keyed by vmaddr).
The disassembly-driven decoders are mode-agnostic (all reads route through
``ctx``).

Every shape reads a function's :func:`~proto.function_body.function_body` (what its entry reaches within its extent,
``LC_FUNCTION_STARTS``) and register values from :class:`proto.arm64_eval.Flow`; a builder's
(number, name) entries are paired by the address they are stored at (:func:`_table_entries`).

The residual swift type/number estimates (and which are flagged) are catalogued
in LIMITATIONS.md (10) / to-do #63a/#63b/#66/#67/#68/#70.
"""
from __future__ import annotations

import logging
import re
import struct
from dataclasses import dataclass, field
from collections import Counter
from typing import Dict, List, NamedTuple, Optional, Tuple

from macho.memory import READ_ERRORS, BinaryContext, _ctx_cache
from macho.disasm import _norm_reg, _parse_imm
from proto.arm64_eval import Flow
from proto.callees import callee_name
from proto.dispatch import listing_flow
from proto.function_body import FunctionBody, _branch_target, function_body
from proto.arm64_operands import CALLS, parse_mem, split_ops, writes
from proto.models import record_heuristic_hit
from serializers.swift_type_recovery import demangle_idents
from serializers.swift_namemap_bytecode import (
    bytecode_literal_from_getter, call_site_registers, decode_namemap_bytecode)

log = logging.getLogger(__name__)

_MAX_FIELD_NUMBER = 0x1FFFFFFF        # proto field numbers are 29-bit
# [cap:INPUT-SANITY] the largest (Int, _NameDescription) element stride tried while deriving a
# static name-map array's stride (the description is a few words in every swift-protobuf version;
# 0x38 in the oracle fixtures' SwiftProtobuf: _NameDescription is 41 bytes, 8-aligned).
_MAX_ELEMENT_STRIDE = 0x78
_NAMEMAP_MARKER = "17_protobuf_nameMap"


# ── data model ──────────────────────────────────────────────────────────────

@dataclass
class SwiftField:
    number: int
    name: str
    # proto type recovered from Swift field metadata (swift_type_recovery), e.g.
    # "int32", "string", "repeated Foo", "map<string, int32>", or None when not
    # recovered (oneof members, stripped metadata).  The int varint/zigzag/fixed
    # encoding nuance is NOT distinguished (base Swift type only).
    proto_type: Optional[str] = None
    # False when the builder listing the number was read off stopped at the runaway guard
    # (it may be incomplete): rendered "number estimated" rather than laundered as confirmed.
    number_confirmed: bool = True
    # Set when the recovered proto_type contains a GUESS filler (an Array element /
    # map key-or-value that didn't decode, shown as `bytes`); surfaced as a note so
    # the `bytes` isn't read as certain (#67).
    type_note: Optional[str] = None


@dataclass
class SwiftMessage:
    module: str
    name: str                       # may be dotted for nested types
    fields: List[SwiftField] = field(default_factory=list)
    is_enum: bool = False
    shape: str = ""                 # which lowering produced it (diagnostic)
    # True when no name-map entries were recovered AND Swift reflection independently
    # lists no stored proto field for the struct: the message is genuinely EMPTY (only
    # swift-protobuf's unknownFields), not one whose name map could not be read.
    fieldless: bool = False

    @property
    def qualified(self) -> str:
        return f"{self.module}.{self.name}" if self.module else self.name


# ── symbol table (name → vmaddr), nlist + export trie ─────────────────────────

def symbol_addrs(ctx: BinaryContext) -> Dict[str, int]:
    """Map every declared symbol name → its vmaddr.

    Merges the ``LC_SYMTAB`` nlist (carries ``n_value`` for an image's own
    *internal* symbols, e.g. an app's message types) with the dyld export trie
    (exported symbols such as a framework's public types).

    Cache-native images keep no per-image symbol table in their (shared-LINKEDIT)
    Mach-O; instead the original local symbols — including each type's
    ``…_protobuf_nameMap`` static-init and ``…traverse`` symbols —
    live in the cache's ``.symbols`` sub-cache, keyed by vmaddr.  We read those directly
    so swift-protobuf recovery works cache-native, not just from a standalone
    binary.  Returns ``{}`` when no symbol source is addressable."""
    reader = getattr(ctx, "_cache_reader", None)
    if reader is not None and getattr(ctx, "is_cache_backed", False):
        try:
            return reader.image_symbol_addrs(
                ctx.image_base, _NAMEMAP_MARKER, "V8traverse")
        except READ_ERRORS:
            return {}

    out: Dict[str, int] = {}
    for name, addr in ctx.iter_symbols():
        if addr:
            out.setdefault(name, addr)
    return out


# ── mangled name parsing ──────────────────────────────────────────────────────

def _split_idents(head: str) -> List[str]:
    """Parse a run of Swift length-prefixed identifiers (``6oracle9Ora_Multi``
    → ``["oracle", "Ora_Multi"]``), skipping single-letter nominal-kind tags and
    resolving word-substitution abbreviations (e.g. ``07Google_B4_Any`` →
    ``Google_Protobuf_Any``).  Delegates to the shared demangler in
    :mod:`swift_type_recovery` so the type and name sides agree."""
    return demangle_idents(head)


def _type_of_symbol(sym: str, member: str) -> Optional[Tuple[str, str, str]]:
    """``(module, type_name, kind)`` of the Swift type a member's symbol belongs to:
    ``…<identifiers>V<member>…`` (kind ``V``: a struct, i.e. a message) or ``…O<member>…``
    (an enum); type_name is dotted for a nested type.  None for any other symbol."""
    m = re.search(r"_\$[sS](.*?)([VO])" + re.escape(member), sym)
    if not m:
        return None
    idents = _split_idents(m.group(1))
    if len(idents) < 2:
        return None
    return idents[0], ".".join(idents[1:]), m.group(2)


def _parse_namemap_symbol(sym: str) -> Optional[Tuple[str, str, bool]]:
    """``…_protobuf_nameMap`` symbol -> ``(module, type_name, is_enum)``, or None."""
    t = _type_of_symbol(sym, _NAMEMAP_MARKER)
    return None if t is None else (t[0], t[1], t[2] == "O")


# ── listings and register values ──────────────────────────────────────────────

def _flow_of(ctx: BinaryContext, insns) -> Flow:
    """The Flow of a listing, built once per :class:`~proto.function_body.FunctionBody`."""
    flow = getattr(insns, "flow", None)
    if flow is None:
        flow = listing_flow(ctx, list(insns))     # each ``br`` reaching its decoded table
        if isinstance(insns, FunctionBody):
            insns.flow = flow
    return flow


def _tail_calls(insns) -> List[int]:
    """Indices of the listing's ``b`` instructions to an address outside it."""
    inside = {i.addr for i in insns}
    return [k for k, ins in enumerate(insns)
            if ins.mnemonic == "b" and _branch_target(ins) not in inside]


def _cstr(ctx: BinaryContext, va: Optional[int]) -> Optional[str]:
    if va is None:
        return None
    try:
        s = ctx.read_cstring(va)
    except READ_ERRORS:
        return None
    return s if s and all(32 <= ord(c) < 127 for c in s) else None


def _symbol_at(ctx: BinaryContext, va: Optional[int]) -> str:
    """The name of the function at *va*: its export / import (:func:`proto.callees.callee_name`)
    or the image's own symbol for it; "" when it has none."""
    if va is None:
        return ""
    own = _ctx_cache(ctx, "_swift_symbol_at", lambda: {a: n for n, a in symbol_addrs(ctx).items()})
    return callee_name(ctx, va) or own.get(va) or ""


def _static_objects(ctx: BinaryContext, insns) -> List[int]:
    """The objects the listing hands ``swift_initStaticObject(metadata, object)``: a static
    ``_NameMap`` array the compiler laid out in the image (shape C)."""
    out: List[int] = []
    for k, regs in call_site_registers(ctx, insns, _flow_of(ctx, insns)):
        t = _branch_target(insns[k]) if insns[k].mnemonic in ("bl", "b") else None
        if _symbol_at(ctx, t).lstrip("_") == "swift_initStaticObject" and "x1" in regs:
            out.append(regs["x1"])
    return out


# Instructions that only compute registers: what a pure tail-call stub is made of (arm64e signs
# a function pointer in place before passing it: ``paciza x16; mov x2, x16``).
_SETUP = frozenset({"adr", "adrp", "add", "mov", "movz", "movk", "movn", "nop", "paciza", "pacia"})


def _tail_call_args(insns) -> Optional[Dict[str, int]]:
    """The argument registers (x0-x7) known at the tail call of a pure stub -- a listing whose
    instructions before its last, a ``b`` out, only compute registers -- or None for any other
    listing.

    Such a getter / builder holds no table of its own: the (number, name) data is in the
    function it passes (shape D), in a literal it passes (shape E, F) or in a static blob."""
    if (len(insns) < 2 or insns[-1].mnemonic != "b" or _tail_calls(insns) != [len(insns) - 1]
            or any(i.mnemonic not in _SETUP for i in insns[:-1])):
        return None
    k = len(insns) - 1
    regs = Flow(None, list(insns)).propagate({}, at=[k]).get(k, {})
    return {f"x{n}": regs[f"x{n}"] for n in range(8) if f"x{n}" in regs}


def _in_executable_text(ctx: BinaryContext, va: int) -> bool:
    """True when *va* lands inside this image's own executable code section
    (as opposed to a data address, e.g. a once-token or a storage slot)."""
    if not ctx.has_section("__TEXT", "__text"):
        return False
    sec = ctx.section("__TEXT", "__text")
    return sec.vmaddr <= va < sec.vmaddr + sec.vmsize


# ── shape C: static-object blob ───────────────────────────────────────────────

def _name_ptr(ctx: BinaryContext, slot_va: int) -> Optional[int]:
    """The name pointer stored at *slot_va*, through the image's pointer fixups
    (``ctx.read_ptr``: a chained-fixup rebase in a standalone binary, the cache's slide)."""
    try:
        return ctx.read_ptr(slot_va)
    except READ_ERRORS:
        return None


_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")


def _static_entry(ctx: BinaryContext, blob_va: int, off: int,
                  enum: bool) -> Optional[Tuple[int, str]]:
    """The ``(key, name)`` of the static name-map element at *blob_va* + *off*, or None: a key
    in range (a field number >= 1, or any int32 case value) and a name pointer, read through
    the image's fixups (:func:`_name_ptr`), whose cstring is exactly the stored length (and an
    identifier, for an enum case)."""
    try:
        num, _ptr, ln = struct.unpack_from("<qQQ", ctx.read_bytes(blob_va + off, 24))
    except READ_ERRORS:
        return None
    if enum:
        if not -(1 << 31) <= num < (1 << 31):
            return None
    elif not 1 <= num <= _MAX_FIELD_NUMBER:
        return None
    nm = _cstr(ctx, _name_ptr(ctx, blob_va + off + 8))
    if not nm or ln != len(nm) or (enum and not _IDENT_RE.match(nm)):
        return None
    return num, nm


def _static_blob_stride(ctx: BinaryContext, blob_va: int, enum: bool = False) -> Optional[int]:
    """The element stride of a static name-map array: the smallest 8-aligned distance from the
    first element at which a second element parses (:func:`_static_entry`).

    A search, not a read: the stride is ``(Int, _NameDescription)``'s, and _NameDescription's
    size is version-specific.  Its value witness table (``_NameMap.NameDescription`` metadata
    - 8: size at +0x40, alignment in the flags at +0x50) gives it exactly, but that table is in
    the swift-protobuf image, which a standalone image linking it dynamically cannot read.  A
    wrong stride would have to land every element on an in-range key and a name pointer to a
    cstring of exactly the stored length, with no key repeated (:func:`_parse_static_blob`).
    ``tests/test_swift_descriptor_extract.TestStaticStrideWitness`` checks the search against the
    value witness stride on every static name map of the oracle fixtures (the only images with
    this lowering in the census)."""
    try:
        count = struct.unpack_from("<Q", ctx.read_bytes(blob_va + 0x10, 8))[0]
    except READ_ERRORS:
        return None
    if count < 2 or _static_entry(ctx, blob_va, 0x20, enum) is None:
        return None
    stride = next((st for st in range(0x18, _MAX_ELEMENT_STRIDE + 8, 8)
                   if _static_entry(ctx, blob_va, 0x20 + st, enum) is not None), None)
    if stride is None:
        record_heuristic_hit(ctx, "_MAX_ELEMENT_STRIDE",
                             f"the static name map at {blob_va:#x}: its first element parses, a "
                             f"second at no stride up to {_MAX_ELEMENT_STRIDE:#x}")
    return stride


def _parse_static_blob(ctx: BinaryContext, blob_va: int,
                       enum: bool = False) -> Optional[List[SwiftField]]:
    """A static ``Array<(Int, _NameDescription)>`` storage object: a 0x20-byte header
    (metadata, refcount, count, capacity), then ``count`` elements of one stride
    (:func:`_static_blob_stride`), each ``(key: Int, name pointer, name length, …)``.  Every
    element must parse (:func:`_static_entry`) and no key may repeat, else None.

    *enum*: the keys are case values (any int32; an alias repeats one) and the names must be
    identifiers; a message's keys are field numbers (>= 1), each once."""
    try:
        count = struct.unpack_from("<Q", ctx.read_bytes(blob_va + 0x10, 8))[0]
    except READ_ERRORS:
        return None
    first = _static_entry(ctx, blob_va, 0x20, enum) if count else None
    if first is None:
        return None
    out = [SwiftField(*first)]
    if count > 1:
        stride = _static_blob_stride(ctx, blob_va, enum)
        if stride is None:
            return None
        for i in range(1, count):
            e = _static_entry(ctx, blob_va, 0x20 + i * stride, enum)
            if e is None:
                return None
            out.append(SwiftField(*e))
    keys = [(f.number, f.name) if enum else f.number for f in out]
    return out if len(set(keys)) == len(keys) else None


# ── shapes A/B/C: the (number, name) stores of a name-map builder ────────────

class _Slot(NamedTuple):
    k: int                                  # the store's index in the listing
    addr: Tuple[Tuple[Tuple, ...], int]     # symbolic address (:func:`_sym`)
    value: Optional[int]                    # the stored register's value, if known
    bits: int                               # the stored register's width


def _sym(flow: Flow, k: int, reg: Optional[str], memo: Dict[int, tuple]) -> tuple:
    """*reg* before ``insns[k]`` as a symbolic address ``(atoms, offset)``: a constant plus a
    sum of values the listing cannot know -- a call's result, a field offset loaded from type
    metadata, a register's value on entry -- each an *atom* named by where it comes from.
    Read off the reaching definitions through ``mov`` copies and ``add`` / ``sub``; two
    addresses with the same atoms lie at a known distance from each other."""
    if reg is None:
        return (("?", k, ""),), 0
    c = flow.const_before(k, reg)
    if c is not None:
        return (), c
    defs = flow.defs_before(k, reg)
    if len(defs) != 1:
        return (("join", k, reg),), 0
    (d,) = defs
    if d < 0:
        return (("entry", -1, reg),), 0
    frag = flow.fragment(d)
    if frag is not None:                            # set by the outlined fragment d runs
        return _sym_fragment(flow, d, len(frag), reg, memo)
    if d in memo:
        return memo[d]
    memo[d] = (("def", d, ""),), 0                  # also what a cycle (a loop counter) sees
    res = _sym_insn(flow.insns[d], lambda r: _sym(flow, d, r, memo)) or memo[d]
    memo[d] = res
    return res


def _sym_fragment(flow: Flow, d: int, j: int, reg: Optional[str], memo: Dict) -> tuple:
    """:func:`_sym` of *reg* before instruction *j* of the outlined fragment the ``bl``
    ``insns[d]`` runs (:meth:`Flow.fragment`): set by an earlier instruction of it, or the value
    the register has at the call."""
    frag = flow.fragment(d)
    w = next((i for i in range(j - 1, -1, -1) if reg in writes(frag[i])), None)
    if w is None:
        return _sym(flow, d, reg, memo)
    key = ("frag", d, w, reg)
    if key in memo:
        return memo[key]
    memo[key] = (("frag", d, str(w)),), 0
    res = _sym_insn(frag[w], lambda r: _sym_fragment(flow, d, w, r, memo)) or memo[key]
    memo[key] = res
    return res


def _sym_insn(ins, operand) -> Optional[tuple]:
    """The symbolic address *ins* writes, its register operands read through *operand*: a
    ``mov`` copy or immediate, an ``add`` / ``sub`` of an immediate or a register; None for
    anything else (an atom of its own)."""
    ops = split_ops(ins.op_str)
    if ins.mnemonic == "mov" and len(ops) == 2:
        return ((), _parse_imm(ops[1])) if ops[1].startswith("#") else operand(_norm_reg(ops[1]))
    if ins.mnemonic in ("add", "sub") and len(ops) == 3:
        a = operand(_norm_reg(ops[1]))
        b = ((), _parse_imm(ops[2])) if ops[2].startswith("#") else operand(_norm_reg(ops[2]))
        if b[1] is not None and ins.mnemonic == "add":
            return tuple(sorted(a[0] + b[0])), a[1] + b[1]
        if b[1] is not None and not b[0]:
            return a[0], a[1] - b[1]
    return None


_STORES = ("str", "stur", "stp")


def _store_slots(flow: Flow, entry: Optional[Dict[str, int]]) -> List[_Slot]:
    """Every 64- / 32-bit register the listing stores outside its frame (``str`` / ``stur`` /
    ``stp``) -- its own stores and those of the outlined fragments it runs
    (:meth:`Flow.fragment`) -- with its address (:func:`_sym`) and value
    (:meth:`Flow.propagate` from *entry*).  Stores the entry cannot reach are left out."""
    ks = [k for k, ins in enumerate(flow.insns) if ins.mnemonic in _STORES]
    inside: Dict[int, List[Dict[str, int]]] = {}
    vals = flow.propagate(dict(entry or {}), at=ks, fragments_out=inside)
    memo: Dict = {}
    out: List[_Slot] = []
    for k in ks:
        if k in vals:
            out += _slots_of(flow.insns[k], k, vals[k], lambda r, k=k: _sym(flow, k, r, memo))
    for k, trace in sorted(inside.items()):
        for j, fi in enumerate(flow.fragment(k)):
            if fi.mnemonic in _STORES:
                out += _slots_of(fi, k, trace[j],
                                 lambda r, k=k, j=j: _sym_fragment(flow, k, j, r, memo))
    return out


def _slots_of(ins, k: int, regs: Dict[str, int], sym) -> List[_Slot]:
    """The slots one store *ins* (at listing index *k*) writes, its registers' values *regs*,
    its base read through *sym*; none for a frame or an indexed store (not a table)."""
    ops = split_ops(ins.op_str)
    n = 2 if ins.mnemonic == "stp" else 1
    if len(ops) < n + 1 or any(r[:1] not in ("x", "w") for r in ops[:n]):
        return []
    pm = parse_mem(ops[n])
    if pm is None or pm.base in (None, "sp", "x29") or pm.index is not None:
        return []
    atoms, off = sym(pm.base)
    if len(ops) == n + 1:                    # a post-indexed store writes at the base itself
        off += pm.disp
    out = []
    for r in ops[:n]:
        width = 8 if r.startswith("x") else 4
        v = 0 if r in ("xzr", "wzr") else regs.get(_norm_reg(r))
        out.append(_Slot(k, (atoms, off), None if v is None else v & ((1 << 8 * width) - 1),
                         8 * width))
        off += width
    return out


def _table_entries(ctx: BinaryContext, insns, enum: bool, entry: Optional[Dict[str, int]] = None,
                   with_len: bool = False) -> List[SwiftField]:
    """The (number, name) entries a name-map builder stores, paired by ADDRESS.  The name
    pointer of an entry is stored either 8 bytes after its number -- ``stp <num>, <name>``
    (shape A) or two ``str`` (shape B) -- or at the number's address plus one more unknown
    offset (shape C: the number is the ``Int`` of an ``(Int, _NameDescription)`` element and
    the name the first word of its ``_NameDescription``, whose offset in the element the
    runtime type metadata supplies: ``str <num>, [E]`` ... ``add Xd, E, <offset>`` ...
    ``stp <name>, <len>, [Xd]``).  A name pairs only with the one number at such an address,
    and each number with one name; entries come in store order.

    *with_len*: the name must be followed by its length (``stp <name>, <len>``, the inline
    closure).  *enum*: a number is any int32 (the stored register sign-extended), else a field
    number (1 .. 2^29-1).  *entry*: register values on entry (a stub's arguments)."""
    slots = _store_slots(_flow_of(ctx, insns), entry)
    at: Dict[tuple, Optional[_Slot]] = {}
    for s in slots:
        at[s.addr] = None if s.addr in at else s          # stored twice: not one entry
    numbers: Dict[tuple, int] = {}
    for a, s in at.items():
        if s is None or s.value is None:
            continue
        v = s.value
        if enum:
            v = v - (1 << s.bits) if v >> (s.bits - 1) else v
            if -(1 << 31) <= v < (1 << 31):
                numbers[a] = v
        elif 1 <= v <= _MAX_FIELD_NUMBER:
            numbers[a] = v
    pairs = []
    for (atoms, off), s in at.items():
        if s is None or s.bits != 64:
            continue
        name = _cstr(ctx, s.value)
        if not name:
            continue
        if with_len:
            ln = at.get((atoms, off + 8))
            if ln is None or ln.value != len(name):
                continue
        keys = {(atoms, off - 8)} | {(atoms[:i] + atoms[i + 1:], off) for i in range(len(atoms))}
        hits = [a for a in keys if a in numbers]
        if len(hits) == 1:
            pairs.append((s.k, hits[0], name))
    once = Counter(a for _k, a, _n in pairs)
    return [SwiftField(numbers[a], name) for _k, a, name in sorted(pairs) if once[a] == 1]


def _walk_inline_closure(ctx: BinaryContext, insns, enum: bool = False,
                         entry: Optional[Dict[str, int]] = None) -> List[SwiftField]:
    """Shape A, inline (device / framework closures): each entry is a number store plus
    ``<name>; mov w,#<len>; stp x,x,[entry]`` -- the name pointer with its length, which pins
    names to real entries (:func:`_table_entries` with the length)."""
    return _table_entries(ctx, insns, enum, entry, with_len=True)


def _walk_namemap_builder(ctx: BinaryContext, insns, enum: bool = False,
                          entry: Optional[Dict[str, int]] = None) -> List[SwiftField]:
    """Runtime-built ``_NameMap``: the ``(fieldNumber, name)`` table the cold builder writes
    into its freshly-allocated buffer (:func:`_table_entries`; the length lives in a separate
    ``_NameDescription`` constant, so none is required).  A message keeps the first entry per
    number; an enum case may be 0, negative or repeated (an alias), so it keeps the first per
    (value, name)."""
    out: List[SwiftField] = []
    seen: set = set()
    for f in _table_entries(ctx, insns, enum, entry):
        key = (f.number, f.name) if enum else f.number
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


def _shared_once_init_targets(insns) -> List[int]:
    """Shape D: the getter is only a tail call into a lazy-once-init TEMPLATE shared across
    many unrelated types (device / newer-toolchain ``static let`` lowering), passing a
    once-token, the type's ``_NameMap`` storage slot and the type's own builder function.
    The template carries no type information; the arguments do.  Returns the values of the
    argument registers (:func:`_tail_call_args`); callers keep the code addresses
    (:func:`_in_executable_text`), which drops the token and the slot in ``__DATA``.

    Only a pure stub qualifies: a once-init getter with its own fast / cold path (the
    :func:`_runtime_namemap_fields` shape) branches first, and an address in its cold path is
    not this type's builder (#74: remindd's UnmigrateRequest picked up its sibling `Option`
    enum's builder that way)."""
    args = _tail_call_args(insns)
    return list(args.values()) if args else []


def _tail_callee(ctx: BinaryContext, insns) -> Optional[Tuple[int, Dict[str, int]]]:
    """``(target, registers)`` when the listing ends in exactly one tail call, to code of
    this image: the function it hands its registers to (:meth:`Flow.propagate` at the
    ``b``), e.g. the shared template a builder stub sets up arguments for."""
    tails = _tail_calls(insns)
    if len(tails) != 1:
        return None
    k = tails[0]
    t = _branch_target(insns[k])
    regs = _flow_of(ctx, insns).propagate({}, at=[k]).get(k)
    if t is None or t == insns[0].addr or regs is None or not _in_executable_text(ctx, t):
        return None
    return t, regs


def _builder_entries(ctx: BinaryContext, va: int,
                     enum: bool = False) -> Tuple[List[SwiftField], bool]:
    """One builder's (number, name) table, and whether the listing it was read off was cut
    by the runaway guard.  When the builder is itself only an arg-setup stub (``adr
    x1,<storage>; adr x2,<name>; mov w3,<len>; b <template>``) for a shared template that does
    the stores, the template is read with the registers the stub hands it (:func:`_tail_callee`)
    as its entry values."""
    try:
        body = function_body(ctx, va)
        got = _walk_namemap_builder(ctx, body, enum)
        callee = None if got else _tail_callee(ctx, body)
        if callee is not None:
            body = function_body(ctx, callee[0])
            got = _walk_namemap_builder(ctx, body, enum, entry=callee[1])
    except READ_ERRORS:
        return [], False
    return got, body.truncated


def _closure_arg_targets(ctx: BinaryContext, insns) -> List[int]:
    """Code addresses the listing hands a callee as an argument (x0-x7 at a call or tail
    call): the closure a once-init getter passes ``swift_once`` (``adr x1,<closure>``, or
    ``adrp``+``add`` when it is far, as in device / cache images).  Values outside this
    image's executable text -- the once-token, a storage slot -- are not closures."""
    out: List[int] = []
    for _k, regs in call_site_registers(ctx, insns, _flow_of(ctx, insns)):
        for r in (f"x{n}" for n in range(8)):
            v = regs.get(r)
            if v is not None and v not in out and _in_executable_text(ctx, v):
                out.append(v)
    return out


def _runtime_namemap_fields(ctx: BinaryContext, getter_insns,
                            enum: bool = False) -> List[SwiftField]:
    """The once-initialised ``_NameMap`` lowering: the getter fast-path loads a
    cached ``_NameMap`` from ``__bss`` and a ``cmn x?,#1; b.ne <builder>`` guards
    a cold builder that constructs it once.  Follow the cold path to the builder
    closure and read its literal ``(number, name)`` table (:func:`_walk_namemap_
    builder`).  Returns ``[]`` unless the once-init signature is present AND a builder is
    found.

    This recovers app types whose nameMap is emitted as a runtime ``_NameMap``
    (e.g. remindd ``StartMigrationRequest.Credential``, 5 fields), not only the SwiftProtobuf
    well-known types."""
    # Gate: the lazy-_NameMap guard compares the cached pointer to the -1 sentinel.
    if not any(ins.mnemonic == "cmn" and ins.op_str.strip().endswith("#1")
               for ins in getter_insns):
        return []
    # The builder: the getter's own cold path, or the closure it hands swift_once.
    readings = [(_walk_namemap_builder(ctx, getter_insns, enum),
                 getattr(getter_insns, "truncated", False))]
    readings += [_builder_entries(ctx, c, enum) for c in _closure_arg_targets(ctx, getter_insns)]
    best: List[SwiftField] = []
    best_truncated = False
    for got, trunc in readings:
        if len(got) > len(best):
            best, best_truncated = got, trunc
    # CAUTIOUS: if the builder's listing ran into the runaway guard, its (number, name) store
    # table may be incomplete.  Rather than launder a partial read as ground truth, flag the
    # recovered numbers as estimated (renders "// number estimated").
    if best_truncated:
        for f in best:
            f.number_confirmed = False
    return best


def _namemap_builder_validated(ctx: BinaryContext, got: List[SwiftField],
                               traverse_va: Optional[int],
                               enum: bool = False) -> bool:
    """Guard the runtime-namemap reading against fabrication.

    A ``stp <smallInt>, <namePtr>, [base,#slot]`` pair is AMBIGUOUS by its stores alone: the
    small int is the field NUMBER in the older codegen (remindd) but the name LENGTH in a
    ``(length, pointer)`` description (nptocompaniond ErrorResponse: 6 = len 'domain',
    4 = 'code'), and both sit 8 bytes before the name, so :func:`_table_entries` pairs either
    as a number.

    Accept only when neither check rejects:
      * the field numbers ``traverse`` visits (:func:`_traverse_visits`, a different codegen
        path) are a SUBSET of the recovered set — a contradiction means we read the
        wrong thing; and
      * not EVERY entry has ``number == len(name)`` — the signature of the
        ``(length, ptr)`` packed form."""
    if enum:
        # no traverse for an enum; the (length, ptr) packed-form
        # confusion is a message-field-number artefact.  Case names must all look
        # like identifiers, and at least one entry must exist.
        return bool(got) and all(_IDENT_RE.match(f.name) for f in got)
    oracle = set(_traverse_field_numbers(ctx, traverse_va)) if traverse_va is not None else set()
    if oracle and not oracle <= {f.number for f in got}:
        return False
    if got and all(f.number == len(f.name) for f in got):
        record_heuristic_hit(ctx, "swift name-map number == len(name)",
                             f"{len(got)} entries of the name map read for the traverse at "
                             f"{traverse_va or 0:#x} are rejected as (length, pointer) pairs")
        return False
    return True


# swift-protobuf's Visitor methods take ``(value, fieldNumber: Int, …)``: in the Swift calling
# convention the field number is the integer argument after the value's registers -- none for a
# Float / Double (it travels in an FP register), two for a String / Data (two words), one for
# everything else (an integer, a Bool, an Array, a Dictionary, an enum or message by reference).
# Checked over every named visit call of the census: each method's constant sits in that register.
_VISIT_RE = re.compile(r"VisitorP\d+visit(Singular|Repeated|Packed)?(\w*?)Field")
_VISIT_SCALARS = {
    "Int32": "int32", "Int64": "int64", "UInt32": "uint32", "UInt64": "uint64",
    "SInt32": "sint32", "SInt64": "sint64", "Fixed32": "fixed32", "Fixed64": "fixed64",
    "SFixed32": "sfixed32", "SFixed64": "sfixed64", "Bool": "bool", "Float": "float",
    "Double": "double", "String": "string", "Bytes": "bytes",
}
# the integer encodings a Swift Int32 / Int64 / UInt32 / UInt64 field may be written with (LIM 10b)
_VISIT_ENCODINGS = frozenset({"sint32", "sint64", "fixed32", "fixed64", "sfixed32", "sfixed64"})


_SWIFT_PROTOBUF_MODULES = ("InternalSwiftProtobuf", "SwiftProtobuf")


def _visitor_symbols(ctx: BinaryContext) -> Dict[str, int]:
    """The symbols that can name a swift-protobuf ``Visitor`` requirement: the image's own (a
    binary that links swift-protobuf statically, or the framework itself), and in a dyld cache
    the exports of the swift-protobuf framework the image links."""
    reader = getattr(ctx, "_cache_reader", None)
    if reader is None or not getattr(ctx, "is_cache_backed", False):
        return {n: a for n, a in ctx.iter_symbols() if a}
    images = [ctx.image_base] + [
        reader.find_image_header(p) for p in reader.image_dependencies(ctx.image_base)
        if p.rsplit("/", 1)[-1] in _SWIFT_PROTOBUF_MODULES]
    out: Dict[str, int] = {}
    for mh in images:
        if mh is not None:
            out.update(reader.image_exports(mh))
    return out


def _build_visitor_slots(ctx: BinaryContext) -> Dict[int, str]:
    out: Dict[int, str] = {}
    syms = _visitor_symbols(ctx)
    for name, desc in syms.items():
        if not name.endswith("7VisitorMp"):
            continue
        # protocol descriptor: flags, parent, name, NumRequirementsInSignature,
        # NumRequirements, associated type names; then the signature's requirements (12
        # bytes each) and the protocol's own (8 bytes each), in witness-table order after the
        # table's first word (the conformance descriptor)
        _f, _p, _n, nsig, nreq, _a = struct.unpack("<IiiIIi", ctx.read_bytes(desc, 24))
        start = desc + 24 + 12 * nsig
        for meth, addr in syms.items():
            if meth.endswith("Tq") and start <= addr < start + 8 * nreq and not (addr - start) % 8:
                out.setdefault(8 + addr - start, meth)
    return out


def _visitor_slots(ctx: BinaryContext) -> Dict[int, str]:
    """``{witness-table offset: method descriptor symbol}`` of the swift-protobuf ``Visitor``
    protocol, read off its descriptor (``…7VisitorMp``) and its methods' descriptors
    (``…VisitorP…Tq``); empty when the image cannot see them.  Memoised on *ctx*."""
    def build():
        try:
            return _build_visitor_slots(ctx)
        except READ_ERRORS:
            return {}
    return _ctx_cache(ctx, "_swift_visitor_slots", build)


def _visit_method(ctx: BinaryContext, flow: Flow, k: int) -> Optional[Tuple[str, str]]:
    """``(label, kind)`` of the swift-protobuf ``Visitor.visit<label><kind>Field`` method the
    call ``insns[k]`` of a ``traverse<V: Visitor>`` goes to; label is Singular / Repeated /
    Packed or "" (``visitMapField``).  A ``bl`` is named by its dispatch thunk
    (``…VisitorP24visitSingularInt64Field…Tj``); a ``blr`` by the witness-table slot its target
    is loaded from -- the table is ``traverse``'s ``x2`` on entry -- and the Visitor requirement
    at that slot (:func:`_visitor_slots`).  None for any other call."""
    ins = flow.insns[k]
    name = ""
    if ins.mnemonic == "bl":
        name = _symbol_at(ctx, _branch_target(ins))
    elif ins.mnemonic in CALLS:
        reg = _norm_reg(split_ops(ins.op_str)[0])
        d = next(iter(flow.defs_before(k, reg)), -1) if len(flow.defs_before(k, reg)) == 1 else -1
        ld = flow.insns[d] if d >= 0 else None
        ops = split_ops(ld.op_str) if ld is not None and ld.mnemonic == "ldr" else []
        pm = parse_mem(ops[1]) if len(ops) == 2 and not ops[1].endswith("!") else None
        if pm is not None and pm.index is None and \
                _sym(flow, d, pm.base, {}) == ((("entry", -1, "x2"),), 0):
            name = _visitor_slots(ctx).get(pm.disp, "")
    m = _VISIT_RE.search(name)
    return (m.group(1) or "", m.group(2)) if m else None


def _visit_number_register(label: str, kind: str) -> Optional[str]:
    if kind == "Extension":
        return None                               # an extension's number is the extension's
    if label == "Singular" and kind in ("Float", "Double"):
        return "x0"
    if label == "Singular" and kind in ("String", "Bytes"):
        return "x2"
    return "x1"


def _traverse_visits(ctx: BinaryContext, traverse_va: int) -> List[Tuple[int, Optional[str]]]:
    """``(field number, proto type or None)`` per field a ``traverse(visitor:)`` body visits,
    in visit order.

    A call to a Visitor method :func:`_visit_method` can name gives the number exactly -- the
    register the method's signature puts it in (:func:`_visit_number_register`), its value by
    :meth:`Flow.propagate` -- and the type (``visitSingularSInt32Field`` -> ``sint32``,
    ``visitRepeatedUInt64Field`` -> ``repeated uint64``; None for a message, enum, group or
    map).  A call it cannot name -- a witness ``blr`` in an image that cannot see the Visitor
    protocol, e.g. an extracted framework whose swift-protobuf is another file -- still takes the
    highest-numbered ``w`` register set by an immediate since the previous call: the remaining
    heuristic."""
    try:
        insns = function_body(ctx, traverse_va)
    except READ_ERRORS:
        return []
    flow = _flow_of(ctx, insns)
    at_call = dict(call_site_registers(ctx, insns, flow))
    out: List[Tuple[int, Optional[str]]] = []
    pend: Dict[str, int] = {}        # w-register -> immediate, since the last call
    for k, ins in enumerate(insns):
        m = ins.mnemonic
        if m in ("mov", "movz") and "," in ins.op_str:
            dst, _, src = ins.op_str.partition(",")
            dst = dst.strip()
            v = _parse_imm(src)
            if v is not None and dst.startswith("w") and 1 <= v <= _MAX_FIELD_NUMBER:
                pend[dst] = v
        elif m in CALLS:
            visit = _visit_method(ctx, flow, k)
            if visit is not None:
                reg = _visit_number_register(*visit)
                v = at_call.get(k, {}).get(reg) if reg else None
                if v is not None and 1 <= v <= _MAX_FIELD_NUMBER:
                    scalar = _VISIT_SCALARS.get(visit[1])
                    typ = None if scalar is None else \
                        scalar if visit[0] == "Singular" else f"repeated {scalar}"
                    out.append((v, typ))
            elif pend:
                hi = max(pend, key=lambda r: int(re.sub(r"\D", "", r) or "-1"))
                out.append((pend[hi], None))
            pend = {}
    return out


def _traverse_field_numbers(ctx: BinaryContext, traverse_va: int) -> List[int]:
    """Field numbers from a ``traverse(visitor:)`` body, in visit order (:func:`_traverse_visits`).
    This is the canonical, complete per-field number source (the swift analog of PBCodable
    ``writeTo:``); the nameMap only supplies names."""
    return [n for n, _t in _traverse_visits(ctx, traverse_va)]


# ── per-type extraction ───────────────────────────────────────────────────────

def _enum_cases_plausible(got: List[SwiftField]) -> bool:
    """Self-consistency of a recovered enum case table.

    protoc-gen-swift writes an enum's name map sorted by case value (aliases share a
    value), with distinct identifier names.  An enum has no ``traverse``
    to cross-check its table against, so one that breaks this invariant is rejected rather
    than emitted with wrong values."""
    nums = [f.number for f in got]
    names = [f.name for f in got]
    return (bool(got) and nums == sorted(nums) and len(set(names)) == len(names)
            and all(_IDENT_RE.match(n) for n in names))


def _extract_namemap(ctx: BinaryContext, init_va: int,
                     traverse_va: Optional[int] = None,
                     enum: bool = False) -> Tuple[List[SwiftField], str]:
    """See :func:`_extract_namemap_raw`; for an enum the result must also pass
    :func:`_enum_cases_plausible`."""
    got, shape = _extract_namemap_raw(ctx, init_va, traverse_va, enum)
    if enum and got and not _enum_cases_plausible(got):
        return [], "none"
    return got, shape


def _extract_namemap_raw(ctx: BinaryContext, init_va: int,
                     traverse_va: Optional[int] = None,
                     enum: bool = False) -> Tuple[List[SwiftField], str]:
    """Recover one type's (number, name) entries, auto-detecting the lowering.

    Every shape reads the getter's :func:`~proto.function_body.function_body` -- what its entry reaches, up to its
    returns and tail calls -- so a stub getter (a tail call) is never read on into the
    next function in memory.

    *enum*: the type is a swift ``enum`` (case value <-> case name) rather than a
    message.  The same lowerings are used, but values may be 0 / negative / repeated
    and there is no ``traverse`` to cross-check against."""
    try:
        insns = function_body(ctx, init_va)
    except READ_ERRORS:
        return [], "none"

    # C — static object: the array the getter hands swift_initStaticObject.
    for blob in _static_objects(ctx, insns):
        got = _parse_static_blob(ctx, blob, enum)
        if got:
            return got, "static"

    # A — inline, directly in this function, or in the function it tail-calls with its
    # registers (CreateML getters: `adrp; add; b <the closure placed next>`).
    got = _walk_inline_closure(ctx, insns, enum)
    callee = None if got else _tail_callee(ctx, insns)
    if callee is not None:
        try:
            got = _walk_inline_closure(ctx, function_body(ctx, callee[0]), enum, entry=callee[1])
        except READ_ERRORS:
            got = []
    if got:
        return got, "inline"

    # Runtime-built _NameMap (once-init `cmn x?,#1; b.ne <builder>`): follow the
    # cold builder closure and read its literal (number, name) table.  #72.
    got = _runtime_namemap_fields(ctx, insns, enum)
    if len(got) > (0 if enum else 1) and _namemap_builder_validated(
            ctx, got, traverse_va, enum):
        return got, "runtime-namemap"
    # a runtime builder with exactly ONE entry is used last, under the same oracle validation and
    # Swift reflection's check of the name (``runtime-single``): its literal is the only support.
    runtime_single = got if (len(got) == 1 and not enum) else None

    # D — shared once-init template (`adr x0,<token>; adr x1,<storage>;
    # adr x2,<builder>; b <shared-template>`): chase every CODE address the stub
    # passes (skipping the once-token / storage data addresses) and read
    # its literal (number, name) table (:func:`_builder_entries`,
    # which follows one further tail-call when the builder is itself just an
    # arg-setup stub for a second shared template) -- oracle-validated for
    # the same reason as runtime-namemap.  #74.
    best_shared: List[SwiftField] = []
    shared_shape = "shared-once"
    for t in _shared_once_init_targets(insns):
        if t == init_va or not _in_executable_text(ctx, t):
            continue
        got = _builder_entries(ctx, t, enum)[0]
        packed = False
        if not got:
            # iOS 27: the builder is a stub passing the packed bytecode literal (x2) and its
            # length (w3) to the shared template (shape E's data, one hop deeper)
            try:
                stub = function_body(ctx, t)
                lit = bytecode_literal_from_getter(ctx, stub, enum=enum, flow=_flow_of(ctx, stub))
            except READ_ERRORS:
                lit = None
            dec = decode_namemap_bytecode(lit, enum=enum) if lit else None
            if dec:
                got = [SwiftField(n, nm) for n, nm in dec]
                packed = True
        if len(got) > len(best_shared):
            best_shared = got
            shared_shape = "bytecode" if packed else "shared-once"
    if best_shared and (shared_shape == "bytecode"
                        or _namemap_builder_validated(ctx, best_shared, traverse_va, enum)):
        return best_shared, shared_shape

    # E — packed-bytecode `_NameMap(bytecode:)` literal (iOS 27 toolchain): the
    # getter hands a string literal + length to a shared template.  Placed after
    # D (whose targets are code addresses; the literal is data, so the two never
    # collide).
    lit = bytecode_literal_from_getter(ctx, insns, enum=enum, flow=_flow_of(ctx, insns))
    if lit is not None:
        decoded = decode_namemap_bytecode(lit, enum=enum)
        if decoded:
            return [SwiftField(n, nm) for n, nm in decoded], "bytecode"

    # A — inline, in the closure the getter passes a call (device getter → swift_once).
    for t in _closure_arg_targets(ctx, insns):
        if t == init_va:
            continue
        try:
            cl = function_body(ctx, t)
        except READ_ERRORS:
            continue
        got = _walk_inline_closure(ctx, cl, enum)
        if got:
            return got, "inline-closure"

    if runtime_single and _namemap_builder_validated(ctx, runtime_single, traverse_va):
        return runtime_single, "runtime-single"
    return [], "none"


# ── top-level ─────────────────────────────────────────────────────────────────

def swift_messages(ctx: BinaryContext) -> List[SwiftMessage]:
    """Recover every swift-protobuf MESSAGE's field names + numbers (and, from
    reflection metadata, types).

    Returns one :class:`SwiftMessage` per struct type with a recovered nameMap,
    sorted by qualified name.  Works both from a standalone binary (LC_SYMTAB /
    export trie) and cache-native (the ``.symbols`` sub-cache); empty only when no
    symbol source resolves the per-type nameMap symbols.  Enums are separate:
    :func:`swift_enums`."""
    return _recover_types(ctx, want_enum=False)


def swift_enums(ctx: BinaryContext) -> List[SwiftMessage]:
    """Recover every swift-protobuf ENUM's cases (``fields`` = (value, name), value
    may be 0, negative, or shared by an alias) with ``is_enum=True``.  Same symbol
    sources and lowerings as :func:`swift_messages`; the enum's case-value table is
    its ``_protobuf_nameMap``."""
    return _recover_types(ctx, want_enum=True)


# A function symbol's own body: ``…F``, or ``…FTm`` when identical bodies of several types were
# merged into one (still this type's function).  ``…XEfU_`` and the like are closures inside it.
_FUNCTION_BODY_SUFFIXES = ("F", "FTm")


def _recover_types(ctx: BinaryContext, want_enum: bool) -> List[SwiftMessage]:
    syms = symbol_addrs(ctx)
    if not syms:
        return []

    # init point per type: prefer the `_WZ` static-init function, else the
    # `vgZ` static getter (the device/framework form).
    inits: Dict[Tuple[str, str], Tuple[int, str]] = {}
    traversers: Dict[Tuple[str, str], int] = {}
    for name, va in syms.items():
        if _NAMEMAP_MARKER in name:
            p = _parse_namemap_symbol(name)
            if not p or p[2] != want_enum:
                continue
            parsed = (p[0], p[1])
            if name.endswith("_WZ"):
                inits[parsed] = (va, "WZ")
            elif name.endswith("vgZ") and parsed not in inits:
                inits[parsed] = (va, "vgZ")
        elif want_enum:
            continue
        elif "V8traverse" in name and name.endswith(_FUNCTION_BODY_SUFFIXES):
            t = _type_of_symbol(name, "8traverse")
            if t and t[2] == "V":
                traversers.setdefault(t[:2], va)

    out: List[SwiftMessage] = []
    for (module, tname), (va, _kind) in inits.items():
        fields, shape = _extract_namemap(ctx, va, traversers.get((module, tname)),
                                         enum=want_enum)
        out.append(SwiftMessage(module=module, name=tname, fields=fields,
                                is_enum=want_enum, shape=shape))
    if not want_enum:
        _attach_field_types(ctx, out)
        for m in out:
            tva = traversers.get((m.module, m.name))
            if m.fields and tva is not None:
                _attach_visit_types(m, _traverse_visits(ctx, tva))
    out.sort(key=lambda m: m.qualified)
    return out


def _norm(name: str) -> str:
    """Normalise a field name for the snake_case (nameMap) <-> camelCase (Swift
    field metadata) join: drop underscores, lowercase."""
    return name.replace("_", "").lower()


# Readings with no cross-check of their own (one builder entry): kept only when Swift reflection
# agrees the message has that field.
_REFLECTION_CONFIRMED_SHAPES = frozenset({"runtime-single"})


def _attach_field_types(ctx: BinaryContext, msgs: List[SwiftMessage]) -> None:
    """Recover field TYPES from Swift field metadata and bind them onto the
    name+number fields by normalised field name (best-effort; leaves proto_type
    None where metadata is absent).  ``swift_type_recovery.collect_field_types``
    supplies types from the message struct, its COW ``_StorageClass``, and its
    ``OneOf_*`` enums (#60), so oneof/storage-backed fields are now covered too."""
    try:
        from serializers import swift_type_recovery
        by_type, incomplete, fieldless, stored = swift_type_recovery.collect_field_types(ctx)
    except (NameError, ImportError):
        raise
    except Exception as exc:
        from proto.models import get_diagnostics
        get_diagnostics(ctx).foreign_errors.append(
            ("swift-protobuf", f"field types: {type(exc).__name__}: {exc}"))
        log.warning("swift-protobuf field-type recovery FAILED (%s: %s); field types missing",
                    type(exc).__name__, exc)
        return
    for m in msgs:
        if m.shape in _REFLECTION_CONFIRMED_SHAPES and m.fields:
            # single-entry readings whose only support is the literal itself: the struct's
            # reflection must list that field, or the reading is another type's
            # (e.g. an empty message whose getter reaches a sibling's closure).  Any
            # stored field record counts, whether or not its type decodes.
            refl = {_norm(k) for k in stored.get(m.name, ())}
            if _norm(m.fields[0].name) not in refl:
                m.fields, m.shape = [], "none"
        if not m.fields and m.name in fieldless:
            m.fieldless = True
    if not by_type:
        return
    # the type map is keyed by the type's QUALIFIED name (Outer.Inner); look up by
    # the message's full name first.  Fall back to a short-name match ONLY when it
    # is UNAMBIGUOUS — several messages can share a nested short name (e.g.
    # `MigrateResponse.Details` vs `StartMigrationResponse.Details`), and binding to
    # an arbitrary one of them would mis-type fields (#68).
    for m in msgs:
        types = by_type.get(m.name)
        inc = incomplete.get(m.name, set())
        if types is None:
            short = m.name.split(".")[-1]
            cands = [(k, v) for k, v in by_type.items() if k.split(".")[-1] == short]
            if len(cands) == 1:
                types, inc = cands[0][1], incomplete.get(cands[0][0], set())
        if not types:
            continue
        norm = {_norm(k): v for k, v in types.items()}
        norm_inc = {_norm(k) for k in inc}
        for f in m.fields:
            key = _norm(f.name)
            t = norm.get(key)
            if t:
                f.proto_type = t
                if key in norm_inc:
                    f.type_note = ("swift-protobuf: container element/value type "
                                   "not recovered (shown as bytes)")


def _attach_visit_types(m: SwiftMessage, visits: List[Tuple[int, Optional[str]]]) -> None:
    """Types from the Visitor method each field is written with (:func:`_traverse_visits`):
    the integer encoding Swift reflection cannot tell (an ``Int32`` written zigzag is ``sint32``,
    a ``UInt64`` written fixed is ``fixed64``), and the scalar type of a field reflection did not
    type at all or only guessed (a ``bytes`` filler with its ``type_note``: the guess is replaced
    and the note cleared)."""
    typed = {}
    for num, typ in visits:
        if typ is not None:
            typed.setdefault(num, typ)
    for f in m.fields:
        typ = typed.get(f.number)
        if typ is None:
            continue
        if f.proto_type is None or f.type_note or typ.split()[-1] in _VISIT_ENCODINGS:
            f.proto_type = typ
            f.type_note = None


# ── fat-binary slice helper ───────────────────────────────────────────────────

_FAT_MAGIC_BE = 0xCAFEBABE
_FAT_MAGIC_64_BE = 0xCAFEBABF
_CPU_TYPE_ARM64 = 0x0100000C


def load_macho_slice(data: bytes, prefer=("arm64e", "arm64")) -> bytes:
    """Return a single-arch Mach-O slice from *data*, picking the preferred arm64
    slice from a fat binary; returns *data* unchanged if already thin."""
    if len(data) < 8:
        return data
    magic = struct.unpack_from(">I", data, 0)[0]
    if magic not in (_FAT_MAGIC_BE, _FAT_MAGIC_64_BE):
        return data
    wide = magic == _FAT_MAGIC_64_BE
    nfat = struct.unpack_from(">I", data, 4)[0]
    entry = 32 if wide else 20
    best: Optional[Tuple[int, int, int]] = None   # (rank, offset, size)
    for i in range(nfat):
        o = 8 + i * entry
        if o + entry > len(data):
            break
        cputype = struct.unpack_from(">I", data, o)[0]
        cpusub = struct.unpack_from(">I", data, o + 4)[0]
        if wide:
            off = struct.unpack_from(">Q", data, o + 8)[0]
            size = struct.unpack_from(">Q", data, o + 16)[0]
        else:
            off = struct.unpack_from(">I", data, o + 8)[0]
            size = struct.unpack_from(">I", data, o + 12)[0]
        if cputype != _CPU_TYPE_ARM64:
            continue
        is_e = (cpusub & 0x00FFFFFF) == 2
        rank = 0 if (is_e and prefer[0] == "arm64e") else 1
        if best is None or rank < best[0]:
            best = (rank, off, size)
    if best and best[1] + best[2] <= len(data):
        return data[best[1]:best[1] + best[2]]
    return data
