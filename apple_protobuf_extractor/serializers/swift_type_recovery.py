"""swift_type_recovery.py — recover swift-protobuf message field TYPES from a
binary's Swift reflection metadata (``__swift5_fieldmd``).

swift-protobuf emits each message as a Swift struct whose stored properties ARE
the proto fields.  Swift always emits field-reflection metadata (name + a mangled
reference to the type) for such structs, so the types are recoverable even though
the nameMap (number↔name) carries none.

Pipeline:
  __swift5_types  -> per-type context descriptor -> FieldDescriptor (__swift5_fieldmd)
                  -> FieldRecord[] : (flags, mangledTypeName relptr, fieldName relptr)
  decode the mangled type:
    * direct codes        Sf/Sd/Sb/SS/Si/Su        -> float/double/bool/string/Int/UInt
    * Array  Say<elem>G                            -> repeated <elem>
    * Optional <inner>Sg                           -> <inner> (proto3 presence)
    * Dictionary SD y<k><v>                         -> map<k, v>
    * symbolic reference (\\x01 direct / \\x02 indirect):
        - resolves to a LOCAL type descriptor  -> its name (message / enum)
        - resolves to a bind import (external)  -> the import symbol name, demangled
          (``_$ss5Int32VMn`` -> Int32, ``_$s10Foundation4DataVMn`` -> Data, …)

The Swift type maps 1:1 to the proto BASE type: the encoding (int32 / sint32 / sfixed32, all
``Int32`` in Swift) is not here.  A field's type comes from the message's own code
(:mod:`serializers.swift_message_code`, TODO #129); these are the last resort, a field joined
to the property of its NAME, reported (``swift-name-join``; LIMITATIONS.md (10)).

Returns ``{type_name: {field_name: proto_type}}`` so a caller can join by field NAME against
the nameMap (number↔name).
"""
from __future__ import annotations

import re
import struct
from typing import Dict, NamedTuple, Optional, Set

from macho.memory import READ_ERRORS, record_unread

# Swift stdlib / Foundation type name -> proto scalar type.
_SWIFT_SCALAR = {
    "Int32": "int32", "Int64": "int64", "UInt32": "uint32", "UInt64": "uint64",
    "Int": "int64", "UInt": "uint64", "Bool": "bool", "Float": "float",
    "Double": "double", "String": "string", "Data": "bytes",
}
# direct two/■-char manglings
_DIRECT = {
    "Sf": "float", "Sd": "double", "Sb": "bool", "SS": "string",
    "Si": "int64", "Su": "uint64",
}
# single-char Swift standard-substitution codes for scalar stdlib types
# (the char following the 'S' marker), used by the run-length expander below.
_STD_SUB = {
    "f": "float", "d": "double", "b": "bool", "S": "string",
    "i": "int64", "u": "uint64",
}


def _runlength_types(text):
    """Expand a leading run of Swift standard-substitution scalar tokens,
    honouring the run-length form ``S<n><char>`` (n copies of one substitution).

    e.g. ``S2SG`` -> ['string', 'string'] (the map<String,String> body, where
    two consecutive ``SS`` Strings collapse to ``S2S``); ``SSSiG`` ->
    ['string', 'int64'].  Stops at the first token that is not a scalar
    standard substitution (symbolic ref, Foundation.Data, nested Array, etc.)."""
    out, i, n = [], 0, len(text)
    while i < n and text[i] == "S":
        j = i + 1
        while j < n and text[j].isdigit():
            j += 1
        count = int(text[i + 1:j]) if j > i + 1 else 1
        if j >= n:
            break
        proto = _STD_SUB.get(text[j])
        if proto is None:
            break
        out.extend([proto] * count)
        i = j + 1
    return out
_STRUCT_KIND, _ENUM_KIND = 17, 18
# [cap:INPUT-SANITY] runaway guard on the parent contexts walked for a qualified name (the
# walk ends at the module).  (A FieldDescriptor's records are bounded by its own count and the
# end of __swift5_fieldmd, :func:`_read_field_types`.)
_MAX_CONTEXT_DEPTH = 12


def _i32(ctx, va):
    return struct.unpack("<i", ctx.read_bytes(va, 4))[0]


def _u32(ctx, va):
    return struct.unpack("<I", ctx.read_bytes(va, 4))[0]


def _u16(ctx, va):
    return struct.unpack("<H", ctx.read_bytes(va, 2))[0]


def _relptr(ctx, va):
    """Swift RelativeDirectPointer: target = address + signed int32.

    The FieldDescriptor / FieldRecord pointers (type name, field name, field
    descriptor) are all *direct* — the low bit is a real address bit (names are
    byte-aligned, often odd), NOT an indirect flag.  The exceptions are read by their
    own helpers: a context descriptor's parent, an indirectable pointer
    (:func:`_parent_desc`), and a ``__swift5_types`` record, which carries a kind in its
    low bits (:func:`_type_record`).  Symbolic references inside a mangled name carry
    their own control byte and are handled separately in :func:`_resolve_symbolic`."""
    v = _i32(ctx, va)
    return 0 if v == 0 else va + v


def _type_record(ctx, va):
    """The nominal type descriptor a ``__swift5_types`` record at *va* names: a relative
    pointer whose low two bits are its TypeReferenceKind -- 0 the descriptor itself, 1 a
    pointer to it (another image's, or behind a fixup); 0 for an ObjC class reference
    (2 / 3), which has no Swift descriptor."""
    v = _i32(ctx, va)
    kind, target = v & 3, va + (v & ~3)
    if v == 0 or kind > 1:
        return 0
    return ctx.read_ptr(target) if kind == 1 else target


def _cstr(ctx, va):
    """A name the metadata points at: up to its terminator, within its segment (no length cap
    -- one that cut a long name made the field vanish)."""
    try:
        return ctx.read_cstring(va, None)
    except READ_ERRORS:
        return None


def _desc_name(ctx, desc):
    try:
        return _cstr(ctx, _relptr(ctx, desc + 0x08))
    except READ_ERRORS:
        return None


def _desc_kind(ctx, desc):
    try:
        return _u32(ctx, desc) & 0x1F
    except READ_ERRORS:
        return -1


# ── mangled symbol demangling (just enough for type-descriptor bind names) ─────

# Swift caps the per-symbol word-substitution table at 26 (one letter each).
_MAX_WORDS = 26


def _is_word_start(c):
    return c not in ("", "\0", "_") and not c.isdigit()


def _is_word_end(c, prev):
    return c in ("", "\0", "_") or (not prev.isupper() and c.isupper())


def _register_words(slc, words):
    """Append the word fragments of a literal identifier slice to *words* (the
    running substitution table), matching Swift's mangler: a word starts at a
    non-digit/non-'_' char and ends at '_' or a camelCase boundary; only words
    of length >= 2 are stored, up to 26 total."""
    start = -1
    n = len(slc)
    for i in range(n + 1):
        c = slc[i] if i < n else "\0"
        prev = slc[i - 1] if i >= 1 else "\0"
        if start >= 0 and _is_word_end(c, prev):
            if i - start >= 2 and len(words) < _MAX_WORDS:
                words.append(slc[start:i])
            start = -1
        if start < 0 and _is_word_start(c):
            start = i


def _demangle_one(s, i, words):
    """Decode ONE Swift identifier starting at *s[i]*, resolving word
    substitutions against (and extending) *words*.  Returns (text, next_i) or
    (None, i) if undecodable.  Handles both the plain ``<len><chars>`` form and
    the leading-'0' word-substitution form where a letter back-references a
    previously seen word (uppercase = last substitution in the run).  A word-
    substituted identifier may be closed by an explicit ``0`` (``06ClientF0`` =
    ``ClientMetadata``: literal ``Client`` + last-subst ``F``, then the
    terminator) -- mirrors the Swift demangler's ``if (nextIf('0')) break``."""
    n = len(s)
    has_subst = False
    subst_ident = False
    if s[i] == "0":
        if i + 1 < n and s[i + 1] == "0":
            return None, i                 # '00' = punycode — unsupported, bail
        has_subst = subst_ident = True
        i += 1
    out = []
    while True:
        if has_subst:
            while i < n and s[i].isalpha():
                c = s[i]
                i += 1
                if c.islower():
                    idx = ord(c) - ord("a")
                else:
                    idx = ord(c) - ord("A")
                    has_subst = False      # uppercase letter ends the subst run
                if idx >= len(words):
                    return None, i
                out.append(words[idx])
                if not has_subst:
                    break
        if subst_ident and i < n and s[i] == "0":
            i += 1                         # '0' terminates a word-substituted identifier
            break
        j = i
        while j < n and s[j].isdigit():
            j += 1
        if j == i:
            break
        num = int(s[i:j])
        i = j
        if num <= 0 or i + num > n:
            return None, i
        slc = s[i:i + num]
        i += num
        out.append(slc)
        _register_words(slc, words)
        if not has_subst:
            break
    return ("".join(out), i) if out else (None, i)


def demangle_idents(s):
    """Parse a run of Swift length-prefixed identifiers, resolving word-
    substitution abbreviations.  The substitution table is SHARED across the run
    (a later identifier references words from an earlier one), e.g.
    ``13SwiftProtobuf07Google_B4_Any`` -> ['SwiftProtobuf', 'Google_Protobuf_Any']
    (``B`` back-references 'Protobuf' from 'SwiftProtobuf')."""
    out, i, n, words = [], 0, len(s), []
    while i < n:
        if not s[i].isdigit():
            i += 1                          # skip stray nominal-kind tags
            continue
        ident, i = _demangle_one(s, i, words)
        if ident is None:
            break
        out.append(ident)
    return out


def _type_from_bind(name):
    """``_$ss5Int32VMn`` -> 'int32'; ``_$s10Foundation4DataVMn`` -> 'bytes';
    a message/enum descriptor bind -> its (last) type identifier."""
    if not name:
        return None
    s = name
    for p in ("__$s", "_$s", "$s", "__$S", "_$S", "$S"):
        if s.startswith(p):
            s = s[len(p):]
            break
    s = s[:-2] if s.endswith("Mn") else s          # drop nominal-descriptor suffix
    # leading 's' = Swift stdlib module (no length prefix)
    if s.startswith("s") and len(s) > 1 and s[1].isdigit():
        s = s[1:]
    idents = demangle_idents(s.rstrip("V"))
    if not idents:
        return None
    last = idents[-1]
    return _SWIFT_SCALAR.get(last, last)           # scalar -> proto, else the type name


# ── symbolic reference resolution ──────────────────────────────────────────────

def _resolve_symbolic(ctx, va):
    """A mangled type beginning with a symbolic-reference control byte
    (0x01 direct / 0x02 indirect).  Returns a proto type string or None."""
    ctrl = ctx.read_bytes(va, 1)[0]
    if ctrl not in (1, 2):
        return None
    off = struct.unpack("<i", ctx.read_bytes(va + 1, 4))[0]
    ptr_site = va + 1 + off
    if ctrl == 1:
        # Direct: the relptr points straight at the local type context descriptor.
        name = _local_type_ref(ctx, ptr_site)
        return _SWIFT_SCALAR.get(name, name) if name else None
    # Indirect: ptr_site is a GOT slot holding a chained-fixup pointer to the
    # descriptor — a REBASE to a local type, or a BIND to an external one.
    # local rebase: the pointer through the image's fixups.
    name = None
    try:
        name = _local_type_ref(ctx, ctx.read_ptr(ptr_site))
    except READ_ERRORS:
        pass
    if name:
        return _SWIFT_SCALAR.get(name, name)
    # external bind: demangle the import symbol name the slot is bound to.
    return _type_from_bind(ctx.bind_name_for(ptr_site))


def _local_type_ref(ctx, desc):
    """Reference name for a LOCAL type descriptor: its QUALIFIED name
    (``Outer.Inner``) so a nested type resolves to exactly the descriptor the field
    points at -- the short name alone is ambiguous (several messages nest a
    ``Details`` / ``Error``) and cannot be linked to the emitted flattened name.
    Top-level types are unchanged.  None if *desc* is not a plausible descriptor."""
    short = _local_desc_name(ctx, desc)
    if not short:
        return None
    return _qualified_name(ctx, desc) or short


def local_enum_names(ctx):
    """Qualified names of the image's own Swift ``enum`` types (excluding the
    ``OneOf_*`` oneof wrappers, which are not proto enums).  A message field whose
    type is one of these is a proto enum field (varint on the wire)."""
    out = set()
    if not ctx.has_section("__TEXT", "__swift5_types"):
        return out
    sec = ctx.section("__TEXT", "__swift5_types")
    for i in range(sec.vmsize // 4):
        try:
            desc = _type_record(ctx, sec.vmaddr + i * 4)
            if not desc or _desc_kind(ctx, desc) != _ENUM_KIND:
                continue
            name = _desc_name(ctx, desc)
            if name and not name.startswith(_ONEOF_PREFIX):
                q = _qualified_name(ctx, desc)
                if q:
                    out.add(q)
        except READ_ERRORS as exc:
            record_unread(ctx, "Swift type record", f"{sec.vmaddr + i * 4:#x}", exc)
    return out


def _local_desc_name(ctx, desc):
    """Name of a LOCAL nominal type context descriptor (struct/enum/class), or
    None if *desc* is not a plausible descriptor."""
    if not desc or _desc_kind(ctx, desc) not in (16, 17, 18):
        return None
    return _desc_name(ctx, desc)


# ── mangled-type decoder ───────────────────────────────────────────────────────

_NOMINAL = re.compile(rb"(s|10Foundation)(\d+)")


def _type_token(ctx, va):
    """``(proto_type, length)`` of the one type mangled at *va* inside a generic argument list
    (``Say<T>G``, ``SDy<K><V>G``): a symbolic reference (control byte and 4-byte offset), a
    standard substitution (``SS``, ``Sf``, ...), a Swift or Foundation struct by name
    (``s5Int32V``, ``10Foundation4DataV``), each optionally followed by ``Sg`` (Optional).
    None when the token is none of these (it is not guessed past)."""
    try:
        raw = ctx.read_bytes(va, 40)          # the longest token, 10Foundation4DataVSg, is 20
    except READ_ERRORS:                       # a token ending the section: a symbolic ref at most
        try:
            raw = ctx.read_bytes(va, 5)
        except READ_ERRORS:
            return None
    if raw[:1] in (b"\x01", b"\x02"):
        proto, n = _resolve_symbolic(ctx, va), 5
    elif len(raw) > 1 and raw[:1] == b"S" and chr(raw[1]) in _STD_SUB:
        proto, n = _STD_SUB[chr(raw[1])], 2
    else:
        m = _NOMINAL.match(raw)
        if not m:
            return None
        k = m.end()
        size = int(m.group(2))
        name = raw[k:k + size].decode("ascii", "replace")
        if raw[k + size:k + size + 1] != b"V" or name not in _SWIFT_SCALAR:
            return None
        proto, n = _SWIFT_SCALAR[name], k + size + 1
    if not proto:
        return None
    if raw[n:n + 2] == b"Sg":
        n += 2
    return proto, n


def decode_mangled(ctx, va):
    """Decode a FieldRecord mangled type at *va* to a (proto_type, label) pair,
    where label is '', 'repeated', or 'map'.  Returns (None, '') if undecodable."""
    try:
        head = ctx.read_bytes(va, 1)[0]
    except READ_ERRORS:
        return None, ""
    if head in (1, 2):
        return _resolve_symbolic(ctx, va), ""
    txt = _cstr(ctx, va) or ""
    # Detect the Array / Dictionary structural prefixes from RAW bytes, not the
    # printable cstring: a generic element/key/value is a symbolic reference whose
    # control byte (0x01/0x02) is non-printable, so `_cstr` returns None and the
    # prefix would otherwise be missed (e.g. `Say<symref>G` -> repeated <message>).
    try:
        raw = ctx.read_bytes(va, 3)
    except READ_ERRORS:
        raw = b""

    # Array  ->  Say<elem>...G   (element starts right after 'Say').  When the
    # element doesn't decode we still know it's repeated, but the `bytes` filler is
    # a GUESS — flag it with the `repeated?` label so the caller can note it (#67).
    if raw[:3] == b"Say":
        tok = _type_token(ctx, va + 3)
        if tok and ctx.read_bytes(va + 3 + tok[1], 1) == b"G":
            return tok[0], "repeated"
        elem, lbl = decode_mangled(ctx, va + 3)
        # an Array or Dictionary element has no proto form: a flagged guess
        return (elem, "repeated") if elem and not lbl else ("bytes", "repeated?")
    # Dictionary -> SDy<key><val>   => map<key,val>
    if raw[:3] == b"SDy" or raw[:2] == b"SD":
        body = va + (3 if raw[:3] == b"SDy" else 2)
        btxt = _cstr(ctx, body) or ""
        # Both key and value scalar: the standard-substitution run (incl. the
        # run-length S<n><char> collapse, e.g. S2S = String,String) yields them.
        scalars = _runlength_types(btxt)
        if len(scalars) >= 2:
            return f"map<{scalars[0]}, {scalars[1]}>", "map"
        # One key token and one value token, each a symbolic reference, a standard
        # substitution or a Swift / Foundation struct, then the list's end.
        key_tok = _type_token(ctx, body)
        val_tok = _type_token(ctx, body + key_tok[1]) if key_tok else None
        if val_tok and ctx.read_bytes(body + key_tok[1] + val_tok[1], 1) == b"G":
            return f"map<{key_tok[0]}, {val_tok[0]}>", "map"
        # Otherwise the value is structural (symbolic-ref message, Data, ...):
        # decode the key, then the value that follows the common String key.  A
        # `string`/`bytes` filler for an unresolved key/value is a GUESS -> `map?`.
        key, _ = decode_mangled(ctx, body)
        val = None
        if btxt.startswith("SS"):
            val, vlbl = decode_mangled(ctx, body + 2)
            val = None if vlbl else val          # an Array / Dictionary value: no proto form
        lbl = "map" if (key and val) else "map?"
        return f"map<{key or 'string'}, {val or 'bytes'}>", lbl
    # direct scalar codes
    for code, proto in _DIRECT.items():
        if txt == code or txt == code + "Sg":
            return proto, ""
    return None, ""


# ── top level ──────────────────────────────────────────────────────────────────

# swift-protobuf's bookkeeping, never a proto field: the unknown-field store by name (a proto
# field of that name is renamed), the copy-on-write pointer by its type (a ``_storage`` typed
# ``_StorageClass``; inside the storage class, ``_storage`` is a proto field ``storage`` --
# BiomeStreams' PgQuery_ColumnDef)
_SKIP_FIELDS = {"unknownFields"}
_CLASS_KIND = 16
# the copy-on-write backing classes swift-protobuf emits for larger messages —
# the real stored properties live here, not in the message struct's own fieldmd.
_STORAGE_CLASS_NAMES = {"_StorageClass", "AnyMessageStorage"}
# swift-protobuf names each proto oneof's backing enum `OneOf_<oneofName>`.
_ONEOF_PREFIX = "OneOf_"


def _read_field_types(ctx, desc, fieldmd):
    """Decode the ``__swift5_fieldmd`` records hanging off a nominal type
    descriptor's FieldDescriptor (at ``desc + 0x10``).  *fieldmd* is that section's
    ``(start, end)``: a descriptor whose header and ``count`` records do not lie inside it is
    malformed, or not a FieldDescriptor, and none of its records is read (not a truncated
    prefix).

    Returns ``(fields, incomplete, names)`` where ``fields`` is ``{name: proto_type}``,
    ``incomplete`` is the subset of names whose ``proto_type`` contains a GUESS
    filler (an Array element / map key-or-value that didn't decode, shown as
    ``bytes``) — flagged so the emitter can note it (#67) — and ``names`` is every
    stored proto field the records list (an enum's case with no payload too: Apple's generators
    give a oneof such cases).  A field whose mangled type doesn't decode
    (e.g. a reference to a type outside the image that an extracted image no longer
    names) is in ``names`` but not ``fields``; bookkeeping fields are in neither."""
    fd = _relptr(ctx, desc + 0x10)
    if not fd:
        return {}, set(), set()
    try:
        nfields = _u32(ctx, fd + 0x0C)
        recsize = _u16(ctx, fd + 0x0A) or 12
    except READ_ERRORS:
        return {}, set(), set()
    if not (fieldmd[0] <= fd and fd + 0x10 + nfields * recsize <= fieldmd[1]):
        return {}, set(), set()
    fields: Dict[str, str] = {}
    incomplete: set = set()
    names: set = set()
    rec = fd + 0x10
    for _ in range(nfields):
        fname = _cstr(ctx, _relptr(ctx, rec + 0x08))
        mva = _relptr(ctx, rec + 0x04)
        rec += recsize
        if not fname or fname in _SKIP_FIELDS:
            continue
        clean = fname.lstrip("_")
        if mva == 0:                     # an enum's case with no payload: a field, untyped
            names.add(clean)
            continue
        ptype, label = decode_mangled(ctx, mva)
        if ptype and ptype.rsplit(".", 1)[-1] in _STORAGE_CLASS_NAMES:
            continue                     # the copy-on-write pointer
        names.add(clean)
        if not ptype:
            continue
        fields[clean] = f"repeated {ptype}" if label.startswith("repeated") else ptype
        if label.endswith("?"):          # 'repeated?' / 'map?' -> inner is a guess
            incomplete.add(clean)
    return fields, incomplete, names


def _parent_desc(ctx, desc):
    """The parent context descriptor: a relative indirectable pointer at ``desc + 0x04`` -- with
    its low bit set, the address of a pointer to the parent (one in another image, or behind a
    fixup: iOS 27 GeoServices' Polygon2D, whose parent MapGeometry is reached so)."""
    v = _i32(ctx, desc + 0x04)
    if not v:
        return 0
    if v & 1:
        return ctx.read_ptr(desc + 0x04 + (v & ~1))
    return desc + 0x04 + v


def _qualified_name(ctx, desc) -> Optional[str]:
    """Dotted qualified name of a nominal type (``Outer.Inner``), built by walking
    the parent-context chain and joining the names of the enclosing nominal types
    (anonymous / extension contexts — which swift nests private types under — are
    skipped; the module terminates the walk)."""
    names = []
    cur = desc
    for _ in range(_MAX_CONTEXT_DEPTH):
        if not cur:
            break
        try:
            k = _desc_kind(ctx, cur)
            if k == 0:                   # module: top of the chain
                break
            if k in (_STRUCT_KIND, _ENUM_KIND, _CLASS_KIND):
                nm = _desc_name(ctx, cur)
                if nm:
                    names.append(nm)
            cur = _parent_desc(ctx, cur)
        except READ_ERRORS:
            break                        # bad parent pointer: degrade to what we have
    else:
        from proto.models import record_heuristic_hit
        record_heuristic_hit(ctx, "_MAX_CONTEXT_DEPTH",
                             f"the type at {desc:#x}: its qualified name stops at "
                             f"{_MAX_CONTEXT_DEPTH} enclosing contexts")
    return ".".join(reversed(names)) if names else None


def _owner_type_name(ctx, desc) -> Optional[str]:
    """Dotted qualified name of the message that ENCLOSES *desc* — used for a COW
    ``_StorageClass`` / ``OneOf_*`` enum, whose own name is not wanted.  Starts the
    qualified-name walk at *desc*'s parent (swift-protobuf nests these inside the
    message struct via a private anonymous context)."""
    try:
        return _qualified_name(ctx, _parent_desc(ctx, desc))
    except READ_ERRORS:                  # an unreadable indirect parent pointer
        return None


class FieldMetadata(NamedTuple):
    """What ``__swift5_fieldmd`` says about each message (:func:`collect_field_types`)."""
    types: Dict[str, Dict[str, str]]
    incomplete: Dict[str, Set[str]]
    fieldless: Set[str]
    stored: Dict[str, Set[str]]


def collect_field_types(ctx) -> FieldMetadata:
    """Walk ``__swift5_types`` once and return ``(types, incomplete, fieldless, stored)``:
      * ``types``      — ``{qualified_type_name: {field_name: proto_type}}``
      * ``incomplete`` — ``{qualified_type_name: set(field_names)}`` for fields whose
        ``proto_type`` carries a ``bytes`` guess filler (#67).
      * ``fieldless``  — qualified names of struct types whose reflection metadata
        lists NO stored proto field (own struct, COW storage class and oneof members
        all empty): the independent proof that a message with no recovered name-map
        entries is genuinely EMPTY rather than unread.  Counted from the field
        records, not from the types that decoded.
      * ``stored``     — ``{qualified_type_name: set(field_names)}``: every stored proto
        field the records list, typed or not.

    Covers the message struct's directly-stored proto fields, the fields moved into
    a copy-on-write ``_StorageClass`` for larger messages, AND the members of a
    proto ``oneof`` (the nested ``OneOf_<name>`` enum), all linked to the owning
    message via the descriptor parent chain (#60) -- or, a oneof enum of its own, by the
    property of its type (#128)."""
    if not (ctx.has_section("__TEXT", "__swift5_types") and
            ctx.has_section("__TEXT", "__swift5_fieldmd")):
        return FieldMetadata({}, {}, set(), {})
    sec = ctx.section("__TEXT", "__swift5_types")
    fmd = ctx.section("__TEXT", "__swift5_fieldmd")
    fieldmd = (fmd.vmaddr, fmd.vmaddr + fmd.vmsize)
    out: Dict[str, Dict[str, str]] = {}
    stored: Dict[str, Set[str]] = {}
    incomplete: Dict[str, set] = {}
    structs: set = set()
    enums: Dict[str, tuple] = {}
    for i in range(sec.vmsize // 4):
        # one malformed descriptor must never abort whole-image recovery.
        try:
            desc = _type_record(ctx, sec.vmaddr + i * 4)
            if not desc:
                continue
            kind = _desc_kind(ctx, desc)
            name = _desc_name(ctx, desc)
            if not name:
                continue
            if kind == _STRUCT_KIND:
                # qualified (Outer.Inner) so nested types sharing a short name (e.g.
                # several `Details` / `Error`) don't collide in the map — #68.
                key = _qualified_name(ctx, desc)
            elif kind == _CLASS_KIND and name in _STORAGE_CLASS_NAMES:
                key = _owner_type_name(ctx, desc)   # link storage to its message
            elif kind == _ENUM_KIND and name.startswith(_ONEOF_PREFIX):
                key = _owner_type_name(ctx, desc)   # oneof members -> owning message
            elif kind == _ENUM_KIND:
                q = _qualified_name(ctx, desc)      # perhaps a oneof's (below)
                if q:
                    enums[q] = _read_field_types(ctx, desc, fieldmd)
                continue
            else:
                continue
            if not key:
                continue
            if kind == _STRUCT_KIND:
                structs.add(key)
            fields, inc, names = _read_field_types(ctx, desc, fieldmd)
            if fields:
                out.setdefault(key, {}).update(fields)
            if inc:
                incomplete.setdefault(key, set()).update(inc)
            if names:
                stored.setdefault(key, set()).update(names)
        except READ_ERRORS as exc:
            record_unread(ctx, "Swift type record", f"{sec.vmaddr + i * 4:#x}", exc)
    # A oneof whose enum is a type of its own, not a nested OneOf_ (Apple's generators:
    # TokenGenerationCore's ``Tokengenerationcore_Wireformat_ValueEnum``): a message's property of
    # an enum whose cases carry payloads beyond UNRECOGNIZED(Int), a proto enum's only one --
    # its cases are the message's fields (checked against Remote Mirror, TODO #128).
    for key, fields in list(out.items()):
        for ptype in list(fields.values()):
            cases = enums.get(ptype)
            if not cases or not set(cases[0]) - {"UNRECOGNIZED"}:
                continue
            for n, t in cases[0].items():
                fields.setdefault(n, t)
            stored.setdefault(key, set()).update(cases[2])
            if cases[1]:
                incomplete.setdefault(key, set()).update(cases[1])
    return FieldMetadata(out, incomplete, structs - set(stored), stored)

