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

The Swift type maps 1:1 to the proto BASE type.  The varint/zigzag/fixed encoding
nuance (int32 vs sint32 vs sfixed32, all ``Int32`` in Swift) is NOT distinguished
here — that needs the decodeMessage/traverse witness slot and is a follow-up; the
base type (and therefore the wire-type category) is correct.  (Swift's residual
type/number estimates are catalogued in LIMITATIONS.md (10); the integer-subtype
collapse specifically is 10b / to-do #63b — DEFERRED, unexercised by the data.)

Returns ``{type_name: {field_name: proto_type}}`` so a caller can join by field
NAME against the nameMap (number↔name).  Binary mode only.
"""
from __future__ import annotations

import struct
from typing import Dict, Optional

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


def _i32(ctx, va):
    return struct.unpack("<i", ctx.read_bytes(va, 4))[0]


def _u32(ctx, va):
    return struct.unpack("<I", ctx.read_bytes(va, 4))[0]


def _u16(ctx, va):
    return struct.unpack("<H", ctx.read_bytes(va, 2))[0]


def _relptr(ctx, va):
    """Swift RelativeDirectPointer: target = address + signed int32.

    The FieldDescriptor / FieldRecord pointers (type name, field name, field
    descriptor) and the __swift5_types entries are all *direct* — the low bit is
    a real address bit (names are byte-aligned, often odd), NOT an indirect flag.
    Symbolic references inside a mangled name carry their own control byte and are
    handled separately in :func:`_resolve_symbolic`."""
    v = _i32(ctx, va)
    return 0 if v == 0 else va + v


def _cstr(ctx, va):
    try:
        return ctx.read_cstring(va, 256)
    except Exception:
        return None


def _desc_name(ctx, desc):
    try:
        return _cstr(ctx, _relptr(ctx, desc + 0x08))
    except Exception:
        return None


def _desc_kind(ctx, desc):
    try:
        return _u32(ctx, desc) & 0x1F
    except Exception:
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
    previously seen word (uppercase = last substitution in the run)."""
    n = len(s)
    has_subst = False
    if s[i] == "0":
        if i + 1 < n and s[i + 1] == "0":
            return None, i                 # '00' = punycode — unsupported, bail
        has_subst = True
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


# Back-compat shim: the old name, now word-substitution aware.
_idents = demangle_idents


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
    idents = _idents(s.rstrip("V"))
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
        name = _local_desc_name(ctx, ptr_site)
        return _SWIFT_SCALAR.get(name, name) if name else None
    # Indirect: ptr_site is a GOT slot holding a chained-fixup pointer to the
    # descriptor — a REBASE to a local type, or a BIND to an external one.
    try:
        raw = struct.unpack("<Q", ctx.read_bytes(ptr_site, 8))[0]
    except Exception:
        return None
    # local rebase: try the decoded pointer, then a manual low-32 + image_base.
    name = None
    try:
        name = _local_desc_name(ctx, ctx.read_ptr(ptr_site))
    except Exception:
        pass
    if not name:
        name = _local_desc_name(ctx, ctx.image_base + (raw & 0xFFFFFFFF))
    if name:
        return _SWIFT_SCALAR.get(name, name)
    # external bind: demangle the import symbol name.
    try:
        return _type_from_bind(ctx.import_name_for_bind(raw))
    except Exception:
        return None


def _local_desc_name(ctx, desc):
    """Name of a LOCAL nominal type context descriptor (struct/enum/class), or
    None if *desc* is not a plausible descriptor."""
    if not desc or _desc_kind(ctx, desc) not in (16, 17, 18):
        return None
    return _desc_name(ctx, desc)


# ── mangled-type decoder ───────────────────────────────────────────────────────

def decode_mangled(ctx, va):
    """Decode a FieldRecord mangled type at *va* to a (proto_type, label) pair,
    where label is '', 'repeated', or 'map'.  Returns (None, '') if undecodable."""
    try:
        head = ctx.read_bytes(va, 1)[0]
    except Exception:
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
    except Exception:
        raw = b""

    # Array  ->  Say<elem>...G   (element starts right after 'Say').  When the
    # element doesn't decode we still know it's repeated, but the `bytes` filler is
    # a GUESS — flag it with the `repeated?` label so the caller can note it (#67).
    if raw[:3] == b"Say":
        elem, _ = decode_mangled(ctx, va + 3)
        return (elem, "repeated") if elem else ("bytes", "repeated?")
    # Dictionary -> SDy<key><val>   => map<key,val>
    if raw[:3] == b"SDy" or raw[:2] == b"SD":
        body = va + (3 if raw[:3] == b"SDy" else 2)
        btxt = _cstr(ctx, body) or ""
        # Both key and value scalar: the standard-substitution run (incl. the
        # run-length S<n><char> collapse, e.g. S2S = String,String) yields them.
        scalars = _runlength_types(btxt)
        if len(scalars) >= 2:
            return f"map<{scalars[0]}, {scalars[1]}>", "map"
        # Otherwise the value is structural (symbolic-ref message, Data, ...):
        # decode the key, then the value that follows the common String key.  A
        # `string`/`bytes` filler for an unresolved key/value is a GUESS -> `map?`.
        key, _ = decode_mangled(ctx, body)
        val = None
        if btxt.startswith("SS"):
            val, _ = decode_mangled(ctx, body + 2)
        lbl = "map" if (key and val) else "map?"
        return f"map<{key or 'string'}, {val or 'bytes'}>", lbl
    # Optional -> <inner>Sg
    if txt.endswith("Sg") and len(txt) > 2:
        inner, lbl = decode_mangled(ctx, va)  # inner handled below via _DIRECT/prefix
        # fall through to direct handling on the stripped form
    # direct scalar codes
    for code, proto in _DIRECT.items():
        if txt == code or txt == code + "Sg":
            return proto, ""
    # bare String optional etc.
    if txt in ("SSSg",):
        return "string", ""
    return None, ""


# ── top level ──────────────────────────────────────────────────────────────────

# field names that are swift-protobuf bookkeeping, never proto fields
_SKIP_FIELDS = {"unknownFields", "_storage"}
_CLASS_KIND = 16
# the copy-on-write backing classes swift-protobuf emits for larger messages —
# the real stored properties live here, not in the message struct's own fieldmd.
_STORAGE_CLASS_NAMES = {"_StorageClass", "AnyMessageStorage"}
# swift-protobuf names each proto oneof's backing enum `OneOf_<oneofName>`.
_ONEOF_PREFIX = "OneOf_"


def _read_field_types(ctx, desc):
    """Decode the ``__swift5_fieldmd`` records hanging off a nominal type
    descriptor's FieldDescriptor (at ``desc + 0x10``).

    Returns ``(fields, incomplete)`` where ``fields`` is ``{name: proto_type}`` and
    ``incomplete`` is the subset of names whose ``proto_type`` contains a GUESS
    filler (an Array element / map key-or-value that didn't decode, shown as
    ``bytes``) — flagged so the emitter can note it (#67).  Bookkeeping fields and
    any whose mangled type doesn't decode at all are skipped."""
    fd = _relptr(ctx, desc + 0x10)
    if not fd:
        return {}, set()
    try:
        nfields = _u32(ctx, fd + 0x0C)
        recsize = _u16(ctx, fd + 0x0A) or 12
    except Exception:
        return {}, set()
    fields: Dict[str, str] = {}
    incomplete: set = set()
    rec = fd + 0x10
    for _ in range(min(nfields, 512)):
        fname = _cstr(ctx, _relptr(ctx, rec + 0x08))
        mva = _relptr(ctx, rec + 0x04)
        rec += recsize
        if not fname or fname in _SKIP_FIELDS or mva == 0:
            continue
        ptype, label = decode_mangled(ctx, mva)
        if not ptype:
            continue
        clean = fname.lstrip("_")
        fields[clean] = f"repeated {ptype}" if label.startswith("repeated") else ptype
        if label.endswith("?"):          # 'repeated?' / 'map?' -> inner is a guess
            incomplete.add(clean)
    return fields, incomplete


def _parent_desc(ctx, desc):
    """The parent context descriptor (relative pointer at ``desc + 0x04``)."""
    v = _i32(ctx, desc + 0x04)
    return desc + 0x04 + v if v else 0


def _qualified_name(ctx, desc) -> Optional[str]:
    """Dotted qualified name of a nominal type (``Outer.Inner``), built by walking
    the parent-context chain and joining the names of the enclosing nominal types
    (anonymous / extension contexts — which swift nests private types under — are
    skipped; the module terminates the walk)."""
    names = []
    cur = desc
    for _ in range(12):
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
        except Exception:
            break                        # bad parent pointer: degrade to what we have
    return ".".join(reversed(names)) if names else None


def _owner_type_name(ctx, desc) -> Optional[str]:
    """Dotted qualified name of the message that ENCLOSES *desc* — used for a COW
    ``_StorageClass`` / ``OneOf_*`` enum, whose own name is not wanted.  Starts the
    qualified-name walk at *desc*'s parent (swift-protobuf nests these inside the
    message struct via a private anonymous context)."""
    return _qualified_name(ctx, _parent_desc(ctx, desc))


def _collect_field_types(ctx):
    """Walk ``__swift5_types`` once and return ``(types, incomplete)``:
      * ``types``      — ``{qualified_type_name: {field_name: proto_type}}``
      * ``incomplete`` — ``{qualified_type_name: set(field_names)}`` for fields whose
        ``proto_type`` carries a ``bytes`` guess filler (#67).

    Covers the message struct's directly-stored proto fields, the fields moved into
    a copy-on-write ``_StorageClass`` for larger messages, AND the members of a
    proto ``oneof`` (the nested ``OneOf_<name>`` enum), all linked to the owning
    message via the descriptor parent chain (#60)."""
    try:
        sec = ctx.section("__TEXT", "__swift5_types")
    except Exception:
        return {}, {}
    out: Dict[str, Dict[str, str]] = {}
    incomplete: Dict[str, set] = {}
    for i in range(sec.vmsize // 4):
        # one malformed descriptor must never abort whole-image recovery.
        try:
            desc = _relptr(ctx, sec.vmaddr + i * 4)
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
            else:
                continue
            if not key:
                continue
            fields, inc = _read_field_types(ctx, desc)
            if fields:
                out.setdefault(key, {}).update(fields)
            if inc:
                incomplete.setdefault(key, set()).update(inc)
        except Exception:
            continue
    return out, incomplete


def recover_field_types(ctx) -> Dict[str, Dict[str, str]]:
    """``{type_name: {field_name: proto_type}}`` from ``__swift5_fieldmd`` — the
    public type map (see :func:`_collect_field_types` for the full walk + the
    companion incomplete-field set used to flag ``bytes`` guess fillers)."""
    return _collect_field_types(ctx)[0]
