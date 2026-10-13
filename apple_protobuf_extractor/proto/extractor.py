"""
proto/extractor.py — Extract protobuf schemas from Apple's custom ObjC proto runtime.

Apple ships its own ObjC protobuf library (not GPB) in binaries such as GeoServices,
CoreLocationProtobuf, and many others.  Classes using this runtime share a distinctive
set of methods:

    Instance methods (required):
        readFrom:          writeTo:           mergeFrom:
        copyTo:            copyWithZone:      isEqual:
        hash               description        dictionaryRepresentation

    Class methods (optional, on metaclass):
        xyzType            (for repeated message-typed fields)
        pressureType, etc.

Field names come straight from ObjC ivars; types are recovered from ObjC type
encodings enriched by method-name patterns; field numbers are assigned in two ways:

    Confirmed — when the ReadFrom function uses a pointer-table dispatch (entries in
    __DATA_CONST/__objc_const that are ivar-offset pointers).  Table index i → field i+1.

    Estimated — for byte-jump-table dispatch (entries in __TEXT/__const), where the
    table maps to code handlers that are harder to trace statically.  In this case
    we fall back to the declaration order of ivars in the classlist, which matches
    proto field-number order for the vast majority of real proto definitions.

Porting notes (files.zip compatibility)
-----------------------------------------
* ObjcIvar in this codebase does NOT have an offset_va field.  Pointer-table
  matching is done by reading the ivar-offset variable's value (a 32-bit byte
  offset) and comparing it to ivar.offset, which holds the same value.
* Pointer tables live in __DATA_CONST/__objc_const (not __DATA_CONST/__const).
* GeoServices has ivar-offset variables in both __DATA/__objc_ivar and
  __DATA_DIRTY/__objc_ivar; both are checked.

Usage
-----
    from macho.memory    import BinaryContext
    from macho.strings   import build_string_table
    from macho.classlist import build_class_list
    from proto.extractor import extract_all
    from proto.emitter   import build_proto_files

    ctx = BinaryContext(binary_bytes)
    st  = build_string_table(ctx)
    cl  = build_class_list(ctx, st)
    msgs = extract_all(ctx, st, cl)
    for pf in build_proto_files(msgs):
        print(pf.emit())
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, FrozenSet, List, Optional, Set, Tuple

# Direct internal dependencies.  proto.extractor is no longer a re-export facade:
# each consumer imports the symbol it needs from the module that defines it
# (proto.protocore / dispatch / repeated / enums / writeto / config, macho.*).
from macho.memory    import BinaryContext, _ctx_cache
from macho.strings   import StringTable
from macho.classlist import ClassList, ObjcClass, ObjcIvar

from proto.models    import FieldLabel, ProtoField, ProtoMessage
from proto.writeto   import _extract_writeto_field_numbers, build_writeto_indegree
from proto.write_helpers import (
    _identify_string_write_helpers, _find_string_write_helper,
    _classify_write_helper, _refine_scalar_by_family, _ensure_writeto_indegree,
    _ensure_string_write_helpers, _ensure_message_write_helper, _same_write_helper,
)
from proto.protocore import (
    _is_proto_flags_ivar, _is_real_field_ivar, _type_from_enc,
    _is_packed_list_enc, _field_label, _proto_name,
    _REQUIRED_INSTANCE_METHODS, _INTERNAL_PB_IVARS, _SCALAR_ENC,
)
# Retired non-structural detectors — kept for investigation, fail the run if they
# ever claim a class.  See proto/protoclass_heuristic.py.
from proto.protoclass_heuristic import (
    _is_proto_class, va_cluster_closure, check_no_heuristic_detection,
    ProtoClassDetectionError, _SYSTEM_ROOT_NAMES,
)
from proto.dispatch  import _build_readfrom_core_index
from proto.repeated  import (
    _resolve_repeated_via_dispatch, _resolve_repeated_via_dispatch_ivars,
    _resolve_repeated_field_type, _resolve_repeated_via_classrefs,
)
from proto.structfields import finalize_struct_fields, record_struct_site
from proto.mapfields import (
    MAP_OBJC_CLASSES, MAP_IVAR_ENCS, MapEntryWriter, MapTypes, find_map_writers,
    record_helper_votes, resolve_map_types,
)
from proto.enums     import _qualify_enum_name, _collect_enum_definitions
from proto.enums_debug import _emit_mode_a_debug
from proto.config    import _class_to_proto_name
from proto.defaults  import DEFAULT_PREFIXES
from serializers.protobufc_detect import ProtobufCDescriptors, find_protobufc_descriptors

log = logging.getLogger(__name__)


class SelectorsUnresolvedError(Exception):
    """Raised by :func:`extract_all` when a binary's ObjC **selector names are
    unresolved** in a mode where that is a hard error (cache-native, or a
    standalone executable).

    A correct run always has resolved selectors: a standalone Mach-O carries its
    own ``__objc_methname`` strings, and a cache-native run resolves them from the
    ``.symbols`` sub-cache.  Zero resolved selectors therefore means the input is
    broken (missing ``.symbols``, stripped/corrupt ObjC metadata), not merely
    hard to analyse — so we fail loudly instead of silently degrading.  (A
    standalone *shared library* is the one tolerated case: it gets a warning and
    best-effort output — see :func:`_check_selectors_resolved`.)
    """


# Enum-fallback debug instrumentation (Modes A/B/C, threaded from extract_all's
# ``enum_debug_writer=`` kwarg) now lives in proto.enums_debug — see that
# module's docstring for the full mode breakdown.


# ── _dictionaryRepresentation: switch-table enum recovery ──────────────────────
#
# Some Apple proto enums have no ``xAsString:``/``StringAsX:`` companion selector
# (e.g. ``GEOComponentType``, ``ComponentStatus``, ``CacheControlType`` on
# ``GEOPDComponent``).  Their int→name map is instead embedded in the class's
# ``-[Class _dictionaryRepresentation:]`` method, as one LLVM switch per enum
# field::
#
#       ldrsw x8, [x.., #ivar_off_slot]   ; load this field's ivar byte offset
#       ldr   w8, [xSELF, x8]             ; w8 = self->_<field>
#       cmp   w8, #N                      ; bounds check (N = max value)
#       b.hi  default
#       adrp  x22, cfstring_<DEFAULT>     ; pre-load the default/UNKNOWN string
#       add   x22, x22, #off
#       adrp  x9,  switch_table           ; the jump table (16- or 8-bit entries)
#       add   x9,  x9, #off
#       adr   x10, case_base
#       ldrh  w11, [x9, x8, lsl #1]       ; entry = table[value]   (ldrb for byte tables)
#       add   x10, x10, x11, lsl #2       ; target = case_base + entry*4
#       br    x10
#     case_base+...:                       ; per-value block
#       adrp  x22, cfstring_<NAME>         ; the value's name string
#       add   x22, x22, #off
#       b     merge
#
# The switch table is indexed directly by the enum value; gap values and value 0
# route to the merge point and inherit the pre-loaded default string.  The table
# base is the adrp+add target whose register also serves as the base of the
# register-offset table load, and that load (decoded by :func:`_decode_ldr_reg_off`
# on raw words) gives the entry width (ldrh→2, ldrb→1) and the value/index
# register directly — no width guessing.  Strings are read via
# :func:`_read_enum_string` (CFStringRef-aware).


# Sentinel returned by _enum_name_from_pairs when no useful multi-word prefix
# can be derived.  Using a NUL-prefixed string guarantees it can never collide
# with a real CamelCase enum name.
_ENUM_NAME_NO_PREFIX: str = "\x00"


# ── readFrom: jump-table element-type dispatch ────────────────────────────────
#
# The element type of a ``repeated <message>`` field is the proto class whose
# ReadAllFrom C-core the field's readFrom: dispatch arm ``bl``-calls.  We recover
# it by decoding the field-dispatch jump table in the ReadSpecified core, walking
# each tag's arm, and matching the arm's ``bl`` target against a per-binary index
# of ``{ReadAllFrom vmaddr -> class name}``.  Identification is purely by
# ADDRESS, so it works in cache-native mode where symbols are stripped.
#
# Dispatch shape (verified on _GEOPDComponentReadSpecified):
#     lsr  Xt, Xtag, #3               ; field number = tag >> 3
#     sub  Wi, Wt, #1                 ; idx = field# - 1
#     cmp  Wi, #<count-1> ; b.hi …    ; field-count gate
#     adr  Rbase, #ARM_BASE           ; arm region base
#     ldrh Roff, [Rtab, Xi, lsl #1]   ; 16-bit offset table (Rtab = adrp+add base)
#     add  Rbase, Rbase, Roff, lsl #2 ; arm = ARM_BASE + table16[idx]*4
#     br   Rbase
#
# The arm64 mini-decoder used when capstone is absent does NOT decode ``adr``,
# register-offset ``ldrh``, or shifted-register ``add``, so the cluster is read
# from RAW WORDS (_decode_adr / _is_br_insn) and the table base is selected by
# validation rather than by decoding the load — only the natively-decodable
# ``adrp+add`` (table base) and ``bl`` scan rely on the Insn stream.


# ── Metaclass lookup ───────────────────────────────────────────────────────────

def _find_metaclass(
    ctx: BinaryContext, cls: ObjcClass, cl: ClassList
) -> Optional[ObjcClass]:
    """Return the metaclass for cls by reading the isa field of class_t."""
    try:
        raw_isa = ctx.read_ptr(cls.vmaddr)
    except ValueError:
        return None
    return cl.by_vmaddr(raw_isa)


# ── writeTo: field-number extraction ─────────────────────────────────────────
# Carved out into proto/writeto.py (output-identical move).  Imported at the top
# of this module as `_extract_writeto_field_numbers`; the budget constants and
# `_writeto_field_number_before` live there too.


# ── String write-helper identification + wire-type-family classification ──
# Moved to proto/write_helpers.py (output-identical carve); imported above as
# `_identify_string_write_helpers`, `_find_string_write_helper`,
# `_classify_write_helper`.


# Inline-comment text attached to a repeated field whose element type could not
# be determined, so it falls back to ``repeated bytes``.  Unlike a genuine
# ``repeated bytes`` (an ``NSData`` element array), this is a degraded result: the
# element is probably a message the tool couldn't resolve, and a reader who treats
# it as opaque bytes would miss that each element may be a parseable sub-message.
# Surfacing it keeps the "tell the user when the tool degraded" contract (the
# singular message case is already flagged via ``unresolved_type_class``).
_ELEMENT_UNRESOLVED_NOTE = (
    "element type could not be determined; emitted as bytes — each element may be "
    "an unparsed message; see LIMITATIONS.md (2)"
)

# protobuf ``map<K, V>`` fields (to-do #41): an ObjC NSMutableDictionary ivar carries no
# key/value type in its @encode, and writeTo: serialises it inside an
# ``enumerateKeysAndObjectsUsingBlock:`` block (or an inline enumeration loop).
# proto.mapfields recovers the number + key/value types from that entry writer and the
# readFrom: arm; :func:`_finalize_map_fields` applies the result after the whole image
# has been extracted (it needs the binary-wide write-helper table).  What cannot be
# recovered stays flagged: a map field whose entry writer was found but whose types
# were not emits as ``repeated bytes`` (each element an entry message); one with no
# entry writer at all keeps the legacy ``bytes`` + note.  See LIMITATIONS.md (1).
_MAP_OBJC_CLASSES = MAP_OBJC_CLASSES
_MAP_FIELD_NOTE = (
    "map<> field (ObjC NSMutableDictionary) emitted as bytes; no map-entry writer "
    "found in writeTo: so key/value types not recovered — see LIMITATIONS.md (1)"
)
_MAP_UNRESOLVED_NOTE = (
    "map<> field: each element is a map-entry message {{key = 1, value = 2}}; "
    "key/value types not recovered ({reason}) — see LIMITATIONS.md (1)"
)
_MAP_VALUE_CLASS_NOTE = (
    "map value is a message whose class could not be determined ({reason}); value "
    "emitted as bytes — see LIMITATIONS.md (1)"
)

# ACCEPTED LIMITATION (field# 0): Apple emits deliberate 0-based proto fields
# (writeTo: `mov w2,#0`, readFrom: `case 0`).  Field 0 is illegal in proto2/proto3
# and cannot be emitted, so the tool estimates the lowest legal number — but that
# number is NOT what's on the wire.  When the writeTo: walk saw a literal-0 write
# for an ESTIMATED field, say so explicitly.  See LIMITATIONS.md (4), to-do #52.
_FIELD_ZERO_NOTE = (
    "wire field number is 0 (Apple 0-based; illegal in .proto) — this estimated "
    "number will NOT match live traffic; see LIMITATIONS.md (4)"
)

# ACCEPTED LIMITATION (singular embedded fixed-struct): a PBCodable field whose
# ivar is a by-VALUE C struct (@encode `{Name=...}`, e.g. {GEOSessionID="_high"Q
# "_low"Q}) is a length-delimited submessage on the wire, but the tool does not
# model the struct's element type/layout, so it emits `bytes`.  This is the
# SINGULAR analogue of the repeated `^{Struct}` case in LIMITATIONS.md (2); it
# reaches the same `("bytes", None)` catch-all in `_type_from_enc`.  A genuine
# NSData field (@encode `@"NSData"`) is a real `bytes` and is NOT flagged.


def _embedded_struct_note(ivar: ObjcIvar, type_name: str,
                          type_class: Optional[str]) -> Optional[str]:
    """Flag a singular by-value embedded C-struct field that resolved to `bytes`.

    @encode `{Name=...}` (a NAMED struct, not the anonymous `{?=...}` has-bits /
    packed-list shapes) stored by value is a submessage on the wire whose element
    type isn't modelled.  Returns the note, or None when this isn't that case.
    See LIMITATIONS.md (2)."""
    enc = ivar.type_enc or ""
    if (type_class is None and type_name == "bytes"
            and enc.startswith("{") and not enc.startswith("{?")):
        m = re.match(r"^\{([^=]+)=", enc)
        sname = m.group(1) if m else "?"
        return (f"embedded fixed-struct '{sname}' emitted as bytes; element "
                f"type/layout not modelled — see LIMITATIONS.md (2)")
    return None


# ── Forward-scan proto-class detection (TODO #46) ─────────────────────────────
# Apple's generated proto message classes all descend from PBCodable (RPC
# request/response messages via PBRequest/PBResponse).  That superclass link is
# GROUND TRUTH — stronger than the per-class metadata heuristic (_is_proto_class),
# which keys on a class's OWN has-bits ivar / _reader+_readerLock / readFrom:+
# writeTo: method score and so MISSES metadata-sparse subclasses.  Recover the full
# set with two complementary, value-independent anchors, SEEDED + sanity-checked by
# the heuristic (so a heuristic hit is never dropped):
#   (1) NAME-anchor (cache frameworks): walk each class's superclass chain via
#       read_ptr (which decodes the chained-fixup pointer and reads cross-image into
#       ProtocolBuffer.framework) until a class named PBCodable/PBRequest/… — the
#       name IS the runtime base contract.  Catches cross-image-parented subclasses.
#   (2) VA-cluster (all modes incl. standalone binaries, where cross-image names do
#       NOT resolve): the non-local superclass VAs shared by heuristic-confirmed
#       proto classes ARE the PB-root VAs (raw bind ordinals in binary mode); every
#       class transitively subclassing one is proto.  The heuristic seeds the roots.
# Verified: GeoServices 1637→1642 (+5 metadata-sparse subclasses), CLP 84=84,
# locationd 65=65 (binary mode → VA-cluster only).  See TODO #46.
_PB_ROOT_NAMES: FrozenSet[str] = frozenset(
    {"PBCodable", "PBRequest", "PBResponse", "PBMessage"})

# _SYSTEM_ROOT_NAMES (the NSObject/NSProxy cluster-root guard) moved to
# proto.protoclass_heuristic alongside the closure it guards; re-exported above for
# existing call sites.

_OBJC_CLASS_SYM_PREFIX = "_OBJC_CLASS_$_"


def _resolve_class_name_at(ctx: BinaryContext, va: int) -> Optional[str]:
    """``class_ro_t.name`` for the ObjC class at *va*, decoding the chained-fixup
    pointer (reads cross-image in cache mode).

    In standalone-binary mode the superclass is a *bind* to another dylib not
    present in the file, so following the pointer fails; instead *va* is the raw
    chained-fixup bind value and its ordinal resolves through the binary's own
    imports table (``import_name_for_bind``) to the import symbol name, e.g.
    ``_OBJC_CLASS_$_PBCodable`` → ``PBCodable``.  This is the principled binary-mode
    NAME anchor (parity with the cache-mode cross-image read).  Returns None if
    neither path resolves."""
    try:
        data = ctx.read_ptr(va + 32) & ~0x7              # class_t.data → class_ro_t
        name = ctx.read_cstring(ctx.read_ptr(data + 24))  # class_ro_t.name
        if name:
            return name
    except Exception:
        pass
    sym = ctx.import_name_for_bind(va)
    if sym and sym.startswith(_OBJC_CLASS_SYM_PREFIX):
        return sym[len(_OBJC_CLASS_SYM_PREFIX):]
    return None


def _proto_class_set(ctx: BinaryContext, cl: ClassList) -> FrozenSet[str]:
    """Full set of proto message class NAMES (TODO #46): the ``_is_proto_class``
    heuristic seed unioned with the PBCodable superclass-chain closure (two anchors,
    above).  Side effect: stamps ``ctx._proto_inherits`` = {child: parent_objc_name}
    for proto-to-proto subclasses (immediate superclass is itself a proto MESSAGE,
    not a PB root) so the emitter can flag inherited fields.  ALSO stamps
    ``ctx._proto_class_heuristic_only`` = frozenset of class names whose proto-ness
    rests SOLELY on the heuristic seed (anchor 1's pure name/bind walk, re-run over
    every class regardless of prior seed membership, did NOT independently confirm
    them) — measured empirically to be empty in every corpus tested so far (0/1642
    GeoServices, 0/391 across a 258-binary corpus), but computed for real on every
    run rather than assumed, so the emitter can flag it the day it isn't.  Memoised
    on ctx."""
    def _build() -> FrozenSet[str]:
        non_meta = [c for c in cl if not c.is_meta]
        by_va: Dict[int, ObjcClass] = {c.vmaddr: c for c in non_meta}
        seed = {c.name for c in non_meta if _is_proto_class(c)}
        proto: Set[str] = set(seed)
        proto_va: Set[int] = {c.vmaddr for c in non_meta if c.name in seed}

        # Anchor 1 — NAME: superclass chain reaches a PB root (cache mode).
        name_memo: Dict[int, Optional[str]] = {}

        def _name(va: int) -> Optional[str]:
            if va not in name_memo:
                name_memo[va] = _resolve_class_name_at(ctx, va)
            return name_memo[va]

        def _reaches_pb_root(va: int, depth: int = 8) -> bool:
            cur, seen = va, set()
            for _ in range(depth):
                if not cur or cur in seen:
                    return False
                seen.add(cur)
                nm = _name(cur)
                if nm is None:
                    return False
                if nm in _PB_ROOT_NAMES:
                    return True
                try:
                    cur = ctx.read_ptr(cur + 8)            # next superclass
                except Exception:
                    return False
            return False

        # Track anchor 1's reach FULLY independently of the heuristic seed (run for
        # every class, not just ones the seed hasn't already claimed) so we can
        # later tell whether a given proto class's membership rests on the
        # heuristic at all, or is independently confirmed by pure superclass-chain
        # structure. Same detection, just not short-circuited by prior membership.
        anchor1_names: Set[str] = set()
        for c in non_meta:
            if c.superclass_vmaddr and _reaches_pb_root(c.superclass_vmaddr):
                anchor1_names.add(c.name)
                if c.name not in proto:
                    proto.add(c.name)
                    proto_va.add(c.vmaddr)

        # Anchor 2 — RETIRED heuristic-seeded VA-cluster closure, now living in
        # proto.protoclass_heuristic.  Mutates proto/proto_va in place and returns
        # the names it alone added, so a class resting on it can be failed below.
        anchor2_names: Set[str] = va_cluster_closure(
            non_meta, by_va, seed, proto, proto_va, _name)

        # Proto-to-proto subclass map (immediate super is a proto MESSAGE, i.e. a
        # local proto class or a cross-image non-PB-root class) → inheritance note.
        inherits: Dict[str, str] = {}
        for c in non_meta:
            if c.name not in proto or not c.superclass_vmaddr:
                continue
            sv = c.superclass_vmaddr
            parent = by_va[sv].name if sv in by_va else _name(sv)
            if parent and parent not in _PB_ROOT_NAMES:
                inherits[c.name] = parent
        try:
            ctx._proto_inherits = inherits
        except Exception:
            pass
        # Classes the pure name/bind walk (anchor 1) did NOT independently reach,
        # split by WHICH non-structural path claimed them.  Both are ERRORS, not
        # footnotes: anchor 1 alone reproduces the full set on every corpus ever
        # measured (391 classes/258 binaries in binary mode, 1642/1 framework in
        # cache mode), so either set being
        # non-empty means the structural detector failed and the class's presence in
        # the output rests on a guess.  Computed for real every run rather than
        # assumed empty, so the day it fires the output says so.
        #   * cluster-only — the heuristic-seeded VA-cluster closure (anchor 2)
        #     claimed it and the superclass chain never confirmed it.
        #   * heuristic-only — neither structural anchor claimed it; it is in the
        #     set solely because the per-class _is_proto_class score seeded it.
        _cluster_only = frozenset(anchor2_names - anchor1_names)
        _heuristic_only = frozenset(proto - anchor1_names - anchor2_names)
        try:
            ctx._proto_class_cluster_only = _cluster_only
            ctx._proto_class_heuristic_only = _heuristic_only
        except Exception:
            pass
        return frozenset(proto)

    return _ctx_cache(ctx, "_proto_class_names_cache", _build)


# The Google Objective-C protobuf runtime base class.  Apple statically links the
# vendored runtime per-binary and prefixes the class to avoid ObjC duplicate-class
# collisions, so the base appears as ``GPBMessage`` OR ``<Prefix>GPBMessage`` (e.g.
# ``TransparencyGPBMessage`` in transparencyd) — hence a SUFFIX match.
_GPB_RUNTIME_SUFFIX = "GPBMessage"


def google_protobuf_classes(
    ctx: BinaryContext, cl: ClassList
) -> "Tuple[List[str], FrozenSet[str]]":
    """Names of ObjC classes that subclass Google's protobuf-objc runtime, paired
    with the runtime base class name(s) found.

    These use Google's Objective-C protobuf library (``GPBMessage``), NOT Apple's
    ``PBCodable``: their wire (de)serialization is driven by a shared ``GPBDescriptor``
    runtime, with no per-class ``writeTo:``/``readFrom:`` to disassemble — so this tool
    does not extract them.  Detection is purely by NAME (the runtime base always ends
    in ``GPBMessage``), mirroring the PBCodable name anchor; ``_resolve_class_name_at``
    supplies cross-image / bind names so it works in cache and binary mode alike."""
    non_meta = [c for c in cl if not c.is_meta]
    by_va: Dict[int, ObjcClass] = {c.vmaddr: c for c in non_meta}
    name_memo: Dict[int, Optional[str]] = {}

    def _name(va: int) -> Optional[str]:
        if va not in name_memo:
            c = by_va.get(va)
            name_memo[va] = c.name if c is not None else _resolve_class_name_at(ctx, va)
        return name_memo[va]

    subs: List[str] = []
    bases: Set[str] = set()
    for c in non_meta:
        cur, seen, depth = c.superclass_vmaddr, set(), 0
        while cur and cur not in seen and depth < 16:
            seen.add(cur); depth += 1
            nm = _name(cur)
            if nm is None:
                break
            if nm.endswith(_GPB_RUNTIME_SUFFIX):
                subs.append(c.name); bases.add(nm); break
            nxt = by_va.get(cur)
            cur = nxt.superclass_vmaddr if nxt is not None else None
    return subs, frozenset(bases)


# ── Swift-protobuf (apple/swift-protobuf, vendored as InternalSwiftProtobuf) ──
# A Swift type generated by swift-protobuf is a *struct*/*enum* conforming to the
# library's ``Message`` / ``Enum`` protocol — there is no ObjC class and no
# per-class writeTo:/readFrom:, so the tool cannot extract it.  The compiler emits
# a protocol-conformance descriptor whose mangled symbol names both the conforming
# type and the protocol, e.g.
#   _$s14bookdatastored15PBPropertyValueV21InternalSwiftProtobuf7MessageAAMc
#    └prefix┘└14:module──────┘└15:type──────┘V└21:proto-module───────┘└7:proto┘
# Keying on the ``…SwiftProtobuf7Message…Mc`` (and ``…4Enum…Mc``) descriptor gives
# exactly one hit per type and recovers its name from the mangled prefix.
_SWIFTPB_CONFORMANCE = re.compile(
    r'(?:Internal)?SwiftProtobuf(?P<proto>7Message|4Enum)(?:[A-Z]*)Mc$'
)


def _parse_swift_pb_symbol(sym: str) -> "Optional[Tuple[str, str, str]]":
    """Parse a Swift-protobuf conformance-descriptor symbol.

    Returns ``(kind, module, type_name)`` where kind is ``"message"``/``"enum"``,
    or None if *sym* is not such a descriptor.  The mangled prefix is a run of
    length-prefixed identifiers (module, then nesting type names) interleaved with
    single-letter nominal-kind tags (``V`` struct / ``O`` enum / ``C`` class)."""
    m = _SWIFTPB_CONFORMANCE.search(sym)
    if not m:
        return None
    kind = "enum" if m.group("proto") == "4Enum" else "message"
    head = sym[:m.start()]
    for pre in ("__$s", "_$s", "$s", "__$S", "_$S", "$S"):
        if head.startswith(pre):
            head = head[len(pre):]
            break
    idents: List[str] = []
    i, n = 0, len(head)
    while i < n:
        j = i
        while j < n and head[j].isdigit():
            j += 1
        if j == i:                 # a nominal-kind tag (V/O/C/…) between idents
            i += 1
            continue
        ln = int(head[i:j])
        ident = head[j:j + ln]
        if not ident:
            break
        idents.append(ident)
        i = j + ln
    if len(idents) < 2:            # need at least module + type
        return None
    return kind, idents[0], ".".join(idents[1:])


def swift_protobuf_messages(
    ctx: BinaryContext,
) -> "Tuple[List[str], List[str], FrozenSet[str]]":
    """Names of Swift types that conform to swift-protobuf's ``Message``/``Enum``
    protocol, recovered from the export-trie conformance descriptors.

    Returns ``(message_types, enum_types, modules)``.  Binary mode only — relies on
    ``ctx.iter_symbol_names()`` (the dyld export trie), which is empty for cache
    images, so this returns empty there (no false negatives that matter: the user
    can point the tool at the standalone binary)."""
    msgs: Set[str] = set()
    enums: Set[str] = set()
    modules: Set[str] = set()
    for sym in ctx.iter_symbol_names():
        if "SwiftProtobuf" not in sym or not sym.endswith("Mc"):
            continue
        parsed = _parse_swift_pb_symbol(sym)
        if parsed is None:
            continue
        kind, module, type_name = parsed
        modules.add(module)
        (enums if kind == "enum" else msgs).add(type_name)
    return sorted(msgs), sorted(enums), frozenset(modules)


# ── C++ libprotobuf (google::protobuf) ───────────────────────────────────────
# C++ protobuf messages subclass ``google::protobuf::Message`` and are driven by a
# reflection runtime — no ObjC class, nothing to disassemble.  The signal is the
# mangled namespace token ``6google8protobuf``, which appears in this image's OWN
# symbols only when it statically embeds / directly references the C++ runtime.  We
# report both:
#   • TOP-LEVEL ``google::protobuf`` (``…N6google8protobuf``) — standard
#     libprotobuf; AND
#   • VENDORED, re-namespaced static copies ``<ns>::google::protobuf`` (e.g. Apple
#     Wireless Diagnostics' ``wireless_diagnostics::google::protobuf``) — these ARE
#     real C++ protobuf usage (e.g. locationd embeds the AWD runtime and emits AWD
#     telemetry protobufs *in addition to* its 65 PBCodable messages), so the user
#     should know they're present even though the tool can't extract them.
# What this still does NOT match: merely *linking* libprotobuf.dylib with zero
# references (a link check would false-positive — locationd links it dynamically too,
# but that alone is not usage; the embedded-symbol references are).
_CPP_PROTOBUF_TOKEN = "6google8protobuf"


def _cpp_protobuf_symbol_names(ctx: BinaryContext):
    """Symbol names to scan for the ``google::protobuf`` C++ token.

    Binary mode reads ``LC_SYMTAB``/export trie via ``iter_symbol_names``;
    cache-native that table is unaddressable, so we read the image's local
    symbols from the cache ``.symbols`` sub-cache (pre-filtered to the token).
    Either way the namespace parse below sees the same mangled names."""
    reader = getattr(ctx, "_cache_reader", None)
    if reader is not None and getattr(ctx, "is_cache_backed", False):
        try:
            return list(reader.image_symbol_addrs(
                ctx.image_base, _CPP_PROTOBUF_TOKEN).keys())
        except Exception:
            return []
    return ctx.iter_symbol_names()


def cpp_protobuf_namespaces(ctx: BinaryContext) -> "Dict[str, int]":
    """Map ``google::protobuf`` C++ namespace (top-level or vendored) -> symbol count.

    e.g. ``{"google::protobuf": 12}`` or, for locationd's statically-embedded Apple
    Wireless Diagnostics copy, ``{"wireless_diagnostics::google::protobuf": 95}``.
    Works in both modes (cache-native reads the ``.symbols`` nlist)."""
    out: Dict[str, int] = {}
    for s in _cpp_protobuf_symbol_names(ctx):
        i = s.find(_CPP_PROTOBUF_TOKEN)
        if i < 0:
            continue
        pre = s[:i]
        if pre.endswith("N") or pre.endswith("NK"):     # ::google::protobuf (top level)
            ns = "google::protobuf"
        else:
            # Vendored ``<vendor>::google::protobuf`` — the Itanium nested-name has the
            # vendor as a length-prefixed component ``<len><vendor>`` ending right
            # before the ``6google`` token.  Collect the trailing run of mangling chars
            # and find the ``<digits><name>`` whose name length matches and runs to the
            # end (e.g. ``20wireless_diagnostics`` -> ``wireless_diagnostics``).
            j = len(pre)
            while j > 0 and (pre[j - 1].isalnum() or pre[j - 1] == "_"):
                j -= 1
            run = pre[j:]
            vendor = ""
            for m in re.finditer(r"\d+", run):
                name = run[m.end():]
                if name and len(name) == int(m.group()) and not name[0].isdigit():
                    vendor = name
                    break
            ns = (vendor + "::google::protobuf") if vendor else "google::protobuf"
        out[ns] = out.get(ns, 0) + 1
    return out


def cpp_protobuf_symbol_count(ctx: BinaryContext) -> int:
    """Total google::protobuf C++ symbols (top-level + vendored).  Binary mode only."""
    return sum(cpp_protobuf_namespaces(ctx).values())


def protobufc_descriptors(ctx: BinaryContext) -> ProtobufCDescriptors:
    """protobuf-c (C runtime, e.g. Apple MMCS) message/enum descriptors and runtime
    symbols in *ctx* — detection only (see :mod:`serializers.protobufc_detect`).
    Reads data sections through the memory API, so it works in BOTH modes; memoised
    per ctx because the warning and ``--list-serializers`` both ask."""
    return _ctx_cache(ctx, "_protobufc_descriptors_cache",
                      lambda: find_protobufc_descriptors(ctx))


def _warn_if_foreign_protobuf(ctx: BinaryContext, cl: ClassList) -> None:
    """Emit ONE consolidated note when an image carries protobuf messages from
    runtimes other than Apple ``PBCodable``.

    The tool now *decodes* several of these in addition to PBCodable: C++
    ``google::protobuf`` (full descriptors) and swift-protobuf (field names +
    numbers) are emitted as additional, serializer-tagged ``.proto`` files (see
    :mod:`proto.foreign`).  Google's ObjC ``GPBMessage`` and the protobuf-c C runtime
    are detected but not decodable.  This distinguishes the two so the user knows
    what was emitted vs merely flagged.  Swift/C++ detection is binary-mode only;
    protobuf-c detection works in both modes."""
    decoded: List[str] = []      # runtimes whose descriptors we emit
    detected: List[str] = []     # present but not decodable

    sw_msgs, sw_enums, sw_modules = swift_protobuf_messages(ctx)
    if sw_msgs or sw_enums:
        decoded.append(
            "swift-protobuf: %d Swift type(s)%s, e.g. %s (field names + numbers; "
            "wire types not recoverable)" % (
                len(sw_msgs) + len(sw_enums),
                " in module %s" % "/".join(sorted(sw_modules)) if sw_modules else "",
                ", ".join((sw_msgs + sw_enums)[:5]),
            )
        )

    cpp_ns = cpp_protobuf_namespaces(ctx)
    if cpp_ns:
        total = sum(cpp_ns.values())
        decoded.append(
            "C++ google::protobuf: %d symbol(s) [namespace(s): %s]%s (full descriptors "
            "from the embedded FileDescriptorProto)" % (
                total, ", ".join(sorted(cpp_ns)),
                " (a vendored static copy, e.g. Apple Wireless Diagnostics telemetry)"
                if any(n != "google::protobuf" for n in cpp_ns) else "",
            )
        )

    gpb_subs, gpb_bases = google_protobuf_classes(ctx, cl)
    if gpb_subs:
        detected.append(
            "Google protobuf-objc (%s): %d ObjC class(es), e.g. %s — driven by a shared "
            "GPBDescriptor runtime; not yet decodable by this tool" % (
                "/".join(sorted(gpb_bases)) or _GPB_RUNTIME_SUFFIX,
                len(gpb_subs), ", ".join(sorted(gpb_subs)[:5]),
            )
        )

    try:
        pbc = protobufc_descriptors(ctx)
    except (NameError, ImportError):
        raise
    except Exception as exc:
        log.debug("protobuf-c detection failed: %s", exc)
        pbc = None
    if pbc:
        detected.append(
            "protobuf-c (C runtime): %d message + %d enum descriptor(s)%s%s — a static "
            "ProtobufCMessageDescriptor table; field layouts not decoded by this tool" % (
                len(pbc.messages), len(pbc.enums),
                ", e.g. " + ", ".join(pbc.messages[:5]) if pbc.messages else "",
                "" if pbc.messages or pbc.enums else
                " (runtime symbols only: %d _protobuf_c_* symbol(s))" % len(pbc.symbols),
            )
        )

    if not decoded and not detected:
        return

    msg = ("this image carries protobuf messages from non-PBCodable runtime(s) "
           "in addition to PBCodable:")
    if decoded:
        msg += ("\n  DECODED (emitted as separate files, each tagged "
                "`// Serializer:`):\n    - " + "\n    - ".join(decoded))
    if detected:
        msg += ("\n  DETECTED but NOT decodable (no descriptor table this tool can "
                "read — see README):\n    - " + "\n    - ".join(detected))
    log.warning(msg)


# ── Helpers extracted from extract_proto_message ──────────────────────────────

@dataclass
class _FieldNumberResult:
    """Return value of :func:`_confirm_field_numbers`."""
    confirmed_numbers: Dict[str, int]   # ivar_name → 1-based field number
    wt_helpers:        Dict[str, int]   # ivar_name → write-helper vmaddr
    string_helper:     Optional[int]    # vmaddr of string write-helper, or None
    # ivars writeTo: wrote with a literal field# 0 (#52); default keeps older
    # constructors (and tests) that predate this field working unchanged.
    wrote_zero_fields: Set[str] = field(default_factory=set)
    # {ivar_name: MapEntryWriter} for NSDictionary ivars whose map-entry writer was
    # recovered (#41); their numbers are already merged into ``confirmed_numbers``.
    map_writers: Dict[str, MapEntryWriter] = field(default_factory=dict)
    # {ivar_name: raw writeTo: walk write event} — the begin-mark of an inline C-struct
    # sub-message is bound here (proto.structfields, #37).
    walk_writes: Dict[str, dict] = field(default_factory=dict)


def _confirm_field_numbers(
    ctx: BinaryContext,
    cls: ObjcClass,
    field_ivars: List[ObjcIvar],
    instance_method_names: Set[str],
    *,
    string_write_helpers: "FrozenSet[int]" = frozenset(),
) -> _FieldNumberResult:
    """Confirm proto field numbers for *cls* via binary analysis.

    Phase 3 of :func:`extract_proto_message`.  The **writeTo: CFG walk is the
    authoritative source** — it reads the literal ``mov w2,#N`` field number and
    binds it to the container ivar by value-tracing (:func:`_extract_writeto_field_numbers`).
    Its bindings are adopted per-field.

    (A legacy pointer-table dispatch pass that gap-filled the walk was REMOVED
    2026-06-15: instrumentation showed ``_try_pointer_table`` returned nothing on
    every supported artifact — 1201 calls, 0 non-empty — so it never contributed a
    confirmed number and the writeTo walk is the sole source.)

    Write-helper addresses are collected regardless (``wt_helpers``) because
    they distinguish ``repeated string`` from ``repeated bytes`` fields.
    The returned ``string_helper`` is resolved locally first, then falls back
    to the caller-supplied binary-wide set.
    """
    # ── writeTo: field numbers (the sole, authoritative source) ───────────────
    # The writeTo CFG walk reads the literal `mov w2,#N` and binds it to the
    # container ivar by value-tracing — the sound field-number decoder.  (It
    # replaced the former all-or-nothing `min_needed` coverage gate, which
    # discarded a sub-threshold walk WHOLESALE and dropped sound confirmations to
    # ivar-order estimates, e.g. GEOLPRRoot {_regions:1} -> regions 2.)  Always
    # collect wt_helpers too — needed for repeated string vs bytes/message.
    wt_helpers: Dict[str, int] = {}
    wt_zero: Set[str] = set()       # ivars written with a literal field# 0 (#52)
    wt_writes: Dict[str, dict] = {}  # raw walk write events (map-entry analysis, #41)
    confirmed_numbers = _extract_writeto_field_numbers(ctx, cls, field_ivars,
                                                       _out_helpers=wt_helpers,
                                                       _out_zero_fields=wt_zero,
                                                       _out_writes=wt_writes)
    if confirmed_numbers:
        log.debug("%s: %d field number(s) from writeTo: walk",
                  cls.name, len(confirmed_numbers))

    # ── Map fields (#41) ──────────────────────────────────────────────────────
    # An NSDictionary ivar is a protobuf map<>; its number + entry key/value writers
    # live in the enumerate-block invoke fn / inline enumeration loop, not in the
    # walk's own bindings.  Recovered numbers join the confirmed set.
    map_writers: Dict[str, MapEntryWriter] = {}
    map_ivars = [iv for iv in field_ivars if iv.type_enc in MAP_IVAR_ENCS]
    if map_ivars:
        offset_to_name = {iv.offset: iv.name for iv in field_ivars
                          if iv.offset != 0 and iv.name}
        map_writers = find_map_writers(ctx, cls, map_ivars, wt_writes,
                                       offset_to_name, confirmed_numbers)
        for _name, _w in map_writers.items():
            confirmed_numbers.setdefault(_name, _w.number)

    # ── Identify string write helper ──────────────────────────────────────────
    string_helper: Optional[int] = _find_string_write_helper(
        wt_helpers, field_ivars, instance_method_names)
    if string_helper is None and string_write_helpers:
        string_helper = next(iter(string_write_helpers))

    return _FieldNumberResult(
        confirmed_numbers = confirmed_numbers,
        wt_helpers        = wt_helpers,
        string_helper     = string_helper,
        wrote_zero_fields = wt_zero,
        map_writers       = map_writers,
        walk_writes       = wt_writes,
    )


# `_ensure_writeto_indegree` moved to proto/write_helpers.py (imported above).


# Sentinel default for the two field-typing pre-pass kwargs of
# extract_proto_message: distinguishes "caller did not pass it → auto-build" from
# an explicit empty/None value (a caller deliberately opting into the degraded path).
_AUTO = object()


# `_ensure_string_write_helpers` moved to proto/write_helpers.py (imported above).


def _ensure_readfrom_core_index(ctx: BinaryContext, cl: ClassList) -> Dict[int, str]:
    """Lazily build + cache the binary-wide ``{ReadAllFrom_va: class}`` index on
    ``ctx``. Same rationale as :func:`_ensure_string_write_helpers` — without it a
    standalone caller loses principled ``repeated <message>`` element resolution."""
    cached = getattr(ctx, "_readfrom_core_index", None)
    if cached is not None:
        return cached
    try:
        index = _build_readfrom_core_index(ctx, cl)
    except Exception as exc:
        log.debug("readFrom-core-index lazy pre-pass failed (%s)", exc)
        index = {}
    try:
        ctx._readfrom_core_index = index
    except Exception:
        pass
    return index


def _resolve_dispatch_context(
    ctx: BinaryContext, cls: ObjcClass,
    readfrom_core_index: "Optional[Dict[int, str]]",
    field_ivars: List[ObjcIvar],
) -> "Tuple[Dict[int, str], Dict[str, Tuple[str, int]], bool]":
    """Resolve the readFrom: dispatch context for repeated-<message> element typing.
    Carved from :func:`extract_proto_message` (pre-loop phase). Returns:

      * ``dispatch_elements`` — ``{field_number: element_class}`` from walking the
        readFrom: jump table / compare chain (keyed by NUMBER).
      * ``dispatch_ivars`` — ``{ivar_name: (element_class, field_number)}`` from the
        adder→ivar lever (keyed by IVAR, so trustworthy even for unconfirmed numbers).
      * ``unambiguous`` — True for the single-real-field + single-dispatch-entry case,
        where the element type can be applied even with an unconfirmed number.

    The lever binds only the element TYPE, never the field number (arm/compare-chain
    indices are unreliable; the writeTo:/pointer-table pass owns numbers)."""
    dispatch_elements: Dict[int, str] = {}
    dispatch_ivars: Dict[str, Tuple[str, int]] = {}
    if readfrom_core_index:
        try:
            dispatch_elements = _resolve_repeated_via_dispatch(ctx, cls, readfrom_core_index)
        except Exception as exc:
            log.debug("dispatch element resolve failed for %s: %s", cls.name, exc)
        try:
            dispatch_ivars = _resolve_repeated_via_dispatch_ivars(ctx, cls, readfrom_core_index)
        except Exception as exc:
            log.debug("dispatch ivar resolve failed for %s: %s", cls.name, exc)
    _n_real_fields = sum(1 for _iv in field_ivars if _proto_name(_iv.name))
    unambiguous = (_n_real_fields == 1 and len(dispatch_elements) == 1)
    return dispatch_elements, dispatch_ivars, unambiguous


def _resolve_classref_context(
    ctx: BinaryContext, cls: ObjcClass, cl: ClassList,
    readfrom_core_index: "Optional[Dict[int, str]]",
) -> "Dict[str, Tuple[str, int]]":
    """``{ivar_name: (element_class, field_number)}`` from the element class-reference
    lever (:func:`proto.repeated._resolve_repeated_via_classrefs`).  Kept apart from
    the dispatch context because its result is only trustworthy for a field whose
    writeTo: helper is the MESSAGE helper (see :func:`_resolve_repeated_element_type`):
    the lever reads a class reference near the add-accessor call, which a neighbouring
    singular field can also provide for a repeated bytes/string field."""
    try:
        return _resolve_repeated_via_classrefs(ctx, cls, cl, readfrom_core_index or {})
    except Exception as exc:
        log.debug("class-ref ivar resolve failed for %s: %s", cls.name, exc)
        return {}


def _is_backing_store_phantom(
    fld: "ProtoField", ivar_enc_by_pname: Dict[str, str]
) -> bool:
    """True if *fld* is a manual-array backing-store ivar that ``writeTo:`` never
    serializes, so it is **not** a protobuf field and must not be emitted.

    Apple's generated PB classes store an inline-C-struct *array* as three ivars::

        _xs       ^{StructName=...}   the data pointer        (the real field)
        _xsCount  Q (uint64)          element count           (loop bound only)
        _xsSpace  Q (uint64)          allocated capacity       (never referenced)

    Only ``_xs`` is on the wire.  ``_xsCount`` appears in ``writeTo:`` solely as
    the iteration bound (``while i < _xsCount``) and ``_xsSpace`` not at all —
    verified in Hopper on GEOTileGroup, GEOTileSetVersion, GEOCoarseLocationRing.
    Without this filter the extractor turns every ivar into a field and emits the
    two companions with a bogus ivar-declaration-order number (the "// number
    estimated" phantoms, e.g. GEOTileGroup ``tileSetsCount = 17``).

    The rule is structural and guarded so it can never drop a real field:
      * the field number is UNCONFIRMED — a serialized field carries a real
        ``writeTo:`` number; these never do (so a genuine ``fooCount`` field that
        *is* serialized is protected by ``number_confirmed``), AND
      * the type is ``uint64`` (the C count/capacity type), AND
      * the name is ``<base>Count`` / ``<base>Space`` where ``<base>`` is itself
        an ivar whose type is a C-struct-array pointer (``^{...}``) — the data
        ivar of the triplet.

    Selectivity verified binary-wide on GeoServices: matches exactly the 85
    Count/Space phantoms, with zero false positives and zero misses.
    """
    if fld.number_confirmed or fld.type_name != "uint64":
        return False
    for suffix in ("Count", "Space"):
        if fld.name.endswith(suffix) and len(fld.name) > len(suffix):
            base_enc = ivar_enc_by_pname.get(fld.name[: -len(suffix)])
            if base_enc and base_enc.startswith("^{"):
                return True
    return False


_UNRESOLVED_OBJECT_NOTE = (
    "unverified: object type does not resolve to a proto message in this binary "
    "(may be an internal ivar — e.g. a lock/trampoline/protocol — not a wire field)")


def _unresolved_object_field_note(
    fld: "ProtoField", ivar_enc_by_pname: Dict[str, str],
    proto_class_names: "FrozenSet[str]",
) -> Optional[str]:
    """Annotation for an object ivar whose type does NOT resolve to a proto message
    or a Foundation type, else None.

    A protobuf object field always references a concrete proto-message class
    (``@"GEOPDPlace"``) or a Foundation container/value type (``@"NSString"`` →
    string, ``@"NSData"`` → bytes, ``@"NSArray"`` → repeated).  An ivar typed as a
    bare protocol (``@"<GEOMapItem>"``) or a non-proto helper class (``@"geo_isolater"``
    — a lock, ``@"_GEOMapItemStorageNotificationTrampoline"`` — a KVO trampoline) may
    not be a real wire field.  Rather than GUESS whether to drop it (which needs a
    name-shape heuristic and risks dropping a cross-framework message), we KEEP the
    field and annotate it so the reader can decide — purely factual: "this type did
    not resolve here".  Only fires for UNCONFIRMED fields (a confirmed writeTo:
    number means the ivar is genuinely serialised, so it is a real field).
    """
    if fld.number_confirmed:
        return None
    enc = ivar_enc_by_pname.get(fld.name) or ""
    if not enc.startswith('@"'):
        return None                        # scalar/struct/packed — not an object ref
    inner = enc[2:].rstrip('"')
    if inner.startswith('<'):              # id<Protocol>
        return _UNRESOLVED_OBJECT_NOTE
    if inner in proto_class_names:         # concrete proto-message class — real
        return None
    if inner.startswith(('NS', 'CF', '_NS')):   # Foundation/CoreFoundation type
        return None
    return _UNRESOLVED_OBJECT_NOTE         # unresolved non-Foundation class


#: ObjC type-encoding of the inherited PBCodable unknown-fields bag.
_UNKNOWN_FIELDS_ENC = '@"PBUnknownFields"'


def _is_opaque_passthrough(ctx: BinaryContext, cls: ObjcClass) -> bool:
    """True when *cls* is a zero-typed-field OPAQUE PASSTHROUGH container.

    Some Apple PBCodable subclasses declare NO wire fields of their own: their
    only ivar is the inherited ``_unknownFields`` (a ``PBUnknownFields`` bag) and
    their ``-[cls writeTo:]`` simply loads that ivar and tail-calls ``writeTo:``
    on it, so every byte on the wire round-trips through the unknown-field store
    (``readFrom:`` likewise absorbs every tag into the same bag with no per-field
    dispatch).  For these, "no fields recovered" is GROUND TRUTH — the schema is
    empty BY DESIGN — not a sign the extractor missed something.  Distinguishing
    them lets the emitter say so instead of implying an extraction gap.

    The decision is purely STRUCTURAL (value-independent), so it can never be
    fooled by a particular field's data:

      1. the class declares exactly ONE ivar, ``_unknownFields`` typed
         ``PBUnknownFields`` — so there are no other field ivars we could have
         failed to recover; and
      2. ``writeTo:`` is the leaf delegating stub: it loads that one ivar into
         ``x0`` and tail-calls (``b``) ``writeTo:``, with no stack frame and no
         helper ``bl`` / ``ret`` (either would mean it serialises real fields).

    Surveyed on GeoServices: 78 classes match, all with this exact shape, and
    none wraps a *typed* inner message (the loaded ivar is always
    ``PBUnknownFields``).  Hopper-verified; see
    notes/REVGEO_OPAQUE_PASSTHROUGH_2026-06-17.md.  Intended to be called only
    for messages with no recovered fields.
    """
    if len(cls.ivars) != 1:
        return False
    iv = cls.ivars[0]
    if iv.name != '_unknownFields' or iv.type_enc != _UNKNOWN_FIELDS_ENC:
        return False
    m = cls.get_method('writeTo:')
    if m is None:
        return False
    from macho.disasm import disasm
    try:
        raw = disasm(ctx, m.imp, max_insns=6, stop_at_ret=True)
    except ValueError:
        return False
    # `disasm` halts only at a ret-family instruction, not at an unconditional
    # `b`, so a tail-calling stub's window runs into the NEXT method.  Truncate at
    # the first terminator (`b` tail-call or `ret`) so we judge only this method.
    insns = []
    for ins in raw:
        insns.append(ins)
        if ins.mnemonic in ('b', 'ret'):
            break
    # A real serializer sets up a frame (`stp`) and/or calls write helpers
    # (`bl`) and returns (`ret`).  The delegating stub does none of these — it is
    # a short straight-line load that ends in a tail-call branch.
    if not insns or insns[-1].mnemonic != 'b':
        return False
    if any(i.mnemonic in ('bl', 'ret', 'stp') for i in insns):
        return False
    # Confirm the value loaded into x0 (and handed to writeTo:) is the
    # _unknownFields ivar — i.e. the load offset resolves to iv.offset.  Two
    # encodings: a direct `ldr x0,[x0,#imm]`, or the ivar-offset-table indirection
    # `adrp x8,#base; ldrsw x8,[x8,#idx]; ldr x0,[x0,x8]`.
    loaded_off = _writeto_self_load_offset(ctx, insns)
    return loaded_off == iv.offset


def _writeto_self_load_offset(ctx: BinaryContext, insns) -> Optional[int]:
    """Byte offset of the ivar that a delegating ``writeTo:`` stub loads into
    ``x0`` (``ldr x0, [x0, ...]``), or None if the shape is not recognised."""
    base = idx = None
    for ins in insns:
        if ins.mnemonic == 'adrp' and ins.op_str.startswith('x8,'):
            mm = re.search(r'#(0x[0-9a-fA-F]+)', ins.op_str)
            base = int(mm.group(1), 16) if mm else None
        elif ins.mnemonic in ('ldrsw', 'ldr') and ins.op_str.startswith('x8, [x8'):
            mm = re.search(r'#(0x[0-9a-fA-F]+)', ins.op_str)
            idx = int(mm.group(1), 16) if mm else 0
        elif ins.mnemonic == 'ldr' and ins.op_str.startswith('x0, [x0'):
            mm = re.search(r'\[x0, #(0x[0-9a-fA-F]+)\]', ins.op_str)
            if mm:                                  # direct immediate offset
                return int(mm.group(1), 16)
            if base is not None:                    # offset-table indirection
                try:
                    return ctx.read_s32(base + (idx or 0))
                except ValueError:
                    return None
            return None
    return None


# ── extract_proto_message per-field helpers ───────────────────────────────────
# These three were carved out of extract_proto_message's per-field loop so each
# field-typing concern is a named, separately-testable unit; the loop reads as a
# short pipeline.  All are behaviour-preserving (byte-identical emitted output).

def _refine_int_wire_form(ctx, type_name, type_class, ivar, wt_helpers):
    """TODO #38/#44: refine the canonical int default to its true wire form.

    The ivar @encode only records storage width, so int32/uint32/sint32/[s]fixed32
    collapse to int32; the field's writeTo: helper VA selects the wire form.  Refine
    ONLY singular scalar ints (``type_class is None`` excludes enum ENUM:/message; the
    packed guard excludes packed-repeated lists, whose encoder is a separate,
    not-yet-ground-truthed packed encoder).  int32<->uint32 stays a genuine tie.
    The helper gives the wire WIDTH (fixed32 vs fixed64); the SIGN half (fixed vs
    sfixed) comes from the ivar exactly like int32↔uint32 — signed ivar (type_name
    int32/int64) → sfixed*, unsigned → fixed*.  See :func:`_classify_write_helper`.
    Returns the (possibly refined) ``type_name``; unchanged for non-int/packed."""
    if (type_class is None
            and type_name in ("int32", "int64", "uint32", "uint64")
            and not _is_packed_list_enc(ivar.type_enc)):
        return _refine_scalar_by_family(
            type_name, _classify_write_helper(ctx, wt_helpers.get(ivar.name)))
    return type_name


def _qualify_field_enum(type_name, type_class, cls, pfx):
    """Class-qualify an enum field's type name at extraction time.

    ``_type_from_enc`` derives the enum name solely from the ivar name, e.g.
    ``_status`` → ``"Status"``.  Many unrelated classes have a ``_status`` ivar,
    so each would produce an enum named ``"Status"`` — colliding in the emitter.
    Prefix with the class's proto name so ``GEOPDPlaceResponse._status`` →
    ``"PDPlaceResponseStatus"``; these are unique by construction.  The later
    ``_enum_name_from_pairs`` step may override this when the value strings reveal
    a genuine binary-level multi-word prefix (e.g. ``MAPS_RESULT_TYPE_*`` →
    ``"MapsResultType"``).  Returns ``(type_name, type_class)`` unchanged for
    non-enum fields."""
    if type_class and type_class.startswith("ENUM:"):
        base_enum  = type_class[5:]
        cls_prefix = _class_to_proto_name(cls.name, pfx)
        qualified  = _qualify_enum_name(cls_prefix, base_enum)
        return qualified, f"ENUM:{qualified}"
    return type_name, type_class


def _resolve_repeated_element_type(
    ctx, cl, ivar, pname, label, type_name, type_class, number, confirmed,
    *, dispatch_elements, dispatch_unambiguous, dispatch_ivars,
    instance_method_names, metaclass, string_helper, wt_helpers,
    classref_ivars=None, message_helper=None,
):
    """Resolve a repeated field's element type (dispatch-first, then heuristic).

    Returns ``(type_name, type_class, type_note)``; returns the inputs unchanged
    with ``note=None`` for fields that are not repeated object arrays.

    The packed-list guard excludes packed repeated *scalar* fields
    (``{?="list"^i…}``): their element is a scalar by construction (the ivar is a C
    array, not an object array), so the message resolvers must not run
    on them — a name-matching message class would be mis-bound to a scalar list
    (e.g. ``geoIds`` → GEOSubPremise).  Their element type is decoded directly from
    ``^<elem>`` in ``_type_from_enc``; the label is already REPEATED.

    Principled-first: the readFrom: dispatch read this field's element class from
    the binary's own field→handler routing.  The dispatch map is keyed by field
    NUMBER, so the ivar↔number match is only trustworthy when the number is
    confirmed, or in the single-field-message case (unambiguous).  The adder→ivar
    lever binds the element type to THIS ivar directly, so it is safe regardless of
    number confirmation.  Always run the heuristic too: it answers when dispatch is
    absent and — crucially — an ABI-confirmed element type (a distinct ``string``
    write helper / +xyzType→NSString) must never be overridden by a dispatch hit
    (which can only be an unconfirmed ordinal collision in that case).  Precedence
    keys on PROVENANCE (``_rr.abi_confirmed``), not the type-name spelling."""
    if not (label is FieldLabel.REPEATED
            and type_class in ("NSArray", "NSMutableArray", None)
            and not _is_packed_list_enc(ivar.type_enc)):
        return type_name, type_class, None

    _disp = dispatch_elements.get(number) if confirmed else None
    if _disp is None and dispatch_unambiguous:
        _disp = next(iter(dispatch_elements.values()))
    if _disp is None and ivar.name in dispatch_ivars:
        _disp = dispatch_ivars[ivar.name][0]
    if (_disp is None and classref_ivars and ivar.name in classref_ivars
            and _same_write_helper(ctx, wt_helpers.get(ivar.name), message_helper)):
        # Element class from the reader's class-reference load next to the
        # add-accessor call, applied only to a field written by the message helper
        # (a repeated bytes/string field can have an unrelated class ref nearby).
        _disp = classref_ivars[ivar.name][0]

    _rr = _resolve_repeated_field_type(
        ivar, pname, instance_method_names, metaclass, cl, ctx,
        string_helper, wt_helpers,
    )
    if _disp is not None and not _rr.abi_confirmed:
        return _disp, _disp, None
    note = None
    if _rr.element_unresolved:
        # Repeated field whose element type could not be determined → emitted as
        # `bytes`.  Flag it so the degradation is visible (a genuine NSData
        # byte-array has element_unresolved=False and is left unflagged).
        note = _ELEMENT_UNRESOLVED_NOTE
    return _rr.type_name, _rr.type_class, note


def extract_proto_message(
    ctx: BinaryContext,
    st: StringTable,
    cl: ClassList,
    cls: ObjcClass,
    *,
    string_write_helpers: "FrozenSet[int]" = _AUTO,
    readfrom_core_index: "Optional[Dict[int, str]]" = _AUTO,
    prefixes: Optional[Tuple[str, ...]] = None,
    enum_debug_writer: Optional[Callable[[Dict[str, Any]], None]] = None,
) -> Optional[ProtoMessage]:
    """
    Extract proto field descriptors from a single ObjC proto class.

    ``string_write_helpers`` is the binary-wide set of write-helper VMAs that
    are known to write string values, obtained from
    :func:`_identify_string_write_helpers`.  Any ``repeated NSArray`` field
    whose ``writeTo:`` write-helper address is in this set will be reclassified
    from ``repeated bytes`` to ``repeated string``.

    ``readfrom_core_index`` is the binary-wide ``{ReadAllFrom_vmaddr:
    class_name}`` map from :func:`_build_readfrom_core_index`.  When present it
    drives the principled ``repeated <message>`` element-type resolver
    (:func:`_resolve_repeated_via_dispatch`), which takes precedence over the
    +xyzType metaclass method for fields whose readFrom: dispatch arm calls a known
    proto class core.

    Both default to ``_AUTO``: when not supplied they are **lazily built + cached
    on ctx** so a standalone call produces the same complete output as one driven
    by :func:`extract_all` (which passes them explicitly).  To deliberately run the
    degraded path, pass an explicit empty/None value (``string_write_helpers=
    frozenset()`` / ``readfrom_core_index=None``) — the degradation is then chosen,
    not silent.

    Returns a ProtoMessage, or None if extraction fails entirely.
    """
    # Gate: emit only for proto message classes.  Membership in the #46
    # superclass-closure set is the detector for real runs (every class being
    # extracted is enumerated in ``cl``, so a heuristic hit is already in the
    # set).  The per-class ``_is_proto_class`` fallback upholds #46's
    # "never drop a heuristic hit" invariant and additionally covers callers
    # that pass a class not present in ``cl`` (e.g. synthetic unit tests).
    # Output-neutral for real extraction: when ``cls in cl`` and
    # ``_is_proto_class(cls)`` is true, ``cls.name`` is already in the set.
    if cls.name not in _proto_class_set(ctx, cl) and not _is_proto_class(cls):
        return None

    # Ensure the writeTo CFG-walk pre-pass is available (extract_all builds it once;
    # a standalone call builds it lazily here so writeTo decoding isn't silently lost).
    _ensure_writeto_indegree(ctx, cl)

    # Resolve the two field-typing pre-passes: auto-build (+cache on ctx) unless the
    # caller passed an explicit value (incl. an explicit empty/None opt-out).
    if string_write_helpers is _AUTO:
        string_write_helpers = _ensure_string_write_helpers(ctx, cl)
    if readfrom_core_index is _AUTO:
        readfrom_core_index = _ensure_readfrom_core_index(ctx, cl)
    _message_helper = _ensure_message_write_helper(ctx, cl)

    # Resolve the two threaded knobs: prefixes default to the canonical set; the
    # enum-debug writer is simply absent (a no-op) when the caller passes none.
    _pfx = prefixes if prefixes is not None else DEFAULT_PREFIXES
    _dbg = enum_debug_writer

    # Inheritance note (TODO #46): when this class is an ObjC subclass of another
    # proto MESSAGE, its own ivars are only a partial field set.  _proto_class_set
    # (run by the gate above) stamped the {child: parent_objc_name} map on ctx.
    _parent_objc = (getattr(ctx, "_proto_inherits", None) or {}).get(cls.name)
    _inherits_from = _class_to_proto_name(_parent_objc, _pfx) if _parent_objc else None

    # Non-structural class detection (see _proto_class_set): the by-name
    # PBCodable-superclass-chain walk did not confirm this class, so its proto-ness
    # rests on a guess. Both flags are emitted as ERRORS. Empty in every real corpus
    # measured so far — but computed for
    # real rather than assumed absent.
    #   heuristic: (a) cls IS in cl and neither structural anchor claimed it
    #   (ctx._proto_class_heuristic_only, stamped by the gate's earlier
    #   _proto_class_set call); (b) cls is NOT in cl at all (e.g. a synthetic caller
    #   per the gate's documented fallback), so the anchors never considered it and
    #   only the direct _is_proto_class(cls) check applies.
    #   va_cluster: the heuristic-seeded VA-cluster closure (anchor 2) claimed it
    #   and the name walk (anchor 1) did not.
    _class_detected_by_heuristic = (
        cls.name not in _proto_class_set(ctx, cl)
        or cls.name in (getattr(ctx, "_proto_class_heuristic_only", None) or frozenset()))
    _class_detected_by_va_cluster = cls.name in (
        getattr(ctx, "_proto_class_cluster_only", None) or frozenset())

    # Collect method names, filtering unresolved (None) entries from
    # preoptimised shared-cache method lists.
    raw_method_names: Set[str] = {m.name for m in cls.methods if m.name is not None}
    # For shared-cache binaries, most selectors can't be resolved and
    # raw_method_names contains only stray partial strings.  Only treat the
    # method names as reliable when at least one core proto selector is
    # present; otherwise fall back to ivar-based heuristics throughout.
    if _REQUIRED_INSTANCE_METHODS & raw_method_names:
        instance_method_names: Set[str] = raw_method_names
    else:
        instance_method_names = set()  # triggers heuristic path in helpers
    metaclass = _find_metaclass(ctx, cls, cl)

    # ── Collect real-field ivars ──────────────────────────────────────────────
    # ACCEPTED LIMITATION: fields are discovered from ivars, so a delegated field
    # with NO backing ivar (e.g. GEOPDReverseGeocodingResult.placeContextMetadata)
    # is never seen and is silently absent from the message — it cannot be flagged
    # inline because no ProtoField exists.  Deferred — see LIMITATIONS.md (3),
    # to-do #35 (full fix = the readFrom CFG/dominator resolver, #42).
    field_ivars: List[ObjcIvar] = [
        iv for iv in cls.ivars
        if _is_real_field_ivar(iv, instance_method_names)
    ]
    if not field_ivars:
        log.debug("No field ivars found for %s", cls.name)
        return ProtoMessage(
            name=_class_to_proto_name(cls.name, _pfx),
            class_name=cls.name,
            inherits_from=_inherits_from,
            # A field-less class whose sole ivar is the unknown-fields bag and
            # whose writeTo: just delegates to it is an opaque passthrough (no
            # typed fields BY DESIGN), not an extraction miss — flag it so the
            # emitter says so.  This early return is the usual opaque path
            # (the _unknownFields ivar is filtered out of field_ivars above).
            opaque_passthrough=_is_opaque_passthrough(ctx, cls),
            class_detected_by_heuristic=_class_detected_by_heuristic,
            class_detected_by_va_cluster=_class_detected_by_va_cluster,
        )

    # ── Confirm field numbers (pointer-table / writeTo: / string-helper) ──────
    _fnr          = _confirm_field_numbers(
        ctx, cls, field_ivars, instance_method_names,
        string_write_helpers=string_write_helpers,
    )
    confirmed_numbers = _fnr.confirmed_numbers
    _wt_helpers       = _fnr.wt_helpers
    _string_helper    = _fnr.string_helper
    _wrote_zero       = _fnr.wrote_zero_fields
    _map_writers      = _fnr.map_writers
    _walk_writes      = _fnr.walk_writes

    # One vote per field for "which wire kind does this write helper encode" — the
    # binary-wide table :func:`_finalize_map_fields` reads to type map keys/values.
    record_helper_votes(ctx, field_ivars, _wt_helpers, _proto_class_set(ctx, cl))

    # ── Principled repeated-<message> element types (readFrom: dispatch) ───────
    dispatch_elements, dispatch_ivars, _dispatch_unambiguous = _resolve_dispatch_context(
        ctx, cls, readfrom_core_index, field_ivars)
    _classref_ivars = _resolve_classref_context(ctx, cls, cl, readfrom_core_index)

    # ── Build ProtoField list ─────────────────────────────────────────────────
    # Build a set of field numbers already taken by confirmed fields so that
    # the ordinal fallback can skip them and avoid duplicate field numbers.
    confirmed_field_nums: set = set(confirmed_numbers.values())
    next_unconfirmed = 1   # lowest candidate ordinal for unconfirmed fields

    fields: List[ProtoField] = []
    for ordinal, ivar in enumerate(field_ivars, start=1):
        pname = _proto_name(ivar.name)
        if not pname:
            continue

        label   = _field_label(ivar, instance_method_names)
        type_name, type_class = _type_from_enc(
            ivar.type_enc, ivar.name, instance_method_names
        )

        # TODO #38/#44: refine the canonical int default to its true wire form
        # (sint*/[s]fixed*) from the field's writeTo: helper VA.
        type_name = _refine_int_wire_form(ctx, type_name, type_class, ivar, _wt_helpers)

        # ── Mode A enum-fallback debug ────────────────────────────────────────
        # Fires when: (a) --cache path (instance_method_names non-empty), (b)
        # the ivar has a scalar type encoding that *could* be an enum, (c) no
        # ENUM: tag was set by _type_from_enc, AND — critically — (d) the
        # xAsString:/StringAsX: selector DOES exist somewhere in the binary's
        # own __objc_methname section.
        #
        # Condition (d) is the key filter: it restricts records to cases where
        # there is positive evidence that an enum method exists but was NOT
        # detected for this class.  Without this gate the hook would fire for
        # every legitimate non-enum int field (ttl, startIndex, componentId,
        # …) producing thousands of noise records.
        #
        # When (d) is False the field is genuinely not an enum — no record needed.
        # When (d) is True the field SHOULD be an enum and the record explains why
        # it wasn't: wrong class (method is on a different class), partially
        # resolved method list, naming mismatch, etc.
        if (_dbg is not None
                and instance_method_names               # --cache path
                and ivar.type_enc in _SCALAR_ENC        # integer-typed ivar
                and type_class is None):                # no ENUM: tag set
            _emit_mode_a_debug(ctx, cls, st, ivar, type_name,
                               instance_method_names, _dbg)

        # Class-qualify enum names at extraction time so unrelated classes'
        # same-named enums (every _status → "Status") don't collide; a later
        # binary-confirmed multi-word prefix may override it (see helper).
        type_name, type_class = _qualify_field_enum(type_name, type_class, cls, _pfx)

        # Assign the field number first — the dispatch map is keyed by field
        # number, so we need the final number (confirmed, or the ivar-order
        # ordinal fallback) before consulting it for the element type below.
        if ivar.name in confirmed_numbers:
            number    = confirmed_numbers[ivar.name]
            confirmed = True
        else:
            # Advance next_unconfirmed past any field numbers already taken
            # by confirmed fields to prevent duplicate field numbers.
            while next_unconfirmed in confirmed_field_nums:
                next_unconfirmed += 1
            number    = next_unconfirmed
            confirmed = False
            next_unconfirmed += 1

        # Resolve a repeated field's element type (dispatch-first, then the write
        # helper / +xyzType) and flag an unresolved element.  Alerts the user via
        # an inline `//` comment when the element type could not be determined.
        type_name, type_class, _type_note = _resolve_repeated_element_type(
            ctx, cl, ivar, pname, label, type_name, type_class, number, confirmed,
            dispatch_elements=dispatch_elements,
            dispatch_unambiguous=_dispatch_unambiguous,
            dispatch_ivars=dispatch_ivars,
            instance_method_names=instance_method_names,
            metaclass=metaclass,
            string_helper=_string_helper, wt_helpers=_wt_helpers,
            classref_ivars=_classref_ivars, message_helper=_message_helper,
        )

        # protobuf map<> field: remember its entry writer for the post-extraction
        # type resolution (:func:`_finalize_map_fields`); until then — and for any map
        # it cannot resolve — the field stays flagged `bytes` (see LIMITATIONS.md (1), #41).
        if type_class in _MAP_OBJC_CLASSES:
            if ivar.name in _map_writers:
                _ctx_cache(ctx, "_map_writers", dict)[(cls.name, pname)] = \
                    _map_writers[ivar.name]
            if not _type_note:
                _type_note = _MAP_FIELD_NOTE

        # ACCEPTED LIMITATION (field# 0): the writeTo: walk saw this ESTIMATED field
        # written with a literal field number 0 (Apple 0-based; illegal in .proto).
        # The estimated number is not wire-accurate — flag it (see LIMITATIONS.md (4),
        # #52).  Only for estimated fields: a confirmed number is the real one.
        if not confirmed and ivar.name in _wrote_zero and not _type_note:
            _type_note = _FIELD_ZERO_NOTE

        # ACCEPTED LIMITATION (singular embedded struct): a by-value `{Name=...}`
        # struct field is a submessage on the wire but emits as bytes; flag it so
        # the degradation is visible (see LIMITATIONS.md (2)).
        if not _type_note:
            _type_note = _embedded_struct_note(ivar, type_name, type_class)

        # Inline C-struct sub-message (by value or an array of them): remember the
        # begin-mark the walk bound to it, so :func:`finalize_struct_fields` can read the
        # struct's serialiser once the whole image is extracted (#37).  Fields it cannot
        # resolve keep the flagged `bytes` fallback set above.
        if type_name == "bytes":
            record_struct_site(ctx, cls.name, pname, ivar.name, ivar.offset, ivar.type_enc,
                               _walk_writes.get(ivar.name))

        fields.append(ProtoField(
            name=pname,
            number=number,
            type_name=type_name,
            label=label,
            type_class=type_class,
            number_confirmed=confirmed,
            type_inference_note=_type_note,
        ))

    # Drop manual-array backing-store ivars (``_xCount``/``_xSpace``) that ObjC
    # keeps for an inline-C-struct array but ``writeTo:`` never serializes — they
    # are not proto fields and would otherwise emit with a bogus ivar-order number
    # (see :func:`_is_backing_store_phantom`; Hopper-verified).
    _ivar_enc_by_pname = {
        _proto_name(iv.name): iv.type_enc for iv in cls.ivars if iv.name}
    fields = [f for f in fields
              if not _is_backing_store_phantom(f, _ivar_enc_by_pname)]

    # Annotate (do NOT drop) object ivars whose type does not resolve to a proto
    # message or Foundation type — bare protocols and internal helper classes (locks,
    # KVO trampolines) that may not be real wire fields.  We keep them and flag them
    # so the reader decides (see :func:`_unresolved_object_field_note`).
    _proto_class_names = _proto_class_set(ctx, cl)
    for f in fields:
        if not f.type_inference_note:
            _note = _unresolved_object_field_note(f, _ivar_enc_by_pname,
                                                  _proto_class_names)
            if _note:
                f.type_inference_note = _note

    fields.sort(key=lambda f: f.number)

    # ── Enum collection ──────────────────────────────────────────────────────
    enums = _collect_enum_definitions(
        ctx, cls, fields, st, instance_method_names, metaclass,
        prefixes=_pfx, enum_debug_writer=_dbg)

    return ProtoMessage(
        name=_class_to_proto_name(cls.name, _pfx),
        class_name=cls.name,
        fields=fields,
        enums=enums,
        # Flagged when -[cls _dictionaryRepresentation:] disassembly hit the budget
        # cap during enum harvest, so some int32 fields may be unrecovered enums.
        enum_recovery_truncated=cls.name in (
            getattr(ctx, "_dictrep_truncated_classes", None) or set()),
        inherits_from=_inherits_from,
        # When no fields were recovered, distinguish a genuine zero-field opaque
        # passthrough (schema empty BY DESIGN) from a possible extraction miss, so
        # the emitter can say which it is.  Only the field-less case pays the
        # writeTo: disasm cost.
        opaque_passthrough=(not fields) and _is_opaque_passthrough(ctx, cls),
        class_detected_by_heuristic=_class_detected_by_heuristic,
        class_detected_by_va_cluster=_class_detected_by_va_cluster,
    )

# ── Class-name to proto-name conversion ───────────────────────────────────────

# Default prefixes (:data:`proto.defaults.DEFAULT_PREFIXES`) cover the Apple
# frameworks that were the original target.  Pass ``prefixes=`` to extract_all
# (CLI: ``--prefix``) to strip a different set for other binaries; it threads down
# to :func:`proto.config._class_to_proto_name` as an explicit argument.

# NOTE: the cache-active / binary-is-executable flags that gate ambiguous-enum
# message *severity* live solely in :mod:`proto.emitter` (its _CACHE_ACTIVE /
# _BINARY_IS_EXECUTABLE + configure_* setters).  The extractor previously carried
# its own copies, but nothing here ever read them — they were dead duplicates and
# a desync hazard, so they were removed.  The emitter is the single owner.


# ── Top-level extraction ───────────────────────────────────────────────────────

def _check_selectors_resolved(ctx: BinaryContext, cl: ClassList) -> None:
    """Fail fast when a binary's ObjC selector names are unresolved.

    A run only reaches the proto extractors meaningfully when method names are
    resolved (``readFrom:`` / ``writeTo:`` etc.).  When **no** proto class has
    them resolved, the input is broken and the result would be silently degraded.
    Severity is by input kind, mirroring the ambiguous-enum policy in
    :mod:`proto.emitter`:

      * **cache-native** (``ctx.is_cache_backed``) — the ``.symbols`` sub-cache is
        missing or doesn't cover this image → :class:`SelectorsUnresolvedError`.
      * **standalone executable** (``ctx.is_executable``) — self-contained, so
        unresolved names mean stripped/corrupt metadata → error.
      * **standalone shared library** (``ctx.is_dylib``, not cache-backed) — a
        stripped dylib may legitimately defer to the cache; emit a warning and
        continue with degraded (best-effort) output.

    The trigger is conservative — ``resolved == 0`` — so a fully- or
    partially-resolved binary is never affected (its resolved classes use the
    normal path; any stray unresolved class degrades per-class as before).

    When ``resolved == 0``, a prior check distinguishes a THIRD case from the
    symbol problems above: if the image's selector NAMES resolve fine but no
    proto-shaped class implements ``writeTo:``/``readFrom:``, the image simply
    has no decodable protobuf messages (the detectors over-include NSObject
    classes with a PB-like ivar shape).  That is warned, not raised — a
    missing-``.symbols`` error would mislead the user (#51).
    """
    proto_classes = [c for c in cl if not c.is_meta and _is_proto_class(c)]
    if not proto_classes:
        return  # nothing proto-shaped to extract — not a symbol problem
    resolved = sum(
        1 for c in proto_classes
        if _REQUIRED_INSTANCE_METHODS.issubset(
            {m.name for m in c.methods if m.name is not None})
    )
    if resolved > 0:
        return  # selectors resolve (fully or partially) — normal path

    # resolved == 0.  Two very different causes share this symptom; distinguish
    # them by IMAGE-WIDE selector-name availability rather than by proto-class
    # detection (which over-includes NSObject classes that merely have a
    # PB-like ivar shape — e.g. SymptomNetworkUsage's NWUsage* carry
    # `_extensionDictionaries` but subclass NSObject and implement no
    # writeTo:/readFrom: anywhere):
    #   * names DO resolve (cache .symbols present / binary not stripped) but no
    #     proto-shaped class implements writeTo:/readFrom: → the image genuinely
    #     has no decodable protobuf messages.  Output is correctly empty; warn,
    #     don't raise (a missing-.symbols error here would mislead the user).
    #   * names DON'T resolve → the real symbol problem (.symbols missing in
    #     cache mode / stripped executable) → raise per input kind, as before.
    total_methods = sum(1 for c in cl for _m in c.methods)
    named_methods = sum(1 for c in cl for m in c.methods if m.name is not None)
    if total_methods > 0 and named_methods * 2 >= total_methods:
        log.warning(
            "%d protobuf-shaped class(es) found but none implement "
            "writeTo:/readFrom: — this image has no decodable protobuf messages. "
            "(ObjC selector names resolve, so this is NOT a missing .symbols / "
            "stripped-binary problem.)", len(proto_classes))
        return

    if ctx.is_cache_backed:
        raise SelectorsUnresolvedError(
            f"no ObjC selector names resolved for any of {len(proto_classes)} "
            "proto classes in cache-native mode — the .symbols sub-cache is "
            "missing or does not cover this image. Re-extract with a complete "
            "dyld shared cache (including the .symbols file).")
    if ctx.is_executable:
        raise SelectorsUnresolvedError(
            f"no ObjC selector names resolved for any of {len(proto_classes)} "
            "proto classes in this standalone executable — a self-contained "
            "executable carries its own selector strings, so this indicates "
            "stripped or corrupt ObjC metadata. Cannot extract proto schemas.")
    # Standalone shared library: degraded best-effort is acceptable.
    log.warning(
        "no ObjC selector names resolved for any of %d proto classes in this "
        "standalone shared library — proto extraction will be degraded "
        "(repeated fields fall back to bytes, field numbers to ivar order, "
        "enums to scalars). For full fidelity, extract this image from the "
        "dyld shared cache instead.", len(proto_classes))


def extract_all(
    ctx: BinaryContext,
    st: StringTable,
    cl: ClassList,
    *,
    prefixes: Optional[Tuple[str, ...]] = None,
    enum_debug_writer: Optional[Callable[[Dict[str, Any]], None]] = None,
) -> List[ProtoMessage]:
    """
    Extract proto message descriptors from every proto-like class in cl.

    Performs a binary-wide pre-pass to identify the string write-helper
    address(es), then passes the result to each :func:`extract_proto_message`
    call so that ``repeated NSArray`` fields can be correctly reclassified as
    ``repeated string`` when the element type is NSString.

    Args:
        prefixes: ObjC class-name prefixes to strip when forming proto message
            names (e.g. ``("GEO", "CLP")``).  When ``None`` the canonical
            :data:`proto.defaults.DEFAULT_PREFIXES` set is used.
        enum_debug_writer: optional callable that receives one ``dict`` per
            enum-fallback diagnostic event.  When ``None`` no diagnostics are
            emitted.

    Returns a list of ProtoMessage objects sorted by class name.

    Raises :class:`SelectorsUnresolvedError` when no proto class has resolvable
    selector names and the input mode treats that as an error (cache-native or a
    standalone executable); a standalone shared library logs a warning instead
    and continues with degraded output.  See :func:`_check_selectors_resolved`.
    """
    _check_selectors_resolved(ctx, cl)
    _warn_if_foreign_protobuf(ctx, cl)

    # Reset per-extraction memoisation caches so a BinaryContext reused across
    # two extractions cannot serve stale cluster/dispatch results.  These attrs
    # are declared on BinaryContext; setattr is guarded for any context-like
    # object that does not allow attribute assignment.
    for _cache_attr in ("_wrapper_cluster_cache", "_dispatch_arms_cache",
                        "_writeto_indeg", "_writeto_foreign_imps",
                        "_string_write_helpers", "_message_write_helper", "_readfrom_core_index",
                        "_dictrep_truncated_classes", "_proto_class_names_cache",
                        "_proto_inherits", "_proto_class_heuristic_only",
                        "_proto_class_cluster_only", "_helper_votes",
                        "_helper_canon", "_map_writers", "_struct_sites",
                        "_dictrep_names"):
        try:
            setattr(ctx, _cache_attr, None)
        except Exception:
            pass

    # Resolve the proto-class set ONCE, up front (memoised on ctx, so the per-class
    # calls below reuse it), then render the structural-detection verdict for the
    # WHOLE IMAGE.  The verdict lives here rather than in _proto_class_set because
    # it is a statement about a complete class graph: "every class admitted to this
    # schema was confirmed by its superclass chain".  A single-class
    # extract_proto_message call (unit tests, probe scripts) has no such graph — a
    # synthetic ObjcClass may have no superclass at all — so it only FLAGS the
    # message inline rather than failing.  Every real consumer of this tool enters
    # through extract_all, so the guarantee holds where it matters.
    #
    # Placed after the cache reset and before the expensive pre-passes: a failure
    # aborts with NO output and no wasted work, and cannot be swallowed by the
    # per-class ``except Exception`` handler further down.
    _proto_class_set(ctx, cl)
    check_no_heuristic_detection(
        getattr(ctx, "_proto_class_heuristic_only", None) or frozenset(),
        getattr(ctx, "_proto_class_cluster_only", None) or frozenset(),
        source=getattr(ctx, "source_name", None) or "<binary>")

    # Pre-pass: build the binary-wide branch-indegree map + method-IMP set that the
    # writeTo: CFG-walk decoder needs, and thread them onto ctx so each per-class
    # _extract_writeto_field_numbers call (incl. the string-helper pre-pass below)
    # can run the walk.  Built ONCE here — building it per class would be O(n^2).
    try:
        _wt_indeg, _wt_foreign = build_writeto_indegree(ctx, cl)
        ctx._writeto_indeg = _wt_indeg
        ctx._writeto_foreign_imps = _wt_foreign
        log.debug("writeTo indegree pre-pass: %d branch targets, %d method IMPs",
                  len(_wt_indeg), len(_wt_foreign))
    except Exception as exc:
        log.debug("writeTo indegree pre-pass failed (%s); CFG walk disabled, "
                  "writeTo field numbers fall back to ivar-order estimates", exc)

    # Pre-pass: find the string write-helper VA(s) from any class that has
    # a confirmed singular @"NSString" ivar with a write-helper.  All proto
    # classes in one binary share the same write helpers so one example
    # suffices; we stop the scan as soon as we have a result.
    string_write_helpers: FrozenSet[int] = frozenset(
        _identify_string_write_helpers(ctx, cl)
    )
    log.debug("String write helpers identified: %s",
              [hex(h) for h in string_write_helpers])

    # Pre-pass: build the {ReadAllFrom vmaddr -> class name} index that drives
    # the principled repeated-<message> element-type resolver.
    readfrom_core_index: Dict[int, str] = _build_readfrom_core_index(ctx, cl)
    log.debug("readFrom core index: %d classes", len(readfrom_core_index))

    messages: List[ProtoMessage] = []
    failed: List[str] = []          # class names whose extraction raised
    for cls in cl:
        if cls.is_meta:
            continue
        msg = None
        try:
            msg = extract_proto_message(ctx, st, cl, cls,
                                        string_write_helpers=string_write_helpers,
                                        readfrom_core_index=readfrom_core_index,
                                        prefixes=prefixes,
                                        enum_debug_writer=enum_debug_writer)
        except (NameError, ImportError):
            # A wiring/refactor bug (e.g. the enums-carve missing-import NameError)
            # must HARD-fail, not be swallowed as a per-class "decode failed" — those
            # are never raised by binary-data processing, only by broken code.
            # (ProtoClassDetectionError cannot reach here: the whole-image verdict is
            # rendered by the pre-pass above, before this loop starts.)
            raise
        except Exception as exc:
            # One bad class must not abort the whole run, but a failure here is
            # a real defect (a decoder that should be robust threw): surface the
            # COUNT loudly so a regression is visible, and the per-class detail
            # at debug for diagnosis.  Normal "not a proto class" cases return
            # None rather than raising, so they are NOT counted here.
            failed.append(cls.name)
            log.debug("Failed to extract proto for %s: %s", cls.name, exc)
        if msg is not None:
            messages.append(msg)

    if failed:
        log.warning(
            "extract_all: %d proto class(es) failed to extract and were "
            "skipped (run at debug level for per-class detail): %s",
            len(failed),
            ", ".join(sorted(failed)[:10]) + (" …" if len(failed) > 10 else ""),
        )

    # Map<> fields (#41): type them now that the binary-wide write-helper table is complete.
    _finalize_map_fields(ctx, cl, messages, readfrom_core_index)

    # Inline C-struct sub-messages (#37): synthesise a message per struct tag and retype the
    # owner fields whose struct serialiser was decoded.
    finalize_struct_fields(ctx, cl, messages, prefixes)

    messages.sort(key=lambda m: m.class_name)
    return messages


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
    core_index: Dict[int, str],
) -> None:
    """Post-extraction pass (#41): type every map field whose entry writer was recovered.

    Runs after the whole image is extracted because a map key/value helper's type is the
    unanimous type of the ivars that use it binary-wide (``ctx._helper_votes``, filled by
    :func:`record_helper_votes` as each class was extracted).  A field with no entry
    writer is left untouched (flagged ``bytes``)."""
    writers = getattr(ctx, "_map_writers", None) or {}
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
                types = resolve_map_types(ctx, cls, writer, core_index, known)
            except (NameError, ImportError):
                raise
            except Exception as exc:
                log.debug("map type resolution failed for %s.%s: %s",
                          msg.class_name, fld.name, exc)
                types = MapTypes(None, None, None, f"analysis failed: {type(exc).__name__}")
            _apply_map_types(fld, types)


def is_proto_class(cls: ObjcClass) -> bool:
    """Public alias for _is_proto_class."""
    return _is_proto_class(cls)


# Public API + the few extractor-local helpers callers/tests still reach for here.
# The 24 private helpers that the #11 split moved into macho/arm64decode.py and
# proto/{protocore,dispatch,repeated,config,enums,writeto}.py were dropped from
# __all__ — tests now import them from their real home modules. (The re-import
# back-compat shim above is retained while a few external consumers — the dev
# scripts — still import moved symbols via proto.extractor.)
__all__ = [
    "extract_all",
    "extract_proto_message",
    "is_proto_class",
    "google_protobuf_classes",
    "swift_protobuf_messages",
    "cpp_protobuf_namespaces",
    "cpp_protobuf_symbol_count",
    "protobufc_descriptors",
    "SelectorsUnresolvedError",
    "_identify_string_write_helpers",
    "_find_string_write_helper",
    "_ENUM_NAME_NO_PREFIX",
]
