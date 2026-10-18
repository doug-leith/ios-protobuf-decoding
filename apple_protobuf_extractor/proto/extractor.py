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

Field names come from the ObjC ivars and types from their type encodings, refined by the
writeTo: writers (proto.write_helpers) and the readFrom: dispatch (proto.dispatch_eval).
Field numbers are confirmed from the writeTo: walk (proto.writeto: the number each write
passes); a field the walk does not bind gets the next free number in ivar order and is
flagged "number estimated".

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
from macho.memory    import BinaryContext, _ctx_cache, _ctx_store, reset_ctx_caches
from macho.strings   import StringTable
from macho.classlist import ClassList, ObjcClass, ObjcIvar

from proto.models    import (FieldLabel, ProtoField, ProtoMessage, get_diagnostics,
                             record_analysis_failure, record_failed_pass)
from proto.writeto   import _extract_writeto_field_numbers, writeto_sent_selectors
from proto.writer_flow import writer_reachable_ivars
from proto.write_helpers import (
    _identify_string_write_helpers, _find_string_write_helper,
    _classify_write_helper, _refine_scalar_by_family, _ensure_writeto_indegree, INT_ENCODING_NOTE,
    _ensure_string_write_helpers,
)
from proto.protocore import (
    _is_real_field_ivar, _type_from_enc,
    _is_packed_list_enc, _field_label, _proto_name,
    _REQUIRED_INSTANCE_METHODS, _SCALAR_ENC,
)
# Retired non-structural detectors — kept for investigation, fail the run if they
# ever claim a class.  See proto/protoclass_heuristic.py.
from proto.protoclass_heuristic import _is_proto_class, check_no_heuristic_detection
from proto.dispatch  import _build_readfrom_core_index
from proto.repeated  import (
    _resolve_repeated_via_dispatch, _resolve_repeated_via_dispatch_ivars,
    _resolve_repeated_field_type,
)
from proto.structfields import finalize_struct_fields, record_struct_site
from proto.mapfields import (
    MAP_OBJC_CLASSES, MAP_IVAR_ENCS, MapEntryWriter, find_map_writers,
    record_helper_votes, _finalize_map_fields, _MAP_FIELD_NOTE,
)
from proto.protoclass_set import _proto_class_set
from proto.foreign_detect import (   # noqa: F401  (public API re-exports)
    _warn_if_foreign_protobuf, google_protobuf_classes, swift_protobuf_messages,
    cpp_protobuf_namespaces, cpp_protobuf_symbol_count, protobufc_descriptors)
from proto.enums     import _qualify_enum_name, _collect_enum_definitions
from proto.enums_debug import _emit_mode_a_debug
from proto.config    import _class_to_proto_name
from proto.defaults  import DEFAULT_PREFIXES

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

# ACCEPTED LIMITATION (field# 0): Apple emits deliberate 0-based proto fields
# (writeTo: `mov w2,#0`, readFrom: `case 0`).  Field 0 is illegal in proto2/proto3
# and cannot be emitted, so the tool estimates the lowest legal number — but that
# number is NOT what's on the wire.  When the writeTo: walk saw a literal-0 write
# for an ESTIMATED field, say so explicitly.  See LIMITATIONS.md (4), to-do #52.
#: Object ivar types that name no wire type: the field is emitted as bytes.
_OPAQUE_OBJECT_TYPES = frozenset({"NSNumber", "NSValue", "NSObject"})
_OPAQUE_OBJECT_NOTE = ("ivar type {enc} names no wire type; emitted as bytes")


def _opaque_object_note(ivar: ObjcIvar, type_class: Optional[str]) -> Optional[str]:
    """The note for a field whose ivar is a bare object (``@``) or a Foundation type that
    names no wire type (``NSNumber`` / ``NSValue`` / ``NSObject``), which emits as bytes."""
    if ivar.type_enc == "@" or type_class in _OPAQUE_OBJECT_TYPES:
        return _OPAQUE_OBJECT_NOTE.format(enc=ivar.type_enc or "@")
    return None


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


# Sentinel default for the two field-typing pre-pass kwargs of
# extract_proto_message: distinguishes "caller did not pass it → auto-build" from
# an explicit empty/None value (a caller deliberately opting into the degraded path).
_AUTO = object()


def _ensure_readfrom_core_index(ctx: BinaryContext, cl: ClassList) -> Dict[int, str]:
    """Lazily build + cache the binary-wide ``{ReadAllFrom_va: class}`` index on
    ``ctx``. Same rationale as :func:`_ensure_string_write_helpers` — without it a
    standalone caller loses principled ``repeated <message>`` element resolution."""
    cached = getattr(ctx, "_readfrom_core_index", None)
    if cached is not None:
        return cached
    try:
        index = _build_readfrom_core_index(ctx, cl)
    except (NameError, ImportError):
        raise
    except Exception as exc:
        record_failed_pass(ctx, "readFrom core index", exc,
                           "repeated-message element types are not recovered from readFrom:")
        index = {}
    _ctx_store(ctx, "_readfrom_core_index", index)
    return index


def _resolve_dispatch_context(
    ctx: BinaryContext, cls: ObjcClass,
    readfrom_core_index: "Optional[Dict[int, str]]",
    field_ivars: List[ObjcIvar],
) -> "Tuple[Dict[int, str], Dict[str, Tuple[str, int]], bool]":
    """Resolve the readFrom: dispatch context for repeated-<message> element typing:

      * ``dispatch_elements`` — ``{field_number: element_class}``: the class each field's
        readFrom: handler builds (:mod:`proto.dispatch_eval`; keyed by NUMBER).
      * ``dispatch_ivars`` — ``{ivar_name: (element_class, field_number)}``: the array ivar
        that handler appends to (keyed by IVAR, so usable even for unconfirmed numbers).
      * ``unambiguous`` — True for the single-real-field + single-dispatch-entry case,
        where the element type can be applied even with an unconfirmed number.

    Only the element TYPE is taken from here, never the field number (the writeTo: pass
    owns numbers)."""
    dispatch_elements: Dict[int, str] = {}
    dispatch_ivars: Dict[str, Tuple[str, int]] = {}
    if readfrom_core_index:
        try:
            dispatch_elements = _resolve_repeated_via_dispatch(ctx, cls, readfrom_core_index)
        except (NameError, ImportError):
            raise
        except Exception as exc:
            record_analysis_failure(ctx, cls.name, "readFrom: dispatch (element classes)",
                                    f"{type(exc).__name__}: {exc}")
        try:
            dispatch_ivars = _resolve_repeated_via_dispatch_ivars(ctx, cls, readfrom_core_index)
        except (NameError, ImportError):
            raise
        except Exception as exc:
            record_analysis_failure(ctx, cls.name, "readFrom: dispatch (element ivars)",
                                    f"{type(exc).__name__}: {exc}")
    _n_real_fields = sum(1 for _iv in field_ivars if _proto_name(_iv.name))
    unambiguous = (_n_real_fields == 1 and len(dispatch_elements) == 1)
    return dispatch_elements, dispatch_ivars, unambiguous


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


def _inherited_writeto_owner(ctx: BinaryContext, cl: ClassList,
                             cls: ObjcClass) -> Optional[ObjcClass]:
    """The ancestor whose ``-writeTo:`` serialises *cls*, when *cls* has none of its own
    and that inherited ``writeTo:`` provably cannot serialise *cls*'s own ivars; else None.

    A class with no ``writeTo:`` in its method list is serialised by the nearest
    ancestor's.  That code was compiled against the ancestor's layout: it reaches ivars
    through the ancestor's ivar-offset variables and writes literal field numbers, so the
    subclass's own ivars (with their own offset variables) can reach the wire only
    through a method the subclass implements.  The rule therefore needs:

      * every method name on *cls* and on the classes between it and the ancestor
        resolved, so that "no ``writeTo:``" is a fact rather than an unresolved name;
      * the ancestor in this image, with its ``writeTo:`` (else: cannot tell); and
      * no ``readFrom:`` on *cls* or an intermediate class (a message the client only reads
        is defined by what its own ``readFrom:`` reads); and
      * that ``writeTo:`` sending no selector *cls* or an intermediate class implements
        (:func:`proto.writeto.writeto_sent_selectors`; None there -- a truncated walk,
        an indirect call, an unentered thunk -- is "cannot tell").

    Not checked: a send made by a function the ancestor's ``writeTo:`` calls.
    GeoServices: GEOAnalyticsPipelineSharedStateData, GEOComposedWaypointEVStop,
    GEOSearchRequest, GEOSearchResponse (IDA cross-check 2026-10-15)."""
    if cls.get_method("writeTo:") is not None:
        return None
    below: Set[str] = set()
    seen: Set[int] = set()
    cur = cls
    while True:
        if cur.vmaddr in seen:                       # a malformed superclass cycle
            return None
        seen.add(cur.vmaddr)
        if any(m.name is None for m in cur.methods):
            return None
        if cur is not cls and cur.get_method("writeTo:") is not None:
            break
        if cur.get_method("readFrom:") is not None:
            # A message the client only reads is defined by its readFrom:, which may read
            # fields the inherited writeTo: never writes: cannot tell.
            return None
        below.update(m.name for m in cur.methods)
        parent = cl.find(cur.superclass_name) if cur.superclass_name else None
        if parent is None:
            return None
        cur = parent
    sent = writeto_sent_selectors(ctx, cur.get_method("writeTo:").imp)
    if sent is None or sent & below:
        return None
    return cur


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

def _refine_int_wire_form(ctx, type_name, type_class, ivar, wt_helpers, walk_writes=None,
                          owner=""):
    """Refine the canonical int default to its true wire form.

    The ivar @encode only records storage width, so int32/uint32/sint32/[s]fixed32
    collapse to int32; the field's writeTo: helper VA selects the wire form.  Refine
    ONLY scalar ints (``type_class is None`` excludes enum ENUM:/message).
    int32<->uint32 stays a genuine tie.  The helper gives the wire WIDTH (fixed32 vs
    fixed64); the SIGN half (fixed vs sfixed) comes from the ivar exactly like
    int32↔uint32 — signed ivar (type_name int32/int64) → sfixed*, unsigned → fixed*.
    See :func:`_classify_write_helper`.

    Which helper carries the wire form depends on how writeTo: writes the field:

    * one tagged value per call — a singular field, or a C-list
      (``{?="list"^<elem>…}``) written UNPACKED (the element writer called per element
      with the real field#): the field-write helper itself (``wt_helpers``);
    * a C-list written PACKED — the walk's write is a length-delimited begin-mark
      (``walk_writes[ivar]['bracket']``, wire type 2, no element family); the wire
      form is that of the no-tag ELEMENT writer called inside the begin/recall bracket
      (``elem_helper_vas``, see :data:`proto.writeto._NO_TAG_FIELD_NUMBER`).  Refined
      only when every element writer in the bracket agrees on one family; none found
      → unchanged.

    Returns ``(type_name, decided)``: the (possibly refined) type, and False when the field
    is a scalar int whose writer shows no encoding (``"unknown"``, or packed element writers
    that disagree) -- int / sint / fixed are then not told apart and the field is flagged.
    Non-int types are unchanged and decided."""
    if type_class is not None or type_name not in ("int32", "int64", "uint32", "uint64"):
        return type_name, True
    w = (walk_writes or {}).get(ivar.name) or {}
    if not w.get('bracket'):
        fams = {_classify_write_helper(ctx, wt_helpers.get(ivar.name))}
    else:
        fams = {_classify_write_helper(ctx, va) for va in w.get('elem_helper_vas', ())}
    if len(fams) != 1 or "unknown" in fams:
        return type_name, False
    return _refine_scalar_by_family(type_name, fams.pop(), f"{owner}.{ivar.name}"), True


def _repeated_encoding(ivar, walk_writes):
    """How ``writeTo:`` writes a repeated scalar/enum C-list ivar (``{?="list"^<elem>…}``):
    ``"PACKED"`` when the walk saw one length-delimited begin/recall bracket around no-tag
    element writes (``walk_writes[ivar]['bracket']``), ``"EXPANDED"`` when it saw the
    element writer called with the field's own number (one tag per element), ``"UNSEEN"``
    when the walk saw no write of the ivar, None when the ivar is not a C-list.  The
    emitter declares the encoding from this, instead of edition 2023's PACKED default."""
    if not _is_packed_list_enc(ivar.type_enc):
        return None
    w = (walk_writes or {}).get(ivar.name)
    if not w:
        return "UNSEEN"
    return "PACKED" if w.get('bracket') else "EXPANDED"


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
    metaclass, string_helper, wt_helpers,
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

    _rr = _resolve_repeated_field_type(
        ivar, pname, metaclass, cl, ctx, string_helper, wt_helpers,
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
    _proto_class_names = _proto_class_set(ctx, cl)
    if cls.name not in _proto_class_names and not _is_proto_class(cls):
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
        cls.name not in _proto_class_names
        or cls.name in (getattr(ctx, "_proto_class_heuristic_only", None) or frozenset()))
    _class_detected_by_va_cluster = cls.name in (
        getattr(ctx, "_proto_class_cluster_only", None) or frozenset())

    # No writeTo: of its own: the ancestor's writeTo: serialises this class and cannot
    # reach its own ivars, so none of them is a wire field (they used to be emitted with
    # ivar-order "estimated" numbers that collide with the parent's real fields).
    _writer_owner = _inherited_writeto_owner(ctx, cl, cls)
    if _writer_owner is not None:
        return ProtoMessage(
            name=_class_to_proto_name(cls.name, _pfx),
            class_name=cls.name,
            inherits_from=_inherits_from,
            serialised_by=_class_to_proto_name(_writer_owner.name, _pfx),
            class_detected_by_heuristic=_class_detected_by_heuristic,
            class_detected_by_va_cluster=_class_detected_by_va_cluster,
        )

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
    record_helper_votes(ctx, field_ivars, _wt_helpers, _proto_class_names)

    # ── Principled repeated-<message> element types (readFrom: dispatch) ───────
    dispatch_elements, dispatch_ivars, _dispatch_unambiguous = _resolve_dispatch_context(
        ctx, cls, readfrom_core_index, field_ivars)

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
        type_name, _int_decided = _refine_int_wire_form(ctx, type_name, type_class, ivar,
                                                        _wt_helpers, _walk_writes, owner=cls.name)

        # Mode A enum-fallback debug: an untagged int field whose xAsString: selector exists
        # somewhere in the image (evidence of an enum this class's methods did not show).
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
            metaclass=metaclass,
            string_helper=_string_helper, wt_helpers=_wt_helpers,
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
        if not _type_note and not _int_decided:
            _type_note = INT_ENCODING_NOTE
        if not _type_note:
            _type_note = _opaque_object_note(ivar, type_class)

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
            repeated_encoding=_repeated_encoding(ivar, _walk_writes),
        ))

    # Drop manual-array backing-store ivars (``_xCount``/``_xSpace``) that ObjC
    # keeps for an inline-C-struct array but ``writeTo:`` never serializes — they
    # are not proto fields and would otherwise emit with a bogus ivar-order number
    # (see :func:`_is_backing_store_phantom`; Hopper-verified).
    _ivar_enc_by_pname = {
        _proto_name(iv.name): iv.type_enc for iv in cls.ivars if iv.name}
    fields = [f for f in fields
              if not _is_backing_store_phantom(f, _ivar_enc_by_pname)]

    # Drop estimated fields whose ivar the class's own writeTo: provably never serialises:
    # no value derived from it can reach the PBDataWriter (:mod:`proto.writer_flow`).  Only
    # when that analysis decides the class, and only if it agrees with the walk -- every
    # ivar the walk bound to a field number must be among the reachable ones; otherwise the
    # two disagree and nothing is dropped.
    _writes_no_ivars = False
    if any(not f.number_confirmed for f in fields):
        _reach, _why = writer_reachable_ivars(ctx, cl, cls)
        if _reach is not None and set(confirmed_numbers) <= _reach:
            _ivar_by_pname = {_proto_name(iv.name): iv.name for iv in field_ivars}
            fields = [f for f in fields
                      if f.number_confirmed or _ivar_by_pname.get(f.name) in _reach]
            _writes_no_ivars = not fields
        elif _reach is not None:
            log.warning("%s: writer flow disagrees with the writeTo: walk (%s not reachable);"
                        " estimated fields kept", cls.name,
                        sorted(set(confirmed_numbers) - _reach))
        else:
            log.debug("%s: writer flow undecided (%s); estimated fields kept",
                      cls.name, "; ".join(_why))

    # Annotate (do NOT drop) object ivars whose type does not resolve to a proto
    # message or Foundation type — bare protocols and internal helper classes (locks,
    # KVO trampolines) that may not be real wire fields.  We keep them and flag them
    # so the reader decides (see :func:`_unresolved_object_field_note`).
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
        writes_no_ivars=_writes_no_ivars,
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

    # Reset every per-extraction memoisation cache (each one registers itself when it is
    # created: macho.memory._ctx_cache / _ctx_store), so a BinaryContext reused across two
    # extractions cannot serve stale results.
    reset_ctx_caches(ctx)

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

    # Image-wide pre-passes, built once here (per class would be O(n^2)); a failure is
    # recorded in the run diagnostics and the run continues without it.
    #  * the branch-indegree map + method-IMP set the writeTo: walk needs;
    #  * the string write helper(s), from a class with a confirmed NSString ivar;
    #  * the {ReadAllFrom vmaddr -> class name} index the readFrom: evaluator names
    #    element classes by.
    _ensure_writeto_indegree(ctx, cl)
    string_write_helpers: FrozenSet[int] = _ensure_string_write_helpers(ctx, cl)
    log.debug("String write helpers identified: %s", [hex(h) for h in string_write_helpers])
    readfrom_core_index: Dict[int, str] = _ensure_readfrom_core_index(ctx, cl)
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
        except (NameError, ImportError):
            raise
        except Exception as exc:
            # One bad class must not abort the whole run, but a failure here is
            # a real defect (a decoder that should be robust threw): surface the
            # COUNT loudly so a regression is visible, and the per-class detail
            # at debug for diagnosis.  Normal "not a proto class" cases return
            # None rather than raising, so they are NOT counted here.
            failed.append(cls.name)
            get_diagnostics(ctx).failed_classes.append((cls.name, f"{type(exc).__name__}: {exc}"))
            log.debug("Failed to extract proto for %s: %s", cls.name, exc)
        if msg is not None:
            messages.append(msg)

    if failed:
        log.warning(
            "extract_all: %d proto class(es) failed to extract and are MISSING from "
            "the output (run with -v for per-class detail): %s",
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


def is_proto_class(cls: ObjcClass) -> bool:
    """Public alias for _is_proto_class."""
    return _is_proto_class(cls)


# Public API, plus the extractor-local helpers callers and tests use.
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
]
