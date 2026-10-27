"""proto/protocore — the shared proto-class / ivar / type-encoding kernel.

The small predicate + encoding helpers the dispatch / repeated / enum modules all depend
on.  Imports only ``proto.models`` + ``macho.classlist`` + stdlib -- never
``proto.extractor`` (a cycle); extractor re-imports the surface.

The retired proto-class detectors (``_is_proto_class``, the VA-cluster closure) are in
``proto.protoclass_heuristic`` and fail the run if they ever claim a class.  Here are the
predicates FIELD work uses however the class was detected: ``_is_proto_flags_ivar`` (also
used by ``_is_real_field_ivar`` and ``proto.write_helpers`` to EXCLUDE the has-bits struct from
the field set) and ``_REQUIRED_INSTANCE_METHODS`` (the selectors gate,
``proto.extractor._check_selectors_resolved``).
"""
import re
from typing import Dict, Optional, Set, Tuple

from proto.models import FieldLabel
from macho.classlist import ObjcIvar

#: Instance methods that every Apple ObjC proto message class has.  ``mergeFrom:`` is not
#: one: oneof classes (``GEOPDComponentValue``) and thin wrapper classes
#: (``GEOPDAddressObject``) do not implement it, and still serialise via
#: ``readFrom:``/``writeTo:``.
_REQUIRED_INSTANCE_METHODS: frozenset = frozenset({
    "readFrom:", "writeTo:",
})


def _is_proto_flags_ivar(ivar: ObjcIvar) -> bool:
    """
    Return True if this ivar is the proto has-bits / lazy-load bitfield.

    Apple's proto runtime stores per-field presence bits in a single anonymous
    struct of 1-bit fields.  Two flavours exist:

    * ``has_*`` bits — scalar and string fields, e.g.
      ``{?="has_latitude"b1"has_longitude"b1...}``
    * ``read_*`` bits — lazy-load sentinels for sub-message fields, e.g.
      ``{?="read_unknownFields"b1"read_entityFilter"b1...}``

    Classes with exclusively sub-message fields (e.g. ``GEOPDComponentFilter``,
    ``GEOPDPlaceRequestParameters``) use only ``read_*`` bits, so checking for
    ``has_`` alone is insufficient and causes those classes to be silently missed
    by the ivar-based proto-class detector.

    The match keys on the flags struct's OPENER (``{?="has_…`` / ``{?="read_…``) —
    the proto runtime always names the first presence bit ``has_<field>`` /
    ``read_<field>`` — rather than a loose ``"has_``/``"read_`` substring.  A large
    C-struct ivar (e.g. SymptomNetworkUsage's kernel ``nstat_*`` network-statistics
    structs) can carry a 1-bit bitfield nested several levels deep, such as
    ``{?="probe_activated"b1…"read_probe_failed"b1…}``; the ``"read_`` member there
    would false-match the substring form and mis-flag a plain NSObject class as a
    proto message (which then poisons the VA-cluster closure).  The opener form
    excludes it (that struct opens with ``probe_activated``, not ``has_``/``read_``)
    while still catching a flags struct that sits behind a name.
    """
    enc = ivar.type_enc
    return '{?="has_' in enc or '{?="read_' in enc


#: Apple's proto runtime injects these bookkeeping ivars into every proto class.
#: They have getters/setters like real fields, but they are NOT proto fields and
#: must be excluded from schema extraction.  Including them shifts every real
#: field number and pollutes the output with PBDataReader, PBUnknownFields, etc.
_INTERNAL_PB_IVARS: frozenset = frozenset({
    "_reader",          # @"PBDataReader"
    "_unknownFields",   # @"PBUnknownFields"
    "_readerMarkPos",   # uint32  (I)
    "_readerMarkLength",# uint32  (I)
    "_readerLock",      # os_unfair_lock
})


def _proto_name(ivar_name: str) -> str:
    """Convert an ObjC ivar name to a proto field name (strip leading '_')."""
    return ivar_name.lstrip("_")


# Names that denote the proto has-bits / presence bitfield rather than a real
# field, when it is stored as a plain integer ivar rather than the named-bit
# struct caught by _is_proto_flags_ivar (e.g. '_hasBits', '_has').  Matched on
# the underscore-stripped, lowercased name so '_hasBits' / '_hasBits_' / 'hasBits'
# all collapse to 'hasbits'.
_HAS_BITS_NAMES: frozenset = frozenset({"hasbits", "has"})


def enum_base_name(pname: str) -> str:
    """The enum name the field named *pname* gives (``feedbackType`` -> ``FeedbackType``), as
    the generator spells it in ``StringAsX:``."""
    return pname[:1].upper() + pname[1:]


def enum_selectors(pname: str) -> Tuple[str, str]:
    """The ``xAsString:`` and ``StringAsX:`` selectors the ProtocolBuffer generator gives the
    enum field named *pname* (``feedbackType`` -> ``feedbackTypeAsString:``,
    ``StringAsFeedbackType:``)."""
    return f"{pname}AsString:", f"StringAs{enum_base_name(pname)}:"


def _is_has_bits_name(ivar_name: str) -> bool:
    """True if *ivar_name* is the has-bits bookkeeping ivar by name."""
    return ivar_name.replace("_", "").lower() in _HAS_BITS_NAMES


def _is_real_field_ivar(ivar: ObjcIvar) -> bool:
    """
    Return True if this ivar is a real proto field (not a has-bits bitfield
    or internal bookkeeping ivar).

    Admission is PURE STORAGE SHAPE — selector-independent, so it behaves the
    same whether or not the getter/setter names survived (cache-native classes
    routinely keep only readFrom:/writeTo: boilerplate).  An ivar is a real field
    unless it is one of the two non-field kinds:

    * named bookkeeping ivars — _reader/_unknownFields/_readerMarkPos/
      _readerMarkLength/_readerLock (``_INTERNAL_PB_IVARS``) and the plain-integer
      has-bits ivar (``_is_has_bits_name``);
    * the proto has-bits / lazy-load bitfield struct (``_is_proto_flags_ivar`` —
      the ``{?="has_…"b1…}`` / ``{?="read_…"b1…}`` form).
    """
    if ivar.name in _INTERNAL_PB_IVARS or _is_has_bits_name(ivar.name):
        return False
    pname = _proto_name(ivar.name)
    if not pname:
        return False
    # Storage-shape only: exclude the has-bits struct; keep all other ivars.
    return not _is_proto_flags_ivar(ivar)


# INTEGER FLAVOUR FROM THE IVAR @encode — a CANONICAL DEFAULT, refine via the helper.
# This map is the type signal available from the ivar alone: the ObjC @encode character,
# which records the *storage* C-type, not the original .proto declaration.  Within a
# storage class proto collapses several declarations onto one ivar:
#   - 'i'/'I' (32-bit), 'q'/'Q' (64-bit): could be int32/uint32/sint32/fixed32/sfixed32
#     (resp. the 64-bit set).  Apple's ObjC even uses signed 'i' for proto uint32/enum.
#   - 'f' (float) vs 'd' (double) ARE distinguishable here by width.
# We emit a canonical default per storage class (signed int32/int64 for 'i'/'q', uint32/
# uint64 for 'I'/'Q').  IMPORTANT — the ivar is NOT the only signal: the field's
# writeTo:/readFrom: HELPER encodes the *wire* form, which DOES separate the families:
#   - plain varint  (int32 / uint32 / enum / bool)  -> one helper  [the ambiguous case]
#   - ZIGZAG varint (sint32 / sint64)               -> a DISTINCT helper  -> RECOVERABLE
#   - fixed-width   (fixed*/sfixed*)                -> their own helpers  -> RECOVERABLE
# The field's write helper is classified by :func:`proto.write_helpers._classify_write_helper`
# (its code, or a standalone binary's import name) and refines the default in
# extract_proto_message: sint32/sint64, fixed32/fixed64, and int32 vs uint32 (how the plain
# varint helper widens its value).  The SIGN half of fixed32 vs sfixed32 (wire-identical)
# comes from the ivar 'i'/'I'; a field whose writer shows no encoding is flagged.  NOTE the
# inverse is also true: a reference declaring `sint` for a field the binary writes with
# the PLAIN helper is a REFERENCE error — the helper is the wire ground truth (observed:
# GEOMapServiceTraits.sequence_number, plain ac30, ref wrongly says sint32).
_SCALAR_ENC: Dict[str, str] = {
    "i": "int32",  "I": "uint32",
    "l": "int32",  "L": "uint32",
    "q": "int64",  "Q": "uint64",
    "s": "int32",  "S": "uint32",
    "c": "int32",  "C": "uint32",
    "B": "bool",
    "f": "float",
    "d": "double",
}


_CLASS_TO_PROTO: Dict[str, str] = {
    "NSString":           "string",
    "NSMutableString":    "string",
    "NSData":             "bytes",
    "NSMutableData":      "bytes",
}


def _type_from_enc(
    type_enc: str,
    ivar_name: str,
    method_names: Set[str],
) -> Tuple[str, Optional[str]]:
    """
    Return (type_name, type_class_or_None) for an ivar.

    type_name  — proto scalar ('int32', 'bool', 'string', …) or ObjC class name
    type_class — ObjC class name when the field is a message/enum type
    """
    pname = _proto_name(ivar_name)

    if type_enc in _SCALAR_ENC:
        if any(sel in method_names for sel in enum_selectors(pname)):
            # Enum field: return the proto enum type name and an "ENUM:" sentinel
            # so downstream code (emitter, value extractor) can identify it.
            # e.g. ivar "_feedbackType"  →  ("FeedbackType", "ENUM:FeedbackType")
            enum_name = enum_base_name(pname)
            return (enum_name, f"ENUM:{enum_name}")
        return (_SCALAR_ENC[type_enc], None)

    m = re.match(r'^@"([^"]+)"$', type_enc)
    if m:
        cls_name = m.group(1)
        if cls_name in _CLASS_TO_PROTO:
            return (_CLASS_TO_PROTO[cls_name], None)
        return (cls_name, cls_name)

    if type_enc == "@":
        return ("bytes", None)

    if type_enc.startswith("^"):
        inner = type_enc[1:]
        return (_SCALAR_ENC.get(inner, "bytes"), None)

    if _is_packed_list_enc(type_enc):
        # Packed repeated scalar list ``{?="list"^<elem>"count"Q"size"Q}``: the
        # element C-type is named directly by ``<elem>``, so emit the matching
        # proto scalar (``^i`` → int32, ``^q`` → int64, ``^d`` → double, …).  The
        # element is a scalar by construction (a packed C array, never an object
        # array — proto only packs scalars), so this is wire-honest; a non-scalar
        # element (none observed) falls back to ``bytes``.  The field is labelled
        # REPEATED by :func:`_field_label`, and the message/name-suffix resolver is
        # guarded off for these in :func:`extract_proto_message`.
        elem = type_enc[len('{?="list"^'):type_enc.index('"count"')]
        scalar = _SCALAR_ENC.get(elem, "bytes")
        # Packed repeated ENUM: an integer-element list whose field carries an
        # ``xAsString:``/``StringAsX:`` selector is an enum — the same signal used
        # for singular scalar enums above.  Enums are int32 on the wire, so this
        # only recovers the type *name* (the int decode is already wire-correct);
        # the value pairs are extracted by _collect_enum_definitions, which reverts
        # to the scalar if no usable xAsString: method resolves.
        if scalar in ("int32", "uint32", "int64", "uint64") and any(
                sel in method_names for sel in enum_selectors(pname)):
            enum_name = enum_base_name(pname)
            return (enum_name, f"ENUM:{enum_name}")
        return (scalar, None)

    return ("bytes", None)


def _is_packed_list_enc(enc: Optional[str]) -> bool:
    """True if *enc* is Apple's packed-repeated C-array struct
    ``{?="list"^<elem>"count"Q"size"Q}`` — the storage emitted for a packed
    repeated scalar/enum field, for any element type (``^i ^I ^q ^Q ^f ^d ^B`` …).

    This is a ground-truth, **selector-independent** signal: it works in
    cache-native mode where the ``add…:``/``…Count`` selectors are stripped, and it
    covers element types the name-construction path misses.  It is unambiguous —
    the has-bits/presence ivar is a different shape (``{?="has_X"b1…}``); verified
    binary-wide that zero packed-list ivars also match :func:`_is_proto_flags_ivar`.
    """
    return bool(enc) and enc.startswith('{?="list"^') and '"count"Q"size"Q}' in enc


def _field_label(
    ivar: ObjcIvar,
) -> FieldLabel:
    """Determine the proto label for a field from the ivar's STORAGE SHAPE.

    Repeated-ness is decided entirely by the ivar's ``@encode`` — a
    selector-independent signal that works even when the ``add…:``/``…Count``
    accessors are stripped (cache-native) or singularised (``estimates`` →
    ``addEstimate:``).  Three storage forms back a repeated field; everything
    else is singular (the only meaningful distinction here — Apple PBCodable
    fields are all optional-presence, and ``FieldLabel.REQUIRED`` is never used):

    1. packed scalar/enum C-array  ``{?="list"^<elem>"count"Q"size"Q}``;
    2. inline-C-struct array  ``^{<Struct>=…}`` — a pointer-to-struct ivar is a
       heap buffer of fixed-layout struct elements (count + buffer + per-element
       writeTo loop, bracketed by the length-delimited helpers).  A *singular*
       fixed struct is stored by VALUE (``{UInt128=QQ}``), never by pointer, so
       ``^{`` unambiguously denotes a repeated field (TODO #60, Hopper-confirmed
       on GEOResource._regions / GEOCoarseLocationRing._points; the element type
       stays ``bytes`` per #37 / LIMITATIONS.md (2));
    3. object array  ``@"NSArray"`` / ``@"NSMutableArray"``.

    A label is never read off a selector's spelling (``add<X>:`` / ``has<X>``): an inline
    C-struct repeated field has no ``add…:`` accessor.
    """
    enc = ivar.type_enc
    if _is_packed_list_enc(enc):
        return FieldLabel.REPEATED
    if enc.startswith("^{"):
        return FieldLabel.REPEATED
    if enc in ("@\"NSArray\"", "@\"NSMutableArray\""):
        return FieldLabel.REPEATED
    return FieldLabel.OPTIONAL
