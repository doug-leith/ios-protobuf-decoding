"""
proto/models.py — Data models for extracted protobuf descriptors.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


# ── Shared helper ─────────────────────────────────────────────────────────────

def _enum_prefix(name: str) -> str:
    """
    Convert a CamelCase enum name to its SCREAMING_SNAKE_CASE value prefix.

    Examples::
        "FeedbackType"  →  "FEEDBACK_TYPE"
        "HTTPMethod"    →  "HTTP_METHOD"
        "APSession"     →  "AP_SESSION"
        "RouteRequest"  →  "ROUTE_REQUEST"
    """
    s = re.sub(r'([A-Z]+)([A-Z][a-z])', r'\1_\2', name)
    s = re.sub(r'([a-z\d])([A-Z])', r'\1_\2', s)
    return s.upper()


# ── Enum models ───────────────────────────────────────────────────────────────

#: Emitted above an enum whose value-string method overran the disassembler's
#: instruction budget, so values encoded past the cap could not be recovered.
#: Unlike a sparse-enum gap (an undefined value), this is a *tool* limit — the
#: missing values exist in the binary but were not read.  See SCAN_CAP_CONSTANTS_ANALYSIS.md.
_ENUM_TRUNCATED_COMMENT = (
    "// WARNING: values may be INCOMPLETE — the value-string method exceeded the "
    "disassembly budget; values beyond the cap were not recovered."
)


@dataclass
class ProtoEnumValue:
    """One value within a proto3 enum."""
    name:   str   # SCREAMING_SNAKE_CASE, e.g. "FEEDBACK_TYPE_UNKNOWN"
    number: int   # numeric value
    comment: Optional[str] = None  # Inline `//` note emitted after the value.
                                   # Used by the emitter for two cosmetic, wire-
                                   # neutral fix-ups: a synthesized proto3 zero
                                   # value (PBCodable enums start at 1), and a
                                   # package-scope de-collision rename (proto's
                                   # C++ enum-value scoping forbids two enums in
                                   # one package sharing a value name).  Value
                                   # NAMES never appear on the wire — only the
                                   # numbers do — so both are purely cosmetic.

    def __repr__(self) -> str:
        return f"ProtoEnumValue({self.name} = {self.number})"


@dataclass
class ProtoEnum:
    """
    One proto3 enum, recovered from an ObjC xAsString: method.

    When *values* is empty the enum could not be extracted from the binary;
    a placeholder ``UNKNOWN = 0`` value is emitted with a comment.
    """
    name:             str                   # e.g. "FeedbackType"
    values:           List[ProtoEnumValue]  # may be empty if not recovered
    values_confirmed: bool = False          # True when cleanly extracted from binary
    values_truncated: bool = False          # True when the value-string method was
                                            # cut off at the disassembler's
                                            # instruction budget: values encoded
                                            # past the cap are missing, so the set
                                            # below may be incomplete.
    collision_origin: Optional[str] = None  # When the RECONSTRUCTED type name
                                            # collided with a message (or other
                                            # enum) of the same name in the
                                            # package, the emitter renames this
                                            # enum and records the original
                                            # colliding name here so the output
                                            # can explain the rename.  Cosmetic:
                                            # enum type names never hit the wire.

    def to_proto(self) -> str:
        """Emit an enum block (proto3 syntax)."""
        lines: List[str] = []
        if self.values_truncated:
            lines.append(_ENUM_TRUNCATED_COMMENT)
        lines.append(f"enum {self.name} {{")
        if not self.values:
            placeholder = f"{_enum_prefix(self.name)}_UNKNOWN"
            lines.append(f"  {placeholder} = 0;  // values not recovered from binary")
        else:
            ordered = sorted(self.values, key=lambda x: x.number)
            # proto3 requires the FIRST listed value to be 0.  Negative values
            # are legal but may not lead, so a zero entry (real or the
            # emitter-synthesized one) is moved to the front; the rest keep
            # numeric order.  Order is cosmetic — only field numbers are on the
            # wire — but it is what lets protoc accept enums like {-1, 0, 1}.
            zero = [v for v in ordered if v.number == 0]
            rest = [v for v in ordered if v.number != 0]
            for v in zero + rest:
                cmt = f"  // {v.comment}" if v.comment else ""
                lines.append(f"  {v.name} = {v.number};{cmt}")
        lines.append("}")
        return "\n".join(lines)

    def __repr__(self) -> str:
        conf = "✓" if self.values_confirmed else "~"
        trunc = "…" if self.values_truncated else ""
        return f"ProtoEnum({self.name!r}{conf}{trunc}, {len(self.values)} values)"


# ── Field / Message models ────────────────────────────────────────────────────

class FieldLabel(str, Enum):
    OPTIONAL = "optional"
    REPEATED = "repeated"
    REQUIRED = "required"


@dataclass
class ProtoField:
    """One field in a proto message."""
    name:             str
    number:           int
    type_name:        str           # proto scalar ('int32', 'bool', 'string', …),
                                    # a message class name ('GEOSessionID'), or
                                    # an enum name ('FeedbackType')
    label:            FieldLabel
    type_class:       Optional[str] = None   # ObjC class name or "ENUM:<EnumName>"
    number_confirmed: bool = False           # True  → dispatch-table derived
                                             # False → ivar-order estimate
    unresolved_type_class: Optional[str] = None
    # Set by proto.emitter.resolve_type_refs() when the ObjC class named in
    # type_class could not be matched to an extracted proto message.
    # type_name is set to "bytes" as a fallback; this field retains the
    # original ObjC class name for inline comment output.

    disambiguation_comment: Optional[str] = None
    # Set when an xAsString: method was detected in __objc_methname but
    # its implementation could not be identified unambiguously (multiple
    # type-compatible candidates, none with a discriminating value prefix).
    # The field is emitted as its raw scalar type (int32/uint32) with this
    # comment so the user knows to re-run with --cache.

    type_inference_note: Optional[str] = None
    # Set when the field's TYPE was chosen by a name-based heuristic rather than
    # a structural/binary signal — i.e. it is an unverified guess.  Emitted as an
    # inline `//` comment so the user is alerted to the increased chance of error
    # and pointed at the documentation (see proto.extractor and
    # FIELD_TYPE_INFERENCE.md).  Distinct from number_confirmed, which is about
    # the field NUMBER, not its type.

    ref_package: Optional[str] = None
    # Proto package of the referenced message/enum type, when already resolved by
    # a foreign-serializer adapter (proto.foreign).  PBCodable resolves cross-
    # package references through type_class + class_to_pkg; foreign descriptors
    # (e.g. C++ libprotobuf, whose schema spans many packages) carry the package
    # here instead, since their type_name is a flat per-package identifier.  When
    # set and different from the emitting file's package, the emitter qualifies
    # the type (``pkg.Type``) and adds the import; same-package leaves it flat.

    ref_file: Optional[str] = None
    # Output .proto FILENAME that declares the referenced type, when resolved by
    # a foreign adapter that emits one file per ORIGINAL source file (proto.
    # foreign C++).  Qualification is by PACKAGE (ref_package), but imports are by
    # FILE: a single package may span several source files, so a same-package
    # reference can still need an import.  When set and different from the
    # emitting file's filename, the emitter adds ``import "<ref_file>";``.

    map_key_type: Optional[str] = None
    # Set (with map_value_type) when this field is a recovered protobuf ``map<K, V>``
    # (proto.mapfields): the proto key type ('string', 'int32', …).  The emitter then
    # renders ``map<K, V>`` — a map field is never ``repeated`` in the source — instead of
    # the field's ObjC type.  type_class stays the ObjC container class (NSMutableDictionary).
    map_value_type: Optional[str] = None
    # Proto value type: a scalar / 'string' / 'bytes', or — for a message value — the proto
    # message name, filled in by proto.emitter.resolve_type_refs from map_value_class.
    map_value_class: Optional[str] = None
    # ObjC class of a message-valued map's value; resolved to a proto message by the
    # emitter (falls back to value type 'bytes' + unresolved_type_class, as for any
    # message field whose class was not extracted).

    def __repr__(self) -> str:
        conf = "✓" if self.number_confirmed else "~"
        return (f"ProtoField({self.number}{conf} {self.label.value} "
                f"{self.type_name} {self.name})")


# Emitted in place of "// (no fields recovered)" for an opaque-passthrough
# message (see ProtoMessage.opaque_passthrough) so a reader can tell a class with
# NO typed fields BY DESIGN apart from one whose fields we merely failed to
# recover.  Shared by ProtoMessage.to_proto and proto.emitter so the two paths
# never drift.
OPAQUE_PASSTHROUGH_COMMENT = (
    "// opaque passthrough — serializes only PBUnknownFields "
    "(no typed fields in this build)"
)

# Both of the following are ERRORS, not footnotes.  Proto-class detection is
# supposed to be structural: a class is a protobuf message because its ObjC
# superclass chain reaches PBCodable/PBRequest/PBResponse/PBMessage.  That walk
# alone reproduces the full class set on every corpus ever measured, in BOTH cache
# and standalone-binary mode (see heuristic_registry.py 'protoclass').  So if a
# class reaches the output via either non-structural path below, the structural
# detector has failed on it and this message's very presence in the schema is a
# guess — the reader must not trust it without checking the binary.
HEURISTIC_CLASS_DETECTION_COMMENT = (
    "// ERROR: this class was identified as a protobuf message ONLY by the "
    "_is_proto_class heuristic (ivar/method scoring) — its ObjC superclass chain "
    "does NOT reach PBCodable, which should never happen; the class may not be a "
    "protobuf message at all and must not be trusted "
    "(see heuristic_registry.py 'protoclass')"
)

VA_CLUSTER_CLASS_DETECTION_COMMENT = (
    "// ERROR: this class was identified as a protobuf message ONLY by the "
    "heuristic-seeded VA-cluster closure (shared superclass VAs) — its ObjC "
    "superclass chain does NOT reach PBCodable by name, which should never happen; "
    "the class may not be a protobuf message at all and must not be trusted "
    "(see heuristic_registry.py 'protoclass-gate')"
)


@dataclass
class ProtoMessage:
    """One proto message, recovered from a single ObjC class."""
    name:       str
    class_name: str          # original ObjC class name
    fields:     List[ProtoField] = field(default_factory=list)
    enums:      List[ProtoEnum]  = field(default_factory=list)
    # Enum definitions inlined by this message (emitted at file scope).
    # Each entry is a unique enum whose type_class is "ENUM:<name>".
    # True when -[cls _dictionaryRepresentation:] disassembly hit the budget cap,
    # so dictRep enum recovery may be incomplete and some int32 fields below may
    # actually be enums.  Emitted as a class-level WARNING comment.
    enum_recovery_truncated: bool = False
    # Proto message name of the parent class when this message is an ObjC subclass
    # of ANOTHER proto message (not the PBCodable/PBRequest base) — TODO #46.  The
    # ObjC subclass carries only its OWN field ivars, so the fields shown below are
    # incomplete: it also inherits the parent's.  Emitted as a class-level comment.
    # (Inherited fields are flagged but not merged — see LIMITATIONS.md (5), #50.)
    inherits_from: Optional[str] = None
    # True when this class is a zero-typed-field OPAQUE PASSTHROUGH: a PBCodable
    # subclass whose only ivar is the inherited ``_unknownFields`` bag and whose
    # ``writeTo:`` simply loads it and tail-calls ``writeTo:`` on it.  Such a
    # message has NO own wire fields BY DESIGN — "no fields recovered" here is
    # GROUND TRUTH, not an extraction miss — so it is flagged distinctly (see
    # :func:`proto.extractor._is_opaque_passthrough` and
    # notes/REVGEO_OPAQUE_PASSTHROUGH_2026-06-17.md).
    opaque_passthrough: bool = False
    # Which protobuf serializer/runtime this message was recovered from.  The
    # default is Apple's ObjC PBCodable (the tool's primary path); messages
    # adapted from other runtimes (C++ libprotobuf, swift-protobuf) set their
    # own label so the emitter can attribute provenance in the output.
    serializer: str = "Apple PBCodable (ObjC)"
    # Explicit package override.  PBCodable messages leave this None and are
    # grouped by package_for_class(class_name); messages adapted from other
    # runtimes carry their own package (the C++ FileDescriptor package or the
    # Swift module) so they group into their own .proto file regardless of the
    # ObjC-prefix heuristic.
    package: Optional[str] = None
    # Explicit OUTPUT-FILE override.  When set, build_proto_files emits this
    # message into a file of this exact name instead of one-file-per-package.
    # Used by the C++ adapter (proto.foreign) to emit one file per ORIGINAL
    # source ``.proto`` so the schema's acyclic import structure is preserved
    # (merging a package's several source files can create an import cycle protoc
    # rejects).  PBCodable / swift leave this None and group by package as before.
    out_file: Optional[str] = None
    # True when this class's PROTO-NESS ITSELF (not any field) rests solely on the
    # per-class _is_proto_class heuristic (ivar/method scoring) — i.e. NEITHER
    # structural anchor in _proto_class_set confirmed it.  Measured empirically to
    # be extremely rare (0/1642 GeoServices, 0/391 across a 258-binary corpus — see
    # heuristic_registry.py 'protoclass'); emitted as an ERROR whenever it does
    # happen, because this message's presence in the output is then a guess rather
    # than a structural fact.
    class_detected_by_heuristic: bool = False
    # As above, but for the OTHER non-structural path: the class was pulled in by
    # _proto_class_set's heuristic-seeded VA-cluster closure (anchor 2) and the
    # by-name superclass-chain walk (anchor 1) never confirmed it.  Also an ERROR.
    class_detected_by_va_cluster: bool = False

    def __repr__(self) -> str:
        return f"ProtoMessage({self.name!r}, {len(self.fields)} fields, {len(self.enums)} enums)"


__all__ = [
    "FieldLabel",
    "ProtoField",
    "ProtoMessage",
    "ProtoEnum",
    "ProtoEnumValue",
    "_enum_prefix",
]
