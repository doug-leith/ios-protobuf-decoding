"""
proto/emitter.py — Build valid .proto files (edition 2023) from extracted ProtoMessage objects.

Pipeline
--------
    messages = extract_all(ctx, st, cl)            # List[ProtoMessage]
    proto_files = build_proto_files(messages, ...)  # List[ProtoFile]
    written = write_proto_files(proto_files, Path("./protos"))

Or as a single call:
    written, proto_files = write_from_messages(messages, Path("./protos"),
                                               source_name="GeoServices")

Cross-reference resolution
--------------------------
Field type_name values that are ObjC class names (e.g. "GEOSessionID") are
resolved to proto message names ("SessionID") when the class was extracted.
Unresolved classes (C structs, external libs) fall back to "bytes" with the
original ObjC class name preserved in ProtoField.unresolved_type_class for
comment output.  ObjC container builtins (NSArray etc.) fall back to "bytes"
silently.

Package grouping
----------------
Messages are split by ObjC prefix into separate .proto files:

    GEO*   →  package "geo"    →  geo.proto
    CLP*   →  package "clp"    →  clp.proto
    CLM*   →  package "clm"    →  clm.proto
    CLN*   →  package "cln"    →  cln.proto
    other  →  package "other"  →  other.proto

Cross-package type references (e.g. a "geo" message that references a "clp"
class) generate import statements and are qualified in the emitted proto
(e.g. ``clp.Location``).
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field, replace
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Set, Tuple

from proto.config import matching_prefix
from proto.defaults import DEFAULT_PREFIXES

from proto.models import (
    FieldLabel, ProtoField, ProtoMessage, ProtoEnum, ProtoEnumValue,
    OPAQUE_PASSTHROUGH_COMMENT, HEURISTIC_CLASS_DETECTION_COMMENT,
    VA_CLUSTER_CLASS_DETECTION_COMMENT, _enum_prefix, PACKABLE_SCALARS as _PACKABLE_SCALARS,
)

_GENERATOR = "apple_protobuf_extractor (ios_protobuf_decoding)"

class InputKind(Enum):
    """What the run extracted from.  It decides what an enum field left unresolved means:
    a dyld-cache image and a standalone executable carry every selector and value string
    the tool reads, so one is a tool bug (an ERROR, and a non-zero exit); a binary-only
    dylib may need string data that lives in the cache, outside the file (a note)."""
    DYLIB = "binary-only dylib"
    EXECUTABLE = "standalone executable"
    CACHE_IMAGE = "dyld cache image"

    @property
    def self_contained(self) -> bool:
        return self is not InputKind.DYLIB


#: One-time explanatory note emitted once above the enum section.  Apple's
#: protobuf enums compile to plain C enums, whose *type* name leaves no symbol
#: in the (stripped) binary — so each enum's name is reconstructed from the
#: SCREAMING_SNAKE prefix of its value strings.  This can be cosmetically wrong
#: (e.g. acronym casing) but is harmless: enum type names never appear on the
#: wire and do not affect values, numbers, decoding, or compilation.
#: Accepted limitation — see LIMITATIONS.md (6), to-do #57.
_ENUM_NAME_RECON_HEADER: tuple = (
    "// NOTE: enum *type* names below are RECONSTRUCTED, not read from the binary.",
    "// Apple's proto enums are plain C enums whose type name leaves no symbol in",
    "// the stripped cache, so each name is inferred from the common prefix of its",
    "// value strings. A name may therefore be inexact (e.g. acronym casing). This",
    "// is harmless: enum type names never appear on the wire and have no effect on",
    "// values, numbers, decoding, or compilation. The value labels and numbers ARE",
    "// reliable. Details: ENUM_TYPE_NAMES.md",
)

#: Terse per-enum reminder (one line) pointing back at the header / doc.
_ENUM_NAME_RECON_NOTE: str = (
    "// type name reconstructed from value-string prefix; may be inexact "
    "(cosmetic only) — see ENUM_TYPE_NAMES.md"
)

#: Note emitted above the `package` line.  The proto package name is not stored
#: in the binary (only bundle IDs / queue labels exist, with no link to the
#: message classes), so it is reconstructed from the class-name prefix.  A wrong
#: package is harmless — it only namespaces the output.  See PACKAGE_NAMES.md.
_PACKAGE_RECON_NOTE: str = (
    "// package reconstructed from the ObjC class-name prefix (not stored in the "
    "binary); may be inexact, harmless — see PACKAGE_NAMES.md"
)


#: All proto3 scalar / built-in type names.
_KNOWN_SCALAR_TYPES: frozenset = frozenset({
    "int32", "int64", "uint32", "uint64",
    "sint32", "sint64", "bool",
    "fixed64", "sfixed64", "double",
    "fixed32", "sfixed32", "float",
    "string", "bytes",
})

#: ObjC Foundation container / root classes whose proto equivalent is "bytes": converted
#: without an unresolved_type_class annotation (the fields that need one -- an unresolved
#: map, or a type naming no wire type such as NSNumber -- are noted at extraction).
_OBJC_BUILTINS: frozenset = frozenset({
    "NSArray", "NSMutableArray",
    "NSDictionary", "NSMutableDictionary",
    "NSObject", "NSNumber", "NSValue",
    "NSData", "NSMutableData",
    "NSString", "NSMutableString",
})


#: Matches the ObjC class-name prefix: the leading all-caps run that ends
#: just before the first CamelCase word (e.g. "GEOPD" from "GEOPDPlace",
#: "APPL" from "APPLFoo", "CLP" from "CLPLocation").
_OBJC_PREFIX_RE = re.compile(r'^([A-Z]{2,})(?=[A-Z][a-z])')


def package_for_class(class_name: str, prefixes: Sequence[str] = ()) -> str:
    """
    Return the proto package name for an ObjC class name.

    A known prefix -- :data:`~proto.defaults.DEFAULT_PREFIXES` and the run's own
    *prefixes* (``--prefix``) -- maps to its lowercase form (e.g. ``GEO`` → ``"geo"``),
    the first that matches at a word boundary winning (:func:`proto.config.matching_prefix`).
    If none matches, auto-derives the package from the ObjC class-name prefix: the leading all-caps run before the first
    CamelCase word, lowercased (e.g. ``"APPLFoo"`` → ``"appl"``) — every
    standard ObjC class name has one, so no catch-all fallback is needed.

    The proto package is never stored in the binary (no ``GPBDescriptor`` to
    read it from — Apple's GEOPD/PB classes use a custom readFrom:/writeTo:
    runtime), so this is reconstructed from the class-name prefix, the only
    available signal.  A wrong result only affects the emitted ``package``
    line and cross-package qualification, and is otherwise harmless — same
    risk profile as the enum type name (see
    :func:`proto.enums._enum_name_from_pairs`).  Full rationale:
    notes/PACKAGE_NAMES.md.
    """
    prefix = matching_prefix(class_name, (*DEFAULT_PREFIXES, *prefixes))
    if prefix:
        return prefix.lower()
    # Auto-derive from the class name itself.
    m = _OBJC_PREFIX_RE.match(class_name)
    if m:
        return m.group(1).lower()
    # Last resort for names without a recognisable prefix (e.g. plain
    # CamelCase with no all-caps run).  Lowercase the whole name so output
    # is still deterministic rather than raising.
    return class_name.lower() if class_name else "unknown"


# ── Cross-reference resolution ─────────────────────────────────────────────────

def resolve_type_refs(messages: List[ProtoMessage]) -> None:
    """
    Resolve ObjC class names in field type_name to proto message names.

    For each field whose type_class is set:
    - If the class was extracted as a ProtoMessage → type_name = proto name
    - If it is a known ObjC builtin/container → type_name = "bytes" (silently)
    - Otherwise (C struct, external lib) → type_name = "bytes",
      ProtoField.unresolved_type_class = original ObjC class name

    Idempotent: safe to call multiple times.
    """
    class_to_msg: Dict[str, ProtoMessage] = {m.class_name: m for m in messages}

    for msg in messages:
        for fld in msg.fields:
            if fld.map_key_type is not None:
                # Recovered map<K, V> (proto.mapfields): only a message VALUE needs
                # resolving, from its ObjC class to the extracted proto message.  A value
                # class that was not extracted degrades to `bytes` (wire-identical:
                # length-delimited), flagged like any unresolved message field.
                if fld.map_value_class is not None:
                    value_msg = class_to_msg.get(fld.map_value_class)
                    if value_msg is not None:
                        fld.map_value_type = value_msg.name
                        fld.unresolved_type_class = None
                    else:
                        fld.map_value_type = "bytes"
                        fld.unresolved_type_class = fld.map_value_class
                continue
            if fld.type_class is None:
                continue  # scalar field — nothing to resolve
            if fld.type_name in _KNOWN_SCALAR_TYPES:
                continue  # already a valid proto scalar
            if fld.unresolved_type_class is not None:
                continue  # already processed (idempotent guard)
            if fld.type_class.startswith("ENUM:"):
                continue  # enum field — type_name is already the enum name

            if fld.type_class in _OBJC_BUILTINS:
                # NSArray, NSData, etc. → bytes.  Unresolved maps and NSNumber / NSValue /
                # NSObject fields are flagged at extraction (_MAP_FIELD_NOTE,
                # _OPAQUE_OBJECT_NOTE); see LIMITATIONS.md (1).
                fld.type_name = "bytes"
                continue

            resolved = class_to_msg.get(fld.type_class)
            if resolved is not None:
                # Resolved: replace ObjC class name with proto message name
                fld.type_name = resolved.name
            else:
                # Unresolved: mark for comment output, fall back to bytes
                fld.unresolved_type_class = fld.type_class
                fld.type_name = "bytes"


def referenced_message_class(fld: ProtoField) -> Optional[str]:
    """The ObjC class *fld* refers to AS A MESSAGE — the class :func:`resolve_type_refs`
    looks up among the extracted messages (a map's value class, else a non-enum, non-builtin
    ``type_class``) — or None.  Valid before and after resolution."""
    if fld.map_key_type is not None:
        return fld.map_value_class
    if fld.type_class is None or fld.type_class.startswith("ENUM:"):
        return None
    if fld.type_class in _OBJC_BUILTINS:
        return None
    if fld.type_name in _KNOWN_SCALAR_TYPES and fld.unresolved_type_class is None:
        return None                     # a scalar the class maps to (NSString → string)
    return fld.type_class


# ── Enum-compatibility helpers ─────────────────────────────────────────────────

def _enums_compatible(a: ProtoEnum, b: ProtoEnum) -> bool:
    """
    Return True if *a* and *b* could represent the same protobuf enum type.

    Two enum instances are **compatible** (and thus mergeable into a single
    file-scope definition) when they have no *conflicting assignments*: every
    integer value that appears in *both* enums must map to the *same* name.

    One enum being a strict subset of the other is always compatible — this is
    the normal situation when a simple class only exercises a subset of the
    full enum range.

    Empty enums (no values recovered from the binary) are compatible with
    everything: we simply have no information to detect a conflict.

    Examples::

        {0: STATUS_SUCCESS, 1: STATUS_FAILED}  ↔  {0: STATUS_SUCCESS, 1: STATUS_FAILED, 5: STATUS_INVALID_REQUEST}
        → compatible (same values at shared indices 0 and 1)

        {0: STATUS_UNKNOWN_FAILURE, 1: STATUS_SUCCESS}  ↔  {0: STATUS_SUCCESS, 1: STATUS_FAILED}
        → INCOMPATIBLE (index 0 maps to different names; index 1 maps to different names)
    """
    if not a.values or not b.values:
        return True   # empty enum is vacuously compatible
    a_map = {v.number: v.name for v in a.values}
    b_map = {v.number: v.name for v in b.values}
    return all(a_map[n] == b_map[n] for n in set(a_map) & set(b_map))


def _best_in_compat_group(
    group: List[Tuple[ProtoEnum, ProtoMessage]],
) -> ProtoEnum:
    """
    Pick the most informative enum representative from a *compatible* group.

    Priority:
      1. ``values_confirmed=True``   (extracted from a clean pointer table)
      2. Most enum values            (richer definition)
      3. First occurrence            (messages are sorted alphabetically;
                                      order is therefore deterministic)
    """
    return max(
        (e for e, _ in group),
        key=lambda e: (e.values_confirmed, len(e.values)),
    )



# A repeated scalar C-list no writeTo: write binds: its wire encoding
# is unknown, and the file's edition default (PACKED) is only a default.
_REPEATED_ENCODING_UNSEEN_NOTE = (
    "packed/expanded not read from writeTo: (declared PACKED by the edition default)")


def _is_packable(fld: ProtoField, type_str: str) -> bool:
    """True for a field whose (resolved) type protobuf can pack: a numeric/bool scalar or
    an enum."""
    return (type_str in _PACKABLE_SCALARS
            or bool(fld.type_class and fld.type_class.startswith("ENUM:")))


# ── ProtoFile data model ───────────────────────────────────────────────────────

@dataclass
class ProtoFile:
    """
    A single .proto file — content, metadata, and emission logic.

    Build via ``build_proto_files()``; do not construct directly.
    """
    package:     str
    filename:    str
    messages:    List[ProtoMessage]
    imports:     List[str]           # sorted list of imported filenames
    source_name: str = ""            # name of the source binary
    # stats — populated by _compute_stats()
    n_confirmed:  int = 0
    n_estimated:  int = 0
    n_unresolved: int = 0            # fields that fell back to bytes (annotated)
    n_enums_incomplete: int = 0      # enums flagged "values may be INCOMPLETE"
    n_ambiguous:  int = 0            # enum fields reverted because their values
                                     # could not be recovered (legacy field name;
                                     # surfaced in output as "unresolved enum type")
    # ObjC class name -> package of EVERY message in the run, exactly as build_proto_files
    # grouped them (so in single-file mode every class maps to this file's one package).
    # emit() qualifies cross-package references with it unless given a map explicitly.
    class_to_pkg: Dict[str, str] = field(default_factory=dict)
    input_kind: InputKind = InputKind.DYLIB
    # The file's enum definitions, planned once when the file is built (_collect_enums:
    # merged, split, renamed, zero value added -- the field references it renames are
    # patched then), so emit() only renders.
    enums: List[ProtoEnum] = field(default=None)

    def __post_init__(self) -> None:
        if self.enums is None:
            self.enums = self._collect_enums()

    # ── Emission ──────────────────────────────────────────────────────────────

    def emit(self, class_to_pkg: Optional[Dict[str, str]] = None) -> str:
        """
        Return the full proto3 file content as a string.

        Parameters
        ----------
        class_to_pkg
            Maps ObjC class name → package name for all known classes.
            Used to qualify cross-package type references (e.g. ``clp.Location``).
            If None, the map build_proto_files grouped the messages by is used
            (``self.class_to_pkg``; empty → no qualification).
        """
        ctop = class_to_pkg if class_to_pkg is not None else self.class_to_pkg
        lines: List[str] = []

        # ── File-header comment ───────────────────────────────────────────────
        total = len(self.messages)
        total_fields = self.n_confirmed + self.n_estimated
        pct = _pct_floor(self.n_confirmed, total_fields)
        lines.append(f"// Generated by {_GENERATOR}")
        # Serializer provenance: which protobuf runtime(s) these messages were
        # recovered from.  A single-serializer file (the common case) is fully
        # attributed by this one header line; mixed files additionally tag each
        # message below (see _emit_message).
        serializers = sorted({m.serializer for m in self.messages})
        if serializers:
            lines.append(f"// Serializer: {', '.join(serializers)}")
        if self.source_name:
            lines.append(f"// Source: {self.source_name}")
        lines.append(
            f"// Package: {self.package}  |  "
            f"{total} message{'s' if total != 1 else ''}  |  "
            f"{self.n_confirmed} confirmed field numbers ({pct}%)"
            + (f", {self.n_estimated} ESTIMATED (ivar order, not read from the binary)"
               if self.n_estimated else "")
        )
        external: Dict[str, int] = {}
        for m in self.messages:
            if m.defined_in:
                image = m.defined_in.rsplit("/", 1)[-1]
                external[image] = external.get(image, 0) + 1
        if external:
            n_ext = sum(external.values())
            lines.append(
                f"// Includes {n_ext} message{'s' if n_ext != 1 else ''} defined in other "
                f"images, referenced by messages here: "
                + ", ".join(f"{img} ({n})" for img, n in sorted(external.items())))
        if self.n_enums_incomplete:
            lines.append(
                f"// Note: {self.n_enums_incomplete} enum(s) may have missing values "
                f"(each carries a WARNING comment)"
            )
        if self.n_unresolved:
            lines.append(
                f"// Note: {self.n_unresolved} field(s) with unresolved message "
                f"types emitted as bytes — see inline comments"
            )
        if self.n_ambiguous:
            if self.input_kind is InputKind.CACHE_IMAGE:
                # Should be impossible in cache-native mode (selector names are
                # resolved through the cache); if it happens the cache or the
                # tool is at fault, so word it as an error, not a footnote.
                lines.append(
                    f"// ERROR: {self.n_ambiguous} field(s) with unresolved enum type "
                    f"emitted as int32 despite a shared cache — this should not happen "
                    f"and indicates a tool bug or an incomplete/corrupt cache; the "
                    f"affected fields must not be trusted (see inline comments)"
                )
            elif self.input_kind is InputKind.EXECUTABLE:
                # A standalone executable is self-contained, so an ambiguous enum
                # should be impossible here too — flag it as an error, not a note.
                lines.append(
                    f"// ERROR: {self.n_ambiguous} field(s) with unresolved enum type "
                    f"emitted as int32 in a standalone executable — a self-contained "
                    f"executable carries all its own selector/value data, so this should "
                    f"not happen and indicates a tool bug; the affected fields must not be "
                    f"trusted (see inline comments)"
                )
            else:
                lines.append(
                    f"// Note: {self.n_ambiguous} field(s) with unresolved enum type "
                    f"emitted as int32 — resolving them needs selector/string data that "
                    f"lives in the dyld shared cache, outside this dylib, which --binary "
                    f"mode cannot scan; re-extract with --framework NAME --cache … for the "
                    f"correct types (see inline comments)"
                )
        lines.append("")

        # The recon caveats (package name and enum type names) apply to PBCodable,
        # which is reverse-engineered: packages come from the ObjC class-name
        # prefix and enum type names from value-string prefixes.  Foreign-
        # serializer messages carry an AUTHORITATIVE package and authoritative
        # enum names decoded from the descriptor, so both notes would mislead —
        # suppress them for files that are PURELY foreign.
        foreign_only = bool(self.messages) and all(
            m.package is not None for m in self.messages
        )

        # ── edition preamble ──────────────────────────────────────────────────
        # Edition 2023, not proto3: Apple's classes keep a `_has` bit per scalar and
        # writeTo: writes a set field even when its value is 0/NO/"", so presence is
        # explicit.  proto3 declares implicit presence, and a decoder then drops those
        # wire-present zeros as indistinguishable from absent fields.  Edition 2023's
        # defaults equal proto3's in every other feature (open enums, packed repeated
        # scalars, UTF-8-verified strings), so the field syntax below is unchanged.
        lines.append('edition = "2023";')
        lines.append("")
        if self.package:
            if not foreign_only:
                lines.append(_PACKAGE_RECON_NOTE)
            lines.append(f"package {self.package};")
            lines.append("")
        for imp in self.imports:
            lines.append(f'import "{imp}";')
        if self.imports:
            lines.append("")

        # ── enum blocks ───────────────────────────────────────────────────────
        all_enums = self.enums
        if all_enums:
            lines.append("// ── Enum types ──────────────────────────────────────────────────────────")
            if not foreign_only:
                lines.extend(_ENUM_NAME_RECON_HEADER)
            lines.append("")
            for enum in all_enums:
                if not foreign_only:
                    lines.append(_ENUM_NAME_RECON_NOTE)
                if enum.collision_origin:
                    lines.append(
                        f"// renamed from reconstructed \"{enum.collision_origin}\" "
                        f"to avoid a name collision with the message of that "
                        f"name (enum type names are cosmetic — never on the wire)"
                    )
                lines.extend(enum.to_proto().split("\n"))
                lines.append("")

        # ── message blocks ────────────────────────────────────────────────────
        # When a file holds messages from more than one serializer, tag each
        # message with its source so provenance is unambiguous per-message.
        mixed = len({m.serializer for m in self.messages}) > 1
        for msg in sorted(self.messages, key=lambda m: m.name):
            lines.extend(self._emit_message(msg, ctop, annotate_serializer=mixed))
            lines.append("")  # blank line between messages

        return "\n".join(lines)

    # ── Internal rendering helpers ─────────────────────────────────────────────

    def _emit_message(
        self,
        msg: ProtoMessage,
        class_to_pkg: Dict[str, str],
        annotate_serializer: bool = False,
    ) -> List[str]:
        out = [f"message {msg.name} {{"]
        if annotate_serializer:
            out.append(f"  // serializer: {msg.serializer}")
        if msg.class_detected_by_heuristic:
            out.append("  " + HEURISTIC_CLASS_DETECTION_COMMENT)
        if msg.class_detected_by_va_cluster:
            out.append("  " + VA_CLUSTER_CLASS_DETECTION_COMMENT)
        if msg.inline_struct:
            out.append(f"  // {msg.inline_struct}")
        if msg.defined_in:
            out.append(f"  // defined in {msg.defined_in}"
                       + (f" ({msg.defined_in_via})" if msg.defined_in_via else ""))
        if msg.message_note:
            out.append(f"  // {msg.message_note}")
        if msg.inherits_from:
            out.append(f"  // inherits all fields from {msg.inherits_from} "
                       "(ObjC subclass — parent fields not repeated here)")
        if msg.enum_recovery_truncated:
            out.append("  // WARNING: enum recovery may be INCOMPLETE "
                       "(_dictionaryRepresentation: disassembly budget exceeded); "
                       "some int32 fields may actually be enums")
        if msg.serialised_by:
            out.append(f"  // no writeTo: of its own: serialised by {msg.serialised_by}'s "
                       "writeTo:, which writes only that message's fields (this class's "
                       "own ivars are not wire fields)")
        elif msg.writes_no_ivars and not msg.fields:
            out.append("  // writeTo: serialises none of this class's ivars (no value derived "
                       "from them reaches the PBDataWriter)")
        elif not msg.fields:
            out.append("  " + OPAQUE_PASSTHROUGH_COMMENT
                       if msg.opaque_passthrough
                       else "  // (no fields recovered)")
        for fld in sorted(msg.fields, key=lambda f: f.number):
            if fld.disambiguation_comment:
                out.append(f"  // {fld.disambiguation_comment}")
            out.append("  " + self._emit_field(fld, class_to_pkg))
        out.append("}")
        return out

    def _emit_field(
        self,
        fld: ProtoField,
        class_to_pkg: Dict[str, str],
    ) -> str:
        type_str     = self._resolve_field_type(fld, class_to_pkg)
        label_prefix = "repeated " if fld.label is FieldLabel.REPEATED else ""

        parts: List[str] = []
        if not fld.number_confirmed:
            parts.append("number estimated")
        if fld.unresolved_type_class:
            parts.append(f"unresolved: {fld.unresolved_type_class}")
        if fld.type_inference_note:
            parts.append(fld.type_inference_note)
        options = ""
        if fld.label is FieldLabel.REPEATED and _is_packable(fld, type_str):
            if fld.repeated_encoding == "EXPANDED":
                options = " [features.repeated_field_encoding = EXPANDED]"
            elif fld.repeated_encoding == "UNSEEN":
                parts.append(_REPEATED_ENCODING_UNSEEN_NOTE)
        comment = f"  // {'; '.join(parts)}" if parts else ""

        return f"{label_prefix}{type_str} {fld.name} = {fld.number}{options};{comment}"

    def _resolve_field_type(
        self,
        fld: ProtoField,
        class_to_pkg: Dict[str, str],
    ) -> str:
        """
        Return the emit-ready type string.

        For cross-package message references, prepend the package qualifier
        (e.g. ``clp.Location`` when emitting into the ``geo`` package).
        Enum types are always in the same file — no qualification needed.
        """
        # Recovered map<K, V> (proto.mapfields): the value is a scalar/string/bytes
        # name, or a proto message qualified like any other message reference.
        if fld.map_key_type is not None:
            value = fld.map_value_type or "bytes"
            if fld.map_value_class and fld.unresolved_type_class is None:
                ref_pkg = class_to_pkg.get(fld.map_value_class)
                if ref_pkg and ref_pkg != self.package:
                    value = f"{ref_pkg}.{value}"
            return f"map<{fld.map_key_type}, {value}>"
        # Foreign-serializer cross-package reference: the adapter already
        # resolved the referenced package (proto.foreign), so qualify against the
        # FILE's package directly.  Covers both message and enum refs uniformly
        # (a multi-package C++ schema has cross-package enums too), which the
        # type_class/ENUM-sentinel path below does not.  Same-package → flat.
        if fld.ref_package is not None and fld.ref_package != self.package:
            return f"{fld.ref_package}.{fld.type_name}"
        if fld.type_class is None:
            return fld.type_name
        if fld.unresolved_type_class is not None:
            return "bytes"
        if fld.type_class.startswith("ENUM:"):
            return fld.type_name   # enum defined in same file, no package prefix
        if fld.type_name in _KNOWN_SCALAR_TYPES:
            # type was silently converted (e.g. NSArray → bytes)
            return fld.type_name
        # Message type — qualify if cross-package
        ref_pkg = class_to_pkg.get(fld.type_class)
        if ref_pkg and ref_pkg != self.package:
            return f"{ref_pkg}.{fld.type_name}"
        return fld.type_name

    def _collect_enums(self) -> List[ProtoEnum]:
        """
        Collect unique ProtoEnum objects from all messages in this file.

        **Enum names are unique by construction** because the extractor now
        prefixes every ivar-derived enum name with the class's proto name
        (e.g. ``GEOPDPlaceResponse._status`` → ``"PDPlaceResponseStatus"``).
        When the extracted value strings reveal a genuine binary-level name
        (multi-word common prefix such as ``MAPS_RESULT_TYPE``), that name
        overrides the class-qualified one — so ``"MapsResultType"`` stays
        ``"MapsResultType"`` regardless of which class produced it.

        The remaining deduplication work is therefore:

        * **Binary-level enums** (e.g. ``"RequestType"``, ``"MapsResultType"``)
          may appear in several classes when multiple classes share the same
          runtime enum type.  These are always *compatible* (same values at
          the same numeric indices) so we pick the most informative
          representative and emit it once.

        * **Class-qualified enums** (e.g. ``"PDPlaceResponseStatus"``) are
          unique by name and pass through unchanged.

        The principled value-compatibility partitioning introduced earlier is
        retained as a safety net: if two same-named enums ever have
        *conflicting* values, they are split rather than silently merged.
        In practice this should no longer happen with per-class naming in
        place, but keeping the check costs nothing and prevents future
        regressions.
        """
        # ── Step 1: group instances by name ──────────────────────────────────
        name_instances: Dict[str, List[Tuple[ProtoEnum, ProtoMessage]]] = {}
        for msg in self.messages:
            for enum in msg.enums:
                name_instances.setdefault(enum.name, []).append((enum, msg))

        result_enums: List[ProtoEnum] = []
        field_renames: Dict[str, Dict[str, str]] = {}

        # ── Step 2: process each name group ──────────────────────────────────
        for enum_name, instances in name_instances.items():

            compat_groups: List[List[Tuple[ProtoEnum, ProtoMessage]]] = []
            for enum, msg in instances:
                placed = False
                for group in compat_groups:
                    if _enums_compatible(group[0][0], enum):
                        group.append((enum, msg))
                        placed = True
                        break
                if not placed:
                    compat_groups.append([(enum, msg)])

            if len(compat_groups) == 1:
                result_enums.append(_best_in_compat_group(compat_groups[0]))
                continue

            # Multiple incompatible groups — split (safety net; should be rare
            # now that extraction uses class-qualified names).
            compat_groups.sort(key=lambda g: (
                -len(g),
                -max((len(e.values) for e, _ in g), default=0),
                -sum(1 for e, _ in g if e.values_confirmed),
            ))

            for i, group in enumerate(compat_groups):
                best = _best_in_compat_group(group)
                if i == 0:
                    result_enums.append(best)
                else:
                    first_msg = min(group, key=lambda t: t[1].name)[1]
                    new_name = f"{first_msg.name}{enum_name}"
                    result_enums.append(replace(best, name=new_name))
                    for _, m in group:
                        field_renames.setdefault(m.class_name, {})[enum_name] = new_name

        # ── Step 3: patch field references for any splits ─────────────────────
        for msg in self.messages:
            renames = field_renames.get(msg.class_name, {})
            if not renames:
                continue
            for fld in msg.fields:
                if not (fld.type_class and fld.type_class.startswith("ENUM:")):
                    continue
                old = fld.type_class[5:]
                if old in renames:
                    new = renames[old]
                    fld.type_name  = new
                    fld.type_class = f"ENUM:{new}"

        # ── Step 4: de-collide enum names against message names ───────────────
        # proto3 forbids an enum and a message sharing a name within one
        # package ("X is already defined").  Enum *type* names here are
        # RECONSTRUCTED from value-string prefixes (cosmetic — they never
        # appear on the wire), whereas message names come from real ObjC class
        # names (authoritative).  So when a reconstructed enum name collides
        # with a message name we rename the ENUM and keep the message name,
        # then patch every field that referenced the old enum name.
        #
        # (The value-compat split above only prevents enum-vs-enum name
        # clashes; it does NOT see message names.  Proven case: AppPrediction-
        # Internal atx.proto, where the reconstructed enum "ATXNotificationsPB-
        # Event" collided with the message of the same name and broke protoc.)
        result_enums = self._decollide_enum_message_names(result_enums)

        # ── Step 5: make the enum VALUES valid proto3 at package scope ────────
        # Two wire-neutral fix-ups, applied to a stable (name-sorted) order so
        # the result is deterministic and the "first definer keeps the plain
        # name" choice is reproducible.  Enum value NAMES never appear on the
        # wire (only the numbers do), so both edits are purely cosmetic and
        # never touch decoding:
        #
        #   (1) proto3 requires every enum's first value to be 0, but Apple's
        #       PBCodable enums genuinely start at 1.  Synthesize a clearly-
        #       marked ``…_UNSPECIFIED = 0`` for any enum that has values but
        #       no 0 — 0 is never on the wire for these, and every real value
        #       keeps its own number.
        #   (2) proto uses C++ enum-value scoping: a value name is a sibling of
        #       its enum TYPE, so two enums in one package may not share a value
        #       name (nor may a value name equal a message / enum-type name).
        #       De-collide by renaming later occurrences (the first definer in
        #       sorted order keeps the plain name).
        result_enums = sorted(result_enums, key=lambda e: e.name)
        return self._synthesize_zero_and_decollide_values(result_enums)

    def _decollide_enum_message_names(
        self, result_enums: List[ProtoEnum],
    ) -> List[ProtoEnum]:
        """
        Rename any enum whose name collides with a message name in this file.

        Returns the (possibly rebuilt) enum list and patches field references
        in-place.  Idempotent: a second call finds the renamed enums no longer
        colliding and leaves them untouched.
        """
        message_names = {m.name for m in self.messages}
        # Names already taken in this package's namespace: messages plus the
        # other (non-colliding) reconstructed enum names.  We must not rename
        # an enum into any of these.
        taken: Set[str] = set(message_names) | {e.name for e in result_enums}

        renames: Dict[str, str] = {}
        for enum in result_enums:
            if enum.name not in message_names:
                continue
            base = enum.name
            new_name = f"{base}Enum"
            n = 2
            while new_name in taken:
                new_name = f"{base}Enum{n}"
                n += 1
            taken.add(new_name)
            renames[enum.name] = new_name

        if not renames:
            return result_enums

        # Rebuild the renamed enums (new objects — never mutate the shared
        # ProtoEnum instances held by msg.enums, so the pass stays idempotent).
        rebuilt: List[ProtoEnum] = []
        for enum in result_enums:
            new_name = renames.get(enum.name)
            if new_name is None:
                rebuilt.append(enum)
                continue
            rebuilt.append(replace(enum, name=new_name, collision_origin=enum.name))

        # Patch every field across the file that referenced a renamed enum.
        for msg in self.messages:
            for fld in msg.fields:
                if not (fld.type_class and fld.type_class.startswith("ENUM:")):
                    continue
                old = fld.type_class[5:]
                new = renames.get(old)
                if new is not None:
                    fld.type_name  = new
                    fld.type_class = f"ENUM:{new}"

        return rebuilt

    def _synthesize_zero_and_decollide_values(
        self, result_enums: List[ProtoEnum],
    ) -> List[ProtoEnum]:
        """
        Make the enum *values* valid proto3 within this package (file).

        See Step 5 in :meth:`_collect_enums` for the rationale.  Returns a new
        list of ``ProtoEnum`` objects with possibly-rewritten value lists; the
        per-message ``msg.enums`` instances captured by the golden snapshot are
        never mutated, so this pass is wire-/golden-neutral and idempotent.
        """
        # The package's type-name namespace.  proto's C++ enum-value scoping
        # makes an enum value a sibling of its enum TYPE, so a value name must
        # not collide with a message name or an enum type name either (proven
        # with protoc: a value sharing a message name is rejected).  Seed the
        # reserved set with both so values are de-collided against everything.
        taken: Set[str] = {m.name for m in self.messages}
        taken |= {e.name for e in result_enums}

        rebuilt: List[ProtoEnum] = []
        for enum in result_enums:
            if not enum.values:
                # Empty enum: the placeholder ``…_UNKNOWN = 0`` is materialised
                # by ProtoEnum.to_proto().  Reserve that name so a later value
                # cannot collide with it; emit the enum unchanged.
                taken.add(f"{_enum_prefix(enum.name)}_UNKNOWN")
                rebuilt.append(enum)
                continue

            new_values: List[ProtoEnumValue] = []

            # (1) Synthesize a zero value (open enums need one) when the enum starts above 0.
            if not any(v.number == 0 for v in enum.values):
                zero_name = self._unique_value_name(
                    f"{_enum_prefix(enum.name)}_UNSPECIFIED", taken
                )
                taken.add(zero_name)
                lowest = min(v.number for v in enum.values)
                new_values.append(ProtoEnumValue(
                    name=zero_name, number=0,
                    comment="synthesized zero value: an open enum requires a 0 value but this "
                            + ("PBCodable enum starts at 1; 0 never appears on the wire"
                               if lowest == 1 else
                               f"PBCodable enum names no value 0 (lowest value {lowest})"),
                ))

            # (2) De-collide every real value name against the package scope.
            for v in sorted(enum.values, key=lambda x: x.number):
                unique = self._unique_value_name(v.name, taken)
                taken.add(unique)
                if unique == v.name:
                    new_values.append(v)
                else:
                    note = (f"renamed from \"{v.name}\" to avoid a package-scope "
                            f"enum-value name collision (value names are cosmetic — "
                            f"never on the wire)")
                    new_values.append(ProtoEnumValue(
                        name=unique, number=v.number,
                        comment=f"{v.comment}; {note}" if v.comment else note,
                    ))

            # Nothing changed → keep the original object (idempotent).
            if (len(new_values) == len(enum.values)
                    and all(a is b for a, b in zip(new_values, enum.values))):
                rebuilt.append(enum)
                continue

            rebuilt.append(replace(enum, values=new_values))

        return rebuilt

    @staticmethod
    def _unique_value_name(base: str, taken: Set[str]) -> str:
        """Return *base*, or ``base_2``/``base_3``/… if already in *taken*."""
        if base not in taken:
            return base
        n = 2
        while f"{base}_{n}" in taken:
            n += 1
        return f"{base}_{n}"


# ── Import computation ─────────────────────────────────────────────────────────

def _compute_imports(
    proto_files: List[ProtoFile],
    class_to_pkg: Dict[str, str],
) -> None:
    """Populate ProtoFile.imports with cross-package dependency filenames."""
    pkg_to_filename = {pf.package: pf.filename for pf in proto_files}

    for pf in proto_files:
        needed: Set[str] = set()
        for msg in pf.messages:
            for fld in msg.fields:
                # Recovered map<K, V> with a message value: import the value class's file.
                if fld.map_key_type is not None:
                    if fld.map_value_class and fld.unresolved_type_class is None:
                        ref_pkg = class_to_pkg.get(fld.map_value_class)
                        if ref_pkg and ref_pkg != pf.package:
                            fname = pkg_to_filename.get(ref_pkg)
                            if fname:
                                needed.add(fname)
                    continue
                # Foreign C++ reference resolved to a specific OUTPUT FILE: import
                # that file when it is not this one.  Imports are by file (a
                # package may span several files); qualification stays by package.
                if fld.ref_file is not None:
                    if fld.ref_file != pf.filename:
                        needed.add(fld.ref_file)
                    continue
                # Foreign-serializer cross-package reference without per-file
                # info (e.g. a future adapter): import the package's file.
                if fld.ref_package is not None and fld.ref_package != pf.package:
                    fname = pkg_to_filename.get(fld.ref_package)
                    if fname:
                        needed.add(fname)
                    continue
                # Only resolved message-type fields generate imports.
                if fld.type_class is None:
                    continue
                if fld.type_class.startswith("ENUM:"):
                    continue  # enum type defined in same file — no import needed
                if fld.unresolved_type_class is not None:
                    continue  # fell back to bytes — no import
                if fld.type_name in _KNOWN_SCALAR_TYPES:
                    continue  # silently converted — no import
                ref_pkg = class_to_pkg.get(fld.type_class)
                if ref_pkg and ref_pkg != pf.package:
                    fname = pkg_to_filename.get(ref_pkg)
                    if fname:
                        needed.add(fname)
        pf.imports = sorted(needed)


# ── Import-cycle breaking for map<> value references ──────────────────────────

def _import_cycles(proto_files: List[ProtoFile]) -> List[Set[str]]:
    """Strongly-connected components of size > 1 in the file import graph (Tarjan,
    iterative) — each is a set of files that (transitively) import one another, which
    protoc rejects ("File recursively imports itself")."""
    graph = {pf.filename: [i for i in pf.imports if i != pf.filename] for pf in proto_files}
    index, low, on_stack, stack, comps = {}, {}, set(), [], []
    counter = 0
    for root in sorted(graph):
        if root in index:
            continue
        work = [(root, iter(sorted(graph[root])))]
        index[root] = low[root] = counter; counter += 1
        stack.append(root); on_stack.add(root)
        while work:
            node, it = work[-1]
            advanced = False
            for nxt in it:
                if nxt not in graph:
                    continue
                if nxt not in index:
                    index[nxt] = low[nxt] = counter; counter += 1
                    stack.append(nxt); on_stack.add(nxt)
                    work.append((nxt, iter(sorted(graph[nxt]))))
                    advanced = True
                    break
                if nxt in on_stack:
                    low[node] = min(low[node], index[nxt])
            if advanced:
                continue
            work.pop()
            if work:
                low[work[-1][0]] = min(low[work[-1][0]], low[node])
            if low[node] == index[node]:
                comp = set()
                while True:
                    w = stack.pop(); on_stack.discard(w); comp.add(w)
                    if w == node:
                        break
                if len(comp) > 1:
                    comps.append(comp)
    return comps


def _break_map_import_cycles(
    proto_files: List[ProtoFile],
    class_to_pkg: Dict[str, str],
) -> None:
    """Degrade a message reference to ``bytes`` when typing it would make two output files
    import each other.

    Per-class packages (e.g. CoreParsec: one ``_cpstruct.proto`` per ObjC class) make a
    mutually-recursive pair of messages — ``_CPStruct`` holds ``map<string, _CPValue>``
    while ``_CPValue`` holds a ``_CPStruct`` — a file import cycle, which protoc rejects
    for the whole set.  Map-value references are cut first (as before 2026-10-15); a cycle
    with no map edge left is cut at a message-typed field (``_CPListValue`` holds ``repeated
    _CPValue`` while ``_CPValue`` holds a ``_CPListValue``).  The reference becomes ``bytes``
    (a message is length-delimited, so it still decodes) with an inline note naming the
    class.  The cut is by (source file → target file) pair, in sorted order, re-checking
    after each, so no more references are degraded than needed."""
    pkg_to_filename = {pf.package: pf.filename for pf in proto_files}
    while True:
        comps = _import_cycles(proto_files)
        if not comps:
            return
        in_cycle = {f: i for i, comp in enumerate(comps) for f in comp}

        def same_cycle(src: str, dst: Optional[str]) -> bool:
            return bool(dst) and dst != src and src in in_cycle \
                and in_cycle.get(dst) == in_cycle[src]

        map_edges: Dict[Tuple[str, str], List[ProtoField]] = {}
        field_edges: Dict[Tuple[str, str], List[ProtoField]] = {}
        for pf in proto_files:
            for msg in pf.messages:
                for fld in msg.fields:
                    if fld.map_key_type is not None:
                        if not fld.map_value_class or fld.unresolved_type_class is not None:
                            continue
                        dst = pkg_to_filename.get(class_to_pkg.get(fld.map_value_class, ""))
                        if same_cycle(pf.filename, dst):
                            map_edges.setdefault((pf.filename, dst), []).append(fld)
                    elif (fld.type_class and not fld.type_class.startswith("ENUM:")
                          and fld.unresolved_type_class is None
                          and fld.type_name not in _KNOWN_SCALAR_TYPES):
                        dst = pkg_to_filename.get(class_to_pkg.get(fld.type_class, ""))
                        if same_cycle(pf.filename, dst):
                            field_edges.setdefault((pf.filename, dst), []).append(fld)
        edges = map_edges or field_edges
        if not edges:
            return                      # remaining cycles aren't ours to cut
        (src, dst), flds = sorted(edges.items(), key=lambda kv: kv[0])[0]
        for fld in flds:
            if fld.map_key_type is not None:
                fld.type_inference_note = (
                    f"map value is message {fld.map_value_class}; emitted as bytes because "
                    f"typing it would make {src} and {dst} import each other (protoc rejects "
                    f"import cycles) — wire-identical, see LIMITATIONS.md (1)")
                fld.map_value_type, fld.map_value_class = "bytes", None
            else:
                fld.type_inference_note = (
                    f"message {fld.type_class}; emitted as bytes because typing it would make "
                    f"{src} and {dst} import each other (protoc rejects import cycles) — "
                    f"wire-identical")
                fld.type_name, fld.type_class = "bytes", None
        _compute_imports(proto_files, class_to_pkg)


# ── Stats computation ─────────────────────────────────────────────────────────

def _pct_floor(part: int, total: int) -> str:
    """``part / total`` as a percentage with one decimal, ROUNDED DOWN: a header must never
    read ``100%`` while any field is estimated (rounding 8221/8249 to 100% hid 28 of them)."""
    if not total:
        return "0.0"
    return f"{int(1000 * part / total) / 10:.1f}"


def _compute_stats(proto_files: List[ProtoFile]) -> None:
    """Populate n_confirmed / n_estimated / n_unresolved / n_ambiguous for each ProtoFile."""
    for pf in proto_files:
        confirmed = estimated = unresolved = ambiguous = 0
        pf.n_enums_incomplete = sum(1 for msg in pf.messages for e in msg.enums
                                    if e.values_truncated)
        for msg in pf.messages:
            for fld in msg.fields:
                if fld.number_confirmed:
                    confirmed += 1
                else:
                    estimated += 1
                if fld.unresolved_type_class is not None:
                    unresolved += 1
                if fld.disambiguation_comment is not None:
                    ambiguous += 1
        pf.n_confirmed  = confirmed
        pf.n_estimated  = estimated
        pf.n_unresolved = unresolved
        pf.n_ambiguous  = ambiguous


# ── Top-level assembly ─────────────────────────────────────────────────────────

def build_proto_files(
    messages: List[ProtoMessage],
    single_file: bool = False,
    package_override: Optional[str] = None,
    source_name: str = "",
    prefixes: Sequence[str] = (),
    input_kind: InputKind = InputKind.DYLIB,
) -> List[ProtoFile]:
    """
    Full pipeline: resolve cross-refs → group by package → compute imports.

    Parameters
    ----------
    messages
        Output of ``proto.extractor.extract_all()``.
    single_file
        Emit all messages into one file instead of one per package.
    package_override
        Package name for single-file mode.  Defaults to a sanitised
        version of *source_name*, or ``"messages"`` if source_name is empty.
    source_name
        Source binary name (embedded in file header comments).
    prefixes
        The run's own ObjC class-name prefixes (``--prefix``), for the package names
        (:func:`package_for_class`).
    input_kind
        What the messages were extracted from (:class:`InputKind`).

    Returns
    -------
    List of ProtoFile objects sorted by filename, ready to call ``.emit()``.
    """
    # 1. Resolve type_name → proto message names (mutates fields in-place)
    resolve_type_refs(messages)

    # 2. Build class_name → package map (covers ALL extracted classes).  A
    #    message may carry an explicit package (foreign-serializer messages do);
    #    otherwise it is derived from the ObjC class-name prefix.
    def _pkg_of(m: ProtoMessage) -> str:
        return m.package or package_for_class(m.class_name, prefixes)

    class_to_pkg: Dict[str, str] = {m.class_name: _pkg_of(m) for m in messages}

    # 3. Group messages into ProtoFile objects
    if single_file:
        pkg = package_override or (
            re.sub(r"[^a-z0-9_]", "_", source_name.lower())
            if source_name else "messages"
        )
        # Every message now lives in this one package, so no reference is cross-package:
        # qualifying by the ObjC-prefix package (``ck.CKCodeProto2Any``) names a package
        # the file does not declare, which protoc rejects.
        class_to_pkg = {c: pkg for c in class_to_pkg}
        # The same holds for a foreign-serializer reference, which carries its own package
        # and output file (proto.foreign): there is now one package and one file.
        for msg in messages:
            for fld in msg.fields:
                fld.ref_package = fld.ref_file = None
        proto_files: List[ProtoFile] = [
            ProtoFile(
                package=pkg,
                filename=f"{pkg}.proto",
                messages=sorted(messages, key=lambda m: m.name),
                imports=[],
                source_name=source_name,
                input_kind=input_kind,
            )
        ]
    else:
        # Group key: a message with an explicit out_file (foreign C++ — emit one
        # file per ORIGINAL source file to preserve its acyclic import structure)
        # groups by that filename; everything else groups by package, one file
        # per package as before.  out_file values end in ".proto" and package
        # values do not, so the two key spaces never overlap.
        by_group: Dict[str, List[ProtoMessage]] = {}
        for msg in messages:
            by_group.setdefault(msg.out_file or _pkg_of(msg), []).append(msg)
        proto_files = []
        for key, msgs in sorted(by_group.items()):
            first = msgs[0]
            if first.out_file:
                # All messages from one source file share that file's package.
                package, filename = first.package, first.out_file
            else:
                package, filename = key, f"{key}.proto"
            proto_files.append(ProtoFile(
                package=package,
                filename=filename,
                messages=sorted(msgs, key=lambda m: m.name),
                imports=[],
                source_name=source_name,
                input_kind=input_kind,
            ))

    # 4. Compute cross-package import statements
    _compute_imports(proto_files, class_to_pkg)

    # 4b. A typed map<K, Message> must not close a file-import cycle (protoc rejects it).
    _break_map_import_cycles(proto_files, class_to_pkg)

    # 5. Compute per-file statistics (confirmed / estimated / unresolved counts)
    _compute_stats(proto_files)

    for pf in proto_files:
        pf.class_to_pkg = class_to_pkg

    return proto_files


# ── File output ────────────────────────────────────────────────────────────────

def write_proto_files(
    proto_files: List[ProtoFile],
    output_dir: Path,
    class_to_pkg: Optional[Dict[str, str]] = None,
) -> List[Path]:
    """
    Write each ProtoFile to ``output_dir/<filename>``.

    Creates *output_dir* (and parents) if it doesn't exist.
    Returns the list of paths written, in the same order as *proto_files*.
    *class_to_pkg* overrides each file's own map (see :meth:`ProtoFile.emit`); leave it
    None to qualify references by the packages build_proto_files grouped them into.
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    written: List[Path] = []
    for pf in proto_files:
        path = output_dir / pf.filename
        path.write_text(pf.emit(class_to_pkg=class_to_pkg), encoding="utf-8")
        written.append(path)
    return written


def write_from_messages(
    messages: List[ProtoMessage],
    output_dir: Path,
    single_file: bool = False,
    package_override: Optional[str] = None,
    source_name: str = "",
    prefixes: Sequence[str] = (),
    input_kind: InputKind = InputKind.DYLIB,
) -> Tuple[List[Path], List[ProtoFile]]:
    """
    Convenience wrapper: build_proto_files → write_proto_files.

    Returns ``(written_paths, proto_files)`` so callers can inspect stats
    without a separate ``build_proto_files`` call.
    """
    proto_files = build_proto_files(
        messages,
        single_file=single_file,
        package_override=package_override,
        source_name=source_name,
        prefixes=prefixes,
        input_kind=input_kind,
    )
    written = write_proto_files(proto_files, Path(output_dir))
    return written, proto_files


# ── Aggregate statistics ───────────────────────────────────────────────────────

def extraction_stats(
    messages: List[ProtoMessage],
    proto_files: List[ProtoFile],
) -> Dict[str, int]:
    """
    Return a dict of aggregate statistics.

    Keys: messages, fields, confirmed, estimated, unresolved, empty, files.
    """
    confirmed  = sum(pf.n_confirmed  for pf in proto_files)
    estimated  = sum(pf.n_estimated  for pf in proto_files)
    unresolved = sum(pf.n_unresolved for pf in proto_files)
    ambiguous  = sum(pf.n_ambiguous  for pf in proto_files)
    # Count unique enum names across all extracted messages
    unique_enums = len({e.name for msg in messages for e in msg.enums})
    return {
        "messages":   len(messages),
        "fields":     confirmed + estimated,
        "confirmed":  confirmed,
        "estimated":  estimated,
        "unresolved": unresolved,
        "ambiguous":  ambiguous,
        "empty":      sum(1 for m in messages if not m.fields),
        "enums":      unique_enums,
        "enums_incomplete": sum(pf.n_enums_incomplete for pf in proto_files),
        "files":      len(proto_files),
    }


def enum_error_escalated(messages: List[ProtoMessage], proto_files: List[ProtoFile]) -> bool:
    """True when :func:`print_summary` reports the "enum fields must not be trusted" ERROR
    (unresolved enums in a self-contained input, where that is a tool bug): the run
    completed but its output is not trustworthy, so the CLI exits non-zero."""
    return bool(extraction_stats(messages, proto_files).get("ambiguous")
                and _input_kind(proto_files).self_contained)


def _input_kind(proto_files: List[ProtoFile]) -> InputKind:
    """The run's input kind: every file a run builds carries the same one."""
    return proto_files[0].input_kind if proto_files else InputKind.DYLIB


def print_summary(
    messages: List[ProtoMessage],
    proto_files: List[ProtoFile],
    source_name: str = "",
    file=None,
    diagnostics=None,
) -> None:
    """Print a formatted extraction summary table.

    *diagnostics* (:class:`proto.models.ExtractionDiagnostics`) adds the run-level problems
    that no single emitted field can carry: classes that failed (and are missing), foreign
    runtimes that failed, and enum-like switches that could not be evaluated."""
    if file is None:
        file = sys.stdout

    stats = extraction_stats(messages, proto_files)
    total_fields = stats["fields"]
    pct_conf = _pct_floor(stats["confirmed"], total_fields)
    pct_est  = _pct_floor(stats["estimated"], total_fields) if stats["estimated"] else "0.0"

    W   = 57
    sep = "─" * W

    def row(label: str, value, extra: str = "") -> str:
        v = str(value)
        return f"│  {label:<28} {v:>7}  {extra:<16}│"

    title = (
        f" {source_name} — proto extraction summary"
        if source_name else " proto extraction summary"
    )
    print(f"\n┌{sep}┐", file=file)
    print(f"│{title:^{W}}│", file=file)
    print(f"├{sep}┤", file=file)
    print(row("Messages extracted",          stats["messages"]),          file=file)
    print(row("  confirmed field numbers",   stats["confirmed"],  f"({pct_conf}%)"),  file=file)
    print(row("  estimated field numbers",   stats["estimated"],  f"({pct_est}%)"),   file=file)
    print(row("  empty (0 fields)",          stats["empty"]),             file=file)
    print(row("  unresolved type refs",      stats["unresolved"]),        file=file)
    if stats.get("ambiguous"):
        print(row("  unresolved enum types",     stats["ambiguous"]),     file=file)
    print(row("Enum types detected",         stats.get("enums", 0)),      file=file)
    if stats.get("enums_incomplete"):
        print(row("  enums possibly incomplete", stats["enums_incomplete"]),  file=file)
    if diagnostics is not None:
        if diagnostics.unevaluated_switches:
            print(row("  enum switches not evaluated", len(diagnostics.unevaluated_switches)),
                  file=file)
        if diagnostics.analysis_failures:
            print(row("  class analyses failed", len(diagnostics.analysis_failures)), file=file)
        if diagnostics.heuristics_hit:
            print(row("  bounds / heuristics hit", len(diagnostics.heuristics_hit)), file=file)
        if diagnostics.failed_classes:
            print(row("!! classes FAILED (missing)", len(diagnostics.failed_classes)), file=file)
        if diagnostics.foreign_errors:
            print(row("!! foreign runtime errors", len(diagnostics.foreign_errors)), file=file)
        if diagnostics.failed_passes:
            print(row("!! pre-passes FAILED", len(diagnostics.failed_passes)), file=file)
        if diagnostics.unread:
            print(row("!! input unreadable (missing)", len(diagnostics.unread)), file=file)
    print(f"├{sep}┤", file=file)
    print(row("Output files", stats["files"]),                            file=file)
    for pf in proto_files:
        print(row(f"  {pf.filename}", len(pf.messages), "messages"),     file=file)
    print(f"└{sep}┘", file=file)

    # Escalation: an ambiguous enum should be impossible whenever the binary is
    # self-contained — cache-native (selector names resolved through the cache)
    # or a standalone executable (carries all its own data).  If the count is
    # non-zero anyway it is a tool bug (or, for cache, a corrupt cache).  Surface
    # it as a loud error on stderr rather than a quiet footnote in the table.
    # A binary-only *dylib* is the one expected case — left as a table note.
    kind = _input_kind(proto_files)
    if stats.get("ambiguous") and kind.self_contained:
        if kind is InputKind.CACHE_IMAGE:
            reason = ("despite a shared cache. This should not happen and "
                      "indicates a tool bug or an incomplete/corrupt cache")
        else:
            reason = ("in a standalone executable. A self-contained executable "
                      "carries all its own enum data, so this should not happen "
                      "and indicates a tool bug")
        print(
            f"\nerror: {stats['ambiguous']} enum field(s) remained unresolved "
            f"{reason}; the affected fields were emitted as int32 and must not "
            f"be trusted.",
            file=sys.stderr,
        )

    if diagnostics is not None and diagnostics.analysis_failures:
        fails = diagnostics.analysis_failures
        print(f"\nwarning: {len(fails)} class analysis(es) failed; the fields they would have "
              f"typed are emitted flagged:", file=sys.stderr)
        for cls_name, analysis, detail in fails[:10]:
            print(f"  {cls_name}: {analysis}: {detail}", file=sys.stderr)
        if len(fails) > 10:
            print(f"  … and {len(fails) - 10} more (run with -v)", file=sys.stderr)

    if diagnostics is not None and diagnostics.heuristics_hit:
        hits = diagnostics.heuristics_hit
        print(f"\nwarning: a bound or heuristic bit {len(hits)} time(s); what it decided there "
              f"may be missing or wrong:", file=sys.stderr)
        for name, where in hits[:10]:
            print(f"  {name}: {where}", file=sys.stderr)
        if len(hits) > 10:
            print(f"  … and {len(hits) - 10} more", file=sys.stderr)

    if diagnostics is not None and diagnostics.n_errors:
        for name, err, consequence in diagnostics.failed_passes:
            print(f"\nerror: the {name} pre-pass failed ({err}); {consequence}", file=sys.stderr)
        if diagnostics.failed_classes:
            print(f"\nerror: {len(diagnostics.failed_classes)} class(es) failed to extract and are "
                  f"MISSING from the output:", file=sys.stderr)
            for name, err in diagnostics.failed_classes[:10]:
                print(f"  {name}: {err}", file=sys.stderr)
            if len(diagnostics.failed_classes) > 10:
                print(f"  … and {len(diagnostics.failed_classes) - 10} more (run with -v)",
                      file=sys.stderr)
        for runtime, err in diagnostics.foreign_errors:
            print(f"\nerror: {runtime}: {err} — its messages may be missing", file=sys.stderr)
        if diagnostics.unread:
            print(f"\nerror: {len(diagnostics.unread)} part(s) of the input could not be read; "
                  f"what they hold is MISSING from the output:", file=sys.stderr)
            for what, where, err in diagnostics.unread[:10]:
                print(f"  {what} at {where}: {err}", file=sys.stderr)
            if len(diagnostics.unread) > 10:
                print(f"  … and {len(diagnostics.unread) - 10} more", file=sys.stderr)


__all__ = [
    "InputKind",
    "ProtoFile",
    "enum_error_escalated",
    "build_proto_files",
    "write_proto_files",
    "write_from_messages",
    "resolve_type_refs",
    "package_for_class",
    "extraction_stats",
    "print_summary",
]
