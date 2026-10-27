"""proto/foreign.py — adapt non-PBCodable serializer descriptors into the shared
:class:`ProtoMessage` model so they flow through the SAME package-grouped emitter
as Apple PBCodable, each tagged with its serializer for provenance.

The tool's primary path reverse-engineers Apple ``PBCodable`` (ObjC) into
``ProtoMessage`` objects.  Other protobuf runtimes carry structured descriptors we
can decode directly:

* **C++ libprotobuf** (``google::protobuf``) — the embedded ``FileDescriptorProto``
  is the schema; :mod:`serializers.cpp_descriptor_extract` decodes it fully (names,
  numbers, TYPES, enums, nesting).  Nested messages are flattened to ``Outer_Inner``
  (the flat emitter has no nested-message syntax) and oneof members become plain
  fields with a note.
* **swift-protobuf** — :mod:`serializers.swift_descriptor_extract` recovers field
  names + numbers (and enum cases); wire TYPES are not recoverable, so fields are
  emitted as ``bytes`` with a note.

Each adapted message sets :attr:`ProtoMessage.serializer` and an explicit
:attr:`ProtoMessage.package` (the C++ FileDescriptor package / the Swift module),
so :func:`proto.emitter.build_proto_files` groups them into their own
``<package>.proto`` files alongside the PBCodable output.

Both modes (:func:`collect_foreign_messages`): with the raw bytes of a binary the C++ scan
sweeps the whole image; cache-native it reads the descriptor sections, and the Swift reader the
``.symbols`` nlist, through the context.
"""
from __future__ import annotations

from macho.memory import PROGRAM_ERRORS

import logging
import re
from collections import Counter
from typing import Dict, List, Optional

from serializers import cpp_descriptor_extract as _cpp
from serializers import swift_descriptor_extract as _swift

from .models import (FieldLabel, ProtoEnum, ProtoEnumValue, ProtoField, ProtoMessage, SCALAR_TYPES,
                     PACKABLE_SCALARS)
from .protoclass_set import _proto_class_set
from .foreign_detect import (google_protobuf_classes, swift_protobuf_messages,
                             cpp_file_protos, cpp_protobuf_namespaces, protobufc_descriptors)

log = logging.getLogger(__name__)

CPP_SERIALIZER = "C++ libprotobuf (google::protobuf)"
CPP_LITE_SERIALIZER = "C++ libprotobuf-lite (google::protobuf)"
SWIFT_SERIALIZER = "swift-protobuf"
PROTOBUFC_SERIALIZER = "protobuf-c (C runtime)"


def _sanitize_pkg(name: str) -> str:
    """Proto package names are lower_snake; sanitise a module / C++ package name."""
    return re.sub(r"[^a-z0-9_.]", "_", name.lower()) or "messages"


def _flat(qualified: str) -> str:
    """Flatten a (possibly dotted/qualified) type name to a single valid proto
    identifier: strip a leading dot, drop any package prefix, join the rest with
    ``_`` (the flat emitter cannot express nested ``Outer.Inner`` message names)."""
    t = qualified[1:] if qualified.startswith(".") else qualified
    return t.replace(".", "_")


# ── C++ libprotobuf ───────────────────────────────────────────────────────────

def _cpp_field(f: "_cpp.Field", package: str,
               registry: "Dict[str, tuple]", syntax: str = "proto2") -> ProtoField:
    """*f* in edition 2023, with what its file's *syntax* implied: a proto2 repeated scalar or
    enum is EXPANDED unless declared packed, a proto3 one PACKED unless declared not;
    ``required`` is LEGACY_REQUIRED presence; a group is a DELIMITED message."""
    ref_package = ref_file = None
    if f.type in (11, 14, 10):                       # message / enum / group
        # Resolve the (absolute) descriptor type name through the global
        # registry so a reference into ANOTHER package is emitted qualified
        # (``pkg.Type``) and a reference into ANOTHER source file is imported.
        # The flat emitter has one package per file (a cross-package ref flattened with
        # ``_`` would name a type no file defines).  Qualification is by package, imports by file —
        # a package may span several source files (see _cpp_out_filenames).
        fqn = f.type_name[1:] if f.type_name.startswith(".") else f.type_name
        entry = registry.get(fqn)
        if entry is not None:
            ref_package, type_name, ref_file = entry  # (pkg, flat name, out file)
        else:
            # Not an extracted type (external/unknown): flattened and left unqualified.
            type_name = _flat(_cpp._ref(f.type_name, package))
    else:
        type_name = _cpp._FTYPE.get(f.type, "bytes")
    label = {3: FieldLabel.REPEATED, 2: FieldLabel.REQUIRED}.get(f.label, FieldLabel.OPTIONAL)
    note = "oneof member (flattened)" if f.oneof_index >= 0 else None
    packed = f.packed if f.has_packed else syntax == "proto3"
    packable = f.type == 14 or _cpp._FTYPE.get(f.type) in PACKABLE_SCALARS
    return ProtoField(name=f.name, number=f.number, type_name=type_name,
                      label=label, number_confirmed=True, type_inference_note=note,
                      ref_package=ref_package, ref_file=ref_file,
                      repeated_encoding=(("PACKED" if packed else "EXPANDED")
                                         if f.label == 3 and packable else None),
                      delimited=f.type == 10)


def _cpp_enum(e: "_cpp.EnumType", name_prefix: str = "", syntax: str = "proto2") -> ProtoEnum:
    # The flat emitter has no nested-enum syntax, so a nested enum is emitted at
    # file scope under the SAME parent-flattened name its field references use
    # (``Outer_Inner``).  ``name_prefix`` is the flattened owner-message name plus
    # ``_`` for a nested enum, or "" for a file-scope enum.  Without it the enum
    # would be declared as the bare leaf name while fields reference the
    # qualified name → protoc "X is not defined".
    return ProtoEnum(name=f"{name_prefix}{e.name}",
                     values=[ProtoEnumValue(name=n, number=num) for n, num in e.values],
                     values_confirmed=True, closed=syntax == "proto2")


def _cpp_out_filenames(names) -> Dict[str, str]:
    """Output ``.proto`` filename for each ORIGINAL C++ source file *names* holds: its
    basename, or, for sources that share one, its whole path -- so no two sources (each with
    its own package) are merged into one file.

    Emitting one file per original ``FileDescriptorProto`` preserves that
    schema's (acyclic) import structure.  Merging a package's several source
    files into a single ``<package>.proto`` can introduce an import cycle protoc
    rejects ("File recursively imports itself"): file A (pkg P) imports gpsd and
    file B (also pkg P) is imported by gpsd — harmless as a chain, but the merge
    makes ``P.proto`` both import and be imported by gpsd.  Restoring the file
    boundaries breaks the cycle; no symbol collides because every ``pkg.Type`` is
    still defined exactly once (a package legitimately spans files, like
    ``google.protobuf``)."""
    def stem(path: str) -> str:
        return path[:-len(".proto")] if path.endswith(".proto") else path

    def clean(path: str) -> str:
        return (re.sub(r"[^a-z0-9_]", "_", stem(path).lower()) or "cpp_protobuf") + ".proto"

    names = set(names)
    bases = Counter(n.rsplit("/", 1)[-1] for n in names)
    return {n: clean(n.rsplit("/", 1)[-1] if bases[n.rsplit("/", 1)[-1]] == 1 else n)
            for n in names}


def _cpp_message(m: "_cpp.Message", package: str, registry: "Dict[str, tuple]",
                 out_file: str, prefix: str = "", syntax: str = "proto2") -> List[ProtoMessage]:
    """Flatten a C++ message (and its nested messages) to ProtoMessage objects."""
    qual = f"{prefix}{m.name}"
    flat_qual = _flat(qual)
    pkg = _sanitize_pkg(package) if package else "cpp_protobuf"
    out = [ProtoMessage(
        name=flat_qual, class_name=flat_qual, package=pkg,
        serializer=CPP_SERIALIZER, out_file=out_file,
        fields=[_cpp_field(f, package, registry, syntax) for f in m.fields],
        # Nested enums carry the flattened owner name so their emitted type name
        # matches the ``Outer_Inner`` reference produced by _cpp_field.
        enums=[_cpp_enum(e, name_prefix=f"{flat_qual}_", syntax=syntax) for e in m.enums],
    )]
    for n in m.nested:
        out += _cpp_message(n, package, registry, out_file, prefix=qual + ".", syntax=syntax)
    return out


def _well_known(name: str) -> bool:
    """*name* is one of the schemas protoc provides (``google/protobuf/*.proto``): a C++ image
    embeds those its runtime uses (``descriptor.proto``).  They are not emitted -- a copy among
    the output files would shadow protoc's own -- and a reference to one of their types imports
    protoc's file under its real (nested, dotted) name."""
    return name.startswith("google/protobuf/")


def _cpp_type_registry(file_protos) -> "Dict[str, tuple]":
    """Map every message/enum's ABSOLUTE descriptor name (``pkg.Outer.Inner``,
    as it appears in a field's ``type_name``) to ``(sanitised_package,
    flat_name_within_that_package, output_filename)``.  Built over ALL files
    first so a field can resolve a reference into another package/file — the
    per-file flat emitter cannot express that without knowing both up front."""
    reg: Dict[str, tuple] = {}
    out_names = _cpp_out_filenames(fp.name for fp in file_protos)

    def walk(m, package: str, prefix: str, out_file: str, flatten: bool) -> None:
        qual = f"{prefix}{m.name}"
        name = _flat(qual) if flatten else qual
        spkg = _sanitize_pkg(package) if package else "cpp_protobuf"
        reg[f"{package}.{qual}" if package else qual] = (spkg, name, out_file)
        for e in m.enums:                            # nested enum: parent-flattened
            key = f"{package}.{qual}.{e.name}" if package else f"{qual}.{e.name}"
            reg[key] = (spkg, f"{name}_{e.name}" if flatten else f"{name}.{e.name}", out_file)
        for n in m.nested:
            walk(n, package, qual + ".", out_file, flatten)

    for fp in file_protos:
        known = _well_known(fp.name)
        out_file = fp.name if known else out_names[fp.name]
        spkg = _sanitize_pkg(fp.package) if fp.package else "cpp_protobuf"
        for e in fp.enums:                           # file-scope enum: bare name
            key = f"{fp.package}.{e.name}" if fp.package else e.name
            reg[key] = (spkg, e.name, out_file)
        for m in fp.messages:
            walk(m, fp.package, "", out_file, flatten=not known)
    return reg


def _cpp_protos_to_messages(file_protos) -> List[ProtoMessage]:
    file_protos = list(file_protos)
    registry = _cpp_type_registry(file_protos)
    out: List[ProtoMessage] = []
    # File-scope (top-level) enums are part of the schema too and are referenced
    # by fields (e.g. CLP.LogEntry.PrivateData's `Band`, `SensorFusionMode`).
    # The flat emitter collects enums only from ``msg.enums`` — it has no separate
    # file-scope enum slot — so carry each file's top-level enums on the first
    # message of the SAME output file (where the referencing fields live, so they
    # land in the same .proto); without them every field that referenced one would fail
    # protoc with "X is not defined".
    file_enums_by_out: Dict[str, List[ProtoEnum]] = {}
    first_msg_by_out: Dict[str, ProtoMessage] = {}
    out_names = _cpp_out_filenames(fp.name for fp in file_protos)
    for fp in file_protos:
        if _well_known(fp.name):
            continue
        out_file = out_names[fp.name]
        for m in fp.messages:
            built = _cpp_message(m, fp.package, registry, out_file, syntax=fp.syntax)
            out += built
            first_msg_by_out.setdefault(out_file, built[0])
        for e in fp.enums:                       # file-scope: no parent prefix
            file_enums_by_out.setdefault(out_file, []).append(_cpp_enum(e, syntax=fp.syntax))

    for out_file, enums in file_enums_by_out.items():
        holder = first_msg_by_out.get(out_file)
        if holder is not None:
            holder.enums = list(holder.enums) + enums
        else:
            # A source file with file-scope enums but no messages: nothing in
            # this run references them, so they are unreachable — but say so
            # rather than drop silently (transparency over a silent guess).
            log.warning("%d file-scope C++ enum(s) in %r have no message to carry "
                        "them and were omitted", len(enums), out_file)

    return _dedupe_cpp_messages(out)


def _dedupe_cpp_messages(messages: List[ProtoMessage]) -> List[ProtoMessage]:
    """Drop duplicate ``(package, name)`` messages, keeping the one with MORE fields.

    A schema embedded by more than one image is decoded once per image, so the same
    messages can appear several times.  protoc rejects a redefinition
    ("X is already defined"), so collapse exact-name duplicates within a package.
    A duplicate that DIFFERS (different protobuf versions of the same well-known message)
    keeps the copy with more fields (on a tie, the first), and the message is annotated and
    warned about -- never silently resolved by discovery order."""
    def fields_of(m: ProtoMessage):
        return {(f.number, f.name, f.type_name, f.label) for f in m.fields}
    seen: Dict[tuple, ProtoMessage] = {}
    out: List[ProtoMessage] = []
    for m in messages:
        key = (m.package, m.name)
        prev = seen.get(key)
        if prev is None:
            seen[key] = m
            out.append(m)
            continue
        if fields_of(prev) != fields_of(m):
            keep, drop = (m, prev) if len(m.fields) > len(prev.fields) else (prev, m)
            lost = len(fields_of(drop) - fields_of(keep))
            log.warning("C++ message %r in package %r decoded twice with different fields "
                        "(%d vs %d); keeping the one with more (%d of the other's not in it)",
                        m.name, m.package, len(prev.fields), len(m.fields), lost)
            keep.message_note = (f"decoded from more than one image with different fields "
                                 f"({len(keep.fields)} kept; {lost} of the other copy's "
                                 f"{len(drop.fields)} not among them): different protobuf "
                                 f"versions of this message")
            seen[key] = keep
            out[out.index(prev)] = keep
    return out


# ── swift-protobuf ────────────────────────────────────────────────────────────

class _SwiftTypes:
    """Resolves swift-protobuf field type names (as recovered from reflection
    metadata) to something the emitted ``.proto`` can reference.

    swift reflection gives the QUALIFIED name of a local type (``Outer.Inner``),
    which is exactly the key the nested message was emitted under (flattened to
    ``Outer_Inner``), so a nested reference resolves to the right message even when
    several messages nest a ``Details``.  What cannot be referenced is degraded to a
    type that still parses and keeps the wire format:

    * a type from another module / the well-known types (not defined in this image's
      own nameMaps) -> ``bytes`` (length-delimited, like any message), annotated;
    * one of this image's own swift enums -> the enum, when its cases were recovered
      (it is then defined in the output); otherwise ``int32`` (varint), annotated.
    """

    def __init__(self, messages, enum_names, enum_defs=()):
        self.known = {(m.module, m.name) for m in messages}
        # enums whose cases were recovered (and so are defined in the output)
        self.defined_enums = {(e.module, e.name) for e in enum_defs}
        self.enum_mods: Dict[str, List[str]] = {}
        for e in enum_defs:
            self.enum_mods.setdefault(e.name, []).append(e.module)
        self.pkg = {m.module: (_sanitize_pkg(m.module) if m.module else "swift_protobuf")
                    for m in messages}
        self.mods_by_name: Dict[str, List[str]] = {}
        for m in messages:
            self.mods_by_name.setdefault(m.name, []).append(m.module)
        self.enums = set(enum_names)

    @staticmethod
    def pkg_of(module: str) -> str:
        return _sanitize_pkg(module) if module else "swift_protobuf"

    def resolve(self, t: str, module: str):
        """-> (type_name, ref_package|None, unresolved_name|None, note|None)."""
        if t in SCALAR_TYPES:
            return t, None, None, None
        if (module, t) in self.known or (module, t) in self.defined_enums:
            return _flat(t), None, None, None
        emods = self.enum_mods.get(t, [])
        if len(emods) == 1:                        # a recovered enum of another module
            return _flat(t), self.pkg_of(emods[0]), None, None
        mods = self.mods_by_name.get(t, [])
        if len(mods) == 1:                         # another module of this image
            return _flat(t), self.pkg[mods[0]], None, None
        if t in self.enums:
            return ("int32", None, None,
                    f"swift-protobuf enum {t}: cases not recovered (shown as int32)")
        return ("bytes", None, t,
                f"swift-protobuf: {t} is defined outside this image's name maps "
                "(shown as bytes; wire-correct only for a message)")


def swift_messages(ctx) -> List[ProtoMessage]:
    """Every swift-protobuf message in *ctx* (names, numbers and, where reflection
    metadata allows, types)."""
    sw = _swift.swift_messages(ctx)
    try:
        from serializers.swift_type_recovery import local_enum_names
        enums = local_enum_names(ctx)
    except PROGRAM_ERRORS:
        raise
    except Exception as exc:
        _foreign_failed(ctx, "swift-protobuf", "enum scan", exc)
        enums = set()
    try:
        enum_defs = [e for e in _swift.swift_enums(ctx) if e.fields]
    except PROGRAM_ERRORS:
        raise
    except Exception as exc:
        _foreign_failed(ctx, "swift-protobuf", "enum recovery", exc)
        enum_defs = []
    types = _SwiftTypes(sw, enums, enum_defs)
    out: List[ProtoMessage] = []
    by_key: Dict[tuple, ProtoMessage] = {}
    for m in sw:
        pkg = _sanitize_pkg(m.module) if m.module else "swift_protobuf"
        fields = [_swift_field(f, m.module, types) for f in m.fields]
        pm = ProtoMessage(name=_flat(m.name), class_name=_flat(m.name),
                          package=pkg, serializer=SWIFT_SERIALIZER, fields=fields,
                          # reflection lists no field either: genuinely empty (only the
                          # unknown-fields bag), not an unread name map
                          opaque_passthrough=bool(m.fieldless and not m.fields))
        out.append(pm)
        by_key[(m.module, m.name)] = pm
    _attach_swift_enums(enum_defs, out, by_key)
    return out


def _swift_enum(e, taken: Optional[set] = None) -> ProtoEnum:
    """A recovered swift enum as a ProtoEnum.  Two cases may share a value (an alias);
    the flat proto emitter has no ``allow_alias``, so the first name is the value and
    the rest are listed in its comment -- names never appear on the wire.

    Value names must also be valid proto3 in the PACKAGE: they share a scope with the
    package's message and enum type names and with the values of every other enum
    (``taken``, updated in place), and within one enum protoc rejects two names that
    are equal ignoring case and underscores once the enum-name prefix is dropped
    (``CAPTION2`` / ``CAPTION_2``).  Swift name maps carry such names verbatim, so the
    later one is renamed here -- both rules at once, because the emitter's own
    package-scope rename checks only exact equality and can create the second kind."""
    values: List[ProtoEnumValue] = []
    by_num: Dict[int, ProtoEnumValue] = {}
    for f in e.fields:
        v = by_num.get(f.number)
        if v is None:
            v = ProtoEnumValue(name=f.name, number=f.number)
            by_num[f.number] = v
            values.append(v)
        else:
            v.comment = (f"{v.comment}, {f.name}" if v.comment
                         else f"alias of this value, not emitted: {f.name}")
    taken = taken if taken is not None else set()
    prefix = _flat(e.name).replace("_", "").lower()

    def norm(n: str) -> str:
        k = n.replace("_", "").lower()
        return k[len(prefix):] if k.startswith(prefix) and len(k) > len(prefix) else k

    keys: Dict[str, str] = {}
    for v in values:
        orig, why = v.name, None
        if v.name in taken:
            why = "an enum value name is unique within its package"
        elif norm(v.name) in keys:
            why = (f"protoc rejects value names equal ignoring case and underscores "
                   f"({keys[norm(v.name)]})")
        if why:
            n = 2
            while True:
                cand = f"{orig}_{n}"
                if cand not in taken and norm(cand) not in keys:
                    break
                n += 1
            v.name = cand
            note = f"renamed from {orig}: {why}"
            v.comment = f"{v.comment}; {note}" if v.comment else note
        taken.add(v.name)
        keys[norm(v.name)] = v.name
    return ProtoEnum(name=_flat(e.name), values=values, values_confirmed=True)


def _attach_swift_enums(enums, messages: List[ProtoMessage], by_key: Dict[tuple, ProtoMessage]) -> None:
    """The flat emitter collects enums only from ``msg.enums``: carry a nested enum on
    its OWNER message and a top-level one on the first message of its module (same
    output file as the fields that reference it)."""
    carrier: Dict[str, ProtoMessage] = {}
    taken: Dict[str, set] = {}               # per package: names sharing the value scope
    for m in messages:
        carrier.setdefault(m.package, m)
        taken.setdefault(m.package, set()).add(m.name)
    for e in enums:
        taken.setdefault(_sanitize_pkg(e.module) if e.module else "swift_protobuf", set()).add(_flat(e.name))
    for e in enums:
        pkg = _sanitize_pkg(e.module) if e.module else "swift_protobuf"
        owner = None
        if "." in e.name:
            owner = by_key.get((e.module, e.name.rsplit(".", 1)[0]))
        owner = owner or carrier.get(pkg)
        if owner is None:
            log.warning("swift enum %s.%s has no message in its module to carry it; omitted",
                        e.module, e.name)
            continue
        owner.enums = list(owner.enums) + [_swift_enum(e, taken[pkg])]


def _swift_field(f, module: str = "", types: Optional["_SwiftTypes"] = None) -> ProtoField:
    """Map a recovered swift field (name+number, optional proto_type) to a
    ProtoField.  ``proto_type`` like 'repeated int32' / 'map<string, int32>' /
    'Foo' is split into (label, type); absent types fall back to ``bytes``.  With
    *types* given, message / enum references are resolved against the image's own
    messages (see :class:`_SwiftTypes`); without it names are only flattened."""
    label, type_name, note = FieldLabel.OPTIONAL, "bytes", None
    ref_pkg = unresolved = None
    t = f.proto_type

    def one(name: str):
        if types is None:
            return _flat(name), None, None, None
        return types.resolve(name, module)

    if not t:
        note = "swift-protobuf: type not recovered"
    elif t.startswith("repeated "):
        label = FieldLabel.REPEATED
        type_name, ref_pkg, unresolved, note = one(t[len("repeated "):])
    elif t.startswith("map<"):
        k, _, v = t[4:-1].partition(", ")
        vt, _vp, unresolved, note = one(v) if v else ("bytes", None, None, None)
        type_name = f"map<{k}, {vt}>"      # emitted verbatim; cross-package map values
        # degrade to bytes above, so no package qualifier is ever needed here
        if _vp is not None:
            type_name, unresolved, note = f"map<{k}, bytes>", v, (
                f"swift-protobuf: map value {v} is in another module (shown as bytes)")
    else:
        type_name, ref_pkg, unresolved, note = one(t)
    # a recovered container whose element/value is a guess filler is flagged (#67)
    note = note or getattr(f, "type_note", None)
    return ProtoField(name=f.name, number=f.number, type_name=type_name,
                      label=label,
                      number_confirmed=getattr(f, "number_confirmed", True),
                      repeated_encoding=(getattr(f, "repeated_encoding", None)
                                         if label is FieldLabel.REPEATED else None),
                      type_inference_note=note,
                      ref_package=ref_pkg,
                      unresolved_type_class=unresolved)


# ── orchestration ─────────────────────────────────────────────────────────────

class SerializerSummary:
    """One serializer's presence in an image: label, whether the tool decodes it,
    the protobuf message/type names found, and an optional ``note`` for a
    name-less detect-only entry (e.g. libprotobuf-lite, which strips the
    descriptors that hold message/field names)."""
    def __init__(self, label: str, decodable: bool, names: List[str],
                 note: Optional[str] = None):
        self.label = label
        self.decodable = decodable
        self.names = names
        self.note = note


def summarize_serializers(ctx, cl, data: Optional[bytes]) -> List[SerializerSummary]:
    """A quick inventory of every protobuf serializer in an image and the message
    names under each — for an at-a-glance overview, WITHOUT the full per-message
    disassembly that extraction does.  Uses the lightweight detectors:

    * PBCodable — the PBCodable subclass set (``_proto_class_set``);
    * C++ libprotobuf — message names from the embedded FileDescriptorProtos;
    * swift-protobuf — conformance-descriptor type names;
    * GPBMessage — the GPB subclass set (detected, not decodable);
    * protobuf-c — descriptor-magic scan of the data sections (detected, not decodable).
    """
    out: List[SerializerSummary] = []

    pb = sorted(_proto_class_set(ctx, cl))
    if pb:
        out.append(SerializerSummary("Apple PBCodable (ObjC)", True, pb))

    cpp_names = []
    try:
        file_protos = cpp_file_protos(ctx, data)
        for fp in file_protos:
            for m in fp.messages:
                pfx = (fp.package + ".") if fp.package else ""
                cpp_names.append(pfx + m.name)
                cpp_names += [f"{pfx}{m.name}.{n.name}" for n in m.nested]
    except PROGRAM_ERRORS:
        raise
    except Exception as exc:
        _foreign_failed(ctx, "C++ libprotobuf", "descriptor inventory", exc)
    if cpp_names:
        out.append(SerializerSummary(CPP_SERIALIZER, True, sorted(cpp_names)))
    else:
        # No decodable descriptors, but google::protobuf symbols may still be
        # present: libprotobuf-LITE strips the FileDescriptorProto, so messages
        # exist on the wire but their names/numbers aren't in a descriptor table.
        # Report it detect-only (the `elif`-style guard: a FULL image already
        # produced cpp_names above and never reaches here).
        try:
            cpp_ns = cpp_protobuf_namespaces(ctx)
        except PROGRAM_ERRORS:
            raise
        except Exception as exc:
            _foreign_failed(ctx, "C++ libprotobuf", "namespace scan", exc)
            cpp_ns = {}
        if cpp_ns:
            total = sum(cpp_ns.values())
            # Detect-only — accepted limitation, see LIMITATIONS.md (9).
            note = ("%d google::protobuf symbol(s) [namespace(s): %s]; no embedded "
                    "FileDescriptorProto — libprotobuf-lite strips the descriptor "
                    "table, so message/field names + numbers are not recoverable"
                    % (total, ", ".join(sorted(cpp_ns))))
            out.append(SerializerSummary(CPP_LITE_SERIALIZER, False, [], note=note))

    try:
        sw_msgs, sw_enums, _mods = swift_protobuf_messages(ctx)
    except PROGRAM_ERRORS:
        raise
    except Exception as exc:
        _foreign_failed(ctx, "swift-protobuf", "conformance scan", exc)
        sw_msgs, sw_enums = [], []
    sw_names = sorted(sw_msgs) + sorted(sw_enums)
    if not sw_names:
        # The conformance-symbol detector reads the export trie, empty for cache
        # images; fall back to the qualified names the nameMap extractor recovers
        # (cache-native) so the inventory matches what extraction would emit.
        try:
            sw_names = sorted(m.qualified for m in _swift.swift_messages(ctx))
        except PROGRAM_ERRORS:
            raise
        except Exception as exc:
            _foreign_failed(ctx, "swift-protobuf", "detection", exc)
            sw_names = []
    if sw_names:
        out.append(SerializerSummary(SWIFT_SERIALIZER, True, sw_names))

    try:
        gpb_subs, _bases = google_protobuf_classes(ctx, cl)
    except PROGRAM_ERRORS:
        raise
    except Exception as exc:
        _foreign_failed(ctx, "Google protobuf-objc (GPBMessage)", "detection", exc)
        gpb_subs = []
    if gpb_subs:
        # Detect-only — accepted limitation, see LIMITATIONS.md (8), #64.
        out.append(SerializerSummary("Google protobuf-objc (GPBMessage)",
                                     False, sorted(gpb_subs)))

    try:
        pbc = protobufc_descriptors(ctx)
    except PROGRAM_ERRORS:
        raise
    except Exception as exc:
        _foreign_failed(ctx, PROTOBUFC_SERIALIZER, "detection", exc)
        pbc = None
    if pbc:
        # Detect-only — accepted limitation, see LIMITATIONS.md (12).  Names are the
        # descriptors' own (package-qualified) names; field layouts are not decoded.
        note = ("%d message + %d enum descriptor(s), %d _protobuf_c_* runtime symbol(s); "
                "field layouts (ProtobufCFieldDescriptor) are not decoded"
                % (len(pbc.messages), len(pbc.enums), len(pbc.symbols)))
        out.append(SerializerSummary(PROTOBUFC_SERIALIZER, False,
                                     pbc.messages, note=note))
    return out


def _foreign_failed(ctx, runtime: str, phase: str, exc: Exception) -> None:
    """A non-PBCodable runtime's *phase* raised: its messages are missing (or its detection
    is unreliable).  Recorded for the run summary / exit status and warned, never only
    debug-logged -- the 'DECODED' line printed earlier would otherwise be a false promise."""
    from proto.models import get_diagnostics
    get_diagnostics(ctx).foreign_errors.append((runtime, f"{phase}: {type(exc).__name__}: {exc}"))
    log.warning("%s %s FAILED (%s: %s); its messages may be missing from the output",
                runtime, phase, type(exc).__name__, exc)


def collect_foreign_messages(ctx, data: Optional[bytes]) -> List[ProtoMessage]:
    """All decodable non-PBCodable messages (C++ + swift), for the CLI to feed
    into the shared emitter.  Both serializers work in BOTH modes: with raw
    bytes (binary mode) C++ sweeps the whole image; cache-native it reads the
    descriptor sections / ``.symbols`` nlist through *ctx*."""
    out: List[ProtoMessage] = []
    try:
        out += _cpp_protos_to_messages(cpp_file_protos(ctx, data))
    except PROGRAM_ERRORS:
        raise
    except Exception as exc:
        _foreign_failed(ctx, "C++ libprotobuf", "message collection", exc)
    try:
        out += swift_messages(ctx)
    except PROGRAM_ERRORS:
        raise
    except Exception as exc:
        _foreign_failed(ctx, "swift-protobuf", "message collection", exc)
    return out
