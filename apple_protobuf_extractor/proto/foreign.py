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

Binary mode only: the C++ scan reads the raw image bytes and the Swift scan reads
the symbol table / export trie — both unavailable for cache-native images.
"""
from __future__ import annotations

import logging
import re
from typing import Dict, List, Optional

from serializers import cpp_descriptor_extract as _cpp
from serializers import swift_descriptor_extract as _swift

from .models import FieldLabel, ProtoEnum, ProtoEnumValue, ProtoField, ProtoMessage

log = logging.getLogger(__name__)

CPP_SERIALIZER = "C++ libprotobuf (google::protobuf)"
CPP_LITE_SERIALIZER = "C++ libprotobuf-lite (google::protobuf)"
SWIFT_SERIALIZER = "swift-protobuf"


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
               registry: "Dict[str, tuple]") -> ProtoField:
    ref_package = ref_file = None
    if f.type in (11, 14, 10):                       # message / enum / group
        # Resolve the (absolute) descriptor type name through the global
        # registry so a reference into ANOTHER package is emitted qualified
        # (``pkg.Type``) and a reference into ANOTHER source file is imported.
        # The flat emitter has one package per file; flattening a cross-package
        # ref with ``_`` produced a name no file defines, so protoc rejected it
        # ("X is not defined").  Qualification is by package, imports by file —
        # a package may span several source files (see _cpp_out_filename).
        fqn = f.type_name[1:] if f.type_name.startswith(".") else f.type_name
        entry = registry.get(fqn)
        if entry is not None:
            ref_package, type_name, ref_file = entry  # (pkg, flat name, out file)
        else:
            # Not an extracted type (external/unknown) — keep the old flatten
            # behaviour and leave it unqualified; nothing better is available.
            type_name = _flat(_cpp._ref(f.type_name, package))
    else:
        type_name = _cpp._FTYPE.get(f.type, "bytes")
    label = FieldLabel.REPEATED if f.label == 3 else FieldLabel.OPTIONAL
    note = "oneof member (flattened)" if f.oneof_index >= 0 else None
    return ProtoField(name=f.name, number=f.number, type_name=type_name,
                      label=label, number_confirmed=True, type_inference_note=note,
                      ref_package=ref_package, ref_file=ref_file)


def _cpp_enum(e: "_cpp.EnumType", name_prefix: str = "") -> ProtoEnum:
    # The flat emitter has no nested-enum syntax, so a nested enum is emitted at
    # file scope under the SAME parent-flattened name its field references use
    # (``Outer_Inner``).  ``name_prefix`` is the flattened owner-message name plus
    # ``_`` for a nested enum, or "" for a file-scope enum.  Without it the enum
    # would be declared as the bare leaf name while fields reference the
    # qualified name → protoc "X is not defined".
    return ProtoEnum(name=f"{name_prefix}{e.name}",
                     values=[ProtoEnumValue(name=n, number=num) for n, num in e.values],
                     values_confirmed=True)


def _cpp_out_filename(name: str) -> str:
    """Output ``.proto`` filename for an ORIGINAL C++ source file.

    Emitting one file per original ``FileDescriptorProto`` preserves that
    schema's (acyclic) import structure.  Merging a package's several source
    files into a single ``<package>.proto`` can introduce an import cycle protoc
    rejects ("File recursively imports itself"): file A (pkg P) imports gpsd and
    file B (also pkg P) is imported by gpsd — harmless as a chain, but the merge
    makes ``P.proto`` both import and be imported by gpsd.  Restoring the file
    boundaries breaks the cycle; no symbol collides because every ``pkg.Type`` is
    still defined exactly once (a package legitimately spans files, like
    ``google.protobuf``)."""
    base = name.rsplit("/", 1)[-1]
    if base.endswith(".proto"):
        base = base[:-len(".proto")]
    base = re.sub(r"[^a-z0-9_]", "_", base.lower()) or "cpp_protobuf"
    return f"{base}.proto"


def _cpp_message(m: "_cpp.Message", package: str, registry: "Dict[str, tuple]",
                 out_file: str, prefix: str = "") -> List[ProtoMessage]:
    """Flatten a C++ message (and its nested messages) to ProtoMessage objects."""
    qual = f"{prefix}{m.name}"
    flat_qual = _flat(qual)
    pkg = _sanitize_pkg(package) if package else "cpp_protobuf"
    out = [ProtoMessage(
        name=flat_qual, class_name=flat_qual, package=pkg,
        serializer=CPP_SERIALIZER, out_file=out_file,
        fields=[_cpp_field(f, package, registry) for f in m.fields],
        # Nested enums carry the flattened owner name so their emitted type name
        # matches the ``Outer_Inner`` reference produced by _cpp_field.
        enums=[_cpp_enum(e, name_prefix=f"{flat_qual}_") for e in m.enums],
    )]
    for n in m.nested:
        out += _cpp_message(n, package, registry, out_file, prefix=qual + ".")
    return out


def _cpp_type_registry(file_protos) -> "Dict[str, tuple]":
    """Map every message/enum's ABSOLUTE descriptor name (``pkg.Outer.Inner``,
    as it appears in a field's ``type_name``) to ``(sanitised_package,
    flat_name_within_that_package, output_filename)``.  Built over ALL files
    first so a field can resolve a reference into another package/file — the
    per-file flat emitter cannot express that without knowing both up front."""
    reg: Dict[str, tuple] = {}

    def walk(m, package: str, prefix: str, out_file: str) -> None:
        qual = f"{prefix}{m.name}"
        flat = _flat(qual)
        spkg = _sanitize_pkg(package) if package else "cpp_protobuf"
        reg[f"{package}.{qual}" if package else qual] = (spkg, flat, out_file)
        for e in m.enums:                            # nested enum: parent-flattened
            key = f"{package}.{qual}.{e.name}" if package else f"{qual}.{e.name}"
            reg[key] = (spkg, f"{flat}_{e.name}", out_file)
        for n in m.nested:
            walk(n, package, qual + ".", out_file)

    for fp in file_protos:
        out_file = _cpp_out_filename(fp.name)
        spkg = _sanitize_pkg(fp.package) if fp.package else "cpp_protobuf"
        for e in fp.enums:                           # file-scope enum: bare name
            key = f"{fp.package}.{e.name}" if fp.package else e.name
            reg[key] = (spkg, e.name, out_file)
        for m in fp.messages:
            walk(m, fp.package, "", out_file)
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
    # land in the same .proto).  Dropping them (the old behaviour) made every
    # field that referenced one fail protoc with "X is not defined".
    file_enums_by_out: Dict[str, List[ProtoEnum]] = {}
    first_msg_by_out: Dict[str, ProtoMessage] = {}
    for fp in file_protos:
        out_file = _cpp_out_filename(fp.name)
        for m in fp.messages:
            built = _cpp_message(m, fp.package, registry, out_file)
            out += built
            first_msg_by_out.setdefault(out_file, built[0])
        for e in fp.enums:                       # file-scope: no parent prefix
            file_enums_by_out.setdefault(out_file, []).append(_cpp_enum(e))

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
    """Drop duplicate ``(package, name)`` messages, keeping the first.

    The well-known ``descriptor.proto`` (package ``google.protobuf``) is embedded
    by — and so decoded once per — every C++ image that registers a descriptor,
    so the same messages can appear several times.  proto3 rejects a redefinition
    ("X is already defined"), so collapse exact-name duplicates within a package.
    A duplicate that DIFFERS in field count is surfaced (it would be a real
    conflict, not a benign re-decode) rather than silently dropped."""
    seen: Dict[tuple, ProtoMessage] = {}
    out: List[ProtoMessage] = []
    for m in messages:
        key = (m.package, m.name)
        prev = seen.get(key)
        if prev is None:
            seen[key] = m
            out.append(m)
            continue
        if len(prev.fields) != len(m.fields):
            log.warning("C++ message %r in package %r decoded twice with differing "
                        "field counts (%d vs %d); keeping the first",
                        m.name, m.package, len(prev.fields), len(m.fields))
    return out


def cpp_messages(data: bytes) -> List[ProtoMessage]:
    """Every C++ libprotobuf message embedded in *data*, as ProtoMessage objects."""
    return _cpp_protos_to_messages(_cpp.extract_cpp_protos(data))


def cpp_messages_from_ctx(ctx) -> List[ProtoMessage]:
    """Cache-native C++ recovery: read the embedded ``FileDescriptorProto``s from
    the image's descriptor sections through *ctx* (no on-disk byte image)."""
    return _cpp_protos_to_messages(_cpp.extract_cpp_protos_from_ctx(ctx))


# ── swift-protobuf ────────────────────────────────────────────────────────────

def swift_messages(ctx) -> List[ProtoMessage]:
    """Every swift-protobuf message in *ctx* (names + numbers; types unrecovered)."""
    out: List[ProtoMessage] = []
    for m in _swift.swift_messages(ctx):
        pkg = _sanitize_pkg(m.module) if m.module else "swift_protobuf"
        fields = [_swift_field(f) for f in m.fields]
        out.append(ProtoMessage(name=_flat(m.name), class_name=_flat(m.name),
                                package=pkg, serializer=SWIFT_SERIALIZER,
                                fields=fields))
    return out


def _swift_field(f) -> ProtoField:
    """Map a recovered swift field (name+number, optional proto_type) to a
    ProtoField.  ``proto_type`` like 'repeated int32' / 'map<string, int32>' /
    'Foo' is split into (label, type); absent types fall back to ``bytes``."""
    label, type_name, note = FieldLabel.OPTIONAL, "bytes", None
    t = f.proto_type
    if not t:
        note = "swift-protobuf: type not recovered"
    elif t.startswith("repeated "):
        label, type_name = FieldLabel.REPEATED, _flat(t[len("repeated "):])
    elif t.startswith("map<"):
        type_name = t                       # emitted verbatim (map<k, v>)
    else:
        type_name = _flat(t)
    # a recovered container whose element/value is a guess filler is flagged (#67)
    note = note or getattr(f, "type_note", None)
    return ProtoField(name=f.name, number=f.number, type_name=type_name,
                      label=label,
                      number_confirmed=getattr(f, "number_confirmed", True),
                      type_inference_note=note)


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
    * GPBMessage — the GPB subclass set (detected, not decodable).
    """
    from proto.extractor import (_proto_class_set, google_protobuf_classes,
                                 swift_protobuf_messages, cpp_protobuf_namespaces)
    out: List[SerializerSummary] = []

    pb = sorted(_proto_class_set(ctx, cl))
    if pb:
        out.append(SerializerSummary("Apple PBCodable (ObjC)", True, pb))

    cpp_names = []
    try:
        file_protos = (_cpp.extract_cpp_protos(data) if data
                       else _cpp.extract_cpp_protos_from_ctx(ctx))
        for fp in file_protos:
            for m in fp.messages:
                pfx = (fp.package + ".") if fp.package else ""
                cpp_names.append(pfx + m.name)
                cpp_names += [f"{pfx}{m.name}.{n.name}" for n in m.nested]
    except (NameError, ImportError):
        raise
    except Exception as exc:
        log.debug("C++ descriptor inventory failed: %s", exc)
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
        except (NameError, ImportError):
            raise
        except Exception as exc:
            log.debug("C++ namespace scan failed: %s", exc)
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
    except (NameError, ImportError):
        raise
    except Exception as exc:
        log.debug("swift conformance scan failed: %s", exc)
        sw_msgs, sw_enums = [], []
    sw_names = sorted(sw_msgs) + sorted(sw_enums)
    if not sw_names:
        # The conformance-symbol detector reads the export trie, empty for cache
        # images; fall back to the qualified names the nameMap extractor recovers
        # (cache-native) so the inventory matches what extraction would emit.
        try:
            sw_names = sorted(m.qualified for m in _swift.swift_messages(ctx))
        except (NameError, ImportError):
            raise
        except Exception as exc:
            log.debug("swift nameMap inventory failed: %s", exc)
            sw_names = []
    if sw_names:
        out.append(SerializerSummary(SWIFT_SERIALIZER, True, sw_names))

    try:
        gpb_subs, _bases = google_protobuf_classes(ctx, cl)
    except (NameError, ImportError):
        raise
    except Exception as exc:
        log.debug("GPBMessage detection failed: %s", exc)
        gpb_subs = []
    if gpb_subs:
        # Detect-only — accepted limitation, see LIMITATIONS.md (8), #64.
        out.append(SerializerSummary("Google protobuf-objc (GPBMessage)",
                                     False, sorted(gpb_subs)))
    return out


def collect_foreign_messages(ctx, data: Optional[bytes]) -> List[ProtoMessage]:
    """All decodable non-PBCodable messages (C++ + swift), for the CLI to feed
    into the shared emitter.  Both serializers work in BOTH modes: with raw
    bytes (binary mode) C++ sweeps the whole image; cache-native it reads the
    descriptor sections / ``.symbols`` nlist through *ctx*."""
    out: List[ProtoMessage] = []
    try:
        out += cpp_messages(data) if data else cpp_messages_from_ctx(ctx)
    except (NameError, ImportError):
        raise
    except Exception as exc:
        log.debug("C++ message collection failed: %s", exc)
    try:
        out += swift_messages(ctx)
    except (NameError, ImportError):
        raise
    except Exception as exc:
        log.debug("swift message collection failed: %s", exc)
    return out
