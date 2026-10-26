"""Recover ``.proto`` schemas from C++ ``libprotobuf`` (full, non-lite) binaries.

Unlike Apple ``PBCodable`` — whose field numbers/types must be reverse-engineered
from hand-emitted ``writeTo:``/``readFrom:`` ARM64 — a binary built against the
*full* C++ protobuf runtime embeds the **serialized ``FileDescriptorProto``** of
every ``.proto`` it compiles (the ``descriptor_table_protodef_*`` byte arrays the
generated ``.pb.cc`` registers with the descriptor pool).  That blob *is* the
schema: message/field/enum names, field numbers, types, labels, nesting — all of
it.  So recovery here is a clean decode, not an inference, and the output is exact.

This is self-contained: a minimal protobuf wire reader + just enough of
``descriptor.proto`` to round-trip a ``.proto`` (no dependency on the ``protobuf``
package, matching the rest of the tool's capstone-only footprint).

Note: libprotobuf-**lite** binaries do NOT embed descriptors (no names), so this
finds nothing there — detection of that case lives in
``proto.foreign_detect.cpp_protobuf_namespaces``.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field as dc_field
from typing import Dict, List, Optional, Tuple

from macho.memory import READ_ERRORS, record_unread


# ── minimal protobuf wire reader ─────────────────────────────────────────────

class _Reader:
    __slots__ = ("b", "p", "end")

    def __init__(self, b: bytes, p: int = 0, end: Optional[int] = None):
        self.b = b
        self.p = p
        self.end = len(b) if end is None else end

    def eof(self) -> bool:
        return self.p >= self.end

    def varint(self) -> int:
        r = s = 0
        while self.p < self.end:
            x = self.b[self.p]; self.p += 1
            r |= (x & 0x7F) << s
            if not (x & 0x80):
                return r
            s += 7
            if s > 70:
                break
        raise ValueError("truncated varint")

    def field(self) -> "Tuple[int, int, object]":
        """Return (field_number, wire_type, value)."""
        tag = self.varint()
        fn, wt = tag >> 3, tag & 7
        if fn == 0:
            raise ValueError("field 0")
        if wt == 0:
            return fn, wt, self.varint()
        if wt == 1:
            v = self.b[self.p:self.p + 8]; self.p += 8
            return fn, wt, v
        if wt == 2:
            ln = self.varint()
            if self.p + ln > self.end:
                raise ValueError("len past end")
            v = self.b[self.p:self.p + ln]; self.p += ln
            return fn, wt, v
        if wt == 5:
            v = self.b[self.p:self.p + 4]; self.p += 4
            return fn, wt, v
        raise ValueError(f"bad wire type {wt}")


def _s(v) -> str:
    return v.decode("utf-8", "replace") if isinstance(v, (bytes, bytearray)) else str(v)


# ── decoded descriptor model (subset of descriptor.proto) ────────────────────

# FieldDescriptorProto.Type -> proto type keyword (1-based).
_FTYPE = {
    1: "double", 2: "float", 3: "int64", 4: "uint64", 5: "int32",
    6: "fixed64", 7: "fixed32", 8: "bool", 9: "string", 10: "group",
    11: "message", 12: "bytes", 13: "uint32", 14: "enum", 15: "sfixed32",
    16: "sfixed64", 17: "sint32", 18: "sint64",
}
_LABEL = {1: "optional", 2: "required", 3: "repeated"}


@dataclass
class Field:
    name: str = ""
    number: int = 0
    label: int = 1
    type: int = 0
    type_name: str = ""          # for message/enum: fully-qualified ".pkg.Name"
    oneof_index: int = -1
    packed: bool = False
    has_packed: bool = False


@dataclass
class EnumType:
    name: str = ""
    values: List[Tuple[str, int]] = dc_field(default_factory=list)


@dataclass
class Message:
    name: str = ""
    fields: List[Field] = dc_field(default_factory=list)
    nested: List["Message"] = dc_field(default_factory=list)
    enums: List[EnumType] = dc_field(default_factory=list)
    oneofs: List[str] = dc_field(default_factory=list)


@dataclass
class FileProto:
    name: str = ""
    package: str = ""
    syntax: str = "proto2"
    dependencies: List[str] = dc_field(default_factory=list)
    messages: List[Message] = dc_field(default_factory=list)
    enums: List[EnumType] = dc_field(default_factory=list)


def _decode_enum(b: bytes) -> EnumType:
    e = EnumType()
    r = _Reader(b)
    while not r.eof():
        fn, wt, v = r.field()
        if fn == 1 and wt == 2:
            e.name = _s(v)
        elif fn == 2 and wt == 2:                 # EnumValueDescriptorProto
            vr = _Reader(v); vn = ""; num = 0
            while not vr.eof():
                f2, w2, v2 = vr.field()
                if f2 == 1 and w2 == 2:
                    vn = _s(v2)
                elif f2 == 2 and w2 == 0:
                    num = _zigzag_int32(v2)
            e.values.append((vn, num))
    return e


def _zigzag_int32(v: int) -> int:
    # descriptor numbers are plain int32 (not zigzag); just sign-correct 64-bit.
    return v - (1 << 64) if v >= (1 << 63) else v


def _decode_field(b: bytes) -> Field:
    f = Field()
    r = _Reader(b)
    while not r.eof():
        fn, wt, v = r.field()
        if fn == 1 and wt == 2:
            f.name = _s(v)
        elif fn == 3 and wt == 0:
            f.number = v
        elif fn == 4 and wt == 0:
            f.label = v
        elif fn == 5 and wt == 0:
            f.type = v
        elif fn == 6 and wt == 2:
            f.type_name = _s(v)
        elif fn == 9 and wt == 0:
            f.oneof_index = v
        elif fn == 8 and wt == 2:                 # FieldOptions
            o = _Reader(v)
            while not o.eof():
                of, ow, ov = o.field()
                if of == 2 and ow == 0:           # packed
                    f.packed = bool(ov); f.has_packed = True
    return f


def _decode_message(b: bytes) -> Message:
    m = Message()
    r = _Reader(b)
    while not r.eof():
        fn, wt, v = r.field()
        if fn == 1 and wt == 2:
            m.name = _s(v)
        elif fn == 2 and wt == 2:
            m.fields.append(_decode_field(v))
        elif fn == 3 and wt == 2:
            m.nested.append(_decode_message(v))
        elif fn == 4 and wt == 2:
            m.enums.append(_decode_enum(v))
        elif fn == 8 and wt == 2:                 # OneofDescriptorProto
            o = _Reader(v)
            while not o.eof():
                of, ow, ov = o.field()
                if of == 1 and ow == 2:
                    m.oneofs.append(_s(ov))
    return m


def decode_file_descriptor(blob: bytes) -> FileProto:
    """Decode a serialized ``FileDescriptorProto`` blob into a :class:`FileProto`."""
    fp = FileProto()
    r = _Reader(blob)
    while not r.eof():
        fn, wt, v = r.field()
        if fn == 1 and wt == 2:
            fp.name = _s(v)
        elif fn == 2 and wt == 2:
            fp.package = _s(v)
        elif fn == 3 and wt == 2:
            fp.dependencies.append(_s(v))
        elif fn == 4 and wt == 2:
            fp.messages.append(_decode_message(v))
        elif fn == 5 and wt == 2:
            fp.enums.append(_decode_enum(v))
        elif fn == 12 and wt == 2:
            fp.syntax = _s(v) or "proto2"
    return fp


# ── blob finder ──────────────────────────────────────────────────────────────

# Field 1 (name) of a FileDescriptorProto: 0x0a <len:varint> <"....proto">.
_PROTO_SUFFIX = re.compile(rb"\.proto")


def _name_fields(data: bytes):
    """``(start, length)`` of every byte run that can be a FileDescriptorProto's name field
    ending at a ``.proto`` in *data*: the name's length, as a one- or two-byte varint, stands
    just before it, and the field's tag (0x0a) before that.  The name is any text without a
    control character; :func:`decode_file_descriptor` decides."""
    for m in _PROTO_SUFFIX.finditer(data):
        end = run = m.end()
        while run > 0 and data[run - 1] >= 0x20 and end - run < 1 << 14:
            run -= 1                     # the name lies in the text run ending here
        for ln in range(len(".proto") + 1, end - run + 1):
            name = end - ln
            if ln < 0x80:
                head = name - 2
                ok = head >= 0 and data[name - 1] == ln
            else:
                head = name - 3
                ok = (head >= 0 and data[name - 2] == (ln & 0x7f) | 0x80
                      and data[name - 1] == ln >> 7)
            if ok and data[head] == 0x0a:
                yield head, ln
_FDP_TOP_FIELDS = frozenset(range(1, 13))   # FileDescriptorProto fields 1..12


def _blob_end(b: bytes, start: int) -> int:
    """Walk top-level fields from *start*; stop at the first byte that is not a
    valid FileDescriptorProto continuation (invalid tag, or a *second* field-1
    name, which marks the next concatenated descriptor)."""
    r = _Reader(b, start)
    seen_name = False
    while not r.eof():
        mark = r.p
        try:
            tag = r.varint()
        except ValueError:
            return mark
        fn, wt = tag >> 3, tag & 7
        if fn not in _FDP_TOP_FIELDS or wt not in (0, 1, 2, 5):
            return mark
        if fn == 1:
            if seen_name:                 # next descriptor begins here
                return mark
            seen_name = True
        try:
            if wt == 0:
                r.varint()
            elif wt == 1:
                r.p += 8
            elif wt == 5:
                r.p += 4
            elif wt == 2:
                ln = r.varint()
                if r.p + ln > r.end:
                    return mark
                r.p += ln
        except ValueError:
            return mark
        if r.p > r.end:
            return mark
    return r.p


def find_descriptor_blobs(data: bytes) -> List[Tuple[int, bytes]]:
    """Find every embedded ``FileDescriptorProto`` blob in *data*.

    Returns ``[(file_offset, blob_bytes), ...]``, de-duplicated by content.  Each
    blob is validated by a successful decode that recovers a ``.proto`` name."""
    out: List[Tuple[int, bytes]] = []
    seen: set = set()
    for start, ln in _name_fields(data):
        end = _blob_end(data, start)
        blob = data[start:end]
        if len(blob) < ln + 2:
            continue
        try:
            fp = decode_file_descriptor(blob)
        except ValueError:
            continue
        if not fp.name.endswith(".proto"):
            continue
        key = (fp.name, len(blob))
        if key in seen:
            continue
        seen.add(key)
        out.append((start, blob))
    return out


def extract_cpp_protos(data: bytes) -> List[FileProto]:
    """Decode every embedded C++ ``FileDescriptorProto`` in a Mach-O image's bytes."""
    return [decode_file_descriptor(blob) for _, blob in find_descriptor_blobs(data)]


# The generated ``descriptor_table_protodef_*`` arrays are ``const char[]``: in a ``__const``
# (``__TEXT``'s, or a data segment's), ``__cstring`` or ``__data`` section, whichever segment
# holds it.  A whole-file regex sweep (binary mode) needs no section list, but cache-native
# there is no contiguous on-disk image, so these sections are read through the cache reader.
_DESC_SECTIONS = ("__const", "__cstring", "__data")


def extract_cpp_protos_from_ctx(ctx) -> List[FileProto]:
    """Cache-native counterpart to :func:`extract_cpp_protos`.

    Scans the image's descriptor-bearing sections through *ctx* (every read
    routes via the dyld-cache reader) rather than sweeping a whole on-disk byte
    image, which a cache image does not have.  Each blob is self-contained, so a
    per-section sweep recovers the same ``FileDescriptorProto``s; results are
    de-duplicated by ``(name, length)`` exactly as the whole-file finder."""
    out: List[FileProto] = []
    seen: set = set()
    for s in ctx.sections_named(*_DESC_SECTIONS):
        try:
            data = ctx.read_bytes(s.vmaddr, s.vmsize)
        except READ_ERRORS as exc:
            record_unread(ctx, "descriptor section", f"{s.segname},{s.name}", exc)
            continue
        for _off, blob in find_descriptor_blobs(data):
            try:
                fp = decode_file_descriptor(blob)
            except ValueError:
                continue
            key = (fp.name, len(blob))
            if key in seen:
                continue
            seen.add(key)
            out.append(fp)
    return out


# ── .proto emitter ───────────────────────────────────────────────────────────

def _ref(type_name: str, package: str) -> str:
    """Render a message/enum type reference, trimming the leading dot and the
    file's own package prefix for readability."""
    t = type_name[1:] if type_name.startswith(".") else type_name
    if package and t.startswith(package + "."):
        t = t[len(package) + 1:]
    return t


def _emit_enum(e: EnumType, ind: str, out: List[str]) -> None:
    out.append(f"{ind}enum {e.name} {{")
    for name, num in e.values:
        out.append(f"{ind}  {name} = {num};")
    out.append(f"{ind}}}")


def _emit_message(m: Message, package: str, proto3: bool, ind: str,
                  out: List[str]) -> None:
    out.append(f"{ind}message {m.name} {{")
    inner = ind + "  "
    for e in m.enums:
        _emit_enum(e, inner, out)
    for n in m.nested:
        _emit_message(n, package, proto3, inner, out)
    # group fields by oneof
    plain = [f for f in m.fields if f.oneof_index < 0]
    by_oneof: Dict[int, List[Field]] = {}
    for f in m.fields:
        if f.oneof_index >= 0:
            by_oneof.setdefault(f.oneof_index, []).append(f)
    for f in plain:
        out.append(inner + _emit_field(f, package, proto3))
    for idx, fs in sorted(by_oneof.items()):
        oname = m.oneofs[idx] if idx < len(m.oneofs) else f"oneof_{idx}"
        out.append(f"{inner}oneof {oname} {{")
        for f in fs:
            out.append("  " + inner + _emit_field(f, package, proto3, in_oneof=True))
        out.append(f"{inner}}}")
    out.append(f"{ind}}}")


def _emit_field(f: Field, package: str, proto3: bool, in_oneof: bool = False) -> str:
    tname = _ref(f.type_name, package) if f.type in (11, 14, 10) else _FTYPE.get(f.type, "bytes")
    parts = []
    if not in_oneof:
        # proto3 omits 'optional'/'required'; keep 'repeated'
        if f.label == 3:
            parts.append("repeated")
        elif not proto3:
            parts.append(_LABEL.get(f.label, "optional"))
        elif f.label == 2:
            parts.append("required")
    parts.append(tname)
    parts.append(f.name)
    line = " ".join(parts) + f" = {f.number}"
    if f.has_packed and f.label == 3:
        line += f" [packed={'true' if f.packed else 'false'}]"
    return line + ";"


def format_proto(fp: FileProto) -> str:
    proto3 = fp.syntax == "proto3"
    out: List[str] = [f'syntax = "{fp.syntax}";']
    if fp.package:
        out.append(f"package {fp.package};")
    for dep in fp.dependencies:
        out.append(f'import "{dep}";')
    out.append("")
    for e in fp.enums:
        _emit_enum(e, "", out); out.append("")
    for m in fp.messages:
        _emit_message(m, fp.package, proto3, "", out); out.append("")
    return "\n".join(out).rstrip() + "\n"


# ── CLI ──────────────────────────────────────────────────────────────────────

def _safe_output_path(out_dir: str, name: str) -> str:
    """Resolve a descriptor's own ``name`` (e.g. ``"deprecated/Foo.proto"``) to a
    path under *out_dir*, preserving any directory component.

    ``FileDescriptorProto.name`` is protobuf's pool-unique logical path for a
    file -- every other file's ``dependency`` list references this exact
    string to mean "import this file". Writing to that path (rather than
    flattening to a basename) keeps the emitted ``import "..."`` lines
    resolvable by ``protoc`` without any rewriting.

    ``name`` comes from decoding untrusted binary bytes, so this also guards
    against a descriptor claiming an absolute path or a ``..`` escape (the
    same class of bug as zip-slip) rather than trusting it outright.
    """
    if os.path.isabs(name):
        raise ValueError(f"refusing to write absolute proto path: {name!r}")
    out_real = os.path.realpath(out_dir)
    target = os.path.realpath(os.path.join(out_dir, name))
    if target != out_real and not target.startswith(out_real + os.sep):
        raise ValueError(f"refusing to write outside output dir: {name!r}")
    return target


def _main(argv: List[str]) -> int:
    import argparse
    ap = argparse.ArgumentParser(
        description="Recover .proto schemas from a C++ libprotobuf Mach-O binary "
                    "by decoding its embedded FileDescriptorProto descriptors.")
    ap.add_argument("binary", help="path to an arm64 Mach-O (single-arch slice)")
    ap.add_argument("-o", "--out", help="output dir (one .proto per file); default: stdout")
    args = ap.parse_args(argv)

    with open(args.binary, "rb") as fh:
        data = fh.read()
    protos = extract_cpp_protos(data)
    if not protos:
        print("no embedded FileDescriptorProto found "
              "(lite runtime, or not a C++ libprotobuf binary)")
        return 1
    if args.out:
        os.makedirs(args.out, exist_ok=True)
        written = 0
        for fp in protos:
            try:
                path = _safe_output_path(args.out, fp.name)
            except ValueError as exc:
                print(f"skipping {fp.name!r}: {exc}")
                continue
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as fh:
                fh.write(format_proto(fp))
            written += 1
        print(f"wrote {written} .proto file(s) to {args.out}")
    else:
        for fp in protos:
            print(f"// ===== {fp.name} =====")
            print(format_proto(fp))
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(_main(sys.argv[1:]))
