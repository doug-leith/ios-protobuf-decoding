"""proto/foreign.py — adapt C++ / swift-protobuf descriptors into ProtoMessage,
and the emitter's serializer-provenance attribution.

Offline tests build C++ FileProto / Swift SwiftMessage objects directly and check
the conversion (flattening, types, package, serializer) and the emitter's header /
per-message serializer comments.  Live tests run the adapters on real binaries.
"""
import os
import unittest

from serializers import cpp_descriptor_extract as C
from serializers import swift_descriptor_extract as SW
from proto import foreign as F
from proto.emitter import build_proto_files
from proto.models import FieldLabel, ProtoField, ProtoMessage
from tests._fakes import NoImage


class TestHelpers(unittest.TestCase):
    def test_flat(self):
        self.assertEqual(F._flat(".pkg.Outer.Inner"), "pkg_Outer_Inner")
        self.assertEqual(F._flat("Outer.Inner"), "Outer_Inner")
        self.assertEqual(F._flat("Simple"), "Simple")

    def test_sanitize_pkg(self):
        self.assertEqual(F._sanitize_pkg("BookDataStore"), "bookdatastore")
        self.assertEqual(F._sanitize_pkg("wireless_diagnostics"), "wireless_diagnostics")
        self.assertEqual(F._sanitize_pkg(""), "messages")


class TestCppAdapter(unittest.TestCase):
    def _fileproto(self):
        fp = C.FileProto(name="t.proto", package=" pkg".strip(), syntax="proto3")
        inner = C.Message(name="Inner", fields=[
            C.Field(name="x", number=1, label=1, type=5),          # int32
        ])
        color = C.EnumType(name="Color", values=[("RED", 0), ("GREEN", 1)])
        mode  = C.EnumType(name="Mode", values=[("ON", 0), ("OFF", 1)])   # file-scope
        m = C.Message(
            name="Outer",
            fields=[
                C.Field(name="n", number=1, label=3, type=5),               # repeated int32
                C.Field(name="child", number=2, label=1, type=11,
                        type_name=".pkg.Outer.Inner"),                       # nested message ref
                C.Field(name="col", number=3, label=1, type=14,
                        type_name=".pkg.Outer.Color"),                       # nested enum ref
                C.Field(name="mode", number=4, label=1, type=14,
                        type_name=".pkg.Mode"),                              # file-scope enum ref
            ],
            nested=[inner],
            enums=[color],
        )
        fp.messages = [m]
        fp.enums = [mode]            # file-scope enum (BUG 3a regression guard)
        return fp

    def test_flatten_and_types(self):
        # Use _cpp_protos_to_messages so file-scope enums are carried (3a).
        msgs = F._cpp_protos_to_messages([self._fileproto()])
        by = {m.name: m for m in msgs}
        self.assertIn("Outer", by)
        self.assertIn("Outer_Inner", by)                  # nested message flattened
        outer = by["Outer"]
        self.assertEqual(outer.serializer, F.CPP_SERIALIZER)
        self.assertEqual(outer.package, "pkg")
        fields = {f.name: f for f in outer.fields}
        self.assertEqual(fields["n"].label, FieldLabel.REPEATED)
        self.assertEqual(fields["n"].type_name, "int32")
        self.assertEqual(fields["child"].type_name, "Outer_Inner")   # message ref flattened
        # 3b: a nested enum's reference and declaration both use the
        # parent-flattened name (was "Color" on the ref but "Color" on the decl
        # vs "Outer_Color" on the ref — a mismatch that broke protoc).
        self.assertEqual(fields["col"].type_name, "Outer_Color")
        # 3a: a file-scope enum reference resolves to the bare name.
        self.assertEqual(fields["mode"].type_name, "Mode")
        self.assertTrue(all(f.number_confirmed for f in outer.fields))
        # Both the nested (renamed) and the file-scope (carried) enum are present
        # in the adapted messages, so every reference above has a declaration.
        enum_names = {e.name for mm in msgs for e in mm.enums}
        self.assertIn("Outer_Color", enum_names)   # 3b
        self.assertIn("Mode", enum_names)          # 3a
        outer_color = next(e for mm in msgs for e in mm.enums if e.name == "Outer_Color")
        self.assertEqual([(v.name, v.number) for v in outer_color.values],
                         [("RED", 0), ("GREEN", 1)])

    def test_emits_valid_proto(self):
        msgs = F._cpp_protos_to_messages([self._fileproto()])
        pf = build_proto_files(msgs, source_name="x")[0]
        out = pf.emit()
        self.assertIn(f"// Serializer: {F.CPP_SERIALIZER}", out)
        self.assertIn("message Outer_Inner {", out)
        self.assertIn("repeated int32 n = 1;", out)
        self.assertIn("Outer_Inner child = 2;", out)
        # 3a/3b: every referenced enum is also DECLARED under the same name, so
        # protoc cannot raise "X is not defined".
        self.assertIn("enum Outer_Color {", out)
        self.assertIn("Outer_Color col = 3;", out)
        self.assertIn("enum Mode {", out)
        self.assertIn("Mode mode = 4;", out)
        # pure-foreign file: names are authoritative (decoded from the
        # descriptor), so neither the package nor the enum-type recon note appears.
        self.assertNotIn("reconstructed from the ObjC class-name prefix", out)
        self.assertNotIn("type name reconstructed from value-string prefix", out)

    def _two_package_protos(self):
        # Package "a" message A references package "b" message B and enum b.E
        # (cross-package, acyclic).  Mirrors addr_obj -> addr_obj.geo3.
        fa = C.FileProto(name="a.proto", package="a", syntax="proto3")
        fa.messages = [C.Message(name="A", fields=[
            C.Field(name="b", number=1, label=1, type=11, type_name=".b.B"),
            C.Field(name="e", number=2, label=1, type=14, type_name=".b.E"),
        ])]
        fb = C.FileProto(name="b.proto", package="b", syntax="proto3")
        fb.messages = [C.Message(name="B", fields=[
            C.Field(name="x", number=1, label=1, type=5)])]
        fb.enums = [C.EnumType(name="E", values=[("E_A", 0)])]
        return [fa, fb]

    def test_cross_package_ref_qualified_and_imported(self):
        msgs = F._cpp_protos_to_messages(self._two_package_protos())
        files = {pf.package: pf for pf in build_proto_files(msgs, source_name="x")}
        a = files["a"].emit()
        # 3c: cross-package message AND enum refs are package-qualified.
        self.assertIn("b.B b = 1;", a)
        self.assertIn("b.E e = 2;", a)
        # and the dependency file is imported.
        self.assertIn('import "b.proto";', a)

    def test_same_package_ref_stays_flat(self):
        # A ref within the same package must NOT be qualified or imported.
        msgs = F._cpp_protos_to_messages([self._fileproto()])
        pf = build_proto_files(msgs, source_name="x")[0]
        out = pf.emit()
        self.assertIn("Outer_Inner child = 2;", out)     # flat, no "pkg."
        self.assertNotIn("import ", out)

    def test_duplicate_messages_deduped(self):
        # The same package+message decoded twice (e.g. descriptor.proto embedded
        # by several images) collapses to one — proto3 forbids redefinition.
        fp1 = C.FileProto(name="d1.proto", package="google.protobuf", syntax="proto3")
        fp1.messages = [C.Message(name="Dup", fields=[
            C.Field(name="x", number=1, label=1, type=5)])]
        fp2 = C.FileProto(name="d2.proto", package="google.protobuf", syntax="proto3")
        fp2.messages = [C.Message(name="Dup", fields=[
            C.Field(name="x", number=1, label=1, type=5)])]
        msgs = F._cpp_protos_to_messages([fp1, fp2])
        dups = [m for m in msgs if m.name == "Dup"]
        self.assertEqual(len(dups), 1)

    def test_referenced_enums_all_declared(self):
        # Compile-soundness invariant: every enum a field references must be
        # declared somewhere in the file (guards 3a/3b against regression without
        # needing protoc in the test environment).
        msgs = F._cpp_protos_to_messages([self._fileproto()])
        declared = {e.name for m in msgs for e in m.enums}
        referenced = {f.type_name for m in msgs for f in m.fields
                      if f.type_name in {"Outer_Color", "Mode"}}
        self.assertTrue(referenced <= declared,
                        f"undeclared enum refs: {referenced - declared}")


# ── TestCppByFileGrouping (3e) ────────────────────────────────────────────────
#
# A C++ package may be split across several source files.  Merging them into one
# <package>.proto can create an import cycle protoc rejects ("File recursively
# imports itself").  Emit one file per ORIGINAL source file instead: same-package
# references then import by FILE (not qualified by package), and the original
# acyclic import graph is preserved.

class TestCppByFileGrouping(unittest.TestCase):

    def _same_pkg_two_files(self):
        # package "p" split across two source files; Aaa.proto's A references
        # Bbb.proto's B (same package, different file).
        fa = C.FileProto(name="dir/Aaa.proto", package="p", syntax="proto3")
        fa.messages = [C.Message(name="A", fields=[
            C.Field(name="b", number=1, label=1, type=11, type_name=".p.B")])]
        fb = C.FileProto(name="dir/Bbb.proto", package="p", syntax="proto3")
        fb.messages = [C.Message(name="B", fields=[
            C.Field(name="x", number=1, label=1, type=5)])]
        return [fa, fb]

    def test_one_output_file_per_source_file(self):
        msgs = F._cpp_protos_to_messages(self._same_pkg_two_files())
        # out_file set from the original source-file basename (sanitised).
        self.assertEqual({m.out_file for m in msgs}, {"aaa.proto", "bbb.proto"})
        files = {pf.filename: pf for pf in build_proto_files(msgs, source_name="x")}
        self.assertEqual(set(files), {"aaa.proto", "bbb.proto"})
        # both files declare the SAME package (a package legitimately spans files)
        self.assertEqual(files["aaa.proto"].package, "p")
        self.assertEqual(files["bbb.proto"].package, "p")

    def test_cross_file_same_package_imported_not_qualified(self):
        msgs = F._cpp_protos_to_messages(self._same_pkg_two_files())
        files = {pf.filename: pf for pf in build_proto_files(msgs, source_name="x")}
        a = files["aaa.proto"].emit()
        self.assertIn('import "bbb.proto";', a)   # imported by FILE
        self.assertIn("B b = 1;", a)              # NOT package-qualified (same pkg)
        self.assertNotIn("p.B b", a)

    def test_by_file_breaks_the_package_merge_cycle(self):
        # The real shape: A (pkg p) -> G (pkg g) -> C (pkg p).  A chain.  Merging
        # A and C into one p.proto makes p<->g mutually import (a cycle).  By file,
        # a.proto -> g.proto -> c.proto stays acyclic.
        fA = C.FileProto(name="A.proto", package="p", syntax="proto3")
        fA.messages = [C.Message(name="MA", fields=[
            C.Field(name="g", number=1, label=1, type=11, type_name=".g.MG")])]
        fG = C.FileProto(name="G.proto", package="g", syntax="proto3")
        fG.messages = [C.Message(name="MG", fields=[
            C.Field(name="c", number=1, label=1, type=11, type_name=".p.MC")])]
        fC = C.FileProto(name="C.proto", package="p", syntax="proto3")
        fC.messages = [C.Message(name="MC", fields=[
            C.Field(name="x", number=1, label=1, type=5)])]
        msgs = F._cpp_protos_to_messages([fA, fG, fC])
        files = {pf.filename: pf for pf in build_proto_files(msgs, source_name="x")}
        a_imp, g_imp = set(files["a.proto"].imports), set(files["g.proto"].imports)
        self.assertIn("g.proto", a_imp)            # A -> G
        self.assertIn("c.proto", g_imp)            # G -> C
        self.assertNotIn("a.proto", g_imp)         # NOT G -> A (the merge cycle)

    def test_pbcodable_message_still_groups_by_package(self):
        # Blast-radius guard: a PBCodable message (out_file=None) is untouched by
        # the C++ by-file path — still one file per package.
        m = ProtoMessage(name="Foo", class_name="GEOFoo")
        self.assertIsNone(m.out_file)
        pf = build_proto_files([m], source_name="x")[0]
        self.assertEqual(pf.filename, "geo.proto")


def _v(n):                                  # varint
    out = bytearray()
    while True:
        b = n & 0x7F; n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def _ld(field, payload):                    # length-delimited (wire type 2)
    return _v(field << 3 | 2) + _v(len(payload)) + payload


def _vf(field, value):                      # varint field (wire type 0)
    return _v(field << 3 | 0) + _v(value)


def _cpp_file_blob(name):
    """A minimal serialized FileDescriptorProto: name + one message {int32 x=1}."""
    fx = _ld(1, b"x") + _vf(3, 1) + _vf(4, 1) + _vf(5, 5)
    return _ld(1, name.encode()) + _ld(2, b"pkg") + _ld(4, _ld(1, b"Msg") + _ld(2, fx))


class _SectionCtx(NoImage):
    """ctx exposing one __TEXT,__const section of bytes (for the cache C++ path)."""
    class _Sec:
        def __init__(self, va, size):
            self.vmaddr, self.vmsize = va, size

    def __init__(self, va, data):
        self._va, self._data = va, data

    def has_section(self, seg, sec):
        return (seg, sec) == ("__TEXT", "__const")

    def section(self, seg, sec):
        return self._Sec(self._va, len(self._data))

    def is_variable(self, vmaddr):        # no program data, no binds
        return False

    def read_bytes(self, va, n):
        if self._va <= va and va + n <= self._va + len(self._data):
            return self._data[va - self._va: va - self._va + n]
        raise ValueError("oob")


class TestCppFromCtxAdapter(unittest.TestCase):
    """Cache-native (no image bytes) the C++ scan reads descriptor blobs through ctx sections."""
    def test_cpp_messages_from_ctx(self):
        ctx = _SectionCtx(0x4000, b"\x00" * 8 + _cpp_file_blob("widget.proto"))
        msgs = F._cpp_protos_to_messages(F.cpp_file_protos(ctx))
        by = {m.name: m for m in msgs}
        self.assertIn("Msg", by)
        self.assertEqual(by["Msg"].serializer, F.CPP_SERIALIZER)
        self.assertEqual(by["Msg"].package, "pkg")
        self.assertEqual(by["Msg"].fields[0].type_name, "int32")

    def test_cpp_messages_from_ctx_empty(self):
        self.assertEqual(F.cpp_file_protos(_SectionCtx(0x4000, b"no protos here")), [])


class TestCollectForeignMessages(unittest.TestCase):
    """The orchestrator merges C++ (whole-bytes binary mode / section-scan cache
    mode) with swift, never raising even when a serializer scan fails."""
    def test_binary_mode_uses_whole_bytes(self):
        data = b"\x00" * 4 + _cpp_file_blob("bin.proto")
        orig = SW.swift_messages
        SW.swift_messages = lambda ctx: []          # no swift in this fixture
        try:
            msgs = F.collect_foreign_messages(ctx=NoImage(), data=data)
        finally:
            SW.swift_messages = orig
        self.assertTrue(any(m.name == "Msg" and m.serializer == F.CPP_SERIALIZER
                            for m in msgs))

    def test_cache_mode_merges_cpp_and_swift(self):
        ctx = _SectionCtx(0x4000, _cpp_file_blob("cache.proto"))
        sm = [SW.SwiftMessage(module="mod", name="SwMsg",
                              fields=[SW.SwiftField(1, "a", proto_type="bool")])]
        orig = SW.swift_messages
        SW.swift_messages = lambda c: sm
        try:
            msgs = F.collect_foreign_messages(ctx=ctx, data=None)   # cache mode
        finally:
            SW.swift_messages = orig
        sers = {m.name: m.serializer for m in msgs}
        self.assertEqual(sers.get("Msg"), F.CPP_SERIALIZER)        # via section scan
        self.assertEqual(sers.get("SwMsg"), F.SWIFT_SERIALIZER)

    def test_scan_failure_is_swallowed(self):
        # a ctx whose section read raises must not propagate out of the collector
        class _Boom(NoImage):
            def has_section(self, *_):
                return True
            def section(self, *_):
                raise RuntimeError("boom")
        orig = SW.swift_messages
        SW.swift_messages = lambda c: []
        try:
            self.assertEqual(F.collect_foreign_messages(ctx=_Boom(), data=None), [])
        finally:
            SW.swift_messages = orig


class TestSwiftAdapter(unittest.TestCase):
    class _FakeSwiftCtx(NoImage):
        pass

    def test_swift_message_to_proto(self):
        sm = [
            SW.SwiftMessage(module="bookdatastored", name="PBPropertyValue",
                            fields=[SW.SwiftField(1, "createdAt"),
                                    SW.SwiftField(2, "identifier", proto_type="string"),
                                    SW.SwiftField(3, "tags", proto_type="repeated string")]),
            SW.SwiftMessage(module="m", name="Outer.Inner",
                            fields=[SW.SwiftField(1, "a")]),
        ]
        # monkeypatch the underlying extractor to return our fixtures
        orig = SW.swift_messages
        SW.swift_messages = lambda ctx: sm
        try:
            msgs = F.swift_messages(self._FakeSwiftCtx())
        finally:
            SW.swift_messages = orig
        by = {m.name: m for m in msgs}
        self.assertEqual(by["PBPropertyValue"].package, "bookdatastored")
        self.assertEqual(by["PBPropertyValue"].serializer, F.SWIFT_SERIALIZER)
        flds = {f.name: f for f in by["PBPropertyValue"].fields}
        # no proto_type -> bytes + note
        self.assertEqual(flds["createdAt"].type_name, "bytes")
        self.assertIn("type not recovered", flds["createdAt"].type_inference_note)
        # recovered scalar -> real type, no note
        self.assertEqual(flds["identifier"].type_name, "string")
        self.assertIsNone(flds["identifier"].type_inference_note)
        # recovered repeated -> label + element type
        self.assertEqual((flds["tags"].label, flds["tags"].type_name),
                         (FieldLabel.REPEATED, "string"))
        self.assertIn("Outer_Inner", by)                  # dotted name flattened

    def test_swift_field_map_and_message_ref(self):
        # map<> proto_type is emitted verbatim; a message-ref type is flattened.
        f_map = F._swift_field(SW.SwiftField(1, "lut", proto_type="map<string, int32>"))
        self.assertEqual(f_map.type_name, "map<string, int32>")
        self.assertEqual(f_map.label, FieldLabel.OPTIONAL)
        self.assertIsNone(f_map.type_inference_note)
        f_msg = F._swift_field(SW.SwiftField(2, "child", proto_type="Pkg.Inner"))
        self.assertEqual(f_msg.type_name, "Pkg_Inner")    # dotted ref flattened
        self.assertEqual(f_msg.label, FieldLabel.OPTIONAL)


class TestSwiftTypeResolution(unittest.TestCase):
    """Swift field types must resolve to something the emitted .proto can
    reference (the output used to fail under protoc: nested types by short name,
    other-module / well-known types and enums undefined)."""
    def _types(self):
        msgs = [SW.SwiftMessage(module="M", name="Outer"),
                SW.SwiftMessage(module="M", name="Outer.Inner"),
                SW.SwiftMessage(module="M", name="Other.Inner"),
                SW.SwiftMessage(module="Lib", name="Shared")]
        return F._SwiftTypes(msgs, {"Mode", "Outer.Kind"})

    def _field(self, t):
        return F._swift_field(SW.SwiftField(1, "f", proto_type=t), "M", self._types())

    def test_nested_reference_uses_the_qualified_flat_name(self):
        # two messages nest an `Inner`; the qualified ref picks the right one
        self.assertEqual(self._field("Outer.Inner").type_name, "Outer_Inner")
        self.assertEqual(self._field("Other.Inner").type_name, "Other_Inner")

    def test_repeated_message_reference(self):
        f = self._field("repeated Outer.Inner")
        self.assertEqual((f.label, f.type_name), (FieldLabel.REPEATED, "Outer_Inner"))

    def test_other_module_message_in_same_image_gets_package(self):
        f = self._field("Shared")
        self.assertEqual((f.type_name, f.ref_package), ("Shared", F._sanitize_pkg("Lib")))

    def test_external_type_degrades_to_bytes_and_is_flagged(self):
        f = self._field("Ckcode_RecordTransport")
        self.assertEqual(f.type_name, "bytes")
        self.assertEqual(f.unresolved_type_class, "Ckcode_RecordTransport")
        self.assertIn("outside this image", f.type_inference_note)

    def test_local_enum_is_int32_with_note(self):
        f = self._field("Mode")
        self.assertEqual(f.type_name, "int32")
        self.assertIsNone(f.unresolved_type_class)
        self.assertIn("enum Mode", f.type_inference_note)
        self.assertEqual(self._field("Outer.Kind").type_name, "int32")

    def test_scalars_untouched(self):
        for t in ("int32", "string", "bytes", "bool", "double"):
            f = self._field(t)
            self.assertEqual((f.type_name, f.type_inference_note), (t, None))

    def test_map_value_resolved_or_degraded(self):
        self.assertEqual(self._field("map<string, Outer.Inner>").type_name,
                         "map<string, Outer_Inner>")
        self.assertEqual(self._field("map<string, Gone>").type_name, "map<string, bytes>")
        self.assertEqual(self._field("map<string, Mode>").type_name, "map<string, int32>")
        # a value in another module cannot be package-qualified inside map<>
        self.assertEqual(self._field("map<string, Shared>").type_name, "map<string, bytes>")

    def test_unqualified_call_keeps_old_flatten_only_behaviour(self):
        f = F._swift_field(SW.SwiftField(2, "child", proto_type="Pkg.Inner"))
        self.assertEqual(f.type_name, "Pkg_Inner")


class TestSwiftEnumEmission(unittest.TestCase):
    def _enum(self, name, *cases):
        return SW.SwiftMessage(module="M", name=name, is_enum=True,
                               fields=[SW.SwiftField(n, c) for n, c in cases])

    def test_aliases_become_a_comment_not_a_duplicate_number(self):
        e = F._swift_enum(self._enum("E", (0, "A"), (1, "B"), (1, "B2"), (2, "C")))
        self.assertEqual([(v.name, v.number) for v in e.values], [("A", 0), ("B", 1), ("C", 2)])
        self.assertIn("B2", e.values[1].comment)

    def test_negative_and_zero_values_kept(self):
        e = F._swift_enum(self._enum("E", (-5, "N"), (0, "Z")))
        self.assertEqual([v.number for v in e.values], [-5, 0])

    def test_case_and_underscore_collision_is_renamed(self):
        # protoc: "Enum name CAPTION2 has the same name as CAPTION_2 if you ignore case ..."
        e = F._swift_enum(self._enum("Style", (0, "CAPTION_2"), (1, "CAPTION2"), (2, "BODY")))
        names = [v.name for v in e.values]
        self.assertEqual(names[0], "CAPTION_2")
        self.assertNotEqual(names[1], "CAPTION2")
        self.assertIn("renamed from CAPTION2", e.values[1].comment)
        self.assertEqual(names[2], "BODY")

    def test_value_names_are_unique_across_enums_of_a_package(self):
        taken = {"M", "E1", "E2"}
        e1 = F._swift_enum(self._enum("E1", (0, "CAPTION"), (1, "CAPTION2")), taken)
        e2 = F._swift_enum(self._enum("E2", (0, "CAPTION"), (1, "BODY")), taken)
        names = [v.name for v in e1.values + e2.values]
        self.assertEqual(len(names), len(set(names)))                  # package-unique
        self.assertEqual(e1.values[0].name, "CAPTION")
        self.assertEqual(e2.values[0].name, "CAPTION_2")
        self.assertIn("unique within its package", e2.values[0].comment)

    def test_package_rename_cannot_recreate_the_case_collision(self):
        # the emitter's own rename of a duplicate CAPTION to CAPTION_2 collided with a
        # real CAPTION2 in the SAME enum (SnippetKit NamedFont)
        taken = {"M", "E", "Other"}
        F._swift_enum(self._enum("Other", (0, "CAPTION")), taken)
        e = F._swift_enum(self._enum("E", (0, "CAPTION"), (1, "CAPTION2")), taken)
        norm = [v.name.replace("_", "").lower() for v in e.values]
        self.assertEqual(len(norm), len(set(norm)))

    def test_prefix_is_ignored_when_comparing(self):
        e = F._swift_enum(self._enum("Kind", (0, "KIND_FOO_BAR"), (1, "KIND_FOOBAR")))
        self.assertNotEqual(e.values[0].name, e.values[1].name)
        self.assertIn("renamed", e.values[1].comment)


class TestEmitterMixedSerializer(unittest.TestCase):
    def test_mixed_file_tags_each_message(self):
        pb = ProtoMessage(name="PBThing", class_name="PBThing",
                          fields=[ProtoField("a", 1, "int32", FieldLabel.OPTIONAL)])
        sw = ProtoMessage(name="SwThing", class_name="SwThing", package="geo",
                          serializer=F.SWIFT_SERIALIZER,
                          fields=[ProtoField("b", 1, "bytes", FieldLabel.OPTIONAL)])
        # force both into one package/file
        pb.package = "geo"
        pf = build_proto_files([pb, sw], source_name="x")[0]
        out = pf.emit()
        self.assertIn("// Serializer:", out)
        self.assertIn("Apple PBCodable (ObjC)", out)
        self.assertIn(F.SWIFT_SERIALIZER, out)
        # mixed → per-message serializer comment
        self.assertIn("// serializer: Apple PBCodable (ObjC)", out)
        self.assertIn(f"// serializer: {F.SWIFT_SERIALIZER}", out)

    def test_single_serializer_no_per_message_tag(self):
        pb = ProtoMessage(name="PBThing", class_name="PBThing",
                          fields=[ProtoField("a", 1, "int32", FieldLabel.OPTIONAL)])
        out = build_proto_files([pb], source_name="x")[0].emit()
        self.assertIn("// Serializer: Apple PBCodable (ObjC)", out)
        self.assertNotIn("// serializer:", out)           # no per-message tag when uniform


class TestSummarizeLite(unittest.TestCase):
    """libprotobuf-lite (google::protobuf symbols, no descriptors) must surface as
    a name-less DETECT-ONLY entry; a FULL image must NOT also get a lite entry."""
    def _run(self, cpp_protos, cpp_ns):
        saved = (F._proto_class_set, F.google_protobuf_classes,
                 F.swift_protobuf_messages, F.cpp_protobuf_namespaces,
                 F._cpp.extract_cpp_protos_from_ctx)
        F._proto_class_set = lambda ctx, cl: []
        F.google_protobuf_classes = lambda ctx, cl: ([], [])
        F.swift_protobuf_messages = lambda ctx: ([], [], [])
        F.cpp_protobuf_namespaces = lambda ctx: cpp_ns
        F._cpp.extract_cpp_protos_from_ctx = lambda ctx: cpp_protos
        try:
            return {s.label: s for s in F.summarize_serializers(NoImage(), [], None)}
        finally:
            (F._proto_class_set, F.google_protobuf_classes,
             F.swift_protobuf_messages, F.cpp_protobuf_namespaces,
             F._cpp.extract_cpp_protos_from_ctx) = saved

    def test_lite_detect_only_entry(self):
        summ = self._run(cpp_protos=[], cpp_ns={"wireless_diagnostics::google::protobuf": 188})
        self.assertIn(F.CPP_LITE_SERIALIZER, summ)
        lite = summ[F.CPP_LITE_SERIALIZER]
        self.assertFalse(lite.decodable)
        self.assertEqual(lite.names, [])
        self.assertIn("188", lite.note)
        self.assertIn("wireless_diagnostics::google::protobuf", lite.note)
        self.assertNotIn(F.CPP_SERIALIZER, summ)          # not the full label

    def test_full_image_no_lite_entry(self):
        fp = C.FileProto(name="t.proto", package="pkg", syntax="proto3")
        fp.messages = [C.Message(name="M", fields=[C.Field(name="x", number=1,
                                                           label=1, type=5)])]
        summ = self._run(cpp_protos=[fp], cpp_ns={"google::protobuf": 9})
        self.assertIn(F.CPP_SERIALIZER, summ)             # full, decodable
        self.assertTrue(summ[F.CPP_SERIALIZER].decodable)
        self.assertNotIn(F.CPP_LITE_SERIALIZER, summ)     # the elif guard

    def test_no_cpp_at_all(self):
        summ = self._run(cpp_protos=[], cpp_ns={})
        self.assertNotIn(F.CPP_LITE_SERIALIZER, summ)
        self.assertNotIn(F.CPP_SERIALIZER, summ)


# ── live ──────────────────────────────────────────────────────────────────────

def _locationd():
    try:
        import artifacts
        p = os.path.join(artifacts.data_dir(), "locationd")
        return p if os.path.isfile(p) else None
    except Exception:
        return None


def _remindd():
    env = os.environ.get("MACHO_TEST_REMINDD", "").strip()
    if env:
        return env if os.path.isfile(env) else None
    try:
        import artifacts
        p = os.path.join(artifacts.data_dir(), "libexec", "remindd")
        return p if os.path.isfile(p) else None
    except Exception:
        return None


@unittest.skipUnless(_locationd(), "locationd not available")
class TestLiveCppIntegration(unittest.TestCase):
    def test_locationd_cpp_messages_emit(self):
        data = open(_locationd(), "rb").read()
        msgs = F._cpp_protos_to_messages(F.cpp_file_protos(NoImage(), data))
        self.assertGreater(len(msgs), 50)                 # AWD telemetry protos
        self.assertTrue(all(m.serializer == F.CPP_SERIALIZER for m in msgs))
        self.assertTrue(all(m.package for m in msgs))
        files = build_proto_files(msgs, source_name="locationd")
        # every emitted file carries the C++ serializer header and no recon note
        for pf in files:
            out = pf.emit()
            self.assertIn(F.CPP_SERIALIZER, out)
            self.assertNotIn("reconstructed from the ObjC class-name prefix", out)


@unittest.skipUnless(_remindd(), "remindd binary not available")
class TestLiveSwiftIntegration(unittest.TestCase):
    """swift-protobuf messages adapted into the shared ProtoMessage model carry the
    swift serializer tag + module package, with names/numbers preserved.  (Replaces
    the retired DPSubmissionService corpus; remindd ships swift-protobuf on this
    build.)"""
    def test_remindd_swift_messages_emit(self):
        from macho.memory import BinaryContext
        data = SW.load_macho_slice(open(_remindd(), "rb").read())
        # The foreign adapter flattens nested type names with `_` (Outer_Inner).
        by = {m.name: m for m in F.swift_messages(BinaryContext(data))}
        self.assertIn("StartMigrationRequest_Credential", by)
        cred = by["StartMigrationRequest_Credential"]
        self.assertEqual(cred.serializer, F.SWIFT_SERIALIZER)
        self.assertEqual(cred.package, "remindd")
        self.assertEqual(
            {(f.number, f.name) for f in cred.fields},
            {(1, "dsID"), (2, "baseURL"), (3, "hostname"),
             (4, "mmeAuthToken"), (5, "partition")})


def _load_with_classlist(path):
    from macho.memory import BinaryContext
    from macho.strings import build_string_table
    from macho.classlist import build_class_list
    data = SW.load_macho_slice(open(path, "rb").read())
    ctx = BinaryContext(data)
    st = build_string_table(ctx)
    cl = build_class_list(ctx, st)
    return ctx, cl, data


@unittest.skipUnless(_locationd(), "locationd not available")
class TestSummarizeLive(unittest.TestCase):
    def test_locationd_lists_pbcodable_and_cpp(self):
        ctx, cl, data = _load_with_classlist(_locationd())
        summ = {s.label: s for s in F.summarize_serializers(ctx, cl, data)}
        self.assertIn("Apple PBCodable (ObjC)", summ)
        self.assertIn(F.CPP_SERIALIZER, summ)
        self.assertTrue(summ["Apple PBCodable (ObjC)"].decodable)
        # names are present and the PBCodable set includes a known class
        self.assertGreater(len(summ["Apple PBCodable (ObjC)"].names), 50)
        self.assertGreater(len(summ[F.CPP_SERIALIZER].names), 50)


@unittest.skipUnless(_remindd(), "remindd binary not available")
class TestSummarizeSwiftLive(unittest.TestCase):
    def test_remindd_lists_swift(self):
        ctx, cl, data = _load_with_classlist(_remindd())
        summ = {s.label: s for s in F.summarize_serializers(ctx, cl, data)}
        self.assertIn(F.SWIFT_SERIALIZER, summ)
        self.assertIn("MigrateRequest", summ[F.SWIFT_SERIALIZER].names)


def _cache_main():
    try:
        import artifacts
        p = artifacts.cache_file()
        return p if p and os.path.isfile(p) else None
    except Exception:
        return None


@unittest.skipUnless(_cache_main(), "dyld shared cache not available")
class TestForeignCacheNative(unittest.TestCase):
    """End-to-end cache-native foreign-serializer recovery through the same
    entry points the CLI uses (data=None), for C++ and swift."""
    @classmethod
    def setUpClass(cls):
        from macho.dyld_cache import DyldCacheReader
        cls.reader = DyldCacheReader(_cache_main())

    @classmethod
    def tearDownClass(cls):
        cls.reader.close()

    def _ctx_cl(self, name):
        from macho.memory import BinaryContext
        from macho.strings import build_string_table
        from macho.classlist import build_class_list
        va = self.reader.find_image_header(name)
        if va is None:
            self.skipTest(f"{name} not in this cache")
        ctx = BinaryContext.from_cache(self.reader, va)
        return ctx, build_class_list(ctx, build_string_table(ctx))

    def test_collect_cpp_cache_native(self):
        ctx, _cl = self._ctx_cl("GeoServices")
        msgs = F.collect_foreign_messages(ctx, None)        # data=None -> ctx path
        cpp = [m for m in msgs if m.serializer == F.CPP_SERIALIZER]
        self.assertGreater(len(cpp), 10)
        self.assertTrue(all(m.package for m in cpp))

    def test_collect_swift_cache_native(self):
        ctx, _cl = self._ctx_cl("CopresenceCore")
        msgs = F.collect_foreign_messages(ctx, None)
        sw = [m for m in msgs if m.serializer == F.SWIFT_SERIALIZER]
        self.assertTrue(any(m.name == "CP_Record" for m in sw))

    def test_summarize_cpp_cache_native(self):
        ctx, cl = self._ctx_cl("GeoServices")
        summ = {s.label: s for s in F.summarize_serializers(ctx, cl, None)}
        self.assertIn(F.CPP_SERIALIZER, summ)
        self.assertTrue(summ[F.CPP_SERIALIZER].decodable)
        self.assertGreater(len(summ[F.CPP_SERIALIZER].names), 10)

    def test_summarize_swift_fallback_cache_native(self):
        # the export-trie conformance detector is empty cache-native; summarize
        # must fall back to the nameMap extractor's names.
        ctx, cl = self._ctx_cl("CopresenceCore")
        summ = {s.label: s for s in F.summarize_serializers(ctx, cl, None)}
        self.assertIn(F.SWIFT_SERIALIZER, summ)
        self.assertTrue(any("CP_Record" in n for n in summ[F.SWIFT_SERIALIZER].names))

    def test_lite_detected_cache_native(self):
        # libAWDProtobufLocation has google::protobuf symbols in the .symbols
        # nlist but 0 embedded descriptors -> detect-only lite, cache-native.
        ctx, cl = self._ctx_cl("libAWDProtobufLocation")
        summ = {s.label: s for s in F.summarize_serializers(ctx, cl, None)}
        self.assertIn(F.CPP_LITE_SERIALIZER, summ)
        self.assertFalse(summ[F.CPP_LITE_SERIALIZER].decodable)
        self.assertEqual(summ[F.CPP_LITE_SERIALIZER].names, [])
        self.assertIn("google::protobuf", summ[F.CPP_LITE_SERIALIZER].note)
        self.assertNotIn(F.CPP_SERIALIZER, summ)          # not full

    def test_full_cpp_not_lite_cache_native(self):
        # GeoServices is FULL C++ (decodable) -> no lite entry (the elif guard).
        ctx, cl = self._ctx_cl("GeoServices")
        summ = {s.label: s for s in F.summarize_serializers(ctx, cl, None)}
        self.assertIn(F.CPP_SERIALIZER, summ)
        self.assertTrue(summ[F.CPP_SERIALIZER].decodable)
        self.assertNotIn(F.CPP_LITE_SERIALIZER, summ)


if __name__ == "__main__":
    unittest.main()
