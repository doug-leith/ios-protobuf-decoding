"""
proto/test_emitter.py — Tests for proto.emitter.

Coverage:
  - resolve_type_refs: resolved refs, unresolved refs, builtins, idempotency
  - package_for_class: all known prefixes, unknown prefix
  - build_proto_files: grouping, single-file mode, package_override
  - _compute_imports: cross-package refs, same-package refs, unresolved skipped
  - ProtoFile.emit: header comments, syntax/package/import lines, field lines
  - ProtoFile._emit_field: qualifiers, comments, repeated labels
  - write_proto_files / write_from_messages: file creation, content
  - extraction_stats: correct aggregation
  - CLI argument parsing: prefix filter, dry-run, single-file, --help
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

# proto/ resolves via the apple_protobuf_extractor editable install; the repo root is on
# sys.path via the root conftest.py.  No per-file path juggling.

from proto.models  import FieldLabel, ProtoField, ProtoMessage
from proto.emitter import (
    ProtoFile,
    _compute_imports,
    _compute_stats,
    build_proto_files,
    InputKind,
    extraction_stats,
    package_for_class,
    print_summary,
    resolve_type_refs,
    write_from_messages,
    write_proto_files,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

def _field(
    name: str,
    number: int,
    type_name: str = "int32",
    label: FieldLabel = FieldLabel.OPTIONAL,
    type_class: str | None = None,
    confirmed: bool = True,
    unresolved: str | None = None,
) -> ProtoField:
    f = ProtoField(
        name=name,
        number=number,
        type_name=type_name,
        label=label,
        type_class=type_class,
        number_confirmed=confirmed,
        unresolved_type_class=unresolved,
    )
    return f


def _msg(
    name: str,
    class_name: str | None = None,
    fields: list[ProtoField] | None = None,
) -> ProtoMessage:
    return ProtoMessage(
        name=name,
        class_name=class_name or f"GEO{name}",
        fields=fields or [],
    )


def _geo_msg(
    name: str,
    fields: list[ProtoField] | None = None,
) -> ProtoMessage:
    return ProtoMessage(name=name, class_name=f"GEO{name}", fields=fields or [])


def _clp_msg(
    name: str,
    fields: list[ProtoField] | None = None,
) -> ProtoMessage:
    return ProtoMessage(name=name, class_name=f"CLP{name}", fields=fields or [])


# ── TestPackageForClass ───────────────────────────────────────────────────────

class TestPackageForClass(unittest.TestCase):

    def test_geo_prefix(self):
        self.assertEqual(package_for_class("GEODirectionsRequest"), "geo")

    def test_clp_prefix(self):
        self.assertEqual(package_for_class("CLPLocation"), "clp")

    def test_clm_prefix(self):
        self.assertEqual(package_for_class("CLMRegion"), "clm")

    def test_cln_prefix(self):
        self.assertEqual(package_for_class("CLNNotification"), "cln")

    def test_unknown_prefix_auto_derives_package(self):
        # "ABC" is not a known prefix; auto-derived from class name
        self.assertEqual(package_for_class("ABCFoo"), "abc")

    def test_empty_string_returns_unknown(self):
        self.assertEqual(package_for_class(""), "unknown")

    def test_geo_prefix_exact_match_only(self):
        # "GEOO" still counts as GEO-prefixed
        self.assertEqual(package_for_class("GEOOtherThing"), "geo")

    def test_case_sensitive(self):
        self.assertEqual(package_for_class("geoFoo"), "geofoo")  # no all-caps run

    def test_unknown_prefix_auto_derives_from_class_name(self):
        # Standard ObjC: leading all-caps + CamelCase → prefix auto-detected
        self.assertEqual(package_for_class("APPLWidget"), "appl")
        self.assertEqual(package_for_class("MSFTThing"), "msft")

    def test_auto_derive_geopd_prefix(self):
        # GEOPDPlace: GEO is in the explicit map, matched before auto-derive
        self.assertEqual(package_for_class("GEOPDPlace"), "geo")

    def test_auto_derive_no_prefix_run(self):
        # No leading all-caps run: last-resort lowercases the whole name
        self.assertEqual(package_for_class("FooBar"), "foobar")


# ── TestResolveTypeRefs ───────────────────────────────────────────────────────

class TestResolveTypeRefs(unittest.TestCase):

    def _run(self, messages):
        resolve_type_refs(messages)
        return messages

    def test_scalar_fields_untouched(self):
        msg = _geo_msg("Point", [_field("x", 1, "int32")])
        resolve_type_refs([msg])
        self.assertEqual(msg.fields[0].type_name, "int32")
        self.assertIsNone(msg.fields[0].unresolved_type_class)

    def test_string_field_untouched(self):
        msg = _geo_msg("Name", [_field("value", 1, "string")])
        resolve_type_refs([msg])
        self.assertEqual(msg.fields[0].type_name, "string")

    def test_resolved_cross_ref(self):
        """Field referencing another extracted class → type_name = proto name."""
        location = _clp_msg("Location")
        request = _geo_msg("Request", [
            _field("location", 1, "CLPLocation", type_class="CLPLocation"),
        ])
        resolve_type_refs([location, request])
        self.assertEqual(request.fields[0].type_name, "Location")
        self.assertIsNone(request.fields[0].unresolved_type_class)

    def test_self_referential_ref(self):
        """A class that references itself (e.g. tree nodes)."""
        node = _geo_msg("Node", [
            _field("child", 1, "GEONode", type_class="GEONode"),
        ])
        resolve_type_refs([node])
        self.assertEqual(node.fields[0].type_name, "Node")

    def test_unresolved_ref_falls_back_to_bytes(self):
        """Field referencing a C struct or external class → bytes + annotation."""
        msg = _geo_msg("Foo", [
            _field("session", 1, "GEOSessionID", type_class="GEOSessionID"),
        ])
        resolve_type_refs([msg])
        self.assertEqual(msg.fields[0].type_name, "bytes")
        self.assertEqual(msg.fields[0].unresolved_type_class, "GEOSessionID")

    def test_objc_builtin_nsarray_silent(self):
        """NSArray → bytes with no unresolved annotation."""
        msg = _geo_msg("Foo", [
            _field("items", 1, "NSArray", type_class="NSArray"),
        ])
        resolve_type_refs([msg])
        self.assertEqual(msg.fields[0].type_name, "bytes")
        self.assertIsNone(msg.fields[0].unresolved_type_class)

    def test_objc_builtin_nsmutablearray_silent(self):
        msg = _geo_msg("Foo", [
            _field("items", 1, "NSMutableArray", type_class="NSMutableArray"),
        ])
        resolve_type_refs([msg])
        self.assertEqual(msg.fields[0].type_name, "bytes")
        self.assertIsNone(msg.fields[0].unresolved_type_class)

    def test_nsdata_silent(self):
        msg = _geo_msg("Foo", [
            _field("blob", 1, "NSData", type_class="NSData"),
        ])
        resolve_type_refs([msg])
        self.assertEqual(msg.fields[0].type_name, "bytes")
        self.assertIsNone(msg.fields[0].unresolved_type_class)

    def test_idempotent(self):
        """Calling resolve_type_refs twice does not double-process fields."""
        location = _clp_msg("Location")
        request = _geo_msg("Request", [
            _field("loc", 1, "CLPLocation", type_class="CLPLocation"),
        ])
        resolve_type_refs([location, request])
        type_after_first = request.fields[0].type_name
        resolve_type_refs([location, request])
        self.assertEqual(request.fields[0].type_name, type_after_first)

    def test_idempotent_unresolved(self):
        """Calling twice on an unresolved field doesn't change unresolved_type_class."""
        msg = _geo_msg("Foo", [
            _field("x", 1, "GEOCStruct", type_class="GEOCStruct"),
        ])
        resolve_type_refs([msg])
        first_val = msg.fields[0].unresolved_type_class
        resolve_type_refs([msg])
        self.assertEqual(msg.fields[0].unresolved_type_class, first_val)

    def test_type_class_none_untouched(self):
        """Fields with type_class=None (scalars) are never touched."""
        msg = _geo_msg("Foo", [
            ProtoField("x", 1, "int32", FieldLabel.OPTIONAL, type_class=None)
        ])
        resolve_type_refs([msg])
        self.assertEqual(msg.fields[0].type_name, "int32")
        self.assertIsNone(msg.fields[0].unresolved_type_class)

    def test_empty_message_list(self):
        resolve_type_refs([])  # must not raise

    def test_multiple_fields_mixed(self):
        """Mix of resolved, unresolved, and scalar fields in one message."""
        location  = _clp_msg("Location")
        msg = _geo_msg("Trip", [
            _field("distance",   1, "double"),
            _field("location",   2, "CLPLocation", type_class="CLPLocation"),
            _field("session",    3, "GEOCStruct",  type_class="GEOCStruct"),
            _field("tags",       4, "NSArray",     type_class="NSArray"),
        ])
        resolve_type_refs([location, msg])
        self.assertEqual(msg.fields[0].type_name, "double")   # untouched
        self.assertEqual(msg.fields[1].type_name, "Location") # resolved
        self.assertEqual(msg.fields[2].type_name, "bytes")    # unresolved
        self.assertEqual(msg.fields[2].unresolved_type_class, "GEOCStruct")
        self.assertEqual(msg.fields[3].type_name, "bytes")    # builtin
        self.assertIsNone(msg.fields[3].unresolved_type_class)


# ── TestBuildProtoFiles ───────────────────────────────────────────────────────

class TestBuildProtoFiles(unittest.TestCase):

    def setUp(self):
        self.geo1 = _geo_msg("RouteRequest", [_field("distance", 1)])
        self.geo2 = _geo_msg("RouteResponse", [_field("eta", 1)])
        self.clp1 = _clp_msg("Location", [_field("lat", 1)])
        self.other = ProtoMessage("Widget", "XYZWidget", [_field("id", 1)])

    def test_groups_by_prefix(self):
        pfs = build_proto_files([self.geo1, self.geo2, self.clp1])
        pkgs = {pf.package for pf in pfs}
        self.assertIn("geo", pkgs)
        self.assertIn("clp", pkgs)
        self.assertEqual(len(pfs), 2)

    def test_geo_file_contains_both_geo_messages(self):
        pfs = build_proto_files([self.geo1, self.geo2, self.clp1])
        geo_pf = next(pf for pf in pfs if pf.package == "geo")
        names = {m.name for m in geo_pf.messages}
        self.assertIn("RouteRequest", names)
        self.assertIn("RouteResponse", names)

    def test_unknown_prefix_auto_derives_package(self):
        # XYZWidget: "XYZ" auto-derived as package "xyz"
        pfs = build_proto_files([self.other])
        self.assertEqual(len(pfs), 1)
        self.assertEqual(pfs[0].package, "xyz")
        self.assertEqual(pfs[0].filename, "xyz.proto")

    def test_messages_sorted_within_file(self):
        pfs = build_proto_files([self.geo2, self.geo1])  # reversed order
        geo_pf = next(pf for pf in pfs if pf.package == "geo")
        names = [m.name for m in geo_pf.messages]
        self.assertEqual(names, sorted(names))

    def test_files_sorted_by_filename(self):
        pfs = build_proto_files([self.clp1, self.geo1, self.other])
        filenames = [pf.filename for pf in pfs]
        self.assertEqual(filenames, sorted(filenames))

    def test_single_file_mode(self):
        pfs = build_proto_files([self.geo1, self.clp1], single_file=True)
        self.assertEqual(len(pfs), 1)

    def test_single_file_package_from_source_name(self):
        pfs = build_proto_files(
            [self.geo1], single_file=True, source_name="GeoServices"
        )
        self.assertEqual(pfs[0].package, "geoservices")

    def test_single_file_package_override(self):
        pfs = build_proto_files(
            [self.geo1], single_file=True, package_override="custom"
        )
        self.assertEqual(pfs[0].package, "custom")
        self.assertEqual(pfs[0].filename, "custom.proto")

    def test_single_file_fallback_package(self):
        pfs = build_proto_files([self.geo1], single_file=True)
        self.assertEqual(pfs[0].package, "messages")

    def test_source_name_propagated(self):
        pfs = build_proto_files([self.geo1], source_name="GeoServices")
        for pf in pfs:
            self.assertEqual(pf.source_name, "GeoServices")

    def test_empty_messages_list(self):
        pfs = build_proto_files([])
        self.assertEqual(pfs, [])

    def test_resolve_called_side_effect(self):
        """build_proto_files calls resolve_type_refs; cross-refs should be resolved."""
        location = _clp_msg("Location")
        req = _geo_msg("Request", [
            _field("loc", 1, "CLPLocation", type_class="CLPLocation"),
        ])
        build_proto_files([location, req])
        # After build_proto_files, type_name should be resolved
        self.assertEqual(req.fields[0].type_name, "Location")


# ── TestComputeImports ────────────────────────────────────────────────────────

class TestComputeImports(unittest.TestCase):

    def _make_pf(self, pkg: str, messages=None):
        return ProtoFile(
            package=pkg,
            filename=f"{pkg}.proto",
            messages=messages or [],
            imports=[],
        )

    def test_no_cross_refs_no_imports(self):
        geo_fld = _field("dist", 1, "double")
        geo_msg = ProtoMessage("Route", "GEORoute", [geo_fld])
        geo_pf  = self._make_pf("geo", [geo_msg])
        class_to_pkg = {"GEORoute": "geo"}
        _compute_imports([geo_pf], class_to_pkg)
        self.assertEqual(geo_pf.imports, [])

    def test_cross_package_ref_generates_import(self):
        # Geo message has a resolved field pointing to a CLP class
        clp_fld = _field("loc", 1, "Location", type_class="CLPLocation")
        geo_msg = ProtoMessage("Request", "GEORequest", [clp_fld])
        geo_pf  = self._make_pf("geo", [geo_msg])
        clp_pf  = self._make_pf("clp")
        class_to_pkg = {"CLPLocation": "clp"}
        _compute_imports([geo_pf, clp_pf], class_to_pkg)
        self.assertIn("clp.proto", geo_pf.imports)
        # CLP file doesn't import GEO
        self.assertEqual(clp_pf.imports, [])

    def test_unresolved_field_no_import(self):
        fld = _field("x", 1, "bytes", type_class="GEOCStruct", unresolved="GEOCStruct")
        msg = ProtoMessage("Foo", "GEOFoo", [fld])
        pf  = self._make_pf("geo", [msg])
        _compute_imports([pf], {"GEOCStruct": "geo"})
        self.assertEqual(pf.imports, [])

    def test_scalar_field_no_import(self):
        fld = _field("x", 1, "int32")
        msg = ProtoMessage("Foo", "GEOFoo", [fld])
        pf  = self._make_pf("geo", [msg])
        _compute_imports([pf], {})
        self.assertEqual(pf.imports, [])

    def test_same_package_ref_no_import(self):
        fld = _field("other", 1, "Bar", type_class="GEOBar")
        msg = ProtoMessage("Foo", "GEOFoo", [fld])
        pf  = self._make_pf("geo", [msg])
        _compute_imports([pf], {"GEOBar": "geo"})
        self.assertEqual(pf.imports, [])

    def test_multiple_cross_package_refs_sorted(self):
        f1 = _field("loc",    1, "Location", type_class="CLPLocation")
        f2 = _field("region", 2, "Region",   type_class="CLMRegion")
        msg = ProtoMessage("Request", "GEORequest", [f1, f2])
        geo_pf = self._make_pf("geo", [msg])
        clp_pf = self._make_pf("clp")
        clm_pf = self._make_pf("clm")
        class_to_pkg = {"CLPLocation": "clp", "CLMRegion": "clm"}
        _compute_imports([geo_pf, clp_pf, clm_pf], class_to_pkg)
        self.assertEqual(geo_pf.imports, ["clm.proto", "clp.proto"])  # sorted


# ── TestProtoFileEmit ─────────────────────────────────────────────────────────

class TestProtoFileEmit(unittest.TestCase):

    def _simple_pf(self, messages=None, imports=None, package="geo") -> ProtoFile:
        return ProtoFile(
            package=package,
            filename=f"{package}.proto",
            messages=messages or [],
            imports=imports or [],
            source_name="TestBinary",
        )

    def test_syntax_line_present(self):
        pf = self._simple_pf()
        out = pf.emit()
        self.assertIn('edition = "2023";', out)

    def test_package_line_present(self):
        pf = self._simple_pf()
        out = pf.emit()
        self.assertIn("package geo;", out)

    def test_package_recon_note_present(self):
        """The package line carries the 'reconstructed, harmless' caveat + doc ref."""
        out = self._simple_pf().emit()
        self.assertIn("PACKAGE_NAMES.md", out)
        note_pos = out.index("package reconstructed from the ObjC class-name prefix")
        pkg_pos  = out.index("package geo;")
        self.assertLess(note_pos, pkg_pos)

    def test_no_package_note_when_no_package(self):
        """No package line → no package caveat."""
        out = self._simple_pf(package="").emit()
        self.assertNotIn("package ", out)
        self.assertNotIn("PACKAGE_NAMES.md", out)

    def test_import_lines_present(self):
        pf = self._simple_pf(imports=["clp.proto", "clm.proto"])
        out = pf.emit()
        self.assertIn('import "clp.proto";', out)
        self.assertIn('import "clm.proto";', out)

    def test_no_import_lines_when_empty(self):
        pf = self._simple_pf(imports=[])
        out = pf.emit()
        self.assertNotIn("import", out)

    def test_generator_comment(self):
        pf = self._simple_pf()
        out = pf.emit()
        self.assertIn("Generated by apple_protobuf_extractor (ios_protobuf_decoding)", out)

    def test_ambiguous_header_note_binary_dylib_explains_external_data(self):
        pf = self._simple_pf()
        pf.n_ambiguous = 2
        pf.input_kind = InputKind.DYLIB
        out = pf.emit()
        # Binary-only dylib: explain the data lives in the cache, outside the
        # dylib, and point at --framework (not the now-rejected --binary --cache).
        self.assertIn("outside this dylib", out)
        self.assertIn("--framework", out)
        self.assertNotIn("ERROR", out)

    def test_ambiguous_header_note_cache_active_reports_error(self):
        pf = self._simple_pf()
        pf.n_ambiguous = 2
        pf.input_kind = InputKind.CACHE_IMAGE
        out = pf.emit()
        # Cache-native: ambiguity should be impossible → worded as an error.
        self.assertIn("ERROR", out)
        self.assertIn("should not happen", out)

    def test_ambiguous_header_note_executable_reports_error(self):
        pf = self._simple_pf()
        pf.n_ambiguous = 2
        pf.input_kind = InputKind.EXECUTABLE
        out = pf.emit()
        # Standalone executable is self-contained → ambiguity is a tool bug.
        self.assertIn("ERROR", out)
        self.assertIn("standalone executable", out)
        self.assertIn("should not happen", out)
        self.assertNotIn("--framework", out)   # re-extracting won't help here

    def test_source_name_in_comment(self):
        pf = self._simple_pf()
        out = pf.emit()
        self.assertIn("TestBinary", out)

    def test_empty_message_body(self):
        msg = _geo_msg("Empty")
        pf  = self._simple_pf([msg])
        out = pf.emit()
        self.assertIn("message Empty {", out)
        self.assertIn("// (no fields recovered)", out)

    def test_opaque_passthrough_comment(self):
        # A field-less message flagged opaque_passthrough gets the distinct
        # "serializes only PBUnknownFields" comment, NOT "(no fields recovered)".
        msg = _geo_msg("Passthrough")
        msg.opaque_passthrough = True
        out = self._simple_pf([msg]).emit()
        self.assertIn("message Passthrough {", out)
        self.assertIn("opaque passthrough", out)
        self.assertIn("serializes only PBUnknownFields", out)
        self.assertNotIn("(no fields recovered)", out)

    def test_field_less_without_flag_keeps_no_fields_comment(self):
        # Without the flag, a field-less message still reads "(no fields recovered)"
        # so a genuine extraction miss is NOT relabelled as intentional.
        out = self._simple_pf([_geo_msg("Empty2")]).emit()
        self.assertIn("// (no fields recovered)", out)
        self.assertNotIn("opaque passthrough", out)

    def test_message_with_scalar_field(self):
        msg = _geo_msg("Point", [
            _field("latitude", 1, "double"),
            _field("longitude", 2, "double"),
        ])
        pf = self._simple_pf([msg])
        out = pf.emit()
        self.assertIn("double latitude = 1;", out)
        self.assertIn("double longitude = 2;", out)

    def test_estimated_number_comment(self):
        fld = _field("x", 1, "int32", confirmed=False)
        msg = _geo_msg("Foo", [fld])
        pf  = self._simple_pf([msg])
        out = pf.emit()
        self.assertIn("// number estimated", out)

    def test_confirmed_number_no_comment(self):
        fld = _field("x", 1, "int32", confirmed=True)
        msg = _geo_msg("Foo", [fld])
        pf  = self._simple_pf([msg])
        out = pf.emit()
        self.assertNotIn("number estimated", out)

    def test_unresolved_type_comment(self):
        fld = _field("sess", 1, "bytes", type_class="GEOCStruct",
                     unresolved="GEOCStruct")
        msg = _geo_msg("Foo", [fld])
        pf  = self._simple_pf([msg])
        out = pf.emit()
        self.assertIn("unresolved: GEOCStruct", out)
        self.assertIn("bytes sess = 1;", out)

    def test_repeated_label_prefix(self):
        fld = _field("tags", 1, "string", label=FieldLabel.REPEATED)
        msg = _geo_msg("Foo", [fld])
        pf  = self._simple_pf([msg])
        out = pf.emit()
        self.assertIn("repeated string tags = 1;", out)

    def test_fields_sorted_by_number_in_output(self):
        # Fields are emitted in field-NUMBER order regardless of construction
        # order (migrated 2026-07-22 from the deleted ProtoMessage.to_proto's
        # test_fields_sorted_by_number -- this behavior otherwise had no
        # coverage against the real _emit_message renderer).
        # RE-ATTRIBUTION NOTE: mutation-testing audit mapped this test's
        # introducing commit to 3e09d35, but that commit's diff is dead-code
        # removal (ProtoMessage.to_proto) -- the sort logic under test
        # (`sorted(msg.fields, key=lambda f: f.number)` in _emit_message) was
        # actually introduced in f4765c4 (`git log -S`), long pre-existing and
        # untouched by 3e09d35. Not a test defect, just a commit-mapping miss.
        msg = _geo_msg("Foo", [
            _field("b", 2, "int32"),
            _field("a", 1, "int32"),
            _field("c", 3, "int32"),
        ])
        out = self._simple_pf([msg]).emit()
        a_pos, b_pos, c_pos = out.index("a ="), out.index("b ="), out.index("c =")
        self.assertLess(a_pos, b_pos)
        self.assertLess(b_pos, c_pos)

    def test_cross_package_qualifier(self):
        """Message field from a different package gets package-qualified type."""
        fld = _field("loc", 1, "Location", type_class="CLPLocation")
        msg = ProtoMessage("Request", "GEORequest", [fld])
        pf  = self._simple_pf([msg], package="geo")
        out = pf.emit(class_to_pkg={"CLPLocation": "clp"})
        self.assertIn("clp.Location loc = 1;", out)

    def test_same_package_no_qualifier(self):
        """Message field in the same package is emitted without qualifier."""
        fld = _field("inner", 1, "Inner", type_class="GEOInner")
        msg = ProtoMessage("Outer", "GEOOuter", [fld])
        pf  = self._simple_pf([msg], package="geo")
        out = pf.emit(class_to_pkg={"GEOInner": "geo"})
        self.assertIn("Inner inner = 1;", out)
        self.assertNotIn("geo.Inner", out)

    def test_messages_sorted_in_output(self):
        """Messages are emitted in alphabetical order regardless of input order."""
        msg_b = _geo_msg("Bravo")
        msg_a = _geo_msg("Alpha")
        pf = self._simple_pf([msg_b, msg_a])
        out = pf.emit()
        pos_a = out.index("message Alpha")
        pos_b = out.index("message Bravo")
        self.assertLess(pos_a, pos_b)

    def test_note_line_when_unresolved_present(self):
        fld = _field("x", 1, "bytes", type_class="GEOCStruct",
                     unresolved="GEOCStruct")
        msg = _geo_msg("Foo", [fld])
        pf  = self._simple_pf([msg])
        pf.n_unresolved = 1  # simulate stats computation
        out = pf.emit()
        self.assertIn("unresolved message types emitted as bytes", out)

    def test_no_note_when_no_unresolved(self):
        pf = self._simple_pf()
        pf.n_unresolved = 0
        out = pf.emit()
        self.assertNotIn("unresolved message types", out)


class TestFieldNotes(unittest.TestCase):
    def test_a_number_note_and_a_type_note_both_show(self):
        # writeTo: writes the field as 0, and its type is a guess: neither hides the other
        f = _field("key", 1, confirmed=False)
        f.number_note, f.type_inference_note = "wire field number is 0", "type guessed"
        out = ProtoFile("geo", "geo.proto", [_geo_msg("Foo", [f])], []).emit()
        line = next(ln for ln in out.splitlines() if " key = 1;" in ln)
        self.assertIn("number estimated; wire field number is 0; type guessed", line)


# ── TestComputeStats ──────────────────────────────────────────────────────────

class TestComputeStats(unittest.TestCase):

    def test_all_confirmed(self):
        f1 = _field("a", 1, confirmed=True)
        f2 = _field("b", 2, confirmed=True)
        msg = _geo_msg("Foo", [f1, f2])
        pf  = ProtoFile("geo", "geo.proto", [msg], [])
        _compute_stats([pf])
        self.assertEqual(pf.n_confirmed, 2)
        self.assertEqual(pf.n_estimated, 0)
        self.assertEqual(pf.n_unresolved, 0)

    def test_mixed_confirmed_estimated(self):
        f1 = _field("a", 1, confirmed=True)
        f2 = _field("b", 2, confirmed=False)
        msg = _geo_msg("Foo", [f1, f2])
        pf  = ProtoFile("geo", "geo.proto", [msg], [])
        _compute_stats([pf])
        self.assertEqual(pf.n_confirmed, 1)
        self.assertEqual(pf.n_estimated, 1)

    def test_unresolved_counted(self):
        f1 = _field("x", 1, "bytes", type_class="GEOCStruct",
                    unresolved="GEOCStruct")
        msg = _geo_msg("Foo", [f1])
        pf  = ProtoFile("geo", "geo.proto", [msg], [])
        _compute_stats([pf])
        self.assertEqual(pf.n_unresolved, 1)

    def test_empty_message_contributes_zero(self):
        msg = _geo_msg("Empty")
        pf  = ProtoFile("geo", "geo.proto", [msg], [])
        _compute_stats([pf])
        self.assertEqual(pf.n_confirmed, 0)
        self.assertEqual(pf.n_estimated, 0)

    def test_multiple_messages_aggregated(self):
        m1 = _geo_msg("A", [_field("x", 1, confirmed=True)])
        m2 = _geo_msg("B", [_field("y", 1, confirmed=False)])
        pf = ProtoFile("geo", "geo.proto", [m1, m2], [])
        _compute_stats([pf])
        self.assertEqual(pf.n_confirmed, 1)
        self.assertEqual(pf.n_estimated, 1)


# ── TestExtractionStats ───────────────────────────────────────────────────────

class TestExtractionStats(unittest.TestCase):

    def test_basic_aggregation(self):
        f1 = _field("a", 1, confirmed=True)
        f2 = _field("b", 2, confirmed=False)
        msg = _geo_msg("Foo", [f1, f2])
        pf  = ProtoFile("geo", "geo.proto", [msg], [], n_confirmed=1, n_estimated=1)
        stats = extraction_stats([msg], [pf])
        self.assertEqual(stats["messages"], 1)
        self.assertEqual(stats["fields"], 2)
        self.assertEqual(stats["confirmed"], 1)
        self.assertEqual(stats["estimated"], 1)
        self.assertEqual(stats["unresolved"], 0)
        self.assertEqual(stats["empty"], 0)
        self.assertEqual(stats["files"], 1)

    def test_empty_message_counted(self):
        msg = _geo_msg("Empty")
        pf  = ProtoFile("geo", "geo.proto", [msg], [])
        stats = extraction_stats([msg], [pf])
        self.assertEqual(stats["empty"], 1)

    def test_multi_file_aggregated(self):
        m1 = _geo_msg("A", [_field("x", 1, confirmed=True)])
        m2 = _clp_msg("B", [_field("y", 1, confirmed=False)])
        pf1 = ProtoFile("geo", "geo.proto", [m1], [], n_confirmed=1, n_estimated=0)
        pf2 = ProtoFile("clp", "clp.proto", [m2], [], n_confirmed=0, n_estimated=1)
        stats = extraction_stats([m1, m2], [pf1, pf2])
        self.assertEqual(stats["messages"], 2)
        self.assertEqual(stats["files"], 2)
        self.assertEqual(stats["confirmed"], 1)
        self.assertEqual(stats["estimated"], 1)


# ── TestWriteProtoFiles ───────────────────────────────────────────────────────

class TestWriteProtoFiles(unittest.TestCase):

    def test_creates_output_directory(self):
        msg = _geo_msg("Foo", [_field("x", 1)])
        pf  = ProtoFile("geo", "geo.proto", [msg], [],
                        n_confirmed=1, n_estimated=0)
        with tempfile.TemporaryDirectory() as tmpdir:
            outdir = Path(tmpdir) / "new_dir" / "nested"
            write_proto_files([pf], outdir)
            self.assertTrue(outdir.exists())

    def test_writes_correct_filename(self):
        msg = _geo_msg("Foo", [_field("x", 1)])
        pf  = ProtoFile("geo", "geo.proto", [msg], [],
                        n_confirmed=1, n_estimated=0)
        with tempfile.TemporaryDirectory() as tmpdir:
            written = write_proto_files([pf], Path(tmpdir))
            self.assertEqual(len(written), 1)
            self.assertEqual(written[0].name, "geo.proto")

    @unittest.skipUnless(__import__("shutil").which("protoc"), "protoc not installed")
    def test_scalar_sent_as_zero_is_kept(self):
        """Apple's writeTo: writes a field whose has-bit is set even when its value is 0, NO or
        "".  The emitted file declares explicit presence (edition 2023), so a decoder keeps such
        a value instead of dropping it as an absent field; enums stay open."""
        import subprocess
        from google.protobuf import descriptor_pb2, descriptor_pool, message_factory
        msg = _geo_msg("Loc", [
            _field("motionVehicleConnected", 1, "bool"),
            _field("mcc", 2, "int32"),
            _field("appBundleId", 3, "string"),
            _field("speed", 4, "double"),
        ])
        pf = ProtoFile("geo", "geo.proto", [msg], [], n_confirmed=4, n_estimated=0)
        with tempfile.TemporaryDirectory() as tmpdir:
            write_proto_files([pf], Path(tmpdir))
            out = Path(tmpdir) / "geo.pb"
            subprocess.run(["protoc", f"-I{tmpdir}", f"--descriptor_set_out={out}", "geo.proto"],
                           check=True, capture_output=True)
            fds = descriptor_pb2.FileDescriptorSet.FromString(out.read_bytes())
        pool = descriptor_pool.DescriptorPool()
        for f in fds.file:
            pool.Add(f)
        cls = message_factory.GetMessageClass(pool.FindMessageTypeByName("geo.Loc"))
        m = cls.FromString(bytes.fromhex("0800" "1000" "1a00" "210000000000000000"))
        self.assertEqual([f.name for f, _ in m.ListFields()],
                         ["motionVehicleConnected", "mcc", "appBundleId", "speed"])
        self.assertEqual(cls.FromString(b"").ListFields(), [])   # absent stays absent

    def test_file_content_is_valid_edition_2023(self):
        msg = _geo_msg("Point", [
            _field("lat", 1, "double"),
            _field("lon", 2, "double"),
        ])
        pf = ProtoFile("geo", "geo.proto", [msg], [],
                       n_confirmed=2, n_estimated=0)
        with tempfile.TemporaryDirectory() as tmpdir:
            written = write_proto_files([pf], Path(tmpdir))
            content = written[0].read_text(encoding="utf-8")
        self.assertIn('edition = "2023";', content)
        self.assertIn("package geo;", content)
        self.assertIn("message Point {", content)
        self.assertIn("double lat = 1;", content)
        self.assertIn("double lon = 2;", content)

    def test_multiple_files_written(self):
        pf1 = ProtoFile("geo", "geo.proto", [], [])
        pf2 = ProtoFile("clp", "clp.proto", [], [])
        with tempfile.TemporaryDirectory() as tmpdir:
            written = write_proto_files([pf1, pf2], Path(tmpdir))
            names = {p.name for p in written}
        self.assertEqual(names, {"geo.proto", "clp.proto"})

    def test_write_from_messages_roundtrip(self):
        """write_from_messages → read back → content looks like proto3."""
        location = _clp_msg("Location", [_field("lat", 1, "double")])
        request  = _geo_msg("Request", [
            _field("loc", 1, "CLPLocation", type_class="CLPLocation"),
        ])
        with tempfile.TemporaryDirectory() as tmpdir:
            written, proto_files = write_from_messages(
                [location, request],
                Path(tmpdir),
                source_name="TestBinary",
            )
            filenames = {p.name for p in written}
            self.assertIn("geo.proto", filenames)
            self.assertIn("clp.proto", filenames)
            geo_content = (Path(tmpdir) / "geo.proto").read_text()
        self.assertIn('edition = "2023";', geo_content)
        self.assertIn('import "clp.proto";', geo_content)


# ── TestPrintSummary ──────────────────────────────────────────────────────────

class TestPrintSummary(unittest.TestCase):

    def test_does_not_raise(self):
        msgs = [_geo_msg("Foo", [_field("x", 1)])]
        pfs  = build_proto_files(msgs)
        buf  = io.StringIO()
        print_summary(msgs, pfs, source_name="Test", file=buf)

    def test_output_contains_key_fields(self):
        msgs = [
            _geo_msg("A", [_field("x", 1, confirmed=True)]),
            _geo_msg("B"),  # empty
        ]
        pfs = build_proto_files(msgs)
        buf = io.StringIO()
        print_summary(msgs, pfs, source_name="TestBinary", file=buf)
        output = buf.getvalue()
        self.assertIn("TestBinary", output)
        self.assertIn("2", output)    # 2 messages
        self.assertIn("geo.proto", output)

    def test_zero_messages(self):
        """Should not crash with no messages."""
        buf = io.StringIO()
        print_summary([], [], source_name="Empty", file=buf)


# ── TestCLIArgParsing ─────────────────────────────────────────────────────────

class TestCLIArgParsing(unittest.TestCase):
    """Test _build_parser() and the dry-run / filter paths via main()."""

    def _parser(self):
        from cli import _build_parser
        return _build_parser()

    # ── --binary option ───────────────────────────────────────────────────────

    def test_binary_option(self):
        args = self._parser().parse_args(["--binary", "GeoServices"])
        self.assertEqual(args.binary, "GeoServices")

    def test_binary_short_path(self):
        args = self._parser().parse_args(["--binary", "/path/to/GeoServices"])
        self.assertEqual(args.binary, "/path/to/GeoServices")

    # ── --framework option ────────────────────────────────────────────────────

    def test_framework_option(self):
        args = self._parser().parse_args(
            ["--framework", "GeoServices", "--cache", "/tmp/cache"]
        )
        self.assertEqual(args.framework, "GeoServices")

    def test_framework_sets_no_binary(self):
        args = self._parser().parse_args(
            ["--framework", "GeoServices", "--cache", "/tmp/cache"]
        )
        self.assertIsNone(args.binary)

    # ── --list-frameworks option ──────────────────────────────────────────────

    def test_list_frameworks_flag(self):
        args = self._parser().parse_args(
            ["--list-frameworks", "--cache", "/tmp/cache"]
        )
        self.assertTrue(args.list_frameworks)

    def test_list_frameworks_default_false(self):
        args = self._parser().parse_args(["--binary", "GeoServices"])
        self.assertFalse(args.list_frameworks)

    # ── mutual exclusivity ────────────────────────────────────────────────────

    def test_binary_and_framework_mutually_exclusive(self):
        with self.assertRaises(SystemExit):
            with contextlib.redirect_stderr(io.StringIO()):
                self._parser().parse_args(
                    ["--binary", "GeoServices",
                     "--framework", "GeoServices",
                     "--cache", "/tmp/cache"]
                )

    def test_binary_and_list_frameworks_mutually_exclusive(self):
        with self.assertRaises(SystemExit):
            with contextlib.redirect_stderr(io.StringIO()):
                self._parser().parse_args(
                    ["--binary", "GeoServices", "--list-frameworks"]
                )

    # ── shared flags ──────────────────────────────────────────────────────────

    def test_output_default(self):
        args = self._parser().parse_args(["--binary", "GeoServices"])
        self.assertEqual(args.output, "./protos")

    def test_output_custom(self):
        args = self._parser().parse_args(
            ["--binary", "GeoServices", "-o", "/tmp/out"]
        )
        self.assertEqual(args.output, "/tmp/out")

    def test_single_file_flag(self):
        args = self._parser().parse_args(["--binary", "GeoServices", "--single-file"])
        self.assertTrue(args.single_file)

    def test_package_option(self):
        args = self._parser().parse_args(
            ["--binary", "GeoServices", "--package", "mypackage"]
        )
        self.assertEqual(args.package, "mypackage")

    def test_prefix_repeatable(self):
        args = self._parser().parse_args(
            ["--binary", "GeoServices", "--prefix", "GEO", "--prefix", "CLP"]
        )
        self.assertEqual(args.prefixes, ["GEO", "CLP"])

    def test_prefix_default_none(self):
        args = self._parser().parse_args(["--binary", "GeoServices"])
        self.assertIsNone(args.prefixes)

    def test_dry_run_flag(self):
        args = self._parser().parse_args(["--binary", "GeoServices", "--dry-run"])
        self.assertTrue(args.dry_run)

    def test_verbose_flag(self):
        args = self._parser().parse_args(["--binary", "GeoServices", "-v"])
        self.assertTrue(args.verbose)

    def test_cache_default_none(self):
        args = self._parser().parse_args(["--binary", "GeoServices"])
        self.assertIsNone(args.cache)

    def test_cache_flag_stores_path(self):
        args = self._parser().parse_args(
            ["--binary", "GeoServices", "--cache", "/tmp/cache"]
        )
        self.assertEqual(args.cache, "/tmp/cache")

    # ── validation via main() ─────────────────────────────────────────────────

    def test_missing_binary_exits(self):
        from cli import main
        with contextlib.redirect_stderr(io.StringIO()):
            rc = main(["--binary", "nonexistent_binary_xyz"])
        self.assertEqual(rc, 1)

    def test_no_source_exits(self):
        """main() must fail when no --binary/--framework/--list-frameworks given."""
        from cli import main
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as cm:
                main([])
        self.assertEqual(cm.exception.code, 2)

    def test_framework_without_cache_exits(self):
        """--framework without --cache must fail."""
        from cli import main
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as cm:
                main(["--framework", "GeoServices"])
        self.assertEqual(cm.exception.code, 2)

    def test_list_frameworks_without_cache_exits(self):
        """--list-frameworks without --cache must fail."""
        from cli import main
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as cm:
                main(["--list-frameworks"])
        self.assertEqual(cm.exception.code, 2)

    def test_binary_with_cache_exits(self):
        """--binary + --cache is rejected: standalone mode resolves selectors
        from the binary itself, so a cache would be ignored rather than used."""
        from cli import main
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as cm:
                main(["--binary", "x", "--cache", "/tmp/nonexistent_cache_xyz"])
        self.assertEqual(cm.exception.code, 2)


# ── TestCliPhaseHelpers ───────────────────────────────────────────────────────

class TestCliPhaseHelpers(unittest.TestCase):
    """The phase helpers main() delegates to.

    These cover the failure paths main() used to handle inline and that no test
    reached: an unopenable/unresolvable cache, and an ambiguous or missing
    --framework name.  Each must print a diagnostic and raise _CliAbort(1) rather
    than let the underlying exception escape.
    """

    # ── _open_cache ───────────────────────────────────────────────────────────

    def test_open_cache_returns_none_when_no_cache_requested(self):
        """--binary mode: no cache argument, so no cache and no error."""
        from cli import _open_cache
        self.assertIsNone(_open_cache(None, cache_native=False))

    def test_open_cache_aborts_when_framework_mode_has_no_cache(self):
        """--framework with an unresolvable --cache path must abort, not return
        None: cache-native extraction cannot proceed without one."""
        from cli import _open_cache, _CliAbort
        with contextlib.redirect_stderr(io.StringIO()) as err:
            with self.assertRaises(_CliAbort) as cm:
                _open_cache("/nonexistent/path/to/cache_xyz", cache_native=True)
        self.assertEqual(cm.exception.code, 1)
        self.assertIn("--cache must be supplied and openable", err.getvalue())

    def test_open_cache_tolerates_unresolvable_path_in_binary_mode(self):
        """Binary mode: an unresolvable --cache is not fatal."""
        from cli import _open_cache
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertIsNone(
                _open_cache("/nonexistent/path/to/cache_xyz", cache_native=False)
            )

    # ── _load_cache_native_context ────────────────────────────────────────────

    class _FakeCache:
        """Minimal DyldCacheReader stand-in: records close(), raises on resolve."""

        def __init__(self, exc):
            self._exc = exc
            self.closed = False

        def resolve_image(self, name):
            raise self._exc

        def close(self):
            self.closed = True

    def test_ambiguous_framework_aborts(self):
        """An ambiguous --framework lists the candidates and aborts (main() closes the cache:
        test_main_closes_the_cache_when_loading_aborts)."""
        from cli import _load_cache_native_context, _CliAbort
        from macho.dyld_cache import AmbiguousImageError

        exc = AmbiguousImageError(
            "GeoServices", ["/a/GeoServices", "/b/GeoServicesCore"])
        cache = self._FakeCache(exc)
        args = SimpleNamespace(framework="GeoServices", cache="/tmp/c")

        with contextlib.redirect_stderr(io.StringIO()) as err:
            with self.assertRaises(_CliAbort) as cm:
                _load_cache_native_context(args, cache, BinaryContext=None)
        self.assertEqual(cm.exception.code, 1)
        out = err.getvalue()
        self.assertIn("matches 2 images", out)
        self.assertIn("/b/GeoServicesCore", out)

    def test_missing_framework_aborts(self):
        from cli import _load_cache_native_context, _CliAbort
        from macho.dyld_cache import ImageNotFoundError

        cache = self._FakeCache(ImageNotFoundError("nope"))
        args = SimpleNamespace(framework="NoSuchFramework", cache="/tmp/c")

        with contextlib.redirect_stderr(io.StringIO()) as err:
            with self.assertRaises(_CliAbort) as cm:
                _load_cache_native_context(args, cache, BinaryContext=None)
        self.assertEqual(cm.exception.code, 1)
        self.assertIn("not found in cache", err.getvalue())

    def test_main_closes_the_cache_when_loading_aborts(self):
        import cli
        from unittest import mock
        from macho.dyld_cache import ImageNotFoundError

        cache = self._FakeCache(ImageNotFoundError("nope"))
        with mock.patch.object(cli, "_open_cache", lambda path, native: cache), \
                contextlib.redirect_stderr(io.StringIO()):
            rc = cli.main(["--framework", "NoSuchFramework", "--cache", "/tmp/c",
                           "-o", "/tmp/never_written"])
        self.assertEqual(rc, 1)
        self.assertTrue(cache.closed)

    def test_a_failed_run_leaves_no_stale_diagnostics_file(self):
        import cli
        import tempfile
        from unittest import mock
        from macho.dyld_cache import ImageNotFoundError

        cache = self._FakeCache(ImageNotFoundError("nope"))
        with tempfile.TemporaryDirectory() as d:
            diag = os.path.join(d, "diag.json")
            with open(diag, "w") as fh:
                fh.write('{"from": "an earlier run"}')
            with mock.patch.object(cli, "_open_cache", lambda path, native: cache), \
                    contextlib.redirect_stderr(io.StringIO()):
                rc = cli.main(["--framework", "NoSuchFramework", "--cache", "/tmp/c",
                               "-o", os.path.join(d, "out"), "--diagnostics-json", diag])
            self.assertEqual(rc, 1)
            self.assertFalse(os.path.exists(diag))

    # ── _load_binary_context ──────────────────────────────────────────────────

    def test_load_binary_context_aborts_on_missing_file(self):
        from cli import _load_binary_context, _CliAbort
        args = SimpleNamespace(binary="/nonexistent/binary_xyz")
        with contextlib.redirect_stderr(io.StringIO()) as err:
            with self.assertRaises(_CliAbort) as cm:
                _load_binary_context(args, BinaryContext=None)
        self.assertEqual(cm.exception.code, 1)
        self.assertIn("binary not found", err.getvalue())

    def test_load_binary_context_aborts_on_non_macho(self):
        """A readable file that is not arm64 Mach-O aborts with exit 1, not a
        traceback out of BinaryContext."""
        from cli import _load_binary_context, _CliAbort
        from macho.memory import BinaryContext as _BC
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as fh:
            fh.write(b"not a mach-o file, just some bytes" * 8)
            path = fh.name
        try:
            args = SimpleNamespace(binary=path)
            with contextlib.redirect_stderr(io.StringIO()) as err:
                with self.assertRaises(_CliAbort) as cm:
                    _load_binary_context(args, _BC)
            self.assertEqual(cm.exception.code, 1)
            self.assertIn("not a valid arm64 Mach-O binary", err.getvalue())
        finally:
            os.unlink(path)

    # ── _open_enum_debug_writer ───────────────────────────────────────────────

    def test_enum_debug_writer_none_when_unset(self):
        from cli import _open_enum_debug_writer
        self.assertEqual(_open_enum_debug_writer(None), (None, None))

    def test_enum_debug_writer_writes_jsonl(self):
        from cli import _open_enum_debug_writer
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "enums.jsonl")
            with contextlib.redirect_stderr(io.StringIO()):
                fh, writer = _open_enum_debug_writer(path)
            self.assertIsNotNone(writer)
            writer({"a": 1})
            writer({"b": "é"})
            fh.close()
            with open(path, encoding="utf-8") as fh2:
                lines = fh2.read().splitlines()
        self.assertEqual([json.loads(x) for x in lines], [{"a": 1}, {"b": "é"}])

    def test_enum_debug_writer_unopenable_path_is_a_warning(self):
        """A bad --debug-enums path must not stop extraction: the trace is
        diagnostic, so the helper warns and returns no writer."""
        from cli import _open_enum_debug_writer
        with contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(
                _open_enum_debug_writer("/nonexistent/dir/enums.jsonl"),
                (None, None),
            )
        self.assertIn("could not open --debug-enums", err.getvalue())

    # ── _apply_prefix_filter ──────────────────────────────────────────────────

    def test_prefix_filter_passthrough_when_no_prefixes(self):
        from cli import _apply_prefix_filter
        msgs = [SimpleNamespace(class_name="GEOFoo")]
        self.assertIs(_apply_prefix_filter(msgs, None), msgs)

    def test_prefix_filter_keeps_only_matching_class_names(self):
        from cli import _apply_prefix_filter
        msgs = [SimpleNamespace(class_name=n)
                for n in ("GEOFoo", "PBBar", "GEOBaz")]
        with contextlib.redirect_stderr(io.StringIO()) as err:
            kept = _apply_prefix_filter(msgs, ["GEO"])
        self.assertEqual([m.class_name for m in kept], ["GEOFoo", "GEOBaz"])
        self.assertIn("3 → 2 messages", err.getvalue())


# ── TestVersioning ───────────────────────────────────────────────────────────

class TestVersioning(unittest.TestCase):
    """Tests for the version module and --version CLI flag."""

    def test_version_module_exists(self):
        import version
        self.assertTrue(hasattr(version, '__version__'))

    def test_version_string_is_1_0_0(self):
        from version import __version__
        self.assertEqual(__version__, '1.0.0')

    def test_version_info_tuple(self):
        from version import __version_info__
        self.assertEqual(__version_info__, (1, 0, 0))

    def test_version_flag_exits_zero(self):
        from cli import main
        with self.assertRaises(SystemExit) as cm:
            with contextlib.redirect_stdout(io.StringIO()):
                main(['--version'])
        self.assertEqual(cm.exception.code, 0)

    def test_version_flag_prints_version(self):
        from cli import main
        buf = io.StringIO()
        with self.assertRaises(SystemExit):
            with contextlib.redirect_stdout(buf):
                main(['--version'])
        self.assertIn('1.0.0', buf.getvalue())


# ── TestResolveCachePath ──────────────────────────────────────────────────────

class TestResolveCachePath(unittest.TestCase):
    """Tests for cli._resolve_cache_path()."""

    def _resolve(self, path_str: str):
        from cli import _resolve_cache_path
        return _resolve_cache_path(path_str)

    # ── direct file path ──────────────────────────────────────────────────────

    def test_direct_file_path_returned(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "dyld_shared_cache_arm64"
            p.write_bytes(b"")
            result = self._resolve(str(p))
            self.assertEqual(result, p)

    def test_direct_file_any_name_accepted(self):
        """Any existing file is accepted regardless of name."""
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "my_cache_file"
            p.write_bytes(b"")
            result = self._resolve(str(p))
            self.assertEqual(result, p)

    # ── directory auto-discovery ──────────────────────────────────────────────

    def test_directory_finds_arm64_cache(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "dyld_shared_cache_arm64"
            p.write_bytes(b"")
            result = self._resolve(d)
            self.assertEqual(result, p)

    def test_directory_finds_arm64e_cache(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "dyld_shared_cache_arm64e"
            p.write_bytes(b"")
            result = self._resolve(d)
            self.assertEqual(result, p)

    def test_directory_with_both_caches_returns_none(self):
        """Both files: nothing in the format says which is meant -- a warning naming both."""
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "dyld_shared_cache_arm64").write_bytes(b"")
            (Path(d) / "dyld_shared_cache_arm64e").write_bytes(b"")
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                result = self._resolve(d)
            self.assertIsNone(result)
            self.assertIn("dyld_shared_cache_arm64e and dyld_shared_cache_arm64", err.getvalue())

    def test_empty_directory_returns_none(self):
        with tempfile.TemporaryDirectory() as d:
            with contextlib.redirect_stderr(io.StringIO()):
                result = self._resolve(d)
            self.assertIsNone(result)

    # ── nonexistent path ──────────────────────────────────────────────────────

    def test_nonexistent_path_returns_none(self):
        with contextlib.redirect_stderr(io.StringIO()):
            result = self._resolve("/nonexistent/path/does/not/exist")
        self.assertIsNone(result)


# ── TestEndToEnd ──────────────────────────────────────────────────────────────

class TestEndToEnd(unittest.TestCase):
    """Synthetic end-to-end: build messages → write files → verify content."""

    def test_geo_clp_two_file_output(self):
        """Two packages → two files; geo.proto imports clp.proto."""
        clp_loc  = _clp_msg("Location", [
            _field("lat", 1, "double"),
            _field("lon", 2, "double"),
        ])
        geo_route = _geo_msg("Route", [
            _field("origin",      1, "CLPLocation", type_class="CLPLocation"),
            _field("destination", 2, "CLPLocation", type_class="CLPLocation"),
            _field("distance",    3, "double"),
        ])
        with tempfile.TemporaryDirectory() as tmpdir:
            written, pfs = write_from_messages(
                [clp_loc, geo_route],
                Path(tmpdir),
                source_name="TestBinary",
            )
            geo_text = (Path(tmpdir) / "geo.proto").read_text()
            clp_text = (Path(tmpdir) / "clp.proto").read_text()

        # geo.proto structure
        self.assertIn('edition = "2023";', geo_text)
        self.assertIn("package geo;", geo_text)
        self.assertIn('import "clp.proto";', geo_text)
        self.assertIn("message Route {", geo_text)
        self.assertIn("clp.Location origin = 1;", geo_text)
        self.assertIn("clp.Location destination = 2;", geo_text)
        self.assertIn("double distance = 3;", geo_text)

        # clp.proto structure
        self.assertIn('edition = "2023";', clp_text)
        self.assertIn("package clp;", clp_text)
        self.assertNotIn("import", clp_text)
        self.assertIn("message Location {", clp_text)
        self.assertIn("double lat = 1;", clp_text)

    def test_single_file_all_messages(self):
        geo_msg = _geo_msg("Route", [_field("dist", 1, "double")])
        clp_msg = _clp_msg("Location", [_field("lat", 1, "double")])
        with tempfile.TemporaryDirectory() as tmpdir:
            written, pfs = write_from_messages(
                [geo_msg, clp_msg],
                Path(tmpdir),
                single_file=True,
                package_override="apple",
                source_name="TestBinary",
            )
            content = (Path(tmpdir) / "apple.proto").read_text()

        self.assertEqual(len(written), 1)
        self.assertIn("package apple;", content)
        self.assertIn("message Route", content)
        self.assertIn("message Location", content)

    def test_unresolved_ref_emitted_as_bytes_with_comment(self):
        msg = _geo_msg("Foo", [
            _field("session", 1, "GEOCStruct", type_class="GEOCStruct"),
        ])
        with tempfile.TemporaryDirectory() as tmpdir:
            written, _ = write_from_messages([msg], Path(tmpdir))
            content = (Path(tmpdir) / "geo.proto").read_text()

        self.assertIn("bytes session = 1;", content)
        self.assertIn("unresolved: GEOCStruct", content)

    def test_repeated_cross_package_field(self):
        clp_loc = _clp_msg("Location", [_field("lat", 1, "double")])
        msg = ProtoMessage("Route", "GEORoute", [
            ProtoField(
                name="waypoints",
                number=1,
                type_name="CLPLocation",
                label=FieldLabel.REPEATED,
                type_class="CLPLocation",
                number_confirmed=True,
            )
        ])
        with tempfile.TemporaryDirectory() as tmpdir:
            write_from_messages([clp_loc, msg], Path(tmpdir))
            content = (Path(tmpdir) / "geo.proto").read_text()

        self.assertIn("repeated clp.Location waypoints = 1;", content)



# ── TestRunPrefixes ───────────────────────────────────────────────────────────

class TestRunPrefixes(unittest.TestCase):
    """package_for_class(name, prefixes): the run's own --prefix set on top of the defaults,
    passed per call -- nothing is registered in the module, so one run's prefixes never
    reach another's."""

    def test_new_prefix_gives_its_lowercase_package(self):
        self.assertEqual(package_for_class("APPLFoo", ("APPL",)), "appl")
        self.assertEqual(package_for_class("MSFTBar", ("MSFT",)), "msft")

    def test_a_default_prefix_wins_over_a_longer_run_prefix(self):
        # the defaults are tried first, as the old registration order did
        self.assertEqual(package_for_class("GEOPDPlace", ("GEOPD",)), "geo")

    def test_a_prefix_shorter_than_the_caps_run_decides(self):
        # without it the leading all-caps run would give "tstxab"
        self.assertEqual(package_for_class("TSTXABFoo"), "tstxab")
        self.assertEqual(package_for_class("TSTXABFoo", ("TSTX",)), "tstx")

    def test_one_calls_prefixes_do_not_reach_the_next(self):
        package_for_class("TSTXABFoo", ("TSTX",))
        self.assertEqual(package_for_class("TSTXABFoo"), "tstxab")

    def test_build_proto_files_takes_the_runs_prefixes(self):
        msg = ProtoMessage(name="ABFoo", class_name="TSTXABFoo", fields=[])
        (pf,) = build_proto_files([msg], prefixes=("TSTX",))
        self.assertEqual(pf.package, "tstx")
        msg2 = ProtoMessage(name="ABFoo", class_name="TSTXABFoo", fields=[])
        (pf2,) = build_proto_files([msg2])
        self.assertEqual(pf2.package, "tstxab")

    def test_case_sensitivity_preserved(self):
        self.assertEqual(package_for_class("APPLFoo", ("APPL",)), "appl")
        # lowercase name: no uppercase run, last-resort lowercasing
        self.assertEqual(package_for_class("applFoo", ("APPL",)), "applfoo")


# ── TestEmitIsPure ────────────────────────────────────────────────────────────

class TestEmitIsPure(unittest.TestCase):
    """The enum plan (merge, split, rename, zero value) is made when the file is built;
    emit() only renders, and the run's input kind lives on the files it builds."""

    def _split_run(self):
        from proto.models import ProtoEnum, ProtoEnumValue
        a, b = _geo_msg("A"), _geo_msg("B")
        a.enums = [ProtoEnum("Kind", [ProtoEnumValue("KIND_ZERO", 0), ProtoEnumValue("KIND_X", 1)])]
        b.enums = [ProtoEnum("Kind", [ProtoEnumValue("KIND_ZERO", 0), ProtoEnumValue("KIND_Y", 1)])]
        a.fields = [_field("k", 1, "Kind", type_class="ENUM:Kind")]
        b.fields = [_field("k", 1, "Kind", type_class="ENUM:Kind")]
        return [a, b]

    def test_emit_changes_no_message_and_repeats_exactly(self):
        msgs = self._split_run()
        (pf,) = build_proto_files(msgs)
        planned = [f.type_class for m in msgs for f in m.fields]
        self.assertIn("ENUM:BKind", planned)        # the split was made at build time
        first = pf.emit()
        self.assertEqual([f.type_class for m in msgs for f in m.fields], planned)
        self.assertEqual(pf.emit(), first)

    def test_input_kind_is_per_run(self):
        msg = _geo_msg("Foo", [_field("e", 1, "int32")])
        (cache_pf,) = build_proto_files([msg], input_kind=InputKind.CACHE_IMAGE)
        (dylib_pf,) = build_proto_files([msg])
        for pf in (cache_pf, dylib_pf):
            pf.n_ambiguous = 1
        self.assertIn("ERROR", cache_pf.emit())
        self.assertNotIn("ERROR", dylib_pf.emit())


# ── TestEnumRebuildKeepsIncompleteReason ──────────────────────────────────────

class TestEnumRebuildKeepsIncompleteReason(unittest.TestCase):
    """The emitter rebuilds an enum to split a name clash, rename it away from a message
    name, or add a zero value; each rebuild keeps why its values may be incomplete."""

    _REASON = "value 7 of the inlined converter could not be evaluated"

    def _enum(self, name, values):
        from proto.models import ProtoEnum, ProtoEnumValue
        return ProtoEnum(name=name, values=[ProtoEnumValue(n, v) for n, v in values],
                         values_truncated=True, incomplete_reason=self._REASON)

    def _emit(self, msgs):
        return ProtoFile("geo", "geo.proto", msgs, []).emit()

    def test_zero_value_synthesis(self):
        msg = _geo_msg("Foo")
        msg.enums = [self._enum("FooKind", [("FOO_KIND_A", 1), ("FOO_KIND_B", 2)])]
        out = self._emit([msg])
        self.assertIn("FOO_KIND_UNSPECIFIED = 0", out)
        self.assertIn(f"INCOMPLETE — {self._REASON}", out)

    def test_message_name_collision_rename(self):
        msg = _geo_msg("Foo")
        msg.enums = [self._enum("Foo", [("FOO_ZERO", 0), ("FOO_A", 1)])]
        out = self._emit([msg])
        self.assertIn("enum FooEnum {", out)
        self.assertIn(f"INCOMPLETE — {self._REASON}", out)

    def test_incompatible_split(self):
        a, b = _geo_msg("A"), _geo_msg("B")
        a.enums = [self._enum("Kind", [("KIND_ZERO", 0), ("KIND_X", 1)])]
        b.enums = [self._enum("Kind", [("KIND_ZERO", 0), ("KIND_Y", 1)])]
        out = self._emit([a, b])
        self.assertIn("enum BKind {", out)
        self.assertEqual(out.count(f"INCOMPLETE — {self._REASON}"), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
