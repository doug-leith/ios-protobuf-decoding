"""
tests/test_cross_image.py — message classes defined in another cache image, and
--single-file package qualification.

  - proto.cross_image.resolve_cross_image over an in-memory fake cache (real
    DyldCacheReader.image_containing / image_dependencies and the real
    macho.cache_classlist readers run against it): class-reference resolution,
    the linked-dylib name fallback, transitive pull-in, and every refusal
    (ambiguous, not a PB message, defined in the extracted image, name taken).
  - build_proto_files(single_file=True): no package qualifier, no import, protoc compiles.
  - live (dyld cache present): CloudKitDaemon's CloudKit / CloudKitDistributedSync
    references resolve, and the CLI output for CloudKitDaemon (multi-file) and CloudKit
    (--single-file) compiles with no unresolved field.
"""

from __future__ import annotations

import os
import shutil
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path

import artifacts
from macho.dyld_cache import DyldCacheReader
from macho.load_commands import parse_load_commands
from proto.cross_image import (VIA_CLASSREF, VIA_LINKED_DYLIB, VIA_SAME_IMAGE,
                               resolve_cross_image)
from proto.emitter import build_proto_files, referenced_message_class
from proto.models import FieldLabel, ProtoField, ProtoMessage


# ── in-memory fake cache ──────────────────────────────────────────────────────

class FakeCache:
    """Just enough of a DyldCacheReader for proto.cross_image: images with __TEXT /
    __DATA / __DATA_CONST segments, ObjC class_t/class_ro_t/name chains, a classlist and
    classrefs per image, and LC_LOAD_DYLIB commands.  The address-to-image, load-command and
    pointer-read methods are DyldCacheReader's own."""

    image_containing = DyldCacheReader.image_containing
    _segment_at = DyldCacheReader._segment_at
    image_dependencies = DyldCacheReader.image_dependencies
    _commands_or_none = DyldCacheReader._commands_or_none
    read_ptr = DyldCacheReader.read_ptr

    def __init__(self):
        self.mem, self.strs = {}, {}
        self.images = []              # [(mach_va, path)]
        self.classes = {}             # name -> (image va, class_t va)
        self._defined, self._refs, self._deps, self._super = {}, {}, {}, {}
        self._cursor = {}

    def image(self, path, classes=(), refs=(), deps=()):
        va = 0x1_0000_0000 * (len(self.images) + 1)
        self.images.append((va, path))
        self._cursor[va] = {"text": va + 0x100, "data": va + 0x10000}
        self._defined[va] = list(classes)
        self._refs[va] = list(refs)
        self._deps[va] = list(deps)
        for name in classes:
            cur = self._cursor[va]
            cls, cur["data"] = cur["data"], cur["data"] + 0x40
            ro, name_va = cur["text"], cur["text"] + 0x40
            cur["text"] += 0x80
            self.mem[cls + 32] = ro
            self.mem[ro + 24] = name_va
            self.strs[name_va] = name
            self.classes[name] = (va, cls)
        return va

    def superclass(self, name, parent):
        self.mem[self.classes[name][1] + 8] = self.classes[parent][1]

    # sections are laid out lazily so every image()/superclass() call can come first
    def image_sections(self, va):
        segs = {"__TEXT": (va, va + 0x10000), "__DATA": (va + 0x10000, va + 0x20000),
                "__DATA_CONST": (va + 0x20000, va + 0x30000)}
        cl = va + 0x20000
        for i, name in enumerate(self._defined.get(va, ())):
            self.mem[cl + 8 * i] = self.classes[name][1]
        if self._defined.get(va):
            segs["__DATA_CONST/__objc_classlist"] = (cl, cl + 8 * len(self._defined[va]))
        refs = va + 0x1F000
        for i, name in enumerate(self._refs.get(va, ())):
            self.mem[refs + 8 * i] = self.classes[name][1]
        if self._refs.get(va):
            segs["__DATA/__objc_classrefs"] = (refs, refs + 8 * len(self._refs[va]))
        return segs

    def image_load_commands(self, va):
        cmds = b""
        for path in self._deps.get(va, ()):
            name = path.encode() + b"\x00"
            cmds += struct.pack("<IIIIII", 0x0C, 24 + len(name), 24, 0, 0, 0) + name
        return parse_load_commands(cmds, len(self._deps.get(va, ())))

    def list_images(self):
        return list(self.images)

    def read_u64(self, va):
        return self.mem.get(va, 0)

    def decode_ptr(self, raw):
        return raw

    def read_cstring(self, va, max_len=4096):
        return self.strs.get(va)


def msg(class_name, *refs, name=None):
    """A ProtoMessage whose fields reference *refs* (class names) as messages."""
    fields = [ProtoField(f"f{i}", i, r, FieldLabel.OPTIONAL, type_class=r,
                         number_confirmed=True)
              for i, r in enumerate(refs, 1)]
    return ProtoMessage(name=name or class_name, class_name=class_name, fields=fields)


class _Extractor:
    """Stands in for extract_cache_image: per-image message lists, and a call log."""

    def __init__(self, cache, per_image):
        self.cache, self.per_image, self.calls = cache, per_image, []

    def __call__(self, reader, va):
        path = dict(self.cache.images)[va]
        self.calls.append(path)
        return [m for m in self.per_image.get(path, [])], None


def _pb_cache():
    """ProtocolBuffer (PBCodable root) + NSObject, the roots every scenario uses."""
    c = FakeCache()
    c.image("/usr/lib/libobjc.A.dylib", classes=["NSObject"])
    c.image("/System/Library/PrivateFrameworks/ProtocolBuffer.framework/ProtocolBuffer",
            classes=["PBCodable"])
    c.superclass("PBCodable", "NSObject")
    return c


DAEMON = "/System/Library/PrivateFrameworks/CloudKitDaemon.framework/CloudKitDaemon"
KIT = "/System/Library/Frameworks/CloudKit.framework/CloudKit"
SYNC = "/System/Library/PrivateFrameworks/CloudKitDistributedSync.framework/CloudKitDistributedSync"


class TestReferencedMessageClass(unittest.TestCase):

    def test_message_ref(self):
        f = ProtoField("r", 1, "CKDPDate", FieldLabel.OPTIONAL, type_class="CKDPDate")
        self.assertEqual(referenced_message_class(f), "CKDPDate")

    def test_after_resolution_unresolved_bytes(self):
        f = ProtoField("r", 1, "bytes", FieldLabel.OPTIONAL, type_class="CKDPDate",
                       unresolved_type_class="CKDPDate")
        self.assertEqual(referenced_message_class(f), "CKDPDate")

    def test_scalars_enums_builtins_are_not_refs(self):
        for f in (ProtoField("s", 1, "string", FieldLabel.OPTIONAL, type_class="NSString"),
                  ProtoField("d", 2, "bytes", FieldLabel.OPTIONAL, type_class="NSData"),
                  ProtoField("e", 3, "Kind", FieldLabel.OPTIONAL, type_class="ENUM:Kind"),
                  ProtoField("i", 4, "int32", FieldLabel.OPTIONAL)):
            self.assertIsNone(referenced_message_class(f), f.name)

    def test_map_value_class(self):
        f = ProtoField("m", 1, "bytes", FieldLabel.OPTIONAL, type_class="NSMutableDictionary",
                       map_key_type="string", map_value_class="CKDPDate")
        self.assertEqual(referenced_message_class(f), "CKDPDate")


class TestResolveCrossImage(unittest.TestCase):

    def test_classref_resolution_is_transitive(self):
        c = _pb_cache()
        daemon = c.image(DAEMON, classes=["CKDPRecord"], refs=["CKDPRecordIdentifier"],
                         deps=[KIT])
        c.image(KIT, classes=["CKDPRecordIdentifier", "CKDPRecordZoneIdentifier"])
        for n in ("CKDPRecord", "CKDPRecordIdentifier", "CKDPRecordZoneIdentifier"):
            c.superclass(n, "PBCodable")
        ex = _Extractor(c, {KIT: [msg("CKDPRecordIdentifier", "CKDPRecordZoneIdentifier"),
                                  msg("CKDPRecordZoneIdentifier"), msg("CKDPUnused")]})
        res = resolve_cross_image(c, daemon, [msg("CKDPRecord", "CKDPRecordIdentifier")],
                                  extract=ex)
        got = {m.class_name: (m.defined_in, m.defined_in_via) for m in res.added}
        self.assertEqual(got, {
            "CKDPRecordIdentifier": (KIT, VIA_CLASSREF),
            "CKDPRecordZoneIdentifier": (KIT, VIA_SAME_IMAGE),
        })
        self.assertEqual(res.unresolved, {})
        self.assertEqual(ex.calls, [KIT])            # one extraction per image

    def test_classref_into_a_third_image(self):
        c = _pb_cache()
        daemon = c.image(DAEMON, classes=["CKDPRecord"], refs=["CKDPDistributedTimestamps"])
        c.image(KIT, classes=["CKDPRecordIdentifier"])
        c.image(SYNC, classes=["CKDPDistributedTimestamps"])
        c.superclass("CKDPDistributedTimestamps", "PBCodable")
        ex = _Extractor(c, {SYNC: [msg("CKDPDistributedTimestamps")]})
        res = resolve_cross_image(c, daemon, [msg("CKDPRecord", "CKDPDistributedTimestamps")],
                                  extract=ex)
        self.assertEqual([(m.class_name, m.defined_in) for m in res.added],
                         [("CKDPDistributedTimestamps", SYNC)])

    def test_name_only_reference_found_in_linked_closure(self):
        # no classref: the class is looked up by name among the images DAEMON links,
        # transitively (DAEMON -> MID -> KIT); an unlinked image defining it is ignored
        c = _pb_cache()
        mid = "/System/Library/PrivateFrameworks/Mid.framework/Mid"
        daemon = c.image(DAEMON, classes=["CKDPRecord"], deps=[mid])
        c.image(mid, deps=[KIT])
        c.image(KIT, classes=["CKDPDate"])
        c.superclass("CKDPDate", "PBCodable")
        ex = _Extractor(c, {KIT: [msg("CKDPDate")]})
        res = resolve_cross_image(c, daemon, [msg("CKDPRecord", "CKDPDate")], extract=ex)
        self.assertEqual([(m.class_name, m.defined_in_via) for m in res.added],
                         [("CKDPDate", VIA_LINKED_DYLIB)])

    def test_name_only_reference_ambiguous_is_refused(self):
        c = _pb_cache()
        other = "/System/Library/PrivateFrameworks/Other.framework/Other"
        daemon = c.image(DAEMON, classes=["CKDPRecord"], deps=[KIT, other])
        c.image(KIT, classes=["CKDPDate"])
        c.image(other, classes=["CKDPDate"])
        ex = _Extractor(c, {})
        res = resolve_cross_image(c, daemon, [msg("CKDPRecord", "CKDPDate")], extract=ex)
        self.assertEqual(res.added, [])
        self.assertIn("several linked images", res.unresolved["CKDPDate"])
        self.assertEqual(ex.calls, [])

    def test_unlinked_unreferenced_class_is_refused(self):
        c = _pb_cache()
        daemon = c.image(DAEMON, classes=["CKDPRecord"])
        c.image(KIT, classes=["CKDPDate"])           # defines it, but DAEMON does not link it
        res = resolve_cross_image(c, daemon, [msg("CKDPRecord", "CKDPDate")],
                                  extract=_Extractor(c, {}))
        self.assertEqual(res.added, [])
        self.assertIn("nor defined by any linked image", res.unresolved["CKDPDate"])

    def test_non_pb_class_is_not_extracted(self):
        c = _pb_cache()
        daemon = c.image(DAEMON, classes=["CKDPRecord"], refs=["CLLocation"])
        loc = "/System/Library/Frameworks/CoreLocation.framework/CoreLocation"
        c.image(loc, classes=["CLLocation"])
        c.superclass("CLLocation", "NSObject")
        ex = _Extractor(c, {loc: [msg("CLLocation")]})
        res = resolve_cross_image(c, daemon, [msg("CKDPRecord", "CLLocation")], extract=ex)
        self.assertEqual(res.added, [])
        self.assertIn("not a protobuf message", res.unresolved["CLLocation"])
        self.assertEqual(ex.calls, [])               # no whole-image extraction paid for

    def test_class_of_the_extracted_image_is_never_sought_elsewhere(self):
        # filtered out / failed in the requested image: that is a fact about this image
        c = _pb_cache()
        daemon = c.image(DAEMON, classes=["CKDPRecord", "CKDPLocal"], refs=["CKDPLocal"])
        c.superclass("CKDPLocal", "PBCodable")
        ex = _Extractor(c, {})
        res = resolve_cross_image(c, daemon, [msg("CKDPRecord", "CKDPLocal")], extract=ex)
        self.assertEqual(res.added, [])
        self.assertIn("the image being extracted", res.unresolved["CKDPLocal"])
        self.assertEqual(ex.calls, [])

    def test_defining_image_does_not_yield_it(self):
        c = _pb_cache()
        daemon = c.image(DAEMON, classes=["CKDPRecord"], refs=["CKDPDate"])
        c.image(KIT, classes=["CKDPDate"])
        c.superclass("CKDPDate", "PBCodable")
        res = resolve_cross_image(c, daemon, [msg("CKDPRecord", "CKDPDate")],
                                  extract=_Extractor(c, {KIT: []}))
        self.assertIn("not a PBCodable message there", res.unresolved["CKDPDate"])

    def test_defining_image_extraction_error_is_reported(self):
        c = _pb_cache()
        daemon = c.image(DAEMON, classes=["CKDPRecord"], refs=["CKDPDate"])
        c.image(KIT, classes=["CKDPDate"])
        c.superclass("CKDPDate", "PBCodable")

        def boom(reader, va):
            raise RuntimeError("bad image")
        res = resolve_cross_image(c, daemon, [msg("CKDPRecord", "CKDPDate")], extract=boom)
        self.assertEqual(res.added, [])
        self.assertIn("RuntimeError: bad image", res.image_errors[KIT])
        self.assertIn("extraction failed", res.unresolved["CKDPDate"])

    def test_proto_name_collision_is_refused(self):
        c = _pb_cache()
        daemon = c.image(DAEMON, classes=["CKDPRecord", "CKDPHere"], refs=["CKDPThere"])
        c.image(KIT, classes=["CKDPThere"])
        c.superclass("CKDPThere", "PBCodable")
        ex = _Extractor(c, {KIT: [msg("CKDPThere", name="Same")]})
        res = resolve_cross_image(
            c, daemon, [msg("CKDPRecord", "CKDPThere"), msg("CKDPHere", name="Same")],
            extract=ex)
        self.assertEqual(res.added, [])
        self.assertIn("already taken", res.unresolved["CKDPThere"])

    def test_input_messages_are_not_modified(self):
        c = _pb_cache()
        daemon = c.image(DAEMON, classes=["CKDPRecord"], refs=["CKDPDate"])
        c.image(KIT, classes=["CKDPDate"])
        c.superclass("CKDPDate", "PBCodable")
        primary = [msg("CKDPRecord", "CKDPDate")]
        resolve_cross_image(c, daemon, primary, extract=_Extractor(c, {KIT: [msg("CKDPDate")]}))
        self.assertEqual(len(primary), 1)
        self.assertIsNone(primary[0].defined_in)


class TestEmitDefinedIn(unittest.TestCase):

    def test_comment_header_and_typed_field(self):
        ext = msg("CKDPDate")
        ext.defined_in, ext.defined_in_via = KIT, VIA_CLASSREF
        pfs = build_proto_files([msg("CKDPRecord", "CKDPDate"), ext], source_name="CloudKitDaemon")
        text = pfs[0].emit()
        self.assertIn("// Includes 1 message defined in other images, referenced by "
                      "messages here: CloudKit (1)", text)
        self.assertIn(f"  // defined in {KIT} ({VIA_CLASSREF})", text)
        self.assertIn("CKDPDate f1 = 1;", text)
        self.assertNotIn("unresolved", text)


_PROTOC = shutil.which("protoc")


def _protoc_ok(directory: Path) -> None:
    for f in sorted(directory.glob("*.proto")):
        r = subprocess.run([_PROTOC, "-I", str(directory), "--descriptor_set_out=/dev/null",
                            str(f)], capture_output=True, text=True)
        assert r.returncode == 0, f"protoc rejects {f.name}:\n{r.stderr}"


class TestSingleFileQualification(unittest.TestCase):
    """--single-file puts every message in ONE package: a reference must not keep the
    ObjC-prefix package (``ck.CKCodeProto2Any``) the file never declares."""

    def _messages(self):
        # CKDP* -> package ckdp, CKCode* -> package ck: cross-package in multi-file mode
        return [msg("CKDPRecord", "CKCodeProto2Any"), msg("CKCodeProto2Any")]

    def test_multi_file_still_qualifies_and_imports(self):
        pfs = {pf.package: pf for pf in build_proto_files(self._messages())}
        self.assertIn("ck.CKCodeProto2Any f1 = 1;", pfs["ckdp"].emit())
        self.assertEqual(pfs["ckdp"].imports, ["ck.proto"])

    def test_single_file_unqualified_no_import(self):
        [pf] = build_proto_files(self._messages(), single_file=True, source_name="CloudKit")
        text = pf.emit()
        self.assertIn("package cloudkit;", text)
        self.assertIn("  CKCodeProto2Any f1 = 1;", text)
        self.assertNotIn("ck.", text.split("package cloudkit;", 1)[1])
        self.assertEqual(pf.imports, [])

    def test_single_file_foreign_ref_package_dropped(self):
        a = ProtoMessage(name="A", class_name="A", package="pkg.one",
                         serializer="C++ libprotobuf",
                         fields=[ProtoField("b", 1, "B", FieldLabel.OPTIONAL,
                                            ref_package="pkg.two", ref_file="two.proto")])
        b = ProtoMessage(name="B", class_name="B", package="pkg.two",
                         serializer="C++ libprotobuf")
        [pf] = build_proto_files([a, b], single_file=True, package_override="all")
        self.assertIn("  B b = 1;", pf.emit())
        self.assertEqual(pf.imports, [])

    @unittest.skipUnless(_PROTOC, "protoc not on PATH")
    def test_single_file_compiles(self):
        from proto.emitter import write_proto_files
        with tempfile.TemporaryDirectory() as d:
            write_proto_files(build_proto_files(self._messages(), single_file=True,
                                                source_name="CloudKit"), Path(d))
            _protoc_ok(Path(d))


# ── live: the real dyld cache ─────────────────────────────────────────────────

_CACHE_MAIN = artifacts.cache_file()
_SKIP = "dyld shared cache not found — set MACHO_TEST_CACHE or see artifacts.py"


@unittest.skipUnless(_CACHE_MAIN, _SKIP)
class TestCrossImageLive(unittest.TestCase):

    def test_cloudkitdaemon_classrefs_name_their_defining_images(self):
        import warnings
        from proto.cross_image import _Locator
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            reader = DyldCacheReader(_CACHE_MAIN)
        try:
            daemon = reader.resolve_image("CloudKitDaemon")
            self.assertIn(KIT, reader.image_dependencies(daemon))
            loc = _Locator(reader)
            expect = {"CKDPRecordIdentifier": KIT, "CKDPIdentifier": KIT,
                      "CKDPRecordZoneIdentifier": KIT, "CKDPDate": KIT,
                      "CKDPLocationCoordinate": KIT, "CKDPRecordReference": KIT,
                      "CKCodeRecordTransport": KIT, "CKDPDistributedTimestamps": SYNC}
            for cname, image in expect.items():
                va, _cls, via = loc.locate(daemon, cname)
                self.assertEqual((loc.path_of(va) if va else None, via),
                                 (image, VIA_CLASSREF), cname)
        finally:
            reader.close()

    def _cli(self, *argv):
        import cli
        with tempfile.TemporaryDirectory() as d:
            import contextlib
            import io
            with contextlib.redirect_stderr(io.StringIO()):
                status = cli.main([*argv, "--cache", os.path.dirname(_CACHE_MAIN), "-o", d])
            out = {p.name: p.read_text() for p in Path(d).glob("*.proto")}
            if _PROTOC:
                _protoc_ok(Path(d))
        return status, out

    def test_cloudkitdaemon_output_has_no_unresolved_field(self):
        status, out = self._cli("--framework", "CloudKitDaemon")
        self.assertEqual(status, 0)
        self.assertFalse([n for n, t in out.items() if "unresolved:" in t])
        self.assertIn("  // defined in " + KIT + " (" + VIA_CLASSREF + ")",
                      out["ckdp.proto"])
        self.assertIn("message CKCodeRecordTransport {", out["ck.proto"])
        self.assertIn("message CKDPDistributedTimestamps {", out["ckdp.proto"])

    def test_no_cross_image_flag_keeps_bytes(self):
        status, out = self._cli("--framework", "CloudKitDaemon", "--no-cross-image")
        self.assertEqual(status, 0)
        self.assertIn("// unresolved: CKDPRecordIdentifier", out["ckdp.proto"])
        self.assertNotIn("ck.proto", out)

    def test_cloudkit_single_file_compiles(self):
        status, out = self._cli("--framework", "CloudKit.framework/CloudKit", "--single-file")
        self.assertEqual(status, 0)
        self.assertEqual(list(out), ["cloudkit.proto"])
        self.assertNotIn("ck.CKCodeProto2Any", out["cloudkit.proto"])


if __name__ == "__main__":
    unittest.main()
