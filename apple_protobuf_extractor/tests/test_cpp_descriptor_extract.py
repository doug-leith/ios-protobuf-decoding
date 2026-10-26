"""C++ libprotobuf .proto recovery: decode embedded FileDescriptorProto descriptors.

Offline: a hand-built minimal descriptor blob (no deps) exercises the decoder +
emitter; a richer descriptor_pb2-built fixture (skipped if the protobuf package is
absent) cross-checks field number/type/label/type_name round-trips.

Live: locationd embeds ~12 vendored (AWD) FileDescriptorProtos -> extract_cpp_protos
recovers them, cross-validated field-for-field against descriptor_pb2 when available.
"""
import os
import unittest
from types import SimpleNamespace

from serializers import cpp_descriptor_extract as C


def _v(n):                       # encode a varint
    out = bytearray()
    while True:
        b = n & 0x7F; n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def _ld(field, payload):         # length-delimited field (wire type 2)
    return _v(field << 3 | 2) + _v(len(payload)) + payload


def _vf(field, value):           # varint field (wire type 0)
    return _v(field << 3 | 0) + _v(value)


class TestCppDecodeMinimal(unittest.TestCase):
    def _blob(self):
        # FieldDescriptorProto x: name=x(1) number=1(3) label=optional(4) type=int32(5)
        fx = _ld(1, b"x") + _vf(3, 1) + _vf(4, 1) + _vf(5, 5)
        # FieldDescriptorProto m: name=m number=2 label=repeated(3) type=message(11) type_name=.p.M
        fm = _ld(1, b"m") + _vf(3, 2) + _vf(4, 3) + _vf(5, 11) + _ld(6, b".p.Inner")
        # EnumDescriptorProto E { A=0; B=1 }
        en = _ld(1, b"E") + _ld(2, _ld(1, b"A") + _vf(2, 0)) + _ld(2, _ld(1, b"B") + _vf(2, 1))
        # DescriptorProto M { field x; field m; enum E }
        msg = _ld(1, b"M") + _ld(2, fx) + _ld(2, fm) + _ld(4, en)
        # FileDescriptorProto
        return (_ld(1, b"test.proto") + _ld(2, b"p") + _ld(4, msg) + _ld(12, b"proto2"))

    def test_decode_fields(self):
        fp = C.decode_file_descriptor(self._blob())
        self.assertEqual((fp.name, fp.package, fp.syntax), ("test.proto", "p", "proto2"))
        self.assertEqual(len(fp.messages), 1)
        m = fp.messages[0]
        self.assertEqual(m.name, "M")
        self.assertEqual([(f.name, f.number, f.type, f.label) for f in m.fields],
                         [("x", 1, 5, 1), ("m", 2, 11, 3)])
        self.assertEqual(m.fields[1].type_name, ".p.Inner")
        self.assertEqual(m.enums[0].values, [("A", 0), ("B", 1)])

    def test_emit_proto_text(self):
        text = C.format_proto(C.decode_file_descriptor(self._blob()))
        self.assertIn('syntax = "proto2";', text)
        self.assertIn("package p;", text)
        self.assertIn("optional int32 x = 1;", text)
        self.assertIn("repeated Inner m = 2;", text)        # .p. prefix trimmed
        self.assertIn("enum E {", text)
        self.assertIn("A = 0;", text)

    def test_find_blobs_among_junk(self):
        blob = self._blob()
        buf = b"\x00\x11\x22" + blob + b"\xff\xfe\x00" + blob + b"garbage"
        found = C.find_descriptor_blobs(buf)
        self.assertEqual(len(found), 1)                     # dedup by (name, len)
        self.assertEqual(C.decode_file_descriptor(found[0][1]).name, "test.proto")

    def test_a_long_name_or_one_with_a_space_is_found(self):
        # the name's length a two-byte varint (over 127 characters), or a space in it
        for name in (b"a/" + b"deep/" * 40 + b"x.proto", b"My Folder/x y.proto"):
            blob = self._blob().replace(_ld(1, b"test.proto"), _ld(1, name), 1)
            found = C.find_descriptor_blobs(b"\x00junk" + blob + b"\xff")
            self.assertEqual([C.decode_file_descriptor(b).name for _o, b in found],
                             [name.decode()])


class TestCppOneofAndProto3(unittest.TestCase):
    def _blob(self):
        # proto3 message with a 2-field oneof + one plain repeated field.
        a = _ld(1, b"a") + _vf(3, 1) + _vf(4, 1) + _vf(5, 5) + _vf(9, 0)   # oneof_index 0
        b = _ld(1, b"b") + _vf(3, 2) + _vf(4, 1) + _vf(5, 9) + _vf(9, 0)   # oneof_index 0
        rep = _ld(1, b"tags") + _vf(3, 3) + _vf(4, 3) + _vf(5, 9)          # repeated string
        oneof = _ld(1, b"choice")                                          # OneofDescriptorProto
        msg = _ld(1, b"M") + _ld(2, a) + _ld(2, b) + _ld(2, rep) + _ld(8, oneof)
        return _ld(1, b"o.proto") + _ld(4, msg) + _ld(12, b"proto3")

    def test_oneof_and_proto3_emit(self):
        fp = C.decode_file_descriptor(self._blob())
        self.assertEqual(fp.syntax, "proto3")
        self.assertEqual(fp.messages[0].oneofs, ["choice"])
        text = C.format_proto(fp)
        self.assertIn("oneof choice {", text)
        self.assertIn("int32 a = 1;", text)        # proto3: no 'optional' label
        self.assertIn("string b = 2;", text)
        self.assertIn("repeated string tags = 3;", text)


class TestCppPackedOption(unittest.TestCase):
    def test_packed_repeated_field(self):
        # repeated int32 with FieldOptions{packed=true}
        opts = _ld(8, _vf(2, 1))                       # FieldOptions.packed = true
        f = _ld(1, b"ids") + _vf(3, 4) + _vf(4, 3) + _vf(5, 5) + opts
        msg = _ld(1, b"M") + _ld(2, f)
        blob = _ld(1, b"p.proto") + _ld(4, msg) + _ld(12, b"proto2")
        fp = C.decode_file_descriptor(blob)
        fld = fp.messages[0].fields[0]
        self.assertTrue(fld.has_packed and fld.packed)
        self.assertIn("repeated int32 ids = 4 [packed=true];", C.format_proto(fp))


class TestCppReader(unittest.TestCase):
    def test_wire_types_and_errors(self):
        r = C._Reader(_vf(1, 300) + _ld(2, b"hi")
                      + (_v(3 << 3 | 1) + b"\x00" * 8)        # I64
                      + (_v(4 << 3 | 5) + b"\x01\x02\x03\x04"))  # I32
        self.assertEqual(r.field(), (1, 0, 300))
        self.assertEqual(r.field(), (2, 2, b"hi"))
        self.assertEqual(r.field()[:2], (3, 1))
        self.assertEqual(r.field()[:2], (4, 5))
        self.assertTrue(r.eof())
        # field 0 is illegal
        self.assertRaises(ValueError, C._Reader(_v(0 << 3 | 0) + b"\x01").field)
        # reserved wire type 3
        self.assertRaises(ValueError, C._Reader(_v(1 << 3 | 3)).field)
        # length-delimited running past the end
        self.assertRaises(ValueError, C._Reader(_v(1 << 3 | 2) + _v(40) + b"xx").field)
        # truncated varint
        self.assertRaises(ValueError, C._Reader(b"\x80\x80\x80").varint)


class TestCppCli(unittest.TestCase):
    def _file_with_blob(self, tmpdir):
        import os
        # a descriptor blob embedded in junk, written to a plain file (the CLI
        # scans raw bytes; it does not require a valid Mach-O).
        blob = (_ld(1, b"cli.proto") + _ld(4, _ld(1, b"M") +
                _ld(2, _ld(1, b"x") + _vf(3, 1) + _vf(4, 1) + _vf(5, 5))) +
                _ld(12, b"proto2"))
        p = os.path.join(tmpdir, "fake.bin")
        with open(p, "wb") as fh:
            fh.write(b"\xca\xfe" + blob + b"\x00\x00trailing")
        return p

    def test_main_writes_proto(self):
        import tempfile, os
        with tempfile.TemporaryDirectory() as d:
            binp = self._file_with_blob(d)
            outd = os.path.join(d, "out")
            rc = C._main([binp, "-o", outd])
            self.assertEqual(rc, 0)
            written = os.listdir(outd)
            self.assertEqual(written, ["cli.proto"])
            text = open(os.path.join(outd, "cli.proto")).read()
            self.assertIn("message M", text)

    def _file_with_two_blobs(self, tmpdir, dep_name, main_name):
        # main.proto imports dep_name; dep_name has no directory component in
        # its own message, main.proto references Dep.M via its type_name.
        dep = _ld(1, dep_name.encode()) + _ld(2, b"p") + _ld(12, b"proto2") + \
            _ld(4, _ld(1, b"Dep") + _ld(2, _ld(1, b"x") + _vf(3, 1) + _vf(4, 1) + _vf(5, 5)))
        main = (_ld(1, main_name.encode()) + _ld(2, b"p") + _ld(3, dep_name.encode()) +
                _ld(12, b"proto2") +
                _ld(4, _ld(1, b"Main") +
                    _ld(2, _ld(1, b"d") + _vf(3, 1) + _vf(4, 1) + _vf(5, 11) +
                        _ld(6, b".p.Dep"))))
        p = os.path.join(tmpdir, "fake.bin")
        with open(p, "wb") as fh:
            fh.write(b"\xca\xfe" + dep + b"\x00\x00" + main + b"\x00\x00trailing")
        return p

    def test_main_preserves_directory_structure_for_imports(self):
        # Mirrors the real nearbyd bug: a descriptor whose own `name` includes
        # a directory component (e.g. "deprecated/Foo.proto") must land at
        # that same relative path on disk, so the importing file's
        # `import "deprecated/Foo.proto";` line still resolves.
        import tempfile, os
        with tempfile.TemporaryDirectory() as d:
            binp = self._file_with_two_blobs(d, "deprecated/dep.proto", "main.proto")
            outd = os.path.join(d, "out")
            rc = C._main([binp, "-o", outd])
            self.assertEqual(rc, 0)
            self.assertTrue(os.path.isfile(os.path.join(outd, "deprecated", "dep.proto")))
            self.assertTrue(os.path.isfile(os.path.join(outd, "main.proto")))
            main_text = open(os.path.join(outd, "main.proto")).read()
            self.assertIn('import "deprecated/dep.proto";', main_text)

    @unittest.skipUnless(__import__("shutil").which("protoc"), "protoc not on PATH")
    def test_main_output_compiles_with_protoc(self):
        import tempfile, os, subprocess
        with tempfile.TemporaryDirectory() as d:
            binp = self._file_with_two_blobs(d, "deprecated/dep.proto", "main.proto")
            outd = os.path.join(d, "out")
            self.assertEqual(C._main([binp, "-o", outd]), 0)
            r = subprocess.run(
                ["protoc", "--proto_path=.", "--descriptor_set_out=/dev/null",
                 "deprecated/dep.proto", "main.proto"],
                cwd=outd, capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)

    def test_main_stdout(self, capsys=None):
        import tempfile, io, contextlib
        with tempfile.TemporaryDirectory() as d:
            binp = self._file_with_blob(d)
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = C._main([binp])           # no -o -> stdout
            self.assertEqual(rc, 0)
            out = buf.getvalue()
            self.assertIn("// ===== cli.proto =====", out)
            self.assertIn("message M", out)

    def test_main_no_descriptors_returns_1(self):
        import tempfile, os
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "empty.bin")
            with open(p, "wb") as fh:
                fh.write(b"no protobuf descriptors here at all")
            self.assertEqual(C._main([p]), 1)


class TestCppSafeOutputPath(unittest.TestCase):
    """`fp.name` comes from decoding untrusted binary bytes, so a descriptor
    claiming an absolute path or a `..` escape must be rejected rather than
    trusted -- same class of bug as zip-slip."""

    def test_plain_name_lands_under_out_dir(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            p = C._safe_output_path(d, "foo.proto")
            self.assertEqual(p, os.path.realpath(os.path.join(d, "foo.proto")))

    def test_nested_name_preserved(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            p = C._safe_output_path(d, "deprecated/foo.proto")
            self.assertEqual(
                p, os.path.realpath(os.path.join(d, "deprecated", "foo.proto")))

    def test_absolute_name_rejected(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError):
                C._safe_output_path(d, "/etc/passwd.proto")

    def test_dotdot_escape_rejected(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError):
                C._safe_output_path(d, "../../../etc/passwd.proto")

    def test_main_skips_escaping_descriptor_without_writing_outside_out_dir(self):
        # A descriptor whose `name` tries to escape `--out` must be skipped,
        # not silently written outside the requested directory.
        import tempfile
        blob_evil = _ld(1, b"../evil.proto") + _ld(4, _ld(1, b"M") +
            _ld(2, _ld(1, b"x") + _vf(3, 1) + _vf(4, 1) + _vf(5, 5))) + _ld(12, b"proto2")
        blob_ok = _ld(1, b"keep.proto") + _ld(4, _ld(1, b"N") +
            _ld(2, _ld(1, b"y") + _vf(3, 1) + _vf(4, 1) + _vf(5, 5))) + _ld(12, b"proto2")
        with tempfile.TemporaryDirectory() as d:
            binp = os.path.join(d, "fake.bin")
            with open(binp, "wb") as fh:
                fh.write(b"\xca\xfe" + blob_evil + b"\x00\x00" + blob_ok + b"\x00\x00trailing")
            outd = os.path.join(d, "out")
            rc = C._main([binp, "-o", outd])
            self.assertEqual(rc, 0)
            self.assertEqual(os.listdir(outd), ["keep.proto"])
            self.assertFalse(os.path.isfile(os.path.join(d, "evil.proto")))


try:
    from google.protobuf import descriptor_pb2 as _DP
    _HAVE_DP = True
except Exception:
    _HAVE_DP = False


@unittest.skipUnless(_HAVE_DP, "protobuf package not available")
class TestCppRoundTripVsDescriptorPb2(unittest.TestCase):
    def test_roundtrip(self):
        fdp = _DP.FileDescriptorProto()
        fdp.name = "round.proto"; fdp.package = "rt"; fdp.syntax = "proto3"
        m = fdp.message_type.add(); m.name = "Msg"
        f1 = m.field.add(); f1.name = "a"; f1.number = 1
        f1.label = _DP.FieldDescriptorProto.LABEL_OPTIONAL
        f1.type = _DP.FieldDescriptorProto.TYPE_SINT64
        f2 = m.field.add(); f2.name = "bs"; f2.number = 7
        f2.label = _DP.FieldDescriptorProto.LABEL_REPEATED
        f2.type = _DP.FieldDescriptorProto.TYPE_STRING
        mine = C.decode_file_descriptor(fdp.SerializeToString())
        self.assertEqual(mine.syntax, "proto3")
        got = {f.name: (f.number, f.type, f.label) for f in mine.messages[0].fields}
        self.assertEqual(got, {"a": (1, 18, 1), "bs": (7, 9, 3)})


def _locationd_bytes():
    path = os.environ.get("MACHO_TEST_LOCATIOND", "").strip()
    if not path:
        try:
            import artifacts
            path = os.path.join(artifacts.data_dir(), "locationd")
        except Exception:
            return None
    if not os.path.isfile(path):
        return None
    with open(path, "rb") as fh:
        return fh.read()


@unittest.skipUnless(_locationd_bytes() is not None, "locationd binary not available")
class TestCppLiveLocationd(unittest.TestCase):
    def test_recovers_embedded_descriptors(self):
        data = _locationd_bytes()
        protos = C.extract_cpp_protos(data)
        self.assertGreater(len(protos), 0)
        self.assertTrue(all(fp.name.endswith(".proto") for fp in protos))
        # every recovered message/enum has a name and fields/values are well-formed
        for fp in protos:
            for m in fp.messages:
                self.assertTrue(m.name)
                for f in m.fields:
                    self.assertGreater(f.number, 0)

    @unittest.skipUnless(_HAVE_DP, "protobuf package not available")
    def test_exact_match_vs_descriptor_pb2(self):
        data = _locationd_bytes()
        blobs = C.find_descriptor_blobs(data)
        self.assertGreater(len(blobs), 0)
        total = match = 0

        def gt(msg, pfx=""):
            d = {f"{pfx}{msg.name}.{f.name}": (f.number, f.type, f.label, f.type_name)
                 for f in msg.field}
            for n in msg.nested_type:
                d.update(gt(n, pfx + msg.name + "."))
            return d

        def mine(m, pfx=""):
            d = {f"{pfx}{m.name}.{f.name}": (f.number, f.type, f.label, f.type_name)
                 for f in m.fields}
            for n in m.nested:
                d.update(mine(n, pfx + m.name + "."))
            return d

        for _, blob in blobs:
            g = _DP.FileDescriptorProto(); g.ParseFromString(blob)
            k = C.decode_file_descriptor(blob)
            gd = {}; kd = {}
            for x in g.message_type:
                gd.update(gt(x))
            for x in k.messages:
                kd.update(mine(x))
            for key, gv in gd.items():
                total += 1
                if kd.get(key) == gv:
                    match += 1
        self.assertEqual(match, total, f"{total - match}/{total} field mismatches")


class _FakeSec:
    def __init__(self, va, size):
        self.vmaddr, self.vmsize = va, size


class _FakeSectionCtx:
    """Minimal ctx exposing named sections of bytes at chosen vmaddrs, enough for
    :func:`extract_cpp_protos_from_ctx` (has_section / section / read_bytes)."""
    def __init__(self, sections):           # {(seg, sec): (vmaddr, bytes)}
        self._s = sections

    def has_section(self, seg, sec):
        return (seg, sec) in self._s

    def section(self, seg, sec):
        va, b = self._s[(seg, sec)]
        return _FakeSec(va, len(b))

    def sections_named(self, *names):
        return [SimpleNamespace(segname=seg, name=sec, vmaddr=va, vmsize=len(b))
                for (seg, sec), (va, b) in self._s.items() if sec in names]

    def is_variable(self, vmaddr):        # no program data, no binds
        return False

    def read_bytes(self, va, n):
        for _va, b in self._s.values():
            if _va <= va and va + n <= _va + len(b):
                return b[va - _va: va - _va + n]
        raise ValueError("oob")


class TestCppFromCtx(unittest.TestCase):
    """Cache-native section scan recovers the same blobs as a whole-image sweep."""
    def _file_blob(self, name):
        # FileDescriptorProto: name(1), package(2), message_type(4){ name, field x }
        fx = _ld(1, b"x") + _vf(3, 1) + _vf(4, 1) + _vf(5, 5)        # int32 x = 1
        msg = _ld(1, b"M") + _ld(2, fx)
        return _ld(1, name.encode()) + _ld(2, b"p") + _ld(4, msg)

    def test_scans_text_const(self):
        blob = self._file_blob("alpha.proto")
        # bury the blob inside a __TEXT,__const section at a non-zero vmaddr
        data = b"\x00" * 16 + blob + b"\xff" * 8
        ctx = _FakeSectionCtx({("__TEXT", "__const"): (0x4000, data)})
        protos = C.extract_cpp_protos_from_ctx(ctx)
        self.assertEqual([fp.name for fp in protos], ["alpha.proto"])
        m = protos[0].messages[0]
        self.assertEqual((m.name, m.fields[0].name, m.fields[0].number), ("M", "x", 1))

    def test_dedup_across_sections(self):
        blob = self._file_blob("dup.proto")
        ctx = _FakeSectionCtx({
            ("__TEXT", "__const"): (0x4000, blob),
            ("__TEXT", "__cstring"): (0x9000, blob),     # same blob, other section
        })
        protos = C.extract_cpp_protos_from_ctx(ctx)
        self.assertEqual([fp.name for fp in protos], ["dup.proto"])   # de-duped

    def test_a_const_section_of_any_segment_is_scanned(self):
        blob = self._file_blob("auth.proto")
        ctx = _FakeSectionCtx({("__AUTH_CONST", "__const"): (0x4000, blob)})
        self.assertEqual([fp.name for fp in C.extract_cpp_protos_from_ctx(ctx)], ["auth.proto"])

    def test_no_sections_returns_empty(self):
        self.assertEqual(C.extract_cpp_protos_from_ctx(_FakeSectionCtx({})), [])


def _cache_main():
    try:
        import artifacts
        p = artifacts.cache_file()
        return p if p and os.path.isfile(p) else None
    except Exception:
        return None


def _geoservices_image():
    try:
        import artifacts
        p = artifacts.geoservices_path()
        return p if p and os.path.isfile(p) else None
    except Exception:
        return None


@unittest.skipUnless(_cache_main() and _geoservices_image(),
                     "cache + a GeoServices image needed for the equivalence test")
class TestCppCacheEqualsBinary(unittest.TestCase):
    """The strongest cache-mode proof: C++ recovery from the cache-native
    GeoServices image must be byte-for-byte identical to a whole-file sweep of
    a second, independently-loaded copy of the same image (same
    FileDescriptorProto decode, two loaders). This is unaffected by GeoServices
    having no genuinely standalone build (see artifacts.geoservices_path()) —
    C++ descriptor recovery reads embedded FileDescriptorProto bytes directly
    and needs no ObjC selector-name resolution."""
    @staticmethod
    def _sig(file_protos):
        out = []
        for fp in file_protos:
            for m in fp.messages:
                for f in m.fields:
                    out.append((fp.name, fp.package, m.name, f.name,
                                f.number, f.type, f.type_name, f.label))
        return sorted(out)

    def test_field_tuples_identical(self):
        from macho.dyld_cache import DyldCacheReader
        from macho.memory import BinaryContext
        from serializers.swift_descriptor_extract import load_macho_slice
        reader = DyldCacheReader(_cache_main())
        try:
            mach_va = reader.find_image_header("GeoServices")
            if mach_va is None:
                self.skipTest("GeoServices not in this cache")
            ctx = BinaryContext.from_cache(reader, mach_va)
            cache_sig = self._sig(C.extract_cpp_protos_from_ctx(ctx))
        finally:
            reader.close()
        with open(_geoservices_image(), "rb") as fh:
            data = load_macho_slice(fh.read())
        bin_sig = self._sig(C.extract_cpp_protos(data))
        self.assertTrue(cache_sig, "expected C++ protos in cache GeoServices")
        self.assertEqual(cache_sig, bin_sig)


@unittest.skipUnless(_HAVE_DP and _cache_main(),
                     "protobuf package + cache needed for the descriptor_pb2 cross-check")
class TestCppCacheVsDescriptorPb2(unittest.TestCase):
    """Hand-verification baseline (SWIFT_PROTO_HAND_VERIFICATION.md, Part 2): the
    cache-native C++ decode must match Google's canonical ``descriptor_pb2`` parse
    of the SAME blob bytes, field-for-field, across several cache frameworks."""
    @staticmethod
    def _ref_fields(msg, pfx=""):
        d = {f"{pfx}{msg.name}.{f.name}":
             (f.number, int(f.type), int(f.label), f.type_name) for f in msg.field}
        for n in msg.nested_type:
            d.update(TestCppCacheVsDescriptorPb2._ref_fields(n, pfx + msg.name + "."))
        return d

    @staticmethod
    def _our_fields(m, pfx=""):
        d = {f"{pfx}{m.name}.{f.name}":
             (f.number, int(f.type), int(f.label), f.type_name) for f in m.fields}
        for n in m.nested:
            d.update(TestCppCacheVsDescriptorPb2._our_fields(n, pfx + m.name + "."))
        return d

    def test_cache_decode_matches_descriptor_pb2(self):
        from macho.dyld_cache import DyldCacheReader
        from macho.memory import BinaryContext
        reader = DyldCacheReader(_cache_main())
        checked = 0
        try:
            for fw in ("GeoServices", "DialogEngine", "CoreNavigation", "CoreIndoor"):
                va = reader.find_image_header(fw)
                if va is None:
                    continue
                ctx = BinaryContext.from_cache(reader, va)
                # collect the raw blobs (to feed descriptor_pb2 the SAME bytes)
                blobs = []
                for s in ctx.sections_named(*C._DESC_SECTIONS):
                    try:
                        data = ctx.read_bytes(s.vmaddr, s.vmsize)
                    except Exception:
                        continue
                    blobs += [b for _o, b in C.find_descriptor_blobs(data)]
                for blob in blobs:
                    ours = C.decode_file_descriptor(blob)
                    g = _DP.FileDescriptorProto()
                    g.ParseFromString(blob)
                    ref = {}
                    for x in g.message_type:
                        ref.update(self._ref_fields(x))
                    mine = {}
                    for m in ours.messages:
                        mine.update(self._our_fields(m))
                    self.assertEqual(mine, ref, f"{fw} {ours.name}")
                    checked += len(ref)
        finally:
            reader.close()
        self.assertGreater(checked, 500)        # sanity: real coverage happened


class TestMalformedDescriptor(unittest.TestCase):
    """Robustness: the descriptor decoder reads length-delimited, binary-controlled
    bytes, so malformed/truncated/garbage input must fail CLEANLY — a `ValueError`
    or a benign empty result — never an uncaught IndexError/other crash that would
    take down the whole extraction.  (extract_cpp_protos* already skip blobs that
    raise; these pin the low-level guards those rely on.)"""

    def test_truncated_varint_raises_valueerror(self):
        with self.assertRaises(ValueError):
            C._Reader(b"\xff\xff\xff").varint()      # continuation bits, never ends

    def test_field_zero_raises_valueerror(self):
        # A bare `assertRaises(ValueError)` can't tell this apart from a
        # DIFFERENT ValueError: if the field==0 guard were removed, this exact
        # 1-byte buffer falls through to a second (now-exhausted) varint()
        # call, which raises its own "truncated varint" ValueError -- a
        # coincidental downstream error, not the deleted guard's own message.
        # Assert on the specific message so only the real guard satisfies this.
        with self.assertRaises(ValueError) as cm:
            C._Reader(b"\x00").field()               # tag 0 → field number 0
        self.assertEqual(str(cm.exception), "field 0")

    def test_lendelim_past_end_raises_valueerror(self):
        with self.assertRaises(ValueError):
            C._Reader(b"\x0a\x63").field()           # field1 wt2, len=99, no payload

    def test_bad_wire_type_raises_valueerror(self):
        with self.assertRaises(ValueError):
            C._Reader(b"\x0b").field()               # field1 wt3 (group) — unsupported

    def test_decode_truncated_descriptor_raises_valueerror(self):
        with self.assertRaises(ValueError):
            C.decode_file_descriptor(b"\xff\xff\xff\xff")

    def test_decode_empty_is_clean_empty_fileproto(self):
        fp = C.decode_file_descriptor(b"")
        self.assertEqual(fp.messages, [])
        self.assertEqual(fp.enums, [])

    def test_decode_garbage_never_crashes_uncaught(self):
        # Hostile inputs must each either decode to a FileProto or raise
        # ValueError — never any other exception type.
        garbage = [
            b"\x08\x96\x01",                         # a stray varint field
            bytes(range(256)),                       # all byte values
            b"\x0a\x05hi",                           # len=5 but only 2 bytes follow
            b"\x22" + b"\xff" * 40,                  # nested message, junk payload
            b"\x2a\x03\x08\x00\x10",                 # enum field w/ field-0 inside
        ]
        for g in garbage:
            try:
                C.decode_file_descriptor(g)
            except ValueError:
                pass                                 # acceptable: clean rejection
            except Exception as exc:                 # noqa: BLE001 — that's the point
                self.fail(f"decode_file_descriptor({g!r}) raised "
                          f"{type(exc).__name__}: {exc}")


if __name__ == "__main__":
    unittest.main()
