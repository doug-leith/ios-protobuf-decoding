"""serializers/protobufc_detect.py — detect-only recognition of the protobuf-c runtime.

Offline tests build a tiny Mach-O whose data section holds hand-made
``ProtobufCMessageDescriptor`` / ``ProtobufCEnumDescriptor`` structs (plus decoys) and
check the magic scan, the name read and the validation.  Live tests run the detector
on Apple's MMCS framework (iOS 16.7.11), which statically links protobuf-c, in both
binary and cache-native mode, and on images that must report nothing.
"""
import logging
import os
import struct
import unittest

from macho.memory import BinaryContext
from proto import foreign as F
from serializers import protobufc_detect as P
from tests.conftest import build_binary

_TEXT_VA, _DATA_VA = 0x10000, 0x20000
MSG, ENUM = P.MESSAGE_MAGIC, P.ENUM_MAGIC


def _desc(magic, name_va, n, ptr_va, n_off, ptr_off, size=72):
    b = bytearray(size)
    struct.pack_into("<I", b, 0, magic)
    struct.pack_into("<Q", b, 8, name_va)
    struct.pack_into("<I", b, n_off, n)
    struct.pack_into("<Q", b, ptr_off, ptr_va)
    return bytes(b)


def _msg(name_va, n=2, ptr_va=0x30000):
    return _desc(MSG, name_va, n, ptr_va, 48, 56)


def _enum(name_va, n=3, ptr_va=0x30000):
    return _desc(ENUM, name_va, n, ptr_va, 40, 48)


def _ctx(data_sections, strings, data_segname="__DATA", extra_text=b""):
    """Binary with a __TEXT/__cstring of *strings* and *data_sections* in one segment.
    Returns (ctx, {string: vmaddr})."""
    blob, addr, off = b"", {}, 0
    for s in strings:
        addr[s] = _TEXT_VA + off
        blob += s.encode() + b"\0"
        off = len(blob)
    segs = [{"name": "__TEXT", "vmaddr": _TEXT_VA,
             "sections": [{"name": "__cstring", "content": blob + extra_text}]},
            {"name": data_segname, "vmaddr": _DATA_VA,
             "sections": [{"name": n, "content": c} for n, c in data_sections]}]
    return BinaryContext(build_binary(segs)), addr


class TestMagicScan(unittest.TestCase):
    def test_messages_and_enums_found_in_address_order(self):
        names = ["pkg.Alpha", "pkg.Beta", "pkg.Alpha.Kind"]
        ctx, a = _ctx([("__const", b"")], names)          # placeholder to learn addrs
        data = _msg(a["pkg.Alpha"]) + _enum(a["pkg.Alpha.Kind"]) + _msg(a["pkg.Beta"])
        ctx, a = _ctx([("__const", data)], names)
        r = P.find_protobufc_descriptors(ctx)
        self.assertEqual(r.messages, ["pkg.Alpha", "pkg.Beta"])
        self.assertEqual(r.enums, ["pkg.Alpha.Kind"])
        self.assertEqual(r.rejected, 0)
        self.assertTrue(r)

    def test_scans_every_data_segment_and_section(self):
        names = ["a.M", "b.N"]
        _, a = _ctx([("__const", b"")], names)
        ctx, _ = _ctx([("__const", _msg(a["a.M"])), ("__data", _msg(a["b.N"]))],
                      names, data_segname="__DATA_CONST")
        self.assertEqual(P.find_protobufc_descriptors(ctx).messages, ["a.M", "b.N"])

    def test_arm64e_auth_segments_scanned(self):
        # iOS 27 / arm64e: message descriptors hold a signed function pointer, so the
        # linker puts them in __AUTH_CONST (enum descriptors stay in __DATA_CONST).
        _, a = _ctx([("__const", b"")], ["a.M"])
        for seg in ("__AUTH_CONST", "__AUTH"):
            ctx, _ = _ctx([("__const", _msg(a["a.M"]))], ["a.M"], data_segname=seg)
            self.assertEqual(P.find_protobufc_descriptors(ctx).messages, ["a.M"], seg)

    def test_name_pointer_must_resolve_to_a_type_name(self):
        names = ["pkg.Good", "not a name!", ""]
        _, a = _ctx([("__const", b"")], names)
        data = (_msg(a["pkg.Good"]) +
                _msg(a["not a name!"]) +           # name not an identifier
                _msg(a[""]) +                       # empty name
                _msg(0x7777000000))                 # dangling pointer
        ctx, _ = _ctx([("__const", data)], names)
        r = P.find_protobufc_descriptors(ctx)
        self.assertEqual(r.messages, ["pkg.Good"])
        self.assertEqual(r.rejected, 3)

    def test_implausible_entry_count_rejected(self):
        names = ["pkg.Huge", "pkg.Null"]
        _, a = _ctx([("__const", b"")], names)
        data = (_msg(a["pkg.Huge"], n=1 << 20) +            # n_fields absurd
                _msg(a["pkg.Null"], n=4, ptr_va=0) +        # fields pointer null
                _enum(a["pkg.Huge"], n=1 << 20))
        ctx, _ = _ctx([("__const", data)], names)
        r = P.find_protobufc_descriptors(ctx)
        self.assertFalse(r.messages or r.enums)
        self.assertEqual(r.rejected, 3)

    def test_empty_message_is_valid(self):
        # a message with no fields has n_fields == 0 and a null fields pointer
        _, a = _ctx([("__const", b"")], ["pkg.Empty"])
        ctx, _ = _ctx([("__const", _msg(a["pkg.Empty"], n=0, ptr_va=0))], ["pkg.Empty"])
        self.assertEqual(P.find_protobufc_descriptors(ctx).messages, ["pkg.Empty"])

    def test_unaligned_magic_ignored(self):
        _, a = _ctx([("__const", b"")], ["pkg.M"])
        data = b"\x00\x00\x00\x00" + _msg(a["pkg.M"])        # struct at +4: not 8-aligned
        ctx, _ = _ctx([("__const", data)], ["pkg.M"])
        self.assertFalse(P.find_protobufc_descriptors(ctx))

    def test_magic_outside_data_segments_ignored(self):
        # a magic word in __TEXT (e.g. an immediate / string pool) is not a descriptor
        _, a = _ctx([("__const", b"")], ["pkg.M"])
        ctx, _ = _ctx([("__const", b"\0" * 16)], ["pkg.M"],
                      extra_text=b"\0" * 7 + _msg(a["pkg.M"]))
        self.assertFalse(P.find_protobufc_descriptors(ctx))

    def test_nothing_found_is_falsy(self):
        ctx, _ = _ctx([("__const", b"\0" * 64)], ["x"])
        r = P.find_protobufc_descriptors(ctx)
        self.assertFalse(r)
        self.assertEqual((r.messages, r.enums, r.symbols, r.rejected), ([], [], [], 0))


class TestSymbols(unittest.TestCase):
    class _Ctx:
        is_cache_backed = False
        def iter_symbol_names(self):
            return iter(["_protobuf_c_message_init", "_protobuf_c__allocator",
                         "_protobuf_c_message_init", "_protobuf_cxx_thing",
                         "__ZN6google8protobuf3FooE", "_malloc"])

    def test_binary_mode_symbols(self):
        self.assertEqual(P.protobufc_symbols(self._Ctx()),
                         ["_protobuf_c__allocator", "_protobuf_c_message_init"])

    def test_symbols_only_image_is_detected(self):
        class C(self._Ctx):
            segments = []
        r = P.find_protobufc_descriptors(C())
        self.assertTrue(r)
        self.assertEqual(r.messages, [])


class TestSummaryAndWarning(unittest.TestCase):
    def _synthetic(self):
        names = ["pkg.A", "pkg.B", "pkg.B.E"]
        _, a = _ctx([("__const", b"")], names)
        data = _msg(a["pkg.A"]) + _msg(a["pkg.B"]) + _enum(a["pkg.B.E"])
        return _ctx([("__const", data)], names)[0]

    def test_summarize_reports_detect_only(self):
        summ = {s.label: s for s in F.summarize_serializers(self._synthetic(), [], None)}
        s = summ[F.PROTOBUFC_SERIALIZER]
        self.assertFalse(s.decodable)
        self.assertEqual(s.names, ["pkg.A", "pkg.B"])
        self.assertIn("2 message + 1 enum", s.note)
        self.assertNotIn(F.CPP_SERIALIZER, summ)
        self.assertNotIn(F.CPP_LITE_SERIALIZER, summ)

    def test_summarize_silent_when_absent(self):
        ctx, _ = _ctx([("__const", b"\0" * 64)], ["x"])
        labels = [s.label for s in F.summarize_serializers(ctx, [], None)]
        self.assertNotIn(F.PROTOBUFC_SERIALIZER, labels)

    def test_foreign_warning_lists_protobufc_as_not_decodable(self):
        from proto.foreign_detect import _warn_if_foreign_protobuf
        with self.assertLogs("proto.foreign_detect", level="WARNING") as cm:
            _warn_if_foreign_protobuf(self._synthetic(), [])
        self.assertEqual(len(cm.records), 1)                # ONE consolidated warning
        text = cm.records[0].getMessage()
        self.assertIn("NOT decodable", text)
        self.assertIn("protobuf-c", text)
        self.assertIn("2 message + 1 enum", text)
        self.assertNotIn("DECODED", text.replace("NOT decodable", ""))

    def test_foreign_warning_silent_without_protobufc(self):
        from proto.foreign_detect import _warn_if_foreign_protobuf
        ctx, _ = _ctx([("__const", b"\0" * 64)], ["x"])
        logger = logging.getLogger("proto.foreign_detect")
        with self.assertLogs(logger, level="WARNING") as cm:
            logger.warning("sentinel")                      # assertLogs needs ≥1 record
            _warn_if_foreign_protobuf(ctx, [])
        self.assertEqual([r.getMessage() for r in cm.records], ["sentinel"])


# ── live: Apple MMCS framework ────────────────────────────────────────────────
# MMCS statically links protobuf-c.  The expected set is what the hand-written
# rustpush_reference_protos/mmcs_protobufc_extract.py decodes from the three MMCS data
# ranges: 48 messages + 1 enum across packages chunkserver / metricsinfo / opaque.
MMCS_MESSAGES = 48
MMCS_ENUMS = 1
MMCS_PACKAGES = {"chunkserver", "metricsinfo", "opaque"}


def _mmcs_binary():
    try:
        import artifacts
        p = os.path.join(artifacts.data_dir(), "dylib", "System", "Library",
                         "PrivateFrameworks", "MMCS.framework", "MMCS")
        return p if os.path.isfile(p) else None
    except Exception:
        return None


def _cache_main():
    try:
        import artifacts
        p = artifacts.cache_file()
        return p if p and os.path.isfile(p) else None
    except Exception:
        return None


class _MMCSChecks:
    def _check(self, r):
        self.assertEqual(len(r.messages), MMCS_MESSAGES)
        self.assertEqual(len(r.enums), MMCS_ENUMS)
        self.assertEqual(r.rejected, 0)
        self.assertEqual({n.split(".")[0] for n in r.messages + r.enums}, MMCS_PACKAGES)
        for n in ("chunkserver.ChunkInfo", "chunkserver.GetChunkKeysRequest",
                  "metricsinfo.SocketInfo", "opaque.FileReferenceData.V3"):
            self.assertIn(n, r.messages)
        self.assertEqual(len(set(r.messages)), MMCS_MESSAGES)
        self.assertIn("_protobuf_c_message_unpack", r.symbols)
        self.assertIn("_protobuf_c_message_pack", r.symbols)


@unittest.skipUnless(_mmcs_binary(), "extracted MMCS binary not available")
class TestMMCSBinaryMode(_MMCSChecks, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from serializers import swift_descriptor_extract as SW
        data = SW.load_macho_slice(open(_mmcs_binary(), "rb").read())
        cls.ctx = BinaryContext(data)

    def test_descriptors(self):
        self._check(P.find_protobufc_descriptors(self.ctx))


@unittest.skipUnless(_cache_main(), "dyld shared cache not available")
class TestMMCSCacheNative(_MMCSChecks, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from macho.dyld_cache import DyldCacheReader
        cls.reader = DyldCacheReader(_cache_main())

    @classmethod
    def tearDownClass(cls):
        cls.reader.close()

    def _ctx_cl(self, name):
        from macho.strings import build_string_table
        from macho.classlist import build_class_list
        va = self.reader.find_image_header(name)
        if va is None:
            self.skipTest(f"{name} not in this cache")
        ctx = BinaryContext.from_cache(self.reader, va)
        return ctx, build_class_list(ctx, build_string_table(ctx))

    def test_descriptors(self):
        ctx, _ = self._ctx_cl("MMCS")
        self._check(P.find_protobufc_descriptors(ctx))

    def test_summarize(self):
        ctx, cl = self._ctx_cl("MMCS")
        summ = {s.label: s for s in F.summarize_serializers(ctx, cl, None)}
        s = summ[F.PROTOBUFC_SERIALIZER]
        self.assertFalse(s.decodable)
        self.assertEqual(len(s.names), MMCS_MESSAGES)

    def test_warning(self):
        from proto.foreign_detect import _warn_if_foreign_protobuf
        ctx, cl = self._ctx_cl("MMCS")
        with self.assertLogs("proto.foreign_detect", level="WARNING") as cm:
            _warn_if_foreign_protobuf(ctx, cl)
        self.assertIn("protobuf-c", cm.records[0].getMessage())

    def test_no_false_positives(self):
        # unrelated images: C++ (GeoServices), swift-protobuf (CopresenceCore),
        # CloudKit, and a PBCodable-only daemon dependency — all must report nothing.
        for name in ("GeoServices", "CopresenceCore", "CloudKit", "CoreLocation"):
            if self.reader.find_image_header(name) is None:
                continue
            ctx, _ = self._ctx_cl(name)
            r = P.find_protobufc_descriptors(ctx)
            self.assertFalse(r, f"{name}: spurious protobuf-c hit {r}")
            self.assertEqual(r.rejected, 0, name)


def _ios27_cache():
    d = os.environ.get("MACHO_TEST_IOS27_CACHE", "").strip()
    try:
        import artifacts
        d = d or os.path.join(artifacts.REPO_ROOT, "ios27_data", "dylib")
    except Exception:
        return None
    p = os.path.join(d, "dyld_shared_cache_arm64e")
    return p if os.path.isfile(p) else None


@unittest.skipUnless(_ios27_cache(), "iOS 27 cache not present")
class TestIos27(unittest.TestCase):
    """arm64e: message descriptors hold a signed function pointer, so they are in
    ``__AUTH_CONST`` (only the enum descriptors are in ``__DATA_CONST``)."""
    @classmethod
    def setUpClass(cls):
        from macho.dyld_cache import DyldCacheReader
        cls.reader = DyldCacheReader(_ios27_cache())

    @classmethod
    def tearDownClass(cls):
        cls.reader.close()

    def _scan(self, name):
        va = self.reader.find_image_header(name)
        if va is None:
            self.skipTest(f"{name} not in this cache")
        return P.find_protobufc_descriptors(BinaryContext.from_cache(self.reader, va))

    def test_mmcs_messages_in_auth_const(self):
        r = self._scan("MMCS")
        self.assertGreaterEqual(len(r.messages), MMCS_MESSAGES)   # iOS 27 adds a few
        self.assertEqual(len(r.enums), MMCS_ENUMS)
        self.assertEqual(r.rejected, 0)
        self.assertTrue(MMCS_PACKAGES <= {n.split(".")[0] for n in r.messages})
        self.assertIn("chunkserver.ChunkInfo", r.messages)

    def test_unrelated_images_report_nothing(self):
        for name in ("GeoServices", "CloudKit"):
            self.assertFalse(self._scan(name), name)


@unittest.skipUnless(_mmcs_binary(), "extracted binaries not available")
class TestNoFalsePositivesBinaryMode(unittest.TestCase):
    def test_locationd_and_geoservices_report_nothing(self):
        import artifacts
        from serializers import swift_descriptor_extract as SW
        d = artifacts.data_dir()
        found = 0
        for rel in ("locationd", "geod", os.path.join("libexec", "routined")):
            p = os.path.join(d, rel)
            if not os.path.isfile(p):
                continue
            ctx = BinaryContext(SW.load_macho_slice(open(p, "rb").read()))
            self.assertFalse(P.find_protobufc_descriptors(ctx), rel)
            found += 1
        self.assertGreater(found, 0)


if __name__ == "__main__":
    unittest.main()
