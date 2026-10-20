"""Detection of Google protobuf-objc (GPBMessage) classes so the tool can tell the
user those messages are out of scope (it decodes Apple PBCodable only).

Offline: a synthetic ClassList exercises the name-suffix anchor (GPBMessage or a
per-binary-prefixed variant like FooGPBMessage), including the negative (PBCodable /
plain classes are not flagged).

Live: transparencyd (Key Transparency) has GPBMessage subclasses and extract_all emits
the informative warning; GeoServices (PBCodable) has none (no false positive).
"""
import logging
import unittest

from macho.classlist import ObjcClass, ClassList
import proto.extractor as E
import proto.foreign_detect as FD
import proto.protoclass_set as PS


def _cls(va, name, super_va):
    return ObjcClass(vmaddr=va, name=name, is_meta=False, superclass_vmaddr=super_va,
                     superclass_name=None, ro_flags=0, instance_size=0,
                     methods=[], ivars=[])


class _NoReadCtx:
    """External supers don't resolve (so a plain NSObject super yields no name)."""
    def read_ptr(self, va): raise ValueError("unmapped")
    def read_cstring(self, va): raise ValueError("unmapped")
    def import_name_for_bind(self, raw): return None


class TestGoogleProtobufDetectOffline(unittest.TestCase):
    def test_prefixed_gpbmessage_subclasses_detected(self):
        NSOBJECT = 0x9000
        base = _cls(0x1000, "FooGPBMessage", NSOBJECT)   # the prefixed Google runtime base
        req  = _cls(0x2000, "FooRequest", 0x1000)
        resp = _cls(0x3000, "FooResponse", 0x1000)
        plain = _cls(0x4000, "Bar", NSOBJECT)            # unrelated NSObject subclass
        cl = ClassList([base, req, resp, plain])
        subs, bases = FD.google_protobuf_classes(_NoReadCtx(), cl)
        self.assertEqual(set(subs), {"FooRequest", "FooResponse"})
        self.assertEqual(set(bases), {"FooGPBMessage"})
        self.assertNotIn("Bar", subs)
        self.assertNotIn("FooGPBMessage", subs)   # the base itself is not a message

    def test_plain_gpbmessage_name_also_anchors(self):
        NSOBJECT = 0x9000
        base = _cls(0x1000, "GPBMessage", NSOBJECT)      # unprefixed runtime base
        msg  = _cls(0x2000, "MyMessage", 0x1000)
        cl = ClassList([base, msg])
        subs, bases = FD.google_protobuf_classes(_NoReadCtx(), cl)
        self.assertEqual(set(subs), {"MyMessage"})
        self.assertEqual(set(bases), {"GPBMessage"})

    def test_no_gpb_classes_returns_empty(self):
        NSOBJECT = 0x9000
        a = _cls(0x1000, "AThing", NSOBJECT)
        b = _cls(0x2000, "BThing", 0x1000)
        subs, bases = FD.google_protobuf_classes(_NoReadCtx(), ClassList([a, b]))
        self.assertEqual(subs, [])
        self.assertEqual(set(bases), set())


try:
    import live_artifacts as _VL
    _HAVE_TD = _VL.load_binary("MACHO_TEST_TRANSPARENCYD", "libexec/transparencyd") is not None
except Exception:
    _HAVE_TD = False


@unittest.skipUnless(_HAVE_TD, "transparencyd binary not available")
class TestGoogleProtobufDetectLive(unittest.TestCase):
    def test_transparencyd_gpb_detected_and_warned(self):
        import live_artifacts as V
        ctx, st, cl = V.load_binary("MACHO_TEST_TRANSPARENCYD", "libexec/transparencyd")
        subs, bases = FD.google_protobuf_classes(ctx, cl)
        self.assertGreater(len(subs), 10)
        self.assertTrue(all(b.endswith("GPBMessage") for b in bases), bases)
        self.assertEqual(len(PS._proto_class_set(ctx, cl)), 0)  # no PBCodable
        with self.assertLogs("proto.foreign_detect", level="WARNING") as cm:
            list(E.extract_all(ctx, st, cl))
        self.assertTrue(any("Google protobuf-objc" in m for m in cm.output))


try:
    _HAVE_GEO = _VL.load_cache("GeoServices") is not None
except Exception:
    _HAVE_GEO = False


@unittest.skipUnless(_HAVE_GEO, "GeoServices cache not available")
class TestGoogleProtobufNoFalsePositive(unittest.TestCase):
    def test_pbcodable_framework_has_no_gpb(self):
        import live_artifacts as V
        ctx, st, cl = V.load_cache("GeoServices")
        subs, _ = FD.google_protobuf_classes(ctx, cl)
        self.assertEqual(subs, [])


# ── Swift-protobuf + C++ libprotobuf detection ───────────────────────────────

class _SymCtx:
    """Minimal ctx for the symbol-based Swift/C++ detectors: symbol names and no
    sections (so no embedded C++ descriptors)."""
    def __init__(self, names):
        self._names = list(names)
    def iter_symbol_names(self):
        return iter(self._names)
    def has_section(self, seg, sect):
        return False


# Real conformance-descriptor symbols (from bookdatastored / synthesised siblings).
_SWIFT_MSG = "_$s14bookdatastored15PBPropertyValueV21InternalSwiftProtobuf7MessageAAMc"
_SWIFT_ENUM = "_$s14bookdatastored25MarkedAsFinishedMechanismO21InternalSwiftProtobuf4EnumAAMc"
_SWIFT_PUBLIC = "_$s6MyTool9MyMessageV13SwiftProtobuf7MessageAAMc"   # public framework, top-level
_SWIFT_NESTED = "_$s6MyTool5OuterV5InnerV13SwiftProtobuf7MessageAAMc"


class TestSwiftProtobufParse(unittest.TestCase):
    def test_parse_message_descriptor(self):
        self.assertEqual(FD._parse_swift_pb_symbol(_SWIFT_MSG),
                         ("message", "bookdatastored", "PBPropertyValue"))

    def test_parse_enum_descriptor(self):
        self.assertEqual(FD._parse_swift_pb_symbol(_SWIFT_ENUM),
                         ("enum", "bookdatastored", "MarkedAsFinishedMechanism"))

    def test_parse_public_framework_descriptor(self):
        self.assertEqual(FD._parse_swift_pb_symbol(_SWIFT_PUBLIC),
                         ("message", "MyTool", "MyMessage"))

    def test_parse_nested_type(self):
        self.assertEqual(FD._parse_swift_pb_symbol(_SWIFT_NESTED),
                         ("message", "MyTool", "Outer.Inner"))

    def test_degenerate_mangling_returns_none(self):
        # matches the protocol regex but has no module+type prefix -> < 2 idents
        self.assertIsNone(FD._parse_swift_pb_symbol("SwiftProtobuf7MessageAAMc"))
        # protocol present but only a single identifier before it
        self.assertIsNone(FD._parse_swift_pb_symbol("_$s3FooSwiftProtobuf7MessageAAMc"))

    def test_non_conformance_returns_none(self):
        self.assertIsNone(FD._parse_swift_pb_symbol("_OBJC_CLASS_$_NSString"))
        # _MessageImplementationBase / _ProtoNameProviding must NOT be counted as
        # the Message protocol (only the bare `7Message` descriptor is).
        impl = "_$s14bookdatastored15PBPropertyValueV21InternalSwiftProtobuf26_MessageImplementationBaseAAMc"
        self.assertIsNone(FD._parse_swift_pb_symbol(impl))


class TestSwiftProtobufDetect(unittest.TestCase):
    def test_collects_messages_and_enums(self):
        ctx = _SymCtx([_SWIFT_MSG, _SWIFT_ENUM, _SWIFT_PUBLIC, "_OBJC_CLASS_$_X",
                       # the impl/nameproviding siblings must not double-count
                       "_$s14bookdatastored15PBPropertyValueV21InternalSwiftProtobuf26_MessageImplementationBaseAAMc"])
        msgs, enums, mods = FD.swift_protobuf_messages(ctx)
        self.assertEqual(msgs, ["MyMessage", "PBPropertyValue"])
        self.assertEqual(enums, ["MarkedAsFinishedMechanism"])
        self.assertEqual(set(mods), {"bookdatastored", "MyTool"})

    def test_no_swift_returns_empty(self):
        msgs, enums, mods = FD.swift_protobuf_messages(_SymCtx(["_OBJC_CLASS_$_X"]))
        self.assertEqual((msgs, enums, list(mods)), ([], [], []))


class TestCppProtobufDetect(unittest.TestCase):
    def test_top_level_google_protobuf(self):
        ctx = _SymCtx([
            "__ZN6google8protobuf11MessageLite14ParseFromArrayEPKvi",
            "__ZNK6google8protobuf7Message11GetTypeNameEv",
            "_OBJC_CLASS_$_X",
        ])
        self.assertEqual(FD.cpp_protobuf_namespaces(ctx), {"google::protobuf": 2})
        self.assertEqual(FD.cpp_protobuf_symbol_count(ctx), 2)

    def test_vendored_awd_namespace_named_and_counted(self):
        # wireless_diagnostics::google::protobuf is the AWD telemetry runtime
        # locationd statically embeds — it IS real C++ protobuf usage, reported
        # under its vendored namespace (not silently dropped).
        ctx = _SymCtx([
            "__ZN20wireless_diagnostics6google8protobuf11MessageLiteD2Ev",
            "__ZN20wireless_diagnostics6google8protobuf14DescriptorPool14generated_poolEv",
        ])
        self.assertEqual(FD.cpp_protobuf_namespaces(ctx),
                         {"wireless_diagnostics::google::protobuf": 2})

    def test_mixed_top_level_and_vendored(self):
        ctx = _SymCtx([
            "__ZN6google8protobuf11MessageLiteD2Ev",
            "__ZN20wireless_diagnostics6google8protobuf11MessageLiteD2Ev",
        ])
        self.assertEqual(FD.cpp_protobuf_namespaces(ctx),
                         {"google::protobuf": 1,
                          "wireless_diagnostics::google::protobuf": 1})


class _SymClassCtx(_SymCtx):
    """_SymCtx plus the no-op pointer/bind resolvers google_protobuf_classes needs."""
    def read_ptr(self, va): raise ValueError("unmapped")
    def read_cstring(self, va): raise ValueError("unmapped")
    def import_name_for_bind(self, raw): return None


class TestForeignProtobufWarnings(unittest.TestCase):
    def test_all_three_runtimes_consolidated(self):
        # GPB (ObjC classlist) + Swift + C++ all present at once -> ONE message
        # naming all three.
        base = _cls(0x1000, "FooGPBMessage", 0x9000)
        req = _cls(0x2000, "FooRequest", 0x1000)
        cl = ClassList([base, req])
        ctx = _SymClassCtx([_SWIFT_MSG, "__ZN6google8protobuf11MessageLiteD2Ev"])
        with self.assertLogs("proto.foreign_detect", level="WARNING") as cm:
            FD._warn_if_foreign_protobuf(ctx, cl)
        self.assertEqual(len(cm.output), 1)            # consolidated, not 3 separate
        out = cm.output[0]
        self.assertIn("non-PBCodable runtime", out)
        # swift + C++ are DECODED; GPB is DETECTED-but-not-decodable
        self.assertIn("DECODED", out)
        self.assertIn("DETECTED", out)
        self.assertIn("Google protobuf-objc", out)
        self.assertIn("swift-protobuf", out)
        self.assertIn("FooRequest", out)              # GPB class named
        self.assertIn("PBPropertyValue", out)         # Swift type named
        # swift is DECODED; GPB and the descriptor-less C++ (lite) are DETECTED
        self.assertLess(out.index("DECODED"), out.index("swift-protobuf"))
        self.assertLess(out.index("swift-protobuf"), out.index("DETECTED"))
        self.assertLess(out.index("DETECTED"), out.index("Google protobuf-objc"))
        self.assertLess(out.index("DETECTED"), out.index("C++ libprotobuf-lite"))
        self.assertNotIn("C++ google::protobuf", out)

    def test_cpp_with_descriptors_is_decoded(self):
        # The same symbols plus an embedded FileDescriptorProto: full C++, DECODED.
        ctx = _SymClassCtx(["__ZN6google8protobuf11MessageLiteD2Ev"])
        saved = FD._cpp.extract_cpp_protos_from_ctx
        FD._cpp.extract_cpp_protos_from_ctx = lambda c: [object()]
        try:
            with self.assertLogs("proto.foreign_detect", level="WARNING") as cm:
                FD._warn_if_foreign_protobuf(ctx, ClassList([]))
        finally:
            FD._cpp.extract_cpp_protos_from_ctx = saved
        out = cm.output[0]
        self.assertIn("DECODED", out)
        self.assertIn("C++ google::protobuf", out)
        self.assertNotIn("DETECTED", out)

    def test_no_runtimes_no_warning(self):
        with self.assertRaises(AssertionError):       # assertLogs fails if nothing logged
            with self.assertLogs("proto.foreign_detect", level="WARNING"):
                FD._warn_if_foreign_protobuf(_SymClassCtx(["_OBJC_CLASS_$_X"]),
                                            ClassList([]))


# Live: locationd is NOT swift-protobuf, but it DOES statically embed the Apple
# Wireless Diagnostics C++ protobuf runtime (vendored google::protobuf) — so it
# emits AWD telemetry protobufs *as well as* its 65 PBCodable messages, and the
# detector must report that vendored namespace (it is real usage, not a false alarm).
try:
    _HAVE_LOCD = _VL.load_locationd() is not None
except Exception:
    _HAVE_LOCD = False


@unittest.skipUnless(_HAVE_LOCD, "locationd binary not available")
class TestForeignProtobufLocationdLive(unittest.TestCase):
    def test_locationd_swift_clean_but_cpp_vendored_reported(self):
        ctx, st, cl = _VL.load_locationd()
        msgs, enums, _ = FD.swift_protobuf_messages(ctx)
        self.assertEqual((msgs, enums), ([], []))           # no swift-protobuf
        ns = FD.cpp_protobuf_namespaces(ctx)
        self.assertTrue(ns, "expected vendored AWD google::protobuf usage")
        self.assertTrue(any("google::protobuf" in n for n in ns), ns)
        # locationd's C++ usage is the vendored AWD copy, not standard libprotobuf
        self.assertIn("wireless_diagnostics::google::protobuf", ns)


if __name__ == "__main__":
    unittest.main()
