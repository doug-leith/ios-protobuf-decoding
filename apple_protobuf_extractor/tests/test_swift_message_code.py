"""serializers.swift_message_code -- a swift-protobuf message's field types read off its own
decodeMessage, by field number, found from its Message conformance (TODO #129)."""
import os
import unittest

import artifacts


def _binary(path):
    from macho.memory import BinaryContext
    from serializers.swift_descriptor_extract import load_macho_slice
    with open(path, "rb") as fh:
        return BinaryContext(load_macho_slice(fh.read()))


IOS27 = artifacts.cache_file_in(artifacts.ios27_cache_dir())
ORACLE = artifacts.swift_oracle_path() if os.path.isfile(artifacts.swift_oracle_path()) else None
REMINDD = os.path.join(artifacts.data_dir(), "libexec", "remindd")
REMINDD = REMINDD if os.path.isfile(REMINDD) else None


@unittest.skipUnless(IOS27, "iOS 27 cache not available")
class TestDecodedOnTheIos27Cache(unittest.TestCase):
    """Resilient witnesses (InternalSwiftProtobuf, another image), a public type's body that is
    an export (no local symbol), library-evolution layouts (offsets from metadata), copy-on-write
    storage, oneofs of Apple's own generator."""

    @classmethod
    def setUpClass(cls):
        from macho.dyld_cache import DyldCacheReader
        cls.reader = DyldCacheReader(IOS27)
        cls.ctxs = {}

    def _decoded(self, image, type_name, numbers):
        from macho.load import load_cache_image
        import serializers.swift_message_code as MC
        from serializers.swift_type_recovery import _qualified_name
        if image not in self.ctxs:
            self.ctxs[image] = load_cache_image(self.reader, self.reader.find_image_header(image)).ctx
        ctx = self.ctxs[image]
        ws = next(ws for td, ws in MC.message_witnesses(ctx).items()
                  if _qualified_name(ctx, td) == type_name)
        return MC.decoded_fields(ctx, ws["decodeMessage"], numbers)

    def test_fields_by_offset(self):
        """GridCleanlinessStats: its name map's #2 / #3 are clean / reduce, its properties
        cleaner / lessClean -- by number, each is the double at its offset in self."""
        got = self._decoded("EnergyKitFoundation", "InsightRecordPayload.GridCleanlinessStats",
                            [1, 2, 3, 4])
        self.assertEqual({n: [(d.label, d.kind, d.origin, d.offset) for d in ds]
                          for n, ds in got.items()},
                         {n: [("Singular", "Double", ("self",), 8 * (n - 1))] for n in (1, 2, 3, 4)})

    def test_a_copy_on_write_message_type(self):
        """PgQuery_A_Const: the message type a field decodes is the metadata it hands the
        decoder (PgQuery_Node's accessor), though its storage's offsets are the runtime's."""
        got = self._decoded("BiomeStreams", "PgQuery_A_Const", [1, 2])
        self.assertEqual([(d.kind, d.type) for d in got[1]], [("Message", "PgQuery_Node")])
        self.assertEqual([(d.kind, d.type) for d in got[2]], [("Int32", None)])

    def test_a_case_with_no_payload_is_a_null_value(self):
        got = self._decoded("TokenGenerationCore", "Tokengenerationcore_Wireformat_FinishReason",
                            [1, 2, 3, 4])
        self.assertEqual([(d.kind, d.type) for d in got[1]], [("Enum", "Google_Protobuf_NullValue")])
        self.assertEqual([d.kind for d in got[2]], ["String"])

    def test_a_merged_body_with_its_parts_as_arguments(self):
        """TokenGenerationCore's AudioContent: identical-code folding made its decodeMessage a
        forwarder to a merged body, handed the field closures in x3 / x4: each number decodes
        its own part (the bytes in self, the enum by its metadata)."""
        got = self._decoded("TokenGenerationCore", "Tokengenerationcore_Wireformat_AudioContent",
                            [1, 2])
        self.assertEqual({n: [(d.label, d.kind, d.type, d.origin, d.offset) for d in ds]
                          for n, ds in got.items()},
                         {1: [("Singular", "Bytes", None, ("self",), 0)],
                          2: [("Singular", "Enum", "Promptkit_Wireformat_AudioFormat", None, None)]})


    def test_traverse_hands_the_same_types(self):
        """traverse's Visitor calls by number, typed as decodeMessage's are: a message by the
        metadata it is handed (x2), a map's key and value (x2, x3), a NullValue oneof case in a
        closure."""
        import serializers.swift_message_code as MC
        from macho.load import load_cache_image
        from serializers.swift_type_recovery import _qualified_name

        def visited(image, type_name):
            if image not in self.ctxs:
                self.ctxs[image] = load_cache_image(self.reader,
                                                    self.reader.find_image_header(image)).ctx
            ctx = self.ctxs[image]
            ws = next(ws for td, ws in MC.message_witnesses(ctx).items()
                      if _qualified_name(ctx, td) == type_name)
            return {n: [(v.label, v.kind, v.type) for v in vs]
                    for n, vs in MC.visited_fields(ctx, ws["traverse"]).items()}
        self.assertEqual(visited("BiomeStreams", "PgQuery_A_Const"),
                         {1: [("Singular", "Message", "PgQuery_Node")],
                          2: [("Singular", "Int32", None)]})
        self.assertEqual(visited("Hands", "HandsKitDataSequencePB")[1],
                         [("Map", "Map", "map<uint64, HandsKitDataPB>")])
        self.assertEqual(visited("TokenGenerationCore",
                                 "Tokengenerationcore_Wireformat_FinishReason")[3],
                         [("Singular", "Enum", "Google_Protobuf_NullValue")])


class TestAOneEntryReadingIsChecked(unittest.TestCase):
    """A one-entry name-map reading (no cross-check of its own) is kept only if the message's
    decodeMessage decodes that number and reflection lists a field of that name; where
    decodeMessage cannot be read, reflection alone decides, reported (#130)."""

    def _run(self, decoded, stored=("value",)):
        from unittest import mock
        import serializers.swift_descriptor_extract as S
        import serializers.swift_message_code as MC
        import serializers.swift_type_recovery as TR
        from proto.models import get_diagnostics
        m = S.SwiftMessage("Mod", "M", fields=[S.SwiftField(1, "value")], shape="runtime-single")
        ctx = type("Ctx", (), {})()
        with mock.patch.object(MC, "message_witnesses", lambda ctx: {1: {"decodeMessage": MC.Code(0x1000)}}), \
                mock.patch.object(TR, "_qualified_name", lambda ctx, td: "M"), \
                mock.patch.object(MC, "decoded_fields", lambda ctx, code, numbers: decoded), \
                mock.patch.object(TR, "collect_field_types",
                                  lambda ctx: ({}, {}, set(), {"M": set(stored)})):
            S._attach_types(ctx, [m], {})
        hits = [h for h in get_diagnostics(ctx).heuristics_hit if h[0] == "swift-reflection-confirm"]
        return [(f.number, f.proto_type) for f in m.fields], len(hits)

    def test_decoded_and_listed(self):
        import serializers.swift_message_code as MC
        self.assertEqual(self._run({1: [MC.Decoded("Singular", "Bool")]}), ([(1, "bool")], 0))

    def test_decoded_but_not_listed(self):
        import serializers.swift_message_code as MC
        self.assertEqual(self._run({1: [MC.Decoded("Singular", "Bool")]}, stored=("other",)),
                         ([], 0))

    def test_not_decoded(self):
        self.assertEqual(self._run({}), ([], 0))

    def test_unreadable_reflection_decides(self):
        self.assertEqual(self._run(None), ([(1, None)], 1))
        self.assertEqual(self._run(None, stored=("other",)), ([], 1))


class TestOneMessageFailingIsItsOwn(unittest.TestCase):
    """A message whose decodeMessage reading raises is recorded as its analysis failure; the
    image's other messages are typed as before."""

    def test_guarded(self):
        from unittest import mock
        import serializers.swift_descriptor_extract as S
        import serializers.swift_message_code as MC
        import serializers.swift_type_recovery as TR
        from proto.models import get_diagnostics
        a = S.SwiftMessage("Mod", "A", fields=[S.SwiftField(1, "x")], shape="static")
        b = S.SwiftMessage("Mod", "B", fields=[S.SwiftField(1, "y")], shape="static")

        def decoded(ctx, code, numbers):
            if code.va == 0xA:
                raise ValueError("bad")
            return {1: [MC.Decoded("Singular", "Bool")]}
        ctx = type("Ctx", (), {})()
        with mock.patch.object(MC, "message_witnesses",
                               lambda ctx: {0xA: {"decodeMessage": MC.Code(0xA)},
                                            0xB: {"decodeMessage": MC.Code(0xB)}}), \
                mock.patch.object(TR, "_qualified_name", lambda ctx, td: "A" if td == 0xA else "B"), \
                mock.patch.object(MC, "decoded_fields", decoded), \
                mock.patch.object(TR, "collect_field_types", lambda ctx: ({}, {}, set(), {})):
            S._attach_types(ctx, [a, b], {})
        self.assertEqual((a.fields[0].proto_type, b.fields[0].proto_type), (None, "bool"))
        self.assertEqual(get_diagnostics(ctx).analysis_failures,
                         [("Mod.A", "swift decodeMessage", "ValueError: bad")])


@unittest.skipUnless(ORACLE, "swift-protobuf oracle fixture not available")
class TestDecodedOnTheOracle(unittest.TestCase):
    """A binary that links SwiftProtobuf in: static witness tables, whose slots are named by
    the witnesses' own symbols (no method descriptor symbols).  The encodings are the .proto's."""

    def test_the_encodings_of_the_proto(self):
        from serializers.swift_descriptor_extract import swift_messages
        from proto.models import get_diagnostics
        ctx = _binary(ORACLE)
        msgs = {m.name: m for m in swift_messages(ctx)}
        kinds = {f.name: f.proto_type for f in msgs["Ora_WithKinds"].fields}
        self.assertEqual(kinds, {"nums": "repeated int32", "child": "Ora_Single1",
                                 "lut": "map<string, int32>", "zig": "sint32", "fx": "fixed32"})
        self.assertFalse([h for h in get_diagnostics(ctx).heuristics_hit
                          if h[0] == "swift-name-join"])


@unittest.skipUnless(REMINDD, "remindd not available")
class TestNameJoinIsTheLastResort(unittest.TestCase):
    """remindd links SwiftProtobuf in, stripped: neither its Decoder nor its Visitor slots
    can be named, so its fields take the reflection type of the property of their name -- and
    each one says so."""

    def test_reported(self):
        from serializers.swift_descriptor_extract import swift_messages
        from proto.models import get_diagnostics
        ctx = _binary(REMINDD)
        msgs = swift_messages(ctx)
        typed = sum(1 for m in msgs for f in m.fields if f.proto_type)
        joined = [h for h in get_diagnostics(ctx).heuristics_hit if h[0] == "swift-name-join"]
        self.assertGreater(typed, 100)
        self.assertEqual(len(joined), typed)
        # and each says so in the .proto (#130)
        self.assertTrue(all(f.type_note for m in msgs for f in m.fields if f.proto_type))


if __name__ == "__main__":
    unittest.main()
