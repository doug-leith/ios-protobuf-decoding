"""serializers.swift_message_code -- a swift-protobuf message's field types read off its own
decodeMessage, by field number, found from its Message conformance (TODO #129)."""
import os
import unittest

import artifacts


def _ios27_cache():
    for name in artifacts.CACHE_BASENAMES:
        p = os.path.join(artifacts.ios27_cache_dir(), name)
        if os.path.isfile(p):
            return p
    return None


def _binary(path):
    from macho.memory import BinaryContext
    from serializers.swift_descriptor_extract import load_macho_slice
    with open(path, "rb") as fh:
        return BinaryContext(load_macho_slice(fh.read()))


IOS27 = _ios27_cache()
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
        from macho.load import load_cache_image
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
        forwarder to a merged body, handed the field closures in x3 / x4."""
        got = self._decoded("TokenGenerationCore", "Tokengenerationcore_Wireformat_AudioContent",
                            [1, 2])
        self.assertEqual(sorted(got), [1, 2])


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


if __name__ == "__main__":
    unittest.main()
