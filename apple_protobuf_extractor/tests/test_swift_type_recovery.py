"""swift_type_recovery — recover swift-protobuf field TYPES from __swift5_fieldmd.

Ground truth comes from two sources:
* the protoc-gen-swift ORACLE (tests/swift_oracle_fixture/, overridable via
  MACHO_TEST_SWIFT_ORACLE) built from a KNOWN .proto — every field's exact
  proto type is asserted (the sint/fixed encoding nuance is documented, not
  asserted);
* the live device binary remindd (iPhone8 libexec) — scalar / nested / repeated /
  oneof / full-WKT-name types checked on real swift-protobuf messages.
Both gated on the artifact being present.
"""
import os
import unittest

from serializers import swift_descriptor_extract as SW
from serializers import swift_type_recovery as TR


def _ctx(path):
    from macho.memory import BinaryContext
    return BinaryContext(SW.load_macho_slice(open(path, "rb").read()))


def _remindd():
    p = os.environ.get("MACHO_TEST_REMINDD", "").strip()
    if p:
        return p if os.path.isfile(p) else None
    try:
        import artifacts
        c = os.path.join(artifacts.data_dir(), "libexec", "remindd")
        return c if os.path.isfile(c) else None
    except Exception:
        return None


def _swift_oracle():
    try:
        import artifacts
        p = artifacts.swift_oracle_path()
        return p if os.path.isfile(p) else None
    except Exception:
        return None


class TestDemangleOffline(unittest.TestCase):
    """Pure-function coverage that needs no binary."""
    def test_type_from_bind(self):
        self.assertEqual(TR._type_from_bind("_$ss5Int32VMn"), "int32")
        self.assertEqual(TR._type_from_bind("_$ss5Int64VMn"), "int64")
        self.assertEqual(TR._type_from_bind("_$ss6UInt32VMn"), "uint32")
        self.assertEqual(TR._type_from_bind("_$ss6UInt64VMn"), "uint64")
        self.assertEqual(TR._type_from_bind("_$s10Foundation4DataVMn"), "bytes")
        # a message descriptor bind -> its last type identifier (not a scalar)
        self.assertEqual(TR._type_from_bind("_$s3Foo3BarVMn"), "Bar")
        self.assertIsNone(TR._type_from_bind(None))

    def test_idents(self):
        self.assertEqual(TR._idents("5Int32"), ["Int32"])
        self.assertEqual(TR._idents("3Foo3Bar"), ["Foo", "Bar"])

    def test_runlength_standard_substitution(self):
        # S2S = run-length 2 copies of the String substitution: the body of a
        # map<String,String> dictionary mangling (SDyS2SG).  Drives #66.
        self.assertEqual(TR._runlength_types("S2SG"), ["string", "string"])
        # plain consecutive substitutions, no run-length: SS Si = String,Int64
        self.assertEqual(TR._runlength_types("SSSiG"), ["string", "int64"])
        # mixed count: S3d = three Doubles
        self.assertEqual(TR._runlength_types("S3dX"), ["double", "double", "double"])
        # stops at the first non-scalar token (symbolic ref / Data / nested)
        self.assertEqual(TR._runlength_types("SS\x01rest"), ["string"])
        self.assertEqual(TR._runlength_types("Xnope"), [])

    def test_word_substitution(self):
        # Swift's leading-'0' identifier form back-references previously seen
        # words (B = the word 'Protobuf' from 'SwiftProtobuf'); the substitution
        # table is shared across the whole run.  Without this, the names collapse
        # ('Google_Protobuf_Any' -> 'Google_._Any', type -> 'Google_').
        self.assertEqual(
            TR.demangle_idents("13SwiftProtobuf07Google_B4_Any"),
            ["SwiftProtobuf", "Google_Protobuf_Any"])
        self.assertEqual(
            TR.demangle_idents("13SwiftProtobuf07Google_B9_Duration"),
            ["SwiftProtobuf", "Google_Protobuf_Duration"])
        # plain identifiers (no substitution) are unaffected
        self.assertEqual(TR.demangle_idents("7remindd12EmptyRequest"),
                         ["remindd", "EmptyRequest"])
        # a word-substituted type-descriptor bind demangles to the full name
        self.assertEqual(
            TR._type_from_bind("_$s13SwiftProtobuf07Google_B4_AnyVMn"),
            "Google_Protobuf_Any")


class TestFieldRecordsBoundedBySection(unittest.TestCase):
    """A FieldDescriptor's records are read only when its header and all ``count`` records lie
    inside ``__swift5_fieldmd``; an overrunning descriptor is not read at all (no truncated
    prefix, and no fixed record cap)."""

    class _Mem:
        def __init__(self, base, data):
            self.base, self.data = base, bytes(data)

        def read_bytes(self, va, n):
            if not self.base <= va <= va + n <= self.base + len(self.data):
                raise ValueError(va)
            return self.data[va - self.base:va - self.base + n]

        def read_cstring(self, va, max_len=4096):
            raw = self.read_bytes(va, min(max_len, self.base + len(self.data) - va))
            return raw.split(b"\0", 1)[0].decode()

    def _image(self, nfields):
        import struct
        base, desc, fd, strs = 0x1000, 0x1000, 0x1100, 0x1400
        buf = bytearray(0x600)
        struct.pack_into("<i", buf, desc + 0x10 - base, fd - (desc + 0x10))
        struct.pack_into("<HHI", buf, fd + 0x08 - base, 0, 12, nfields)
        names = []
        for i in range(nfields):
            rec = fd + 0x10 + 12 * i
            name_va, type_va = strs + 0x20 * i, strs + 0x20 * i + 0x10
            buf[name_va - base:name_va - base + 3] = f"f{i}".encode() + b"\0"
            buf[type_va - base:type_va - base + 3] = b"Si\0"
            struct.pack_into("<Iii", buf, rec - base, 0, type_va - (rec + 4), name_va - (rec + 8))
            names.append(f"f{i}")
        return self._Mem(base, buf), desc, fd, names

    def test_records_inside_the_section_are_read(self):
        mem, desc, fd, names = self._image(3)
        fields, _inc, got = TR._read_field_types(mem, desc, (fd, fd + 0x10 + 3 * 12))
        self.assertEqual(got, set(names))
        self.assertEqual(fields, {n: "int64" for n in names})

    def test_a_descriptor_overrunning_the_section_is_not_read(self):
        mem, desc, fd, _names = self._image(3)
        self.assertEqual(TR._read_field_types(mem, desc, (fd, fd + 0x10 + 2 * 12)),
                         ({}, set(), set()))


@unittest.skipUnless(_swift_oracle(),
                     "swift-protobuf oracle fixture not available (see "
                     "tests/swift_oracle_fixture/README.md); "
                     "MACHO_TEST_SWIFT_ORACLE overrides")
class TestOracleExactTypes(unittest.TestCase):
    """The oracle is built from a known .proto; recovered base types must match."""
    @classmethod
    def setUpClass(cls):
        cls.t = TR.collect_field_types(_ctx(_swift_oracle()))[0]

    def test_scalars_messages_repeated_map(self):
        self.assertEqual(self.t.get("Ora_Single7"), {"only": "string"})
        self.assertEqual(self.t.get("Ora_Multi"),
                         {"a": "int32", "b": "string", "c": "bool",
                          "big": "int64", "raw": "bytes"})
        wk = self.t.get("Ora_WithKinds")
        self.assertEqual(wk["nums"], "repeated int32")
        self.assertEqual(wk["child"], "Ora_Single1")
        self.assertEqual(wk["lut"], "map<string, int32>")
        # sint32 / fixed32 collapse to their Swift base type (Int32 / UInt32) —
        # the varint/zigzag/fixed encoding nuance is a documented limitation.
        self.assertEqual(wk["zig"], "int32")     # proto sint32, base Int32
        self.assertEqual(wk["fx"], "uint32")     # proto fixed32, base UInt32


@unittest.skipUnless(_remindd(), "remindd binary not available")
class TestLiveDeviceTypes(unittest.TestCase):
    """The field-type map on a real device swift-protobuf binary (remindd):
    scalars, nested/repeated messages, oneofs, and full (un-truncated) WKT names.
    (Replaces the retired bookdatastored corpus, which this dump's build no longer
    ships as swift-protobuf; remindd exercises the same code more richly.)"""
    @classmethod
    def setUpClass(cls):
        cls.t = TR.collect_field_types(_ctx(_remindd()))[0]

    def test_scalar_types(self):
        mr = self.t["MigrateRequest"]
        self.assertEqual(mr["archivePath"], "string")
        self.assertEqual(mr["options"], "uint32")
        self.assertEqual(mr["userInitiated"], "bool")
        self.assertEqual(mr["simulatedError"], "int32")
        self.assertEqual(self.t["MigrateResponse.Details"]["timeElapsed"], "double")

    def test_nested_and_oneof_message(self):
        smr = self.t["StartMigrationRequest"]
        self.assertEqual(smr["credential"], "StartMigrationRequest.Credential")     # nested message (qualified)
        self.assertEqual(smr["source"], "StartMigrationRequest.OneOf_Source")       # oneof wrapper (qualified)
        self.assertEqual(self.t["MigrateRequest"]["user"], "MigrateRequest.User")   # nested, qualified

    def test_repeated_message_and_full_wkt_name(self):
        # Google_Protobuf_Field.options is `repeated Google_Protobuf_Option` — a
        # repeated message whose WKT element name is recovered in FULL (not
        # truncated to 'Google_' by un-decoded word-substitution mangling).
        self.assertEqual(self.t["Google_Protobuf_Field"]["options"],
                         "repeated Google_Protobuf_Option")


@unittest.skipUnless(_remindd(), "remindd binary not available")
class TestEndToEndTypesBound(unittest.TestCase):
    """Types must bind onto the name+number fields (snake_case <-> camelCase join)."""
    def test_types_attached_to_fields(self):
        msgs = {m.name: m for m in SW.swift_messages(_ctx(_remindd()))}
        mr = {f.name: f for f in msgs["MigrateRequest"].fields}
        self.assertEqual(mr["archivePath"].proto_type, "string")
        self.assertEqual(mr["options"].proto_type, "uint32")
        fld = {f.name: f for f in msgs["Google_Protobuf_Field"].fields}
        self.assertEqual(fld["options"].proto_type, "repeated Google_Protobuf_Option")


if __name__ == "__main__":
    unittest.main()
