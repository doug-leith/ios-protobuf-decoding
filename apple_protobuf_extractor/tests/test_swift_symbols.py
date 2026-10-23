"""serializers.swift_symbols -- the symbols and Swift runtime records the swift-protobuf readers
name things by -- and the readers of serializers.swift_message_code built on them: the Message
witnesses, the requirement slots."""
import os
import struct
import unittest

import artifacts
from serializers import swift_descriptor_extract as S
from serializers import swift_message_code as MC
from serializers import swift_symbols as SY

ORACLE = artifacts.swift_oracle_path() if os.path.isfile(artifacts.swift_oracle_path()) else None
IOS27 = artifacts.cache_file_in(artifacts.ios27_cache_dir())

_MESSAGE = "_$s13SwiftProtobuf7MessageMp"
_TRAVERSE_REQ = "_$s13SwiftProtobuf7MessageP8traverse7visitoryqd__z_tKAA7VisitorRd__lFTq"


def _binary(path):
    from macho.memory import BinaryContext
    with open(path, "rb") as fh:
        return BinaryContext(S.load_macho_slice(fh.read()))


class _ProtoCtx:
    """An image whose ``__swift5_proto`` lists two records: a static witness table whose
    conformance names its type through a slot that cannot be read, and resilient witnesses."""
    image_base = 0

    class _Sec:
        vmaddr, vmsize = 0x100, 8

    def __init__(self):
        mem = bytearray(0x800)

        def i32(at, v):
            struct.pack_into("<i", mem, at, v)
        i32(0x100, 0x200 - 0x100)                    # record -> conformance descriptor
        i32(0x104, 0x240 - 0x104)
        # static: protocol through the bound slot 0x300, the type through the slot 0x400, the
        # witness table at 0x500, the type reference indirect (kind 1)
        i32(0x200, (0x300 - 0x200) | 1)
        i32(0x204, 0x400 - 0x204)
        i32(0x208, 0x500 - 0x208)
        struct.pack_into("<I", mem, 0x20C, 1 << 3)
        # resilient: the type direct at 0x600, one witness (requirement through the slot 0x310,
        # implementation 0x700)
        i32(0x240, (0x300 - 0x240) | 1)
        i32(0x244, 0x600 - 0x244)
        struct.pack_into("<I", mem, 0x24C, 1 << 16)
        struct.pack_into("<I", mem, 0x250, 1)
        i32(0x254, (0x310 - 0x254) | 1)
        i32(0x258, 0x700 - 0x258)
        self._mem = bytes(mem)
        self._binds = {0x300: _MESSAGE, 0x310: _TRAVERSE_REQ}

    def has_section(self, seg, name):
        return (seg, name) == ("__TEXT", "__swift5_proto")

    def section(self, seg, name):
        return self._Sec()

    def read_bytes(self, va, n):
        if va < 0 or va + n > len(self._mem):
            raise ValueError("oob")
        return self._mem[va:va + n]

    def read_ptr(self, va):
        if va == 0x400:
            raise ValueError("unreadable slot")
        return struct.unpack("<Q", self.read_bytes(va, 8))[0]

    def bind_name_for(self, va):
        return self._binds.get(va)


class TestConformances(unittest.TestCase):
    def test_both_kinds_of_record(self):
        self.assertEqual(SY.conformances(_ProtoCtx()), [
            SY.Conformance((_MESSAGE,), None, 0x500),
            SY.Conformance((_MESSAGE,), 0x600, None, (((_TRAVERSE_REQ,), 0x700),))])

    def test_an_unreadable_type_keeps_the_static_table(self):
        # the static table is still a witness table of the protocol (its slots are named by
        # what it holds), though the conformance's own type is not known
        tables = [c.witness_table for c in SY.conformances(_ProtoCtx()) if _MESSAGE in c.protocol]
        self.assertEqual(tables, [0x500, None])


class TestRelativePointers(unittest.TestCase):
    def test_direct_and_indirect(self):
        ctx = _ProtoCtx()
        self.assertEqual(SY.rel(ctx, 0x100), 0x200)
        self.assertEqual(SY.rel_indirect(ctx, 0x200), (0x300, True))
        self.assertEqual(SY.rel_indirect(ctx, 0x204), (0x400, False))
        self.assertEqual(SY.referenced_names(ctx, 0x300, True), (_MESSAGE,))


@unittest.skipUnless(ORACLE, "swift-protobuf oracle fixture not available")
class TestOnTheOracle(unittest.TestCase):
    """A binary that links SwiftProtobuf in: static witness tables, no method descriptor
    symbols (a requirement is named by what the tables hold at its slot)."""

    @classmethod
    def setUpClass(cls):
        cls.ctx = _binary(ORACLE)

    def test_every_message_has_both_witnesses(self):
        msgs = S.swift_messages(self.ctx)
        confs = [c for c in SY.conformances(self.ctx) if _MESSAGE in c.protocol]
        self.assertEqual(len(msgs), 64)
        self.assertEqual(len(confs), 64)
        self.assertTrue(all(c.witness_table is not None and c.type_descriptor for c in confs))
        witnesses = MC.message_witnesses(self.ctx)
        self.assertEqual(len(witnesses), 64)
        self.assertTrue(all(set(ws) == {"traverse", "decodeMessage"} for ws in witnesses.values()))
        self.assertEqual({m.name for m in msgs}, set(S._witnesses(self.ctx)))

    def test_requirement_slots(self):
        # every requirement of the three protocols named by the tables' witnesses; the Visitor
        # and Decoder field methods by their offsets
        for protocol, n in (("_$s13SwiftProtobuf7VisitorMp", 56),
                            ("_$s13SwiftProtobuf7DecoderMp", 59), (_MESSAGE, 11)):
            self.assertEqual(len(SY.protocol_requirements(self.ctx, protocol)), n, protocol)
            slots = MC.requirement_slots(self.ctx, protocol)
            self.assertEqual(len(slots), n, protocol)
            self.assertTrue(all(slots.values()), protocol)
        self.assertEqual((len(MC._visitor_slots(self.ctx)), len(MC._decoder_slots(self.ctx))),
                         (55, 56))

    def test_alias_order_does_not_matter(self):
        # the same readings whichever of an address's names comes first
        def reading(reverse):
            ctx = _binary(ORACLE)
            if reverse:
                by_addr, by_name = SY._tables(ctx)
                ctx._swift_symbol_tables = ({a: ns[::-1] for a, ns in by_addr.items()}, by_name)
            msgs = S.swift_messages(ctx)
            return ([(m.qualified, m.shape, [(f.number, f.name, f.proto_type) for f in m.fields])
                     for m in msgs], MC._visitor_slots(ctx), MC._decoder_slots(ctx))
        aliased = sum(1 for ns in SY._tables(self.ctx)[0].values() if len(ns) > 1)
        self.assertGreater(aliased, 1000)
        self.assertEqual(reading(False), reading(True))


@unittest.skipUnless(IOS27, "iOS 27 cache not available")
class TestOnTheIos27Cache(unittest.TestCase):
    """Resilient witnesses to InternalSwiftProtobuf's Message, its requirements named by their
    descriptors' symbols, which are that framework's exports."""

    @classmethod
    def setUpClass(cls):
        from macho.dyld_cache import DyldCacheReader
        from macho.load import load_cache_image
        cls.reader = DyldCacheReader(IOS27)
        cls.ctx = load_cache_image(cls.reader, cls.reader.find_image_header("CipherML")).ctx

    @classmethod
    def tearDownClass(cls):
        cls.reader.close()

    def test_every_message_has_both_witnesses(self):
        msgs = S.swift_messages(self.ctx)
        confs = [c for c in SY.conformances(self.ctx)
                 if "_$s21InternalSwiftProtobuf7MessageMp" in c.protocol]
        self.assertEqual(len(msgs), 70)
        self.assertEqual(len(confs), 70)
        self.assertTrue(all(c.witness_table is None and c.resilient for c in confs))
        witnesses = MC.message_witnesses(self.ctx)
        self.assertEqual(len(witnesses), 70)
        self.assertTrue(all(set(ws) == {"traverse", "decodeMessage"} for ws in witnesses.values()))

    def test_requirement_slots(self):
        for protocol, n in (("_$s21InternalSwiftProtobuf7VisitorMp", 56),
                            ("_$s21InternalSwiftProtobuf7DecoderMp", 59)):
            reqs = SY.protocol_requirements(self.ctx, protocol)
            self.assertEqual(len(reqs), n, protocol)
            self.assertTrue(all(any(x.endswith("Tq") for x in names) for names in reqs), protocol)
        self.assertEqual((len(MC._visitor_slots(self.ctx)), len(MC._decoder_slots(self.ctx))),
                         (55, 56))

    def test_the_symbol_scope(self):
        # the swift-protobuf framework's exports name its descriptors; name-map discovery
        # (symbol_addrs) stays the image's own
        visitor = SY.address_of(self.ctx, "_$s21InternalSwiftProtobuf7VisitorMp")
        self.assertIsNotNone(visitor)
        self.assertNotIn("_$s21InternalSwiftProtobuf7VisitorMp", SY.symbol_addrs(self.ctx))
        self.assertIn("_$s21InternalSwiftProtobuf7VisitorMp", SY.names_at(self.ctx, visitor))


if __name__ == "__main__":
    unittest.main()
