"""swift-protobuf field name+number recovery (swift_descriptor_extract).

Offline: hand-built static-object blobs + a synthetic fat header exercise the
shape-C scanner, the mangled-name parser, the fat-slice picker, and the emitter
without needing any binary.

Live: remindd (iPhone8 libexec) is the device-form swift-protobuf ground truth —
dense multi-field, nested types, empty messages, and the runtime-_NameMap builder
are checked by name+number (45 messages incl. the SwiftProtobuf WKTs).  Skipped
when the dump is absent.  (Retired the bookdatastored corpus: this dump's build
of that daemon ships no swift-protobuf at all — BookDataStore moved to
Coherence/CRDT.  DPSubmissionService WAS also retired by e4d3d76 as "schema
drift"; that was a misdiagnosis -- the real cause was the then-unhandled shape-D
lowering (#74) -- so its corpus is restored below, exercising that shape.)
"""
import os
import struct
import unittest

import pytest

from serializers import swift_descriptor_extract as S
from serializers import swift_message_code as MC
from proto import function_body as FB
from tests.conftest import encode_adrp, encode_add_imm64, encode_movz, NOP_BYTES, RET_BYTES
from tests._listing import insns as _listing
from tests._fakes import NoImage, TextImage


# ── a minimal in-memory ctx where vmaddr == file offset (image_base 0) ────────

class _FakeCtx:
    image_base = 0

    def __init__(self, data: bytes, fixups=None):
        self._data = data
        self._symtab = None
        self._export_trie = None
        self._fixups = fixups or {}     # slot -> the pointer its fixup decodes to

    def function_starts(self):          # no LC_FUNCTION_STARTS
        return []

    def has_section(self, segname, sectname):   # no sections
        return False

    def iter_symbols(self):             # no symbol table
        return iter(())

    def read_bytes(self, va: int, n: int) -> bytes:
        if va < 0 or va + n > len(self._data):
            raise ValueError("oob")
        return self._data[va:va + n]

    def is_variable(self, vmaddr):        # no program data, no binds
        return False

    def read_ptr(self, va: int) -> int:
        return self._fixups.get(va, struct.unpack("<Q", self.read_bytes(va, 8))[0])

    def read_cstring(self, va: int, max_len: int = 4096) -> str:
        if va < 0 or va >= len(self._data):
            raise ValueError("oob")
        end = self._data.find(b"\x00", va, min(va + max_len, len(self._data)))
        if end < 0:
            raise ValueError("unterminated")
        return self._data[va:end].decode("utf-8", "replace")

    def vmaddr_to_offset(self, va: int, length: int = 1) -> int:
        # Needed by macho.disasm.disasm's pre-read validation (image_base == 0,
        # so file offset == va, same convention as read_bytes/read_cstring above).
        if va < 0 or va + length > len(self._data):
            raise ValueError("oob")
        return va


def _build_static_blob(entries, stride):
    """Build a buffer holding name cstrings + a static Array storage blob.

    Entry layout: number @ +0, name-ptr @ +8, len @ +0x10 (rest padded to
    *stride*).  Returns (buf, blob_va)."""
    buf = bytearray(b"\x00" * 0x80)            # leading pad; names live here
    name_va = {}
    for _num, nm in entries:
        name_va[nm] = len(buf)
        buf += nm.encode() + b"\x00"
    while len(buf) % 8:
        buf += b"\x00"
    blob_va = len(buf)
    buf += struct.pack("<QQQQ", 0, 0, len(entries), len(entries))   # 0x20 header
    for num, nm in entries:
        entry = bytearray(b"\x00" * stride)
        struct.pack_into("<QQQ", entry, 0, num, name_va[nm], len(nm))
        buf += entry
    return bytes(buf), blob_va


class TestMangledNameParse(unittest.TestCase):
    @staticmethod
    def _type(sym):
        """``(module, type_name)`` of a ``…_protobuf_nameMap`` symbol, or None."""
        parsed = S._parse_namemap_symbol(sym)
        return parsed and parsed[:2]

    def test_oracle_and_device_forms(self):
        self.assertEqual(
            self._type(
                "_$s6oracle9Ora_MultiV17_protobuf_nameMap13SwiftProtobuf05_NameG0VvgZ"),
            ("oracle", "Ora_Multi"))
        self.assertEqual(
            self._type(
                "_$s14bookdatastored15PBPropertyValueV17_protobuf_nameMap"
                "21InternalSwiftProtobuf05_NameF0VvgZ"),
            ("bookdatastored", "PBPropertyValue"))

    def test_nested_type_is_dotted(self):
        # module=M, Outer.Inner
        self.assertEqual(
            self._type(
                "_$s1M5OuterV5InnerV17_protobuf_nameMap13SwiftProtobufXX"),
            ("M", "Outer.Inner"))

    def test_non_namemap_returns_none(self):
        self.assertIsNone(self._type("_OBJC_CLASS_$_NSString"))
        self.assertIsNone(self._type("_$s1MV17_protobuf_nameMap"))  # <2 idents

    def test_split_idents(self):
        self.assertEqual(S._split_idents("6oracle9Ora_Multi"), ["oracle", "Ora_Multi"])
        self.assertEqual(S._split_idents("1M5OuterV5Inner"), ["M", "Outer", "Inner"])

    def test_word_substituted_identifier_with_zero_terminator(self):
        # `06ClientF0` = literal 'Client' + last-subst 'F' ('Metadata') closed by
        # an explicit '0'.  The terminator must not truncate the nested name: it
        # used to resolve to the PARENT's key (EscrowInformation.Metadata), so the
        # nested type silently collided with, and was lost behind, its parent.
        child = ("_$s18TrustedPeersHelper17EscrowInformationV8MetadataV06ClientF0V"
                 "17_protobuf_nameMap21InternalSwiftProtobuf05_NameJ0VvgZ")
        parent = ("_$s18TrustedPeersHelper17EscrowInformationV8MetadataV"
                  "17_protobuf_nameMap21InternalSwiftProtobuf05_NameI0VvgZ")
        self.assertEqual(self._type(child),
                         ("TrustedPeersHelper", "EscrowInformation.Metadata.ClientMetadata"))
        self.assertEqual(self._type(parent),
                         ("TrustedPeersHelper", "EscrowInformation.Metadata"))

    def test_word_substituted_wkt_name(self):
        # SwiftProtobuf's bundled well-known types mangle with word
        # substitution (B = 'Protobuf' from 'SwiftProtobuf'); the full name must
        # be recovered, not 'Google_._Any'.
        self.assertEqual(
            self._type(
                "_$s13SwiftProtobuf07Google_B4_AnyV17_protobuf_nameMap"
                "AA05_NameG0VvgZ"),
            ("SwiftProtobuf", "Google_Protobuf_Any"))


class TestStaticBlobScan(unittest.TestCase):
    def test_two_entries_stride_independent(self):
        for stride in (0x20, 0x38, 0x40):
            buf, blob = _build_static_blob([(1, "alpha"), (7, "beta")], stride)
            got = S._parse_static_blob(_FakeCtx(buf), blob)
            self.assertEqual([(f.number, f.name) for f in got],
                             [(1, "alpha"), (7, "beta")], f"stride {stride:#x}")

    def test_nondense_numbers(self):
        buf, blob = _build_static_blob([(2, "b"), (5, "big"), (9, "raw")], 0x38)
        got = S._parse_static_blob(_FakeCtx(buf), blob)
        self.assertEqual([(f.number, f.name) for f in got],
                         [(2, "b"), (5, "big"), (9, "raw")])

    def test_name_pointer_read_through_its_fixup(self):
        # a standalone binary's static blob holds chained-fixup words, not addresses: the
        # name is found through ctx.read_ptr at the slot, never by masking the raw word
        buf, blob = _build_static_blob([(3, "gamma")], 0x28)
        slot = blob + 0x20 + 8
        name_va = struct.unpack_from("<Q", buf, slot)[0]
        raw = bytearray(buf)
        struct.pack_into("<Q", raw, slot, 0x8010_0000_0000_0000 | name_va)   # an encoded rebase
        self.assertIsNone(S._parse_static_blob(_FakeCtx(bytes(raw)), blob))
        got = S._parse_static_blob(_FakeCtx(bytes(raw), {slot: name_va}), blob)
        self.assertEqual([(f.number, f.name) for f in got], [(3, "gamma")])

    def test_zero_count_returns_none(self):
        # a header counting 0 elements, followed by bytes that would parse as an element:
        # an empty array, not a one-field table
        buf, blob = _build_static_blob([(1, "alpha")], 0x28)
        raw = bytearray(buf)
        struct.pack_into("<QQ", raw, blob + 0x10, 0, 0)          # count, capacity
        self.assertIsNone(S._parse_static_blob(_FakeCtx(bytes(raw)), blob))

    def test_count_beyond_the_elements_returns_none(self):
        # a well-formed first element, but the header counts 4097: every element must parse,
        # so an array that ends after one is not read as a one-field table
        name = "alpha"
        count = 4097
        header = struct.pack("<QQQQ", 0, 0, count, count)
        name_va = len(header) + 24
        entry = struct.pack("<QQQ", 1, name_va, len(name))
        buf = header + entry + name.encode() + b"\x00"
        self.assertIsNone(S._parse_static_blob(_FakeCtx(buf), 0))
        # two elements (so a stride is found) and a header counting 3: the third must parse too
        buf, blob = _build_static_blob([(1, "alpha"), (2, "beta")], 0x28)
        raw = bytearray(buf)
        struct.pack_into("<QQ", raw, blob + 0x10, 3, 3)
        self.assertIsNone(S._parse_static_blob(_FakeCtx(bytes(raw)), blob))

    def test_unreadable_returns_none(self):
        # the header itself is unreadable (the buffer is shorter than its 0x20 bytes)
        self.assertIsNone(S._parse_static_blob(_FakeCtx(b"\x00" * 8), 0))


class _FI:
    """Minimal stand-in for a disassembled instruction (mnemonic + op_str)."""
    def __init__(self, mnemonic, op_str=""):
        self.mnemonic, self.op_str = mnemonic, op_str


class TestInlineClosureWalk(unittest.TestCase):
    """Entries are paired by ADDRESS (:func:`_table_entries`): the closure builds each
    ``(Int, _NameDescription)`` element ``E`` -- the number stored at ``E``, the name and its
    length at ``E`` plus the ``_NameDescription`` offset read from type metadata (CreateML /
    iOS 27 MessageProtection).  The name pointer is an ``adr`` or ``adrp``+``add``."""
    def _ctx(self):
        data = bytearray(0x40)
        data[0x10:0x14] = b"key\x00"
        data[0x20:0x25] = b"data\x00"
        return _FakeCtx(bytes(data))

    # x26 = element 0 (a call's result), x25 = the stride, [x21, #0x30] = the field offset
    _TWO = [
        ("ldrsw", "x8, [x21, #0x30]"), ("add", "x22, x26, x8"),
        ("mov", "w8, #1"), ("str", "x8, [x26]"),
        ("adrp", "x8, #0x0"), ("add", "x8, x8, #0x10"), ("mov", "w9, #3"),
        ("stp", "x8, x9, [x22]"),
        ("add", "x8, x26, x25"), ("ldrsw", "x9, [x21, #0x30]"), ("add", "x0, x8, x9"),
        ("mov", "w10, #2"), ("str", "x10, [x8]"),
        ("adr", "x8, #0x20"), ("mov", "w9, #4"), ("stp", "x8, x9, [x0]"),
    ]

    def test_adrp_add_and_adr_name_pointers(self):
        got = S._walk_inline_closure(self._ctx(), _listing(self._TWO))
        self.assertEqual([(f.number, f.name) for f in got], [(1, "key"), (2, "data")])

    def test_pairing_is_by_address_not_program_order(self):
        # both numbers stored first, then the names, the second element's first
        lines = [self._TWO[i] for i in (0, 1, 2, 3, 8, 9, 10, 11, 12, 13, 14, 15, 4, 5, 6, 7)]
        got = S._walk_inline_closure(self._ctx(), _listing(lines))
        self.assertEqual(sorted((f.number, f.name) for f in got), [(1, "key"), (2, "data")])

    def test_name_at_an_unrelated_address_is_not_paired(self):
        # the number at [x20], the name at [x21]: no address relation, no entry
        lines = [("mov", "w0, #1"), ("str", "x0, [x20]"), ("adrp", "x1, #0x0"),
                 ("add", "x1, x1, #0x10"), ("mov", "w2, #3"), ("stp", "x1, x2, [x21]")]
        self.assertEqual(S._walk_inline_closure(self._ctx(), _listing(lines)), [])

    def test_length_mismatch_rejected(self):
        lines = list(self._TWO[:8])
        lines[6] = ("mov", "w9, #9")                       # 9 != len("key")
        self.assertEqual(S._walk_inline_closure(self._ctx(), _listing(lines)), [])

    def test_builder_store_shapes(self):
        # remindd: A `stp <num>, <name>, [x0, #o]`, B `str <num>` + `str <name>` 8 bytes on,
        # and an enum value 0 stored from the zero register
        lines = [("adrp", "x8, #0x0"), ("add", "x8, x8, #0x10"), ("stp", "xzr, x8, [x0, #0x20]"),
                 ("mov", "w9, #1"), ("adr", "x8, #0x20"), ("stp", "x9, x8, [x0, #0x58]")]
        got = S._walk_namemap_builder(self._ctx(), _listing(lines), enum=True)
        self.assertEqual([(f.number, f.name) for f in got], [(0, "key"), (1, "data")])
        self.assertEqual([(f.number, f.name) for f in
                          S._walk_namemap_builder(self._ctx(), _listing(lines))], [(1, "data")])
        lines = [("mov", "w8, #9"), ("str", "x8, [x0, #0x218]"),
                 ("adr", "x8, #0x10"), ("str", "x8, [x0, #0x220]")]
        got = S._walk_namemap_builder(self._ctx(), _listing(lines))
        self.assertEqual([(f.number, f.name) for f in got], [(9, "key")])

    def test_template_reads_the_stub_arguments(self):
        # a builder stub hands name / length to a shared template that does the stores
        got = S._walk_namemap_builder(
            self._ctx(), _listing([("mov", "x20, x2"), ("mov", "x19, x3"),
                                   ("ldrsw", "x9, [x21, #0x30]"), ("add", "x23, x8, x9"),
                                   ("mov", "w9, #5"), ("str", "x9, [x8]"),
                                   ("stp", "x20, x19, [x23]")]),
            entry={"x2": 0x20, "x3": 4})
        self.assertEqual([(f.number, f.name) for f in got], [(5, "data")])



class _NamedListingCtx(NoImage):
    """A cache-style ctx over a hand-built listing whose call targets have export names, so
    :func:`FB.function_body`, Flow's call model and the call naming of
    :mod:`serializers.swift_symbols` run offline.  Every call target in a test needs a name (an
    unnamed own-image target would be scanned)."""
    is_cache_backed = True
    image_base = 0

    class _Reader:
        def __init__(self, names):
            self._names = names

        def export_name_at(self, va):
            return self._names.get(va)

        def image_symbol_addrs(self, base, *subs):
            return {}

        def image_exports(self, base):
            return {}

        def image_dependencies(self, base):
            return []

    def __init__(self, lines, names, base=0x1000):
        from tests._listing import layout
        self.order, self.fake = layout((base, lines))
        self._cache_reader = self._Reader(names)
        self._end = base + 4 * len(lines)

    def function_starts(self):
        return [self.order[0].addr, self._end]


_OTHER = "_swift_retain"
_VISIT = "_$s21InternalSwiftProtobuf7VisitorP{n}visit{l}{k}Field5value11fieldNumberyxKFTj"


def _visit(label, kind):
    return _VISIT.format(n=len(f"visit{label}{kind}Field"), l=label, k=kind)


def _traverse(lines, names, slots=None):
    """``{N: proto type or None}`` :func:`MC.visited_fields` reads off the listing, the visitor's
    witness-table slots named *slots* (offset -> requirement)."""
    from unittest import mock
    ctx = _NamedListingCtx(lines, names)
    with mock.patch.object(FB, "disasm", ctx.fake), \
            mock.patch.object(MC, "_visitor_slots", lambda ctx: dict(slots or {})):
        got = MC.visited_fields(ctx, 0x1000)
    return {n: [MC.decoded_type(v) for v in vs] for n, vs in got.items()}


class TestTraverseVisits(unittest.TestCase):
    """:func:`MC.visited_fields`: a call to a Visitor method -- named by its symbol, or through
    a ``blr`` by the visitor witness-table slot its target is loaded from -- gives the field
    number from the register its signature puts it in, and the field's type.  A call it cannot
    name visits nothing."""
    def test_named_visit_number_follows_the_value_registers(self):
        # String value in x0/x1 -> fieldNumber in x2, whatever else holds a small constant
        got = _traverse([("mov", "w2, #4"), ("mov", "w3, #9"), ("bl", "#0x3000")],
                        {0x3000: _visit("Singular", "String")})
        self.assertEqual(got, {4: ["string"]})

    def test_named_visit_gives_the_integer_encoding(self):
        got = _traverse([("mov", "w0, #3"), ("mov", "w1, #7"), ("bl", "#0x3000"),
                         ("mov", "w1, #8"), ("bl", "#0x3100"),
                         ("mov", "w0, #2"), ("bl", "#0x3200")],
                        {0x3000: _visit("Singular", "SInt32"),
                         0x3100: _visit("Repeated", "Fixed64"),
                         0x3200: _visit("Singular", "Double")})
        self.assertEqual(got, {7: ["sint32"], 8: ["repeated fixed64"], 2: ["double"]})

    def test_message_visit_without_its_metadata_has_no_type(self):
        got = _traverse([("mov", "w1, #5"), ("bl", "#0x3000")],
                        {0x3000: _visit("Singular", "Message")})
        self.assertEqual(got, {5: [None]})

    def test_unnamed_witness_call_visits_nothing(self):
        # a blr whose slot the image cannot name: no number is guessed from the immediates
        # set before it (the highest w register's, the guess this replaced)
        self.assertEqual(_traverse([("mov", "w2, #5"), ("mov", "x3, x22"), ("blr", "x8")], {}), {})
        self.assertEqual(_traverse([("mov", "w2, #3"), ("mov", "w10, #5"), ("mov", "w9, #7"),
                                    ("mov", "x3, x22"), ("blr", "x8")], {}), {})
        # nor through the visitor's witness table when that slot has no name
        self.assertEqual(_traverse([("ldr", "x8, [x2, #0x20]"), ("mov", "w1, #6"),
                                    ("blr", "x8")], {}, slots={0x28: _visit("Singular", "Bool")}),
                         {})

    def test_witness_table_slot_names_the_blr(self):
        got = _traverse([("ldr", "x8, [x2, #0x20]"), ("mov", "w1, #6"), ("blr", "x8")], {},
                        slots={0x20: _visit("Singular", "Bool")})
        self.assertEqual(got, {6: ["bool"]})

    def test_other_calls_contribute_nothing(self):
        # a non-Visitor call adds nothing, though x1 holds a constant (only a Visitor method's
        # number register is read)
        got = _traverse([("mov", "x1, #9"), ("bl", "#0x2000"), ("mov", "w1, #1"),
                         ("bl", "#0x3000"), ("mov", "w1, #2"), ("bl", "#0x3000")],
                        {0x2000: _OTHER, 0x3000: _visit("Singular", "Bool")})
        self.assertEqual(got, {1: ["bool"], 2: ["bool"]})


class TestNameMapBuilderValidation(unittest.TestCase):
    """The runtime-_NameMap reading is cross-validated: the cold-builder stp pair
    is `(smallInt, namePtr)` whose int is the field NUMBER in the older codegen
    but the name LENGTH in the newer packed-bytecode form, so the walker can
    mis-read lengths as numbers (e.g. nptocompaniond: 6=len'domain', 4='code');
    and every number the message's traverse visits must be in it."""
    def test_length_form_rejected(self):
        # every entry's number == len(name) -> the (length, ptr) packed form; the rejection
        # (a heuristic, kept by choice) is reported
        got = [S.SwiftField(6, "domain"), S.SwiftField(4, "code")]
        with self.assertLogs('proto.models', 'WARNING') as logs:
            self.assertFalse(S._namemap_builder_validated(NoImage(), got, None))
        self.assertIn('number == len(name) hit', logs.output[0])

    def test_one_entry_is_not_judged_by_its_length(self):
        # `string name = 4`: one entry says nothing of the form; decodeMessage checks it
        self.assertTrue(S._namemap_builder_validated(None, [S.SwiftField(4, "name")], None))

    def test_genuine_numbers_accepted(self):
        # numbers differ from name lengths, no oracle to contradict -> accept
        got = [S.SwiftField(1, "dsID"), S.SwiftField(2, "baseURL")]
        self.assertTrue(S._namemap_builder_validated(None, got, None))
        self.assertTrue(S._namemap_builder_validated(None, got, set()))
        # one entry whose number happens to equal its name's length: not every entry -> accept
        got.append(S.SwiftField(4, "code"))
        self.assertTrue(S._namemap_builder_validated(None, got, None))

    def test_oracle_subset_of_recovered_accepted(self):
        # traverse visits {1,2}; the reading recovered a strict SUPERSET {1,2,3} -> accept
        got = [S.SwiftField(1, "dsID"), S.SwiftField(2, "baseURLX"), S.SwiftField(3, "extra")]
        self.assertTrue(S._namemap_builder_validated(None, got, {1, 2}))

    def test_oracle_contradiction_rejected(self):
        # traverse visits {1,2,5} but the reading only recovered {1,2} -> reject
        got = [S.SwiftField(1, "dsID"), S.SwiftField(2, "baseURLX")]
        self.assertFalse(S._namemap_builder_validated(None, got, {1, 2, 5}))

    def _extract(self, visited):
        """:func:`S._extract_namemap` of a getter whose runtime builder reads {1, 2, 3}, its
        message's traverse visiting *visited*."""
        from unittest import mock
        ctx = _NamedListingCtx([("ret", "")], {})
        read = [(1, "a_field"), (2, "b_field"), (3, "c_field")]
        visits = {n: [MC.Visited("Singular", "Int32")] for n in visited}
        with mock.patch.object(FB, "disasm", ctx.fake), \
                mock.patch.object(S, "_read_runtime", lambda *a, **k: S._Reading(
                    [S.SwiftField(*e) for e in read], "runtime-namemap")), \
                mock.patch.object(MC, "visited_fields", lambda ctx, code: visits):
            got, shape = S._extract_namemap(ctx, 0x1000, MC.Code(0x2000), owner="Mod.M")
        return [(f.number, f.name) for f in got], shape

    def test_a_reading_missing_a_visited_number_is_not_emitted(self):
        # traverse visits 4, the reading has no 4: it is not this message's table
        self.assertEqual(self._extract({1, 2, 3, 4}), ([], "none"))
        self.assertEqual(self._extract({1, 3}),
                         ([(1, "a_field"), (2, "b_field"), (3, "c_field")], "runtime-namemap"))


class TestUnlistedVisitedNumbersReported(unittest.TestCase):
    """A reading with no check of its own (here a bytecode literal) that lacks a number
    traverse visits is emitted, and the message's analysis failure says so."""
    def test_reported(self):
        from unittest import mock
        import serializers.swift_type_recovery as TR
        from proto.models import get_diagnostics
        m = S.SwiftMessage("Mod", "M", fields=[S.SwiftField(n, f"f{n}") for n in (1, 2, 3)],
                           shape="bytecode")
        ctx = type("Ctx", (), {})()
        visits = {n: [MC.Visited("Singular", "Int32")] for n in (1, 2, 3, 4)}
        with mock.patch.object(MC, "message_witnesses", lambda ctx: {}), \
                mock.patch.object(MC, "visited_fields", lambda ctx, code: visits), \
                mock.patch.object(TR, "collect_field_types", lambda ctx: ({}, {}, set(), {})):
            S._attach_types(ctx, [m], {("Mod", "M"): MC.Code(0x2000)})
        self.assertEqual(get_diagnostics(ctx).analysis_failures,
                         [("Mod.M", "swift name map",
                           "traverse visits [4], the name map does not list them")])
        self.assertEqual([(f.number, f.proto_type) for f in m.fields],
                         [(1, "int32"), (2, "int32"), (3, "int32")])


class TestSharedOnceInitTargets(unittest.TestCase):
    """Shape D getter gate (:func:`_shared_once_init_targets`).  The once-token and
    storage slot are in ``__DATA`` and often beyond ``adr`` reach, so the compiler
    emits them as ``adrp``+``add``; that must still count as the minimal
    straight-line dispatch (iOS 16 TrustedPeersHelper: 72 messages read as empty
    until it did)."""

    def test_adr_only_form(self):
        insns = [("adr", "x0, #0x100"), ("adr", "x1, #0x200"),
                 ("adr", "x2, #0x300"), ("nop", ""), ("b", "#0x400")]
        self.assertEqual(S._shared_once_init_targets(_listing(insns)), [0x100, 0x200, 0x300])

    def test_adrp_add_token_and_slot_with_adr_builder(self):
        # the verbatim TrustedPeersHelper EstablishRequest getter
        insns = [("adrp", "x0, #0x1001e7000"), ("add", "x0, x0, #0x5d8"),
                 ("adrp", "x1, #0x1001f3000"), ("add", "x1, x1, #0xcd8"),
                 ("adr", "x2, #0x100071e9c"), ("nop", ""),
                 ("b", "#0x100087efc")]
        got = S._shared_once_init_targets(_listing(insns))
        self.assertIn(0x100071E9C, got)               # the builder
        self.assertIn(0x1001E7000 + 0x5D8, got)       # token (data; caller filters)
        self.assertIn(0x1001F3000 + 0xCD8, got)       # storage slot (data)

    def test_builder_materialised_by_adrp_add(self):
        insns = [("adr", "x0, #0x100"), ("adr", "x1, #0x200"),
                 ("adrp", "x2, #0x7000"), ("add", "x2, x2, #0x1c"),
                 ("b", "#0x400")]
        self.assertIn(0x701C, S._shared_once_init_targets(_listing(insns)))

    def test_add_without_adrp_page_is_ignored(self):
        insns = [("add", "x0, x0, #0x10"), ("adr", "x2, #0x300"),
                 ("b", "#0x400")]
        self.assertEqual(S._shared_once_init_targets(_listing(insns)), [0x300])

    def test_inline_fast_path_getter_still_rejected(self):
        # #74 regression guard: a once-init getter with its own cmn/b.ne fast path
        # is the runtime-_NameMap shape, not shape D -- even though it contains
        # adrp/add/adr and ends in a tail call.
        insns = [("adrp", "x8, #0x1001f3000"), ("ldr", "x8, [x8, #0x60]"),
                 ("cmn", "x8, #1"), ("b.ne", "#0x500"),
                 ("adr", "x1, #0x300"), ("b", "#0x400")]
        self.assertEqual(S._shared_once_init_targets(_listing(insns)), [])

    def test_no_tail_branch_rejected(self):
        self.assertEqual(S._shared_once_init_targets(
            _listing([("adr", "x0, #0x100"), ("nop", "")])), [])


class _TextCtx:
    """Just enough ctx for :func:`proto.callees.text_holding`: one __TEXT,__text section."""
    class _Sec:
        vmaddr, vmsize = 0x1000, 0x1000

    def has_section(self, seg, name):
        return (seg, name) == ("__TEXT", "__text")

    def section(self, seg, name):
        return self._Sec()


class TestClosureArgTargets(unittest.TestCase):
    """``_closure_arg_targets``: the code addresses a listing hands a callee -- the once-init
    closure ``swift_once`` gets in x1, ``adr`` when near and ``adrp``+``add`` when far (device /
    cache images -- SeymourCore, SiriOntology, NewsPersonalization: ~300 messages read as empty
    before)."""
    def test_adr_closure(self):
        insns = _listing([("adr", "x1, #0x1200"), ("blr", "x8")])
        self.assertEqual(S._closure_arg_targets(_TextCtx(), insns), [0x1200])

    def test_adrp_add_closure_in_text(self):
        insns = _listing([("adrp", "x1, #0x1000"), ("add", "x1, x1, #0xcf8"), ("blr", "x8")])
        self.assertEqual(S._closure_arg_targets(_TextCtx(), insns), [0x1CF8])

    def test_data_token_not_taken_as_closure(self):
        # the swift_once token (x0) and a once-storage address outside __text
        insns = _listing([("adrp", "x0, #0x9000"), ("add", "x0, x0, #0"),
                          ("adrp", "x1, #0x9000"), ("add", "x1, x1, #0x40"), ("blr", "x8")])
        self.assertEqual(S._closure_arg_targets(_TextCtx(), insns), [])

    def test_code_address_not_passed_to_a_call_ignored(self):
        insns = _listing([("adrp", "x9, #0x1000"), ("add", "x9, x9, #0x10"), ("blr", "x8")])
        self.assertEqual(S._closure_arg_targets(_TextCtx(), insns), [])

class TestSharedOnceInitTargetsArm64e(unittest.TestCase):
    """arm64e (iOS 27): the builder pointer is signed before being passed --
    ``adrp/add x16,<builder>; paciza x16; mov x2,x16; b <template>``."""
    def _getter(self):
        return [("adrp", "x0, #0x100345000"), ("add", "x0, x0, #0x560"),
                ("adrp", "x1, #0x10035f000"), ("add", "x1, x1, #0x7f8"),
                ("adrp", "x16, #0x1000f4000"), ("add", "x16, x16, #0x390"),
                ("paciza", "x16"), ("mov", "x2, x16"), ("b", "#0x10011a25c")]

    def test_signed_builder_pointer_is_returned(self):
        self.assertIn(0x1000F4390, S._shared_once_init_targets(_listing(self._getter())))

    def test_still_rejects_conditional_control_flow(self):
        g = self._getter()
        g.insert(6, ("cmn", "x8, #1"))
        g.insert(7, ("b.ne", "#0x500"))
        self.assertEqual(S._shared_once_init_targets(_listing(g)), [])

    def test_is_a_pure_stub(self):
        self.assertIsNotNone(S._tail_call_args(_listing(self._getter())))


def _ios27_tph_path():
    try:
        import artifacts
        p = os.path.join(artifacts.REPO_ROOT, "ios27_data", "ipsw_extract", "24A446__iPhone17,3", "System",
                         "Library", "Frameworks", "Security.framework", "XPCServices",
                         "TrustedPeersHelper.xpc", "TrustedPeersHelper")
        return p if os.path.isfile(p) else None
    except Exception:
        return None


@unittest.skipUnless(_ios27_tph_path(), "iOS 27.0.1 TrustedPeersHelper (ipsw extract) not available")
class TestLiveIos27TrustedPeersHelper(unittest.TestCase):
    """iOS 27.0.1 (arm64e) service: the getter is the signed-pointer shared-once form and the
    builder is a stub that passes a packed-bytecode literal, so every message was empty
    before.  iOS 16.7.11's service has no `metrics` field; this one does."""
    @classmethod
    def setUpClass(cls):
        ctx = _load_ctx(_ios27_tph_path())
        cls.msgs = {m.name: m for m in S.swift_messages(ctx)}
        cls.enums = {e.name: e for e in S.swift_enums(ctx)}

    def test_everything_is_read_or_proven_empty(self):
        self.assertEqual(len(self.msgs), 76)
        self.assertEqual(sum(1 for m in self.msgs.values() if m.fields), 73)
        self.assertTrue(all(m.fieldless for m in self.msgs.values() if not m.fields))
        self.assertEqual(len(self.enums), 12)
        self.assertTrue(all(e.fields for e in self.enums.values()))
        self.assertEqual({m.shape for m in self.msgs.values() if m.fields}, {"bytecode"})

    def test_metrics_field_exists_in_ios27(self):
        self.assertEqual(_fieldset(self.msgs["FetchViableBottlesRequest"]),
                         {(1, "filter_request"), (2, "metrics"), (3, "accountInfo")})
        self.assertEqual(_fieldset(self.msgs["Metrics"]), {(1, "flow_id"), (2, "device_session_id")})

    def test_join_with_voucher_fields_6_to_8(self):
        got = _fieldset(self.msgs["JoinWithVoucherRequest"])
        self.assertTrue({(6, "trusted_devices_version"), (7, "metrics"), (8, "accountInfo")} <= got)
        self.assertEqual({n for n, _ in got}, set(range(1, 9)))


class TestFatSlice(unittest.TestCase):
    def _fat(self, slices):
        # slices: list of (cputype, cpusubtype, payload)
        n = len(slices)
        header = struct.pack(">II", 0xCAFEBABE, n)
        offs = []
        cur = 8 + n * 20
        descs = b""
        for cputype, cpusub, payload in slices:
            descs += struct.pack(">IIIII", cputype, cpusub, cur, len(payload), 0)
            offs.append(cur)
            cur += len(payload)
        out = header + descs
        for (_, _, payload), o in zip(slices, offs):
            assert len(out) == o
            out += payload
        return out

    def test_picks_arm64e_over_arm64(self):
        a64 = b"ARM64_SLICE_____"
        a64e = b"ARM64E_SLICE____"
        fat = self._fat([(0x0100000C, 0, a64), (0x0100000C, 2, a64e)])
        self.assertEqual(S.load_macho_slice(fat), a64e)
        # in either order, and with the CPU_SUBTYPE_PTRAUTH_ABI bit a real arm64e slice
        # carries (0x80000002); arm64 v8 (subtype 1) is not arm64e
        for slices in ([(0x0100000C, 0x80000002, a64e), (0x0100000C, 0, a64)],
                       [(0x0100000C, 0, a64), (0x0100000C, 0x80000002, a64e)],
                       [(0x0100000C, 1, a64), (0x0100000C, 2, a64e)]):
            self.assertEqual(S.load_macho_slice(self._fat(slices)), a64e, slices)

    def test_thin_passthrough(self):
        thin = b"\xcf\xfa\xed\xfe" + b"\x00" * 60
        self.assertEqual(S.load_macho_slice(thin), thin)


# ── live: remindd device binary ───────────────────────────────────────────────

def _data_path(*rel):
    try:
        import artifacts
        cand = os.path.join(artifacts.data_dir(), *rel)
        return cand if os.path.isfile(cand) else None
    except Exception:
        return None


_NPTO = ("libexec", "nptocompaniond")


def _remindd_path():
    p = os.environ.get("MACHO_TEST_REMINDD", "").strip()
    if p:
        return p if os.path.isfile(p) else None
    return _data_path("libexec", "remindd")


def _trustedpeershelper_path():
    """iOS 16.7.11 TrustedPeersHelper.xpc (Cuttlefish/Octagon keychain-trust
    swift-protobuf messages) from the iPhone 8 disk image (``artifacts.disk_image_dir()``;
    skipped when it is not there).  ``MACHO_TEST_TRUSTEDPEERSHELPER``
    overrides."""
    p = os.environ.get("MACHO_TEST_TRUSTEDPEERSHELPER", "").strip()
    if p:
        return p if os.path.isfile(p) else None
    try:
        import artifacts
        cand = os.path.join(
            artifacts.disk_image_dir(), "System",
            "Library", "Frameworks", "Security.framework", "XPCServices",
            "TrustedPeersHelper.xpc", "TrustedPeersHelper")
        return cand if os.path.isfile(cand) else None
    except Exception:
        return None


def _swift_oracle_path():
    try:
        import artifacts
        p = artifacts.swift_oracle_path()
        return p if os.path.isfile(p) else None
    except Exception:
        return None


def _load_ctx(path):
    from macho.memory import BinaryContext
    with open(path, "rb") as fh:
        return BinaryContext(S.load_macho_slice(fh.read()))


def _msgs_by_name(path):
    return {m.name: m for m in S.swift_messages(_load_ctx(path))}


def _fieldset(msg):
    return {(f.number, f.name) for f in msg.fields}


def _decode_message_numbers_oracle(ctx, va):
    """INDEPENDENT oracle: the field numbers decodeMessage switches on — dense
    jump table ``sub xN,x0,#lo ; cmp xN,#span ; … ; br xN`` => lo..lo+span, plus
    explicit ``cmp/subs xN,#K``.  Emitted by different codegen than the nameMap,
    so it must never switch on a number the nameMap lacks."""
    from macho.disasm import disasm
    import re as _re
    try:
        insns = disasm(ctx, va, max_insns=500, stop_at_ret=True)
    except Exception:
        return set()
    nums, sub_lo = set(), {}
    for i, ins in enumerate(insns):
        if ins.mnemonic == "sub":
            m = _re.match(r"(\w+),\s*(x0|w0),\s*#(0x[0-9a-f]+|\d+)$", ins.op_str)
            if m:
                sub_lo[m.group(1)] = int(m.group(3), 0)
        elif ins.mnemonic in ("cmp", "subs"):
            m = _re.match(r"(\w+),\s*#(0x[0-9a-f]+|\d+)", ins.op_str)
            if not m:
                continue
            reg, k = m.group(1), int(m.group(2), 0)
            if reg in sub_lo and any(n.mnemonic == "br" for n in insns[i:i + 8]):
                nums.update(range(sub_lo[reg], sub_lo[reg] + k + 1))
            elif reg in ("x0", "w0", "x16", "w16") and 1 <= k <= S.MAX_FIELD_NUMBER:
                nums.add(k)
    return nums


@unittest.skipUnless(_remindd_path(), "remindd binary not available")
class TestLiveRemindd(unittest.TestCase):
    """libexec remindd — the device swift-protobuf workhorse (45 messages).
    Replaces the retired bookdatastored / DPSubmissionService corpora: this dump's
    builds of those daemons no longer ship swift-protobuf (BookDataStore moved to
    Coherence/CRDT).  remindd exercises the same live nameMap/number/shape paths;
    exhaustive field + type pins live in test_swift_ground_truth.TestRuntimeNameMap."""
    @classmethod
    def setUpClass(cls):
        cls.msgs = _msgs_by_name(_remindd_path())

    def test_dense_multifield_message(self):
        # Google_Protobuf_Field — 10 fields incl. the #11 split-str-tail builder
        # store-shape; numbers non-contiguous (no #5).
        self.assertEqual(
            [(f.number, f.name)
             for f in sorted(self.msgs["Google_Protobuf_Field"].fields,
                             key=lambda x: x.number)],
            [(1, "kind"), (2, "cardinality"), (3, "number"), (4, "name"),
             (6, "type_url"), (7, "oneof_index"), (8, "packed"), (9, "options"),
             (10, "json_name"), (11, "default_value")])

    def test_nested_type_message(self):
        self.assertEqual(
            _fieldset(self.msgs["MigrateResponse.Details"]),
            {(1, "time_elapsed"), (2, "is_observer"),
             (3, "lists_migrated"), (4, "reminders_migrated")})

    def test_well_known_wrappers_single_runtime_entry(self):
        # BoolValue & co: a runtime-built name map with ONE entry, reached through a closure
        # that is only a stub tail-calling the real builder.  Held back before (the
        # single-field path found nothing), and confirmed against reflection now.
        for name, typ in (("Google_Protobuf_BoolValue", "bool"), ("Google_Protobuf_StringValue", "string"),
                          ("Google_Protobuf_Int64Value", "int64"), ("Google_Protobuf_DoubleValue", "double")):
            self.assertEqual(_fieldset(self.msgs[name]), {(1, "value")}, name)
            self.assertEqual(self.msgs[name].fields[0].proto_type, typ)

    def test_empty_message(self):
        # A message whose nameMap carries no entries recovers as zero fields —
        # not an error, not a spurious field.
        self.assertEqual(self.msgs["Google_Protobuf_Empty"].fields, [])
        self.assertTrue(self.msgs["Google_Protobuf_Empty"].fieldless)   # reflection agrees
        # UnmigrateRequest was long believed empty (its runtime name map has ONE entry, which
        # the extractor declined to read).  It is not: the struct has `options: UInt32`,
        # decodeMessage switches on field 1 and traverse visits 1.
        self.assertEqual(_fieldset(self.msgs["UnmigrateRequest"]), {(1, "options")})

    def test_numbers_confirmed(self):
        m = self.msgs["StartMigrationRequest.Credential"]
        self.assertEqual(sorted(f.number for f in m.fields), [1, 2, 3, 4, 5])
        self.assertTrue(all(f.number_confirmed for f in m.fields))


@unittest.skipUnless(_data_path(*_NPTO), "nptocompaniond not available")
class TestLiveNptoCompanion(unittest.TestCase):
    """libexec standalone daemon."""
    def test_error_response(self):
        msgs = _msgs_by_name(_data_path(*_NPTO))
        self.assertEqual(_fieldset(msgs["ErrorResponse"]), {(1, "domain"), (2, "code")})


def _dpsubmission_path():
    p = os.environ.get("MACHO_TEST_DPSUBMISSION", "").strip()
    if p:
        return p if os.path.isfile(p) else None
    return _data_path("DPSubmissionService")


@unittest.skipUnless(_dpsubmission_path(), "DPSubmissionService binary not available")
class TestLiveDPSubmission(unittest.TestCase):
    """DPSubmissionService.xpc — shape-D (shared once-init template) ground
    truth: every message here reaches its (number, name) table via a tail-call
    into a builder shared across unrelated types (``adr x0,<token>; adr
    x1,<storage>; adr x2,<builder>; b <shared-template>``), not via the
    inline/runtime shapes remindd/nptocompaniond exercise.  Restores the
    corpus e4d3d76 retired as "schema drift" -- the real cause was this then-
    unhandled shape (#74)."""
    @classmethod
    def setUpClass(cls):
        cls.msgs = _msgs_by_name(_dpsubmission_path())

    def test_dense_multifield_message(self):
        self.assertEqual(
            [(f.number, f.name)
             for f in sorted(self.msgs["DediscoDonation"].fields, key=lambda x: x.number)],
            [(1, "collection_id"), (2, "algorithm"), (3, "algorithm_parameters"),
             (4, "fs_encrypted_share"), (5, "ds_encrypted_share"), (6, "fs_public_key"),
             (7, "ds_public_key"), (8, "version_hash"), (9, "report")])
        self.assertEqual(self.msgs["DediscoDonation"].shape, "shared-once")

    def test_single_field_message(self):
        self.assertEqual(_fieldset(self.msgs["CollectionID"]), {(1, "collection_id")})

    def test_nested_type_message(self):
        self.assertEqual(
            _fieldset(self.msgs["DediscoDonation.AlgorithmParameters"]),
            {(1, "dimension"), (2, "epsilon"), (3, "other_params")})
        self.assertEqual(self.msgs["DediscoDonation.AlgorithmParameters"].shape, "shared-once")

    def test_empty_message(self):
        self.assertEqual(self.msgs["Empty"].fields, [])

    def test_two_hop_builder_shape(self):
        # ProtectedDonation's builder is itself an arg-setup stub tail-calling
        # a second shared template (the two-stub form of shape D, #74) that
        # ISN'T laid out contiguously with it, unlike CollectionID's -- this
        # is the case that needs _builder_entries' explicit follow
        # rather than falling out of a single linear disasm.
        self.assertEqual(_fieldset(self.msgs["ProtectedDonation"]),
                          {(1, "baa_signed_donation_envelope")})


@unittest.skipUnless(_trustedpeershelper_path(), "TrustedPeersHelper binary not available")
class TestLiveTrustedPeersHelper(unittest.TestCase):
    """iOS 16.7.11 TrustedPeersHelper.xpc -- Cuttlefish/Octagon (``InternalSwiftProtobuf``
    fork).  Shape D with ``adrp``+``add``-materialised once-token/storage and
    unoptimised builders (name via ``adrp``+``add``, entry address computed from the
    value-witness stride).  Before the gate fix every message here came back empty.

    Field NUMBERS are cross-checked loosely against the published hand-written
    Cuttlefish descriptor (rustpush ``cloudkit.proto``, a different version, so
    equality is expected only where the messages did not change) and strictly
    against the independent ``traverse`` visit numbers (must be a subset)."""
    @classmethod
    def setUpClass(cls):
        cls.ctx = _load_ctx(_trustedpeershelper_path())
        cls.msgs = {m.name: m for m in S.swift_messages(cls.ctx)}

    def test_establish_request(self):
        self.assertEqual(_fieldset(self.msgs["EstablishRequest"]),
                         {(1, "peer"), (2, "bottle"), (3, "view_keys"), (4, "tlk_shares")})
        self.assertEqual(self.msgs["EstablishRequest"].shape, "shared-once")

    def test_fetch_changes_request(self):
        self.assertEqual(_fieldset(self.msgs["FetchChangesRequest"]), {(1, "change_token")})

    def test_update_trust_request_matches_published_cuttlefish(self):
        # rustpush cloudkit.proto CuttlefishUpdateTrustRequest: restorePoint=1,
        # peerId=2, stableInfo=3, dynamicInfo=4, tlkshares=5, viewKeys=6.  Names 2, 5 and 6
        # are the published ones; this version names 1, 3 and 4 otherwise.
        got = {f.number: f.name for f in self.msgs["UpdateTrustRequest"].fields}
        self.assertEqual(got, {1: "change_token", 2: "peer_id", 3: "stable_info_and_sig",
                               4: "dynamic_info_and_sig", 5: "tlk_shares", 6: "view_keys"})

    def test_nested_word_substituted_type_not_lost(self):
        # EscrowInformation.Metadata.ClientMetadata's symbol uses `06ClientF0`; it
        # must be its own message, distinct from (not merged into) its parent.
        self.assertIn("EscrowInformation.Metadata.ClientMetadata", self.msgs)
        parent = _fieldset(self.msgs["EscrowInformation.Metadata"])
        child = _fieldset(self.msgs["EscrowInformation.Metadata.ClientMetadata"])
        self.assertEqual(len(parent), 8)
        self.assertGreaterEqual(len(child), 12)
        self.assertIn((7, "device_mid"), child)

    def test_genuinely_empty_messages_stay_empty(self):
        for name in ("ReportHealthResponse", "PushHealthInquiryRequest",
                     "ValidatePeersRequest", "GetSupportAppInfoRequest"):
            self.assertEqual(self.msgs[name].fields, [], name)

    def test_every_empty_message_is_proven_empty_by_reflection(self):
        # none of the 9 is merely unread: Swift reflection lists no stored proto field
        empty = [m for m in self.msgs.values() if not m.fields]
        self.assertEqual(len(empty), 9)
        self.assertTrue(all(m.fieldless for m in empty), [m.name for m in empty if not m.fieldless])
        self.assertFalse(any(m.fieldless for m in self.msgs.values() if m.fields))

    def test_most_messages_recovered(self):
        # 64/73 have fields; the other 9 are empty request/response stubs.
        with_fields = sum(1 for m in self.msgs.values() if m.fields)
        self.assertGreaterEqual(with_fields, 60)

    def test_every_field_type_is_defined_or_degraded(self):
        # what protoc checks: each non-scalar field type must name a message the
        # output defines (flat name), else the field must have degraded to bytes/int32.
        from proto import foreign as F
        out = F.swift_messages(self.ctx)
        defined = {m.name for m in out} | {e.name for m in out for e in m.enums}
        for m in out:
            for f in m.fields:
                t = f.type_name
                if t.startswith("map<"):
                    t = t[4:-1].partition(", ")[2]
                if t in F.SCALAR_TYPES:
                    continue
                self.assertIn(t, defined, f"{m.name}.{f.name}: {t}")
        # the references that used to be undefined
        by = {m.name: {f.name: f for f in m.fields} for m in out}
        self.assertEqual(by["EscrowInformation_Metadata"]["client_metadata"].type_name,
                         "EscrowInformation_Metadata_ClientMetadata")
        # an enum whose cases were recovered is defined in the output and referenced by name
        self.assertEqual(by["EscrowInformation"]["record_status"].type_name, "RecordStatus")
        self.assertIn("RecordStatus", {e.name for m in out for e in m.enums})
        self.assertEqual(by["EscrowInformation_Metadata"]["secure_backup_timestamp"].type_name,
                         "bytes")

    def test_traverse_numbers_never_contradict_namemap(self):
        # every message's traverse is its Message conformance's witness; each number it visits
        # is in the name map
        witnesses = S._witnesses(self.ctx)
        checked = 0
        for m in self.msgs.values():
            if not m.fields:
                continue
            seen = set(MC.visited_fields(self.ctx, witnesses[m.name]["traverse"]))
            self.assertLessEqual(seen, {f.number for f in m.fields}, m.name)
            checked += bool(seen)
        self.assertGreaterEqual(checked, 60)     # 64 (the cross-check actually ran)


def _seymourcore_path():
    try:
        import artifacts
        p = os.path.join(artifacts.data_dir(), "dylib", "System", "Library",
                         "PrivateFrameworks", "SeymourCore.framework", "SeymourCore")
        return p if os.path.isfile(p) else None
    except Exception:
        return None


@unittest.skipUnless(_seymourcore_path(), "SeymourCore image not available")
class TestLiveSeymourCoreClosureViaAdrpAdd(unittest.TestCase):
    """Device-form once-init getter (``cmn; b.ne``) whose swift_once closure is
    loaded by ``adrp``+``add`` (too far for ``adr``): previously 200 of 229
    messages in this image came back empty."""
    @classmethod
    def setUpClass(cls):
        cls.msgs = _msgs_by_name(_seymourcore_path())

    def test_two_field_message(self):
        self.assertEqual(
            _fieldset(self.msgs["CatalogEditorialCollectionDetailAnnotationProtobuf"]),
            {(1, "editorialCollection"), (2, "tileDescriptors")})

    def test_most_messages_recovered(self):
        # every one of the image's 229, each with its fields
        self.assertEqual(len(self.msgs), 229)
        self.assertEqual(sum(1 for m in self.msgs.values() if m.fields), 229)


def _ios27_cache_file():
    try:
        import artifacts
        p = os.path.join(artifacts.REPO_ROOT, "ios27_data", "dylib", "dyld_shared_cache_arm64e")
        return p if os.path.isfile(p + ".symbols") else None
    except Exception:
        return None


@unittest.skipUnless(_ios27_cache_file(), "iOS 27 cache (+ .symbols) not available")
class TestLiveIos27PackedBytecode(unittest.TestCase):
    """iOS 27 ``_NameMap(bytecode:)`` (shape E), cache-native.  Before it, every
    message in these images came back empty."""
    @classmethod
    def setUpClass(cls):
        from macho.dyld_cache import DyldCacheReader
        from macho.memory import BinaryContext
        cls.reader = DyldCacheReader(_ios27_cache_file())
        cls.msgs = {}
        for fw in ("CipherML", "WorkoutKit"):
            ctx = BinaryContext.from_cache(cls.reader, cls.reader.resolve_image(fw))
            cls.msgs[fw] = {m.name: m for m in S.swift_messages(ctx)}

    @classmethod
    def tearDownClass(cls):
        try:
            cls.reader.close()
        except Exception:
            pass

    def test_sequential_numbers(self):
        m = self.msgs["CipherML"]["AspireApiEvaluationKeyMetadata"]
        self.assertEqual(_fieldset(m), {(1, "timestamp"), (2, "identifier")})
        self.assertEqual(m.shape, "bytecode")

    def test_delta_encoded_numbers(self):
        m = self.msgs["WorkoutKit"]["Apple_Workout_WorkoutPlan"]
        nums = {f.name: f.number for f in m.fields}
        self.assertEqual(nums["id"], 9)
        self.assertEqual(nums["route"], 100)
        self.assertEqual(nums["majorVersion"], 1000)
        self.assertEqual(nums["privateVersion"], 1002)

    def test_inline_getter_form(self):
        # reached via `bl _NameMap.init(bytecode:)` inside the getter, no tail call
        m = self.msgs["WorkoutKit"]["Apple_Workout_WorkoutConfiguration"]
        self.assertEqual(_fieldset(m), {(1, "activity"), (2, "location"), (3, "swimmingLocation")})
        self.assertEqual(m.shape, "bytecode")

    def test_bytecode_names_match_reflection_names(self):
        # independent source: __swift5_fieldmd.  (Reflection renames a proto field
        # `has_x` to `hasXp`, so compare only names reflection did not rename.)
        from serializers import swift_type_recovery as TR
        from macho.memory import BinaryContext
        ctx = BinaryContext.from_cache(self.reader, self.reader.resolve_image("CipherML"))
        by_type = TR.collect_field_types(ctx).types
        checked = 0
        for name, m in self.msgs["CipherML"].items():
            fm = {k.replace("_", "").lower() for k, t in by_type.get(name, {}).items()
                  if not t.split(".")[-1].startswith("OneOf_")}      # oneof wrapper property, not a field
            got = {f.name.replace("_", "").lower() for f in m.fields}
            if m.shape == "bytecode" and fm and not any(n.startswith("has") for n in got):
                self.assertEqual(got, fm, name)
                checked += 1
        self.assertGreater(checked, 30)


@unittest.skipUnless(_ios27_cache_file(), "iOS 27 cache (+ .symbols) not available")
class TestLiveIos27PromptKitOutlinedHelpers(unittest.TestCase):
    """iOS 27 PromptKit's Candidate{Annotation,Audio,File,Image}Event share one name-map
    builder whose entry 4 reloads x2 / x3, spilled by two machine-outlined helpers: a prologue
    that moves sp (``sub sp, sp, #0x80 ; stp ... ; ret``) and a thunk (``stp x2, x3, [sp,
    #0x10] ; ... ; <LR check> ; b <metadata accessor>``).  Both run in the caller; taken as
    calls, entry 4 was lost."""
    @classmethod
    def setUpClass(cls):
        from macho.dyld_cache import DyldCacheReader
        from macho.memory import BinaryContext
        cls.reader = DyldCacheReader(_ios27_cache_file())
        ctx = BinaryContext.from_cache(cls.reader, cls.reader.resolve_image("PromptKit"))
        cls.msgs = {m.name: m for m in S.swift_messages(ctx)}

    @classmethod
    def tearDownClass(cls):
        try:
            cls.reader.close()
        except Exception:
            pass

    def test_candidate_annotation_event_has_its_four_fields(self):
        m = self.msgs["Promptkit_Wireformat_CandidateAnnotationEvent"]
        self.assertEqual([(f.number, f.name, f.proto_type, f.number_confirmed) for f in m.fields],
                         [(1, "response_identifier", "string", True),
                          (2, "candidate_identifier", "string", True),
                          (3, "segment_index", "int32", True),
                          (4, "annotation", "Promptkit_Wireformat_Annotation", True)])
        self.assertEqual(m.shape, "shared-once")

    def test_the_other_events_of_the_builder_have_field_4(self):
        for event, name in (("Audio", "audio"), ("File", "file"), ("Image", "image")):
            m = self.msgs[f"Promptkit_Wireformat_Candidate{event}Event"]
            self.assertEqual({(f.number, f.name) for f in m.fields},
                             {(1, "response_identifier"), (2, "candidate_identifier"),
                              (3, "segment_index"), (4, name)}, event)


def _enum_oracle(name):
    p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "swift_enum_oracle_fixture", name)
    return p if os.path.isfile(p) else None


# Ground truth: tests/swift_enum_oracle_fixture/enum_oracle.proto (compiled by a real
# protoc + protoc-gen-swift + Swift compiler).
_ORACLE_ENUMS = {
    "Eo_Top": {(-5, "T_NEG"), (0, "T_ZERO"), (1, "T_ONE"), (100000, "T_BIG")},
    "Eo_NonZero": {(1, "NZ_FIRST"), (7, "NZ_SEVEN")},
    "Eo_Single": {(4, "SINGLE_ONLY")},
    "Eo_Holder.Inner": {(0, "I_A"), (3, "I_B")},
}
_ORACLE_ALIASED = {(0, "AL_X"), (1, "AL_Y"), (1, "AL_Y2"), (2, "AL_Z")}


class _EnumOracleBase:
    BINARY = None
    SHAPE = None
    ALIASED = None

    @classmethod
    def setUpClass(cls):
        cls.ctx = _load_ctx(_enum_oracle(cls.BINARY))
        cls.enums = {e.name: e for e in S.swift_enums(cls.ctx) if e.module == "eo"}
        cls.msgs = {m.name: m for m in S.swift_messages(cls.ctx) if m.module == "eo"}

    def test_enum_cases_match_the_proto_exactly(self):
        for name, want in _ORACLE_ENUMS.items():
            self.assertEqual(_fieldset(self.enums[name]), want, name)
            self.assertTrue(self.enums[name].is_enum)

    def test_zero_negative_large_and_non_zero_first_values(self):
        top = {f.name: f.number for f in self.enums["Eo_Top"].fields}
        self.assertEqual((top["T_ZERO"], top["T_NEG"], top["T_BIG"]), (0, -5, 100000))
        self.assertEqual(min(f.number for f in self.enums["Eo_NonZero"].fields), 1)

    def test_aliased_enum_is_exact_or_empty_never_wrong(self):
        self.assertEqual(_fieldset(self.enums["Eo_Aliased"]), self.ALIASED)

    def test_messages_still_exact(self):
        self.assertEqual(_fieldset(self.msgs["Eo_Multi"]),
                         {(1, "a"), (2, "b"), (3, "c"), (10, "n10"), (11, "t"), (100, "big")})
        self.assertEqual(_fieldset(self.msgs["Eo_Holder"]),
                         {(1, "top"), (2, "inner"), (3, "nz"), (4, "al"), (5, "single"), (6, "plain")})
        self.assertEqual({m.shape for m in self.msgs.values()}, {self.SHAPE})

    def test_enums_are_not_returned_as_messages(self):
        self.assertFalse(set(self.enums) & set(self.msgs))

    def test_emitted_proto_defines_and_references_the_enums(self):
        from proto import foreign as F
        out = {m.name: m for m in F.swift_messages(self.ctx) if m.package == "eo"}
        holder = {f.name: f for f in out["Eo_Holder"].fields}
        self.assertEqual(holder["top"].type_name, "Eo_Top")
        self.assertEqual(holder["inner"].type_name, "Eo_Holder_Inner")   # nested enum
        self.assertEqual(holder["nz"].type_name, "Eo_NonZero")           # no zero value
        self.assertEqual(holder["single"].type_name, "Eo_Single")        # one case
        self.assertEqual(out["Eo_Multi"].fields[4].type_name, "Eo_Top")
        names = {e.name: e for m in out.values() for e in m.enums}
        self.assertIn("Eo_Holder_Inner", {e.name for e in out["Eo_Holder"].enums})  # on its owner
        top = {v.name: v.number for v in names["Eo_Top"].values}
        self.assertEqual(top, {"T_NEG": -5, "T_ZERO": 0, "T_ONE": 1, "T_BIG": 100000})
        # every enum of the proto is defined with its values (the aliased one where recovered)
        self.assertEqual({n: {v.name: v.number for v in e.values}
                          for n, e in names.items() if n != "Eo_Aliased"},
                         {n.replace(".", "_"): {nm: v for v, nm in cases}
                          for n, cases in _ORACLE_ENUMS.items()})
        self.assertEqual("Eo_Aliased" in names, bool(self.ALIASED))
        # with Eo_Multi the package's first message (the carrier of its top-level enums), the
        # nested enum is still on its owner
        recovered = S.swift_messages(self.ctx)
        orig = S.swift_messages
        S.swift_messages = lambda ctx: sorted(recovered, key=lambda m: m.name != "Eo_Multi")
        try:
            moved = {m.name: m for m in F.swift_messages(self.ctx) if m.package == "eo"}
        finally:
            S.swift_messages = orig
        self.assertEqual({e.name for e in moved["Eo_Holder"].enums}, {"Eo_Holder_Inner"})


@unittest.skipUnless(_enum_oracle("eo_bytecode"), "enum oracle (bytecode) not available")
class TestEnumOracleBytecode(_EnumOracleBase, unittest.TestCase):
    """swift-protobuf 1.33.3: the packed `_NameMap(bytecode:)` form (iOS 27)."""
    BINARY, SHAPE, ALIASED = "eo_bytecode", "bytecode", _ORACLE_ALIASED

    def test_alias_names_share_the_primary_value_in_the_emitted_enum(self):
        from proto import foreign as F
        out = [m for m in F.swift_messages(self.ctx) if m.package == "eo"]
        al = {e.name: e for m in out for e in m.enums}["Eo_Aliased"]
        self.assertEqual({v.name: v.number for v in al.values}, {"AL_X": 0, "AL_Y": 1, "AL_Z": 2})
        self.assertIn("AL_Y2", [v.comment for v in al.values if v.name == "AL_Y"][0])


@unittest.skipUnless(_enum_oracle("eo_classic"), "enum oracle (classic) not available")
class TestEnumOracleClassic(_EnumOracleBase, unittest.TestCase):
    """swift-protobuf 1.30.0: classic dictionary-literal name map (static array).  The
    aliased enum is built at runtime in this lowering and is reported EMPTY (a known
    gap), not wrongly -- an earlier open-ended blob scan returned a neighbouring type's
    case for it."""
    BINARY, SHAPE, ALIASED = "eo_classic", "static", set()

    def test_aliased_enum_falls_back_to_int32_in_the_emitted_proto(self):
        from proto import foreign as F
        out = {m.name: m for m in F.swift_messages(self.ctx) if m.package == "eo"}
        al = {f.name: f for f in out["Eo_Holder"].fields}["al"]
        self.assertEqual(al.type_name, "int32")
        self.assertIn("cases not recovered", al.type_inference_note)


@unittest.skipUnless(_trustedpeershelper_path(), "TrustedPeersHelper binary not available")
class TestLiveTrustedPeersHelperEnums(unittest.TestCase):
    """The same enums used to read shifted by one (the zero case is stored from the
    zero register) and, via a tail-call getter walked 'until ret', as the NEXT
    enum's cases."""
    @classmethod
    def setUpClass(cls):
        cls.enums = {e.name: e for e in S.swift_enums(_load_ctx(_trustedpeershelper_path()))}

    def test_values_start_at_zero_and_are_contiguous(self):
        self.assertEqual(len(self.enums), 7)
        for name, e in self.enums.items():
            self.assertGreaterEqual(len(e.fields), 2, name)      # read, not empty
            self.assertEqual([f.number for f in e.fields], list(range(len(e.fields))), name)

    def test_cases_belong_to_their_own_enum(self):
        # the cases carry their type's name as a prefix
        for name, prefix in (("ResetReason", "RESET_REASON_"), ("RepairAction", "REPAIR_ACTION_"),
                             ("ViewKeyClass", "VIEW_KEY_CLASS_"), ("SOSViability", "SOS_"),
                             ("RecordStatus", "RECORD_STATUS_"), ("FilteringRequest", "FILTERING_REQUEST_"),
                             ("SupportAppDeviceStatus", "SUPPORT_APP_DEVICE_STATUS_")):
            self.assertTrue(self.enums[name].fields, name)
            self.assertTrue(all(f.name.startswith(prefix) for f in self.enums[name].fields), name)

    def test_reset_reason_exact(self):
        self.assertEqual(
            [(f.number, f.name) for f in self.enums["ResetReason"].fields],
            [(0, "RESET_REASON_UNKNOWN"), (1, "RESET_REASON_USER_INITIATED_RESET"),
             (2, "RESET_REASON_HEALTH_CHECK"),
             (3, "RESET_REASON_NO_BOTTLE_DURING_ESCROW_RECOVERY"),
             (4, "RESET_REASON_LEGACY_JOIN_CIRCLE"), (5, "RESET_REASON_RECOVERY_KEY"),
             (6, "RESET_REASON_TEST_GENERATED"), (7, "RESET_REASON_SUPPORT_APP_INITIATED_RESET")])


class TestEnumCasePlausibility(unittest.TestCase):
    def _f(self, *pairs):
        return [S.SwiftField(n, nm) for n, nm in pairs]

    def test_sorted_distinct_identifiers_pass(self):
        self.assertTrue(S._enum_cases_plausible(self._f((-5, "A_B"), (0, "A_C"), (1, "A_D"))))

    def test_alias_shares_a_value(self):
        self.assertTrue(S._enum_cases_plausible(self._f((0, "X"), (1, "Y"), (1, "Y2"), (2, "Z"))))

    def test_scrambled_pairing_is_rejected(self):
        # remindd Google_Protobuf_Field.Kind as the loose pairing used to return it
        self.assertFalse(S._enum_cases_plausible(
            self._f((8, "TYPE_BOOL"), (0, "TYPE_UNKNOWN"), (0, "TYPE_STRING"))))

    def test_duplicate_or_non_identifier_names_rejected(self):
        self.assertFalse(S._enum_cases_plausible(self._f((0, "A"), (1, "A"))))
        self.assertFalse(S._enum_cases_plausible(self._f((0, "A B"))))
        self.assertFalse(S._enum_cases_plausible([]))


class TestTailCallArgs(unittest.TestCase):
    """A pure stub -- register setup ending in a tail ``b`` -- hands its argument registers on
    (:func:`_tail_call_args`); anything else is not a stub."""
    def test_tail_call_stub(self):
        self.assertEqual(S._tail_call_args(_listing(
            [("adrp", "x0, #0x1000"), ("add", "x0, x0, #8"), ("adr", "x2, #0x40"),
             ("nop", ""), ("b", "#0x100")])), {"x0": 0x1008, "x2": 0x40})
        self.assertEqual(S._tail_call_args(_listing(
            [("adrp", "x1, #0x1000"), ("add", "x1, x1, #8"), ("mov", "w3, #24"),
             ("b", "#0x100")])), {"x1": 0x1008, "x3": 24})
        # every argument register up to x7 (PegasusAPI's single-entry stub passes a length in
        # w4), none past it
        self.assertEqual(S._tail_call_args(_listing(
            [("adrp", "x1, #0x1000"), ("add", "x1, x1, #8"), ("adrp", "x3, #0x2000"),
             ("add", "x3, x3, #0x10"), ("mov", "w2, #2"), ("mov", "w4, #19"), ("mov", "w7, #1"),
             ("mov", "x8, #5"), ("b", "#0x100")])),
            {"x1": 0x1008, "x2": 2, "x3": 0x2010, "x4": 19, "x7": 1})

    def test_real_function_is_not_a_stub(self):
        self.assertIsNone(S._tail_call_args(_listing(
            [("pacibsp", ""), ("stp", "x29, x30, [sp, #-0x10]!"), ("bl", "#0x100")])))
        self.assertIsNone(S._tail_call_args(_listing(
            [("adrp", "x0, #0x1000"), ("ldr", "x8, [x0]"), ("cmn", "x8, #1"), ("b.ne", "#0x40")])))
        # ending in a tail `b`, but with a frame and a call before it
        self.assertIsNone(S._tail_call_args(_listing(
            [("pacibsp", ""), ("stp", "x29, x30, [sp, #-0x10]!"), ("bl", "#0x100"),
             ("ldp", "x29, x30, [sp], #0x10"), ("b", "#0x200")])))
        # ending in a tail `b` after one load
        self.assertIsNone(S._tail_call_args(_listing(
            [("adrp", "x0, #0x1000"), ("ldr", "x8, [x0]"), ("b", "#0x100")])))
        # register setup ending in a call (`bl`), or in a `b` back into the listing
        self.assertIsNone(S._tail_call_args(_listing(
            [("adrp", "x0, #0x1000"), ("add", "x0, x0, #8"), ("bl", "#0x100")])))
        self.assertIsNone(S._tail_call_args(_listing(
            [("mov", "w0, #1"), ("nop", ""), ("b", "#0x1004")])))

    def test_no_branch_is_not_a_stub(self):
        self.assertIsNone(S._tail_call_args(_listing([("adrp", "x0, #0x1000"),
                                                      ("add", "x0, x0, #8")])))


class _ListingCtx(TextImage):
    """A disasm-able ctx over a hand-built listing, with a function index
    (``BinaryContext.function_starts``) so :func:`FB.function_body` can be driven offline."""
    def __init__(self, lines, base, starts):
        from tests._listing import layout
        super().__init__(starts=starts)
        self.order, self.fake = layout((base, lines))


class TestListing(unittest.TestCase):
    """:func:`FB.function_body` reads what the entry reaches inside the function's extent (up to
    the next function entry): a jump inside it is followed, a branch out of it is a tail call."""
    def _read(self, lines, starts):
        ctx = _ListingCtx(lines, 0x1000, starts)
        orig = FB.disasm
        FB.disasm = ctx.fake
        try:
            return [i.addr for i in FB.function_body(ctx, 0x1000)]
        finally:
            FB.disasm = orig

    def test_forward_jump_inside_the_function_is_followed(self):
        # decodeMessage enters its loop with `b` over the loop's continue block
        lines = [("mov", "x0, x1"), ("b", "#0x100c"), ("mov", "x0, x2"),
                 ("bl", "#0x9000"), ("cbz", "x0, #0x1008"), ("ret", "")]
        self.assertEqual(self._read(lines, [0x1000, 0x1018]),
                         [0x1000, 0x1004, 0x1008, 0x100c, 0x1010, 0x1014])

    def test_branch_to_the_next_function_is_a_tail_call(self):
        # CreateML getters: `adrp; add; b <next>` where the next instruction starts a function
        lines = [("adrp", "x1, #0x1000"), ("add", "x1, x1, #8"), ("b", "#0x100c"),
                 ("stp", "x22, x21, [sp, #-0x30]!"), ("ret", "")]
        self.assertEqual(self._read(lines, [0x1000, 0x100c]), [0x1000, 0x1004, 0x1008])
        # ... while the same `b` inside one function is a fall-through
        self.assertEqual(self._read(lines, [0x1000, 0x1100]),
                         [0x1000, 0x1004, 0x1008, 0x100c, 0x1010])

    def test_cold_path_after_the_return_is_read(self):
        lines = [("cmn", "x8, #1"), ("b.ne", "#0x100c"), ("ret", ""),
                 ("adr", "x1, #0x2000"), ("bl", "#0x9000"), ("b", "#0x1008")]
        self.assertEqual(len(self._read(lines, [0x1000, 0x1018])), 6)




def _pegasus_path():
    try:
        import artifacts
        p = os.path.join(artifacts.data_dir(), "dylib", "System", "Library",
                         "PrivateFrameworks", "PegasusAPI.framework", "PegasusAPI")
        return p if os.path.isfile(p) else None
    except Exception:
        return None


@unittest.skipUnless(_pegasus_path(), "PegasusAPI image not available")
class TestLivePegasusSingleEntryStub(unittest.TestCase):
    """Builders that are only an arg-setup stub for the shared single-entry template:
    ``adrp/add x1,<slot>; adrp/add x3,<name>; mov w2,#<number>; mov w4,#<len>; b <tmpl>``.
    The number is a literal (here 2, not 1, so it is not a default).  The template is read
    with the stub's arguments (shape D), through the outlined fragment that moves them into
    callee-saved registers (TODO #97)."""
    @classmethod
    def setUpClass(cls):
        cls.msgs = {m.name: m for m in S.swift_messages(_load_ctx(_pegasus_path()))}

    def test_number_is_read_from_the_stub(self):
        m = self.msgs["Searchfoundation_ReferentialCommand"]
        self.assertEqual(_fieldset(m), {(2, "referenceIdentifier")})
        self.assertEqual(m.shape, "shared-once")
        self.assertEqual(m.fields[0].proto_type, "string")

    def test_enum_single_case(self):
        # the enum's lone case, read through the shared template's outlined fragments (#97)
        enums = {e.name: e for e in S.swift_enums(_load_ctx(_pegasus_path()))}
        self.assertEqual(_fieldset(enums["Apple_Parsec_Feedback_V2_NullValue"]),
                         {(0, "NULL_VALUE")})


def _pegasus_in_cache():
    try:
        import live_artifacts as V
        return V.load_cache("PegasusAPI")
    except Exception:
        return None


@pytest.mark.slow
class TestLivePegasusFromCache(unittest.TestCase):
    """PegasusAPI read from the iPhone 8 cache (the gate's mode), not from its extracted file."""
    @classmethod
    def setUpClass(cls):
        loaded = _pegasus_in_cache()
        cls.msgs = {m.name: m for m in S.swift_messages(loaded[0])} if loaded else None

    def setUp(self):
        if self.msgs is None:
            self.skipTest("iPhone 8 cache not available")

    def test_a_decode_four_calls_from_its_arm_confirms_the_entry(self):
        # decodeMessage decodes field 1 four calls from the arm: with calls followed only three
        # deep the one-entry reading was dropped as another type's (no fields)
        for name, field in (("Searchfoundation_CopyCommand", "copyableItem"),
                            ("Searchfoundation_ShareCommand", "shareItem")):
            self.assertEqual(_fieldset(self.msgs[name]), {(1, field)}, name)


class TestFieldlessMarker(unittest.TestCase):
    def test_provably_empty_message_is_flagged_not_failed(self):
        from proto import foreign as F
        orig = S.swift_messages
        sm = [S.SwiftMessage(module="m", name="Empty", fieldless=True),
              S.SwiftMessage(module="m", name="Unread"),
              S.SwiftMessage(module="m", name="Real", fields=[S.SwiftField(1, "a", proto_type="int32")])]
        S.swift_messages = lambda ctx: sm
        try:
            msgs = {x.name: x for x in F.swift_messages(_FakeCtx(b"\x00" * 64))}
        finally:
            S.swift_messages = orig
        self.assertTrue(msgs["Empty"].opaque_passthrough)
        self.assertFalse(msgs["Unread"].opaque_passthrough)      # still reported as not recovered
        self.assertFalse(msgs["Real"].opaque_passthrough)


class TestLiveDecoderCrossCheck(unittest.TestCase):
    """Layer-regression guard: across every available swift-protobuf binary, the
    field numbers ``decodeMessage`` switches on must NEVER include a number the
    nameMap lacks (independent codegen path), an empty reading included.  Zero
    contradictions tool-wide."""
    def _binaries(self):
        for p in (_remindd_path(), _data_path(*_NPTO), _trustedpeershelper_path(),
                  _seymourcore_path()):
            if p:
                yield p

    def test_no_decoder_contradictions(self):
        bins = list(self._binaries())
        if not bins:
            self.skipTest("no swift-protobuf binaries available")
        total_confirmed = 0
        for path in bins:
            ctx = _load_ctx(path)
            syms = S.symbol_addrs(ctx)
            decoders = {}
            for name, va in syms.items():
                if "13decodeMessage" in name and name.endswith("F"):
                    t = S._type_of_symbol(name, "13decodeMessage")
                    if t and t[2] == "V":
                        decoders.setdefault(t[:2], va)
            for m in S.swift_messages(ctx):
                # an empty reading too: a genuinely empty message's decoder switches on nothing
                dva = decoders.get((m.module, m.name))
                if dva is None:
                    continue
                nm = {f.number for f in m.fields}
                dn = _decode_message_numbers_oracle(ctx, dva)
                self.assertFalse(dn - nm,
                                 f"{os.path.basename(path)} {m.name}: decoder "
                                 f"switches on {sorted(dn - nm)} absent from nameMap {sorted(nm)}")
                if dn:
                    total_confirmed += 1
        # at least one message TOOL-WIDE must be independently confirmed (proves the
        # cross-check ran against a real decoder, not vacuously).  Not every binary
        # has decoders the oracle's jump-table reader recognises — remindd's decode
        # cores don't — so this is a tool-wide total, not a per-binary requirement.
        self.assertGreaterEqual(total_confirmed, 1,
                                "no decoder confirmation across any swift binary")


class TestStaticStrideWitness(unittest.TestCase):
    """The static name-map stride is found by search (:func:`S._static_blob_stride`).  Where the
    image carries swift-protobuf itself, the exact stride is ``(Int, _NameDescription)``'s, from
    _NameDescription's value witness table: every searched stride must equal it.  The oracle
    fixtures are the only census images with static name maps."""

    @staticmethod
    def _witness_stride(ctx):
        names = {n: a for n, a in ctx.iter_symbols() if a}
        md = [a for n, a in names.items()
              if "_NameMapV" in n and n.endswith("11DescriptionON")]
        if len(md) != 1:
            return None
        vwt = ctx.read_ptr(md[0] - 8)
        size, _stride, flags = struct.unpack("<QQI", ctx.read_bytes(vwt + 0x40, 20))
        align = (flags & 0xFF) + 1
        off = -(-8 // align) * align                  # _NameDescription after the Int key
        return -(-(off + size) // max(8, align)) * max(8, align)

    def test_searched_stride_is_the_value_witness_stride(self):
        paths = [p for p in (_swift_oracle_path(), _enum_oracle("eo_classic")) if p]
        if not paths:
            self.skipTest("no oracle fixture available")
        checked = 0
        for path in paths:
            ctx = _load_ctx(path)
            witness = self._witness_stride(ctx)
            self.assertIsNotNone(witness, path)
            for name, va in S.symbol_addrs(ctx).items():
                p = S._parse_namemap_symbol(name)
                if not p or not name.endswith(("_WZ", "vgZ")):
                    continue
                for blob in S._static_objects(ctx, S.function_body(ctx, va)):
                    stride = S._static_blob_stride(ctx, blob, p[2])
                    if stride is not None:
                        self.assertEqual(stride, witness, f"{os.path.basename(path)} {name}")
                        checked += 1
        self.assertGreaterEqual(checked, 100)        # 137 static name maps of two or more


@unittest.skipUnless(_swift_oracle_path(),
                     "swift-protobuf oracle fixture not available (see "
                     "tests/swift_oracle_fixture/README.md); "
                     "MACHO_TEST_SWIFT_ORACLE overrides")
class TestLiveStaticOracle(unittest.TestCase):
    """End-to-end on the static-object lowering (newer toolchains): an oracle
    binary built from a KNOWN proto must round-trip exactly."""
    def test_known_proto_roundtrip(self):
        msgs = _msgs_by_name(_swift_oracle_path())
        self.assertEqual(_fieldset(msgs["Ora_Single7"]), {(7, "only")})
        self.assertEqual(
            {(f.number, f.name) for f in msgs["Ora_Multi"].fields},
            {(1, "a"), (2, "b"), (3, "c"), (5, "big"), (9, "raw")})

    def test_static_table_is_the_one_handed_to_swift_init_static_object(self):
        # descriptor.proto's FeatureSet.VisibilityFeature has no fields (it only nests an
        # enum); reading every address the getter builds took a neighbouring table's
        # (1, "ALLOW") for it.  The table is the object passed to swift_initStaticObject.
        msgs = _msgs_by_name(_swift_oracle_path())
        self.assertEqual(msgs["Google_Protobuf_FeatureSet.VisibilityFeature"].fields, [])


def _cache_path():
    try:
        import artifacts
        p = artifacts.cache_file()
        return p if p and os.path.isfile(p) else None
    except Exception:
        return None


@unittest.skipUnless(_cache_path() and os.path.isfile(_cache_path() + ".symbols"),
                     "dyld shared cache (+ .symbols sub-cache) not available")
class TestLiveCacheNative(unittest.TestCase):
    """Cache-native swift recovery: the per-type ``_protobuf_nameMap`` symbols
    come from the ``.symbols`` sub-cache (no in-image LC_SYMTAB), and the inline
    closures load names via ``adrp+add``.  CopresenceCore's CP_Record /
    CP_KeyValue are hand-verified against the init-closure disassembly (the
    function literally stores ``mov #N`` + ``adrp+add <name>``)."""
    @classmethod
    def setUpClass(cls):
        from macho.dyld_cache import DyldCacheReader
        from macho.memory import BinaryContext
        cls.reader = DyldCacheReader(_cache_path())
        mach_va = cls.reader.find_image_header("CopresenceCore")
        ctx = BinaryContext.from_cache(cls.reader, mach_va)
        cls.ctx = ctx
        cls.msgs = {m.name: m for m in S.swift_messages(ctx)}

    @classmethod
    def tearDownClass(cls):
        try:
            cls.reader.close()
        except Exception:
            pass

    def test_symbol_source_is_cache_symbols(self):
        # cache-native: no in-image symbol table, yet nameMap symbols resolve.
        self.assertFalse(getattr(self.ctx, "_data", b""))
        syms = S.symbol_addrs(self.ctx)
        self.assertTrue(any(S._NAMEMAP_MARKER in n for n in syms))
        # every nameMap symbol of the .symbols sub-cache, at its address -- CP_KeyValue's static
        # init among them, which the export trie does not have
        local = {n: a for n, a in self.reader.image_symbol_addrs(
            self.ctx.image_base, S._NAMEMAP_MARKER).items() if S._NAMEMAP_MARKER in n}
        kv = "_$s14CopresenceCore11CP_KeyValueV17_protobuf_nameMap_WZ"
        self.assertNotIn(kv, self.reader.image_exports(self.ctx.image_base))
        self.assertIn(kv, local)
        self.assertEqual({n: syms.get(n) for n in local}, local)

    def test_traverse_symbols_reach_the_cross_check(self):
        # the .symbols sub-cache carries each message's traverse(visitor:); symbol_addrs
        # used to filter it out, so the cache-mode readings ran without that cross-check
        syms = S.symbol_addrs(self.ctx)
        bodies = [n for n in syms if "V8traverse" in n and n.endswith(S._FUNCTION_BODY_SUFFIXES)]
        local = self.reader.image_symbol_addrs(self.ctx.image_base, "V8traverse")
        # CopresenceCore's local ones are all identical-body merges (``…FTm``; closures,
        # ``…XEfU_``, are not bodies); a public type's own body is an export (``…F``)
        self.assertTrue(all(n.endswith("FTm") for n in bodies if n in local))
        kv_traverse = ("_$s14CopresenceCore11CP_KeyValueV8traverse7visitoryxz_tK21InternalSwift"
                       "Protobuf7VisitorRzlF")
        self.assertIn(kv_traverse, bodies)
        # the sub-cache's own bodies are there too
        local_bodies = {n for n in local if "V8traverse" in n
                        and n.endswith(S._FUNCTION_BODY_SUFFIXES)}
        self.assertTrue(local_bodies)
        self.assertLessEqual(local_bodies, set(bodies))
        # and each message's reading is handed its traverse for the cross-check: its Message
        # conformance's witness, here the body its symbol names
        handed = {}
        orig = S._extract_namemap

        def record(ctx, init_va, traverse=None, enum=False, owner=""):
            handed[init_va] = traverse
            return orig(ctx, init_va, traverse, enum, owner)
        S._extract_namemap = record
        try:
            S.swift_messages(self.ctx)
        finally:
            S._extract_namemap = orig
        self.assertEqual(len(handed), len(self.msgs))
        self.assertTrue(all(isinstance(t, MC.Code) for t in handed.values()))
        kv = handed[syms["_$s14CopresenceCore11CP_KeyValueV17_protobuf_nameMap_WZ"]]
        self.assertEqual(kv, S._witnesses(self.ctx)["CP_KeyValue"]["traverse"])
        self.assertEqual(kv.va, syms[kv_traverse])
        self.assertEqual(set(MC.visited_fields(self.ctx, kv)), {1, 2})

    def test_cp_keyvalue(self):
        self.assertEqual(
            [(f.number, f.name) for f in sorted(self.msgs["CP_KeyValue"].fields,
                                                key=lambda x: x.number)],
            [(1, "key"), (2, "dataValue")])

    def test_cp_record_dense(self):
        self.assertEqual(
            [(f.number, f.name) for f in sorted(self.msgs["CP_Record"].fields,
                                                key=lambda x: x.number)],
            [(1, "topic"), (2, "data"), (3, "seqNum"),
             (4, "destinationParticipantIDs"), (5, "encryptionID"),
             (6, "sentEpochMillis")])

    def test_types_recovered_cache_native(self):
        # field TYPES also resolve cache-native -- from the message's decodeMessage, by number
        # (#129): sentEpochMillis is decoded with decodeSingularFixed64Field and visited with
        # visitSingularFixed64Field (reflection alone says UInt64, which was taken for uint64)
        rec = {f.name: f.proto_type for f in self.msgs["CP_Record"].fields}
        self.assertEqual(rec["topic"], "string")
        self.assertEqual(rec["sentEpochMillis"], "fixed64")
        self.assertEqual(rec["seqNum"], "CP_SequenceNumber")   # message ref

    def test_more_hand_verified_messages(self):
        # Ground truth (SWIFT_PROTO_HAND_VERIFICATION.md): closure numbers +
        # fieldmd types; the integer encodings by decodeMessage and traverse (#129).
        seq = {(f.number, f.name, f.proto_type)
               for f in self.msgs["CP_SequenceNumber"].fields}
        self.assertEqual(seq, {(1, "publisherParticipantID", "fixed64"),
                               (2, "seqNum", "uint64")})
        enc = self.msgs["CP_EncryptionID"].fields
        self.assertEqual([(f.number, f.name, f.proto_type) for f in enc],
                         [(1, "uuid", "bytes")])

    def test_namemap_covers_fieldmd_scalars(self):
        # Independent cross-source check: every SCALAR field the metadata
        # (__swift5_fieldmd) reports must appear in the nameMap-recovered set.
        from serializers import swift_type_recovery as TR
        scalar = {"int32", "int64", "uint32", "uint64", "sint32", "sint64",
                  "bool", "float", "double", "string", "bytes"}
        fmd = TR.collect_field_types(self.ctx)[0]
        nm_by = {}
        for m in self.msgs.values():
            nm_by[m.name] = m
            nm_by.setdefault(m.name.split(".")[-1], m)
        norm = lambda s: s.replace("_", "").lower()
        checked = 0
        for key, md in fmd.items():
            m = nm_by.get(key)
            if not m or not m.fields:
                continue
            names = {norm(f.name) for f in m.fields}
            for fn, ft in md.items():
                if ft.replace("repeated ", "") not in scalar:
                    continue
                # skip the known same-short-name nested-type join ambiguity
                if key == "Config":
                    continue
                checked += 1
                self.assertIn(norm(fn), names,
                              f"{key}.{fn} ({ft}) missing from nameMap")
        self.assertGreater(checked, 10)


@unittest.skipUnless(_cache_path() and os.path.isfile(_cache_path() + ".symbols"),
                     "dyld shared cache (+ .symbols sub-cache) not available")
class TestLiveCacheMessageProtection(unittest.TestCase):
    """Second cache framework — MPPB_KeyAndIndex hand-verified against its nameMap
    init closure @0x1e83ecaac (mov w8,#1 + name-len-3 'key', mov w27,#2 +
    name-len-5 'index') and __swift5_fieldmd.  See SWIFT_PROTO_HAND_VERIFICATION.md."""
    @classmethod
    def setUpClass(cls):
        from macho.dyld_cache import DyldCacheReader
        from macho.memory import BinaryContext
        cls.reader = DyldCacheReader(_cache_path())
        va = cls.reader.find_image_header("MessageProtection")
        cls.va = va
        if va is not None:
            ctx = BinaryContext.from_cache(cls.reader, va)
            cls.msgs = {m.name: m for m in S.swift_messages(ctx)}

    @classmethod
    def tearDownClass(cls):
        try:
            cls.reader.close()
        except Exception:
            pass

    def setUp(self):
        if self.va is None:
            self.skipTest("MessageProtection not in this cache")

    def test_key_and_index(self):
        m = self.msgs["MPPB_KeyAndIndex"]
        self.assertEqual([(f.number, f.name, f.proto_type)
                          for f in sorted(m.fields, key=lambda x: x.number)],
                         [(1, "key", "bytes"), (2, "index", "uint64")])


class TestRuntimeNamemapFieldsHitCapLive(unittest.TestCase):
    """A builder listing read without a function index stops at the runaway guard
    (``_UNBOUNDED_MAX_INSNS``) with its path still open: the name map read off it
    (:func:`S._extract_namemap_raw`, the runtime builder's one entry) has its numbers estimated.  A genuine (if synthetic) arm64 instruction stream --
    disassembled through capstone, not faked -- long enough to reach the guard without a ret,
    embedding one real (number, name) store, behind a once-init getter (``cmn x0, #1; b.ne
    <builder>``) whose listing reaches it."""

    _GETTER_VA = 0x100

    _BUILDER_VA = 0x10000
    _PAGE_DELTA = 5
    _STR_OFF = 0x100
    _STR_VA = (_BUILDER_VA & ~0xFFF) + _PAGE_DELTA * 0x1000 + _STR_OFF
    _FIELD_NAME = "hitCapField"
    _FIELD_NUM = 7
    _CAP = FB._UNBOUNDED_MAX_INSNS

    def _build(self, n_total_insns, terminate_with_ret):
        # mov w8,#num ; adrp x1,#page ; add x1,x1,#off ; stp x8,x1,[x20] ; then
        # NOP filler (optionally ending in `ret`) up to n_total_insns; the name
        # string sits well past the instruction stream.
        buf = bytearray(self._STR_VA + len(self._FIELD_NAME) + 16)
        buf[self._BUILDER_VA:self._BUILDER_VA + 4] = encode_movz(8, self._FIELD_NUM)
        buf[self._BUILDER_VA + 4:self._BUILDER_VA + 8] = encode_adrp(1, self._PAGE_DELTA)
        buf[self._BUILDER_VA + 8:self._BUILDER_VA + 12] = encode_add_imm64(1, 1, self._STR_OFF)
        stp_word = 0xA9000000 | (1 << 10) | (20 << 5) | 8   # stp x8, x1, [x20]
        buf[self._BUILDER_VA + 12:self._BUILDER_VA + 16] = struct.pack('<I', stp_word)
        pad_start = self._BUILDER_VA + 16
        n_pad = n_total_insns - 4
        if terminate_with_ret:
            buf[pad_start:pad_start + (n_pad - 1) * 4] = NOP_BYTES * (n_pad - 1)
            buf[pad_start + (n_pad - 1) * 4: pad_start + n_pad * 4] = RET_BYTES
        else:
            buf[pad_start:pad_start + n_pad * 4] = NOP_BYTES * n_pad
        name_bytes = self._FIELD_NAME.encode() + b"\x00"
        buf[self._STR_VA:self._STR_VA + len(name_bytes)] = name_bytes
        g = self._GETTER_VA
        buf[g:g + 4] = struct.pack('<I', 0xB100041F)                       # cmn x0, #1
        imm19 = (self._BUILDER_VA - (g + 4)) // 4
        buf[g + 4:g + 8] = struct.pack('<I', 0x54000000 | (imm19 << 5) | 1)  # b.ne <builder>
        return _FakeCtx(bytes(buf))

    def _fields(self, ctx):
        return S._extract_namemap_raw(ctx, self._GETTER_VA)[0]

    def test_builder_hitting_cap_flags_number_unconfirmed(self):
        ctx = self._build(self._CAP + 16, terminate_with_ret=False)   # runs on past the guard
        fields = self._fields(ctx)
        self.assertEqual(len(fields), 1)
        self.assertEqual(fields[0].number, self._FIELD_NUM)
        self.assertEqual(fields[0].name, self._FIELD_NAME)
        self.assertFalse(fields[0].number_confirmed,
                         'a builder read that ran to the disasm cap without '
                         'reaching a ret must not be laundered as confirmed')

    def test_builder_ending_in_ret_leaves_number_confirmed(self):
        # Same shape, well under the cap, ends in a real ret -- the contrasting
        # case: confirms the flag is genuinely conditional on hitting the cap,
        # not just always False for this builder shape.
        ctx = self._build(5, terminate_with_ret=True)
        fields = self._fields(ctx)
        self.assertEqual(len(fields), 1)
        self.assertTrue(fields[0].number_confirmed)



class TestPropertyNameJoin(unittest.TestCase):
    """A name-map field joins its Swift property less the ``_p`` swift-protobuf adds to a name that
    would collide (``has_aggs`` -> ``hasAggs_p``; BiomeStreams' PgQuery_Query), on the property's
    side only: ``foo_p`` is the property ``fooP`` (TODO #128)."""

    def test_the_join(self):
        from serializers.swift_descriptor_extract import _norm, _norm_property
        self.assertEqual(_norm("has_aggs"), _norm_property("hasAggs_p"))
        self.assertEqual(_norm("user_id"), _norm_property("userID"))
        self.assertEqual(_norm("foo_p"), _norm_property("fooP"))
        self.assertNotEqual(_norm("foo_p"), _norm_property("foo"))
        # only the `_p` suffix goes, not a trailing p or underscore
        self.assertEqual(_norm("group"), _norm_property("group"))
        self.assertEqual(_norm("timestamp"), _norm_property("timestamp"))


if __name__ == "__main__":
    unittest.main()
