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

from serializers import swift_descriptor_extract as S
from tests.conftest import encode_adrp, encode_add_imm64, encode_movz, NOP_BYTES, RET_BYTES


# ── a minimal in-memory ctx where vmaddr == file offset (image_base 0) ────────

class _FakeCtx:
    image_base = 0

    def __init__(self, data: bytes):
        self._data = data
        self._symtab = None
        self._export_trie = None

    def read_bytes(self, va: int, n: int) -> bytes:
        if va < 0 or va + n > len(self._data):
            raise ValueError("oob")
        return self._data[va:va + n]

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
    def test_oracle_and_device_forms(self):
        self.assertEqual(
            S._type_from_namemap_symbol(
                "_$s6oracle9Ora_MultiV17_protobuf_nameMap13SwiftProtobuf05_NameG0VvgZ"),
            ("oracle", "Ora_Multi"))
        self.assertEqual(
            S._type_from_namemap_symbol(
                "_$s14bookdatastored15PBPropertyValueV17_protobuf_nameMap"
                "21InternalSwiftProtobuf05_NameF0VvgZ"),
            ("bookdatastored", "PBPropertyValue"))

    def test_nested_type_is_dotted(self):
        # module=M, Outer.Inner
        self.assertEqual(
            S._type_from_namemap_symbol(
                "_$s1M5OuterV5InnerV17_protobuf_nameMap13SwiftProtobufXX"),
            ("M", "Outer.Inner"))

    def test_non_namemap_returns_none(self):
        self.assertIsNone(S._type_from_namemap_symbol("_OBJC_CLASS_$_NSString"))
        self.assertIsNone(S._type_from_namemap_symbol("_$s1MV17_protobuf_nameMap"))  # <2 idents

    def test_split_idents(self):
        self.assertEqual(S._split_idents("6oracle9Ora_Multi"), ["oracle", "Ora_Multi"])
        self.assertEqual(S._split_idents("1M5OuterV5Inner"), ["M", "Outer", "Inner"])

    def test_word_substituted_wkt_name(self):
        # SwiftProtobuf's bundled well-known types mangle with word
        # substitution (B = 'Protobuf' from 'SwiftProtobuf'); the full name must
        # be recovered, not 'Google_._Any'.
        self.assertEqual(
            S._type_from_namemap_symbol(
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

    def test_zero_count_returns_none(self):
        # NOTE: with count=0, `len(out) < count` (0 < 0) is False from the very
        # first loop check regardless of buffer size or content -- no fixture
        # variation can make this literal zero-count case discriminate the
        # `0 < count < 4096` bound on its own (a structural, not incidental,
        # guarantee). See test_huge_count_with_reachable_entry_returns_none
        # below, which targets the SAME check from the other, discriminable
        # direction (a plausible-looking but over-cap count).
        buf = struct.pack("<QQQQ", 0, 0, 0, 0)
        self.assertIsNone(S._parse_static_blob(_FakeCtx(buf), 0))

    def test_huge_count_with_reachable_entry_returns_none(self):
        # Isolates the `0 < count < 4096` plausibility bound from BOTH
        # downstream masking guards (`off + 24 <= len(buf)` and
        # `len(out) < count`): the buffer is long enough to reach a real,
        # well-formed (number, name-ptr, len) entry right after the header,
        # and count (4097, one over the cap) is non-zero so `len(out) < count`
        # does not itself block the loop -- only the count bound stands
        # between this corrupt-looking count and a wrongly-parsed field.
        name = "alpha"
        count = 4097
        header = struct.pack("<QQQQ", 0, 0, count, count)
        name_va = len(header) + 24
        entry = struct.pack("<QQQ", 1, name_va, len(name))
        buf = header + entry + name.encode() + b"\x00"
        self.assertIsNone(S._parse_static_blob(_FakeCtx(buf), 0))

    def test_unreadable_returns_none(self):
        # This exercises the OUTER try/except around the initial header read
        # (buffer too short even for the 0x20-byte header) -- a different code
        # path from the `0 < count < 4096` bound above, not a weaker version of
        # it. Genuinely effective for what it covers; see the two tests above
        # for the count-bound-specific coverage.
        self.assertIsNone(S._parse_static_blob(_FakeCtx(b"\x00" * 8), 0))


class _FI:
    """Minimal stand-in for a disassembled instruction (mnemonic + op_str)."""
    def __init__(self, mnemonic, op_str=""):
        self.mnemonic, self.op_str = mnemonic, op_str


class TestInlineClosureWalk(unittest.TestCase):
    """The inline-closure walker must read name pointers from BOTH a single
    ``adr`` (standalone-binary form) and an ``adrp x,#page; add x,x,#off`` pair
    (device / cache form, where the name pool is far past ``adr`` reach)."""
    def _ctx(self):
        data = bytearray(0x40)
        data[0x10:0x14] = b"key\x00"
        data[0x20:0x25] = b"data\x00"
        return _FakeCtx(bytes(data))

    def test_adrp_add_name_pointer(self):
        # entry 1: number 1 + name "key" via adrp+add (page 0x0, off 0x10)
        insns = [
            _FI("mov", "w0, #1"), _FI("str", "x0, [x20]"),
            _FI("adrp", "x1, #0x0"), _FI("add", "x1, x1, #0x10"),
            _FI("mov", "w2, #3"), _FI("stp", "x1, x2, [x21]"),
            # entry 2: number 2 + name "data" via a single adr
            _FI("mov", "w0, #2"), _FI("str", "x0, [x20]"),
            _FI("adr", "x1, #0x20"), _FI("mov", "w2, #4"),
            _FI("stp", "x1, x2, [x21]"),
        ]
        got = S._walk_inline_closure(self._ctx(), insns)
        self.assertEqual([(f.number, f.name) for f in got], [(1, "key"), (2, "data")])

    def test_length_mismatch_rejected(self):
        # a name whose len immediate disagrees with the cstring is not an entry
        insns = [
            _FI("mov", "w0, #1"), _FI("str", "x0, [x20]"),
            _FI("adrp", "x1, #0x0"), _FI("add", "x1, x1, #0x10"),
            _FI("mov", "w2, #9"), _FI("stp", "x1, x2, [x21]"),   # 9 != len("key")
        ]
        self.assertEqual(S._walk_inline_closure(self._ctx(), insns), [])

    _SINGLE_FIELD_INSNS = [
        _FI("adrp", "x2, #0x0"), _FI("add", "x2, x2, #0x10"),  # -> "key"
        _FI("mov", "w3, #3"), _FI("b", "#0x100"),
    ]

    def test_single_field_tail_call_adrp_add(self):
        # cache/device single-field shape: name via adrp+add, len via mov, tail b.
        # (Regression for the CP_EncryptionID 'uuid' miss — see
        # SWIFT_PROTO_HAND_VERIFICATION.md.)
        got = S._single_field_tail_call(self._ctx(), self._SINGLE_FIELD_INSNS,
                                        decode_va=None)
        self.assertEqual([(f.number, f.name) for f in got], [(1, "key")])

    def test_single_field_number_unconfirmed_without_decode(self):
        # the number is NOT in the closure; with no decodeMessage the default 1
        # is a GUESS and must surface as unconfirmed (to-do #63a).
        got = S._single_field_tail_call(self._ctx(), self._SINGLE_FIELD_INSNS,
                                        decode_va=None)
        self.assertEqual(got[0].number, 1)
        self.assertFalse(got[0].number_confirmed)

    def test_single_field_number_confirmed_from_single_decode_compare(self):
        # exactly one decodeMessage field-number compare => independent source =>
        # the number is real and confirmed.
        orig = S._decode_message_numbers
        S._decode_message_numbers = lambda ctx, va: [5]
        try:
            got = S._single_field_tail_call(self._ctx(), self._SINGLE_FIELD_INSNS,
                                            decode_va=0x1000)
        finally:
            S._decode_message_numbers = orig
        self.assertEqual(got[0].number, 5)
        self.assertTrue(got[0].number_confirmed)

    def test_single_field_number_unconfirmed_when_decode_ambiguous(self):
        # >1 (or 0) compares => no single independent number => default 1, flagged.
        orig = S._decode_message_numbers
        S._decode_message_numbers = lambda ctx, va: [1, 2]
        try:
            got = S._single_field_tail_call(self._ctx(), self._SINGLE_FIELD_INSNS,
                                            decode_va=0x1000)
        finally:
            S._decode_message_numbers = orig
        self.assertEqual(got[0].number, 1)
        self.assertFalse(got[0].number_confirmed)

    def _with_sources(self, decode_nums, traverse_nums, decode_va=None,
                      traverse_va=None):
        od, ot = S._decode_message_numbers, S._traverse_field_numbers
        S._decode_message_numbers = lambda ctx, va: decode_nums
        S._traverse_field_numbers = lambda ctx, va: traverse_nums
        try:
            return S._single_field_tail_call(self._ctx(), self._SINGLE_FIELD_INSNS,
                                             decode_va=decode_va,
                                             traverse_va=traverse_va)
        finally:
            S._decode_message_numbers, S._traverse_field_numbers = od, ot

    def test_single_field_confirmed_from_traverse_only(self):
        # Tier-2a: traverse's single visit number confirms even with no decode.
        got = self._with_sources([], [9], traverse_va=0x2000)
        self.assertEqual(got[0].number, 9)
        self.assertTrue(got[0].number_confirmed)

    def test_single_field_unconfirmed_on_source_disagreement(self):
        # decode says 1, traverse says 2 => distrust => default 1, flagged.
        got = self._with_sources([1], [2], decode_va=0x1000, traverse_va=0x2000)
        self.assertEqual(got[0].number, 1)
        self.assertFalse(got[0].number_confirmed)

    def test_single_field_unconfirmed_when_traverse_multifield(self):
        # traverse exposes many numbers => message is really multi-field, shape-B
        # under-extracted it => don't confirm a single number (to-do #72).
        got = self._with_sources([], [1, 2, 3], traverse_va=0x2000)
        self.assertEqual(got[0].number, 1)
        self.assertFalse(got[0].number_confirmed)


class TestTraverseFieldNumbers(unittest.TestCase):
    """`_traverse_field_numbers` reads the field number (highest w-reg immediate)
    before each visit call, for direct `bl` and protocol-witness `blr` forms."""
    def _run(self, insns):
        orig = S.disasm
        S.disasm = lambda ctx, va, **kw: insns
        try:
            return S._traverse_field_numbers(None, 0x1000)
        finally:
            S.disasm = orig

    def test_value_and_number_picks_highest_reg(self):
        # visitSingularBoolField(value:fieldNumber:): w0=value, w1=#N => 7
        self.assertEqual(self._run([
            _FI("mov", "w0, #1"), _FI("mov", "w1, #7"), _FI("bl", "#0x200")]), [7])

    def test_float_value_in_fp_reg_number_in_w0(self):
        # float value uses d0 (no w imm), fieldNumber lands in w0
        self.assertEqual(self._run([
            _FI("mov", "w0, #3"), _FI("bl", "#0x200")]), [3])

    def test_witness_blr_form(self):
        self.assertEqual(self._run([
            _FI("mov", "w2, #5"), _FI("mov", "x3, x22"), _FI("blr", "x8")]), [5])

    def test_multi_field_in_visit_order(self):
        self.assertEqual(self._run([
            _FI("mov", "w1, #1"), _FI("bl", "#0x1"),
            _FI("mov", "w1, #2"), _FI("bl", "#0x2"),
            _FI("mov", "w1, #3"), _FI("bl", "#0x3")]), [1, 2, 3])

    def test_call_without_field_number_immediate_ignored(self):
        # a metadata/release call (no field-number imm) contributes nothing
        self.assertEqual(self._run([
            _FI("bl", "#0x100"), _FI("mov", "w1, #4"), _FI("bl", "#0x200")]), [4])


class TestNameMapBuilderValidation(unittest.TestCase):
    """The runtime-_NameMap reading is cross-validated: the cold-builder stp pair
    is `(smallInt, namePtr)` whose int is the field NUMBER in the older codegen
    but the name LENGTH in the newer packed-bytecode form, so the walker can
    mis-read lengths as numbers (e.g. nptocompaniond: 6=len'domain', 4='code')."""
    def test_length_form_rejected(self):
        # every entry's number == len(name) -> the (length, ptr) packed form
        got = [S.SwiftField(6, "domain"), S.SwiftField(4, "code")]
        self.assertFalse(S._namemap_builder_validated(None, got, None, None))

    def test_genuine_numbers_accepted(self):
        # numbers differ from name lengths, no oracle to contradict -> accept
        got = [S.SwiftField(1, "dsID"), S.SwiftField(2, "baseURL")]
        self.assertTrue(S._namemap_builder_validated(None, got, None, None))

    def test_oracle_subset_of_recovered_accepted(self):
        # traverse exposes {1,2}; the reading recovered a strict SUPERSET {1,2,3}
        # -> accept: the oracle is fully explained by recovery plus extra info,
        # not a contradiction.  Under the WRONG reversed check ("recovered subset
        # of oracle") this would be incorrectly rejected, since 3 isn't in the
        # oracle -- this is what distinguishes the correct direction.
        orig = S.disasm
        S.disasm = lambda ctx, va, **kw: [
            _FI("mov", "w1, #1"), _FI("bl", "#0x1"),
            _FI("mov", "w1, #2"), _FI("bl", "#0x2")]
        try:
            got = [S.SwiftField(1, "dsID"), S.SwiftField(2, "baseURLX"),
                   S.SwiftField(3, "extra")]
            self.assertTrue(S._namemap_builder_validated(None, got, None, 0x1000))
        finally:
            S.disasm = orig

    def test_oracle_contradiction_rejected(self):
        # traverse exposes {1,2,5} but the reading only recovered {1,2} -> reject:
        # the oracle independently knows field 5 that the recovery MISSED, a
        # genuine contradiction.  Under the WRONG reversed check ("recovered
        # subset of oracle") this would be incorrectly ACCEPTED, since {1,2} IS
        # a subset of {1,2,5} -- this is what distinguishes the correct direction.
        orig = S.disasm
        S.disasm = lambda ctx, va, **kw: [
            _FI("mov", "w1, #1"), _FI("bl", "#0x1"),
            _FI("mov", "w1, #2"), _FI("bl", "#0x2"),
            _FI("mov", "w1, #5"), _FI("bl", "#0x3")]
        try:
            # names chosen so num != len(name): isolates the oracle-subset check
            got = [S.SwiftField(1, "dsID"), S.SwiftField(2, "baseURLX")]
            self.assertFalse(S._namemap_builder_validated(None, got, None, 0x1000))
        finally:
            S.disasm = orig


class TestFatSlice(unittest.TestCase):
    def _fat(self, slices):
        # slices: list of (cputype, cpusubtype, payload)
        n = len(slices)
        header = struct.pack(">II", 0xCAFEBABE, n)
        body = b""
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

    def test_thin_passthrough(self):
        thin = b"\xcf\xfa\xed\xfe" + b"\x00" * 60
        self.assertEqual(S.load_macho_slice(thin), thin)


class TestFormatProto(unittest.TestCase):
    def test_message_enum_empty(self):
        msgs = [
            S.SwiftMessage("m", "Msg", [S.SwiftField(2, "b"), S.SwiftField(1, "a")]),
            S.SwiftMessage("m", "Col", [S.SwiftField(0, "U"), S.SwiftField(1, "R")],
                           is_enum=True),
            S.SwiftMessage("m", "Empty", []),
        ]
        text = S.format_proto(msgs)
        self.assertIn("message Msg {", text)
        # fields sorted by number, type shown as ??? (not recovered)
        self.assertIn("optional ??? a = 1;", text)
        self.assertIn("optional ??? b = 2;", text)
        # The two assertIn checks above are TAUTOLOGICAL for "sorted by number"
        # specifically: assertIn ignores position, so they'd pass even if `b`
        # (constructed first, field 2) were emitted before `a` (field 1).
        # Msg's fields are deliberately constructed out of number order above
        # ([b, a]) so this actually exercises the sort; assert genuine
        # ordering by string position.
        self.assertLess(text.index("a = 1;"), text.index("b = 2;"))
        self.assertIn("enum Col {", text)
        self.assertIn("R = 1;", text)
        self.assertIn("message Empty {}", text)


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
            elif reg in ("x0", "w0", "x16", "w16") and 1 <= k <= S._MAX_FIELD_NUMBER:
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

    def test_empty_message(self):
        # A message whose nameMap carries no entries recovers as zero fields —
        # not an error, not a spurious field.
        self.assertEqual(self.msgs["Google_Protobuf_Empty"].fields, [])
        self.assertEqual(self.msgs["UnmigrateRequest"].fields, [])

    def test_numbers_confirmed(self):
        m = self.msgs["StartMigrationRequest.Credential"]
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

    def test_single_field_message(self):
        self.assertEqual(_fieldset(self.msgs["CollectionID"]), {(1, "collection_id")})

    def test_nested_type_message(self):
        self.assertEqual(
            _fieldset(self.msgs["DediscoDonation.AlgorithmParameters"]),
            {(1, "dimension"), (2, "epsilon"), (3, "other_params")})

    def test_empty_message(self):
        self.assertEqual(self.msgs["Empty"].fields, [])

    def test_two_hop_builder_shape(self):
        # ProtectedDonation's builder is itself an arg-setup stub tail-calling
        # a second shared template (the two-stub form of shape D, #74) that
        # ISN'T laid out contiguously with it, unlike CollectionID's -- this
        # is the case that needs _walk_namemap_builder_hop's explicit follow
        # rather than falling out of a single linear disasm.
        self.assertEqual(_fieldset(self.msgs["ProtectedDonation"]),
                          {(1, "baa_signed_donation_envelope")})


class TestLiveDecoderCrossCheck(unittest.TestCase):
    """Layer-regression guard: across every available swift-protobuf binary, the
    field numbers ``decodeMessage`` switches on must NEVER include a number the
    nameMap lacks (independent codegen path).  Zero contradictions tool-wide."""
    def _binaries(self):
        for p in (_remindd_path(), _data_path(*_NPTO)):
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
                    p = S._type_from_namemap_symbol_like(name, "V13decodeMessage")
                    if p:
                        decoders.setdefault(p, va)
            for m in S.swift_messages(ctx):
                if not m.fields:
                    continue
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
        # field TYPES (from __swift5_fieldmd) also resolve cache-native.
        rec = {f.name: f.proto_type for f in self.msgs["CP_Record"].fields}
        self.assertEqual(rec["topic"], "string")
        self.assertEqual(rec["sentEpochMillis"], "uint64")
        self.assertEqual(rec["seqNum"], "CP_SequenceNumber")   # message ref

    def test_more_hand_verified_messages(self):
        # Ground truth (SWIFT_PROTO_HAND_VERIFICATION.md): closure numbers +
        # fieldmd types.
        seq = {(f.number, f.name, f.proto_type)
               for f in self.msgs["CP_SequenceNumber"].fields}
        self.assertEqual(seq, {(1, "publisherParticipantID", "uint64"),
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
        fmd = TR.recover_field_types(self.ctx)
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


class TestCli(unittest.TestCase):
    def test_not_a_macho_returns_2(self):
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as fh:
            fh.write(b"not a mach-o file at all, no valid header here")
            p = fh.name
        try:
            self.assertEqual(S._main([p]), 2)     # BinaryContext rejects → error 2
        finally:
            os.unlink(p)


@unittest.skipUnless(_remindd_path(), "remindd binary not available")
class TestCliLive(unittest.TestCase):
    def test_cli_emits_messages(self):
        import io
        import contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = S._main([_remindd_path(), "--all-shapes"])
        out = buf.getvalue()
        self.assertEqual(rc, 0)
        self.assertIn("message StartMigrationRequest {", out)
        self.assertIn("credential = 2;", out)
        self.assertIn("message StartMigrationRequest.Credential {", out)


class TestDisasmHitCap(unittest.TestCase):
    """`_disasm_hit_cap` decides whether a stop_at_ret disasm overran its window
    (so a runtime-_NameMap builder read off it may be INCOMPLETE → flag the
    recovered numbers estimated rather than launder a partial read as confirmed).
    A complete function stops at — and includes — its ret, so it ends on a ret
    mnemonic and/or is shorter than the cap."""

    def test_short_body_not_truncated(self):
        self.assertFalse(S._disasm_hit_cap([_FI("mov"), _FI("ret")], 400))

    def test_cap_length_ending_in_ret_not_truncated(self):
        body = [_FI("mov")] * 399 + [_FI("ret")]      # exactly cap, ends in ret
        self.assertFalse(S._disasm_hit_cap(body, 400))

    def test_cap_length_no_ret_is_truncated(self):
        body = [_FI("mov")] * 400                      # ran to cap, no ret reached
        self.assertTrue(S._disasm_hit_cap(body, 400))

    def test_retaa_retab_count_as_ret(self):
        for r in ("retaa", "retab"):
            body = [_FI("mov")] * 399 + [_FI(r)]
            self.assertFalse(S._disasm_hit_cap(body, 400))

    def test_empty_body_not_truncated(self):
        self.assertFalse(S._disasm_hit_cap([], 400))


class TestRuntimeNamemapFieldsHitCapLive(unittest.TestCase):
    """The 5 tests above only unit-test `_disasm_hit_cap` in isolation with bare
    `_FI` (mnemonic, op_str) stand-ins -- its one production caller,
    `_runtime_namemap_fields`, drives it off a REAL `disasm(ctx, ..., stop_at_ret=
    True)` call, and nothing anywhere in the suite exercised that call actually
    hitting its 400-instruction cap. Build a genuine (if synthetic) arm64
    instruction stream -- disassembled through capstone, not faked -- long
    enough to run out the cap without reaching a ret, embedding one real
    `_walk_namemap_builder`-recognizable (number, name) store, and confirm the
    real code path flags the recovered field `number_confirmed=False`."""

    _BUILDER_VA = 0x10000
    _PAGE_DELTA = 1
    _STR_OFF = 0x100
    _STR_VA = (_BUILDER_VA & ~0xFFF) + _PAGE_DELTA * 0x1000 + _STR_OFF
    _FIELD_NAME = "hitCapField"
    _FIELD_NUM = 7
    _CAP = 400

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
        return _FakeCtx(bytes(buf))

    def _getter_insns(self):
        # Only the once-init guard + cold-path branch target matter to
        # _runtime_namemap_fields's outer gate; these can be bare stand-ins --
        # it's the disasm() call AT the branch target that must be real.
        return [_FI("cmn", "x0, #1"), _FI("b.ne", f"#{self._BUILDER_VA}")]

    def test_builder_hitting_cap_flags_number_unconfirmed(self):
        ctx = self._build(self._CAP, terminate_with_ret=False)
        fields = S._runtime_namemap_fields(ctx, self._getter_insns())
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
        fields = S._runtime_namemap_fields(ctx, self._getter_insns())
        self.assertEqual(len(fields), 1)
        self.assertTrue(fields[0].number_confirmed)


if __name__ == "__main__":
    unittest.main()
