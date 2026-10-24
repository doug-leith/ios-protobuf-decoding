"""Packed-bytecode ``_NameMap`` decoder (serializers/swift_namemap_bytecode, PROTOTYPE).

All vectors are REAL literals read from the iOS 27 dyld cache (CipherML,
WorkoutKit), so the delta/continuation-integer encoding is pinned to what the
toolchain actually emitted.  Offline: no binary needed.
"""
import unittest

from serializers import swift_namemap_bytecode as B
from tests._listing import insns as _listing
from tests._fakes import NoImage


class _Ctx(NoImage):
    """*data* at *base*: one section of ``__TEXT``."""
    def __init__(self, data, base):
        from types import SimpleNamespace
        self._d, self._b = data, base
        self._sections = [SimpleNamespace(vmaddr=base, vmsize=len(data))]

    def segment_at(self, va):
        from types import SimpleNamespace
        if self._b <= va < self._b + len(self._d):
            return SimpleNamespace(name="__TEXT", sections=self._sections)
        return None

    def is_variable(self, vmaddr):        # no program data, no binds
        return False

    def read_bytes(self, va, n):
        off = va - self._b
        if off < 0 or off + n > len(self._d):
            raise ValueError("oob")
        return self._d[off:off + n]


class TestTheLiteralLiesInText(unittest.TestCase):
    """A literal is read only when all of it lies in one section of ``__TEXT`` (iOS 27: every
    name-map literal is in ``__TEXT,__const``; a "length" read off registers holding something
    else points into ``__DATA`` with a length of some 3e9).  No length limit besides."""

    def test_any_length_in_text(self):
        ctx = _Ctx(b"\0" * 0x2000, 0x4000)
        self.assertEqual(len(B._read(ctx, 0x4000, 0x1800)), 0x1800)      # past the old 4096

    def test_not_past_its_section_nor_outside_text(self):
        from types import SimpleNamespace
        ctx = _Ctx(b"\0" * 0x2000, 0x4000)
        self.assertIsNone(B._read(ctx, 0x4000, 0x2001))
        ctx.segment_at = lambda va: SimpleNamespace(name="__DATA", sections=ctx._sections)
        self.assertIsNone(B._read(ctx, 0x4000, 0x10))


class TestDecode(unittest.TestCase):
    def test_sequential_same_next(self):
        # CipherML AspireApiEvaluationKeyMetadata
        raw = b"\x00\x01timestamp\x00\x01identifier\x00"
        self.assertEqual(B.decode_namemap_bytecode(raw),
                         [(1, "timestamp"), (2, "identifier")])

    def test_standard_next_and_trailing_reserved_range(self):
        # CipherML AspireApiKeyStatus: op 3 (JSON derived) + trailing op 12
        # reservedNumbers, which declares no field
        raw = b"\x00\x01timestamp\x00\x03key_config\x00\x0c\x03\x01"
        self.assertEqual(B.decode_namemap_bytecode(raw),
                         [(1, "timestamp"), (2, "key_config")])

    def test_single_byte_delta(self):
        # CipherML AspireApiPIRConfig: `\x04\x03batch_pir_params` = standardDelta, +3
        raw = (b"\x00\x03a\x00\x03b\x00\x04\x03c\x00")
        self.assertEqual(B.decode_namemap_bytecode(raw),
                         [(1, "a"), (2, "b"), (5, "c")])

    def test_multibyte_delta_uses_6bit_groups_with_0x40_continuation(self):
        # WorkoutKit Apple_Workout_WorkoutPlan: ids 9..14, then 100..102, 1000..1002.
        # 'V\x01' = 0x16 | 1<<6 = 86 (14+86=100); 'B\x0e' = 2 | 14<<6 = 898 (102+898=1000).
        raw = (b"\x00\x02\tid\x00\x01goalComposition\x00\x01customComposition\x00"
               b"\x02\x02pacerComposition\x00\x01swimBikeRunComposition\x00"
               b"\x02V\x01route\x00\x01referenceId\x00\x01alternativeUUIDs\x00"
               b"\x02B\x0emajorVersion\x00\x01minorVersion\x00\x01privateVersion\x00")
        self.assertEqual(B.decode_namemap_bytecode(raw), [
            (9, "id"), (10, "goalComposition"), (11, "customComposition"),
            (13, "pacerComposition"), (14, "swimBikeRunComposition"),
            (100, "route"), (101, "referenceId"), (102, "alternativeUUIDs"),
            (1000, "majorVersion"), (1001, "minorVersion"), (1002, "privateVersion")])

    def test_unique_name_consumes_json_name(self):
        raw = b"\x00\x05proto_name\x00jsonName\x00\x01next\x00"
        self.assertEqual(B.decode_namemap_bytecode(raw),
                         [(1, "proto_name"), (2, "next")])

    def test_reserved_name_skipped(self):
        raw = b"\x00\x0boldname\x00\x01x\x00"
        self.assertEqual(B.decode_namemap_bytecode(raw), [(1, "x")])

    def test_malformed_returns_none_rather_than_fabricating(self):
        self.assertIsNone(B.decode_namemap_bytecode(b""))
        self.assertIsNone(B.decode_namemap_bytecode(b"capabilities"))   # shape-B bare name
        self.assertIsNone(B.decode_namemap_bytecode(b"\x00\x01unterminated"))
        self.assertIsNone(B.decode_namemap_bytecode(b"\x00\x7fjunk\x00"))   # bad opcode
        self.assertIsNone(B.decode_namemap_bytecode(b"\x00\x02\x40"))       # truncated int


class TestLiteralFromGetter(unittest.TestCase):
    def test_reads_x2_literal_and_w3_length(self):
        lit = b"\x00\x01timestamp\x00\x01identifier\x00"
        data = b"\x00" * 0x1c0 + lit
        ctx = _Ctx(data, 0x22b73a000 - 0x0)   # base such that 0x22b73a1c0 -> offset 0x1c0
        insns = [("adrp", "x1, #0x2706aa000"), ("add", "x1, x1, #0x2e8"),
                 ("adrp", "x2, #0x22b73a000"), ("add", "x2, x2, #0x1c0"),
                 ("mov", "w3, #0x18"), ("b", "#0x22b6b11c8")]
        got = B.bytecode_literal_from_getter(ctx, _listing(insns))
        self.assertEqual(got, lit)
        self.assertEqual(B.decode_namemap_bytecode(got),
                         [(1, "timestamp"), (2, "identifier")])

    def test_inline_form_x0_ptr_w1_len_w2_flags_then_bl(self):
        # WorkoutKit inline getter: literal via x9 -> x0, len w1, StaticString flags
        # w2=#2, then `bl _NameMap.init(bytecode:)`; a preceding bl must not matter.
        lit = b"\x00\x01name\x00\x01value\x00"
        data = b"\x00" * 0x40 + lit
        ctx = _Ctx(data, 0x1000)                       # 0x1040 -> offset 0x40
        insns = [("bl", "#0x2000"),
                 ("adrp", "x9, #0x1000"), ("add", "x9, x9, #0x40"),
                 ("mov", "x8, x0"), ("mov", "x0, x9"),
                 ("mov", "w1, #%d" % len(lit)), ("mov", "w2, #2"),
                 ("bl", "#0x3000"), ("ret", "")]
        self.assertEqual(B.bytecode_literal_from_getter(ctx, _listing(insns)), lit)

    def test_inline_form_requires_staticstring_flags_and_valid_bytecode(self):
        bare = b"capabilities"                          # not a bytecode (no header)
        ctx = _Ctx(b"\x00" * 0x40 + bare, 0x1000)
        insns = [("adrp", "x0, #0x1000"), ("add", "x0, x0, #0x40"),
                 ("mov", "w1, #12"), ("mov", "w2, #2"), ("bl", "#0x3000")]
        self.assertIsNone(B.bytecode_literal_from_getter(ctx, _listing(insns)))
        insns[3] = ("mov", "w2, #0")                 # wrong flags
        self.assertIsNone(B.bytecode_literal_from_getter(ctx, _listing(insns)))

    def test_registers_clobbered_by_call_are_not_reused(self):
        lit = b"\x00\x01a\x00"
        ctx = _Ctx(b"\x00" * 0x40 + lit, 0x1000)
        insns = [("adrp", "x0, #0x1000"), ("add", "x0, x0, #0x40"),
                 ("mov", "w1, #4"), ("mov", "w2, #2"),
                 ("bl", "#0x5000"),                 # clobbers x0-x17 (this call has no literal ... ok)
                 ("bl", "#0x6000")]
        # first bl already sees a complete, valid argument set and accepts it
        self.assertEqual(B.bytecode_literal_from_getter(ctx, _listing(insns)), lit)

    def test_non_dispatch_getter_rejected(self):
        insns = [("adrp", "x2, #0x1000"), ("add", "x2, x2, #0"),
                 ("cmn", "x8, #1"), ("mov", "w3, #4"), ("b", "#0x40")]
        self.assertIsNone(B.bytecode_literal_from_getter(_Ctx(b"", 0), _listing(insns)))


class TestEnumBytecode(unittest.TestCase):
    """Real enum literals from tests/swift_enum_oracle_fixture/eo_bytecode (protoc-gen-swift
    1.33.3).  Integers are signed 32-bit; an enum's first value 0 / a negative value
    needs an explicit delta; an alias list is a count then that many names."""
    TOP = b"\x00\x02{\x7f\x7f\x7f\x7f\x03T_NEG\x00\x02\x05T_ZERO\x00\x01T_ONE\x00\x02_Z\x18T_BIG\x00"
    ALIASED = b"\x00\x02\x00AL_X\x00\tAL_Y\x00\x01AL_Y2\x00\x01AL_Z\x00"
    INNER = b"\x00\x02\x00I_A\x00\x02\x03I_B\x00"

    def test_negative_zero_and_large_values(self):
        self.assertEqual(B.decode_namemap_bytecode(self.TOP, enum=True),
                         [(-5, "T_NEG"), (0, "T_ZERO"), (1, "T_ONE"), (100000, "T_BIG")])

    def test_alias_entries_share_the_primary_number(self):
        self.assertEqual(B.decode_namemap_bytecode(self.ALIASED, enum=True),
                         [(0, "AL_X"), (1, "AL_Y"), (1, "AL_Y2"), (2, "AL_Z")])

    def test_any_number_of_aliases(self):
        # 65 aliases (one past the old limit of 64); a count past the data is unterminated
        names = [f"AL_{i}" for i in range(65)]
        raw = b"\x00\x02\x00AL_X\x00\tAL_Y\x00\x41\x01" + b"".join(n.encode() + b"\x00" for n in names)
        self.assertEqual(B.decode_namemap_bytecode(raw, enum=True),
                         [(0, "AL_X"), (1, "AL_Y")] + [(1, n) for n in names])
        self.assertIsNone(B.decode_namemap_bytecode(raw[:-4], enum=True))

    def test_zero_first_value(self):
        self.assertEqual(B.decode_namemap_bytecode(self.INNER, enum=True), [(0, "I_A"), (3, "I_B")])

    def test_message_mode_rejects_zero_and_negative_numbers(self):
        # a field number is >= 1: the same bytes are not a valid MESSAGE name map
        self.assertIsNone(B.decode_namemap_bytecode(self.INNER))
        self.assertIsNone(B.decode_namemap_bytecode(self.TOP))

    def test_inline_locator_honours_enum_flag(self):
        data = b"\x00" * 0x40 + self.INNER
        ctx = _Ctx(data, 0x1000)
        insns = [("adrp", "x0, #0x1000"), ("add", "x0, x0, #0x40"), ("mov", "x8, sp"),
                 ("mov", "w1, #%d" % len(self.INNER)), ("mov", "w2, #2"), ("bl", "#0x3000")]
        self.assertIsNone(B.bytecode_literal_from_getter(ctx, _listing(insns)))
        self.assertEqual(B.bytecode_literal_from_getter(ctx, _listing(insns), enum=True), self.INNER)


if __name__ == "__main__":
    unittest.main()
