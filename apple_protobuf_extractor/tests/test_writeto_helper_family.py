"""TODO #38/#44 — `_classify_write_helper`: recover sint32/sint64 (zigzag
`lsl (w|x)1,#1` shift) and fixed32/fixed64 (tag wire-type `mov w_,#{5,1}` +
`bfi w_,w<field>,#3,#0x1d`) from the writeTo: write-helper's structural signature.

Offline unit tests drive the classifier with hand-assembled arm64 (self-checked by
disassembling first), covering the PLT-style stub follow, the w1/x1 width split, the
plain fallback, the direct (non-stub) path, and the fixed tag wire-type immediates.
Live tests assert the real flips on the cache (the helper VA is the wire contract, so
these are ground truth).
"""
import os
import struct
import unittest

from macho.disasm import disasm
import proto.extractor as E
import proto.write_helpers as WH   # _classify_write_helper now lives here


# ── arm64 encoders (only what this test needs) ────────────────────────────────
def _enc_lsl(rd, rn, shift, sf):
    """LSL (immediate) = UBFM Rd,Rn,#(-shift mod w),#(w-1-shift)."""
    w = 64 if sf else 32
    immr = (-shift) % w
    imms = w - 1 - shift
    word = ((sf << 31) | (0b10 << 29) | (0b100110 << 23) | (sf << 22)
            | (immr << 16) | (imms << 10) | (rn << 5) | rd)
    return struct.pack('<I', word)


def _enc_mov(rd, rm):                 # MOV Xd,Xm  == ORR Xd,XZR,Xm
    word = 0xAA000000 | (rm << 16) | (31 << 5) | rd
    return struct.pack('<I', word)


def _enc_adrp(rd, pages_delta):
    imm21 = pages_delta & 0x1FFFFF
    word = 0x90000000 | ((imm21 & 0x3) << 29) | (((imm21 >> 2) & 0x7FFFF) << 5) | rd
    return struct.pack('<I', word)


def _enc_add(rd, rn, imm):
    return struct.pack('<I', 0x91000000 | (imm << 10) | (rn << 5) | rd)


def _enc_movz(rd, imm):               # MOVZ Wd,#imm  (capstone aliases to `mov`)
    return struct.pack('<I', 0x52800000 | ((imm & 0xFFFF) << 5) | rd)


def _enc_bfi(rd, rn, lsb, width):     # BFI Wd,Wn,#lsb,#width == BFM Wd,Wn,#immr,#imms
    immr = (-lsb) % 32
    imms = width - 1
    word = ((0b01 << 29) | (0b100110 << 23) | (immr << 16) | (imms << 10)
            | (rn << 5) | rd)
    return struct.pack('<I', word)


def _enc_br(rn):
    return struct.pack('<I', 0xD61F0000 | (rn << 5))


def _enc_ret():
    return struct.pack('<I', 0xD65F03C0)


class _RegionCtx:
    """ctx serving bytes from named regions {base: buffer} (for cross-'image' reads)."""
    def __init__(self, regions):
        self._regions = dict(regions)

    def _find(self, va, length):
        for base, buf in self._regions.items():
            if base <= va and va + length <= base + len(buf):
                return base, buf
        raise ValueError(f"unmapped {va:#x}")

    def read_bytes(self, va, length):
        base, buf = self._find(va, length)
        return buf[va - base: va - base + length]

    def vmaddr_to_offset(self, va, length=1):
        base, _ = self._find(va, length)
        return va - base


class TestClassifyWriteHelperOffline(unittest.TestCase):
    # Two pages apart so adrp pages_delta is non-zero (exercises the stub follow).
    STUB = 0x180001000
    TGT  = 0x1a0002000

    def _self_check(self, va, buf, expect_first):
        ctx = _RegionCtx({va: buf})
        ins = disasm(ctx, va, max_insns=1, stop_at_ret=False)
        self.assertEqual(ins[0].mnemonic, expect_first,
                         f"encoder produced {ins[0].mnemonic} {ins[0].op_str}")

    def _stub_to(self, target):
        d = (target & ~0xFFF) - (self.STUB & ~0xFFF)
        return _enc_adrp(16, d >> 12) + _enc_add(16, 16, target & 0xFFF) + _enc_br(16)

    def _classify(self, target_body):
        ctx = _RegionCtx({self.STUB: self._stub_to(self.TGT), self.TGT: target_body})
        return WH._classify_write_helper(ctx, self.STUB)

    def test_encoder_helpers_produce_expected_mnemonics(self):
        # Test-infrastructure sanity check ONLY: confirms this file's hand-rolled
        # arm64 encoders (_enc_lsl/_enc_mov/_enc_movz/_enc_bfi) round-trip through
        # the real disassembler to the mnemonics the other tests below assume —
        # it never calls proto.write_helpers._classify_write_helper (the commit's
        # actual production function), so it is NOT a regression test for the
        # sint/fixed recovery feature; see the _classify()-driven tests below for
        # that.
        self._self_check(self.TGT, _enc_lsl(8, 1, 1, sf=0), 'lsl')
        self._self_check(self.TGT, _enc_lsl(23, 1, 1, sf=1), 'lsl')
        self._self_check(self.TGT, _enc_mov(20, 1), 'mov')
        # MOVZ #imm aliases to `mov w_,#imm`; BFI decodes back to `bfi …,#3,#0x1d`.
        self._self_check(self.TGT, _enc_movz(9, 5), 'mov')
        ctx = _RegionCtx({self.TGT: _enc_bfi(9, 21, 3, 29)})
        ins = disasm(ctx, self.TGT, max_insns=1, stop_at_ret=False)[0]
        self.assertEqual(ins.mnemonic, 'bfi')
        ops = [o.strip() for o in ins.op_str.split(',')]
        self.assertEqual(ops[0], 'w9')
        self.assertEqual(ops[2], '#3')

    def test_stub_follow_zigzag32_is_sint32(self):
        body = _enc_mov(19, 0) + _enc_lsl(8, 1, 1, sf=0) + _enc_ret()
        self.assertEqual(self._classify(body), 'sint32')

    def test_stub_follow_zigzag64_is_sint64(self):
        body = _enc_mov(19, 0) + _enc_lsl(23, 1, 1, sf=1) + _enc_ret()
        self.assertEqual(self._classify(body), 'sint64')

    def test_plain_value_passthrough_is_plain(self):
        body = _enc_mov(20, 1) + _enc_ret()           # value unmodified
        self.assertEqual(self._classify(body), 'plain')

    def test_lsl_on_non_value_reg_is_plain(self):
        # A shift of a register that is NOT the value arg (w1/x1) is not zigzag.
        body = _enc_lsl(8, 9, 1, sf=0) + _enc_ret()
        self.assertEqual(self._classify(body), 'plain')

    def test_fixed32_tag_wire_type_5(self):
        # tag = (field<<3)|5  → 32-bit fixed.  bfi sits ~28 insns in on the real
        # helper, so pad the body to exercise the scan budget.
        pad = _enc_mov(8, 9) * 24
        body = pad + _enc_movz(9, 5) + _enc_bfi(9, 21, 3, 29) + _enc_ret()
        self.assertEqual(self._classify(body), 'fixed32')

    def test_fixed64_tag_wire_type_1(self):
        pad = _enc_mov(8, 9) * 24
        body = pad + _enc_movz(9, 1) + _enc_bfi(9, 21, 3, 29) + _enc_ret()
        self.assertEqual(self._classify(body), 'fixed64')

    def test_lendelim_tag_wire_type_2_is_plain(self):
        # wire type 2 (length-delimited / inline-struct bracket) is NOT fixed.
        body = _enc_movz(9, 2) + _enc_bfi(9, 21, 3, 29) + _enc_ret()
        self.assertEqual(self._classify(body), 'plain')
        # On its own, wt=2 never reaches the mov/bfi fixed32/64 detection at all
        # (2 matches neither 5 nor 1), so this negative case alone can't tell
        # whether that detection exists or was reverted.  Pair it with the wt=5
        # positive case (same mov/bfi shape, real fixed wire type) so this test
        # alone would have failed on the pre-#44 code.
        pad = _enc_mov(8, 9) * 24
        fixed_body = pad + _enc_movz(9, 5) + _enc_bfi(9, 21, 3, 29) + _enc_ret()
        self.assertEqual(self._classify(fixed_body), 'fixed32')

    def test_varint_tag_shift_is_plain(self):
        # Plain varint builds the tag with `lsl w_,w<field>,#3` (no mov+bfi).  The
        # field# (w2/x2) is moved to a callee-saved reg first, then shifted by 3 — that
        # tag-build IS the plain terminator (#59), and it must not be mistaken for the
        # zigzag value shift (`lsl …,w1,#1`).
        # NOTE: for THIS short (3-insn) body alone, the #59 "stop at the
        # terminator" mechanism is TAUTOLOGICAL -- the unconditional 'plain'
        # fallback and the genuine terminator match agree here regardless of
        # whether #59's early-stop logic fires at all (nothing else in this
        # short body could flip the verdict either way).  See
        # test_plain_terminator_stops_at_tag_build_not_budget below (same
        # class) for a body where a broken/budget-exhausting scan WOULD
        # disagree with the terminator-match verdict -- that is what actually
        # discriminates #59's mechanism.
        body = _enc_mov(21, 2) + _enc_lsl(10, 21, 3, sf=0) + _enc_ret()
        self.assertEqual(self._classify(body), 'plain')
        # This input (register w21/shift 3) never matches the mov/bfi idiom's
        # register or shift-amount pattern either, so it can't discriminate the
        # #44 fixed32/64 detection on its own.  Pair with a wt=1 (fixed64)
        # positive case using the real mov/bfi encoding.
        pad = _enc_mov(8, 9) * 24
        fixed_body = pad + _enc_movz(9, 1) + _enc_bfi(9, 21, 3, 29) + _enc_ret()
        self.assertEqual(self._classify(fixed_body), 'fixed64')

    def test_plain_terminator_stops_at_tag_build_not_budget(self):
        # #59: the plain verdict comes from the tag-build, NOT from exhausting the
        # scan budget.  Put a (would-be sint) `lsl w8,w1,#1` AFTER the plain tag-build:
        # if the scan stopped at the tag-build it stays 'plain'; if it kept scanning to
        # the budget it would wrongly flip to 'sint32'.
        body = (_enc_mov(21, 2)               # field# -> x21
                + _enc_lsl(10, 21, 3, sf=0)   # plain varint tag (wt 0) — STOP here
                + _enc_lsl(8, 1, 1, sf=0)     # zigzag value shift — must NOT be reached
                + _enc_ret())
        self.assertEqual(self._classify(body), 'plain')   # NOT 'sint32'

    def test_index_scale_lsl3_on_nonfield_reg_does_not_block_fixed(self):
        # An `lsl Rd,Rs,#3` whose source is NOT the field# reg (e.g. an array
        # index *8 scale) must be ignored, not treated as the plain tag-build — so a
        # later fixed `bfi` still classifies as fixed32.
        body = (_enc_lsl(8, 9, 3, sf=0)       # index scale on w9 (not field#) — ignore
                + _enc_movz(9, 5)
                + _enc_bfi(9, 21, 3, 29)      # fixed32 tag
                + _enc_ret())
        self.assertEqual(self._classify(body), 'fixed32')
        # Contrast: the SAME lsl-by-3 shape, but its source IS the field# reg
        # (w21, set up by the mov below) — the register-gate must actually let
        # the plain tag-build terminator fire here, confirming the gate is
        # selective (rejects non-field-reg lsl-by-3, accepts field-reg
        # lsl-by-3) rather than just absent.  A would-be zigzag `lsl w8,w1,#1`
        # AFTER the field-reg lsl-by-3 makes this genuinely discriminating:
        # if the terminator didn't actually fire (fell through to the
        # unconditional 'plain' default instead), the scan would keep going
        # and wrongly find the later zigzag, flipping the verdict to 'sint32'.
        field_reg_body = (_enc_mov(21, 2)             # field# -> x21
                          + _enc_lsl(10, 21, 3, sf=0)  # lsl on the field reg -> plain terminator
                          + _enc_lsl(8, 1, 1, sf=0)    # zigzag value shift — must NOT be reached
                          + _enc_ret())
        self.assertEqual(self._classify(field_reg_body), 'plain')   # NOT 'sint32'

    def test_fixed_tag_after_size_test_shift_newer_toolchain(self):
        # The newer toolchain (iOS 27 / macOS 27) opens EVERY helper with
        # `lsl w10,w21,#3` (the tag-size test, `cmp w10,#0x80`) and only then builds a
        # fixed-width helper's tag: `mov w9,#5 ; bfi w9,w21,#3,#0x1d`.  The shift must not
        # end the scan; the `bfi` that follows in the same block decides.
        pad = _enc_mov(8, 9) * 4
        for wt, want in ((5, 'fixed32'), (1, 'fixed64')):
            body = (_enc_mov(21, 2) + pad
                    + _enc_lsl(10, 21, 3, sf=0)        # size test, not the tag build
                    + _enc_movz(9, wt) + _enc_bfi(9, 21, 3, 29)
                    + _enc_ret())
            self.assertEqual(self._classify(body), want)

    def test_size_test_shift_then_block_end_is_plain(self):
        # Same shift, but the block ends (a `ret`/branch) before any wire-type `bfi`:
        # a `bfi` in a LATER block belongs to another path and must not be read —
        # this is the plain varint helper.
        body = (_enc_mov(21, 2) + _enc_lsl(10, 21, 3, sf=0) + _enc_ret()
                + _enc_movz(9, 5) + _enc_bfi(9, 21, 3, 29))
        self.assertEqual(self._classify(body), 'plain')

    def test_direct_non_stub_zigzag(self):
        # A helper whose body IS the zigzag (no PLT stub) — the direct-bl shape.
        body = _enc_lsl(8, 1, 1, sf=0) + _enc_ret()
        ctx = _RegionCtx({self.TGT: body})
        self.assertEqual(WH._classify_write_helper(ctx, self.TGT), 'sint32')

    def test_falsy_helper_va_short_circuits_before_disasm(self):
        # test_none_helper_is_plain (below) can't discriminate the explicit
        # `if not helper_va: return "plain"` guard: `disasm(ctx, None, ...)` raises
        # inside the try block, and the surrounding `except Exception: fam="plain"`
        # ALSO falls back to "plain" regardless of the guard. Use helper_va=0 (also
        # falsy -- a real "no helper resolved" value) over a ctx region that WOULD
        # disassemble successfully to a zigzag shift if the guard didn't short-circuit
        # first, so only the explicit guard -- not the except -- is what's protective.
        ctx = _RegionCtx({0: _enc_lsl(8, 1, 1, sf=0) + _enc_ret()})
        self.assertEqual(WH._classify_write_helper(ctx, 0), 'plain')

    def test_none_helper_is_plain(self):
        self.assertEqual(WH._classify_write_helper(_RegionCtx({}), None), 'plain')


# ── Live cache assertions (the helper VA is the wire contract → ground truth) ──
def _find_cache():
    for p in (os.path.expanduser('~/dyld_shared_cache_arm64e'),
              'dylib', 'artifacts'):
        if os.path.exists(p):
            return True
    return os.path.exists('dylib')


try:
    import validate_lever as _V
    _HAVE = _V._load_cache('GeoServices') is not None
except Exception:
    _HAVE = False


@unittest.skipUnless(_HAVE, 'GeoServices cache not available')
class TestSintRecoveryLive(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import validate_lever as V
        cls.ctx, cls.st, cls.cl = V._load_cache('GeoServices')
        cls.msgs = {m.class_name: m for m in E.extract_all(cls.ctx, cls.st, cls.cl)}

    def _field(self, cn, fn):
        m = self.msgs.get(cn)
        self.assertIsNotNone(m, f'{cn} missing')
        f = next((x for x in m.fields if x.name == fn), None)
        self.assertIsNotNone(f, f'{cn}.{fn} missing')
        return f

    def test_classifier_on_real_helper_vas(self):
        # Ground-truthed stub VAs (GeoServices → ProtocolBuffer.framework).
        self.assertEqual(WH._classify_write_helper(self.ctx, 0x18dbdac00), 'sint32')
        self.assertEqual(WH._classify_write_helper(self.ctx, 0x18dbdac0c), 'sint64')
        self.assertEqual(WH._classify_write_helper(self.ctx, 0x18dbdabd0), 'plain')
        self.assertEqual(WH._classify_write_helper(self.ctx, 0x18dbdac30), 'plain')
        # TODO #44: fixed32 (wire 5) / fixed64 (wire 1) tag-builder helpers.
        self.assertEqual(WH._classify_write_helper(self.ctx, 0x18dbdabe8), 'fixed32')
        self.assertEqual(WH._classify_write_helper(self.ctx, 0x18dbdabf4), 'fixed64')

    def test_fixed32_flips(self):
        # E7 coordinates write fixed32; signed ivar → sfixed32 (lat/lng go negative).
        self.assertEqual(self._field('GEOLatLngE7', 'latE7').type_name, 'sfixed32')
        self.assertEqual(self._field('GEOMapRegionE7', 'westLngE7').type_name, 'sfixed32')

    def test_fixed64_flips(self):
        # GEORouteIncident timestamps write fixed64; signed ivar → sfixed64.
        self.assertEqual(self._field('GEORouteIncident', 'startTime').type_name,
                         'sfixed64')

    def test_sint32_flips(self):
        # Signed signal metrics → sint32 (negative dBm).
        self.assertEqual(self._field('GEOCellConnectionQuality', 'cellLteRSRP').type_name,
                         'sint32')
        self.assertEqual(self._field('GEOPoint', 'elevationCm').type_name, 'sint32')

    def test_sint64_flips(self):
        self.assertEqual(self._field('GEOABConfigValue', 'intValue').type_name, 'sint64')
        self.assertEqual(self._field('GEOTFRoadSpeed', 'geoid').type_name, 'sint64')

    def test_plain_field_unchanged(self):
        # sequence_number is a positive counter → plain varint; the reference's
        # `sint32` claim is a reference error.  Must stay non-sint.  On its own
        # this is a negative control only (sequenceNumber was never sint under
        # either version); the sint-recovery positive cases are
        # test_sint32_flips/test_sint64_flips above, in this same class/file,
        # which always run alongside this one.
        self.assertNotIn('sint',
                         self._field('GEOMapServiceTraits', 'sequenceNumber').type_name)


if __name__ == '__main__':
    unittest.main()
