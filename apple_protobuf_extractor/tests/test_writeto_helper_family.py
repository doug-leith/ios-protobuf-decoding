"""TODO #38/#44 — `_classify_write_helper`: recover sint32/sint64 and fixed32/fixed64 from
what the writeTo: write helper computes when run with probe arguments (#112): the zigzag
of its value argument, and the wire type in the tag ``field << 3 | wire type`` it builds.

Offline unit tests drive the classifier with hand-assembled arm64 (self-checked by
disassembling first), covering the PLT-style stub follow, the 32- / 64-bit zigzag, the
plain varint, the direct (non-stub) path, and the fixed tag wire types.
Live tests assert the real flips on the cache (the helper VA is the wire contract, so
these are ground truth).
"""
import os
import struct
import unittest

from macho.disasm import disasm
from tests._fakes import NoImage
import proto.extractor as E
import proto.write_helpers as WH   # _classify_write_helper now lives here
import pytest


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


def _enc_eor_asr(rd, rn, rm, shift, sf):   # EOR Rd,Rn,Rm,ASR #shift
    word = (0xCA000000 if sf else 0x4A000000) | (0b10 << 22) | (rm << 16) | (shift << 10) \
        | (rn << 5) | rd
    return struct.pack('<I', word)


def _zigzag_body(sf):
    """The zigzag of the value argument, ``(v << 1) ^ (v >> width-1)``: an sint helper."""
    return _enc_lsl(8, 1, 1, sf=sf) + _enc_eor_asr(8, 8, 1, 63 if sf else 31, sf)


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


class _RegionCtx(NoImage):
    """ctx serving bytes from named regions {base: buffer} (for cross-'image' reads)."""
    def __init__(self, regions):
        self._regions = dict(regions)

    def _find(self, va, length):
        for base, buf in self._regions.items():
            if base <= va and va + length <= base + len(buf):
                return base, buf
        raise ValueError(f"unmapped {va:#x}")

    def is_variable(self, vmaddr):        # no program data, no binds
        return False

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
        body = _enc_mov(19, 0) + _zigzag_body(sf=0) + _enc_ret()
        self.assertEqual(self._classify(body), 'sint32')

    def test_stub_follow_zigzag64_is_sint64(self):
        body = _enc_mov(19, 0) + _zigzag_body(sf=1) + _enc_ret()
        self.assertEqual(self._classify(body), 'sint64')

    def test_value_passthrough_without_a_tag_build_is_unknown(self):
        body = _enc_mov(20, 1) + _enc_ret()           # value unmodified, no tag built
        self.assertEqual(self._classify(body), 'unknown')

    def test_a_shift_alone_is_not_a_zigzag(self):
        # `lsl w8, w1, #1` without the `eor` of the sign is not the sint encoding, nor is a
        # shift of a register that is not the value
        self.assertEqual(self._classify(_enc_lsl(8, 1, 1, sf=0) + _enc_ret()), 'unknown')
        self.assertEqual(self._classify(_enc_lsl(8, 9, 1, sf=0) + _enc_ret()), 'unknown')

    def _tag_body(self, wt, pad=24):
        # the field number (w2) copied to a callee-saved register, then the tag built
        return (_enc_mov(21, 2) + _enc_mov(8, 9) * pad
                + _enc_movz(9, wt) + _enc_bfi(9, 21, 3, 29) + _enc_ret())

    def test_fixed32_tag_wire_type_5(self):
        self.assertEqual(self._classify(self._tag_body(5)), 'fixed32')

    def test_fixed64_tag_wire_type_1(self):
        self.assertEqual(self._classify(self._tag_body(1)), 'fixed64')

    def test_a_floating_point_writer_takes_its_field_number_in_w1(self):
        # PBDataWriterWriteFloatField(writer, value v0, field w1): `mov x20, x1` is the field
        body = _enc_mov(20, 1) + _enc_movz(9, 5) + _enc_bfi(9, 20, 3, 29) + _enc_ret()
        self.assertEqual(self._classify(body), 'fixed32')

    def test_lendelim_tag_wire_type_2_is_plain(self):
        # wire type 2 (length-delimited / inline-struct bracket) is not fixed
        self.assertEqual(self._classify(self._tag_body(2, pad=0)), 'plain')

    def test_varint_tag_is_plain(self):
        # plain varint: tag = field << 3 (wire type 0), the value encoded as it came
        body = _enc_mov(21, 2) + _enc_lsl(10, 21, 3, sf=0) + _enc_ret()
        self.assertEqual(self._classify(body), 'plain')

    def test_a_value_shift_after_the_varint_tag_is_not_a_zigzag(self):
        body = (_enc_mov(21, 2) + _enc_lsl(10, 21, 3, sf=0)   # plain varint tag
                + _enc_lsl(8, 1, 1, sf=0)                      # value << 1: no sign eor
                + _enc_ret())
        self.assertEqual(self._classify(body), 'plain')

    def test_index_scale_lsl3_on_a_non_field_register_does_not_matter(self):
        # an `lsl Rd, Rs, #3` of something else (an index * 8) computes no tag
        body = (_enc_mov(21, 2) + _enc_lsl(8, 9, 3, sf=0)
                + _enc_movz(9, 5) + _enc_bfi(9, 21, 3, 29) + _enc_ret())
        self.assertEqual(self._classify(body), 'fixed32')

    def test_fixed_tag_after_size_test_shift_newer_toolchain(self):
        # The newer toolchain (iOS 27 / macOS 27) opens EVERY helper with
        # `lsl w10,w21,#3` (the tag-size test, `cmp w10,#0x80`) and only then builds a
        # fixed-width helper's tag: `mov w9,#5 ; bfi w9,w21,#3,#0x1d`.  Both values are
        # computed; the wire type that is not 0 is the helper's.
        pad = _enc_mov(8, 9) * 4
        for wt, want in ((5, 'fixed32'), (1, 'fixed64')):
            body = (_enc_mov(21, 2) + pad
                    + _enc_lsl(10, 21, 3, sf=0)        # size test, not the tag build
                    + _enc_movz(9, wt) + _enc_bfi(9, 21, 3, 29)
                    + _enc_ret())
            self.assertEqual(self._classify(body), want)

    def test_code_past_the_return_is_not_run(self):
        # a `bfi` no path from the entry reaches is not the helper's
        body = (_enc_mov(21, 2) + _enc_lsl(10, 21, 3, sf=0) + _enc_ret()
                + _enc_movz(9, 5) + _enc_bfi(9, 21, 3, 29))
        self.assertEqual(self._classify(body), 'plain')

    def test_direct_non_stub_zigzag(self):
        # A helper whose body IS the zigzag (no PLT stub) — the direct-bl shape.
        ctx = _RegionCtx({self.TGT: _zigzag_body(sf=0) + _enc_ret()})
        self.assertEqual(WH._classify_write_helper(ctx, self.TGT), 'sint32')

    def test_falsy_helper_va_short_circuits_before_disasm(self):
        # helper_va 0 ("no helper resolved") over a region that WOULD disassemble to a
        # zigzag shift: only the explicit guard, not the except, gives "unknown" here.
        ctx = _RegionCtx({0: _enc_lsl(8, 1, 1, sf=0) + _enc_ret()})
        self.assertEqual(WH._classify_write_helper(ctx, 0), 'unknown')

    def test_none_helper_is_unknown(self):
        self.assertEqual(WH._classify_write_helper(_RegionCtx({}), None), 'unknown')

    def test_a_helper_with_no_tag_build_is_unknown_not_plain(self):
        # neither a zigzag shift, a wire-type bfi nor the plain tag shift: nothing decided it
        self.assertEqual(self._classify(_enc_movz(9, 5) + _enc_ret()), 'unknown')


# ── Live cache assertions (the helper VA is the wire contract → ground truth) ──
def _find_cache():
    for p in (os.path.expanduser('~/dyld_shared_cache_arm64e'),
              'dylib', 'artifacts'):
        if os.path.exists(p):
            return True
    return os.path.exists('dylib')


try:
    import live_artifacts as _V
    _HAVE = _V.load_cache('GeoServices') is not None
except Exception:
    _HAVE = False


@pytest.mark.slow
@pytest.mark.xdist_group("geoservices_iphone8")
@unittest.skipUnless(_HAVE, 'GeoServices cache not available')
class TestSintRecoveryLive(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tests._live import extracted
        cls.ctx, cls.st, cls.cl, msgs = extracted('GeoServices')
        cls.msgs = {m.class_name: m for m in msgs}

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
        # plain varints of a 32-bit value: int32 sign-extends (sxtw), uint32 zero-extends
        self.assertEqual(WH._classify_write_helper(self.ctx, 0x18dbdabd0), 'int32')
        self.assertEqual(WH._classify_write_helper(self.ctx, 0x18dbdac30), 'uint32')
        # 64-bit varints (int64/uint64 share code) and bool stay plain
        self.assertEqual(WH._classify_write_helper(self.ctx, 0x18dbdac3c), 'plain')
        self.assertEqual(WH._classify_write_helper(self.ctx, 0x18dbdabdc), 'plain')
        self.assertEqual(WH._classify_write_helper(self.ctx, 0x18dbdaba0), 'plain')
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

    def test_clist_element_writer_flips(self):
        # Repeated C-list ({?="list"^…}) fields: typed by the ELEMENT writer — the no-tag
        # writer inside the packed begin/recall bracket, or the per-element tagged writer
        # of an unpacked list — not by the begin-mark.
        self.assertEqual(self._field('GEOBusynessPoiLookupTile', 'latitudeE7s').type_name,
                         'sfixed32')                                   # packed, fixed32
        self.assertEqual(self._field('GEOTFCompactRoadSpeeds', 'geoIds').type_name,
                         'sint64')                                     # packed, zigzag
        self.assertEqual(self._field('GEOTFRoadSpeed', 'geoIds').type_name,
                         'sint64')                                     # unpacked, zigzag
        # negative control: unpacked list written by the plain int32 writer stays int32
        self.assertEqual(self._field('GEOPDSearchParameters',
                                     'supportedSearchTierTypes').label.name, 'REPEATED')
        self.assertNotIn('sint', self._field('GEOPDSearchParameters',
                                             'supportedSearchTierTypes').type_name)


try:
    _HAVE_CLP = _V.load_cache('CoreLocationProtobuf') is not None
except Exception:
    _HAVE_CLP = False


@unittest.skipUnless(_HAVE_CLP, 'CoreLocationProtobuf cache not available')
class TestPackedElementFamilyLiveCLP(unittest.TestCase):
    """CLPSatelliteInfo writes satIds with the plain int32 writer but cnos/azimuths/
    elevations with the sint32 (zigzag) writer, all packed (begin-mark field#, element
    writer with no-tag field# -1, recall-mark).  Real iPhone 8 satReport traffic only
    decodes to plausible C/N0 / azimuth / elevation values as sint32."""

    @classmethod
    def setUpClass(cls):
        import live_artifacts as V
        ctx, st, cl = V.load_cache('CoreLocationProtobuf')
        cls.msgs = {m.class_name: m for m in E.extract_all(ctx, st, cl)}

    def _type(self, fn):
        m = self.msgs['CLPSatelliteInfo']
        return next(f for f in m.fields if f.name == fn).type_name

    def test_sint32_elements(self):
        for fn in ('cnos', 'azimuths', 'elevations'):
            self.assertEqual(self._type(fn), 'sint32', fn)

    def test_plain_int32_elements_unchanged(self):
        self.assertEqual(self._type('satIds'), 'int32')
        self.assertEqual(self._type('isUsedInFixes'), 'bool')


if __name__ == '__main__':
    unittest.main()
