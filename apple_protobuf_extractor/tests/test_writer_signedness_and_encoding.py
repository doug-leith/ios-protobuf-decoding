"""Two facts the writeTo: code states and the @encode does not:

1. int32 vs uint32 from the WRITER: a plain varint helper's first read of its value argument
   widens it to the 64-bit varint value -- ``sxtw`` (int32: a negative value takes 10 bytes)
   or a 32-bit ``mov`` (uint32: zero-extends).  PB 0x1a47ae8cc / 0x1a47af658.
2. packed vs expanded repeated scalars: a C-list written inside one begin/recall bracket
   is PACKED, one written with a tag per element is EXPANDED; the emitter declares EXPANDED
   (edition 2023 defaults to PACKED).

Offline tests use hand-assembled helper bodies (self-checked by disassembling); the live
tests read the iPhone 8 cache.
"""
import struct
import unittest

import pytest

from macho.disasm import disasm
import proto.write_helpers as WH
from proto.extractor import _repeated_encoding
from proto.writeto import BoundWrite
from proto.emitter import build_proto_files
from proto.models import FieldLabel, ProtoField, ProtoMessage
from tests.test_writeto_helper_family import (
    _RegionCtx, _enc_adrp, _enc_add, _enc_br, _enc_lsl, _enc_mov, _enc_ret)


def _enc_mov_w(rd, rm):               # MOV Wd,Wm == ORR Wd,WZR,Wm (zero-extends)
    return struct.pack('<I', 0x2A000000 | (rm << 16) | (31 << 5) | rd)


def _enc_sxtw(rd, rn):                # SXTW Xd,Wn == SBFM Xd,Xn,#0,#31
    return struct.pack('<I', 0x93407C00 | (rn << 5) | rd)


def _enc_cmp_x(rn, imm):              # CMP Xn,#imm == SUBS XZR,Xn,#imm
    return struct.pack('<I', 0xF100001F | (imm << 10) | (rn << 5))


def _enc_strb(rt, rn):                # STRB Wt,[Xn]
    return struct.pack('<I', 0x39000000 | (rn << 5) | rt)


class TestVarint32SignednessOffline(unittest.TestCase):
    STUB = 0x180001000
    TGT = 0x1a0002000

    def _classify(self, body):
        # every plain varint helper builds its tag first: field# (x2 -> x21) << 3
        body = _enc_mov(21, 2) + _enc_lsl(10, 21, 3, sf=0) + body
        d = (self.TGT & ~0xFFF) - (self.STUB & ~0xFFF)
        stub = _enc_adrp(16, d >> 12) + _enc_add(16, 16, self.TGT & 0xFFF) + _enc_br(16)
        return WH._classify_write_helper(_RegionCtx({self.STUB: stub, self.TGT: body}),
                                         self.STUB)

    def test_encoders(self):
        for enc, mn in ((_enc_mov_w(8, 20), 'mov'), (_enc_sxtw(8, 20), 'sxtw'),
                        (_enc_cmp_x(20, 0x80), 'cmp'), (_enc_strb(20, 8), 'strb')):
            ins = disasm(_RegionCtx({self.TGT: enc}), self.TGT, max_insns=1,
                         stop_at_ret=False)[0]
            self.assertEqual(ins.mnemonic, mn, ins.op_str)

    def test_sign_extend_is_int32(self):
        self.assertEqual(self._classify(_enc_mov(20, 1) + _enc_sxtw(8, 20) + _enc_ret()),
                         'int32')

    def test_zero_extend_is_uint32(self):
        self.assertEqual(self._classify(_enc_mov(20, 1) + _enc_mov_w(8, 20) + _enc_ret()),
                         'uint32')

    def test_64bit_use_is_plain(self):
        # int64/uint64 helpers use the value register as is (code-identical: no signal)
        self.assertEqual(self._classify(_enc_mov(20, 1) + _enc_cmp_x(20, 0x80) + _enc_ret()),
                         'plain')

    def test_bool_byte_store_is_plain(self):
        self.assertEqual(self._classify(_enc_mov(20, 1) + _enc_strb(20, 8) + _enc_ret()),
                         'plain')

    def test_overwritten_argument_register_is_not_the_value(self):
        # x1 is reused (e.g. `csel x1,...` before a call) before the 32-bit move
        self.assertEqual(self._classify(_enc_mov(1, 8) + _enc_mov_w(9, 1) + _enc_ret()),
                         'plain')

    def test_refine(self):
        self.assertEqual(WH._refine_scalar_by_family('int32', 'uint32'), 'uint32')
        self.assertEqual(WH._refine_scalar_by_family('uint32', 'int32'), 'int32')
        self.assertEqual(WH._refine_scalar_by_family('uint32', 'uint32'), 'uint32')
        self.assertEqual(WH._refine_scalar_by_family('int64', 'int32'), 'int64')
        self.assertEqual(WH._refine_scalar_by_family('int32', 'plain'), 'int32')

    def test_disagreement_is_logged(self):
        with self.assertLogs('proto.write_helpers', level='WARNING') as cm:
            WH._refine_scalar_by_family('int32', 'uint32', 'GEOX._y')
        self.assertIn('GEOX._y', cm.output[0])


class _Ivar:
    def __init__(self, name, enc):
        self.name, self.type_enc = name, enc


class TestRepeatedEncodingOffline(unittest.TestCase):
    CLIST = '{?="list"^I"count"Q"size"Q}'

    def test_bracket_is_packed(self):
        self.assertEqual(_repeated_encoding(_Ivar('_a', self.CLIST), {'_a': BoundWrite(3, 0x1000, True)}),
                         'PACKED')

    def test_tag_per_element_is_expanded(self):
        self.assertEqual(_repeated_encoding(_Ivar('_a', self.CLIST), {'_a': BoundWrite(3, 0x1000)}),
                         'EXPANDED')

    def test_unseen_write(self):
        self.assertEqual(_repeated_encoding(_Ivar('_a', self.CLIST), {}), 'UNSEEN')

    def test_object_array_of_scalars_is_read_the_same_way(self):
        # an NSArray whose elements are scalars (written per element with the field's number)
        arr = _Ivar('_a', '@"NSArray"')
        self.assertEqual(_repeated_encoding(arr, {'_a': BoundWrite(3, 0x1000)}, 'uint64'), 'EXPANDED')
        self.assertEqual(_repeated_encoding(arr, {}, 'int32', 'ENUM:E'), 'UNSEEN')
        self.assertIsNone(_repeated_encoding(arr, {'_a': BoundWrite(3, 0x1000)}, 'string'))

    def test_neither_a_clist_nor_an_array(self):
        self.assertIsNone(_repeated_encoding(_Ivar('_a', '@"NSString"'), {}))

    def _emit(self, **kw):
        f = ProtoField(name='xs', number=3, label=FieldLabel.REPEATED, number_confirmed=True,
                       **kw)
        files = build_proto_files([ProtoMessage(name='M', class_name='GEOM', fields=[f])],
                                  single_file=True, package_override='t')
        return files[0].emit()

    def test_emitter(self):
        out = self._emit(type_name='uint32', repeated_encoding='EXPANDED')
        self.assertIn('repeated uint32 xs = 3 [features.repeated_field_encoding = EXPANDED];', out)
        out = self._emit(type_name='uint32', repeated_encoding='PACKED')
        self.assertIn('repeated uint32 xs = 3;', out)
        out = self._emit(type_name='uint32', repeated_encoding='UNSEEN')
        self.assertIn('repeated uint32 xs = 3;  // packed/expanded not read from writeTo:', out)
        out = self._emit(type_name='string')   # not packable: its producer sets no encoding
        self.assertIn('repeated string xs = 3;', out)


try:
    import live_artifacts as _V
    _HAVE = _V.load_cache('GeoServices') is not None
except Exception:
    _HAVE = False


@pytest.mark.slow
@pytest.mark.xdist_group("geoservices_iphone8")
@unittest.skipUnless(_HAVE, 'GeoServices cache not available')
class TestLiveGeoServices(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tests._live import extracted
        cls.msgs = {m.class_name: m for m in extracted('GeoServices').messages}

    def _f(self, cn, fn):
        return next(f for f in self.msgs[cn].fields if f.name == fn)

    def test_expanded_list(self):
        # -[GEOPDClientMetadata writeTo:] 0x18c202dac..dcc: int32 writer with field# 20 per element
        self.assertEqual(self._f('GEOPDClientMetadata', 'knownClientResolvedTypes')
                         .repeated_encoding, 'EXPANDED')

    def test_packed_list(self):
        # begin-mark + no-tag fixed32 element writer + recall-mark (886f3b76)
        self.assertEqual(self._f('GEOBusynessPoiLookupTile', 'latitudeE7s').repeated_encoding,
                         'PACKED')

    def test_uint32_from_writer_matches_encode(self):
        # GEOTileSetRegion members are `I` and written by the uint32 writer
        self.assertEqual(self._f('GEOTileSetVersion', 'identifier').type_name, 'uint32')


if __name__ == '__main__':
    unittest.main()
