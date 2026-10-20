"""
tests/test_repeated_element_types.py -- element types of repeated-message fields:
the precedence in proto.extractor._resolve_repeated_element_type (the readFrom:
evaluator's adder->ivar result, outranked by an ABI-confirmed string writer) and the
string-writer-first rule of _resolve_repeated_field_type.

Two layers:

* synthetic unit tests of the precedence (no artifacts needed);
* live regression tests against the GeoServices dyld-cache image and the standalone
  locationd binary (artifact-gated like the other live tests).

Background (see ../report_on_apple_location_services/notes/codex_eval/
extractor_networks_type_bug.md): a generated reader builds each repeated-message
element with ``[[Element alloc] init]`` and appends it with the field's add-accessor,
so the element class is a class-reference load right before the accessor call.  That
is a structural source for readers that call no ``<Class>ReadAllFrom`` core, and it
replaces the former name-suffix guess ("Strategy 2").
"""
from __future__ import annotations

import os
import sys
import unittest
from typing import Dict, List, Optional
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import artifacts
from macho.disasm import Insn
from macho.classlist import ObjcClass, ObjcIvar, ObjcMethod
from tests._fakes import NoImage


# ── tiny fakes ────────────────────────────────────────────────────────────────

class _FakeClass:
    def __init__(self, name, is_meta=False):
        self.name, self.is_meta = name, is_meta


class _FakeCL:
    """ClassList stand-in: ``by_vmaddr`` / ``find`` over a {vmaddr: name} table."""
    def __init__(self, classes: Dict[int, str]):
        self._by_va = {va: _FakeClass(n) for va, n in classes.items()}
        self._by_name = {c.name: c for c in self._by_va.values()}

    def by_vmaddr(self, va):
        return self._by_va.get(va)

    def find(self, name):
        return self._by_name.get(name)


class _FakeCtx:
    """BinaryContext stand-in: slots map a slot VA to a pointer; strings by VA;
    binds map a slot VA to a bind symbol."""
    def __init__(self, ptrs=None, strings=None, binds=None):
        self.ptrs, self.strings, self.binds = ptrs or {}, strings or {}, binds or {}

    def read_ptr(self, va):
        return self.ptrs.get(va, 0)

    def read_cstring(self, va):
        return self.strings.get(va)

    def bind_name_for(self, va):
        return self.binds.get(va)


_PAGE = 0x10000


def _insn(addr, mnemonic, op_str):
    return Insn(addr=addr, mnemonic=mnemonic, op_str=op_str, size=4, raw=b'\0\0\0\0')


def _adrp(addr, reg, page=_PAGE):
    return _insn(addr, 'adrp', f'{reg}, #0x{page:x}')


def _ldr(addr, dest, base, off):
    return _insn(addr, 'ldr', f'{dest}, [{base}, #0x{off:x}]')


def _bl(addr, target):
    return _insn(addr, 'bl', f'#0x{target:x}')


# ══════════════════════════════════════════════════════════════════════════════
# Precedence in proto.extractor._resolve_repeated_element_type.  The element class comes
# from the readFrom: evaluator's adder->ivar result (tests/test_dispatch_eval.py); the
# separate class-reference lever and its write-helper guard were deleted 2026-10-18, as
# that lever returned exactly the evaluator's result.
# ══════════════════════════════════════════════════════════════════════════════

STR_HELPER = 0xAC18


class TestRepeatedElementPrecedence(unittest.TestCase):

    def _call(self, *, dispatch_ivars=None, rr=None):
        import proto.extractor as X
        from proto.repeated import _RepeatedTypeResult
        from proto.models import FieldLabel
        ivar = ObjcIvar(name='_items', type_enc='@"NSMutableArray"', offset=8, size=8)
        rr = rr or _RepeatedTypeResult(type_name='bytes', type_class=None,
                                       element_unresolved=True)
        with patch.object(X, '_resolve_repeated_field_type', return_value=rr):
            return X._resolve_repeated_element_type(
                None, None, ivar, 'items', FieldLabel.REPEATED, 'NSMutableArray',
                'NSMutableArray', 1, True,
                dispatch_elements={}, dispatch_unambiguous=False,
                dispatch_ivars=dispatch_ivars or {},
                metaclass=None, string_helper=STR_HELPER, wt_helpers={})

    def test_dispatch_ivar_supplies_the_element(self):
        out = self._call(dispatch_ivars={'_items': ('GEOFromDispatch', 3)})
        self.assertEqual(out[0], 'GEOFromDispatch')

    def test_no_dispatch_result_stays_bytes(self):
        self.assertEqual(self._call()[0], 'bytes')

    def test_string_writer_outranks_dispatch(self):
        # an ABI-confirmed element type (a distinct string write helper) is never overridden
        from proto.repeated import _RepeatedTypeResult
        rr = _RepeatedTypeResult(type_name='string', type_class=None, abi_confirmed=True)
        out = self._call(dispatch_ivars={'_items': ('GEOFromDispatch', 3)}, rr=rr)
        self.assertEqual(out[0], 'string')


class TestScalarWriterElementType(unittest.TestCase):
    """A repeated object array written with a named ProtocolBuffer scalar writer has that
    writer's element type (CoreParsec _CPVisibleResultsFeedback.uniqueIdsOfVisibleButtons:
    an NSArray written element by element with _PBDataWriterWriteUint64Field)."""

    def _resolve(self, writer_name):
        import proto.repeated as R
        ivar = ObjcIvar(name='_ids', type_enc='@"NSArray"', offset=8, size=8)
        with patch.object(R, 'callee_name', lambda ctx, va: writer_name if va == 0x9000 else None):
            return R._resolve_repeated_field_type(ivar, 'ids', None, None, None, STR_HELPER,
                                                  {'_ids': 0x9000})

    def test_scalar_writer_names_the_element_type(self):
        rr = self._resolve('_PBDataWriterWriteUint64Field')
        self.assertEqual((rr.type_name, rr.abi_confirmed), ('uint64', True))
        self.assertEqual(self._resolve('_PBDataWriterWriteSfixed32Field').type_name, 'sfixed32')

    def test_data_writer_is_genuine_bytes_not_a_give_up(self):
        rr = self._resolve('_PBDataWriterWriteDataField')
        self.assertEqual((rr.type_name, rr.element_unresolved), ('bytes', False))

    def test_submessage_and_unnamed_writers_name_nothing(self):
        import proto.repeated as R
        self.assertIsNone(R._writer_element_type(None, None))
        with patch.object(R, 'callee_name', lambda ctx, va: '_PBDataWriterWriteSubmessage'):
            self.assertIsNone(R._writer_element_type(None, 0x9000))
        with patch.object(R, 'callee_name', lambda ctx, va: None):
            self.assertIsNone(R._writer_element_type(None, 0x9000))


class TestReturnedClassRef(unittest.TestCase):
    """proto.repeated._returned_class_ref: what a ``+xyzType`` method returns in x0, by its
    reaching definition at every exit the entry reaches."""
    OPT_CLASS, CLAIM = 0x9000, 0x9100

    def _ref(self, blocks, entries=(0x1000, 0x2000)):
        import proto.repeated as R
        from tests._listing import layout
        _o, fd = layout(*blocks)
        names = {self.OPT_CLASS: '_objc_opt_class', self.CLAIM: '_objc_claimAutoreleasedReturnValue'}
        ctx = NoImage(_function_entries=set(entries))
        with patch.object(R, 'disasm', fd), \
                patch.object(R, 'callee_name', lambda c, va: names.get(va)):
            return R._returned_class_ref(ctx, 0x1000)

    def test_a_slot_loaded_then_tail_called_into_objc_opt_class(self):
        self.assertEqual(self._ref([(0x1000, [('adrp', 'x8, #0x5000'), ('ldr', 'x0, [x8, #0x80]'),
                                              ('b', '#0x9000')])]), ("slot", 0x5080))

    def test_the_class_address_itself(self):
        # iOS 27: adrp ; add x0 ; b _objc_opt_class
        self.assertEqual(self._ref([(0x1000, [('adrp', 'x8, #0x6000'), ('add', 'x0, x8, #0x248'),
                                              ('b', '#0x9000')])]), ("class", 0x6248))

    def test_through_calls_that_return_their_class(self):
        self.assertEqual(self._ref([(0x1000, [
            ('stp', 'x29, x30, [sp, #-0x10]!'), ('mov', 'x29, sp'), ('adrp', 'x8, #0x5000'),
            ('ldr', 'x0, [x8, #0x80]'), ('bl', '#0x9000'), ('bl', '#0x9100'),
            ('ldp', 'x29, x30, [sp], #0x10'), ('ret', '')])]), ("slot", 0x5080))

    def test_code_past_the_tail_call_is_not_this_method(self):
        # padding, then an unnamed C function before the next method returns something else
        self.assertEqual(self._ref([(0x1000, [('adrp', 'x8, #0x5000'), ('ldr', 'x0, [x8, #0x80]'),
                                              ('b', '#0x9000'), ('udf', '#0'),
                                              ('mov', 'x0, #0'), ('ret', '')])]), ("slot", 0x5080))

    def test_any_other_tail_call_returns_no_class(self):
        self.assertIsNone(self._ref([(0x1000, [('mov', 'w2, #0'), ('b', '#0x9200')])]))


# ══════════════════════════════════════════════════════════════════════════════
# live: GeoServices (dyld cache) and locationd (standalone binary)
# ══════════════════════════════════════════════════════════════════════════════

def _find_cache_main() -> Optional[str]:
    cache_dir = os.environ.get('MACHO_TEST_CACHE', '').strip()
    for d in ([cache_dir] if cache_dir else []) + [artifacts.cache_dir()]:
        for name in ('dyld_shared_cache_arm64e', 'dyld_shared_cache_arm64'):
            p = os.path.join(d, name)
            if os.path.isfile(p):
                return p
    return None


_CACHE_MAIN = _find_cache_main()
_LOCATIOND = os.environ.get('MACHO_TEST_LOCATIOND', '').strip() or artifacts.locationd_path()


@unittest.skipUnless(_CACHE_MAIN, 'dyld shared cache not found (see artifacts.py)')
class TestGeoServicesRepeatedElementTypes(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        from macho.dyld_cache import DyldCacheReader
        from macho.memory import BinaryContext
        from macho.strings import build_string_table
        from macho import classlist as CL
        from macho.local_symbols import apply_to_classes
        from proto.extractor import extract_all
        reader = DyldCacheReader(_CACHE_MAIN)
        mach_va = reader.find_image_header('GeoServices')
        cls.ctx = BinaryContext.from_cache(reader, mach_va)
        st = build_string_table(cls.ctx)
        cls.cl = CL.build_class_list(cls.ctx, st)
        apply_to_classes(cls.cl, reader.image_local_symbols(mach_va))
        cls.msgs = {m.class_name: m for m in extract_all(cls.ctx, st, cls.cl)}

    def _field(self, cls_name, fname):
        return next(f for f in self.msgs[cls_name].fields if f.name == fname)

    # -- a Data writer's elements are genuine bytes (not a flagged give-up) -----

    def test_data_writer_array_is_unflagged_bytes(self):
        f = self._field('GEOPDExternalTransitLookupParameters', 'externalTransitStationCodes')
        self.assertEqual((f.type_name, f.type_inference_note), ('bytes', None))

    # -- the reported bug: string writer vs name-suffix guess ------------------

    def test_ev_charging_networks_is_repeated_string(self):
        f = self._field('GEOPDSSearchEvChargingParameters', 'networks')
        self.assertEqual((f.type_name, f.type_class), ('string', None))
        self.assertIsNone(f.type_inference_note)

    def test_search_chain_triggers_is_repeated_string(self):
        f = self._field('GEOPDSearchSearchChainInfo', 'triggers')
        self.assertEqual((f.type_name, f.type_class), ('string', None))

    def test_ev_charging_ports_stays_message(self):
        f = self._field('GEOPDSSearchEvChargingParameters', 'ports')
        self.assertEqual(f.type_name, 'GEOPDEvChargingPort')

    def test_genuine_repeated_bytes_next_to_a_message_field_is_not_retyped(self):
        # GEODirectionsRequest.trafficApiResponses is written by the bytes helper; a
        # class reference to the neighbouring singular GEORouteAttributes field is in
        # its reader window and must not become its element type.
        f = self._field('GEODirectionsRequest', 'trafficApiResponses')
        self.assertEqual((f.type_name, f.type_class), ('bytes', None))

    # -- class-ref lever: former `repeated bytes` give-ups ---------------------

    def test_inline_reader_elements_resolved_from_class_ref(self):
        for cls_name, fname, elem in [
                ('GEOPDTileList', 'tiles', 'GEOTileCoordinate'),
                ('GEOSupportedTileSets', 'tileSets', 'GEOTileSet'),
                ('GEOCoarseLocationTileData', 'territorys', 'GEOCoarseLocationTerritoryInfo'),
                ('GEOTerritoryDataTileData', 'territorys', 'GEOTerritoryDataTerritoryInfo'),
                ('GEOPDSearchKey64ValuePairList', 'pairs', 'GEOPDSearchKey64ValuePair')]:
            with self.subTest(field=f'{cls_name}.{fname}'):
                f = self._field(cls_name, fname)
                self.assertEqual(f.type_name, elem)
                self.assertIsNone(f.type_inference_note)

    def test_no_repeated_bytes_give_up_left_for_inline_readers(self):
        left = [(m.class_name, f.name) for m in self.msgs.values() for f in m.fields
                if f.type_name == 'bytes' and f.type_inference_note
                and 'PairList' in m.class_name]
        self.assertEqual(left, [])


@unittest.skipUnless(os.path.isfile(_LOCATIOND), 'locationd binary not found')
class TestLocationdRepeatedElementTypes(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        from macho.memory import BinaryContext
        from macho.strings import build_string_table
        from macho import classlist as CL
        from proto.extractor import extract_all
        with open(_LOCATIOND, 'rb') as fh:
            cls.ctx = BinaryContext(fh.read())
        st = build_string_table(cls.ctx)
        cls.cl = CL.build_class_list(cls.ctx, st)
        cls.msgs = {m.class_name: m for m in extract_all(cls.ctx, st, cls.cl)}

    def _elem(self, cls_name):
        return next(f for f in self.msgs[cls_name].fields
                    if f.name == 'locationFingerprints')

    def test_fingerprints_element_from_message_stub_call(self):
        f = self._elem('TRANSITPbLocationFingerprints')
        self.assertEqual(f.type_name, 'TRANSITPbLocationFingerprint')
        self.assertIsNone(f.type_inference_note)

    def test_fingerprints_v1_element_is_the_v1_class(self):
        # The name-suffix guess said TRANSITPbLocationFingerprint (the V1 class does
        # not end in "Fingerprint"); the reader loads the V1 element class.
        f = self._elem('TRANSITPbLocationFingerprintsV1')
        self.assertEqual(f.type_name, 'TRANSITPbLocationFingerprintV1')
        self.assertIsNone(f.type_inference_note)


if __name__ == '__main__':
    unittest.main()
