"""
tests/test_repeated_element_types.py -- the element class-reference lever for
repeated-message fields (proto.repeated._resolve_repeated_via_classrefs) and the
string-writer-first rule of _resolve_repeated_field_type.

Two layers:

* synthetic unit tests of the window scanner / resolver (no artifacts needed);
* live regression + calibration tests against the GeoServices dyld-cache image
  and the standalone locationd binary (artifact-gated like the other live tests).

Background (see report_on_apple_location_services/notes/codex_eval/
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
# The class-reference lever's write-helper guard (proto.extractor).  The lever itself
# is the dispatch evaluator's adder->ivar result now (tests/test_dispatch_eval.py); the
# window-pairing implementation these sections tested was retired 2026-10-15.
# ══════════════════════════════════════════════════════════════════════════════

MSG_HELPER, BYTES_HELPER, STR_HELPER = 0xAC24, 0xABAC, 0xAC18


class TestClassrefLeverGuard(unittest.TestCase):
    """GEODirectionsRequest.trafficApiResponses is a genuine ``repeated bytes`` field
    (bytes writer) but its reader sits next to a singular GEORouteAttributes field, so
    a class reference is in the window.  The lever result must only be applied to a
    field the MESSAGE helper writes."""

    def _call(self, *, helper, classref=True, dispatch_ivars=None, message_helper=MSG_HELPER,
              rr=None):
        import proto.extractor as X
        from proto.repeated import _RepeatedTypeResult
        from proto.models import FieldLabel
        ivar = ObjcIvar(name='_items', type_enc='@"NSMutableArray"', offset=8, size=8)
        rr = rr or _RepeatedTypeResult(type_name='bytes', type_class=None,
                                       element_unresolved=True)
        with patch.object(X, '_resolve_repeated_field_type', return_value=rr), \
             patch('proto.write_helpers._helper_real_target', side_effect=lambda c, v: v):
            return X._resolve_repeated_element_type(
                None, None, ivar, 'items', FieldLabel.REPEATED, 'NSMutableArray',
                'NSMutableArray', 1, True,
                dispatch_elements={}, dispatch_unambiguous=False,
                dispatch_ivars=dispatch_ivars or {}, instance_method_names=set(),
                metaclass=None, string_helper=STR_HELPER,
                wt_helpers={'_items': helper} if helper is not None else {},
                classref_ivars={'_items': ('GEOElem', 0)} if classref else {},
                message_helper=message_helper)

    def test_applied_when_written_by_message_helper(self):
        self.assertEqual(self._call(helper=MSG_HELPER), ('GEOElem', 'GEOElem', None))

    def test_not_applied_to_bytes_written_field(self):
        tn, tc, note = self._call(helper=BYTES_HELPER)
        self.assertEqual((tn, tc), ('bytes', None))

    def test_not_applied_when_field_writer_unknown(self):
        self.assertEqual(self._call(helper=None)[0], 'bytes')

    def test_not_applied_when_message_helper_unknown(self):
        self.assertEqual(self._call(helper=MSG_HELPER, message_helper=None)[0], 'bytes')

    def test_string_writer_outranks_lever(self):
        from proto.repeated import _RepeatedTypeResult
        rr = _RepeatedTypeResult(type_name='string', type_class=None, abi_confirmed=True)
        self.assertEqual(self._call(helper=MSG_HELPER, rr=rr)[0], 'string')

    def test_dispatch_lever_outranks_classref_lever(self):
        out = self._call(helper=MSG_HELPER, dispatch_ivars={'_items': ('GEOFromDispatch', 3)})
        self.assertEqual(out[0], 'GEOFromDispatch')


class TestSameWriteHelper(unittest.TestCase):

    def setUp(self):
        from proto.write_helpers import _same_write_helper
        self.fn = _same_write_helper

    def test_equal_addresses(self):
        self.assertTrue(self.fn(None, 0x1000, 0x1000))

    def test_unknown_is_never_same(self):
        self.assertFalse(self.fn(None, None, 0x1000))
        self.assertFalse(self.fn(None, 0x1000, None))
        self.assertFalse(self.fn(None, None, None))

    def test_different_stubs_with_same_real_target(self):
        # per-callsite stub islands: different VAs, one shared target
        with patch('proto.write_helpers._helper_real_target', return_value=0x9999):
            self.assertTrue(self.fn(None, 0x1000, 0x2000))

    def test_different_real_targets(self):
        with patch('proto.write_helpers._helper_real_target',
                   side_effect=lambda c, v: v):
            self.assertFalse(self.fn(None, 0x1000, 0x2000))


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

    # -- calibration gate: lever vs the structural dispatch lever --------------

    def test_lever_agrees_with_dispatch_lever_wherever_both_resolve(self):
        """The class-ref lever must reproduce the (independent) adder->ivar /
        ReadAllFrom-core lever exactly on the fields both resolve.  Prototype
        calibration: 516/516 agreed, 0 disagreed."""
        from proto.dispatch import _build_readfrom_core_index
        from proto.repeated import (_resolve_repeated_via_classrefs,
                                    _resolve_repeated_via_dispatch_ivars)
        core_index = _build_readfrom_core_index(self.ctx, self.cl)
        agree, disagree = 0, []
        for m in self.msgs.values():
            c = self.cl.find(m.class_name)
            if c is None:
                continue
            ref = _resolve_repeated_via_dispatch_ivars(self.ctx, c, core_index)
            if not ref:
                continue
            got = _resolve_repeated_via_classrefs(self.ctx, c, self.cl, core_index)
            for ivn, (elem, _fn) in ref.items():
                if ivn in got:
                    if got[ivn][0] == elem:
                        agree += 1
                    else:
                        disagree.append((m.class_name, ivn, elem, got[ivn][0]))
        self.assertEqual(disagree, [])
        self.assertGreaterEqual(agree, 400,
                                'calibration set unexpectedly small -- gate is vacuous')


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
