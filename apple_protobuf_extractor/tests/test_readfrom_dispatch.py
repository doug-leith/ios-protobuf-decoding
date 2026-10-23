"""
Tests for the principled ``repeated <message>`` element-type resolver
(``proto/extractor.py``): the readFrom: field-dispatch jump-table walk that names
each repeated field's element class by the ReadAllFrom callee address its
dispatch arm invokes.

The dispatch itself is decoded by evaluation (proto.dispatch_eval; synthetic
tests in tests/test_dispatch_eval.py).  Here: the full resolver against the real
GeoServices cache, gated on the cache being present.  Ground truth
(cross-checked against the hand-decoded ``GEOPDPlaceResponse.proto``):
``GEOPDComponent.values`` (field 8) -> ``GEOPDComponentValue`` and
``GEOPDComponent.commingledAttributions`` (field 14) -> ``GEOPDAttribution`` —
both of which the name-suffix heuristics mis-resolve to ``repeated bytes``.
"""

import os
import artifacts
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))


# ══════════════════════════════════════════════════════════════════════════════
# Live tests against the real GeoServices cache
# ══════════════════════════════════════════════════════════════════════════════

_CACHE_MAIN = artifacts.cache_file()
_SKIP_MSG = ('dyld shared cache not found — place the full cache in '
             '<repo>/iphone8_data/dylib/ (or set MACHO_DATA_DIR)')


@unittest.skipUnless(_CACHE_MAIN is not None, _SKIP_MSG)
class TestReadFromDispatchLive(unittest.TestCase):
    """Resolve GEOPDComponent's repeated-message element types from the cache."""

    @classmethod
    def setUpClass(cls):
        from macho.dyld_cache import DyldCacheReader
        from macho.memory import BinaryContext
        from macho.strings import build_string_table
        from macho.classlist import build_class_list
        from macho.local_symbols import apply_to_classes
        from proto.dispatch import _build_readfrom_core_index, _find_readfrom_c_func

        cls.reader = DyldCacheReader(_CACHE_MAIN)
        cls.mach_va = cls.reader.find_image_header('GeoServices')
        if cls.mach_va is None:
            raise unittest.SkipTest('GeoServices image not in cache')
        cls.ctx = BinaryContext.from_cache(cls.reader, cls.mach_va)
        cls.st = build_string_table(cls.ctx)
        cls.cl = build_class_list(cls.ctx, cls.st)
        syms = cls.reader.image_local_symbols(cls.mach_va)
        if syms:
            apply_to_classes(cls.cl, syms)
        cls.core_index = _build_readfrom_core_index(cls.ctx, cls.cl)
        cls._find_readfrom_c_func = staticmethod(_find_readfrom_c_func)

    def test_core_index_non_trivial(self):
        # Hundreds of proto classes -> hundreds of ReadAllFrom cores indexed.
        self.assertGreater(len(self.core_index), 100)

    def test_core_index_keys_are_addresses(self):
        self.assertTrue(all(isinstance(k, int) and k > 0
                            for k in self.core_index))

    def test_component_value_core_indexed_by_address(self):
        gv = self.cl.find('GEOPDComponentValue')
        self.assertIsNotNone(gv)
        core = self._find_readfrom_c_func(self.ctx, gv)
        self.assertIsNotNone(core)
        self.assertEqual(self.core_index.get(core), 'GEOPDComponentValue')

    def test_dispatch_resolves_known_message_fields(self):
        from proto.repeated import _resolve_repeated_via_dispatch
        comp = self.cl.find('GEOPDComponent')
        self.assertIsNotNone(comp)
        elems = _resolve_repeated_via_dispatch(self.ctx, comp, self.core_index)
        # Ground truth from the hand-decoded reference.
        self.assertEqual(elems.get(8),  'GEOPDComponentValue')   # values
        self.assertEqual(elems.get(14), 'GEOPDAttribution')      # commingledAttributions
        self.assertEqual(elems.get(7),  'GEOPDAttribution')      # attribution
        self.assertEqual(elems.get(11), 'GEOPDSource')           # source

    def test_end_to_end_values_field_is_message_not_bytes(self):
        from proto.extractor import extract_proto_message
        from proto.write_helpers import _identify_string_write_helpers
        comp = self.cl.find('GEOPDComponent')
        helpers = frozenset(_identify_string_write_helpers(self.ctx, self.cl))
        msg = extract_proto_message(self.ctx, self.st, self.cl, comp,
                                    string_write_helpers=helpers,
                                    readfrom_core_index=self.core_index)
        by_num = {f.number: f for f in msg.fields}
        values = by_num.get(8)
        self.assertIsNotNone(values)
        self.assertEqual(str(values.label).split('.')[-1], 'REPEATED')
        self.assertEqual(values.type_class, 'GEOPDComponentValue')
        self.assertNotEqual(values.type_name, 'bytes')

    def test_end_to_end_without_index_falls_back_to_heuristics(self):
        # With an EXPLICIT opt-out (readfrom_core_index=None) the dispatch resolver
        # never fires — behaviour is the pre-existing heuristic path (values stays
        # `repeated bytes`), proving the resolver is additive. NOTE: the kwarg now
        # auto-builds when omitted, so the degraded path must be requested explicitly
        # (see extract_proto_message _AUTO sentinel); passing None is that opt-out.
        from proto.extractor import extract_proto_message
        comp = self.cl.find('GEOPDComponent')
        msg = extract_proto_message(self.ctx, self.st, self.cl, comp,
                                    readfrom_core_index=None)
        values = {f.number: f for f in msg.fields}.get(8)
        self.assertIsNotNone(values)
        self.assertEqual(values.type_name, 'bytes')

    # ── Compare-chain dispatch (no jump table) ────────────────────────────────

    def test_compare_chain_resolves_single_field_message(self):
        # GEOPDPlaceGlobalCommonResult has ONE repeated field whose readFrom: is a
        # flat tag-decode loop (no jump table).  The compare-chain tier reads the
        # element class from the `cmp w23,#1`-guarded element bl — and must NOT
        # pick up the field-0-guarded runtime-helper call.
        from proto.repeated import _resolve_repeated_via_dispatch
        cls = self.cl.find('GEOPDPlaceGlobalCommonResult')
        self.assertIsNotNone(cls)
        elems = _resolve_repeated_via_dispatch(self.ctx, cls, self.core_index)
        self.assertEqual(elems.get(1), 'GEOPDPlaceContextMetadata')
        # field 0 is not a legal protobuf field number → never present.
        self.assertNotIn(0, elems)

    def test_end_to_end_compare_chain_field_is_message_not_bytes(self):
        from proto.extractor import extract_proto_message
        from proto.write_helpers import _identify_string_write_helpers
        cls = self.cl.find('GEOPDPlaceGlobalCommonResult')
        helpers = frozenset(_identify_string_write_helpers(self.ctx, self.cl))
        msg = extract_proto_message(self.ctx, self.st, self.cl, cls,
                                    string_write_helpers=helpers,
                                    readfrom_core_index=self.core_index)
        fld = {f.name: f for f in msg.fields}.get('placeContextMetadatas')
        self.assertIsNotNone(fld)
        self.assertEqual(fld.type_class, 'GEOPDPlaceContextMetadata')
        self.assertNotEqual(fld.type_name, 'bytes')
        # Principled (dispatch), so NOT flagged as a name-suffix guess.
        self.assertIsNone(fld.type_inference_note)

    # ── Wrapper→separate-core dispatch (ReadAllFrom wrapper calls a core) ──────

    def test_wrapper_core_finder_locates_separate_core(self):
        # GEOPDDepartureSequence's readFrom: anchor is a thin ReadAllFrom wrapper
        # that only *calls* a separate ReadSpecified core past an early ret; the
        # evaluator must follow the call that is handed this object to that core.
        from proto.dispatch import _find_readfrom_c_func
        from proto.dispatch_eval import find_cores, _known_entries
        cls = self.cl.find('GEOPDDepartureSequence')
        self.assertIsNotNone(cls)
        rf = _find_readfrom_c_func(self.ctx, cls)
        self.assertIsNotNone(rf)
        cores, notes = find_cores(self.ctx, cls, _known_entries(self.ctx, cls, self.core_index))
        self.assertEqual(len(cores), 1, notes)
        self.assertNotEqual(cores[0][0], rf)

    def test_wrapper_core_resolves_repeated_message_fields(self):
        # The wrapper→core fallback lets the dispatch resolver reach the table, so
        # the repeated-message fields resolve to their real element classes.
        from proto.repeated import _resolve_repeated_via_dispatch
        cls = self.cl.find('GEOPDDepartureSequence')
        elems = _resolve_repeated_via_dispatch(self.ctx, cls, self.core_index)
        self.assertEqual(elems.get(5), 'GEOPDDeparture')             # departures
        self.assertEqual(elems.get(6), 'GEOPDDepartureFrequency')    # departureFrequencys

    def test_wrapper_core_end_to_end_field_is_message_not_bytes(self):
        # End-to-end: GEOPDDepartureSequence's wrapper also calls nested message
        # readers, but the own-IMP identity check picks THIS class's core, so
        # `departures` resolves to its real element class via principled dispatch
        # (not the name-suffix guess, and not a nested type).
        from proto.extractor import extract_proto_message
        from proto.write_helpers import _identify_string_write_helpers
        cls = self.cl.find('GEOPDDepartureSequence')
        helpers = frozenset(_identify_string_write_helpers(self.ctx, self.cl))
        msg = extract_proto_message(self.ctx, self.st, self.cl, cls,
                                    string_write_helpers=helpers,
                                    readfrom_core_index=self.core_index)
        by_name = {f.name: f for f in msg.fields}
        dep = by_name.get('departures')
        self.assertIsNotNone(dep)
        self.assertEqual(dep.type_class, 'GEOPDDeparture')
        self.assertNotEqual(dep.type_name, 'bytes')
        # Principled dispatch result → not a name-suffix guess.
        self.assertIsNone(dep.type_inference_note)

    # ── Adder→ivar lever (binds element type to the exact ivar) ───────────────

    def test_adder_array_ivar_pins_exact_offset(self):
        # The _addNoFlagsDeparture: accessor loads the _departures ivar-offset
        # variable; the lever reads that slot and returns the backing array
        # ivar's byte offset — even though the accessor also touches the _flags
        # struct ivar (which is excluded by the array-encoding filter).
        from proto.repeated import _adder_array_ivar
        cls = self.cl.find('GEOPDDepartureSequence')
        adder = next((m.imp for m in cls.methods
                      if m.name == '_addNoFlagsDeparture:'), None)
        self.assertIsNotNone(adder)
        dep_off = next(iv.offset for iv in cls.ivars if iv.name == '_departures')
        array_offs = frozenset(
            iv.offset for iv in cls.ivars
            if iv.type_enc in ('@"NSArray"', '@"NSMutableArray"'))
        self.assertEqual(_adder_array_ivar(self.ctx, adder, array_offs), dep_off)

    def test_adder_array_ivar_rejects_singular_message_ivar_offset(self):
        # test_lever_never_binds_singular_message_field (below) can't discriminate
        # the array_offsets type-check on its own: GEOETARequest's singular
        # `_origin` (GEOWaypoint) field has no _addNoFlags<X>: adder at all, so the
        # jump-table arm walk's OTHER gate (the arm's second `bl` must land in
        # `own_imps` AND be treated as an adder) already excludes it before
        # `_adder_array_ivar` is ever called — reverting the type-check alone
        # would not move that test.  Here we call `_adder_array_ivar` directly on
        # `setOrigin:`, which IS in `own_imps` and loads the ivar-offset-table slot
        # with the exact same `adrp+add+ldrsw` pattern a real adder uses — so the
        # "found via own_imps" gate is satisfied and only the array_offsets
        # type-check can still reject binding to this singular, non-array ivar.
        from proto.repeated import _adder_array_ivar
        cls = self.cl.find('GEOETARequest')
        self.assertIsNotNone(cls)
        setter = next((m.imp for m in cls.methods if m.name == 'setOrigin:'), None)
        self.assertIsNotNone(setter)
        origin_off = next(iv.offset for iv in cls.ivars if iv.name == '_origin')
        array_offs = frozenset(
            iv.offset for iv in cls.ivars
            if iv.type_enc in ('@"NSArray"', '@"NSMutableArray"'))
        self.assertNotIn(origin_off, array_offs)   # _origin is GEOWaypoint, not an array
        self.assertIsNone(_adder_array_ivar(self.ctx, setter, array_offs))

    def test_dispatch_ivars_jumptable_binds_by_ivar_with_number(self):
        # The jump-table lever returns {ivar_name: (element_class, field_number)}.
        from proto.repeated import _resolve_repeated_via_dispatch_ivars
        cls = self.cl.find('GEOPDDepartureSequence')
        ivmap = _resolve_repeated_via_dispatch_ivars(
            self.ctx, cls, self.core_index)
        self.assertEqual(ivmap.get('_departures'), ('GEOPDDeparture', 5))
        self.assertEqual(ivmap.get('_departureFrequencys'),
                         ('GEOPDDepartureFrequency', 6))

    def test_dispatch_ivars_compare_chain_binds_unconfirmed_field(self):
        # GEOPDExternalAction uses the compare-chain reader; its repeated
        # externalActionDetails field is bound by ivar via the adder.  Its
        # handler is a FORWARD-branch block (cmp w23,#2; b.eq <later addr>),
        # placed at a higher address than the field-1 fall-through — so the
        # control-flow block attribution must report field 2 (matching writeTo:,
        # verified by hand-decoding readFrom:), not the address-adjacent 1.
        from proto.repeated import _resolve_repeated_via_dispatch_ivars
        cls = self.cl.find('GEOPDExternalAction')
        if cls is None:
            self.skipTest('GEOPDExternalAction not in this cache')
        ivmap = _resolve_repeated_via_dispatch_ivars(
            self.ctx, cls, self.core_index)
        self.assertEqual(ivmap.get('_externalActionDetails'),
                         ('GEOPDExternalActionDetail', 2))

    def test_direct_core_preferred_over_wrong_wrapper_sibling(self):
        # GEOPDExternalAction has a real direct compare-chain core
        # (read_specified_va) AND its readFrom: body calls sibling cores the wrapper
        # scan used to mistake for the dispatch core.  The evaluator follows only the
        # call handed this object, so a sibling core is never adopted — else
        # externalActionDetails would silently drop to bytes.
        from proto.repeated import _resolve_repeated_via_dispatch
        cls = self.cl.find('GEOPDExternalAction')
        if cls is None:
            self.skipTest('GEOPDExternalAction not in this cache')
        # The core handed this object resolves field 2 to the real element class.
        elems = _resolve_repeated_via_dispatch(self.ctx, cls, self.core_index)
        self.assertEqual(elems.get(2), 'GEOPDExternalActionDetail')

    def test_degenerate_jumptable_collapse_yields_no_mis_binding(self):
        # GEORPFeedbackFieldValue is a large JUMP-TABLE reader (21 feedback-type fields).
        # TODO #42: the compare-chain tier now attributes element bls by DOMINANCE over a
        # COMPLETE CFG (br arms injected) — so a field is credited only with the cores its
        # match edge dominates; it can't lump 21 distinct cores under one field.  The old
        # _degenerate_block_partition guard (deleted in #42) is unnecessary by construction.
        # At the time this test was written, no mechanism could yet resolve
        # _hoursFields at all, so it asserted the conservative "not bound rather
        # than mis-bound" outcome: _hoursFields must not be mis-bound to the
        # first-scanned element (GEORPFeedbackFieldAnnotations).
        # Since then, _walk_jumptable_arms gained two structural guards (reject
        # an arm address shared by >=2 different field numbers; bound each arm's
        # scan by the next arm's own start) that let it correctly resolve this
        # class's jump table without that ambiguity.  _hoursFields (field 16)
        # now resolves to GEORPFeedbackBusinessHours -- matching golden exactly
        # (tests/golden/GeoServices.json) -- so the guard is updated to assert
        # the verified-correct value instead of "not bound", while keeping the
        # original regression check (never GEORPFeedbackFieldAnnotations).
        from proto.repeated import _resolve_repeated_via_dispatch_ivars
        cls = self.cl.find('GEORPFeedbackFieldValue')
        if cls is None:
            self.skipTest('GEORPFeedbackFieldValue not in this cache')
        ivmap = _resolve_repeated_via_dispatch_ivars(
            self.ctx, cls, self.core_index)
        self.assertEqual(ivmap.get('_hoursFields'), ('GEORPFeedbackBusinessHours', 16))
        self.assertNotEqual(
            ivmap.get('_hoursFields', (None, None))[0],
            'GEORPFeedbackFieldAnnotations')

    def test_thick_wrapper_compare_chain_core_resolves(self):
        # GEOLPRWorld's readFrom: is a thick wrapper: _readspecified_and_count finds
        # no direct core (read_specified_va is None), and the dispatch core is a
        # COMPARE CHAIN (not a jump table).  The wrapper→core finder must surface
        # that compare-chain core so the elements resolve from the binary's own
        # parse code (replacing the old name-suffix guesses that dropped the "Map"
        # suffix, e.g. GEOLPRPowerType -> the real GEOLPRPowerTypeMap).
        from proto.repeated import _resolve_repeated_via_dispatch_ivars
        cls = self.cl.find('GEOLPRWorld')
        if cls is None:
            self.skipTest('GEOLPRWorld not in this cache')
        ivmap = _resolve_repeated_via_dispatch_ivars(
            self.ctx, cls, self.core_index)
        self.assertEqual(ivmap.get('_powerTypes'), ('GEOLPRPowerTypeMap', 3))
        self.assertEqual(ivmap.get('_vehicleTypes'), ('GEOLPRVehicleTypeMap', 4))
        self.assertEqual(ivmap.get('_regions'), ('GEOLPRRegion', 1))

    def test_lever_promotes_bytes_field_to_message(self):
        # GEOPDEventCategory.localizedCategorys had no confirmed number and fell
        # to `repeated bytes`; the adder→ivar lever now types it as GEOPDCategory.
        from proto.extractor import extract_proto_message
        from proto.write_helpers import _identify_string_write_helpers
        cls = self.cl.find('GEOPDEventCategory')
        if cls is None:
            self.skipTest('GEOPDEventCategory not in this cache')
        helpers = frozenset(_identify_string_write_helpers(self.ctx, self.cl))
        msg = extract_proto_message(self.ctx, self.st, self.cl, cls,
                                    string_write_helpers=helpers,
                                    readfrom_core_index=self.core_index)
        fld = next((f for f in msg.fields
                    if f.name == 'localizedCategorys'), None)
        self.assertIsNotNone(fld)
        self.assertEqual(fld.type_class, 'GEOPDCategory')
        self.assertNotEqual(fld.type_name, 'bytes')
        self.assertIsNone(fld.type_inference_note)   # principled, not a guess

    def test_lever_drops_guess_without_touching_the_number(self):
        # GEOPDExternalAction.externalActionDetails was a Strategy-2 GUESS.  The
        # compare-chain lever binds its element type by ivar, dropping the warning
        # note.  The lever NEVER adopts the dispatch field number (the dispatch
        # index is not reliable as a confirmation), so the number is left exactly
        # as the writeTo:/pointer-table pass set it.
        from proto.protocore import _is_real_field_ivar
        from proto.extractor import _confirm_field_numbers, extract_proto_message
        from proto.write_helpers import _identify_string_write_helpers
        cls = self.cl.find('GEOPDExternalAction')
        if cls is None:
            self.skipTest('GEOPDExternalAction not in this cache')
        helpers = frozenset(_identify_string_write_helpers(self.ctx, self.cl))
        msg = extract_proto_message(self.ctx, self.st, self.cl, cls,
                                    string_write_helpers=helpers,
                                    readfrom_core_index=self.core_index)
        fld = next((f for f in msg.fields
                    if f.name == 'externalActionDetails'), None)
        self.assertIsNotNone(fld)
        # Type fixed to principled dispatch ground truth, guess note removed.
        self.assertEqual(fld.type_class, 'GEOPDExternalActionDetail')
        self.assertIsNone(fld.type_inference_note)
        # Number is whatever the confirmation pass decided — the lever did not
        # override it with the dispatch index.
        imn = {m.name for m in cls.methods if m.name}
        fivars = [iv for iv in cls.ivars if _is_real_field_ivar(iv)]
        conf = _confirm_field_numbers(self.ctx, cls, fivars, imn).confirmed_numbers
        self.assertEqual(fld.number, conf['_externalActionDetails'])

    def test_lever_never_binds_singular_message_field(self):
        # GEOETARequest has a singular GEOWaypoint field (no adder) alongside a
        # repeated `destinations` GEOWaypoint field (has _addNoFlagsDestination:).
        # The lever must bind ONLY the repeated ivar — the singular field has no
        # adder, so the ordinal-mis-binding hazard cannot occur.
        from proto.repeated import _resolve_repeated_via_dispatch_ivars
        cls = self.cl.find('GEOETARequest')
        if cls is None:
            self.skipTest('GEOETARequest not in this cache')
        ivmap = _resolve_repeated_via_dispatch_ivars(
            self.ctx, cls, self.core_index)
        self.assertEqual(ivmap.get('_destinations'), ('GEOWaypoint', 4))
        # The singular waypoint ivars are NOT array-typed, so never bound here.
        for ivn, (_el, _fn) in ivmap.items():
            iv = next(iv for iv in cls.ivars if iv.name == ivn)
            self.assertIn(iv.type_enc, ('@"NSArray"', '@"NSMutableArray"'))


if __name__ == '__main__':
    unittest.main(verbosity=2)
