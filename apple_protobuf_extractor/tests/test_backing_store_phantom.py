"""Tests for the manual-array backing-store phantom filter.

Apple's generated PB classes store an inline-C-struct array as three ivars:
``_xs`` (``^{Struct}`` data pointer, the real field), ``_xsCount`` (uint64,
element count) and ``_xsSpace`` (uint64, capacity).  Only ``_xs`` is serialised;
``writeTo:`` uses ``_xsCount`` as the loop bound and never touches ``_xsSpace``.
``_is_backing_store_phantom`` drops the two companions so they are not emitted as
phantom fields with bogus ivar-order numbers.  Ground truth (GEOTileGroup,
GEOTileSetVersion, GEOCoarseLocationRing) verified in Hopper.
"""
import os
import artifacts
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(_HERE))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from proto.extractor import (_is_backing_store_phantom,
                             _unresolved_object_field_note)
from proto.models import ProtoField, FieldLabel


def _f(name, type_name="uint64", confirmed=False):
    return ProtoField(name=name, number=9, type_name=type_name,
                      label=FieldLabel.OPTIONAL, type_class=None,
                      number_confirmed=confirmed)


# The data ivar of the triplet is a C-struct-array pointer.
_ENC = {"tileSets": "^{GEOVersionedTileSet=II}",
        "points":   "^{GEOCoarseLocationPoint=ii}"}


class TestBackingStorePhantom(unittest.TestCase):

    # ── Positive: the two companions of a ^{Struct} array are dropped ──────────
    def test_count_companion_is_phantom(self):
        self.assertTrue(_is_backing_store_phantom(_f("tileSetsCount"), _ENC))

    def test_space_companion_is_phantom(self):
        self.assertTrue(_is_backing_store_phantom(_f("tileSetsSpace"), _ENC))

    def test_points_triplet(self):
        self.assertTrue(_is_backing_store_phantom(_f("pointsCount"), _ENC))
        self.assertTrue(_is_backing_store_phantom(_f("pointsSpace"), _ENC))

    # ── Guards: must never drop a real field ──────────────────────────────────
    def test_confirmed_number_is_never_dropped(self):
        # A genuinely-serialised field carries a real writeTo number.
        self.assertFalse(
            _is_backing_store_phantom(_f("tileSetsCount", confirmed=True), _ENC))

    def test_non_uint64_is_not_phantom(self):
        self.assertFalse(
            _is_backing_store_phantom(_f("tileSetsCount", type_name="int32"), _ENC))

    def test_no_sibling_data_ivar_is_not_phantom(self):
        # `widgetsCount` with no `_widgets` ivar at all.
        self.assertFalse(_is_backing_store_phantom(_f("widgetsCount"), _ENC))

    def test_sibling_not_struct_pointer_is_not_phantom(self):
        # Sibling exists but is NSData / NSArray, not a ^{Struct} array pointer.
        enc = {"blob": '@"NSData"', "items": '@"NSMutableArray"'}
        self.assertFalse(_is_backing_store_phantom(_f("blobCount"), enc))
        self.assertFalse(_is_backing_store_phantom(_f("itemsSpace"), enc))

    def test_real_field_name_is_not_phantom(self):
        # The data field itself, and an unrelated field, are never phantoms.
        self.assertFalse(_is_backing_store_phantom(_f("tileSets", confirmed=True), _ENC))
        self.assertFalse(_is_backing_store_phantom(_f("identifier", "uint32"), _ENC))

    def test_suffix_must_be_a_real_suffix(self):
        # A field literally named "Count"/"Space" has no base name.
        self.assertFalse(_is_backing_store_phantom(_f("Count"), _ENC))
        self.assertFalse(_is_backing_store_phantom(_f("Space"), _ENC))
        # Against _ENC alone the empty-string base-name lookup already misses
        # (`ivar_enc_by_pname.get("")` is None), so the `len(name) > len(suffix)`
        # guard is never load-bearing above.  Use a sibling dict where the EMPTY
        # string key DOES resolve to a struct-array-pointer ivar, so only the
        # length guard can still stop "Count"/"Space" from matching themselves.
        enc_with_empty_base = dict(_ENC, **{"": "^{GEOPoint=ii}"})
        self.assertFalse(_is_backing_store_phantom(_f("Count"), enc_with_empty_base))
        self.assertFalse(_is_backing_store_phantom(_f("Space"), enc_with_empty_base))


# ── Live: the phantoms are actually gone from emitted classes ─────────────────

_PROTOSET = frozenset({"GEOPDPlace", "GEOPlaceResult", "GEOLatLng"})


def _ofld(name, enc, confirmed=False):
    f = ProtoField(name=name, number=9, type_name="bytes",
                   label=FieldLabel.OPTIONAL, type_class=None,
                   number_confirmed=confirmed)
    return f, {name: enc}


class TestUnresolvedObjectFieldNote(unittest.TestCase):
    """_unresolved_object_field_note ANNOTATES (does not drop) object ivars whose
    type doesn't resolve to a proto message or Foundation type — so the reader
    decides whether they're real.  No name-shape heuristic; never annotates a
    resolved proto/Foundation field or a confirmed field."""

    def _note(self, name, enc, confirmed=False):
        f, m = _ofld(name, enc, confirmed)
        return _unresolved_object_field_note(f, m, _PROTOSET)

    def test_protocol_typed_is_annotated(self):
        self.assertIsNotNone(self._note("geoMapItem", '@"<GEOMapItem>"'))

    def test_non_proto_helper_class_is_annotated(self):
        self.assertIsNotNone(self._note("isolater", '@"geo_isolater"'))
        self.assertIsNotNone(self._note("trampoline", '@"_GEOMapItemStorageNotificationTrampoline"'))
        # an unresolved CamelCase class (maybe cross-framework) is ALSO flagged —
        # honest "didn't resolve here", no guess, kept as a field
        self.assertIsNotNone(self._note("meta", '@"CLPMeta"'))

    def test_resolved_proto_class_not_annotated(self):
        self.assertIsNone(self._note("placeData", '@"GEOPDPlace"'))
        # On its own this only exercises the `inner in proto_class_names` guard,
        # which predates 59a9c48 and is unrelated to the casing-heuristic region
        # that commit replaced (an unresolved LOWERCASE-first class name used to
        # be silently DROPPED via a name-shape guess; now it is always kept and
        # ANNOTATED, no guess).  Also check that region directly so this test
        # alone would have caught a revert of that change.
        self.assertIsNotNone(self._note("isolater", '@"geo_isolater"'))

    def test_foundation_not_annotated(self):
        for enc in ('@"NSString"', '@"NSMutableArray"', '@"NSData"', '@"NSMutableDictionary"'):
            self.assertIsNone(self._note("x", enc), enc)

    def test_confirmed_field_not_annotated(self):
        self.assertIsNone(self._note("isolater", '@"geo_isolater"', confirmed=True))
        # On its own this only exercises the `number_confirmed` early-return,
        # which predates 59a9c48 and is unrelated to the casing-heuristic region
        # that commit replaced.  Check the SAME ivar unconfirmed too, so this
        # test alone reaches that region and would have caught a revert of the
        # drop-vs-annotate change (old code silently DROPPED this lowercase-first
        # unresolved class via a name-shape guess; new code keeps + annotates it).
        self.assertIsNotNone(self._note("isolater", '@"geo_isolater"', confirmed=False))

    def test_scalar_or_struct_not_annotated(self):
        # NOTE: this exercises the `not enc.startswith('@"')` guard, which predates
        # the 59a9c48 annotate-don't-drop rewrite (introduced with the function
        # itself in d09ee93, as _is_internal_nonproto_ivar's "scalar/struct/packed"
        # early-return) — mis-attributed to 59a9c48 by the commit-mapping script.
        self.assertIsNone(self._note("count", "Q"))             # uint64
        self.assertIsNone(self._note("pts", '^{GEOPoint=ii}'))  # inline struct


def _find_cache_main():
    cache_dir = os.environ.get('MACHO_TEST_CACHE', '').strip()
    for d in ([cache_dir] if cache_dir else []) + [artifacts.cache_dir()]:
        for name in ('dyld_shared_cache_arm64e', 'dyld_shared_cache_arm64'):
            p = os.path.join(d, name)
            if os.path.isfile(p):
                return p
    return None


@unittest.skipUnless(_find_cache_main() is not None,
                     'dyld shared cache not found in <repo>/iphone8_data/dylib/ (or set MACHO_DATA_DIR)')
class TestBackingStorePhantomLive(unittest.TestCase):
    """GEOTileGroup keeps its real fields and loses the Count/Space phantoms."""

    @classmethod
    def setUpClass(cls):
        import validate_lever as V
        import proto.extractor as E
        loaded = V._load_cache('GeoServices')
        if loaded is None:
            cls.msgs = None
            return
        cls.msgs = {m.class_name: m for m in E.extract_all(*loaded)}

    def setUp(self):
        if not getattr(self, 'msgs', None):
            self.skipTest('GeoServices not available')

    def test_tilegroup_phantoms_removed_real_fields_kept(self):
        m = self.msgs.get('GEOTileGroup')
        self.assertIsNotNone(m)
        names = {f.name for f in m.fields}
        for phantom in ('tileSetsCount', 'tileSetsSpace',
                        'hybridUnavailableRegionsCount', 'regionalResourceIndexsSpace'):
            self.assertNotIn(phantom, names, f'{phantom} should be omitted')
        for real in ('tileSets', 'identifier', 'hybridUnavailableRegions',
                     'muninVersionIndex'):
            self.assertIn(real, names, f'{real} must be kept')

    def test_no_countspace_phantoms_remain_anywhere(self):
        leftover = [(cn, f.name) for cn, m in self.msgs.items() for f in m.fields
                    if not f.number_confirmed and f.name.endswith(('Count', 'Space'))]
        self.assertEqual(leftover, [], f'unconfirmed Count/Space remain: {leftover[:10]}')


if __name__ == '__main__':
    unittest.main()
