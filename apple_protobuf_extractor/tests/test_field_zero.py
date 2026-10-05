"""TODO #52 — field-number-0 quirk: the writeTo: walk captures top-level fields
written with a literal field number 0 (Apple's deliberate 0-based numbering, illegal
in proto2/proto3) and the extractor flags the resulting ESTIMATE as NOT wire-accurate.

Ground truth (Hopper): `-[NTPBCacheHint writeTo:]` writes `_key` with `mov w2,#0`,
`_lifetime` `#2`, `_accessTime` `#3`; `_NTPBCacheHintReadFrom` dispatches `case 0 →
_key` (no case 1).  So `key` is the field-0 case: estimated as 1, flagged; the
confirmed siblings carry no such flag.  See LIMITATIONS.md (4).

Live-gated on the NewsTransport image (the field-0 cases do not occur in the
GeoServices/locationd/CoreLocationProtobuf golden artifacts).
"""
import unittest

import proto.extractor as E

try:
    import validate_lever as _V
    _HAVE = _V._load_cache('NewsTransport') is not None
except Exception:
    _HAVE = False


@unittest.skipUnless(_HAVE, 'NewsTransport cache not available')
class TestFieldZeroFlagLive(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import validate_lever as V
        ctx, st, cl = V._load_cache('NewsTransport')
        cls.msgs = {m.class_name: m for m in E.extract_all(ctx, st, cl)}

    def _field(self, cn, fn):
        m = self.msgs.get(cn)
        self.assertIsNotNone(m, f'{cn} missing')
        f = next((x for x in m.fields if x.name == fn), None)
        self.assertIsNotNone(f, f'{cn}.{fn} missing')
        return f

    def test_ntpbcachehint_key_flagged_field_zero(self):
        key = self._field('NTPBCacheHint', 'key')
        # estimated (field 0 is illegal → tool can't confirm it), and flagged.
        self.assertFalse(key.number_confirmed,
                         'field-0 field must be estimated, not confirmed')
        self.assertIsNotNone(key.type_inference_note)
        self.assertIn('wire field number is 0', key.type_inference_note)
        self.assertIn('LIMITATIONS.md (4)', key.type_inference_note)

    def test_confirmed_siblings_not_flagged(self):
        # lifetime #2 / accessTime #3 are written with real (non-zero) numbers →
        # confirmed, and must NOT carry the field-0 flag.  On its own this is a
        # negative control only -- `lifetime`/`accessTime` never enter the
        # `_wrote_zero` gate either way, so it can't discriminate the field-0
        # detection itself.  It is meant to be read alongside the commit's
        # positive case, test_ntpbcachehint_key_flagged_field_zero (above, same
        # class) -- the two always run together as part of this file/suite.
        for fn in ('lifetime', 'accessTime'):
            f = self._field('NTPBCacheHint', fn)
            self.assertTrue(f.number_confirmed, f'{fn} should be confirmed')
            note = f.type_inference_note or ''
            self.assertNotIn('wire field number is 0', note)


if __name__ == '__main__':
    unittest.main()
