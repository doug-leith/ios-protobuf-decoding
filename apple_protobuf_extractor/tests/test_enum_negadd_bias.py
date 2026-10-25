"""TODO #53 — large index biases materialised as a register constant then add/sub-ed
with the value reg (the >4095 analytics/log enums).  A 12-bit `sub #imm` can't hold a
bias like 50000, so LLVM emits e.g. `mov w8,#-0xc350; add w8,w2,w8; cmp w8,#3; <jump
table>`.  The data-flow evaluator (proto/dictrep_flow.py) recovers the bias because it
evaluates the register the table is indexed with; the synthetic forms are covered in
tests/test_xasstring_flow.py.

Live-gated on GeoServices.  Two guards:
  • RECOVERY  — LogMessageType gains its 50000-class segment (was capped at 40000).
  • CORRECTION — LogMsgEventUserAction's RAP_* names, which the bias-0 decoder put at
    9/23/24, now sit at their true biased values 10110/10124/10125 (bias 10101).
"""
import unittest
import pytest

try:
    import live_artifacts as _V
    _HAVE = _V.load_cache('GeoServices') is not None
except Exception:
    _HAVE = False


@pytest.mark.slow
@pytest.mark.xdist_group("geoservices_iphone8")
@unittest.skipUnless(_HAVE, 'GeoServices cache not available')
class TestNegAddBiasLive(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tests._live import extracted
        cls.enums = {}
        for m in extracted('GeoServices').messages:
            for e in getattr(m, 'enums', []) or []:
                cls.enums.setdefault(e.name, {}).update(
                    {v.number: v.name for v in e.values})

    def test_logmessagetype_recovers_50000_segment(self):
        d = self.enums.get('LogMessageType')
        self.assertIsNotNone(d, 'LogMessageType missing')
        self.assertEqual(d.get(50000), 'LOG_MESSAGE_TYPE_REALTIME_TRAFFIC_PROBE')
        self.assertEqual(d.get(50003), 'LOG_MESSAGE_TYPE_LOG_DISCARD_EVENT')
        # the 50000-class segment was the formerly-unattributed (flagged) one.
        for v in (50000, 50001, 50002, 50003):
            self.assertIn(v, d)

    def test_useraction_rap_names_at_true_biased_values(self):
        d = self.enums.get('LogMsgEventUserActionEventAction')
        self.assertIsNotNone(d)
        # bias 10101 segment: index 9/23/24 -> 10110/10124/10125 (NOT the bias-0 9/23/24).
        self.assertEqual(d.get(10110), 'LOG_MSG_EVENT_USER_ACTION_EVENT_ACTION_RAP_NEXT')
        self.assertEqual(d.get(10124), 'LOG_MSG_EVENT_USER_ACTION_EVENT_ACTION_RAP_OTHER')
        self.assertEqual(d.get(10125), 'LOG_MSG_EVENT_USER_ACTION_EVENT_ACTION_RAP_LOCATION')
        # the bias-0 mis-numbering must be gone.
        self.assertNotEqual(d.get(9), 'LOG_MSG_EVENT_USER_ACTION_EVENT_ACTION_RAP_NEXT')


if __name__ == '__main__':
    unittest.main()
