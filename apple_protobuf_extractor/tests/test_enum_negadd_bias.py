"""TODO #53 — large index biases materialised as a register constant then add/sub-ed
with the value reg (the >4095 analytics/log enums).  A 12-bit `sub #imm` can't hold a
bias like 50000, so LLVM emits e.g. `mov w8,#-0xc350; add w8,w2,w8; cmp w8,#3; <jump
table>`.  `_leading_materialized_bias` recovers the bias (TIED to the gate's compared
register, so a neighbouring segment's materialise+add can't bleed in).

Live-gated on GeoServices.  Two guards:
  • RECOVERY  — LogMessageType gains its 50000-class segment (was capped at 40000).
  • CORRECTION — LogMsgEventUserAction's RAP_* names, which the bias-0 decoder put at
    9/23/24, now sit at their true biased values 10110/10124/10125 (bias 10101).
"""
import unittest

import proto.extractor as E
from proto.enums import _leading_materialized_bias
from tests.test_disasm import make_insn

try:
    import validate_lever as _V
    _HAVE = _V._load_cache('GeoServices') is not None
except Exception:
    _HAVE = False


class TestLeadingMaterializedBiasUnit(unittest.TestCase):
    """Direct synthetic unit tests for _leading_materialized_bias, covering both
    families documented in its docstring: NEGATIVE-ADD (only ever exercised
    indirectly, via the live GeoServices tests below) and the "defensive sibling"
    materialised-positive-SUB form, which previously had no test at all (neither
    live nor synthetic)."""

    def test_negative_add_form(self):
        # mov w8,#-50000 ; add w2,w2,w8  (value_reg=2) -> bias 50000.
        # _leading_materialized_bias reads op_str textually (not the raw word), so
        # build the mov/add pair directly as the decoder would render them.
        insns = [
            make_insn(0x1000, 'mov', 'w8, #-50000'),
            make_insn(0x1004, 'add', 'w2, w2, w8'),
        ]
        bias = _leading_materialized_bias(insns, 0, len(insns), value_reg=2)
        self.assertEqual(bias, 50000)

    def test_materialized_positive_sub_form(self):
        # movz w8,#50000 ; sub w2,w2,w8  (value_reg=2) -> bias 50000.
        # This is the "same family; defensive" SUB form from the docstring, which
        # (unlike the ADD form above) had zero coverage anywhere in the suite.
        insns = [
            make_insn(0x1000, 'movz', 'w8, #50000'),
            make_insn(0x1004, 'sub', 'w2, w2, w8'),
        ]
        bias = _leading_materialized_bias(insns, 0, len(insns), value_reg=2)
        self.assertEqual(bias, 50000)

    def test_sub_form_wrong_register_not_biased(self):
        # The sub targets w3, not the gate's value_reg=2 -> must NOT contribute.
        insns = [
            make_insn(0x1000, 'movz', 'w8, #50000'),
            make_insn(0x1004, 'sub', 'w3, w3, w8'),
        ]
        bias = _leading_materialized_bias(insns, 0, len(insns), value_reg=2)
        self.assertEqual(bias, 0)

    def test_sub_form_negative_constant_not_used_as_bias(self):
        # sub with a NEGATIVE materialised constant doesn't match the documented
        # "positive constant subtracted" shape -> no bias (only the mov/add pair
        # models negative constants).
        insns = [
            make_insn(0x1000, 'mov', 'w8, #-50000'),
            make_insn(0x1004, 'sub', 'w2, w2, w8'),
        ]
        bias = _leading_materialized_bias(insns, 0, len(insns), value_reg=2)
        self.assertEqual(bias, 0)


@unittest.skipUnless(_HAVE, 'GeoServices cache not available')
class TestNegAddBiasLive(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import validate_lever as V
        ctx, st, cl = V._load_cache('GeoServices')
        cls.enums = {}
        for m in E.extract_all(ctx, st, cl):
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
