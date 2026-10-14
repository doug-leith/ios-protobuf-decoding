"""Synthetic unit test for enum type naming — NO real binary.

``_enum_name_from_pairs`` derives the enum's type name from the common SCREAMING_SNAKE prefix
of its value names (the binary holds only value names, so the type name is a heuristic).

The decoders that used to be tested here (``_dictrep_cmp_range``, ``_find_index_bias``,
``_detect_unrecovered_csel_chain``, ``_detect_unreached_branch_gate``) were window-scanners
for the ``xAsString:`` switch; the method is now evaluated by :class:`proto.dictrep_flow.Flow`
and its behaviour is covered by tests/test_dictrep_enums.py, tests/test_dictrep_inline_enums.py
(assembled bodies) and the compiled fixtures f11/f16/f18/f21/f25.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

from proto.enums import _enum_name_from_pairs


# ══════════════════════════════════════════════════════════════════════════════
# _enum_name_from_pairs — value-string prefix -> CamelCase enum type name (pure)
# ══════════════════════════════════════════════════════════════════════════════

class TestEnumNameFromPairs(unittest.TestCase):
    def test_multiword_prefix_becomes_camelcase(self):
        # The documented case: MAPS_RESULT_TYPE_* -> "MapsResultType" (better than the
        # ivar-derived fallback "ResultType").
        pairs = [(0, "MAPS_RESULT_TYPE_UNKNOWN"), (1, "MAPS_RESULT_TYPE_PLACE"),
                 (2, "MAPS_RESULT_TYPE_TRANSIT")]
        self.assertEqual(_enum_name_from_pairs(pairs, "ResultType"), "MapsResultType")

    def test_fewer_than_two_pairs_returns_fallback(self):
        self.assertEqual(_enum_name_from_pairs([(0, "FOO_BAR_BAZ")], "Fallback"),
                         "Fallback")

    def test_empty_pairs_returns_fallback(self):
        self.assertEqual(_enum_name_from_pairs([], "Fallback"), "Fallback")

    def test_single_word_common_prefix_returns_fallback(self):
        # common prefix "STATUS" is one word -> no benefit over ivar-derived "Status".
        # NOTE: using fallback="Status" here can't tell the guard's early-return
        # apart from just falling through and capitalizing "STATUS" -- both give
        # "Status" coincidentally. Use an unrelated fallback so the guard's
        # absence would visibly produce the wrong (capitalized-common) name.
        self.assertEqual(
            _enum_name_from_pairs([(0, "STATUS_OK"), (1, "STATUS_FAILED")], "Status"),
            "Status")
        self.assertEqual(
            _enum_name_from_pairs([(0, "STATUS_OK"), (1, "STATUS_FAILED")],
                                  "SomeOtherIvarDerivedName"),
            "SomeOtherIvarDerivedName")

    def test_no_common_prefix_returns_fallback(self):
        self.assertEqual(
            _enum_name_from_pairs([(0, "ALPHA_ONE"), (1, "BETA_TWO")], "Fallback"),
            "Fallback")


if __name__ == "__main__":
    unittest.main()
