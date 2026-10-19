"""Synthetic ground-truth test for write_helpers.py's LAZY PRE-PASS builders
(_ensure_writeto_prepass, _ensure_string_write_helpers) — the standalone
proto.extractor.extract_proto_message() call path.

Both functions are no-ops (early return, guard already satisfied) whenever
extract_all is the caller: extract_all builds the writeTo: writer flow and
the string-write-helper set itself, up front, and either the ctx attrs are
already set by the time a per-class extraction runs or an explicit
(non-_AUTO) value is passed down — so their actual BUILD logic never
executes on any binary run through tests/test_synthetic_fixtures.py's
_extract() helper (which always goes through extract_all), regardless of
which fixture.

extract_proto_message is also a public, documented standalone entry point
(single-class extraction — see its own docstring and proto/write_helpers.py's
_ensure_writeto_prepass docstring: "a standalone caller ... without
extract_all"), used by standalone callers. Reusing an
EXISTING fixture binary and calling extract_proto_message directly on a
FRESH BinaryContext (built the same way _extract() does, just skipping
extract_all) exercises this path with real, already-verified ground truth —
no new binary needed, and no internal argument needs overriding (contrast
with proto.enums's shared-cache methname-scan fallback in
test_enum_cache_fallback_synthetic.py, where the gap is a VALUE no real
standalone binary can naturally produce, not a call path a standalone binary
never takes).
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

from macho.memory import BinaryContext
from macho.strings import build_string_table
from macho.classlist import build_class_list
from serializers.swift_descriptor_extract import load_macho_slice
from proto.extractor import extract_proto_message
from proto.write_helpers import _identify_string_write_helpers

_FIXTURE_DIR = os.path.join(
    os.path.dirname(__file__), "synthetic_fixtures", "f3_write_helper_family")
_BINARY = os.path.join(_FIXTURE_DIR, "testwt")


class TestWriteHelpersStandaloneCall(unittest.TestCase):
    """extract_proto_message() called directly (no extract_all) must build
    both lazy pre-passes on first use and produce the same correct output
    the fixture's normal extract_all-based run does."""

    def _fresh_ctx(self):
        if not os.path.exists(_BINARY):
            self.skipTest(
                f"binary not built — run tests/synthetic_fixtures/build_fixtures.sh "
                f"f3_write_helper_family")
        with open(_BINARY, "rb") as fh:
            data = load_macho_slice(fh.read())
        ctx = BinaryContext(data)
        st = build_string_table(ctx)
        cl = build_class_list(ctx, st)
        return ctx, st, cl

    def test_lazy_prepasses_absent_before_first_call(self):
        ctx, st, cl = self._fresh_ctx()
        self.assertIsNone(getattr(ctx, "_writer_flow", None))
        self.assertIsNone(getattr(ctx, "_string_write_helpers", None))

    def test_standalone_call_builds_prepasses_and_matches_fixture_ground_truth(self):
        ctx, st, cl = self._fresh_ctx()
        cls = cl.find("TestWireTypes")
        self.assertIsNotNone(cls, "TestWireTypes not found in classlist")

        msg = extract_proto_message(ctx, st, cl, cls)

        # The lazy pre-passes must now be built (not left None/absent).
        self.assertIsNotNone(getattr(ctx, "_writer_flow", None))
        self.assertIsNotNone(getattr(ctx, "_writeto_foreign_imps", None))
        got_string_helpers = getattr(ctx, "_string_write_helpers", None)
        self.assertIsNotNone(got_string_helpers)
        # Must match an independent, direct computation -- not just "non-None".
        want_string_helpers = frozenset(_identify_string_write_helpers(ctx, cl))
        self.assertEqual(got_string_helpers, want_string_helpers)

        # And the actual field-typing result must be identical to what
        # extract_all produces for this same fixture (f3's own expected.py
        # ground truth) -- proves the lazily-built pre-pass is not just
        # present but CORRECT, exercising _classify_write_helper's sint/fixed
        # decode through this call path too.
        got = {f.name: f.type_name for f in msg.fields}
        want = {
            "sVal32": "sint32", "sVal64": "sint64",
            "fVal32": "fixed32", "sfVal32": "sfixed32",
            "fVal64": "fixed64", "sfVal64": "sfixed64",
        }
        self.assertEqual(got, want)


if __name__ == "__main__":
    unittest.main()
