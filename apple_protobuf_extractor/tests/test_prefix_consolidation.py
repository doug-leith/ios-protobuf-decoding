"""
tests/test_prefix_consolidation.py — Tests for the DEFAULT_PREFIXES consolidation.

Written BEFORE implementation; all fail until proto/defaults.py is created
and extractor/emitter are updated to import from it.

The change is purely structural (no behaviour change), so tests focus on:
  • DEFAULT_PREFIXES is importable from proto.defaults
  • config._class_to_proto_name defaults to DEFAULT_PREFIXES (no hardcoded literal)
  • an explicit prefixes= tuple overrides the default
  • emitter.package_for_class takes its known prefixes from DEFAULT_PREFIXES
    (the run's own --prefix set is an argument, no module-level map)
"""

from __future__ import annotations

import sys
import os
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


class TestDefaultPrefixesModule(unittest.TestCase):
    """proto.defaults must export DEFAULT_PREFIXES."""

    def setUp(self):
        from proto.defaults import DEFAULT_PREFIXES
        self.defaults = DEFAULT_PREFIXES

    def test_importable(self):
        from proto.defaults import DEFAULT_PREFIXES
        self.assertIsNotNone(DEFAULT_PREFIXES)

    def test_is_tuple(self):
        self.assertIsInstance(self.defaults, tuple)

    def test_contains_geo(self):
        self.assertIn("GEO", self.defaults)

    def test_contains_clp(self):
        self.assertIn("CLP", self.defaults)

    def test_contains_clm(self):
        self.assertIn("CLM", self.defaults)

    def test_contains_cln(self):
        self.assertIn("CLN", self.defaults)

    def test_all_uppercase_strings(self):
        for p in self.defaults:
            self.assertIsInstance(p, str)
            self.assertTrue(p.isupper(), f"Prefix {p!r} must be uppercase")


class TestConfigDefaultPrefixes(unittest.TestCase):
    """config._class_to_proto_name must default to DEFAULT_PREFIXES (no globals)."""

    def test_default_prefix_set_strips_each_default(self):
        # NOTE: never calls configure_prefixes()/touches the (removed) global, so
        # this can't discriminate 1ec059a's global-removal on its own -- see
        # TestSingleCanonicalSource.test_no_module_level_prefix_global_and_no_cross_call_leakage
        # below for a test that does.
        from proto.defaults import DEFAULT_PREFIXES
        from proto.config import _class_to_proto_name
        # With no explicit prefixes the canonical default set is used.
        self.assertEqual(_class_to_proto_name("GEOPDPlace"), "PDPlace")
        for p in DEFAULT_PREFIXES:
            self.assertEqual(_class_to_proto_name(p + "Foo"), "Foo")

    def test_explicit_prefixes_override_default(self):
        from proto.config import _class_to_proto_name
        self.assertEqual(_class_to_proto_name("APPLFoo", ("APPL",)), "Foo")
        # GEO is NOT stripped when an explicit non-GEO set is passed.
        self.assertEqual(_class_to_proto_name("GEOBar", ("APPL",)), "GEOBar")


class TestEmitterUsesDefaultPrefixes(unittest.TestCase):
    """emitter.package_for_class must take its known prefixes from DEFAULT_PREFIXES."""

    def test_each_default_prefix_gives_its_lowercase_package(self):
        from proto.defaults import DEFAULT_PREFIXES
        from proto.emitter import package_for_class
        for p in DEFAULT_PREFIXES:
            self.assertEqual(package_for_class(p + "ABFoo"), p.lower())

    def test_no_module_level_prefix_map(self):
        import proto.emitter as em
        self.assertFalse(hasattr(em, "_PREFIX_PACKAGE"))
        self.assertFalse(hasattr(em, "configure_prefix_packages"))


class TestSingleCanonicalSource(unittest.TestCase):
    """The default strings must appear only in proto.defaults, not duplicated."""

    def test_config_default_derives_from_default_prefixes(self):
        """config._class_to_proto_name must default to DEFAULT_PREFIXES, not a
        hardcoded literal — stripping each canonical prefix with no explicit set.

        NOTE: the old global was itself initialized from DEFAULT_PREFIXES, so
        this is value-identical by construction, not just coincidentally -- see
        test_no_module_level_prefix_global_and_no_cross_call_leakage below for a
        test that actually exercises the global's removal."""
        from proto.config import _class_to_proto_name
        from proto.defaults import DEFAULT_PREFIXES
        for p in DEFAULT_PREFIXES:
            self.assertEqual(_class_to_proto_name(p + "X"), "X")

    def test_no_module_level_prefix_global_and_no_cross_call_leakage(self):
        """1ec059a's actual change (none of the 4 flagged tests above can observe
        it: they never call configure_prefixes()/touch the global, so old and new
        semantics coincide by construction) -- proto.config must carry no mutable
        module-level prefix state at all (the removed configure_prefixes()/
        current_prefixes()/_PROTO_PREFIXES global), and an explicit prefixes=
        override on one call must never leak into a later call that omits it."""
        import proto.config as cfg
        self.assertFalse(hasattr(cfg, 'configure_prefixes'))
        self.assertFalse(hasattr(cfg, 'current_prefixes'))
        self.assertFalse(hasattr(cfg, '_PROTO_PREFIXES'))
        from proto.config import _class_to_proto_name
        self.assertEqual(_class_to_proto_name('APPLFoo', ('APPL',)), 'Foo')
        # A later call with NO explicit prefixes must still fall back to the
        # canonical default -- not silently reuse the previous call's ('APPL',)
        # override, which the old global design would have permitted.
        self.assertEqual(_class_to_proto_name('APPLFoo'), 'APPLFoo')
        self.assertEqual(_class_to_proto_name('GEOPDPlace'), 'PDPlace')


if __name__ == '__main__':
    unittest.main(verbosity=2)
