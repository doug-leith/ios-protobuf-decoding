"""Relative-method-list selector base recovery (cache-native).

Preoptimized "direct selector" relative method lists encode each selector as
``base + nameOffset`` where *base* is the cache-wide magic ``🤯`` (U+1F92F)
anchor selector — NOT the method_t field address.  Resolving that base lets
selector names decode from the binary alone, so cache images that ship NO
``.symbols`` local-symbol table (e.g. CloudKitDaemon) still get correct method
names — and therefore confirmed protobuf ``writeTo:`` field numbers — instead
of falling back to ivar-order estimates.

These tests are live-gated on the real dyld shared cache.  CloudKitDaemon is the
key regressor: it has zero local symbols, so before this fix its CKDP*/CKCDP*
selectors resolved to ~6 % (null / false-positive) and every CKDP field number
was an estimate.
"""
import os
import unittest

import artifacts
from macho.dyld_cache import DyldCacheReader
from macho.memory import BinaryContext
from macho.classlist import build_class_list
from macho.strings import build_string_table

_CACHE = artifacts.cache_file()


@unittest.skipUnless(_CACHE, "dyld shared cache not available")
class TestRelativeSelectorBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.reader = DyldCacheReader(_CACHE)

    @classmethod
    def tearDownClass(cls):
        cls.reader.close()

    def _load(self, image):
        mv = self.reader.resolve_image(image)
        ctx = BinaryContext.from_cache(self.reader, mv)
        st = build_string_table(ctx)
        cl = build_class_list(ctx, st)
        return ctx, cl

    def test_candidates_found_and_anchor_is_magic_selector(self):
        cands = self.reader.relative_selector_base_candidates()
        self.assertTrue(cands, "no 🤯 anchor selector found in cache")
        # At least one candidate must literally be the magic selector string.
        self.assertTrue(
            any(self.reader.read_cstring(c) == "\U0001F92F" for c in cands),
            "no candidate vmaddr holds the 🤯 anchor cstring",
        )

    def test_calibration_picks_a_resolving_base(self):
        _, cl = self._load("GeoServices")
        base = cl.rel_sel_base
        self.assertIsNotNone(base, "selector base should resolve in cache mode")
        # The chosen base must hold the magic anchor selector.
        self.assertEqual(self.reader.read_cstring(base), "\U0001F92F")

    def test_geoservices_resolution_high(self):
        ctx, cl = self._load("GeoServices")
        named = sum(1 for c in cl for m in c.methods if m.name)
        total = sum(1 for c in cl for m in c.methods)
        self.assertGreater(total, 1000)
        # GeoServices direct selectors should resolve from the binary alone.
        self.assertGreater(named / total, 0.8)

    def test_cloudkitdaemon_writeto_resolves_without_symbols(self):
        # CloudKitDaemon ships no .symbols local symbols; the base-relative
        # decode is the ONLY way its CKDP selectors resolve.
        self.assertFalse(
            bool(self.reader.image_local_symbols(
                self.reader.resolve_image("CloudKitDaemon"))),
            "precondition: CloudKitDaemon should have no local symbols",
        )
        ctx, cl = self._load("CloudKitDaemon")
        self.assertIsNotNone(cl.rel_sel_base)
        named = sum(1 for c in cl for m in c.methods if m.name)
        total = sum(1 for c in cl for m in c.methods)
        self.assertGreater(named / total, 0.8,
                           "CKDP selectors should resolve from the base")
        # The CKDPRecord proto class must now expose its writeTo: serializer,
        # which is what unlocks confirmed (not estimated) field numbers.
        rec = next(c for c in cl
                   if c.name == "CKDPRecord" and not c.is_meta)
        self.assertIsNotNone(rec.get_method("writeTo:"))
        # And a broad swath of CKDP* classes regain writeTo:.
        wt = sum(1 for c in cl
                 if not c.is_meta and c.name.startswith("CKDP")
                 and c.get_method("writeTo:"))
        self.assertGreater(wt, 20)

    def test_binary_mode_base_is_none(self):
        # A standalone binary (no cache reader) must leave the base unset so the
        # existing __objc_methname / selref decode path is used unchanged.
        path = artifacts.locationd_path()
        if not os.path.isfile(path):
            self.skipTest("locationd binary not available")
        ctx = BinaryContext(open(path, "rb").read())
        st = build_string_table(ctx)
        cl = build_class_list(ctx, st)
        self.assertIsNone(cl.rel_sel_base)
        # locationd still resolves its own selectors from its methname section.
        named = sum(1 for c in cl for m in c.methods if m.name)
        total = sum(1 for c in cl for m in c.methods)
        self.assertGreater(named / max(total, 1), 0.8)


if __name__ == "__main__":
    unittest.main()
