"""The independent oracles (:mod:`oracles`) over whole images: operand semantics against capstone,
method names against the cache's ``.symbols``, Swift fields and types against Apple's Remote
Mirror.  Each asserts no difference the oracle's own known errors do not explain.

By default the standard set (a few minutes): locationd's whole ``__text`` and the first 2M
instructions of iOS 27 GeoServices; the method names of 14 cache images; the Swift messages of
the census's 18 iOS 27 images.  ``MACHO_TEST_ORACLE_FULL=1`` adds iOS 27 GeoServices' whole
``__text`` (another ~3 minutes).  Each is skipped without its artifact (the Remote Mirror library:
:func:`artifacts.remote_mirror_lib`)."""
import os
import unittest
from unittest import mock

import artifacts

FULL = os.environ.get("MACHO_TEST_ORACLE_FULL", "").strip() == "1"


def _cache(cache_dir):
    for name in artifacts.CACHE_BASENAMES:
        p = os.path.join(cache_dir, name)
        if os.path.isfile(p):
            return p
    return None


IPHONE8_CACHE = artifacts.cache_file()
IOS27_CACHE = _cache(artifacts.ios27_cache_dir())
LOCATIOND = artifacts.locationd_path() if os.path.isfile(artifacts.locationd_path()) else None


def _cache_ctx(cache, image):
    from macho.dyld_cache import DyldCacheReader
    from macho.load import load_cache_image
    r = DyldCacheReader(cache)
    return load_cache_image(r, r.find_image_header(image)).ctx


def _binary_ctx(path):
    from macho.memory import BinaryContext
    from serializers.swift_descriptor_extract import load_macho_slice
    return BinaryContext(load_macho_slice(open(path, "rb").read()))


def _report(diffs, examples):
    return "\n".join("%6d  %s  %s missing=%s extra=%s" % (n, k[0], examples[k], list(k[2]), list(k[3]))
                     for k, n in diffs.most_common(20))


class TestOperandsAgainstCapstone(unittest.TestCase):
    """``reads()`` / ``writes()`` against capstone's register-access lists (TODO #123)."""

    @unittest.skipUnless(LOCATIOND, "locationd binary not available")
    def test_locationd(self):
        from oracles.operands import compare
        n, diffs, examples = compare(_binary_ctx(LOCATIOND))
        self.assertGreater(n, 5_000_000)
        self.assertEqual(sum(diffs.values()), 0, _report(diffs, examples))

    @unittest.skipUnless(IOS27_CACHE, "iOS 27 cache not available")
    def test_ios27_geoservices(self):
        from oracles.operands import compare
        n, diffs, examples = compare(_cache_ctx(IOS27_CACHE, "GeoServices"),
                                     None if FULL else 2_000_000)
        self.assertEqual(sum(diffs.values()), 0, _report(diffs, examples))

    @unittest.skipUnless(LOCATIOND, "locationd binary not available")
    def test_planted_errors_are_reported(self):
        """The known-error allowances leave our own errors visible: ldr's write of its
        destination and add's read of its last operand, each dropped, are reported."""
        import oracles.operands as O
        real_reads, real_writes = O.reads, O.writes

        def writes(ins):
            return [] if ins.mnemonic == "ldr" else real_writes(ins)

        def reads(ins):
            r = real_reads(ins)
            return r[:-1] if ins.mnemonic == "add" and ins.op_str.count(",") == 2 and r else r
        with mock.patch.object(O, "writes", writes), mock.patch.object(O, "reads", reads):
            _n, diffs, _ex = O.compare(_binary_ctx(LOCATIOND), 1_000_000)
        flagged = {(k[0], k[1]) for k in diffs}
        self.assertIn(("W", "ldr"), flagged)
        self.assertIn(("R", "add"), flagged)


@unittest.skipUnless(IPHONE8_CACHE, "iPhone 8 cache not available")
class TestMethodNamesAgainstSymbols(unittest.TestCase):
    """The class-list parser's method names against ``.symbols`` (TODO #123): none unnamed, none
    wrong -- iPhone 8 GeoServices had selectors over 200 characters, UIKitCore one with an empty
    keyword."""

    # (CloudKitDaemon and CoreLocation have no .symbols in this cache)
    IPHONE8 = ("GeoServices", "CoreLocationProtobuf", "AdCore", "CoreParsec", "iTunesCloud",
               "AppPredictionInternal", "C2", "NetworkServiceProxy", "ProactiveEventTracker",
               "Foundation", "UIKitCore")
    IOS27 = ("GeoServices", "MessageProtection", "TrustedPeers")

    def _check(self, cache, images):
        from macho.dyld_cache import DyldCacheReader
        from oracles.method_names import compare
        reader = DyldCacheReader(cache)
        for image in images:
            with self.subTest(image=image):
                res = compare(reader, image)
                self.assertIsNotNone(res, "no .symbols")
                self.assertGreater(res.agree, 0)
                self.assertEqual((res.unnamed, res.wrong), (0, 0),
                                 {k: v[:5] for k, v in res.examples.items()})

    def test_iphone8(self):
        self._check(IPHONE8_CACHE, self.IPHONE8)

    @unittest.skipUnless(IOS27_CACHE, "iOS 27 cache not available")
    def test_ios27(self):
        self._check(IOS27_CACHE, self.IOS27)


def _remote_mirror():
    try:
        from oracles.swift_mirror import library
        return library() is not None
    except OSError:
        return False


@unittest.skipUnless(IOS27_CACHE and _remote_mirror(),
                     "iOS 27 cache or libswiftRemoteMirror (MACHO_REMOTE_MIRROR) not available")
class TestSwiftAgainstRemoteMirror(unittest.TestCase):
    """Every emitted Swift message's stored fields and their types against Remote Mirror (TODO
    #124): all agree; the one not compared is CipherML's AspireApiPIRShardConfigs, a one-case
    oneof."""

    IMAGES = ("BiomeStreams", "TokenGenerationCore", "TokenGeneration", "WorkoutKit",
              "CopresenceCore", "PaperKit", "SiriKitRuntime", "WorkoutCore", "EnergyKitFoundation",
              "CipherML", "AONSense.dylib", "NearbySessions", "Hands", "MessageProtection",
              "NeighborhoodActivityConduit", "OmniSearch", "SiriTaskEngagement",
              "LocalFederatedSearch")

    def test_ios27_images(self):
        from oracles.swift_mirror import CacheMirror, compare
        mirror = CacheMirror(IOS27_CACHE)
        not_compared = {}
        for image in self.IMAGES:
            with self.subTest(image=image):
                res = compare(mirror, image)
                self.assertGreater(res.stats["messages"], 0)
                self.assertEqual(res.differences, [])
                left = res.stats["messages"] - res.stats["agree"]
                if left:
                    not_compared[image] = dict(res.stats)
        self.assertEqual(list(not_compared), ["CipherML"], not_compared)
        self.assertEqual(not_compared["CipherML"].get("not compared: a one-case oneof"), 1)

    def test_a_planted_error_is_reported(self):
        """TokenGeneration's stopSequences typed back to the old filler (``repeated bytes``)."""
        import oracles.swift_mirror as M
        real = M.TR.collect_field_types

        def wrong(ctx):
            meta = real(ctx)
            for fields in meta.types.values():
                if "stopSequences" in fields:
                    fields["stopSequences"] = "repeated bytes"
            return meta
        with mock.patch.object(M.TR, "collect_field_types", wrong):
            res = M.compare(M.CacheMirror(IOS27_CACHE), "TokenGeneration")
        self.assertTrue(any(what == "field types" and any(f == "stopSequences" for f, *_ in detail)
                            for _q, what, detail in res.differences), res.differences)

    def test_slide_info_decodes_as_the_reader(self):
        """Every pointer of a data page, decoded from the slide info's chains, is what the
        cache reader's own decode_ptr makes of it."""
        import struct
        from oracles.swift_mirror import CacheMirror, SlideInfo
        reader = CacheMirror(IOS27_CACHE).reader
        slide = SlideInfo(reader)
        m = slide.maps[0]
        page = next(pg for pg, st in enumerate(m[3]) if st != 0xFFFF)
        base = m[0] + page * m[2]
        raw = reader.read_raw(base, m[2])
        decoded = slide.apply(base, raw)
        pointers = slide._page(m, page)
        self.assertTrue(pointers)
        for off in pointers:
            v = struct.unpack_from("<Q", raw, off)[0]
            self.assertEqual(struct.unpack_from("<Q", decoded, off)[0], reader.decode_ptr(v))


if __name__ == "__main__":
    unittest.main()
