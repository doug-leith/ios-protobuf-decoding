"""The independent oracles (:mod:`oracles`) over whole images: operand semantics against capstone,
method names against the cache's ``.symbols``, Swift fields and types against Apple's Remote
Mirror, Flow and the emitted ObjC messages and enums against concrete runs in an emulator.  Each asserts no difference the oracle's own
known errors do not explain.

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


def _unicorn():
    try:
        import unicorn  # noqa: F401
        return True
    except ImportError:
        return False


_STRUCTURE = ("ran an instruction the body lacks", "an edge the CFG lacks",
              "a reaching definition not in defs_before", "a block propagation does not reach")
_VALUES = ("a known value that does not hold", "a known stack address that does not hold",
           "a constant Flow takes for a stack address")


@unittest.skipUnless(LOCATIOND and _unicorn(), "locationd binary or unicorn not available")
class TestFlowAgainstEmulation(unittest.TestCase):
    """:class:`proto.arm64_eval.Flow`'s CFG, reaching definitions and known values against
    concrete runs in Unicorn (:mod:`oracles.flow_emulation`): one function in 100 of locationd,
    4 runs each (every one in 4 with MACHO_TEST_ORACLE_FULL=1)."""

    @classmethod
    def setUpClass(cls):
        from oracles.flow_emulation import compare
        ctx = _binary_ctx(LOCATIOND)
        cls.report = compare(ctx, ctx.function_starts()[::4 if FULL else 100], runs=4)

    def _findings(self, kinds):
        return {k: self.report.findings[k][:5] for k in kinds if self.report.stats[k]}

    def test_structure(self):
        self.assertGreater(self.report.stats["edges"], 10_000)
        self.assertGreater(self.report.stats["reads"], 100_000)
        self.assertEqual(self._findings(_STRUCTURE), {})

    def test_values(self):
        """Every value Flow knows holds.  Before TODO #125 frame addresses and import slots were
        numbers in bands -- a constant passed for one (2^62 - 1, the double 2.0), arithmetic
        broke one (a frame address plus a large constant, an import's slot value + 16) -- and a
        writable __data variable was read as its file contents."""
        self.assertGreater(self.report.stats["known values"], 100_000)
        self.assertEqual(self._findings(_VALUES), {})

    def test_runs_from_entry_values(self):
        """propagate / run_from / value_at entered with self (a token) and numbers in some
        argument registers: one function in 200."""
        from oracles.flow_emulation import compare
        ctx = _binary_ctx(LOCATIOND)
        rep = compare(ctx, ctx.function_starts()[::40 if FULL else 200], runs=4, entry=True)
        self.assertGreater(rep.stats["entry values"], 100_000)
        self.assertGreater(rep.stats["call arguments"], 10_000)
        self.assertEqual(dict(rep.findings), {})

    def test_a_planted_error_is_reported(self):
        """An add evaluated one too high is a known value that does not hold."""
        import proto.arm64_eval as E
        from oracles.flow_emulation import compare
        real = E.Flow._exec

        def wrong(self, m, ins):
            real(self, m, ins)
            if ins.mnemonic == "add" and ins.op_str.startswith("x8, x8, #"):
                v = m.get("x8")
                if v is not None:
                    m.put("x8", v + 1)
        ctx = _binary_ctx(LOCATIOND)
        with mock.patch.object(E.Flow, "_exec", wrong):
            rep = compare(ctx, ctx.function_starts()[::400], runs=2)
            from_entry = compare(ctx, ctx.function_starts()[::400], runs=2, entry=True)
        self.assertGreater(rep.stats["a known value that does not hold"], 0)
        self.assertGreater(from_entry.stats["a value propagated from the entry that does not hold"], 0)


@unittest.skipUnless(LOCATIOND and _unicorn(), "locationd binary or unicorn not available")
class TestCallReadsAgainstEmulation(unittest.TestCase):
    """:func:`proto.callees.call_reads` against concrete runs of each function, its callees
    in the image run too (:mod:`oracles.callreads_emulation`): one locationd function in 400
    (one in 100 with MACHO_TEST_ORACLE_FULL=1)."""

    def test_call_reads(self):
        from oracles.callreads_emulation import compare
        ctx = _binary_ctx(LOCATIOND)
        rep = compare(ctx, ctx.function_starts()[::100 if FULL else 400], runs=4)
        self.assertGreater(rep.stats["registers read"], 1000)
        self.assertEqual(dict(rep.findings), {})

    def test_a_planted_error_is_reported(self):
        """call_reads without the first register it lists."""
        import oracles.callreads_emulation as C
        real = C.call_reads
        ctx = _binary_ctx(LOCATIOND)
        with mock.patch.object(C, "call_reads", lambda c, va: real(c, va)[1:]):
            rep = C.compare(ctx, ctx.function_starts()[::800], runs=2)
        self.assertGreater(rep.stats["a register read that call_reads does not list"], 0)


@unittest.skipUnless(LOCATIOND and _unicorn(), "locationd binary or unicorn not available")
class TestObjcMessagesAgainstEmulation(unittest.TestCase):
    """The emitted ObjC messages against concrete runs of each class's ``writeTo:`` (each tag
    written: its field's number, type, name and label; :mod:`oracles.writer_emulation`), of its
    ``readFrom:`` (each field read: into its ivar, decoded as its type, a message field's class;
    :mod:`oracles.reader_emulation`) and of each enum field's ``AsString:`` (its values and their
    names; :mod:`oracles.enum_emulation`) -- locationd's 65 messages and 46 enum fields."""

    @classmethod
    def setUpClass(cls):
        from macho.load import load_classes
        from proto import extractor as E
        cls.img = load_classes(_binary_ctx(LOCATIOND))
        cls.msgs = E.extract_all(cls.img.ctx, cls.img.st, cls.img.cl)

    def _writer(self, msgs):
        from oracles.writer_emulation import compare
        return compare(self.img.ctx, self.img.st, self.img.cl, msgs)

    def _enums(self, msgs):
        from oracles.enum_emulation import compare
        return compare(self.img.ctx, self.img.st, self.img.cl, msgs)

    def test_writeto(self):
        rep = self._writer(self.msgs)
        self.assertGreater(rep.stats["tags written"], 400)
        self.assertEqual(rep.stats["runs returned"], rep.stats["messages"])
        self.assertEqual(dict(rep.findings), {})
        self.assertEqual(rep.stats["fields not written in the run"], 0)

    def test_enums(self):
        rep = self._enums(self.msgs)
        self.assertGreater(rep.stats["values agree"], 400)
        self.assertEqual(dict(rep.findings), {})

    def test_readfrom(self):
        from oracles.reader_emulation import compare
        rep = compare(self.img.ctx, self.img.st, self.img.cl, self.msgs)
        self.assertGreater(rep.stats["fields run"], 400)
        self.assertEqual(rep.stats["runs returned"], rep.stats["fields run"])
        self.assertEqual(dict(rep.findings), {})

    def test_planted_errors_are_reported_by_readfrom(self):
        """An int64 called sint64 decodes otherwise, a number shifted is skipped, a message
        field of another class allocates its own."""
        import copy
        from oracles.reader_emulation import compare
        msgs = copy.deepcopy(self.msgs)
        hr = next(m for m in msgs if m.class_name == "ALCLAllDayHeartRate")
        mode = next(f for f in hr.fields if f.name == "mode")
        mode.type_name = "sint64"
        body = next(m for m in msgs if m.class_name == "ALCLBodyMetrics")
        body.fields[1].number += 50
        log = next(m for m in msgs if m.class_name == "ALActivityLog")
        log.fields[1].type_class = "ALCLBodyMetrics"
        rep = compare(self.img.ctx, self.img.st, self.img.cl, [hr, body, log])
        for kind, cls in (("a value the class decodes differently", "ALCLAllDayHeartRate"),
                          ("an emitted field the class skips", "ALCLBodyMetrics"),
                          ("a message field that allocates another class", "ALActivityLog")):
            self.assertTrue(any(cls in r[1] for r in rep.findings[kind]), kind)

    def test_planted_errors_are_reported(self):
        import copy
        msgs = copy.deepcopy(self.msgs)
        odo = next(m for m in msgs if m.class_name == "ALCLOdometer")
        odo.fields[0].number += 100                      # a wrong number
        odo.fields[1].type_name = "int32"                # a wrong type
        odo.fields[2].name = "notIts"                    # a wrong name
        gender = next(m for m in msgs if m.class_name == "ALCLBodyMetrics")
        enum = next(e for e in gender.enums if e.values)
        enum.values[0].name = enum.values[0].name + "_X"  # a value named for another string
        del enum.values[1]                               # a value lost
        rep = self._writer(msgs)
        for kind in ("a written tag the message lacks", "a type the writer does not write",
                     "a name other than its ivar's"):
            self.assertTrue(any("ALCLOdometer" in r[1] for r in rep.findings[kind]), kind)
        rep = self._enums(msgs)
        for kind in ("a value the enum lacks", "a value named for another string"):
            self.assertTrue(any("ALCLBodyMetrics" in r[1] for r in rep.findings[kind]), kind)


@unittest.skipUnless(IPHONE8_CACHE and _unicorn(), "iPhone 8 cache or unicorn not available")
class TestCacheImagesAgainstEmulation(unittest.TestCase):
    """The oracles on images of the iPhone 8 dyld cache (:class:`oracles.flow_emulation.CacheMachine`:
    other images' memory read from the cache, calls into them answered at their exports):
    CoreParsec (maps, oneofs) and CoreLocationProtobuf (packed arrays) through writeTo:, readFrom:
    and AsString:, and Flow over a sample of CoreLocationProtobuf's functions; GeoServices (inline
    C structs, lazily read messages) too with MACHO_TEST_ORACLE_FULL=1."""

    IMAGES = ("CoreParsec", "CoreLocationProtobuf") + (("GeoServices",) if FULL else ())

    @classmethod
    def setUpClass(cls):
        import contextlib
        import io
        from macho.dyld_cache import DyldCacheReader
        from macho.load import load_cache_image
        from proto import extractor as E
        reader = DyldCacheReader(IPHONE8_CACHE)
        cls.images = {}
        for image in cls.IMAGES:
            img = load_cache_image(reader, reader.find_image_header(image))
            with contextlib.redirect_stdout(io.StringIO()):
                cls.images[image] = (img, E.extract_all(img.ctx, img.st, img.cl))

    def _each(self, module):
        for image, (img, msgs) in self.images.items():
            with self.subTest(image=image):
                rep = module.compare(img.ctx, img.st, img.cl, msgs)
                self.assertEqual(dict(rep.findings), {})
                yield image, rep

    def test_writeto(self):
        from oracles import writer_emulation as W
        for image, rep in self._each(W):
            self.assertEqual(rep.stats["runs returned"], rep.stats["messages"])
            if image == "CoreParsec":
                self.assertGreaterEqual(rep.stats["nested fields"], 4)     # its maps

    def test_readfrom(self):
        from oracles import reader_emulation as RD
        for _image, rep in self._each(RD):
            self.assertEqual(rep.stats["runs returned"], rep.stats["fields run"])

    def test_enums(self):
        from oracles import enum_emulation as EN
        list(self._each(EN))

    def test_flow(self):
        from oracles.flow_emulation import compare
        img, _msgs = self.images["CoreLocationProtobuf"]
        rep = compare(img.ctx, img.ctx.function_starts()[::4 if FULL else 20], runs=4)
        self.assertGreater(rep.stats["known values"], 100_000)
        self.assertEqual(dict(rep.findings), {})


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



class TestCacheMemory(unittest.TestCase):
    """The pointers :class:`oracles.cache_memory.SlideInfo` decodes from a cache's slide info
    chains are what the reader's own ``decode_ptr`` makes of them (version 2, the iPhone 8 cache;
    version 5, iOS 27) -- version 2 keeps a pointer's top-byte flag bits, as dyld does, which
    ``decode_ptr`` strips."""

    def _check(self, cache):
        import struct
        from macho.dyld_cache import DyldCacheReader
        from oracles.cache_memory import SlideInfo
        reader = DyldCacheReader(cache)
        slide = SlideInfo(reader)
        checked = 0
        for m in slide.maps:
            size = slide._page_size(m)
            for pg in range(0, (m[1] - m[0]) // size, 211):
                for off, v in slide._page(m, pg).items():
                    raw = struct.unpack("<Q", reader.read_raw(m[0] + pg * size + off, 8))[0]
                    want = reader.decode_ptr(raw)
                    if v or want:
                        self.assertEqual(v & ((1 << 56) - 1), want, hex(m[0] + pg * size + off))
                        checked += 1
        self.assertGreater(checked, 1000)

    @unittest.skipUnless(IPHONE8_CACHE, "iPhone 8 cache not available")
    def test_version_2(self):
        self._check(IPHONE8_CACHE)

    @unittest.skipUnless(IOS27_CACHE, "iOS 27 cache not available")
    def test_version_5(self):
        self._check(IOS27_CACHE)


if __name__ == "__main__":
    unittest.main()
