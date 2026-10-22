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
        self.assertGreaterEqual(n, 2_000_000)
        self.assertEqual(sum(diffs.values()), 0, _report(diffs, examples))

    @unittest.skipUnless(LOCATIOND, "locationd binary not available")
    def test_planted_errors_are_reported(self):
        """The corrections of capstone's errors leave our own visible, in the operands they
        correct too: ldr's write of its destination, add's read of its last operand, cmp's and
        tst's read of their first (capstone lists it as written) and lsl's of a source that is
        also its destination (capstone lists any destination as read), each dropped."""
        import oracles.operands as O
        real_reads, real_writes = O.reads, O.writes

        def writes(ins):
            return [] if ins.mnemonic == "ldr" else real_writes(ins)

        def reads(ins):
            r = real_reads(ins)
            if ins.mnemonic in ("cmp", "tst") or \
                    (ins.mnemonic == "lsl" and r and r[0] in real_writes(ins)):
                return r[1:]
            return r[:-1] if ins.mnemonic == "add" and ins.op_str.count(",") == 2 and r else r
        with mock.patch.object(O, "writes", writes), mock.patch.object(O, "reads", reads):
            _n, diffs, _ex = O.compare(_binary_ctx(LOCATIOND), 1_000_000)
        flagged = {(k[0], k[1]) for k in diffs}
        for planted in (("W", "ldr"), ("R", "add"), ("R", "cmp"), ("R", "tst"), ("R", "lsl")):
            self.assertIn(planted, flagged)


def _unicorn():
    try:
        import unicorn  # noqa: F401
        return True
    except ImportError:
        return False


_STRUCTURE = ("ran an instruction the body lacks", "an edge the CFG lacks",
              "a reaching definition not in defs_before", "a block propagation does not reach",
              "ran past the end of the body", "a decoded br that jumps elsewhere",
              "a register written that writes() does not list")
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

    def test_runs_reach_the_code(self):
        """A third of the runs return, few fault: the checks above are not of first blocks
        only."""
        st = self.report.stats
        runs = sum(v for k, v in st.items() if k.startswith("runs "))
        self.assertGreater(st["runs returned"], runs // 3)
        self.assertLess(st["runs faulted"], runs // 4)

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

    def test_a_write_writes_does_not_list_is_reported(self):
        """The registers a run writes are its own, not writes()'s: ldr's destination dropped."""
        import oracles.flow_emulation as F
        real = F.writes
        ctx = _binary_ctx(LOCATIOND)
        with mock.patch.object(F, "writes", lambda ins: [] if ins.mnemonic == "ldr" else real(ins)):
            rep = F.compare(ctx, ctx.function_starts()[::800], runs=2)
        self.assertGreater(rep.stats["a register written that writes() does not list"], 0)


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
        # what the check cannot see: every register claimed, and runs cut short
        self.assertLess(rep.stats["functions call_reads says read every register"],
                        rep.stats["functions"] // 20)
        self.assertLess(rep.stats["runs faulted"], rep.stats["functions"] * 4 // 2)

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
        self.assertEqual(rep.stats["tags from no ivar"], 0)
        self.assertEqual(dict(rep.unanswered), {})

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
        self.assertEqual(dict(rep.unanswered), {})

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
        fp = next(m for m in msgs if m.class_name == "TRANSITPbLocationFingerprint")
        macs, modes = (next(f for f in fp.fields if f.name == n) for n in ("macs", "modes"))
        macs.name, modes.name = "modes", "macs"                 # each the other's array
        rep = compare(self.img.ctx, self.img.st, self.img.cl, [hr, body, log, fp])
        for kind, cls in (("a value the class decodes differently", "ALCLAllDayHeartRate"),
                          ("an emitted field the class skips", "ALCLBodyMetrics"),
                          ("a message field that allocates another class", "ALActivityLog"),
                          ("a repeated field appended to another ivar's array",
                           "TRANSITPbLocationFingerprint")):
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
        odo.fields[7].label = type(odo.fields[7].label).REPEATED    # one double, not repeated
        rep = self._writer(msgs)
        for kind in ("a written tag the message lacks", "a type the writer does not write",
                     "a name other than its ivar's", "repeated, written once"):
            self.assertTrue(any("ALCLOdometer" in r[1] for r in rep.findings[kind]), kind)
        rep = self._enums(msgs)
        for kind in ("a value the enum lacks", "a value named for another string"):
            self.assertTrue(any("ALCLBodyMetrics" in r[1] for r in rep.findings[kind]), kind)

    def test_planted_enum_errors_are_reported(self):
        """The probes follow the class's own compares: the highest value of the motion activity
        type (90603, past any margin of those emitted) lost; an enum emptied; and a field with an
        AsString: emitted as an int32."""
        import copy
        msgs = copy.deepcopy(self.msgs)
        enum, owner = next((e, m) for m in msgs for e in m.enums
                           if any(v.number == 90603 for v in e.values))
        enum.values = [v for v in enum.values if v.number != 90603]
        body = next(m for m in msgs if m.class_name == "ALCLBodyMetrics")
        gender = next(f for f in body.fields if f.name == "gender")
        next(e for e in body.enums if e.name == gender.type_class[5:]).values = []
        plain, plain_msg = next((f, m) for m in msgs if m is not owner and m is not body
                                for f in m.fields if (f.type_class or "").startswith("ENUM:"))
        plain.type_class, plain.type_name = None, "int32"
        rep = self._enums(msgs)
        lacks = [r[1] for r in rep.findings["a value the enum lacks"]]
        self.assertTrue(any(owner.class_name in r and ": 90603 " in r for r in lacks), lacks)
        self.assertTrue(any("ALCLBodyMetrics.gender" in r for r in lacks), lacks)
        self.assertTrue(any(plain_msg.class_name in r[1] for r in
                            rep.findings["a field with an AsString: not emitted as an enum"]))


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

    def _each(self, module, check):
        for image, (img, msgs) in self.images.items():
            with self.subTest(image=image):
                rep = module.compare(img.ctx, img.st, img.cl, msgs)
                self.assertEqual(dict(rep.findings), {})
                check(image, rep)

    # the least each image's runs check: tags written, fields read, enum values named
    FLOORS = {"CoreParsec": (520, 500, 0), "CoreLocationProtobuf": (500, 500, 140),
              "GeoServices": (10_000, 10_000, 15_000)}

    def test_writeto(self):
        """CoreParsec's oneof cases #33-#45 are written only with the case's ivar set to its
        field number."""
        from oracles import writer_emulation as W

        def check(image, rep):
            self.assertEqual(rep.stats["runs returned"], rep.stats["messages"])
            self.assertGreaterEqual(rep.stats["tags written"], self.FLOORS[image][0])
            self.assertEqual(rep.stats["tags from no ivar"], 0)
            if image == "CoreParsec":
                self.assertGreaterEqual(rep.stats["nested fields"], 4)     # its maps
        self._each(W, check)

    def test_readfrom(self):
        from oracles import reader_emulation as RD

        def check(image, rep):
            self.assertEqual(rep.stats["runs returned"], rep.stats["fields run"])
            self.assertGreaterEqual(rep.stats["fields run"], self.FLOORS[image][1])
        self._each(RD, check)

    def test_enums(self):
        from oracles import enum_emulation as EN
        self._each(EN, lambda image, rep: self.assertGreaterEqual(rep.stats["values agree"],
                                                                  self.FLOORS[image][2]))

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
                self.assertEqual((res.unnamed, res.wrong, res.missed, res.ivars_wrong),
                                 (0, 0, 0, 0), {k: v[:5] for k, v in res.examples.items()})
                self.assertLess(res.no_symbol, res.methods // 50 + 1, res.examples.get("no_symbol"))

    def test_iphone8(self):
        self._check(IPHONE8_CACHE, self.IPHONE8)

    def test_planted_errors_are_reported(self):
        """A class's method dropped, two of its ivars' names swapped."""
        from macho import classlist as CL
        from macho.dyld_cache import DyldCacheReader
        from oracles.method_names import compare
        real = CL.build_class_list

        def wrong(ctx, st):
            cl = real(ctx, st)
            c = cl.find("PARSessionConfiguration")          # (its ivars have offset variables)
            del c.methods[0]
            c.ivars[0].name, c.ivars[1].name = c.ivars[1].name, c.ivars[0].name
            return cl
        with mock.patch.object(CL, "build_class_list", wrong):
            res = compare(DyldCacheReader(IPHONE8_CACHE), "CoreParsec")
        self.assertEqual(res.missed, 1)
        self.assertEqual(res.ivars_wrong, 2)

    @unittest.skipUnless(IOS27_CACHE, "iOS 27 cache not available")
    def test_ios27(self):
        self._check(IOS27_CACHE, self.IOS27)


@unittest.skipUnless(IPHONE8_CACHE and _unicorn(), "iPhone 8 cache or unicorn not available")
class TestCallModelsAgainstTheRuntime(unittest.TestCase):
    """RUNTIME_CONTRACTS, CALL_CLOBBERS and RETURNS_ARGUMENT against runs of the functions
    themselves, from the iPhone 8 cache (:mod:`oracles.call_models`, TODO #128): before, the
    stack probe's x9 was taken as kept."""

    @classmethod
    def setUpClass(cls):
        from macho.dyld_cache import DyldCacheReader
        cls.reader = DyldCacheReader(IPHONE8_CACHE)

    def test_the_tables(self):
        from oracles.call_models import compare
        res = compare(self.reader)
        self.assertEqual(res.findings, [])
        self.assertGreaterEqual(len(res.checked), 70)
        self.assertEqual(sorted(res.not_run), ["_objc_enumerationMutation",
                                               "_objc_opt_respondsToSelector"], res.not_run)

    def test_planted_errors_are_reported(self):
        """The probe's x9 kept again, isKindOfClass: without its class (x1), and
        objc_opt_class taken to return its argument."""
        import oracles.call_models as M
        names = ["____chkstk_darwin", "_objc_opt_isKindOfClass", "_objc_opt_class"]
        with mock.patch.dict(M.CALL_CLOBBERS, {"____chkstk_darwin": ("x16", "x17", "x30")}), \
                mock.patch.dict(M.RUNTIME_CONTRACTS, {"_objc_opt_isKindOfClass": (("x0",), None)}), \
                mock.patch.object(M, "RETURNS_ARGUMENT", M.RETURNS_ARGUMENT | {"_objc_opt_class"}):
            res = M.compare(self.reader, names)
        got = {(n, what) for n, what, _d in res.findings}
        self.assertIn(("____chkstk_darwin", "a register changed that CALL_CLOBBERS does not list"),
                      got)
        self.assertIn(("_objc_opt_isKindOfClass", "reads a register its contract does not list"),
                      got)
        self.assertIn(("_objc_opt_class", "does not return its argument"), got)


def _remote_mirror():
    try:
        from oracles.swift_mirror import library
        return library() is not None
    except OSError:
        return False


@unittest.skipUnless(IOS27_CACHE and _remote_mirror(),
                     "iOS 27 cache or libswiftRemoteMirror (MACHO_REMOTE_MIRROR) not available")
class TestSwiftAgainstRemoteMirror(unittest.TestCase):
    """Every emitted Swift message's stored fields and their types, and the types of the fields
    it emits (paired with its property by offset where static: #130), against Remote Mirror (TODO
    #124, #128): all agree; not compared, two one-case oneofs
    (CipherML's AspireApiPIRShardConfigs, one of TokenGeneration's).  Before #128 the oneofs of
    Apple's own generator (an enum of their own, not a nested OneOf_) went untyped and unread,
    and the fields swift-protobuf names with a ``_p`` were emitted with no type."""

    IMAGES = ("BiomeStreams", "TokenGenerationCore", "TokenGeneration", "WorkoutKit",
              "CopresenceCore", "PaperKit", "SiriKitRuntime", "WorkoutCore", "EnergyKitFoundation",
              "CipherML", "AONSense.dylib", "NearbySessions", "Hands", "MessageProtection",
              "NeighborhoodActivityConduit", "OmniSearch", "SiriTaskEngagement",
              "LocalFederatedSearch")

    def test_ios27_images(self):
        from oracles.swift_mirror import CacheMirror, compare
        mirror = CacheMirror(IOS27_CACHE)
        not_compared, unpaired, compared, renamed, by_offset = {}, {}, {}, [], 0
        for image in self.IMAGES:
            with self.subTest(image=image):
                res = compare(mirror, image)
                self.assertGreater(res.stats["messages"], 0)
                self.assertEqual(res.differences, [])
                for skipped in ("not compared: no mangled name", "fields with no type recovered",
                                "not compared: emitted, no type descriptor",
                                "emitted fields with no type"):
                    self.assertEqual(res.stats[skipped], 0, skipped)
                left = res.stats["messages"] - res.stats["agree"]
                if left:
                    not_compared[image] = res.stats["not compared: a one-case oneof"]
                if res.stats["emitted fields with no one property of their name"]:
                    unpaired[image] = res.stats["emitted fields with no one property of their name"]
                compared[image] = res.stats["emitted fields compared"]
                renamed += [(q, n) for q, n, _f, _p in res.renamed]
                by_offset += res.stats["emitted fields paired by offset"]
        self.assertEqual(not_compared, {"CipherML": 1, "TokenGeneration": 1})
        self.assertEqual(unpaired, {})
        # paired by the offset decodeMessage writes where it is static (#130): EnergyKitFoundation's
        # GridCleanlinessStats #2 / #3 (clean / reduce) are the properties cleaner / lessClean
        self.assertEqual(sorted(renamed), [("InsightRecordPayload.GridCleanlinessStats", 2),
                                           ("InsightRecordPayload.GridCleanlinessStats", 3)])
        self.assertGreater(by_offset, 1_000)
        self.assertGreaterEqual(compared["TokenGenerationCore"], 190)       # its oneofs' cases
        self.assertGreater(sum(compared.values()), 5_900)

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

    def test_a_planted_emitted_error_is_reported(self):
        """An emitted field's type changed after recovery: sint64 for a string."""
        import oracles.swift_mirror as M
        real = M.SW.swift_messages

        def wrong(ctx):
            msgs = real(ctx)
            f = next(f for m in msgs for f in m.fields if f.proto_type == "string")
            f.proto_type = "sint64"
            return msgs
        with mock.patch.object(M.SW, "swift_messages", wrong):
            res = M.compare(M.CacheMirror(IOS27_CACHE), "TokenGeneration")
        self.assertTrue(any(what == "emitted field types" for _q, what, _d in res.differences),
                        res.differences)



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
