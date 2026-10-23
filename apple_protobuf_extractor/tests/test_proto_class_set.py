"""TODO #46 — forward-scan proto-class detection (_proto_class_set).

Offline: a synthetic ClassList exercises the VA-cluster anchor (binary mode, where
cross-image superclass names don't resolve) — the heuristic seeds the PB-root VA and
the closure expands to siblings + local-parented subclasses, with the inheritance map.

Live: GeoServices recovers the 5 metadata-sparse PBCodable subclasses the per-class
heuristic misses, each carrying the correct inherits_from; CLP/locationd unchanged.
"""
import contextlib
import os
import unittest

from tests._fakes import NoImage

from macho.classlist import ObjcClass, ObjcIvar, ClassList
import proto.extractor as E
import proto.protoclass_set as PS


def _ivar(name):
    return ObjcIvar(name=name, type_enc="@", offset=0, size=8)


def _cls(va, name, super_va, ivars=()):
    return ObjcClass(vmaddr=va, name=name, is_meta=False, superclass_vmaddr=super_va,
                     superclass_name=None, ro_flags=0, instance_size=0,
                     methods=[], ivars=list(ivars))


class _NoReadCtx(NoImage):
    """Standalone-binary-like ctx: cross-image reads always fail, so the name-anchor
    contributes nothing and the VA-cluster anchor must carry detection."""
    def is_variable(self, vmaddr):        # no program data, no binds
        return False

    def read_ptr(self, va):
        raise ValueError("unmapped (binary mode)")
    def read_cstring(self, va):
        raise ValueError("unmapped (binary mode)")
    def import_name_for_bind(self, raw):
        # No imports table in this synthetic ctx → name anchor contributes nothing,
        # so the VA-cluster anchor alone must carry detection.
        return None


@contextlib.contextmanager
def _allow_heuristic():
    """Opt into the retired non-structural detectors for one block.

    These offline fixtures deliberately construct classes the STRUCTURAL anchor
    cannot confirm (no imports table, so no name resolves), which is now a hard
    failure. The env override is what a human investigating such a binary would
    use, so exercising the retired paths through it tests the real escape hatch
    rather than bypassing the check.
    """
    from proto.protoclass_heuristic import _ALLOW_ENV
    prev = os.environ.get(_ALLOW_ENV)
    os.environ[_ALLOW_ENV] = "1"
    try:
        yield
    finally:
        if prev is None:
            os.environ.pop(_ALLOW_ENV, None)
        else:
            os.environ[_ALLOW_ENV] = prev


class TestProtoClassSetOffline(unittest.TestCase):
    def test_va_cluster_anchor_binary_mode(self):
        ROOT = 0x8010_0000_0000_0b0b          # imported PB base (non-local bind ordinal)
        # Seed: a confirmed proto class (has _reader+_readerLock) subclassing the root.
        a = _cls(0x1000, "AReq", ROOT, ivars=[_ivar("_reader"), _ivar("_readerLock")])
        # Sibling on the same root, but metadata-sparse (heuristic would miss it).
        b = _cls(0x2000, "BReq", ROOT)
        # Subclass of a LOCAL proto class (proto-to-proto) — also metadata-sparse.
        c = _cls(0x3000, "CSub", 0x1000)
        # Unrelated class on a different superclass — must NOT be proto.
        d = _cls(0x4000, "DPlain", 0x9999_9999)
        cl = ClassList([a, b, c, d])
        ctx = _NoReadCtx()

        with _allow_heuristic():
            pset = PS._proto_class_set(ctx, cl)
        self.assertEqual(pset, frozenset({"AReq", "BReq", "CSub"}))
        self.assertNotIn("DPlain", pset)
        # CSub's immediate superclass is the local proto class AReq → inheritance note.
        self.assertEqual(getattr(ctx, "_proto_inherits", {}).get("CSub"), "AReq")
        # BReq/AReq subclass the PB root directly → no inheritance note.
        self.assertNotIn("BReq", getattr(ctx, "_proto_inherits", {}))
        self.assertNotIn("AReq", getattr(ctx, "_proto_inherits", {}))

    def test_system_root_is_never_a_pb_cluster_root(self):
        """A (false) seed whose immediate non-local super resolves to NSObject must
        NOT turn NSObject into a PB-cluster root and sweep in every NSObject
        subclass.  Guards the SymptomNetworkUsage 4→28 blow-up: even if a class is
        mis-seeded, the unrelated siblings are not dragged in."""
        from unittest import mock
        NSOBJECT = 0x8020_0000_0000_0001          # cross-image NSObject VA
        # A class the heuristic seeds (has _reader+_readerLock) but whose super is
        # NSObject — i.e. a detector false positive.
        s = _cls(0x1000, "FalseSeed", NSOBJECT,
                 ivars=[_ivar("_reader"), _ivar("_readerLock")])
        t = _cls(0x2000, "UnrelatedSibling", NSOBJECT)   # plain NSObject subclass
        cl = ClassList([s, t])
        ctx = _NoReadCtx()

        def _fake_name(_ctx, va):
            return "NSObject" if va == NSOBJECT else None

        with _allow_heuristic(), mock.patch.object(PS, "_resolve_class_name_at", _fake_name):
            pset = PS._proto_class_set(ctx, cl)
        # The false seed itself is still present (it IS the heuristic seed), but the
        # NSObject-root guard stops the unrelated sibling from being swept in.
        self.assertIn("FalseSeed", pset)
        self.assertNotIn("UnrelatedSibling", pset)

    def test_non_structural_detection_is_split_by_cause(self):
        """Neither non-structural path may pass silently: _proto_class_set must
        stamp WHICH one claimed each unconfirmed class, so the emitter can raise the
        matching ERROR.  Here the name anchor resolves nothing, so the heuristic seed
        (AReq) and the VA-cluster closure (BReq/CSub) are the only claimants."""
        ROOT = 0x8010_0000_0000_0b0b
        a = _cls(0x1000, "AReq", ROOT, ivars=[_ivar("_reader"), _ivar("_readerLock")])
        b = _cls(0x2000, "BReq", ROOT)
        c = _cls(0x3000, "CSub", 0x1000)
        cl = ClassList([a, b, c])
        ctx = _NoReadCtx()

        with _allow_heuristic():
            PS._proto_class_set(ctx, cl)
        self.assertEqual(ctx._proto_class_heuristic_only, frozenset({"AReq"}))
        self.assertEqual(ctx._proto_class_cluster_only, frozenset({"BReq", "CSub"}))

    def test_structurally_confirmed_class_is_flagged_by_neither(self):
        """The normal case: the by-name superclass walk reaches PBCodable, so the
        class is structurally confirmed and NO error stamp applies to it."""
        from unittest import mock
        PB = 0x8010_0000_0000_0b0b
        a = _cls(0x1000, "AReq", PB, ivars=[_ivar("_reader"), _ivar("_readerLock")])
        cl = ClassList([a])
        ctx = _NoReadCtx()

        with mock.patch.object(PS, "_resolve_class_name_at",
                               lambda _c, va: "PBCodable" if va == PB else None):
            pset = PS._proto_class_set(ctx, cl)
        self.assertIn("AReq", pset)
        self.assertEqual(ctx._proto_class_heuristic_only, frozenset())
        self.assertEqual(ctx._proto_class_cluster_only, frozenset())


class TestNonStructuralDetectionFailsTheRun(unittest.TestCase):
    """Detection by either retired path must ABORT a whole-image extraction, not
    warn — it means the structural detector failed, so the whole class set for that
    image is suspect.

    The verdict is deliberately scoped to extract_all, which is where a COMPLETE
    class graph exists (and is the entry point every real consumer of this tool
    uses).  A single-class extract_proto_message call has no such graph — a
    synthetic ObjcClass may have no superclass at all — so it flags inline instead;
    TestSingleClassPathFlagsButDoesNotFail below pins that boundary.
    """

    def _cluster_only_fixture(self):
        """Two classes on a shared imported root, no imports table → the name anchor
        confirms neither, so the VA-cluster is BReq's only claimant."""
        ROOT = 0x8010_0000_0000_0b0b
        a = _cls(0x1000, "AReq", ROOT, ivars=[_ivar("_reader"), _ivar("_readerLock")])
        b = _cls(0x2000, "BReq", ROOT)
        ctx = _NoReadCtx()
        # extract_all runs two gates before the structural check (selector
        # resolution, foreign-serializer detection); give the synthetic ctx just
        # enough surface for them to pass through to the check under test.
        ctx.is_cache_backed = False
        ctx.is_executable = False
        ctx.iter_symbol_names = lambda: iter(())
        return ClassList([a, b]), ctx

    def test_raises_by_default(self):
        from proto.protoclass_heuristic import ProtoClassDetectionError
        cl, ctx = self._cluster_only_fixture()
        with self.assertRaises(ProtoClassDetectionError):
            E.extract_all(ctx, None, cl)

    def test_error_names_both_the_classes_and_the_failing_path(self):
        from proto.protoclass_heuristic import ProtoClassDetectionError
        cl, ctx = self._cluster_only_fixture()
        with self.assertRaises(ProtoClassDetectionError) as cm:
            E.extract_all(ctx, None, cl)
        text = str(cm.exception)
        self.assertIn("BReq", text)                      # the offending class
        self.assertIn("VA-cluster", text)                # which detector claimed it
        self.assertIn("MACHO_ALLOW_HEURISTIC_PROTO_CLASSES", text)   # the way out

    def test_a_chain_that_leaves_the_file_is_named_as_the_cause(self):
        """The shared root is a pointer the file does not map (a dylib extracted from a
        dyld cache): the error says so, with the pointer, and points at the cache."""
        from proto.protoclass_heuristic import ProtoClassDetectionError
        cl, ctx = self._cluster_only_fixture()
        with self.assertRaises(ProtoClassDetectionError) as cm:
            E.extract_all(ctx, None, cl)
        text = str(cm.exception)
        self.assertIn("[2] of them: the superclass chain leaves this file", text)
        self.assertIn("(AReq: 0x8010000000000b0b)", text)
        self.assertIn("--cache", text)
        self.assertNotIn("never happened", text)

    def test_a_chain_that_ends_in_the_file_is_not_explained(self):
        """A seeded class under a local root class: its chain ends in the file, so the
        failure has no known cause and the error says to investigate."""
        from proto.protoclass_heuristic import ProtoClassDetectionError
        _cl, ctx = self._cluster_only_fixture()
        cl = ClassList([_cls(0x1000, "AReq", 0x2000, ivars=[_ivar("_reader"),
                                                            _ivar("_readerLock")]),
                        _cls(0x2000, "LocalRoot", 0)])
        with self.assertRaises(ProtoClassDetectionError) as cm:
            E.extract_all(ctx, None, cl)
        text = str(cm.exception)
        self.assertIn("This has never happened", text)
        self.assertNotIn("leaves this file", text)

    def test_failure_is_raised_before_any_extraction_work(self):
        """The verdict must abort the run, not surface after a schema was built —
        so it fires before the writeTo/string-helper pre-passes even start."""
        from unittest import mock
        from proto.protoclass_heuristic import ProtoClassDetectionError
        cl, ctx = self._cluster_only_fixture()
        with mock.patch.object(E, "_ensure_writeto_prepass") as pre_pass:
            with self.assertRaises(ProtoClassDetectionError):
                E.extract_all(ctx, None, cl)
        pre_pass.assert_not_called()

    def test_env_override_downgrades_to_a_logged_error(self):
        cl, ctx = self._cluster_only_fixture()
        with _allow_heuristic():
            with self.assertLogs("proto.protoclass_heuristic", level="ERROR") as logs:
                E.extract_all(ctx, None, cl)
        self.assertTrue(any("BReq" in r for r in logs.output))
        # Extraction continued: the suspect class is still in the set, and is
        # flagged rather than dropped.
        self.assertIn("BReq", PS._proto_class_set(ctx, cl))

    def test_clean_binary_does_not_raise(self):
        """The check must be inert on a structurally-confirmed class set.

        NOTE: calling _proto_class_set directly (as this test did before)
        never reaches check_no_heuristic_detection at all -- extract_all is
        the ONLY function that wires that gate in (see the module docstring
        above) -- so a revert of the gate a95197e9 added was invisible here.
        Route through extract_all instead, matching the sibling tests in
        TestNonStructuralDetectionFailsTheRun above.
        """
        from unittest import mock
        PB = 0x8010_0000_0000_0b0b
        a = _cls(0x1000, "AReq", PB, ivars=[_ivar("_reader"), _ivar("_readerLock")])
        cl, ctx = ClassList([a]), _NoReadCtx()
        ctx.is_cache_backed = False
        ctx.is_executable = False
        ctx.iter_symbol_names = lambda: iter(())
        with mock.patch.object(PS, "_resolve_class_name_at",
                               lambda _c, va: "PBCodable" if va == PB else None):
            msgs = E.extract_all(ctx, None, cl)   # must not raise
        self.assertTrue(any(m.class_name == "AReq" for m in msgs))


class TestSingleClassPathFlagsButDoesNotFail(unittest.TestCase):
    """extract_proto_message on a class with NO superclass chain must still work.

    Pins the boundary the whole-image verdict is scoped against.  Synthetic
    fixtures across the suite (tests/test_enum.py, tests/test_proto.py) build a
    proto class with superclass_vmaddr=0 and call extract_proto_message directly:
    there is no chain to walk, so the heuristic is necessarily the only claimant.
    That must FLAG the message, not abort — otherwise the retired detector's
    failure gate would break every single-class caller in the suite.
    """

    def test_no_superclass_single_class_extraction_flags_and_succeeds(self):
        # NOTE: this used to only call _proto_class_set directly, never
        # extract_proto_message -- the class docstring's actual claim (a
        # class_detected_by_heuristic FLAG on the returned ProtoMessage, not
        # an abort) was untested.  Route through extract_proto_message, the
        # real single-class-path entry point this class documents.
        from macho.strings import StringTable
        cls = _cls(0x1000, "AReq", 0,
                   ivars=[_ivar("_reader"), _ivar("_readerLock")])
        cl, ctx = ClassList([cls]), _NoReadCtx()
        # No raise, and the message is tagged so the guess is never silent.
        msg = E.extract_proto_message(ctx, StringTable(), cl, cls)
        self.assertIsNotNone(msg)
        self.assertTrue(msg.class_detected_by_heuristic)
        self.assertEqual(ctx._proto_class_heuristic_only, frozenset({"AReq"}))


class TestNonStructuralDetectionRendersAsError(unittest.TestCase):
    """Both non-structural detection paths must surface as ERRORs in the emitted
    .proto — they mean the structural detector failed, so the message's presence in
    the schema is a guess. Guards proto.emitter.ProtoFile._emit_message (the only
    renderer the real CLI path ever calls) against drifting back to a soft
    informational note.

    (Previously also guarded the now-deleted ProtoMessage.to_proto, a dead-code
    twin nothing in production called. Migrated 2026-07-22 to render through the real path instead, since
    this was the ONLY place this specific ERROR-comment behavior was tested at
    all.)"""

    def _msg(self, **kw):
        from proto.models import ProtoMessage
        return ProtoMessage(name="M", class_name="GEOM", **kw)

    def _render(self, msg) -> str:
        from proto.emitter import ProtoFile
        pf = ProtoFile(package="test", filename="test.proto", messages=[], imports=[])
        return "\n".join(pf._emit_message(msg, {}))

    def test_comments_are_worded_as_errors(self):
        from proto.models import (HEURISTIC_CLASS_DETECTION_COMMENT,
                                  VA_CLUSTER_CLASS_DETECTION_COMMENT)
        for c in (HEURISTIC_CLASS_DETECTION_COMMENT,
                  VA_CLUSTER_CLASS_DETECTION_COMMENT):
            self.assertTrue(c.startswith("// ERROR:"), c)

    def test_emit_message_emits_each_error(self):
        self.assertIn("// ERROR:", self._render(self._msg(class_detected_by_heuristic=True)))
        self.assertIn("// ERROR:", self._render(self._msg(class_detected_by_va_cluster=True)))
        self.assertNotIn("// ERROR:", self._render(self._msg()))

    def test_va_cluster_error_names_the_cluster_path(self):
        from proto.models import VA_CLUSTER_CLASS_DETECTION_COMMENT
        out = self._render(self._msg(class_detected_by_va_cluster=True))
        self.assertIn(VA_CLUSTER_CLASS_DETECTION_COMMENT, out)
        # The two causes are distinct: the cluster flag must not emit the heuristic
        # wording (they point the reader at different code paths).
        from proto.models import HEURISTIC_CLASS_DETECTION_COMMENT
        self.assertNotIn(HEURISTIC_CLASS_DETECTION_COMMENT, out)


try:
    import live_artifacts as _V
    _HAVE = _V.load_cache("GeoServices") is not None
except Exception:
    _HAVE = False


@unittest.skipUnless(_HAVE, "GeoServices cache not available")
class TestProtoClassSetLive(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import live_artifacts as V
        cls.ctx, cls.st, cls.cl = V.load_cache("GeoServices")
        cls.msgs = {m.class_name: m for m in E.extract_all(cls.ctx, cls.st, cls.cl)}

    def test_recovered_subclasses_emitted_with_inheritance(self):
        expected = {
            "GEOAnalyticsPipelineSharedStateData": "AnalyticsPipelineStateData",
            "GEOComposedWaypointEVStop": "ComposedWaypoint",
            "GEOSearchRequest": "PlaceSearchRequest",
            "GEOSearchResponse": "PlaceSearchResponse",
            "GEOCLPLocationCollectionRequest": "LocationCollectionRequest",
        }
        for cn, parent in expected.items():
            m = self.msgs.get(cn)
            self.assertIsNotNone(m, f"{cn} not recovered/emitted")
            self.assertEqual(m.inherits_from, parent, f"{cn} inherits_from")

    def test_normal_top_level_message_has_no_inheritance_note(self):
        m = self.msgs.get("GEOLatLngE7")
        self.assertIsNotNone(m)
        self.assertIsNone(m.inherits_from)

    def test_set_is_superset_of_heuristic(self):
        from proto.protoclass_heuristic import _is_proto_class
        heur = {c.name for c in self.cl if not c.is_meta and _is_proto_class(c)}
        pset = PS._proto_class_set(self.ctx, self.cl)
        self.assertTrue(heur <= pset, "forward-scan set must never drop a heuristic hit")
        self.assertEqual(len(pset - heur), 5)  # the 5 metadata-sparse subclasses


try:
    import live_artifacts as _VL
    _HAVE_LOCATIOND = _VL.load_locationd() is not None
except Exception:
    _HAVE_LOCATIOND = False


@unittest.skipUnless(_HAVE_LOCATIOND, "locationd binary not available")
class TestProtoClassSetBinaryNameAnchor(unittest.TestCase):
    """Principled binary-mode NAME anchor: in a standalone binary the superclass
    slot is an undecoded bind whose ordinal resolves through the imports table to
    ``_OBJC_CLASS_$_PBCodable`` — so the name anchor works WITHOUT cross-image
    reads and is now the primary detector (the heuristic seed is redundant here,
    parity with cache mode)."""
    @classmethod
    def setUpClass(cls):
        import live_artifacts as V
        cls.ctx, cls.st, cls.cl = V.load_locationd()

    def test_resolve_class_name_at_resolves_bind_super_to_pbcodable(self):
        # Every PB subclass shares the same raw bind super value; it must resolve
        # to the PB root NAME via the imports table (not None as before the fix).
        from proto.protoclass_heuristic import _is_proto_class
        sub = next(c for c in self.cl if not c.is_meta and _is_proto_class(c)
                   and c.superclass_vmaddr and c.superclass_vmaddr not in
                   {x.vmaddr for x in self.cl})
        self.assertEqual(PS._resolve_class_name_at(self.ctx, sub.superclass_vmaddr),
                         "PBCodable")

    def test_name_anchor_alone_reproduces_full_set(self):
        from unittest import mock
        full = PS._proto_class_set(self.ctx, self.cl)
        self.assertTrue(full, "locationd should have proto classes")
        # Disable the heuristic seed: the principled name anchor alone must recover
        # the same set in binary mode (heuristic retired as primary).
        if hasattr(self.ctx, "_proto_class_names_cache"):
            delattr(self.ctx, "_proto_class_names_cache")
        with mock.patch.object(E, "_is_proto_class", lambda c: False):
            anchor_only = PS._proto_class_set(self.ctx, self.cl)
        if hasattr(self.ctx, "_proto_class_names_cache"):
            delattr(self.ctx, "_proto_class_names_cache")
        self.assertEqual(anchor_only, full,
                         "name anchor alone must equal the with-seed set")


if __name__ == "__main__":
    unittest.main()
