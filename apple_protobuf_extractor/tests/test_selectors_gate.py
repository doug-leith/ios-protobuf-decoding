"""
tests/test_selectors_gate.py — the up-front selector-resolution gate.

`extract_all` calls `_check_selectors_resolved(ctx, cl)` before doing any work.
When NO proto class has its required selectors (`readFrom:` / `writeTo:`)
resolved, the run is treated by input kind:

  * cache-native (`ctx.is_cache_backed`)      → SelectorsUnresolvedError
  * standalone executable (`ctx.is_executable`) → SelectorsUnresolvedError
  * standalone shared library (`ctx.is_dylib`)  → warning, no raise

When at least one proto class IS resolved, the gate is a no-op in every mode.  The proto
classes are those whose superclass chain names a PB root
(`proto.protoclass_set.rooted_proto_classes`); here a class whose superclass is named
``PBCodable``.
These replace the old silent "no-symbols" fallbacks (find-readFrom/writeTo/enum
by pattern), which were removed.
"""
from __future__ import annotations

import logging
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from macho.classlist import ClassList, ObjcClass, ObjcIvar, ObjcMethod
from proto.extractor import _check_selectors_resolved, SelectorsUnresolvedError


class _FakeCtx:
    """Minimal stand-in exposing only the mode flags the gate reads."""

    def __init__(self, *, cache=False, executable=False, dylib=False):
        self.is_cache_backed = cache
        self.is_executable = executable
        self.is_dylib = dylib


def _proto_class(name="GEOThing", *, resolved: bool, vmaddr=0x1000):
    """A PBCodable subclass.  ``resolved`` controls whether readFrom:/writeTo: appear
    as resolved method names."""
    ivars = [
        ObjcIvar(name="_reader", type_enc='@"PBDataReader"', offset=8, size=8),
        ObjcIvar(name="_readerLock", type_enc='^{os_unfair_lock_s}', offset=16,
                 size=4),
        ObjcIvar(name="_value", type_enc='i', offset=24, size=4),
    ]
    if resolved:
        methods = [
            ObjcMethod(name="readFrom:", types="", imp=0x2000),
            ObjcMethod(name="writeTo:", types="", imp=0x2100),
        ]
    else:
        # Cache-without-.symbols / stripped: names unresolved.
        methods = [
            ObjcMethod(name=None, types="", imp=0x2000),
            ObjcMethod(name=None, types="", imp=0x2100),
        ]
    return ObjcClass(
        vmaddr=vmaddr, name=name, is_meta=False, superclass_vmaddr=0,
        superclass_name="PBCodable", ro_flags=0, instance_size=32,
        methods=methods, ivars=ivars,
    )


def _proto_shaped_no_pb(name="NWUsageSnapshot", vmaddr=0x5000, superclass="NSObject"):
    """A class with a PB-like ivar shape whose method names RESOLVE but are NOT
    readFrom:/writeTo: — the SymptomNetworkUsage case (#51: an NSObject subclass).
    Names are available (so .symbols is fine / binary not stripped); the image simply
    has no protobuf messages."""
    ivars = [
        ObjcIvar(name="_reader", type_enc='@"PBDataReader"', offset=8, size=8),
        ObjcIvar(name="_readerLock", type_enc='^{os_unfair_lock_s}', offset=16,
                 size=4),
        ObjcIvar(name="_value", type_enc='i', offset=24, size=4),
    ]
    methods = [
        ObjcMethod(name="snapshot", types="", imp=0x6000),
        ObjcMethod(name="description", types="", imp=0x6100),
    ]
    return ObjcClass(
        vmaddr=vmaddr, name=name, is_meta=False, superclass_vmaddr=0,
        superclass_name=superclass, ro_flags=0, instance_size=32,
        methods=methods, ivars=ivars,
    )


def _cl(*classes):
    return ClassList(list(classes))


class TestSelectorsGate(unittest.TestCase):

    def setUp(self):
        patcher = mock.patch(
            "proto.extractor.rooted_proto_classes",
            lambda ctx, cl: frozenset(c.name for c in cl if c.superclass_name == "PBCodable"))
        patcher.start()
        self.addCleanup(patcher.stop)

    # ── Unresolved → error for cache and executable ───────────────────────────
    def test_cache_native_unresolved_raises(self):
        cl = _cl(_proto_class(resolved=False))
        with self.assertRaises(SelectorsUnresolvedError):
            _check_selectors_resolved(_FakeCtx(cache=True, dylib=True), cl)

    def test_executable_unresolved_raises(self):
        cl = _cl(_proto_class(resolved=False))
        with self.assertRaises(SelectorsUnresolvedError):
            _check_selectors_resolved(_FakeCtx(executable=True), cl)

    # ── Unresolved → warning (no raise) for a standalone dylib ────────────────
    def test_standalone_dylib_unresolved_warns_only(self):
        cl = _cl(_proto_class(resolved=False))
        with self.assertLogs("proto.extractor", level="WARNING") as cm:
            _check_selectors_resolved(_FakeCtx(dylib=True), cl)   # must not raise
        self.assertTrue(any("degraded" in m.lower() for m in cm.output))

    # ── Resolved → no-op in every mode ────────────────────────────────────────
    def test_resolved_is_noop_cache(self):
        cl = _cl(_proto_class(resolved=True))
        # No raise, and no WARNING emitted.
        logger = logging.getLogger("proto.extractor")
        with mock.patch.object(logger, "warning") as warn:
            _check_selectors_resolved(_FakeCtx(cache=True, dylib=True), cl)
        warn.assert_not_called()

    def test_resolved_is_noop_executable(self):
        cl = _cl(_proto_class(resolved=True))
        _check_selectors_resolved(_FakeCtx(executable=True), cl)   # no raise

    def test_partial_resolution_is_noop(self):
        # One resolved + one unresolved proto class → resolved > 0 → no error,
        # even in cache mode (the conservative `resolved == 0` trigger).
        cl = _cl(_proto_class(name="GEOA", resolved=True, vmaddr=0x1000),
                 _proto_class(name="GEOB", resolved=False, vmaddr=0x3000))
        _check_selectors_resolved(_FakeCtx(cache=True, dylib=True), cl)

    # ── Names resolve but no writeTo:/readFrom: → "no PB messages", not .symbols ─
    def test_a_pb_shaped_class_not_rooted_in_pb_is_not_a_proto_class(self):
        # #51's SymptomNetworkUsage classes subclass NSObject: no proto class, no-op.
        logger = logging.getLogger("proto.extractor")
        with mock.patch.object(logger, "warning") as warn:
            _check_selectors_resolved(_FakeCtx(cache=True, dylib=True), _cl(_proto_shaped_no_pb()))
        warn.assert_not_called()

    def test_names_resolve_but_no_pb_selectors_warns_not_raises(self):
        # #51: proto classes whose selector names resolve but none implement
        # writeTo:/readFrom: → "no decodable protobuf messages" warning, no raise,
        # even in cache mode.
        cl = _cl(_proto_shaped_no_pb(superclass="PBCodable"))
        with self.assertLogs("proto.extractor", level="WARNING") as cm:
            _check_selectors_resolved(_FakeCtx(cache=True, dylib=True), cl)  # no raise
        self.assertTrue(
            any("no decodable protobuf messages" in m for m in cm.output),
            cm.output)
        # MUST NOT blame the .symbols sub-cache here (the #51 mis-message); the
        # new text may MENTION .symbols only to say it is NOT the cause.
        self.assertFalse(
            any("sub-cache is missing" in m for m in cm.output), cm.output)

    def test_names_resolve_but_no_pb_selectors_no_raise_executable(self):
        # Same discriminator in standalone-executable mode: names present →
        # genuinely no PB messages → warn, don't raise the "stripped metadata" error.
        cl = _cl(_proto_shaped_no_pb(superclass="PBCodable"))
        with self.assertLogs("proto.extractor", level="WARNING"):
            _check_selectors_resolved(_FakeCtx(executable=True), cl)  # no raise

    # ── No proto classes at all → never an error ──────────────────────────────
    def test_no_proto_classes_is_noop(self):
        plain = ObjcClass(vmaddr=0x1000, name="NSWhatever", is_meta=False,
                          superclass_vmaddr=0, superclass_name=None, ro_flags=0,
                          instance_size=8, methods=[], ivars=[])
        _check_selectors_resolved(_FakeCtx(cache=True, dylib=True), _cl(plain))


if __name__ == "__main__":
    unittest.main(verbosity=2)
