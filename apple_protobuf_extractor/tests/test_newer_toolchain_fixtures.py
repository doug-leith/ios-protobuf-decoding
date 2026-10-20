"""Ground-truth checks on REAL compiled code for the newer-toolchain dispatch
mechanisms, as the readFrom: dispatch evaluator (proto.dispatch_eval) sees them.

These are not regression pins of past tool output: every expected value is a
fact about the fixture sources their author wrote (f25: the engine's field switch
covers cases 1..8 and only 5/6 construct an element, appended through generic
helpers; the guard function right before it has no switch.  f27: TestGrContainer's
engine dispatches with a compare tree and no range guard; TestGrPlainCall has its
own copy of it; TestGrForeignEngine hands ITSELF to TestGrContainer's engine).  The
schema-level view of the same binaries is in ``test_synthetic_fixtures.py``; this
module checks the INTERMEDIATE structure those results rest on -- which function is
the core, which handler each field number reaches -- so a failure points at the
mechanism rather than just at "the field came back as bytes".
"""
import os
import unittest

from macho.memory import BinaryContext
from macho.strings import build_string_table
from macho.classlist import build_class_list
from serializers.swift_descriptor_extract import load_macho_slice
from proto.dispatch import _build_readfrom_core_index, decoded_flow, function_entries
from proto import dispatch_eval as E

_FIXTURE_DIR = os.path.join(
    os.path.dirname(__file__), "synthetic_fixtures", "f25_newer_dispatch_engine")


def _symbol_addrs(ctx):
    """``{symbol_name: vmaddr}`` of the symbols the (unstripped) fixture defines."""
    return {name: addr for name, addr in ctx.iter_symbols() if addr}


def _load(binary):
    if not os.path.exists(binary):
        raise unittest.SkipTest(f"{binary} not built — run tests/synthetic_fixtures/build_fixtures.sh")
    with open(binary, "rb") as fh:
        ctx = BinaryContext(load_macho_slice(fh.read()))
    cl = build_class_list(ctx, build_string_table(ctx))
    return ctx, cl, _build_readfrom_core_index(ctx, cl)


class _EngineChecks:
    """Checks shared by the arm64 and arm64e builds of the f25 source (they differ only in
    codegen the source does not determine: arm64 indexes its tables with ``ldrb``, arm64e
    with a signed 4-byte difference table)."""

    BINARY = None

    @classmethod
    def setUpClass(cls):
        cls.ctx, cls.cl, cls.core_index = _load(cls.BINARY)
        syms = _symbol_addrs(cls.ctx)
        cls.engine = syms["_TestNtEngine"]
        cls.guard = syms["_TestNtShortGuard"]
        cls.cls = cls.cl.find("TestNtContainer")
        cls.ev = E.evaluate_class(cls.ctx, cls.cls, cls.core_index)

    def test_the_core_is_the_engine_the_wrapper_hands_self_to(self):
        """The wrapper calls a validator and a guard (each handed the reader, not self)
        and the engine (handed self).  The guard sits right before the engine, whose
        jump tables start a few instructions past the guard's own ``ret``."""
        self.assertLess(self.guard, self.engine)
        self.assertLess(self.engine - self.guard, 64)
        self.assertEqual(self.ev.cores, [self.engine], self.ev.notes)

    def test_fields_5_and_6_reach_their_own_arms_in_the_engine(self):
        """The field switch is the engine's second jump table (the first switches on the
        wire type): each field number's ``br`` target is its own arm."""
        h5, h6 = self.ev.fields[5].handler, self.ev.fields[6].handler
        self.assertNotEqual(h5, h6)
        for h in (h5, h6):
            self.assertGreater(h, self.engine)

    def test_the_arms_build_their_element_classes(self):
        self.assertEqual(self.ev.elements(), {5: "TestNtElemA", 6: "TestNtElemB"})

    def test_the_append_helper_is_handed_self_and_the_ivar_offset(self):
        """PBAppendMessageAtOffset(self, 8 / 16, e): the literal offset names the ivar."""
        self.assertEqual(self.ev.ivars(), {"_alphas": ("TestNtElemA", 5),
                                           "_betas": ("TestNtElemB", 6)})


class TestNewerDispatchEngineFixture(_EngineChecks, unittest.TestCase):
    BINARY = os.path.join(_FIXTURE_DIR, "testnde")


class TestNewerDispatchEngineFixtureArm64e(_EngineChecks, unittest.TestCase):
    """The same checks on the arm64e build: PAC-signed code, chained-fixup
    format 12, and the signed-difference-table jump table."""
    BINARY = os.path.join(_FIXTURE_DIR, "testnde_e")


_F27_DIR = os.path.join(
    os.path.dirname(__file__), "synthetic_fixtures", "f27_compare_tree_engine_no_guard")


class _GuardlessEngineChecks:
    """Ground truth on the f27 binary (source: fixture.m)."""

    BINARY = None

    @classmethod
    def setUpClass(cls):
        cls.ctx, cls.cl, cls.core_index = _load(cls.BINARY)
        syms = _symbol_addrs(cls.ctx)
        cls.engine = syms["_TestGrEngine"]
        cls.plain_engine = syms["_TestGrPlainEngine"]

    def ev(self, name):
        return E.evaluate_class(self.ctx, self.cl.find(name), self.core_index)

    def test_engine_has_no_range_guard_and_still_dispatches(self):
        # no ordered gate on the field number (``tag >> 3``): only compares for equality
        flow = decoded_flow(self.ctx, E._function_insns(
            self.ctx, self.engine, entries=function_entries(self.ctx)))
        sites = E._lsr3_sites(flow)
        self.assertTrue(sites)
        for k, dest in sites:
            self.assertEqual(flow.candidates(k, dest, (1, 1 << 29)).intervals, [])
        ev = self.ev("TestGrContainer")
        self.assertEqual(ev.cores, [self.engine])
        self.assertEqual(ev.elements(), {5: "TestGrElemA", 6: "TestGrElemB"})

    def test_the_plain_call_reaches_the_plain_classs_own_engine(self):
        ev = self.ev("TestGrPlainCall")
        self.assertEqual(ev.cores, [self.plain_engine])
        self.assertEqual(ev.elements(), {5: "TestGrElemA"})

    def test_a_class_handing_itself_to_another_classs_engine_is_not_decoded(self):
        ev = self.ev("TestGrForeignEngine")
        self.assertEqual(ev.cores, [self.engine])          # it IS handed self ...
        self.assertEqual(ev.elements(), {})                # ... but fills TestGrContainer's ivars
        self.assertTrue(any("another class's ivars" in n for n in ev.notes), ev.notes)


class TestGuardlessEngineFixture(_GuardlessEngineChecks, unittest.TestCase):
    BINARY = os.path.join(_F27_DIR, "testgr")


class TestGuardlessEngineFixtureArm64e(_GuardlessEngineChecks, unittest.TestCase):
    BINARY = os.path.join(_F27_DIR, "testgr_e")


if __name__ == "__main__":
    unittest.main()
