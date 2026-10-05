"""Ground-truth checks on REAL compiled code for the newer-toolchain dispatch
mechanisms — the compiled counterpart of the raw-word tests in
``test_readfrom_dispatch.py`` / ``test_dictrep_enums.py``.

These are not regression pins of past tool output: every expected value is a
fact about ``synthetic_fixtures/f25_newer_dispatch_engine/fixture.m`` that its
author wrote (the engine's switch covers cases 1..8; the guard function has no
switch at all; field 5/6's arms allocate ``TestNtElemA``/``TestNtElemB``) and
that was confirmed against the compiled disassembly when the fixture was
built.  The schema-level view of the same binary (repeated fields resolve to
the right element classes) is in ``test_synthetic_fixtures.py``; this module
checks the INTERMEDIATE structure those results rest on, so a failure points
at the mechanism rather than just at "the field came back as bytes".
"""
import os
import re
import struct
import unittest

from macho.memory import BinaryContext
from macho.strings import build_string_table
from macho.classlist import build_class_list
from serializers.swift_descriptor_extract import load_macho_slice
from macho.arm64decode import _decode_b_bl_target
from macho.disasm import disasm
from proto.dispatch import (
    _find_dispatch_cluster, _decode_readfrom_jumptable, _walk_jumptable_arms,
    _any_arm_loads_known_classref, _call_site_selects_data_table,
    _build_readfrom_core_index, _read_raw_word, _find_field_count,
    _core_resolves_compare_chain, _core_loads_own_ivar_slot, _core_insns,
)
from proto.arm64cfg import ivar_slot_loads

_FIXTURE_DIR = os.path.join(
    os.path.dirname(__file__), "synthetic_fixtures", "f25_newer_dispatch_engine")


def _symbol_addrs(ctx):
    """``{symbol_name: vmaddr}`` from the binary's own LC_SYMTAB (the fixture
    is unstripped).  Test-only: the extractor itself never needs to look a
    function up by name."""
    symoff, nsyms, stroff, strsize = ctx._symtab
    out = {}
    for i in range(nsyms):
        n_strx, _t, n_sect, _d, n_value = struct.unpack_from(
            "<IBBHQ", ctx._data, symoff + i * 16)
        if n_sect == 0 or n_value == 0:
            continue
        end = ctx._data.index(b"\0", stroff + n_strx)
        out[ctx._data[stroff + n_strx:end].decode()] = n_value
    return out


def _bl_sites_to(ctx, func_va, target_va, max_words=256):
    """VAs of every ``bl target_va`` inside the function starting at *func_va*
    (bounded by its own first ``ret``)."""
    sites = []
    for i in range(max_words):
        va = func_va + 4 * i
        w = _read_raw_word(ctx, va)
        if w is None:
            break
        if _decode_b_bl_target(w, va) == target_va and (w >> 26) == 0b100101:
            sites.append(va)
        if w == 0xD65F03C0:      # ret
            break
    return sites


class _EngineChecks:
    """Checks shared by the arm64 and arm64e builds of the f25 source.  The
    two differ only in codegen the SOURCE does not determine — see
    ``TABLE_ENTRY_SIZE`` — never in what the source says."""

    BINARY = None
    TABLE_ENTRY_SIZE = None

    @classmethod
    def setUpClass(cls):
        if not os.path.exists(cls.BINARY):
            raise unittest.SkipTest(
                f"{cls.BINARY} not built — run tests/synthetic_fixtures/"
                "build_fixtures.sh f25_newer_dispatch_engine")
        with open(cls.BINARY, "rb") as fh:
            data = load_macho_slice(fh.read())
        cls.ctx = BinaryContext(data)
        st = build_string_table(cls.ctx)
        cl = build_class_list(cls.ctx, st)
        cls.core_index = _build_readfrom_core_index(cls.ctx, cl)
        syms = _symbol_addrs(cls.ctx)
        cls.engine = syms["_TestNtEngine"]
        cls.guard = syms["_TestNtShortGuard"]
        cls.wrapper = syms["_TestNtContainerReadFrom_wrapper"]
        cls.validate = syms["_PBValidateReader"]

    # -- mechanism 3: function-boundary bound ---------------------------------

    def test_short_guard_has_no_dispatch_cluster(self):
        """TestNtShortGuard contains no switch; the engine's jump table starts
        a few instructions past its own ``ret``.  A scan that ignores the
        function boundary would report the ENGINE's cluster as the guard's."""
        self.assertLess(self.guard, self.engine,
                        "fixture layout changed: guard must precede the engine")
        self.assertLess(self.engine - self.guard, 64,
                        "guard must be immediately adjacent to the engine")
        self.assertIsNone(_find_dispatch_cluster(self.ctx, self.guard))

    def test_engine_cluster_is_the_field_switch(self):
        """The engine holds two jump tables (wire type: cases 0..7; field
        number: cases 1..8).  The returned cluster must be the field switch —
        8 entries and bias 1 (source: ``case 1``..``8``, an 8-case switch over
        a `sub w,w,#1` index).  The table's entry WIDTH is the compiler's
        choice: plain arm64 emits a one-byte index table (``ldrb``), arm64e a
        signed 4-byte difference table (``ldrsw``, the idiom
        ``_jump_table_arm_addrs`` documents) — both recorded from the
        disassembly of each build."""
        cluster = _find_dispatch_cluster(self.ctx, self.engine)
        self.assertIsNotNone(cluster)
        _arm_base, count, _table_reg, entry_size, bias, br_va = cluster
        self.assertEqual((count, bias, entry_size),
                         (8, 1, self.TABLE_ENTRY_SIZE))
        self.assertGreater(br_va, self.engine)

    # -- mechanism 1: table-base reaching definition --------------------------

    def test_engine_arms_are_the_field_switchs_own_table(self):
        """Both of the engine's tables take their base from the same register,
        so the decoded arms only line up with the source if the table base is
        the one reaching THIS cluster's ``br``.  Ground truth from the source:
        8 arms for fields 1..8, each a distinct address, laid out in the order
        the cases were written (so strictly ascending), with fields 5 and 6 —
        the only arms that construct an element — being the two that load a
        classref."""
        cluster = _find_dispatch_cluster(self.ctx, self.engine)
        arms = _decode_readfrom_jumptable(
            self.ctx, self.engine, cluster[1], cluster=cluster)
        self.assertEqual(sorted(arms), list(range(1, 9)))
        addrs = [arms[f] for f in range(1, 9)]
        self.assertEqual(len(set(addrs)), 8, "every field has its own arm")
        self.assertEqual(addrs, sorted(addrs), "arms follow source order")
        self.assertTrue(all(self.engine < a < self.engine + 0x200
                            for a in addrs), "every arm lies inside the engine")

        # The checks above hold for the WIRE-TYPE table too (also 8 distinct,
        # ascending, in-engine arms), so they cannot tell the two apart.  What
        # does: the source wrote `PBHandleUnknownField(self, N)` for cases
        # 1-4/7/8 (the arm passes N in w1), and `PBAppendMessageAtOffset(self,
        # 8|16, e)` for cases 5/6 (the arm passes the ivar offset in w1) — the
        # wire-type arms just do `add x0, x22, #k`.
        want_w1 = {1: 1, 2: 2, 3: 3, 4: 4, 5: 8, 6: 16, 7: 7, 8: 8}
        self.assertEqual({f: self._arm_w1_immediate(arms[f]) for f in arms},
                         want_w1)

    def _arm_w1_immediate(self, arm_va):
        """The immediate of the last ``mov w1, #imm`` before the arm's first
        unconditional branch (its tail call / merge point)."""
        insns = disasm(self.ctx, arm_va, max_insns=48, stop_at_ret=False)
        imm = None
        for ins in insns:
            if ins.mnemonic in ("b", "br", "ret"):
                break
            m = re.fullmatch(r"w1, #(0x[0-9a-f]+|\d+)", ins.op_str)
            if ins.mnemonic == "mov" and m:
                imm = int(m.group(1), 0)
        return imm

    # -- mechanism 2: classref fallback + call-site signal --------------------

    def test_arm_elements_resolve_via_classref(self):
        """No arm calls an own accessor or ``bl``s a ReadAllFrom core, so the
        only way to learn the element class is the classref the arm loads for
        ``[TestNtElemX alloc]``."""
        cluster = _find_dispatch_cluster(self.ctx, self.engine)
        arms = _decode_readfrom_jumptable(
            self.ctx, self.engine, cluster[1], cluster=cluster)
        self.assertEqual(
            _walk_jumptable_arms(self.ctx, arms, self.core_index),
            {5: "TestNtElemA", 6: "TestNtElemB"})

    def test_classref_only_trusted_for_known_proto_classes(self):
        """The same classrefs, but with no known proto classes to match them
        against, must not be trusted (the fallback accepts a name only when it
        is itself a message class in this binary)."""
        cluster = _find_dispatch_cluster(self.ctx, self.engine)
        arms = _decode_readfrom_jumptable(
            self.ctx, self.engine, cluster[1], cluster=cluster)
        self.assertTrue(_any_arm_loads_known_classref(
            self.ctx, arms, self.core_index))
        self.assertFalse(_any_arm_loads_known_classref(self.ctx, arms, {}))
        self.assertEqual(_walk_jumptable_arms(self.ctx, arms, {}), {})

    def test_call_site_selects_data_table_only_at_the_engine_call(self):
        """The wrapper makes three calls the source wrote: PBValidateReader,
        TestNtShortGuard, then TestNtEngine with a ``cond ? kTabA : kTabB``
        argument.  Only the last is a dual-data-table ``csel`` call site."""
        engine_sites = _bl_sites_to(self.ctx, self.wrapper, self.engine)
        validate_sites = _bl_sites_to(self.ctx, self.wrapper, self.validate)
        guard_sites = _bl_sites_to(self.ctx, self.wrapper, self.guard)
        self.assertEqual(
            (len(engine_sites), len(validate_sites), len(guard_sites)),
            (1, 1, 1))
        self.assertTrue(
            _call_site_selects_data_table(self.ctx, engine_sites[0]))
        self.assertFalse(
            _call_site_selects_data_table(self.ctx, validate_sites[0]))
        self.assertFalse(
            _call_site_selects_data_table(self.ctx, guard_sites[0]))


class TestNewerDispatchEngineFixture(_EngineChecks, unittest.TestCase):
    BINARY = os.path.join(_FIXTURE_DIR, "testnde")
    TABLE_ENTRY_SIZE = 1


class TestNewerDispatchEngineFixtureArm64e(_EngineChecks, unittest.TestCase):
    """The same checks on the arm64e build: PAC-signed code, chained-fixup
    format 12, and the signed-difference-table jump table."""
    BINARY = os.path.join(_FIXTURE_DIR, "testnde_e")
    TABLE_ENTRY_SIZE = 4


_F27_DIR = os.path.join(
    os.path.dirname(__file__), "synthetic_fixtures", "f27_compare_tree_engine_no_guard")


class _GuardlessEngineChecks:
    """Ground truth on the f27 binary (source: fixture.m).  The premise of the
    fixture — TestGrContainer's engine has a compare tree and NO range guard —
    and the two facts the ownership check rests on: the engine loads its OWN
    class's ivar-offset variables, and nobody else's."""

    BINARY = None

    @classmethod
    def setUpClass(cls):
        if not os.path.exists(cls.BINARY):
            raise unittest.SkipTest(
                f"{cls.BINARY} not built — run tests/synthetic_fixtures/"
                "build_fixtures.sh f27_compare_tree_engine_no_guard")
        with open(cls.BINARY, "rb") as fh:
            data = load_macho_slice(fh.read())
        cls.ctx = BinaryContext(data)
        st = build_string_table(cls.ctx)
        cls.cl = build_class_list(cls.ctx, st)
        cls.core_index = _build_readfrom_core_index(cls.ctx, cls.cl)
        syms = _symbol_addrs(cls.ctx)
        cls.engine = syms["_TestGrEngine"]
        cls.plain_engine = syms["_TestGrPlainEngine"]

    def _slots(self, class_name):
        return frozenset(iv.offset_slot for iv in self.cl.find(class_name).ivars)

    def test_engine_has_no_range_guard_but_is_a_real_dispatcher(self):
        self.assertEqual(_find_field_count(self.ctx, self.engine), 0)
        self.assertTrue(_core_resolves_compare_chain(
            self.ctx, self.engine, self.core_index))

    def test_engine_loads_exactly_its_own_classs_ivar_slots(self):
        loaded = {slot for _i, slot in
                  ivar_slot_loads(_core_insns(self.ctx, self.engine))}
        self.assertEqual(loaded, set(self._slots("TestGrContainer")))
        self.assertFalse(loaded & self._slots("TestGrPlainCall"))
        self.assertFalse(loaded & self._slots("TestGrForeignEngine"))

    def test_ownership_is_true_for_the_owner_only(self):
        for cls, want in (("TestGrContainer", True), ("TestGrPlainCall", False),
                          ("TestGrForeignEngine", False)):
            self.assertEqual(
                _core_loads_own_ivar_slot(self.ctx, self.engine, self._slots(cls)),
                want, cls)

    def test_plain_engine_belongs_to_the_plain_class(self):
        self.assertTrue(_core_loads_own_ivar_slot(
            self.ctx, self.plain_engine, self._slots("TestGrPlainCall")))
        self.assertFalse(_core_loads_own_ivar_slot(
            self.ctx, self.plain_engine, self._slots("TestGrContainer")))


class TestGuardlessEngineFixture(_GuardlessEngineChecks, unittest.TestCase):
    BINARY = os.path.join(_F27_DIR, "testgr")


class TestGuardlessEngineFixtureArm64e(_GuardlessEngineChecks, unittest.TestCase):
    BINARY = os.path.join(_F27_DIR, "testgr_e")


if __name__ == "__main__":
    unittest.main()
