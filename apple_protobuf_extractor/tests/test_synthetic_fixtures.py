"""Synthetic ground-truth regression suite.

Unlike every other test in this repo, these fixtures are NOT derived from real
Apple binaries — there is no independent ground truth to check the extractor's
core claims against (recovered field names/numbers, the true semantic
type of a length-delimited field: string vs message vs bytes, which
concrete class a repeated message field's elements are, and an enum field's
recovered value table: names and numbers). ``protoc
--decode_raw`` only verifies wire-type-level decoding; it says nothing about
whether the tool's SCHEMA recovery is correct.

So each fixture here is a tiny, genuinely-compiled ObjC PBCodable-shaped
Mach-O binary (real clang, real arm64 instructions — see build_fixtures.sh)
whose schema is known EXACTLY because we wrote it. The oracle in each
fixture's ``expected.py`` documents the schema the source was authored to
express, not a snapshot of current tool output — a failing assertion here
means the tool is objectively wrong, not just "changed" (contrast with
test_golden_output.py, which is regression-only against real, un-verifiable
binaries).

See tests/synthetic_fixtures/README.md for the methodology and the gotchas
involved in writing a new fixture (compiler flags, calling convention, the
venv/capstone requirement, etc).
"""
import importlib.util
import os
import unittest

from macho.memory import BinaryContext
from macho.strings import build_string_table
from macho.classlist import build_class_list
from serializers.swift_descriptor_extract import load_macho_slice
from proto.extractor import extract_all

_FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "synthetic_fixtures")

# (fixture dir name, compiled binary filename inside it)
_FIXTURES = [
    ("f1_writeto_fieldnum", "testmsg"),
    ("f2_readfrom_element_type", "testrf"),
    ("f3_write_helper_family", "testwt"),
    ("f4_packed_repeated", "testpr"),
    ("f5_jumptable_dispatch", "testjt"),
    ("f6_geo_route_incident", "testri"),
    ("f7_geo_tf_road_speed", "testrs"),
    ("f8_geo_companion_drive_step", "testcds"),
    ("f9_clp_location", "testcl"),
    ("f10_geo_log_message", "testlm"),
    ("f11_enum_pointer_table", "testenum"),
    ("f12_repeated_metaclass_type", "testrmt"),
    ("f13_writeto_accessor_sourced", "testgac"),
    ("f14_repeated_suffix_ambiguity", "testrsa"),
    ("f15_opaque_passthrough", "testop"),
    ("f16_enum_isolated_compares", "testeic"),
    ("f17_repeated_adder_ivar_lever", "testrail"),
    ("f18_enum_multi_segment", "testems"),
    ("f19_enum_dictrep_switch", "testeds"),
    ("f20_dispatch_wrapper_core_picker", "testdwp"),
    ("f21_enum_long_body_extent", "testlbe"),
    ("f22_writeto_forward_array_load", "testfwd"),
    ("f23_writeto_hoisted_value", "testhoist"),
    ("f28_enum_dictrep_biased", "testbiased"),
    ("f24_enum_dictrep_hybrid", "testedh"),
    ("f25_enum_large_bias", "testelb"),
    ("f24_dictrep_compare_chain", "testdcc"),
    ("f25_newer_dispatch_engine", "testnde"),
    # arm64e builds of the same sources (PAC code, chained-fixup format 12) —
    # checked against the SAME expected.py as their arm64 twins.
    ("f24_dictrep_compare_chain", "testdcc_e"),
    ("f25_newer_dispatch_engine", "testnde_e"),
    ("f27_compare_tree_engine_no_guard", "testgr"),
    ("f27_compare_tree_engine_no_guard", "testgr_e"),
]


def _load_expected(fixture_dir):
    path = os.path.join(_FIXTURES_DIR, fixture_dir, "expected.py")
    spec = importlib.util.spec_from_file_location(
        f"synthetic_fixtures_expected_{fixture_dir}", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.EXPECTED


def _extract(binary_path):
    with open(binary_path, "rb") as fh:
        data = load_macho_slice(fh.read())
    ctx = BinaryContext(data)
    st = build_string_table(ctx)
    cl = build_class_list(ctx, st)
    return {m.name: m for m in extract_all(ctx, st, cl)}


class TestSyntheticFixtures(unittest.TestCase):
    """One generated test method per fixture (see bottom of module)."""

    def _check(self, fixture_dir, binary_name):
        binary_path = os.path.join(_FIXTURES_DIR, fixture_dir, binary_name)
        if not os.path.exists(binary_path):
            self.skipTest(
                f"{fixture_dir}: binary not built — run "
                f"tests/synthetic_fixtures/build_fixtures.sh {fixture_dir}"
            )
        expected = _load_expected(fixture_dir)
        messages = _extract(binary_path)

        missing = set(expected) - set(messages)
        extra = set(messages) - set(expected)
        self.assertFalse(
            missing, f"{fixture_dir}: expected message(s) not extracted: {missing}")
        self.assertFalse(
            extra, f"{fixture_dir}: unexpected extra message(s): {extra}")

        for msg_name, spec in expected.items():
            msg = messages[msg_name]

            if "opaque_passthrough" in spec:
                self.assertEqual(
                    msg.opaque_passthrough, spec["opaque_passthrough"],
                    f"{fixture_dir}.{msg_name}: opaque_passthrough")

            got_fields = {f.name: f for f in msg.fields}
            want_fields = {f["name"]: f for f in spec["fields"]}

            missing_f = set(want_fields) - set(got_fields)
            extra_f = set(got_fields) - set(want_fields)
            self.assertFalse(
                missing_f, f"{fixture_dir}.{msg_name}: missing field(s): {missing_f}")
            self.assertFalse(
                extra_f, f"{fixture_dir}.{msg_name}: unexpected field(s): {extra_f}")

            for fname, want in want_fields.items():
                got = got_fields[fname]
                self.assertEqual(
                    got.number, want["number"],
                    f"{fixture_dir}.{msg_name}.{fname}: field number")
                self.assertEqual(
                    got.type_name, want["type_name"],
                    f"{fixture_dir}.{msg_name}.{fname}: type_name")
                self.assertEqual(
                    got.label.value, want["label"],
                    f"{fixture_dir}.{msg_name}.{fname}: label")
                self.assertEqual(
                    got.number_confirmed, want.get("number_confirmed", True),
                    f"{fixture_dir}.{msg_name}.{fname}: number_confirmed "
                    "(a synthetic fixture should never fall back to an estimate)")
                if "type_class" in want:
                    self.assertEqual(
                        got.type_class, want["type_class"],
                        f"{fixture_dir}.{msg_name}.{fname}: type_class")

            # ── Enum value-table checks (optional: only fixtures with an
            # ENUM:-tagged field carry an "enums" key) ──────────────────────
            want_enums = spec.get("enums")
            if want_enums is not None:
                got_enums = {e.name: e for e in msg.enums}
                missing_e = set(want_enums) - set(got_enums)
                extra_e = set(got_enums) - set(want_enums)
                self.assertFalse(
                    missing_e,
                    f"{fixture_dir}.{msg_name}: missing enum(s): {missing_e}")
                self.assertFalse(
                    extra_e,
                    f"{fixture_dir}.{msg_name}: unexpected extra enum(s): {extra_e}")

                for ename, ewant in want_enums.items():
                    egot = got_enums[ename]
                    self.assertEqual(
                        [(v.number, v.name) for v in egot.values],
                        ewant["values"],
                        f"{fixture_dir}.{msg_name}.<enum:{ename}>: values")
                    self.assertEqual(
                        egot.values_confirmed, ewant.get("values_confirmed", True),
                        f"{fixture_dir}.{msg_name}.<enum:{ename}>: values_confirmed")
                    self.assertEqual(
                        egot.values_truncated, ewant.get("values_truncated", False),
                        f"{fixture_dir}.{msg_name}.<enum:{ename}>: values_truncated")


def _make_test(fixture_dir, binary_name):
    def test(self):
        self._check(fixture_dir, binary_name)
    suffix = "_arm64e" if binary_name.endswith("_e") else ""
    test.__name__ = f"test_{fixture_dir}{suffix}"
    test.__doc__ = f"Extractor output for synthetic_fixtures/{fixture_dir} matches expected.py"
    return test


for _fixture_dir, _binary_name in _FIXTURES:
    _t = _make_test(_fixture_dir, _binary_name)
    setattr(TestSyntheticFixtures, _t.__name__, _t)


if __name__ == "__main__":
    unittest.main()
