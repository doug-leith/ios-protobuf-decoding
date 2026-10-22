"""Synthetic ground-truth test for proto.enums's shared-cache methname-scan
fallback (``_collect_enum_definitions``'s Phase 1, and the ``_enum_name_from_methname``
helper it calls) — the ONE code path structurally unreachable by every fixture in
tests/synthetic_fixtures/, because Phase 1 only runs when ``instance_method_names``
is empty (see proto/extractor.py: it's set to ``set()`` only when neither
``readFrom:`` nor ``writeTo:`` resolves by name — the real shared-cache / --cache
scenario), and every synthetic fixture is a standalone-compiled binary whose class
methods DO resolve by name, so ``instance_method_names`` is always non-empty for
them and Phase 1 never fires through the normal test_synthetic_fixtures.py path.

Rather than build a new binary, this reuses f11_enum_pointer_table/testenum (real
xAsString: method, real __objc_methname selector strings — the only inputs Phase 1
actually reads) and calls proto.enums._collect_enum_definitions directly with
``instance_method_names=set()`` passed explicitly, exactly mirroring what
extract_proto_message computes for a genuine cache-native class. Everything else
(ctx, st, cls) is the real, already-verified f11 binary — so this is still a
ground-truth check, not a mock: the expected ENUM: tag and full 3-value table come
straight from f11_enum_pointer_table/expected.py.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

from macho.memory import BinaryContext
from macho.strings import build_string_table
from macho.classlist import build_class_list
from serializers.swift_descriptor_extract import load_macho_slice
from proto.models import ProtoField, FieldLabel
from proto.enums import _collect_enum_definitions, _enum_name_from_methname

_FIXTURE_DIR = os.path.join(
    os.path.dirname(__file__), "synthetic_fixtures", "f11_enum_pointer_table")
_BINARY = os.path.join(_FIXTURE_DIR, "testenum")


class TestEnumMethnameFallback(unittest.TestCase):
    """Phase 1 of _collect_enum_definitions: the no-cache-hit (empty
    instance_method_names) __objc_methname scan."""

    @classmethod
    def setUpClass(cls):
        if not os.path.exists(_BINARY):
            raise unittest.SkipTest(
                "binary not built — run tests/synthetic_fixtures/build_fixtures.sh "
                "f11_enum_pointer_table")
        with open(_BINARY, "rb") as fh:
            data = load_macho_slice(fh.read())
        cls.ctx = BinaryContext(data)
        cls.st = build_string_table(cls.ctx)
        cl = build_class_list(cls.ctx, cls.st)
        cls.cls_status = cl.find("TestEnumStatus")
        assert cls.cls_status is not None, "TestEnumStatus not found in classlist"

    def test_enum_name_from_methname_direct(self):
        """The pure helper: 'status' -> 'statusAsString:' is a real selector in
        this binary's __objc_methname, so the derived enum name is 'Status'."""
        name = _enum_name_from_methname("status", self.st)
        self.assertEqual(name, "Status")

    def test_enum_name_from_methname_no_selector(self):
        """A field name with no matching xAsString:/StringAsX: selector anywhere
        in __objc_methname returns None (genuinely absent, not a lookup bug)."""
        name = _enum_name_from_methname("thisFieldDoesNotExistAnywhere", self.st)
        self.assertIsNone(name)

    def test_phase1_tags_and_recovers_via_cache_path(self):
        """End-to-end: with instance_method_names forced empty (the real
        --cache / shared-cache scenario), Phase 1 must discover the ENUM: tag
        from __objc_methname alone, and Phase 2 must then recover the full
        value table via cls.get_method (which still resolves by name on this
        standalone binary, exactly as it would on a resolved --cache run)."""
        fld = ProtoField(name="status", number=7, type_name="int32",
                         label=FieldLabel.OPTIONAL)
        enums = _collect_enum_definitions(
            self.ctx, self.cls_status, [fld], self.st,
            instance_method_names=set(),   # forces the Phase-1 fallback path
            metaclass=None,
        )
        self.assertEqual(fld.type_class, "ENUM:TestEnumStatus")
        self.assertEqual(fld.type_name, "TestEnumStatus")
        self.assertEqual(len(enums), 1)
        enum = enums[0]
        self.assertEqual(enum.name, "TestEnumStatus")
        self.assertEqual(
            [(v.number, v.name) for v in enum.values],
            [(0, "TEST_ENUM_STATUS_UNKNOWN"),
             (1, "TEST_ENUM_STATUS_OK"),
             (2, "TEST_ENUM_STATUS_FAIL")])
        self.assertTrue(enum.values_confirmed)
        self.assertFalse(enum.values_truncated)


if __name__ == "__main__":
    unittest.main()
