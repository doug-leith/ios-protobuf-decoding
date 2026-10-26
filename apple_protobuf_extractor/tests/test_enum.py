"""
proto/test_enum.py — Tests for enum detection, extraction, and emission.

Coverage:
  - _enum_prefix: CamelCase → SCREAMING_SNAKE_CASE conversion
  - _normalize_enum_value_name: raw binary string → canonical proto name
  - _is_valid_enum_string: identifier validation
  - ProtoEnum.to_proto(): with values, without values, proto3 compliance
  - _type_from_enc: AsString / StringAs patterns → ENUM: sentinel
  - extract_proto_message: enum fields collected into ProtoMessage.enums
  - resolve_type_refs: ENUM: sentinel fields left untouched
  - _compute_imports: ENUM: sentinel fields generate no imports
  - ProtoFile._resolve_field_type: enum fields not cross-package qualified
  - ProtoFile._collect_enums: deduplication logic
  - ProtoFile.emit(): enum blocks appear before message blocks
  - extraction_stats: "enums" key present and correct
  - print_summary: enum row present
  - End-to-end: message with enum field → complete valid proto3 output
"""

from __future__ import annotations

import io
import tempfile
import unittest
from pathlib import Path

# proto/ resolves via the apple_protobuf_extractor editable install; the repo root is on
# sys.path via the root conftest.py.  No per-file path juggling.

from proto.models import (
    FieldLabel, ProtoField, ProtoMessage,
    ProtoEnum, ProtoEnumValue, _enum_prefix,
)
from proto.protocore import _type_from_enc
from proto.enums import _is_valid_enum_string, _normalize_enum_value_name
from macho.strings import read_cfstring_text
from proto.emitter import (
    ProtoFile,
    _compute_imports,
    build_proto_files,
    extraction_stats,
    print_summary,
    resolve_type_refs,
    write_from_messages,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

def _enum_field(
    name: str,
    number: int,
    enum_name: str,
    confirmed: bool = True,
) -> ProtoField:
    return ProtoField(
        name=name,
        number=number,
        type_name=enum_name,
        label=FieldLabel.OPTIONAL,
        type_class=f"ENUM:{enum_name}",
        number_confirmed=confirmed,
    )


def _proto_enum(name: str, values: list[tuple[int, str]] | None = None,
                confirmed: bool = False) -> ProtoEnum:
    if values is None:
        return ProtoEnum(name=name, values=[], values_confirmed=False)
    return ProtoEnum(
        name=name,
        values=[ProtoEnumValue(name=v, number=n) for n, v in values],
        values_confirmed=confirmed,
    )


def _msg(name: str, class_name: str | None = None,
         fields: list | None = None, enums: list | None = None) -> ProtoMessage:
    return ProtoMessage(
        name=name,
        class_name=class_name or f"GEO{name}",
        fields=fields or [],
        enums=enums or [],
    )


# ── TestEnumPrefix ────────────────────────────────────────────────────────────

class TestEnumPrefix(unittest.TestCase):

    def test_simple_camel(self):
        self.assertEqual(_enum_prefix("FeedbackType"), "FEEDBACK_TYPE")

    def test_two_word(self):
        self.assertEqual(_enum_prefix("RouteRequest"), "ROUTE_REQUEST")

    def test_acronym_prefix(self):
        self.assertEqual(_enum_prefix("HTTPMethod"), "HTTP_METHOD")

    def test_ap_prefix(self):
        self.assertEqual(_enum_prefix("APSession"), "AP_SESSION")

    def test_single_word(self):
        self.assertEqual(_enum_prefix("Status"), "STATUS")

    def test_already_upper(self):
        self.assertEqual(_enum_prefix("TYPE"), "TYPE")

    def test_three_words(self):
        self.assertEqual(_enum_prefix("DirectionsRequestType"), "DIRECTIONS_REQUEST_TYPE")

    def test_geo_stripped_name(self):
        # Proto names come with ObjC prefix stripped
        self.assertEqual(_enum_prefix("PDComponentType"), "PD_COMPONENT_TYPE")


# ── TestNormalizeEnumValueName ─────────────────────────────────────────────────

class TestNormalizeEnumValueName(unittest.TestCase):

    def _n(self, enum_name, raw):
        return _normalize_enum_value_name(enum_name, raw)

    def test_simple_upcase(self):
        self.assertEqual(self._n("FeedbackType", "UNKNOWN"),
                         "FEEDBACK_TYPE_UNKNOWN")

    def test_positive(self):
        self.assertEqual(self._n("FeedbackType", "POSITIVE"),
                         "FEEDBACK_TYPE_POSITIVE")

    def test_already_prefixed(self):
        self.assertEqual(self._n("FeedbackType", "FEEDBACK_TYPE_UNKNOWN"),
                         "FEEDBACK_TYPE_UNKNOWN")

    def test_camel_case_raw(self):
        # "FeedbackType_Unknown" → "FEEDBACK_TYPE_UNKNOWN"
        self.assertEqual(self._n("FeedbackType", "FeedbackType_Unknown"),
                         "FEEDBACK_TYPE_UNKNOWN")

    def test_lowercase_raw(self):
        self.assertEqual(self._n("Status", "ok"), "STATUS_OK")

    def test_hyphenated_raw(self):
        self.assertEqual(self._n("Status", "not-found"), "STATUS_NOT_FOUND")

    def test_single_letter_enum(self):
        result = self._n("Type", "X")
        self.assertTrue(result.startswith("TYPE_"))

    def test_empty_prefix_case(self):
        """Ensure no double underscore when raw starts with prefix."""
        result = self._n("RouteType", "ROUTE_TYPE_DIRECT")
        self.assertEqual(result, "ROUTE_TYPE_DIRECT")
        self.assertNotIn("__", result)

    def test_screaming_snake_raw_keeps_digit_letter_words(self):
        # GeoServices value strings: case is not a word boundary in an all-caps string
        self.assertEqual(self._n("UseEventType", "PUNCH_IN_3RD_PARTY"),
                         "USE_EVENT_TYPE_PUNCH_IN_3RD_PARTY")
        self.assertEqual(self._n("Action", "MAP_3D_OFF"), "ACTION_MAP_3D_OFF")
        self.assertEqual(self._n("Hypothesis", "EARLIER_THAN_7M"),
                         "HYPOTHESIS_EARLIER_THAN_7M")
        self.assertEqual(self._n("ResourceFilterScale", "RESOURCE_FILTER_SCALE_1X"),
                         "RESOURCE_FILTER_SCALE_1X")

    def test_camel_case_raw_with_digits_still_splits(self):
        self.assertEqual(self._n("Status", "notFound2Times"), "STATUS_NOT_FOUND2_TIMES")

    def test_convention_is_decided_per_table(self):
        # CoreLocationProtobuf magnetic calibration: "_3D" sits in a camelCase table
        from proto.enums import _enum_values_from_pairs
        names = [v.name for v in _enum_values_from_pairs(
            "Calibration", [(3, "_3DWeak"), (4, "_3D"), (5, "_3DStrong")])]
        self.assertEqual(names, ["CALIBRATION_3_D_WEAK", "CALIBRATION_3_D",
                                 "CALIBRATION_3_D_STRONG"])
        names = [v.name for v in _enum_values_from_pairs(
            "Action", [(17048, "MAP_3D_OFF"), (17049, "MAP_3D_ON")])]
        self.assertEqual(names, ["ACTION_MAP_3D_OFF", "ACTION_MAP_3D_ON"])


# ── TestIsValidEnumString ─────────────────────────────────────────────────────

class TestIsValidEnumString(unittest.TestCase):

    def test_simple_upper(self):
        self.assertTrue(_is_valid_enum_string("UNKNOWN"))

    def test_lower(self):
        self.assertTrue(_is_valid_enum_string("unknown"))

    def test_with_underscore(self):
        self.assertTrue(_is_valid_enum_string("FEEDBACK_TYPE_UNKNOWN"))

    def test_empty_string(self):
        self.assertFalse(_is_valid_enum_string(""))

    def test_none_like_empty(self):
        self.assertFalse(_is_valid_enum_string(""))

    def test_long_identifier_ok(self):
        # (iOS 27 GeoServices: 98 characters; the identifier is the test, not a length)
        self.assertTrue(_is_valid_enum_string(
            "ALERT_TYPE_LAST_CHANCE_TO_SUGGEST_DIFFERENT_ROUTE_WITH_SAME_NUM_STOPS_FOR_EV_"
            "INFEASIBLE_US" + "E" * 60))

    def test_starts_with_digit(self):
        self.assertFalse(_is_valid_enum_string("1INVALID"))

    def test_space(self):
        self.assertFalse(_is_valid_enum_string("INVALID VALUE"))

    def test_dot(self):
        self.assertFalse(_is_valid_enum_string("INVALID.VALUE"))

    def test_leading_underscore_ok(self):
        self.assertTrue(_is_valid_enum_string("_PRIVATE"))


# ── TestReadCfstringTextLayouts ───────────────────────────────────────────────

class TestReadCfstringTextLayouts(unittest.TestCase):
    """`read_cfstring_text` (which reads enum value strings) must decode CFStringRef
    constant-string structs in BOTH section layouts and via the context's pointer
    decoder:

      • `__DATA_CONST/__cfstring` — shared-cache-extracted dylibs (GeoServices).
      • `__DATA/__cfstring`       — standalone binaries (locationd).

    The struct's char* field (offset +16) is decoded through `ctx.read_ptr`
    (chained-fixup / cache-mapping aware), NOT a hardcoded 36-bit cache tag mask.

    Regression: the old code only checked `__DATA_CONST/__cfstring` and masked
    the low 36 bits, so every standalone-binary enum (all 44 in locationd)
    silently reverted to a `// values not recovered` placeholder.
    """

    STRUCT_VA = 0x101bfbcf8     # the CFStringRef struct
    CHAR_VA   = 0x1017ba8ca     # the characters the struct +16 points to

    def _fake_ctx(self, *, cfstring_seg, plus16_raw, chars=b"kRadioAccessTechnologyGSM",
                  flags=0x7c8, count=None):
        struct_va, char_va = self.STRUCT_VA, self.CHAR_VA
        count = len(chars) if count is None else count

        class _Sec:
            vmaddr = struct_va
            vmsize = 0x1000

        class _Ctx:
            def has_section(self, seg, name):
                return seg == cfstring_seg and name == "__cfstring"

            def section(self, seg, name):
                return _Sec()

            def read_cstring(self, va, max_len=4096):
                raise ValueError(va)             # a CFString is read by its count

            def read_bytes(self, va, n):
                if va == char_va and n <= len(chars):
                    return chars[:n]
                raise ValueError(va)

            def read_u32(self, va):
                if va == struct_va + 8:
                    return flags
                raise ValueError(va)

            def is_variable(self, vmaddr):        # no program data, no binds
                return False

            def read_ptr(self, va):
                # Proper decode of the +16 char* field → the real char address,
                # regardless of the high tag bits in the raw word.
                if va == struct_va + 16:
                    return char_va
                raise ValueError(va)

            def read_u64(self, va):
                if va == struct_va + 16:
                    return plus16_raw
                if va == struct_va + 24:
                    return count
                raise ValueError(va)

        return _Ctx()

    def test_standalone_data_cfstring_resolved_via_read_ptr(self):
        # Tagged raw word a 36-bit mask would corrupt; read_ptr returns the truth.
        ctx = self._fake_ctx(cfstring_seg="__DATA", plus16_raw=0x200000017ba8ca)
        self.assertEqual(read_cfstring_text(ctx, self.STRUCT_VA),
                         "kRadioAccessTechnologyGSM")

    def test_cache_data_const_cfstring_still_resolved(self):
        ctx = self._fake_ctx(cfstring_seg="__DATA_CONST", plus16_raw=0x4018d88981a)
        self.assertEqual(read_cfstring_text(ctx, self.STRUCT_VA),
                         "kRadioAccessTechnologyGSM")

    def test_pointer_outside_cfstring_section_returns_none(self):
        ctx = self._fake_ctx(cfstring_seg="__DATA", plus16_raw=0x200000017ba8ca)
        self.assertIsNone(read_cfstring_text(ctx, 0x900000))

    def test_the_count_is_read_not_a_terminator_within_128_bytes(self):
        # (An SQL statement of AppPredictionInternal's, 227 bytes, read as None.)
        text = "INSERT INTO t (" + "c, " * 80 + "d) VALUES (?)"
        ctx = self._fake_ctx(cfstring_seg="__DATA", plus16_raw=0, chars=text.encode(),
                             count=len(text))
        self.assertEqual(read_cfstring_text(ctx, self.STRUCT_VA), text)

    def test_a_unicode_cfstring_is_utf16(self):
        # (flags 0x7d0: GeoServices' "p:[%u:%u] (%f,%f)±(%f,%f)", read as "p" as a C string)
        text = "p:[%u:%u] (%f,%f)±(%f,%f)"
        ctx = self._fake_ctx(cfstring_seg="__DATA", plus16_raw=0, flags=0x7d0,
                             chars=text.encode("utf-16-le"), count=len(text))
        self.assertEqual(read_cfstring_text(ctx, self.STRUCT_VA), text)

    def test_an_empty_cfstring_is_empty(self):
        ctx = self._fake_ctx(cfstring_seg="__DATA", plus16_raw=0, chars=b"", count=0)
        self.assertEqual(read_cfstring_text(ctx, self.STRUCT_VA), "")


# ── TestProtoEnumModel ────────────────────────────────────────────────────────

class TestProtoEnumModel(unittest.TestCase):

    def test_empty_enum_has_placeholder(self):
        e = ProtoEnum("FeedbackType", [], values_confirmed=False)
        out = e.to_proto()
        self.assertIn("enum FeedbackType {", out)
        self.assertIn("FEEDBACK_TYPE_UNKNOWN = 0;", out)
        self.assertIn("values not recovered", out)

    def test_enum_with_values(self):
        e = ProtoEnum("Status", [
            ProtoEnumValue("STATUS_UNKNOWN", 0),
            ProtoEnumValue("STATUS_OK", 1),
            ProtoEnumValue("STATUS_ERROR", 2),
        ], values_confirmed=True)
        out = e.to_proto()
        self.assertIn("enum Status {", out)
        self.assertIn("STATUS_UNKNOWN = 0;", out)
        self.assertIn("STATUS_OK = 1;", out)
        self.assertIn("STATUS_ERROR = 2;", out)
        self.assertNotIn("not recovered", out)

    def test_values_sorted_by_number(self):
        e = ProtoEnum("Type", [
            ProtoEnumValue("TYPE_B", 2),
            ProtoEnumValue("TYPE_A", 1),
            ProtoEnumValue("TYPE_UNKNOWN", 0),
        ])
        out = e.to_proto()
        pos_unknown = out.index("TYPE_UNKNOWN")
        pos_a = out.index("TYPE_A")
        pos_b = out.index("TYPE_B")
        self.assertLess(pos_unknown, pos_a)
        self.assertLess(pos_a, pos_b)

    def test_closing_brace(self):
        e = ProtoEnum("Foo", [])
        self.assertTrue(e.to_proto().endswith("}"))

    def test_repr_confirmed(self):
        e = ProtoEnum("Foo", [ProtoEnumValue("FOO_X", 0)], values_confirmed=True)
        self.assertIn("✓", repr(e))

    def test_repr_unconfirmed(self):
        e = ProtoEnum("Foo", [])
        self.assertIn("~", repr(e))

    def test_truncated_enum_emits_incomplete_warning(self):
        # An enum whose value-string method was read only in part must be flagged so the
        # user knows the value set may be incomplete.
        e = ProtoEnum("MotionType", [
            ProtoEnumValue("MOTION_TYPE_UNKNOWN", 0),
            ProtoEnumValue("MOTION_TYPE_WALK", 1),
        ], values_confirmed=False, values_truncated=True)
        out = e.to_proto()
        self.assertIn("INCOMPLETE", out)
        self.assertIn("read only in part", out)
        # The comment sits ABOVE the enum block (a leading // line).
        self.assertLess(out.index("INCOMPLETE"), out.index("enum MotionType {"))
        # The values themselves are still emitted normally.
        self.assertIn("MOTION_TYPE_WALK = 1;", out)

    def test_non_truncated_enum_has_no_warning(self):
        e = ProtoEnum("Status", [
            ProtoEnumValue("STATUS_OK", 0),
        ], values_truncated=False)
        self.assertNotIn("INCOMPLETE", e.to_proto())

    def test_repr_truncated_marker(self):
        e = ProtoEnum("Foo", [ProtoEnumValue("FOO_X", 0)], values_truncated=True)
        self.assertIn("…", repr(e))


# ── TestTypeFromEncEnum ───────────────────────────────────────────────────────

class TestTypeFromEncEnum(unittest.TestCase):
    """Tests for _type_from_enc returning the ENUM: sentinel."""

    def _t(self, type_enc, ivar_name="_x", methods=None):
        return _type_from_enc(type_enc, ivar_name, set(methods or []))

    def test_as_string_returns_enum_sentinel(self):
        name, cls = self._t('i', '_feedbackType',
                             methods=['feedbackTypeAsString:'])
        self.assertEqual(name, 'FeedbackType')
        self.assertEqual(cls, 'ENUM:FeedbackType')

    def test_string_as_pattern_returns_enum_sentinel(self):
        name, cls = self._t('i', '_routeType',
                             methods=['StringAsRouteType:'])
        self.assertEqual(name, 'RouteType')
        self.assertEqual(cls, 'ENUM:RouteType')

    def test_both_patterns_together(self):
        name, cls = self._t('i', '_status',
                             methods=['statusAsString:', 'StringAsStatus:'])
        self.assertEqual(name, 'Status')
        self.assertEqual(cls, 'ENUM:Status')

    def test_no_as_string_is_plain_int32(self):
        name, cls = self._t('i', '_count')
        self.assertEqual(name, 'int32')
        self.assertIsNone(cls)

    def test_uint_with_as_string(self):
        name, cls = self._t('I', '_mode', methods=['modeAsString:'])
        self.assertEqual(name, 'Mode')
        self.assertEqual(cls, 'ENUM:Mode')

    def test_leading_underscore_stripped_for_enum_name(self):
        # ivar "_type" → pname "type" → enum name "Type"
        name, cls = self._t('i', '_type', methods=['typeAsString:'])
        self.assertEqual(name, 'Type')
        self.assertEqual(cls, 'ENUM:Type')

    def test_no_method_names_no_enum(self):
        name, cls = self._t('i', '_feedbackType', methods=[])
        self.assertEqual(name, 'int32')
        self.assertIsNone(cls)

    def test_bool_not_affected_by_as_string(self):
        # 'B' (bool) is not in _SCALAR_ENC that maps to int32/uint32;
        # it is, but AsString: check only applies if type IS a scalar enc
        name, cls = self._t('B', '_enabled', methods=['enabledAsString:'])
        # 'B' maps to 'bool', AsString triggers enum detection
        self.assertEqual(cls, 'ENUM:Enabled')

    def test_object_type_not_affected(self):
        name, cls = self._t('@"GEOLocation"', '_location',
                             methods=['locationAsString:'])
        # Object types don't trigger the AsString path
        self.assertEqual(name, 'GEOLocation')
        self.assertEqual(cls, 'GEOLocation')


# ── TestEnumInExtractProtoMessage ─────────────────────────────────────────────

class TestEnumInExtractProtoMessage(unittest.TestCase):
    """
    Synthetic tests for enum collection inside extract_proto_message.

    We use the public extract_proto_message() with a BinaryContext that has
    no real binary data — only enough to satisfy the type-classification path
    (no binary analysis needed for the purely ObjC-metadata tests).
    """

    def _build_ctx(self):
        """Build a minimal valid BinaryContext (no real code needed)."""
        from tests.conftest import build_text_binary
        return build_text_binary(b'\xc0\x03\x5f\xd6' * 4)  # four RETs

    def test_enum_field_populates_message_enums(self):
        """A class with an AsString method → ProtoMessage.enums has one entry."""
        from macho.memory    import BinaryContext
        from macho.strings   import StringTable
        from macho.classlist import ObjcClass, ObjcIvar, ObjcMethod, ClassList
        from proto.extractor import extract_proto_message

        # Build a synthetic ObjcClass with a flags ivar + feedbackType ivar
        # and feedbackTypeAsString: method
        flags_ivar = ObjcIvar(
            name='_flags',
            type_enc='{?="has_feedbackType"b1}',
            offset=8, size=4,
        )
        fb_ivar = ObjcIvar(
            name='_feedbackType',
            type_enc='i',
            offset=16, size=4,
        )
        methods = [
            ObjcMethod(name='readFrom:',    types='', imp=0, is_relative=False),
            ObjcMethod(name='writeTo:',     types='', imp=0, is_relative=False),
            ObjcMethod(name='mergeFrom:',   types='', imp=0, is_relative=False),
            ObjcMethod(name='copyTo:',      types='', imp=0, is_relative=False),
            ObjcMethod(name='copyWithZone:', types='', imp=0, is_relative=False),
            ObjcMethod(name='isEqual:',     types='', imp=0, is_relative=False),
            ObjcMethod(name='hash',         types='', imp=0, is_relative=False),
            ObjcMethod(name='description',  types='', imp=0, is_relative=False),
            ObjcMethod(name='dictionaryRepresentation', types='', imp=0, is_relative=False),
            # real field methods
            ObjcMethod(name='feedbackType',           types='', imp=0, is_relative=False),
            ObjcMethod(name='setFeedbackType:',       types='', imp=0, is_relative=False),
            ObjcMethod(name='feedbackTypeAsString:',  types='', imp=0, is_relative=False),
        ]
        cls = ObjcClass(
            vmaddr=0x100001000,
            name='GEODirectionsRequestFeedback',
            is_meta=False,
            superclass_vmaddr=0,
            superclass_name='NSObject',
            ro_flags=0,
            instance_size=32,
            methods=methods,
            ivars=[flags_ivar, fb_ivar],
        )

        ctx = BinaryContext(self._build_ctx())
        st  = StringTable()
        cl  = ClassList([cls])

        msg = extract_proto_message(ctx, st, cl, cls)
        self.assertIsNotNone(msg)
        self.assertEqual(len(msg.enums), 1)
        enum = msg.enums[0]
        # Class GEODirectionsRequestFeedback → proto "DirectionsRequestFeedback"
        # Ivar _feedbackType → base "FeedbackType"
        # _qualify_enum_name strips the overlapping "Feedback" word:
        #   "DirectionsRequest" + "FeedbackType" → "DirectionsRequestFeedbackType"
        # (In a real binary _enum_name_from_pairs would further override to the
        # binary-confirmed "FeedbackType" once value strings are available.)
        self.assertEqual(enum.name, 'DirectionsRequestFeedbackType')

    def test_non_enum_field_produces_no_enums(self):
        """A class with plain int32 ivars (no AsString) → empty enums list."""
        from macho.memory    import BinaryContext
        from macho.strings   import StringTable
        from macho.classlist import ObjcClass, ObjcIvar, ObjcMethod, ClassList
        from proto.extractor import extract_proto_message

        flags_ivar = ObjcIvar(
            name='_flags',
            type_enc='{?="has_distance"b1}',
            offset=8, size=4,
        )
        dist_ivar = ObjcIvar(
            name='_distance',
            type_enc='d',   # double — no AsString method
            offset=16, size=8,
        )
        methods = [
            ObjcMethod(name='readFrom:',  types='', imp=0, is_relative=False),
            ObjcMethod(name='writeTo:',   types='', imp=0, is_relative=False),
            ObjcMethod(name='mergeFrom:', types='', imp=0, is_relative=False),
            ObjcMethod(name='copyTo:',    types='', imp=0, is_relative=False),
            ObjcMethod(name='copyWithZone:', types='', imp=0, is_relative=False),
            ObjcMethod(name='isEqual:',   types='', imp=0, is_relative=False),
            ObjcMethod(name='hash',       types='', imp=0, is_relative=False),
            ObjcMethod(name='description', types='', imp=0, is_relative=False),
            ObjcMethod(name='dictionaryRepresentation', types='', imp=0, is_relative=False),
            ObjcMethod(name='distance',   types='', imp=0, is_relative=False),
            ObjcMethod(name='setDistance:', types='', imp=0, is_relative=False),
        ]
        cls = ObjcClass(
            vmaddr=0x100001000,
            name='GEORoute',
            is_meta=False,
            superclass_vmaddr=0,
            superclass_name='NSObject',
            ro_flags=0,
            instance_size=32,
            methods=methods,
            ivars=[flags_ivar, dist_ivar],
        )

        ctx = BinaryContext(self._build_ctx())
        st  = StringTable()
        cl  = ClassList([cls])

        msg = extract_proto_message(ctx, st, cl, cls)
        self.assertIsNotNone(msg)
        self.assertEqual(msg.enums, [])

    def test_enum_field_type_name_and_class(self):
        """The enum field itself has correct type_name and type_class."""
        from macho.memory    import BinaryContext
        from macho.strings   import StringTable
        from macho.classlist import ObjcClass, ObjcIvar, ObjcMethod, ClassList
        from proto.extractor import extract_proto_message

        flags_ivar = ObjcIvar(name='_flags',
                               type_enc='{?="has_status"b1}',
                               offset=8, size=4)
        status_ivar = ObjcIvar(name='_status', type_enc='i', offset=16, size=4)
        methods = [
            ObjcMethod(name='readFrom:',   types='', imp=0, is_relative=False),
            ObjcMethod(name='writeTo:',    types='', imp=0, is_relative=False),
            ObjcMethod(name='mergeFrom:',  types='', imp=0, is_relative=False),
            ObjcMethod(name='copyTo:',     types='', imp=0, is_relative=False),
            ObjcMethod(name='copyWithZone:', types='', imp=0, is_relative=False),
            ObjcMethod(name='isEqual:',    types='', imp=0, is_relative=False),
            ObjcMethod(name='hash',        types='', imp=0, is_relative=False),
            ObjcMethod(name='description', types='', imp=0, is_relative=False),
            ObjcMethod(name='dictionaryRepresentation', types='', imp=0, is_relative=False),
            ObjcMethod(name='status',        types='', imp=0, is_relative=False),
            ObjcMethod(name='setStatus:',    types='', imp=0, is_relative=False),
            ObjcMethod(name='statusAsString:', types='', imp=0, is_relative=False),
        ]
        cls = ObjcClass(
            vmaddr=0x100001000,
            name='GEORequest',
            is_meta=False,
            superclass_vmaddr=0,
            superclass_name='NSObject',
            ro_flags=0,
            instance_size=32,
            methods=methods,
            ivars=[flags_ivar, status_ivar],
        )
        ctx = BinaryContext(self._build_ctx())
        msg = extract_proto_message(ctx, StringTable(), ClassList([cls]), cls)
        self.assertIsNotNone(msg)
        status_field = next(f for f in msg.fields if f.name == 'status')
        # GEORequest → proto "Request"; _status → base "Status"
        # No word overlap → "RequestStatus"
        self.assertEqual(status_field.type_name, 'RequestStatus')
        self.assertEqual(status_field.type_class, 'ENUM:RequestStatus')

    def test_duplicate_enum_name_only_one_entry(self):
        """Two fields with the same enum name → only one ProtoEnum."""
        from macho.memory    import BinaryContext
        from macho.strings   import StringTable
        from macho.classlist import ObjcClass, ObjcIvar, ObjcMethod, ClassList
        from proto.extractor import extract_proto_message

        flags_ivar = ObjcIvar(name='_flags',
                               type_enc='{?="has_type"b1"has_subType"b1}',
                               offset=8, size=4)
        type_ivar    = ObjcIvar(name='_type',    type_enc='i', offset=16, size=4)
        subtype_ivar = ObjcIvar(name='_subType', type_enc='i', offset=20, size=4)
        base_methods = [
            ObjcMethod(name=sel, types='', imp=0, is_relative=False)
            for sel in ('readFrom:', 'writeTo:', 'mergeFrom:', 'copyTo:',
                        'copyWithZone:', 'isEqual:', 'hash',
                        'description', 'dictionaryRepresentation')
        ]
        extra_methods = [
            ObjcMethod(name='type',          types='', imp=0, is_relative=False),
            ObjcMethod(name='setType:',      types='', imp=0, is_relative=False),
            ObjcMethod(name='typeAsString:', types='', imp=0, is_relative=False),
            ObjcMethod(name='subType',       types='', imp=0, is_relative=False),
            ObjcMethod(name='setSubType:',   types='', imp=0, is_relative=False),
            # Note: subTypeAsString: is NOT present → _subType stays as int32
        ]
        cls = ObjcClass(
            vmaddr=0x100001000,
            name='GEOFoo',
            is_meta=False,
            superclass_vmaddr=0,
            superclass_name='NSObject',
            ro_flags=0,
            instance_size=32,
            methods=base_methods + extra_methods,
            ivars=[flags_ivar, type_ivar, subtype_ivar],
        )
        ctx = BinaryContext(self._build_ctx())
        msg = extract_proto_message(ctx, StringTable(), ClassList([cls]), cls)
        self.assertIsNotNone(msg)
        # Only _type has AsString → one enum
        enum_names = [e.name for e in msg.enums]
        self.assertEqual(len(enum_names), len(set(enum_names)),
                         "Duplicate enum name in ProtoMessage.enums")


# ── TestResolveTypeRefsEnum ───────────────────────────────────────────────────

class TestResolveTypeRefsEnum(unittest.TestCase):

    def test_enum_field_untouched_by_resolve(self):
        """resolve_type_refs must not mark ENUM: fields as unresolved."""
        fld = _enum_field("feedback_type", 1, "FeedbackType")
        msg = _msg("Foo", fields=[fld])
        resolve_type_refs([msg])
        self.assertEqual(fld.type_name, "FeedbackType")
        self.assertIsNone(fld.unresolved_type_class)

    def test_enum_field_type_class_unchanged(self):
        fld = _enum_field("status", 2, "Status")
        msg = _msg("Bar", fields=[fld])
        resolve_type_refs([msg])
        self.assertEqual(fld.type_class, "ENUM:Status")

    def test_mixed_message_enum_and_scalar(self):
        fld_enum   = _enum_field("kind", 1, "Kind")
        fld_scalar = ProtoField("dist", 2, "double", FieldLabel.OPTIONAL)
        msg = _msg("Mix", fields=[fld_enum, fld_scalar])
        resolve_type_refs([msg])
        self.assertEqual(fld_enum.type_name, "Kind")
        self.assertEqual(fld_scalar.type_name, "double")


# ── TestComputeImportsEnum ────────────────────────────────────────────────────

class TestComputeImportsEnum(unittest.TestCase):

    def test_enum_field_does_not_generate_import(self):
        fld = _enum_field("feedback_type", 1, "FeedbackType")
        geo_msg = _msg("Request", "GEORequest", fields=[fld])
        geo_pf  = ProtoFile("geo", "geo.proto", [geo_msg], [])
        _compute_imports([geo_pf], {"GEORequest": "geo"})
        self.assertEqual(geo_pf.imports, [])

    def test_message_field_still_generates_import(self):
        """Non-enum cross-package message fields still trigger imports."""
        msg_fld = ProtoField("loc", 1, "Location",
                             FieldLabel.OPTIONAL, type_class="CLPLocation")
        geo_msg = _msg("Request", "GEORequest", fields=[msg_fld])
        geo_pf  = ProtoFile("geo", "geo.proto", [geo_msg], [])
        clp_pf  = ProtoFile("clp", "clp.proto", [], [])
        _compute_imports([geo_pf, clp_pf], {"CLPLocation": "clp"})
        self.assertIn("clp.proto", geo_pf.imports)


# ── TestProtoFileEmitEnum ─────────────────────────────────────────────────────

class TestProtoFileEmitEnum(unittest.TestCase):

    def _pf(self, messages, package="geo") -> ProtoFile:
        pf = ProtoFile(package=package, filename=f"{package}.proto",
                       messages=messages, imports=[])
        return pf

    def test_enum_block_in_output(self):
        enum = _proto_enum("FeedbackType", [(0, "FEEDBACK_TYPE_UNKNOWN"),
                                             (1, "FEEDBACK_TYPE_POSITIVE")],
                            confirmed=True)
        msg  = _msg("Request", fields=[_enum_field("feedback_type", 1, "FeedbackType")],
                    enums=[enum])
        pf   = self._pf([msg])
        out  = pf.emit()
        self.assertIn("enum FeedbackType {", out)
        self.assertIn("FEEDBACK_TYPE_UNKNOWN = 0;", out)
        self.assertIn("FEEDBACK_TYPE_POSITIVE = 1;", out)

    def test_reconstructed_name_caveat_comment(self):
        """Each enum block carries the 'reconstructed name' caveat + doc ref,
        and the section header note is emitted once.  See ENUM_TYPE_NAMES.md."""
        enum = _proto_enum("MapsResultType",
                           [(0, "MAPS_RESULT_TYPE_UNKNOWN"),
                            (1, "MAPS_RESULT_TYPE_PLACE")], confirmed=True)
        msg  = _msg("Foo", fields=[_enum_field("result_type", 1, "MapsResultType")],
                    enums=[enum])
        out  = self._pf([msg]).emit()
        # One-time section header note.
        self.assertIn("RECONSTRUCTED", out)
        # Per-enum reminder, immediately above the enum block.
        self.assertIn("type name reconstructed from value-string prefix", out)
        self.assertIn("ENUM_TYPE_NAMES.md", out)
        note_pos = out.index("type name reconstructed from value-string prefix")
        enum_pos = out.index("enum MapsResultType {")
        self.assertLess(note_pos, enum_pos)

    def test_no_recon_caveat_when_no_enums(self):
        """The enum caveat text must not appear when the file has no enums.
        (Note: the unrelated package-reconstruction note may still appear.)"""
        msg = _msg("Foo", fields=[ProtoField("x", 1, "int32", FieldLabel.OPTIONAL)])
        out = self._pf([msg]).emit()
        self.assertNotIn("ENUM_TYPE_NAMES.md", out)
        self.assertNotIn("type name reconstructed from value-string prefix", out)

    def test_enum_appears_before_message(self):
        enum = _proto_enum("Status", [(0, "STATUS_UNKNOWN")], confirmed=True)
        msg  = _msg("Foo", fields=[_enum_field("status", 1, "Status")], enums=[enum])
        pf   = self._pf([msg])
        out  = pf.emit()
        pos_enum = out.index("enum Status")
        pos_msg  = out.index("message Foo")
        self.assertLess(pos_enum, pos_msg)

    def test_empty_enum_placeholder(self):
        enum = _proto_enum("Category")   # no values
        msg  = _msg("Foo", fields=[_enum_field("category", 1, "Category")], enums=[enum])
        pf   = self._pf([msg])
        out  = pf.emit()
        self.assertIn("enum Category {", out)
        self.assertIn("not recovered", out)

    def test_no_enums_no_enum_section(self):
        msg = _msg("Foo", fields=[ProtoField("x", 1, "int32", FieldLabel.OPTIONAL)])
        pf  = self._pf([msg])
        out = pf.emit()
        self.assertNotIn("enum ", out)

    def test_enum_field_type_in_message_block(self):
        """The field line references the enum name, not 'int32'."""
        enum = _proto_enum("FeedbackType", [(0, "FEEDBACK_TYPE_UNKNOWN")])
        fld  = _enum_field("feedback_type", 1, "FeedbackType")
        msg  = _msg("Request", fields=[fld], enums=[enum])
        pf   = self._pf([msg])
        out  = pf.emit()
        self.assertIn("FeedbackType feedback_type = 1;", out)
        self.assertNotIn("int32 feedback_type", out)

    def test_enum_not_cross_package_qualified(self):
        """Enum type names are never qualified with a package prefix."""
        enum = _proto_enum("Status", [(0, "STATUS_UNKNOWN")])
        fld  = _enum_field("status", 1, "Status")
        msg  = _msg("Req", fields=[fld], enums=[enum])
        pf   = self._pf([msg], package="geo")
        out  = pf.emit(class_to_pkg={"GEOReq": "geo"})
        self.assertIn("Status status = 1;", out)
        self.assertNotIn("geo.Status", out)


# ── TestCollectEnums ──────────────────────────────────────────────────────────

class TestCollectEnums(unittest.TestCase):

    def _pf(self, messages) -> ProtoFile:
        return ProtoFile("geo", "geo.proto", messages, [])

    def test_single_message_single_enum(self):
        enum = _proto_enum("Type", [(0, "TYPE_UNKNOWN")])
        msg  = _msg("Foo", enums=[enum])
        pf   = self._pf([msg])
        enums = pf._collect_enums()
        self.assertEqual(len(enums), 1)
        self.assertEqual(enums[0].name, "Type")

    def test_same_enum_from_two_messages_deduplicated(self):
        e1 = _proto_enum("FeedbackType", [(0, "FEEDBACK_TYPE_UNKNOWN")])
        e2 = _proto_enum("FeedbackType", [(0, "FEEDBACK_TYPE_UNKNOWN"),
                                           (1, "FEEDBACK_TYPE_POSITIVE")])
        m1 = _msg("A", enums=[e1])
        m2 = _msg("B", enums=[e2])
        pf = self._pf([m1, m2])
        enums = pf._collect_enums()
        self.assertEqual(len(enums), 1)

    def test_prefers_richer_enum_over_empty(self):
        empty  = _proto_enum("Status")  # no values
        richer = _proto_enum("Status", [(0, "STATUS_UNKNOWN"), (1, "STATUS_OK")])
        m1 = _msg("A", enums=[empty])
        m2 = _msg("B", enums=[richer])
        pf = self._pf([m1, m2])
        enums = pf._collect_enums()
        self.assertEqual(len(enums[0].values), 2)

    def test_prefers_confirmed_over_unconfirmed(self):
        unconf  = _proto_enum("Status", [(0, "STATUS_UNKNOWN"), (1, "STATUS_OK")])
        conf    = ProtoEnum("Status",
                            [ProtoEnumValue("STATUS_UNKNOWN", 0),
                             ProtoEnumValue("STATUS_OK", 1)],
                            values_confirmed=True)
        m1 = _msg("A", enums=[unconf])
        m2 = _msg("B", enums=[conf])
        pf = self._pf([m1, m2])
        enums = pf._collect_enums()
        self.assertTrue(enums[0].values_confirmed)

    def test_result_sorted_by_name(self):
        ea = _proto_enum("ZType", [(0, "Z_TYPE_UNKNOWN")])
        eb = _proto_enum("AType", [(0, "A_TYPE_UNKNOWN")])
        m1 = _msg("Msg", enums=[ea, eb])
        pf = self._pf([m1])
        names = [e.name for e in pf._collect_enums()]
        self.assertEqual(names, sorted(names))

    def test_no_enums_returns_empty(self):
        msg = _msg("Foo")
        pf  = self._pf([msg])
        self.assertEqual(pf._collect_enums(), [])


# ── TestEnumMessageNameCollision ──────────────────────────────────────────────
#
# proto3 forbids an enum and a message sharing a name in one package.  Enum type
# names are reconstructed (cosmetic); message names are authoritative — so the
# emitter renames the colliding ENUM and patches field references.
# Proven case: AppPredictionInternal atx.proto (ATXNotificationsPBEvent enum vs
# message).

class TestEnumMessageNameCollision(unittest.TestCase):

    def _pf(self, messages) -> ProtoFile:
        return ProtoFile("atx", "atx.proto", messages, [])

    def test_enum_renamed_when_colliding_with_message(self):
        # Mirrors atx.proto: message "Event" with a field typed by the enum
        # "Event" reconstructed from value strings.
        enum  = _proto_enum("Event", [(0, "EVENT_UNKNOWN"), (1, "EVENT_TAP")])
        fld   = _enum_field("event", 1, "Event")
        # The message that collides AND references the enum.
        owner = _msg("Event", class_name="ATXEvent",
                     fields=[fld], enums=[enum])
        pf    = self._pf([owner])

        enums = pf._collect_enums()
        names = [e.name for e in enums]
        # Enum got a non-colliding name; message name unchanged.
        self.assertEqual(names, ["EventEnum"])
        self.assertNotIn("Event", names)
        # Field reference repatched to the new enum name.
        self.assertEqual(fld.type_name, "EventEnum")
        self.assertEqual(fld.type_class, "ENUM:EventEnum")
        # Original name recorded for the explanatory comment.
        self.assertEqual(enums[0].collision_origin, "Event")

    def test_no_rename_without_collision(self):
        enum = _proto_enum("Status", [(0, "STATUS_OK")])
        fld  = _enum_field("status", 1, "Status")
        msg  = _msg("Request", fields=[fld], enums=[enum])
        pf   = self._pf([msg])
        enums = pf._collect_enums()
        self.assertEqual([e.name for e in enums], ["Status"])
        self.assertIsNone(enums[0].collision_origin)
        self.assertEqual(fld.type_class, "ENUM:Status")

    def test_rename_avoids_secondary_collision(self):
        # Both "Event" (message) and "EventEnum" (another message) are taken,
        # so the rename must fall through to "EventEnum2".
        enum    = _proto_enum("Event", [(0, "EVENT_UNKNOWN")])
        owner   = _msg("Event", class_name="ATXEvent", enums=[enum])
        blocker = _msg("EventEnum", class_name="ATXEventEnum")
        pf      = self._pf([owner, blocker])
        enums   = pf._collect_enums()
        self.assertEqual([e.name for e in enums], ["EventEnum2"])

    def test_decollision_is_idempotent(self):
        enum  = _proto_enum("Event", [(0, "EVENT_UNKNOWN")])
        fld   = _enum_field("event", 1, "Event")
        owner = _msg("Event", class_name="ATXEvent",
                     fields=[fld], enums=[enum])
        pf    = self._pf([owner])
        first  = [e.name for e in pf._collect_enums()]
        second = [e.name for e in pf._collect_enums()]
        self.assertEqual(first, ["EventEnum"])
        self.assertEqual(second, ["EventEnum"])
        self.assertEqual(fld.type_class, "ENUM:EventEnum")

    def test_emit_has_no_collision_and_notes_rename(self):
        enum  = _proto_enum("Event", [(0, "EVENT_UNKNOWN"), (1, "EVENT_TAP")])
        fld   = _enum_field("event", 1, "Event")
        owner = _msg("Event", class_name="ATXEvent",
                     fields=[fld], enums=[enum])
        out   = self._pf([owner]).emit(class_to_pkg={"ATXEvent": "atx"})
        # No duplicate definition: the message keeps "Event", the enum is renamed.
        self.assertIn("message Event {", out)
        self.assertIn("enum EventEnum {", out)
        self.assertNotIn("enum Event {", out)
        # Field now references the renamed enum.
        self.assertIn("EventEnum event = 1;", out)
        # Explanatory comment present.
        self.assertIn('renamed from reconstructed "Event"', out)


# ── TestEnumZeroSynthesis ─────────────────────────────────────────────────────
#
# BUG 1: proto3 requires every enum's first value to be 0, but Apple's PBCodable
# enums genuinely start at 1.  The emitter synthesizes a clearly-marked
# `<PREFIX>_UNSPECIFIED = 0` for any enum that has values but no 0.  Value 0
# never appears on the wire for these enums, so it is purely cosmetic and every
# real value keeps its own number.

class TestEnumZeroSynthesis(unittest.TestCase):

    def _pf(self, messages) -> ProtoFile:
        return ProtoFile("als", "als.proto", messages, [])

    def test_zero_synthesized_for_one_based_enum(self):
        # Mirrors als.proto ALSLocationRequestSurroundingWifiBands (1,2).
        enum = _proto_enum("Bands", [(1, "BANDS_K2DOT4_GHZ"), (2, "BANDS_K5_GHZ")])
        msg  = _msg("Req", class_name="ALSReq", enums=[enum])
        out  = self._pf([msg]).emit()
        self.assertIn("BANDS_UNSPECIFIED = 0;", out)
        self.assertIn("synthesized zero value", out)
        # Real values preserved at their own numbers.
        self.assertIn("BANDS_K2DOT4_GHZ = 1;", out)
        self.assertIn("BANDS_K5_GHZ = 2;", out)

    def test_collected_enum_has_zero_value(self):
        enum  = _proto_enum("Bands", [(1, "BANDS_A"), (2, "BANDS_B")])
        msg   = _msg("Req", class_name="ALSReq", enums=[enum])
        out_e = self._pf([msg])._collect_enums()[0]
        self.assertTrue(any(v.number == 0 for v in out_e.values))

    def test_no_zero_synthesized_when_already_present(self):
        enum  = _proto_enum("Status", [(0, "STATUS_UNKNOWN"), (1, "STATUS_OK")])
        msg   = _msg("Req", class_name="ALSReq", enums=[enum])
        out   = self._pf([msg]).emit()
        self.assertNotIn("UNSPECIFIED", out)       # no synthetic 0 added
        self.assertEqual(out.count("= 0;"), 1)      # exactly one zero value

    def test_msg_enums_not_mutated_by_synthesis(self):
        # The golden snapshot reads msg.enums directly, so synthesis must build
        # new ProtoEnum objects and never touch the per-message instances.
        enum  = _proto_enum("Bands", [(1, "BANDS_A")])
        msg   = _msg("Req", class_name="ALSReq", enums=[enum])
        self._pf([msg]).emit()
        self.assertEqual([v.number for v in enum.values], [1])  # untouched

    def test_negative_only_enum_still_gets_zero(self):
        # An enum with only a negative value has no 0 either — proto3 still
        # needs one synthesized.
        enum  = _proto_enum("Off", [(-1, "OFF_INVALID")])
        msg   = _msg("Req", class_name="ALSReq", enums=[enum])
        out_e = self._pf([msg])._collect_enums()[0]
        self.assertTrue(any(v.number == 0 for v in out_e.values))

    def test_zero_listed_first_despite_negative(self):
        # proto3 requires the FIRST listed value to be 0; negatives are legal but
        # may not lead.  An enum {-1, 0, 1} must emit the 0 value before -1.
        enum = ProtoEnum("State", [ProtoEnumValue("S_UNKNOWN", -1),
                                    ProtoEnumValue("S_OK", 0),
                                    ProtoEnumValue("S_BAD", 1)])
        body = enum.to_proto().split("\n")
        first_val = next(l for l in body if "=" in l)
        self.assertIn("S_OK = 0;", first_val)            # zero leads

    def test_synthesized_zero_leads_with_negatives(self):
        # No 0 present but a negative is: the synthesized 0 must still lead.
        enum  = _proto_enum("Dir", [(-1, "DIR_BACK"), (1, "DIR_FWD")])
        msg   = _msg("Req", class_name="ALSReq", enums=[enum])
        out_e = self._pf([msg])._collect_enums()[0]
        body  = out_e.to_proto().split("\n")
        first_val = next(l for l in body if "=" in l)
        self.assertIn("= 0;", first_val)


# ── TestEnumValueNameDecollision ──────────────────────────────────────────────
#
# BUG 2: proto uses C++ enum-value scoping — a value name is a sibling of its
# enum TYPE, so two enums in one package may not share a value name (nor may a
# value name equal a message / enum-type name).  The emitter de-collides by
# renaming later occurrences; the first definer (in sorted order) keeps the
# plain name.  Proven case: geo.proto ListType / LogMsg…ListType both define
# LIST_TYPE_UNKNOWN.

class TestEnumValueNameDecollision(unittest.TestCase):

    def _pf(self, messages) -> ProtoFile:
        return ProtoFile("geo", "geo.proto", messages, [])

    def test_colliding_value_names_decollided(self):
        e1  = _proto_enum("AListType", [(0, "LIST_TYPE_UNKNOWN")])
        e2  = _proto_enum("BListType", [(0, "LIST_TYPE_UNKNOWN")])
        msg = _msg("M", class_name="GEOM", enums=[e1, e2])
        out = self._pf([msg]).emit()
        # Exactly one plain occurrence + one de-collided occurrence.
        self.assertEqual(out.count("LIST_TYPE_UNKNOWN = 0;"), 1)
        self.assertIn("LIST_TYPE_UNKNOWN_2 = 0;", out)
        self.assertIn("renamed from", out)

    def test_value_decollided_against_message_name(self):
        # protoc rejects an enum value sharing a name with a message in the
        # package (C++ scoping), so de-collide against message names too.
        enum    = _proto_enum("E", [(0, "FOO_BAR")])
        owner   = _msg("M", class_name="GEOM", enums=[enum])
        clash   = _msg("FOO_BAR", class_name="GEOFooBar")
        out     = self._pf([owner, clash]).emit()
        self.assertIn("message FOO_BAR {", out)
        self.assertIn("FOO_BAR_2 = 0;", out)
        self.assertNotIn("FOO_BAR = 0;", out)

    def test_no_decollision_when_unique(self):
        e1  = _proto_enum("AType", [(0, "A_TYPE_UNKNOWN")])
        e2  = _proto_enum("BType", [(0, "B_TYPE_UNKNOWN")])
        msg = _msg("M", class_name="GEOM", enums=[e1, e2])
        out = self._pf([msg]).emit()
        self.assertNotIn("renamed from", out)
        self.assertIn("A_TYPE_UNKNOWN = 0;", out)
        self.assertIn("B_TYPE_UNKNOWN = 0;", out)

    def test_decollision_idempotent(self):
        e1  = _proto_enum("AListType", [(0, "LIST_TYPE_UNKNOWN")])
        e2  = _proto_enum("BListType", [(0, "LIST_TYPE_UNKNOWN")])
        msg = _msg("M", class_name="GEOM", enums=[e1, e2])
        pf  = self._pf([msg])
        first  = pf.emit()
        second = pf.emit()
        self.assertEqual(first, second)


# ── TestEnumCompatibility ─────────────────────────────────────────────────────
#
# Tests for _enums_compatible and the principled value-compatibility
# partitioning in _collect_enums.

class TestEnumCompatibility(unittest.TestCase):
    """Unit tests for _enums_compatible."""

    def setUp(self):
        from proto.emitter import _enums_compatible
        self._compat = _enums_compatible

    def test_both_empty_compatible(self):
        a = _proto_enum("Status")
        b = _proto_enum("Status")
        self.assertTrue(self._compat(a, b))

    def test_one_empty_compatible_with_any(self):
        empty = _proto_enum("Status")
        full  = _proto_enum("Status", [(0, "STATUS_SUCCESS"), (1, "STATUS_FAILED")])
        self.assertTrue(self._compat(empty, full))
        self.assertTrue(self._compat(full, empty))

    def test_same_values_compatible(self):
        a = _proto_enum("Status", [(0, "STATUS_SUCCESS"), (1, "STATUS_FAILED")])
        b = _proto_enum("Status", [(0, "STATUS_SUCCESS"), (1, "STATUS_FAILED")])
        self.assertTrue(self._compat(a, b))

    def test_subset_compatible(self):
        """One enum having fewer values than the other is still compatible."""
        small = _proto_enum("Status", [(0, "STATUS_SUCCESS")])
        large = _proto_enum("Status", [(0, "STATUS_SUCCESS"), (1, "STATUS_FAILED"),
                                        (5, "STATUS_INVALID_REQUEST")])
        self.assertTrue(self._compat(small, large))
        self.assertTrue(self._compat(large, small))

    def test_conflicting_value_at_zero_incompatible(self):
        """
        Real-world case: PlaceResponse Status (SUCCESS=0) vs routing Status
        (UNKNOWN_FAILURE=0).  Index 0 carries different names → incompatible.
        """
        place_resp = _proto_enum("Status", [(0, "STATUS_SUCCESS"),
                                             (1, "STATUS_FAILED"),
                                             (2, "STATUS_INCOMPLETE")])
        routing    = _proto_enum("Status", [(0, "STATUS_UNKNOWN_FAILURE"),
                                             (1, "STATUS_SUCCESS"),
                                             (2, "STATUS_FAILURE")])
        self.assertFalse(self._compat(place_resp, routing))

    def test_disjoint_indices_vacuously_compatible(self):
        """
        Two enums with no shared numeric indices cannot conflict,
        so _enums_compatible returns True (vacuous compatibility).
        """
        a = _proto_enum("Type", [(0, "TYPE_A"), (1, "TYPE_B")])
        b = _proto_enum("Type", [(5, "TYPE_E"), (6, "TYPE_F")])
        self.assertTrue(self._compat(a, b))

    def test_single_conflict_anywhere_incompatible(self):
        """A single conflicting index is sufficient to declare incompatibility."""
        a = _proto_enum("T", [(0, "T_OK"), (1, "T_FAIL")])
        b = _proto_enum("T", [(0, "T_OK"), (1, "T_ERROR")])   # index 1 differs
        self.assertFalse(self._compat(a, b))


class TestCollectEnumsPrincipled(unittest.TestCase):
    """Tests for the value-compatibility partitioning in _collect_enums."""

    def _pf(self, messages):
        return ProtoFile("geo", "geo.proto", messages, [])

    # ── Compatible cases (no split needed) ───────────────────────────────────

    def test_single_message_single_enum_unchanged(self):
        enum = _proto_enum("Status", [(0, "STATUS_SUCCESS")])
        pf   = self._pf([_msg("A", enums=[enum])])
        enums = pf._collect_enums()
        self.assertEqual(len(enums), 1)
        self.assertEqual(enums[0].name, "Status")

    def test_compatible_subset_merged_uses_larger(self):
        """
        A class with fewer values and one with more values for the same enum:
        the richer definition should be used, the enum stays as one entry.
        """
        small = _proto_enum("Status", [(0, "STATUS_SUCCESS")])
        large = _proto_enum("Status", [(0, "STATUS_SUCCESS"), (1, "STATUS_FAILED"),
                                        (5, "STATUS_INVALID_REQUEST")])
        m1 = _msg("A", "GEOA", enums=[small])
        m2 = _msg("B", "GEOB", enums=[large])
        pf = self._pf([m1, m2])
        enums = pf._collect_enums()
        self.assertEqual(len(enums), 1)
        self.assertEqual(enums[0].name, "Status")
        self.assertEqual(len(enums[0].values), 3)

    def test_compatible_confirmed_preferred_over_unconfirmed(self):
        """For equal-size compatible enums, confirmed wins."""
        unconf = _proto_enum("Status", [(0, "STATUS_UNKNOWN"), (1, "STATUS_OK")])
        conf   = ProtoEnum("Status",
                           [ProtoEnumValue("STATUS_UNKNOWN", 0),
                            ProtoEnumValue("STATUS_OK", 1)],
                           values_confirmed=True)
        pf = self._pf([_msg("A", enums=[unconf]), _msg("B", enums=[conf])])
        enums = pf._collect_enums()
        self.assertEqual(len(enums), 1)
        self.assertTrue(enums[0].values_confirmed)

    def test_compatible_enums_emit_the_union_of_their_values(self):
        # each class's code shows some of the values: none may be lost
        a = _proto_enum("Status", [(0, "STATUS_OK"), (1, "STATUS_FAILED")])
        b = _proto_enum("Status", [(0, "STATUS_OK"), (7, "STATUS_RETRY")])
        enums = self._pf([_msg("A", enums=[a]), _msg("B", enums=[b])])._collect_enums()
        self.assertEqual([(v.number, v.name) for v in enums[0].values],
                         [(0, "STATUS_OK"), (1, "STATUS_FAILED"), (7, "STATUS_RETRY")])

    def test_an_enum_joins_a_group_only_if_it_agrees_with_every_member(self):
        # {0} and {1: B} agree; {0, 1: X} agrees with the first but not the second
        e1 = _proto_enum("Kind", [(0, "KIND_A")])
        e2 = _proto_enum("Kind", [(1, "KIND_B")])
        e3 = _proto_enum("Kind", [(0, "KIND_A"), (1, "KIND_X")])
        enums = self._pf([_msg("A", enums=[e1]), _msg("B", enums=[e2]),
                          _msg("C", enums=[e3])])._collect_enums()
        # two enums, each with a 0 and its own 1 (value names are de-collided package-wide)
        self.assertEqual(sorted((sorted(v.number for v in e.values),
                                 {v.number: v.name for v in e.values}[1]) for e in enums),
                         [([0, 1], "KIND_B"), ([0, 1], "KIND_X")])

    # ── Incompatible cases (split with qualified names) ────────────────────────

    def test_incompatible_enums_produce_two_entries(self):
        """
        Core regression: PlaceResponse Status (SUCCESS=0) vs routing Status
        (UNKNOWN_FAILURE=0) must produce two *separate* enum definitions.
        """
        place_status   = _proto_enum("Status", [(0, "STATUS_SUCCESS"),
                                                 (1, "STATUS_FAILED")])
        routing_status = _proto_enum("Status", [(0, "STATUS_UNKNOWN_FAILURE"),
                                                 (1, "STATUS_SUCCESS"),
                                                 (2, "STATUS_FAILURE")])
        # Many messages share the PlaceResponse status
        place_msgs = [_msg(f"Place{i}", f"GEOPDPlace{i}", enums=[place_status])
                      for i in range(4)]
        # Fewer messages use the routing status
        route_msgs = [_msg("DirectionsResponse", "GEODirectionsResponse",
                           enums=[routing_status]),
                      _msg("ETAResponse", "GEOETAResponse",
                           enums=[routing_status])]

        pf = self._pf(place_msgs + route_msgs)
        enums = pf._collect_enums()

        enum_names = {e.name for e in enums}
        self.assertIn("Status", enum_names,
                      "Dominant group must keep the original name")
        # A non-dominant group must exist with a qualified name
        qualified = [n for n in enum_names if n != "Status" and "Status" in n]
        self.assertEqual(len(qualified), 1,
                         f"Expected exactly one qualified enum, got: {enum_names}")

    def test_incompatible_dominant_group_keeps_original_name(self):
        """
        The group with the most messages retains the original enum name.
        """
        common = _proto_enum("Status", [(0, "STATUS_SUCCESS"), (1, "STATUS_FAILED")])
        rare   = _proto_enum("Status", [(0, "STATUS_UNKNOWN"), (1, "STATUS_OK")])

        common_msgs = [_msg(f"M{i}", f"GEOM{i}", enums=[common]) for i in range(5)]
        rare_msg    = _msg("Rare", "GEORare", enums=[rare])

        pf = self._pf(common_msgs + [rare_msg])
        enums = pf._collect_enums()
        names = {e.name for e in enums}
        self.assertIn("Status", names)
        self.assertEqual(len([n for n in names if "Status" in n]), 2)

    def test_field_references_updated_for_non_dominant_group(self):
        """
        After splitting, the fields in non-dominant messages must reference
        the qualified enum name, not the original.

        Setup mirrors the real-world PlaceResponse-vs-routing Status case:
        - PlaceResponse Status: 9 values (SUCCESS=0/FAILED=1/…), used by many messages
          → dominant group, keeps the original "Status" name
        - Routing Status: 3 values (UNKNOWN_FAILURE=0/SUCCESS=1/FAILURE=2), fewer messages
          → non-dominant group, gets a qualified name like "DirectionsResponseStatus"
        """
        place_status   = _proto_enum("Status", [
            (0, "STATUS_SUCCESS"), (1, "STATUS_FAILED"), (2, "STATUS_INCOMPLETE"),
            (5, "STATUS_INVALID_REQUEST"), (20, "STATUS_FAILED_NO_RESULT"),
        ])
        routing_status = _proto_enum("Status", [(0, "STATUS_UNKNOWN_FAILURE"),
                                                 (1, "STATUS_SUCCESS"),
                                                 (2, "STATUS_FAILURE")])

        place_field   = _enum_field("status", 1, "Status")
        routing_field = _enum_field("status", 1, "Status")

        # Multiple place messages (dominant — more instances + more values)
        place_msgs = [_msg(f"Place{i}", f"GEOPDPlace{i}",
                           fields=[_enum_field("status", 1, "Status")],
                           enums=[place_status])
                      for i in range(3)]
        place_msg = place_msgs[0]
        # Override the field reference we'll inspect
        place_msg.fields[0] = place_field

        # One routing message (non-dominant)
        route_msg  = _msg("DirectionsResponse", "GEODirectionsResponse",
                           fields=[routing_field], enums=[routing_status])

        pf = self._pf(place_msgs + [route_msg])
        pf._collect_enums()   # mutates fields in-place

        # PlaceResponse.status should still reference "Status"
        self.assertEqual(place_field.type_name, "Status")
        self.assertEqual(place_field.type_class, "ENUM:Status")

        # DirectionsResponse.status must reference the qualified name
        self.assertNotEqual(routing_field.type_name, "Status",
                            "Non-dominant field should be renamed")
        self.assertTrue(routing_field.type_name.endswith("Status"),
                        f"Qualified name should end with 'Status', got {routing_field.type_name!r}")
        self.assertEqual(routing_field.type_class, f"ENUM:{routing_field.type_name}")

    def test_three_incompatible_groups_all_get_unique_names(self):
        """
        When a name splits into three incompatible groups, each non-dominant
        group gets its own qualified name; all names are distinct.
        """
        e1 = _proto_enum("Type", [(0, "TYPE_A")])
        e2 = _proto_enum("Type", [(0, "TYPE_B")])   # conflicts with e1 at 0
        e3 = _proto_enum("Type", [(0, "TYPE_C")])   # conflicts with both

        # 3 messages per group for tie-breaking by count
        msgs1 = [_msg(f"Alpha{i}", f"GEOAlpha{i}", enums=[e1]) for i in range(3)]
        msgs2 = [_msg(f"Beta{i}",  f"GEOBeta{i}",  enums=[e2]) for i in range(3)]
        msgs3 = [_msg(f"Gamma{i}", f"GEOGamma{i}", enums=[e3]) for i in range(3)]

        pf = self._pf(msgs1 + msgs2 + msgs3)
        enums = pf._collect_enums()
        names = [e.name for e in enums]
        # All enum names must be unique
        self.assertEqual(len(names), len(set(names)),
                         f"Duplicate enum names: {names}")
        # Exactly 3 entries for 3 groups
        self.assertEqual(len([n for n in names if "Type" in n]), 3)

    def test_result_sorted_alphabetically(self):
        """Returned enum list must be sorted by name for deterministic output."""
        ea = _proto_enum("ZType", [(0, "Z_TYPE_UNKNOWN")])
        eb = _proto_enum("AType", [(0, "A_TYPE_UNKNOWN")])
        pf = self._pf([_msg("Msg", enums=[ea, eb])])
        names = [e.name for e in pf._collect_enums()]
        self.assertEqual(names, sorted(names))

    def test_no_enums_returns_empty(self):
        pf = self._pf([_msg("Foo")])
        self.assertEqual(pf._collect_enums(), [])

    def test_incompatible_enum_emitted_with_correct_values(self):
        """
        The emitted non-dominant enum must carry the values of the
        non-dominant group's best representative, not the dominant one's.
        """
        dominant_vals = [(0, "STATUS_SUCCESS"), (1, "STATUS_FAILED")]
        minority_vals = [(0, "STATUS_UNKNOWN_FAILURE"), (1, "STATUS_SUCCESS")]

        dominant = _proto_enum("Status", dominant_vals)
        minority = _proto_enum("Status", minority_vals)

        dom_msgs = [_msg(f"D{i}", f"GEOD{i}", enums=[dominant]) for i in range(3)]
        min_msg  = _msg("ETAResponse", "GEOETAResponse", enums=[minority])

        pf = self._pf(dom_msgs + [min_msg])
        enums = pf._collect_enums()

        qualified = next(e for e in enums if e.name != "Status")
        # The qualified enum must NOT contain STATUS_SUCCESS=0 (that's the dominant)
        val_map = {v.number: v.name for v in qualified.values}
        self.assertEqual(val_map[0], "STATUS_UNKNOWN_FAILURE",
                         "Non-dominant enum must keep its own values")


# ── TestExtractionStatsEnum ───────────────────────────────────────────────────

class TestExtractionStatsEnum(unittest.TestCase):

    def test_enum_count_in_stats(self):
        enum = _proto_enum("FeedbackType", [(0, "FEEDBACK_TYPE_UNKNOWN")])
        msg  = _msg("Foo", fields=[_enum_field("feedback_type", 1, "FeedbackType")],
                    enums=[enum])
        pfs = build_proto_files([msg])
        stats = extraction_stats([msg], pfs)
        self.assertIn("enums", stats)
        self.assertEqual(stats["enums"], 1)

    def test_zero_enums(self):
        msg  = _msg("Foo", fields=[ProtoField("x", 1, "int32", FieldLabel.OPTIONAL)])
        pfs  = build_proto_files([msg])
        stats = extraction_stats([msg], pfs)
        self.assertEqual(stats["enums"], 0)

    def test_same_enum_name_two_messages_counted_once(self):
        e1 = _proto_enum("Status")
        e2 = _proto_enum("Status")
        m1 = _msg("A", "GEOA", enums=[e1])
        m2 = _msg("B", "GEOB", enums=[e2])
        pfs = build_proto_files([m1, m2])
        stats = extraction_stats([m1, m2], pfs)
        self.assertEqual(stats["enums"], 1)   # deduplicated

    def test_two_distinct_enums_counted_separately(self):
        e1 = _proto_enum("Status")
        e2 = _proto_enum("Category")
        msg = _msg("Foo", "GEOFoo", enums=[e1, e2])
        pfs = build_proto_files([msg])
        stats = extraction_stats([msg], pfs)
        self.assertEqual(stats["enums"], 2)


# ── TestPrintSummaryEnum ──────────────────────────────────────────────────────

class TestPrintSummaryEnum(unittest.TestCase):

    def test_enum_row_in_summary(self):
        enum = _proto_enum("Type")
        msg  = _msg("Foo", enums=[enum])
        pfs  = build_proto_files([msg])
        buf  = io.StringIO()
        print_summary([msg], pfs, source_name="Test", file=buf)
        self.assertIn("Enum", buf.getvalue())


# ── TestEndToEndEnum ──────────────────────────────────────────────────────────

class TestEndToEndEnum(unittest.TestCase):

    def test_complete_proto3_file_with_enum(self):
        """
        Full pipeline: message with enum field → valid proto3 file on disk.
        """
        enum = ProtoEnum(
            name="FeedbackType",
            values=[
                ProtoEnumValue("FEEDBACK_TYPE_UNKNOWN",  0),
                ProtoEnumValue("FEEDBACK_TYPE_POSITIVE", 1),
                ProtoEnumValue("FEEDBACK_TYPE_NEGATIVE", 2),
            ],
            values_confirmed=True,
        )
        msg = ProtoMessage(
            name="DirectionsRequestFeedback",
            class_name="GEODirectionsRequestFeedback",
            fields=[
                ProtoField("feedback_type", 1, "FeedbackType",
                           FieldLabel.OPTIONAL, type_class="ENUM:FeedbackType",
                           number_confirmed=True),
                ProtoField("route_index", 2, "int32",
                           FieldLabel.OPTIONAL, number_confirmed=True),
            ],
            enums=[enum],
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            written, pfs = write_from_messages(
                [msg], Path(tmpdir), source_name="GeoServices"
            )
            content = (Path(tmpdir) / "geo.proto").read_text()

        # Valid proto3 skeleton
        self.assertIn('edition = "2023";', content)
        self.assertIn("package geo;", content)

        # Enum block before message block
        self.assertIn("enum FeedbackType {", content)
        self.assertIn("FEEDBACK_TYPE_UNKNOWN = 0;", content)
        self.assertIn("FEEDBACK_TYPE_POSITIVE = 1;", content)
        self.assertIn("FEEDBACK_TYPE_NEGATIVE = 2;", content)
        pos_enum = content.index("enum FeedbackType")
        pos_msg  = content.index("message DirectionsRequestFeedback")
        self.assertLess(pos_enum, pos_msg, "enum block should precede message block")

        # Field uses enum type, not int32
        self.assertIn("FeedbackType feedback_type = 1;", content)
        self.assertNotIn("int32 feedback_type", content)

        # Plain int32 field
        self.assertIn("int32 route_index = 2;", content)

    def test_enum_and_message_cross_ref(self):
        """Enum field in geo + message cross-ref to clp — both emitted correctly."""
        clp_loc = ProtoMessage("Location", "CLPLocation",
                               fields=[ProtoField("lat", 1, "double", FieldLabel.OPTIONAL)])
        geo_msg = ProtoMessage(
            "Trip", "GEOTrip",
            fields=[
                ProtoField("start", 1, "CLPLocation",
                           FieldLabel.OPTIONAL, type_class="CLPLocation",
                           number_confirmed=True),
                ProtoField("trip_type", 2, "TripType",
                           FieldLabel.OPTIONAL, type_class="ENUM:TripType",
                           number_confirmed=True),
            ],
            enums=[ProtoEnum("TripType",
                             [ProtoEnumValue("TRIP_TYPE_UNKNOWN", 0),
                              ProtoEnumValue("TRIP_TYPE_DRIVING", 1)],
                             values_confirmed=True)],
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            write_from_messages([clp_loc, geo_msg], Path(tmpdir))
            geo_text = (Path(tmpdir) / "geo.proto").read_text()

        self.assertIn('import "clp.proto";', geo_text)
        self.assertIn("clp.Location start = 1;", geo_text)
        self.assertIn("TripType trip_type = 2;", geo_text)
        self.assertIn("enum TripType {", geo_text)
        self.assertNotIn("geo.TripType", geo_text)


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TestEnumWithoutValues(unittest.TestCase):
    """An enum field with no value-string method is its ivar's integer type again, flagged --
    uint32 for an unsigned ivar, not int32.  (One whose method yields no values stays an enum:
    its placeholder value says the values were not recovered.)"""

    def _collect(self, enc, recovered):
        from types import SimpleNamespace
        from unittest import mock
        import proto.enums as EN
        cls = SimpleNamespace(name="GEOX", ivars=[SimpleNamespace(name="_kind", type_enc=enc)])
        fld = ProtoField(name="kind", number=1, type_name="Kind", label=FieldLabel.OPTIONAL,
                         type_class="ENUM:Kind")
        with mock.patch.object(EN, "_tag_dictrep_enums", lambda *a, **k: ({}, {})), \
                mock.patch.object(EN, "_recover_enum_values", lambda *a, **k: (None, recovered)):
            enums = EN._collect_enum_definitions(None, cls, [fld], None, {"readFrom:"}, None)
        return enums, fld

    def test_an_unsigned_ivar_reverts_to_uint32(self):
        enums, fld = self._collect("I", None)
        self.assertEqual(enums, [])
        self.assertEqual((fld.type_name, fld.type_class), ("uint32", None))
        self.assertIn("could not be recovered", fld.disambiguation_comment)

    def test_a_signed_one_to_int32(self):
        enums, fld = self._collect("i", None)
        self.assertEqual((enums, fld.type_name), ([], "int32"))


class TestEnumNamesDecollided(unittest.TestCase):
    def _pf(self, messages):
        return ProtoFile(package="geo", filename="geo.proto", messages=messages, imports=[])

    def test_a_split_enum_s_new_name_is_not_one_already_taken(self):
        # two incompatible "Status" enums: the second becomes BStatus -- which another
        # message's enum already is
        a = _proto_enum("Status", [(0, "STATUS_OK")])
        b = _proto_enum("Status", [(0, "STATUS_FAIL")])
        taken = _proto_enum("BStatus", [(0, "B_STATUS_X")])
        enums = self._pf([_msg("A", enums=[a]), _msg("B", enums=[b]),
                          _msg("C", enums=[taken])])._collect_enums()
        names = [e.name for e in enums]
        self.assertEqual(len(names), len(set(names)), names)

    def test_an_empty_enum_s_placeholder_is_decollided(self):
        # "Other" (de-collided first) holds a value ZONE_UNKNOWN: the empty "Zone"'s
        # placeholder cannot be it too
        other = _proto_enum("Other", [(0, "OTHER_A"), (3, "ZONE_UNKNOWN")])
        zone = _proto_enum("Zone")
        text = self._pf([_msg("A", enums=[other]), _msg("B", enums=[zone])]).emit()
        self.assertEqual(text.count(" ZONE_UNKNOWN = "), 1, text)
