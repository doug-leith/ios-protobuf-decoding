"""
proto/test_proto.py — Tests for the proto extractor.

Two categories:
  1. Pure-logic unit tests — test individual functions without any binary.
  2. Live integration tests — run against GeoServices (skipped if binary absent).

Run with: python3 -m pytest proto/test_proto.py  OR  python3 proto/test_proto.py
"""

from __future__ import annotations

import os
import artifacts
import struct
import sys
import unittest
from unittest.mock import patch
from dataclasses import dataclass, field
from typing import List, Optional, Set

# ── path setup ────────────────────────────────────────────────────────────────
# proto/ macho/ resolve via the apple_protobuf_extractor editable install; the
# repo root (root-level helpers + tests/) is put on sys.path by the root
# conftest.py.  No per-file sys.path juggling needed.

from proto.protocore import _field_label, _is_real_field_ivar, _type_from_enc
from proto.protoclass_heuristic import _is_proto_class
from proto.config import _class_to_proto_name
from proto.extractor import extract_all, extract_proto_message, is_proto_class
from proto.models import FieldLabel, ProtoField, ProtoMessage
from macho.classlist import ObjcClass, ObjcIvar, ObjcMethod

# ── helpers ───────────────────────────────────────────────────────────────────

def _method(name: str, imp: int = 0) -> ObjcMethod:
    return ObjcMethod(name=name, types='', imp=imp, is_relative=False)


def _ivar(name: str, type_enc: str = '', offset: int = 0,
          size: int = 8) -> ObjcIvar:
    return ObjcIvar(name=name, type_enc=type_enc, offset=offset, size=size)


def _proto_class(name: str, extra_methods: Optional[List[str]] = None,
                 ivars: Optional[List[ObjcIvar]] = None,
                 is_meta: bool = False) -> ObjcClass:
    """Build a minimal proto-like ObjcClass fixture."""
    base_methods = [
        'readFrom:', 'writeTo:', 'mergeFrom:',
        'copyTo:', 'copyWithZone:', 'isEqual:',
        'hash', 'description', 'dictionaryRepresentation',
    ]
    methods = [_method(sel) for sel in (base_methods + (extra_methods or []))]
    return ObjcClass(
        vmaddr=0x1000,
        name=name,
        is_meta=is_meta,
        superclass_vmaddr=0,
        superclass_name=None,
        ro_flags=0,
        instance_size=64,
        methods=methods,
        ivars=ivars or [],
    )


# ══════════════════════════════════════════════════════════════════════════════
# 1. Proto-class detection
# ══════════════════════════════════════════════════════════════════════════════

class TestIsProtoClass(unittest.TestCase):

    def test_full_signature_is_detected(self):
        cls = _proto_class('CLPLocation')
        self.assertTrue(_is_proto_class(cls))

    def test_is_proto_class_public_alias(self):
        cls = _proto_class('CLPLocation')
        self.assertTrue(is_proto_class(cls))

    def test_metaclass_is_rejected(self):
        cls = _proto_class('CLPLocation', is_meta=True)
        self.assertFalse(_is_proto_class(cls))

    def test_missing_required_method_rejected(self):
        """Without writeTo: the class should not be detected."""
        base = [
            'readFrom:', 'mergeFrom:',
            'copyTo:', 'copyWithZone:', 'isEqual:',
            'hash', 'description', 'dictionaryRepresentation',
        ]
        cls = ObjcClass(
            vmaddr=0x1000, name='Not', is_meta=False,
            superclass_vmaddr=0, superclass_name=None,
            ro_flags=0, instance_size=64,
            methods=[_method(m) for m in base],
        )
        self.assertFalse(_is_proto_class(cls))

    def test_score_below_minimum_rejected(self):
        """Only 4 scored methods — below minimum of 5."""
        cls = ObjcClass(
            vmaddr=0x1000, name='Incomplete', is_meta=False,
            superclass_vmaddr=0, superclass_name=None,
            ro_flags=0, instance_size=64,
            methods=[_method(m) for m in
                     ('readFrom:', 'writeTo:', 'mergeFrom:', 'hash')],
        )
        self.assertFalse(_is_proto_class(cls))

    def test_regular_objc_class_not_detected(self):
        cls = ObjcClass(
            vmaddr=0x1000, name='GEORoute', is_meta=False,
            superclass_vmaddr=0, superclass_name=None,
            ro_flags=0, instance_size=64,
            methods=[_method(m) for m in ('init', 'dealloc', 'description')],
        )
        self.assertFalse(_is_proto_class(cls))

    def test_ivar_based_detection_with_has_bits(self):
        """A class with a has_* flags ivar is detected even with no method names."""
        flags_ivar = _ivar('_flags',
                           '{?="has_latitude"b1"has_longitude"b1}')
        cls = ObjcClass(
            vmaddr=0x1000, name='GEOCoord', is_meta=False,
            superclass_vmaddr=0, superclass_name=None,
            ro_flags=0, instance_size=32,
            ivars=[flags_ivar],   # no methods → forces ivar path
        )
        self.assertTrue(_is_proto_class(cls))

    def test_ivar_based_detection_with_read_bits(self):
        """A class with ONLY read_* flags ivar (no has_* bits) must also be
        detected.  This is the pattern used by classes with exclusively
        sub-message fields (e.g. GEOPDComponentFilter, GEOPDPlaceRequestParameters).
        Previously _is_proto_flags_ivar only matched has_* patterns, so these
        classes were silently missed.
        """
        flags_ivar = _ivar('_flags',
                           '{?="read_unknownFields"b1"read_entityFilter"b1}')
        cls = ObjcClass(
            vmaddr=0x1000, name='GEOPDComponentFilter', is_meta=False,
            superclass_vmaddr=0, superclass_name=None,
            ro_flags=0, instance_size=64,
            ivars=[flags_ivar],
        )
        self.assertTrue(_is_proto_class(cls),
                        "Classes with read_* flags ivar must be detected as proto")

    def test_oneof_without_mergefrom_detected(self):
        """A oneof / thin-wrapper proto class implements readFrom:/writeTo: but
        NOT mergeFrom: (its fields are mutually exclusive — nothing to merge).
        With no has-bits ivar it must still be detected via the method-name
        fallback, gated on the core {readFrom:, writeTo:} selectors plus the
        score threshold.  Real cases: GEOPDComponentValue (96-field oneof),
        GEOPDAddressObject (wrapper).  Previously the gate mandated mergeFrom:,
        so these were missed and referencing fields fell back to repeated bytes.
        """
        # readFrom:, writeTo:, copyTo:, copyWithZone:, isEqual:,
        # dictionaryRepresentation → score 6, no mergeFrom:.
        methods = [
            'readFrom:', 'writeTo:',
            'copyTo:', 'copyWithZone:', 'isEqual:',
            'dictionaryRepresentation',
        ]
        cls = ObjcClass(
            vmaddr=0x1000, name='GEOPDComponentValue', is_meta=False,
            superclass_vmaddr=0, superclass_name=None,
            ro_flags=0, instance_size=64,
            methods=[_method(m) for m in methods],
        )
        self.assertTrue(_is_proto_class(cls),
                        "oneof/wrapper proto classes without mergeFrom: must be detected")


# ══════════════════════════════════════════════════════════════════════════════
# 1b. _is_proto_flags_ivar unit tests
# ══════════════════════════════════════════════════════════════════════════════

class TestIsProtoFlagsIvar(unittest.TestCase):
    """Direct unit tests for _is_proto_flags_ivar covering all flavours."""

    from proto.protocore import _is_proto_flags_ivar as _f

    def _f(self, name, type_enc):
        from proto.protocore import _is_proto_flags_ivar
        return _is_proto_flags_ivar(_ivar(name, type_enc))

    def test_has_bits_detected(self):
        """Standard scalar/string has-bits pattern."""
        self.assertTrue(self._f('_flags', '{?="has_latitude"b1"has_longitude"b1}'))

    def test_read_bits_detected(self):
        """Sub-message lazy-load read_* pattern — the previously missing case."""
        self.assertTrue(self._f('_flags',
                                '{?="read_unknownFields"b1"read_entityFilter"b1}'))

    def test_mixed_has_and_read_detected(self):
        """Flags ivar with both has_* and read_* bits."""
        self.assertTrue(self._f('_flags',
                                '{?="has_requestType"b1"read_unknownFields"b1}'))

    def test_non_bitfield_struct_rejected(self):
        """A regular struct (no bit fields) must not be detected as flags."""
        self.assertFalse(self._f('_size', '{CGSize=dd}'))

    def test_os_unfair_lock_rejected(self):
        """The reader lock ivar must not be detected as a flags ivar."""
        self.assertFalse(self._f('_readerLock',
                                 '{os_unfair_lock_s="_os_unfair_lock_opaque"I}'))

    def test_scalar_rejected(self):
        self.assertFalse(self._f('_someInt', 'i'))
        self.assertFalse(self._f('_someDouble', 'd'))

    def test_empty_encoding_rejected(self):
        self.assertFalse(self._f('_flags', ''))

    def test_nested_read_bitfield_in_c_struct_rejected(self):
        """A large C-struct ivar carrying a 1-bit bitfield nested deep inside must
        NOT be mis-detected as a proto flags ivar.  SymptomNetworkUsage's kernel
        `nstat_*` structs hold a `{?="probe_activated"b1..."read_probe_failed"b1...}`
        bitfield; the `read_` member there false-matched the old `"read_` substring
        rule and poisoned the proto-class VA-cluster closure (SymptomNetworkUsage
        4→28 phantom NSObject classes).  The opener-based match excludes it."""
        kernel = ('{nstat_msg="hdr"{nstat_hdr="type"I}"connstatus"'
                  '{tcp_conn_status="flags"(?=""{?="probe_activated"b1'
                  '"write_probe_failed"b1"read_probe_failed"b1'
                  '"conn_probe_failed"b1}"pad"I)}}')
        self.assertFalse(self._f('_nstat_update', kernel))

    def test_flags_struct_behind_name_still_detected(self):
        """The opener match keys on `{?="has_`/`{?="read_` anywhere, so a flags
        struct that sits behind a struct name is still caught.

        NOTE: a bare `{Outer={?="has_x"...}}` also satisfies the OLD (pre-
        515ba078) looser check (`enc.startswith('{') and '"has_' in enc and
        'b1' in enc`), so it can't discriminate the opener-anchoring change on
        its own. Prefix with `^` (a pointer to the outer struct) so the OLD
        check's `enc.startswith('{')` term fails while the NEW opener-anywhere
        match still finds `{?="has_` further inside -- old and new now
        disagree."""
        self.assertTrue(self._f('_flags', '{Outer={?="has_x"b1"has_y"b1}}'))
        self.assertTrue(self._f('_flags', '^{Outer={?="has_x"b1"has_y"b1}}'))


# ══════════════════════════════════════════════════════════════════════════════
# 1c. Internal PB ivar exclusion
# ══════════════════════════════════════════════════════════════════════════════

class TestInternalIvarExclusion(unittest.TestCase):
    """_is_real_field_ivar must reject the Apple PB runtime's bookkeeping ivars
    regardless of whether matching getter/setter methods exist.

    Previously these ivars appeared as proto fields 1–5, shifting every real
    field number and inserting PBDataReader / PBUnknownFields into the schema.
    """

    def _check(self, ivar_name: str, type_enc: str, methods=None) -> bool:
        from proto.protocore import _is_real_field_ivar
        iv = _ivar(ivar_name, type_enc)
        mnames = set(methods) if methods else set()
        return _is_real_field_ivar(iv, mnames)

    def test_reader_excluded(self):
        """_reader (PBDataReader) must always be excluded."""
        self.assertFalse(self._check('_reader', '@"PBDataReader"',
                                     methods=['reader', 'setReader:']))

    def test_unknown_fields_excluded(self):
        """_unknownFields (PBUnknownFields) must always be excluded."""
        self.assertFalse(self._check('_unknownFields', '@"PBUnknownFields"',
                                     methods=['unknownFields', 'setUnknownFields:']))

    def test_reader_mark_pos_excluded(self):
        self.assertFalse(self._check('_readerMarkPos', 'I',
                                     methods=['readerMarkPos', 'setReaderMarkPos:']))

    def test_reader_mark_length_excluded(self):
        self.assertFalse(self._check('_readerMarkLength', 'I',
                                     methods=['readerMarkLength', 'setReaderMarkLength:']))

    def test_reader_lock_excluded(self):
        self.assertFalse(self._check('_readerLock',
                                     '{os_unfair_lock_s="_os_unfair_lock_opaque"I}'))

    def test_normal_field_not_excluded(self):
        """A real field with a getter must pass through unchanged."""
        self.assertTrue(self._check('_latitude', 'd',
                                    methods=['latitude', 'setLatitude:']))

    def test_internal_ivar_excluded_even_without_methods(self):
        """Exclusion must happen before method-name fallback (empty method set)."""
        self.assertFalse(self._check('_reader', '@"PBDataReader"', methods=[]))


# ══════════════════════════════════════════════════════════════════════════════
# 2. Real-field ivar filtering
# ══════════════════════════════════════════════════════════════════════════════

class TestIsRealFieldIvar(unittest.TestCase):

    def _mnames(self, selectors: List[str]) -> Set[str]:
        return set(selectors)

    def test_simple_string_ivar_is_real(self):
        iv = _ivar('make', '@"NSString"')
        # not a bookkeeping/flags ivar → real field (shape, not name)
        self.assertTrue(_is_real_field_ivar(iv, self._mnames(['make', 'setMake:'])))

    def test_scalar_ivar_is_real(self):
        iv = _ivar('latitude', 'd')
        self.assertTrue(_is_real_field_ivar(iv, self._mnames(['setLatitude:'])))

    def test_ivar_with_no_getter_no_setter_is_filtered(self):
        # A has-bits bitfield: rejected by name (_is_has_bits_name)
        iv = _ivar('_hasBits_', 'c')
        self.assertFalse(_is_real_field_ivar(iv, self._mnames(
            ['make', 'setMake:', 'hasMake']
        )))

    def test_empty_ivar_name_is_filtered(self):
        iv = _ivar('', 'i')
        self.assertFalse(_is_real_field_ivar(iv, self._mnames(['foo'])))

    def test_leading_underscore_stripped_for_matching(self):
        iv = _ivar('_make', '@"NSString"')
        self.assertTrue(_is_real_field_ivar(iv, self._mnames(['make', 'setMake:'])))

    # TODO #60: admission is STORAGE-SHAPE only — selector-independent.
    def test_getterless_non_flags_ivar_is_admitted(self):
        # No getter/setter at all (cache-native stripped): a plain field ivar is
        # still admitted because its shape is not the has-bits struct.
        # NOTE: swapping in a non-empty, name-matching method_names set here
        # would NOT tighten this test -- _is_real_field_ivar's current body
        # never reads method_names at all (2e8f4ea6 made it fully unused; see
        # its own docstring), so for a NON-flags ivar like this one, shape
        # alone already admits it under any method_names value. The actual
        # discriminator for 2e8f4ea6's shape-over-name change is
        # test_flags_struct_ivar_rejected_even_with_getter below, which uses a
        # FLAGS-shaped ivar WITH a matching getter and confirms shape still
        # wins (that combination is the one old vs. new code disagree on).
        iv = _ivar('_score', 'i')
        self.assertTrue(_is_real_field_ivar(iv, self._mnames([])))

    def test_flags_struct_ivar_rejected_even_with_getter(self):
        # The has-bits struct is rejected by SHAPE even if a same-name getter
        # exists — the name no longer rescues it (NAME-rescues-flags == 0).
        iv = _ivar('_flags', '{?="has_a"b1"has_b"b1}')
        self.assertFalse(_is_real_field_ivar(iv, self._mnames(['flags', 'setFlags:'])))


# ══════════════════════════════════════════════════════════════════════════════
# 3. Type encoding → proto type
# ══════════════════════════════════════════════════════════════════════════════

class TestTypeFromEnc(unittest.TestCase):

    def _t(self, enc: str, name: str = 'field',
           methods: Optional[List[str]] = None):
        return _type_from_enc(enc, name, set(methods or []))

    def test_int32(self):
        self.assertEqual(self._t('i'), ('int32', None))

    def test_int64(self):
        self.assertEqual(self._t('q'), ('int64', None))

    def test_uint32(self):
        self.assertEqual(self._t('I'), ('uint32', None))

    def test_uint64(self):
        self.assertEqual(self._t('Q'), ('uint64', None))

    def test_bool(self):
        self.assertEqual(self._t('B'), ('bool', None))

    def test_float(self):
        self.assertEqual(self._t('f'), ('float', None))

    def test_double(self):
        self.assertEqual(self._t('d'), ('double', None))

    def test_nsstring(self):
        self.assertEqual(self._t('@"NSString"'), ('string', None))

    def test_nsdata(self):
        self.assertEqual(self._t('@"NSData"'), ('bytes', None))

    def test_nsarray(self):
        # NSArray → type_name=NSArray, type_class=NSArray (resolved later)
        type_name, type_class = self._t('@"NSArray"')
        self.assertEqual(type_class, 'NSArray')

    def test_message_class(self):
        type_name, type_class = self._t('@"GEOSessionID"')
        self.assertEqual(type_name, 'GEOSessionID')
        self.assertEqual(type_class, 'GEOSessionID')

    def test_packed_list_scalar_element(self):
        """Packed repeated scalar list decodes to its element scalar (not bytes)."""
        self.assertEqual(self._t('{?="list"^i"count"Q"size"Q}'), ('int32', None))
        self.assertEqual(self._t('{?="list"^q"count"Q"size"Q}'), ('int64', None))
        self.assertEqual(self._t('{?="list"^I"count"Q"size"Q}'), ('uint32', None))
        self.assertEqual(self._t('{?="list"^Q"count"Q"size"Q}'), ('uint64', None))
        self.assertEqual(self._t('{?="list"^d"count"Q"size"Q}'), ('double', None))
        self.assertEqual(self._t('{?="list"^f"count"Q"size"Q}'), ('float', None))
        self.assertEqual(self._t('{?="list"^B"count"Q"size"Q}'), ('bool', None))

    def test_packed_list_enum_via_asstring_selector(self):
        """A packed integer list whose field has an xAsString:/StringAsX: selector
        is a repeated ENUM (same signal as the singular scalar enum path)."""
        # field 'scales' with scalesAsString: → enum
        self.assertEqual(
            self._t('{?="list"^i"count"Q"size"Q}', 'scales', ['scalesAsString:']),
            ('Scales', 'ENUM:Scales'))
        # StringAsX: form also recognised
        self.assertEqual(
            self._t('{?="list"^i"count"Q"size"Q}', 'modes', ['StringAsModes:']),
            ('Modes', 'ENUM:Modes'))
        # no enum selector → plain scalar
        self.assertEqual(
            self._t('{?="list"^i"count"Q"size"Q}', 'scales', []), ('int32', None))
        # non-integer element never becomes an enum even with a selector
        self.assertEqual(
            self._t('{?="list"^d"count"Q"size"Q}', 'scales', ['scalesAsString:']),
            ('double', None))

    def test_bare_object(self):
        type_name, _ = self._t('@')
        self.assertEqual(type_name, 'bytes')

    def test_enum_field_with_as_string_method(self):
        # ivar 'type' with typeAsString: → enum type name + ENUM: sentinel
        type_name, type_class = self._t('i', 'type',
                                        methods=['typeAsString:', 'StringAsType:'])
        self.assertEqual(type_name, 'Type')
        self.assertEqual(type_class, 'ENUM:Type')

    def test_pointer_to_int(self):
        type_name, _ = self._t('^i')
        self.assertEqual(type_name, 'int32')

    def test_unknown_encoding_becomes_bytes(self):
        type_name, _ = self._t('{CGSize=dd}')
        self.assertEqual(type_name, 'bytes')


# ══════════════════════════════════════════════════════════════════════════════
# 4. Field label classification
# ══════════════════════════════════════════════════════════════════════════════

class TestFieldLabel(unittest.TestCase):

    def test_nsarray_ivar_is_repeated(self):
        iv = _ivar('locations', '@"NSArray"')
        self.assertEqual(_field_label(iv, set()), FieldLabel.REPEATED)

    def test_optional_scalar_field(self):
        iv = _ivar('make', '@"NSString"')
        self.assertEqual(_field_label(iv, set()), FieldLabel.OPTIONAL)

    def test_nsmutablearray_ivar_is_repeated(self):
        iv = _ivar('items', '@"NSMutableArray"')
        self.assertEqual(_field_label(iv, set()), FieldLabel.REPEATED)

    def test_default_is_optional(self):
        iv = _ivar('latitude', 'd')
        self.assertEqual(_field_label(iv, set()), FieldLabel.OPTIONAL)

    # TODO #60: the label is STORAGE-SHAPE only — selector names are ignored.
    def test_inline_c_struct_pointer_is_repeated(self):
        """A ``^{<Struct>=…}`` ivar is a heap array of fixed structs → REPEATED,
        even with NO add/count selectors (the inline-C-struct case, #37).  A
        singular fixed struct is stored by value (``{UInt128=QQ}``), never by
        pointer, so ``^{`` is unambiguous.  Hopper-confirmed on
        GEOResource._regions / GEOCoarseLocationRing._points."""
        for enc in ('^{GEOTileSetRegion=IIIIII}',
                    '^{GEOCoarseLocationPoint=ii}',
                    '^{GEOPDTimeRange=II{?=b1b1}}'):
            iv = _ivar('_regions', enc)
            self.assertEqual(_field_label(iv, set()), FieldLabel.REPEATED, enc)

    def test_label_ignores_selector_names(self):
        """add<X>:/<x>Count/has<X> no longer influence the label — shape decides.
        A scalar ivar carrying (contrived) add/count selectors stays OPTIONAL; an
        NSArray carrying a has<X> selector stays REPEATED."""
        scalar = _ivar('estimates', 'i')
        self.assertEqual(
            _field_label(scalar, {'addEstimate:', 'estimatesCount'}),
            FieldLabel.OPTIONAL)
        arr = _ivar('tags', '@"NSMutableArray"')
        self.assertEqual(_field_label(arr, {'hasTags', 'setHasTags:'}),
                         FieldLabel.REPEATED)

    def test_value_struct_is_not_repeated(self):
        """An inline struct stored BY VALUE ({...}, not ^{...}) is a singular
        embedded struct → OPTIONAL (only the pointer form is the array).

        NOTE: a non-empty, name-matching method_names set (e.g. {'addSize:',
        'sizeCount'}) would NOT tighten this test -- _field_label's current
        body never reads method_names at all (2e8f4ea6 made it fully unused;
        see its own docstring), so no method_names value can change this
        result. test_label_ignores_selector_names below is the actual
        discriminator: it uses matching add/count selectors on both a scalar
        and an NSArray ivar and confirms shape still wins in both directions
        -- test_inline_c_struct_pointer_is_repeated covers the commit's other
        real fix (^{struct} -> REPEATED with NO selectors at all)."""
        iv = _ivar('_size', '{CGSize=dd}')
        self.assertEqual(_field_label(iv, set()), FieldLabel.OPTIONAL)

    def test_packed_list_encoding_is_repeated_without_selectors(self):
        """Apple's packed C-array struct {?="list"^<elem>"count"Q"size"Q} is a
        packed repeated scalar field — REPEATED even with NO add/count selectors
        (the cache-native / singularised-adder case that defeats the name path)."""
        for enc in ('{?="list"^i"count"Q"size"Q}',     # int32
                    '{?="list"^Q"count"Q"size"Q}',     # uint64
                    '{?="list"^d"count"Q"size"Q}',     # double
                    '{?="list"^B"count"Q"size"Q}'):    # bool
            iv = _ivar('_prbOnFloorEstimates', enc)
            self.assertEqual(_field_label(iv, set()), FieldLabel.REPEATED, enc)

    def test_is_packed_list_enc(self):
        from proto.protocore import _is_packed_list_enc
        self.assertTrue(_is_packed_list_enc('{?="list"^i"count"Q"size"Q}'))
        self.assertTrue(_is_packed_list_enc('{?="list"^d"count"Q"size"Q}'))
        # has-bits / presence ivars must NOT match (no collision with flags)
        self.assertFalse(_is_packed_list_enc('{?="has_latitude"b1"has_longitude"b1}'))
        self.assertFalse(_is_packed_list_enc('@"NSArray"'))
        self.assertFalse(_is_packed_list_enc('i'))
        self.assertFalse(_is_packed_list_enc(None))


# ══════════════════════════════════════════════════════════════════════════════
# 5. Class-name to proto-name
# ══════════════════════════════════════════════════════════════════════════════

class TestClassToProtoName(unittest.TestCase):

    def test_geo_prefix_stripped(self):
        self.assertEqual(_class_to_proto_name('GEOAPSessionData'), 'APSessionData')

    def test_clp_prefix_stripped(self):
        self.assertEqual(_class_to_proto_name('CLPLocation'), 'Location')

    def test_no_known_prefix_unchanged(self):
        self.assertEqual(_class_to_proto_name('SomeUnknownClass'), 'SomeUnknownClass')

    def test_just_prefix_edge_case(self):
        self.assertEqual(_class_to_proto_name('GEO'), '')


class TestConfigurePrefixes(unittest.TestCase):
    """
    Regression tests for the CLI ``--prefix`` flag, now threaded as the
    ``prefixes=`` argument to ``_class_to_proto_name`` (and ``extract_all``).

    Before the original fix, the prefix set was a module constant the CLI never
    updated, so a binary with a non-Apple ObjC class prefix (e.g. APPL, FB) kept
    its prefix in the proto message name ("APPLFoo" instead of "Foo").  The knob
    is now an explicit per-call parameter — these assert the stripping behaviour
    for a custom prefix set passed that way.
    """

    def test_new_prefix_is_stripped(self):
        self.assertEqual(_class_to_proto_name("APPLFoo", ("APPL",)), "Foo")

    def test_original_prefixes_replaced_not_extended(self):
        # An explicit set replaces the default; GEO is no longer stripped.
        self.assertEqual(_class_to_proto_name("GEOBar", ("APPL",)), "GEOBar")

    def test_multiple_prefixes_all_stripped(self):
        self.assertEqual(_class_to_proto_name("APPLFoo", ("APPL", "MSFT")), "Foo")
        self.assertEqual(_class_to_proto_name("MSFTBar", ("APPL", "MSFT")), "Bar")

    def test_unknown_prefix_unchanged(self):
        self.assertEqual(_class_to_proto_name("ZZZBaz", ("APPL",)), "ZZZBaz")

    def test_empty_tuple_strips_nothing(self):
        # No prefix will match; every class name returned unchanged.  NOTE: an
        # explicit empty tuple never reaches the fallback-to-DEFAULT_PREFIXES
        # branch at all, so this can't discriminate 1ec059a's global-removal
        # refactor (which only changed what happens when prefixes IS None) --
        # see test_prefix_consolidation.py::TestSingleCanonicalSource::
        # test_no_module_level_prefix_global_and_no_cross_call_leakage for a
        # test that actually exercises that removal.
        self.assertEqual(_class_to_proto_name("GEOFoo", ()), "GEOFoo")

    def test_just_prefix_edge_case(self):
        self.assertEqual(_class_to_proto_name("APPL", ("APPL",)), "")

    def test_case_sensitive(self):
        # Lowercase "appl" is a different string — not stripped.
        self.assertEqual(_class_to_proto_name("applFoo", ("APPL",)), "applFoo")


# ══════════════════════════════════════════════════════════════════════════════
# 7. (removed) ProtoMessage.to_proto output
#
# ProtoMessage.to_proto() was deleted 2026-07-22: it was a dead-code twin of
# proto/emitter.py's _emit_message (the ONLY renderer the real CLI path ever
# calls) that had drifted from it (no cross-package type qualification). Every
# assertion this class made duplicated existing coverage of _emit_message in
# tests/test_emitter.py EXCEPT "fields sorted by number", which had no other
# coverage and was migrated to tests/test_emitter.py::TestEmitMessage
# (test_fields_sorted_by_number_in_output) against the real renderer instead.
# ══════════════════════════════════════════════════════════════════════════════


# ══════════════════════════════════════════════════════════════════════════════
# 8. Synthetic full-pipeline test (no binary needed)
# ══════════════════════════════════════════════════════════════════════════════

class TestExtractProtoMessageSynthetic(unittest.TestCase):
    """
    Build an ObjcClass with the correct method+ivar layout and verify that
    extract_proto_message produces the expected schema — without a real binary.

    We use a None ctx since _find_readfrom_c_func will just return None for a
    class with no real IMP, causing the extractor to fall through to ivar ordering.
    """

    def _run(self, cls: ObjcClass) -> Optional[ProtoMessage]:
        # We need a minimal ctx stub that supports has_section (returns False)
        # so the extractor can skip dispatch-table analysis cleanly.
        ctx = _MinimalCtxStub()
        return extract_proto_message(ctx, _NullStringTable(), _NullClassList(), cls)

    def test_simple_message_with_three_string_fields(self):
        """CLPAccessoryMeta equivalent: make, model, version."""
        ivars = [
            _ivar('make',    '@"NSString"', offset=0x08),
            _ivar('model',   '@"NSString"', offset=0x10),
            _ivar('version', '@"NSString"', offset=0x18),
        ]
        cls = _proto_class('CLPAccessoryMeta', extra_methods=[
            'make', 'setMake:', 'hasMake',
            'model', 'setModel:', 'hasModel',
            'version', 'setVersion:', 'hasVersion',
        ], ivars=ivars)

        msg = self._run(cls)
        self.assertIsNotNone(msg)
        self.assertEqual(msg.name, 'AccessoryMeta')
        self.assertEqual(len(msg.fields), 3)

        names = [f.name for f in msg.fields]
        self.assertEqual(names, ['make', 'model', 'version'])

        types = {f.name: f.type_name for f in msg.fields}
        self.assertEqual(types['make'], 'string')

    def test_mixed_type_message(self):
        """Message with int, bool, string, and a nested message."""
        ivars = [
            _ivar('latitude',  'd',            offset=0x08),
            _ivar('longitude', 'd',            offset=0x10),
            _ivar('altitude',  'd',            offset=0x18),
            _ivar('provider',  '@"NSString"',  offset=0x20),
            _ivar('floor',     'i',            offset=0x28),
        ]
        extra = [
            'latitude', 'setLatitude:',
            'longitude', 'setLongitude:',
            'altitude', 'setAltitude:',
            'provider', 'setProvider:',
            'floor', 'setFloor:',
            'hasAltitude', 'hasProvider', 'hasFloor',
        ]
        cls = _proto_class('CLPLocation', extra_methods=extra, ivars=ivars)
        msg = self._run(cls)
        self.assertIsNotNone(msg)
        self.assertEqual(len(msg.fields), 5)

        type_map = {f.name: f.type_name for f in msg.fields}
        self.assertEqual(type_map['latitude'],  'double')
        self.assertEqual(type_map['longitude'], 'double')
        self.assertEqual(type_map['provider'],  'string')
        self.assertEqual(type_map['floor'],     'int32')

    def test_repeated_field_classified_correctly(self):
        """A CLPCellWifiCollectionRequest equivalent with repeated field."""
        ivars = [
            _ivar('meta',              '@"CLPMeta"',  offset=0x08),
            _ivar('cellTowerLocations','@"NSArray"',  offset=0x10),
        ]
        extra = [
            'meta', 'setMeta:', 'hasMeta',
            'cellTowerLocations', 'setCellTowerLocations:',
            'addCellTowerLocation:', 'cellTowerLocationsCount',
            'cellTowerLocationAtIndex:',
        ]
        cls = _proto_class('CLPCellWifiCollectionRequest',
                           extra_methods=extra, ivars=ivars)
        msg = self._run(cls)
        self.assertIsNotNone(msg)
        labels = {f.name: f.label for f in msg.fields}
        self.assertEqual(labels.get('cellTowerLocations'), FieldLabel.REPEATED)
        self.assertEqual(labels.get('meta'), FieldLabel.OPTIONAL)

    def test_non_proto_class_returns_none(self):
        cls = ObjcClass(
            vmaddr=0x1000, name='GEORoute', is_meta=False,
            superclass_vmaddr=0, superclass_name=None,
            ro_flags=0, instance_size=64,
            methods=[_method(m) for m in ('init', 'dealloc', 'description')],
        )
        self.assertIsNone(self._run(cls))

    def test_has_bits_ivar_is_excluded(self):
        """An ivar with no getter/setter (has-bits bitfield) must be excluded."""
        ivars = [
            _ivar('submissionId', 'q',  offset=0x08),
            _ivar('_hasBits',     'c',  offset=0x14),  # no getter/setter
        ]
        extra = ['submissionId', 'setSubmissionId:', 'hasSubmissionId']
        cls = _proto_class('CLPMeta', extra_methods=extra, ivars=ivars)
        msg = self._run(cls)
        self.assertIsNotNone(msg)
        names = [f.name for f in msg.fields]
        self.assertIn('submissionId', names)
        self.assertNotIn('hasBits', names)
        self.assertNotIn('_hasBits', names)

    def test_field_numbers_are_estimated_for_ivar_order(self):
        """Without dispatch-table analysis, numbers are 1-indexed by ivar order."""
        ivars = [_ivar('a', 'i', offset=8), _ivar('b', 'i', offset=12)]
        cls = _proto_class('CLPAB', extra_methods=['a', 'setA:', 'b', 'setB:'],
                           ivars=ivars)
        msg = self._run(cls)
        self.assertIsNotNone(msg)
        for f in msg.fields:
            self.assertFalse(f.number_confirmed,
                             f"field {f.name} should have estimated number")
        nums = {f.name: f.number for f in msg.fields}
        self.assertEqual(nums.get('a'), 1)
        self.assertEqual(nums.get('b'), 2)


# ── minimal stubs for no-binary tests ────────────────────────────────────────

class _MinimalCtxStub:
    """Bare-minimum BinaryContext stub for synthetic tests."""

    def has_section(self, segname: str, sectname: str) -> bool:
        return False

    def section(self, segname: str, sectname: str):
        raise ValueError(f"Section {segname}/{sectname} not available in stub")

    def read_ptr(self, va: int) -> int:
        raise ValueError(f"No binary available in stub ctx (va={va:#x})")

    def read_u32(self, va: int) -> int:
        raise ValueError(f"No binary available in stub ctx (va={va:#x})")

    def read_bytes(self, va: int, length: int) -> bytes:
        raise ValueError("No binary in stub ctx")


class _NullStringTable:
    """StringTable stub: always returns ''."""
    def get(self, va: int) -> str:
        return ''
    def find(self, s: str):
        return []


class _NullClassList:
    """ClassList stub: no classes, by_vmaddr always None."""
    def __iter__(self):
        return iter([])
    def by_vmaddr(self, va: int):
        return None
    def find(self, name: str):
        return None
    def find_subclasses(self, name: str, transitive: bool = True):
        return []
    def __len__(self):
        return 0
    def __contains__(self, name):
        return False


# ══════════════════════════════════════════════════════════════════════════════
# 9-A. Disasm ADRP+ADD roundtrip
# ══════════════════════════════════════════════════════════════════════════════

class TestDisasmAdrpAdd(unittest.TestCase):
    """Verify encode_adrp + encode_add, disassembled, evaluate to the target address."""

    def _roundtrip(self, text_va: int, target: int, rd: int = 26) -> Optional[int]:
        import struct as _struct
        pages_delta = ((target & ~0xFFF) - (text_va & ~0xFFF)) >> 12
        page_off    = target & 0xFFF

        imm21    = pages_delta & 0x1FFFFF
        immlo    = imm21 & 0x3
        immhi    = (imm21 >> 2) & 0x7FFFF
        adrp_w   = 0x90000000 | (immlo << 29) | (immhi << 5) | (rd & 0x1F)
        add_w    = 0x91000000 | (page_off << 10) | (rd << 5) | rd

        raw = _struct.pack('<III', adrp_w, add_w, 0xD65F03C0)          # ... ; ret

        from macho.disasm import disasm as _disasm
        from proto.arm64_eval import Flow

        class _FakeCtx:
            def read_bytes(self, va, length):
                off = va - text_va
                if off < 0 or off + length > len(raw):
                    raise ValueError
                return raw[off:off+length]

            def vmaddr_to_offset(self, va, length=1):
                off = va - text_va
                if off < 0 or off + length > len(raw):
                    raise ValueError
                return off

        insns = _disasm(_FakeCtx(), text_va, max_insns=4)
        return Flow(None, insns).const_before(len(insns) - 1, f'x{rd}')

    def test_same_page_offset(self):
        text_va, target = 0x18c000000, 0x18c000123
        self.assertEqual(self._roundtrip(text_va, target), target)

    def test_cross_page_forward(self):
        text_va = 0x18c1a7000
        target  = 0x1da25c3d0   # CLPAccessoryMeta dispatch table address
        self.assertEqual(self._roundtrip(text_va, target), target)

    def test_different_register(self):
        # text_va and target must be within ADRP range (±4GB - 4KB).
        # 0x200000000 is exactly 4GB from 0x100000000 — out of range.
        # Use a target within 2GB instead.
        text_va = 0x18c1a7000
        target  = 0x1dc000000   # ~0x15900000 bytes away — well within ±4GB range
        self.assertEqual(self._roundtrip(text_va, target, rd=21), target)


# ══════════════════════════════════════════════════════════════════════════════
# 9. (retired) Live integration tests — GeoServices, binary-only mode
# ══════════════════════════════════════════════════════════════════════════════
#
# TestProtoExtractorLive (full extract_all() against a standalone GeoServices
# binary) was removed 2026-07-22: GeoServices has no genuinely standalone
# build — it only ships inside the dyld shared cache — so the "standalone
# binary" this class needed was always a cache EXTRACTION with 0% resolved
# ObjC selector names. Commit 148f9a5 ("Replace no-symbols fallbacks with an
# up-front error/warning gate", 2026-06-09) already established that
# binary-only extraction from that kind of image is fallback-driven and
# unsupportable, and retired this class's siblings (test_live_geoservices.py,
# test_live_enums.py) for exactly that reason — this class was simply missed
# in that pass. With the fallbacks gone, extract_all() on such an image now
# correctly hard-fails (ProtoClassDetectionError / SelectorsUnresolvedError)
# instead of silently degrading, so there is no fixture that could make this
# class pass short of a genuinely standalone GeoServices build, which does not
# exist on-device. Every assertion this class made about GeoServices' actual
# extracted content (message/field counts, specific classes and field
# numbers, no internal ivars, .proto rendering) is still exercised via the
# cache-native path by test_golden_output.py, so no
# coverage was lost. See artifacts.py:geoservices_path() for the full caveat.


# ── Unit tests: repeated-string reclassification (Cause-1 + Cause-2 fixes) ───

class TestRepeatedStringReclassification(unittest.TestCase):
    """
    Unit tests for the two complementary mechanisms that reclassify
    ``repeated NSArray`` fields from ``repeated bytes`` to ``repeated string``:

    Cause-1 fix: ``_resolve_repeated_type`` now calls
    ``_class_from_type_method_imp`` with ``ctx`` when selector-name suffix
    matching fails, so that ``+displayLanguageType`` → bind-table lookup →
    ``"NSString"`` → ``_CLASS_TO_PROTO`` → ``"string"``.

    Cause-2 fix: ``_extract_writeto_field_numbers`` captures write-helper
    VMAs; a string-helper identified from a known scalar ``@"NSString"`` ivar
    is then used to reclassify any repeated field whose element write-helper
    matches.
    """

    def _meta_with(self, sel, imp=0x1000):
        return ObjcClass(
            vmaddr=0x8000, name='GEOThing_meta', is_meta=True,
            superclass_vmaddr=0, superclass_name=None, ro_flags=0,
            instance_size=32,
            methods=[ObjcMethod(name=sel, types='', imp=imp, is_relative=False)],
            ivars=[])

    def test_resolve_repeated_type_maps_system_class_name_to_string(self):
        """
        The +xyzType IMP resolves to the external class NSString (bind table);
        _resolve_repeated_type must map it through _CLASS_TO_PROTO to 'string'.
        """
        from proto.repeated import _resolve_repeated_type
        with patch('proto.repeated._class_from_type_method_imp', return_value='NSString'):
            result = _resolve_repeated_type('fooType', metaclass=self._meta_with('fooType'),
                                            cl=None, ctx=object())
        self.assertEqual(result, ("string", False),
                         "NSString must map to 'string' via _CLASS_TO_PROTO")

    def test_resolve_repeated_type_maps_nsdata_to_bytes(self):
        """NSData maps to a *genuine* 'bytes' — resolved, so NOT element_unresolved."""
        from proto.repeated import _resolve_repeated_type
        with patch('proto.repeated._class_from_type_method_imp', return_value='NSData'):
            result = _resolve_repeated_type('fooType', metaclass=self._meta_with('fooType'),
                                            cl=None, ctx=object())
        self.assertEqual(result, ("bytes", False))

    def test_resolve_repeated_type_unresolved_bytes_flagged(self):
        """A give-up 'bytes' (no metaclass, lowercase selector) IS element_unresolved."""
        from proto.repeated import _resolve_repeated_type
        result = _resolve_repeated_type("fooType", metaclass=None, cl=None)
        self.assertEqual(result, ("bytes", True))

    def test_resolve_repeated_type_no_name_suffix_guess(self):
        """IMP resolution unavailable + a name-matching class in the classlist
        must NOT be guessed by name suffix.  The unguarded/unflagged name-suffix
        fallback was removed 2026-06-09 → such a field falls to the safe
        ('bytes', element_unresolved=True), not the matching class."""
        from proto.repeated import _resolve_repeated_type
        meta = ObjcClass(
            vmaddr=0x8000, name='GEOThingMeta', is_meta=False,
            superclass_vmaddr=0, superclass_name=None, ro_flags=0,
            instance_size=32,
            methods=[ObjcMethod(name='fooType', types='', imp=0, is_relative=False)],
            ivars=[])
        # GEOFoo ends with the "Foo" suffix the old guess would have matched.
        name_match = ObjcClass(
            vmaddr=0x9000, name='GEOFoo', is_meta=False,
            superclass_vmaddr=0, superclass_name=None, ro_flags=0,
            instance_size=32, methods=[], ivars=[])
        # ctx=None → IMP resolution skipped → reaches the fallback.
        result = _resolve_repeated_type('fooType', metaclass=meta,
                                        cl=[name_match], ctx=None)
        self.assertEqual(result, ("bytes", True))

    def test_resolve_repeated_type_returns_local_class_from_imp(self):
        """A binary-local class read out of the +xyzType IMP is returned unchanged
        (no _CLASS_TO_PROTO entry)."""
        from proto.repeated import _resolve_repeated_type
        with patch('proto.repeated._class_from_type_method_imp',
                   return_value='GEOPDMapsResult'):
            result = _resolve_repeated_type('mapsResultType',
                                            metaclass=self._meta_with('mapsResultType'),
                                            cl=None, ctx=object())
        self.assertEqual(result, ("GEOPDMapsResult", False))

    def test_resolve_repeated_type_class_name_is_not_a_selector(self):
        """An uppercase 'selector' used to be treated as an already-resolved class name
        (the output of the removed name-suffix matcher).  It is now just an unknown
        selector -> the safe give-up."""
        from proto.repeated import _resolve_repeated_type
        result = _resolve_repeated_type("GEOPDMapsResult", metaclass=None, cl=None)
        self.assertEqual(result, ("bytes", True))

    def test_extract_writeto_collects_helper_addresses(self):
        """
        _extract_writeto_field_numbers must populate its
        helpers with at least the field numbers that are confirmed.
        This is a structural test using a minimal mock — the helper addresses
        themselves are arbitrary, but the keys must match the confirmed fields.
        """
        from proto.writeto import _extract_writeto_field_numbers
        from macho.classlist import ObjcClass, ObjcIvar, ObjcMethod
        # A class where get_method("writeTo:") returns None — no binary needed,
        # _extract_writeto_field_numbers returns {} gracefully.
        cls = ObjcClass(
            vmaddr=0x1000, name="GEOMockMsg", is_meta=False,
            superclass_vmaddr=0, superclass_name=None, ro_flags=0,
            instance_size=32,
        )
        ivars = [ObjcIvar(name="_x", type_enc="i", offset=8, size=4)]
        # Pass a None context — the function handles it gracefully via try/except
        try:
            walk = _extract_writeto_field_numbers(None, cls, ivars)
            result, helpers = walk.numbers, walk.helpers
        except Exception:
            result, helpers = {}, {}
        # Invariant: every key in helpers must also appear in result
        for k in helpers:
            self.assertIn(k, result,
                          f"Helper key {k!r} not in confirmed field numbers")

    def test_find_string_write_helper_from_nsstring_ivar(self):
        """
        _find_string_write_helper must return the helper VA for a @"NSString"
        ivar when it exists in the confirmed-helpers dict.
        """
        from proto.write_helpers import _find_string_write_helper
        from macho.classlist import ObjcIvar
        ivars = [
            ObjcIvar(name="_foo", type_enc="i", offset=8, size=4),
            ObjcIvar(name="_bar", type_enc='@"NSString"', offset=16, size=8),
            ObjcIvar(name="_baz", type_enc='@"NSArray"', offset=24, size=8),
        ]
        helpers = {"_foo": 0x1000, "_bar": 0x2000, "_baz": 0x3000}
        result = _find_string_write_helper(helpers, ivars, set())
        self.assertEqual(result, 0x2000,
                         "String helper should come from the @NSString ivar")

    def test_find_string_write_helper_returns_none_when_no_string_ivar(self):
        """When no @"NSString" ivar is present, return None."""
        from proto.write_helpers import _find_string_write_helper
        from macho.classlist import ObjcIvar
        ivars = [
            ObjcIvar(name="_x", type_enc="i", offset=8, size=4),
            ObjcIvar(name="_arr", type_enc='@"NSArray"', offset=16, size=8),
        ]
        helpers = {"_x": 0x1000, "_arr": 0x2000}
        result = _find_string_write_helper(helpers, ivars, set())
        self.assertIsNone(result)

    def test_memory_bind_name_for_returns_none_when_no_fixups(self):
        """
        bind_name_for should return None for an arbitrary address when the
        binary has no LC_DYLD_CHAINED_FIXUPS (or no bind entries there).
        Verified with the minimal Mach-O stub used elsewhere in the suite.
        """
        import struct
        from macho.memory import BinaryContext
        # Build minimal arm64 Mach-O with 0 load commands
        hdr = struct.pack('<IIIIIIII',
                          0xFEEDFACF,          # magic
                          0x0100000C,          # CPU_TYPE_ARM64
                          0x00000000,          # cpusubtype
                          0x6,                 # MH_DYLIB
                          0, 0, 0, 0)          # ncmds=0, sizeofcmds=0, flags=0, reserved=0
        ctx = BinaryContext(hdr)
        result = ctx.bind_name_for(0x1000)
        self.assertIsNone(result, "bind_name_for should return None when no bind table")


# ══════════════════════════════════════════════════════════════════════════════
# 11. No name-based element-class guess — _repeated_element_type
# ══════════════════════════════════════════════════════════════════════════════

class TestRepeatedElementTypeSelector(unittest.TestCase):
    """
    _repeated_element_type only ever names the ``+[Cls xyzType]`` SELECTOR (or gives
    up with 'bytes').  It used to have a second strategy that guessed the element class
    from the field name (strip the plural -s, capitalise, accept a unique classlist
    name ending with it).  That guess typed fields wrongly -- the PDComponent.values
    ambiguity bug, then GEOPDSSearchEvChargingParameters.networks (a repeated string)
    -> GEOLogMsgEventNetwork -- and was deleted 2026-10-13; the class now comes from
    the binary (readFrom dispatch / class-reference lever) or the field stays bytes.
    """

    def _meta(self, *selectors):
        return ObjcClass(
            vmaddr=0x9000, name="GEOPDComponent_meta", is_meta=True,
            superclass_vmaddr=0, superclass_name=None, ro_flags=0, instance_size=8,
            methods=[ObjcMethod(name=n, types='', imp=0x5000, is_relative=False)
                     for n in selectors])

    def test_no_metaclass_method_is_bytes_even_with_a_unique_suffix_class(self):
        """A class ending in 'MapsResult' exists, but there is no +mapsResultType
        method: no name guess -> 'bytes'."""
        from proto.repeated import _repeated_element_type
        ivar = ObjcIvar(name="_mapsResults", type_enc='@"NSArray"', offset=8, size=8)
        self.assertEqual(_repeated_element_type(ivar, metaclass=None), "bytes")
        self.assertEqual(
            _repeated_element_type(ivar, metaclass=self._meta("otherType")), "bytes")

    def test_signature_has_no_classlist_parameter(self):
        """The classlist was only needed by the removed name-suffix matcher."""
        import inspect
        from proto.repeated import _repeated_element_type
        self.assertNotIn("cl", inspect.signature(_repeated_element_type).parameters)

    def test_metaclass_selector_is_returned(self):
        from proto.repeated import _repeated_element_type
        ivar = ObjcIvar(name="_values", type_enc='@"NSArray"', offset=8, size=8)
        self.assertEqual(
            _repeated_element_type(ivar, metaclass=self._meta("valuesType")),
            "valuesType")

    def test_singular_selector_form_is_found(self):
        from proto.repeated import _repeated_element_type
        ivar = ObjcIvar(name="_mapsResults", type_enc='@"NSArray"', offset=8, size=8)
        self.assertEqual(
            _repeated_element_type(ivar, metaclass=self._meta("mapsResultType")),
            "mapsResultType")


# ══════════════════════════════════════════════════════════════════════════════
# 12. +xyzType IMP resolution end to end (formerly the "IMP-scan pool" test)
# ══════════════════════════════════════════════════════════════════════════════

class TestMetaclassTypeMethodResolution(unittest.TestCase):
    """
    Integration regression test: ``GEOPDComponent._values`` has a ``+valuesType``
    metaclass method whose IMP loads the class reference ``GEOPDComponentValue``.
    The field must be typed from that IMP -- not from a name match, which would be
    ambiguous (``GEODefaultsDBValue`` is also a ``*Value`` class and sorts first).

    History: this guarded the removal of the pool gate for the IMP-scan pool and the
    uniqueness guard of the name-suffix matcher.  Both mechanisms are gone (the pool
    refinement and the matcher were deleted 2026-10-13); the test now pins the
    behaviour they were protecting.

    This test constructs a minimal but self-consistent binary context where:
      * ``GEODefaultsDBValue`` (alphabetically first, wrong) is in the classlist
      * ``GEOPDComponentValue`` (correct) is also in the classlist
      * The metaclass ``+valuesType`` method IMP contains an ADRP+LDR sequence
        that points to GEOPDComponentValue's class data slot
      * ``instance_method_names`` is non-empty (simulating --cache)

    ``GEOPDComponent.values`` must be typed as ``GEOPDComponentValue``, not
    ``bytes`` or ``GEODefaultsDBValue``.
    """

    # ── Virtual-address layout ────────────────────────────────────────────────
    _IMP_VA             = 0x1000   # +valuesType method body
    _DATA_SLOT_VA       = 0x2000   # class-ref slot read by +valuesType
    _COMPONENT_VA       = 0x3000   # GEOPDComponentValue vmaddr
    _DEFAULTS_VA        = 0x4000   # GEODefaultsDBValue vmaddr (trap)
    _CLS_VA             = 0x5000   # GEOPDComponent vmaddr
    _META_VA            = 0x8000   # GEOPDComponent metaclass vmaddr

    @classmethod
    def _encode_adrp_ldr(cls) -> bytes:
        """
        Encode ``adrp x8, <data_page>; ldr x0, [x8, #<data_off>]; ret`` for the
        +valuesType IMP that returns the class pointer at _DATA_SLOT_VA.
        """
        import struct
        pc_page   = cls._IMP_VA   & ~0xFFF
        data_page = cls._DATA_SLOT_VA & ~0xFFF
        data_off  = cls._DATA_SLOT_VA &  0xFFF

        pages_delta = (data_page - pc_page) >> 12
        imm21  = pages_delta & 0x1FFFFF
        immlo  = imm21 & 0x3
        immhi  = (imm21 >> 2) & 0x7FFFF
        adrp_w = 0x90000000 | (immlo << 29) | (immhi << 5) | 8   # x8

        # ldr x0, [x8, #data_off] — unsigned scaled offset (8-byte scale)
        imm12  = data_off // 8
        ldr_w  = 0xF9400000 | (imm12 << 10) | (8 << 5) | 0       # x0 from [x8]

        return struct.pack('<III', adrp_w, ldr_w, 0xD65F03C0)    # ... ; ret

    def _make_fake_ctx(self):
        """Build a minimal BinaryContext-like object for the test."""
        import struct

        imp_bytes       = self._encode_adrp_ldr()              # 12 instruction bytes
        slot_ptr_bytes  = struct.pack('<Q', self._COMPONENT_VA) # pointer to correct class

        meta_va  = self._META_VA
        cls_va   = self._CLS_VA
        imp_va   = self._IMP_VA
        slot_va  = self._DATA_SLOT_VA
        comp_va  = self._COMPONENT_VA

        memory: dict = {
            imp_va:  imp_bytes,         # +valuesType instructions
            slot_va: slot_ptr_bytes,    # class-ref pointer → GEOPDComponentValue
        }

        class _FakeCtx:
            def has_section(self, seg, sect):
                return False

            def section(self, seg, sect):
                raise ValueError(f"no section {seg}/{sect} in test stub")

            def vmaddr_to_offset(self, va, length=1):
                # Only the IMP is mapped as executable; everything else raises.
                if imp_va <= va < imp_va + len(memory[imp_va]):
                    return va - imp_va
                raise ValueError(f"unmapped va 0x{va:x} in test stub")

            def read_bytes(self, va, length):
                # Return bytes from the memory map; fall back to zeros for
                # the disasm over-read (disasm asks for max_insns*4 bytes).
                for base, data in memory.items():
                    if base <= va and va + length <= base + len(data):
                        return data[va - base: va - base + length]
                # Partial over-read past end of IMP block: return zeros
                if imp_va <= va < imp_va + len(memory[imp_va]):
                    avail = memory[imp_va][va - imp_va:]
                    return avail + b'\x00' * (length - len(avail))
                raise ValueError(f"no test memory at 0x{va:x}")

            def read_ptr(self, va):
                # isa-pointer read: GEOPDComponent.vmaddr → metaclass.vmaddr
                if va == cls_va:
                    return meta_va
                # class-ref slot read: DATA_SLOT_VA → GEOPDComponentValue.vmaddr
                if va == slot_va:
                    return comp_va
                raise ValueError(f"unexpected read_ptr(0x{va:x}) in test stub")

            def read_u32(self, va):
                raise ValueError(f"unexpected read_u32(0x{va:x}) in test stub")

            def bind_name_for(self, va):
                return None   # not a bind entry

        return _FakeCtx()

    def _make_cl_and_cls(self):
        """
        Build the ClassList and subject ObjcClass for the test.

        The classlist intentionally places GEODefaultsDBValue *before*
        GEOPDComponentValue so alphabetical iteration order (the old bug
        trigger) is exercised.
        """
        from macho.classlist import ClassList

        # The "trap" class — same suffix 'Value', sorts first alphabetically.
        defaults_db = ObjcClass(
            vmaddr=self._DEFAULTS_VA,
            name="GEODefaultsDBValue",
            is_meta=False,
            superclass_vmaddr=0,
            superclass_name=None,
            ro_flags=0,
            instance_size=8,
        )
        # The correct element class.
        comp_value = ObjcClass(
            vmaddr=self._COMPONENT_VA,
            name="GEOPDComponentValue",
            is_meta=False,
            superclass_vmaddr=0,
            superclass_name=None,
            ro_flags=0,
            instance_size=8,
        )
        # Metaclass with a +valuesType method whose IMP is fully encoded.
        metaclass = ObjcClass(
            vmaddr=self._META_VA,
            name="GEOPDComponent_meta",
            is_meta=True,
            superclass_vmaddr=0,
            superclass_name=None,
            ro_flags=0,
            instance_size=8,
            methods=[
                ObjcMethod(name="valuesType", types='',
                           imp=self._IMP_VA, is_relative=False),
            ],
        )
        # Required proto instance methods (non-zero subset so
        # instance_method_names is considered "resolved" / non-empty).
        proto_methods = [
            'readFrom:', 'writeTo:', 'mergeFrom:',
            'copyTo:', 'copyWithZone:', 'isEqual:',
            'hash', 'description', 'dictionaryRepresentation',
            # field accessors (needed so the ivars pass _is_real_field_ivar)
            'type', 'setType:', 'values', 'addValue:',
        ]
        cls = ObjcClass(
            vmaddr=self._CLS_VA,
            name="GEOPDComponent",
            is_meta=False,
            superclass_vmaddr=0,
            superclass_name=None,
            ro_flags=0,
            instance_size=64,
            methods=[ObjcMethod(name=n, types='', imp=0, is_relative=False)
                     for n in proto_methods],
            ivars=[
                ObjcIvar(name="_type",   type_enc='i',          offset=8,  size=4),
                ObjcIvar(name="_values", type_enc='@"NSArray"', offset=16, size=8),
            ],
        )

        # Classlist order: defaults_db first so alphabetical trap fires if
        # a name-based guess would pick it.
        cl = ClassList([defaults_db, comp_value, metaclass, cls])
        return cl, cls

    def test_values_field_typed_as_component_value_not_defaults_db_value(self):
        """
        GEOPDComponent._values must be resolved to GEOPDComponentValue via the
        IMP-scan pool / +valuesType method, not GEODefaultsDBValue via a name guess.

        This exercises the full fix path:
          1. A name guess would be ambiguous (two classes share the 'Value' suffix).
          2. Pool is built unconditionally (gate removed).
          3. Pool Pass A: only GEOPDComponentValue matches 'Value' in the pool
             (GEODefaultsDBValue is never a +xyzType return value so it is
             absent from the pool).
          4. Field is correctly typed as GEOPDComponentValue.
        """
        ctx      = self._make_fake_ctx()
        cl, cls_ = self._make_cl_and_cls()

        class _NullST:
            def get(self, va):       return ''
            def find(self, s):       return []
            def all_in_section(self, s): return iter([])

        msg = extract_proto_message(ctx, _NullST(), cl, cls_)
        self.assertIsNotNone(msg, "extract_proto_message should succeed")

        field_types = {f.name: f.type_name for f in msg.fields}

        # The values field must resolve to the correct element class.
        self.assertIn('values', field_types,
                      "Expected a 'values' field in extracted message")
        self.assertEqual(
            field_types['values'], 'GEOPDComponentValue',
            f"'values' must resolve to GEOPDComponentValue via the IMP-scan pool, "
            f"not '{field_types.get('values')}' (GEODefaultsDBValue is the "
            f"alphabetically-first 'Value' class and would be returned by a "
            f"name-based guess)",
        )
        # Belt-and-suspenders: the trap class must not appear anywhere.
        for f in msg.fields:
            self.assertNotEqual(
                f.type_name, 'GEODefaultsDBValue',
                f"Field '{f.name}' must not be typed as the trap class "
                f"GEODefaultsDBValue",
            )

    def test_values_field_is_repeated(self):
        """The _values NSArray ivar must be classified as a REPEATED field."""
        ctx      = self._make_fake_ctx()
        cl, cls_ = self._make_cl_and_cls()

        class _NullST:
            def get(self, va):       return ''
            def find(self, s):       return []
            def all_in_section(self, s): return iter([])

        msg = extract_proto_message(ctx, _NullST(), cl, cls_)
        self.assertIsNotNone(msg)
        field_labels = {f.name: f.label for f in msg.fields}
        self.assertEqual(field_labels.get('values'), FieldLabel.REPEATED,
                         "NSArray ivar must be classified REPEATED")


if __name__ == '__main__':
    unittest.main(verbosity=2)
