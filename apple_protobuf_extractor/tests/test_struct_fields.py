#!/usr/bin/env python3
"""Tests for inline C-struct field recovery (TODO #37, ``proto/structfields.py``).

A field whose ivar is a C struct — by value (``{GEOPDTimeRange=...}``) or an array of them
(``^{GEOWiFiQualityTimeRange=...}``) — is a length-delimited sub-message on the wire, but no
ObjC class stands behind it, so the extractor used to emit ``bytes``.  The struct *name*, its
*member layout*, and each member's *field number* are all in the binary: the encoding names the
struct and lays out the members, and ``writeTo:`` serialises it through a small C function whose
body is ``has-bit test ; load [struct+offset] ; write(field#)`` per member.

Synthetic tests use instruction listings copied from the real iPhone 8 GeoServices disassembly,
with ``disasm`` monkeypatched to read them (no binary needed).  The live-gated tests run the
extractor on the dyld cache.
"""
import os
import unittest
from tests._listing import layout
from tests._fakes import NoImage, TextImage, name_marks

import artifacts
import proto.extractor as E
import proto.structfields as SF
import proto.function_body as FB
from proto.dispatch import listing_flow
import live_artifacts as V
from proto.models import FieldLabel
from macho.disasm import disasm
from tests._a64asm import assemble, FlowCtx


# ── fake instruction memory (same idiom as test_map_fields) ───────────────────


asm = layout


# Real listing (iPhone 8 GeoServices): the C function that serialises one GEOPDTimeRange
# {_duration @0, _startTime @4, has-bits @8}.  Member 1 (startTime, offset 4) is guarded by
# has-bit 1, member 2 (duration, offset 0) by has-bit 0 and is a tail call.
_PD_TIMERANGE_WRITER = (0x18c241b50, [
    ('stp', 'x20, x19, [sp, #-0x20]!'), ('stp', 'x29, x30, [sp, #0x10]'),
    ('add', 'x29, sp, #0x10'), ('mov', 'x19, x1'), ('mov', 'x20, x0'),
    ('ldrb', 'w8, [x0, #8]'), ('tbz', 'w8, #1, #0x18c241b80'),
    ('ldr', 'w1, [x20, #4]'), ('mov', 'x0, x19'), ('mov', 'w2, #1'),
    ('bl', '#0x18dbdac30'), ('ldrb', 'w8, [x20, #8]'),
    ('tbnz', 'w8, #0, #0x18c241b90'),
    ('ldp', 'x29, x30, [sp, #0x10]'), ('ldp', 'x20, x19, [sp], #0x20'), ('ret', ''),
])
_PD_TIMERANGE_WRITER_TAIL = (0x18c241b90, [
    ('ldr', 'w1, [x20]'), ('mov', 'x0, x19'), ('mov', 'w2, #2'),
    ('ldp', 'x29, x30, [sp, #0x10]'), ('ldp', 'x20, x19, [sp], #0x20'),
    ('b', '#0x18dbdac30'),
])


class _Patched(unittest.TestCase):
    def setUp(self):
        name_marks(self)

    def patch(self, fake):
        orig = FB.disasm
        FB.disasm = fake
        self.addCleanup(setattr, FB, 'disasm', orig)


class TestWriterExtent(_Patched):
    """structfields._writer_insns: a ``b`` inside the serialiser's extent (entry .. the next
    function entry) is one of its blocks, however far; a ``b`` to a function entry or past
    the next one is a tail call, however near."""

    def _addrs(self, blocks, entries=()):
        insns, fd = asm(*blocks)
        self.patch(fd)
        return {i.addr for i in SF._writer_insns(TextImage(_function_entries=set(entries)), 0x1000)}

    def test_a_far_block_of_the_same_function_is_followed(self):
        got = self._addrs([(0x1000, [('mov', 'x19, x0'), ('b', '#0x2000')]),
                           (0x2000, [('mov', 'x0, x19'), ('ret', '')])], entries=(0x1000, 0x3000))
        self.assertIn(0x2000, got)                     # 0x1000 bytes away, still this function

    def test_a_near_function_entry_is_a_tail_call(self):
        got = self._addrs([(0x1000, [('mov', 'x19, x0'), ('b', '#0x1040')]),
                           (0x1040, [('mov', 'x0, x19'), ('ret', '')])],
                          entries=(0x1000, 0x1040, 0x3000))
        self.assertNotIn(0x1040, got)

    def test_a_jump_past_the_next_entry_is_a_tail_call(self):
        got = self._addrs([(0x1000, [('mov', 'x19, x0'), ('b', '#0x3100')]),
                           (0x3100, [('ret', '')])], entries=(0x1000, 0x3000))
        self.assertNotIn(0x3100, got)


class _SelectorsPatched(_Patched):
    """Also answers which selector each ``bl`` target sends (``None``: not a message send)."""

    def patch_selectors(self, selectors):
        orig = SF.stub_selector
        SF.stub_selector = lambda ctx, target: selectors.get(target)
        self.addCleanup(setattr, SF, 'stub_selector', orig)


# The selector stubs the real GeoServices listings below call, as resolved in the cache (the
# others -- objc_retainAutoreleasedReturnValue, objc_release... -- send no selector).  The
# synthetic listings use 0x3000 for setObject:forKey:, 0x3100 for the NSNumber box and 0x3200
# for the ARC return-value handshake.
_GEO_SELECTORS = {0x18db17fc0: 'setObject:forKey:', 0x18dafbee0: 'numberWithUnsignedInt:',
                  0x18dafbe20: 'numberWithInt:', 0x18dacae80: 'addObject:',
                  0x18daee0e0: 'initWithCapacity:', 0x18dade6e0: 'dictionary',
                  0x3000: 'setObject:forKey:', 0x3100: 'numberWithInt:'}
_BOX = [('bl', '#0x3100'), ('bl', '#0x3200'), ('mov', 'x2, x0')]


# ── @encode parsing ────────────────────────────────────────────────────────────


class TestParseStructEncoding(unittest.TestCase):
    def test_pointer_array_of_structs_with_anonymous_members(self):
        s = SF.parse_struct_encoding('^{GEOWiFiQualityTimeRange=II{?=b1b1}}')
        self.assertEqual(s.tag, 'GEOWiFiQualityTimeRange')
        self.assertTrue(s.is_array)
        self.assertEqual([(m.offset, m.code, m.name) for m in s.members],
                         [(0, 'I', None), (4, 'I', None)])

    def test_by_value_struct_carries_member_names(self):
        s = SF.parse_struct_encoding(
            '{GEOPDTimeRange="_duration"I"_startTime"I"_has"{?="duration"b1"startTime"b1}}')
        self.assertEqual(s.tag, 'GEOPDTimeRange')
        self.assertFalse(s.is_array)
        self.assertEqual([(m.offset, m.name) for m in s.members],
                         [(0, '_duration'), (4, '_startTime')])

    def test_member_offsets_follow_natural_alignment(self):
        s = SF.parse_struct_encoding('^{GEOActiveResourceFilter=dii{?=b1b1b1}}')
        self.assertEqual([(m.offset, m.code) for m in s.members],
                         [(0, 'd'), (8, 'i'), (12, 'i')])
        s = SF.parse_struct_encoding('{GEOPixelPoint="_x"d"_y"d"_z"i"_has"{?="z"b1}}')
        self.assertEqual([m.offset for m in s.members], [0, 8, 16])

    def test_not_a_wire_struct_is_rejected(self):
        # (A flat struct such as a lock parses fine: only a begin-mark site whose writer
        # matches the layout ever makes one a message.)
        for enc in ('^{sqlite3=}', '@"NSData"', 'I', '{?=b1b1}',
                    '^{GeoCodecsConnectivityJunction=II^{GeoCodecsPointFeature}QQ}',
                    '{GEOOrientedPosition="position"{?="x"d"y"d"z"d}"yaw"f"pitch"f"roll"f}'):
            self.assertIsNone(SF.parse_struct_encoding(enc), enc)


# ── the struct's own C serialiser ──────────────────────────────────────────────


class TestDecodeStructWriter(_Patched):
    def test_members_numbers_and_helpers_are_read_from_the_writer(self):
        _, fake = asm(_PD_TIMERANGE_WRITER, _PD_TIMERANGE_WRITER_TAIL)
        self.patch(fake)
        writes = SF.decode_struct_writer(NoImage(), 0x18c241b50)
        self.assertEqual(sorted((w.offset, w.number, w.width) for w in writes),
                         [(0, 2, 4), (4, 1, 4)])

    def test_a_function_that_writes_no_member_is_not_a_struct_writer(self):
        _, fake = asm((0x1000, [('mov', 'x19, x1'), ('bl', '#0x2000'), ('ret', '')]))
        self.patch(fake)
        self.assertEqual(SF.decode_struct_writer(NoImage(), 0x1000), [])


class TestMatchWritesToLayout(unittest.TestCase):
    def setUp(self):
        self.layout = SF.parse_struct_encoding(
            '{GEOPDTimeRange="_duration"I"_startTime"I"_has"{?="duration"b1"startTime"b1}}')

    def test_every_member_written_once_with_the_right_width_is_accepted(self):
        w = [SF.MemberWrite(0, 2, 0x1, 4), SF.MemberWrite(4, 1, 0x1, 4)]
        self.assertEqual(SF.match_layout(self.layout, w), {0: 2, 4: 1})

    def test_a_missing_member_rejects_the_struct(self):
        self.assertIsNone(SF.match_layout(self.layout, [SF.MemberWrite(0, 2, 0x1, 4)]))

    def test_a_width_mismatch_rejects_the_struct(self):
        w = [SF.MemberWrite(0, 2, 0x1, 8), SF.MemberWrite(4, 1, 0x1, 4)]
        self.assertIsNone(SF.match_layout(self.layout, w))

    def test_a_write_at_an_unknown_offset_rejects_the_struct(self):
        w = [SF.MemberWrite(0, 2, 0x1, 4), SF.MemberWrite(4, 1, 0x1, 4),
             SF.MemberWrite(6, 3, 0x1, 4)]
        self.assertIsNone(SF.match_layout(self.layout, w))


# Real listing: -[GEOPDDeparturePredicate writeTo:] — field 1 is the by-value GEOPDTimeRange,
# serialised as begin(1) ; sub-writer(&self->_timeRange, writer) ; end.
_PD_DEPARTURE_WRITETO = (0x18c27d07c, [
    ('sub', 'sp, sp, #0x40'), ('stp', 'x22, x21, [sp, #0x10]'),
    ('stp', 'x20, x19, [sp, #0x20]'), ('stp', 'x29, x30, [sp, #0x30]'),
    ('add', 'x29, sp, #0x30'), ('mov', 'x20, x0'), ('bl', '#0x18dbdbf74'),
    ('mov', 'x19, x0'), ('adrp', 'x8, #0x1dcfb2000'), ('ldrsw', 'x21, [x8, #0x260]'),
    ('ldrb', 'w8, [x20, x21]'), ('tbz', 'w8, #0, #0x18c27d0e4'),
    ('str', 'xzr, [sp, #8]'), ('add', 'x1, sp, #8'), ('mov', 'x0, x19'), ('mov', 'w2, #1'),
    ('bl', '#0x18dbdab88'),                                               # begin, field 1
    ('adrp', 'x8, #0x1dcfb2000'), ('ldrsw', 'x8, [x8, #0x25c]'), ('add', 'x0, x20, x8'),
    ('mov', 'x1, x19'), ('bl', '#0x18c241b50'),                           # the struct writer
    ('add', 'x1, sp, #8'), ('mov', 'x0, x19'), ('bl', '#0x18dbdab94'),    # end
    ('ldrb', 'w8, [x20, x21]'), ('tbz', 'w8, #1, #0x18c27d100'),
    ('ldr', 'w1, [x20, x8]'), ('mov', 'x0, x19'), ('mov', 'w2, #2'), ('bl', '#0x18dbdac30'),
    ('ret', ''),
])


class TestAnalyzeBracket(_Patched):
    def _insns(self):
        insns, fake = asm(_PD_DEPARTURE_WRITETO)
        self.patch(fake)
        begin = next(i for i, x in enumerate(insns)
                     if x.mnemonic == 'bl' and x.op_str == '#0x18dbdab88')
        return insns, begin

    def test_field_number_and_struct_writer_callee_of_a_bracketed_member(self):
        insns, begin = self._insns()
        b = SF.analyze_bracket(None, insns, begin)
        self.assertEqual(b.number, 1)
        self.assertEqual(b.callees, (0x18c241b50,))

    def test_a_begin_with_no_end_mark_is_rejected(self):
        insns, begin = self._insns()
        cut = [x for x in insns if x.op_str != '#0x18dbdab94']
        self.assertIsNone(SF.analyze_bracket(None, cut, begin))

    def test_not_a_begin_mark_is_rejected(self):
        insns, _ = self._insns()
        self.assertIsNone(SF.analyze_bracket(None, insns, 0))

    def test_a_mark_is_the_runtime_s_by_name_not_a_call_of_its_shape(self):
        # (the same call, a frame scratch in x1 and a field number, to a function not named
        # _PBDataWriterPlaceMark)
        from unittest import mock
        import proto.submessage_marks as SM
        insns, begin = self._insns()
        with mock.patch.object(SM, "callee_name", lambda ctx, va: None):
            self.assertIsNone(SF.analyze_bracket(None, insns, begin))


# Real listing: the dictionary-representation function of GEOWiFiQualityTimeRange — per member
# it boxes the value loaded from [x20+off] into x2 and files it under the CFString key in x3.
_WIFI_TIMERANGE_DICTREP = (0x18cb8cdb8, [
    ('stp', 'x22, x21, [sp, #-0x30]!'), ('stp', 'x20, x19, [sp, #0x10]'),
    ('stp', 'x29, x30, [sp, #0x20]'), ('add', 'x29, sp, #0x20'), ('mov', 'x20, x0'),
    ('adrp', 'x8, #0x1dcfa5000'), ('ldr', 'x0, [x8, #0x800]'), ('bl', '#0x18dade6e0'),
    ('bl', '#0x18dbdbd58'), ('mov', 'x19, x0'), ('ldrb', 'w8, [x20, #8]'),
    ('adrp', 'x22, #0x1dcfa5000'), ('tbz', 'w8, #0, #0x18cb8ce1c'),
    ('ldr', 'x0, [x22, #0x838]'), ('ldr', 'w2, [x20]'), ('bl', '#0x18dafbee0'),
    ('bl', '#0x18dbdbd58'), ('mov', 'x21, x0'), ('adrp', 'x3, #0x1d5fda000'),
    ('add', 'x3, x3, #0xae0'), ('mov', 'x0, x19'), ('mov', 'x2, x21'), ('bl', '#0x18db17fc0'),
    ('bl', '#0x18dbdbe78'), ('ldrb', 'w8, [x20, #8]'),
])
_WIFI_TIMERANGE_DICTREP_2 = (0x18cb8ce1c, [
    ('tbz', 'w8, #1, #0x18cb8ce4c'),
    ('ldr', 'x0, [x22, #0x838]'), ('ldr', 'w2, [x20, #4]'), ('bl', '#0x18dafbee0'),
    ('bl', '#0x18dbdbd58'), ('mov', 'x20, x0'), ('adrp', 'x3, #0x1d5fda000'),
    ('add', 'x3, x3, #0xb00'), ('mov', 'x0, x19'), ('mov', 'x2, x20'), ('bl', '#0x18db17fc0'),
    ('bl', '#0x18dbdbe6c'),
])
_WIFI_TIMERANGE_DICTREP_3 = (0x18cb8ce4c, [
    ('mov', 'x0, x19'), ('ldp', 'x29, x30, [sp, #0x20]'), ('ldp', 'x20, x19, [sp, #0x10]'),
    ('ldp', 'x22, x21, [sp], #0x30'), ('b', '#0x18dbdbd40'),
])


def _held(table, va):
    if va not in table:
        raise ValueError(f"{va:#x} not mapped")
    return table[va]


class _NoStringsMixin(NoImage):
    """What the data-flow analysis may ask of ANY ctx: no named sections, no raw C strings."""

    def read_cstring(self, va, max_len=4096):
        raise ValueError(f"no string at {va:#x}")


class _CfCtx(_NoStringsMixin):
    """A ctx exposing two key constants (``from``/``to``).  Like every test ctx here it has no
    named sections, so a string constant is read as a direct C string at its address (the
    storage a binary without ``__cfstring`` uses; macho.strings.read_cfstring_text)."""
    TEXT = {0x1d5fdaae0: (0x2000, b'from'), 0x1d5fdab00: (0x2010, b'to')}

    def read_cstring(self, va, max_len=4096):
        if va in self.TEXT:
            return self.TEXT[va][1].decode()[:max_len]
        raise ValueError(f"no string at {va:#x}")

    def is_variable(self, vmaddr):        # no program data, no binds
        return False

    # an address nothing holds raises ValueError, as BinaryContext's reads do
    def read_ptr(self, va):
        return _held(self.TEXT, va - 16)[0]

    def read_u64(self, va):
        return len(_held(self.TEXT, va - 24)[1])

    def read_bytes(self, va, n):
        for p, b in self.TEXT.values():
            if p == va:
                return b[:n]
        raise ValueError(f"{va:#x} not mapped")


def _keys(members):
    """``{member offset: dictionary key}`` of decoded dictRep members."""
    return {off: md.key for off, md in members.items() if md.key}


class TestAKeyIsAnyIdentifier(unittest.TestCase):
    """A dictionary-representation key is an identifier of any length (iPhone 8 GeoServices
    holds 28 identifier CFStrings longer than 64 characters)."""

    def test_long_key_read(self):
        from unittest import mock
        key = "place_card_place_action_details_transit_place_card_transit_departure_sequence_usage_direct"
        with mock.patch.object(SF, "read_cfstring_text", lambda ctx, va: {1: key, 2: "a b"}[va]):
            self.assertEqual(SF._cfstring(None, 1), key)
            self.assertIsNone(SF._cfstring(None, 2))


class TestDecodeDictrepKeys(_SelectorsPatched):
    def setUp(self):
        self.patch_selectors(_GEO_SELECTORS)

    def test_each_key_names_the_member_its_call_files(self):
        _, fake = asm(_WIFI_TIMERANGE_DICTREP, _WIFI_TIMERANGE_DICTREP_2, _WIFI_TIMERANGE_DICTREP_3)
        self.patch(fake)
        self.assertEqual(_keys(SF.decode_dictrep_members(_CfCtx(), 0x18cb8cdb8, {0, 4})), {0: 'from', 4: 'to'})

    def test_a_key_that_is_not_an_identifier_is_ignored(self):
        _, fake = asm(_WIFI_TIMERANGE_DICTREP, _WIFI_TIMERANGE_DICTREP_2, _WIFI_TIMERANGE_DICTREP_3)
        self.patch(fake)
        ctx = _CfCtx()
        ctx.TEXT = {0x1d5fdaae0: (0x2000, b'a b'), 0x1d5fdab00: (0x2010, b'to')}
        self.assertEqual(_keys(SF.decode_dictrep_members(ctx, 0x18cb8cdb8, {0, 4})), {4: 'to'})

    def test_a_function_with_no_keys_is_not_a_dictionary_representation(self):
        _, fake = asm(_PD_TIMERANGE_WRITER, _PD_TIMERANGE_WRITER_TAIL)
        self.patch(fake)
        self.assertEqual(_keys(SF.decode_dictrep_members(_CfCtx(), 0x18c241b50, {0, 4})), {})

    def test_json_dependent_key_takes_the_camel_case_spelling(self):
        # real GEOPBTransitTimeRange dictrep: ``forJSON ? @"startTime" : @"start_time"`` is
        # chosen with a csel, the two CFStrings built by separate adrp+add pairs
        ctx = _CfCtx()
        ctx.TEXT = {0x1d5fdaae0: (0x2000, b'start_time'), 0x1d5fdab00: (0x2010, b'startTime')}
        _, fake = asm((0x1000, [
            ('mov', 'x20, x1'), ('mov', 'x21, x0'), ('ldr', 'w2, [x21, #4]'), *_BOX,
            ('adrp', 'x8, #0x1d5fda000'), ('add', 'x8, x8, #0xae0'),
            ('adrp', 'x9, #0x1d5fda000'), ('add', 'x9, x9, #0xb00'),
            ('cmp', 'w20, #0'), ('csel', 'x3, x9, x8, ne'), ('bl', '#0x3000'), ('ret', '')]))
        self.patch(fake)
        self.assertEqual(_keys(SF.decode_dictrep_members(ctx, 0x1000, {0, 4})), {4: 'startTime'})


# Real listing: -[GEOTransitRouteUpdateRequest writeTo:] field 10, a by-value GEOSessionID
# {_high @0, _low @8} serialised INLINE: base = self + ivar offset, then one write per member.
_SESSIONID_WRITETO = (0x18c52df40, [
    ('adrp', 'x8, #0x1e1dd6000'), ('ldrsw', 'x22, [x8, #0x2fc]'), ('ldrh', 'w8, [x21, x22]'),
    ('tbz', 'w8, #0, #0x18c52dfa0'), ('str', 'xzr, [sp, #0x48]'), ('add', 'x1, sp, #0x48'),
    ('mov', 'x0, x19'), ('mov', 'w2, #0xa'), ('bl', '#0x18dbdab88'),
    ('adrp', 'x8, #0x1e1dd6000'), ('ldrsw', 'x8, [x8, #0x328]'), ('add', 'x23, x21, x8'),
    ('ldr', 'x1, [x23, #8]'), ('mov', 'x0, x19'), ('mov', 'w2, #1'), ('bl', '#0x18dbdac3c'),
    ('ldr', 'x1, [x23]'), ('mov', 'x0, x19'), ('mov', 'w2, #2'), ('bl', '#0x18dbdac3c'),
    ('add', 'x1, sp, #0x48'), ('mov', 'x0, x19'), ('bl', '#0x18dbdab94'),
    ('ldrh', 'w8, [x21, x22]'), ('ret', ''),
])

# Real listing: -[GEOTileSetVersion writeTo:] field 4, an array of GEOGenericTile
# {u32 @0, u32 @4, i32 @8, has-bits @0xc}.  The offset variable is hoisted above the loop and
# the has-bit jump table puts two members out of line, AFTER the loop's back-edge.
_GENERICTILE_WRITETO = (0x18d2f8ee8, [
    ('mov', 'x24, #0'), ('mov', 'x25, #0'), ('adrp', 'x8, #0x1e1ddf000'),
    ('ldrsw', 'x26, [x8, #0xbe4]'), ('str', 'xzr, [sp, #8]'), ('add', 'x1, sp, #8'),
    ('mov', 'x0, x19'), ('mov', 'w2, #4'), ('bl', '#0x18dbdab88'),
    ('ldr', 'x27, [x21, x26]'), ('add', 'x28, x27, x24'), ('ldrb', 'w8, [x28, #0xc]'),
    ('tbnz', 'w8, #2, #0x18d2f8f58'), ('tbnz', 'w8, #1, #0x18d2f8f70'),
    ('tbz', 'w8, #0, #0x18d2f8f34'),
    ('ldr', 'w1, [x27, x24]'), ('mov', 'x0, x19'), ('mov', 'w2, #3'), ('bl', '#0x18dbdac30'),
    ('add', 'x1, sp, #8'), ('mov', 'x0, x19'), ('bl', '#0x18dbdab94'),
    ('add', 'x25, x25, #1'), ('ldr', 'x8, [x21, x23]'), ('add', 'x24, x24, #0x10'),
    ('cmp', 'x25, x8'), ('b.lo', '#0x18d2f8ef8'), ('b', '#0x18d2f8f90'),
    ('ldr', 'w1, [x28, #8]'), ('mov', 'x0, x19'), ('mov', 'w2, #1'), ('bl', '#0x18dbdabd0'),
    ('ldrb', 'w8, [x28, #0xc]'), ('tbz', 'w8, #1, #0x18d2f8f20'),
    ('add', 'x8, x27, x24'), ('ldr', 'w1, [x8, #4]'), ('mov', 'x0, x19'), ('mov', 'w2, #2'),
    ('bl', '#0x18dbdac30'), ('ldrb', 'w8, [x28, #0xc]'), ('tbnz', 'w8, #0, #0x18d2f8f24'),
    ('b', '#0x18d2f8f34'),
    ('ret', ''),
])


class TestInlineStructWrites(_Patched):
    def _bracket(self, listing, layout_enc, ivar_off_var):
        insns, fake = asm(listing)
        self.patch(fake)
        begin = next(i for i, x in enumerate(insns)
                     if x.mnemonic == 'bl' and x.op_str == '#0x18dbdab88')
        br = SF.analyze_bracket(None, insns, begin)
        return insns, br, SF.parse_struct_encoding(layout_enc), (lambda a: a == ivar_off_var)

    def test_by_value_struct_members_are_read_from_the_inline_writes(self):
        insns, br, layout, var = self._bracket(
            _SESSIONID_WRITETO, '{GEOSessionID="_high"Q"_low"Q}', 0x1e1dd6328)
        self.assertEqual((br.number, br.callees), (10, ()))
        w = SF.decode_inline_writes(None, insns, br, var, layout)
        self.assertEqual(SF.match_layout(layout, w), {8: 1, 0: 2})

    def test_array_members_including_out_of_line_ones_are_found(self):
        insns, br, layout, var = self._bracket(
            _GENERICTILE_WRITETO, '^{GEOGenericTile=IIi{?=b1b1b1}}', 0x1e1ddfbe4)
        self.assertEqual(br.number, 4)
        w = SF.decode_inline_writes(None, insns, br, var, layout)
        self.assertEqual(SF.match_layout(layout, w), {0: 3, 8: 1, 4: 2})

    def test_a_double_member_is_traced_by_data_flow_not_by_distance(self):
        # The double is loaded into a callee-saved register long before its write and copied
        # into d0 just ahead of it (number in w1, value in v0): reaching definitions through
        # the fmov find the member however far back the load sits.
        listing = (0x1000, [
            ('str', 'xzr, [sp, #0x48]'), ('add', 'x1, sp, #0x48'), ('mov', 'x0, x19'),
            ('mov', 'w2, #0xa'), ('bl', '#0x18dbdab88'),
            ('adrp', 'x8, #0x1e1dd6000'), ('ldrsw', 'x8, [x8, #0x328]'), ('add', 'x23, x21, x8'),
            ('ldr', 'd8, [x23]'), *[('add', 'x9, x9, #1')] * 12, ('fmov', 'd0, d8'),
            ('mov', 'x0, x19'), ('mov', 'w1, #1'), ('bl', '#0x18dbdac40'),
            ('ldr', 'w1, [x23, #8]'), ('mov', 'x0, x19'), ('mov', 'w2, #2'), ('bl', '#0x18dbdac3c'),
            ('add', 'x1, sp, #0x48'), ('mov', 'x0, x19'), ('bl', '#0x18dbdab94'), ('ret', '')])
        insns, br, layout, var = self._bracket(listing, '{GEOFix="_lat"d"_n"i}', 0x1e1dd6328)
        self.assertEqual(br.number, 10)
        w = SF.decode_inline_writes(None, insns, br, var, layout)
        self.assertEqual(SF.match_layout(layout, w), {0: 1, 8: 2})

    def test_wrong_offset_variable_binds_nothing(self):
        insns, br, layout, _ = self._bracket(
            _SESSIONID_WRITETO, '{GEOSessionID="_high"Q"_low"Q}', 0x1e1dd6328)
        self.assertEqual(
            SF.decode_inline_writes(None, insns, br, lambda a: a == 0xdead0000, layout), [])


# Real listing: the loop in -[GEOCoarseLocationRing _dictionaryRepresentation:] that builds one
# {lat, lng} dictionary per element of the GEOCoarseLocationPoint array — the compiler inlined the
# struct's dictionary representation, so the members are reached through the ivar offset variable.
_RING_DICTREP = (0x18c50dd90, [
    ('adrp', 'x8, #0x1e1dd6000'), ('ldrsw', 'x8, [x8, #0x24c]'), ('ldr', 'x25, [x20, x8]'),
    ('ldr', 'x0, [x24, #0x800]'), ('bl', '#0x18dade6e0'), ('bl', '#0x18dbdbd58'),
    ('mov', 'x22, x24'), ('mov', 'x24, x0'), ('ldr', 'x0, [x27, #0x838]'),
    ('add', 'x26, x25, x28'), ('ldr', 'w2, [x26]'), ('bl', '#0x18dafbe20'),
    ('bl', '#0x18dbdbd58'), ('mov', 'x25, x0'), ('mov', 'x0, x24'), ('mov', 'x2, x25'),
    ('adrp', 'x3, #0x1d5fa1000'), ('add', 'x3, x3, #0x260'), ('bl', '#0x18db17fc0'),
    ('bl', '#0x18dbdbea8'), ('ldr', 'x0, [x27, #0x838]'), ('ldr', 'w2, [x26, #4]'),
    ('bl', '#0x18dafbe20'), ('bl', '#0x18dbdbd58'), ('mov', 'x25, x0'), ('mov', 'x0, x24'),
    ('mov', 'x2, x25'), ('adrp', 'x3, #0x1d5fa1000'), ('add', 'x3, x3, #0x280'),
    ('bl', '#0x18db17fc0'), ('bl', '#0x18dbdbea8'), ('ret', ''),
])


class TestInlineDictrepNames(_SelectorsPatched):
    def setUp(self):
        self.patch_selectors(_GEO_SELECTORS)

    def test_keys_are_paired_through_the_ivar_offset_variable(self):
        insns, fake = asm(_RING_DICTREP)
        self.patch(fake)
        ctx = _CfCtx()
        ctx.TEXT = {0x1d5fa1260: (0x2000, b'lat'), 0x1d5fa1280: (0x2010, b'lng')}
        layout = SF.parse_struct_encoding('^{GEOCoarseLocationPoint=ii}')
        self.assertEqual(
            _keys(SF.decode_inline_dictrep_members(ctx, insns, lambda a: a == 0x1e1dd624c, layout)),
            {0: 'lat', 4: 'lng'})

    def test_another_ivars_loop_is_not_paired(self):
        insns, fake = asm(_RING_DICTREP)
        self.patch(fake)
        layout = SF.parse_struct_encoding('^{GEOCoarseLocationPoint=ii}')
        self.assertEqual(
            _keys(SF.decode_inline_dictrep_members(_CfCtx(), insns, lambda a: a == 0xdead0000, layout)), {})


# Real listing: -[GEOFlyoverRegionVersions _dictionaryRepresentation:] 0x18c502e6c, the loop that
# builds one dictionary per GEOFlyoverRegion {u32 @0, u32 @4, u32 @8, has-bits @0xc}, inlined.
# Member 0's key is chosen BEFORE the loop by the JSON flag (x1 -> w22: ``cmp w22,#0; csel
# x8,x9,x8,ne`` between @"dataVersion" and @"data_version"), spilled to [sp,#8] and reloaded
# into x3 at its setObject:forKey: (0x18c502fc4); members 4 and 8 build their keys in x3.
_FLYOVER_DICTREP = (0x18c502e6c, [
    ('sub', 'sp, sp, #0x70'), ('stp', 'x28, x27, [sp, #0x10]'), ('stp', 'x26, x25, [sp, #0x20]'),
    ('stp', 'x24, x23, [sp, #0x30]'), ('stp', 'x22, x21, [sp, #0x40]'), ('stp', 'x20, x19, [sp, #0x50]'),
    ('stp', 'x29, x30, [sp, #0x60]'), ('add', 'x29, sp, #0x60'), ('cbz', 'x0, #0x18c503054'),
    ('mov', 'x22, x1'), ('mov', 'x20, x0'), ('adrp', 'x8, #0x1dcfa5000'),
    ('ldr', 'x0, [x8, #0x800]'), ('bl', '#0x18dade6e0'), ('bl', '#0x18dbdbd58'),
    ('mov', 'x19, x0'), ('adrp', 'x24, #0x1dcfaf000'), ('ldrsw', 'x8, [x24, #0x424]'),
    ('ldr', 'x8, [x20, x8]'), ('cbz', 'x8, #0x18c503030'), ('str', 'x19, [sp]'),
    ('adrp', 'x8, #0x1dcfa5000'), ('ldr', 'x0, [x8, #0x7a8]'), ('bl', '#0x18dbdbd04'),
    ('ldrsw', 'x8, [x24, #0x424]'), ('ldr', 'x2, [x20, x8]'), ('bl', '#0x18daee0e0'),
    ('mov', 'x21, x0'), ('ldrsw', 'x8, [x24, #0x424]'), ('ldr', 'x8, [x20, x8]'),
    ('cbz', 'x8, #0x18c503014'), ('mov', 'x19, #0'), ('mov', 'x23, #0'),
    ('adrp', 'x8, #0x1d5f9f000'), ('add', 'x8, x8, #0x6c0'), ('adrp', 'x9, #0x1d5f9f000'),
    ('add', 'x9, x9, #0x6a0'), ('cmp', 'w22, #0'), ('csel', 'x8, x9, x8, ne'),
    ('str', 'x8, [sp, #8]'), ('adrp', 'x27, #0x1dcfa5000'), ('mov', 'x22, x24'),
    ('adrp', 'x8, #0x1dcfaf000'), ('ldrsw', 'x8, [x8, #0x428]'), ('ldr', 'x28, [x20, x8]'),
    ('adrp', 'x8, #0x1dcfa5000'), ('ldr', 'x0, [x8, #0x800]'), ('bl', '#0x18dade6e0'),
    ('bl', '#0x18dbdbd58'), ('mov', 'x25, x0'), ('add', 'x24, x28, x19'),
    ('ldrb', 'w8, [x24, #0xc]'), ('tbnz', 'w8, #0, #0x18c502fa8'), ('tbnz', 'w8, #1, #0x18c502fd8'),
    ('tbz', 'w8, #2, #0x18c502f78'), ('ldr', 'x0, [x27, #0x838]'), ('add', 'x8, x28, x19'),
    ('ldr', 'w2, [x8, #8]'), ('bl', '#0x18dafbee0'), ('bl', '#0x18dbdbd58'),
    ('mov', 'x26, x0'), ('mov', 'x0, x25'), ('mov', 'x2, x26'),
    ('adrp', 'x3, #0x1d5f9f000'), ('add', 'x3, x3, #0x6e0'), ('bl', '#0x18db17fc0'),
    ('bl', '#0x18dbdbeb4'), ('mov', 'x0, x21'), ('mov', 'x2, x25'),
    ('bl', '#0x18dacae80'), ('bl', '#0x18dbdbea8'), ('add', 'x23, x23, #1'),
    ('mov', 'x24, x22'), ('ldrsw', 'x8, [x22, #0x424]'), ('ldr', 'x8, [x20, x8]'),
    ('add', 'x19, x19, #0x10'), ('cmp', 'x23, x8'), ('b.lo', '#0x18c502f10'),
    ('b', '#0x18c503014'), ('ldr', 'x0, [x27, #0x838]'), ('ldr', 'w2, [x28, x19]'),
    ('bl', '#0x18dafbee0'), ('bl', '#0x18dbdbd58'), ('mov', 'x26, x0'),
    ('mov', 'x0, x25'), ('mov', 'x2, x26'), ('ldr', 'x3, [sp, #8]'),
    ('bl', '#0x18db17fc0'), ('bl', '#0x18dbdbeb4'), ('ldrb', 'w8, [x24, #0xc]'),
    ('tbz', 'w8, #1, #0x18c502f44'), ('ldr', 'x0, [x27, #0x838]'), ('add', 'x8, x28, x19'),
    ('ldr', 'w2, [x8, #4]'), ('bl', '#0x18dafbee0'), ('bl', '#0x18dbdbd58'),
    ('mov', 'x26, x0'), ('mov', 'x0, x25'), ('mov', 'x2, x26'),
    ('adrp', 'x3, #0x1d5f9f000'), ('add', 'x3, x3, #0x680'), ('bl', '#0x18db17fc0'),
    ('bl', '#0x18dbdbeb4'), ('ldrb', 'w8, [x24, #0xc]'), ('tbnz', 'w8, #2, #0x18c502f48'),
    ('b', '#0x18c502f78'), ('adrp', 'x3, #0x1d5f9f000'), ('add', 'x3, x3, #0x680'),
    ('ldr', 'x19, [sp]'), ('mov', 'x0, x19'), ('mov', 'x2, x21'),
    ('bl', '#0x18db17fc0'), ('bl', '#0x18dbdbe78'), ('mov', 'x0, x19'),
    ('ldp', 'x29, x30, [sp, #0x60]'), ('ldp', 'x20, x19, [sp, #0x50]'), ('ldp', 'x22, x21, [sp, #0x40]'),
    ('ldp', 'x24, x23, [sp, #0x30]'), ('ldp', 'x26, x25, [sp, #0x20]'), ('ldp', 'x28, x27, [sp, #0x10]'),
    ('add', 'sp, sp, #0x70'), ('b', '#0x18dbdbd40'), ('mov', 'x19, #0'),
    ('b', '#0x18c503030'),
])
# What the stubs it calls send (None: objc_retainAutoreleasedReturnValue / objc_release, no
# selector) and the CFString keys it uses, as resolved in the cache.
_FLYOVER_SELECTORS = _GEO_SELECTORS
_FLYOVER_KEYS = {0x1d5f9f6a0: 'dataVersion', 0x1d5f9f6c0: 'data_version', 0x1d5f9f6e0: 'version',
                 0x1d5f9f680: 'region'}


class TestKeysReadAtTheDictionaryCall(_SelectorsPatched):
    LAYOUT = '^{GEOFlyoverRegion=III{?=b1b1b1}}'

    def setUp(self):
        self.insns, fake = asm(_FLYOVER_DICTREP)
        self.patch(fake)
        self.patch_selectors(_FLYOVER_SELECTORS)
        self.ctx = _TextCtx(_FLYOVER_KEYS)

    def test_a_key_hoisted_by_the_json_flag_and_spilled_to_the_stack_names_its_member(self):
        layout = SF.parse_struct_encoding(self.LAYOUT)
        self.assertEqual(
            _keys(SF.decode_inline_dictrep_members(self.ctx, self.insns, lambda a: a == 0x1dcfaf428, layout)),
            {0: 'dataVersion', 4: 'region', 8: 'version'})


class TestPairingAtTheCall(_SelectorsPatched):
    SELS = {0x3000: 'setObject:forKey:', 0x3100: 'numberWithInt:'}     # 0x3200: ARC, no selector

    def pair(self, *lines):
        insns, fake = asm((0x1000, list(lines)))
        self.patch(fake)
        self.patch_selectors(self.SELS)
        loads = {k for k, i in enumerate(insns) if i.op_str == 'w2, [x20]'}
        return SF._pair_members(_CfCtx(), insns, lambda k: 0 if k in loads else None)

    BOX = [('ldr', 'w2, [x20]'), ('bl', '#0x3100'), ('bl', '#0x3200'), ('mov', 'x2, x0')]

    def test_the_key_is_the_one_x3_holds_at_the_call(self):
        # @"from" is built in x3 but overwritten by the reload of @"to" before the call
        members, unpaired = self.pair(
            ('sub', 'sp, sp, #0x20'), ('adrp', 'x8, #0x1d5fda000'), ('add', 'x8, x8, #0xb00'),
            ('str', 'x8, [sp, #8]'), *self.BOX,
            ('adrp', 'x3, #0x1d5fda000'), ('add', 'x3, x3, #0xae0'), ('ldr', 'x3, [sp, #8]'),
            ('bl', '#0x3000'), ('ret', ''))
        self.assertEqual((members, unpaired), ({0: SF.MemberDict('to', None)}, 0))

    def test_a_call_with_no_selector_is_followed_only_through_the_return_value_handshake(self):
        # x0 at the selectorless call is a copy, not the result of the call right before it:
        # nothing says that callee returns its argument, so the member is not paired
        members, _ = self.pair(
            ('sub', 'sp, sp, #0x20'), ('adrp', 'x8, #0x1d5fda000'), ('add', 'x8, x8, #0xb00'),
            ('str', 'x8, [sp, #8]'), ('ldr', 'w2, [x20]'), ('bl', '#0x3100'), ('mov', 'x19, x0'),
            ('mov', 'x0, x19'), ('bl', '#0x3200'), ('mov', 'x2, x0'), ('ldr', 'x3, [sp, #8]'),
            ('bl', '#0x3000'), ('ret', ''))
        self.assertEqual(members, {})

    def test_the_handshake_is_followed_to_the_boxed_member(self):
        members, _ = self.pair(
            ('sub', 'sp, sp, #0x20'), ('adrp', 'x8, #0x1d5fda000'), ('add', 'x8, x8, #0xb00'),
            ('str', 'x8, [sp, #8]'), *self.BOX, ('ldr', 'x3, [sp, #8]'),
            ('bl', '#0x3000'), ('ret', ''))
        self.assertEqual(members, {0: SF.MemberDict('to', None)})


class TestDecodeDictrepNamesRejectsLargerStructs(_Patched):
    def test_a_function_with_a_key_for_an_unknown_member_is_not_this_structs(self):
        # the dictrep of a 3-member struct, asked for a 2-member layout: its third key finds
        # no member at the layout's offsets, so the function is rejected, not truncated
        _, fake = asm((0x1000, [
            ('mov', 'x20, x0'), ('ldr', 'w2, [x20]'),
            ('adrp', 'x3, #0x1d5fda000'), ('add', 'x3, x3, #0xae0'), ('bl', '#0x3000'),
            ('ldr', 'w2, [x20, #4]'),
            ('adrp', 'x3, #0x1d5fda000'), ('add', 'x3, x3, #0xb00'), ('bl', '#0x3000'),
            ('ldr', 'w2, [x20, #8]'),
            ('adrp', 'x3, #0x1d5fda000'), ('add', 'x3, x3, #0xae0'), ('bl', '#0x3000'),
            ('ret', '')]))
        self.patch(fake)
        self.assertEqual(_keys(SF.decode_dictrep_members(_CfCtx(), 0x1000, {0, 4})), {})


# ── live: the dyld cache's GeoServices ─────────────────────────────────────────


def _extract(classes):
    """``({class_name: ProtoMessage}, messages)`` after the struct pass, for just *classes*."""
    loaded = V.load_cache("GeoServices")
    if loaded is None:
        return None
    ctx, st, cl = loaded
    msgs = [E.extract_proto_message(ctx, st, cl, cl.find(c)) for c in classes]
    SF.finalize_struct_fields(ctx, cl, msgs)
    return {m.class_name: m for m in msgs}


class TestLiveStructRecovery(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.by = _extract(['GEOPDDeparturePredicate', 'GEOPDTransitTripStopTimeFilter',
                           'GEOPDSpatialEventLookupParameters', 'GEOWiFiQualityHours'])

    def setUp(self):
        if self.by is None:
            self.skipTest("GeoServices cache not available")

    def _field(self, cls, name):
        return next(f for f in self.by[cls].fields if f.name == name)

    def test_by_value_struct_becomes_a_message_field(self):
        for owner, fname in (('GEOPDDeparturePredicate', 'timeRange'),
                             ('GEOPDTransitTripStopTimeFilter', 'operatingHoursRange'),
                             ('GEOPDSpatialEventLookupParameters', 'timeRange')):
            f = self._field(owner, fname)
            self.assertEqual((f.type_name, f.type_class), ('GEOPDTimeRange', 'GEOPDTimeRange'), owner)
            self.assertIsNone(f.type_inference_note, owner)
            self.assertIs(f.label, FieldLabel.OPTIONAL)

    def test_one_message_per_struct_tag_with_numbers_names_and_types(self):
        msg = self.by['GEOPDTimeRange']
        self.assertEqual(msg.name, 'PDTimeRange')
        self.assertIn('GEOPDTimeRange', msg.inline_struct)
        self.assertEqual([(f.number, f.name, f.type_name) for f in
                          sorted(msg.fields, key=lambda f: f.number)],
                         [(1, 'startTime', 'uint32'), (2, 'duration', 'uint32')])
        self.assertTrue(all(f.number_confirmed for f in msg.fields))

    def test_array_of_structs_becomes_a_repeated_message_field(self):
        f = self._field('GEOWiFiQualityHours', 'timeRanges')
        self.assertEqual((f.type_name, f.type_class), ('GEOWiFiQualityTimeRange',) * 2)
        self.assertIs(f.label, FieldLabel.REPEATED)
        msg = self.by['GEOWiFiQualityTimeRange']
        self.assertEqual(sorted((f.number, f.name, f.type_name) for f in msg.fields),
                         [(1, 'from', 'uint32'), (2, 'to', 'uint32')])
        self.assertTrue(all(f.type_inference_note is None for f in msg.fields))


class TestLiveInlineStructRecovery(unittest.TestCase):
    """Structs the compiler serialised inline (no struct-writer function) and/or whose
    dictionary representation it inlined into the owner."""

    @classmethod
    def setUpClass(cls):
        cls.by = _extract(['GEOTransitRouteUpdateRequest', 'GEOTileSetVersion', 'GEOTileGroup',
                           'GEOCoarseLocationRing', 'GEOFlyoverRegionVersions'])

    def setUp(self):
        if self.by is None:
            self.skipTest("GeoServices cache not available")

    def _members(self, tag):
        return [(f.number, f.name, f.type_name)
                for f in sorted(self.by[tag].fields, key=lambda f: f.number)]

    def test_inline_by_value_struct(self):
        self.assertEqual(self._members('GEOSessionID'),
                         [(1, 'low', 'uint64'), (2, 'high', 'uint64')])
        f = next(f for f in self.by['GEOTransitRouteUpdateRequest'].fields if f.name == 'sessionId')
        self.assertEqual((f.type_name, f.type_class), ('GEOSessionID', 'GEOSessionID'))

    def test_inline_array_with_has_bit_jump_table(self):
        self.assertEqual(self._members('GEOGenericTile'),
                         [(1, 'tileType', 'GenericTileType'), (2, 'textureIndex', 'uint32'),
                          (3, 'resourceIndex', 'uint32')])
        f = next(f for f in self.by['GEOTileSetVersion'].fields if f.name == 'genericTiles')
        self.assertEqual((f.type_name, f.label), ('GEOGenericTile', FieldLabel.REPEATED))

    def test_owner_with_several_struct_arrays_names_each_from_its_own_callee(self):
        # three struct arrays in one owner whose dictionary-representation callees share their
        # first offsets: the larger structs' functions must not be taken for the smaller ones
        self.assertEqual([n for _, n, _ in self._members('GEOVersionedTileSet')],
                         ['tileSetIndex', 'identifier'])
        self.assertEqual([n for _, n, _ in self._members('GEORegionalResourceIndex')],
                         ['regionalResourceIndex', 'iconIndex', 'attributionIndex'])

    def test_key_spilled_to_the_stack_names_the_member(self):
        # member 0's key is chosen by the JSON flag before the loop and reloaded from the frame
        self.assertEqual(self._members('GEOFlyoverRegion'),
                         [(1, 'region', 'uint32'), (2, 'version', 'uint32'), (3, 'dataVersion', 'uint32')])

    def test_inlined_dictionary_representation_names_the_members(self):
        self.assertEqual(self._members('GEOCoarseLocationPoint'),
                         [(1, 'lat', 'sint32'), (2, 'lng', 'sint32')])


# ── enum members (the struct's dictionary representation) ──────────────────────


class _TextCtx(_NoStringsMixin):
    """A ctx exposing the string constants in *texts* (``{VA: text}``), read as direct C strings
    (no named sections, as _CfCtx)."""

    def __init__(self, texts):
        self.texts = texts

    def read_cstring(self, va, max_len=4096):
        if va in self.texts:
            return self.texts[va][:max_len]
        raise ValueError(f"no string at {va:#x}")

    def is_variable(self, vmaddr):        # no program data, no binds
        return False

    def read_ptr(self, va):
        return 0x100000 + (va - 16)

    def read_u64(self, va):
        return len(_held(self.texts, va - 24))

    def read_bytes(self, va, n):
        return _held(self.texts, va - 0x100000).encode()[:n]


class TestEnumMemberEvidence(_SelectorsPatched):
    def _insns(self, *lines):
        order, _ = asm((0x1000, list(lines)))
        return order

    # ---- a struct member's name switch, read by proto.dictrep_flow ----------------------

    class _MemberCtx(FlowCtx):
        """Assembled code plus the key constant, a direct C string like the names (FlowCtx)."""
        def read_u64(self, va):
            return self.read_ptr(va)

    KEY_VA = 0x9000

    def _member_run(self, switch, strings, *, member_off=0x10):
        # helper: setObject:forKey: (and, on the fallback path, the "(unknown: %i)" formatter);
        # box / arc: +[NSNumber numberWithInt:] and the ARC return-value handshake
        code = ['ldr w8, [x20, #0x10]'] + switch + [
            'merge:', 'adrp x3, #0x9000', 'add x3, x3, #0', 'mov x0, x19', 'bl helper',
            'end:', 'ret', 'helper:', 'ret', 'box:', 'ret', 'arc:', 'ret']
        words, labels = assemble(0x1000, code)
        self.patch_selectors({labels['helper']: 'setObject:forKey:', labels['box']: 'numberWithInt:'})
        ctx = self._MemberCtx(0x1000, words)
        ctx._strings = {**strings, self.KEY_VA: 'kind'}      # direct C strings (FlowCtx)
        order = disasm(ctx, 0x1000, max_insns=100, stop_at_ret=False)
        members, unpaired = SF._pair_members(
            ctx, order, lambda k: member_off if k == 0 else None)
        return members, unpaired

    COMPARE_CHAIN = ['cbz w8, zero', 'cmp w8, #1', 'b.ne unk',
                     'adrp x2, #0x6000', 'add x2, x2, #0x80', 'b merge',
                     'zero:', 'adrp x2, #0x6000', 'add x2, x2, #0x40', 'b merge',
                     'unk:', 'adrp x2, #0x8000', 'add x2, x2, #0x20', 'bl helper', 'b merge']
    NAMES = {0x6040: 'KIND_ZERO', 0x6080: 'KIND_ONE', 0x8020: '(unknown: %i)'}

    def test_a_member_whose_string_varies_with_its_value_is_an_enum(self):
        members, unpaired = self._member_run(self.COMPARE_CHAIN, self.NAMES)
        self.assertEqual(unpaired, 0)
        self.assertEqual(members, {0x10: SF.MemberDict('kind', ((0, 'KIND_ZERO'), (1, 'KIND_ONE')))})

    def test_an_older_compiler_with_no_unknown_fallback_is_still_an_enum(self):
        chain = [c for c in self.COMPARE_CHAIN if not c.startswith(('adrp x2, #0x8000', 'add x2, x2, #0x20'))]
        chain = [c.replace('b.ne unk', 'b.ne end') for c in chain if c not in ('bl helper',)]
        members, _ = self._member_run(chain, self.NAMES)
        self.assertEqual(members[0x10].enum, ((0, 'KIND_ZERO'), (1, 'KIND_ONE')))

    def test_a_plain_number_member_is_not_an_enum(self):
        members, _ = self._member_run(['mov x2, x8', 'bl box', 'bl arc', 'mov x2, x0'], {})
        self.assertEqual(members, {0x10: SF.MemberDict('kind', None)})

    def test_an_enum_like_switch_that_cannot_be_evaluated_files_no_member(self):
        # every path branches on a register the analysis does not track: no run reaches the
        # call with a name, so nothing ties the key to the member -- it is counted unpaired,
        # never handed to the nearest load
        chain = ['cbz x5, merge', 'cbz w8, merge', 'cmp w8, #1', 'b.eq merge',
                 'cmp w8, #2', 'b.eq merge', 'cmp w8, #3', 'b.eq merge', 'bl helper']
        self.assertEqual(self._member_run(chain, self.NAMES), ({}, 1))

    def test_a_key_chosen_between_two_spellings_that_differ_only_in_case(self):
        # real GEONavigationAudioFeedback dictrep: ``isJSON ? @"BTHFPRoutesAvailable" :
        # @"bTHFPRoutesAvailable"`` -- no name is guessed, but the member is still filed
        # (the helper is accepted and its enum-ness read)
        ctx = _TextCtx({0x1d5fda0e0: 'bTHFPRoutesAvailable', 0x1d5fda100: 'BTHFPRoutesAvailable'})
        self.patch_selectors({0x3000: 'setObject:forKey:', 0x3100: 'numberWithBool:'})
        order = self._insns(
            ('mov', 'x20, x1'), ('mov', 'x21, x0'), ('ldrb', 'w2, [x21, #1]'), *_BOX,
            ('adrp', 'x8, #0x1d5fda000'), ('add', 'x8, x8, #0xe0'),
            ('adrp', 'x9, #0x1d5fda000'), ('add', 'x9, x9, #0x100'),
            ('cmp', 'w20, #0'), ('csel', 'x3, x9, x8, ne'), ('bl', '#0x3000'), ('ret', ''))
        members, unpaired = SF._pair_members(
            ctx, order, lambda k: 1 if order[k].mnemonic == 'ldrb' else None)
        self.assertEqual((unpaired, members), (0, {1: SF.MemberDict(None, None)}))

    def test_a_double_member_is_traced_through_the_float_argument_register(self):
        # +[NSNumber numberWithDouble:] takes its value in d0, not x2
        ctx = _TextCtx({0x1d5fda0e0: 'time'})
        self.patch_selectors({0x3000: 'setObject:forKey:', 0x3100: 'numberWithDouble:'})
        order = self._insns(('ldr', 'd0, [x20]'), *_BOX, ('adrp', 'x3, #0x1d5fda000'),
                            ('add', 'x3, x3, #0xe0'), ('bl', '#0x3000'), ('ret', ''))
        members, _ = SF._pair_members(ctx, order, lambda k: 0 if k == 0 else None)
        self.assertEqual(members, {0: SF.MemberDict('time', None)})

    def test_a_float_member_boxed_as_a_double_is_traced_through_the_conversion(self):
        ctx = _TextCtx({0x1d5fda0e0: 'speed'})
        self.patch_selectors({0x3000: 'setObject:forKey:', 0x3100: 'numberWithDouble:'})
        order = self._insns(('ldr', 's0, [x20, #4]'), ('fcvt', 'd0, s0'), *_BOX,
                            ('adrp', 'x3, #0x1d5fda000'), ('add', 'x3, x3, #0xe0'),
                            ('bl', '#0x3000'), ('ret', ''))
        members, _ = SF._pair_members(ctx, order, lambda k: 4 if k == 0 else None)
        self.assertEqual(members, {4: SF.MemberDict('speed', None)})

    def test_a_double_in_a_callee_saved_register_survives_the_calls_before_the_box(self):
        # d8 is preserved across a call (AAPCS64); d0 is not, so a value parked in d8 is still
        # the member's at the box
        ctx = _TextCtx({0x1d5fda0e0: 'time'})
        self.patch_selectors({0x3000: 'setObject:forKey:', 0x3100: 'numberWithDouble:'})
        order = self._insns(('ldr', 'd8, [x20]'), ('bl', '#0x3300'), ('fmov', 'd0, d8'), *_BOX,
                            ('adrp', 'x3, #0x1d5fda000'), ('add', 'x3, x3, #0xe0'),
                            ('bl', '#0x3000'), ('ret', ''))
        members, _ = SF._pair_members(ctx, order, lambda k: 0 if k == 0 else None)
        self.assertEqual(members, {0: SF.MemberDict('time', None)})


class TestMergeEnums(unittest.TestCase):
    D = staticmethod(lambda enum: {0: SF.MemberDict('type', enum)})

    def test_owners_that_agree_give_the_values(self):
        pairs = ((0, 'DEPART'), (1, 'ARRIVE'))
        self.assertEqual(SF._merge_enums([self.D(pairs), self.D(pairs)]), {0: pairs})

    def test_an_owner_that_shows_a_plain_number_vetoes_the_enum(self):
        self.assertEqual(SF._merge_enums([self.D(((0, 'A'), (1, 'B'))), self.D(None)]), {})

    def test_owners_that_name_a_value_differently_drop_the_values(self):
        self.assertEqual(SF._merge_enums([self.D(((0, 'A'),)), self.D(((0, 'B'),))]), {0: ()})

    def test_owners_that_could_not_be_read_say_nothing(self):
        self.assertEqual(SF._merge_enums([None, self.D(((0, 'A'), (1, 'B')))]),
                         {0: ((0, 'A'), (1, 'B'))})


class TestMakeEnum(unittest.TestCase):
    def test_screaming_snake_values_name_the_type_from_their_prefix(self):
        e = SF._make_enum('NavigationAudioFeedbackCurrentRouteTypeAtEndOfNav',
                          [(1, 'AUDIO_DEVICE_TYPE_BT_HFP_ONLY'), (2, 'AUDIO_DEVICE_TYPE_OTHER')])
        self.assertEqual((e.name, [(v.name, v.number) for v in e.values]),
                         ('AudioDeviceType', [('AUDIO_DEVICE_TYPE_BT_HFP_ONLY', 1),
                                              ('AUDIO_DEVICE_TYPE_OTHER', 2)]))

    def test_type_name_spelled_in_the_values_is_taken_verbatim(self):
        e = SF._make_enum('VLFPositionContextClassificationType',
                          [(0, 'VLFPositionContextType_UNKNOWN'), (1, 'VLFPositionContextType_OUTDOOR')])
        self.assertEqual((e.name, [v.name for v in e.values]),
                         ('VLFPositionContextType', ['VLF_POSITION_CONTEXT_TYPE_UNKNOWN',
                                                     'VLF_POSITION_CONTEXT_TYPE_OUTDOOR']))

    def test_unprefixed_values_keep_the_member_derived_name(self):
        e = SF._make_enum('TimepointType', [(0, 'DEPART'), (1, 'ARRIVE')])
        self.assertEqual((e.name, [v.name for v in e.values]),
                         ('TimepointType', ['TIMEPOINT_TYPE_DEPART', 'TIMEPOINT_TYPE_ARRIVE']))


class TestFramePointerScratch(_Patched):
    """A function that addresses its locals from the frame pointer says ``sub x1, x29, #K``
    (not ``add x1, sp, #K``) for the begin/end-mark scratch (real GEOPDDepartureSequence)."""

    def test_the_begin_and_end_marks_pair_on_the_same_frame_slot(self):
        order, _ = asm((0x1000, [
            ('sub', 'x1, x29, #0xd8'), ('mov', 'x0, x19'), ('mov', 'w2, #0xb'),
            ('bl', '#0x18dbdab88'), ('sub', 'x1, x29, #0xd8'), ('mov', 'x0, x19'),
            ('bl', '#0x18dbdab94')]))
        flow = listing_flow(None, order)
        from proto.submessage_marks import scratch_slot_of
        begin, end = scratch_slot_of(flow, 3), scratch_slot_of(flow, 6)
        self.assertEqual(begin, end)
        self.assertIsNotNone(begin)


class TestLiveStructEnums(unittest.TestCase):
    """The six enum members of the inline structs that have no ObjC class, and the repeated
    12-byte struct array the walk used to bind to its count ivar.  Values are the binary's own
    (the name switches in the struct dictionary representations)."""

    @classmethod
    def setUpClass(cls):
        cls.by = _extract(['GEORouteAttributes', 'GEOJunctionInfo', 'GEOLogMsgEventDirections',
                           'GEOVLFLocalizationResults', 'GEOTileSetVersion',
                           'GEOPDDepartureSequence', 'GEOETAResponse'])

    def setUp(self):
        if self.by is None:
            self.skipTest("GeoServices cache not available")

    def _enum_of(self, tag, member):
        f = next(f for f in self.by[tag].fields if f.name == member)
        self.assertTrue(f.type_class and f.type_class.startswith('ENUM:'), (tag, member))
        e = next(e for e in self.by[tag].enums if e.name == f.type_name)
        return e.name, [(v.name, v.number) for v in e.values]

    def test_compare_chain_enum(self):
        self.assertEqual(self._enum_of('GEOTimepoint', 'type'),
                         ('TimepointType', [('TIMEPOINT_TYPE_DEPART', 0), ('TIMEPOINT_TYPE_ARRIVE', 1)]))

    def test_pointer_table_enums(self):
        name, vals = self._enum_of('GEOJunctionElement', 'type')
        self.assertEqual([n for n, _ in vals], ['JUNCTION_ELEMENT_TYPE_NORMAL', 'JUNCTION_ELEMENT_TYPE_RAMP',
                                                 'JUNCTION_ELEMENT_TYPE_HIGHWAY'])
        self.assertEqual([v for _, v in self._enum_of('GEOJunctionElement', 'usage')[1]], [0, 1, 2])
        self.assertEqual(self._enum_of('GEOVLFPositionContextClassification', 'type')[0],
                         'VLFPositionContextType')

    def test_biased_enum_keeps_the_binary_values(self):
        # ``sub w9,w8,#1`` before the table read: the values start at 1
        name, vals = self._enum_of('GEONavigationAudioFeedback', 'currentRouteTypeAtEndOfNav')
        self.assertEqual((name, [v for _, v in vals]), ('AudioDeviceType', [1, 2, 3]))

    def test_enum_member_of_an_inlined_dictrep(self):
        # GEOGenericTile's dictionary representation is inlined into GEOTileSetVersion's;
        # tileType is 1-based by compare chain (value 0 is the unknown branch)
        self.assertEqual(self._enum_of('GEOGenericTile', 'tileType')[1],
                         [('GENERIC_TILE_TYPE_WATER', 1), ('GENERIC_TILE_TYPE_NO_TILE', 2)])

    def test_sparse_pointer_table_enum_skips_the_holes(self):
        # GEOProblemDetail.problemType: 1-based, values 6 and 7 are not declared (their table
        # slots hold a filler name that must not become values)
        name, vals = self._enum_of('GEOProblemDetail', 'problemType')
        self.assertEqual([v for _, v in vals], [1, 2, 3, 4, 5] + list(range(8, 19)))
        self.assertEqual(dict((v, n) for n, v in vals)[8], 'PROBLEM_DETAIL_PROBLEM_TYPE_ZILCH_MISMATCH')

    def test_plain_members_stay_numbers(self):
        for tag in ('GEOGenericTile', 'GEOJunctionElement', 'GEOTimepoint',
                    'GEONavigationAudioFeedback', 'GEOVLFPositionContextClassification'):
            n_enum = sum(1 for f in self.by[tag].fields if f.type_class and f.type_class.startswith('ENUM:'))
            self.assertEqual(n_enum, len(self.by[tag].enums), tag)
        self.assertEqual({f.name: f.type_name for f in self.by['GEOTimepoint'].fields},
                         {'time': 'double', 'type': 'TimepointType', 'currentUserTime': 'double'})
        self.assertEqual(self.by['GEONavigationAudioFeedback'].enums[0].name, 'AudioDeviceType')
        self.assertEqual(len(self.by['GEONavigationAudioFeedback'].enums), 1)

    def test_repeated_struct_array_binds_to_the_array_not_its_count(self):
        owner = self.by['GEOPDDepartureSequence']
        f = next(f for f in owner.fields if f.name == 'operatingHours')
        self.assertEqual((f.number, f.type_name, f.label, f.number_confirmed),
                         (11, 'GEOPDTimeRange', FieldLabel.REPEATED, True))
        self.assertFalse([f for f in owner.fields if f.name == 'operatingHoursCount'])



# ── newer toolchain (macOS 27 / iOS 27, arm64e) ────────────────────────────────


# Real listing (macOS 27 GeoServices): the same GEOPDTimeRange serialiser as
# _PD_TIMERANGE_WRITER.  The last member's tail call now carries the arm64e return-address
# check between its argument setup and the branch (autibsp ; eor x16,x30,x30,lsl #1 ;
# tbz x16,#62 ; brk), which hid its field number from a backward window.
_PD_TIMERANGE_WRITER_ARM64E = (0x19848d78c, [
    ('pacibsp', ''), ('stp', 'x20, x19, [sp, #-0x20]!'), ('stp', 'x29, x30, [sp, #0x10]'),
    ('add', 'x29, sp, #0x10'), ('mov', 'x19, x1'), ('mov', 'x20, x0'),
    ('ldrb', 'w8, [x0, #8]'), ('tbz', 'w8, #1, #0x19848d7c0'),
    ('ldr', 'w1, [x20, #4]'), ('mov', 'x0, x19'), ('mov', 'w2, #1'), ('bl', '#0x1a0103de0'),
    ('ldrb', 'w8, [x20, #8]'), ('tbnz', 'w8, #0, #0x19848d7d0'),
    ('ldp', 'x29, x30, [sp, #0x10]'), ('ldp', 'x20, x19, [sp], #0x20'), ('retab', ''),
    ('ldr', 'w1, [x20]'), ('mov', 'x0, x19'), ('mov', 'w2, #2'),
    ('ldp', 'x29, x30, [sp, #0x10]'), ('ldp', 'x20, x19, [sp], #0x20'), ('autibsp', ''),
    ('eor', 'x16, x30, x30, lsl #1'), ('tbz', 'x16, #0x3e, #0x19848d7f4'), ('brk', '#0xc471'),
    ('b', '#0x1a0103de0'),
])

# Real listing (macOS 27): the GEOTimepoint serialiser {_time d @0, _currentUserTime d @8,
# _type i @16, has-bits @20}.  The doubles ride in d0 with the field number in w1; the last
# one is a tail call behind the return-address check.
_TIMEPOINT_WRITER_ARM64E = (0x19850174c, [
    ('pacibsp', ''), ('stp', 'x20, x19, [sp, #-0x20]!'), ('stp', 'x29, x30, [sp, #0x10]'),
    ('add', 'x29, sp, #0x10'), ('mov', 'x19, x1'), ('mov', 'x20, x0'),
    ('ldrb', 'w8, [x0, #0x14]'), ('tbnz', 'w8, #1, #0x198501780'),
    ('tbnz', 'w8, #2, #0x198501798'), ('tbnz', 'w8, #0, #0x1985017b0'),
    ('ldp', 'x29, x30, [sp, #0x10]'), ('ldp', 'x20, x19, [sp], #0x20'), ('retab', ''),
    ('ldr', 'd0, [x20, #8]'), ('mov', 'x0, x19'), ('mov', 'w1, #1'), ('bl', '#0x1a0103d40'),
    ('ldrb', 'w8, [x20, #0x14]'), ('tbz', 'w8, #2, #0x198501770'),
    ('ldr', 'w1, [x20, #0x10]'), ('mov', 'x0, x19'), ('mov', 'w2, #2'), ('bl', '#0x1a0103d60'),
    ('ldrb', 'w8, [x20, #0x14]'), ('tbz', 'w8, #0, #0x198501774'),
    ('ldr', 'd0, [x20]'), ('mov', 'x0, x19'), ('mov', 'w1, #4'),
    ('ldp', 'x29, x30, [sp, #0x10]'), ('ldp', 'x20, x19, [sp], #0x20'), ('autibsp', ''),
    ('eor', 'x16, x30, x30, lsl #1'), ('tbz', 'x16, #0x3e, #0x1985017d4'), ('brk', '#0xc471'),
    ('b', '#0x1a0103d40'),
])


class TestDecodeStructWriterNewerToolchain(_Patched):
    def test_a_tail_write_behind_the_return_address_check_is_read(self):
        _, fake = asm(_PD_TIMERANGE_WRITER_ARM64E)
        self.patch(fake)
        writes = SF.decode_struct_writer(NoImage(), 0x19848d78c)
        self.assertEqual(sorted((w.offset, w.number, w.width, w.helper) for w in writes),
                         [(0, 2, 4, 0x1a0103de0), (4, 1, 4, 0x1a0103de0)])

    def test_float_values_ride_in_v0_with_the_field_number_in_w1(self):
        _, fake = asm(_TIMEPOINT_WRITER_ARM64E)
        self.patch(fake)
        writes = SF.decode_struct_writer(NoImage(), 0x19850174c)
        self.assertEqual(sorted((w.offset, w.number, w.width) for w in writes),
                         [(0, 4, 8), (8, 1, 8), (16, 2, 4)])
        layout = SF.parse_struct_encoding('{GEOTimepoint="_time"d"_currentUserTime"d"_type"i'
                                          '"_has"{?="time"b1"currentUserTime"b1"type"b1}}')
        self.assertEqual(SF.match_layout(layout, writes), {0: 4, 8: 1, 16: 2})

    def test_a_value_not_loaded_from_the_struct_is_not_a_member_write(self):
        # the field number is a constant but x1 comes from the stack, not [struct + k]
        _, fake = asm((0x1000, [('mov', 'x19, x1'), ('mov', 'x20, x0'), ('ldr', 'w1, [sp, #4]'),
                                ('mov', 'x0, x19'), ('mov', 'w2, #1'), ('bl', '#0x2000'),
                                ('ret', '')]))
        self.patch(fake)
        self.assertEqual(SF.decode_struct_writer(NoImage(), 0x1000), [])


# Real listing (macOS 27): -[GEOCoarseLocationRing writeTo:] up to the end mark of field 1, a
# repeated GEOCoarseLocationPoint {i lat @0, i lng @4}.  The element is addressed as
# add xS,self,xOff ; ldr xA,[xS] ; add xE,xA,xI,lsl #3 (iPhone 8: ldr xA,[self,xOff] ;
# add xE,xA,xI).
_RING_WRITETO_ARM64E = (0x1986d66b8, [
    ('pacibsp', ''), ('sub', 'sp, sp, #0x50'), ('stp', 'x24, x23, [sp, #0x10]'),
    ('stp', 'x22, x21, [sp, #0x20]'), ('stp', 'x20, x19, [sp, #0x30]'),
    ('stp', 'x29, x30, [sp, #0x40]'), ('add', 'x29, sp, #0x40'), ('mov', 'x19, x0'),
    ('mov', 'x0, x2'), ('bl', '#0x1a01057e0'), ('mov', 'x20, x0'),
    ('adrp', 'x8, #0x1e4930000'), ('ldrsw', 'x21, [x8, #0x554]'), ('add', 'x8, x19, x21'),
    ('ldr', 'x8, [x8]'), ('cbz', 'x8, #0x1986d6760'), ('mov', 'x22, #0'),
    ('adrp', 'x23, #0x1e4930000'), ('str', 'xzr, [sp, #8]'), ('add', 'x1, sp, #8'),
    ('mov', 'x0, x20'), ('mov', 'w2, #1'), ('bl', '#0x1a0103d00'),               # begin, field 1
    ('ldrsw', 'x8, [x23, #0x558]'), ('add', 'x8, x19, x8'), ('ldr', 'x8, [x8]'),
    ('add', 'x24, x8, x22, lsl #3'), ('ldr', 'w1, [x24]'), ('mov', 'x0, x20'),
    ('mov', 'w2, #1'), ('bl', '#0x1a0103da0'), ('ldr', 'w1, [x24, #4]'), ('mov', 'x0, x20'),
    ('mov', 'w2, #2'), ('bl', '#0x1a0103da0'), ('add', 'x1, sp, #8'), ('mov', 'x0, x20'),
    ('bl', '#0x1a0103d10'),                                                     # end
    ('add', 'x22, x22, #1'), ('ret', ''),
])


class TestInlineStructWritesNewerToolchain(_Patched):
    def test_array_element_through_the_ivar_slot_and_a_scaled_index(self):
        insns, fake = asm(_RING_WRITETO_ARM64E)
        self.patch(fake)
        begin = next(i for i, x in enumerate(insns)
                     if x.mnemonic == 'bl' and x.op_str == '#0x1a0103d00')
        br = SF.analyze_bracket(None, insns, begin)
        layout = SF.parse_struct_encoding('^{GEOCoarseLocationPoint=ii}')
        var = lambda a: a == 0x1e4930558                                       # noqa: E731
        loads = SF.track_struct_loads(None, insns, max(br.region), var, True, window=set(br.region))
        # the array-pointer load through &self->_points is not a member; the two element loads are
        self.assertEqual(sorted(loads.values()), [(0, 4), (4, 4)])
        w = SF.decode_inline_writes(None, insns, br, var, layout)
        self.assertEqual(SF.match_layout(layout, w), {0: 1, 4: 2})

    def test_a_by_value_struct_through_add_is_still_the_struct(self):
        insns, _ = asm((0x1000, [('adrp', 'x8, #0x5000'), ('ldrsw', 'x8, [x8, #0x10]'),
                                 ('add', 'x8, x19, x8'), ('ldr', 'w1, [x8, #4]')]))
        loads = SF.track_struct_loads(None, insns, 3, lambda a: a == 0x5010, False)
        self.assertEqual(loads, {3: (4, 4)})

    def test_a_role_set_on_one_branch_only_does_not_reach_the_join(self):
        # x8 is the struct on the fall-through path only; the cbz path reaches the load with
        # whatever x8 held on entry.  (In address order the struct set-up comes last, so an
        # address-order tracker took the load for a member.)
        insns, _ = asm((0x1000, [('cbz', 'x0, #0x1014'),
                                 ('adrp', 'x8, #0x5000'), ('ldrsw', 'x8, [x8, #0x10]'),
                                 ('add', 'x8, x19, x8'), ('nop', ''),
                                 ('ldr', 'w1, [x8, #4]'), ('ret', '')]))   # 0x1014: the join
        self.assertEqual(SF.track_struct_loads(None, insns, 5, lambda a: a == 0x5010, False), {})

    def test_an_offset_load_hoisted_above_a_loop_reaches_its_body(self):
        insns, _ = asm((0x1000, [('adrp', 'x8, #0x5000'), ('ldrsw', 'x9, [x8, #0x10]'),
                                 ('add', 'x20, x19, x9'),                          # callee-saved
                                 ('ldr', 'w1, [x20, #8]'), ('bl', '#0x9000'),      # 0x100c: loop
                                 ('add', 'x21, x21, #1'), ('cmp', 'x21, #3'),
                                 ('b.lo', '#0x100c'), ('ret', '')]))
        self.assertEqual(SF.track_struct_loads(None, insns, 8, lambda a: a == 0x5010, False),
                         {3: (8, 4)})


class _FakeMethod:
    def __init__(self, imp):
        self.imp = imp


class _FakeClass:
    def __init__(self, methods):
        self.methods = methods                     # {selector: IMP}

    def get_method(self, sel):
        imp = self.methods.get(sel)
        return _FakeMethod(imp) if imp is not None else None


class TestDictrepBodyOfAStrippedMethod(_Patched):
    """macOS 27 leaves `_dictionaryRepresentation:` out of the method list; its body is reached
    from the public wrappers' tail branch (proto.enums._find_dictrep_c_func)."""

    def setUp(self):
        import proto.enums as EN
        self.addCleanup(setattr, FB, 'disasm', FB.disasm)
        self.EN = EN

    def find(self, cls, *blocks):
        _, fake = asm(*blocks)
        FB.disasm = fake
        return self.EN._find_dictrep_c_func(TextImage((0x2000, 0x3000)), cls)   # the image's __text

    def test_the_registered_method_wins(self):
        cls = _FakeClass({'_dictionaryRepresentation:': 0x2400, 'dictionaryRepresentation': 0x1000})
        self.assertEqual(self.find(cls, (0x1000, [('mov', 'w1, #0'), ('b', '#0x2000')])), 0x2400)

    def test_the_plain_wrapper_hands_self_and_flag_zero(self):
        cls = _FakeClass({'dictionaryRepresentation': 0x1000, 'jsonRepresentation': 0x1100})
        self.assertEqual(self.find(cls, (0x1000, [('mov', 'w1, #0'), ('b', '#0x2000')]),
                                   (0x1100, [('mov', 'w1, #1'), ('b', '#0x2000')])), 0x2000)

    def test_a_dropped_flag_leaves_x1_as_it_came_in(self):
        # the body never reads the flag, so the compiler passes none: x1 is still _cmd
        cls = _FakeClass({'dictionaryRepresentation': 0x1000})
        self.assertEqual(self.find(cls, (0x1000, [('b', '#0x2008')])), 0x2008)
        # ... but an x1 the wrapper computed is some other argument
        self.assertIsNone(self.find(cls, (0x1000, [('ldr', 'x1, [x0, #8]'), ('b', '#0x2008')])))

    def test_a_self_contained_implementation_is_its_own_body(self):
        # opens with a frame and a call that is not a tail call: it builds the dictionary
        # itself, so its own IMP is the body; its branches are not followed
        cls = _FakeClass({'dictionaryRepresentation': 0x1000, 'jsonRepresentation': 0x1100})
        self.assertEqual(self.find(cls, (0x1000, [('pacibsp', ''), ('stp', 'x29, x30, [sp, #-0x10]!'),
                                                  ('bl', '#0x2000'), ('b', '#0x2100')])), 0x1000)

    def test_a_branch_not_handed_self_or_out_of_the_image_is_not_the_body(self):
        cls = _FakeClass({'dictionaryRepresentation': 0x1000})
        self.assertIsNone(self.find(cls, (0x1000, [('mov', 'x0, x1'), ('mov', 'w1, #0'),
                                                   ('b', '#0x2000')])))
        self.assertIsNone(self.find(cls, (0x1000, [('mov', 'w1, #0'), ('b', '#0x9000')])))
        self.assertIsNone(self.find(cls, (0x1000, [('mov', 'w1, #1'), ('b', '#0x2000')])))


# ── live: the newer caches ─────────────────────────────────────────────────────


def _cache_file(env, *rel):
    d = os.environ.get(env, '').strip() or os.path.join(artifacts.REPO_ROOT, *rel)
    path = os.path.join(d, 'dyld_shared_cache_arm64e')
    return path if os.path.isfile(path) else None


_MACOS27 = _cache_file('MACHO_TEST_MACOS27_CACHE', 'macos27_data', 'dylib')
_IOS27 = _cache_file('MACHO_TEST_IOS27_CACHE', 'ios27_data', 'dylib')

# The iPhone 8 golden's struct messages (number, name, type), which the newer builds must
# reproduce: a by-value struct, a float/double tail write with an enum, two inline arrays (one
# with a folded JSON flag), an inline array with an enum, a has-bit jump table.
_GOLDEN_STRUCTS = {
    'GEOPDTimeRange': [(1, 'startTime', 'uint32'), (2, 'duration', 'uint32')],
    'GEOTimepoint': [(1, 'time', 'double'), (2, 'type', 'TimepointType'),
                     (4, 'currentUserTime', 'double')],
    'GEOCoarseLocationPoint': [(1, 'lat', 'sint32'), (2, 'lng', 'sint32')],
    'GEOGenericTile': [(1, 'tileType', 'GenericTileType'), (2, 'textureIndex', 'uint32'),
                       (3, 'resourceIndex', 'uint32')],
    'GEOFlyoverRegion': [(1, 'region', 'uint32'), (2, 'version', 'uint32'),
                         (3, 'dataVersion', 'uint32')],
    'GEOVLFPositionContextClassification': [(1, 'type', 'VLFPositionContextType'),
                                            (2, 'indoorProbability', 'double'),
                                            (3, 'outdoorProbability', 'double')],
}
_OWNERS = ['GEOPDDeparturePredicate', 'GEOETARequest', 'GEOCoarseLocationRing',
           'GEOTileSetVersion', 'GEOFlyoverRegionVersions', 'GEOVLFLocalizationResults']


def _extract_from(cache, classes):
    from macho.dyld_cache import DyldCacheReader
    from macho.memory import BinaryContext
    from macho.strings import build_string_table
    from macho import classlist as CL
    from macho.local_symbols import apply_to_classes
    reader = DyldCacheReader(cache)
    try:
        mv = reader.find_image_header('GeoServices')
        ctx = BinaryContext.from_cache(reader, mv)
        st = build_string_table(ctx)
        cl = CL.build_class_list(ctx, st)
        syms = reader.image_local_symbols(mv)
        if syms:
            apply_to_classes(cl, syms)
        msgs = [E.extract_proto_message(ctx, st, cl, cl.find(c)) for c in classes]
        SF.finalize_struct_fields(ctx, cl, msgs)
        return {m.class_name: m for m in msgs}
    finally:
        reader.close()


class _NewerBuild:
    CACHE = None

    @classmethod
    def setUpClass(cls):
        cls.by = _extract_from(cls.CACHE, _OWNERS)

    def test_struct_messages_match_the_iphone8_golden(self):
        for tag, want in _GOLDEN_STRUCTS.items():
            with self.subTest(tag=tag):
                self.assertIn(tag, self.by)
                self.assertEqual(sorted((f.number, f.name, f.type_name) for f in self.by[tag].fields),
                                 want)

    def test_owner_fields_are_typed(self):
        for owner, fname, tag, label in (
                ('GEOPDDeparturePredicate', 'timeRange', 'GEOPDTimeRange', FieldLabel.OPTIONAL),
                ('GEOETARequest', 'timepoint', 'GEOTimepoint', FieldLabel.OPTIONAL),
                ('GEOCoarseLocationRing', 'points', 'GEOCoarseLocationPoint', FieldLabel.REPEATED),
                ('GEOTileSetVersion', 'genericTiles', 'GEOGenericTile', FieldLabel.REPEATED)):
            with self.subTest(owner=owner):
                f = next(f for f in self.by[owner].fields if f.name == fname)
                self.assertEqual((f.type_name, f.type_class, f.label), (tag, tag, label))


@unittest.skipUnless(_MACOS27, 'macOS 27 cache not present (macos27_data/dylib or MACHO_TEST_MACOS27_CACHE)')
class TestLiveStructRecoveryMacOS27(_NewerBuild, unittest.TestCase):
    CACHE = _MACOS27


@unittest.skipUnless(_IOS27, 'iOS 27 cache not present (ios27_data/dylib or MACHO_TEST_IOS27_CACHE)')
class TestLiveStructRecoveryIOS27(_NewerBuild, unittest.TestCase):
    CACHE = _IOS27


if __name__ == '__main__':
    unittest.main()
