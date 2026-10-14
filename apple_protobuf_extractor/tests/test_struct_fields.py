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
import unittest

import proto.extractor as E
import proto.structfields as SF
import proto.writeto as W
import live_artifacts as V
from proto.models import FieldLabel
from macho.disasm import Insn, disasm
from tests._a64asm import assemble, FlowCtx


# ── fake instruction memory (same idiom as test_map_fields) ───────────────────


def asm(*blocks):
    """``(base, [(mnemonic, op_str), ...])`` blocks -> ``(insn_list, fake_disasm)``."""
    mem, order = {}, []
    for base, lines in blocks:
        a = base
        for mn, op in lines:
            ins = Insn(addr=a, mnemonic=mn, op_str=op, size=4, raw=b'\x00' * 4)
            mem[a] = ins
            order.append(ins)
            a += 4

    def fake_disasm(ctx, addr, max_insns=400, stop_at_ret=True):
        out, a = [], addr
        while len(out) < max_insns and a in mem:
            ins = mem[a]
            out.append(ins)
            if stop_at_ret and ins.mnemonic in ('ret', 'retaa', 'retab'):
                break
            a += 4
        return out

    return order, fake_disasm


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
    def patch(self, fake):
        orig = SF.disasm
        SF.disasm = fake
        self.addCleanup(setattr, SF, 'disasm', orig)


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
        writes = SF.decode_struct_writer(None, 0x18c241b50)
        self.assertEqual(sorted((w.offset, w.number, w.width) for w in writes),
                         [(0, 2, 4), (4, 1, 4)])

    def test_a_function_that_writes_no_member_is_not_a_struct_writer(self):
        _, fake = asm((0x1000, [('mov', 'x19, x1'), ('bl', '#0x2000'), ('ret', '')]))
        self.patch(fake)
        self.assertEqual(SF.decode_struct_writer(None, 0x1000), [])


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
        b = SF.analyze_bracket(insns, begin)
        self.assertEqual(b.number, 1)
        self.assertEqual(b.callees, (0x18c241b50,))

    def test_a_begin_with_no_end_mark_is_rejected(self):
        insns, begin = self._insns()
        cut = [x for x in insns if x.op_str != '#0x18dbdab94']
        self.assertIsNone(SF.analyze_bracket(cut, begin))

    def test_not_a_begin_mark_is_rejected(self):
        insns, _ = self._insns()
        self.assertIsNone(SF.analyze_bracket(insns, 0))


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


class _NoStringsMixin:
    """What the data-flow analysis may ask of ANY ctx: no named sections, no raw C strings."""

    def has_section(self, segname, sectname):
        return False

    def read_cstring(self, va, max_len=4096):
        raise ValueError(f"no string at {va:#x}")


class _CfCtx(_NoStringsMixin):
    """A ctx exposing two CFString constants (``from``/``to``) the way the cache does."""
    TEXT = {0x1d5fdaae0: (0x2000, b'from'), 0x1d5fdab00: (0x2010, b'to')}

    def read_ptr(self, va):
        return self.TEXT[va - 16][0]

    def read_u64(self, va):
        return len(self.TEXT[va - 24][1])

    def read_bytes(self, va, n):
        return next(b for p, b in self.TEXT.values() if p == va)[:n]


class TestDecodeDictrepNames(_Patched):
    def test_keys_are_paired_with_the_member_loaded_just_before(self):
        _, fake = asm(_WIFI_TIMERANGE_DICTREP, _WIFI_TIMERANGE_DICTREP_2, _WIFI_TIMERANGE_DICTREP_3)
        self.patch(fake)
        self.assertEqual(SF.decode_dictrep_names(_CfCtx(), 0x18cb8cdb8, {0, 4}), {0: 'from', 4: 'to'})

    def test_a_key_that_is_not_an_identifier_is_ignored(self):
        _, fake = asm(_WIFI_TIMERANGE_DICTREP, _WIFI_TIMERANGE_DICTREP_2, _WIFI_TIMERANGE_DICTREP_3)
        self.patch(fake)
        ctx = _CfCtx()
        ctx.TEXT = {0x1d5fdaae0: (0x2000, b'a b'), 0x1d5fdab00: (0x2010, b'to')}
        self.assertEqual(SF.decode_dictrep_names(ctx, 0x18cb8cdb8, {0, 4}), {4: 'to'})

    def test_a_function_with_no_keys_is_not_a_dictionary_representation(self):
        _, fake = asm(_PD_TIMERANGE_WRITER, _PD_TIMERANGE_WRITER_TAIL)
        self.patch(fake)
        self.assertEqual(SF.decode_dictrep_names(_CfCtx(), 0x18c241b50, {0, 4}), {})

    def test_a_member_loaded_into_a_scratch_register_still_gets_its_key(self):
        # real GEOProblemDetail dictrep shape: member 0 is an enum, so its value is loaded into
        # w8 (to index the name table), not into x2 for boxing; member 1 is boxed from [x20,#4]
        _, fake = asm((0x1000, [
            ('mov', 'x20, x0'), ('bl', '#0x2000'), ('ldrb', 'w8, [x20, #8]'),
            ('tbz', 'w8, #0, #0x1050'), ('ldr', 'w8, [x20]'), ('sub', 'w9, w8, #1'),
            ('adrp', 'x3, #0x1d5fda000'), ('add', 'x3, x3, #0xae0'), ('bl', '#0x3000'),
            ('ldrb', 'w8, [x20, #8]'), ('tbz', 'w8, #1, #0x1070'), ('ldr', 'w2, [x20, #4]'),
            ('adrp', 'x3, #0x1d5fda000'), ('add', 'x3, x3, #0xb00'), ('bl', '#0x3000'),
            ('mov', 'x0, x19'), ('ret', '')]))
        self.patch(fake)
        self.assertEqual(SF.decode_dictrep_names(_CfCtx(), 0x1000, {0, 4}), {0: 'from', 4: 'to'})

    def test_json_dependent_key_takes_the_camel_case_spelling(self):
        # real GEOPBTransitTimeRange dictrep: ``forJSON ? @"startTime" : @"start_time"`` is
        # chosen with a csel, the two CFStrings built by separate adrp+add pairs
        ctx = _CfCtx()
        ctx.TEXT = {0x1d5fdaae0: (0x2000, b'start_time'), 0x1d5fdab00: (0x2010, b'startTime')}
        _, fake = asm((0x1000, [
            ('mov', 'x21, x0'), ('ldr', 'w2, [x21, #4]'),
            ('adrp', 'x8, #0x1d5fda000'), ('add', 'x8, x8, #0xae0'),
            ('adrp', 'x9, #0x1d5fda000'), ('add', 'x9, x9, #0xb00'),
            ('cmp', 'w20, #0'), ('csel', 'x3, x9, x8, ne'), ('bl', '#0x3000'), ('ret', '')]))
        self.patch(fake)
        self.assertEqual(SF.decode_dictrep_names(ctx, 0x1000, {0, 4}), {4: 'startTime'})


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
        br = SF.analyze_bracket(insns, begin)
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

    def test_wrong_offset_variable_binds_nothing(self):
        insns, br, layout, _ = self._bracket(
            _SESSIONID_WRITETO, '{GEOSessionID="_high"Q"_low"Q}', 0x1e1dd6328)
        self.assertEqual(SF.decode_inline_writes(None, insns, br, lambda a: a == 0xdead0000, layout), [])


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


class TestInlineDictrepNames(_Patched):
    def test_keys_are_paired_through_the_ivar_offset_variable(self):
        insns, fake = asm(_RING_DICTREP)
        self.patch(fake)
        ctx = _CfCtx()
        ctx.TEXT = {0x1d5fa1260: (0x2000, b'lat'), 0x1d5fa1280: (0x2010, b'lng')}
        layout = SF.parse_struct_encoding('^{GEOCoarseLocationPoint=ii}')
        self.assertEqual(
            SF.decode_inline_dictrep_names(ctx, insns, lambda a: a == 0x1e1dd624c, layout),
            {0: 'lat', 4: 'lng'})

    def test_another_ivars_loop_is_not_paired(self):
        insns, fake = asm(_RING_DICTREP)
        self.patch(fake)
        layout = SF.parse_struct_encoding('^{GEOCoarseLocationPoint=ii}')
        self.assertEqual(
            SF.decode_inline_dictrep_names(_CfCtx(), insns, lambda a: a == 0xdead0000, layout), {})


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
        self.assertEqual(SF.decode_dictrep_names(_CfCtx(), 0x1000, {0, 4}), {})


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
                           'GEOCoarseLocationRing'])

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

    def test_inlined_dictionary_representation_names_the_members(self):
        self.assertEqual(self._members('GEOCoarseLocationPoint'),
                         [(1, 'lat', 'sint32'), (2, 'lng', 'sint32')])


# ── enum members (the struct's dictionary representation) ──────────────────────


class _TextCtx(_NoStringsMixin):
    """A ctx exposing the CFStrings in *texts* (``{cfstring VA: text}``) the way the cache does:
    the constant's character pointer is ``0x100000 + its VA``."""

    def __init__(self, texts):
        self.texts = texts

    def read_ptr(self, va):
        return 0x100000 + (va - 16)

    def read_u64(self, va):
        return len(self.texts[va - 24])

    def read_bytes(self, va, n):
        return self.texts[va - 0x100000].encode()[:n]


class TestEnumMemberEvidence(_Patched):
    def _insns(self, *lines):
        order, _ = asm((0x1000, list(lines)))
        return order

    # ---- a struct member's name switch, read by proto.dictrep_flow ----------------------

    class _MemberCtx(FlowCtx):
        """Assembled code plus a CFString key constant, as the cache lays them out."""
        def read_u64(self, va):
            return self.read_ptr(va)

    KEY_VA, KEY_CHARS = 0x9000, 0x9100

    def _member_run(self, switch, strings, *, member_off=0x10):
        code = ['ldr w8, [x20, #0x10]'] + switch + [
            'merge:', 'adrp x3, #0x9000', 'add x3, x3, #0', 'mov x0, x19', 'bl helper',
            'end:', 'ret', 'helper:', 'ret']
        words, _ = assemble(0x1000, code)
        ctx = self._MemberCtx(0x1000, words)
        ctx.put_ptr(self.KEY_VA + 16, self.KEY_CHARS)
        ctx.put_bytes(self.KEY_CHARS, b'kind')
        ctx._m[self.KEY_VA + 24] = 4
        ctx._m[self.KEY_VA + 28] = 0
        ctx._strings = strings
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
        members, _ = self._member_run(['bl helper'], {})
        self.assertEqual(members, {0x10: SF.MemberDict('kind', None)})

    def test_an_enum_like_switch_that_cannot_be_evaluated_is_reported_as_unread(self):
        # every path branches on a register the analysis does not track: still an enum
        # (the compare constants show it) but with no values, never silently a number
        chain = ['cbz x5, merge', 'cbz w8, merge', 'cmp w8, #1', 'b.eq merge',
                 'cmp w8, #2', 'b.eq merge', 'cmp w8, #3', 'b.eq merge', 'bl helper']
        members, _ = self._member_run(chain, self.NAMES)
        self.assertEqual(members, {0x10: SF.MemberDict('kind', ())})

    def test_a_key_chosen_between_two_spellings_that_differ_only_in_case(self):
        # real GEONavigationAudioFeedback dictrep: ``isJSON ? @"BTHFPRoutesAvailable" :
        # @"bTHFPRoutesAvailable"`` -- no name is guessed, but the member is still filed
        # (the helper is accepted and its enum-ness read)
        ctx = _TextCtx({0x1d5fda0e0: 'bTHFPRoutesAvailable', 0x1d5fda100: 'BTHFPRoutesAvailable'})
        order = self._insns(
            ('mov', 'x21, x0'), ('ldrb', 'w2, [x21, #1]'),
            ('adrp', 'x8, #0x1d5fda000'), ('add', 'x8, x8, #0xe0'),
            ('adrp', 'x9, #0x1d5fda000'), ('add', 'x9, x9, #0x100'),
            ('cmp', 'w20, #0'), ('csel', 'x3, x9, x8, ne'), ('bl', '#0x3000'))
        members, unpaired = SF._pair_members(
            ctx, order, lambda k: 1 if order[k].mnemonic == 'ldrb' else None)
        self.assertEqual((unpaired, members), (0, {1: SF.MemberDict(None, None)}))

    def test_a_plain_member_is_not_an_enum_even_with_a_key(self):
        ctx = _TextCtx({0x1d5fda0e0: 'time'})
        order = self._insns(('ldr', 'd0, [x20]'), ('adrp', 'x3, #0x1d5fda000'),
                            ('add', 'x3, x3, #0xe0'), ('bl', '#0x3000'))
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
        begin, end = SF._scratch_slot_of(order, 3), SF._scratch_slot_of(order, 6)
        self.assertEqual(begin, end)
        self.assertIsNotNone(begin)

    def test_value_is_stack_scratch_accepts_the_frame_relative_form(self):
        order, _ = asm((0x1000, [('sub', 'x1, x29, #0xd8'), ('mov', 'w2, #0xb'),
                                 ('bl', '#0x18dbdab88')]))
        self.assertTrue(W._value_is_stack_scratch(order, 2))
        order, _ = asm((0x1000, [('sub', 'x1, x21, #0xd8'), ('mov', 'w2, #0xb'),
                                 ('bl', '#0x18dbdab88')]))
        self.assertFalse(W._value_is_stack_scratch(order, 2))


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


if __name__ == '__main__':
    unittest.main()
