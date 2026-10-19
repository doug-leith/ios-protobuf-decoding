"""Tests for the opaque-passthrough detector (`_is_opaque_passthrough`).

Some Apple PBCodable subclasses declare NO wire fields of their own: their only
ivar is the inherited ``_unknownFields`` bag and ``-[cls writeTo:]`` just loads it
and tail-calls ``writeTo:`` on it, so the message is an opaque passthrough — "no
fields recovered" is GROUND TRUTH, not an extraction miss.  The detector flags
these so the emitter prints a distinct comment.  Hopper-verified anchor case:
GEOPDReverseGeocodingResult (see notes/REVGEO_OPAQUE_PASSTHROUGH_2026-06-17.md).
"""
import os
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
ROOT  = os.path.dirname(os.path.dirname(_HERE))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import artifacts
import proto.extractor as E


def _cache_present():
    return artifacts.cache_file() is not None


@unittest.skipUnless(_cache_present(), 'dyld shared cache not available')
class TestOpaquePassthroughLive(unittest.TestCase):
    """Detector behaviour against the real GeoServices cache image."""

    @classmethod
    def setUpClass(cls):
        import live_artifacts as V
        loaded = V.load_cache('GeoServices')
        if loaded is None:
            cls.ctx = cls.cl = cls.msgs = None
            return
        cls.ctx, cls.st, cls.cl = loaded
        cls.msgs = {m.class_name: m for m in E.extract_all(cls.ctx, cls.st, cls.cl)}

    def setUp(self):
        if not getattr(self, 'msgs', None):
            self.skipTest('GeoServices not available')

    def test_revgeo_is_flagged_opaque(self):
        m = self.msgs.get('GEOPDReverseGeocodingResult')
        self.assertIsNotNone(m)
        self.assertEqual(m.fields, [])
        self.assertTrue(m.opaque_passthrough)

    def test_detector_helper_on_revgeo(self):
        cls = self.cl.find('GEOPDReverseGeocodingResult')
        self.assertTrue(E._is_opaque_passthrough(self.ctx, cls))

    def test_flag_implies_field_less(self):
        # The flag must never appear on a message that has typed fields.
        for m in self.msgs.values():
            if m.opaque_passthrough:
                self.assertEqual(
                    m.fields, [],
                    f"{m.class_name} flagged opaque but has fields")

    def test_detector_rejects_field_bearing_class_on_its_own_merits(self):
        # The above test alone is close to tautological: the call site sets
        # `opaque_passthrough=(not fields) and _is_opaque_passthrough(...)`, so a
        # field-bearing message is `False` from the `(not fields)` short-circuit
        # alone -- `_is_opaque_passthrough` is never even called, let alone
        # exercised.  Call the detector DIRECTLY on a real field-bearing class
        # (bypassing that call-site guard entirely) so its own structural check
        # (ivar count/name/type + writeTo: shape) is what's actually asserted.
        cls = self.cl.find('GEOPDComponent')
        self.assertIsNotNone(cls)
        self.assertGreater(len(cls.ivars), 1, 'fixture must be a real multi-ivar class')
        self.assertFalse(E._is_opaque_passthrough(self.ctx, cls))

    def test_some_field_less_messages_are_not_opaque(self):
        # The whole point is to DISTINGUISH: not every field-less message is an
        # opaque passthrough (some are extension stubs / genuine misses).
        field_less = [m for m in self.msgs.values() if not m.fields]
        opaque     = [m for m in field_less if m.opaque_passthrough]
        self.assertTrue(opaque, "expected some opaque passthroughs")
        self.assertTrue(
            len(opaque) < len(field_less),
            "expected SOME field-less messages to NOT be opaque passthroughs")

    def test_a_non_opaque_field_less_message_keeps_plain_comment(self):
        # GEOACResult is field-less but NOT an opaque passthrough — it must keep
        # the "(no fields recovered)" wording, not the opaque comment. Rendered
        # via the real proto.emitter.ProtoFile._emit_message path (not the
        # deleted ProtoMessage.to_proto ).
        m = self.msgs.get('GEOACResult')
        if m is None:
            self.skipTest('GEOACResult not present in this build')
        self.assertEqual(m.fields, [])
        self.assertFalse(m.opaque_passthrough)
        from proto.emitter import ProtoFile
        pf = ProtoFile(package="test", filename="test.proto", messages=[], imports=[])
        out = "\n".join(pf._emit_message(m, {}))
        self.assertIn('// (no fields recovered)', out)


class _SlotCtx:
    """Just the ivar-offset variables a stub reads."""
    def __init__(self, s32):
        self.s32 = s32

    def read_s32(self, addr):
        return self.s32[addr]


def _listing(*lines, base=0x1000):
    from macho.disasm import Insn
    return [Insn(addr=base + 4 * i, mnemonic=mn, op_str=op, size=4, raw=b'\x00' * 4)
            for i, (mn, op) in enumerate(lines)]


class TestSelfLoadOffset(unittest.TestCase):
    """`_writeto_self_load_offset`: the ivar of self in x0 at the tail call, by reaching
    definitions (TODO #81 (3)) -- not by the literal registers x8 / x0."""

    CTX = _SlotCtx({0x10040: 8})

    def test_offset_table_form(self):
        insns = _listing(('adrp', 'x8, #0x10000'), ('ldrsw', 'x8, [x8, #0x40]'),
                         ('ldr', 'x0, [x0, x8]'), ('b', '#0x2000'))
        self.assertEqual(E._writeto_self_load_offset(self.CTX, insns), 8)

    def test_any_offset_register(self):
        insns = _listing(('adrp', 'x9, #0x10000'), ('ldrsw', 'x9, [x9, #0x40]'),
                         ('ldr', 'x0, [x0, x9]'), ('b', '#0x2000'))
        self.assertEqual(E._writeto_self_load_offset(self.CTX, insns), 8)

    def test_self_through_a_copy(self):
        insns = _listing(('mov', 'x10, x0'), ('adrp', 'x8, #0x10000'),
                         ('ldrsw', 'x8, [x8, #0x40]'), ('ldr', 'x0, [x10, x8]'),
                         ('b', '#0x2000'))
        self.assertEqual(E._writeto_self_load_offset(self.CTX, insns), 8)

    def test_address_computed_in_a_register(self):
        # iOS 27 -[GEOPDReverseGeocodingResult writeTo:] (0x190d7bfb0): self + offset is
        # formed with `add` before the load
        ctx = _SlotCtx({0x1e4559550: 8})
        insns = _listing(('adrp', 'x8, #0x1e4559000'), ('ldrsw', 'x8, [x8, #0x550]'),
                         ('add', 'x8, x0, x8'), ('ldr', 'x0, [x8]'), ('b', '#0x198040bf0'),
                         base=0x190d7bfb0)
        self.assertEqual(E._writeto_self_load_offset(ctx, insns), 8)

    def test_added_offset_that_is_not_an_ivar_offset(self):
        insns = _listing(('mov', 'x8, #0x40'), ('add', 'x8, x0, x8'), ('ldr', 'x0, [x8]'),
                         ('b', '#0x2000'))
        self.assertIsNone(E._writeto_self_load_offset(self.CTX, insns))

    def test_immediate_offset(self):
        insns = _listing(('ldr', 'x0, [x0, #0x10]'), ('b', '#0x2000'))
        self.assertEqual(E._writeto_self_load_offset(self.CTX, insns), 0x10)

    def test_load_from_another_object_is_not_self(self):
        # x0 is the WRITER's field here, not self's (the old regex matched `ldr x0, [x0`)
        insns = _listing(('mov', 'x0, x1'), ('adrp', 'x8, #0x10000'),
                         ('ldrsw', 'x8, [x8, #0x40]'), ('ldr', 'x0, [x0, x8]'),
                         ('b', '#0x2000'))
        self.assertIsNone(E._writeto_self_load_offset(self.CTX, insns))

    def test_x0_not_loaded(self):
        insns = _listing(('mov', 'x0, x1'), ('b', '#0x2000'))
        self.assertIsNone(E._writeto_self_load_offset(self.CTX, insns))


if __name__ == '__main__':
    unittest.main()
