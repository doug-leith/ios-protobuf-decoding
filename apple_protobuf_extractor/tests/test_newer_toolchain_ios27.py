"""Newer-toolchain (iOS 27 / macOS 27, arm64e) recovery fixes, 2026-10-04.

Four shapes that the iPhone 8 images never contain made the iOS 27 / macOS 27 runs
degrade (see notes/descriptor_comparison_2026-10-04/REPORT.md):

* a tail call ``b <fn>`` straight into ANOTHER image (the old toolchain branched to a stub
  in the image's own ``__stubs``) was taken for the method's own outlined block, the walk
  ran off the image, and the whole class fell back to ivar-order "number estimated";
* a ``bl`` to a no-return function followed by ``udf`` padding let the walk read on into
  the next method;
* the write helper of a fixed-width field computes ``lsl w,field,#3`` BEFORE its
  ``mov w,#5 ; bfi`` tag build, so the sfixed32 helper was classified plain (int32);
* enum ``switch`` jump tables are read with ``ldrsw`` (signed byte-delta entries, not the
  unsigned ``*4`` index of ``ldrh``/``ldrb`` tables), so ``…AsString:`` and
  ``_dictionaryRepresentation:`` enums came back as ``int32`` or with a partial value set.

The offline tests drive the decoders with hand-built instructions.  The live tests
(skipped unless an iOS 27 cache is present: ``<repo>/ios27_data/dylib``, or
``MACHO_TEST_IOS27_CACHE``) assert facts about the real cache that are also true of the
iPhone 8 golden schema — i.e. the iOS 16 numbers/types the later build must still produce.
Those runs are NOT golden-guarded; these assertions are the guard.
"""
import os
import unittest

import artifacts
import proto.writeto as W
from macho.arm64decode import jumptable_arm_target
from macho.disasm import Insn
from macho.memory import Segment


# ── offline: the walk ─────────────────────────────────────────────────────────

def _asm(*blocks):
    mem = {}
    for base, lines in blocks:
        a = base
        for mn, op in lines:
            mem[a] = Insn(addr=a, mnemonic=mn, op_str=op, size=4, raw=b'\x00\x00\x00\x00')
            a += 4

    def fake_disasm(ctx, addr, max_insns=400, stop_at_ret=False):
        out, a = [], addr
        while len(out) < max_insns and a in mem:
            out.append(mem[a])
            a += 4
        return out
    return fake_disasm


class _ImageCtx:
    """Stand-in context exposing only ``segments`` (what ``_image_text_range`` reads)."""
    def __init__(self, lo, size):
        self.segments = [Segment(name="__TEXT", vmaddr=lo, vmsize=size, fileoff=0, filesize=size)]


def _walk(fd, imp, ctx, **kw):
    orig = W.disasm
    W.disasm = fd
    try:
        writes, _ = W.writeto_walk(ctx, imp, set(), kw.pop("indeg", {}), **kw)
    finally:
        W.disasm = orig
    return {w['n'] for w in writes}


class TestWalkStaysInImage(unittest.TestCase):
    # Image text is [0x1000, 0x2000); 0x9000 is another image's code.
    CTX = _ImageCtx(0x1000, 0x1000)

    def test_image_text_range(self):
        self.assertEqual(W._image_text_range(self.CTX), (0x1000, 0x2000))
        self.assertIsNone(W._image_text_range(None))           # unit-test stub: no bound

    def test_tail_call_into_other_image_not_followed(self):
        # `b 0x9000` is branched to from this method only, so the in-degree test alone
        # calls it "our own outlined block".  It is outside the image's __TEXT: not ours.
        fd = _asm(
            (0x1000, [('mov', 'w2, #1'), ('bl', '#0x1800'), ('b', '#0x9000')]),
            (0x9000, [('mov', 'w2, #77'), ('bl', '#0x1800'), ('ret', '')]),
        )
        self.assertEqual(_walk(fd, 0x1000, self.CTX, indeg={0x9000: {0x1000}}), {1})

    def test_same_tail_call_followed_without_an_image_bound(self):
        # Contrast: with no text range (stub ctx) the single-source target IS followed —
        # the bound, not something else, is what stops it above.
        fd = _asm(
            (0x1000, [('mov', 'w2, #1'), ('bl', '#0x1800'), ('b', '#0x9000')]),
            (0x9000, [('mov', 'w2, #77'), ('bl', '#0x1800'), ('ret', '')]),
        )
        self.assertEqual(_walk(fd, 0x1000, None, indeg={0x9000: {0x1000}}), {1, 77})

    def test_in_image_outlined_block_still_followed(self):
        fd = _asm(
            (0x1000, [('mov', 'w2, #1'), ('bl', '#0x1800'), ('b', '#0x1500')]),
            (0x1500, [('mov', 'w2, #2'), ('bl', '#0x1800'), ('ret', '')]),
        )
        self.assertEqual(_walk(fd, 0x1000, self.CTX), {1, 2})

    def test_conditional_branch_out_of_image_not_followed(self):
        fd = _asm(
            (0x1000, [('cbz', 'x8, #0x9000'), ('mov', 'w2, #1'), ('bl', '#0x1800'), ('ret', '')]),
            (0x9000, [('mov', 'w2, #77'), ('bl', '#0x1800'), ('ret', '')]),
        )
        self.assertEqual(_walk(fd, 0x1000, self.CTX), {1})

    def test_tail_call_field_write_into_other_image_still_recorded(self):
        # `mov w2,#5 ; b <helper in another image>` is a field WRITE (the helper is where
        # the value is serialised), not a branch to follow: classified before the bound.
        fd = _asm((0x1000, [('mov', 'w2, #5'), ('b', '#0x9000')]))
        self.assertEqual(_walk(fd, 0x1000, self.CTX), {5})

    def test_udf_padding_ends_the_path(self):
        # `bl <no-return>` is followed by `udf` padding, then the NEXT method's body.
        fd = _asm((0x1000, [
            ('mov', 'w2, #1'), ('bl', '#0x1800'),
            ('bl', '#0x1900'), ('udf', '#0'), ('udf', '#0'),
            ('mov', 'w2, #9'), ('bl', '#0x1800'), ('ret', ''),          # the next method
        ]))
        self.assertEqual(_walk(fd, 0x1000, self.CTX), {1})


class TestFieldNumberInW1NeedsAnFpValue(unittest.TestCase):
    """`mov w1,#N` is the field number only for a double/float write (value in d0/s0)."""

    def test_w1_constant_without_fp_value_is_not_a_field_number(self):
        fd = _asm((0x1000, [
            ('mov', 'w2, #1'), ('bl', '#0x1800'),
            ('add', 'x0, x21, x8'), ('mov', 'w1, #0x10000'), ('bl', '#0x1900'),
            ('ret', ''),
        ]))
        self.assertEqual(_walk(fd, 0x1000, None), {1})

    def test_w1_with_d0_value_is_the_field_number(self):
        fd = _asm((0x1000, [
            ('ldr', 'd0, [x8]'), ('mov', 'x0, x19'), ('mov', 'w1, #0x14'), ('bl', '#0x1800'),
            ('ldr', 's0, [x9]'), ('mov', 'x0, x19'), ('mov', 'w1, #0x15'), ('bl', '#0x1800'),
            ('ret', ''),
        ]))
        self.assertEqual(_walk(fd, 0x1000, None), {0x14, 0x15})

    def test_newer_toolchain_vector_register_copy_counts_as_the_fp_value(self):
        # CLPPressure.writeTo: on iOS 27 passes a spilled double with `mov v0.16b,v8.16b`
        # (the old toolchain wrote `fmov d0,d8`).
        fd = _asm((0x1000, [
            ('ldr', 'd8, [x8]'), ('bl', '#0x1900'),
            ('mov', 'v0.16b, v8.16b'), ('mov', 'w1, #1'), ('bl', '#0x1800'),
            ('ret', ''),
        ]))
        self.assertEqual(_walk(fd, 0x1000, None), {1})

    def test_store_of_d0_is_not_an_fp_argument(self):
        # `str d0,[sp]` READS d0; it does not set up the call's FP argument.
        fd = _asm((0x1000, [
            ('str', 'd0, [sp, #8]'), ('mov', 'w1, #0x10000'), ('bl', '#0x1900'),
            ('ret', ''),
        ]))
        self.assertEqual(_walk(fd, 0x1000, None), set())

    def test_fp_value_of_an_earlier_call_does_not_count(self):
        # d0 was set for the PREVIOUS call; the scan stops at that `bl`.
        fd = _asm((0x1000, [
            ('ldr', 'd0, [x8]'), ('mov', 'w1, #0x14'), ('bl', '#0x1800'),
            ('mov', 'w1, #0x10000'), ('bl', '#0x1900'),
            ('ret', ''),
        ]))
        self.assertEqual(_walk(fd, 0x1000, None), {0x14})


# ── offline: jump-table arm address ───────────────────────────────────────────

class TestJumpTableArmTarget(unittest.TestCase):
    def test_unsigned_index_table_is_scaled_by_4(self):
        # ldrb / ldrh: entry is an arm INDEX, `add xB,xB,w,lsl #2`
        self.assertEqual(jumptable_arm_target(0x1000, 1, b'\x05'), 0x1000 + 5 * 4)
        self.assertEqual(jumptable_arm_target(0x1000, 2, b'\x00\x01'), 0x1000 + 256 * 4)

    def test_ldrsw_table_is_a_signed_unscaled_byte_delta(self):
        # ldrsw: `adr xB,. ; ldrsw x,[table,idx,lsl#2] ; add xB,xB,x ; br`
        self.assertEqual(jumptable_arm_target(0x1000, 4, (0x120).to_bytes(4, 'little')),
                         0x1000 + 0x120)
        self.assertEqual(jumptable_arm_target(0x1000, 4, (-0x40 & 0xFFFFFFFF).to_bytes(4, 'little')),
                         0x1000 - 0x40)


def _insns(*lines):
    return [Insn(addr=0x1000 + 4 * i, mnemonic=mn, op_str=op, size=4, raw=b'\0\0\0\0')
            for i, (mn, op) in enumerate(lines)]


# ── offline: does the engine use the table it is handed? ──────────────────────

class TestCoreReadsTableArg(unittest.TestCase):
    def _reads(self, *lines):
        import proto.dispatch as D
        orig = D._core_insns
        D._core_insns = lambda ctx, va: _insns(*lines)
        try:
            return D._core_reads_table_arg(None, 0x1000)
        finally:
            D._core_insns = orig

    def test_engine_indexing_its_table_through_a_copy_of_x2(self):
        # GEOLPRWorld's engine: `mov x21,x2 ; … ; ldr w12,[x21,x8,lsl #2]`
        self.assertTrue(self._reads(('mov', 'x21, x2'), ('ldr', 'w12, [x21, x8, lsl #2]')))

    def test_direct_load_from_x2(self):
        self.assertTrue(self._reads(('ldrb', 'w8, [x2, x9]')))

    def test_table_only_forwarded_is_not_the_engine(self):
        # f27 TestGrPlainEngine: the constant is handed on to another call, never read.
        self.assertFalse(self._reads(('mov', 'x21, x2'), ('mov', 'x0, x21'), ('bl', '#0x2000')))

    def test_overwritten_copy_is_no_longer_the_table(self):
        self.assertFalse(self._reads(('mov', 'x21, x2'), ('mov', 'x21, x8'),
                                     ('ldr', 'w12, [x21, x8, lsl #2]')))


# ── live: the real iOS 27 cache ───────────────────────────────────────────────

def _ios27_cache_dir():
    d = os.environ.get("MACHO_TEST_IOS27_CACHE", "").strip() or \
        os.path.join(artifacts.REPO_ROOT, "ios27_data", "dylib")
    return d if os.path.isfile(os.path.join(d, "dyld_shared_cache_arm64e")) else None


@unittest.skipUnless(_ios27_cache_dir(), "iOS 27 cache not present")
class TestIos27Live(unittest.TestCase):
    """Facts about iOS 27's GeoServices that the iPhone 8 golden schema also states."""
    @classmethod
    def setUpClass(cls):
        from macho.dyld_cache import DyldCacheReader
        from macho.memory import BinaryContext
        from macho.strings import build_string_table
        from macho.classlist import build_class_list
        from macho.local_symbols import apply_to_classes
        import proto.extractor as E
        reader = DyldCacheReader(os.path.join(_ios27_cache_dir(), "dyld_shared_cache_arm64e"))
        mv = reader.find_image_header("GeoServices")
        cls.ctx = BinaryContext.from_cache(reader, mv)
        st = cls.st = build_string_table(cls.ctx)
        cl = cls.cl = build_class_list(cls.ctx, st)
        syms = reader.image_local_symbols(mv)
        if syms:
            apply_to_classes(cl, syms)
        wanted = {"GEOClientNetworkMetrics", "GEOPDPhotoPosition", "GEOPDTip", "GEOLPRWorld", "GEOLatLngE7",
                  "GEOLPRBoundingBoxE7", "GEOPDComponent", "GEOTileSet"}
        # extract_all runs the binary-wide pre-passes; keep only the classes under test.
        cls.msgs = {m.class_name: m for m in E.extract_all(cls.ctx, st, cl)
                    if m.class_name in wanted}

    def _fields(self, cname):
        return {f.name: f for f in self.msgs[cname].fields}

    def test_walk_confirms_every_number_of_a_class_that_used_to_fall_back(self):
        # GEOClientNetworkMetrics' writeTo: tail-calls out of the image; before the fix its
        # nine fields were ALL "number estimated".  Expected = the iPhone 8 (golden) numbers,
        # incl. the two doubles at 20/21 (field# in w1, value in d0).
        f = self._fields("GEOClientNetworkMetrics")
        self.assertTrue(all(x.number_confirmed for x in f.values()))
        self.assertEqual({k: v.number for k, v in f.items()}, {
            "httpResponseCode": 1, "serviceIpAddress": 2, "requestDataSize": 3,
            "responseDataSize": 4, "rnfTriggered": 5, "requestStart": 20,
            "requestEnd": 21, "redirectCount": 22, "transactionMetrics": 23})

    def test_photo_position_numbers_confirmed(self):
        f = self._fields("GEOPDPhotoPosition")
        self.assertTrue(all(x.number_confirmed for x in f.values()))
        self.assertEqual(sorted(x.number for x in f.values()), list(range(1, 13)))

    def test_no_field_number_65536_from_a_lock_option_argument(self):
        # GEOPDTip.writeTo: calls os_unfair_lock_lock_with_options(lock, 0x10000); the
        # `mov w1,#0x10000` is not a double-field write, and used to bind _tipster = 65536.
        f = self._fields("GEOPDTip")
        self.assertEqual({k: v.number for k, v in f.items()},
                         {"snippets": 1, "tipTime": 2, "tipster": 3, "tipId": 4})

    def test_latlng_e7_is_sfixed32(self):
        # iOS 16: sfixed32 (wire type 5, confirmed by plausible values in live traffic).
        # The iOS 27 helper builds the tag with `mov w9,#5 ; bfi w9,w21,#3,#0x1d`.
        f = self._fields("GEOLatLngE7")
        self.assertEqual({k: v.type_name for k, v in f.items()},
                         {"latE7": "sfixed32", "lngE7": "sfixed32"})

    def test_lpr_bounding_box_e7_is_sfixed32(self):
        f = self._fields("GEOLPRBoundingBoxE7")
        self.assertEqual(len(f), 4)
        self.assertTrue(all(x.type_name == "sfixed32" for x in f.values()))

    def test_single_table_engine_resolves_element_types(self):
        # GEOLPRWorld's readFrom engine is called with ONE const table (no csel of two).
        # iPhone 8: regions -> LPRRegion, powerTypes -> LPRPowerTypeMap, vehicleTypes ->
        # LPRVehicleTypeMap (the ObjC class names carry the GEO prefix; the emitter strips it).
        f = self._fields("GEOLPRWorld")
        self.assertEqual({k: v.type_name for k, v in f.items()},
                         {"regions": "GEOLPRRegion", "powerTypes": "GEOLPRPowerTypeMap",
                          "vehicleTypes": "GEOLPRVehicleTypeMap"})
        self.assertTrue(all(v.unresolved_type_class is None and not v.type_inference_note
                            for v in f.values()))      # resolved, not name-suffix guessed

    def test_sparse_enum_with_a_hole_is_read_in_full(self):
        # networkServiceAsString:'s pointer table has an undeclared value 15; the iPhone 8
        # enum has all 29 values (0..28).  Reading to the first empty slot gave 15.
        from proto.enums import _extract_enum_values
        m = next(c for c in self.cl if c.name == "GEOLogMsgEventNetwork" and not c.is_meta)
        imp = m.get_method("networkServiceAsString:").imp
        pairs, _confirmed, _trunc = _extract_enum_values(self.ctx, imp, self.st)
        self.assertEqual([v for v, _ in pairs], [v for v in range(29) if v != 15])

    def test_component_type_is_the_enum_not_int32(self):
        # `_dictionaryRepresentation:` switches with `ldrsw` signed-delta jump-table entries.
        t = self._fields("GEOPDComponent")["type"]
        self.assertNotEqual(t.type_name, "int32")
        self.assertEqual(t.type_class, "ENUM:ComponentType")      # iOS 16's name, 89 values


@unittest.skipUnless(_ios27_cache_dir(), "iOS 27 cache not present")
class TestIos27ImagesBeyond4GB(unittest.TestCase):
    """Images whose data lies past cache_base + 4 GB (slide-info v5, 34-bit runtime offset).

    The 32-bit mask in ``decode_ptr`` mapped every pointer of such an image to a different
    *mapped* address, so MessageProtection (NGMPB) and TrustedPeers (TPPB) yielded no ObjC
    classes at all.  Expected schemas = the iPhone 8 ones (plus newer fields)."""

    @classmethod
    def setUpClass(cls):
        from macho.dyld_cache import DyldCacheReader
        from macho.memory import BinaryContext
        from macho.strings import build_string_table
        from macho.classlist import build_class_list
        import proto.extractor as E

        cls.reader = DyldCacheReader(os.path.join(_ios27_cache_dir(), "dyld_shared_cache_arm64e"))

        def run(fw):
            mv = cls.reader.find_image_header(fw)
            ctx = BinaryContext.from_cache(cls.reader, mv)
            st = build_string_table(ctx)
            cl = build_class_list(ctx, st)
            return mv, {m.class_name: m for m in E.extract_all(ctx, st, cl)}
        cls.mp_va, cls.mp = run("MessageProtection")
        cls.tp_va, cls.tp = run("TrustedPeers")

    @staticmethod
    def _nums(msg):
        return {f.name: f.number for f in msg.fields}

    def test_the_images_under_test_are_beyond_the_4gb_mark(self):
        lim = self.reader.cache_base + (1 << 32)
        for va in (self.mp_va, self.tp_va):
            start, _ = self.reader.image_sections(va)["__DATA_CONST/__objc_classlist"]
            self.assertGreaterEqual(start, lim)
        self.assertEqual(self.reader._runtime_offset_mask, (1 << 34) - 1)

    def test_message_protection_ngmpb_classes_are_recovered(self):
        self.assertEqual(
            sorted(n for n in self.mp if n.startswith("NGMPB")),
            ["NGMPBDevicePreKey", "NGMPBFullDeviceIdentity", "NGMPBInnerMessage", "NGMPBLegacyKey",
             "NGMPBOuterMessage", "NGMPBP256Key", "NGMPBPublicDeviceIdentity", "NGMPBPublicDevicePrekey"])

    def test_ngmpb_numbers_match_the_iphone8_schema(self):
        inner = self._nums(self.mp["NGMPBInnerMessage"])
        self.assertEqual(inner, {"message": 1, "counter": 2, "ktGossipData": 3, "debugInfo": 99})
        outer = self._nums(self.mp["NGMPBOuterMessage"])
        for name, num in {"encryptedPayload": 1, "ephemeralPubKey": 2, "signature": 3, "keyValidator": 99}.items():
            self.assertEqual(outer[name], num)
        self.assertTrue(all(f.number_confirmed for m in self.mp.values()
                            if m.class_name.startswith("NGMPB") for f in m.fields))

    def test_trusted_peers_tppb_classes_are_recovered(self):
        tppb = [n for n in self.tp if n.startswith("TPPB")]
        self.assertEqual(len(tppb), 29)
        self.assertEqual(self._nums(self.tp["TPPBVoucher"]), {"reason": 1, "beneficiary": 2, "sponsor": 3})


if __name__ == "__main__":
    unittest.main()
