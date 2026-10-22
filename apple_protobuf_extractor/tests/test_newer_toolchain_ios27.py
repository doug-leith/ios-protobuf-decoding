"""Newer-toolchain (iOS 27 / macOS 27, arm64e) recovery fixes, 2026-10-04.

Four shapes that the iPhone 8 images never contain made the iOS 27 / macOS 27 runs
degrade (see notes/descriptor_comparison_2026-10-04/REPORT.md):

* a tail call ``b <fn>`` straight into ANOTHER image (the old toolchain branched to a stub
  in the image's own ``__stubs``) was taken for the method's own outlined block, the
  writeTo: walk ran off the image, and the whole class fell back to ivar-order "number
  estimated" (the writer flow, which replaced the walk, takes it as a call);
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
from tests._listing import insns, layout
from tests._fakes import NoImage, TextImage

import artifacts
from proto.callees import text_holding


# ── offline: the writer flow on hand-built code ──────────────────────────────

def _asm(*blocks):
    return layout(*blocks)[1]


# Image text is [0x1000, 0x2000); 0x9000 is another image's code.
_CTX = TextImage((0x1000, 0x2000))
# writeTo: entry: self in x0, the writer in x2, kept in x19 across calls
_KEEP_WRITER = [('mov', 'x19, x2')]


def _flow(*blocks, names=None):
    """WriterFlow run of the writeTo: at 0x1000 in *blocks*: (decided, [site numbers]).
    *names* are the exported callee names; every other callee is an unnamed function."""
    from unittest import mock
    import proto.writer_flow as WF
    fd, names = _asm(*blocks), names or {}
    # a fresh context per listing: the evaluator memoises a listing's Flow on its context by
    # address, and every listing here starts at 0x1000
    wf = WF.WriterFlow(TextImage((0x1000, 0x2000)), [])
    with mock.patch('proto.function_body.disasm', fd), \
            mock.patch.object(WF, 'callee_name', lambda ctx, va: names.get(va)), \
            mock.patch.object(WF, 'stub_selector', lambda ctx, va: None):
        res = wf._run(0x1000, {'x0': frozenset({'S'}), 'x2': frozenset({'W'})}, 0, 0x1000)
    return res.complete, [res.sites[a].number for a in sorted(res.sites)]


class TestFlowStaysInImage(unittest.TestCase):
    def test_image_text(self):
        self.assertIsNotNone(text_holding(_CTX, 0x1800))
        self.assertIsNone(text_holding(_CTX, 0x9000))            # another image's code
        self.assertIsNone(text_holding(NoImage(), 0x1800))       # no __text: nothing is in it

    def test_tail_call_into_another_images_function_is_a_call(self):
        # `b 0x9000` to a function another image exports (the newer toolchain's direct
        # tail call): a call that ends the path, its code never read as this method's.
        code = (0x1000, _KEEP_WRITER + [('mov', 'x0, x19'), ('mov', 'w2, #1'),
                                        ('bl', '#0x1800'), ('b', '#0x9000')])
        other = (0x9000, [('mov', 'x0, x19'), ('mov', 'w2, #77'), ('bl', '#0x1800'),
                          ('ret', '')])
        decided, numbers = _flow(code, other, names={0x9000: "_objc_sync_exit"})
        self.assertTrue(decided)
        self.assertEqual([n for n in numbers if n is not None], [1])

    def test_branch_out_of_the_function_to_no_function_is_undecided(self):
        code = (0x1000, _KEEP_WRITER + [('mov', 'x0, x19'), ('mov', 'w2, #1'),
                                        ('bl', '#0x1800'), ('b', '#0x9000')])
        self.assertFalse(_flow(code)[0])

    def test_conditional_branch_out_of_the_function_is_undecided(self):
        code = (0x1000, _KEEP_WRITER + [('cbz', 'x8, #0x9000'), ('mov', 'x0, x19'),
                                        ('mov', 'w2, #1'), ('bl', '#0x1800'), ('ret', '')])
        self.assertFalse(_flow(code)[0])

    def test_no_return_call_ends_the_path(self):
        # `bl <no-return>` is followed by `udf` padding, then the NEXT method's body.
        code = (0x1000, _KEEP_WRITER + [
            ('mov', 'x0, x19'), ('mov', 'w2, #1'), ('bl', '#0x1800'),
            ('bl', '#0x1900'), ('udf', '#0'), ('udf', '#0'),
            ('mov', 'x0, x19'), ('mov', 'w2, #9'), ('bl', '#0x1800'), ('ret', '')])
        decided, numbers = _flow(code, names={0x1900: "___stack_chk_fail"})
        self.assertTrue(decided)
        self.assertEqual([n for n in numbers if n is not None], [1])


class TestFieldNumberInW1NeedsAnFpValue(unittest.TestCase):
    """For a writer with no ABI name, `mov w1,#N` is the field number only for a double /
    float write (value set up in v0 for that call); otherwise w2 is."""

    def _numbers(self, *lines):
        return _flow((0x1000, _KEEP_WRITER + list(lines) + [('ret', '')]))[1]

    def test_w1_constant_without_fp_value_is_not_a_field_number(self):
        self.assertEqual(self._numbers(
            ('mov', 'x0, x19'), ('mov', 'w1, #0x10000'), ('mov', 'w2, #3'), ('bl', '#0x1900'),
            ('mov', 'x0, x19'), ('mov', 'w1, #7'), ('bl', '#0x1900')), [3, None])

    def test_w1_with_d0_value_is_the_field_number(self):
        self.assertEqual(self._numbers(
            ('ldr', 'd0, [x8]'), ('mov', 'x0, x19'), ('mov', 'w1, #0x14'), ('bl', '#0x1800'),
            ('ldr', 's0, [x9]'), ('mov', 'x0, x19'), ('mov', 'w1, #0x15'), ('bl', '#0x1800')),
            [0x14, 0x15])

    def test_newer_toolchain_vector_register_copy_counts_as_the_fp_value(self):
        # CLPPressure.writeTo: on iOS 27 passes a spilled double with `mov v0.16b,v8.16b`
        # (the old toolchain wrote `fmov d0,d8`).
        self.assertEqual(self._numbers(
            ('ldr', 'd8, [x8]'), ('bl', '#0x1900'),
            ('mov', 'v0.16b, v8.16b'), ('mov', 'x0, x19'), ('mov', 'w1, #1'), ('bl', '#0x1800')),
            [None, 1])

    def test_store_of_d0_is_not_an_fp_argument(self):
        # `str d0,[sp]` READS d0; it does not set up the call's FP argument.
        self.assertEqual(self._numbers(
            ('str', 'd0, [sp, #8]'), ('mov', 'x0, x19'), ('mov', 'w1, #0x10000'),
            ('bl', '#0x1900')), [None])

    def test_fp_value_of_an_earlier_call_does_not_count(self):
        # d0 was set for the PREVIOUS call, which clobbers it.
        self.assertEqual(self._numbers(
            ('ldr', 'd0, [x8]'), ('mov', 'x0, x19'), ('mov', 'w1, #0x14'), ('bl', '#0x1800'),
            ('mov', 'x0, x19'), ('mov', 'w1, #0x10000'), ('bl', '#0x1900')), [0x14, None])


def _insns(*lines):
    return insns(lines)


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

    def test_every_number_of_a_class_that_used_to_fall_back_is_confirmed(self):
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
        pairs, _confirmed, _trunc = _extract_enum_values(self.ctx, imp)
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
