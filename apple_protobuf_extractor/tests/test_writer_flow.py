"""Rule (b): an ivar whose value can never reach the PBDataWriter in its class's own
``writeTo:`` is not a wire field (:mod:`proto.writer_flow`), plus what it is built on: the
dyld-cache export-trie reader (callee names) and the iOS 27 shared selector stub.

Before this, such ivars were emitted with ivar-order "number estimated" numbers: the
GEOMapItemStorage trampoline / geoMapItem / geoMapItemIsolater (whole-image IDA cross-check
2026-10-15), CoreParsec's oneof-case ivars (``_whichKind`` ...) and
PETProtobufRawDecodedMessage's two dictionaries (its ``writeTo:`` is a bare ``ret``).
"""
import os
import unittest

import artifacts
from macho.export_trie import decode_export_trie
from proto.writer_flow import WriterFlow, writer_reachable_ivars


def _uleb(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


class TestExportTrie(unittest.TestCase):
    def _trie(self):
        # root -> "_a" (export at image offset 0x1234) and "_b" (a re-export: no address)
        a_node = _uleb(3) + _uleb(0) + _uleb(0x1234) + b"\x00"
        b_term = _uleb(0x08) + _uleb(1) + b"_c\x00"
        b_node = _uleb(len(b_term)) + b_term + b"\x00"
        # offsets of the child nodes are only known once the root is laid out
        for guess in range(8, 64):
            root = _uleb(0) + b"\x02" + b"_a\x00" + _uleb(guess) + b"_b\x00" + \
                _uleb(guess + len(a_node))
            if len(root) == guess:
                return root + a_node + b_node
        raise AssertionError("layout")

    def test_names_offsets_and_skips_reexports(self):
        self.assertEqual(decode_export_trie(self._trie()), {"_a": (0, 0x1234)})

    def test_truncated_trie_does_not_raise(self):
        self.assertIsInstance(decode_export_trie(self._trie()[:5]), dict)


class TestZeroEdge(unittest.TestCase):
    class _I:
        def __init__(self, mn, op, addr=0x1000):
            self.mnemonic, self.op_str, self.addr = mn, op, addr

    def test_cbz_taken_edge_and_cbnz_fallthrough(self):
        self.assertEqual(WriterFlow._zero_edge(self._I("cbz", "x0, #0x2000")), ("x0", 0x2000))
        self.assertEqual(WriterFlow._zero_edge(self._I("cbnz", "w8, #0x2000")), ("x8", 0x1004))
        self.assertIsNone(WriterFlow._zero_edge(self._I("tbz", "w8, #0, #0x2000")))


class TestFastEnumerationContract(unittest.TestCase):
    """``countByEnumeratingWithState:objects:count:`` refills the NSFastEnumerationState its
    caller reuses: what a later loop reads through ``itemsPtr`` derives from that call's
    receiver only, not from the arrays earlier loops enumerated."""

    def test_state_holds_only_the_receiver_after_the_call(self):
        from types import SimpleNamespace
        from unittest import mock
        import proto.writer_flow as WF
        wf = WF.WriterFlow(SimpleNamespace(segments=[]), [])
        wf._cx = {0x1000: {'sp': WF._STACK_TOP, 'x2': WF._STACK_TOP + 0x40}}   # x2 = &state
        st = WF._St({'x0': frozenset({('I', '_b')})})
        st.frame_write(0x40, 64, frozenset({('I', '_a')}))      # an earlier loop's state
        with mock.patch.object(WF, 'stub_selector', lambda ctx, va: WF._FAST_ENUMERATION), \
                mock.patch.object(WF, 'callee_name', lambda ctx, va: None):
            wf._call(st, 0x9000, WF._Result(), 0, 0, 0x1000)
        self.assertEqual(st.frame_read(0x48, 8), frozenset({('I', '_b')}))   # itemsPtr
        self.assertEqual(st.p('x0'), frozenset({('I', '_b')}))               # the count



class TestFrameAddressesComeFromTheEvaluation(unittest.TestCase):
    """WriterFlow reads frame addresses from the function's Flow run, so a large frame's
    shifted ``sub sp, sp, #1, lsl #12`` is the 4096 bytes it is: a value stored through x29
    and reloaded through sp is the same slot (GEOActiveTileGroup's prologue; WriterFlow's
    own constant tracking used to read only the unshifted form)."""

    def test_a_slot_stored_through_x29_reloads_through_a_shifted_sp(self):
        from types import SimpleNamespace
        from unittest import mock
        import proto.writer_flow as WF
        from tests._listing import layout
        _order, fd = layout((0x1000, [
            ('stp', 'x29, x30, [sp, #-0x10]!'), ('mov', 'x29, sp'),
            ('sub', 'sp, sp, #1, lsl #12'),
            ('mov', 'x19, x2'), ('ldr', 'x8, [x0, #8]'),     # self->_a
            ('stur', 'x8, [x29, #-8]'),
            ('ldr', 'x1, [sp, #0xff8]'),                     # sp + 0xff8 == x29 - 8
            ('mov', 'x0, x19'), ('mov', 'w2, #1'), ('bl', '#0x9000'), ('ret', '')]))
        wf = WF.WriterFlow(SimpleNamespace(segments=[]), [])
        wf.off_to_ivar = {8: '_a'}
        with mock.patch('proto.dispatch_eval.disasm', fd), \
                mock.patch.object(WF, 'callee_name', lambda ctx, va: None), \
                mock.patch.object(WF, 'stub_selector', lambda ctx, va: None):
            res = wf._run(0x1000, {'x0': frozenset({'S'}), 'x2': frozenset({'W'})}, 0, 0x1000)
        site = res.sites[0x1024]
        self.assertEqual((site.number, set(site.value_origins)), (1, {('I', '_a')}))

try:
    import live_artifacts as _V
    _HAVE = artifacts.cache_file() is not None
except Exception:
    _HAVE = False


def _bound_ivars(ctx, cl, cls):
    import proto.writeto as W
    from proto.protocore import _is_real_field_ivar
    from proto.write_helpers import _ensure_writeto_prepass
    names = {m.name for m in cls.methods if m.name}
    fivars = [iv for iv in cls.ivars if _is_real_field_ivar(iv, names)]
    _ensure_writeto_prepass(ctx, cl)
    return set(W._extract_writeto_field_numbers(ctx, cls, fivars).numbers)


@unittest.skipUnless(_HAVE, "iPhone 8 dyld cache not available")
class TestCacheExports(unittest.TestCase):
    def test_libobjc_and_protocolbuffer_exports(self):
        from macho.dyld_cache import DyldCacheReader
        r = DyldCacheReader(artifacts.cache_file())
        objc = r.image_exports(r.find_image_header("libobjc.A.dylib"))
        pb = r.image_exports(r.find_image_header("ProtocolBuffer"))
        for name in ("_objc_retain_x2", "_objc_release_x19", "_objc_autoreleaseReturnValue"):
            self.assertIn(name, objc)
            self.assertEqual(r.export_name_at(objc[name]), name)
        self.assertEqual(r.export_name_at(pb["_PBDataWriterWriteInt32Field"]),
                         "_PBDataWriterWriteInt32Field")
        self.assertIsNone(r.export_name_at(objc["_objc_retain_x2"] + 4))   # mid-function

    def test_callee_name_follows_the_image_stub(self):
        # CoreParsec's -[_CPValue writeTo:] retains the writer through a stub island.
        from proto.callees import callee_name
        from macho.disasm import disasm, _parse_imm
        ctx, _st, cl = _V.load_cache("CoreParsec")
        imp = cl.find("_CPValue").get_method("writeTo:").imp
        first_bl = next(i for i in disasm(ctx, imp, max_insns=16, stop_at_ret=True)
                        if i.mnemonic == "bl")
        self.assertEqual(callee_name(ctx, _parse_imm(first_bl.op_str)), "_objc_retain_x2")


@unittest.skipUnless(_HAVE, "iPhone 8 dyld cache not available")
class TestWriterFlowLive(unittest.TestCase):
    def _check(self, image, cls_name, gone=(), kept=()):
        ctx, _st, cl = _V.load_cache(image)
        cls = cl.find(cls_name)
        reach, why = writer_reachable_ivars(ctx, cl, cls)
        self.assertIsNotNone(reach, f"{cls_name} undecided: {why}")
        self.assertLessEqual(_bound_ivars(ctx, cl, cls), reach)   # every bound ivar reaches it
        for iv in gone:
            self.assertNotIn(iv, reach)
        for iv in kept:
            self.assertIn(iv, reach)
        return reach

    def test_oneof_case_ivar_never_reaches_the_writer(self):
        # -[_CPValue string_value] reads _whichKind only to choose; it returns _string_value.
        self._check("CoreParsec", "_CPValue", gone=("_whichKind",),
                    kept=("_string_value", "_struct_value", "_bytes_value"))

    def test_bare_ret_writeto_serialises_nothing(self):
        self.assertEqual(self._check("ProactiveEventTracker", "PETProtobufRawDecodedMessage",
                                     gone=("_decodedDict", "_nestedFields")), frozenset())

    def test_fast_enumerated_arrays_reach_the_writer(self):
        # the elements come back through the countByEnumeratingWithState: buffer
        self._check("ProactiveEventTracker", "PETUpload",
                    kept=("_aggregatedMessages", "_unaggregatedMessages"))

    def test_mapitemstorage_helper_ivars(self):
        # writeTo: writes fields 1-9 and, when unmodified, re-emits its reader's bytes; the
        # notification trampoline, the <GEOMapItem> and the isolater never reach the writer.
        self._check("GeoServices", "GEOMapItemStorage",
                    gone=("_trampoline", "_geoMapItem", "_geoMapItemIsolater"),
                    kept=("_placeData", "_mapsURL", "_additionalPlaceDatas"))

    def test_class_that_serialises_no_ivar_says_so(self):
        import proto.extractor as E
        from proto.emitter import ProtoFile
        ctx, st, cl = _V.load_cache("ProactiveEventTracker")
        m = E.extract_proto_message(ctx, st, cl, cl.find("PETProtobufRawDecodedMessage"))
        self.assertEqual(m.fields, [])
        self.assertTrue(m.writes_no_ivars)
        pf = ProtoFile(package="t", filename="t.proto", messages=[], imports=[])
        out = "\n".join(pf._emit_message(m, {}))
        self.assertIn("writeTo: serialises none of this class's ivars", out)
        self.assertNotIn("(no fields recovered)", out)

    def test_extraction_drops_them(self):
        import proto.extractor as E
        ctx, st, cl = _V.load_cache("GeoServices")
        m = E.extract_proto_message(ctx, st, cl, cl.find("GEOMapItemStorage"))
        self.assertEqual(sorted(f.number for f in m.fields), list(range(1, 10)))
        self.assertTrue(all(f.number_confirmed for f in m.fields))


def _ios27_cache_dir():
    d = os.environ.get("MACHO_TEST_IOS27_CACHE", "").strip() or \
        os.path.join(artifacts.REPO_ROOT, "ios27_data", "dylib")
    return d if os.path.isfile(os.path.join(d, "dyld_shared_cache_arm64e")) else None


@unittest.skipUnless(_ios27_cache_dir(), "iOS 27 cache not present")
class TestIOS27SharedSelectorStub(unittest.TestCase):
    def test_add_form_stub_is_a_message_send(self):
        # iOS 27: `adrp x1,#page ; add x1,x1,#off ; b _objc_msgSend` (x1 = the selector string)
        from macho.dyld_cache import DyldCacheReader
        from macho.memory import BinaryContext
        from macho.strings import build_string_table
        from macho.classlist import build_class_list
        from macho.disasm import disasm
        from proto.callees import stub_selector
        r = DyldCacheReader(os.path.join(_ios27_cache_dir(), "dyld_shared_cache_arm64e"))
        mv = r.find_image_header("GeoServices")
        ctx = BinaryContext.from_cache(r, mv)
        cl = build_class_list(ctx, build_string_table(ctx))
        wf = WriterFlow(ctx, cl)
        cls = cl.find("GEOPlaceSearchRequest")
        add_form = [s.target for s in wf.write_sites(cls) if s.target is not None
                    and [i.mnemonic for i in disasm(ctx, s.target, 3, stop_at_ret=False)]
                    == ["adrp", "add", "b"]]
        self.assertTrue(add_form)
        sels = {stub_selector(ctx, t) for t in add_form}
        self.assertNotIn(None, sels)
        self.assertIn("writeData:", sels)
        self.assertIn("writeData:", wf.sent_selectors(cls))


if __name__ == "__main__":
    unittest.main()
