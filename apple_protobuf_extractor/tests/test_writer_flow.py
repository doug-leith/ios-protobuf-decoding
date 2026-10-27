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
from proto.writer_flow import WriterFlow, _ClassFlow, writer_reachable_ivars
from tests._fakes import NoImage, TextImage


def _uleb(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def _trie_bytes(nodes):
    """Trie bytes of *nodes* (``(terminal bytes, [(edge label, child index), ...])``, node 0
    the root), laid out in order."""
    offs = [0] * len(nodes)
    while True:      # the child offsets are only known once the nodes before them are laid out
        body = [_uleb(len(t)) + t + bytes([len(ch)]) +
                b"".join(lab + b"\x00" + _uleb(offs[i]) for lab, i in ch) for t, ch in nodes]
        new = [sum(map(len, body[:i])) for i in range(len(nodes))]
        if new == offs:
            return b"".join(body)
        offs = new


class TestExportTrie(unittest.TestCase):
    def _trie(self):
        # root -"_"-> {"a": export at image offset 0x1234,
        #              "b": a weak re-export (no address) -"x"-> "_bx", export at 0x5678}
        return _trie_bytes([
            (b"", [(b"_", 1)]),
            (b"", [(b"a", 2), (b"b", 3)]),
            (_uleb(0) + _uleb(0x1234), []),
            (_uleb(0x08 | 0x04) + _uleb(1) + b"_c\x00", [(b"x", 4)]),
            (_uleb(0) + _uleb(0x5678), [])])

    def test_names_offsets_and_skips_reexports(self):
        # names are the edges along the path; a re-export's children follow its terminal
        self.assertEqual(decode_export_trie(self._trie()),
                         {"_a": (0, 0x1234), "_bx": (0, 0x5678)})

    def test_an_absolute_symbol_s_value_is_not_offset_by_the_image_base(self):
        from macho.export_trie import export_address
        self.assertEqual(export_address(0x00, 0x1234, 0x1_0000_0000), 0x1_0000_1234)
        self.assertEqual(export_address(0x02, 0x1234, 0x1_0000_0000), 0x1234)   # ABSOLUTE
        self.assertIsNone(export_address(0x08, None, 0x1_0000_0000))           # re-export

    def test_truncated_trie_does_not_raise(self):
        # cut anywhere, the trie yields only symbols it states in full
        trie = self._trie()
        whole = set(decode_export_trie(trie).items())
        for n in range(len(trie)):
            with self.subTest(n=n):
                self.assertLessEqual(set(decode_export_trie(trie[:n]).items()), whole)

    def test_a_terminal_is_read_inside_its_declared_size(self):
        # "_a"'s 2-byte terminal ends inside its offset ULEB (0xb4 of 0xb4 0x24): no symbol
        trie = _trie_bytes([(b"", [(b"_a", 1), (b"_b", 2)]),
                            (_uleb(0) + _uleb(0x1234)[:1], []),
                            (_uleb(0) + _uleb(0x5678), [])])
        self.assertEqual(decode_export_trie(trie), {"_b": (0, 0x5678)})


class TestZeroEdge(unittest.TestCase):
    class _I:
        def __init__(self, mn, op, addr=0x1000):
            self.mnemonic, self.op_str, self.addr = mn, op, addr

    def test_cbz_taken_edge_and_cbnz_fallthrough(self):
        self.assertEqual(_ClassFlow._zero_edge(self._I("cbz", "x0, #0x2000")), ("x0", 0x2000))
        self.assertEqual(_ClassFlow._zero_edge(self._I("cbnz", "w8, #0x2000")), ("x8", 0x1004))
        self.assertIsNone(_ClassFlow._zero_edge(self._I("tbz", "w8, #0, #0x2000")))


class TestFastEnumerationContract(unittest.TestCase):
    """``countByEnumeratingWithState:objects:count:`` refills the NSFastEnumerationState its
    caller reuses: what a later loop reads through ``itemsPtr`` derives from that call's
    receiver only, not from the arrays earlier loops enumerated."""

    def test_state_holds_only_the_receiver_after_the_call(self):
        from unittest import mock
        import proto.writer_flow as WF
        wf = WF._ClassFlow(WF.WriterFlow(NoImage(segments=[]), []))
        vals = {'sp': WF._STACK_TOP, 'x2': WF._STACK_TOP + 0x40}      # x2 = &state
        st = WF._St({'x0': frozenset({('I', '_b')})})
        st.frame_write(0x40, 64, frozenset({('I', '_a')}))      # an earlier loop's state
        with mock.patch.object(WF, 'stub_selector', lambda ctx, va: WF._FAST_ENUMERATION), \
                mock.patch.object(WF, 'sent_selector', lambda ctx, va, x1: WF._FAST_ENUMERATION), \
                mock.patch.object(WF, 'callee_name', lambda ctx, va: None):
            wf._call(st, 0x9000, WF._Result(), 0, 0, 0x1000, vals)
        self.assertEqual(st.frame_read(0x48, 8), frozenset({('I', '_b')}))   # itemsPtr
        self.assertEqual(st.p('x0'), frozenset({('I', '_b')}))               # the count



class TestFrameAddressesComeFromTheEvaluation(unittest.TestCase):
    """WriterFlow reads frame addresses from the function's Flow run, so a large frame's
    shifted ``sub sp, sp, #1, lsl #12`` is the 4096 bytes it is: a value stored through x29
    and reloaded through sp is the same slot (GEOActiveTileGroup's prologue; WriterFlow's
    own constant tracking used to read only the unshifted form)."""

    def test_a_slot_stored_through_x29_reloads_through_a_shifted_sp(self):
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
        wf = WF._ClassFlow(WF.WriterFlow(NoImage(segments=[]), []))
        wf.off_to_ivar = {8: '_a'}
        with mock.patch('proto.function_body.disasm', fd), \
                mock.patch.object(WF, 'callee_name', lambda ctx, va: None), \
                mock.patch.object(WF, 'stub_selector', lambda ctx, va: None):
            res = wf._run(0x1000, {'x0': frozenset({'S'}), 'x2': frozenset({'W'})}, 0, 0x1000)
        site = res.sites[0x1024]
        self.assertEqual((site.number, set(site.value_origins)), (1, {('I', '_a')}))


class TestOutlinedFragments(unittest.TestCase):
    """A ``bl`` to a machine-outlined fragment runs the fragment as part of ``writeTo:``
    (:meth:`proto.arm64_eval.Flow.fragment`): the value it loads into x1 is still there at
    the write, where an AAPCS64 call would have taken x1."""

    def _site(self, frag_lines, before=(), after=()):
        # *before* / *after*: the function's own instructions either side of the bl
        from unittest import mock
        import proto.writer_flow as WF
        from proto.callees import Outlined
        from tests._listing import insns, layout
        frag = tuple(insns(frag_lines, 0x2000))
        _order, fd = layout((0x1000, [
            ('mov', 'x19, x2'), *before, ('bl', '#0x2000'), *after,
            ('mov', 'x0, x19'), ('mov', 'w2, #1'), ('bl', '#0x9000'), ('ret', '')]))
        wf = WF._ClassFlow(WF.WriterFlow(NoImage(segments=[]), []))
        wf.off_to_ivar = {8: '_a'}
        with mock.patch('proto.function_body.disasm', fd), \
                mock.patch('proto.arm64_eval.outlined_code', lambda ctx, t: (
                    Outlined(frag, None, None) if t == 0x2000 else None)), \
                mock.patch.object(WF, 'callee_name', lambda ctx, va: None), \
                mock.patch.object(WF, 'stub_selector', lambda ctx, va: None):
            res = wf._run(0x1000, {'x0': frozenset({'S'}), 'x2': frozenset({'W'})}, 0, 0x1000)
        return res.sites[0x1010 + 4 * (len(before) + len(after))]

    def test_the_value_it_loads_reaches_the_write(self):
        site = self._site([('ldr', 'x1, [x0, #8]')])                     # self->_a
        self.assertEqual((site.number, set(site.value_origins)), (1, {('I', '_a')}))

    def test_its_frame_stores_are_the_functions(self):
        load_a = ('ldr', 'x8, [x0, #8]')                                   # self->_a
        cases = {
            "stored and reloaded in the fragment": dict(frag_lines=[
                load_a, ('str', 'x8, [sp, #-0x10]'), ('ldur', 'x1, [sp, #-0x10]')]),
            # through an address the fragment computes; the slot outlives the fragment
            "stored in the fragment, reloaded after it": dict(frag_lines=[
                load_a, ('sub', 'x9, sp, #0x10'), ('str', 'x8, [x9]')],
                after=[('ldur', 'x1, [sp, #-0x10]')]),
            # the fragment's sp is the function's
            "stored before the fragment, reloaded in it": dict(frag_lines=[
                ('ldur', 'x1, [sp, #-0x10]')],
                before=[load_a, ('stur', 'x8, [sp, #-0x10]')]),
        }
        for name, kw in cases.items():
            with self.subTest(name):
                self.assertEqual(set(self._site(**kw).value_origins), {('I', '_a')})

class TestBoundsReachedAreReported(unittest.TestCase):
    """A summary cut at _MAX_SUMMARY_DEPTH is an unknown part of self: the run says so."""

    def test_the_summary_depth(self):
        import proto.writer_flow as WF
        from proto.models import get_diagnostics
        ctx = NoImage(segments=[])
        wf = WF._ClassFlow(WF.WriterFlow(ctx, []))
        with self.assertLogs('proto.models', 'WARNING') as logs:
            self.assertEqual(wf._summary(0x1000, WF._MAX_SUMMARY_DEPTH), frozenset({WF._T}))
        self.assertIn('_MAX_SUMMARY_DEPTH hit', logs.output[0])
        self.assertEqual([c for c, _w in get_diagnostics(ctx).heuristics_hit], ['_MAX_SUMMARY_DEPTH'])


class TestTailCallToACFunction(unittest.TestCase):
    """A ``b`` out of the function window to a C function of the image (an LC_FUNCTION_STARTS
    entry, neither a method IMP nor named) is a tail call: a helper handed self that ends
    ``ldr x0, [x0, #ivar] ; b <C function>`` returns what that call returns (iPhone 8
    GeoServices' GEOPDSearchAttributeIntent and three more were undecided on it)."""

    def test_the_summary_is_the_tail_calls_result(self):
        from unittest import mock
        import proto.writer_flow as WF
        from tests._listing import layout

        _order, fd = layout((0x1000, [('ldr', 'x0, [x0, #8]'), ('b', '#0x3000')]),
                            (0x3000, [('ldrb', 'w0, [x0, #4]'), ('ret', '')]))   # reads x0
        wf = WF._ClassFlow(WF.WriterFlow(TextImage(starts=[0x1000, 0x3000], segments=[]), []))
        wf.off_to_ivar = {8: '_a'}
        with mock.patch('proto.function_body.disasm', fd), \
                mock.patch.object(WF, 'callee_name', lambda ctx, va: None), \
                mock.patch.object(WF, 'stub_selector', lambda ctx, va: None):
            self.assertEqual(wf._summary(0x1000, 0), frozenset({('I', '_a')}))


try:
    import live_artifacts as _V
    _HAVE = artifacts.cache_file() is not None
except Exception:
    _HAVE = False


def _bound_ivars(ctx, cl, cls):
    import proto.writeto as W
    from proto.protocore import _is_real_field_ivar
    from proto.write_helpers import _ensure_writeto_prepass
    fivars = [iv for iv in cls.ivars if _is_real_field_ivar(iv)]
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

    def test_a_self_handed_helper_tail_calling_a_c_function(self):
        # -[GEOPDSearchAttributeIntent writeTo:] hands self to a C helper that ends in a tail
        # call to another C function of the image
        self._check("GeoServices", "GEOPDSearchAttributeIntent")

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
        add_form = [s.target for s in wf.writer_calls(cls).sites if s.target is not None
                    and [i.mnemonic for i in disasm(ctx, s.target, 3, stop_at_ret=False)]
                    == ["adrp", "add", "b"]]
        self.assertTrue(add_form)
        sels = {stub_selector(ctx, t) for t in add_form}
        self.assertNotIn(None, sels)
        self.assertIn("writeData:", sels)
        self.assertIn("writeData:", wf.sent_selectors(cls))


if __name__ == "__main__":
    unittest.main()


class TestReviewFixes(unittest.TestCase):
    """The writer-flow faults of the 2026-10-22 review (TODO #132)."""

    def _run(self, *functions, own=(), patch_visits=None):
        from unittest import mock
        import proto.writer_flow as WF
        from tests._listing import layout
        _order, fd = layout(*functions)
        wf = WF._ClassFlow(WF.WriterFlow(NoImage(segments=[]), []))
        wf.off_to_ivar = {8: '_a'}
        wf.own_imps = set(own)
        patches = [mock.patch('proto.function_body.disasm', fd),
                   mock.patch.object(WF, 'callee_name', lambda ctx, va: None),
                   mock.patch.object(WF, 'stub_selector', lambda ctx, va: None)]
        if patch_visits is not None:
            patches.append(mock.patch.object(WF, '_VISITS_PER_BLOCK', patch_visits))
        for p in patches:
            p.start()
        try:
            return wf._run(0x1000, {'x0': frozenset({'S'}), 'x2': frozenset({'W'})}, 0, 0x1000)
        finally:
            for p in patches:
                p.stop()

    def test_the_visit_cap_leaves_the_class_undecided(self):
        res = self._run((0x1000, [('mov', 'x19, x2'), ('ret', '')]), patch_visits=0)
        self.assertFalse(res.complete)

    def test_a_value_through_a_frame_array_reaches_the_write(self):
        # x9 = the array; an indexed load is any element of it, an indexed store adds to it
        cases = {
            "indexed store, indexed load": [
                ('str', 'x8, [x9, x10, lsl #3]'), ('ldr', 'x1, [x9, x11, lsl #3]')],
            "store to element 1, indexed load": [
                ('str', 'x8, [x9, #8]'), ('ldr', 'x1, [x9, x11, lsl #3]')],
            "indexed store, load of element 1": [
                ('str', 'x8, [x9, x10, lsl #3]'), ('ldr', 'x1, [x9, #8]')],
            "a second indexed store keeps the first": [
                ('str', 'x8, [x9, x10, lsl #3]'), ('str', 'x12, [x9, x11, lsl #3]'),
                ('ldr', 'x1, [x9, #8]')],
        }
        for name, body in cases.items():
            lines = [('mov', 'x19, x2'), ('ldr', 'x8, [x0, #8]'), ('add', 'x9, sp, #0x20'),
                     *body, ('mov', 'x0, x19'), ('mov', 'w2, #1'), ('bl', '#0x9000'), ('ret', '')]
            with self.subTest(name):
                res = self._run((0x1000, lines))
                self.assertEqual(set(res.sites[0x1000 + 4 * (len(lines) - 2)].value_origins),
                                 {('I', '_a')})

    def test_a_method_of_self_returns_what_it_is_handed(self):
        """[self f:self->_a] returning its argument: the value written is _a's."""
        res = self._run(
            (0x1000, [('mov', 'x19, x2'), ('ldr', 'x2, [x0, #8]'), ('bl', '#0x3000'),
                      ('mov', 'x1, x0'), ('mov', 'x0, x19'), ('mov', 'w2, #1'),
                      ('bl', '#0x9000'), ('ret', '')]),
            (0x3000, [('mov', 'x0, x2'), ('ret', '')]), own=(0x3000,))
        self.assertEqual(set(res.sites[0x1018].value_origins), {('I', '_a')})


class TestReview20261025(unittest.TestCase):
    """The writer-flow findings of the 2026-10-25 review (notes/code_review_2026-10-25.md)."""

    NAMES = {0x9000: '_PBDataWriterWriteDataField', 0xd000: '_PBDataWriterWriteInt32Field',
             0xe000: '_PBDataWriterWriteInt64Field'}

    def _run(self, lines, ivars):
        from unittest import mock
        import proto.writer_flow as WF
        from tests._listing import layout
        _o, fd = layout((0x1000, lines))
        wf = WF._ClassFlow(WF.WriterFlow(NoImage(segments=[]), []))
        wf.off_to_ivar = ivars
        with mock.patch('proto.function_body.disasm', fd), \
                mock.patch.object(WF, 'callee_name', lambda ctx, va: self.NAMES.get(va)), \
                mock.patch.object(WF, 'stub_selector', lambda ctx, va: None), \
                mock.patch.object(WF, 'sent_selector', lambda ctx, va, x1: None), \
                mock.patch.object(WF._ClassFlow, '_is_function', lambda self, va: True):
            return wf._run(0x1000, {'x0': frozenset({'S'}), 'x2': frozenset({'W'})}, 0, 0x1000)

    def test_an_ivar_put_into_an_object_the_writer_gets_reaches_it(self):
        # buf = make(); append(buf, self->_a); WriteDataField(writer, buf, 5)
        res = self._run([
            ('stp', 'x29, x30, [sp, #-0x30]!'), ('mov', 'x29, sp'), ('mov', 'x20, x0'),
            ('mov', 'x19, x2'), ('mov', 'x0, #0'), ('mov', 'x2, #0'), ('bl', '#0xa000'),
            ('mov', 'x21, x0'), ('ldr', 'x1, [x20, #8]'), ('bl', '#0xb000'),
            ('mov', 'x0, x19'), ('mov', 'x1, x21'), ('mov', 'w2, #5'), ('bl', '#0x9000'),
            ('ldp', 'x29, x30, [sp], #0x30'), ('ret', '')], {8: '_a'})
        self.assertIn(('I', '_a'), res.ser)

    def test_a_store_into_such_an_object_too(self):
        res = self._run([
            ('stp', 'x29, x30, [sp, #-0x30]!'), ('mov', 'x29, sp'), ('mov', 'x20, x0'),
            ('mov', 'x19, x2'), ('mov', 'x0, #0'), ('bl', '#0xa000'), ('mov', 'x21, x0'),
            ('ldr', 'x8, [x20, #8]'), ('str', 'x8, [x21, #0x10]'),
            ('mov', 'x0, x19'), ('mov', 'x1, x21'), ('mov', 'w2, #5'), ('bl', '#0x9000'),
            ('ldp', 'x29, x30, [sp], #0x30'), ('ret', '')], {8: '_a'})
        self.assertIn(('I', '_a'), res.ser)

    def test_a_put_after_the_write_does_not_reach_it(self):
        # buf = make(); WriteDataField(writer, buf, 5); append(buf, self->_a)
        res = self._run([
            ('stp', 'x29, x30, [sp, #-0x30]!'), ('mov', 'x29, sp'), ('mov', 'x20, x0'),
            ('mov', 'x19, x2'), ('mov', 'x0, #0'), ('mov', 'x2, #0'), ('bl', '#0xa000'),
            ('mov', 'x21, x0'),
            ('mov', 'x0, x19'), ('mov', 'x1, x21'), ('mov', 'w2, #5'), ('bl', '#0x9000'),
            ('mov', 'x0, x21'), ('ldr', 'x1, [x20, #8]'), ('bl', '#0xb000'),
            ('ldp', 'x29, x30, [sp], #0x30'), ('ret', '')], {8: '_a'})
        self.assertNotIn(('I', '_a'), res.ser)

    def test_a_put_into_a_call_s_result_reaches_the_object_it_was_handed(self):
        # buf = make(); same = retain(buf); append(same, self->_a); WriteDataField(writer, buf, 5)
        res = self._run([
            ('stp', 'x29, x30, [sp, #-0x30]!'), ('mov', 'x29, sp'), ('mov', 'x20, x0'),
            ('mov', 'x19, x2'), ('mov', 'x0, #0'), ('mov', 'x2, #0'), ('bl', '#0xa000'),
            ('mov', 'x21, x0'), ('bl', '#0xc000'), ('mov', 'x22, x0'),
            ('mov', 'x0, x22'), ('ldr', 'x1, [x20, #8]'), ('bl', '#0xb000'),
            ('mov', 'x0, x19'), ('mov', 'x1, x21'), ('mov', 'w2, #5'), ('bl', '#0x9000'),
            ('ldp', 'x29, x30, [sp], #0x30'), ('ret', '')], {8: '_a'})
        self.assertIn(('I', '_a'), res.ser)

    def test_self_plus_a_constant_keeps_its_offset(self):
        # x8 = self + 0x10; [x8, #8] is the ivar at 0x18, not the one at 8
        res = self._run([('add', 'x8, x0, #0x10'), ('ldr', 'x1, [x8, #8]'), ('mov', 'x0, x2'),
                         ('mov', 'w2, #7'), ('b', '#0xe000')], {8: '_a', 0x18: '_b'})
        self.assertEqual(res.ser, {('I', '_b')})

    def test_a_summary_cut_by_depth_is_not_reused_shallower(self):
        # B returns ivar _b; A returns what B's summary gives.  Asked for at the depth limit, a
        # summary is unknown (T) -- and so is one that asked for another there; neither may
        # stand for the summary asked for at depth 0.
        from unittest import mock
        import proto.writer_flow as WF
        wf = WF._ClassFlow(WF.WriterFlow(NoImage(segments=[]), []))

        def run(self_, imp, entry, depth, top):
            r = WF._Result()
            r.ret = {('I', '_b')} if imp == 0xB else set(self_._summary(0xB, depth))
            return r
        with mock.patch.object(WF._ClassFlow, '_run', run):
            self.assertEqual(wf._summary(0xB, WF._MAX_SUMMARY_DEPTH), {WF._T})
            self.assertEqual(wf._summary(0xB, 0), {('I', '_b')})
            wf._summary_memo.clear()
            self.assertEqual(wf._summary(0xA, WF._MAX_SUMMARY_DEPTH - 1), {WF._T})
            self.assertEqual(wf._summary(0xA, 0), {('I', '_b')})


class TestWriteSiteNumber(unittest.TestCase):
    def _site(self, name, x1=None, x2=None):
        from proto.writer_flow import WriteSite
        return WriteSite(addr=0x1000, target=0x2000, name=name, writer_reg="x0", x1=x1, x2=x2,
                         args=(), v0_origins=frozenset(), slot=None)

    def test_a_bare_varint_takes_no_field_number(self):
        # PBDataWriterWriteBareVarint(writer, value): whatever w2 holds is not its number
        self.assertIsNone(self._site("_PBDataWriterWriteBareVarint", x1=5, x2=7).number)

    def test_the_number_is_the_writer_s_third_argument(self):
        self.assertEqual(self._site("_PBDataWriterWriteDoubleField", x1=3, x2=9).number, 3)
        self.assertEqual(self._site("_PBDataWriterWriteInt32Field", x1=0, x2=4).number, 4)
