"""proto/callees.py: the one call-stub decoder (:func:`proto.callees.stub_target`) and the
callers built on it (:func:`real_target`, :func:`import_name`; TODO #83).

The listings are copied from real disassembly; ``disasm`` is routed to them.  The decoder
evaluates the stub's straight-line code up to its branch, so each stub form is told by what
its instructions compute, not by their positions or registers.
"""
import unittest
from tests._listing import layout

import proto.callees as C


def _memory(*blocks):
    return layout(*blocks)[1]


# iPhone 8 GeoServices: the PLT form, a computed target (_BZ2_bzBuffToBuffCompress).
_PLT = (0x18dbda6c0, [('adrp', 'x16, #0x1d1f4b000'), ('add', 'x16, x16, #0x460'),
                      ('br', 'x16'), ('adrp', 'x16, #0x1d1f51000')])
# locationd: an import stub through a GOT slot the binary binds by name.
_IMPORT = (0x10138cbd8, [('adrp', 'x16, #0x101b3c000'), ('ldr', 'x16, [x16, #0x30]'),
                         ('br', 'x16'), ('adrp', 'x16, #0x101b3c000')])
# iOS 27 GeoServices: the arm64e stub island (adrp+add a GOT slot into x17, ldr, braa).
_ISLAND = (0x198104920, [('adrp', 'x17, #0x1ea4fb000'), ('add', 'x17, x17, #0x828'),
                         ('ldr', 'x16, [x17]'), ('braa', 'x16, x17')])
# iOS 27 MessageProtection, more than 4 GB past the cache base: a far branch island that
# computes a target below it (_objc_release).
_FAR_ISLAND = (0x290065a10, [('adr', 'x16, #0x290005964'), ('mov', 'x17, #0x87e'),
                             ('sub', 'x16, x16, x17, lsl #21'), ('br', 'x16')])
# locationd: an objc selector stub -- x1 = the selector, then through objc_msgSend's slot.
_SELECTOR = (0x101391460, [('adrp', 'x1, #0x101c54000'), ('ldr', 'x1, [x1, #0xfc0]'),
                           ('adrp', 'x16, #0x101b40000'), ('ldr', 'x16, [x16, #0x200]'),
                           ('br', 'x16'), ('brk', '#1')])
# locationd: NOT a stub -- outlined code that loads a bound GOT entry and goes on.  The
# position matcher this decoder replaced named it _OBJC_CLASS_$_NSString.
_NOT_STUB = (0x10017105c, [('adrp', 'x9, #0x101c65000'), ('ldr', 'x0, [x9, #0xa58]'),
                           ('str', 'x8, [sp]'), ('adrp', 'x2, #0x101bde000'),
                           ('add', 'x2, x2, #0x6d8'), ('bl', '#0x1013c07c0')])
# a branch on a register the stub did not compute
_UNKNOWN_REG = (0x1000, [('adrp', 'x16, #0x2000'), ('br', 'x17')])


class _Ctx:
    def __init__(self, cache, ptrs=None, binds=None):
        self.is_cache_backed = cache
        self.ptrs, self.binds = ptrs or {}, binds or {}

    def read_ptr(self, addr):
        if addr not in self.ptrs:
            raise ValueError(addr)
        return self.ptrs[addr]

    def bind_name_for(self, addr):
        return self.binds.get(addr)


class TestStubTarget(unittest.TestCase):
    def setUp(self):
        orig = C.disasm
        C.disasm = _memory(_PLT, _IMPORT, _ISLAND, _FAR_ISLAND, _SELECTOR, _NOT_STUB,
                           _UNKNOWN_REG)
        self.addCleanup(setattr, C, 'disasm', orig)

    def test_plt_stub_computes_its_target(self):
        self.assertEqual(C.stub_target(_Ctx(True), 0x18dbda6c0),
                         C.Stub(target=0x1d1f4b000 + 0x460))

    def test_import_stub_branches_through_its_slot(self):
        self.assertEqual(C.stub_target(_Ctx(False), 0x10138cbd8),
                         C.Stub(slot=0x101b3c000 + 0x30))

    def test_stub_island_branches_through_its_slot(self):
        self.assertEqual(C.stub_target(_Ctx(True), 0x198104920),
                         C.Stub(slot=0x1ea4fb000 + 0x828))

    def test_far_branch_island_computes_its_target(self):
        self.assertEqual(C.stub_target(_Ctx(True), 0x290065a10),
                         C.Stub(target=0x290005964 - (0x87e << 21)))
        self.assertEqual(C.real_target(_Ctx(True), 0x290065a10), 0x180405964)

    def test_selector_stub_branches_through_objc_msgsend_slot(self):
        self.assertEqual(C.stub_target(_Ctx(False), 0x101391460),
                         C.Stub(slot=0x101b40000 + 0x200))

    def test_code_that_does_not_branch_is_not_a_stub(self):
        self.assertIsNone(C.stub_target(_Ctx(False), 0x10017105c))

    def test_branch_on_an_uncomputed_register_is_not_a_stub(self):
        self.assertIsNone(C.stub_target(_Ctx(True), 0x1000))

    def test_unmapped_address_is_not_a_stub(self):
        self.assertIsNone(C.stub_target(_Ctx(True), 0x5000))

    # ── real_target ──

    def test_real_target_of_plt_stub(self):
        self.assertEqual(C.real_target(_Ctx(True), 0x18dbda6c0), 0x1d1f4b460)

    def test_real_target_of_island_reads_the_slot(self):
        ctx = _Ctx(True, ptrs={0x1ea4fb828: 0x1c0001000})
        self.assertEqual(C.real_target(ctx, 0x198104920), 0x1c0001000)

    def test_real_target_of_unreadable_slot_is_the_stub(self):
        self.assertEqual(C.real_target(_Ctx(True), 0x198104920), 0x198104920)

    def test_real_target_in_a_binary_is_the_import_stub(self):
        # the slot is bound at load time to another image: the stub is the callee
        ctx = _Ctx(False, ptrs={0x101b3c030: 0x1234})
        self.assertEqual(C.real_target(ctx, 0x10138cbd8), 0x10138cbd8)

    def test_real_target_of_a_direct_call_is_itself(self):
        self.assertEqual(C.real_target(_Ctx(False), 0x10017105c), 0x10017105c)

    # ── import_name ──

    def test_import_name_is_the_slot_binding(self):
        ctx = _Ctx(False, binds={0x101b3c030: '_ADClientAddValueForScalarKey'})
        self.assertEqual(C.import_name(ctx, 0x10138cbd8), '_ADClientAddValueForScalarKey')

    def test_import_name_of_non_stub_is_none_even_if_it_loads_a_bound_slot(self):
        ctx = _Ctx(False, binds={0x101c65a58: '_OBJC_CLASS_$_NSString'})
        self.assertIsNone(C.import_name(ctx, 0x10017105c))

    def test_cache_binds_no_import_names(self):
        ctx = _Ctx(True, binds={0x101b3c030: '_ADClientAddValueForScalarKey'})
        self.assertIsNone(C.import_name(ctx, 0x10138cbd8))


if __name__ == '__main__':
    unittest.main()
