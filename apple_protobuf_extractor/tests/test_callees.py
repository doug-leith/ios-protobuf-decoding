"""proto/callees.py: callee naming must not hide wiring bugs.

``callee_name`` used to catch AttributeError, so a renamed or missing reader method turned
into "no name", which in turn relaxed the objc_msgSend check of the shared selector stub
(:func:`proto.callees.stub_selector`; code review 2026-10-18).  A context that has no names
still gets None; a broken reader raises.
"""
import unittest
from types import SimpleNamespace
from unittest import mock

from proto.callees import callee_name, stub_selector


class _NoNamesCtx:
    """A context-like stub with no cache reader and no import stubs (as unit tests use)."""
    is_cache_backed = True
    _cache_reader = None


class _Reader:
    def __init__(self, names):
        self.names = names

    def export_name_at(self, va):
        return self.names.get(va)


class _CacheCtx:
    is_cache_backed = True

    def __init__(self, reader):
        self._cache_reader = reader


class TestCalleeName(unittest.TestCase):
    def test_none_address(self):
        self.assertIsNone(callee_name(_NoNamesCtx(), None))

    def test_context_without_reader_has_no_names(self):
        self.assertIsNone(callee_name(_NoNamesCtx(), 0x1000))

    def test_exported_name(self):
        ctx = _CacheCtx(_Reader({0x1000: "_objc_msgSend"}))
        self.assertEqual(callee_name(ctx, 0x1000), "_objc_msgSend")

    def test_memoised(self):
        reader = _Reader({0x1000: "_objc_retain"})
        ctx = _CacheCtx(reader)
        callee_name(ctx, 0x1000)
        reader.names.clear()
        self.assertEqual(callee_name(ctx, 0x1000), "_objc_retain")

    def test_wiring_bug_is_not_swallowed(self):
        class Broken:                               # the reader lost its export_name_at
            pass
        with self.assertRaises(AttributeError):
            callee_name(_CacheCtx(Broken()), 0x1000)


class _SelrefCtx:
    """__objc_selrefs slot 0x2008 -> selector string at 0x3000."""
    def read_ptr(self, va):
        return {0x2008: 0x3000}.get(va)

    def read_cstring(self, va):
        return {0x3000: "count"}.get(va)


def _ins(mnemonic, op_str):
    return SimpleNamespace(mnemonic=mnemonic, op_str=op_str)


class TestStubSelector(unittest.TestCase):
    def _sel(self, tail):
        stub = [_ins('adrp', 'x1, #0x2000'), _ins('ldr', 'x1, [x1, #8]')] + tail
        with mock.patch('proto.callees.disasm', return_value=stub):
            return stub_selector(_SelrefCtx(), 0x1000)

    def test_selref_stub(self):
        self.assertEqual(self._sel([_ins('adrp', 'x16, #0x4000'), _ins('ldr', 'x16, [x16]'),
                                    _ins('br', 'x16')]), "count")

    def test_arm64e_selref_stub_branches_authenticated(self):
        self.assertEqual(self._sel([_ins('adrp', 'x17, #0x4000'), _ins('add', 'x17, x17, #0'),
                                    _ins('ldr', 'x16, [x17]'), _ins('braa', 'x16, x17')]),
                         "count")

    def test_no_indirect_branch_is_not_a_stub(self):
        self.assertIsNone(self._sel([_ins('ret', '')]))


class TestCallReads(unittest.TestCase):
    """proto.callees.call_reads: one answer to "what may this call read" for both
    interpreters (WriterFlow and arm64_eval.Flow)."""

    def _reads(self, name=None, sel=None, blocks=(), names=None, text=(0x1000, 0x100000)):
        import proto.callees as C
        from tests._fakes import TextImage
        from tests._listing import layout

        _o, fd = layout(*blocks) if blocks else ([], lambda *a, **k: [])
        named = names or {}
        with mock.patch.object(C, 'callee_name',
                               lambda ctx, va: name if va == 0x9000 else named.get(va)), \
                mock.patch.object(C, 'stub_selector', lambda ctx, va: sel if va == 0x9000 else None), \
                mock.patch('proto.function_body.disasm', fd):
            image = TextImage(text, starts={a for a, _body in blocks} | set(named))
            return set(C.call_reads(image, 0x9000))

    def test_a_runtime_contract_is_what_it_reads(self):
        self.assertEqual(self._reads("_objc_retain_x19"), {"x19"})

    def test_a_named_function_or_a_send_reads_the_abi_arguments(self):
        from proto.callees import ABI_ARGS
        self.assertEqual(self._reads("_memcpy"), set(ABI_ARGS))
        self.assertEqual(self._reads(sel="count"), set(ABI_ARGS))

    def test_an_outlined_fragment_reads_what_it_reads_before_writing(self):
        got = self._reads(blocks=[(0x9000, [('mov', 'x0, x21'), ('add', 'x1, x22, #8'), ('ret', '')])])
        self.assertEqual(got, {'x21', 'x22'})            # x0 written before it returns

    def test_a_function_of_another_image_reads_the_abi_arguments(self):
        from proto.callees import ABI_ARGS
        got = self._reads(blocks=[(0x9000, [('add', 'x1, x22, #8'), ('ret', '')])],
                          text=(0x10000, 0x20000))
        self.assertEqual(got, set(ABI_ARGS))

    def test_a_load_or_store_reads_its_address_registers(self):
        got = self._reads(blocks=[(0x9000, [('ldr', 'x8, [x1, #8]'), ('str', 'x8, [x2, x3]'),
                                            ('mov', 'x0, #0'), ('ret', '')])])
        self.assertEqual(got, {'x1', 'x2', 'x3'})

    def test_a_return_hands_back_x0(self):
        self.assertEqual(self._reads(blocks=[(0x9000, [('add', 'x1, x22, #8'), ('ret', '')])]),
                         {'x22', 'x0'})

    def test_every_path_counts(self):
        got = self._reads(blocks=[(0x9000, [('cbz', 'x2, #0x9010'), ('mov', 'x0, x1'), ('ret', ''),
                                            ('nop', ''), ('mov', 'x0, x3'), ('ret', '')])])
        self.assertEqual(got, {'x2', 'x1', 'x3'})

    def test_what_a_call_inside_it_reads(self):
        # a named callee reads the argument registers this function has not set; its own
        # spill of x29 / x30 and the callee-saved copy of x0 are not reads
        from proto.callees import ABI_ARGS
        got = self._reads(blocks=[(0x9000, [
            ('stp', 'x29, x30, [sp, #-0x10]!'), ('mov', 'x19, x0'), ('mov', 'x0, x19'),
            ('mov', 'x1, #2'), ('bl', '#0xa000'), ('mov', 'x0, x19'),
            ('ldp', 'x29, x30, [sp], #0x10'), ('ret', '')])], names={0xa000: '_f'})
        self.assertEqual(got, (set(ABI_ARGS) - {'x1'}) | {'x0'})

    def test_the_epilogue_restores_are_not_reads(self):
        # `ldp x20, x19, [sp], #0x10` writes both registers: only sp, its address, is read
        got = self._reads(blocks=[(0x9000, [
            ('stp', 'x20, x19, [sp, #-0x10]!'), ('mov', 'x19, x1'), ('mov', 'x0, x19'),
            ('ldp', 'x20, x19, [sp], #0x10'), ('ret', '')])])
        self.assertEqual(got, {'x1'})

    def test_functions_calling_each_other_are_solved_together(self):
        # 0x9000 and 0xa000 call each other: the cycle's reads are what its members read,
        # not every register
        got = self._reads(blocks=[(0x9000, [('cbz', 'x2, #0x900c'), ('bl', '#0xa000'),
                                            ('ret', ''), ('mov', 'x0, x3'), ('ret', '')]),
                                  (0xa000, [('add', 'x2, x2, #1'), ('mov', 'x4, x5'),
                                            ('bl', '#0x9000'), ('ret', '')])])
        self.assertEqual(got, {'x2', 'x3', 'x5'})        # x0: set on both paths to a return

    def test_a_tail_call_reads_what_its_target_reads(self):
        from proto.callees import ABI_ARGS
        got = self._reads(blocks=[(0x9000, [('mov', 'x0, x20'), ('b', '#0xa000')])],
                          names={0xa000: '_f'})
        self.assertEqual(got, (set(ABI_ARGS) - {'x0'}) | {'x20'})


if __name__ == "__main__":
    unittest.main()
