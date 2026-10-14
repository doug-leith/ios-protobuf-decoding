"""``-[C xAsString:]`` enum recovery on assembled bodies (no binary, no dyld cache).

The method is the function from the enum value (w2) to its name, so it is recovered by
evaluating it (:class:`proto.dictrep_flow.Flow`) rather than by pattern-matching the switch
the compiler happened to emit.  These bodies model the shapes the old window decoders each
needed a separate routine for (pointer table with a ``sub`` bias, biases materialised in a
register because they do not fit a 12-bit immediate, bitmask-gated tables, compare chains
with ``cbz`` for value 0) and the disclosure when a value cannot be evaluated.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

from proto.enums import _extract_xasstring
from tests.test_dictrep_inline_enums import _enum_ctx

NAMES = {0x9000 + 0x20 * i: f'K_{i}' for i in range(6)}
A, B, C, D, E, F = sorted(NAMES)


def _pointer_table(first, count):
    return {0x6100 + 8 * i: sorted(NAMES)[first + i] for i in range(count)}


def _xas(code, **kw):
    ctx, _ = _enum_ctx(code, strings=NAMES, **kw)
    return _extract_xasstring(ctx, 0x1000)


class TestPointerTables(unittest.TestCase):

    def test_zero_based_table_numbers_come_from_the_index(self):
        r = _xas(['cmp w2, #3', 'b.hi dflt', 'adrp x9, #0x6000', 'add x9, x9, #0x100',
                  'ldr x0, [x9, w2, sxtw #3]', 'ret', 'dflt:', 'mov x0, #0', 'ret'],
                 ptrs=_pointer_table(0, 4))
        self.assertEqual(r.pairs, [(0, 'K_0'), (1, 'K_1'), (2, 'K_2'), (3, 'K_3')])
        self.assertTrue(r.confirmed)
        self.assertFalse(r.truncated)

    def test_one_based_table_sub_bias_is_added_back(self):
        r = _xas(['sub w8, w2, #1', 'cmp w8, #3', 'b.hi dflt', 'adrp x9, #0x6000',
                  'add x9, x9, #0x100', 'ldr x0, [x9, w8, sxtw #3]', 'ret',
                  'dflt:', 'mov x0, #0', 'ret'],
                 ptrs=_pointer_table(0, 4))
        self.assertEqual([n for n, _ in r.pairs], [1, 2, 3, 4])

    def test_bias_materialised_in_a_register_negative_add(self):
        # 50000 does not fit a 12-bit immediate:  mov w8,#-50000 ; add w8,w2,w8
        r = _xas(['mov w8, #-50000', 'add w8, w2, w8', 'cmp w8, #3', 'b.hi dflt',
                  'adrp x9, #0x6000', 'add x9, x9, #0x100', 'ldr x0, [x9, w8, sxtw #3]',
                  'ret', 'dflt:', 'mov x0, #0', 'ret'],
                 ptrs=_pointer_table(0, 4))
        self.assertEqual([n for n, _ in r.pairs], [50000, 50001, 50002, 50003])
        self.assertTrue(r.confirmed)

    def test_bias_materialised_in_a_register_positive_sub(self):
        r = _xas(['mov w8, #50000', 'sub w8, w2, w8', 'cmp w8, #3', 'b.hi dflt',
                  'adrp x9, #0x6000', 'add x9, x9, #0x100', 'ldr x0, [x9, w8, sxtw #3]',
                  'ret', 'dflt:', 'mov x0, #0', 'ret'],
                 ptrs=_pointer_table(0, 4))
        self.assertEqual([n for n, _ in r.pairs], [50000, 50001, 50002, 50003])

    def test_a_sub_into_another_register_does_not_bias_the_table(self):
        r = _xas(['sub w9, w2, #7', 'cmp w2, #3', 'b.hi dflt', 'adrp x9, #0x6000',
                  'add x9, x9, #0x100', 'ldr x0, [x9, w2, sxtw #3]', 'ret',
                  'dflt:', 'mov x0, #0', 'ret'],
                 ptrs=_pointer_table(0, 4))
        self.assertEqual([n for n, _ in r.pairs], [0, 1, 2, 3])

    def test_bitmask_gated_table_names_only_the_set_bits(self):
        r = _xas(['cmp w2, #4', 'b.hi dflt', 'mov w9, #0b10101', 'lsr w9, w9, w2',
                  'tbz w9, #0, dflt', 'adrp x9, #0x6000', 'add x9, x9, #0x100',
                  'ldr x0, [x9, w2, sxtw #3]', 'ret', 'dflt:', 'mov x0, #0', 'ret'],
                 ptrs={0x6100: A, 0x6108: B, 0x6110: C, 0x6118: D, 0x6120: E})
        self.assertEqual(r.pairs, [(0, 'K_0'), (2, 'K_2'), (4, 'K_4')])


class TestPointerAuthenticationReturnCheck(unittest.TestCase):
    """arm64e: ``eor x16,x30,x30,lsl #1; tbz x16,#62,ok; brk`` guards the return.  It tests a
    register the analysis does not track, but one side traps, so it passes whenever the
    method returns and the evaluation follows the other side (iOS 27 GeoServices)."""

    CODE = ['cmp w2, #3', 'b.hi dflt', 'adrp x9, #0x6000', 'add x9, x9, #0x100',
            'ldr x0, [x9, w2, uxtw #3]', 'eor x16, x30, x30, lsl #1', 'tbz x16, #62, ok',
            'brk #0xc471', 'ok:', 'ret', 'dflt:', 'mov x0, #0', 'ret']

    def test_trap_side_is_not_followed(self):
        r = _xas(self.CODE, ptrs=_pointer_table(0, 4))
        self.assertEqual([n for n, _ in r.pairs], [0, 1, 2, 3])
        self.assertTrue(r.confirmed)

    def test_an_untracked_test_with_no_trap_side_still_aborts(self):
        code = [c if not c.startswith('brk') else 'nop' for c in self.CODE]
        r = _xas(code, ptrs=_pointer_table(0, 4))
        self.assertEqual(r.pairs, [])
        self.assertIn('untracked', r.reason)


class TestCompareChains(unittest.TestCase):

    CHAIN = ['cbz w2, zero', 'cmp w2, #7', 'b.eq seven', 'cmp w2, #300', 'b.eq big',
             'mov x0, #0', 'ret',
             'zero:', 'adrp x0, #0x9000', 'add x0, x0, #0x00', 'ret',
             'seven:', 'adrp x0, #0x9000', 'add x0, x0, #0x20', 'ret',
             'big:', 'adrp x0, #0x9000', 'add x0, x0, #0x40', 'ret']

    def test_values_are_the_constants_compared_against(self):
        r = _xas(self.CHAIN)
        self.assertEqual(r.pairs, [(0, 'K_0'), (7, 'K_1'), (300, 'K_2')])
        self.assertTrue(r.confirmed)


class TestDisclosure(unittest.TestCase):

    def test_a_value_that_cannot_be_evaluated_is_reported_not_dropped_quietly(self):
        # value 7's path depends on x5, which nothing defines
        code = ['cbz w2, zero', 'cmp w2, #9', 'b.eq nine', 'cmp w2, #7', 'b.eq seven',
                'mov x0, #0', 'ret',
                'zero:', 'adrp x0, #0x9000', 'add x0, x0, #0x00', 'ret',
                'nine:', 'adrp x0, #0x9000', 'add x0, x0, #0x40', 'ret',
                'seven:', 'cbz x5, zero', 'adrp x0, #0x9000', 'add x0, x0, #0x20', 'ret']
        r = _xas(code)
        self.assertEqual(r.pairs, [(0, 'K_0'), (9, 'K_2')])
        self.assertTrue(r.truncated)
        self.assertFalse(r.confirmed)
        self.assertIn('value 7', r.reason)

    def test_nothing_recovered_from_an_empty_method(self):
        ctx, _ = _enum_ctx(['ret'], strings=NAMES)
        r = _extract_xasstring(ctx, 0x1000)
        self.assertEqual((r.pairs, r.confirmed), ([], False))

    def test_imp_zero_is_not_an_enum(self):
        ctx, _ = _enum_ctx(['ret'], strings=NAMES)
        self.assertEqual(_extract_xasstring(ctx, 0).pairs, [])


if __name__ == '__main__':
    unittest.main()
