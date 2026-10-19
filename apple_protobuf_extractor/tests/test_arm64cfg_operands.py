#!/usr/bin/env python3
"""The shared operand-parse / offset-resolve helpers in :mod:`proto.arm64cfg`, on
hand-built instructions (no binary).  (Split from the writeTo: walk's unit tests when the
walk was replaced by :mod:`proto.writer_flow`, TODO #85.)"""
import unittest
from tests._listing import insns

import proto.arm64cfg as CFG


def ins_list(*pairs, base=0x2000):
    return insns(pairs, base)


class TestParseLoad(unittest.TestCase):
    def test_reg_indexed(self):
        self.assertEqual(CFG._parse_load('x1, [x20, x8]'), ('x1', 'x20', 'x8'))

    def test_imm_offset_has_no_off_reg(self):
        self.assertEqual(CFG._parse_load('w1, [x20, #0x10]'), ('w1', 'x20', None))

    def test_shifted_index(self):
        self.assertEqual(CFG._parse_load('x1, [x8, x24, lsl #3]'),
                         ('x1', 'x8', 'x24'))

    def test_fp_value_reg_preserved(self):
        self.assertEqual(CFG._parse_load('d0, [x20, x8]'), ('d0', 'x20', 'x8'))

    def test_non_memory_is_none(self):
        self.assertIsNone(CFG._parse_load('x0, x1'))


class TestResolveOffsetAddr(unittest.TestCase):
    def test_direct_adrp_ldrsw(self):
        # adrp x8,page ; ldrsw x9,[x8,#0x40]  -> resolve x9 = page + 0x40
        pre = ins_list(('adrp', 'x8, #0x10000'), ('ldrsw', 'x9, [x8, #0x40]'))
        self.assertEqual(CFG._resolve_offset_addr(pre, 'x9', {}), 0x10040)

    def test_adrp_add_base(self):
        # adrp x8,page ; add x8,x8,#0x200 ; ldrsw x9,[x8,#0x40] -> page+0x200+0x40
        pre = ins_list(('adrp', 'x8, #0x10000'), ('add', 'x8, x8, #0x200'),
                       ('ldrsw', 'x9, [x8, #0x40]'))
        self.assertEqual(CFG._resolve_offset_addr(pre, 'x9', {}), 0x10240)

    def test_base_regs_fallback(self):
        # offset reg defined from a callee-saved base captured in base_regs
        pre = ins_list(('ldrsw', 'x9, [x21, #0x40]'))
        self.assertEqual(
            CFG._resolve_offset_addr(pre, 'x9', {'x21': 0x30000}), 0x30040)

    def test_unresolvable_base_returns_none(self):
        pre = ins_list(('ldrsw', 'x9, [x21, #0x40]'))   # x21 not local, not in base_regs
        self.assertIsNone(CFG._resolve_offset_addr(pre, 'x9', {}))


class TestOperandToolkit(unittest.TestCase):
    """The shared op_str parser primitives in proto.arm64cfg."""

    def test_split_ops_keeps_brackets_intact(self):
        self.assertEqual(CFG.split_ops('w1, [x20, x8]'), ['w1', '[x20, x8]'])
        self.assertEqual(CFG.split_ops('x8, x8, #0x200'), ['x8', 'x8', '#0x200'])
        self.assertEqual(CFG.split_ops('x1, [x8, x24, lsl #3]'),
                         ['x1', '[x8, x24, lsl #3]'])

    def test_split_ops_strips_lowercases_and_handles_empty(self):
        self.assertEqual(CFG.split_ops('X20, X0'), ['x20', 'x0'])
        self.assertEqual(CFG.split_ops(''), [])
        self.assertEqual(CFG.split_ops('x0'), ['x0'])

    def test_dst_reg(self):
        self.assertEqual(CFG.dst_reg('x20, x0'), 'x20')
        # _norm_reg normalises the w-view to the x-view (what clobber detection needs)
        self.assertEqual(CFG.dst_reg('w1, [x20, x8]'), 'x1')
        # ldp: first operand is the destination
        self.assertEqual(CFG.dst_reg('x22, x21, [sp], #0x30'), 'x22')
        self.assertIsNone(CFG.dst_reg(''))

    def test_parse_adrp(self):
        self.assertEqual(CFG.parse_adrp('x21, #0x10000'), ('x21', 0x10000))
        self.assertIsNone(CFG.parse_adrp('x21'))             # malformed (one operand)

    def test_mem_operand_forms(self):
        self.assertEqual(CFG.mem_operand('x1, [x20, x8]'),   ('x1', 'x20', 'x8', 0, 0))
        self.assertEqual(CFG.mem_operand('w1, [x20, #0x10]'), ('w1', 'x20', None, 0x10, 0))
        self.assertEqual(CFG.mem_operand('x8, [x20]'),        ('x8', 'x20', None, 0, 0))
        self.assertEqual(CFG.mem_operand('x1, [x8, x24, lsl #3]'),
                         ('x1', 'x8', 'x24', 0, 3))
        self.assertEqual(CFG.mem_operand('d0, [x20, x8]'),    ('d0', 'x20', 'x8', 0, 0))
        self.assertIsNone(CFG.mem_operand('x0, x1'))         # not a memory operand

    def test_parse_load_is_mem_operand_shim(self):
        # the back-compat shim returns (value, base, index) — the first three
        self.assertEqual(CFG._parse_load('x1, [x8, x24, lsl #3]'), ('x1', 'x8', 'x24'))
        self.assertIsNone(CFG._parse_load('x0, x1'))


class TestSameReg(unittest.TestCase):
    """_same_reg treats the w/x views of a GPR as the same register (the int32/enum
    hoist loads `ldr w20,[self,off]` but moves `mov x1, x20`), while keeping the
    SIMD d/s registers distinct (offline; no cache needed)."""

    def test_wx_views_equal(self):
        self.assertTrue(CFG._same_reg('w20', 'x20'))
        self.assertTrue(CFG._same_reg('x20', 'w20'))
        self.assertTrue(CFG._same_reg('x1', 'x1'))

    def test_different_gprs_not_equal(self):
        self.assertFalse(CFG._same_reg('x20', 'x21'))
        self.assertFalse(CFG._same_reg('w20', 'x19'))

    def test_simd_exact_match_only(self):
        self.assertTrue(CFG._same_reg('d8', 'd8'))
        self.assertFalse(CFG._same_reg('d8', 's8'))   # both _norm_reg->None; names differ
        self.assertFalse(CFG._same_reg('d8', 'd9'))


if __name__ == '__main__':
    unittest.main()
