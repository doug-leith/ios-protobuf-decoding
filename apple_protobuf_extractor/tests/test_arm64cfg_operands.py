#!/usr/bin/env python3
"""The shared operand-parse helpers in :mod:`proto.arm64cfg`, on hand-built instructions
(no binary).  (Split from the writeTo: walk's unit tests when the
walk was replaced by :mod:`proto.writer_flow`, TODO #85.)"""
import unittest
from tests._listing import insns

import proto.arm64cfg as CFG
import proto.arm64_operands as OPS


def ins_list(*pairs, base=0x2000):
    return insns(pairs, base)


class TestOperandToolkit(unittest.TestCase):
    """The shared op_str parser primitives in proto.arm64cfg."""

    def test_split_ops_keeps_brackets_intact(self):
        self.assertEqual(OPS.split_ops('w1, [x20, x8]'), ['w1', '[x20, x8]'])
        self.assertEqual(OPS.split_ops('x8, x8, #0x200'), ['x8', 'x8', '#0x200'])
        self.assertEqual(OPS.split_ops('x1, [x8, x24, lsl #3]'),
                         ['x1', '[x8, x24, lsl #3]'])

    def test_split_ops_strips_lowercases_and_handles_empty(self):
        self.assertEqual(OPS.split_ops('X20, X0'), ['x20', 'x0'])
        self.assertEqual(OPS.split_ops(''), [])
        self.assertEqual(OPS.split_ops('x0'), ['x0'])

    def test_operand_regs_names_memory_bases_and_indices(self):
        self.assertEqual(OPS.operand_regs(['w0', '[x0, #4]']), ['x0', 'x0'])
        self.assertEqual(OPS.operand_regs(['[x20, x8]']), ['x20', 'x8'])
        self.assertEqual(OPS.operand_regs(['[x1, w2, sxtw #2]']), ['x1', 'x2'])
        self.assertEqual(OPS.operand_regs(['[x0, #-0x10]!']), ['x0'])
        self.assertEqual(OPS.operand_regs(['[sp, #8]', 'xzr', 'lsl #3']), [])

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



if __name__ == '__main__':
    unittest.main()
