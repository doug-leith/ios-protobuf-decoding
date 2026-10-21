"""proto.arm64_operands on operand text as capstone prints it: register names and widths,
memory operands and register lists, the registers an instruction reads and writes, the flexible
second operand.  Every evaluator and data-flow pass reads instructions through these, so a form
misread here is misread everywhere (``operand_regs`` named no register of ``[x0, #4]`` from #88
to #117)."""
import unittest

from proto import arm64_operands as O
from tests._listing import insns


def _ins(mn, op_str):
    return insns([(mn, op_str)])[0]


class TestRegisters(unittest.TestCase):
    def test_widths(self):
        self.assertEqual([O.reg_bytes(t) for t in ('x0', 'w0', 'sp', 'wsp', 'xzr', 'wzr',
                                                   'q1', 'd2', 's3', 'h4', 'b5')],
                         [8, 4, 8, 4, 8, 4, 16, 8, 4, 2, 1])
        self.assertEqual((O.reg_mask('w3'), O.reg_bits('w3')), (0xFFFFFFFF, 32))
        self.assertEqual((O.reg_mask('x3'), O.reg_bits('x3')), (0xFFFFFFFFFFFFFFFF, 64))

    def test_names(self):
        self.assertEqual([O.reg_name(t) for t in ('w8', 'x8', 'sp', 'wsp', 'wzr', 'd0', 'q31',
                                                  'v3.16b', 's7')],
                         ['x8', 'x8', 'sp', 'sp', 'xzr', 'v0', 'v31', 'v3', 'v7'])
        self.assertEqual(O.reg_name('v0.s[1]'), 'v0')                  # a lane
        self.assertIsNone(O.reg_name('v32'))
        self.assertIsNone(O.reg_name('#4'))


class TestSplitAndMemory(unittest.TestCase):
    def test_split_keeps_memory_operands_and_register_lists(self):
        self.assertEqual(O.split_ops('x1, [x8, x24, lsl #3]'), ['x1', '[x8, x24, lsl #3]'])
        self.assertEqual(O.split_ops('{v0.16b, v1.16b}, [x0]'), ['{v0.16b, v1.16b}', '[x0]'])
        self.assertEqual(O.split_ops('x0, [x1], #8'), ['x0', '[x1]', '#8'])

    def test_parse_mem(self):
        self.assertEqual(O.parse_mem('[x0]')[:3], ('x0', None, 0))
        self.assertEqual(O.parse_mem('[sp, #-0x10]!')[:3], ('sp', None, -16))
        self.assertEqual(O.parse_mem('[x1, w2, sxtw #2]'), ('x1', 'x2', 0, 'sxtw', 2, True))
        self.assertEqual(O.parse_mem('[x8, x24, lsl #3]'), ('x8', 'x24', 0, 'lsl', 3, False))
        self.assertIsNone(O.parse_mem('x0'))
        self.assertEqual(O.mem_regs('[x20, x8]'), ('x20', 'x8', 0))

    def test_writeback_base(self):
        self.assertEqual(O.writeback_base(O.split_ops('x0, [x1, #8]!')), 'x1')
        self.assertEqual(O.writeback_base(O.split_ops('x0, [x1], #8')), 'x1')
        self.assertIsNone(O.writeback_base(O.split_ops('x0, [x1, #8]')))
        self.assertIsNone(O.writeback_base(O.split_ops('x0, x1, #8')))

    def test_operand_regs(self):
        self.assertEqual(O.operand_regs(O.split_ops('x8, [x0, #4]')), ['x8', 'x0'])
        self.assertEqual(O.operand_regs(['[x1, w2, sxtw #2]']), ['x1', 'x2'])
        self.assertEqual(O.operand_regs(O.split_ops('{v0.16b, v1.16b}, [x0]')), ['v0', 'v1', 'x0'])
        self.assertEqual(O.operand_regs(['[sp, #8]', 'xzr', 'lsl #3', '#1']), [])


class TestWrites(unittest.TestCase):
    def w(self, mn, op_str):
        return O.writes(_ins(mn, op_str))

    def test_ordinary_and_pair(self):
        self.assertEqual(self.w('csel', 'w0, w1, w2, eq'), ['x0'])
        self.assertEqual(self.w('ldp', 'x29, x30, [sp], #0x10'), ['x29', 'x30'])
        self.assertEqual(self.w('ldpsw', 'x0, x1, [x2]'), ['x0', 'x1'])
        self.assertEqual(self.w('ldxp', 'x0, x1, [x2]'), ['x0', 'x1'])

    def test_writeback(self):
        self.assertEqual(self.w('ldr', 'x0, [x1], #8'), ['x1', 'x0'])
        self.assertEqual(self.w('str', 'x0, [x1, #8]!'), ['x1'])
        self.assertEqual(self.w('stp', 'x29, x30, [sp, #-0x10]!'), [])

    def test_no_destination(self):
        for mn, ops in (('cmp', 'x0, #1'), ('str', 'x0, [x1]'), ('mov', 'xzr, x1'),
                        ('fcmp', 'd0, d1'), ('st1', '{v0.16b}, [x0]'), ('b.eq', '#0x1000')):
            self.assertEqual(self.w(mn, ops), [], mn)
        self.assertEqual(self.w('bl', '#0x9000'), list(O.CALLER_SAVED))

    def test_exclusive_store_writes_its_status(self):
        self.assertEqual(self.w('stlxr', 'w9, x0, [x1]'), ['x9'])
        self.assertEqual(self.w('stxp', 'w8, x0, x1, [x2]'), ['x8'])

    def test_atomics(self):
        self.assertEqual(self.w('ldaddal', 'w8, w9, [x10]'), ['x9'])     # the old value
        self.assertEqual(self.w('swp', 'x1, x2, [x3]'), ['x2'])
        self.assertEqual(self.w('casal', 'x0, x1, [x2]'), ['x0'])
        self.assertEqual(self.w('casp', 'x0, x1, x2, x3, [x4]'), ['x0', 'x1'])

    def test_register_list_load(self):
        self.assertEqual(self.w('ld1', '{v0.16b, v1.16b}, [x0]'), ['v0', 'v1'])
        self.assertEqual(self.w('ld1r', '{v0.4s}, [x0], #4'), ['x0', 'v0'])


class TestReads(unittest.TestCase):
    """reads() is writes()'s counterpart: every pass that asks what an instruction reads asks
    it (the call-read liveness, the writer flow, the jump-table bound's sources)."""

    def r(self, mn, op_str):
        return O.reads(_ins(mn, op_str))

    def test_ordinary_loads_and_stores(self):
        self.assertEqual(self.r('add', 'x0, x1, x2, lsl #3'), ['x1', 'x2'])
        self.assertEqual(self.r('ldr', 'x8, [x1, #8]'), ['x1'])
        self.assertEqual(self.r('ldp', 'x0, x1, [x2, x3]'), ['x2', 'x3'])
        self.assertEqual(self.r('str', 'x8, [x2, x3]'), ['x8', 'x2', 'x3'])
        self.assertEqual(self.r('cmp', 'w8, w9'), ['x8', 'x9'])
        self.assertEqual(self.r('cbz', 'x0, #0x1000'), ['x0'])
        self.assertEqual(self.r('mov', 'x0, #0'), [])

    def test_partial_writes_read_their_destination(self):
        self.assertEqual(self.r('movk', 'x8, #1, lsl #16'), ['x8'])
        self.assertEqual(self.r('bfi', 'x8, x9, #4, #4'), ['x8', 'x9'])
        self.assertEqual(self.r('mov', 'v0.s[1], w8'), ['v0', 'x8'])
        self.assertEqual(self.r('mov', 'w8, v0.s[1]'), ['v0'])            # a lane is no address

    def test_exclusives_and_atomics(self):
        self.assertEqual(self.r('stxr', 'w9, x8, [x0]'), ['x8', 'x0'])
        self.assertEqual(self.r('ldaxr', 'x0, [x1]'), ['x1'])
        self.assertEqual(self.r('ldadd', 'w8, w9, [x0]'), ['x8', 'x0'])
        self.assertEqual(self.r('stadd', 'w8, [x0]'), ['x8', 'x0'])
        self.assertEqual(O.writes(_ins('stadd', 'w8, [x0]')), [])
        self.assertEqual(self.r('cas', 'x8, x9, [x0]'), ['x8', 'x9', 'x0'])

    def test_branches_and_calls(self):
        self.assertEqual(self.r('bl', '#0x9000'), [])
        self.assertEqual(self.r('blr', 'x16'), ['x16'])
        self.assertEqual(self.r('braa', 'x16, x17'), ['x16', 'x17'])
        self.assertEqual(self.r('b.eq', '#0x1000'), [])


class TestSecondOperand(unittest.TestCase):
    def test_immediates(self):
        self.assertEqual(O.imm_operand(['#0x11', 'lsl #12'], 0), 0x11000)
        self.assertEqual(O.imm_operand(['#5'], 0), 5)
        self.assertIsNone(O.imm_operand(['x1'], 0))

    def test_shifts_and_extends(self):
        self.assertEqual(O.apply_shift(3, 'x1', 'lsl #3'), 24)
        self.assertEqual(O.apply_shift(0x80000000, 'w1', 'asr #4'), -0x8000000)
        self.assertEqual(O.apply_shift(1, 'x1', 'ror #1'), 1 << 63)
        self.assertEqual(O.apply_shift(0xFF, 'w1', 'sxtb'), -1)
        self.assertEqual(O.apply_shift(0xFFFFFFFF, 'w1', 'uxtw #2'), 0xFFFFFFFF << 2)
        self.assertIsNone(O.apply_shift(1, 'w1', 'msl #8'))

    def test_operand2(self):
        self.assertEqual(O.operand2(['x9', 'x10', 'lsl #3'], 1, lambda t: 3), 24)
        self.assertEqual(O.operand2(['x9', '#0x10'], 1, lambda t: None), 0x10)
        self.assertIsNone(O.operand2(['x9', 'x10'], 1, lambda t: None))

    def test_signed_and_shift_values(self):
        self.assertEqual(O.as_signed(0xFFFFC43C, 'w9'), -0x3BC4)
        self.assertEqual(O.as_signed(5, 'x9'), 5)
        self.assertIsNone(O.as_signed(None, 'x9'))
        self.assertEqual(O.shift_value('asr', 0x80000000, 4, 'w0'), -0x8000000)
        self.assertEqual(O.shift_value('lsl', 1, 33, 'w0'), 2)              # n mod 32
        self.assertEqual(O.shift_value('lsr', 0x100, 4, 'x0'), 0x10)

    def test_branch_kinds(self):
        self.assertTrue(O.is_cond_branch('b.ne'))
        self.assertFalse(O.is_cond_branch('bl'))
        self.assertEqual(O.TRAPS, frozenset(('brk', 'udf', 'hlt')))


if __name__ == "__main__":
    unittest.main()
