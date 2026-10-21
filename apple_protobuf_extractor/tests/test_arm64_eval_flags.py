"""
proto/arm64_eval.py: the evaluator's condition flags and second operands.

A value the evaluator cannot compute must come out unknown, never wrong.  These cases were
silently mis-evaluated (code review 2026-10-18):

* a flag-setting instruction the evaluator did not model (``ccmp``, ``ands``, a shifted
  ``tst``/``cmp``, ``fcmp``) left the previous ``cmp``'s flags live, so a later ``b.eq`` was
  decided on the wrong comparison;
* ``tst``/``ands`` clear C (and V), which a ``cmp``-shaped flag record could not express, so
  ``b.hs`` after ``tst`` was taken;
* a shifted or extended register second operand (``add x8, x9, x10, lsl #3``,
  ``add x8, x9, w10, sxtw #2``) was read without its shift / extension.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

from proto.arm64_eval import Flow
from tests.test_arm64_eval_propagate import listing, at_mark

CALL = '#0x9000'


def x3_at_call(value, *body, reg='x2'):
    """x3 at the final call after running *body* with *reg* = *value* (None: unknown)."""
    insns = listing(*body, 'end:', f'bl {CALL}', 'ret')
    k = at_mark(insns)
    return Flow(None, insns).propagate({reg: value}, [k])[k].get('x3')


def branch_on(*flag_setting, cond='eq'):
    """A listing that sets x3 = 2 when *cond* holds after *flag_setting*, else 1."""
    return (*flag_setting, f'b.{cond} @yes', 'mov x3, #1', 'b @end', 'yes:', 'mov x3, #2')


class TestConditionalCompare(unittest.TestCase):
    """``ccmp a, b, #nzcv, cond``: compare when *cond* holds, else set the literal flags."""

    CODE = branch_on('cmp w2, #3', 'ccmp w2, #5, #4, ne')     # V == 3 || V == 5 -> eq

    def test_second_compare_taken(self):
        self.assertEqual(x3_at_call(5, *self.CODE), 2)

    def test_literal_flags_when_condition_fails(self):
        self.assertEqual(x3_at_call(3, *self.CODE), 2)           # #4 = Z set -> eq

    def test_neither(self):
        self.assertEqual(x3_at_call(7, *self.CODE), 1)

    def test_ccmn(self):
        code = branch_on('cmp w2, #3', 'ccmn w2, #1, #0, ne')    # V == 3 ? nzcv 0 : V + 1
        self.assertEqual(x3_at_call(0xFFFFFFFF, *code), 2)       # -1 + 1 == 0 -> eq
        self.assertEqual(x3_at_call(3, *code), 1)                # literal nzcv 0 -> ne


class TestLogicalFlags(unittest.TestCase):
    def test_tst_clears_carry(self):
        # tst sets C = 0, so b.hs is never taken after it
        self.assertEqual(x3_at_call(0xFF, *branch_on('tst w2, #0xf', cond='hs')), 1)
        self.assertEqual(x3_at_call(0xFF, *branch_on('tst w2, #0xf', cond='lo')), 2)

    def test_tst_negative(self):
        self.assertEqual(x3_at_call(0x80000000, *branch_on('tst w2, w2', cond='mi')), 2)

    def test_ands_sets_flags_and_result(self):
        code = branch_on('ands w8, w2, #0xf0', cond='eq')
        self.assertEqual(x3_at_call(0x0F, *code), 2)
        self.assertEqual(x3_at_call(0x10, *code), 1)

    def test_shifted_tst(self):
        code = branch_on('mov w9, #1', 'tst w2, w9, lsl #4', cond='ne')   # bit 4 set?
        self.assertEqual(x3_at_call(0x10, *code), 2)
        self.assertEqual(x3_at_call(0x01, *code), 1)


class TestAddFlags(unittest.TestCase):
    def test_cmn_zero_carry(self):
        # cmn w2, #0 computes V + 0: C = 0 for every V, so b.hs is never taken
        self.assertEqual(x3_at_call(5, *branch_on('cmn w2, #0', cond='hs')), 1)

    def test_adds_carry(self):
        code = branch_on('adds w8, w2, #1', cond='hs')            # carry out of V + 1
        self.assertEqual(x3_at_call(0xFFFFFFFF, *code), 2)
        self.assertEqual(x3_at_call(4, *code), 1)

    def test_mi_is_the_result_sign(self):
        # cmp 0x7fffffff, -1: the 32-bit result 0x80000000 is negative (signed overflow)
        code = branch_on('mov w9, #-1', 'cmp w2, w9', cond='mi')
        self.assertEqual(x3_at_call(0x7FFFFFFF, *code), 2)


class TestUnmodelledFlagSetters(unittest.TestCase):
    """An unmodelled flag-setter makes the flags unknown: the later branch is undecided, so
    x3 is unknown at the join -- not the answer the earlier ``cmp`` would give."""

    def test_fcmp(self):
        self.assertIsNone(x3_at_call(3, *branch_on('cmp w2, #3', 'fcmp s0, s1')))

    def test_shifted_cmp_is_shifted(self):
        code = branch_on('mov w9, #1', 'cmp w2, w9, lsl #2')       # V == 4 ?
        self.assertEqual(x3_at_call(4, *code), 2)
        self.assertEqual(x3_at_call(1, *code), 1)

    def test_unmodelled_operand_form(self):
        # a 4-operand subs (register, extended) the evaluator does not model clears the flags
        self.assertIsNone(x3_at_call(3, *branch_on('cmp w2, #3', 'subs w8, w2, w9, uxtb #1')))


class TestSecondOperand(unittest.TestCase):
    def x3(self, *body):
        return x3_at_call(None, *body, reg='x2')

    def test_lsl(self):
        self.assertEqual(self.x3('mov x9, #2', 'mov x10, #3', 'add x3, x9, x10, lsl #3'), 26)

    def test_lsr_asr(self):
        self.assertEqual(self.x3('mov x9, #0', 'mov x10, #0x40', 'add x3, x9, x10, lsr #4'), 4)
        self.assertEqual(self.x3('mov x9, #0', 'mov x10, #-16', 'add x3, x9, x10, asr #2'),
                         (-4) & 0xFFFFFFFFFFFFFFFF)

    def test_sxtw(self):
        self.assertEqual(self.x3('mov x9, #0x100', 'mov w10, #-1', 'add x3, x9, w10, sxtw #2'), 0xFC)

    def test_uxtw(self):
        self.assertEqual(self.x3('mov x9, #0x100', 'mov w10, #-1', 'add x3, x9, w10, uxtw'),
                         0x100 + 0xFFFFFFFF)

    def test_reaching_definition_constant_is_shifted(self):
        insns = listing('mov x9, #2', 'mov x10, #3', 'add x8, x9, x10, lsl #3', f'bl {CALL}')
        k = at_mark(insns)
        self.assertEqual(Flow(None, insns).const_before(k, 'x8'), 26)

    def test_unknown_extension_is_unknown(self):
        self.assertIsNone(self.x3('mov x9, #1', 'mov w10, #1', 'add x3, x9, w10, msl #8'))


class TestConstantOnEveryPath(unittest.TestCase):
    """const_before: a register is a constant when every definition reaching it is that constant
    (a jump table's base set the same way on each path into its loop)."""

    def x15(self, other):
        insns = listing('cbz x0, @other', 'adrp x15, #0x5000', 'add x15, x15, #0x44', 'b @end',
                        'other:', 'adrp x15, #0x5000', f'add x15, x15, #{other}',
                        'end:', f'bl {CALL}', 'ret')
        return Flow(None, insns).const_before(at_mark(insns), 'x15')

    def test_the_same_constant_on_both_paths(self):
        self.assertEqual(self.x15('0x44'), 0x5044)

    def test_different_constants_are_unknown(self):
        self.assertIsNone(self.x15('0x48'))

    def test_a_constant_parked_across_a_call_and_copied_back(self):
        # locationd's readFrom core: the table base x30 (the link register) is moved to x20
        # around each call and back; by reaching definitions that is a copy cycle (unknown),
        # by the forward evaluation it is the constant on every path
        insns = listing('adrp x30, #0x5000', 'add x30, x30, #0x70', 'end:', 'mov x20, x30',
                        f'bl {CALL}', 'mov x30, x20', 'cbnz x0, @end', 'ret')
        flow = Flow(None, insns)
        k = at_mark(insns)
        self.assertIsNone(flow.const_before(k, 'x30'))
        self.assertEqual(flow.known_before(k).get('x30'), 0x5070)

    def test_a_swift_call_is_assumed_to_succeed(self):
        # x21, Swift's error register, is kept across a Swift call (heuristic registry
        # swift-call-succeeds): the caller's `cbnz x21, <error>` after it is decided
        from unittest import mock
        import proto.callees as C
        from tests._fakes import NoImage
        insns = listing('mov x21, #0', f'bl {CALL}', 'ret')
        with mock.patch.object(C, 'callee_name', lambda ctx, va: '_$s4main5thingyyKF'), \
                mock.patch.object(C, 'stub_selector', lambda ctx, va: None):
            flow = Flow(NoImage(), insns)
            self.assertEqual(flow.known_before(len(insns) - 1).get('x21'), 0)

    def test_a_path_from_the_entry_is_unknown(self):
        insns = listing('cbz x0, @end', 'mov x15, #3', 'end:', f'bl {CALL}', 'ret')
        self.assertIsNone(Flow(None, insns).const_before(at_mark(insns), 'x15'))


if __name__ == '__main__':
    unittest.main()
