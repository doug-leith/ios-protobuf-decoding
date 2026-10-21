"""
proto/arm64_eval.py: the stack-slot model and the whole-function constant propagation
(``Flow.propagate`` / ``Flow.flag_runs``) that read a dictionary key wherever the compiler put
it -- chosen once before a loop by the JSON flag (``cmp w22,#0; csel x8,x9,x8,ne``), spilled to
the frame and reloaded into x3 at the ``setObject:forKey:`` call (the real
GEOFlyoverRegionVersions shape; its listing is in tests/test_struct_fields.py).

The listings are instruction text as capstone prints it (``Insn`` objects, no binary needed);
``@label`` operands are resolved to addresses.
"""
import os
import sys
import unittest

from tests._listing import text_listing
from tests._fakes import NoImage

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

from proto.arm64_eval import Flow, _STACK_TOP

PLAIN, JSON = 0x5040, 0x5060           # the two spellings' CFString addresses
CALL = '#0x9000'                       # some callee outside the listing


def listing(*lines, base=0x1000):
    """``Insn`` list of *lines* (``'mnemonic ops'`` or ``'label:'``) placed at *base*."""
    return text_listing(*lines, base=base)[0]


def at_mark(insns, mark='bl', nth=-1):
    """Index of the *nth* instruction with mnemonic *mark*."""
    return [k for k, i in enumerate(insns) if i.mnemonic == mark][nth]


class _StringsCtx(NoImage):
    """A binary with no ``__cfstring`` section: string constants are plain C strings."""

    def __init__(self, strings):
        self.strings = strings

    def has_section(self, segname, sectname):
        return False

    def read_cstring(self, va, max_len=4096):
        if va not in self.strings:
            raise ValueError(f"no string at {va:#x}")
        return self.strings[va]


PROLOGUE = ('sub sp, sp, #0x30', 'stp x29, x30, [sp, #0x20]', 'add x29, sp, #0x20')
EPILOGUE = ('ldp x29, x30, [sp, #0x20]', 'add sp, sp, #0x30', 'ret')


class TestStackSlots(unittest.TestCase):
    def known_x3(self, *body):
        insns = listing(*PROLOGUE, *body, *EPILOGUE)
        k = at_mark(insns)
        return Flow(None, insns).propagate({}, [k])[k].get('x3')

    def test_a_value_spilled_to_the_frame_survives_a_call_and_reloads(self):
        self.assertEqual(self.known_x3(
            'adrp x8, #0x5000', 'add x8, x8, #0x40', 'str x8, [sp, #8]',
            f'bl {CALL}', 'ldr x3, [sp, #8]', f'bl {CALL}'), PLAIN)

    def test_the_frame_pointer_and_sp_forms_address_the_same_slot(self):
        # x29 = sp + 0x20, so [x29, #-0x18] is [sp, #8]
        self.assertEqual(self.known_x3(
            'adrp x8, #0x5000', 'add x8, x8, #0x40', 'stur x8, [x29, #-0x18]',
            f'bl {CALL}', 'ldr x3, [sp, #8]', f'bl {CALL}'), PLAIN)

    def test_writeback_moves_sp(self):
        insns = listing('stp x29, x30, [sp, #-0x10]!', 'mov x29, sp', 'sub sp, sp, #0x10',
                        f'bl {CALL}', 'add sp, sp, #0x10', 'ldp x29, x30, [sp], #0x10', 'ret')
        k_call, k_ret = at_mark(insns), at_mark(insns, 'ret')
        got = Flow(None, insns).propagate({}, [k_call, k_ret])
        self.assertEqual((got[k_call]['sp'], got[k_call]['x29']), (_STACK_TOP - 0x20, _STACK_TOP - 0x10))
        self.assertEqual(got[k_ret]['sp'], _STACK_TOP)

    def test_a_slot_whose_address_escaped_is_lost_at_the_next_call(self):
        # the callee was handed &slot (x1), so it may have overwritten it
        self.assertIsNone(self.known_x3(
            'adrp x8, #0x5000', 'add x8, x8, #0x40', 'str x8, [sp, #8]',
            'add x1, sp, #8', f'bl {CALL}', 'ldr x3, [sp, #8]', f'bl {CALL}'))

    def test_a_stack_address_no_callee_is_handed_does_not_expose_the_frame(self):
        # x17 holds &slot (the block-building idiom) but no call is handed it
        self.assertEqual(self.known_x3(
            'adrp x8, #0x5000', 'add x8, x8, #0x40', 'str x8, [sp, #8]',
            'add x17, sp, #8', f'bl {CALL}', 'ldr x3, [sp, #8]', f'bl {CALL}'), PLAIN)

    def test_a_runtime_call_is_handed_only_the_registers_its_contract_reads(self):
        # objc_retain_x19 reads x19 only: the stack address in x8 (a scratch) is not handed
        from unittest import mock
        import proto.arm64_eval as AE
        insns = listing(*PROLOGUE, 'adrp x8, #0x5000', 'add x8, x8, #0x40', 'str x8, [sp, #8]',
                        'add x8, sp, #8', f'bl {CALL}', 'ldr x3, [sp, #8]', f'bl {CALL}',
                        *EPILOGUE)
        k = at_mark(insns)
        from proto.callees import ABI_ARGS, RUNTIME_CONTRACTS
        for reads, want in ((RUNTIME_CONTRACTS["_objc_retain_x19"][0], PLAIN), (ABI_ARGS, None)):
            with mock.patch.object(AE, 'call_reads', lambda ctx, va, r=reads: r):
                self.assertEqual(Flow(NoImage(), insns).propagate({}, [k])[k].get('x3'), want)

    def test_a_stack_address_handed_once_exposes_the_frame_to_every_later_call(self):
        self.assertIsNone(self.known_x3(
            'add x1, sp, #0x10', f'bl {CALL}',
            'adrp x8, #0x5000', 'add x8, x8, #0x40', 'str x8, [sp, #8]',
            f'bl {CALL}', 'ldr x3, [sp, #8]', f'bl {CALL}'))

    def test_a_stack_address_stored_outside_the_frame_exposes_it(self):
        self.assertIsNone(self.known_x3(
            'adrp x8, #0x5000', 'add x8, x8, #0x40', 'str x8, [sp, #8]',
            'add x9, sp, #8', 'adrp x10, #0x6000', 'str x9, [x10]',
            f'bl {CALL}', 'ldr x3, [sp, #8]', f'bl {CALL}'))

    def test_a_narrower_store_over_the_slot_invalidates_it(self):
        self.assertIsNone(self.known_x3(
            'adrp x8, #0x5000', 'add x8, x8, #0x40', 'str x8, [sp, #8]',
            'strb wzr, [sp, #0xc]', 'ldr x3, [sp, #8]', f'bl {CALL}'))

    def test_a_caller_saved_register_does_not_survive_a_call(self):
        self.assertIsNone(self.known_x3(
            'adrp x3, #0x5000', 'add x3, x3, #0x40', f'bl {CALL}', f'bl {CALL}'))

    def test_concrete_evaluation_from_the_entry_reads_a_spilled_value_back(self):
        # Flow.evaluate shares the instruction model: from the entry (root -1) the frame is
        # known, so a spill and reload before the first call is followed too
        insns = listing(*PROLOGUE, 'adrp x8, #0x5000', 'add x8, x8, #0x40',
                        'str x8, [sp, #8]', 'ldr x0, [sp, #8]', f'bl {CALL}', *EPILOGUE)
        self.assertEqual(Flow(_StringsCtx({PLAIN: 'name'}), insns).evaluate(-1, 'x2', 0),
                         {'x0': 'name'})


# The GEOFlyoverRegionVersions shape, reduced: the key is chosen by the flag in x1 BEFORE the
# loop, spilled, and reloaded into x3 inside it.
HOISTED_CSEL = (
    *PROLOGUE, 'mov x22, x1', 'mov x19, #0',
    'adrp x8, #0x5000', 'add x8, x8, #0x40', 'adrp x9, #0x5000', 'add x9, x9, #0x60',
    'cmp w22, #0', 'csel x8, x9, x8, ne', 'str x8, [sp, #8]',
    'loop:', f'bl {CALL}', 'ldr x3, [sp, #8]', 'mov x0, x20', f'bl {CALL}',
    'add x19, x19, #1', 'cmp x19, x21', 'b.lo @loop', *EPILOGUE)


class TestFlagRuns(unittest.TestCase):
    def test_the_flag_argument_is_the_entry_register_the_key_choice_tests(self):
        self.assertEqual(Flow(None, listing(*HOISTED_CSEL)).flag_arguments(), ('x1',))

    def test_a_hoisted_csel_gives_one_key_per_flag_value(self):
        insns = listing(*HOISTED_CSEL)
        k = at_mark(insns, nth=1)
        runs = Flow(None, insns).flag_runs([k])
        self.assertEqual([r[k]['x3'] for r in runs], [PLAIN, JSON])

    def test_a_loop_counter_is_not_a_constant(self):
        insns = listing(*HOISTED_CSEL)
        k = at_mark(insns, nth=1)
        self.assertNotIn('x19', Flow(None, insns).propagate({'x1': 0}, [k])[k])

    def test_without_the_flag_fixed_the_key_is_unknown(self):
        insns = listing(*HOISTED_CSEL)
        k = at_mark(insns, nth=1)
        self.assertNotIn('x3', Flow(None, insns).propagate({}, [k])[k])

    def test_a_branch_on_the_flag_follows_only_the_side_taken(self):
        # the same choice compiled to a branch: the join would lose x3 unless the branch
        # decided by the flag is followed one way only
        insns = listing(
            'cbz w1, @plain', 'adrp x3, #0x5000', 'add x3, x3, #0x60', 'b @merge',
            'plain:', 'adrp x3, #0x5000', 'add x3, x3, #0x40',
            'merge:', f'bl {CALL}', 'ret')
        k = at_mark(insns)
        flow = Flow(None, insns)
        self.assertEqual(flow.flag_arguments(), ('x1',))
        self.assertEqual([r[k]['x3'] for r in flow.flag_runs([k])], [PLAIN, JSON])
        self.assertNotIn('x3', flow.propagate({}, [k])[k])

    def test_the_object_register_is_never_a_flag(self):
        # `cbz x0` is the nil check of self / the struct pointer, not a flag
        insns = listing('cbz x0, @out', f'bl {CALL}', 'out:', 'ret')
        self.assertEqual(Flow(None, insns).flag_arguments(), ())


if __name__ == '__main__':
    unittest.main()


class TestSymbolicValues(unittest.TestCase):
    """A frame address is not a number: it lives above the 64-bit value space, keeps its meaning
    only through copies, adding or subtracting a number, the difference of two and 16-byte
    alignment, and no constant can be taken for one (the emulation oracle,
    oracles/flow_emulation.py: locationd's `mov x8, #0x4000000000000000` -- the double 2.0 --
    and 2^62 - 1 were frame addresses, `sp + 0xaee7507db13ae316` a known number)."""

    def known(self, *body, reg='x8'):
        insns = listing(*body, f'bl {CALL}')
        k = at_mark(insns)
        return Flow(None, insns).propagate({}, [k])[k].get(reg)

    def test_a_constant_is_never_a_frame_address(self):
        for c in ('#0x4000000000000000', '#0x3fffffffffffffff'):
            with self.subTest(c=c):
                self.assertEqual(self.known(f'mov x8, {c}'), int(c[1:], 16))

    def test_a_frame_address_plus_a_number(self):
        self.assertEqual(self.known('add x8, sp, #0x40'), _STACK_TOP + 0x40)
        self.assertEqual(self.known('mov x9, #-0x10', 'add x8, sp, x9'), _STACK_TOP - 0x10)
        self.assertEqual(self.known('sub x8, sp, #0x40', 'and x8, x8, #-0x10'), _STACK_TOP - 0x40)
        self.assertEqual(self.known('add x9, sp, #0x40', 'add x10, sp, #8', 'sub x8, x9, x10'), 0x38)

    def test_what_depends_on_where_the_stack_is_is_unknown(self):
        big = ('mov x8, #0xe316', 'movk x8, #0xb13a, lsl #16', 'movk x8, #0x507d, lsl #32',
               'movk x8, #0xaee7, lsl #48')
        for body in ((*big, 'add x9, sp, #0x5b0', 'add x8, x9, x8'),   # locationd 0x1000dac54
                     ('mov x9, sp', 'mov w8, w9'),                      # its low half
                     ('mov x9, sp', 'lsr x8, x9, #4'),
                     ('mov x9, sp', 'and x8, x9, #-0x40'),              # beyond the ABI's alignment
                     ('mov x9, #0x40', 'sub x8, x9, sp'),
                     ('mov x9, sp', 'eor x8, x9, #1')):
            with self.subTest(body=body):
                self.assertIsNone(self.known(*body))

    def test_flags_of_a_frame_address(self):
        """Two frame addresses compare by their offsets; against a number, unknown."""
        decided = listing('add x9, sp, #0x10', 'add x10, sp, #0x20', 'cmp x9, x10',
                          'b.lo @lo', 'mov x8, #1', f'bl {CALL}', 'ret', 'lo:', 'mov x8, #2',
                          f'bl {CALL}', 'ret')
        ks = [k for k, i in enumerate(decided) if i.mnemonic == 'bl']
        got = Flow(None, decided).propagate({}, ks)
        self.assertEqual([got.get(k, {}).get('x8') for k in ks], [None, 2])
        undecided = listing('mov x9, sp', 'cmp x9, #0x10', 'b.lo @lo', 'mov x8, #1',
                            f'bl {CALL}', 'ret', 'lo:', 'mov x8, #2', f'bl {CALL}', 'ret')
        ks = [k for k, i in enumerate(undecided) if i.mnemonic == 'bl']
        got = Flow(None, undecided).propagate({}, ks)
        self.assertEqual([got[k].get('x8') for k in ks], [1, 2])     # both paths run


class TestRunTimeMemory(unittest.TestCase):
    """A load gives the file's bytes only where they are the run-time value: not a variable the
    program writes (locationd 0x100d0d9ac read its __data global's file value 0x19 after storing
    to it), nor a slot bound to an import (its raw chained-fixup encoding was a known number)."""

    class _Ctx(NoImage):
        def __init__(self, variable):
            self.variable = variable

        def is_variable(self, va):
            return va in self.variable

        def read_ptr(self, va):
            return 0x8010000000000696

        def read_bytes(self, va, n):
            return (0x19).to_bytes(n, 'little')

    def test_variable_memory_is_unknown(self):
        insns = listing('adrp x9, #0x7000', 'ldr w8, [x9, #0x788]', 'ldr x10, [x9, #0x790]',
                        f'bl {CALL}')
        k = at_mark(insns)
        fixed = Flow(self._Ctx(set()), insns).propagate({}, [k])[k]
        self.assertEqual((fixed.get('x8'), fixed.get('x10')), (0x19, 0x8010000000000696))
        variable = Flow(self._Ctx({0x7788, 0x7790}), insns).propagate({}, [k])[k]
        self.assertEqual((variable.get('x8'), variable.get('x10')), (None, None))


class TestEntryBlockLoop(unittest.TestCase):
    """A function whose first instruction heads a loop (locationd 0x1013769ac): the definitions
    reaching the entry block are the entry's and the back edge's (the emulation oracle found
    defs_before giving the entry's alone)."""

    def test_back_edge_into_the_entry_block(self):
        insns = listing('loop:', 'ldrb w8, [x0, #-0x18]', 'sub x8, x0, #0x48', 'cbz w9, @out',
                        'mov x0, x8', 'b @loop', 'out:', 'ret')
        flow = Flow(None, insns)
        self.assertEqual(flow.defs_before(0, 'x0'), frozenset((-1, 3)))


class TestFlagsOfFrameAddresses(unittest.TestCase):
    """The review of #125: ``ands`` on a frame address leaves no flags behind; ``cmn`` / ``adds``
    of two frame addresses (a sum, which depends on where the stack is) decide nothing."""

    def x8_at_calls(self, *body):
        insns = listing(*body, 'mov x8, #1', f'bl {CALL}', 'ret', 'other:', 'mov x8, #2',
                        f'bl {CALL}', 'ret')
        ks = [k for k, i in enumerate(insns) if i.mnemonic == 'bl']
        got = Flow(None, insns).propagate({}, ks)
        return [got.get(k, {}).get('x8') for k in ks]

    def test_ands_of_a_frame_address_leaves_no_flags(self):
        # cmp sets Z; the ands after it must not leave that Z for b.eq to decide
        self.assertEqual(self.x8_at_calls('mov x9, #0', 'cmp x9, #0', 'mov x10, sp',
                                          'ands x11, x10, #0xff', 'b.eq @other'), [1, 2])

    def test_a_sum_of_frame_addresses_decides_nothing(self):
        for op in ('cmn x9, x10', 'adds x11, x9, x10'):
            with self.subTest(op=op):
                self.assertEqual(self.x8_at_calls('add x9, sp, #0x10', 'add x10, sp, #0x20', op,
                                                  'b.cs @other'), [1, 2])
