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

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

from macho.disasm import Insn
from proto.arm64_eval import Flow, _STACK_TOP

PLAIN, JSON = 0x5040, 0x5060           # the two spellings' CFString addresses
CALL = '#0x9000'                       # some callee outside the listing


def listing(*lines, base=0x1000):
    """``Insn`` list of *lines* (``'mnemonic ops'`` or ``'label:'``) placed at *base*."""
    labels, code, pc = {}, [], base
    for ln in lines:
        if ln.endswith(':'):
            labels[ln[:-1]] = pc
        else:
            code.append((pc, ln))
            pc += 4
    out = []
    for a, ln in code:
        mn, _, ops = ln.partition(' ')
        for name, addr in labels.items():
            ops = ops.replace('@' + name, hex(addr).replace('0x', '#0x'))
        out.append(Insn(addr=a, mnemonic=mn, op_str=ops, size=4, raw=b'\0' * 4))
    return out


def at_mark(insns, mark='bl', nth=-1):
    """Index of the *nth* instruction with mnemonic *mark*."""
    return [k for k, i in enumerate(insns) if i.mnemonic == mark][nth]


class _StringsCtx:
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
                self.assertEqual(Flow(object(), insns).propagate({}, [k])[k].get('x3'), want)

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
