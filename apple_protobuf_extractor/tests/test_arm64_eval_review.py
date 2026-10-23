"""proto/arm64_eval.py: the faults the 2026-10-22 review found (TODO #131), each on a listing
whose right answer is plain."""
import unittest
from unittest import mock

from macho.disasm import Insn
import proto.arm64_eval as E
from proto.arm64_eval import Flow, Objects, Sym, _Abort

B = 0x1000


def I(a, m, o=''):
    return Insn(a, m, o, 4, b'\0' * 4)


def is_pointer(v):
    return isinstance(v, Sym) and v.kind == "pointer"


def pointer(k, off=0):
    return Sym("pointer", k, off)


class TestFlowReview(unittest.TestCase):

    def test_a_jump_table_arm_starts_a_block(self):
        """Arm B falls in from arm A: entered at B, x8 is 7 or 5 -- not known."""
        insns = [I(B, 'mov', 'w8, #7'), I(B + 4, 'br', 'x9'), I(B + 8, 'mov', 'w8, #5'),
                 I(B + 12, 'add', 'w0, w8, #0'), I(B + 16, 'ret')]
        f = Flow(None, insns, jump_table_arms={B + 8, B + 12})
        self.assertIsNone(f.const_before(3, 'x8'))

    def test_a_trap_ends_a_block(self):
        # what follows the brk ends in a branch: only the trap can leave its block no successor
        insns = [I(B, 'cmp', 'w8, #3'), I(B + 4, 'b.hs', '#0x100c'), I(B + 8, 'ret'),
                 I(B + 12, 'brk', '#0x1'), I(B + 16, 'mov', 'w0, #1'), I(B + 20, 'b', '#0x1008')]
        self.assertEqual(Flow(None, insns).cfg.succ[B + 12], [])

    def test_evaluate_stops_at_an_authenticated_branch_and_a_trap(self):
        with mock.patch.object(E, "read_cfstring_text", lambda ctx, va: f"S{va:#x}"):
            braa = [I(B, 'ldr', 'w8, [x0]'), I(B + 4, 'braaz', 'x16'), I(B + 8, 'mov', 'x1, #0x10'),
                    I(B + 12, 'ret')]
            with self.assertRaises(_Abort):
                Flow(None, braa).evaluate(0, 'x8', 1)
            brk = [I(B, 'ldr', 'w8, [x0]'), I(B + 4, 'brk', '#0x1'), I(B + 8, 'mov', 'x1, #0x10'),
                   I(B + 12, 'ret')]
            self.assertEqual(Flow(None, brk).evaluate(0, 'x8', 1), {})

    def test_a_negative_value_has_its_load_width(self):
        """ldrsw x8 = -5: cmn x8, #5 is equal (masked to 32 bits it was not)."""
        with mock.patch.object(E, "read_cfstring_text", lambda ctx, va: f"S{va:#x}"):
            insns = [I(B, 'ldrsw', 'x8, [x0]'), I(B + 4, 'cmn', 'x8, #5'), I(B + 8, 'b.ne', '#0x1010'),
                     I(B + 12, 'mov', 'x1, #0x20'), I(B + 16, 'ret')]
            self.assertEqual(Flow(None, insns).evaluate(0, 'x8', -5), {'x1': 'S0x20'})

    def test_a_known_br_target_off_the_cfg_runs_no_arm(self):
        insns = [I(B, 'adr', 'x9, #0x1010'), I(B + 4, 'br', 'x9'), I(B + 8, 'bl', '#0x9000'),
                 I(B + 12, 'ret'), I(B + 16, 'bl', '#0xa000'), I(B + 20, 'ret')]
        reg = Flow(None, insns, br_arms={B + 4: [B + 8]}).run_from(0, {})
        self.assertEqual(reg.calls, [])
        self.assertIn((B + 4, B + 16), reg.br_targets)

    def test_a_frame_store_at_an_unknown_index_clears_the_slots(self):
        insns = [I(B, 'mov', 'w8, #5'), I(B + 4, 'str', 'w8, [sp, #12]'),
                 I(B + 8, 'str', 'wzr, [sp, x9, lsl #2]'), I(B + 12, 'ldr', 'w0, [sp, #12]'),
                 I(B + 16, 'ret')]
        self.assertIsNone(Flow(None, insns).propagate({}, [4])[4].get('x0'))

    def test_a_copy_has_its_register_width(self):
        insns = [I(B, 'mov', 'x9, #-1'), I(B + 4, 'mov', 'w8, w9'), I(B + 8, 'ret')]
        self.assertEqual(Flow(None, insns).const_before(2, 'x8'), 0xFFFFFFFF)

    def test_pointers_are_not_numbers(self):
        """A loaded pointer may be nil (both sides of cbz / tbnz run); two objects' addresses
        have no difference; a pointer's bits are not masked as a number's."""
        loads = {}
        model = Objects(pointer=is_pointer,
                        field_value=lambda v, d: loads.setdefault((v, d), pointer(10 + len(loads))))
        # the cbz and the tbnz each branch to a call of their own
        insns = [I(B, 'ldr', 'x8, [x20, #0x10]'), I(B + 4, 'cbz', 'x8, #0x1014'),
                 I(B + 8, 'tbnz', 'x8, #63, #0x101c'), I(B + 12, 'bl', '#0x9000'), I(B + 16, 'ret'),
                 I(B + 20, 'bl', '#0xa000'), I(B + 24, 'ret'), I(B + 28, 'bl', '#0xb000'),
                 I(B + 32, 'ret')]
        reg = Flow(None, insns).run_from(0, {'x20': pointer(0)}, objects=model)
        self.assertEqual(sorted(c.addr for c in reg.calls), [B + 12, B + 20, B + 28])
        arith = [I(B, 'sub', 'x0, x20, x21'), I(B + 4, 'and', 'x1, x20, #0xfffffffffffffff'),
                 I(B + 8, 'ret')]
        got = Flow(None, arith).propagate({'x20': pointer(0, 8), 'x21': pointer(1)}, [2],
                                          objects=model)[2]
        self.assertNotIn('x0', got)
        self.assertNotIn('x1', got)


    def test_an_object_field_load_with_a_symbolic_index_is_unknown(self):
        """``ldr x0, [x19, x8]`` off an object, with x8 a frame address or a pointer: no
        offset, so nothing is loaded (#144: it raised TypeError, and PegasusAPI's Swift messages
        were lost)."""
        model = Objects(pointer=is_pointer, field_value=lambda v, d: pointer(5, d))
        for name, pre, regs, mem in (
                ("frame address", [I(B, 'add', 'x8, sp, #0x10')], {}, 'x0, [x19, x8]'),
                ("frame address, uxtw", [I(B, 'add', 'x8, sp, #0x10')], {}, 'x0, [x19, w8, uxtw]'),
                ("pointer, lsl", [I(B, 'nop', '')], {'x8': pointer(1)}, 'x0, [x19, x8, lsl #3]')):
            with self.subTest(name):
                insns = pre + [I(B + 4, 'ldr', mem), I(B + 8, 'ret')]
                got = Flow(None, insns).propagate({'x19': pointer(0), **regs}, [2],
                                                  objects=model)[2]
                self.assertNotIn('x0', got)
        # a number index still loads the field at its offset
        insns = [I(B, 'mov', 'x8, #0x18'), I(B + 4, 'ldr', 'x0, [x19, x8]'), I(B + 8, 'ret')]
        got = Flow(None, insns).propagate({'x19': pointer(0)}, [2], objects=model)[2]
        self.assertEqual(got.get('x0'), pointer(5, 0x18))


class TestSymbolicValues(unittest.TestCase):
    """Frame addresses, pointers and tokens are Sym values, not integers in bands (TODO #139):
    what keeps their meaning is defined, anything else raises -- or, in the machine, is unknown
    where it means to be."""

    def test_defined(self):
        f = E.frame(-0x20)
        self.assertEqual((f + 0x10, 0x10 + f, f - 0x10, E.frame(8) - f, f < E.frame(0)),
                         (E.frame(-0x10), E.frame(-0x10), E.frame(-0x30), 0x28, True))
        self.assertEqual((f < f, f <= f, E.frame(0) <= f), (False, True, False))
        self.assertEqual((pointer(3, 8) + 8, 8 + pointer(3, 8), pointer(3, 16) - 8),
                         (pointer(3, 16), pointer(3, 16), pointer(3, 8)))

    def test_anything_else_raises(self):
        tok = Sym("token", "self")
        for op in (lambda: tok + 1, lambda: E.frame(0) >> 3, lambda: E.frame(0) & 0xF,
                   lambda: pointer(1) - pointer(1), lambda: 0 < pointer(1)):
            with self.assertRaises(TypeError):
                op()

    def test_the_machine_takes_them_as_unknown(self):
        tok = Sym("token", "self")
        insns = [I(B, 'add', 'x1, x0, #8'), I(B + 4, 'mov', 'x9, #0x7fffffffffff0000'),
                 I(B + 8, 'add', 'x2, sp, x9'), I(B + 12, 'ret')]
        got = Flow(None, insns).propagate({'x0': tok, 'sp': E.frame(0)}, [3])[3]
        self.assertNotIn('x1', got)          # a token plus a number: no object, no address
        self.assertNotIn('x2', got)          # a frame address 2^47 bytes off: not one

if __name__ == "__main__":
    unittest.main()
