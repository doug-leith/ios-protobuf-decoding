"""proto.function_body: a function's extent is bounded by every function entry known (the image's
LC_FUNCTION_STARTS and a caller's own index), and a body follows the jump-table arms a caller
found by evaluation.  The swift-side reading rules are in test_swift_descriptor_extract's
TestListing."""
import unittest
from unittest import mock

from proto import dispatch as D
from proto import function_body as FB
from tests._fakes import TextImage
from tests._listing import layout


def _Ctx(starts):
    """Function starts *starts* in a ``__text`` of 0x1000-0x3000."""
    return TextImage((0x1000, 0x3000), starts)


def _read(lines, starts, entries=(), arms=None):
    _order, fd = layout((0x1000, lines))
    with mock.patch.object(FB, 'disasm', fd):
        return [i.addr for i in FB.function_body(_Ctx(starts), 0x1000, D.FunctionEntries(entries),
                                                 arms)]


# a function ending in a call that never returns, then the next function's code
_NORETURN = [('mov', 'x0, x1'), ('bl', '#0x9000'),
             ('stp', 'x29, x30, [sp, #-0x10]!'), ('ret', '')]


class TestExtent(unittest.TestCase):
    def test_the_next_function_start_ends_the_body_past_a_noreturn_call(self):
        self.assertEqual(_read(_NORETURN, [0x1000, 0x1008]), [0x1000, 0x1004])

    def test_the_callers_index_bounds_it_too(self):
        # no LC_FUNCTION_STARTS entry after the function, but the caller knows one
        self.assertEqual(_read(_NORETURN, [0x1000], entries=[0x1000, 0x1008]), [0x1000, 0x1004])

    def test_the_nearer_entry_wins(self):
        self.assertEqual(_read(_NORETURN, [0x1000, 0x2000], entries=[0x1008]), [0x1000, 0x1004])
        self.assertEqual(_read(_NORETURN, [0x1000, 0x1008], entries=[0x2000]), [0x1000, 0x1004])

    def test_is_function_entry(self):
        ctx = _Ctx([0x1000, 0x1100])
        self.assertTrue(FB.is_function_entry(ctx, 0x1100))
        self.assertTrue(FB.is_function_entry(ctx, 0x1080, D.FunctionEntries([0x1080])))
        self.assertFalse(FB.is_function_entry(ctx, 0x1004))

    def test_function_end(self):
        ctx = _Ctx([0x1000, 0x1100])
        self.assertEqual(FB.function_end(ctx, 0x1000), 0x1100)
        self.assertEqual(FB.function_end(ctx, 0x1000, D.FunctionEntries([0x1080])), 0x1080)
        self.assertEqual(FB.function_end(ctx, 0x1100), 0x3000)        # the last: __text's end
        # outside __text (a stub island, another image) the index bounds nothing
        self.assertIsNone(FB.function_end(ctx, 0x3000, D.FunctionEntries([0x4000])))


class TestGivenArms(unittest.TestCase):
    # `br x9` whose table the decoder cannot read (no image); its arm at 0x100c is known to the
    # caller (found by evaluating the br under each field number)
    _LINES = [('ldr', 'x9, [x0]'), ('br', 'x9'), ('ret', ''), ('mov', 'x0, #1'), ('ret', '')]

    def test_an_arm_the_caller_found_is_read(self):
        self.assertEqual(_read(self._LINES, [0x1000, 0x1014], arms={0x1004: {0x100c}}),
                         [0x1000, 0x1004, 0x100c, 0x1010])

    def test_without_it_the_br_ends_the_path(self):
        self.assertEqual(_read(self._LINES, [0x1000, 0x1014]), [0x1000, 0x1004])

    def test_an_arm_outside_the_extent_is_not_read(self):
        self.assertEqual(_read(self._LINES, [0x1000, 0x100c], arms={0x1004: {0x100c}}),
                         [0x1000, 0x1004])


# `and w8, w0, #3` bounds a table of 8-byte arms after the br; the nops between are never run
_MASK_TABLE = [('and', 'w8, w0, #3'), ('adr', 'x9, #0x1010'), ('add', 'x9, x9, x8, lsl #3'),
               ('br', 'x9'), ('ret', ''), ('nop', ''), ('ret', ''), ('nop', ''), ('ret', ''),
               ('nop', ''), ('ret', '')]


class TestDecodedTables(unittest.TestCase):
    def test_a_decoded_tables_arms_are_read(self):
        self.assertEqual(_read(_MASK_TABLE, [0x1000, 0x102c]),
                         [0x1000, 0x1004, 0x1008, 0x100c, 0x1010, 0x1018, 0x1020, 0x1028])

    def test_the_bodys_decode_is_its_callers(self):
        # the reader decodes the finished body within its extent; every arm lies in the body's
        # span, so the callers' decode of the body (no bounds) is that same decode
        _order, fd = layout((0x1000, _MASK_TABLE))
        ctx = _Ctx([0x1000, 0x1030])
        with mock.patch.object(FB, 'disasm', fd):
            body = FB.function_body(ctx, 0x1000)
        self.assertIs(D._decoded(ctx, body), D._decoded(ctx, body, (0x1000, 0x1030)))

    def test_a_partial_listing_is_not_its_own_decode(self):
        # arms past the listing's last instruction: found within bounds, not without
        _order, fd = layout((0x1000, _MASK_TABLE))
        ctx = _Ctx([])
        partial = fd(ctx, 0x1000, max_insns=4)
        self.assertEqual(D._jump_table_arm_addrs(ctx, partial, bounds=(0x1000, 0x102c)),
                         {0x1010, 0x1018, 0x1020, 0x1028})
        self.assertEqual(D._jump_table_arm_addrs(ctx, partial), set())


if __name__ == "__main__":
    unittest.main()
