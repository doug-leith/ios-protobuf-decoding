"""The writer flow (:mod:`proto.writer_flow`) run over hand-built listings: the calls of a
function handed the writer, as :meth:`proto.writer_flow.WriterFlow.writer_calls` reports them,
with no binary."""
from unittest import mock

import proto.writer_flow as WF
from tests._fakes import MARKS, TextImage
from tests._listing import layout


class _CodeOnly(TextImage):
    """An image with code and no data: every data address is one no segment holds."""

    def read_bytes(self, addr, size):
        raise ValueError(f"vmaddr {addr:#x} not in any segment")

    def read_ptr(self, addr):
        raise ValueError(f"vmaddr {addr:#x} not in any segment")


def exits(listing):
    """A ``ret`` block at every branch target outside the fragment *listing* (``(base,
    lines)``), and at its end when its last instruction runs on: a real listing cut short,
    whose code past the cut is taken to return (the *tails* of :func:`run_writer_flow`)."""
    base, lines = listing
    end = base + 4 * len(lines)
    targets = {int(op.split('#')[-1], 16) for mn, op in lines
               if (mn == 'b' or mn.startswith('b.') or mn in ('cbz', 'cbnz', 'tbz', 'tbnz'))
               and '#' in op}
    if lines and lines[-1][0] not in ('b', 'ret', 'retab', 'br'):
        targets.add(end)
    return [(t, [('ret', '')]) for t in sorted(targets) if not base <= t < end]


def run_writer_flow(blocks, entry=None, names=None, ctx=None, tails=(), why=None,
                    outlined=False):
    """``(WriterCalls, insns)`` of the function at the first of *blocks* (``(base, [(mnemonic,
    op_str), ...])``, each base a function start; *tails* more blocks of their code) entered
    with the origins *entry* (default: the writer in x0), the callees *names* (``{address: ABI
    symbol}``, default :data:`tests._fakes.MARKS`) named; *ctx* the image (default: one with
    only that code).  The WriterCalls is None when the flow does not decide the function; its
    reasons are added to the list *why*, when given.  *outlined*: the blocks are also read as
    the code a ``bl`` may run in place (a thunk, a fragment: :func:`proto.callees.outlined_code`);
    else a call to them is a call."""
    import contextlib
    order, fd = layout(*blocks, *tails)
    starts = [base for base, _lines in blocks]
    if ctx is None:
        ctx = _CodeOnly(text=(order[0].addr, max(i.addr for i in order) + 4), starts=starts,
                        segments=[])
    names = MARKS if names is None else names
    with mock.patch('proto.function_body.disasm', fd), \
            (mock.patch('proto.callees.disasm', fd) if outlined else contextlib.nullcontext()), \
            mock.patch.object(WF, 'callee_name', lambda c, va: names.get(va)), \
            mock.patch.object(WF, 'stub_selector', lambda c, va: None):
        res = WF._ClassFlow(WF.WriterFlow(ctx, []))._run(
            starts[0], entry or {'x0': frozenset({WF._W})}, 0, starts[0])
    if why is not None and res is not None:
        why.extend(res.why)
    calls = None if res is None or not res.complete else res.calls()
    base, lines = blocks[0]
    return calls, [i for i in order if base <= i.addr < base + 4 * len(lines)]
