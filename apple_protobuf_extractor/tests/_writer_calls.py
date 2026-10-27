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
    lines)``): a real listing cut short, whose code past the cut is taken to return (the
    *tails* of :func:`run_writer_flow`)."""
    base, lines = listing
    end = base + 4 * len(lines)
    targets = {int(op.split('#')[-1], 16) for mn, op in lines
               if (mn == 'b' or mn.startswith('b.') or mn in ('cbz', 'cbnz', 'tbz', 'tbnz'))
               and '#' in op}
    return [(t, [('ret', '')]) for t in sorted(targets) if not base <= t < end]


def run_writer_flow(blocks, entry=None, names=None, ctx=None, tails=()):
    """``(WriterCalls, insns)`` of the function at the first of *blocks* (``(base, [(mnemonic,
    op_str), ...])``, each base a function start; *tails* more blocks of their code) entered
    with the origins *entry* (default: the writer in x0), the callees *names* (``{address: ABI
    symbol}``, default :data:`tests._fakes.MARKS`) named; *ctx* the image (default: one with
    only that code).  The WriterCalls is None when the flow does not decide the function."""
    order, fd = layout(*blocks, *tails)
    starts = [base for base, _lines in blocks]
    if ctx is None:
        ctx = _CodeOnly(text=(order[0].addr, max(i.addr for i in order) + 4), starts=starts,
                        segments=[])
    names = MARKS if names is None else names
    with mock.patch('proto.function_body.disasm', fd), \
            mock.patch.object(WF, 'callee_name', lambda c, va: names.get(va)), \
            mock.patch.object(WF, 'stub_selector', lambda c, va: None):
        res = WF._ClassFlow(WF.WriterFlow(ctx, []))._run(
            starts[0], entry or {'x0': frozenset({WF._W})}, 0, starts[0])
    calls = (None if res is None or not res.complete
             else WF.WriterCalls(tuple(res.sites[a] for a in sorted(res.sites)),
                                 frozenset(res.open_at_exit)))
    base, lines = blocks[0]
    return calls, [i for i in order if base <= i.addr < base + 4 * len(lines)]
