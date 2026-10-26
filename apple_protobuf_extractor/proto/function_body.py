"""proto/function_body -- the instructions of a function: what its entry reaches inside its
extent.  The one reader of a function body for the ObjC readers (:mod:`proto.dispatch_eval`,
:mod:`proto.writer_flow`) and the swift serializers
(:mod:`serializers.swift_descriptor_extract`).

* :func:`function_end` -- where the function at an address of the image's ``__text`` ends: the
  next function entry the image's ``LC_FUNCTION_STARTS`` or a caller's own index (method IMPs,
  ReadAllFrom cores) knows, else the end of ``__text``.
* :func:`is_function_entry` -- whether a function starts at an address, by the same index.
* :func:`function_body` -- the instructions its entry reaches before that, following ``b`` and
  conditional branches inside the extent and each ``br``'s decoded jump table.  A branch out
  of the extent is a tail call.
* :func:`function_listing` -- every instruction of that extent in address order, for a reader
  that evaluates from the entry itself (its evaluation decides what runs).
"""
from __future__ import annotations
import bisect
from typing import Dict, Iterable, Optional

from macho.memory import READ_ERRORS, BinaryContext
from macho.disasm import disasm
from proto.arm64_operands import PATH_ENDS, branch_target, is_conditional
from proto.callees import text_holding
from proto.dispatch import _jump_table_arm_addrs
from proto.models import record_heuristic_hit

# [cap:COSMETIC — ×8 changes none of the 19 gate targets, 2026-10-26] runaway guard on a body read with no known extent (:func:`function_body`;
# with one, the extent bounds it).  A body that reaches it is marked truncated.
_UNBOUNDED_MAX_INSNS = 4000
# [cap:COSMETIC] instructions disassembled per read while following a path when the extent is
# unknown (with one, a read covers the rest of the extent); a path is read on until it ends,
# whatever this is.
_READ_CHUNK = 64


class FunctionBody(list):
    """A function's instructions in address order (:func:`function_body`); *truncated* when the
    read is incomplete -- it stopped at :data:`_UNBOUNDED_MAX_INSNS` with paths still open, or a
    path (a listing) ran into a word that cannot be read or decoded; *flow* a reader's
    :class:`~proto.arm64_eval.Flow` of it once built."""
    truncated = False
    flow = None


def function_end(ctx: BinaryContext, va: int, entries=None) -> Optional[int]:
    """Where the function at *va* ends: the first function entry above it that
    :meth:`BinaryContext.function_starts` or *entries* (a
    :class:`proto.dispatch.FunctionEntries`) holds, else -- the image's last function -- the
    end of the image's ``__TEXT,__text``.  None when *va* is not in that section (another
    image's code, a stub island): this image's function index does not bound it."""
    text = text_holding(ctx, va)
    if text is None:
        return None
    end = text.vmaddr + text.vmsize
    starts = ctx.function_starts()
    i = bisect.bisect_right(starts, va)
    if i < len(starts):
        end = min(end, starts[i])
    nxt = entries.next_after(va) if entries else None
    return min(end, nxt) if nxt is not None else end


def is_function_entry(ctx: BinaryContext, va: int, entries=None) -> bool:
    """*va* is where a function starts: in :meth:`BinaryContext.function_starts` or *entries*
    (a :class:`proto.dispatch.FunctionEntries`)."""
    if entries is not None and va in entries.members:
        return True
    starts = ctx.function_starts()
    i = bisect.bisect_left(starts, va)
    return i < len(starts) and starts[i] == va


def function_body(ctx: BinaryContext, va: int, entries=None,
                  arms: Optional[Dict[int, Iterable[int]]] = None) -> FunctionBody:
    """The instructions of the function at *va* that its entry reaches, in address order.

    The function's extent is *va* up to :func:`function_end`.  Both sides of each conditional
    branch and the target of each ``b`` inside the extent are followed; each path runs on to a
    return, an indirect jump, a trap, or a branch out of the extent (a tail call, not
    followed).  Calls return.  A ``br`` goes on to its jump table's arms inside the extent,
    decoded by evaluation (:func:`proto.dispatch._jump_table_arm_addrs`), and to the arms
    *arms* gives it (``{br address: targets}``, found by a caller's own evaluation).  A table
    reached only through another's arms is decoded once those are read.

    With no known end (:func:`function_end` is None) the extent is unknown: a ``b`` ends its path unless it
    goes to the next instruction, no table is decoded, and the read stops at
    :data:`_UNBOUNDED_MAX_INSNS` (*truncated*).  Raises when *va* itself cannot be read."""
    end = function_end(ctx, va, entries)

    def inside(t: Optional[int]) -> bool:
        return t is not None and va <= t and (end is None or t < end)

    decoded: Dict[int, object] = {}

    def insn_at(a: int):
        """The instruction at *a*: the extent from *a* is disassembled once (a read stops at a
        word capstone cannot decode, the next read starts past it); None if none decodes."""
        if a not in decoded:
            n = (end - a) // 4 if end is not None else _READ_CHUNK
            for ins in disasm(ctx, a, max_insns=n, stop_at_ret=False):
                if end is not None and ins.addr >= end:
                    break
                decoded[ins.addr] = ins
        return decoded.get(a)

    out: Dict[int, object] = {}
    open_path = False                  # a path stopped at a word that cannot be read or decoded
    work = [va]
    while True:
        while work:
            a = work.pop()
            while a is not None and a not in out and (end is None or a < end):
                try:
                    ins = insn_at(a)
                except READ_ERRORS:
                    if a == va:
                        raise
                    open_path = True
                    break
                if ins is None:
                    open_path = True
                    break
                if end is None and len(out) >= _UNBOUNDED_MAX_INSNS:
                    record_heuristic_hit(ctx, "_UNBOUNDED_MAX_INSNS", f"the function at {va:#x}")
                    body = FunctionBody(sorted(out.values(), key=lambda i: i.addr))
                    body.truncated = True
                    return body
                out[a] = ins
                mn = ins.mnemonic
                a += 4
                if mn in PATH_ENDS:
                    break
                if mn == "b":
                    t = branch_target(ins)
                    if inside(t) if end is not None else t == ins.addr + 4:
                        work.append(t)
                    break
                if is_conditional(mn):
                    t = branch_target(ins)
                    if inside(t):
                        work.append(t)
        targets = {t for b, ts in (arms or {}).items() if b in out for t in ts}
        if end is not None:
            tables = _jump_table_arm_addrs(ctx, sorted(out.values(), key=lambda i: i.addr),
                                           per_br=True, bounds=(va, end))
            targets.update(t for ts in tables.values() for t in ts)
        work = sorted(t for t in targets if t not in out and inside(t))
        if not work:
            break
    body = FunctionBody(sorted(out.values(), key=lambda i: i.addr))
    body.truncated = open_path
    return body


def function_listing(ctx: BinaryContext, va: int, entries=None) -> FunctionBody:
    """The function at *va* as one linear listing: every instruction of its extent (*va* up to
    :func:`function_end`) in address order, out-of-line blocks included, for a reader that
    evaluates from the entry and so decides itself what runs (a jump table only evaluation
    resolves reaches its arms).  A word capstone cannot decode ends it (*truncated*).
    With no known end, the instructions the entry reaches (:func:`function_body`).  Raises
    when *va* cannot be read."""
    end = function_end(ctx, va, entries)
    if end is None:
        return function_body(ctx, va, entries)
    body = FunctionBody(i for i in disasm(ctx, va, max_insns=max(1, (end - va) // 4),
                                          stop_at_ret=False) if i.addr < end)
    body.truncated = not body or body[-1].addr + 4 < end
    return body
