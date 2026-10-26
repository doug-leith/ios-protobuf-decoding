"""proto/submessage_marks — a sub-message write in a ``writeTo:``: its begin and end marks.

The runtime writes a length-delimited sub-message as ``PlaceMark(writer, &scratch, F)`` (the
begin mark: a stack scratch slot in x1, the field number F), the sub-message's own fields,
then ``RecallMark(writer, &scratch)`` (the end mark: the same slot, no field number).  A map
entry (:mod:`proto.mapfields`: fields 1 and 2) and an inlined struct (:mod:`proto.structfields`)
are both read as the body between the two marks (:func:`analyze_bracket`).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Sequence, Tuple

from macho.disasm import _parse_imm
from proto.arm64_operands import RETURNS, branch_target, is_conditional, split_ops
from proto.callees import callee_name
from proto.dispatch import listing_flow
from proto.writeto import field_number_at

#: The ProtocolBuffer runtime's begin and end marks
PLACE_MARK, RECALL_MARK = "_PBDataWriterPlaceMark", "_PBDataWriterRecallMark"


def _sp_offset(ins) -> Optional[int]:
    """``K`` of ``add xD, sp, #K`` (``0`` for the ``mov xD, sp`` a block at the very
    bottom of the frame compiles to); else None — i.e. the stack offset *xD* points at."""
    ops = split_ops(ins.op_str)
    if ins.mnemonic == 'add' and len(ops) == 3 and ops[1] == 'sp' and ops[2].startswith('#'):
        return _parse_imm(ops[2])
    if ins.mnemonic == 'mov' and len(ops) == 2 and ops[1] == 'sp':
        return 0
    return None


def scratch_slot_of(flow, k: int) -> Optional[int]:
    """Stack offset K of the ``add x1, sp, #K`` that defines ``x1`` as the argument of
    the call at ``insns[k]`` (the begin/end-mark idiom), else None.  A function that
    addresses its locals from the frame pointer says ``sub x1, x29, #K`` instead; that
    slot is reported as ``-K`` (never equal to an sp-relative one), which is all the
    begin/end pairing needs.  A call between the definition and *k* redefines ``x1``,
    so a stale scratch is never reported."""
    d = flow.only_def(k, 'x1')
    if d is None:
        return None
    ins = flow.insns[d]
    ops = split_ops(ins.op_str)
    if ins.mnemonic == 'sub' and len(ops) == 3 and ops[1] == 'x29' and ops[2].startswith('#'):
        k_off = _parse_imm(ops[2])
        return None if k_off is None else -k_off
    return _sp_offset(ins)


@dataclass(frozen=True)
class Bracket:
    """What one ``begin(F) … end`` sub-message write in an owner's ``writeTo:`` contains."""
    number: int                  # the field number the begin mark carries
    callees: Tuple[int, ...]     # calls with no field number — candidate struct writers
    region: Tuple[int, ...]      # indices (into the listing) of every instruction between the marks
    writes: Tuple[Tuple[int, int, int], ...]   # inline member writes: (index, field#, helper)


def analyze_bracket(ctx, insns: Sequence, begin_idx: int) -> Optional[Bracket]:
    """Analyse the sub-message write whose BEGIN mark (a ``bl`` to :data:`PLACE_MARK` with a
    stack-scratch ``x1`` and a literal field number) is at ``insns[begin_idx]`` in the owner's
    linear ``writeTo:`` listing.  The body is every instruction reachable from the mark WITHOUT
    passing the matching END mark (:data:`RECALL_MARK`, same scratch slot): the branches an inlined struct's
    has-bit tests compile to put some members out of line, past the loop's back-edge, so a
    straight read to the end mark would miss them.

    Returns the field number, the calls inside that carry NO field number (candidate struct
    serialisers ``f(&struct, writer)``) and the calls that DO carry one (members written
    inline), or ``None`` if there is no begin mark here, a path leaves the listing or reaches
    ``ret`` before an end mark, or a nested/foreign mark appears (an unmodelled shape)."""
    flow = listing_flow(ctx, insns)
    begin = insns[begin_idx]
    if begin.mnemonic != 'bl' or callee_name(ctx, branch_target(begin)) != PLACE_MARK:
        return None
    slot = scratch_slot_of(flow, begin_idx)
    if slot is None:
        return None
    number = field_number_at(flow, begin_idx)
    if number is None or number < 1:
        return None
    at = {ins.addr: k for k, ins in enumerate(insns)}
    seen, work = set(), [begin_idx + 1]
    callees: List[int] = []
    writes: List[Tuple[int, int, int]] = []
    ended = False
    while work:
        k = work.pop()
        while k is not None and 0 <= k < len(insns) and k not in seen:
            seen.add(k)
            ins, mn, nxt = insns[k], insns[k].mnemonic, k + 1
            if mn in RETURNS:
                return None                          # a path with no end mark
            if mn == 'b':
                t = at.get(branch_target(ins))
                if t is None:
                    return None                      # leaves the function (a tail-called write
                                                     # too): no end mark
                nxt = t                              # in-function jump (a shared tail's write
                                                     # is recorded at its own bl)
            elif mn == 'bl':
                fn = field_number_at(flow, k)
                target = branch_target(ins)
                mark = callee_name(ctx, target)
                if mark == RECALL_MARK and scratch_slot_of(flow, k) == slot:
                    ended = True
                    break                            # END mark: this path is complete
                if mark in (PLACE_MARK, RECALL_MARK):
                    return None                      # nested begin / another bracket's end
                if fn is not None and target is not None:
                    writes.append((k, fn, target))
                elif target is not None:
                    callees.append(target)
            elif is_conditional(mn):
                t = at.get(branch_target(ins))
                if t is None:
                    return None
                work.append(t)
            k = nxt
    if not ended:
        return None
    return Bracket(number, tuple(dict.fromkeys(callees)), tuple(sorted(seen)), tuple(writes))
