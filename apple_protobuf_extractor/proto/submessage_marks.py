"""proto/submessage_marks — a sub-message write in a ``writeTo:``: its begin and end marks.

The runtime writes a length-delimited sub-message as ``PlaceMark(writer, &scratch, F)`` (the
begin mark: a stack scratch slot in x1, the field number F), the sub-message's own fields,
then ``RecallMark(writer, &scratch)`` (the end mark: the same slot, no field number).  The
writer flow (:mod:`proto.writer_flow`) records, at every call handed the writer, the marks open
on the paths into it (:attr:`WriteSite.open_marks`) and those open where the function is left.
A map entry (:mod:`proto.mapfields`: fields 1 and 2) and an inlined struct
(:mod:`proto.structfields`) are both read as the calls directly inside one begin mark
(:func:`submessage`).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Optional, Tuple

if TYPE_CHECKING:
    from proto.writer_flow import WriteSite, WriterCalls

#: The ProtocolBuffer runtime's begin and end marks
PLACE_MARK, RECALL_MARK = "_PBDataWriterPlaceMark", "_PBDataWriterRecallMark"

#: No length-delimited mark is open on any path into a call
NO_OPEN_MARK = frozenset({()})


@dataclass(frozen=True)
class Submessage:
    """What one ``begin(F) … end`` sub-message write contains: the calls made with that mark
    innermost on a path into them."""
    number: int                          # the field number the begin mark carries
    calls: Tuple["WriteSite", ...]       # every call inside but the marks
    writes: Tuple["WriteSite", ...]      # of those, the writer-in-x0 calls handed a field
                                         # number: members written inline
    callees: Tuple[int, ...]             # the others' targets: candidate struct serialisers
                                         # ``f(&struct, writer)``
    nested: bool                         # another sub-message begins inside it


def submessage(calls: "WriterCalls", begin: "WriteSite") -> Optional[Submessage]:
    """The sub-message whose begin mark is the call *begin* among *calls*, or None: *begin* is
    not a begin mark handed a frame scratch and a field number, no end mark closes it, a path
    leaves the function with it open, or an end mark inside it closes another."""
    if begin.name != PLACE_MARK or begin.writer_reg != 'x0' or begin.slot is None:
        return None
    number = begin.number
    if number is None or number < 1:
        return None
    mark = (begin.slot, begin.addr)
    if any(mark in stk for stk in calls.open_at_exit):
        return None
    inside = [t for t in calls.sites if any(stk and stk[-1] == mark for stk in t.open_marks)]
    ends = [t for t in inside if t.name == RECALL_MARK and t.writer_reg == 'x0'
            and t.slot == begin.slot]
    if not ends or any(t.name == RECALL_MARK and t not in ends for t in inside):
        return None
    others = tuple(t for t in inside if not t.is_mark)
    writes = tuple(t for t in others if t.writer_reg == 'x0' and t.number is not None
                   and t.target is not None)
    callees = tuple(dict.fromkeys(t.target for t in others
                                  if t not in writes and t.target is not None))
    return Submessage(number, others, writes, callees,
                      any(t.name == PLACE_MARK for t in inside))
