"""proto/writeto.py — writeTo: field-number extraction.

Recovers confirmed protobuf field numbers from a class's ``-[Cls writeTo:]`` serializer
body.  Imports only ``macho.*`` and the shared ``proto.*`` helpers (never
``proto.extractor``).

The bindings come from :class:`proto.writer_flow.WriterFlow`'s write sites -- every call
of ``writeTo:`` handed the writer, as its forward dataflow over the CFG leaves it: the
field number the call is handed and the ivars its value derives from
(:func:`_site_bindings`).  Its :class:`WriteBindings` hold the confirmed ``{ivar:
field_number}`` map and the per-ivar write-helper address (used downstream to tell
``repeated string`` from ``repeated message/bytes``).

The writer flow is built by the binary-wide ``writeTo:`` pre-pass
(:func:`proto.write_helpers._ensure_writeto_prepass`); a bare call with no pre-pass
(e.g. a direct unit test) binds nothing (no decode, fail-safe).

A map field written inside an ``enumerateKeysAndObjectsUsingBlock:`` block binds
nothing here (the number lives in the block's invoke function — 5 GeoServices ivars);
:mod:`proto.mapfields` recovers those from the block, and any it cannot degrade to a
flagged ivar-order estimate — fail-safe, never a confident error.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from macho.memory import BinaryContext
from macho.classlist import ObjcClass, ObjcIvar
from macho.disasm import _parse_imm
from proto.arm64cfg import split_ops
from proto.arm64_operands import writes
from proto.models import record_analysis_failure


# Instructions execution does not fall through: the straight-line run that ends at a call
# starts after the last of them (or after the previous call).
_NO_FALL_THROUGH = frozenset(('b', 'br', 'braa', 'brab', 'ret', 'retaa', 'retab', 'eret',
                              'brk', 'udf'))


def _run_definition(insns: List, idx: int, reg: str) -> Optional[int]:
    """Index of the instruction that defines *reg* (``xN`` / ``vN`` form) for ``insns[idx]``
    along the straight-line run ending there -- conditional branches fall through, a call
    (which clobbers the caller-saved registers) or an instruction that does not fall through
    ends the run -- or None when nothing in the run defines it."""
    for j in range(idx - 1, -1, -1):
        ins = insns[j]
        if ins.mnemonic in _NO_FALL_THROUGH:
            return None
        if reg in writes(ins):
            return j
    return None


def _immediate_in(insns: List, idx: int, reg: str) -> Optional[int]:
    """The immediate *reg* holds at ``insns[idx]`` when its definition in the run
    (:func:`_run_definition`) is a ``mov`` / ``movz`` of one into it; else None.  Only the
    move itself counts: a copy from another register (``mov x2, x21``) may carry a loop
    counter whose other definitions sit on a back edge this run does not see."""
    d = _run_definition(insns, idx, reg)
    if d is None or insns[d].mnemonic not in ('mov', 'movz'):
        return None
    ops = split_ops(insns[d].op_str)
    return _parse_imm(ops[1]) if len(ops) == 2 and ops[1].startswith('#') else None


def _writeto_field_number_before(insns: List, idx: int) -> Optional[int]:
    """The proto field number of the field-write call (``bl``, or tail-call ``b``) at
    ``insns[idx]``: the immediate w2 holds there -- or, for a float/double writer, whose
    value travels in v0 and number in w1, the immediate w1 holds when the run sets v0 -- by
    the definition reaching the call along its straight-line run (:func:`_immediate_in`).
    So epilogue restores hoisted between the number and a tail call, or argument set-up in
    any order, read the same.  A float/double writer takes no third argument, so an
    immediate in w2 means an integer writer.  Without an FP value a constant w1 is just an
    argument (``os_unfair_lock_lock_with_options(lock, 0x10000)``), not a field number; nor
    does a call ending the run count as setting v0 (it only clobbers it).  None when no
    such immediate reaches the call."""
    n = _immediate_in(insns, idx, 'x2')
    if n is None:
        v0 = _run_definition(insns, idx, 'v0')
        if v0 is not None and insns[v0].mnemonic not in ('bl', 'blr'):
            n = _immediate_in(insns, idx, 'x1')
    return n


# ════════════════════════════════════════════════════════════════════════════

# protobuf wire-format field-number range (spec): 1 .. 2^29-1.  Principled
# validity test on the `mov w2,#N` immediate (the wire spec, not a tuned cap).
_MAX_PROTO_FIELD_NUMBER = (1 << 29) - 1

# The field# a ProtocolBuffer write helper takes to mean "write the bare value, NO
# tag": every PB element writer opens with ``cmn w<field>,#1 ; b.eq <skip-tag>``.
# writeTo: passes it for each element of a PACKED repeated field, which it writes
# between a length-delimited begin-mark (``PBDataWriterPlaceMark``, carrying the real
# field#, wire type 2) and its recall-mark — so that no-tag call is the field's
# element writer, the one whose wire family (sint/fixed/plain) types the elements.
_NO_TAG_FIELD_NUMBER = -1


def _is_field_number(n) -> bool:
    return n is not None and 1 <= n <= _MAX_PROTO_FIELD_NUMBER


def _is_field_number(n) -> bool:
    return n is not None and 1 <= n <= _MAX_PROTO_FIELD_NUMBER


@dataclass
class WriteBindings:
    """What ``writeTo:`` binds for one class, per ivar name."""
    numbers: Dict[str, int] = field(default_factory=dict)    # the field number written
    helpers: Dict[str, int] = field(default_factory=dict)    # the write helper's VA
    # the binding write: {n, write_addr, bracket (a begin mark), elem_helper_vas}
    writes: Dict[str, dict] = field(default_factory=dict)
    zero_fields: Set[str] = field(default_factory=set)       # written with field# 0 only (#52)


# No length-delimited mark is open on any path into the call (WriteSite.open_marks).
_NO_OPEN_MARK = frozenset({()})


def _ivars_of(origins) -> Set[str]:
    return {o[1] for o in origins if isinstance(o, tuple) and o[0] == 'I'}


def _site_bindings(sites, field_ivars) -> WriteBindings:
    """Bindings from :class:`proto.writer_flow.WriteSite` records, in address order.

    A call outside every mark binds the one field ivar its value derives from to the field
    number it is handed (number 0: a #52 zero field).  A begin mark (PlaceMark) outside every
    mark binds the one field ivar the values written directly inside it derive from -- a
    packed list or an inline sub-message -- and its no-tag calls are the element writers
    (:data:`_NO_TAG_FIELD_NUMBER`).  Calls inside a mark write the element's own fields.  A
    value from more than one ivar binds nothing; the first call binding an ivar wins."""
    names = {iv.name for iv in field_ivars if iv.offset != 0 and iv.name}
    out = WriteBindings()
    zero: Set[str] = set()
    for s in sites:
        n = s.number
        if n is None or s.open_marks != _NO_OPEN_MARK:
            continue
        elem: List[int] = []
        if s.is_mark:
            if not _is_field_number(n):
                continue
            inner = [t for t in sites if not t.is_mark
                     and any(stk and stk[-1] == (s.slot, s.addr) for stk in t.open_marks)]
            ivs = set().union(*(_ivars_of(t.value_origins) for t in inner))
            for t in inner:
                if (t.number == _NO_TAG_FIELD_NUMBER and t.target is not None
                        and t.target not in elem):
                    elem.append(t.target)
        elif n == 0 or _is_field_number(n):
            ivs = _ivars_of(s.value_origins)
        else:
            continue
        if len(ivs) != 1:
            continue
        (name,) = ivs
        if name not in names:
            continue
        if n == 0:
            zero.add(name)
        elif name not in out.numbers:
            out.numbers[name] = n
            if s.target is not None:
                out.helpers[name] = s.target
            out.writes[name] = dict(n=n, write_addr=s.addr, bracket=s.is_mark,
                                    elem_helper_vas=elem)
    out.zero_fields = zero - set(out.numbers)
    return out


def _extract_writeto_field_numbers(
    ctx: BinaryContext,
    cls: ObjcClass,
    field_ivars: List[ObjcIvar],
) -> WriteBindings:
    """The ``writeTo:`` bindings of *cls* (:func:`_site_bindings` on the image's writer flow,
    ``ctx._writer_flow``).  Empty when the pre-pass has not built the flow (``ctx`` None, a
    direct unit test) or the flow does not decide the class -- the caller then falls back
    to its own flagged estimate."""
    wf = getattr(ctx, "_writer_flow", None)
    if wf is None:
        return WriteBindings()
    try:
        sites = wf.write_sites(cls)
    except (NameError, ImportError):
        raise                       # our own wiring bug — never mask it
    except Exception as exc:
        # Bad binary input → per-class fail-safe (flagged ivar-order estimate), reported.
        record_analysis_failure(ctx, getattr(cls, "name", "?"), "writeTo: flow",
                                f"{type(exc).__name__}: {exc}")
        return WriteBindings()
    return WriteBindings() if sites is None else _site_bindings(sites, field_ivars)


def writeto_sent_selectors(ctx: BinaryContext, cls: ObjcClass) -> Optional[frozenset]:
    """Every selector *cls*'s own ``writeTo:`` sends
    (:meth:`proto.writer_flow.WriterFlow.sent_selectors`), or None when that cannot be told:
    the body is not decoded, its fixpoint does not go through, it makes an indirect call, or
    the image's writer flow (built by the ``writeTo:`` pre-pass) is absent."""
    wf = getattr(ctx, "_writer_flow", None)
    if wf is None:
        return None
    try:
        return wf.sent_selectors(cls)
    except (NameError, ImportError):
        raise
    except Exception as exc:
        record_analysis_failure(ctx, cls.name, "writeTo: flow", f"{type(exc).__name__}: {exc}")
        return None
