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
from typing import Dict, List, Optional, Set, Tuple

from macho.memory import BinaryContext, PROGRAM_ERRORS
from macho.classlist import ObjcClass, ObjcIvar
from proto.models import record_analysis_failure
from proto.arm64_operands import CALLS


def field_number_at(flow, k: int) -> Optional[int]:
    """The proto field number the field-write call (``bl``, or tail-call ``b``) at
    ``flow.insns[k]`` is handed: the constant w2 holds there (:meth:`Flow.const_before`:
    exactly one constant definition reaches it over the listing's CFG) -- or, for a
    float/double writer, whose value travels in v0 and number in w1, the constant w1 holds
    when the one definition of v0 reaching the call is not a call (an FP argument set up for
    it; a call only clobbers v0).  A float/double writer takes no third argument, so a
    constant in w2 means an integer writer; without an FP value a constant w1 is just an
    argument (``os_unfair_lock_lock_with_options(lock, 0x10000)``).  None when no such
    constant reaches the call."""
    n = flow.const_before(k, 'x2')
    if n is None:
        defs = flow.defs_before(k, 'v0')
        if len(defs) == 1:
            (d,) = defs
            if d >= 0 and flow.insns[d].mnemonic not in CALLS:
                n = flow.const_before(k, 'x1')
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


@dataclass(frozen=True)
class BoundWrite:
    """The write call that binds an ivar: the field number it is handed, its address, whether
    it is a length-delimited begin mark (a packed list or an inline sub-message), and -- for
    a mark -- the no-tag element writers called directly inside it."""
    number: int
    addr: int
    bracket: bool = False
    elem_helper_vas: Tuple[int, ...] = ()


@dataclass
class WriteBindings:
    """What ``writeTo:`` binds for one class, per ivar name."""
    numbers: Dict[str, int] = field(default_factory=dict)    # the field number written
    helpers: Dict[str, int] = field(default_factory=dict)    # the write helper's VA
    writes: Dict[str, BoundWrite] = field(default_factory=dict)   # the binding write
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
            out.writes[name] = BoundWrite(n, s.addr, s.is_mark, tuple(elem))
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
    except PROGRAM_ERRORS:
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
    except PROGRAM_ERRORS:
        raise
    except Exception as exc:
        record_analysis_failure(ctx, cls.name, "writeTo: flow", f"{type(exc).__name__}: {exc}")
        return None
