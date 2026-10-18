"""proto/dispatch -- the readFrom: anchors the dispatch evaluator (:mod:`proto.dispatch_eval`)
starts from:

* :func:`_find_readfrom_c_func` / :func:`_build_readfrom_core_index` -- the ReadAllFrom core
  each proto class's ``-readFrom:`` tail-calls, indexed by address (an element core a parent's
  handler calls names the element class);
* :func:`_jump_table_arm_addrs` -- decoded ``br`` jump tables, the CFG completion every
  :class:`proto.arm64_eval.Flow` user seeds its graph with;
* :func:`_find_field_count` -- the ``cmp wN,#N ; b.hi`` gate reader (enum diagnostics).

Top-level imports are macho.* and the proto-class set only (never proto.extractor); the
evaluator (:mod:`proto.arm64_eval`, :mod:`proto.dispatch_eval`, which imports this module) is
imported inside the functions that run it.
"""
from __future__ import annotations
import bisect
import logging
import struct
from typing import Dict, List, Optional

from macho.memory    import BinaryContext, _ctx_cache, _ctx_store
from macho.classlist import ObjcClass
from macho.disasm   import disasm, Insn, _norm_reg, _parse_imm
from macho.arm64decode import (_decode_bcond, _decode_cmp_imm, _COND_HI, _COND_HS,
                               range_from_unsigned_gate)
from proto.arm64cfg import dominators
from proto.arm64_operands import imm_operand, split_ops
from proto.protoclass_set import _proto_class_set

log = logging.getLogger(__name__)

# [cap:COSMETIC — verified] the readFrom: wrapper's call is in its first two instructions (x8 changed nothing).
_READFROM_MAX_INSNS = 12


def _find_readfrom_c_func(
    ctx: BinaryContext, cls: ObjcClass
) -> Optional[int]:
    """
    The C ReadFrom core ``-[Cls readFrom:]`` is a thin wrapper around, or None.

    The thin wrapper hands its object and its reader straight on::

        mov x1, x2              ; (mov w2, #0)
        b   _ClsReadFrom        ; or: bl _ClsReadFrom ... ret

    Decided by data flow, not by "the first branch": the wrapper (up to its first
    unconditional terminator) is run with x0 = self and x2 = the reader as opaque tokens
    (:mod:`proto.dispatch_eval`), and its first call must be handed both (x0 = self, x1 =
    reader).  So an inline reader -- ``-readFrom:`` holding the dispatch itself, whose first
    call retains the reader -- has no C core (a parent cannot ``bl`` one; it messages
    ``readFrom:``), and a ``-readFrom:`` that hands only the reader to a shared function
    (a field-less filter's skip-everything helper) has none either.
    """
    from proto.arm64_eval import Flow
    from proto.dispatch_eval import SELF, READER, _opaque
    method = cls.get_method("readFrom:")
    if method is None or method.imp == 0:
        return None

    try:
        insns = disasm(ctx, method.imp, max_insns=_READFROM_MAX_INSNS, stop_at_ret=False)
    except (NameError, ImportError):
        raise
    except Exception:
        return None
    end = next((k for k, i in enumerate(insns)
                if i.mnemonic in ('b', 'br', 'ret', 'retaa', 'retab', 'udf')), None)
    insns = insns[:end + 1] if end is not None else insns
    if not insns:
        return None
    region = Flow(ctx, insns).run_from(0, {'x0': SELF, 'x2': READER}, opaque=_opaque)
    if not region.calls:
        return None
    first = region.calls[0]
    if first.args.get('x0') == SELF and first.args.get('x1') == READER:
        return first.target
    return None


def _read_raw_word(ctx: BinaryContext, va: int) -> Optional[int]:
    """Read a 4-byte little-endian word at va, returning None on error."""
    try:
        raw = ctx.read_bytes(va, 4)
        return struct.unpack_from("<I", raw)[0]
    except (ValueError, struct.error):
        return None


def _find_field_count(ctx: BinaryContext, func_va: int) -> int:
    """
    Find the proto field count for a C ReadFrom function by scanning its raw
    instruction stream for the `cmp wN, #N ; b.hi/b.hs` dispatch gate.

    Returns 0 if the count cannot be determined.
    """
    MAX_SCAN = 256
    va = func_va
    for _ in range(MAX_SCAN):
        word = _read_raw_word(ctx, va)
        if word is None:
            break
        result = _decode_cmp_imm(word)
        if result is not None:
            _, imm = result
            next_word = _read_raw_word(ctx, va + 4)
            if next_word is not None:
                cond = _decode_bcond(next_word)
                if cond in (_COND_HS, _COND_HI):
                    return range_from_unsigned_gate(cond, imm)
        va += 4
    return 0


def _section_name(ctx: BinaryContext, va: int) -> Optional[str]:
    """Name of the section containing *va*, or ``None`` if unmapped."""
    for seg in ctx.segments:
        if seg.vmaddr <= va < seg.vmaddr + seg.vmsize:
            for sec in seg.sections:
                if sec.vmaddr <= va < sec.vmaddr + sec.vmsize:
                    return sec.name
            return None
    return None


def _index_bounds(flow, k: int):
    """``(start, register, values)`` when ``insns[k]`` bounds a register a jump table may be
    indexed by: a compare with an immediate (``cmp w8, #N`` ahead of the ``b.hi`` / ``b.hs`` /
    ``b.ls`` / ``b.lo`` that guards the table) -- evaluated from the compare itself with
    values 0 .. N+1, the gate deciding which reach the ``br`` -- or a low-bit mask (``and w8,
    w0, #2^k-1``), evaluated from just after it with every value the mask lets through.
    None for anything else."""
    from proto.arm64_eval import _MAX_GATE_SPAN
    ins = flow.insns[k]
    ops = split_ops(ins.op_str)
    if ins.mnemonic == 'cmp' and len(ops) in (2, 3) and ops[1].startswith('#'):
        n = imm_operand(ops, 1)
        r = _norm_reg(ops[0])
        if n is None or r is None or n > _MAX_GATE_SPAN:
            return None
        return k, r, n + 2
    if ins.mnemonic == 'and' and len(ops) == 3 and ops[2].startswith('#'):
        mask = _parse_imm(ops[2])
        r = _norm_reg(ops[0])
        if mask is None or r is None or mask <= 0 or mask & (mask + 1) or mask >= _MAX_GATE_SPAN:
            return None
        return k + 1, r, mask + 1
    return None


def _evaluated_arms(flow, idom, kb: int, lo: int, hi: int) -> set:
    """The targets the ``br`` at ``insns[kb]`` takes, by evaluation: from every index bound
    (:func:`_index_bounds`) in the code that dominates it, each value the bound lets through is
    run to the ``br`` (:meth:`proto.arm64_eval.Flow.value_at`) and its register read there.
    So the table's shape -- entry width and signedness, scaling, a bias or clamp of the index,
    the base -- is whatever the code computes, not a pattern."""
    reg = flow.insns[kb].op_str.strip()
    blk = flow._block_of[kb]
    arms: set = set()
    d = blk
    while True:
        first = flow._first_in_block[d]
        end = kb if d == blk else first + len(flow.cfg.blocks[d])
        for k in range(first, end):
            bound = _index_bounds(flow, k)
            if bound is None:
                continue
            start, r, count = bound
            for v in range(count):
                t = flow.value_at(start, {r: v}, kb, reg)
                if t is not None and lo <= t < hi:
                    arms.add(t)
        up = idom.get(d)
        if up is None or up == d:
            break
        d = up
    return arms


def _jump_table_arm_addrs(ctx: BinaryContext, insns: List["Insn"], per_br: bool = False):
    """Arm-target addresses of every ``br Xn`` jump table in *insns*, decided by evaluation
    (:func:`_evaluated_arms`): each value the index's bound lets through is run to the ``br``.
    That covers every compiler idiom alike -- an index table (``ldrb``/``ldrh`` entry scaled by
    the final ``add``'s shift), a difference table (signed ``ldrsw`` byte deltas from an
    ``adr`` anchor inside the dispatch), a mask-bounded index (``and w8, w0, #7`` on a wire
    type) -- with no look-back window.

    A GENERAL CFG-completion decoder: it recovers arm targets for any such ``br`` so a CFG
    (and :func:`proto.arm64cfg.dominators`) reaches the blocks behind it.  Without it a
    reader whose field dispatch shares its function with a control ``br`` ahead of the
    field-number extraction (e.g. GEOHours) has that extraction unreachable.  A ``br`` reached
    only through another table's arms (a segmented switch) is decoded once those arms are CFG
    edges; a ``br`` the entry never reaches is not decoded.
    Read-only; returns in-range arm addresses -- with *per_br*, as ``{br address: its arms}``.
    Memoised on *ctx* per instruction listing."""
    if ctx is None or not insns:
        return {} if per_br else set()
    from proto.arm64_eval import Flow
    ins = sorted(insns, key=lambda i: i.addr)
    key = tuple(i.addr for i in ins)
    memo = _ctx_cache(ctx, "_jump_table_arms", dict)
    by_br = memo.get(key)
    if by_br is None:
        by_br = {}
        lo, hi = ins[0].addr, ins[-1].addr + 4
        todo = {k for k, i in enumerate(ins) if i.mnemonic == 'br'}
        while todo:
            flow = Flow(ctx, ins, br_arms=by_br)
            idom = dominators(flow.cfg)
            reached = sorted(k for k in todo if flow._block_of.get(k) in idom)
            todo.difference_update(reached)
            new = False
            for kb in reached:
                arms = _evaluated_arms(flow, idom, kb, lo, hi)
                if arms:
                    by_br[ins[kb].addr] = frozenset(arms)
                    new = True
            if not new:
                break
        memo[key] = by_br
    if per_br:
        return {b: set(a) for b, a in by_br.items()}
    return set().union(*by_br.values())


def build_function_index(ctx: BinaryContext, cl: 'ClassList') -> None:
    """Record on *ctx* every method IMP of the image (``_function_entries``) and every ivar's
    offset-variable address (``_ivar_offset_slots``).  The readFrom: evaluator
    (:mod:`proto.dispatch_eval`) uses the IMPs, with the ReadAllFrom cores, as function
    boundaries and tail-call targets, and the slots to tell this class's ivars from others'.
    Built once per extraction; :func:`_build_readfrom_core_index` calls it."""
    entries = _ctx_cache(ctx, "_function_entries", set)
    ivar_slots = _ctx_cache(ctx, "_ivar_offset_slots", set)
    for cls in cl:
        entries.update(m.imp for m in cls.methods if m.imp)
        ivar_slots.update(iv.offset_slot for iv in cls.ivars if iv.offset_slot)


class FunctionEntries(list):
    """Sorted function-entry addresses with set membership (``members``) and the next entry
    after an address (:meth:`next_after`): a function ends where the next one starts, and a
    ``b`` to an entry is a tail call."""
    __slots__ = ("members",)

    def __init__(self, addrs=()):
        super().__init__(sorted(set(addrs)))
        self.members = frozenset(self)

    def next_after(self, va: int) -> Optional[int]:
        """The first entry above *va*, or None."""
        i = bisect.bisect_right(self, va)
        return self[i] if i < len(self) else None


def function_entries(ctx: BinaryContext) -> FunctionEntries:
    """The image's function index (:func:`build_function_index`) as :class:`FunctionEntries`,
    sorted once per extraction rather than by every caller (empty when the index is not built).
    Rebuilt if the index has grown since."""
    es = getattr(ctx, "_function_entries", None) or set()
    memo = getattr(ctx, "_function_entries_sorted", None)
    if memo is None or memo[0] is not es or memo[1] != len(es):
        memo = _ctx_store(ctx, "_function_entries_sorted", (es, len(es), FunctionEntries(es)))
    return memo[2]


def _build_readfrom_core_index(
    ctx: BinaryContext,
    cl: 'ClassList',
) -> Dict[int, str]:
    """
    Binary-wide pre-pass: map every proto class's ReadAllFrom C-core address to
    its class name — ``{ReadAllFrom_vmaddr: class_name}``.

    The ReadAllFrom core is the tail target of ``-[Cls readFrom:]`` (recovered by
    :func:`_find_readfrom_c_func`) — exactly the address a *parent* class's
    readFrom: dispatch handler calls on a new object when parsing an embedded ``<Cls>``
    element.  The dispatch evaluator (:mod:`proto.dispatch_eval`) names an element class
    **by that call target**, which works in cache-native mode where symbol names are
    stripped.  Also builds the function index (:func:`build_function_index`).

    One pass over the classlist, threaded through to every :func:`extract_proto_message`
    call.  Two classes sharing one core would make the index name only the first; none do
    (GeoServices: 1598 cores, all distinct).
    """
    index: Dict[int, str] = {}
    build_function_index(ctx, cl)
    proto_classes = _proto_class_set(ctx, cl)
    for cls in cl:
        if cls.is_meta or cls.name not in proto_classes:
            continue
        core = _find_readfrom_c_func(ctx, cls)
        if core is None:
            continue
        prev = index.get(core)
        if prev is None:
            index[core] = cls.name
        elif prev != cls.name:
            log.debug("readFrom core 0x%x maps to both %s and %s; keeping %s",
                      core, prev, cls.name, prev)
    return index
