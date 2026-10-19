"""proto/arm64cfg.py — shared arm64 control-flow / operand-parsing helpers.

Pure, serializer-agnostic primitives shared by the writeTo: field-number walk and the
evaluator (:mod:`proto.arm64_eval`): basic blocks, dominators, the lazy block walk, and
operand helpers.  They carry no writeTo: or readFrom: meaning and operate on decoded
``macho.disasm.Insn`` objects.  Imports only ``macho.*`` and :mod:`proto.arm64_operands`.
"""
import bisect
from collections import deque

from macho.disasm import _parse_imm, _norm_reg
from proto.arm64_operands import split_ops, parse_mem, writes  # noqa: F401  (re-export)


TERMINALS = {'ret', 'retaa', 'retab', 'eret'}
CONDITIONALS = ('cbz', 'cbnz', 'tbz', 'tbnz')


# [cap:INPUT-SANITY] 0x4000 — only used when an imp is the LAST method in the
# image (no successor to bound the scan); 16 KiB is a generous per-method span.
_LAST_METHOD_SPAN = 0x4000


def _is_cond(mn: str) -> bool:
    return mn in CONDITIONALS or mn.startswith('b.')


# ── Operand toolkit ───────────────────────────────────────────────────────────
# One place that turns capstone's operand TEXT into structured pieces, so the walk
# and binding code stop re-implementing ad-hoc `op_str.split(',')` parses (each of
# which only handled the forms it happened to need).



def dst_reg(op_str):
    """Normalised destination (first-operand) GPR, or None (SIMD/empty operand).
    The reg written by a `mov`/`add`/`ldr`/… — used for clobber detection."""
    ops = split_ops(op_str)
    return _norm_reg(ops[0]) if ops else None


def parse_adrp(op_str):
    """``adrp xR, #page`` -> (xR, page); None if malformed (reg or page unparsable)."""
    ops = split_ops(op_str)
    if len(ops) != 2:
        return None
    reg, page = _norm_reg(ops[0]), _parse_imm(ops[1])
    return (reg, page) if reg is not None and page is not None else None


def mem_operand(op_str):
    """Parse a load/store memory operand into (value, base, index, disp, shift):

        'rV, [Rbase, Rindex{, lsl #s}]'  -> (rV, Rbase, Rindex, 0,    s)
        'rV, [Rbase, #imm]'              -> (rV, Rbase, None,   imm,  0)
        'rV, [Rbase]'                    -> (rV, Rbase, None,   0,    0)

    ``value`` is the lowercased value register as-written (so d0/s0 survive
    _norm_reg, which only understands x/w GPRs); ``base``/``index`` are normalised
    to xN; ``disp``/``shift`` are ints.  Returns None if the second operand is not a
    ``[...]`` memory reference."""
    ops = split_ops(op_str)
    pm = parse_mem(ops[1]) if len(ops) >= 2 else None
    if pm is None:
        return None
    return ops[0], pm.base, pm.index, pm.disp, pm.shift


def ivar_slot_loads(insns):
    """``[(insn_index, slot_vmaddr)]`` for every ivar-offset-variable load in
    *insns*: ``adrp Xn,#page; … ldrsw Xm,[Xn,#off]`` where ``page+off`` is the
    slot holding a field's ivar byte offset.  ``insn_index`` is the ``ldrsw``.

    The ``adrp`` need not lie close to (or even before, within a window) its
    ``ldrsw`` — a compiler may hoist one page register across several loads — so
    the page map is function-wide.  Immediate/no-offset form only (a
    register-offset ``ldrsw`` is not a slot load)."""
    pages = {}
    out = []
    for i, ins in enumerate(insns):
        if ins.mnemonic == 'adrp':
            pa = parse_adrp(ins.op_str)
            if pa is not None:
                pages[pa[0]] = pa[1]
        elif ins.mnemonic == 'ldrsw':
            mo = mem_operand(ins.op_str)
            if mo is not None and mo[2] is None and mo[1] in pages:
                out.append((i, pages[mo[1]] + mo[3]))
    return out


def _parse_load(op_str):
    """Back-compat shim: (value, base, index|None) for a register/immediate-indexed
    load.  Thin wrapper over :func:`mem_operand` (kept for existing call sites and
    tests)."""
    m = mem_operand(op_str)
    return (m[0], m[1], m[2]) if m is not None else None


def _same_reg(a, b):
    """True if *a* and *b* name the same physical register, treating the w/x views
    of a GPR as equal (``w20`` == ``x20``) and matching SIMD regs (``d8``/``s8``,
    which _norm_reg leaves as None) by exact name."""
    na, nb = _norm_reg(a), _norm_reg(b)
    if na is not None and nb is not None:
        return na == nb
    return a == b


def _adrp_page(pre, reg):
    for ins in reversed(pre):
        if ins.mnemonic == 'adrp':
            pa = parse_adrp(ins.op_str)
            if pa is not None and pa[0] == reg:
                return pa[1]
    return None


def _value_before(pre, reg, entry):
    """Value of *reg* at the end of *pre*, from its NEAREST definition in *pre*: an ``adrp``
    gives its page, ``add reg, src, #imm`` the value of *src* there plus *imm*; any other
    definition is not a constant (None).  With no definition in *pre* the register holds its
    value on entry to *pre*: ``entry.get(reg)``."""
    for i in range(len(pre) - 1, -1, -1):
        ins = pre[i]
        if reg not in writes(ins):
            continue
        if ins.mnemonic == 'adrp':
            pa = parse_adrp(ins.op_str)
            return pa[1] if pa is not None and pa[0] == reg else None
        ops = split_ops(ins.op_str)
        if ins.mnemonic == 'add' and len(ops) == 3 and ops[2].startswith('#'):
            src = _norm_reg(ops[1])
            v = _value_before(pre[:i], src, entry) if src is not None else None
            return None if v is None else v + _parse_imm(ops[2])
        return None
    return entry.get(reg)


def _resolve_offset_addr(pre, off, base_regs):
    """Address of the ivar-offset variable held in register *off* at the end of the block
    prefix *pre*.  Follows the defining ``ld* off,[base,#k]`` and takes *base* from its
    NEAREST definition before the load (:func:`_value_before`: an ``adrp`` [+ ``add``] chain),
    so a register reused for another page later in the block resolves to its CURRENT value,
    not an earlier one; a base not defined by such a chain is the walk's tracked value
    (*base_regs*: a callee-saved table base set up in the prologue).  Also the PC-relative
    LITERAL form (``ldrsw x8, #ADDR``) a standalone image uses instead of the cache's
    ``adrp+ldrsw[base,#k]``."""
    for i in range(len(pre) - 1, -1, -1):
        ins = pre[i]
        if ins.mnemonic not in ('ldrsw', 'ldr', 'ldrsh', 'ldrh', 'ldrb', 'ldrsb'):
            continue
        m = mem_operand(ins.op_str)
        if m is None:
            # PC-relative literal load `ld* off, #ADDR` (no `[...]`): the immediate
            # IS the absolute address of the ivar-offset variable, so return it
            # directly — there is no base register to resolve.
            ops = split_ops(ins.op_str)
            if (len(ops) == 2 and _norm_reg(ops[0]) == off
                    and ops[1].startswith('#')):
                return _parse_imm(ops[1])
            continue
        if _norm_reg(m[0]) != off:
            continue
        base, imm = m[1], m[3]
        val = _value_before(pre[:i], base, base_regs)
        if val is None:
            val = base_regs.get(base)
        return None if val is None else val + imm
    return None


def _cond_target(ins):
    """Branch target of a conditional.  tbz/tbnz carry the test bit as the first
    immediate, so take the LAST immediate; cbz/b.cc have the target as the only
    immediate."""
    if ins.mnemonic in ('tbz', 'tbnz'):
        toks = [t for t in ins.op_str.replace(',', ' ').split() if t.startswith('#')]
        return _parse_imm(toks[-1]) if toks else None
    return _parse_imm(ins.op_str)


def _next_imp(imps_sorted, imp):
    i = bisect.bisect_right(imps_sorted, imp)
    return imps_sorted[i] if i < len(imps_sorted) else imp + _LAST_METHOD_SPAN


# ══════════════════════════════════════════════════════════════════════════════
# Basic-block CFG + dominators
# ══════════════════════════════════════════════════════════════════════════════
# Pure, serializer-agnostic: operate on a list of macho.disasm.Insn over one function
# (proto.arm64_eval.Flow builds on them).  The caller completes the CFG with decoded `br`
# jump-table arms (inject_arm_edges, or Flow's per-br arms) so blocks reached only through
# an indirect branch are reachable.


def _succ_addrs(ins, fallthrough, lo, hi):
    """Successor instruction-addresses of a block ending at *ins*. Out-of-[lo,hi)
    `b` targets (tail calls) are dropped; `bl`/`blr` are calls (fall through); `br`
    is indirect (arms injected separately)."""
    mn = ins.mnemonic
    if mn in TERMINALS:
        return []
    if mn in ('bl', 'blr'):
        return [fallthrough] if fallthrough is not None else []
    if mn == 'b':
        t = _parse_imm(ins.op_str)
        return [t] if (t is not None and lo <= t < hi) else []
    if mn == 'br':
        return []
    if _is_cond(mn):
        out = []
        t = _cond_target(ins)
        if t is not None and lo <= t < hi:
            out.append(t)
        if fallthrough is not None:
            out.append(fallthrough)
        return out
    return [fallthrough] if fallthrough is not None else []


def _is_block_end(ins):
    return ins.mnemonic in TERMINALS or ins.mnemonic in ('b', 'br') or _is_cond(ins.mnemonic)


class CFG:
    __slots__ = ('blocks', 'succ', 'addr_to_block', 'order', 'entry')

    def __init__(self, blocks, succ, addr_to_block, order):
        self.blocks = blocks
        self.succ = succ
        self.addr_to_block = addr_to_block
        self.order = order
        self.entry = order[0] if order else None


def build_blocks(insns, extra_leaders=()):
    """Partition a function's Insn list into basic blocks + successor edges.  *extra_leaders*
    (e.g. jump-table arm addresses) also start a block, so an edge to one enters at that
    instruction rather than at the start of the block that would otherwise contain it."""
    if not insns:
        return CFG({}, {}, {}, [])
    insns = sorted(insns, key=lambda i: i.addr)
    lo, hi = insns[0].addr, insns[-1].addr + 4
    by_addr = {i.addr: i for i in insns}
    nxt = {insns[k].addr: (insns[k + 1].addr if k + 1 < len(insns) else None)
           for k in range(len(insns))}
    leaders = {insns[0].addr} | {a for a in extra_leaders if a in by_addr}
    for ins in insns:
        if _is_block_end(ins):
            n = nxt[ins.addr]
            if n is not None:
                leaders.add(n)
            for s in _succ_addrs(ins, n, lo, hi):
                if s in by_addr:
                    leaders.add(s)
    order = sorted(leaders)
    blocks = {b: [] for b in order}
    addr_to_block = {}
    li = 0
    for ins in insns:
        while li + 1 < len(order) and ins.addr >= order[li + 1]:
            li += 1
        b = order[li]
        blocks[b].append(ins)
        addr_to_block[ins.addr] = b
    succ = {}
    for b in order:
        last = blocks[b][-1]
        sb = []
        for s in _succ_addrs(last, nxt[last.addr], lo, hi):
            blk = addr_to_block.get(s)
            if blk is not None and blk not in sb:
                sb.append(blk)
        succ[b] = sb
    return CFG(blocks, succ, addr_to_block, order)


def build_blocks_with_br_arms(insns, br_arms):
    """:func:`build_blocks` with each ``br``'s own jump-table arms (*br_arms*: ``{br address:
    its arms}``) as block leaders and, in address order, as that ``br``'s successors only."""
    cfg = build_blocks(insns, {a for arms in br_arms.values() for a in arms})
    for b in cfg.order:
        last = cfg.blocks[b][-1]
        if last.mnemonic == 'br':
            for a in sorted(br_arms.get(last.addr, ())):
                ab = cfg.addr_to_block.get(a)
                if ab is not None and ab not in cfg.succ[b]:
                    cfg.succ[b].append(ab)
    return cfg


def inject_arm_edges(cfg, arm_addrs):
    """Add edges from each `br` block to every arm block (by arm ADDRESS), completing
    the CFG so dominators() reaches jump-table handlers."""
    arm_blocks = sorted({cfg.addr_to_block.get(a) for a in arm_addrs} - {None})
    if not arm_blocks:
        return
    for b in cfg.order:
        body = cfg.blocks[b]
        if body and body[-1].mnemonic == 'br':
            for ab in arm_blocks:
                if ab not in cfg.succ[b]:
                    cfg.succ[b].append(ab)


def predecessors(cfg):
    """``{block: [its predecessors]}`` for every block of *cfg*."""
    preds = {b: [] for b in cfg.order}
    for b in cfg.order:
        for s in cfg.succ.get(b, []):
            preds.setdefault(s, []).append(b)
    return preds


def reverse_postorder(cfg):
    """The blocks reachable from ``cfg.entry``, in reverse postorder of a depth-first search."""
    if cfg.entry is None:
        return []
    post = []
    seen = {cfg.entry}
    stack = [(cfg.entry, iter(cfg.succ.get(cfg.entry, [])))]
    while stack:
        node, it = stack[-1]
        nxt = next((s for s in it if s not in seen), None)
        if nxt is None:
            post.append(node)
            stack.pop()
        else:
            seen.add(nxt)
            stack.append((nxt, iter(cfg.succ.get(nxt, []))))
    return list(reversed(post))


def dominators(cfg):
    """Immediate-dominator map {block: idom} (Cooper-Harvey-Kennedy); entry→entry."""
    if cfg.entry is None:
        return {}
    rpo = reverse_postorder(cfg)
    idx = {b: i for i, b in enumerate(rpo)}
    preds = predecessors(cfg)
    idom = {cfg.entry: cfg.entry}

    def inter(a, b):
        while a != b:
            while idx[a] > idx[b]:
                a = idom[a]
            while idx[b] > idx[a]:
                b = idom[b]
        return a

    changed = True
    while changed:
        changed = False
        for b in rpo:
            if b == cfg.entry:
                continue
            new = None
            for p in preds.get(b, []):
                if p in idom and p in idx:
                    new = p if new is None else inter(p, new)
            if new is not None and idom.get(b) != new:
                idom[b] = new
                changed = True
    return idom


def dominates(idom, a, b):
    """True if block *a* dominates block *b* (a == b, or a on b's idom chain)."""
    cur = b
    while True:
        if cur == a:
            return True
        n = idom.get(cur)
        if n is None or n == cur:
            return False
        cur = n
