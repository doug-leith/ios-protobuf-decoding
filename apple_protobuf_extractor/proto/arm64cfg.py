"""proto/arm64cfg.py — shared arm64 control-flow / operand-parsing helpers.

Pure, serializer-agnostic primitives shared by the evaluator (:mod:`proto.arm64_eval`),
the writer flow and the decoders: basic blocks, predecessors / reverse postorder,
dominators, and operand helpers.  They carry no writeTo: or readFrom: meaning and operate
on decoded ``macho.disasm.Insn`` objects.  Imports only ``macho.*`` and :mod:`proto.arm64_operands`.
"""

from macho.disasm import _parse_imm, _norm_reg
from proto.arm64_operands import split_ops, parse_mem
from proto.arm64_operands import (CALLS, INDIRECT_BRANCHES, RETURNS, TRAPS, branch_target,
                                  is_conditional)

# a block that ends here has no successor: a return, or a trap (brk / udf / hlt)
TERMINALS = RETURNS | TRAPS


# ── Operand toolkit ───────────────────────────────────────────────────────────
# Capstone's operand TEXT as structured pieces (register VALUES are the evaluator's,
# :class:`proto.arm64_eval.Flow`).


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


# ══════════════════════════════════════════════════════════════════════════════
# Basic-block CFG + dominators
# ══════════════════════════════════════════════════════════════════════════════
# Pure, serializer-agnostic: operate on a list of macho.disasm.Insn over one function
# (proto.arm64_eval.Flow builds on them).  The caller completes the CFG with decoded `br`
# jump-table arms (inject_arm_edges, or Flow's per-br arms) so blocks reached only through
# an indirect branch are reachable.


def _succ_addrs(ins, fallthrough, lo, hi):
    """Successor instruction-addresses of a block ending at *ins*. Out-of-[lo,hi)
    `b` targets (tail calls) are dropped; calls fall through; an indirect branch has none
    (a jump table's `br` arms are injected separately)."""
    mn = ins.mnemonic
    if mn in TERMINALS:
        return []
    if mn in CALLS:
        return [fallthrough] if fallthrough is not None else []
    if mn == 'b':
        t = branch_target(ins)
        return [t] if (t is not None and lo <= t < hi) else []
    if mn in INDIRECT_BRANCHES:
        return []
    if is_conditional(mn):
        out = []
        t = branch_target(ins)
        if t is not None and lo <= t < hi:
            out.append(t)
        if fallthrough is not None:
            out.append(fallthrough)
        return out
    return [fallthrough] if fallthrough is not None else []


def _is_block_end(ins):
    return (ins.mnemonic in TERMINALS or ins.mnemonic == 'b' or ins.mnemonic in INDIRECT_BRANCHES
            or is_conditional(ins.mnemonic))


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
