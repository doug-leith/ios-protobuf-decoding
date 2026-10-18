"""proto/arm64cfg.py — shared arm64 control-flow / operand-parsing helpers.

Pure, serializer-agnostic primitives shared by the writeTo: field-number walk and the
evaluator (:mod:`proto.arm64_eval`): basic blocks, dominators, the lazy block walk, and
operand helpers.  They carry no writeTo: or readFrom: meaning and operate on decoded
``macho.disasm.Insn`` objects.  Imports only ``macho.*`` and :mod:`proto.arm64_operands`.
"""
import bisect
from collections import deque

from macho.disasm import find_adrp_add_target, _parse_imm, _norm_reg
from proto.arm64_operands import split_ops, parse_mem  # noqa: F401  (re-export)


TERMINALS = {'ret', 'retaa', 'retab', 'eret'}
CONDITIONALS = ('cbz', 'cbnz', 'tbz', 'tbnz')

# AArch64 callee-saved GPRs — the registers a serializer uses to hold a persistent
# ivar-offset-table base across the readAll:/lock calls.  The live base tracker in
# writeto_walk only adopts/updates bases in this set.
_CALLEE_SAVED = frozenset('x19 x20 x21 x22 x23 x24 x25 x26 x27 x28'.split())

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


def _resolve_offset_addr(pre, off, base_regs):
    """Address of the ivar-offset variable held in register *off*.  Follows the
    defining `ld* off,[base,#k]` and resolves *base* — preferring a LOCAL `adrp+add`
    or `adrp` in the window (so a callee-saved base reg reloaded mid-function uses
    its CURRENT value, not the stale prologue capture), falling back to base_regs.
    Covers direct (`adrp x8; ldrsw x8,[x8,#k]`) and indirect/base-reg forms, plus
    the PC-relative LITERAL form (`ldrsw x8, #ADDR`) the compiler emits in
    BINARY-MODE standalone images instead of the cache's `adrp+ldrsw[base,#k]`."""
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
        before = pre[:i]
        add_val = find_adrp_add_target(before, base)        # local adrp+add table base
        if add_val is not None:
            return add_val + imm
        page = _adrp_page(before, base)                     # local adrp scratch reg
        if page is not None:
            return page + imm
        if base in base_regs:                               # prologue base (far from use)
            return base_regs[base] + imm
        return None
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


def dominators(cfg):
    """Immediate-dominator map {block: idom} (Cooper-Harvey-Kennedy); entry→entry."""
    if cfg.entry is None:
        return {}
    visited, post = set(), []
    stack = [(cfg.entry, False)]
    while stack:
        n, done = stack.pop()
        if done:
            post.append(n); continue
        if n in visited:
            continue
        visited.add(n)
        stack.append((n, True))
        for s in cfg.succ.get(n, []):
            if s not in visited:
                stack.append((s, False))
    rpo = list(reversed(post))
    idx = {b: i for i, b in enumerate(rpo)}
    preds = {b: [] for b in cfg.order}
    for b in cfg.order:
        for s in cfg.succ.get(b, []):
            preds.setdefault(s, []).append(b)
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


# ══════════════════════════════════════════════════════════════════════════════
# Lazy/incremental worklist walk — the OTHER CFG-construction mode
# ══════════════════════════════════════════════════════════════════════════════
# build_blocks() above needs the complete instruction list for exactly one
# function, disassembled up front, and is safe exactly when that function is
# CONTIGUOUS (readFrom: dispatch cores are; proto.dispatch_eval._function_insns
# bounds one by the next function entry). writeTo: bodies are NOT: the compiler outlines some
# field-write blocks past OTHER functions' bodies (see proto/enums.py's
# _function_body_extent docstring), so there is no safe way to bound "the whole
# function" ahead of time. LazyWalk is the alternative this requires: it
# discovers and disassembles blocks ONE AT A TIME, only once a branch has
# already proven they are reachable, so it never reads past what it has
# structurally justified visiting.


class LazyWalk:
    """Generic lazy/incremental worklist driver for CFG-shaped walks over a
    possibly-non-contiguous function.

    Threads an opaque per-edge ``state`` payload (whatever the caller needs --
    e.g. writeto_walk threads a has-bit guard address, a container ivar-offset
    address, and live table-base registers) alongside each queued block
    address.  This class owns only the worklist / visited-address /
    known-leader bookkeeping; the caller supplies how to disassemble one block
    and drives its own per-instruction dispatch by pulling blocks with
    :meth:`next_block`.

    Three distinct ways an address can be queued, corresponding to three
    distinct real cases in a walk -- conflating them changes behavior:

    * :meth:`push` -- a genuine branch target (conditional branch, or an
      unconditional tail-call this class of walk chooses to follow).  Marks
      the address a known LEADER, so an in-progress linear scan that later
      wanders into it knows to stop and hand off rather than read through it
      as if it were ordinary fall-through.
    * :meth:`push_front` -- a fall-through hand-off: the address was ALREADY a
      known leader (that's why the in-progress scan stopped), so it is not
      re-marked; it is processed next, ahead of anything already queued, so
      the walk resumes immediately rather than after unrelated queued work.
    * :meth:`push_continue` -- the block's own disassembly ran out of budget
      before hitting a terminator or branch; the next address is ordinary
      linear continuation, not a branch target, so it must NOT be marked a
      leader (marking it would make a later scan wrongly treat plain
      fall-through as a block boundary).
    """

    def __init__(self, ctx, entry, disasm_block, initial_state=None, max_blocks=2000):
        self._ctx = ctx
        self._disasm_block = disasm_block
        self._work = deque([(entry, initial_state)])
        self.leaders = {entry}
        self.visited = set()
        self.max_blocks = max_blocks
        self.blocks_seen = 0
        self.truncated = False

    def push(self, addr, state):
        """Queue a genuine branch target; marks it a leader (see class docstring)."""
        self._work.append((addr, state))
        self.leaders.add(addr)

    def push_front(self, addr, state):
        """Queue a fall-through hand-off into an ALREADY-known leader, to be
        processed next (see class docstring)."""
        self._work.appendleft((addr, state))

    def push_continue(self, addr, state):
        """Queue plain linear continuation (ran out of per-block budget);
        does NOT mark a leader (see class docstring)."""
        self._work.append((addr, state))

    def is_visited(self, addr):
        return addr in self.visited

    def mark_visited(self, addr):
        self.visited.add(addr)

    def is_leader_handoff(self, addr, block_start):
        """True if *addr* (mid-block, i.e. not the block's own start) is a
        known leader -- some other path already proved it's a block boundary,
        so an in-progress linear scan must stop and hand off rather than read
        through it."""
        return addr != block_start and addr in self.leaders

    def next_block(self):
        """Pop the next unvisited block and disassemble it via the
        ``disasm_block(ctx, addr)`` callback supplied at construction.

        Returns ``(insns, addr, state)``, or ``None`` when the walk is
        exhausted or :attr:`max_blocks` was hit (check :attr:`truncated` to
        tell the two apart)."""
        while self._work:
            if self.blocks_seen >= self.max_blocks:
                self.truncated = True
                return None
            addr, state = self._work.popleft()
            if addr in self.visited:
                continue
            self.blocks_seen += 1
            insns = self._disasm_block(self._ctx, addr)
            if not insns:
                continue
            return insns, addr, state
        return None
