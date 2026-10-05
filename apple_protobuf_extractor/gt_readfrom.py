"""PoC oracle for TODO #42 — CFG/dominator readFrom dispatch resolver.

STATUS: SPENT — #42 LANDED 2026-06-13 (commit 3cfb3ef).  This file is kept as the
record of how the algorithm was validated, NOT as a live oracle.  Its approach is
now production: ``_dominance_field_of`` + ``_jump_table_arm_addrs`` in
``proto/dispatch.py``, engine in ``proto/arm64cfg.py``.  So the ~80 lines this
file shares with ``proto/dispatch.py`` are a COPY of production, not an
independent reimplementation of it — **diffing the two no longer proves
anything**, and the differential value described below is used up (pre-swap:
AGREE=400, DISAGREE=0; output byte-identical on all 3 artifacts).  Do not
"deduplicate" the overlap into a shared helper: that would be wrong if the file
were still independent and is pointless now that it is not.  Nothing imports this
module; ``proto/arm64cfg.py`` and the sibling ``macho_disasm`` tool's ``cfg.py`` cite it in
comments as the provenance of the validated CFG/dominator engine, which is why it
is still here.

Original purpose, for the record:
STANDALONE proof of concept: this script does NOT modify production code.  It
re-derives the readFrom field->handler routing independently of
``proto.dispatch`` (the linear compare-chain pass it is meant to replace), so the
two can be diffed before anything is swapped in.  See
``notes/TODO42_READFROM_CFG_RESOLVER_PLAN.md``.

The resolver is four structural moves over the reader core's basic-block CFG:
  1. build_blocks   — partition [func_va, func_end) into basic blocks + edges.
  2. dominators     — Cooper-Harvey-Kennedy iterative dominator tree.
  3. field_handlers — collect every `cmp Wf,#N; b.eq/ne` site -> field N's handler
                      block (NOT a fall-through spine: readers run a preamble before
                      the dispatch, and jump-table fan-out scatters the compares).
  4. attribute      — credit each element `bl` to the field whose handler block
                      DOMINATES it (exact, vs the address-range approximation; this
                      is what makes the two #39 guards unnecessary).

It uses capstone ``Insn`` objects (the production venv has capstone), so control
flow is read from mnemonics — clean, and avoids the native mini-decoder's `unk`.

Usage:
    ../venv/bin/python3 gt_readfrom.py --selftest          # synthetic, no cache
    ../venv/bin/python3 gt_readfrom.py <framework> <Class>  # live dump vs prod
    ../venv/bin/python3 gt_readfrom.py <framework> --all     # every proto class
"""
import sys
from types import SimpleNamespace
from typing import Dict, List, Optional, Set, Tuple

# ── read-only reuse (no production mutation) ──────────────────────────────────
try:
    from proto.arm64cfg import split_ops, _parse_imm
except Exception:                                   # pragma: no cover - selftest path
    split_ops = _parse_imm = None


# ══════════════════════════════════════════════════════════════════════════════
# Instruction classification (capstone mnemonics)
# ══════════════════════════════════════════════════════════════════════════════

_TERMINALS = ('ret', 'eret', 'brk')
_CALLS = ('bl', 'blr')


def _norm(reg: str) -> str:
    """Normalise a register token to its w-name ('x8'->'w8', 'w8'->'w8')."""
    reg = reg.strip()
    if reg and reg[0] in 'xX':
        return 'w' + reg[1:]
    return reg


def _imm_tokens(op_str: str) -> List[int]:
    out = []
    for t in op_str.replace(',', ' ').split():
        if t.startswith('#'):
            v = _imm(t)
            if v is not None:
                out.append(v)
    return out


def _imm(tok: str) -> Optional[int]:
    tok = tok.strip().lstrip('#')
    try:
        return int(tok, 16) if tok.lower().startswith('0x') else int(tok)
    except ValueError:
        return None


def _cond_tgt(ins) -> Optional[int]:
    """Target of a conditional/compare branch (tbz/tbnz: last imm; else only imm)."""
    if ins.mnemonic in ('tbz', 'tbnz'):
        t = _imm_tokens(ins.op_str)
        return t[-1] if t else None
    t = _imm_tokens(ins.op_str)
    return t[-1] if t else None


def _is_terminal(ins) -> bool:
    return ins.mnemonic in _TERMINALS


def successors(ins, fallthrough: Optional[int],
               lo: int, hi: int) -> List[int]:
    """Control-flow successor addresses of a block ending at *ins*.

    *fallthrough* is the addr of the next instruction (or None at end-of-func).
    Targets outside [lo,hi) (tail calls / out-of-func b) are dropped — they leave
    the function.  ``bl``/``blr`` are CALLS, not edges (they fall through)."""
    mn = ins.mnemonic
    if _is_terminal(ins):
        return []
    if mn in _CALLS:
        return [fallthrough] if fallthrough is not None else []
    if mn == 'b':                                   # unconditional
        t = _imm_tokens(ins.op_str)
        tgt = t[-1] if t else None
        return [tgt] if (tgt is not None and lo <= tgt < hi) else []
    if mn == 'br':                                  # indirect / jump table
        return []                                   # arms supplied separately (PoC: none)
    if mn.startswith('b.') or mn in ('cbz', 'cbnz', 'tbz', 'tbnz'):
        out = []
        tgt = _cond_tgt(ins)
        if tgt is not None and lo <= tgt < hi:
            out.append(tgt)
        if fallthrough is not None:
            out.append(fallthrough)
        return out
    # straight-line: fall through
    return [fallthrough] if fallthrough is not None else []


def _branch_or_terminal(ins) -> bool:
    mn = ins.mnemonic
    return (_is_terminal(ins) or mn == 'b' or mn == 'br'
            or mn.startswith('b.') or mn in ('cbz', 'cbnz', 'tbz', 'tbnz'))


# ══════════════════════════════════════════════════════════════════════════════
# 1. basic-block CFG
# ══════════════════════════════════════════════════════════════════════════════

class CFG:
    def __init__(self, blocks, succ, addr_to_block, insns_by_addr, order):
        self.blocks = blocks                # {block_entry_addr: [Insn,...]}
        self.succ = succ                    # {block_entry_addr: [block_entry_addr,...]}
        self.addr_to_block = addr_to_block  # {insn_addr: block_entry_addr}
        self.insns_by_addr = insns_by_addr  # {insn_addr: Insn}
        self.order = order                  # block entry addrs, ascending
        self.entry = order[0] if order else None


def build_blocks(insns: List) -> CFG:
    """Partition a function's instruction list into basic blocks + successor edges."""
    if not insns:
        return CFG({}, {}, {}, {}, [])
    insns = sorted(insns, key=lambda i: i.addr)
    lo, hi = insns[0].addr, insns[-1].addr + 4
    by_addr = {i.addr: i for i in insns}
    next_addr = {insns[k].addr: (insns[k + 1].addr if k + 1 < len(insns) else None)
                 for k in range(len(insns))}

    leaders: Set[int] = {insns[0].addr}
    for ins in insns:
        if _branch_or_terminal(ins):
            nxt = next_addr[ins.addr]
            if nxt is not None:
                leaders.add(nxt)                    # instr after a branch starts a block
            for s in successors(ins, nxt, lo, hi):  # explicit branch targets
                if s is not None and s in by_addr:
                    leaders.add(s)
    order = sorted(leaders)

    # assign each instruction to the most recent leader
    blocks: Dict[int, List] = {b: [] for b in order}
    addr_to_block: Dict[int, int] = {}
    cur = order[0]
    li = 0
    for ins in insns:
        while li + 1 < len(order) and ins.addr >= order[li + 1]:
            li += 1
        cur = order[li]
        blocks[cur].append(ins)
        addr_to_block[ins.addr] = cur

    succ: Dict[int, List[int]] = {}
    for b in order:
        body = blocks[b]
        last = body[-1]
        nxt = next_addr[last.addr]
        raw = successors(last, nxt, lo, hi)
        # map successor instruction-addr -> its block entry
        sb = []
        for s in raw:
            if s is None:
                continue
            blk = addr_to_block.get(s)
            if blk is not None and blk not in sb:
                sb.append(blk)
        succ[b] = sb
    return CFG(blocks, succ, addr_to_block, by_addr, order)


# ══════════════════════════════════════════════════════════════════════════════
# 2. dominators (Cooper-Harvey-Kennedy)
# ══════════════════════════════════════════════════════════════════════════════

def dominators(cfg: CFG) -> Dict[int, int]:
    """Return idom: {block -> immediate dominator block}; entry maps to itself."""
    if cfg.entry is None:
        return {}
    # reverse-postorder
    rpo: List[int] = []
    seen: Set[int] = set()

    def dfs(b):
        stack = [b]
        post = []
        local = set()
        while stack:
            n = stack.pop()
            if n in local:
                continue
            local.add(n)
            post.append(n)
            for s in cfg.succ.get(n, []):
                if s not in local:
                    stack.append(s)
        return post
    # iterative DFS postorder for correct RPO
    post_order: List[int] = []
    visited: Set[int] = set()
    stack = [(cfg.entry, False)]
    while stack:
        n, processed = stack.pop()
        if processed:
            post_order.append(n)
            continue
        if n in visited:
            continue
        visited.add(n)
        stack.append((n, True))
        for s in cfg.succ.get(n, []):
            if s not in visited:
                stack.append((s, False))
    rpo = list(reversed(post_order))
    rpo_index = {b: i for i, b in enumerate(rpo)}

    idom: Dict[int, Optional[int]] = {b: None for b in rpo}
    idom[cfg.entry] = cfg.entry
    # predecessors
    preds: Dict[int, List[int]] = {b: [] for b in cfg.order}
    for b in cfg.order:
        for s in cfg.succ.get(b, []):
            preds.setdefault(s, []).append(b)

    def intersect(a, b):
        while a != b:
            while rpo_index[a] > rpo_index[b]:
                a = idom[a]
            while rpo_index[b] > rpo_index[a]:
                b = idom[b]
        return a

    changed = True
    while changed:
        changed = False
        for b in rpo:
            if b == cfg.entry:
                continue
            new_idom = None
            for p in preds.get(b, []):
                if p not in rpo_index:
                    continue
                if idom[p] is None:
                    continue
                new_idom = p if new_idom is None else intersect(p, new_idom)
            if new_idom is not None and idom[b] != new_idom:
                idom[b] = new_idom
                changed = True
    return {b: d for b, d in idom.items() if d is not None}


def dominates(idom: Dict[int, int], a: int, b: int) -> bool:
    """True if block *a* dominates block *b* (a on b's idom chain, incl a==b)."""
    if a == b:
        return True
    cur = b
    while cur in idom and idom[cur] != cur:
        cur = idom[cur]
        if cur == a:
            return True
    return False


# ══════════════════════════════════════════════════════════════════════════════
# 3. field register + dispatch-core gate + spine
# ══════════════════════════════════════════════════════════════════════════════

def field_register(insns: List) -> Optional[str]:
    """Unique dest of ``lsr Wf, Wtag, #3`` (field# = tag>>3), else None.

    ONLY `lsr …,#3` — matching production's `_find_field_number_register`.  A `ubfx
    wd,ws,#3,#w` is a bit-FIELD extract (lsb 3), NOT tag>>3; counting it added a
    spurious second candidate and falsely made the field reg "ambiguous" (e.g.
    GEOPDFeatureBuilding: real `lsr x22,x8,#3` + an unrelated `ubfx …,#3` → None)."""
    dests: Set[str] = set()
    for ins in insns:
        if ins.mnemonic == 'lsr':
            ops = [o.strip() for o in ins.op_str.split(',')]
            if len(ops) == 3 and _imm(ops[2]) == 3:
                dests.add(_norm(ops[0]))
    return next(iter(dests)) if len(dests) == 1 else None


def _cmp_on(ins, field_reg: str) -> Optional[int]:
    """If *ins* is ``cmp/subs <field_reg>, #N`` return N, else None."""
    if ins.mnemonic not in ('cmp', 'subs'):
        return None
    ops = [o.strip() for o in ins.op_str.split(',')]
    if len(ops) >= 2 and _norm(ops[0]) == field_reg and ops[1].startswith('#'):
        return _imm(ops[1])
    return None


def is_dispatch_core(cfg: CFG, field_reg: Optional[str]) -> bool:
    """A reader core extracts Wf=tag>>3 AND branches on Wf (excludes accessors)."""
    if field_reg is None:
        return False
    for b in cfg.order:
        body = cfg.blocks[b]
        for k, ins in enumerate(body):
            if _cmp_on(ins, field_reg) is not None:
                # followed by a conditional branch within the block tail
                for j in range(k + 1, min(k + 3, len(body))):
                    if body[j].mnemonic.startswith('b.'):
                        return True
    return False


def field_handlers(cfg: CFG, field_reg: str) -> Dict[int, int]:
    """Collect every ``cmp Wf,#N ; b.eq/ne`` site in the function and map field N to
    its HANDLER block (``b.eq`` → branch target; ``b.ne`` → fall-through), regardless
    of where in the function it sits.

    This is intentionally NOT a fall-through "spine" walk: real readers run a
    preamble (read tag, bounds checks) before the field dispatch, and the compares
    are not always a single contiguous chain (jump-table fan-out lands several
    compares in parallel blocks).  Collecting all of them — then attributing element
    calls by DOMINANCE (``attribute_calls``) — is what makes the address-range
    approximation and its two guards unnecessary: each field owns exactly the blocks
    its match edge dominates, so a neighbour (or a stray ``cmp Wf,#K`` sentinel) can
    never swallow another field's calls.  Only the field reg is compared, so a
    sentinel on a DIFFERENT register is excluded for free."""
    field_match: Dict[int, int] = {}
    for b in cfg.order:
        body = cfg.blocks[b]
        for k, ins in enumerate(body):
            n = _cmp_on(ins, field_reg)
            if n is None:
                continue
            for j in range(k + 1, min(k + 3, len(body))):
                bm = body[j].mnemonic
                if bm in ('b.eq', 'b.ne'):
                    tgt = _cond_tgt(body[j])
                    tgt_blk = cfg.addr_to_block.get(tgt)
                    ft_blk = _fallthrough_block(cfg, b)
                    handler = tgt_blk if bm == 'b.eq' else ft_blk
                    if handler is not None:
                        field_match.setdefault(n, handler)   # first compare wins
                    break
    return field_match


def _fallthrough_block(cfg: CFG, block: int) -> Optional[int]:
    """Block entry immediately following *block* in address order."""
    try:
        i = cfg.order.index(block)
    except ValueError:
        return None
    return cfg.order[i + 1] if i + 1 < len(cfg.order) else None


# ══════════════════════════════════════════════════════════════════════════════
# 4. dominator-based element-bl attribution
# ══════════════════════════════════════════════════════════════════════════════

def attribute_calls(cfg: CFG, idom: Dict[int, int], field_match: Dict[int, int],
                    call_addrs: List[int]) -> Dict[int, List[int]]:
    """{field# -> [call_addr,...]}: each call credited to the field whose handler
    block dominates it (the DEEPEST such handler when several apply)."""
    out: Dict[int, List[int]] = {}
    # block -> field# for handler blocks
    for a in sorted(call_addrs):
        blk = cfg.addr_to_block.get(a)
        if blk is None:
            continue
        best_field = None
        best_depth = -1
        for fn, hblk in field_match.items():
            if dominates(idom, hblk, blk):
                d = _dom_depth(idom, hblk)
                if d > best_depth:
                    best_depth, best_field = d, fn
        if best_field is not None:
            out.setdefault(best_field, []).append(a)
    return out


def _dom_depth(idom: Dict[int, int], b: int) -> int:
    d = 0
    cur = b
    while cur in idom and idom[cur] != cur:
        cur = idom[cur]
        d += 1
    return d


def _jumptable_arms(ctx, core_va):
    """{field# -> arm_va} for a ReadSpecified/inline jump-table core, via the
    production arm decoder (validation-driven; reused read-only), else None."""
    if ctx is None or core_va is None:
        return None
    try:
        from proto.dispatch import _decode_readfrom_jumptable, _find_field_count
        fc = _find_field_count(ctx, core_va)
        return _decode_readfrom_jumptable(ctx, core_va, fc if fc else 256)
    except Exception:
        return None


def _inject_arm_edges(cfg: CFG, arm_addrs) -> None:
    """Add CFG edges from each `br` block to every arm block (by arm ADDRESS), so the
    dominator tree reaches jump-table handlers (build_blocks leaves `br` edgeless)."""
    arm_blocks = {cfg.addr_to_block.get(a) for a in arm_addrs}
    arm_blocks.discard(None)
    if not arm_blocks:
        return
    for b in cfg.order:
        body = cfg.blocks[b]
        if body and body[-1].mnemonic == 'br':
            for ab in sorted(arm_blocks):
                if ab not in cfg.succ[b]:
                    cfg.succ[b].append(ab)


def _inject_jumptable_edges(cfg: CFG, arms: Dict[int, int]) -> None:
    """Arm-block edges from a {field#: arm_va} map (proto-field jump table)."""
    _inject_arm_edges(cfg, arms.values())


def _norm_w(r: str) -> str:
    r = r.strip()
    return 'w' + r[1:] if r and r[0] in 'xX' else r


def _jump_table_arms_general(ctx, insns) -> set:
    """Arm-target addresses of EVERY `br Xn` jump table built by the compiler idiom
    ``adr xT,#base; ldrb/ldrh wK,[xtable,widx]; add xT,xT,wK,lsl#s; br xT``.

    This is a GENERAL CFG-completion decoder (not the proto-field-specific
    `_decode_readfrom_jumptable`): it recovers arm targets for any such `br` so
    `dominators()` can reach jump-table handler blocks.  Without it, a reader whose
    field dispatch is a compare chain SHARING the function with a `br` control table
    (e.g. GEOHours: specified-list dispatch + a cmp-chain for the real fields) leaves
    most blocks unreachable → dominance returns None → the swap regresses.  Read-only;
    returns a set of in-range arm addresses."""
    if ctx is None or not insns:
        return set()
    try:
        from macho.disasm import find_adrp_add_target
    except Exception:
        return set()
    ins = sorted(insns, key=lambda i: i.addr)
    lo, hi = ins[0].addr, ins[-1].addr + 4
    arms: set = set()
    for k, br in enumerate(ins):
        if br.mnemonic != 'br':
            continue
        reg = br.op_str.strip()
        win = ins[max(0, k - 24):k]
        # add xT, xT, wK, lsl/sxtw/uxtw #s   (dest == br reg)
        scale = kreg = None
        for w in reversed(win):
            if w.mnemonic == 'add':
                o = [t.strip() for t in w.op_str.split(',')]
                if len(o) == 4 and o[0] == reg and any(s in o[3] for s in ('lsl', 'sxtw', 'uxtw')):
                    try:
                        scale = 1 << int(o[3].split('#')[1])
                    except Exception:
                        scale = 4
                    kreg = o[2]
                    break
        if kreg is None:
            continue
        # adr xT, #arm_base   (dest == br reg)
        arm_base = None
        for w in reversed(win):
            if w.mnemonic == 'adr':
                o = [t.strip() for t in w.op_str.split(',')]
                if len(o) == 2 and o[0] == reg:
                    arm_base = _imm(o[1])
                    break
        if arm_base is None:
            continue
        # ldrb/ldrh wK, [xtable, widx]
        kre = _norm_w(kreg)
        table_reg = idx_reg = width = None
        for w in reversed(win):
            if w.mnemonic in ('ldrb', 'ldrh'):
                parts2 = w.op_str.split(',', 1)
                if len(parts2) != 2 or _norm_w(parts2[0]) != kre:
                    continue
                mem = parts2[1].strip()
                if '[' not in mem or ']' not in mem:
                    continue
                inner = [p.strip() for p in mem[mem.index('[') + 1:mem.rindex(']')].split(',')]
                table_reg = inner[0]
                idx_reg = inner[1] if len(inner) > 1 else None
                width = 1 if w.mnemonic == 'ldrb' else 2
                break
        if table_reg is None:
            continue
        table_va = find_adrp_add_target(win, table_reg)
        if table_va is None:
            continue
        # entry count: cmp on the index reg + b.hi(=N+1)/b.hs(=N)
        count = None
        idxn = _norm_w(idx_reg) if idx_reg else None
        for j in range(len(win) - 1, -1, -1):
            w = win[j]
            if w.mnemonic in ('cmp', 'subs'):
                o = [t.strip() for t in w.op_str.split(',')]
                if len(o) >= 2 and o[1].startswith('#') and (idxn is None or _norm_w(o[0]) == idxn):
                    n = _imm(o[1])
                    if n is None:
                        continue
                    nb = win[j + 1].mnemonic if j + 1 < len(win) else ''
                    count = n if nb == 'b.hs' else n + 1
                    break
        if not count or count <= 0 or count > 4096:
            continue
        try:
            raw = ctx.read_bytes(table_va, count * width)
        except Exception:
            continue
        for v in range(count):
            ent = int.from_bytes(raw[v * width:(v + 1) * width], 'little')
            arm = arm_base + ent * scale
            if lo <= arm < hi:
                arms.add(arm)
    return arms


def resolve(insns: List, call_addrs: List[int],
            ctx=None, core_va=None, arms=None) -> Tuple[Optional[str], Dict[int, List[int]], bool]:
    """Full PoC resolve: (field_reg, {field#->[call addrs]}, is_core).

    Handles BOTH dispatch shapes: compare-chain (`field_handlers` + dominance) and
    jump-table (arms = {field#: arm_va}, inject br→arm edges, then the same dominance
    attribution).  *arms* may be supplied by the caller (production's
    `_locate_dispatch_arms`, the principled core-locator); when None and ctx+core_va
    are given, self-decode via the production jump-table decoder."""
    cfg = build_blocks(insns)
    # CFG COMPLETION (always): inject every `br` jump-table's arm edges via the GENERAL
    # decoder so dominators() reaches blocks only reachable through an indirect dispatch.
    # This is control-flow only — it covers ALL `br` tables (proto-field AND control), so
    # no separate proto-arm edge injection is needed (mixing in production's proto-field
    # arm ADDRESSES as extra edges previously broke dominance for compare-chain fields).
    _inject_arm_edges(cfg, _jump_table_arms_general(ctx, insns))
    fr = field_register(insns)
    core = is_dispatch_core(cfg, fr) or bool(arms)
    if not core:
        return fr, {}, False
    fm: Dict[int, int] = field_handlers(cfg, fr) if fr else {}
    # When the caller KNOWS this is a proto-field jump table (arms passed), each arm is
    # that field's handler block — add those mappings (field_handlers only finds compare
    # chains).  Edges are already present from the general completion above.
    if arms:
        for f, arm_va in arms.items():
            blk = cfg.addr_to_block.get(arm_va)
            if blk is not None:
                fm.setdefault(f, blk)
    idom = dominators(cfg)
    attr = attribute_calls(cfg, idom, fm, call_addrs)
    return fr, attr, True


# ══════════════════════════════════════════════════════════════════════════════
# Self-test (synthetic, no cache) — proves spine + dominance independently
# ══════════════════════════════════════════════════════════════════════════════

def _ins(addr, mn, op=''):
    return SimpleNamespace(addr=addr, mnemonic=mn, op_str=op)


def _selftest() -> int:
    fails = []

    def check(cond, msg):
        if not cond:
            fails.append(msg)

    # ── Case 1: forward-branch handlers (the GEOPDExternalAction shape) ───────
    # 0x00 lsr w8, w9, #3
    # 0x04 cmp w8, #1
    # 0x08 b.eq 0x20            (field 1 handler forward)
    # 0x0c cmp w8, #2
    # 0x10 b.eq 0x30            (field 2 handler forward)
    # 0x14 b 0x40               (default)
    # 0x20 bl FIELD1_ELEM ; b 0x40
    # 0x30 bl FIELD2_ELEM ; b 0x40
    # 0x40 ret
    base = 0x1000
    A = [
        _ins(base + 0x00, 'lsr', 'w8, w9, #3'),
        _ins(base + 0x04, 'cmp', 'w8, #1'),
        _ins(base + 0x08, 'b.eq', f'#{base + 0x20}'),
        _ins(base + 0x0c, 'cmp', 'w8, #2'),
        _ins(base + 0x10, 'b.eq', f'#{base + 0x30}'),
        _ins(base + 0x14, 'b',    f'#{base + 0x40}'),
        _ins(base + 0x20, 'bl',   '#0xAAAA'),
        _ins(base + 0x24, 'b',    f'#{base + 0x40}'),
        _ins(base + 0x30, 'bl',   '#0xBBBB'),
        _ins(base + 0x34, 'b',    f'#{base + 0x40}'),
        _ins(base + 0x40, 'ret',  ''),
    ]
    fr, attr, core = resolve(A, [base + 0x20, base + 0x30])
    check(fr == 'w8', f'C1 field_reg expected w8 got {fr}')
    check(core, 'C1 should be a dispatch core')
    check(attr.get(1) == [base + 0x20], f'C1 field1 attr wrong: {attr.get(1)}')
    check(attr.get(2) == [base + 0x30], f'C1 field2 attr wrong: {attr.get(2)}')

    # ── Case 2: stray sentinel must NOT swallow everything (degenerate-partition) ─
    # A trailing `cmp w8,#1000; b.eq` AFTER the real chain ends must not capture
    # the real handlers' calls.  Real chain: field 1 (eq->0x20). Then a sentinel.
    base = 0x2000
    B = [
        _ins(base + 0x00, 'lsr', 'w8, w9, #3'),
        _ins(base + 0x04, 'cmp', 'w8, #1'),
        _ins(base + 0x08, 'b.eq', f'#{base + 0x20}'),
        _ins(base + 0x0c, 'b',    f'#{base + 0x40}'),   # else -> default (no more field cmps)
        _ins(base + 0x20, 'bl',   '#0xAAAA'),           # field1 handler
        _ins(base + 0x24, 'b',    f'#{base + 0x40}'),
        _ins(base + 0x40, 'cmp',  'w8, #1000'),          # stray sentinel block
        _ins(base + 0x44, 'b.eq', f'#{base + 0x50}'),
        _ins(base + 0x48, 'ret',  ''),
        _ins(base + 0x50, 'bl',   '#0xCCCC'),            # sentinel handler (NOT field 1)
        _ins(base + 0x54, 'ret',  ''),
    ]
    fr, attr, core = resolve(B, [base + 0x20, base + 0x50])
    check(attr.get(1) == [base + 0x20], f'C2 field1 should own only its own bl: {attr.get(1)}')
    check(base + 0x50 not in attr.get(1, []), 'C2 sentinel bl must NOT be credited to field 1')

    # ── Case 3: accessor (no tag>>3) is not a core ───────────────────────────
    base = 0x3000
    C = [
        _ins(base + 0x00, 'stp', 'x29, x30, [sp, #-16]!'),
        _ins(base + 0x04, 'bl',  '#0xDDDD'),
        _ins(base + 0x08, 'ret', ''),
    ]
    fr, attr, core = resolve(C, [base + 0x04])
    check(not core, 'C3 accessor must NOT be classified a dispatch core')

    # ── Case 4: b.ne handler is the fall-through ──────────────────────────────
    # cmp w8,#5; b.ne 0x20 (skip); fall-through 0x0c = field5 handler; 0x20 next
    base = 0x4000
    D = [
        _ins(base + 0x00, 'lsr', 'w8, w9, #3'),
        _ins(base + 0x04, 'cmp', 'w8, #5'),
        _ins(base + 0x08, 'b.ne', f'#{base + 0x20}'),
        _ins(base + 0x0c, 'bl',   '#0xEEEE'),            # field5 handler (fall-through)
        _ins(base + 0x10, 'b',    f'#{base + 0x40}'),
        _ins(base + 0x20, 'cmp',  'w8, #6'),
        _ins(base + 0x24, 'b.ne', f'#{base + 0x40}'),
        _ins(base + 0x28, 'bl',   '#0xFFFF'),            # field6 handler
        _ins(base + 0x2c, 'b',    f'#{base + 0x40}'),
        _ins(base + 0x40, 'ret',  ''),
    ]
    fr, attr, core = resolve(D, [base + 0x0c, base + 0x28])
    check(attr.get(5) == [base + 0x0c], f'C4 field5 (b.ne fall-through) wrong: {attr.get(5)}')
    check(attr.get(6) == [base + 0x28], f'C4 field6 wrong: {attr.get(6)}')

    if fails:
        print("SELFTEST FAILED:")
        for f in fails:
            print("  -", f)
        return 1
    print("SELFTEST OK (4 cases: forward-branch, sentinel-isolation, accessor-reject, b.ne)")
    return 0


# ══════════════════════════════════════════════════════════════════════════════
# Live: run the PoC over real reader cores and diff against production
# ══════════════════════════════════════════════════════════════════════════════

def _bl_target(ins):
    t = _imm_tokens(ins.op_str)
    return t[-1] if t else None


def _element_calls(insns, core_index):
    """Addrs of bls that are ELEMENT calls — target is another class's ReadAllFrom
    core (so it carries an element message TYPE).  Excludes the shared runtime
    helpers (skip-unknown-field, release, cleanup) that carry no type and only
    manufacture spurious diffs.  Returns {bl_addr: element_type_name}."""
    out = {}
    for i in insns:
        if i.mnemonic == 'bl':
            t = _bl_target(i)
            if t is not None and t in core_index:
                out[i.addr] = core_index[t]
    return out


def _types_by_field(attr, addr_to_type):
    """Map {field# -> [bl addr]} to {field# -> sorted set(element type)}."""
    out = {}
    for fn, addrs in attr.items():
        ts = sorted({addr_to_type[a] for a in addrs if a in addr_to_type})
        if ts:
            out[fn] = ts
    return out


def _dump_class(ctx, cls, core_index):
    """PoC element-type bindings {field# -> [types]} for *cls*, using PRODUCTION's
    principled core-locator (`_locate_dispatch_arms`) for the core entry.

    Scope of the #42 contribution = COMPARE-CHAIN cores only: there the element `bl`s
    sit IN the core and dominance attribution replaces production's address-range
    approximation.  JUMP-TABLE cores (arms set) are deferred — production already
    resolves them principally (`_decode_readfrom_jumptable` arms + `_walk_jumptable_arms`
    follow each arm into its per-field handler's element `bl`, which is one level below
    the core, out of reach of in-core dominance).  Returns jt=True / poc=None for those."""
    from proto.dispatch import _locate_dispatch_arms, _func_end
    from macho.disasm import disasm
    arms, core, _readfrom_va = _locate_dispatch_arms(ctx, cls, core_index)
    if core is None:
        return None
    if arms:                                          # jump-table: production-principled
        return dict(core=core, jt=True, poc=None)
    end = _func_end(ctx, core)
    if end is None or end <= core:
        return None
    insns = [i for i in disasm(ctx, core, max_insns=max(1, (end - core) // 4),
                               stop_at_ret=False) if core <= i.addr < end]
    elem = _element_calls(insns, core_index)         # {addr: type}; in-core element calls
    calls = sorted(elem)
    _, poc, _is_core = resolve(insns, calls, ctx=ctx, core_va=core, arms=None)
    return dict(core=core, jt=False, poc=_types_by_field(poc, elem))


def _cmp_maps(poc, prod):
    """Classify each field: AGREE / POC_ONLY / PROD_ONLY / DISAGREE on element types."""
    agree = poc_only = prod_only = disagree = 0
    detail = []
    for f in sorted(set(poc) | set(prod)):
        p, q = set(poc.get(f, [])), set(prod.get(f, []))
        if p == q and p:
            agree += 1
        elif p and not q:
            poc_only += 1; detail.append(('POC_ONLY', f, sorted(p)))
        elif q and not p:
            prod_only += 1; detail.append(('PROD_ONLY', f, sorted(q)))
        else:
            disagree += 1; detail.append(('DISAGREE', f, sorted(p), sorted(q)))
    return agree, poc_only, prod_only, disagree, detail


def _prod_element_types(ctx, st, cl, core_index):
    """Production's REAL emitted element types: {class: {field#: set(msg type)}} from
    extract_all (the shipped output — the faithful comparison target)."""
    import proto.extractor as E
    msgtypes = set(core_index.values())
    prod = {}
    for m in E.extract_all(ctx, st, cl):
        d = {}
        for fld in m.fields:
            if fld.type_name in msgtypes:
                d.setdefault(fld.number, set()).add(fld.type_name)
        if d:
            prod[m.class_name] = d
    return prod


def _run_live(fw, target):
    from gt_fields import load
    from proto.protoclass_heuristic import _is_proto_class
    from proto.dispatch import _build_readfrom_core_index
    ctx, st, cl = load(fw)
    core_index = _build_readfrom_core_index(ctx, cl)
    prod_all = _prod_element_types(ctx, st, cl, core_index)
    classes = [c for c in cl if not c.is_meta and _is_proto_class(c)
               and c.get_method('readFrom:') is not None]
    if target and target != '--all':
        classes = [c for c in classes if c.name == target]
        if not classes:
            print(f"{target}: not found / no readFrom:"); return 1
    tA = tP = tQ = tD = 0
    jt_classes = jt_fields = cc_classes = 0
    for c in classes:
        r = _dump_class(ctx, c, core_index)
        prod = {k: sorted(v) for k, v in prod_all.get(c.name, {}).items()}
        if r is not None and r['jt']:                 # jump-table: deferred (production-principled)
            if prod:
                jt_classes += 1; jt_fields += len(prod)
            continue
        poc = r['poc'] if r else {}
        if not poc and not prod:
            continue
        cc_classes += 1
        a, po, pq, d, detail = _cmp_maps(poc, prod)
        tA += a; tP += po; tQ += pq; tD += d
        if target or po or pq or d:
            core = f"0x{r['core']:x}" if r else "NONE(uncloated)"
            print(f"[{c.name}] core={core} agree={a} poc_only={po} "
                  f"prod_only={pq} disagree={d}")
            for row in detail:
                print("     ", row)
    print(f"\n== {fw}: COMPARE-CHAIN classes (the #42 scope): {cc_classes}; "
          f"AGREE={tA} POC_ONLY={tP} PROD_ONLY={tQ} DISAGREE={tD} element-type fields.")
    print(f"   JUMP-TABLE classes deferred (production-principled): {jt_classes} "
          f"({jt_fields} element fields). ==")
    return 0


def main() -> int:
    if '--selftest' in sys.argv:
        return _selftest()
    args = [a for a in sys.argv[1:] if a != '--selftest']
    if not args:
        print(__doc__)
        return 0
    fw = args[0]
    target = args[1] if len(args) > 1 else '--all'
    return _run_live(fw, target)


if __name__ == '__main__':
    sys.exit(main())
