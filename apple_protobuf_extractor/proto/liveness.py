"""proto/liveness.py -- the registers a call may read (:func:`call_reads`).

A runtime function's ABI contract, a named Swift function the Swift convention's, any other named
or unknown callee the AAPCS64 arguments (:mod:`proto.callees`); an unnamed function of the image
the registers it reads before writing them: a backward liveness fixpoint over its CFG
(:func:`_live_in`), whose calls read what their callees read -- so the functions of a call cycle
are solved together, as a least fixpoint.  Jump tables decoded meanwhile with an answer of a
cycle still being solved are decoded again once it settles
(:func:`proto.dispatch.recheck_provisional_decodes`).
"""
from __future__ import annotations

from typing import Dict, Optional, Tuple

from macho.disasm import _norm_reg, _parse_imm
from macho.memory import READ_ERRORS, _ctx_cache
from proto.arm64_operands import (parse_mem, split_ops, reads, writes, STORE_BYTES, PAIR_STORES,
                                  RETURNS, AUTHENTICATED_BRANCHES, CALLS, CALLER_SAVED, TRAPS,
                                  branch_target, is_conditional)
from proto.callees import (ABI_ARGS, NORETURN, RUNTIME_CONTRACTS, SWIFT_CALL_ARGS, _is_swift_name,
                           _moves_sp, call_clobbers, callee_name, outlined_code,
                           outlined_fragment, stub_selector, text_holding)
from proto.dispatch import (decoded_flow, function_entries, note_provisional_answer,
                            recheck_provisional_decodes)
from proto.function_body import function_body
from proto.models import record_heuristic_hit

#: Every register a callee could read as a value its caller hands it (not the frame pointer or
#: the link register).
_ALL_REGS = tuple(f"x{i}" for i in range(29)) + tuple(f"v{i}" for i in range(32))
#: The callee-saved registers the Swift calling convention passes arguments in: self (x20), the
#: error register (x21), the async context (x22).
_SWIFT_ARGS = frozenset(("x20", "x21", "x22"))
#: The frame pointer and link register: read on entry by design (arm64e's return-address check
#: before a tail call reads x30), saved with the callee-saved registers.
_FRAME_LINK = frozenset(("x29", "x30"))
_CALLEE_SAVED = frozenset(f"x{i}" for i in range(19, 31)) | frozenset(f"v{i}" for i in range(8, 16))
#: What a return hands its caller: the result register (a function that does not write v0
#: returns no floating-point value).
_RETURN_REGS = frozenset(("x0",))


def call_reads(ctx, target: Optional[int]) -> Tuple[str, ...]:
    """The registers a call to *target* may read: a runtime function's ABI contract
    (:data:`RUNTIME_CONTRACTS`: ``objc_retain_x19`` reads x19); a named Swift function (a
    mangled ``$s`` symbol) the Swift convention's (:data:`SWIFT_CALL_ARGS`); any other named function or
    message send, function outside this image's ``__text`` -- or an unknown target -- the
    AAPCS64 argument registers (:data:`ABI_ARGS`); an unnamed function of the image's
    ``__text`` (with a calling convention, or a machine-outlined fragment with none) the
    registers it reads before writing them (:func:`_live_in`).  Memoised on *ctx*.

    Unnamed functions that call one another in a cycle are solved together, as the least
    fixpoint: a call back to a function still being read sees what is known of it so far
    (nothing, at first), and the function the cycle entered at is read again until nothing in
    it grows.  A function of the cycle read in one round of that is not read again in the same
    round (its answer is held on the outermost function it depended on, for that round); the
    whole cycle is memoised once its entry settles."""
    name = callee_name(ctx, target) if target is not None else None
    contract = RUNTIME_CONTRACTS.get(name) if name else None
    if contract is not None:
        return contract[0]
    if _is_swift_name(name):
        return SWIFT_CALL_ARGS
    if (target is None or name is not None or stub_selector(ctx, target) is not None
            or text_holding(ctx, target) is None):
        return ABI_ARGS
    state = _ctx_cache(ctx, "_call_reads", _State)
    memo, open_, held = state.memo, state.open, state.held
    # A body read ends at the next function entry the index knows: an answer read while the
    # index was smaller may have read into the next function, so it is dropped once it grows.
    size = len(function_entries(ctx))
    if state.index_size != size:
        memo.clear()
        held.clear()
        state.index_size = size
    if target in memo:
        return memo[target]
    if target in open_:
        frame = open_[target]
        _depends_on(open_, frame.index)
        note_provisional_answer(ctx)
        return frame.reads
    before: Tuple[str, ...] = ()
    if target in held:
        owner, rnd, before = held.pop(target)
        f = open_.get(owner)
        if f is not None and f.round == rnd:
            held[target] = (owner, rnd, before)
            _depends_on(open_, f.index)
            note_provisional_answer(ctx)
            return before
    frame = _Open(len(open_))
    frame.reads = before                     # (read in an earlier round: answers only grow)
    outermost = not open_
    open_[target] = frame
    too_deep = False
    try:
        while True:
            frame.round += 1
            frame.low, frame.cyclic, frame.stale = frame.index, False, False
            try:
                res = _live_in(ctx, target)
            except READ_ERRORS:
                res = _ALL_REGS
            grew = res != frame.reads
            frame.reads = res
            if not ((frame.cyclic and grew or frame.stale) and frame.low == frame.index):
                break
    except RecursionError:
        # a chain of calls deeper than the interpreter's stack: the reads of every function
        # left open are unknown -- the outermost one answers every register (what settled
        # inside stays memoised), and the run goes on
        if not outermost:
            raise
        too_deep = True
    finally:
        del open_[target]
    if too_deep:
        held.clear()
        record_heuristic_hit(ctx, "call chain deeper than the stack",
                             f"the function at {target:#x}: every register taken as read")
        memo[target] = _ALL_REGS
        recheck_provisional_decodes(ctx)
        return _ALL_REGS
    if frame.low < frame.index:
        # settled only once the outermost function it depended on is: held for that one's
        # round, and what was held on it moves there
        owner = list(open_)[frame.low]
        f = open_[owner]
        if frame.cyclic and grew or frame.stale:
            f.stale = True                   # an answer used in this round was short of it
        for t, (o, rnd, r) in list(held.items()):
            if o == target:
                held[t] = (owner, f.round, r)
        held[target] = (owner, f.round, res)
        _depends_on(open_, frame.low)
    else:
        memo[target] = res
        for t, (o, rnd, r) in list(held.items()):
            if o == target:
                if rnd == frame.round:
                    memo[t] = r              # read in the round its cycle settled in
                del held[t]
    if not open_:
        recheck_provisional_decodes(ctx)     # every cycle has settled
    return res


class _State:
    """:func:`call_reads`' memo for one image: the answers settled (``memo``), the size of the
    function index they were read with, the functions being read (``open``: target ->
    :class:`_Open`), and the answers read in a round of a cycle still open (``held``: target ->
    (the open function it depended on, its round, the answer))."""
    __slots__ = ("memo", "index_size", "open", "held")

    def __init__(self):
        self.memo: Dict[int, Tuple[str, ...]] = {}
        self.index_size: Optional[int] = None
        self.open: Dict[int, "_Open"] = {}
        self.held: Dict[int, tuple] = {}


class _Open:
    """A function whose reads are being computed (:func:`call_reads`): its depth among those
    open, what is known of its reads so far, the outermost open function its reading has
    used, whether a call came back to it, its round (each reading of it), and whether an
    answer used in this round has since grown (another round is due)."""
    __slots__ = ("index", "reads", "low", "cyclic", "round", "stale")

    def __init__(self, index: int):
        self.index, self.reads, self.low, self.cyclic = index, (), index, False
        self.round, self.stale = 0, False


def _depends_on(open_: dict, index: int) -> None:
    """The function being read now (the innermost open one) used the reads of the open
    function at *index* (directly, or an answer read from them): that one's answer so far was
    used -- a call came back to it -- so its growth must be read again."""
    if open_:
        frames = list(open_.values())
        frames[-1].low = min(frames[-1].low, index)
        frames[index].cyclic = True


def _live_in(ctx, target: int) -> Tuple[str, ...]:
    """The registers the function at *target* reads before writing them on some path from its
    entry: a backward fixpoint over its CFG (:func:`proto.function_body.function_body`, each
    ``br``'s jump table decoded).  A call inside it reads what its callee reads
    (:func:`call_reads`) and leaves the caller-saved registers to the callee; a call to an
    outlined fragment runs the fragment's instructions; a tail call reads what its target
    reads; a return hands back :data:`_RETURN_REGS`; a trap or a call that does not return
    ends the path.  A call to a thunk runs its prefix, then reads what its tail target reads
    (:func:`outlined_code`).  A prologue spill of a callee-saved register is not a read.  An
    authenticated branch with no successor is a tail call through a signed pointer, a ``br`` to a
    pointer handed in or loaded from memory one through a plain pointer
    (:func:`_pointer_tail_call`): each reads what an unknown callee reads.  Every register when the body is read only in part or a
    ``br`` goes somewhere unknown."""
    body = function_body(ctx, target, function_entries(ctx))
    if not body or body.truncated:
        return _ALL_REGS
    flow = decoded_flow(ctx, list(body))
    cfg = flow.cfg
    own = frozenset(i.addr for i in flow.insns)
    # it has a frame of its own (set up in place or by an outlined prologue it calls)
    frame = any(_moves_sp(i) or any(_moves_sp(fi) for fi in _outlined_body(ctx, i))
                for i in flow.insns)
    live_in: Dict[int, frozenset] = {b: frozenset() for b in cfg.order}
    unresolved, pointer_calls = [], set()
    for b in cfg.order:
        last = cfg.blocks[b][-1]
        if last.mnemonic == 'br' and not cfg.succ.get(b):
            (pointer_calls.add if _pointer_tail_call(flow, last) else unresolved.append)(last.addr)
    changed = True
    while changed:
        changed = False
        for b in reversed(cfg.order):
            succ = cfg.succ.get(b, ())
            last = cfg.blocks[b][-1]
            if last.addr in unresolved:
                live = set(_ALL_REGS)                   # a jump nothing resolved
            elif not succ and (last.mnemonic in AUTHENTICATED_BRANCHES
                               or last.addr in pointer_calls):
                live = set(call_reads(ctx, None))       # a tail call through a pointer
            else:
                live = set().union(*(live_in[x] for x in succ)) if succ else set()
            for ins in reversed(cfg.blocks[b]):
                live = _live_before(ctx, ins, live, own, frame)
            if frozenset(live) != live_in[b]:
                live_in[b] = frozenset(live)
                changed = True
    entry = live_in.get(cfg.entry)
    if entry is None:
        return _ALL_REGS
    for a in unresolved:
        record_heuristic_hit(ctx, "undecoded jump table",
                             f"the br at {a:#x} in the function at {target:#x}: every register "
                             f"taken as read")
    saved = sorted(entry & _CALLEE_SAVED - _FRAME_LINK - _SWIFT_ARGS)
    if frame and saved and not unresolved:
        # A function with a calling convention has no use for its caller's callee-saved
        # registers but to save them: a save the spill test does not see (through x29, say)?
        record_heuristic_hit(ctx, "callee-saved spill test",
                             f"the function at {target:#x} reads {', '.join(saved)}")
    return tuple(r for r in _ALL_REGS if r in entry)


def _pointer_tail_call(flow, br) -> bool:
    """The ``br`` *br* jumps to a pointer: one the function was handed (its register holds its
    value on entry on every path: ``mov x0, x24 ; mov x1, x19 ; br x8``, an outlined tail, or
    ``mov x20, x0 ; br x2``, a partial-apply forwarder) or one loaded from memory (the register's
    one definition an 8-byte load from a base and a constant offset: ``ldr x2, [x8, #8] ; br x2``,
    a Swift value witness): a tail call, not a jump table (a code base plus an offset read from a
    table at an index, or a pointer read at one -- computed in the function)."""
    reg = _norm_reg(split_ops(br.op_str)[0]) if br.op_str else None
    if reg is None:
        return False
    k = flow.addr_idx[br.addr]
    if flow.from_entry(k, reg):
        return True
    d = flow.only_def(k, reg)
    if d is None:
        return False
    ins = flow.insns[d]
    ops = split_ops(ins.op_str)
    pm = parse_mem(ops[1]) if ins.mnemonic in ("ldr", "ldur") and len(ops) == 2 else None
    return pm is not None and ops[0].startswith("x") and pm[1] is None


def _live_before(ctx, ins, live_after: set, own: frozenset, frame: bool = True) -> set:
    """The registers live before *ins* given *live_after* (:func:`_live_in`); *own*: the
    addresses of the function's own instructions (a ``b`` elsewhere is a tail call); *frame*:
    the function has a frame of its own, so a callee-saved register stored to ``[sp ...]`` is
    saved there (without one, the store is into its caller's frame: a read)."""
    mn = ins.mnemonic
    ops = split_ops(ins.op_str)
    if mn in RETURNS:
        return set(_RETURN_REGS)
    if mn in TRAPS:
        return set()
    if mn == "b":
        t = branch_target(ins)
        return set(live_after) if t in own else set(call_reads(ctx, t))
    if mn in CALLS:
        t = _parse_imm(ops[0]) if mn == "bl" and ops else None
        code = outlined_code(ctx, t) if t is not None else None
        if code is not None:
            live = set(live_after)
            if code.tail is not None:                    # a thunk's tail call
                live = _live_before_call(ctx, code.tail, live)
            elif code.tail_reg is not None:              # through a register
                live = _live_before_call(ctx, None, live) | {code.tail_reg}
            for fi in reversed(code.body):
                live = _live_before(ctx, fi, live, own, frame)
            live.discard("x30")
            return live
        return _live_before_call(ctx, t, live_after) | set(reads(ins))   # (the target register)
    src = set(reads(ins))
    if frame and (mn in STORE_BYTES or mn in PAIR_STORES) and "[sp" in ins.op_str:
        src -= _CALLEE_SAVED                            # a prologue spill is not a read
    if is_conditional(mn):
        t = branch_target(ins)
        if t not in own:                                # a conditional tail call
            src |= set(call_reads(ctx, t))
    return (set(live_after) - set(writes(ins))) | src


def _live_before_call(ctx, t: Optional[int], live_after: set) -> set:
    """The registers live before a call to *t* given *live_after*: what it reads, and what it
    leaves alone of *live_after* (nothing, for a function that does not return)."""
    used = set(call_reads(ctx, t))
    if callee_name(ctx, t) in NORETURN:
        return used
    clob = call_clobbers(ctx, t)
    return (set(live_after) - set(clob if clob is not None else CALLER_SAVED)) | used


def _outlined_body(ctx, ins) -> Tuple:
    """The instructions the call *ins* runs in its caller (:func:`outlined_fragment`), else ()."""
    if ins.mnemonic != "bl":
        return ()
    return outlined_fragment(ctx, branch_target(ins)) or ()
