"""proto/callees.py -- what a call reaches: the symbol name of its target, the selector an
objc message stub sends, and the runtime functions' ABI contracts.

A call into another image is named by that image's ABI: the exported symbol it lands on
(``_objc_retain_x2``, ``_PBDataWriterWriteInt32Field``, ``_objc_msgSend``).  These names are
fixed by the Objective-C runtime / ProtocolBuffer ABI, the same in every binary, so code may
rely on them the way it relies on the ``writeTo:`` selector.

* dyld shared cache: the cache links calls directly (or through a stub island) to the
  callee's code; the name comes from the exporting image's export trie
  (:meth:`macho.dyld_cache.DyldCacheReader.export_name_at`).
* standalone binary: a call goes through an import stub whose GOT slot the binary binds by
  name (:func:`import_name`).

Every stub is decoded by one reader, :func:`stub_target` (its computed target or its GOT slot);
:func:`real_target` follows it to the callee.

A function of the image itself (not exported) has no name here: None.

This module is the one owner of call naming (the writer flow, the map and
struct decoders and the readFrom: evaluator use it).
"""
from __future__ import annotations

from typing import Dict, NamedTuple, Optional, Tuple

from macho.disasm import disasm, _norm_reg, _parse_imm
from macho.memory import READ_ERRORS, BinaryContext, _ctx_cache
from proto.arm64_operands import (parse_mem, split_ops, reads, writes, writeback_base, STORE_BYTES,
                                  PAIR_STORES, RETURNS, BLOCK_ENDS, NO_DEST, AUTHENTICATED_BRANCHES,
                                  INDIRECT_BRANCHES, CALL_ARG_GPRS, ARG_FPRS, CALLS, CALLER_SAVED,
                                  TRAPS,
                                  branch_target, is_cond_branch, is_conditional)
from proto.arm64cfg import parse_adrp


def callee_name(ctx: BinaryContext, va: Optional[int]) -> Optional[str]:
    """Exported (cache) or imported (binary) symbol name of the function a ``bl`` / ``b`` to
    *va* reaches, or None.  Memoised on *ctx*."""
    if va is None:
        return None
    memo = _ctx_cache(ctx, "_callee_names", dict)
    if va in memo:
        return memo[va]
    name: Optional[str] = None
    try:
        if getattr(ctx, "is_cache_backed", False):
            reader = getattr(ctx, "_cache_reader", None)
            if reader is not None:                   # (a cache context always has one)
                name = reader.export_name_at(va)
                if name is None:
                    real = real_target(ctx, va)
                    if real != va:
                        name = reader.export_name_at(real)
        else:
            name = import_name(ctx, va)
    except READ_ERRORS:
        name = None                                  # unreadable bytes at va: no name
    memo[va] = name
    return name


def _adrp(ins) -> Optional[Tuple[str, int]]:
    """``adrp xR, #page`` -> (xR, page), else None."""
    return parse_adrp(ins.op_str) if ins.mnemonic == 'adrp' else None


class Stub(NamedTuple):
    """Where a call stub branches: to the code address it computes (*target*), or through
    the GOT slot it loads the address from (*slot*).  Exactly one is set."""
    target: Optional[int] = None
    slot: Optional[int] = None


def stub_target(ctx, va: Optional[int]) -> Optional[Stub]:
    """Decode the call stub at *va*, or None: *va* is not a stub.  A stub is a straight line
    that only computes the address it branches to -- no store, no frame -- ending in an
    indirect branch::

        adrp  x16, <page>               ; PLT form (dyld cache): the target itself
        add   x16, x16, #off
        br    x16                        -> Stub(target=page+off)

        adrp  x16, <page>               ; import stub (standalone binary)
        ldr   x16, [x16, #off]
        br    x16                        -> Stub(slot=page+off)

        adrp  x17, <page>               ; arm64e stub island (iOS 27 / macOS 27 caches)
        add   x17, x17, #off
        ldr   x16, [x17]
        braa  x16, x17                   -> Stub(slot=page+off)

        adr   x16, <a>                  ; far branch island (iOS 27: code more than 4 GB
        mov   x17, #k                   ; past the cache base reaching code below it)
        sub   x16, x16, x17, lsl #s
        br    x16                        -> Stub(target=a - (k << s))

    The branch register is read by :class:`proto.arm64_eval.Flow` over that line: loaded
    from a known address, the stub goes through that GOT slot; else its constant value is
    the target.  Memoised on *ctx*."""
    if not va:
        return None
    memo = _ctx_cache(ctx, "_stub_targets", dict)
    if va in memo:
        return memo[va]
    res: Optional[Stub] = None
    try:
        line = []
        while True:
            ins = disasm(ctx, va + 4 * len(line), max_insns=1, stop_at_ret=False)
            if not ins:
                break
            line.append(ins[0])
            if ins[0].mnemonic in BLOCK_ENDS or is_cond_branch(ins[0].mnemonic):
                break
            if not _computes_only(ins[0]):
                break
        if line and line[-1].mnemonic in INDIRECT_BRANCHES:
            res = _branch_register_stub(ctx, line)
    except READ_ERRORS:                               # unreadable bytes at va: not a stub
        res = None
    memo[va] = res
    return res


def _computes_only(ins) -> bool:
    """*ins* writes registers only: no memory, no sp (a stub keeps no frame)."""
    ops = split_ops(ins.op_str)
    return (ins.mnemonic not in STORE_BYTES and ins.mnemonic not in PAIR_STORES
            and ins.mnemonic not in NO_DEST and bool(ops) and ops[0] not in ('sp', 'wsp')
            and _norm_reg(ops[0]) is not None and writeback_base(ops) is None)


def _branch_register_stub(ctx, line) -> Optional[Stub]:
    """The :class:`Stub` the indirect branch ending *line* takes: the GOT slot its register
    was loaded from, or the register's constant value."""
    from proto.arm64_eval import Flow                  # (arm64_eval imports this module)
    flow = Flow(ctx, line)
    k = len(line) - 1
    ops = split_ops(line[k].op_str)
    reg = _norm_reg(ops[0]) if ops else None
    if reg is None:
        return None
    d = flow.only_def(k, reg)
    if d is not None and line[d].mnemonic == 'ldr':
        slot = flow.load_address(d)
        return Stub(slot=slot) if slot is not None else None
    target = flow.const_before(k, reg)
    return Stub(target=target) if target is not None else None


def real_target(ctx, va: int) -> int:
    """The function a call to *va* really reaches: a stub's target (:func:`stub_target`) --
    computed, or read from its GOT slot through :meth:`BinaryContext.read_ptr` (which decodes
    an arm64e-authenticated entry) -- else *va* itself (a direct call).  The canonical
    identity of a callee: a per-callsite stub island has a different address at every call
    site but one shared target.  In a standalone binary a GOT slot is bound at load time to
    another image: the stub is the callee there, named by :func:`import_name`."""
    stub = stub_target(ctx, va)
    if stub is None:
        return va
    if stub.target is not None:
        return stub.target
    if not getattr(ctx, "is_cache_backed", False):
        return va
    try:
        return ctx.read_ptr(stub.slot) or va
    except ValueError:                               # slot not mapped
        return va


def import_name(ctx, va: Optional[int]) -> Optional[str]:
    """Symbol a standalone binary's call stub at *va* imports: the name the binary binds
    the stub's GOT slot to (:func:`stub_target`), or None.  A dyld cache binds nothing by
    name (its calls are named by the callee's export, :func:`callee_name`): None there."""
    if getattr(ctx, "is_cache_backed", False):
        return None
    stub = stub_target(ctx, va)
    return ctx.bind_name_for(stub.slot) if stub is not None and stub.slot is not None else None


def stub_selector(ctx, va: Optional[int]) -> Optional[str]:
    """Selector the objc message stub at *va* sends, or None (not a message stub).  The
    linker emits one stub per selector a binary messages, in one of two forms::

        adrp  x1, <page>
        ldr   x1, [x1, #off]      ; the __objc_selrefs slot -> x1 = the selector
        ... ; br x16              ; to objc_msgSend (arm64e: braa x16, x17)

        adrp  x1, <page>          ; newer caches (iOS 27 / macOS 27): one shared stub per
        add   x1, x1, #off        ; selector, x1 = the selector string itself
        b     _objc_msgSend

    Either is a send only if its branch lands on ``_objc_msgSend``, named by its export or
    import (:func:`callee_name`; the first form's instructions after the ``ldr x1`` are an
    import stub), not by the shape.  Memoised on *ctx*."""
    if va is None:
        return None
    memo = _ctx_cache(ctx, "_stub_selectors", dict)
    if va in memo:
        return memo[va]
    sel: Optional[str] = None
    try:
        ins = disasm(ctx, va, 6, stop_at_ret=False)
        pa = _adrp(ins[0]) if ins else None
        if pa is not None and pa[0] == 'x1' and len(ins) >= 3 \
                and ins[1].mnemonic == 'add' and ins[2].mnemonic == 'b':
            ops = split_ops(ins[1].op_str)
            if (len(ops) == 3 and _norm_reg(ops[0]) == 'x1' and _norm_reg(ops[1]) == 'x1'
                    and ops[2].startswith('#')
                    and callee_name(ctx, _parse_imm(ins[2].op_str)) == '_objc_msgSend'):
                sel = ctx.read_cstring(pa[1] + _parse_imm(ops[2]))
        elif pa is not None and pa[0] == 'x1' and len(ins) >= 3 and ins[1].mnemonic == 'ldr' \
                and callee_name(ctx, ins[2].addr) == '_objc_msgSend':
            ops = split_ops(ins[1].op_str)
            pm = parse_mem(ops[1]) if len(ops) == 2 else None
            if (pm is not None and _norm_reg(ops[0]) == 'x1' and pm.base == 'x1'
                    and pm.index is None):
                slot = ctx.read_ptr(pa[1] + pm.disp)
                sel = ctx.read_cstring(slot) if slot else None
    except READ_ERRORS:                               # unreadable bytes: not a stub
        sel = None
    memo[va] = sel
    return sel


# ── runtime ABI contracts ─────────────────────────────────────────────────────
#: (registers read, register the call returns in x0 or None) by exported symbol name: the
#: Objective-C runtime's ARC and locking entry points, fixed by its ABI (the compiler emits
#: these calls by name in every binary).
RUNTIME_CONTRACTS: Dict[str, Tuple[Tuple[str, ...], Optional[str]]] = {}
for _n in range(29):
    RUNTIME_CONTRACTS[f"_objc_retain_x{_n}"] = ((f"x{_n}",), f"x{_n}")
    RUNTIME_CONTRACTS[f"_objc_release_x{_n}"] = ((f"x{_n}",), None)
for _name in ("_objc_retain", "_objc_autorelease", "_objc_autoreleaseReturnValue",
              "_objc_retainAutorelease", "_objc_retainAutoreleaseReturnValue",
              "_objc_retainAutoreleasedReturnValue", "_objc_claimAutoreleasedReturnValue",
              "_objc_unsafeClaimAutoreleasedReturnValue", "_objc_retain_autorelease",
              "_objc_retainBlock"):
    RUNTIME_CONTRACTS[_name] = (("x0",), "x0")
for _name in ("_objc_release", "_objc_sync_enter", "_objc_sync_exit",
              "_objc_enumerationMutation", "_os_unfair_lock_lock", "_os_unfair_lock_unlock",
              "_os_unfair_lock_assert_owner", "_os_unfair_lock_assert_not_owner"):
    RUNTIME_CONTRACTS[_name] = (("x0",), None)
RUNTIME_CONTRACTS["_os_unfair_lock_lock_with_options"] = (("x0", "x1"), None)
RUNTIME_CONTRACTS["____chkstk_darwin"] = (("x9",), None)

#: Callees that change fewer registers than AAPCS64 lets a call change (every caller-saved one,
#: and the frame slots it can reach): the registers each changes; none writes memory its caller
#: owns.  The stack probe a frame over a page calls first (``mov w9, #size ; adrp x17 ;
#: add x17 ; ldr x16, [x17] ; blraa x16, x17``) saves and restores its other scratch registers
#: below sp, so the caller's x0 (self) survives it; x9, the size, it counts down a page at a time
#: as it probes (its caller allocates the frame by an immediate) -- run from the iPhone 8 cache's
#: libsystem_pthread, :mod:`oracles.call_models` (TODO #128).
CALL_CLOBBERS: Dict[str, Tuple[str, ...]] = {"____chkstk_darwin": ("x9", "x16", "x17", "x30")}
RUNTIME_CONTRACTS["_objc_opt_class"] = (("x0",), None)
for _name in ("_objc_opt_isKindOfClass", "_objc_opt_respondsToSelector"):
    RUNTIME_CONTRACTS[_name] = (("x0", "x1"), None)



def sent_selector(ctx, target: Optional[int], x1) -> Optional[str]:
    """Selector a call to *target* sends: a ``_objc_msgSend$<sel>`` stub's, or -- for a call
    to the generic ``objc_msgSend`` a standalone binary imports by name -- the selector string
    *x1* (the call's x1, a number) points at."""
    if target is None:
        return None
    sel = stub_selector(ctx, target)
    if sel is not None or type(x1) is not int or callee_name(ctx, target) != '_objc_msgSend':
        return sel
    try:
        return ctx.read_cstring(x1)
    except READ_ERRORS:
        return None

def call_clobbers(ctx, target: Optional[int]) -> Optional[Tuple[str, ...]]:
    """The registers a call to *target* changes when its callee changes fewer than a call may
    (:data:`CALL_CLOBBERS`); None for any other callee, or an unknown target (every
    caller-saved register, and the frame slots handed to it)."""
    name = callee_name(ctx, target) if target is not None else None
    return CALL_CLOBBERS.get(name) if name else None

#: AAPCS64 argument registers (x8: an indirect result's address): what a function with a
#: calling convention reads.
ABI_ARGS = CALL_ARG_GPRS + ARG_FPRS
#: Every register a callee could read as a value its caller hands it (not the frame pointer or
#: the link register).
_ALL_REGS = tuple(f"x{i}" for i in range(29)) + tuple(f"v{i}" for i in range(32))
#: The callee-saved registers the Swift calling convention passes arguments in: self (x20), the
#: error register (x21), the async context (x22).
_SWIFT_ARGS = frozenset(("x20", "x21", "x22"))
#: What a named function of the Swift calling convention may read: those and the AAPCS64 arguments.
SWIFT_CALL_ARGS = ABI_ARGS + ("x20", "x21", "x22")
#: Swift mangled-symbol prefixes as Mach-O names them (Swift 5 `$s`, 4.2 `$S`, 4 `_T0`, each
#: with the Mach-O underscore).
_SWIFT_SYMBOL_PREFIXES = ("_$s", "_$S", "__T0")


def _is_swift_name(name: Optional[str]) -> bool:
    """*name* is a function of the Swift calling convention: a mangled Swift symbol that is not
    an ``@objc`` thunk (mangled ``...To``, which has the C convention).

    Such a call is assumed to succeed: a throwing Swift function writes its error to x21 (which
    its caller zeroes and tests after the call), but x21 is kept across the call like the other
    callee-saved registers, so the error path is not followed (heuristic registry
    ``swift-call-succeeds``)."""
    return bool(name) and name.startswith(_SWIFT_SYMBOL_PREFIXES) and not name.endswith("To")

#: The frame pointer and link register: read on entry by design (arm64e's return-address check
#: before a tail call reads x30), saved with the callee-saved registers.
_FRAME_LINK = frozenset(("x29", "x30"))
_CALLEE_SAVED = frozenset(f"x{i}" for i in range(19, 31)) | frozenset(f"v{i}" for i in range(8, 16))
#: What a return hands its caller: the result register (a function that does not write v0
#: returns no floating-point value).
_RETURN_REGS = frozenset(("x0",))


class Outlined(NamedTuple):
    """Code a ``bl`` runs as part of its caller (:func:`outlined_code`)."""
    body: Tuple             # the instructions the caller runs (a thunk's prefix)
    tail: Optional[int]     # a thunk's tail-call target; None for a fragment
    tail_reg: Optional[str] = None   # the register a thunk's tail call goes through


def outlined_code(ctx, target: Optional[int]) -> Optional[Outlined]:
    """What a ``bl`` to *target* runs as part of its caller, when the callee is a straight line
    of this image's ``__text`` (up to the next function start) whose instructions run in the
    caller (:func:`_runs_in_caller`: no branch, call, or link-register write, sp moved only by
    an immediate) and that ends in

    * a ``ret``: a *fragment* (``ldrsw x9, [x23, #0x30] ; add x0, x8, x9 ; ret``, the outlined
      prologue ``sub sp, sp, #0x80 ; stp x28, x27, [sp, #0x20] ; ... ; ret``), ``tail`` None;
    * the last instruction of its extent, a ``b`` out of it, after an optional arm64e
      return-address check (``eor x16, x30, x30, lsl #1 ; tbz x16, #62, L ; brk ; L: b T``): a
      *thunk*, its prefix run in the caller and then a call to ``tail`` = T;
    * the last instruction of its extent, a ``br`` (or an authenticated one) through a register:
      a thunk whose tail call goes through ``tail_reg`` (``mov x19, x0 ; mov x0, #0 ; br x1``,
      Swift's outlined call of a metadata accessor, which sets the caller's x19).

    The machine outliner's helpers keep no calling convention: running them in the caller's
    state is what the call does, so a caller evaluates through them rather than assume the
    AAPCS64 clobber.  None for any other callee, or without a function index to bound it.
    Memoised on *ctx*."""
    if target is None or ctx is None:
        return None
    memo = _ctx_cache(ctx, "_outlined_code", dict)
    if target in memo:
        return memo[target]
    from proto.function_body import function_end      # (function_body imports this module)
    res = None
    try:
        end = function_end(ctx, target) if ctx.function_starts() else None
        if end is not None:
            body = disasm(ctx, target, max_insns=max(0, (end - target) // 4), stop_at_ret=True)
            j = next((i for i, ins in enumerate(body) if not _runs_in_caller(ins)), len(body))
            if j < len(body) and body[j].mnemonic in RETURNS:
                res = Outlined(tuple(body[:j]), None)
            else:
                prefix, last = (j - 1, j + 2) if _return_address_check(body, j - 1) else (j, j)
                if last == len(body) - 1 and body[last].mnemonic == "b":
                    t = branch_target(body[last])
                    if t is not None and not target <= t < end:
                        res = Outlined(tuple(body[:prefix]), t)
                elif last == len(body) - 1 and body[last].mnemonic in INDIRECT_BRANCHES:
                    reg = _norm_reg(split_ops(body[last].op_str)[0])
                    if reg is not None:
                        res = Outlined(tuple(body[:prefix]), None, reg)
    except READ_ERRORS:                               # unreadable bytes: an ordinary call
        res = None
    memo[target] = res
    return res


def outlined_fragment(ctx, target: Optional[int]) -> Optional[Tuple]:
    """The instructions a ``bl`` to *target* runs in its caller (:func:`outlined_code`'s
    ``body``: a fragment without its ``ret``, a thunk's prefix), else None."""
    o = outlined_code(ctx, target)
    return None if o is None else o.body


def outlined_tail(ctx, target: Optional[int]) -> Optional[int]:
    """The target of the tail call a thunk at *target* ends in (:func:`outlined_code`), else
    None (a fragment, or a tail call through a register: :func:`outlined_tail_reg`)."""
    o = outlined_code(ctx, target)
    return None if o is None else o.tail


def outlined_tail_reg(ctx, target: Optional[int]) -> Optional[str]:
    """The register the tail call a thunk at *target* ends in goes through
    (:func:`outlined_code`), else None."""
    o = outlined_code(ctx, target)
    return None if o is None else o.tail_reg


def _return_address_check(body, i: int) -> bool:
    """``body[i:i + 3]`` is arm64e's check of the return address before a tail call:
    ``eor x16, x30, x30, lsl #1 ; tbz x16, #62, <past the brk> ; brk``."""
    if i < 0 or i + 3 > len(body):
        return False
    eor, tbz, brk = body[i:i + 3]
    ops = split_ops(tbz.op_str)
    return (eor.mnemonic == "eor" and split_ops(eor.op_str)[:3] == ["x16", "x30", "x30"]
            and tbz.mnemonic == "tbz" and len(ops) == 3 and ops[0] == "x16"
            and _parse_imm(ops[1]) == 62 and _parse_imm(ops[2]) == brk.addr + 4
            and brk.mnemonic == "brk")


def text_holding(ctx, va: Optional[int]):
    """The image's ``__TEXT,__text`` section when it holds *va*, else None."""
    if va is None or not ctx.has_section("__TEXT", "__text"):
        return None
    text = ctx.section("__TEXT", "__text")
    return text if text.vmaddr <= va < text.vmaddr + text.vmsize else None


def _moves_sp(ins) -> bool:
    """*ins* changes sp: sp as its destination, or a pre/post-index access through sp."""
    ops = split_ops(ins.op_str)
    return writeback_base(ops) == "sp" or bool(
        ops and ops[0] in ("sp", "wsp") and ins.mnemonic not in NO_DEST)


def _moves_sp_by_immediate(ins) -> bool:
    """*ins* moves sp by an immediate: ``add`` / ``sub sp, sp, #imm``, or a pre- / post-index
    access through sp (``[sp, #-0x10]!``, ``[sp], #0x10``)."""
    ops = split_ops(ins.op_str)
    if ins.mnemonic in ("add", "sub") and len(ops) == 3:
        return ops[0] == "sp" and ops[1] == "sp" and ops[2].startswith("#")
    if writeback_base(ops) != "sp":
        return False
    return ops[-1].endswith("!") or ops[-1].startswith("#")


def _runs_in_caller(ins) -> bool:
    """*ins* may run as part of the calling function: not a control transfer, and it leaves the
    link register (x30) as the caller has it and moves sp, if at all, by an immediate (the
    caller's state tracks sp)."""
    mn = ins.mnemonic
    if mn in BLOCK_ENDS or is_cond_branch(mn) or mn in TRAPS or mn == "svc":
        return False
    return "x30" not in writes(ins) and (not _moves_sp(ins) or _moves_sp_by_immediate(ins))

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
    from proto.dispatch import function_entries, recheck_provisional_decodes
    memo = _ctx_cache(ctx, "_call_reads", dict)
    # A body read ends at the next function entry the index knows: an answer read while the
    # index was smaller may have read into the next function, so it is dropped once it grows.
    stamp = _ctx_cache(ctx, "_call_reads_index_size", lambda: [None])
    size = len(function_entries(ctx))
    if stamp[0] != size:
        memo.clear()
        _ctx_cache(ctx, "_call_reads_held", dict).clear()
        stamp[0] = size
    if target in memo:
        return memo[target]
    open_ = _ctx_cache(ctx, "_call_reads_open", dict)    # being read: target -> _Open
    if target in open_:
        frame = open_[target]
        _depends_on(open_, frame.index)
        provisional_answers(ctx)[0] += 1
        return frame.reads
    # read in this round of an open cycle: {target: (the open function it depended on, its
    # round, the answer)}
    held = _ctx_cache(ctx, "_call_reads_held", dict)
    before: Tuple[str, ...] = ()
    if target in held:
        owner, rnd, before = held.pop(target)
        f = open_.get(owner)
        if f is not None and f.round == rnd:
            held[target] = (owner, rnd, before)
            _depends_on(open_, f.index)
            provisional_answers(ctx)[0] += 1
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
        from proto.models import record_heuristic_hit
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


def provisional_answers(ctx) -> list:
    """``[n]``: how many times :func:`call_reads` has answered with what was known so far of a
    function still being read (a call back into an unsettled cycle).  A jump table decoded
    while this grows used such an answer (:func:`proto.dispatch.recheck_provisional_decodes`)."""
    return _ctx_cache(ctx, "_call_reads_provisional", lambda: [0])


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
    function at *index*."""
    if open_:
        cur = next(reversed(open_.values()))
        cur.low = min(cur.low, index)
        if index == cur.index:
            cur.cyclic = True


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
    from proto.dispatch import decoded_flow, function_entries
    from proto.function_body import function_body
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
    from proto.models import record_heuristic_hit
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


#: Functions that never return.
NORETURN = frozenset(("___stack_chk_fail", "__Unwind_Resume", "_objc_exception_throw",
                      "_abort", "___assert_rtn"))

#: The runtime functions that return their (first) argument itself -- the ARC retain /
#: autorelease / return-value handshake.  (``_objc_retainBlock`` returns x0 but may return a
#: copy, so it is not one.)
RETURNS_ARGUMENT = frozenset((
    '_objc_retain', '_objc_retainAutorelease', '_objc_retainAutoreleasedReturnValue',
    '_objc_claimAutoreleasedReturnValue', '_objc_unsafeClaimAutoreleasedReturnValue',
    '_objc_retainAutoreleaseReturnValue', '_objc_autorelease', '_objc_autoreleaseReturnValue',
))
