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
from proto.arm64_operands import (parse_mem, split_ops, writes, writeback_base, STORE_BYTES,
                                  PAIR_STORES, RETURNS, BLOCK_ENDS, NO_DEST, INDIRECT_BRANCHES,
                                  CALL_ARG_GPRS, ARG_FPRS, TRAPS, branch_target, is_cond_branch)
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

#: ProtocolBuffer.framework's field writers, ``_PBDataWriterWrite<T>Field(writer, value,
#: field)`` (the floating-point ones take the value in v0, the field number in w1): the proto
#: type of the one value each serialises, by T.
PB_FIELD_WRITERS: Dict[str, str] = {
    "BOOL": "bool", "Int32": "int32", "Int64": "int64", "Uint32": "uint32",
    "Uint64": "uint64", "Sint32": "sint32", "Sint64": "sint64", "Fixed32": "fixed32",
    "Fixed64": "fixed64", "Sfixed32": "sfixed32", "Sfixed64": "sfixed64",
    "Float": "float", "Double": "double", "String": "string", "Data": "bytes",
}


#: Where a field writer ``(writer, value, field#)`` takes its value and its field number
#: (AAPCS64; the writer in x0): ``(value register, number register)`` -- an integer value in x1
#: with the number in w2, a float / double value in v0 with the number in w1.
INT_WRITE_ARGS, FP_WRITE_ARGS = ("x1", "x2"), ("v0", "x1")


def pb_field_writer_type(name: Optional[str]) -> Optional[str]:
    """The proto type the field writer named *name* (:data:`PB_FIELD_WRITERS`) serialises;
    None for any other name."""
    if not name or not (name.startswith("_PBDataWriterWrite") and name.endswith("Field")):
        return None
    return PB_FIELD_WRITERS.get(name[len("_PBDataWriterWrite"):-len("Field")])


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
#: What a named function of the Swift calling convention may read: the callee-saved registers
#: it passes arguments in -- self (x20), the error register (x21), the async context (x22) --
#: and the AAPCS64 arguments.
SWIFT_CALL_ARGS = ABI_ARGS + ("x20", "x21", "x22")
#: Swift mangled-symbol prefixes as Mach-O names them (Swift 5 `$s`, 4.2 `$S`, 4 `_T0`, each
#: with the Mach-O underscore).
_SWIFT_SYMBOL_PREFIXES = ("_$s", "_$S", "__T0")


def _is_swift_name(name: Optional[str]) -> bool:
    """*name* is a function of the Swift calling convention: a mangled Swift symbol that is not
    an ``@objc`` thunk (mangled ``...To``, which has the C convention)."""
    return bool(name) and name.startswith(_SWIFT_SYMBOL_PREFIXES) and not name.endswith("To")

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
