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

import bisect
from typing import Dict, NamedTuple, Optional, Tuple

from macho.disasm import disasm, _norm_reg, _parse_imm
from macho.memory import BinaryContext, _ctx_cache
from proto.arm64_operands import (parse_mem, split_ops, writes, writeback_base, operand_regs, STORE_BYTES,
                                  PAIR_STORES, RETURNS, COMPARE_BRANCHES, BLOCK_ENDS, NO_DEST,
                                  INDIRECT_BRANCHES, is_cond_branch)
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
    except (ValueError, KeyError, IndexError):
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
    """Decode the call stub at *va* by evaluating its straight-line code up to its branch,
    or None: *va* is not a stub.  A stub only computes the address it branches to::

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

    Each instruction is evaluated (``adrp`` a page, ``adr`` an address, ``mov #imm`` a
    constant, ``add`` / ``sub`` of an immediate or a shifted register to a known value,
    ``ldr`` of a pointer from a known address or a PC-relative literal); the first instruction
    that is none of these ends the decode -- an indirect branch on a register the stub computed is a
    stub, anything else is not.  No instruction position or register is assumed.  Memoised
    on *ctx*."""
    if not va:
        return None
    memo = _ctx_cache(ctx, "_stub_targets", dict)
    if va in memo:
        return memo[va]
    res: Optional[Stub] = None
    # reg -> Stub: the address a register holds (target=) or the slot it was loaded from (slot=)
    regs: Dict[str, Stub] = {}
    try:
        k = va
        while True:
            ins = disasm(ctx, k, max_insns=1, stop_at_ret=False)
            if not ins:
                break
            mn, ops = ins[0].mnemonic, split_ops(ins[0].op_str)
            if mn in INDIRECT_BRANCHES:
                res = regs.get(_norm_reg(ops[0])) if ops else None
                break
            dst = _norm_reg(ops[0]) if ops and ops[0].startswith('x') else None
            if dst is None:
                break
            if mn == 'adrp':
                pa = _adrp(ins[0])
                if pa is None:
                    break
                regs[dst] = Stub(target=pa[1])
            elif mn == 'adr' and len(ops) == 2 and ops[1].startswith('#'):
                regs[dst] = Stub(target=_parse_imm(ops[1]))
            elif mn in ('mov', 'movz') and len(ops) == 2 and ops[1].startswith('#'):
                regs[dst] = Stub(target=_parse_imm(ops[1]))
            elif mn in ('add', 'sub') and len(ops) in (3, 4):
                src = regs.get(_norm_reg(ops[1]))
                if ops[2].startswith('#') and len(ops) == 3:
                    v = _parse_imm(ops[2])
                else:                               # a register, optionally `lsl #s`
                    r = regs.get(_norm_reg(ops[2]))
                    sh = (_parse_imm(ops[3][len('lsl '):])
                          if len(ops) == 4 and ops[3].startswith('lsl #') else 0 if len(ops) == 3
                          else None)
                    v = r.target << sh if r is not None and r.target is not None \
                        and sh is not None else None
                if src is None or src.target is None or v is None:
                    break
                regs[dst] = Stub(target=(src.target + v if mn == 'add' else src.target - v)
                                 & 0xFFFFFFFFFFFFFFFF)
            elif mn == 'ldr' and len(ops) == 2 and ops[1].startswith('#'):
                regs[dst] = Stub(slot=_parse_imm(ops[1]))           # PC-relative literal
            elif mn == 'ldr' and len(ops) == 2 and not ops[1].endswith('!'):
                pm = parse_mem(ops[1])
                src = regs.get(pm.base) if pm is not None and pm.index is None else None
                if src is None or src.target is None:
                    break
                regs[dst] = Stub(slot=src.target + pm.disp)
            else:
                break
            k += 4
    except (NameError, ImportError):
        raise
    except Exception:                               # unreadable bytes at va: not a stub
        res = None
    memo[va] = res
    return res


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

    The second form is a send only if its branch lands on ``_objc_msgSend``, named by its
    export or import (:func:`callee_name`), not by the shape.  Memoised on *ctx*."""
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
        elif pa is not None and pa[0] == 'x1' and len(ins) >= 2 and ins[1].mnemonic == 'ldr' \
                and any(i.mnemonic in INDIRECT_BRANCHES for i in ins[2:]):
            ops = split_ops(ins[1].op_str)
            pm = parse_mem(ops[1]) if len(ops) == 2 else None
            if (pm is not None and _norm_reg(ops[0]) == 'x1' and pm.base == 'x1'
                    and pm.index is None):
                slot = ctx.read_ptr(pa[1] + pm.disp)
                sel = ctx.read_cstring(slot) if slot else None
    except (NameError, ImportError):
        raise
    except Exception:                               # unreadable bytes: not a stub
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
#: add x17 ; ldr x16, [x17] ; blraa x16, x17``) saves and restores its scratch registers below
#: sp, so the caller's x0 (self) survives it.
CALL_CLOBBERS: Dict[str, Tuple[str, ...]] = {"____chkstk_darwin": ("x16", "x17", "x30")}
for _name in ("_objc_opt_class", "_objc_opt_isKindOfClass", "_objc_opt_respondsToSelector"):
    RUNTIME_CONTRACTS[_name] = (("x0", "x1"), None)


def call_clobbers(ctx, target: Optional[int]) -> Optional[Tuple[str, ...]]:
    """The registers a call to *target* changes when its callee changes fewer than a call may
    (:data:`CALL_CLOBBERS`); None for any other callee, or an unknown target (every
    caller-saved register, and the frame slots handed to it)."""
    name = callee_name(ctx, target) if target is not None else None
    return CALL_CLOBBERS.get(name) if name else None

#: AAPCS64 argument registers (x8: an indirect result's address): what a function with a
#: calling convention reads.
ABI_ARGS = tuple(f"x{i}" for i in range(9)) + tuple(f"v{i}" for i in range(8))
#: Every register a callee could read.
_ALL_REGS = tuple(f"x{i}" for i in range(29)) + tuple(f"v{i}" for i in range(32))
_CALLEE_SAVED = frozenset(f"x{i}" for i in range(19, 31)) | frozenset(f"v{i}" for i in range(8, 16))
# [cap:INPUT-SANITY] runaway backstop for the entry scan below (it stops at the first branch).
_ENTRY_SCAN_INSNS = 64


def outlined_fragment(ctx, target: Optional[int]) -> Optional[Tuple]:
    """The instructions a ``bl`` to *target* runs as part of its caller (its ``ret`` left out),
    when the callee is a straight line of this image's ``__text`` that returns inside its own
    extent (up to the next function start) with no branch, call, or write to sp or the link
    register: the machine outliner's fragments (``ldrsw x9, [x23, #0x30] ; add x0, x8, x9 ;
    ret``) keep no calling convention.  Running them in the caller's state is what the call
    does, so a caller evaluates through them rather than assume the AAPCS64 clobber.  None
    for any other callee, or without a function index to bound it.  Memoised on *ctx*."""
    if target is None or ctx is None:
        return None
    memo = _ctx_cache(ctx, "_outlined_fragments", dict)
    if target in memo:
        return memo[target]
    res = None
    try:
        text = ctx.section("__TEXT", "__text") if ctx.has_section("__TEXT", "__text") else None
        starts = ctx.function_starts() if text is not None else []
        if text is not None and text.vmaddr <= target < text.vmaddr + text.vmsize and starts:
            i = bisect.bisect_right(starts, target)
            end = starts[i] if i < len(starts) else text.vmaddr + text.vmsize
            body = disasm(ctx, target, max_insns=max(0, (end - target) // 4), stop_at_ret=True)
            if body and body[-1].mnemonic in RETURNS and all(
                    _runs_in_caller(ins) for ins in body[:-1]):
                res = tuple(body[:-1])
    except (NameError, ImportError):
        raise
    except Exception:                               # unreadable bytes: an ordinary call
        res = None
    memo[target] = res
    return res


def _runs_in_caller(ins) -> bool:
    """*ins* may run as part of the calling function: not a control transfer, and it leaves sp
    and the link register (x30) as the caller has them."""
    mn = ins.mnemonic
    if mn in BLOCK_ENDS or is_cond_branch(mn) or mn in ("brk", "udf", "hlt", "svc"):
        return False
    ops = split_ops(ins.op_str)
    if "x30" in writes(ins) or writeback_base(ops) == "sp":
        return False
    return not (ops and ops[0] in ("sp", "wsp") and mn not in NO_DEST)

def call_reads(ctx, target: Optional[int]) -> Tuple[str, ...]:
    """The registers a call to *target* may read: a runtime function's ABI contract
    (:data:`RUNTIME_CONTRACTS`: ``objc_retain_x19`` reads x19); any other named function or
    message send -- or an unknown target -- the AAPCS64 argument registers
    (:data:`ABI_ARGS`); an unnamed function of the image (possibly a machine-outlined
    fragment with no calling convention), what its entry path reads before writing it, and,
    once it branches, every register not yet written.  Memoised on *ctx*."""
    name = callee_name(ctx, target) if target is not None else None
    contract = RUNTIME_CONTRACTS.get(name) if name else None
    if contract is not None:
        return contract[0]
    if target is None or name is not None or stub_selector(ctx, target) is not None:
        return ABI_ARGS
    memo = _ctx_cache(ctx, "_call_reads", dict)
    if target in memo:
        return memo[target]
    res: Tuple[str, ...] = _ALL_REGS
    try:
        written, read = set(), set()
        for ins in disasm(ctx, target, max_insns=_ENTRY_SCAN_INSNS, stop_at_ret=True):
            mn = ins.mnemonic
            ops = split_ops(ins.op_str)
            if mn in RETURNS:
                res = tuple(r for r in _ALL_REGS if r in read or (r == 'x0' and r not in written))
                break
            if mn in BLOCK_ENDS or is_cond_branch(mn):
                if mn in COMPARE_BRANCHES:
                    read |= set(operand_regs(ops[:1])) - written
                res = tuple(r for r in _ALL_REGS if r in read or r not in written)
                break
            dst = set(writes(ins))
            if mn in NO_DEST:
                src = set(operand_regs(ops))
                if (mn in STORE_BYTES or mn in PAIR_STORES) and '[sp' in ins.op_str:
                    src -= _CALLEE_SAVED                # a prologue spill is not a use
            else:
                src = set(operand_regs(ops[1:] if dst else ops))
            read |= src - written
            written |= dst
    except (NameError, ImportError):
        raise
    except Exception:
        res = _ALL_REGS
    memo[target] = res
    return res


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
