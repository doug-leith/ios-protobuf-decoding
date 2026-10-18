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

A function of the image itself (not exported) has no name here: None.

This module is the one owner of call naming; the writeTo: walk, the writer flow, the map and
struct decoders and the readFrom: evaluator each used to keep their own copy, with different
rules for the same stub shape (code review 2026-10-18).
"""
from __future__ import annotations

from typing import Dict, Optional, Tuple

from macho.disasm import disasm, _norm_reg, _parse_imm
from macho.memory import BinaryContext, _ctx_cache
from proto.arm64_operands import parse_mem, split_ops
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
                from proto.write_helpers import _helper_real_target   # (import cycle via writeto)
                name = reader.export_name_at(va)
                if name is None:
                    real = _helper_real_target(ctx, va)
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


def import_name(ctx, va: Optional[int]) -> Optional[str]:
    """Symbol a standalone binary's call stub at *va* imports (``adrp x16; ldr x16,[x16,#o];
    br x16`` -- or the ``add`` + ``ldr [x17]`` + ``braa`` form -- through a GOT slot the binary
    binds by name), or None.  Memoised on *ctx*."""
    if not va:
        return None
    memo = _ctx_cache(ctx, "_import_names", dict)
    if va in memo:
        return memo[va]
    name = None
    try:
        ins = disasm(ctx, va, max_insns=4, stop_at_ret=False)
        page = _adrp(ins[0]) if ins else None
        if page is not None:
            reg, addr = page
            for i in ins[1:]:
                ops = split_ops(i.op_str)
                if i.mnemonic == 'add' and len(ops) == 3 and _norm_reg(ops[1]) == reg:
                    addr += int(ops[2].lstrip('#'), 0)
                elif i.mnemonic == 'ldr' and len(ops) == 2 and '[' in ops[1]:
                    pm = parse_mem(ops[1])
                    if pm is not None and pm.base == reg and pm.index is None:
                        name = ctx.bind_name_for(addr + pm.disp)
                    break
    except (NameError, ImportError):
        raise
    except Exception:                               # bytes that are not a stub: no name
        name = None
    memo[va] = name
    return name


def stub_selector(ctx, va: Optional[int]) -> Optional[str]:
    """Selector the objc message stub at *va* sends, or None (not a message stub).  The
    linker emits one stub per selector a binary messages, in one of two forms::

        adrp  x1, <page>
        ldr   x1, [x1, #off]      ; the __objc_selrefs slot -> x1 = the selector
        ... ; br x16              ; to objc_msgSend

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
                and any(i.mnemonic == 'br' for i in ins[2:]):
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
for _name in ("_objc_opt_class", "_objc_opt_isKindOfClass", "_objc_opt_respondsToSelector"):
    RUNTIME_CONTRACTS[_name] = (("x0", "x1"), None)

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
