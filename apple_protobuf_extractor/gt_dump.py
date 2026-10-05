"""Independent ground-truth dump for a single ObjC proto class.

Disassembles writeTo:/readFrom: with raw capstone (macho.disasm.disasm) and
symbolizes the call stream WITHOUT reusing proto/writeto.py's field-decoding
logic.  Symbolication is generic disassembly only:
  * adrp+ldr from __objc_selrefs   -> selector cstring  (=> PB writer => wire type)
  * adrp+add to a classref/cstring -> name
  * ldr [self/x0, #off]            -> ivar name (from the class ivar table)
  * mov/movz w2,#imm               -> candidate field NUMBER (arg2 of PB writer)

Read the output BY HAND to establish ground truth, then compare to the tool's
emitted .proto.  Independent of the production decoder by construction.

Usage:
    ../venv/bin/python3 gt_dump.py <framework> <ClassName> [writeTo:|readFrom:] [n_insns]
"""
import sys

from macho import disasm
from gt_fields import load   # shared cache→(ctx, st, cl) loader (was duplicated here)


def _cstr(ctx, va):
    try:
        s = ctx.read_cstring(va)
        return s
    except Exception:
        return None


def dump(fw, clsname, sel="writeTo:", n=400):
    ctx, st, cl = load(fw)
    c = cl.find(clsname)
    if c is None:
        print(f"class {clsname} not found"); return
    ivars = {iv.offset: iv.name for iv in c.ivars}
    print(f"# {fw} :: {clsname} :: {sel}")
    print("# ivars:")
    for iv in c.ivars:
        print(f"#   +0x{iv.offset:<4x} {iv.name:30s} {iv.type_enc}")
    m = c.get_method(sel)
    if m is None:
        print(f"# (no {sel})"); return
    insns = disasm.disasm(ctx, m.imp, n, stop_at_ret=False)
    # track adrp page values per reg for selref/cstring resolution
    adrp = {}
    last_imm = {}  # reg -> imm (for mov)
    for ins in insns:
        ann = ""
        op = ins.op_str
        mn = ins.mnemonic
        if mn == "adrp":
            try:
                rd, pg = op.split(", ")
                adrp[rd.strip()] = int(pg, 16)
            except Exception:
                pass
        elif mn in ("ldr", "ldrsw") and "[" in op:
            # ldr xT, [xN, #off]  -- selref (global) or ivar (self/x0/x19...)
            try:
                rt = op.split(",")[0].strip()
                inside = op[op.index("[")+1:op.index("]")]
                parts = [p.strip() for p in inside.split(",")]
                base = parts[0]
                off = int(parts[1].replace("#", ""), 16) if len(parts) > 1 else 0
                if base in adrp:
                    tgt = adrp[base] + off
                    ptr = None
                    try:
                        ptr = ctx.read_ptr(tgt)
                    except Exception:
                        pass
                    s = _cstr(ctx, ptr) if ptr else None
                    if s:
                        ann = f"  ; SEL/str={s!r}"
                        last_imm[rt] = ("sel", s)
                elif off in ivars:
                    ann = f"  ; ivar {ivars[off]}"
            except Exception:
                pass
        elif mn in ("mov", "movz") and op.startswith("w"):
            try:
                rd, imm = op.split(", ")
                if imm.startswith("#"):
                    v = int(imm[1:], 0)
                    ann = f"  ; #{v}"
                    last_imm[rd.strip()] = v
            except Exception:
                pass
        elif mn in ("bl", "b") and op.startswith("0x"):
            tgt = int(op, 16)
            # resolve a branch target name via local symbols / class methods
            nm = _branch_name(ctx, cl, tgt)
            if nm:
                ann = f"  ; -> {nm}"
        print(f"  0x{ins.addr:x}: {mn:8s} {op}{ann}")


def _branch_name(ctx, cl, va):
    # try: is it an IMP of a known method?  cheap reverse map omitted; resolve via
    # cache local symbol table if available on the reader.
    nm = getattr(ctx, "symbol_for_addr", None)
    if callable(nm):
        try:
            return ctx.symbol_for_addr(va)
        except Exception:
            return None
    return None


if __name__ == "__main__":
    fw = sys.argv[1]
    cls = sys.argv[2]
    sel = sys.argv[3] if len(sys.argv) > 3 else "writeTo:"
    n = int(sys.argv[4]) if len(sys.argv) > 4 else 400
    dump(fw, cls, sel, n)
