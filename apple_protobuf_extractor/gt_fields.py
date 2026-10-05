"""Independent field-number/type oracle for proto writeTo: methods.

A deliberately SIMPLE linear scan (NOT the production CFG-walk decoder), used
for differential ground-truthing.  For each PB-writer call site in writeTo: it
records the field number (the `mov w2,#imm` feeding arg2) and the ivar whose
value is being written (resolved through the cache's indirect ivar-offset
globals: `adrp/ldrsw x8,[x8,#G]; ldr w?,[self,x8]`).

Output: one line per field, `#<num> <ivar> <load-width> helper=0x..`, sorted by
number.  Disagreement with the tool, or any control flow this linear scan can't
follow (jump tables / compare chains), is the signal to drill into gt_dump.py
and read the assembly by hand.

Usage:
    ../venv/bin/python3 gt_fields.py <framework> <ClassName>
    ../venv/bin/python3 gt_fields.py <framework> --all       # every proto class
"""
import sys

from macho.dyld_cache import DyldCacheReader
from macho.memory import BinaryContext
from macho.strings import build_string_table
from macho import classlist as CL
from macho.local_symbols import apply_to_classes
from macho import disasm
import proto.extractor as E

import artifacts
CACHE = artifacts.cache_file()


def load(fw):
    reader = DyldCacheReader(CACHE)
    mv = reader.find_image_header(fw)
    ctx = BinaryContext.from_cache(reader, mv)
    st = build_string_table(ctx)
    cl = CL.build_class_list(ctx, st)
    syms = reader.image_local_symbols(mv)
    if syms:
        apply_to_classes(cl, syms)
    return ctx, st, cl


def _ivar_by_offset(c):
    return {iv.offset: iv for iv in c.ivars}


def fields_of(ctx, c, imp_bounds=None):
    """Return list of (number, ivar_name, width, helper_va) for writeTo:.

    ``imp_bounds`` is a sorted list of ALL method IMPs in the image; the writeTo:
    disassembly is capped at the next IMP so the scan never bleeds into adjacent
    methods (whose `mov w2,#imm` would masquerade as field numbers).  Mirrors the
    tool's own next-IMP extent bound."""
    m = c.get_method("writeTo:")
    if m is None:
        return None
    ivmap = _ivar_by_offset(c)
    n = 2000
    if imp_bounds:
        import bisect
        i = bisect.bisect_right(imp_bounds, m.imp)
        if i < len(imp_bounds):
            n = max(4, (imp_bounds[i] - m.imp) // 4)
    insns = disasm.disasm(ctx, m.imp, n, stop_at_ret=False)
    adrp = {}          # reg -> page
    offreg = {}        # reg -> resolved ivar offset (from ldrsw of a global)
    valreg_ivar = {}   # reg -> ivar name (a value loaded from an ivar)
    valreg_width = {}  # reg -> 'w'/'x'/'b'/'h'/'d'/'s'
    # Two PB-writer calling conventions:
    #   GPR  field (int/string/bool/msg): value in x1/w1, field# in w2.
    #   FP   field (float/double):        value in s0/d0, field# in w1.
    # So `mov w1,#imm` (with an FP value loaded) marks an FP field; `mov w2,#imm`
    # marks a GPR field.  Track both and pick by which immediate is live at the call.
    w1 = w2 = None
    fp_ivar = fp_w = None   # last s0/d0 ivar load (the FP field's backing ivar)
    # S1 hoist: an FP value loaded into a CALLEE-SAVED reg (d8-d15/s8-s15) BEFORE
    # the writer-init bl, then `fmov d0,d8` just before the write.  The init bl
    # clears fp_ivar, so remember callee-saved FP loads here (they survive the
    # call) and restore fp_ivar on the fmov.
    _CALLEE_FP = frozenset([f"d{i}" for i in range(8, 16)]
                           + [f"s{i}" for i in range(8, 16)])
    fp_callee = {}          # callee-saved fp reg -> (ivar_name, width)
    out = []

    def _ivar_load(rt, off):
        iv = ivmap.get(off)
        nm = iv.name if iv else f"+0x{off:x}"
        valreg_ivar[rt] = nm
        if rt.startswith(("d", "s")):
            valreg_width[rt] = "d" if rt.startswith("d") else "s"
            if rt in _CALLEE_FP:                 # remember for the S1 fmov restore
                fp_callee[rt] = (nm, valreg_width[rt])
        else:
            valreg_width[rt] = "x" if rt.startswith("x") else "w"
        return nm, valreg_width[rt]

    for ins in insns:
        mn, op = ins.mnemonic, ins.op_str
        if mn == "adrp":
            try:
                rd, pg = op.split(", "); adrp[rd.strip()] = int(pg.lstrip("#"), 16)
            except Exception:
                pass
            continue
        if mn == "fmov":                         # S1 hoist: fmov d0,d8 / s0,s8
            parts = [p.strip() for p in op.split(",")]
            if (len(parts) == 2 and parts[0] in ("d0", "s0")
                    and parts[1] in fp_callee):
                fp_ivar, fp_w = fp_callee[parts[1]]
            continue
        if mn in ("ldrsw", "ldr") and "[" not in op and "#" in op:
            # binary-mode PC-relative literal: `ldrsw xT, #ADDR` loads the ivar
            # byte-offset straight from the literal pool (the cache form is
            # adrp+ldrsw[base,#G]).  The immediate IS the offset-variable address.
            parts = [p.strip() for p in op.split(",")]
            if len(parts) == 2 and parts[1].startswith("#"):
                rt = parts[0]
                try:
                    offreg[rt] = ctx.read_u32(int(parts[1].lstrip("#"), 16))
                except Exception:
                    pass
                valreg_ivar.pop(rt, None)
            continue
        if mn in ("ldrsw", "ldr") and "[" in op:
            rt = op.split(",")[0].strip()
            inside = op[op.index("[")+1:op.index("]")]
            parts = [p.strip() for p in inside.split(",")]
            base = parts[0]
            # global ivar-offset load:  ldrsw xT,[xBase,#G]  (xBase from adrp)
            if mn == "ldrsw" and base in adrp and len(parts) > 1 and "#" in parts[1]:
                g = int(parts[1].replace("#", ""), 16)
                try:
                    off = ctx.read_u32(adrp[base] + g)
                except Exception:
                    off = None
                if off is not None:
                    offreg[rt] = off
                valreg_ivar.pop(rt, None)
                continue
            # value load from ivar:  ldr {w,x,d,s}T,[self, xOff]  (xOff in offreg)
            if len(parts) > 1 and parts[1] in offreg:
                nm, w = _ivar_load(rt, offreg[parts[1]])
                if rt.startswith(("d", "s")):
                    fp_ivar, fp_w = nm, w
                continue
            # direct ivar load:  ldr {w,x,d,s}T,[self,#imm]
            if len(parts) > 1 and "#" in parts[1]:
                off = int(parts[1].replace("#", ""), 16)
                if off in ivmap:
                    nm, w = _ivar_load(rt, off)
                    if rt.startswith(("d", "s")):
                        fp_ivar, fp_w = nm, w
            continue
        if mn in ("ldrb", "ldrh") and "[" in op:
            rt = op.split(",")[0].strip()
            inside = op[op.index("[")+1:op.index("]")]
            parts = [p.strip() for p in inside.split(",")]
            if len(parts) > 1 and parts[1] in offreg:
                iv = ivmap.get(offreg[parts[1]])
                valreg_ivar[rt] = iv.name if iv else "?"
                valreg_width[rt] = "b" if mn == "ldrb" else "h"
            continue
        if mn in ("mov", "movz") and op.startswith("w1,"):
            try:
                w1 = int(op.split(", ")[1].replace("#", ""), 0)
            except Exception:
                w1 = None
            continue
        if mn in ("mov", "movz") and op.startswith("w2,"):
            try:
                w2 = int(op.split(", ")[1].replace("#", ""), 0)
            except Exception:
                w2 = None
            continue
        if mn in ("bl", "b") and (op.startswith("0x") or op.startswith("#0x")):
            tgt = int(op.lstrip("#"), 16)
            # Valid proto field numbers are 1..2^29-1; the helper sentinels
            # 0 (no number) and -1/0xffffffff (write raw, no tag — packed element)
            # are NOT fields, so require a positive, in-range immediate.
            def _valid(v):
                return v is not None and 1 <= v < (1 << 29)
            # FP field: an s0/d0 value was loaded and field# is the w1 immediate.
            if fp_ivar is not None and _valid(w1):
                out.append((w1, fp_ivar, fp_w, tgt))
            # GPR field: field# is the w2 immediate; value came from x1/w1.
            elif _valid(w2):
                cand = valreg_ivar.get("w1") or valreg_ivar.get("x1") \
                    or (list(valreg_ivar.values())[-1] if valreg_ivar else None)
                width = valreg_width.get("w1") or valreg_width.get("x1") or "?"
                out.append((w2, cand, width, tgt))
            w1 = w2 = None
            fp_ivar = fp_w = None
            continue
    # dedupe by (number,helper) — numbers + helper VA are the reliable signals;
    # ivar name from this linear scan is best-effort only.
    seen = {}
    for num, iv, w, h in out:
        seen.setdefault((num, h), (num, iv, w, h))
    return sorted(seen.values(), key=lambda t: (t[0], t[3]))


def all_imp_bounds(cl):
    imps = set()
    for c in cl:
        for m in c.methods:
            if m.imp:
                imps.add(m.imp)
    return sorted(imps)


def main():
    fw = sys.argv[1]
    ctx, st, cl = load(fw)
    bounds = all_imp_bounds(cl)
    if len(sys.argv) > 2 and sys.argv[2] == "--all":
        classes = [c for c in cl if not c.is_meta and E._is_proto_class(c)
                   and c.get_method("writeTo:")]
        classes.sort(key=lambda c: c.name)
    else:
        classes = [cl.find(sys.argv[2])]
    for c in classes:
        if c is None:
            print("class not found"); continue
        fs = fields_of(ctx, c, bounds)
        print(f"\n== {c.name} ==")
        if fs is None:
            print("  (no writeTo:)"); continue
        for num, iv, w, h in fs:
            print(f"  #{num:<5d} {str(iv):32s} {w}  helper=0x{h:x}")


if __name__ == "__main__":
    main()
