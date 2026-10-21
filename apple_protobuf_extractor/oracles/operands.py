"""``reads()`` / ``writes()`` (:mod:`proto.arm64_operands`) against capstone's register-access lists
(detail mode), over an image's ``__text``.

Capstone's own errors, each checked against the architecture, are corrected in its lists before
they are compared (:data:`CAPSTONE_CORRECTIONS`: by operand, never by what we answer), so a real
error of ours in the same instruction still shows.
Calls are compared on their operands only (our ``writes()`` gives a call every caller-saved
register by design); fp16 and SVE forms, for which capstone gives no or partial detail, are not
compared.

    python -m oracles.operands BINARY | cache:CACHE@IMAGE [MAX_INSNS]"""
import collections
import re
import sys

import capstone

from macho.disasm import Insn
from proto.arm64_operands import CALLS, reads, reg_name, writes

# registers neither side tracks
_IGNORE = {"sp", "wsp", "xzr", "wzr", "nzcv", "fpcr", "fpsr", "pc", "x29"}


_COMPARES = ("cmp", "cmn", "tst", "ccmp", "ccmn", "fcmp", "fcmpe")


def _prefixes(*names):
    return lambda mn, _ops: mn.startswith(names)


def _split(op_str):
    """The operands of *op_str*, split at the commas outside brackets and braces."""
    out, depth, cur = [], 0, ""
    for ch in op_str:
        depth += ch in "[{"
        depth -= ch in "]}"
        if ch == "," and not depth:
            out.append(cur.strip())
            cur = ""
        else:
            cur += ch
    return out + [cur.strip()] if cur.strip() else out


_REG = re.compile(r"\b([xwvqdsbh]\d{1,2}|lr|fp)\b")


def _regs(text):
    return {r for r in map(_norm, _REG.findall(text)) if r}


def _dest(ops):
    return _regs(ops[0]) if ops else set()


def _sources(ops):
    return set().union(*map(_regs, ops[1:])) if len(ops) > 1 else set()


def _list(ops):
    return set().union(*(_regs(o) for o in ops if o.startswith("{")))


def _base(ops):
    return set().union(*(_regs(o) for o in ops if o.startswith("[")))


def _lse(mn, ops):
    """An LSE atomic's registers, by the architecture: ``ld<op> / swp Rs, Rt, [Xn]`` read Rs and
    Xn and write Rt; ``cas Rs, Rt, [Xn]`` reads all three and writes Rs; ``casp`` the pairs."""
    regs = [_regs(o) for o in ops]
    if mn.startswith("casp"):
        return set().union(*regs), set().union(*regs[:2])
    if mn.startswith("cas"):
        return set().union(*regs), regs[0]
    return regs[0] | _base(ops), regs[1]


# Capstone's errors, each checked against the architecture, as corrections to its lists before
# they are compared: (test of mnemonic and operands, side, the registers it should list and does
# not, those it lists and should not).  A correction names operands, never what we answer, so an
# error of ours in the same instruction still shows.
CAPSTONE_CORRECTIONS = [
    # flag-setting compares: capstone "writes" their first operand instead of reading it
    (lambda mn, _ops: mn in _COMPARES, "R", _dest, None),
    (lambda mn, _ops: mn in _COMPARES, "W", None, _dest),
    # shifts, extends, bitfield moves and immediate moves: capstone "reads" their destination
    # (where it is not also a source)
    (lambda mn, _ops: mn in ("lsr", "lsl", "asr", "ror", "ubfx", "sbfx", "ubfiz", "sbfiz", "sxtb",
                       "sxth", "sxtw", "uxtb", "uxth", "fmov", "movi", "mvni", "adds", "ushr",
                       "tbl", "umov"), "R", None, lambda ops: _dest(ops) - _sources(ops)),
    # ...and two of them it does not list as written
    (lambda mn, _ops: mn in ("adds", "umov"), "W", _dest, None),
    # multi-register loads and stores: capstone has the register list on the wrong side (a lane
    # load reads its list too)
    (_prefixes("ld1", "ld2", "ld3", "ld4"), "R", None,
     lambda ops: set() if any("}[" in o for o in ops) else _list(ops)),
    (_prefixes("ld1", "ld2", "ld3", "ld4"), "W", _list, None),
    (_prefixes("st1", "st2", "st3", "st4"), "R", _list, None),
    (_prefixes("st1", "st2", "st3", "st4"), "W", None, _list),
    # tbl / tbx read the table (the list) and the index (the last operand)
    (lambda mn, _ops: mn in ("tbl", "tbx"), "R", lambda ops: _list(ops) | _regs(ops[-1]), None),
    # pointer-authenticated loads: the loaded register is omitted
    (lambda mn, _ops: mn in ("ldraa", "ldrab"), "W", _dest, None),
    # MTE tag stores: capstone omits the tag register
    (lambda mn, _ops: mn in ("stg", "stzg", "st2g", "stz2g", "stgp"), "R", _dest, None),
    # a bare ret reads x30
    (lambda mn, ops: mn in ("ret", "retaa", "retab") and not ops, "R", lambda _ops: {"x30"}, None),
    # LSE atomics: capstone omits the value read (Rs, and CAS's compared Rt) and the loaded Rt
    (_prefixes("ldadd", "ldclr", "ldeor", "ldset", "ldsmax", "ldsmin", "ldumax", "ldumin", "swp",
               "cas"), "LSE", None, None),
    # a halfword lane read (umov w8, v0.h[0]) and the vector bic's sources: capstone omits them
    (lambda mn, ops: mn == "umov" and ".h[" in ",".join(ops), "R", _sources, None),
    (lambda mn, ops: mn == "bic" and ops[0].startswith("v"), "R", _sources, None),
    # ...and the destination the vector orr / bic of an immediate changes (Vd = Vd | imm)
    (lambda mn, ops: mn in ("orr", "bic") and ops[0].startswith("v") and len(ops) > 1 and
     ops[1].startswith("#"), "R", _dest, None),
    # pacia1716 / autia1716 ...: x16 is the modifier, read only
    (lambda mn, _ops: mn.endswith("1716"), "R", lambda _ops: {"x16"}, None),
    (lambda mn, _ops: mn.endswith("1716"), "W", None, lambda _ops: {"x16"}),
]


def _norm(name):
    n = {"lr": "x30", "fp": "x29"}.get(name.lower(), name.lower())
    if n in _IGNORE:
        return None
    r = reg_name(n)
    return r if r and r not in ("sp", "xzr") else None


def _not_compared(mn, op_str):
    return ("{z" in op_str or " z" in op_str or op_str.startswith("z") or
            (mn.startswith("f") and (".8h" in op_str or ".4h" in op_str or
                                     re.search(r"\bh\d", op_str))))


def corrected(mn, op_str, cap):
    """Capstone's ``{"R": ..., "W": ...}`` for one instruction with its known errors corrected."""
    ops = _split(op_str)
    cap = {k: set(v) for k, v in cap.items()}
    for test, side, add, remove in CAPSTONE_CORRECTIONS:
        if not test(mn, ops):
            continue
        if side == "LSE":
            cap["R"], cap["W"] = _lse(mn, ops)
            continue
        if remove:
            cap[side] -= remove(ops)
        if add:
            cap[side] |= add(ops)
    return cap


def compare(ctx, limit=None):
    """``(instructions compared, Counter{(side, mnemonic, missing, extra): count}, examples)`` of
    the differences capstone's known errors do not explain, over *ctx*'s ``__text``."""
    text = ctx.section("__TEXT", "__text")
    data = ctx.read_bytes(text.vmaddr, text.vmsize)
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    md.detail = True
    diffs, examples = collections.Counter(), {}
    n = off = 0
    while off < len(data) and (limit is None or n < limit):
        decoded = False
        for ci in md.disasm(data[off:off + 4096], text.vmaddr + off):
            decoded = True
            off = ci.address + 4 - text.vmaddr
            mn, ops = ci.mnemonic, ci.op_str
            if _not_compared(mn, ops):
                continue
            try:
                cr, cw = ci.regs_access()
            except capstone.CsError:
                continue
            n += 1
            ins = Insn(addr=ci.address, mnemonic=mn, op_str=ops, size=4, raw=bytes(ci.bytes))
            cap = {"R": {x for x in map(_norm, map(ci.reg_name, cr)) if x},
                   "W": {x for x in map(_norm, map(ci.reg_name, cw)) if x}}
            ours = {"R": set(reads(ins)) - {"x29"}, "W": set(writes(ins)) - {"x29"}}
            if mn in CALLS:
                cap["W"] = ours["W"] = set()
            cap = corrected(mn, ops, cap)
            for side in ("R", "W"):
                missing, extra = cap[side] - ours[side], ours[side] - cap[side]
                if missing or extra:
                    key = (side, mn, tuple(sorted(missing)), tuple(sorted(extra)))
                    diffs[key] += 1
                    examples.setdefault(key, "%#x: %s %s" % (ci.address, mn, ops))
            if limit is not None and n >= limit:
                break
        if not decoded:
            off += 4                                    # an undecodable word
    return n, diffs, examples


def main(argv):
    if argv[0].startswith("cache:"):
        from macho.dyld_cache import DyldCacheReader
        from macho.load import load_cache_image
        cache, image = argv[0][6:].split("@")
        r = DyldCacheReader(cache)
        ctx = load_cache_image(r, r.find_image_header(image)).ctx
    else:
        from macho.memory import BinaryContext
        from serializers.swift_descriptor_extract import load_macho_slice
        ctx = BinaryContext(load_macho_slice(open(argv[0], "rb").read()))
    n, diffs, examples = compare(ctx, int(argv[1]) if len(argv) > 1 else None)
    print("instructions", n, "unexplained differences", sum(diffs.values()))
    for key, count in diffs.most_common(40):
        side, _mn, missing, extra = key
        print("  %7d  %s  %-44s missing=%s extra=%s" % (count, side, examples[key][:44],
                                                         list(missing), list(extra)))


if __name__ == "__main__":
    main(sys.argv[1:])
