"""``reads()`` / ``writes()`` (:mod:`proto.arm64_operands`) against capstone's register-access lists
(detail mode), over an image's ``__text``.

Capstone's own errors, each checked against the architecture, are allowed for narrowly -- which
side (read / write), which direction (capstone lists a register we do not, or we list one it
does not) and which operand -- so a real error of ours in the same instruction still shows.
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


# (test of mnemonic and operands, side, direction, operand): capstone's error on that side -- "missing" a register
# it lists and we do not, "extra" one we list and it does not -- confined to *operand*: "dest"
# (the first operand's registers), "last" (the last operand's), "list" (a {...} register list's),
# "all", or a register name.
CAPSTONE_ERRORS = [
    # flag-setting compares: capstone "writes" their first operand instead of reading it
    (lambda mn, _ops: mn in _COMPARES, "W", "missing", "dest"),
    (lambda mn, _ops: mn in _COMPARES, "R", "extra", "dest"),
    # shifts, extends, bitfield moves and immediate moves: capstone "reads" their destination
    (lambda mn, _ops: mn in ("lsr", "lsl", "asr", "ror", "ubfx", "sbfx", "ubfiz", "sbfiz", "sxtb",
                       "sxth", "sxtw", "uxtb", "uxth", "fmov", "movi", "mvni", "adds", "ushr",
                       "tbl", "umov"), "R", "missing", "dest"),
    # ...and two of them it does not list as written
    (lambda mn, _ops: mn in ("adds", "umov"), "W", "extra", "dest"),
    # multi-register loads and stores: capstone lists only some of the register list
    (_prefixes("ld1", "ld2", "ld3", "ld4"), "R", "missing", "list"),
    (_prefixes("ld1", "ld2", "ld3", "ld4"), "W", "extra", "list"),
    (_prefixes("st1", "st2", "st3", "st4"), "R", "extra", "list"),
    (_prefixes("st1", "st2", "st3", "st4"), "W", "missing", "list"),
    (lambda mn, _ops: mn == "tbl" or mn == "tbx", "R", "extra", "list"),
    # ...and with a four-register table, tbl's index register too
    (lambda mn, _ops: mn == "tbl" or mn == "tbx", "R", "extra", "last"),
    # pointer-authenticated loads: the loaded register is omitted
    (lambda mn, _ops: mn in ("ldraa", "ldrab"), "W", "extra", "dest"),
    # MTE tag stores: capstone omits the tag register
    (lambda mn, _ops: mn in ("stg", "stzg", "st2g", "stz2g", "stgp"), "R", "extra", "dest"),
    # returns read x30
    (lambda mn, _ops: mn in ("ret", "retaa", "retab"), "R", "extra", "x30"),
    # LSE atomics: capstone omits the value read (Rs, and CAS's compared Rt) and the loaded Rt
    (_prefixes("ldadd", "ldclr", "ldeor", "ldset", "ldsmax", "ldsmin", "ldumax", "ldumin", "swp",
               "cas"), "R", "extra", "all"),
    (_prefixes("ldadd", "ldclr", "ldeor", "ldset", "ldsmax", "ldsmin", "ldumax", "ldumin", "swp",
               "cas"), "W", "extra", "all"),
    # a halfword lane read (umov w8, v0.h[0]) and the vector bic's Vm: capstone omits the source
    (lambda mn, ops: mn == "umov" and ".h[" in ops, "R", "extra", "all"),
    (lambda mn, ops: mn == "bic" and ops.startswith("v"), "R", "extra", "all"),
    # pacia1716 / autia1716 ...: x16 is the modifier, read only
    (lambda mn, _ops: mn.endswith("1716"), "R", "extra", "x16"),
    (lambda mn, _ops: mn.endswith("1716"), "W", "missing", "x16"),
]


def _norm(name):
    n = {"lr": "x30", "fp": "x29"}.get(name.lower(), name.lower())
    if n in _IGNORE:
        return None
    r = reg_name(n)
    return r if r and r not in ("sp", "xzr") else None


def _operand_regs(op_str, which):
    if which == "all":
        return None
    if which.startswith(("x", "v")) and which[1:].isdigit():
        return {which}
    if which == "list":
        m = re.search(r"\{([^}]*)\}", op_str)
        return {r for r in (_norm(t.strip().split(".")[0]) for t in m.group(1).split(","))
                if r} if m else set()
    if which == "last":
        last = re.sub(r"\{[^}]*\}", "", op_str).rsplit(",", 1)[-1].strip()
        return {r for r in (_norm(last.split(".")[0]),) if r}
    first = op_str.split(",", 1)[0].strip()
    return {r for r in (_norm(first.strip("{}").split(".")[0]),) if r}


def _not_compared(mn, op_str):
    return ("{z" in op_str or " z" in op_str or op_str.startswith("z") or
            (mn.startswith("f") and (".8h" in op_str or ".4h" in op_str or
                                     re.search(r"\bh\d", op_str))))


def _unexplained(mn, op_str, side, diff, direction):
    """*diff* less what capstone's known errors on that side and direction explain."""
    left = set(diff)
    for test, s, d, which in CAPSTONE_ERRORS:
        if s == side and d == direction and test(mn, op_str):
            regs = _operand_regs(op_str, which)
            left = set() if regs is None else left - regs
    return left


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
            for side in ("R", "W"):
                missing = _unexplained(mn, ops, side, cap[side] - ours[side], "missing")
                extra = _unexplained(mn, ops, side, ours[side] - cap[side], "extra")
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
