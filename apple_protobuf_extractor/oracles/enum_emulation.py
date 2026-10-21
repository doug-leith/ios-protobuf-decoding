"""The enums the extractor emits for ObjC message fields against concrete runs of each field's
``-<field>AsString:`` in an emulator (Unicorn): the value -> string table the class itself
answers with.

For an enum field ``foo`` the class's ``-fooAsString:(int)v`` returns a string constant for each
value it knows (a CFString of the image) and, for any other, a formatted ``(unknown: %i)`` (a
message send, answered with nil here).  Every ``AsString:`` method of a message's class is run --
its field must be emitted as an enum -- with each emitted value and its neighbours, every value
from 64 below the lowest to 64 above the highest (from 64 about each when that is too many), and
then the values its own compares test against: a register holding the value plus c (the same c
in two runs) compared with y gives y - c and its neighbours, a bound n under 256 also -c .. n - c
(a jump table's).  The values that return a constant must be the enum's values,
each named for its string (the emitted name's last words, letters and digits only, are the
string's: ``kOverrideActionNone`` -> ``..._K_OVERRIDE_ACTION_NONE``).

    python -m oracles.enum_emulation BINARY"""
import re
import struct
import sys

from unicorn import UcError, UC_HOOK_CODE
from unicorn import arm64_const as A

from oracles.flow_emulation import RET_SENTINEL, Report, make_machine
from oracles.writer_emulation import SELF, Run, _all_ivars, _method

PROBE_MARGIN = 64
MAX_PROBES = 4096                      # (a bound no enum table reaches: each probe is a run)
_COMPARES = ("cmp", "cmn", "subs", "adds", "ccmp", "ccmn")


def _cfstring(uc, va):
    """The text of the CFString at *va* (``isa, flags, chars, length``), from the run's memory."""
    try:
        _isa, flags, chars, length = struct.unpack("<QQQQ", bytes(uc.mem_read(va, 32)))
        if not 0 < length < 4096:
            return None
        wide = bool(flags & 0x10)               # 0x7d0: UTF-16; 0x7c8: 8-bit
        raw = bytes(uc.mem_read(chars, length * (2 if wide else 1)))
        return raw.decode("utf-16-le" if wide else "latin-1")
    except (UcError, struct.error, UnicodeDecodeError):
        return None


def table(machine, cl, cls, selector, values):
    """``{value: string}`` that ``-[cls selector]`` answers with a string constant, over *values*
    and the values its compares test (above), until no run finds another."""
    import capstone
    run = Run(machine, cl, cls, _all_ivars(cl, cls))
    uc = run.uc
    imp = _method(cl, cls, selector)
    hook = machine.hook_calls(uc, run._call)
    cs = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    decoded, wanted, current, offsets = {}, [], [0], {}
    reg = lambda name: uc.reg_read(getattr(A, "UC_ARM64_REG_" + name.upper()))

    def on_code(uc_, address, size, _data):
        ins = decoded.get(address)
        if ins is None:
            ins = decoded[address] = next(cs.disasm(bytes(uc_.mem_read(address, 4)), address), False)
        if not ins or ins.mnemonic not in _COMPARES:
            return
        ops = [o.strip() for o in ins.op_str.split(",")]
        if ins.mnemonic in ("subs", "adds"):
            ops = ops[1:]
        try:
            bits = 32 if ops[0].startswith("w") else 64
            x = reg(ops[0])
            y = int(ops[1].lstrip("#"), 0) if ops[1].startswith("#") else reg(ops[1])
        except (AttributeError, ValueError, IndexError):
            return                              # (a shifted or extended operand: not a bound)
        if ins.mnemonic in ("cmn", "adds", "ccmn"):
            y = -y
        mask = (1 << bits) - 1
        c = ((x - current[0]) & mask)
        c = c - (1 << bits) if c >> (bits - 1) else c
        y = y & mask
        y = y - (1 << bits) if y >> (bits - 1) and bits == 32 else y
        first = offsets.setdefault(address, (c, current[0]))
        if first[0] != c or first[1] == current[0]:
            return                              # the value plus c: only once two values say so
        wanted.extend((y - c - 1, y - c, y - c + 1))
        if 0 <= y < 256:                        # an unsigned bound: every value under it
            wanted.extend(range(-c, y - c + 2))

    code_hook = uc.hook_add(UC_HOOK_CODE, on_code)
    cfstrings = _cfstring_range(machine.ctx)
    out, done = {}, set()
    todo = list(values)
    try:
        while todo and len(done) < MAX_PROBES:
            v = todo.pop(0)
            if v in done or not -(1 << 31) <= v < (1 << 31):
                continue
            done.add(v)
            current[0] = v
            uc.reg_write(A.UC_ARM64_REG_X0, SELF)
            uc.reg_write(A.UC_ARM64_REG_X2, v & ((1 << 64) - 1))
            uc.reg_write(A.UC_ARM64_REG_X30, RET_SENTINEL)
            uc.reg_write(A.UC_ARM64_REG_SP, 0x7f0000038000)
            try:
                uc.emu_start(imp, RET_SENTINEL, count=20_000)
            except UcError:
                continue
            x0 = uc.reg_read(A.UC_ARM64_REG_X0)
            if uc.reg_read(A.UC_ARM64_REG_PC) == RET_SENTINEL and cfstrings and \
                    cfstrings[0] <= x0 < cfstrings[1]:
                s = _cfstring(uc, x0)
                if s is not None:
                    out[v] = s
            todo.extend(w for w in wanted if w not in done)
            del wanted[:]
    finally:
        uc.hook_del(code_hook)
        if hook is not None:
            uc.hook_del(hook)
    table.probes = len(done)
    return out


def _cfstring_range(ctx):
    try:
        sec = ctx.section("__DATA", "__cfstring")
    except KeyError:
        try:
            sec = ctx.section("__DATA_CONST", "__cfstring")
        except KeyError:
            return None
    return sec.vmaddr, sec.vmaddr + sec.vmsize


def _alnum(s):
    return re.sub(r"[^0-9a-z]", "", s.lower())


def _as_string_methods(cl, cls):
    """``{field name: selector}`` of the ``-<field>AsString:`` methods of *cls* and its superclasses
    in the image."""
    out, c = {}, cls
    while c is not None and not c.is_meta:
        for m in c.methods:
            if m.name.endswith("AsString:") and len(m.name) > len("AsString:"):
                out.setdefault(m.name[:-len("AsString:")], m.name)
        c = cl.find(c.superclass_name) if c.superclass_name else None
    return out


def _named_for(name, string):
    """The emitted value *name*'s last words (``_``-separated), letters and digits only, are
    *string*'s."""
    want, words = _alnum(string), name.lower().split("_")
    return bool(want) and any(_alnum("".join(words[i:])) == want for i in range(len(words)))


def compare(ctx, st, cl, messages=None, report=None):
    from proto import extractor as E
    report = report or Report()
    machine = make_machine(ctx)
    msgs = messages if messages is not None else E.extract_all(ctx, st, cl)
    for msg in msgs:
        cls = cl.find(msg.class_name)
        if cls is None:
            continue
        enums = {e.name: e for e in msg.enums}
        fields = {f.name: f for f in msg.fields}
        for name, sel in sorted(_as_string_methods(cl, cls).items()):
            f = fields.get(name)
            where = "%s.%s" % (msg.class_name, name)
            if f is None:
                report.stats["AsString: methods of no emitted field"] += 1
                continue
            if not (f.type_class or "").startswith("ENUM:"):
                report.find("a field with an AsString: not emitted as an enum", 0,
                            "%s: %s" % (where, f.type_name), key=where)
                continue
            enum = enums.get(f.type_class[5:]) or enums.get(f.type_name)
            if enum is None:
                report.find("an enum field whose enum is not emitted", 0,
                            "%s: %s" % (where, f.type_class), key=where)
                continue
            report.stats["enum fields"] += 1
            nums = [v.number for v in enum.values] or [0]
            lo, hi = min(nums) - PROBE_MARGIN, max(nums) + PROBE_MARGIN
            probes = [n + d for n in nums for d in (-1, 0, 1)] + (
                list(range(lo, hi + 1)) if hi - lo < MAX_PROBES // 2 else
                list(range(lo, lo + 2 * PROBE_MARGIN)) + list(range(hi - 2 * PROBE_MARGIN, hi + 1)))
            got = table(machine, cl, cls, sel, probes)
            report.stats["values run"] += table.probes
            emitted = {v.number: v for v in enum.values}
            for n in sorted(set(got) - set(emitted)):
                report.find("a value the enum lacks", 0, "%s: %d %r" % (where, n, got[n]),
                            key=(where, n))
            for n in sorted(set(emitted) - set(got)):
                report.find("an emitted value the class does not name", 0,
                            "%s: %d %s" % (where, n, emitted[n].name), key=(where, n))
            for n in sorted(set(got) & set(emitted)):
                if _named_for(emitted[n].name, got[n]):
                    report.stats["values agree"] += 1
                else:
                    report.find("a value named for another string", 0,
                                "%s: %d %s, the class says %r" % (where, n, emitted[n].name, got[n]),
                                key=(where, n))
    return report


def main(argv):
    from macho.memory import BinaryContext
    from serializers.swift_descriptor_extract import load_macho_slice
    from macho.load import load_classes
    with open(argv[0], "rb") as fh:
        img = load_classes(BinaryContext(load_macho_slice(fh.read())))
    rep = compare(img.ctx, img.st, img.cl)
    print(dict(rep.stats))
    for kind, rows in rep.findings.items():
        print("==", kind, rep.stats[kind])
        for row in rows[:15]:
            print("   ", row[1])


if __name__ == "__main__":
    main(sys.argv[1:])
