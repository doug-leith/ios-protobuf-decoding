"""The enums the extractor emits for ObjC message fields against concrete runs of each field's
``-<field>AsString:`` in an emulator (Unicorn): the value -> string table the class itself
answers with.

For an enum field ``foo`` the class's ``-fooAsString:(int)v`` returns a string constant for each
value it knows (a CFString of the image) and, for any other, a formatted ``(unknown: %i)`` (a
message send, answered with nil here).  It is run with every value from 64 below the lowest
emitted value to 64 above the highest; the values that return a constant must be the enum's
values, each named for its string (the emitted name, letters and digits only, ends with the
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
    """``{value: string}`` that ``-[cls selector]`` answers with a string constant, over *values*."""
    run = Run(machine, cl, cls, _all_ivars(cl, cls))
    uc = run.uc
    imp = _method(cl, cls, selector)
    hook = machine.hook_calls(uc, run._call)
    cfstrings = _cfstring_range(machine.ctx)
    out = {}
    try:
        for v in values:
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
    finally:
        if hook is not None:
            uc.hook_del(hook)
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
        for f in msg.fields:
            if not (f.type_class or "").startswith("ENUM:"):
                continue
            sel = f.name + "AsString:"
            enum = enums.get(f.type_class[5:]) or enums.get(f.type_name)
            if _method(cl, cls, sel) is None or enum is None or not enum.values:
                report.stats["enum fields without an AsString: and values"] += 1
                continue
            report.stats["enum fields"] += 1
            nums = [v.number for v in enum.values]
            probes = range(min(nums) - PROBE_MARGIN, max(nums) + PROBE_MARGIN + 1)
            got = table(machine, cl, cls, sel, probes)
            report.stats["values run"] += len(probes)
            where = "%s.%s" % (msg.class_name, f.name)
            emitted = {v.number: v for v in enum.values}
            for n in sorted(set(got) - set(emitted)):
                report.find("a value the enum lacks", 0, "%s: %d %r" % (where, n, got[n]),
                            key=(where, n))
            for n in sorted(set(emitted) - set(got)):
                report.find("an emitted value the class does not name", 0,
                            "%s: %d %s" % (where, n, emitted[n].name), key=(where, n))
            for n in sorted(set(got) & set(emitted)):
                report.stats["values agree"] += 1
                if not _alnum(emitted[n].name).endswith(_alnum(got[n])):
                    report.stats["values agree"] -= 1
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
