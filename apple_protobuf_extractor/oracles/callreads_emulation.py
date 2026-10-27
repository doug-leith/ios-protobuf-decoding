""":func:`proto.liveness.call_reads` against concrete runs of each function in an emulator (Unicorn):
the registers a run of it really reads before writing them -- through every function of the image
it calls, which run too -- must be among those ``call_reads`` says a call to it may read.

Not a read of a register's value: saving a callee-saved register (x19-x28, d8-d15) to the stack
before writing it (a prologue's spill), and the frame link (x29, x30) and sp, read on entry by
design.  A call out of the image (through an import's slot) reads what its ABI says -- a runtime
function its contract (:data:`proto.callees.RUNTIME_CONTRACTS`: ``objc_opt_class`` reads x0, x1;
the contracts are checked against runs of the runtime's own code, :mod:`oracles.call_models`),
a Swift function the Swift convention's (stated here from the Swift ABI, not taken from the
analysis checked), any other the AAPCS64 arguments (x0-x8, v0-v7) -- and
leaves the caller-saved registers written: what is checked is the analysis of the image's own
functions.  A run ends at the return to the
function's caller, a fault, or a step budget.

    python -m oracles.callreads_emulation BINARY [EVERY_NTH_FUNCTION] [RUNS]"""
import random
import sys

from unicorn import UcError, UC_HOOK_CODE
from unicorn import arm64_const as A

from macho.disasm import disasm
from oracles.flow_emulation import (make_machine, Report, RET_SENTINEL, SP0, random_value,
                                    _X)
from proto.arm64_operands import (CALLER_SAVED, PAIR_STORES, STORE_BYTES, parse_mem, reads,
                                  reg_name, split_ops, writes)
from proto.callees import RUNTIME_CONTRACTS
from proto.liveness import _ALL_REGS, call_reads

_CALLEE_SAVED = frozenset([f"x{i}" for i in range(19, 29)] + [f"v{i}" for i in range(8, 16)])
_NOT_VALUES = frozenset(("sp", "x29", "x30", "xzr"))
#: What a call to a function of the C convention may read (AAPCS64): its arguments in x0-x7 /
#: v0-v7 and an indirect result's address in x8.
_IMPORT_READS = tuple(f"x{i}" for i in range(9)) + tuple(f"v{i}" for i in range(8))
#: What a call to a Swift function may read: the Swift calling convention on arm64
#: (swift/docs/ABI/CallConvSummary.rst) passes those, and context in callee-saved registers:
#: self in x20, the error in x21, the async context in x22.
_SWIFT_READS = _IMPORT_READS + ("x20", "x21", "x22")
#: Swift's mangled-name prefixes as Mach-O spells them (swift/docs/ABI/Mangling.rst: ``$s``
#: Swift 5, ``$S`` 4.2, ``_T0`` 4.0; with the C underscore).
_SWIFT_PREFIXES = ("_$s", "_$S", "__T0")


def _swift_function(name) -> bool:
    """*name* is a function of the Swift calling convention: a mangled Swift symbol other than
    an ``@objc`` thunk (mangled ``...To``: the C convention)."""
    return bool(name) and name.startswith(_SWIFT_PREFIXES) and not name.endswith("To")
_EVERY = frozenset(_ALL_REGS)


class Run:
    def __init__(self, machine, va, seed, budget=100_000):
        self.m, self.va, self.budget = machine, va, budget
        self.written, self.read = set(), set()
        self.decoded = machine.__dict__.setdefault("_decoded", {})
        rng = random.Random(seed)
        uc = self.uc = machine.reset(rng)
        for r in _X:
            if r not in ("sp", "x30"):
                uc.reg_write(_X[r], random_value(rng))
        uc.reg_write(A.UC_ARM64_REG_SP, SP0)
        uc.reg_write(A.UC_ARM64_REG_X30, RET_SENTINEL)

    def _insn(self, address):
        ins = self.decoded.get(address)
        if ins is None:
            got = disasm(self.m.ctx, address, max_insns=1, stop_at_ret=False)
            ins = self.decoded[address] = got[0] if got else False
        return ins

    def _step(self, uc, address, _size, _data):
        ins = self._insn(address)
        if not ins:
            return
        spill = self._spills(ins)
        for r in reads(ins):
            if r not in self.written and r not in _NOT_VALUES and r not in spill:
                self.read.add(r)
        self.written.update(writes(ins))

    def _spills(self, ins):
        """The callee-saved registers a store saves to the frame (``stp x20, x19, [sp, #-0x20]!``)."""
        if ins.mnemonic not in STORE_BYTES and ins.mnemonic not in PAIR_STORES:
            return ()
        ops = split_ops(ins.op_str)
        mem = next((o for o in ops if o.startswith("[")), None)
        pm = parse_mem(mem) if mem else None
        if not pm or pm[0] not in ("sp", "x29"):
            return ()
        vals = ops[:2] if ins.mnemonic in PAIR_STORES else ops[:1]
        return {r for r in map(reg_name, vals) if r in _CALLEE_SAVED}

    def _call(self, uc, name):
        contract = RUNTIME_CONTRACTS.get(name)
        for r in (contract[0] if contract else _SWIFT_READS if _swift_function(name)
                  else _IMPORT_READS):
            if r not in self.written:
                self.read.add(r)
        self.written.update(CALLER_SAVED)
        uc.reg_write(_X["x0"], 0)

    def go(self):
        uc, m = self.uc, self.m
        text = m.ctx.section("__TEXT", "__text")
        hooks = [uc.hook_add(UC_HOOK_CODE, self._step, begin=text.vmaddr,
                             end=text.vmaddr + text.vmsize - 1)]
        calls = m.hook_calls(uc, self._call)
        if calls is not None:
            hooks.append(calls)
        try:
            uc.emu_start(self.va, RET_SENTINEL, count=self.budget)
            self.ended = "returned" if uc.reg_read(A.UC_ARM64_REG_PC) == RET_SENTINEL else "budget"
        except UcError:
            self.ended = "faulted"
        finally:
            for h in hooks:
                uc.hook_del(h)
        return self


def compare(ctx, functions, runs=4, report=None):
    report = report or Report()
    machine = make_machine(ctx)
    for va in functions:
        claimed = set(call_reads(ctx, va))
        report.stats["functions"] += 1
        if claimed >= _EVERY:                   # (an undecoded jump table, no CFG): nothing to check
            report.stats["functions call_reads says read every register"] += 1
        read = set()
        for seed in range(runs):
            run = Run(machine, va, (va << 8) | seed).go()
            report.stats["runs " + run.ended] += 1
            report.stats["registers read"] += len(run.read)
            read |= run.read
            for r in sorted(run.read - claimed):
                report.find("a register read that call_reads does not list", va,
                            "%#x reads %s; call_reads %s" % (va, r, sorted(claimed)), key=r)
        report.stats["registers listed that no run reads"] += len(claimed - read)
    return report


def main(argv):
    from macho.memory import BinaryContext
    from serializers.swift_descriptor_extract import load_macho_slice
    ctx = BinaryContext(load_macho_slice(open(argv[0], "rb").read()))
    every = int(argv[1]) if len(argv) > 1 else 100
    runs = int(argv[2]) if len(argv) > 2 else 4
    rep = compare(ctx, ctx.function_starts()[::every], runs)
    print(dict(rep.stats))
    for kind, rows in rep.findings.items():
        print("==", kind, rep.stats[kind])
        for row in rows[:25]:
            print("   ", row[1])


if __name__ == "__main__":
    main(sys.argv[1:])
