""":func:`proto.callees.call_reads` against concrete runs of each function in an emulator (Unicorn):
the registers a run of it really reads before writing them -- through every function of the image
it calls, which run too -- must be among those ``call_reads`` says a call to it may read.

Not a read of a register's value: saving a callee-saved register (x19-x28, d8-d15) to the stack
before writing it (a prologue's spill), and the frame link (x29, x30) and sp, read on entry by
design.  A call out of the image (through an import's slot) reads what its ABI says -- a runtime
function its contract (:data:`proto.callees.RUNTIME_CONTRACTS`: ``objc_opt_class`` reads x0, x1),
a Swift function the Swift convention's, any other the AAPCS64 arguments (x0-x8, v0-v7) -- and
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
from proto.arm64_operands import (ARG_FPRS, CALL_ARG_GPRS, CALLER_SAVED, PAIR_STORES, STORE_BYTES,
                                  parse_mem, reads, reg_name, split_ops, writes)
from proto.callees import RUNTIME_CONTRACTS, SWIFT_CALL_ARGS, _is_swift_name, call_reads

_CALLEE_SAVED = frozenset([f"x{i}" for i in range(19, 29)] + [f"v{i}" for i in range(8, 16)])
_NOT_VALUES = frozenset(("sp", "x29", "x30", "xzr"))
_IMPORT_READS = tuple(CALL_ARG_GPRS) + tuple(ARG_FPRS)


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
        for r in (contract[0] if contract else SWIFT_CALL_ARGS if _is_swift_name(name)
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
        for seed in range(runs):
            run = Run(machine, va, (va << 8) | seed).go()
            report.stats["runs " + run.ended] += 1
            report.stats["registers read"] += len(run.read)
            for r in sorted(run.read - claimed):
                report.find("a register read that call_reads does not list", va,
                            "%#x reads %s; call_reads %s" % (va, r, sorted(claimed)), key=r)
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
