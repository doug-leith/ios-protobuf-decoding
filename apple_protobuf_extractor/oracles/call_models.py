"""The call models the analyses and the other oracles share -- :data:`proto.callees.RUNTIME_CONTRACTS`
(the registers a runtime function reads, the one it returns), :data:`proto.callees.CALL_CLOBBERS`
(the few it changes) and :data:`proto.callees.RETURNS_ARGUMENT` -- against runs of the functions
themselves, from a dyld cache (libobjc, libsystem_platform, libsystem_pthread), in an emulator
(:class:`oracles.flow_emulation.CacheMachine`).  Everywhere else these tables are only checked
against themselves: Flow's oracle models a call with them, as Flow does.

Each function is run with its arguments as its ABI says they are -- an object, a lock word, a
class, a probe size -- and every other register random, the thread's TSD (``tpidrro_el0``) a
zeroed page but for a thread port.  The object's nonpointer isa holds a count of two and a class
built here as a realized one is: the cache's own classes are not realized (their bits lack the
default retain / release flag, so a retain of one takes the runtime's slow path), and the fast
paths read only the class's cache flags (+0x1e: bit 15 its default core, bit 2 a metaclass), its
bits (+0x20: bit 2 the default retain / release) and its superclass (+8).  On a
run that returns:

* the callee-saved registers (x19-x29, sp) are kept;
* a function :data:`CALL_CLOBBERS` lists changes no register it does not list;
* one :data:`RETURNS_ARGUMENT` lists returns its argument, a contract's return register its value;
* no register the contract does not list is read: the run again with it changed leaves every
  other register as before, writes the same memory (the stack aside: a save is no read) and ends
  the same way.

A function no case brings to its return is not checked and is counted: on the iPhone 8 cache
``objc_opt_respondsToSelector`` (a method lookup in a class the runtime has not built) and
``objc_enumerationMutation`` (which by design does not return: it calls the handler or aborts).

    python -m oracles.call_models CACHE [NAME...]"""
import collections
import random
import struct
import sys

from unicorn import UcError, UC_HOOK_MEM_WRITE
from unicorn import arm64_const as A

from oracles.flow_emulation import (CacheMachine, HEAP_BASE, RET_SENTINEL, SP0, STACK_BASE,
                                    STACK_SIZE, _X, random_value)
from proto.callees import CALL_CLOBBERS, RETURNS_ARGUMENT, RUNTIME_CONTRACTS

IMAGES = ("libobjc.A.dylib", "libsystem_platform.dylib", "libsystem_pthread.dylib")
OBJECT = HEAP_BASE + 0x1000          # a stand-in object
SELECTOR = OBJECT + 0x200            # a selector's name
LOCK = HEAP_BASE + 0x2000            # a lock word
HELD = LOCK + 0x10                   # one this thread holds (its port)
CLASS, META = HEAP_BASE + 0x2800, HEAP_BASE + 0x2900   # the object's class and its metaclass
TSD = HEAP_BASE + 0x3000             # the thread's TSD page
BLOCK = HEAP_BASE + 0x2a00           # a global block (retainBlock of any other returns a copy)
BLOCK_IS_GLOBAL = 1 << 28
RW = HEAP_BASE + 0x2b00              # the class's class_rw_t: realized and initialized
RW_REALIZED, RW_INITIALIZED = 1 << 31, 1 << 29
POOL = HEAP_BASE + 0x8000            # the thread's autorelease pool page (16 KB, aligned)
POOL_KEY = 43                        # its TSD slot: __PTK_FRAMEWORK_OBJC_KEY3
POOL_MAGIC = struct.pack("<I", 0xA1A1A1A1) + b"AUTORELEASE!"
FAST_CACHE_DEFAULT_CORE, FAST_CACHE_META, FAST_DEFAULT_RR = 1 << 15, 1 << 2, 1 << 2
THREAD_PORT = 0x1503                 # (os_unfair_lock: the owner's port, TSD slot 3)
# arm64 nonpointer isa: magic 0x1a at bits 36-41, the class at 3-35, the retain count from bit 45
ISA_MAGIC, ISA_MASK, EXTRA_RC = 0x000001A000000001, 0x0000000FFFFFFFF8, 45
_CALLEE_SAVED = ["x%d" % i for i in range(19, 30)] + ["sp"]
_ARGS = ["x%d" % i for i in range(29)]


class Result(collections.namedtuple("Result", "checked findings not_run absent")):
    """*checked*: name -> runs that returned; *findings*: (name, what, detail); *not_run*: the
    names no run brought to their return (name -> how the runs ended); *absent*: the names no
    image exports (``objc_retain_x16`` ... : no such entry point)."""


def _roles(name):
    """``{register: role}`` for *name*'s arguments."""
    if name.startswith(("_objc_retain_x", "_objc_release_x")):
        return {"x" + name.rsplit("_x", 1)[1]: "object"}
    if name == "____chkstk_darwin":
        return {"x9": "size"}
    if name in ("_os_unfair_lock_unlock", "_os_unfair_lock_assert_owner"):
        return {"x0": "held lock"}
    if name.startswith("_os_unfair_lock"):
        return {"x0": "lock", "x1": "options"}
    if name == "_objc_opt_isKindOfClass":
        return {"x0": "object", "x1": "class"}
    if name == "_objc_opt_respondsToSelector":
        return {"x0": "object", "x1": "selector"}
    if name == "_objc_retainBlock":
        return {"x0": "block"}
    return {"x0": "object"}


class Runner:
    def __init__(self, reader):
        from macho.load import load_cache_image
        import contextlib
        import io
        self.reader = reader
        self.exports = {}
        for image in IMAGES:
            for n, va in reader.image_exports(reader.find_image_header(image)).items():
                self.exports.setdefault(n, va)
        with contextlib.redirect_stdout(io.StringIO()):
            img = load_cache_image(reader, reader.find_image_header("libobjc.A.dylib"))
        self.m = CacheMachine(img.ctx)

    def run(self, va, roles, seed, change=None):
        """``(how it ended, registers before, registers after, memory written)`` of a run of the
        function at *va*; *change*, a register given another random value."""
        uc = self.m.reset(random.Random(seed))
        heap = bytearray(0xC000)
        struct.pack_into("<Q", heap, OBJECT - HEAP_BASE,
                         ISA_MAGIC | (CLASS & ISA_MASK) | 2 << EXTRA_RC)  # a count of two
        heap[SELECTOR - HEAP_BASE:SELECTOR - HEAP_BASE + 12] = b"description\0"
        for cls, isa, flags in ((CLASS, META, FAST_CACHE_DEFAULT_CORE),
                                (META, META, FAST_CACHE_DEFAULT_CORE | FAST_CACHE_META)):
            struct.pack_into("<QQ", heap, cls - HEAP_BASE, isa, 0)      # isa, no superclass
            struct.pack_into("<H", heap, cls - HEAP_BASE + 0x1e, flags)
            struct.pack_into("<Q", heap, cls - HEAP_BASE + 0x20, RW | FAST_DEFAULT_RR)
        struct.pack_into("<I", heap, RW - HEAP_BASE, RW_REALIZED | RW_INITIALIZED)
        heap[POOL - HEAP_BASE:POOL - HEAP_BASE + 16] = POOL_MAGIC
        struct.pack_into("<Q", heap, POOL - HEAP_BASE + 0x10, POOL + 0x40)    # next
        struct.pack_into("<Q", heap, TSD - HEAP_BASE + POOL_KEY * 8, POOL)
        struct.pack_into("<Q", heap, TSD - HEAP_BASE + 3 * 8, THREAD_PORT)
        struct.pack_into("<I", heap, HELD - HEAP_BASE, THREAD_PORT)
        struct.pack_into("<QI", heap, BLOCK - HEAP_BASE, CLASS, BLOCK_IS_GLOBAL)
        uc.mem_write(HEAP_BASE, bytes(heap))
        uc.reg_write(A.UC_ARM64_REG_TPIDRRO_EL0, TSD)
        values = {"object": OBJECT, "lock": LOCK, "held lock": HELD, "options": 0, "class": CLASS,
                  "selector": SELECTOR, "size": 0x2010, "block": BLOCK}
        for r, role in roles.items():
            uc.reg_write(_X[r], values[role])
        if change is not None:
            rng = random.Random(seed * 1000 + 1)
            uc.reg_write(_X[change], random_value(rng))
        uc.reg_write(_X["x30"], RET_SENTINEL)
        uc.reg_write(_X["sp"], SP0)
        names = _ARGS + ["x29", "sp"]
        before = {r: uc.reg_read(_X[r]) for r in names}
        written = {}

        def wrote(uc_, _access, addr, size, value, _data):
            if not STACK_BASE <= addr < STACK_BASE + STACK_SIZE:
                written[addr] = (size, value & ((1 << (8 * size)) - 1))
        hook = uc.hook_add(UC_HOOK_MEM_WRITE, wrote)
        try:
            uc.emu_start(va, RET_SENTINEL, count=50_000)
            ended = "returned" if uc.reg_read(A.UC_ARM64_REG_PC) == RET_SENTINEL else "budget"
        except UcError as e:
            ended = "fault: %s" % e
        finally:
            uc.hook_del(hook)
        after = {r: uc.reg_read(_X[r]) for r in names}
        return ended, before, after, written


def compare(reader, names=None, seeds=(1, 2, 3)):
    runner = Runner(reader)
    names = names or sorted(set(RUNTIME_CONTRACTS) | set(CALL_CLOBBERS) | set(RETURNS_ARGUMENT))
    checked, findings, not_run, absent = collections.Counter(), [], {}, []
    for name in names:
        va = runner.exports.get(name)
        if va is None:
            absent.append(name)
            continue
        roles = _roles(name)
        contract = RUNTIME_CONTRACTS.get(name)
        ends = collections.Counter()
        for seed in seeds:
            ended, before, after, written = runner.run(va, roles, seed)
            ends[ended.split(":")[0]] += 1
            if ended != "returned":
                continue
            checked[name] += 1
            for r in _CALLEE_SAVED:
                if before[r] != after[r]:
                    findings.append((name, "a callee-saved register changed", r))
            if name in CALL_CLOBBERS:
                for r in _ARGS:
                    if before[r] != after[r] and r not in CALL_CLOBBERS[name]:
                        findings.append((name, "a register changed that CALL_CLOBBERS does not "
                                               "list", r))
            if name in RETURNS_ARGUMENT and after["x0"] != before["x0"]:
                findings.append((name, "does not return its argument",
                                 "%#x -> %#x" % (before["x0"], after["x0"])))
            if contract and contract[1] and after["x0"] != before[contract[1]]:
                findings.append((name, "does not return %s" % contract[1],
                                 "%#x, x0 %#x" % (before[contract[1]], after["x0"])))
            if contract:
                for r in _ARGS:
                    if r in contract[0]:
                        continue
                    e2, _b2, a2, w2 = runner.run(va, roles, seed, change=r)
                    rest = lambda regs: {k: v for k, v in regs.items() if k != r}
                    if (e2, rest(a2), w2) != (ended, rest(after), written):
                        findings.append((name, "reads a register its contract does not list", r))
        if not checked[name]:
            not_run[name] = dict(ends)
    return Result(dict(checked), findings, not_run, absent)


def main(argv):
    from macho.dyld_cache import DyldCacheReader
    res = compare(DyldCacheReader(argv[0]), argv[1:] or None)
    print("checked", len(res.checked), "not run", len(res.not_run), "absent", len(res.absent))
    for row in res.findings:
        print("  ", row)
    for name, how in sorted(res.not_run.items()):
        print("   not run", name, how)


if __name__ == "__main__":
    main(sys.argv[1:])
