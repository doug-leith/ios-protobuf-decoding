""":class:`proto.arm64_eval.Flow`'s claims about a function against concrete runs of it in an emulator
(Unicorn), from its entry with random registers and memory.

Whatever a run does, what Flow says holds on every path must hold on it:

* the CFG: each step from one instruction to the next is an edge of ``flow.cfg`` (a ``br``'s jump
  table arms included), every instruction run is in the listing, a ``br`` whose table is decoded
  stays in the function, and no run reaches the bytes between the body's end and the next
  function;
* reaching definitions: the instruction that last wrote a register an instruction reads is one
  of :meth:`Flow.defs_before`'s -- the last writes the run's own (each register an instruction
  changes; one ``writes()`` does not list is itself a finding);
* constants: each register :meth:`Flow.known_before` knows (with nothing known on entry) holds
  that value -- a stack address relative to the entry ``sp`` -- and each block a run reaches is
  one its propagation reaches.

The runs model what Flow assumes of the rest of the program, and nothing more: a call (other
than an outlined fragment, which runs) returns with every caller-saved register and the flags
random, the callee-saved ones kept, and the stack from the lowest frame address any argument
register hands it up to the entry ``sp`` overwritten; the runtime functions Flow has contracts
for keep them (the ARC calls return their argument, the stack probe writes x16 / x17).  The
image's own memory is as loaded (chained-fixup rebases applied, each bound slot pointing at its
import's block); any other address reads random words.  A run ends at the return to its caller,
a branch out of the function, a fault, or a step budget.

    python -m oracles.flow_emulation BINARY [EVERY_NTH_FUNCTION] [RUNS]"""
import bisect
import collections
import random
import struct
import sys

from unicorn import (Uc, UcError, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_MEM_UNMAPPED,
                     UC_HOOK_MEM_WRITE)
from unicorn import arm64_const as A

from proto.arm64_eval import Flow, _ENTRY, _STACK_TOP, _is_stack, _is_symbolic
from proto.arm64_operands import CALLS, RETURNS, reads, writes
from proto.callees import RETURNS_ARGUMENT, callee_name, call_clobbers
from proto.dispatch import listing_flow
from proto.function_body import function_body
from macho.disasm import _parse_imm

PAGE = 0x1000
STACK_BASE, STACK_SIZE = 0x7f0000000000, 0x40000
SP0 = STACK_BASE + STACK_SIZE - 0x8000        # the entry sp: room above for the caller's frame
HEAP_BASE, HEAP_SIZE = 0x500000000, 0x100000
RET_SENTINEL = 0x6ffff0000000                  # the caller's return address
BIND_BASE, BIND_STRIDE = 0x600000000, 0x40     # where each import's bound slot points
RET = struct.pack("<I", 0xd65f03c0)            # an import block's first word: a callee's return
# where the oracles put their stand-ins (objects, self, the writer / reader, its bytes): never
# mapped on demand
RESERVED = (0x700000000, 0x7c0000000)
CALLER_SAVED = [f"x{i}" for i in range(19)] + [f"v{i}" for i in range(8)] + \
    [f"v{i}" for i in range(16, 32)]
_X = {f"x{i}": getattr(A, f"UC_ARM64_REG_X{i}") for i in range(29)}
_X.update(x29=A.UC_ARM64_REG_X29, x30=A.UC_ARM64_REG_X30, sp=A.UC_ARM64_REG_SP)
_V = {f"v{i}": getattr(A, f"UC_ARM64_REG_Q{i}") for i in range(32)}
_GPRS = ["x%d" % i for i in range(31)]
_GPR_IDS = [_X[r] for r in _GPRS]
MASK64 = (1 << 64) - 1


class Machine:
    """One emulator with the image mapped (each segment's bytes, its rebases applied), reset for
    each run: the pages a run wrote of the image's writable segments restored, the stack and heap
    random, each page mapped on demand given its first contents again (a page is mapped once:
    unmapping makes Unicorn drop the code it has translated)."""

    def __init__(self, ctx):
        self.ctx = ctx
        self.uc = uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        self.writable = []
        binds = sorted(getattr(ctx, "_bind_name_map", None) or ())
        self.bind_size = (len(getattr(ctx, "_imports", ())) * BIND_STRIDE + PAGE - 1) & ~(PAGE - 1)
        for s in ctx.segments:
            if s.name == "__PAGEZERO" or not s.vmsize:
                continue
            data = bytearray(ctx._data[s.fileoff:s.fileoff + s.filesize]) + \
                bytes(s.vmsize - s.filesize)
            for va, target in ctx._fixup_map.items():
                if s.vmaddr <= va < s.vmaddr + s.vmsize - 7:
                    struct.pack_into("<Q", data, va - s.vmaddr, target)
            for va in binds:                         # a bound slot: its import's address
                if s.vmaddr <= va < s.vmaddr + s.vmsize - 7:
                    raw = struct.unpack_from("<Q", data, va - s.vmaddr)[0]
                    struct.pack_into("<Q", data, va - s.vmaddr, import_address(raw))
            lo = s.vmaddr & ~(PAGE - 1)
            hi = (s.vmaddr + s.vmsize + PAGE - 1) & ~(PAGE - 1)
            uc.mem_map(lo, hi - lo)
            uc.mem_write(s.vmaddr, bytes(data))
            if s.name != "__TEXT":
                self.writable.append((s.vmaddr, bytes(data)))
        uc.mem_map(STACK_BASE, STACK_SIZE)
        uc.mem_map(HEAP_BASE, HEAP_SIZE)
        if self.bind_size:
            uc.mem_map(BIND_BASE, self.bind_size)
        uc.mem_map(RET_SENTINEL, PAGE)
        self._paging()

    def _paging(self):
        """The pages mapped on demand, and the record of which writable pages a run writes."""
        uc = self.uc
        self.on_demand = {}                     # page -> its first contents (None: random words)
        self.dirty = set()
        self.rng = random.Random(0)
        # random memory contents, made once (a run picks one for its stack and one for its heap)
        self.fillers = [random_words(random.Random(i), max(STACK_SIZE, HEAP_SIZE)) for i in range(4)]

        def unmapped(uc_, _access, addr, _size, _value, _data):
            page = addr & ~(PAGE - 1)
            self.bad = addr
            if page >= 1 << 47 or RESERVED[0] <= page < RESERVED[1]:
                return False
            first = self._first_contents(page)
            try:
                uc_.mem_map(page, PAGE)
                uc_.mem_write(page, first if first is not None else self._random_page(page))
            except UcError:
                return False
            self.on_demand[page] = first
            return True
        uc.hook_add(UC_HOOK_MEM_UNMAPPED, unmapped)

        def written(_uc, _access, addr, size, _value, _data):
            self.dirty.add(addr & ~(PAGE - 1))
            self.dirty.add((addr + size - 1) & ~(PAGE - 1))
        for va, data in self.writable:
            uc.hook_add(UC_HOOK_MEM_WRITE, written, begin=va, end=va + len(data) - 1)

    def _first_contents(self, page):
        """What a page mapped on demand holds first: random words (None)."""
        return None

    def _random_page(self, page):
        filler = self.fillers[(page // PAGE) % len(self.fillers)]
        at = (page // PAGE * PAGE) % (len(filler) - PAGE)
        return filler[at:at + PAGE]

    def reset(self, rng):
        uc = self.uc
        self.rng = rng
        for page, first in self.on_demand.items():
            uc.mem_write(page, first if first is not None else self._random_page(page))
        for page in self.dirty:
            for va, data in self.writable:
                lo, hi = max(page, va), min(page + PAGE, va + len(data))
                if lo < hi:
                    uc.mem_write(lo, data[lo - va:hi - va])
        self.dirty = set()
        uc.mem_write(STACK_BASE, self.fillers[rng.randrange(len(self.fillers))][:STACK_SIZE])
        uc.mem_write(HEAP_BASE, self.fillers[rng.randrange(len(self.fillers))][:HEAP_SIZE])
        if self.bind_size:                      # each import's block: random words after a ret
            blocks = bytearray(random_words(rng, self.bind_size))
            for at in range(0, self.bind_size, BIND_STRIDE):
                blocks[at:at + 4] = RET
            uc.mem_write(BIND_BASE, bytes(blocks))
        for uid in _X.values():
            uc.reg_write(uid, random_value(rng))
        for uid in _V.values():
            uc.reg_write(uid, rng.getrandbits(128))
        uc.reg_write(A.UC_ARM64_REG_SP, SP0)
        uc.reg_write(A.UC_ARM64_REG_X30, RET_SENTINEL)
        uc.reg_write(A.UC_ARM64_REG_NZCV, rng.getrandbits(4) << 28)
        return uc

    def callee_name(self, address):
        """The import whose block *address* is (its first word: the call's ``ret``)."""
        i = (address - BIND_BASE) // BIND_STRIDE
        imports = getattr(self.ctx, "_imports", ())
        return imports[i] if 0 <= i < len(imports) else None

    def hook_calls(self, uc, handler):
        """Call ``handler(uc, name)`` on each call out of the image, before it returns (to its
        caller's x30, unless the handler sends it elsewhere: a message to self's own method)."""
        if not self.bind_size:
            return None

        def on_import(uc_, address, _size, _data):
            handler(uc_, self.callee_name(address))
        return uc.hook_add(UC_HOOK_CODE, on_import, begin=BIND_BASE,
                           end=BIND_BASE + self.bind_size - 1)


class CacheMachine(Machine):
    """A :class:`Machine` over an image of a dyld cache: the image's segments as loaded (pointers
    decoded by the cache's slide info, :class:`oracles.cache_memory.SlideInfo`), and any other
    address of the cache read from it on demand the same way -- another image's classes, strings,
    ivar offset variables; an address outside the cache reads random words.  A call into another
    image is answered where that image's export begins, by its name (an image reaches another
    only by an export; the stub islands on the way run)."""

    def __init__(self, ctx):
        from oracles.cache_memory import SlideInfo
        self.ctx, self.reader = ctx, ctx._cache_reader
        self.slide = SlideInfo(self.reader)
        self.uc = uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        self.writable, self.bind_size, self.own = [], 0, []
        for s in ctx.segments:
            if s.name == "__LINKEDIT" or not s.vmsize:
                continue
            data = self.slide.apply(s.vmaddr, self.reader.read_raw(s.vmaddr, s.vmsize))
            lo = s.vmaddr & ~(PAGE - 1)
            hi = (s.vmaddr + s.vmsize + PAGE - 1) & ~(PAGE - 1)
            self._map(lo, hi)
            uc.mem_write(s.vmaddr, data)
            self.own.append((s.vmaddr, s.vmaddr + s.vmsize))
            if s.name == "__TEXT":
                self.code = (s.vmaddr, s.vmaddr + s.vmsize)
            else:
                self.writable.append((s.vmaddr, data))
        uc.mem_map(STACK_BASE, STACK_SIZE)
        uc.mem_map(HEAP_BASE, HEAP_SIZE)
        uc.mem_map(RET_SENTINEL, PAGE)
        self.names = {}
        self._paging()

    def _first_contents(self, page):
        """A page of the cache: its bytes with their pointers decoded; elsewhere random words."""
        raw = self.reader.read_raw(page, PAGE) if self.reader.has_vmaddr(page) else None
        return self.slide.apply(page, raw) if raw and len(raw) == PAGE else None

    def _map(self, lo, hi):
        """Map [lo, hi) -- in one piece, or around the pages a neighbouring segment mapped."""
        try:
            self.uc.mem_map(lo, hi - lo)
            return
        except UcError:
            pass
        mapped = [(b, e) for b, e, _p in self.uc.mem_regions()]
        page = lo
        while page < hi:
            covering = next((e for b, e in mapped if b <= page <= e), None)
            if covering is not None:
                page = covering + 1
                continue
            end = min([hi] + [b for b, _e in mapped if b > page])
            self.uc.mem_map(page, end - page)
            page = end

    def callee_name(self, address):
        if address not in self.names:
            self.names[address] = self.reader.export_name_at(address)
        return self.names[address]

    def hook_calls(self, uc, handler):
        lo, hi = self.code

        def on_code(uc_, address, _size, _data):
            if lo <= address < hi or address == RET_SENTINEL:
                return
            name = self.callee_name(address)
            if name is None:                    # a stub island on its way there: runs
                return
            lr = uc_.reg_read(A.UC_ARM64_REG_X30)
            handler(uc_, name)
            if uc_.reg_read(A.UC_ARM64_REG_PC) == address:      # not sent elsewhere: return
                uc_.reg_write(A.UC_ARM64_REG_PC, lr)
        return uc.hook_add(UC_HOOK_CODE, on_code, begin=1, end=0)


def make_machine(ctx):
    """The emulator for *ctx*: a dyld cache image's, or a binary's."""
    return CacheMachine(ctx) if getattr(ctx, "is_cache_backed", False) else Machine(ctx)


def import_address(raw):
    """The address a run gives the import a bound slot's raw chained-fixup value names (its
    ordinal, the low 24 bits: :meth:`BinaryContext.import_name_for_bind`)."""
    return BIND_BASE + (raw & 0xFFFFFF) * BIND_STRIDE


def random_value(rng):
    """A register's or memory word's random value: a small integer, a 32-bit one or a heap
    pointer (a load through it stays in mapped memory)."""
    kind = rng.randrange(3)
    if kind == 0:
        return rng.randrange(16)
    if kind == 1:
        return rng.getrandbits(32)
    return HEAP_BASE + (rng.randrange(HEAP_SIZE) & ~7)


def random_words(rng, size):
    return struct.pack("<%dQ" % (size // 8), *(random_value(rng) for _ in range(size // 8)))


class Report:
    def __init__(self):
        self.stats = collections.Counter()
        self.findings = collections.defaultdict(list)    # kind -> [(function, detail)]
        self.faults = collections.Counter()               # (error, mnemonic) -> runs
        self.unanswered = collections.Counter()           # calls a stand-in did not answer
        self._seen = set()
        self.fault_addrs = collections.Counter()

    def find(self, kind, fn, detail, key=None):
        """One finding; *key* identifies it (each counted once: a run repeats what it finds at
        every step on)."""
        key = (kind, fn, key if key is not None else detail)
        if key in self._seen:
            return
        self._seen.add(key)
        self.stats[kind] += 1
        if len(self.findings[kind]) < 40:
            self.findings[kind].append((hex(fn), detail))


class Emulation:
    """One function's Flow, checked over *runs* random runs (seeded, so repeatable)."""

    def __init__(self, machine, va, report, budget=20000):
        self.machine, self.ctx, self.va, self.report, self.budget = \
            machine, machine.ctx, va, report, budget
        body = function_body(self.ctx, va)
        self.flow = listing_flow(self.ctx, list(body))
        self.lo, self.hi = body[0].addr, body[-1].addr + 4
        starts = self.ctx.function_starts()
        i = bisect.bisect_right(starts, va)
        self.next_start = starts[i] if i < len(starts) else self.hi   # (the body may end before it)

    # ── one run ──────────────────────────────────────────────────────────────

    def _stub(self, uc, ins, rng):
        """A call's effect (see the module docstring)."""
        target = _parse_imm(ins.op_str) if ins.mnemonic == "bl" else None
        name = callee_name(self.ctx, target) if target is not None else None
        keep = call_clobbers(self.ctx, target)
        written = list(keep) if keep is not None else CALLER_SAVED + ["x30"]
        x0 = uc.reg_read(A.UC_ARM64_REG_X0)
        sp = uc.reg_read(A.UC_ARM64_REG_SP)
        handed = [v for v in (uc.reg_read(_X[f"x{i}"]) for i in range(9))
                  if max(sp, STACK_BASE) <= v < SP0]           # (a frame run past the stack faults)
        if handed:
            lo = min(handed)
            uc.mem_write(lo, random_words(rng, (SP0 - lo) & ~7) + bytes((SP0 - lo) & 7))
        for r in written:
            if r in _X:
                uc.reg_write(_X[r], random_value(rng))
            elif r in _V:
                uc.reg_write(_V[r], rng.getrandbits(128))
        if name in RETURNS_ARGUMENT:
            uc.reg_write(A.UC_ARM64_REG_X0, x0)
        if keep is None:
            uc.reg_write(A.UC_ARM64_REG_NZCV, rng.getrandbits(4) << 28)
        uc.reg_write(A.UC_ARM64_REG_X30, ins.addr + 4)
        return written

    def run(self, seed, regs=None):
        """One run; *regs* the registers' values on entry (any other: random)."""
        rng = random.Random(seed)
        flow, rep = self.flow, self.report
        uc = self.machine.reset(rng)
        for r, v in (regs or {}).items():
            uc.reg_write(_X[r], v)
        last = {}                                  # register -> index of its last write
        pc, prev = self.va, None
        for _step in range(self.budget):
            if pc == RET_SENTINEL:
                rep.stats["runs returned"] += 1
                return
            k = flow.addr_idx.get(pc)
            if k is None:
                if self.lo <= pc < self.hi:
                    rep.find("ran an instruction the body lacks", self.va, hex(pc))
                elif self.hi <= pc < self.next_start:
                    rep.find("ran past the end of the body", self.va,
                             "%#x (the body ends at %#x, the next function starts at %#x)"
                             % (pc, self.hi, self.next_start))
                elif prev is not None and flow.cfg.succ.get(flow._block_of[prev]) and \
                        flow.insns[prev].mnemonic.startswith("br"):
                    rep.find("a decoded br that jumps elsewhere", self.va,
                             "%s -> %#x" % (flow.insns[prev], pc), key=prev)
                else:
                    rep.stats["runs left the function" if pc in self._starts() else
                              "runs left for an address no function starts at"] += 1
                return
            self._check(uc, k, prev, last)
            ins = flow.insns[k]
            if ins.mnemonic in CALLS and flow.fragment(k) is None:
                for r in self._stub(uc, ins, rng):
                    last[r] = k
                self._returned(uc, k)
                pc, prev = ins.addr + 4, None
                continue
            if flow.fragment(k) is not None:
                if not self._fragment(uc, k, last):
                    return
                pc, prev = ins.addr + 4, None
                continue
            before = uc.reg_read_batch(_GPR_IDS)
            try:
                uc.emu_start(pc, RET_SENTINEL, count=1)
            except UcError as e:
                if ins.mnemonic in RETURNS:        # to a return address the run overwrote
                    rep.stats["runs returned to an address the run overwrote"] += 1
                else:
                    rep.stats["runs faulted"] += 1
                    rep.faults[(str(e), ins.mnemonic)] += 1
                    rep.fault_addrs[hex(self.machine.bad >> 44)] += 1
                return
            listed = writes(ins)
            for r, a, b in zip(_GPRS, before, uc.reg_read_batch(_GPR_IDS)):
                if a != b and r not in listed:     # the run's own writes, not only writes()'s
                    rep.find("a register written that writes() does not list", self.va,
                             "%s writes %s" % (ins, r), key=(ins.mnemonic, r))
                    last[r] = k
            for r in listed:
                last[r] = k
            pc, prev = uc.reg_read(A.UC_ARM64_REG_PC), k
        rep.stats["runs over budget"] += 1

    def _starts(self):
        m = self.machine.__dict__
        if "_start_set" not in m:
            m["_start_set"] = set(self.ctx.function_starts())
        return m["_start_set"]

    def _returned(self, uc, k):
        """After the call ``insns[k]`` (a hook for :class:`EntryEmulation`)."""

    def _fragment(self, uc, k, last):
        """Run the outlined fragment the ``bl`` at *k* calls; its writes are the call's."""
        ins = self.flow.insns[k]
        uc.reg_write(A.UC_ARM64_REG_X30, ins.addr + 4)
        pc = _parse_imm(ins.op_str)
        for fi in self.flow.fragment(k):
            try:
                uc.emu_start(pc, RET_SENTINEL, count=1)
            except UcError:
                self.report.stats["runs faulted"] += 1
                return False
            for r in writes(fi):
                last[r] = k
            pc = uc.reg_read(A.UC_ARM64_REG_PC)
        last["x30"] = k
        return pc == ins.addr + 4

    # ── the checks ───────────────────────────────────────────────────────────

    def _check(self, uc, k, prev, last):
        flow, rep, fn = self.flow, self.report, self.va
        b = flow._block_of[k]
        if prev is not None and not (k == prev + 1 and flow._block_of[prev] == b):
            pb = flow._block_of[prev]
            rep.stats["edges"] += 1
            if b not in flow.cfg.succ.get(pb, ()):
                rep.find("an edge the CFG lacks", fn,
                         "%s -> %#x" % (flow.insns[prev], flow.insns[k].addr), key=(prev, k))
        ins = flow.insns[k]
        for r in reads(ins):
            if not (r.startswith(("x", "v")) and r[1:].isdigit()):
                continue
            defs = flow.defs_before(k, r)
            d = last.get(r, _ENTRY)
            rep.stats["reads"] += 1
            if d not in defs:
                rep.find("a reaching definition not in defs_before", fn,
                         "%s reads %s, last written at %s, defs_before %s"
                         % (ins, r, flow.insns[d] if d >= 0 else "entry",
                            sorted(defs)[:6]), key=(k, r, d))
        known = flow.known_before(k)
        if b not in flow._entry_states:
            rep.find("a block propagation does not reach", fn, str(ins), key=b)
            return
        for r, v in known.items():
            if r not in _X or v is None:
                continue
            got = uc.reg_read(_X[r]) & MASK64
            rep.stats["known values"] += 1
            if _is_stack(v):
                want = (SP0 + v - _STACK_TOP) & MASK64
                if got != want:
                    kind = ("a constant Flow takes for a stack address"
                            if not STACK_BASE <= got < STACK_BASE + STACK_SIZE
                            else "a known stack address that does not hold")
                    rep.find(kind, fn, "before %s: %s known %#x (stack), ran %#x" % (ins, r, v, got),
                             key=(r, v))
            elif got != v & MASK64:
                rep.find("a known value that does not hold", fn,
                         "before %s: %s known %#x, ran %#x" % (ins, r, v, got), key=(r, v))


class EntryEmulation(Emulation):
    """Flow's runs from values known on entry against concrete runs from those values: ``self``
    (x0) a stand-in object -- :data:`proto.eval_tokens.SELF` to Flow, a heap pointer to the run --
    and some argument registers numbers.  What must hold: each register :meth:`Flow.propagate`
    knows before an instruction, with the evaluators' object model (a call's result is a token
    for that call): ``self`` is the pointer, a call's result what that call last returned, a
    frame address relative to the entry sp, a number itself; every instruction run is one the
    propagation reaches under those values; each argument :meth:`Flow.run_from` records at a call
    is what the call is handed; and what :meth:`Flow.value_at` gives a call's or a ``br``'s
    operand from the entry, on first reaching it, is what it holds."""

    def run(self, seed, regs=None):
        from proto.arm64_eval import Objects
        from proto.eval_tokens import SELF, call_result, opaque
        rng = random.Random(seed ^ 0x5EED)
        self.self_ptr = HEAP_BASE + 0x1000
        entry, concrete = {"x0": SELF}, {"x0": self.self_ptr}
        for i in range(1, 8):
            if rng.random() < 0.5:
                entry[f"x{i}"] = concrete[f"x{i}"] = rng.randrange(16)
        flow = self.flow
        objects = Objects(opaque=opaque, call_result=call_result(self.ctx))
        self.known = flow.propagate(entry, range(len(flow.insns)), objects)
        self.args = {c.k: c.args for c in flow.run_from(0, entry, objects=objects).calls}
        self.numbers = {r: v for r, v in entry.items() if r != "x0"}
        self.returned, self.first = {}, set()
        super().run(seed, concrete)

    def _returned(self, uc, k):
        self.returned[k] = uc.reg_read(A.UC_ARM64_REG_X0)

    def _expect(self, v):
        """What the run holds where Flow knows *v* (None: nothing to check)."""
        from proto.eval_tokens import SELF, FIELD_BASE, _RET_BASE
        if _is_stack(v):
            return (SP0 + v - _STACK_TOP) & MASK64
        if v == SELF:
            return self.self_ptr
        if _RET_BASE <= v < FIELD_BASE:
            return self.returned.get((v - _RET_BASE) // 16)
        if _is_symbolic(v):
            return None
        return v & MASK64

    def _check(self, uc, k, prev, last):
        flow, rep, fn, ins = self.flow, self.report, self.va, self.flow.insns[k]
        if k not in self.known:
            rep.find("an instruction run that propagation from the entry does not reach", fn,
                     str(ins), key=flow._block_of[k])
            return
        for r, v in self.known[k].items():
            if r in _X and v is not None and (want := self._expect(v)) is not None:
                rep.stats["entry values"] += 1
                got = uc.reg_read(_X[r]) & MASK64
                if got != want:
                    rep.find("a value propagated from the entry that does not hold", fn,
                             "before %s: %s known %#x, ran %#x" % (ins, r, v, got), key=(k, r))
        for r, v in self.args.get(k, {}).items():
            if r in _X and (want := self._expect(v)) is not None:
                rep.stats["call arguments"] += 1
                got = uc.reg_read(_X[r]) & MASK64
                if got != want:
                    rep.find("a call argument run_from records that does not hold", fn,
                             "%s: %s recorded %#x, ran %#x" % (ins, r, v, got), key=(k, r))
        if k not in self.first and (ins.mnemonic in CALLS or ins.mnemonic == "br"):
            self.first.add(k)
            ops = ("x0", "x1", "x2") if ins.mnemonic in CALLS else (ins.op_str.strip(),)
            for r in (r for r in ops if r in _X):
                v = flow.value_at(0, self.numbers, k, r)
                if v is not None and not _is_symbolic(v):
                    rep.stats["value_at values"] += 1
                    got = uc.reg_read(_X[r]) & MASK64
                    if got != v & MASK64:
                        rep.find("a value value_at gives that does not hold", fn,
                                 "first at %s: %s value_at %#x, ran %#x" % (ins, r, v, got),
                                 key=(k, r))


def compare(ctx, functions, runs=4, report=None, entry=False):
    """A :class:`Report` of every check over *functions* (entry addresses), *runs* runs each;
    with *entry*, of :class:`EntryEmulation`'s."""
    report = report or Report()
    machine = make_machine(ctx)
    for va in functions:
        try:
            em = (EntryEmulation if entry else Emulation)(machine, va, report)
        except Exception as e:                   # a body the readers cannot build: not Flow's
            report.stats["functions not built: %s" % type(e).__name__] += 1
            continue
        report.stats["functions"] += 1
        for seed in range(runs):
            em.run((va << 8) | seed)
    return report


def main(argv):
    from macho.memory import BinaryContext
    from serializers.swift_descriptor_extract import load_macho_slice
    ctx = BinaryContext(load_macho_slice(open(argv[0], "rb").read()))
    every = int(argv[1]) if len(argv) > 1 else 50
    runs = int(argv[2]) if len(argv) > 2 else 4
    rep = compare(ctx, ctx.function_starts()[::every], runs)
    print(dict(rep.stats))
    print("faults", rep.faults.most_common(12))
    print("fault addresses >> 44", rep.fault_addrs.most_common(12))
    for kind, rows in rep.findings.items():
        print("==", kind, rep.stats[kind])
        for row in rows[:10]:
            print("   ", row)


if __name__ == "__main__":
    main(sys.argv[1:])
