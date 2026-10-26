"""An independent field number <-> name oracle for swift-protobuf messages, from ``traverse``
and the struct's own layout -- not from the ``_protobuf_nameMap`` the extractor reads.

``traverse(visitor:)`` visits field N with the value read from a storage LOCATION of ``self``.
A location is a root -- ``self`` passed indirectly in x20, or the i-th GPR / j-th FPR part of a
``self`` passed in registers (traverse's GPR parts start at x1, after the inout visitor; a
getter's at x0) -- and the chain of load offsets from it.  An offset is a constant, or an
offset ATOM read at run time: a 32-bit load off a metadata accessor's result
(``("meta", accessor, disp)``) or a word loaded from a fixed address (``("glob", address)``).
Two things name a location:

* the instance getter ``<type><property>…vg`` of a STORED property (a field record of the type
  or of a class one of its records holds, its ``_StorageClass``; a computed property may read a
  stored field under another name) returns the value at it.  A getter may return it through a
  constant default (``csel w0, wzr, w8, eq``: ``_x ?? 0``), or tail-call a body merged across
  types (``…vgTm``) with the metadata accessor it needs as an argument;
* the type's metadata: an offset the type's metadata supplies -- ``add self, <the type's metadata
  accessor()>[disp]`` -- is entry ``(disp - FieldOffsetVectorOffset) / 4`` of the field offset
  vector, whose order is the field records'.  A field one load further in, at a class's field
  offset global (``ldr x8, <…Wvd>``), is the class field that global's symbol names, when the
  record loaded from is typed by a direct reference to that class.

Only visits whose Visitor method :func:`serializers.swift_message_code.visit_methods` names
are read (the method fixes the field number's register); a location two visits or two
properties share names nothing, and nor does one the getters and the metadata name apart."""
import re
from typing import Dict, List, Optional, Set, Tuple

from proto.arm64_eval import _is_stack
from proto.arm64_operands import (CALLS, LOAD_BYTES, PAIR_LOADS, PAIR_STORES, POINTER_AUTH, RETURNS,
                                  STORE_BYTES, branch_target, parse_mem, reg_name, split_ops,
                                  writeback_base)
from macho.disasm import _parse_imm
from macho.memory import READ_ERRORS
from serializers import swift_descriptor_extract as S
from serializers import swift_message_code as MC
from serializers import swift_symbols as SY
from serializers.swift_symbols import read_i32 as _i32, read_u16 as _u16, read_u32 as _u32
from serializers.swift_type_recovery import _cstr, _demangle_one, _relptr

_LOADS = frozenset(("ldr", "ldur", "ldrb", "ldurb", "ldrh", "ldurh", "ldrsw", "ldursw", "ldp"))
_WIDTH = {"x": 8, "w": 4, "d": 8, "s": 4, "q": 16, "h": 2, "b": 1}
_RET_TAIL = frozenset(("swift_retain", "swift_bridgeObjectRetain", "objc_retain"))  # return x0
_ATOMS = ("meta", "glob")
_FP_CONST = frozenset(("movi", "fmov"))
_MAX_DEPTH = 24
_ACCESS_BUFFER = 24    # swift_beginAccess's ValueBuffer: 3 words the runtime keeps in its access set


def _callee(ctx, va) -> str:
    return SY.symbol_at(ctx, va).lstrip("_")


def _const(flow, k, reg, entry, depth=0) -> Optional[int]:
    """*reg*'s constant before ``insns[k]``, through moves and in-place pointer signing; a register
    a merged body is entered with takes its value from *entry*."""
    reg = reg_name(reg)
    if reg == "xzr":
        return 0
    defs = flow.defs_before(k, reg) if reg and depth <= _MAX_DEPTH else ()
    if len(defs) != 1:
        return None
    (d,) = defs
    if d < 0:
        return entry.get(reg) if entry else None
    ins = flow.insns[d]
    ops = split_ops(ins.op_str)
    if ins.mnemonic in POINTER_AUTH and ops and reg_name(ops[0]) == reg or \
            ins.mnemonic == "mov" and len(ops) == 2 and not ops[1].startswith("#"):
        return _const(flow, d, ops[-1] if ins.mnemonic == "mov" else reg, entry, depth + 1)
    return flow.const_before(k, reg)


def _is_const(flow, k, tok, entry) -> bool:
    """Whether operand *tok* before ``insns[k]`` is a constant (an integer, or an FP register a
    ``movi`` / ``fmov #imm`` / ``fmov dN, xzr`` set)."""
    reg = reg_name(tok)
    if reg is None:
        return False
    if reg.startswith("v"):
        defs = flow.defs_before(k, reg)
        if len(defs) != 1 or min(defs) < 0:
            return False
        ins = flow.insns[min(defs)]
        ops = split_ops(ins.op_str)
        return ins.mnemonic in _FP_CONST and len(ops) == 2 and \
            (ops[1].startswith("#") or reg_name(ops[1]) == "xzr")
    return _const(flow, k, reg, entry) is not None


def _call_target(flow, d, entry) -> Optional[int]:
    ins = flow.insns[d]
    if ins.mnemonic == "bl":
        return branch_target(ins)
    ops = split_ops(ins.op_str)
    return _const(flow, d, ops[0], entry) if ops else None


def _loc(flow, k, reg, kind, memo, depth=0, entry=None):
    """*reg* before ``insns[k]``: ``("addr", root, path, off)``, ``("val", root, path)``, an
    offset atom (``("meta", accessor, disp)`` / ``("glob", address)``), a call's result
    (``("ret", target)``), or None.  *entry*: the
    constant arguments a merged body is entered with; its only root is then self (x20)."""
    if depth > _MAX_DEPTH:
        return None
    reg = reg_name(reg)
    defs = flow.defs_before(k, reg) if reg else ()
    if len(defs) != 1:
        return None
    (d,) = defs
    if d < 0:
        if reg == "x20":
            return ("addr", ("self",), (), 0)
        m = re.fullmatch(r"([xv])(\d+)", reg)
        if not m or entry is not None:
            return None
        i = int(m.group(2)) - (1 if kind == "traverse" and m.group(1) == "x" else 0)
        return ("val", ("gpr" if m.group(1) == "x" else "fpr", i), ()) if 0 <= i <= 7 else None
    if flow.fragment(d) is not None and not (
            flow.fragment_calls(d) and reg in flow.tail_writes(d)):
        return None         # set by outlined code; one a thunk's tail call sets is the bl's (below)
    key = (d, reg)
    if key in memo:
        return memo[key]
    memo[key] = None
    ins = flow.insns[d]
    ops = split_ops(ins.op_str)
    mn = ins.mnemonic
    mem = next((i for i, o in enumerate(ops) if o.startswith("[")), None)
    res = None
    if mem is not None and writeback_base(ops) == reg:
        # the base a pre-index (``[x20, #8]!``) or post-index (``[x20], #8``) access moved
        pm = parse_mem(ops[mem])
        step = pm.disp if ops[mem].endswith("!") else \
            _parse_imm(ops[mem + 1]) if len(ops) > mem + 1 else None
        b = _addr(flow, d, pm.base, kind, memo, depth, entry) if pm else None
        if b is not None and isinstance(b[2], int) and step is not None:
            res = ("addr", b[0], b[1], b[2] + step)
    elif (mn in ("mov", "fmov") and len(ops) == 2 and not ops[1].startswith("#")) or \
            (mn in POINTER_AUTH and ops and reg_name(ops[0]) == reg):
        res = _loc(flow, d, ops[1] if mn in ("mov", "fmov") else reg, kind, memo, depth + 1, entry)
    elif mn in CALLS and reg == "x0":
        t = _call_target(flow, d, entry)
        if _callee(flow.ctx, t) in _RET_TAIL:
            res = _loc(flow, d, "x0", kind, memo, depth + 1, entry)     # a retain returns its x0
        elif t is not None:
            res = ("ret", t)                                    # what the call at t returned
    elif mn in ("csel", "fcsel") and len(ops) == 4:
        # ``_x ?? default``: the location, or a constant in its place
        ca, cb = (_is_const(flow, d, o, entry) for o in ops[1:3])
        if ca != cb:
            v = _loc(flow, d, ops[2] if ca else ops[1], kind, memo, depth + 1, entry)
            res = v if v is not None and v[0] == "val" else None
    elif mn == "and" and len(ops) == 3 and ops[2].startswith("#"):
        # bits of one stored value: ``Bool?``'s payload bit, a bridged object's address bits
        v = _loc(flow, d, ops[1], kind, memo, depth + 1, entry)
        res = v if v is not None and v[0] == "val" else None
    elif mn == "add" and len(ops) == 3 and ops[2].startswith("#"):
        b = _addr(flow, d, ops[1], kind, memo, depth, entry)
        if b is not None and isinstance(b[2], int):
            res = ("addr", b[0], b[1], b[2] + int(ops[2][1:], 0))
    elif mn == "add" and len(ops) == 3:
        x, y = (_loc(flow, d, o, kind, memo, depth + 1, entry) for o in ops[1:])
        if x is not None and x[0] in _ATOMS:
            x, y = y, x
        b = _as_addr(x)
        if b is not None and y is not None and y[0] in _ATOMS and b[2] == 0:
            res = ("addr", b[0], b[1], y)
    elif mn in _LOADS and mem == (2 if mn == "ldp" else 1) and len(ops) in (mem + 1, mem + 2):
        pm = parse_mem(ops[mem])        # a post-index access reads at its base
        if pm is not None and pm.index is None:
            glob = _const(flow, d, pm.base, entry) if mn == "ldr" and ops[0].startswith("x") \
                else None
            got = _loc(flow, d, pm.base, kind, memo, depth + 1, entry)
            if got is not None and got[0] == "ret":
                # a 32-bit offset read off a metadata accessor's result
                if mem == 1 and (mn == "ldrsw" or (mn == "ldr" and ops[0].startswith("w"))):
                    res = ("meta", got[1], pm.disp)
            elif glob is not None:
                res = ("glob", glob + pm.disp)
            else:
                dests = [reg_name(o) for o in ops[:mem]]
                lane = dests.index(reg) if reg in dests else None
                b = _addr(flow, d, pm.base, kind, memo, depth, entry)
                if b is None or lane is None:
                    pass
                elif isinstance(b[2], int):
                    res = ("val", b[0], b[1] + (b[2] + pm.disp + lane * _WIDTH.get(ops[0][0], 8),))
                elif pm.disp == 0 and lane == 0:
                    res = ("val", b[0], b[1] + (b[2],))
    memo[key] = res
    return res


def _as_addr(v):
    """A value as an address ``(root, path, off)``: a loaded pointer is dereferenced."""
    if v is None or v[0] not in ("addr", "val"):
        return None
    return (v[1], v[2], v[3]) if v[0] == "addr" else (v[1], v[2], 0)


def _addr(flow, k, reg, kind, memo, depth, entry=None):
    return _as_addr(_loc(flow, k, reg, kind, memo, depth + 1, entry))


def _location(v):
    """The storage location a value came from (or, passed by address, is)."""
    if v is None or v[0] not in ("addr", "val"):
        return None
    return (v[1], v[2]) if v[0] == "val" else (v[1], v[2] + (v[3],))


class _Stores:
    """A :meth:`Flow.forward` state: the last store into each frame slot, ``{address: (size,
    store index, register stored or None)}``; the frame ranges a later callee can still write
    (*kept*); the lowest frame address a pointer the function does not track may hold (*esc*)."""
    __slots__ = ("slots", "kept", "esc")

    def __init__(self, slots=None, kept=frozenset(), esc=None):
        self.slots, self.kept, self.esc = dict(slots or {}), kept, esc

    def copy(self):
        return _Stores(self.slots, self.kept, self.esc)

    def join(self, other):
        esc = [e for e in (self.esc, other.esc) if e is not None]
        return _Stores({a: v for a, v in self.slots.items() if other.slots.get(a) == v},
                       self.kept | other.kept, min(esc) if esc else None)

    def same(self, other):
        return self.slots == other.slots and self.kept == other.kept and self.esc == other.esc

    def kill(self, lo, hi=None):
        self.slots = {a: v for a, v in self.slots.items()
                      if a + v[0] <= lo or (hi is not None and a >= hi)}


class _Frame:
    """The last store reaching each frame slot, over the function's CFG.

    Frame addresses are :meth:`Flow.propagate`'s (sp at a fixed top on entry).  A store to a
    known frame address writes its slots.  A callee writes a frame object only while it runs
    -- it is handed the object's address (in x0-x8) and may write from it upward -- since a
    swift indirect argument is borrowed for the call alone; the exception is
    ``swift_beginAccess``, whose access buffer (x1, 24 bytes) stays in the runtime's access set,
    so every later call may write it.  A store through a pointer that may hold a frame address
    (one that has been in a register other than sp / x29, *esc*) clears the slots from the
    lowest such address up; a pointer derived from the function's arguments cannot, unless a
    frame address was stored to memory."""

    def __init__(self, ctx, flow):
        self.ctx, self.flow = ctx, flow
        n = len(flow.insns)
        self._inside: Dict[int, List[Dict[str, int]]] = {}     # in each outlined fragment run
        self.regs = flow.propagate({}, range(n), fragments_out=self._inside)
        self._before: Dict[int, _Stores] = {}
        self._leaked = any(                         # a frame address stored to memory
            _is_stack(self.regs.get(k, {}).get(reg_name(r)))
            for k, ins in enumerate(flow.insns)
            if ins.mnemonic in STORE_BYTES or ins.mnemonic in PAIR_STORES
            for r in split_ops(ins.op_str)[:-1] if not r.startswith("[") and not r.startswith("#"))
        states = flow.forward([(flow.cfg.entry, _Stores())], self._run_block)
        for blk, st in (states or {}).items():
            st = st.copy()
            for k in flow.block_range(blk):
                self._before[k] = st.copy()
                self._step(st, k)

    def stack(self, k, reg, regs=None) -> Optional[int]:
        v = (self.regs.get(k, {}) if regs is None else regs).get(reg_name(reg) or reg)
        return v if _is_stack(v) else None

    def last_store(self, k, addr) -> Optional[Tuple[int, str]]:
        """``(store index, register)`` of the one store whose value the slot at *addr* holds
        before ``insns[k]``."""
        st = self._before.get(k)
        v = st.slots.get(addr) if st is not None else None
        return (v[1], v[2]) if v is not None and v[2] is not None else None

    def _run_block(self, blk, st):
        for k in self.flow.block_range(blk):
            self._step(st, k)
        return [(s, st) for s in self.flow.cfg.succ.get(blk, [])]

    def _unknown_store(self, st, k, base):
        """A store through *base*, whose value is not a known address."""
        v = _loc(self.flow, k, base, "traverse", {})
        if v is not None and v[0] in ("addr", "val") and not self._leaked:
            return                                  # into memory the arguments reach
        if st.esc is not None:
            st.kill(st.esc)

    def _step(self, st, k):
        flow, ins = self.flow, self.flow.insns[k]
        regs = self.regs.get(k, {})
        for r, v in regs.items():                   # a frame address in a register
            if r not in ("sp", "x29") and _is_stack(v):
                st.esc = v if st.esc is None else min(st.esc, v)
        mn, ops = ins.mnemonic, split_ops(ins.op_str)
        frag = flow.fragment(k) if mn in CALLS else None
        if frag is not None:
            if any("[" in fi.op_str and fi.mnemonic not in LOAD_BYTES and
                   fi.mnemonic not in PAIR_LOADS and fi.mnemonic != "prfm" for fi in frag):
                st.slots.clear()                    # an outlined fragment that writes memory
            if flow.fragment_calls(k):              # a thunk: then its tail call
                inside = self._inside.get(k)
                regs = inside[-1] if inside else {}
                self._call(st, k, flow.thunk_target(k, regs), regs)
            return
        if mn in CALLS:
            self._call(st, k, _call_target(flow, k, None), self.regs.get(k, {}))
            return
        mem = next((i for i, o in enumerate(ops) if o.startswith("[")), None)
        if mem is None or mn in LOAD_BYTES or mn in PAIR_LOADS or mn == "prfm":
            return
        pm = parse_mem(ops[mem])
        if pm is None:
            st.slots.clear()
            return
        base = regs.get(reg_name(pm.base) or pm.base)
        known = mn in STORE_BYTES or mn in PAIR_STORES
        srcs = ops[:mem] if known and pm.index is None else []
        if base is None:
            self._unknown_store(st, k, pm.base)
            return
        if not _is_stack(base):
            return
        if not srcs:
            st.kill(base)
            return
        addr = base + (pm.disp if ops[mem].endswith("!") or len(ops) == mem + 1 else 0)
        w = STORE_BYTES.get(mn) or _WIDTH.get(srcs[0][0], 8)
        st.kill(addr, addr + w * len(srcs))
        for i, r in enumerate(srcs):
            st.slots[addr + i * w] = (w, k, None if reg_name(r) == "xzr" else reg_name(r))

    def _call(self, st, k, target, regs):
        """A call at ``insns[k]`` to *target*, the registers before it *regs*."""
        for lo, hi in st.kept:
            st.kill(lo, hi)
        for r in (f"x{i}" for i in range(9)):
            v = self.stack(k, r, regs)
            if v is not None:
                st.kill(v)
        if self._leaked and st.esc is not None:
            st.kill(st.esc)
        if _callee(self.ctx, target) == "swift_beginAccess":
            b = self.stack(k, "x1", regs)
            if b is not None:
                st.kept = st.kept | {(b, b + _ACCESS_BUFFER)}


def _proven_equal(flow, k, c):
    """The value a branch proved equal to the constant *c* on the only way into ``insns[k]``'s
    block: ``cmp wN, #c ; b.ne`` falling through to it, or ``b.eq`` to it (a ``true`` the
    compiler passes for ``self.flag`` once it has tested ``self.flag == true``)."""
    blk = flow._block_of.get(k)
    preds = [p for p, ss in flow.cfg.succ.items() if blk in ss]
    if blk is None or len(preds) != 1:
        return None
    last = flow.cfg.blocks[preds[0]][-1]
    kl = flow.addr_idx[last.addr]
    nxt = flow.insns[kl + 1].addr if kl + 1 < len(flow.insns) else None
    taken = branch_target(last) == blk if last.mnemonic in ("b.eq", "b.ne") else None
    if taken is None or taken == (nxt == blk) or (last.mnemonic == "b.eq") != taken or kl < 1:
        return None
    cmp = flow.insns[kl - 1]
    ops = split_ops(cmp.op_str)
    if cmp.mnemonic != "cmp" or len(ops) != 2 or _parse_imm(ops[1]) != c:
        return None
    return _loc(flow, kl - 1, ops[0], "traverse", {})


def traverse_locations(ctx, va) -> Dict[tuple, int]:
    """{location: field number} over the visits :func:`MC.visit_methods` names."""
    flow = SY.function_flow(ctx, va)
    if flow is None:
        return {}
    visits = MC.visit_methods(ctx, va)
    out: Dict[tuple, int] = {}
    shared = set()
    frame = None
    for k in range(len(flow.insns)):
        visit = visits.get(k)
        nreg = MC.visit_number_register(*visit) if visit else None
        num = flow.const_before(k, nreg) if nreg else None
        if num is None:
            continue
        vreg = "v0" if visit[0] == "Singular" and visit[1] in ("Float", "Double") else "x0"
        where = _location(_loc(flow, k, vreg, "traverse", {}))
        if where is None and vreg == "x0":
            # a value passed by address after a copy into the frame: the stored value's location
            frame = frame or _Frame(ctx, flow)
            a = frame.stack(k, "x0")
            last = frame.last_store(k, a) if a is not None else None
            v = _loc(flow, last[0], last[1], "traverse", {}) if last else None
            where = _location(v) if v is not None and v[0] == "val" else None
        if where is None and visit == ("Singular", "Bool"):
            c = flow.const_before(k, "x0")
            v = _proven_equal(flow, k, c) if c is not None else None
            where = _location(v) if v is not None and v[0] == "val" else None
        if where is None:
            continue
        if out.get(where, num) != num:
            shared.add(where)
        out[where] = num
    return {w: n for w, n in out.items() if w not in shared}


def getter_location(ctx, va, fp=False, entry=None, depth=0) -> Optional[tuple]:
    """The one location a getter returns the value at, or None; it returns in v0 when *fp* (a
    ``Double`` / ``Float`` property), else in x0.  A tail call that passes every argument on
    unchanged is the getter under another name (identical code folded); a getter that tail-calls
    a body merged across types hands it its constant arguments (*entry*), self staying in x20."""
    insns = S.function_body(ctx, va)
    flow = S._flow_of(ctx, insns)
    inside = {i.addr for i in insns}
    found = set()
    for k, ins in enumerate(insns):
        if ins.mnemonic in RETURNS:
            reg = "v0" if fp else "x0"
        elif ins.mnemonic == "b" and branch_target(ins) not in inside:
            t = branch_target(ins)
            if _callee(ctx, t) in _RET_TAIL and not fp:
                reg = "x0"
            elif entry is None and depth < 2 and flow.from_entry(k, "x20"):
                args = [f"{x}{i}" for x in "xv" for i in range(8)]
                sub = None if all(flow.from_entry(k, r) for r in args) else \
                    {r: c for r in args[:8] if (c := _const(flow, k, r, None)) is not None}
                if sub == {}:
                    return None
                try:
                    found.add(getter_location(ctx, t, fp, sub, depth + 1))
                except READ_ERRORS:
                    return None
                continue
            else:
                return None
        else:
            continue
        where = _location(_loc(flow, k, reg, "getter", {}, entry=entry))
        if where is None:
            return None
        found.add(where)
    return found.pop() if len(found) == 1 else None


def _records(ctx, desc) -> List[Tuple[str, int]]:
    """``(name, record address)`` of each field record of the type at *desc*."""
    fd = _relptr(ctx, desc + 0x10)
    n, size = _u32(ctx, fd + 0x0C), _u16(ctx, fd + 0x0A) or 12
    recs = [fd + 0x10 + i * size for i in range(n)]
    return [(_cstr(ctx, _relptr(ctx, r + 0x08)), r) for r in recs]


def _class_ref(ctx, record) -> Optional[int]:
    """The class descriptor a field record's type names, when the type is exactly a direct
    symbolic reference (``\\x01`` + 32-bit offset) to it."""
    tn = _relptr(ctx, record + 0x04)
    b = ctx.read_bytes(tn, 6)
    return tn + 1 + _i32(ctx, tn + 1) if b[0] == 1 and b[5] == 0 else None


def _held_classes(ctx, desc) -> List[int]:
    return [c for c in (_class_ref(ctx, r) for _n, r in _records(ctx, desc)) if c is not None]


def stored_names(ctx, desc) -> Set[str]:
    """The stored properties of the type at *desc* and of the classes its records hold."""
    out = set()
    for d in [desc] + _held_classes(ctx, desc):
        out.update(n.lstrip("_") for n, _r in _records(ctx, d) if n)
    return out


def _member(sym, prefix) -> Optional[Tuple[str, str]]:
    """``(identifier, rest)`` of the member *sym* names right after *prefix*; the identifier is
    demangled with the word table the prefix built."""
    lead = 3 if prefix.startswith("_$s") else 2
    head, body = len(prefix) - lead, sym[lead:]
    i, words = 0, []
    while i < head:
        if not body[i].isdigit():
            i += 1
            continue
        ident, i = _demangle_one(body, i, words)
        if ident is None:
            return None
    if i != head or not body[i:i + 1].isdigit():
        return None
    ident, j = _demangle_one(body, i, words)
    return (ident, body[j:]) if ident else None


def getters(names, prefix, stored) -> Dict[str, Tuple[int, bool]]:
    """{stored property: (getter, returns a Double / Float)} for ``<prefix><ident><type>vg``
    getters of this very type."""
    out = {}
    for n, va in names.items():
        if not n.startswith(prefix) or not n.endswith("vg") or n.endswith("vgZ"):
            continue
        m = _member(n, prefix)
        if m is None:
            continue
        ident, tail = m
        if ident in stored and not (len(tail) > 1 and tail[0] in "VOC" and tail[1].isdigit()):
            out[ident] = (va, tail in ("Sdvg", "Sfvg"))
    return out


def _meta_index(ctx, desc, atom) -> Optional[int]:
    """The field record index at ``atom = ("meta", accessor called, disp)``: the accessor must be
    the type's own (StructDescriptor.AccessFunction), and disp indexes the field offset vector
    (FieldOffsetVectorOffset words into the metadata, 4 bytes an entry)."""
    if desc is None or atom[0] != "meta" or _relptr(ctx, desc + 0x0C) != atom[1]:
        return None
    i, r = divmod(atom[2] - _u32(ctx, desc + 0x18) * 8, 4)
    return i if not r and 0 <= i < _u32(ctx, _relptr(ctx, desc + 0x10) + 0x0C) else None


class _Symbols:
    """The image's class descriptors and field offset globals, by address."""
    def __init__(self, names):
        self.classes: Dict[int, str] = {}
        self.offsets: Dict[int, List[str]] = {}
        for n, a in names.items():
            if n.endswith("CMn"):
                self.classes[a] = n
            elif n.endswith("Wvd"):
                self.offsets.setdefault(a, []).append(n)

    def class_field(self, ctx, cls, glob) -> Optional[str]:
        """The field of class *cls* whose offset global (``<class><field>…vpWvd``) is at *glob*."""
        sym = self.classes.get(cls)
        if sym is None:
            return None
        stored = {n for n, _r in _records(ctx, cls)}
        hits = {m[0] for m in (_member(s, sym[:-2]) for s in self.offsets.get(glob, ()))
                if m and m[0] in stored and m[1].endswith("vpWvd")}
        return hits.pop() if len(hits) == 1 else None


def layout_name(ctx, desc, where, syms: _Symbols) -> Optional[str]:
    """The stored property at *where* by the type's metadata (see the module docstring)."""
    root, path = where
    if root != ("self",) or not path or not isinstance(path[0], tuple):
        return None
    i = _meta_index(ctx, desc, path[0])
    if i is None:
        return None
    name, record = _records(ctx, desc)[i]
    if len(path) == 1:
        return name
    if len(path) == 2 and isinstance(path[1], tuple) and path[1][0] == "glob":
        cls = _class_ref(ctx, record)
        return syms.class_field(ctx, cls, path[1][1]) if cls is not None else None
    return None


def oracle(ctx, names, conflicts=None) -> Dict[Tuple[str, str], Dict[int, str]]:
    """{(module, type): {field number: stored property name}} for every message *names* has a
    ``traverse`` for (*names*: the image's symbols -- traverse, getters, ``…Mn`` descriptors,
    ``…Wvd`` field offset globals).  A location the getters and the metadata name apart is
    appended to *conflicts* and names nothing."""
    out = {}
    syms = _Symbols(names)
    for n, va in names.items():
        if "V8traverse" not in n or not n.endswith(S._FUNCTION_BODY_SUFFIXES):
            continue
        t = S._type_of_symbol(n, "8traverse")
        if not t or t[2] != "V" or t[:2] in out:
            continue
        prefix = n[:n.index("8traverse")]
        tloc = traverse_locations(ctx, va)
        if not tloc:
            continue
        desc = names.get(prefix + "Mn")
        by_loc: Dict[tuple, Set[str]] = {}
        if desc is not None:
            for prop, (gva, fp) in getters(names, prefix, stored_names(ctx, desc)).items():
                where = getter_location(ctx, gva, fp)
                if where is not None:
                    by_loc.setdefault(where, set()).add(prop)
        fields = {}
        for where, num in tloc.items():
            props = by_loc.get(where, ())
            got = {x.lstrip("_") for x in (next(iter(props)) if len(props) == 1 else None,
                                           layout_name(ctx, desc, where, syms)) if x}
            if len(got) == 1:
                fields[num] = got.pop()
            elif got and conflicts is not None:
                conflicts.append((t[:2], num, where, sorted(got)))
        if fields:
            out[t[:2]] = fields
    return out


def same_name(proto_name: str, swift_name: str) -> bool:
    """protoc-gen-swift's property for a proto field: lowerCamelCase of the proto name, with
    ``_p`` appended to a Swift keyword."""
    a, b = proto_name.replace("_", "").lower(), swift_name.replace("_", "").lower()
    return a == b or a + "p" == b
