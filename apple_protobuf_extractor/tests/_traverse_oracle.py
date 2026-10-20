"""An independent field number <-> name oracle for swift-protobuf messages, from ``traverse``
and the struct's own layout -- not from the ``_protobuf_nameMap`` the extractor reads.

``traverse(visitor:)`` visits field N with the value read from a storage LOCATION of ``self``.
A location is a root -- ``self`` passed indirectly in x20, or the i-th GPR / j-th FPR part of a
``self`` passed in registers (traverse's GPR parts start at x1, after the inout visitor; a
getter's at x0) -- and the chain of load offsets from it.  Two things name a location:

* the instance getter ``<type><property>…vg`` of a STORED property (a field record of the type
  or of its ``_StorageClass``; a computed property may read a stored field under another name)
  returns the value at it;
* an offset the type's metadata supplies -- ``add self, <the type's metadata accessor()>[disp]``
  -- is entry ``(disp - FieldOffsetVectorOffset) / 4`` of the field offset vector, whose order is
  the field records'.

Only visits whose Visitor method :func:`serializers.swift_descriptor_extract._visit_method` names
are read (the method fixes the field number's register); a location two visits or two
properties share names nothing."""
import re
from typing import Dict, Optional, Set, Tuple

from macho.disasm import _norm_reg
from proto.arm64_operands import CALLS, RETURNS, parse_mem, split_ops
from serializers import swift_descriptor_extract as S
from serializers.swift_type_recovery import _cstr, _demangle_one, _relptr, _u16, _u32

_LOADS = frozenset(("ldr", "ldur", "ldrb", "ldurb", "ldrh", "ldurh", "ldrsw", "ldursw", "ldp"))
_WIDTH = {"x": 8, "w": 4, "d": 8, "s": 4, "q": 16, "h": 2, "b": 1}
_RET_TAIL = ("swift_retain", "swift_bridgeObjectRetain", "objc_retain")   # return their x0
_MAX_DEPTH = 24


def _loc(flow, k, reg, kind, memo, depth=0):
    """*reg* before ``insns[k]``: ``("addr", root, path, off)``, ``("val", root, path)``,
    ``("meta", accessor, disp)`` (a 32-bit load off a call's result), or None."""
    if depth > _MAX_DEPTH:
        return None
    reg = _norm_reg(reg)
    defs = flow.defs_before(k, reg)
    if len(defs) != 1:
        return None
    (d,) = defs
    if d < 0:
        if reg == "x20":
            return ("addr", ("self",), (), 0)
        m = re.fullmatch(r"([xv])(\d+)", reg)
        if not m:
            return None
        i = int(m.group(2)) - (1 if kind == "traverse" and m.group(1) == "x" else 0)
        return ("val", ("gpr" if m.group(1) == "x" else "fpr", i), ()) if 0 <= i <= 7 else None
    if flow.fragment(d) is not None:
        return None
    key = (d, reg)
    if key in memo:
        return memo[key]
    memo[key] = None
    ins = flow.insns[d]
    ops = split_ops(ins.op_str)
    mn = ins.mnemonic
    res = None
    if mn in ("mov", "fmov") and len(ops) == 2 and not ops[1].startswith("#"):
        res = _loc(flow, d, ops[1], kind, memo, depth + 1)
    elif mn == "add" and len(ops) == 3 and ops[2].startswith("#"):
        b = _addr(flow, d, ops[1], kind, memo, depth)
        if b is not None and isinstance(b[2], int):
            res = ("addr", b[0], b[1], b[2] + int(ops[2][1:], 0))
    elif mn == "add" and len(ops) == 3:
        x = _loc(flow, d, ops[1], kind, memo, depth + 1)
        y = _loc(flow, d, ops[2], kind, memo, depth + 1)
        if x is not None and x[0] == "meta":
            x, y = y, x
        if x is not None and y is not None and y[0] == "meta" and x[0] == "addr" and x[3] == 0:
            res = ("addr", x[1], x[2], y[1:])
    elif mn in _LOADS:
        nd = 2 if mn == "ldp" else 1
        pm = parse_mem(ops[-1]) if len(ops) == nd + 1 and not ops[-1].endswith("!") else None
        if pm is not None and pm.index is None:
            base = flow.defs_before(d, _norm_reg(pm.base))
            if nd == 1 and (mn == "ldrsw" or (mn == "ldr" and ops[0].startswith("w"))) and \
                    len(base) == 1 and min(base) >= 0 and flow.insns[min(base)].mnemonic == "bl" \
                    and flow.fragment(min(base)) is None:
                res = ("meta", S._branch_target(flow.insns[min(base)]), pm.disp)
            else:
                dests = [_norm_reg(o) for o in ops[:nd]]
                lane = dests.index(reg) if reg in dests else None
                b = _addr(flow, d, pm.base, kind, memo, depth)
                if b is None or lane is None:
                    pass
                elif isinstance(b[2], int):
                    res = ("val", b[0], b[1] + (b[2] + pm.disp + lane * _WIDTH.get(ops[0][0], 8),))
                elif pm.disp == 0 and lane == 0:
                    res = ("val", b[0], b[1] + (b[2],))
    memo[key] = res
    return res


def _addr(flow, k, reg, kind, memo, depth):
    """*reg* as an address ``(root, path, off)``: a loaded pointer is dereferenced."""
    v = _loc(flow, k, reg, kind, memo, depth + 1)
    if v is None or v[0] == "meta":
        return None
    return (v[1], v[2], v[3]) if v[0] == "addr" else (v[1], v[2], 0)


def _location(v):
    """The storage location a value came from (or, passed by address, is)."""
    if v is None or v[0] == "meta":
        return None
    return (v[1], v[2]) if v[0] == "val" else (v[1], v[2] + (v[3],))


def traverse_locations(ctx, va) -> Dict[tuple, int]:
    """{location: field number} over the visits :func:`S._visit_method` names."""
    insns = S._listing(ctx, va)
    flow = S._flow_of(ctx, insns)
    out: Dict[tuple, int] = {}
    shared = set()
    for k, ins in enumerate(insns):
        visit = S._visit_method(ctx, flow, k) if ins.mnemonic in CALLS else None
        nreg = S._visit_number_register(*visit) if visit else None
        num = flow.const_before(k, nreg) if nreg else None
        if num is None:
            continue
        vreg = "v0" if visit[0] == "Singular" and visit[1] in ("Float", "Double") else "x0"
        where = _location(_loc(flow, k, vreg, "traverse", {}))
        if where is None:
            continue
        if out.get(where, num) != num:
            shared.add(where)
        out[where] = num
    return {w: n for w, n in out.items() if w not in shared}


def getter_location(ctx, va) -> Optional[tuple]:
    """The one location a getter returns the value at, or None."""
    insns = S._listing(ctx, va)
    flow = S._flow_of(ctx, insns)
    found = set()
    for k, ins in enumerate(insns):
        if ins.mnemonic in RETURNS:
            regs = ("x0", "v0")
        elif ins.mnemonic == "b" and any(t in S._symbol_at(ctx, S._branch_target(ins))
                                         for t in _RET_TAIL):
            regs = ("x0",)
        else:
            continue
        got = [w for w in (_location(_loc(flow, k, r, "getter", {})) for r in regs) if w]
        if len(got) != 1:
            return None
        found.add(got[0])
    return found.pop() if len(found) == 1 else None


def _records(ctx, desc) -> list:
    fd = _relptr(ctx, desc + 0x10)
    n, size = _u32(ctx, fd + 0x0C), _u16(ctx, fd + 0x0A) or 12
    return [_cstr(ctx, _relptr(ctx, fd + 0x10 + i * size + 0x08)) for i in range(n)]


def stored_names(ctx, names, prefix) -> Set[str]:
    out = set()
    for d in (names.get(prefix + "Mn"), names.get(prefix + "13_StorageClassCMn")):
        if d is not None:
            out.update(n.lstrip("_") for n in _records(ctx, d) if n)
    return out


def getters(names, prefix, stored) -> Dict[str, int]:
    """{stored property: getter} for ``<prefix><ident><type>vg`` getters of this very type; the
    identifier is demangled with the word table the prefix built."""
    head = prefix[3:] if prefix.startswith("_$s") else prefix[2:]
    out = {}
    for n, va in names.items():
        if not n.startswith(prefix) or not n.endswith("vg") or n.endswith("vgZ"):
            continue
        body = n[len(prefix) - len(head):]
        i, words = 0, []
        while i < len(head):
            if not head[i].isdigit():
                i += 1
                continue
            ident, i = _demangle_one(body, i, words)
            if ident is None:
                break
        if i != len(head) or not body[i:i + 1].isdigit():
            continue
        ident, j = _demangle_one(body, i, words)
        tail = body[j:] if ident else ""
        if ident in stored and not (len(tail) > 1 and tail[0] in "VOC" and tail[1].isdigit()):
            out[ident] = va
    return out


def meta_field_name(ctx, desc, atom) -> Optional[str]:
    """The stored property at ``atom = (accessor called, disp)``: the accessor must be the type's
    own (StructDescriptor.AccessFunction), and disp indexes the field offset vector
    (FieldOffsetVectorOffset words into the metadata, 4 bytes an entry)."""
    target, disp = atom
    if desc is None or _relptr(ctx, desc + 0x0C) != target:
        return None
    i, r = divmod(disp - _u32(ctx, desc + 0x18) * 8, 4)
    recs = _records(ctx, desc)
    return recs[i] if not r and 0 <= i < len(recs) else None


def oracle(ctx, names) -> Dict[Tuple[str, str], Dict[int, str]]:
    """{(module, type): {field number: stored property name}} for every message *names* has a
    ``traverse`` for (*names*: the image's symbols -- traverse, getters, ``…Mn`` descriptors)."""
    out = {}
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
        by_loc: Dict[tuple, Set[str]] = {}
        for prop, gva in getters(names, prefix, stored_names(ctx, names, prefix)).items():
            where = getter_location(ctx, gva)
            if where is not None:
                by_loc.setdefault(where, set()).add(prop)
        desc = names.get(prefix + "Mn")
        fields = {}
        for where, num in tloc.items():
            last = where[1][-1] if where[1] else None
            if isinstance(last, tuple):
                name = meta_field_name(ctx, desc, last) \
                    if where[0] == ("self",) and len(where[1]) == 1 else None
            else:
                props = by_loc.get(where, ())
                name = next(iter(props)) if len(props) == 1 else None
            if name:
                fields[num] = name.lstrip("_")
        if fields:
            out[t[:2]] = fields
    return out


def same_name(proto_name: str, swift_name: str) -> bool:
    """protoc-gen-swift's property for a proto field: lowerCamelCase of the proto name, with
    ``_p`` appended to a Swift keyword."""
    a, b = proto_name.replace("_", "").lower(), swift_name.replace("_", "").lower()
    return a == b or a + "p" == b
