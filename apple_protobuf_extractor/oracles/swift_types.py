"""An image's Swift nominal types, read from ``__swift5_types`` for the oracles: each type's
kind, qualified name and mangled name, by the Swift ABI's layout of the records and context
descriptors (swift/include/swift/ABI/Metadata.h) -- not by the readers of the analysis the
oracles check (:mod:`serializers.swift_type_recovery`).

* a ``__swift5_types`` record: a 32-bit relative pointer whose low two bits are its
  TypeReferenceKind -- 0 the context descriptor itself, 1 a pointer to it, 2 / 3 an ObjC class
  (no Swift descriptor);
* a context descriptor: ``flags`` (u32, the kind in its low five bits: 0 module, 1 extension,
  2 anonymous, 3 protocol, 16 class, 17 struct, 18 enum), ``parent`` (a relative pointer,
  indirect when its low bit is set), and for a module, a protocol or a nominal type its ``name``
  (a relative pointer to a C string) at +8;
* a ``__swift5_proto`` record: a 32-bit relative pointer to a protocol conformance descriptor --
  ``protocol`` (a relative pointer, indirect when its low bit is set), ``type`` (a relative
  pointer read as the TypeReferenceKind in bits 3-5 of its ``flags`` at +12 says: 0 the type
  descriptor, 1 a pointer to it, 2 / 3 an ObjC class).
"""
import struct
from typing import Dict, List, NamedTuple, Optional, Set, Tuple

MODULE, PROTOCOL, CLASS, STRUCT, ENUM = 0, 3, 16, 17, 18
_NOMINAL_CODE = {STRUCT: "V", ENUM: "O", CLASS: "C"}
_MAX_DEPTH = 64                       # a parent chain longer than this is not a real one


class SwiftType(NamedTuple):
    desc: int
    kind: int
    name: str
    qualified: Optional[str]          # ``Outer.Inner``: the enclosing nominal types' names
    mangled: Optional[str]            # ``$s<module><Outer>V<Inner>V``; None inside an
                                      # extension or an anonymous context
    owner: Optional[str]              # the qualified name of the enclosing nominal type


def _i32(ctx, va) -> int:
    return struct.unpack("<i", ctx.read_bytes(va, 4))[0]


def _cstring(ctx, va) -> str:
    out = b""
    while b"\0" not in out:
        out += ctx.read_bytes(va + len(out), 16)
    return out.split(b"\0", 1)[0].decode("utf-8", "replace")


def _parent(ctx, desc) -> int:
    v = _i32(ctx, desc + 4)
    if not v:
        return 0
    return ctx.read_ptr(desc + 4 + (v & ~1)) if v & 1 else desc + 4 + v


def _kind(ctx, desc) -> int:
    return struct.unpack("<I", ctx.read_bytes(desc, 4))[0] & 0x1F


def _name(ctx, desc) -> str:
    return _cstring(ctx, desc + 8 + _i32(ctx, desc + 8))


def _chain(ctx, desc) -> List[int]:
    """*desc* and its parents, up to its module (empty when it cannot be read to one)."""
    out, cur = [], desc
    while cur and len(out) < _MAX_DEPTH:
        out.append(cur)
        if _kind(ctx, cur) == MODULE:
            return out
        cur = _parent(ctx, cur)
    return []


def _describe(ctx, desc) -> Optional[SwiftType]:
    chain = _chain(ctx, desc)
    if not chain:
        return None
    kinds = [_kind(ctx, d) for d in chain]
    names = [_name(ctx, d) if k in _NOMINAL_CODE or k == MODULE else None
             for d, k in zip(chain, kinds)]
    nominal = [n for n, k in zip(names[:-1], kinds[:-1]) if k in _NOMINAL_CODE]
    qualified = ".".join(reversed(nominal)) or None
    owner = ".".join(reversed([n for n, k in zip(names[1:-1], kinds[1:-1])
                               if k in _NOMINAL_CODE])) or None
    mangled = None
    if all(k in _NOMINAL_CODE for k in kinds[:-1]):
        module = names[-1]
        mangled = "$s%d%s" % (len(module), module) + "".join(
            "%d%s%s" % (len(n), n, _NOMINAL_CODE[k])
            for n, k in zip(reversed(names[:-1]), reversed(kinds[:-1])))
    return SwiftType(desc, kinds[0], names[0], qualified, mangled, owner)


def swift_types(ctx) -> List[SwiftType]:
    """The image's Swift nominal types (``__swift5_types``); an unreadable record or descriptor
    is left out."""
    try:
        sec = ctx.section("__TEXT", "__swift5_types")
    except Exception:
        return []
    out = []
    for va in range(sec.vmaddr, sec.vmaddr + sec.vmsize, 4):
        try:
            v = _i32(ctx, va)
            ref, target = v & 3, va + (v & ~3)
            if not v or ref > 1:
                continue
            desc = ctx.read_ptr(target) if ref == 1 else target
            t = _describe(ctx, desc)
        except Exception:
            continue
        if t is not None:
            out.append(t)
    return out


def by_qualified_name(types: List[SwiftType]) -> Dict[str, SwiftType]:
    return {t.qualified: t for t in types if t.qualified}


def _indirectable(ctx, va) -> int:
    v = _i32(ctx, va)
    if not v:
        return 0
    return ctx.read_ptr(va + (v & ~1)) if v & 1 else va + v


def conformances(ctx) -> Set[Tuple[int, str, str]]:
    """``{(type descriptor, protocol's module, protocol)}`` of the image's conformance records
    (``__swift5_proto``) whose conforming type is a Swift type descriptor; an unreadable record
    is left out."""
    try:
        sec = ctx.section("__TEXT", "__swift5_proto")
    except Exception:
        return set()
    out = set()
    for va in range(sec.vmaddr, sec.vmaddr + sec.vmsize, 4):
        try:
            cd = va + _i32(ctx, va)
            proto = _indirectable(ctx, cd)
            flags = struct.unpack("<I", ctx.read_bytes(cd + 12, 4))[0]
            ref = (flags >> 3) & 7
            if ref > 1 or _kind(ctx, proto) != PROTOCOL:
                continue
            target = cd + 4 + _i32(ctx, cd + 4)
            desc = ctx.read_ptr(target) if ref == 1 else target
            module = _parent(ctx, proto)
            out.add((desc, _name(ctx, module) if module else "", _name(ctx, proto)))
        except Exception:
            continue
    return out
