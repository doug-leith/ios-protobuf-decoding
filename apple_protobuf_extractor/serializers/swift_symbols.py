"""serializers/swift_symbols.py -- the symbols and Swift runtime records the swift-protobuf readers
name things by.

* :func:`symbol_addrs`: name -> address of the image's own symbols (where the name maps are found).
* :func:`names_at` / :func:`symbol_at`: address -> names, over those and, in a dyld cache, the
  exports of the image and of the swift-protobuf framework it links (protocol and requirement
  descriptors, dispatch thunks, witnesses).
* :func:`function_flow`: a function's :class:`~proto.arm64_eval.Flow`, once per address.
* :func:`protocol_requirements`: a protocol descriptor's requirements, by their descriptors' symbols.
* :func:`conformances`: the image's ``__swift5_proto`` records.
"""
from __future__ import annotations

import struct
from typing import Dict, Iterator, List, NamedTuple, Optional, Tuple

from macho.memory import READ_ERRORS, BinaryContext, _ctx_cache, record_unread
from proto.arm64_eval import Flow
from proto.callees import callee_name
from proto.dispatch import listing_flow
from proto.function_body import function_body

NAMEMAP_MARKER = "17_protobuf_nameMap"
SWIFT_PROTOBUF_MODULES = ("InternalSwiftProtobuf", "SwiftProtobuf")

# the cache symbols swift-protobuf recovery reads: name maps, traverse bodies, and the runtime
# helper a field's generic metadata is made with (serializers.swift_message_code.metadata_type)
_CACHE_SYMBOL_MARKERS = (NAMEMAP_MARKER, "V8traverse",
                         "swift_instantiateConcreteTypeFromMangledName")


# ── the image's own symbols ───────────────────────────────────────────────────

def symbol_addrs(ctx: BinaryContext) -> Dict[str, int]:
    """Map every declared symbol name → its vmaddr.

    Merges the ``LC_SYMTAB`` nlist (carries ``n_value`` for an image's own
    *internal* symbols, e.g. an app's message types) with the dyld export trie
    (exported symbols such as a framework's public types).

    Cache-native images keep no per-image symbol table in their (shared-LINKEDIT)
    Mach-O; instead the original local symbols — including each type's
    ``…_protobuf_nameMap`` static-init and ``…traverse`` symbols —
    live in the cache's ``.symbols`` sub-cache, keyed by vmaddr, and a public type's in the
    image's export trie.  There only the names swift-protobuf recovery reads are kept
    (:data:`_CACHE_SYMBOL_MARKERS`).  Returns ``{}`` when no symbol source is addressable."""
    reader = getattr(ctx, "_cache_reader", None)
    if reader is not None and getattr(ctx, "is_cache_backed", False):
        try:
            out = dict(reader.image_symbol_addrs(ctx.image_base, *_CACHE_SYMBOL_MARKERS))
            for name, addr in reader.image_exports(ctx.image_base).items():
                if any(m in name for m in _CACHE_SYMBOL_MARKERS):
                    out.setdefault(name, addr)
        except (OSError, *READ_ERRORS) as exc:
            record_unread(ctx, ".symbols local symbols", f"{ctx.image_base:#x}", exc)
            return {}
        return out

    out: Dict[str, int] = {}
    for name, addr in ctx.iter_symbols():
        if addr:
            out.setdefault(name, addr)
    return out


# ── address -> names ──────────────────────────────────────────────────────────

def _symbol_pairs(ctx: BinaryContext) -> Iterator[Tuple[str, Optional[int]]]:
    """``(name, address)`` of every symbol a swift-protobuf reader can name a thing by: a
    binary's own (nlist and export trie); in a dyld cache :func:`symbol_addrs` and the exports
    of the image and of the swift-protobuf framework it links."""
    reader = getattr(ctx, "_cache_reader", None)
    if reader is None or not getattr(ctx, "is_cache_backed", False):
        yield from ctx.iter_symbols()
        return
    yield from symbol_addrs(ctx).items()
    images = [ctx.image_base] + [
        reader.find_image_header(p) for p in reader.image_dependencies(ctx.image_base)
        if p.rsplit("/", 1)[-1] in SWIFT_PROTOBUF_MODULES]
    for mh in images:
        if mh is not None:
            yield from reader.image_exports(mh).items()


def _tables(ctx: BinaryContext) -> Tuple[Dict[int, Tuple[str, ...]], Dict[str, int]]:
    """``({address: names}, {name: address})`` of :func:`_symbol_pairs` (a name's first
    address).  Memoised."""
    def build():
        by_addr: Dict[int, List[str]] = {}
        by_name: Dict[str, int] = {}
        try:
            for name, addr in _symbol_pairs(ctx):
                if not addr:
                    continue
                names = by_addr.setdefault(addr, [])
                if name not in names:
                    names.append(name)
                by_name.setdefault(name, addr)
        except (OSError, *READ_ERRORS) as exc:
            record_unread(ctx, "swift-protobuf symbols", f"{getattr(ctx, 'image_base', 0):#x}", exc)
        return {a: tuple(ns) for a, ns in by_addr.items()}, by_name
    return _ctx_cache(ctx, "_swift_symbol_tables", build)


def names_at(ctx: BinaryContext, va: Optional[int]) -> Tuple[str, ...]:
    """Every symbol at *va* (:func:`_symbol_pairs`); a reader matches a pattern against all of
    them, so which of several aliases comes first does not matter."""
    return _tables(ctx)[0].get(va, ()) if va is not None else ()


def address_of(ctx: BinaryContext, name: str) -> Optional[int]:
    """The address of the symbol *name* (:func:`_symbol_pairs`), or None."""
    return _tables(ctx)[1].get(name)


def names_ending(ctx: BinaryContext, suffix: str) -> List[str]:
    """The symbols (:func:`_symbol_pairs`) whose name ends in *suffix*."""
    return [n for n in _tables(ctx)[1] if n.endswith(suffix)]


def function_names(ctx: BinaryContext, va: Optional[int]) -> Tuple[str, ...]:
    """The names of the function a call to *va* reaches: its export / import
    (:func:`proto.callees.callee_name`), then :func:`names_at`."""
    if va is None:
        return ()
    first = callee_name(ctx, va)
    rest = tuple(n for n in names_at(ctx, va) if n != first)
    return ((first,) + rest) if first else rest


def symbol_at(ctx: BinaryContext, va: Optional[int]) -> str:
    """The first of :func:`function_names`; "" when *va* has none."""
    names = function_names(ctx, va)
    return names[0] if names else ""


def referenced_names(ctx: BinaryContext, va: int, indirect: bool) -> Tuple[str, ...]:
    """The symbols a relative reference names (:func:`rel_indirect`): an indirect one's slot is
    bound to an import (its name) or holds the address."""
    if indirect:
        name = ctx.bind_name_for(va)
        if name:
            return (name,)
        va = ctx.read_ptr(va)
    return names_at(ctx, va)


# ── a function's flow ─────────────────────────────────────────────────────────

def function_flow(ctx: BinaryContext, va: int) -> Optional[Flow]:
    """The :class:`~proto.arm64_eval.Flow` of the function at *va* (its
    :func:`~proto.function_body.function_body`, each ``br`` reaching its decoded table), or None
    when it cannot be read.  Memoised per address."""
    memo = _ctx_cache(ctx, "_swift_function_flows", dict)
    if va not in memo:
        try:
            memo[va] = listing_flow(ctx, list(function_body(ctx, va)))
        except READ_ERRORS:
            memo[va] = None
    return memo[va]


# ── relative pointers ─────────────────────────────────────────────────────────

def read_i32(ctx, va: int) -> int:
    return struct.unpack("<i", ctx.read_bytes(va, 4))[0]


def read_u32(ctx, va: int) -> int:
    return struct.unpack("<I", ctx.read_bytes(va, 4))[0]


def rel(ctx, va: int) -> int:
    """The target of the relative direct pointer at *va*."""
    return va + read_i32(ctx, va)


def rel_indirect(ctx, va: int) -> Tuple[int, bool]:
    """A relative indirectable pointer: ``(target, through a slot)``; for an indirect one the
    slot's address (named by :func:`referenced_names`)."""
    v = read_i32(ctx, va)
    return (va + (v & ~1), True) if v & 1 else (va + v, False)


# ── protocols and conformances ────────────────────────────────────────────────

def protocol_requirements(ctx: BinaryContext, protocol: str) -> Tuple[Tuple[str, ...], ...]:
    """The names of each requirement of the protocol whose descriptor's symbol is *protocol*, in
    witness-table order after the table's first word (the conformance descriptor): the symbols
    at its requirement descriptor (``…Tq``).  The descriptor is flags, parent, name,
    NumRequirementsInSignature, NumRequirements, associated type names; then the signature's
    requirements (12 bytes each) and the protocol's own (8 bytes each).  Empty when the image
    cannot see it.  Memoised."""
    memo = _ctx_cache(ctx, "_swift_protocol_requirements", dict)
    if protocol not in memo:
        memo[protocol] = _requirements(ctx, protocol)
    return memo[protocol]


def _requirements(ctx: BinaryContext, protocol: str) -> Tuple[Tuple[str, ...], ...]:
    va = address_of(ctx, protocol)
    if va is None:
        return ()
    try:
        _f, _p, _n, nsig, nreq, _a = struct.unpack("<IiiIIi", ctx.read_bytes(va, 24))
    except READ_ERRORS:
        return ()
    start = va + 24 + 12 * nsig
    return tuple(names_at(ctx, start + 8 * i) for i in range(nreq))


class Conformance(NamedTuple):
    """One ``__swift5_proto`` record: the protocol's names (:func:`referenced_names`), the
    conforming type's nominal type descriptor (None when the record references no type
    descriptor or it cannot be read), and its witnesses -- a static witness table's address,
    or the resilient witnesses (requirement names, implementation)."""
    protocol: Tuple[str, ...]
    type_descriptor: Optional[int]
    witness_table: Optional[int] = None
    resilient: Tuple[Tuple[Tuple[str, ...], int], ...] = ()


def conformances(ctx: BinaryContext) -> List[Conformance]:
    """Every protocol conformance record of the image.  Memoised."""
    return _ctx_cache(ctx, "_swift_conformances", lambda: _conformances(ctx))


_RESILIENT_WITNESSES = 1 << 16
_RETROACTIVE = 1 << 6


def _conformances(ctx: BinaryContext) -> List[Conformance]:
    out: List[Conformance] = []
    if not ctx.has_section("__TEXT", "__swift5_proto"):
        return out
    sec = ctx.section("__TEXT", "__swift5_proto")
    for rec in range(sec.vmaddr, sec.vmaddr + sec.vmsize, 4):
        # descriptor: protocol, type reference, witness table pattern, flags; then the
        # retroactive context, the conditional requirements (12 bytes each), resilient witnesses
        try:
            cd = rel(ctx, rec)
            proto, ind = rel_indirect(ctx, cd)
            pnames = referenced_names(ctx, proto, ind)
            flags = read_u32(ctx, cd + 12)
        except READ_ERRORS:
            continue
        kind = (flags >> 3) & 7
        try:
            tref = rel(ctx, cd + 4)
            tdesc = tref if kind == 0 else ctx.read_ptr(tref) if kind == 1 else None
        except READ_ERRORS:
            tdesc = None
        if not flags & _RESILIENT_WITNESSES:
            try:
                wt: Optional[int] = rel(ctx, cd + 8)
            except READ_ERRORS:
                wt = None
            out.append(Conformance(pnames, tdesc or None, wt))
            continue
        at = cd + 16 + (4 if flags & _RETROACTIVE else 0) + 12 * ((flags >> 8) & 0xFF)
        witnesses = []
        try:
            count = read_u32(ctx, at)
        except READ_ERRORS:
            count = 0
        for i in range(count):
            w = at + 4 + 8 * i
            try:
                req, rind = rel_indirect(ctx, w)
                witnesses.append((referenced_names(ctx, req, rind), rel(ctx, w + 4)))
            except READ_ERRORS:
                continue
        out.append(Conformance(pnames, tdesc or None, None, tuple(witnesses)))
    return out
