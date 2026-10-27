"""proto/protoclass_set — the set of proto message class names of one image.

A class is a proto message if its superclass chain reaches a
PBCodable root by NAME (anchor 1, structural), or -- retired, hard-failing heuristics -- by
the VA-cluster closure / the per-class score (see proto.protoclass_heuristic).  The set
carries what the detection found on the way: the inheritance map and the classes claimed only
by a heuristic (:class:`ProtoClassSet`).
"""
from __future__ import annotations

from typing import Dict, FrozenSet, Optional, Set

from macho.memory import BinaryContext, _ctx_cache
from macho.classlist import ClassList, ObjcClass, superclass_chain
from proto.protoclass_heuristic import _is_proto_class, va_cluster_closure


# Apple's generated proto message classes all descend from PBCodable (RPC messages via
# PBRequest / PBResponse).  The superclass chain (macho.classlist.superclass_chain: cross-image
# into ProtocolBuffer.framework in a cache; to the import its slot binds in a standalone
# binary) naming one of these is the structural anchor.  The VA-cluster closure and the
# per-class score are computed only to fail the run if either claims a class the anchor does
# not (proto.protoclass_heuristic).
_PB_ROOT_NAMES: FrozenSet[str] = frozenset(
    {"PBCodable", "PBRequest", "PBResponse", "PBMessage"})


class ProtoClassSet(frozenset):
    """The proto message class names of an image (a frozenset of them), and what their
    detection found (:func:`_proto_class_set`):

    * ``inherits`` -- {child: parent ObjC name} for a proto-to-proto subclass (its immediate
      superclass is itself a proto MESSAGE, not a PB root): the emitter flags its inherited
      fields;
    * ``rooted`` -- the classes whose superclass chain names a PB root (anchor 1);
    * ``cluster_only`` / ``heuristic_only`` -- the classes the name walk did NOT confirm,
      claimed by the VA-cluster closure, or by the per-class seed alone: errors (empty on every
      corpus measured, :mod:`proto.protoclass_heuristic`, computed on every run);
    * ``chain_exits`` -- where an unconfirmed class's chain left the image (a standalone file
      cannot follow it: a dylib extracted from a dyld cache points into the cache)."""

    def __new__(cls, names=(), inherits: Optional[Dict[str, str]] = None,
                rooted: FrozenSet[str] = frozenset(), cluster_only: FrozenSet[str] = frozenset(),
                heuristic_only: FrozenSet[str] = frozenset(),
                chain_exits: Optional[Dict[str, int]] = None):
        self = super().__new__(cls, names)
        self.inherits = inherits or {}
        self.rooted, self.cluster_only, self.heuristic_only = rooted, cluster_only, heuristic_only
        self.chain_exits = chain_exits or {}
        return self


def _proto_class_set(ctx: BinaryContext, cl: ClassList) -> ProtoClassSet:
    """Full set of proto message class NAMES (TODO #46): the ``_is_proto_class``
    heuristic seed unioned with the PBCodable superclass-chain closure (two anchors,
    above), with what the detection found (:class:`ProtoClassSet`).  Memoised on ctx."""
    def _build() -> ProtoClassSet:
        non_meta = [c for c in cl if not c.is_meta]
        by_va: Dict[int, ObjcClass] = {c.vmaddr: c for c in non_meta}
        seed = {c.name for c in non_meta if _is_proto_class(c)}
        proto: Set[str] = set(seed)
        proto_va: Set[int] = {c.vmaddr for c in non_meta if c.name in seed}

        # Anchor 1 — NAME: the superclass chain names a PB root.  Run for every class, not
        # only the ones the seed has not claimed, so a class whose membership rests on the
        # heuristic alone can be told from one the chain confirms.
        chains = {c.name: superclass_chain(ctx, c.vmaddr, cl) for c in non_meta}
        anchor1_names: Set[str] = set()
        exits: Dict[str, int] = {}
        for c in non_meta:
            ch = chains[c.name]
            if _PB_ROOT_NAMES.intersection(ch.names):
                anchor1_names.add(c.name)
                if c.name not in proto:
                    proto.add(c.name)
                    proto_va.add(c.vmaddr)
            elif ch.end == "unnamed" and ch.left_file:
                exits[c.name] = ch.end_va
        # (the retired closure names a superclass by its pointer: the chains' first links)
        first_name = {c.superclass_vmaddr: chains[c.name].names[0] for c in non_meta
                      if c.superclass_vmaddr and chains[c.name].names}

        # Anchor 2 — RETIRED heuristic-seeded VA-cluster closure, now living in
        # proto.protoclass_heuristic.  Mutates proto/proto_va in place and returns
        # the names it alone added, so a class resting on it can be failed below.
        anchor2_names: Set[str] = va_cluster_closure(
            non_meta, by_va, seed, proto, proto_va, first_name.get)

        # Proto-to-proto subclass map (immediate super is a proto MESSAGE, i.e. a
        # local proto class or a cross-image non-PB-root class) → inheritance note.
        inherits: Dict[str, str] = {}
        for c in non_meta:
            if c.name not in proto or not c.superclass_vmaddr:
                continue
            names = chains[c.name].names
            parent = names[0] if names else None
            if parent and parent not in _PB_ROOT_NAMES:
                inherits[c.name] = parent
        # Classes the pure name/bind walk (anchor 1) did NOT independently reach,
        # split by WHICH non-structural path claimed them.  Both are ERRORS, not
        # footnotes: anchor 1 alone reproduces the full set on every corpus measured
        # (:mod:`proto.protoclass_heuristic`), so either set being non-empty means the
        # structural detector failed and the class's presence in the output rests on a
        # guess.
        #   * cluster-only — the heuristic-seeded VA-cluster closure (anchor 2)
        #     claimed it and the superclass chain never confirmed it.
        #   * heuristic-only — neither structural anchor claimed it; it is in the
        #     set solely because the per-class _is_proto_class score seeded it.
        return ProtoClassSet(proto, inherits=inherits, rooted=frozenset(anchor1_names),
                             cluster_only=frozenset(anchor2_names - anchor1_names),
                             heuristic_only=frozenset(proto - anchor1_names - anchor2_names),
                             chain_exits=exits)

    return _ctx_cache(ctx, "_proto_class_names_cache", _build)


def rooted_proto_classes(ctx: BinaryContext, cl: ClassList) -> FrozenSet[str]:
    """The names of the classes whose superclass chain names a PB root (anchor 1): the
    proto classes by structure alone."""
    return _proto_class_set(ctx, cl).rooted
