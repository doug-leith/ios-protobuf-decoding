"""proto/protoclass_set — the set of proto message class names of one image.

A class is a proto message if its superclass chain reaches a
PBCodable root by NAME (anchor 1, structural), or -- retired, hard-failing heuristics -- by
the VA-cluster closure / the per-class score (see proto.protoclass_heuristic).  Also stamps
the inheritance and "claimed only by a heuristic" sets on ``ctx`` for the emitter.
"""
from __future__ import annotations

from typing import Dict, FrozenSet, Set

from macho.memory import BinaryContext, _ctx_cache, _ctx_store
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


def _proto_class_set(ctx: BinaryContext, cl: ClassList) -> FrozenSet[str]:
    """Full set of proto message class NAMES (TODO #46): the ``_is_proto_class``
    heuristic seed unioned with the PBCodable superclass-chain closure (two anchors,
    above).  Side effect: stamps ``ctx._proto_inherits`` = {child: parent_objc_name}
    for proto-to-proto subclasses (immediate superclass is itself a proto MESSAGE,
    not a PB root) so the emitter can flag inherited fields.  ALSO stamps
    ``ctx._proto_class_heuristic_only`` = frozenset of class names whose proto-ness
    rests SOLELY on the heuristic seed (anchor 1's pure name/bind walk, re-run over
    every class regardless of prior seed membership, did NOT independently confirm
    them) — measured empirically to be empty in every corpus tested so far (0/1642
    GeoServices, 0/391 across a 258-binary corpus), but computed for real on every
    run rather than assumed, so the emitter can flag it the day it isn't.  Memoised
    on ctx."""
    def _build() -> FrozenSet[str]:
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
        _ctx_store(ctx, "_proto_inherits", inherits)
        # Classes the pure name/bind walk (anchor 1) did NOT independently reach,
        # split by WHICH non-structural path claimed them.  Both are ERRORS, not
        # footnotes: anchor 1 alone reproduces the full set on every corpus ever
        # measured (391 classes/258 binaries in binary mode, 1642/1 framework in
        # cache mode), so either set being
        # non-empty means the structural detector failed and the class's presence in
        # the output rests on a guess.  Computed for real every run rather than
        # assumed empty, so the day it fires the output says so.
        #   * cluster-only — the heuristic-seeded VA-cluster closure (anchor 2)
        #     claimed it and the superclass chain never confirmed it.
        #   * heuristic-only — neither structural anchor claimed it; it is in the
        #     set solely because the per-class _is_proto_class score seeded it.
        _cluster_only = frozenset(anchor2_names - anchor1_names)
        _heuristic_only = frozenset(proto - anchor1_names - anchor2_names)
        _ctx_store(ctx, "_proto_class_cluster_only", _cluster_only)
        _ctx_store(ctx, "_proto_class_heuristic_only", _heuristic_only)
        # where an unconfirmed class's chain left the image (a standalone file cannot
        # follow it: a dylib extracted from a dyld cache points into the cache)
        _ctx_store(ctx, "_proto_class_chain_exits", exits)
        return frozenset(proto)

    return _ctx_cache(ctx, "_proto_class_names_cache", _build)
