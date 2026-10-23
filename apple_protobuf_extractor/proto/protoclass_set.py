"""proto/protoclass_set — the set of proto message class names of one image.

A class is a proto message if its superclass chain reaches a
PBCodable root by NAME (anchor 1, structural), or -- retired, hard-failing heuristics -- by
the VA-cluster closure / the per-class score (see proto.protoclass_heuristic).  Also stamps
the inheritance and "claimed only by a heuristic" sets on ``ctx`` for the emitter.
"""
from __future__ import annotations

from typing import Dict, FrozenSet, Optional, Set, Tuple

from macho.memory import READ_ERRORS, BinaryContext, _ctx_cache, _ctx_store
from macho.classlist import ClassList, ObjcClass, class_name_at
from proto.protoclass_heuristic import _is_proto_class, va_cluster_closure


# Apple's generated proto message classes all descend from PBCodable (RPC messages via
# PBRequest / PBResponse).  The superclass chain is walked by read_ptr (cross-image into
# ProtocolBuffer.framework in a cache; through the bind's import name in a standalone
# binary) until a class with one of these names: the structural anchor.  The VA-cluster
# closure and the per-class score are computed only to fail the run if either claims a
# class the anchor does not (proto.protoclass_heuristic).
_PB_ROOT_NAMES: FrozenSet[str] = frozenset(
    {"PBCodable", "PBRequest", "PBResponse", "PBMessage"})


_OBJC_CLASS_SYM_PREFIX = "_OBJC_CLASS_$_"


def _resolve_class_name_at(ctx: BinaryContext, va: int) -> Optional[str]:
    """``class_ro_t.name`` for the ObjC class at *va*, decoding the chained-fixup
    pointer (reads cross-image in cache mode).

    In standalone-binary mode the superclass is a *bind* to another dylib not
    present in the file, so following the pointer fails; instead *va* is the raw
    chained-fixup bind value and its ordinal resolves through the binary's own
    imports table (``import_name_for_bind``) to the import symbol name, e.g.
    ``_OBJC_CLASS_$_PBCodable`` → ``PBCodable``.  This is the principled binary-mode
    NAME anchor (parity with the cache-mode cross-image read).  Returns None if
    neither path resolves."""
    name = class_name_at(ctx, va)
    if name:
        return name
    sym = ctx.import_name_for_bind(va)
    if sym and sym.startswith(_OBJC_CLASS_SYM_PREFIX):
        return sym[len(_OBJC_CLASS_SYM_PREFIX):]
    return None


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

        # Anchor 1 — NAME: superclass chain reaches a PB root (cache mode).
        name_memo: Dict[int, Optional[str]] = {}

        def _name(va: int) -> Optional[str]:
            if va not in name_memo:
                name_memo[va] = _resolve_class_name_at(ctx, va)
            return name_memo[va]

        def _outside(va: int) -> bool:
            """*va* is no address of this file (a cache reads every image's)."""
            if ctx.is_cache_backed:
                return False
            try:
                ctx.vmaddr_to_offset(va)
                return False
            except READ_ERRORS:
                return True

        def _reaches_pb_root(va: int) -> Tuple[bool, Optional[int]]:
            """Whether the chain from *va* reaches a PB root; when it does not, the class
            pointer where it left the image unnamed (None: it ended inside it)."""
            cur, seen = va, set()
            while True:
                if not cur or cur in seen:
                    return False, None
                seen.add(cur)
                nm = _name(cur)
                if nm is None:
                    return False, (cur if cur not in by_va and _outside(cur) else None)
                if nm in _PB_ROOT_NAMES:
                    return True, None
                local = by_va.get(cur)
                if local is not None:                      # read with the class list (where
                    cur = local.superclass_vmaddr          # a failure is recorded)
                    continue
                try:
                    cur = ctx.read_ptr(cur + 8)            # another image's class: in binary
                except READ_ERRORS:                        # mode, not in this file
                    return False, None

        # Track anchor 1's reach FULLY independently of the heuristic seed (run for
        # every class, not just ones the seed hasn't already claimed) so we can
        # later tell whether a given proto class's membership rests on the
        # heuristic at all, or is independently confirmed by pure superclass-chain
        # structure. Same detection, just not short-circuited by prior membership.
        anchor1_names: Set[str] = set()
        exits: Dict[str, int] = {}
        for c in non_meta:
            if not c.superclass_vmaddr:
                continue
            reached, left_at = _reaches_pb_root(c.superclass_vmaddr)
            if reached:
                anchor1_names.add(c.name)
                if c.name not in proto:
                    proto.add(c.name)
                    proto_va.add(c.vmaddr)
            elif left_at is not None:
                exits[c.name] = left_at

        # Anchor 2 — RETIRED heuristic-seeded VA-cluster closure, now living in
        # proto.protoclass_heuristic.  Mutates proto/proto_va in place and returns
        # the names it alone added, so a class resting on it can be failed below.
        anchor2_names: Set[str] = va_cluster_closure(
            non_meta, by_va, seed, proto, proto_va, _name)

        # Proto-to-proto subclass map (immediate super is a proto MESSAGE, i.e. a
        # local proto class or a cross-image non-PB-root class) → inheritance note.
        inherits: Dict[str, str] = {}
        for c in non_meta:
            if c.name not in proto or not c.superclass_vmaddr:
                continue
            sv = c.superclass_vmaddr
            parent = by_va[sv].name if sv in by_va else _name(sv)
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
