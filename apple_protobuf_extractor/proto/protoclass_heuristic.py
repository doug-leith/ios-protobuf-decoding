"""proto/protoclass_heuristic — the RETIRED non-structural proto-class detectors.

Proto-class detection is supposed to be STRUCTURAL: an ObjC class is a protobuf
message because its superclass chain reaches PBCodable/PBRequest/PBResponse/
PBMessage, resolved BY NAME (cross-image ``read_ptr`` in cache mode, the
LC_DYLD_CHAINED_FIXUPS imports table in standalone-binary mode).  That walk —
``protoclass_set._proto_class_set`` anchor 1 — is ground truth and is the sole detector
this tool relies on.

This module holds the two non-structural detectors:

  * :func:`_is_proto_class` — the original per-class metadata heuristic (has-bits
    flags ivar / ``{_reader,_readerLock}`` proxy / ``readFrom:``+``writeTo:``
    method scoring).
  * :func:`va_cluster_closure` — the heuristic-SEEDED VA-cluster closure
    (``_proto_class_set`` anchor 2): treat the non-local superclass VAs shared by
    seeded classes as PB roots and sweep in everything transitively subclassing
    one.  The imports-table name anchor makes it redundant in standalone binaries.

WHY THEY ARE KEPT.  Neither has ever been the reason a real class was classified
as proto.  Anchor 1 alone reproduces the full class set on both corpora ever
measured — 391 classes across 258 standalone binaries in binary mode, and 1642
classes in the GeoServices cache, including 5 metadata-sparse subclasses.  Their measured
contribution is zero.  They remain
here as an investigative safety net for a shape the corpora have not yet shown —
e.g. a class whose superclass is an EXTERNAL non-root PBCodable subclass, which
the binary-mode name anchor cannot walk into.

WHY THEY NOW FAIL THE RUN.  Because their contribution is measured zero, either
one actually claiming a class means the structural detector has FAILED on it, and
the class may not be a protobuf message at all — emitting it would put a guessed
message into a schema that otherwise carries only structural facts.  So
:func:`check_no_heuristic_detection` raises :class:`ProtoClassDetectionError`
rather than letting the guess through.  Set ``MACHO_ALLOW_HEURISTIC_PROTO_CLASSES=1``
to downgrade the failure to a loud warning when you are deliberately investigating
such a binary; the affected messages are then tagged with an inline ``// ERROR:``
in the emitted .proto (models.HEURISTIC_CLASS_DETECTION_COMMENT /
VA_CLUSTER_CLASS_DETECTION_COMMENT) so the output is never silently wrong.

WHERE THE CHECK APPLIES.  ``extract_all`` only — a whole-image extraction, which is
the entry point every real consumer uses and the only place a COMPLETE class graph
exists.  The claim being enforced is "every class admitted to this schema was
confirmed by its superclass chain", which is a statement about a graph, not about
one class.  A single-class ``extract_proto_message`` call (unit tests, probe
scripts) may legitimately be handed a synthetic ObjcClass with no superclass at
all, where there is no chain to walk and the caller has already decided the class
is proto; that path FLAGS the message inline and continues.

Imports only ``proto.protocore`` + ``macho.classlist`` + stdlib — never
``proto.extractor`` (cycle).
"""
import logging
import os
from typing import Callable, Dict, FrozenSet, Iterable, List, Mapping, Optional, Set

from macho.classlist import ObjcClass
from proto.protocore import _is_proto_flags_ivar, _REQUIRED_INSTANCE_METHODS

log = logging.getLogger(__name__)

#: Env override: downgrade the hard failure below to a loud warning.  For
#: deliberate investigation of a binary the structural detector cannot handle.
_ALLOW_ENV = "MACHO_ALLOW_HEURISTIC_PROTO_CLASSES"


#: Broader set used to score "proto-likeness"; at least N of these must be present.
_SCORED_INSTANCE_METHODS: frozenset = frozenset({
    "readFrom:", "writeTo:", "mergeFrom:",
    "copyTo:", "copyWithZone:", "isEqual:",
    "hash", "description", "dictionaryRepresentation",
})


_MIN_SCORED = 5   # require at least this many from _SCORED_INSTANCE_METHODS


# Universal ObjC roots that must NEVER be treated as a PB-cluster root: a proto
# MESSAGE class subclasses PBCodable (or another proto message), never NSObject
# directly, so a seed whose immediate non-local super resolves to one of these is a
# detector false positive.  Without this guard a single such false seed makes the
# VA-cluster sweep in every NSObject subclass in the image (the SymptomNetworkUsage
# 4→28 blow-up).  Cache-mode defence (names must resolve); binary mode relies on a
# precise seed (cross-image names don't resolve there).
_SYSTEM_ROOT_NAMES: FrozenSet[str] = frozenset({"NSObject", "NSProxy"})


def _is_proto_class(cls: ObjcClass) -> bool:
    """
    Return True if cls looks like an Apple ObjC proto message class.

    RETIRED as a detector — see the module docstring.  Retained as the union floor
    (it never DROPS a hit found structurally) and as the sanity superset, and still
    used directly by the binary-derived oracle (gt_fields) and by
    tests that build synthetic classes with no superclass chain to walk.

    Three detection paths are tried in order:

    1. Ivar-based (primary): look for the proto has-bits bitfield ivar whose
       type encoding is {?="has_field"b1...}.  This pattern is unique to
       Apple's proto runtime and works even when method names are unavailable
       (e.g. in binaries extracted from the dyld shared cache, where
       preoptimised method lists store selector references into the unified
       cache's string table rather than the binary's own __objc_methname).

    2. Tertiary: proto-runtime bookkeeping ivar heuristic.  Apple's ObjC proto
       runtime injects _reader and _readerLock into every proto message class.
       When the has-bits bitfield type_enc cannot be read (e.g. cache-native mode
       with a sparse DATA_CONST mapping), fall back to checking these two ivar
       names as a structural proxy.  The combination is highly specific — no
       non-proto ObjC class typically has both.

    3. Method-name-based (fallback): check that the core proto serialisation
       selectors (readFrom:, writeTo:) are present and score at least
       _MIN_SCORED from the broader _SCORED_INSTANCE_METHODS set.  mergeFrom:
       is NOT required here — oneof and wrapper classes omit it — but it still
       contributes to the score.  This path works for standalone binaries where
       selector names are resolved.
    """
    if cls.is_meta:
        return False
    # Primary: ivar-based detection (works even with no resolved method names)
    if cls.ivars and any(_is_proto_flags_ivar(iv) for iv in cls.ivars):
        return True
    # Tertiary: {_reader,_readerLock} bookkeeping-ivar proxy.
    if cls.ivars:
        ivar_names = {iv.name for iv in cls.ivars if iv.name}
        if {'_reader', '_readerLock'}.issubset(ivar_names):
            return True
    # Fallback: method-name-based detection (standalone binaries)
    method_names = {m.name for m in cls.methods if m.name is not None}
    if not _REQUIRED_INSTANCE_METHODS.issubset(method_names):
        return False
    score = sum(1 for m in _SCORED_INSTANCE_METHODS if m in method_names)
    return score >= _MIN_SCORED


def va_cluster_closure(
    non_meta: List[ObjcClass],
    by_va: Dict[int, ObjcClass],
    seed: Set[str],
    proto: Set[str],
    proto_va: Set[int],
    name_of: Callable[[int], Optional[str]],
) -> Set[str]:
    """Heuristic-seeded VA-cluster closure (``_proto_class_set`` anchor 2).

    RETIRED as a detector — see the module docstring.  Roots are the non-local
    superclass VAs that *seed*-confirmed classes share (raw chained-fixup bind
    ordinals in binary mode); every class transitively subclassing one is taken to
    be proto.  ``proto`` / ``proto_va`` are the caller's running sets and are
    MUTATED in place, so the closure also expands over anchor 1's output.

    Returns the set of class names THIS closure added, so the caller can tell
    which classes rest on it alone.
    """
    root_vas = {c.superclass_vmaddr for c in non_meta
                if c.name in seed and c.superclass_vmaddr
                and c.superclass_vmaddr not in by_va
                and name_of(c.superclass_vmaddr) not in _SYSTEM_ROOT_NAMES}
    added: Set[str] = set()
    changed = True
    while changed:
        changed = False
        for c in non_meta:
            if c.name in proto:
                continue
            sv = c.superclass_vmaddr
            if sv and (sv in root_vas or sv in proto_va):
                proto.add(c.name)
                proto_va.add(c.vmaddr)
                added.add(c.name)
                changed = True
    return added


class ProtoClassDetectionError(RuntimeError):
    """A proto class was claimed ONLY by a retired non-structural detector.

    Raised by :func:`check_no_heuristic_detection`.  Signals that the structural
    PBCodable-superclass-chain walk failed on the named classes, so their presence
    in the output would be a guess rather than a fact.
    """


def _fmt(names: Iterable[str], limit: int = 20) -> str:
    ordered = sorted(names)
    shown = ", ".join(ordered[:limit])
    return shown + (f" … (+{len(ordered) - limit} more)" if len(ordered) > limit else "")


def check_no_heuristic_detection(
    heuristic_only: FrozenSet[str],
    cluster_only: FrozenSet[str],
    source: str = "<binary>",
    exits: Optional[Mapping[str, int]] = None,
) -> None:
    """Fail the run if either retired detector was the SOLE claimant of a class.  *exits*:
    where a class's superclass chain left the image (:func:`proto.protoclass_set._proto_class_set`),
    the cause the error then names.

    Raises :class:`ProtoClassDetectionError` unless ``MACHO_ALLOW_HEURISTIC_PROTO_CLASSES``
    is set, in which case the same text is logged at ERROR level and extraction
    continues (the affected messages carry an inline ``// ERROR:`` in the .proto).
    """
    if not heuristic_only and not cluster_only:
        return

    parts: List[str] = [
        f"proto-class detection FAILED STRUCTURALLY on {source}: "
        f"{len(heuristic_only) + len(cluster_only)} class(es) are in the proto set "
        f"ONLY because a retired non-structural detector claimed them. Their ObjC "
        f"superclass chain does not reach PBCodable, so they may not be protobuf "
        f"messages at all and must not be emitted as if they were."
    ]
    if heuristic_only:
        parts.append(
            f"  [{len(heuristic_only)}] claimed by the _is_proto_class metadata "
            f"heuristic alone: {_fmt(heuristic_only)}")
    if cluster_only:
        parts.append(
            f"  [{len(cluster_only)}] claimed by the heuristic-seeded VA-cluster "
            f"closure alone: {_fmt(cluster_only)}")
    claimed = heuristic_only | cluster_only
    left = {n: va for n, va in (exits or {}).items() if n in claimed}
    if left:
        name = min(left)
        parts.append(
            f"  [{len(left)}] of them: the superclass chain leaves this file, at a class "
            f"pointer it does not map ({name}: {left[name]:#x}). A dylib extracted from a "
            f"dyld shared cache points into the cache, where its superclasses are: run it "
            f"on the cache instead (--cache DIR --framework NAME).")
    if len(left) < len(claimed):
        parts.append(
            f"  {'The other ' + str(len(claimed) - len(left)) + ': t' if left else 'T'}"
            "his has never happened on any measured corpus (391 classes/258 binaries, "
            "1642 classes/GeoServices cache) and indicates either a tool bug in the "
            "name-anchor walk or a genuinely new binary shape — investigate before "
            "trusting ANY output for this image. See proto/protoclass_heuristic.py.")
    parts.append(
        f"  To investigate anyway, set {_ALLOW_ENV}=1 to downgrade this to a "
        f"warning; affected messages are then tagged '// ERROR:' inline.")
    msg = "\n".join(parts)

    if os.environ.get(_ALLOW_ENV):
        log.error("%s\n  [%s set — continuing with FLAGGED output]", msg, _ALLOW_ENV)
        return
    raise ProtoClassDetectionError(msg)
