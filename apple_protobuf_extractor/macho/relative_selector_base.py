"""macho/relative_selector_base — the dyld-cache relative-method-selector anchor.

``classlist.py`` calls its one entry point, :func:`_resolve_relative_selector_base`, once
before parsing methods.  It resolves ONE vmaddr — the cache-wide '🤯' anchor a preoptimized
"direct selector" relative method_t's ``nameOffset`` is measured from — and
has no dependency on ``ObjcClass``/``ClassList`` or any other parsing state.

Preferred sources, tried in order — both documented fields dyld itself wrote
at cache-build time, not estimates:

1. :func:`_resolve_relative_selector_base_from_cache_header` — the NEW,
   cache-header-embedded ``ObjCOptimizationHeader`` (newer/larger caches).
2. :func:`_resolve_relative_selector_base_from_libobjc` — the older,
   per-dylib ``objc_opt_t`` in ``libobjc.A.dylib``'s ``__objc_opt_ro``
   (caches too old/small for the NEW form; e.g. the iPhone 8 cache).

Fallback, only when neither documented source is usable:
:func:`_resolve_relative_selector_base_by_heuristic_scan` estimates the
anchor by byte-scanning for '🤯' and calibrating against sampled real
``nameOffset`` values — and warns, per the project's policy of always
flagging estimate-based decisions.
"""

from __future__ import annotations

import warnings
from typing import List, Optional

from .memory import BinaryContext
from .objc_abi import (CLASS_T_DATA, CLASS_RO_METHODS, FAST_DATA_MASK,
                       METHOD_FLAG_RELATIVE, MIN_RELATIVE_METHOD_ENTSIZE,
                       is_valid_selector)

# Minimum fraction of sampled direct-selector offsets that must resolve to a
# valid selector for a candidate base to be accepted.  The correct anchor
# resolves ~90 %; a stray '🤯' copy elsewhere resolves only a few percent, so
# the two are cleanly separated and the threshold need not be precise.
_REL_SEL_BASE_MIN_RATE = 0.5
# How many direct-selector name offsets to sample when calibrating the base.
_REL_SEL_BASE_SAMPLE = 600

# ``objc_opt_t`` (the legacy, per-dylib form living in libobjc.A.dylib's own
# __TEXT,__objc_opt_ro — see dyld's objc-shared-cache.h).  Only the two fields
# we need are named; the rest of the 48-byte struct (six more int32 hash-table
# offsets) is skipped.
#   uint32_t version;                                  // +0
#   uint32_t flags;                                     // +4
#   int32_t  selectorOptOffset, headerOptRoOffset,      // +8 .. +36
#            unusedClassOptOffset, unusedProtocolOptOffset,
#            headerOptRwOffset, unusedProtocolOpt2Offset,
#            largeSharedCachesClassOffset, largeSharedCachesProtocolOffset;
#   int64_t  relativeMethodSelectorBaseAddressCacheOffset;  // +40
_OBJC_OPT_T_MIN_SIZE = 48
_OBJC_OPT_T_REL_SEL_OFFSET_POS = 40
# Newest objc_opt_t layout this code understands (matches ipsw's own guard);
# a higher version means the field layout may have changed and the value at
# _OBJC_OPT_T_REL_SEL_OFFSET_POS can no longer be trusted blindly.
_OBJC_OPT_T_MAX_KNOWN_VERSION = 16


def _sample_direct_selector_name_offsets(
    ctx: BinaryContext, sect, count: int
) -> List[int]:
    """Collect up to :data:`_REL_SEL_BASE_SAMPLE` real ``nameOffset`` values
    from ``has_direct`` (preoptimized direct-selector) method lists.

    Used both to calibrate the byte-scan fallback and to sanity-check the
    documented anchor read from ``libobjc.A.dylib`` before trusting it."""
    samples: List[int] = []
    for ptr in ctx.iter_ptrs(sect.vmaddr, count):
        if ptr == 0:
            continue
        try:
            # read_ptr() never clears the low ObjC/Swift tag bits, which can be set
            # together with a high fixup bit: mask them off (as classlist._parse_class does).
            ro_va = ctx.read_ptr(ptr + CLASS_T_DATA) & FAST_DATA_MASK
            if not ro_va:
                continue
            mlist = ctx.read_ptr(ro_va + CLASS_RO_METHODS)
            if not mlist:
                continue
            ef = ctx.read_u32(mlist)
        except ValueError:
            continue
        if not (ef & METHOD_FLAG_RELATIVE) or not (ef & 0x40000000):
            continue
        try:
            mcount = ctx.read_u32(mlist + 4)
        except ValueError:
            continue
        entry = mlist + 8
        for i in range(min(mcount, 8)):
            try:
                samples.append(ctx.read_s32(entry + i * MIN_RELATIVE_METHOD_ENTSIZE))
            except ValueError:
                break
        if len(samples) >= _REL_SEL_BASE_SAMPLE:
            break
    return samples


def _score_candidate_base(
    ctx: BinaryContext, base: int, samples: List[int]
) -> int:
    """Count how many sampled ``nameOffset`` values decode to a syntactically
    valid selector string when read as ``base + nameOffset``."""
    ok = 0
    for nr in samples:
        try:
            s = ctx.read_cstring(base + nr)
        except (ValueError, UnicodeDecodeError):
            s = None
        if s and is_valid_selector(s):
            ok += 1
    return ok


# ── Principled sources: documented dyld/objc fields, no scanning or guessing ──

def _resolve_relative_selector_base_from_cache_header(
    ctx: BinaryContext,
) -> Optional[int]:
    """Read the relative-selector anchor from the NEW, cache-header-embedded
    ObjC optimization header (``dyld_cache_header.objcOptsOffset`` →
    ``ObjCOptimizationHeader.relativeMethodSelectorBaseAddressOffset``).

    Newer/larger caches carry this directly in the cache header rather than
    inside ``libobjc.A.dylib`` (see
    :func:`_resolve_relative_selector_base_from_libobjc` for the older,
    per-dylib form) — a real value dyld wrote at cache-build time, not an
    estimate.  All the field-location and version-gating logic lives in
    :meth:`~macho.dyld_cache.DyldCacheReader.new_format_relative_selector_base`,
    since it only needs cache-header bytes, no ``BinaryContext``.

    Returns ``None`` (never raises) in binary mode or when this cache doesn't
    carry a big-enough/recognizable header here, so the caller can fall back
    cleanly.
    """
    if not ctx.is_cache_backed:
        return None
    return ctx._cache_reader.new_format_relative_selector_base()


def _resolve_relative_selector_base_from_libobjc(
    ctx: BinaryContext,
) -> Optional[int]:
    """Read the relative-selector anchor from its other documented,
    non-heuristic source: the ``objc_opt_t`` struct in ``libobjc.A.dylib``'s
    own ``__TEXT,__objc_opt_ro`` section — the form used by caches too old
    (or too small) to carry the NEW cache-header-embedded header (see
    :func:`_resolve_relative_selector_base_from_cache_header`).

    ``objc_opt_t.relativeMethodSelectorBaseAddressCacheOffset`` is a signed
    64-bit distance from that struct's own address (i.e. the section's vmaddr)
    to the anchor — dyld writes this value at cache-build time, so it can be
    read directly with no scanning or statistical calibration.

    Returns ``None`` (never raises) whenever this source isn't usable —
    binary mode, ``libobjc.A.dylib`` not found, no ``__objc_opt_ro`` section,
    or a struct version newer than this code understands — so the caller can
    fall back cleanly.
    """
    if not ctx.is_cache_backed:
        return None
    reader = ctx._cache_reader
    header_va = reader.find_image_header("libobjc.A.dylib")
    if header_va is None:
        return None
    sects = reader.image_sections(header_va)
    bounds = sects.get("__TEXT/__objc_opt_ro")
    if bounds is None:
        return None
    sect_va, sect_end = bounds
    if sect_end - sect_va < _OBJC_OPT_T_MIN_SIZE:
        return None
    try:
        version = ctx.read_u32(sect_va)
        if version > _OBJC_OPT_T_MAX_KNOWN_VERSION:
            return None
        rel_offset = ctx.read_s64(sect_va + _OBJC_OPT_T_REL_SEL_OFFSET_POS)
    except ValueError:
        return None
    return (sect_va + rel_offset) & 0xFFFFFFFFFFFFFFFF


# ── Fallback: no documented source available, estimate and say so ───────────

def _resolve_relative_selector_base_by_heuristic_scan(
    ctx: BinaryContext, samples: List[int]
) -> Optional[int]:
    """Estimate the relative-selector anchor by scanning for the magic
    ``🤯`` selector and calibrating against real ``nameOffset`` samples.

    Only reached when neither documented source above is usable.  A cache can
    contain more than one copy of the ``🤯`` byte sequence (one canonical
    anchor plus the odd stray copy in unrelated string data), so this tries
    each candidate and picks whichever resolves the most *samples* to
    syntactically valid selectors.

    Per the project's policy of always flagging estimate-based decisions,
    a successful resolution here emits a ``UserWarning`` naming the estimate
    and its confidence.  Returns ``None`` (silently — the caller has nothing
    to warn about) when there are no candidates, no samples to calibrate
    against, or no candidate clears :data:`_REL_SEL_BASE_MIN_RATE`.
    """
    if not ctx.is_cache_backed:
        return None
    reader = ctx._cache_reader
    cands = reader.relative_selector_base_candidates()
    if not cands or not samples:
        return None

    best_base, best_ok = None, -1
    for base in cands:
        ok = _score_candidate_base(ctx, base, samples)
        if ok > best_ok:
            best_base, best_ok = base, ok
    if best_base is None or best_ok < len(samples) * _REL_SEL_BASE_MIN_RATE:
        return None

    warnings.warn(
        "classlist: relative-selector anchor could not be read from either "
        "documented source (dyld_cache_header's NEW ObjC optimization header, "
        "or libobjc.A.dylib's __objc_opt_ro) — falling back to a statistical "
        f"estimate (byte-scan for the '🤯' anchor selector, calibrated "
        f"against {len(samples)} sampled selectors, "
        f"{best_ok}/{len(samples)} matched). Selector names in this image "
        "rest on that estimate rather than a directly-read value.",
        stacklevel=3,
    )
    return best_base


# ── Entry point: try the principled sources first, estimate as a last resort ─

def _resolve_relative_selector_base(
    ctx: BinaryContext, sect, count: int
) -> Optional[int]:
    """Determine the dyld cache's relative-method-selector base vmaddr.

    Preoptimized relative method lists (the ``has_direct`` form) encode each
    selector as ``base + nameOffset`` where *base* is the address of the magic
    ``🤯`` anchor selector in the cache's uniqued selector pool — NOT the
    method_t field address.

    Each documented source is sanity-checked against a sample of real
    ``nameOffset`` values before being trusted, in case of an unrecognized
    layout variant; see the module docstring for the two documented sources
    and the heuristic-scan fallback.

    Returns the chosen base, or ``None`` in binary mode or when no source
    yields a usable value (in which case the parser keeps its existing
    selref/methname behaviour)."""
    if not ctx.is_cache_backed:
        return None

    samples = _sample_direct_selector_name_offsets(ctx, sect, count)

    for documented in (
        _resolve_relative_selector_base_from_cache_header(ctx),
        _resolve_relative_selector_base_from_libobjc(ctx),
    ):
        if documented is None:
            continue
        if not samples or (
            _score_candidate_base(ctx, documented, samples)
            >= len(samples) * _REL_SEL_BASE_MIN_RATE
        ):
            return documented
        # This documented value failed its sanity check against real method
        # lists in *this* image — don't trust it silently; try the next
        # source (and ultimately the heuristic fallback, which will warn).

    return _resolve_relative_selector_base_by_heuristic_scan(ctx, samples)
