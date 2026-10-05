"""
macho/cache_classlist.py
========================
Proof-of-concept: read ObjC class names directly from the dyld shared cache
without going through an ipsw-extracted binary.

Core validation question
------------------------
Can we walk the ObjC pointer chain

    __objc_classlist entry → class_t → class_ro_t → name cstring

using only ``DyldCacheReader.read_u64`` / ``read_cstring``?

Key finding (June 2026, arm64 GeoServices cache)
-------------------------------------------------
For caches with ``builtFromChainedFixups = 0`` (the common non-chained iOS
format), all DATA-section pointers are stored as absolute cache vmaddrs in the
range 0x180000000–0x22ace8000 — well under the 36-bit (0xFFFFFFFFF) threshold
where ``BinaryContext._decode_packed_ptr`` would strip metadata bits.  They
therefore round-trip through ``read_u64`` without transformation.

The only decode step required is masking the three least-significant tag bits
on ``class_t.data`` (offset 32), which the ObjC runtime uses for
isSwift/fastAlloc/realised flags.  The resulting address is the ``class_ro_t``
pointer.

Struct offsets (arm64 ObjC ABI, verified against Hopper-loaded GeoServices)
-----------------------------------------------------------------------------
class_t  (40 bytes):
  [0]   isa          u64 → class_t*  (metaclass)
  [8]   superclass   u64 → class_t*
  [16]  cache        u64  (method cache, not used here)
  [24]  vtable       u64  (not used here)
  [32]  data         u64 → class_ro_t*  **low 3 bits are ObjC/Swift flags**

class_ro_t:
  [0]   flags        u32
  [4]   instanceStart u32
  [8]   instanceSize  u32
  [12]  reserved     u32  (arm64 padding)
  [16]  ivarLayout   u64 → const uint8_t*  (not used here)
  [24]  name         u64 → const char*  ← class name in __TEXT/__objc_classname
  [32]  baseMethods  u64 → method_list_t*
  ...

Ground-truth addresses (Hopper-verified, June 2026)
----------------------------------------------------
  _OBJC_CLASS_$_GEOPDPlaceRequest   class_t  0x1e1de3be8  (in __DATA_DIRTY)
  __OBJC_CLASS_RO_$_GEOPDPlaceRequest class_ro_t 0x1d6050c28  (in __DATA_CONST)
  "GEOPDPlaceRequest"                name str 0x18d97f901  (in __TEXT/__objc_classname)

  _OBJC_CLASS_$_GEOPDPlaceResponse  class_t  0x1e1de3d28
  __OBJC_CLASS_RO_$_GEOPDPlaceResponse class_ro_t 0x1d6050cb8
  "GEOPDPlaceResponse"               name str 0x18d97f94c
"""

from __future__ import annotations

from typing import Dict, Iterator, Optional, Tuple

from macho.dyld_cache import DyldCacheReader
from macho.objc_abi import CLASS_T_DATA, CLASS_RO_NAME, FAST_DATA_MASK


# ── Pointer decoding ──────────────────────────────────────────────────────────

def _decode_cache_ptr(reader: DyldCacheReader, raw: int) -> int:
    """Decode a raw DATA-section pointer from the cache to a valid vmaddr.

    Thin wrapper around :meth:`DyldCacheReader.decode_ptr`.  Kept for
    backward compatibility with callers that import this function directly.
    """
    return reader.decode_ptr(raw)


# ── Public API ────────────────────────────────────────────────────────────────

def read_objc_class_name(
    reader: DyldCacheReader, class_va: int
) -> Optional[str]:
    """
    Return the ObjC class name for the ``class_t`` at *class_va*.

    Follows the two-pointer chain::

        class_t.data [+32]  → class_ro_t*   (mask low 3 tag bits)
        class_ro_t.name [+24] → const char* → cstring

    Returns ``None`` if *class_va* is unmapped, the pointer chain is broken,
    or the name string cannot be decoded.

    This function is the core of the cache-native class extraction proof of
    concept: it requires only a ``DyldCacheReader`` — no extracted binary and
    no ``BinaryContext``.
    """
    # ── Step 1: class_t.data → class_ro_t* ──────────────────────────────────
    raw_ro = reader.read_u64(class_va + CLASS_T_DATA)
    if not raw_ro:
        return None
    # Strip ObjC/Swift low 3 tag bits (FAST_DATA_MASK convention)
    ro_va = _decode_cache_ptr(reader, raw_ro & FAST_DATA_MASK)
    if not ro_va:
        return None

    # ── Step 2: class_ro_t.name → const char* ───────────────────────────────
    raw_name = reader.read_u64(ro_va + CLASS_RO_NAME)
    if not raw_name:
        return None
    name_va = _decode_cache_ptr(reader, raw_name)
    if not name_va:
        return None

    # ── Step 3: read the null-terminated class name ──────────────────────────
    return reader.read_cstring(name_va)


def iter_class_names(
    reader: DyldCacheReader,
    classlist_start: int,
    classlist_end: int,
) -> Iterator[Tuple[int, str]]:
    """
    Iterate over ``(class_va, class_name)`` pairs from a classlist section.

    Reads each 8-byte entry in the ``__DATA_CONST/__objc_classlist`` range,
    decodes the pointer to a ``class_t``, and resolves the class name via
    :func:`read_objc_class_name`.  Entries that cannot be resolved are silently
    skipped.

    Parameters
    ----------
    reader:
        An open :class:`DyldCacheReader`.  All relevant sub-caches (``__TEXT``
        for names, ``__DATA_CONST`` for ``class_ro_t``, writable DATA for
        ``class_t``) must be loaded for names to resolve.
    classlist_start:
        Inclusive start vmaddr of ``__DATA_CONST/__objc_classlist``.
    classlist_end:
        Exclusive end vmaddr of the section.

    Yields
    ------
    (class_va, class_name) : (int, str)
        ``class_va`` is the absolute cache vmaddr of the ``class_t`` struct.
        ``class_name`` is the bare ObjC class name (e.g. ``"GEOPDPlaceRequest"``).
    """
    count = (classlist_end - classlist_start) // 8
    for i in range(count):
        entry_va = classlist_start + i * 8
        raw_cls = reader.read_u64(entry_va)
        if not raw_cls:
            continue
        class_va = _decode_cache_ptr(reader, raw_cls)
        if not class_va:
            continue
        name = read_objc_class_name(reader, class_va)
        if name:
            yield class_va, name


def class_names_for_image(
    reader: DyldCacheReader, image_name: str
) -> Optional[Dict[int, str]]:
    """
    Return ``{class_va: class_name}`` for every class in *image_name*.

    Convenience wrapper that calls :func:`find_image_header`,
    :meth:`~DyldCacheReader.image_sections`, and :func:`iter_class_names` in
    sequence.

    Returns ``None`` if the image is not found or its classlist section is
    absent.  Returns an empty dict if the classlist is empty or no sub-caches
    are loaded (DATA sections unmapped).
    """
    va = reader.find_image_header(image_name)
    if va is None:
        return None

    sections = reader.image_sections(va)
    bounds = sections.get('__DATA_CONST/__objc_classlist')
    if bounds is None:
        return None

    classlist_start, classlist_end = bounds
    return dict(iter_class_names(reader, classlist_start, classlist_end))
