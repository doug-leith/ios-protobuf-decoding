"""macho/cache_classlist.py -- ObjC class names read straight from a dyld shared cache, with no
extracted binary: ``__objc_classlist`` entry -> ``class_t`` -> ``class_ro_t`` -> name
(:func:`macho.classlist.class_name_at` over the reader), each pointer decoded by
:meth:`DyldCacheReader.decode_ptr` (the cache's slide info) and ``class_t.data``'s low three tag
bits (isSwift / fastAlloc / realised) masked off.

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
"""

from __future__ import annotations

from typing import Dict, Iterator, Tuple

from macho.classlist import class_name_at, walk_superclasses
from macho.dyld_cache import DyldCacheReader
from macho.objc_abi import CLASS_T_SUPERCLASS


def iter_class_names(
    reader: DyldCacheReader,
    classlist_start: int,
    classlist_end: int,
) -> Iterator[Tuple[int, str]]:
    """
    Iterate over ``(class_va, class_name)`` pairs from a classlist section.

    Reads each 8-byte entry in the ``__DATA_CONST/__objc_classlist`` range,
    decodes the pointer to a ``class_t``, and resolves the class name via
    :func:`macho.classlist.class_name_at`.  Entries that cannot be resolved are silently
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
        class_va = reader.decode_ptr(raw_cls)
        if not class_va:
            continue
        name = class_name_at(reader, class_va)
        if name:
            yield class_va, name


def _image_pointer_sections(reader: DyldCacheReader, mach_va: int, *sectnames: str):
    """``(start, end)`` of every section of the image named one of *sectnames*, in any
    segment (the cache builder moves ``__objc_classrefs`` between ``__DATA`` and
    ``__DATA_CONST`` / ``__AUTH_CONST`` across OS versions)."""
    for key, bounds in sorted(reader.image_sections(mach_va).items()):
        if '/' in key and key.split('/', 1)[1] in sectnames:
            yield bounds


def class_refs_for_image(reader: DyldCacheReader, mach_va: int) -> Dict[str, int]:
    """``{class name: class_t vmaddr}`` for every class the image at *mach_va* references
    through a class-reference slot (``__objc_classrefs`` / ``__objc_superrefs``).

    In the shared cache these slots are already bound to the referenced ``class_t``,
    wherever it lives, so each entry is the exact link-time answer to "which class does
    this image mean by that name" — no name lookup is involved.  Pair with
    :meth:`DyldCacheReader.image_containing` to name the image that defines it."""
    out: Dict[str, int] = {}
    for start, end in _image_pointer_sections(
            reader, mach_va, '__objc_classrefs', '__objc_superrefs'):
        for slot in range(start, end - 7, 8):
            raw = reader.read_u64(slot)
            if not raw:
                continue
            class_va = reader.decode_ptr(raw)
            if not class_va:
                continue
            name = class_name_at(reader, class_va)
            if name:
                out.setdefault(name, class_va)
    return out


def class_names_defined_by_image(reader: DyldCacheReader, mach_va: int) -> Dict[str, int]:
    """``{class name: class_t vmaddr}`` for the classes the image at *mach_va* defines
    (its ``__objc_classlist``, in whichever segment holds it)."""
    out: Dict[str, int] = {}
    for start, end in _image_pointer_sections(reader, mach_va, '__objc_classlist'):
        for class_va, name in iter_class_names(reader, start, end):
            out.setdefault(name, class_va)
    return out


def superclass_chain_names(reader: DyldCacheReader, class_va: int) -> list:
    """Names of the superclasses of the ``class_t`` at *class_va*, nearest first, followed
    across images (the cache builder binds ``superclass`` to the parent's ``class_t``
    wherever it lives): :func:`macho.classlist.walk_superclasses` over the cache reader."""
    return list(walk_superclasses(class_va, lambda va: reader.read_ptr(va + CLASS_T_SUPERCLASS),
                                  lambda va: class_name_at(reader, va)).names)
