"""
macho/local_symbols.py
======================
Recovers ObjC method names from a dyld shared cache's **local-symbol table**
(the ``…arm64.symbols`` sub-cache file).

Why this exists
---------------
A cache image's optimised method lists name their methods (relative selectors, through the
cache's selector base: :mod:`macho.relative_selector_base`), but leave methods out, and a
metaclass's ``baseMethods`` is NULL.  The ``.symbols`` file carries the original local symbol
table with full ``-[Class selector]`` / ``+[Class selector]`` entries, keyed by implementation
address: the methods a list leaves out, and the class methods.  This module parses that table,
scoped to a single image, and returns the lookup maps.

Format (verified against a real iOS arm64 ``.symbols`` file)
-----------------------------------------------------------
The ``.symbols`` file is itself a dyld cache file (same ``dyld_v1`` magic).
Its header's ``localSymbolsOffset`` (u64 @ 0x48) / ``localSymbolsSize``
(u64 @ 0x50) point at a ``dyld_cache_local_symbols_info`` block::

    struct dyld_cache_local_symbols_info {   // all offsets relative to localSymbolsOffset
        uint32_t nlistOffset;
        uint32_t nlistCount;
        uint32_t stringsOffset;
        uint32_t stringsSize;
        uint32_t entriesOffset;
        uint32_t entriesCount;   // one entry per image in the cache
    };

Each per-image entry (64-bit form) is::

    struct dyld_cache_local_symbols_entry_64 {
        uint64_t dylibOffset;       // (mach-header vmaddr − cache base)
        uint32_t nlistStartIndex;
        uint32_t nlistCount;
    };

The nlist entries are standard ``nlist_64`` (``n_strx`` u32, ``n_type`` u8,
``n_sect`` u8, ``n_desc`` u16, ``n_value`` u64 = 16 bytes); ``n_value`` is the
symbol's vmaddr and the string lives at ``stringsOffset + n_strx``.
"""

from __future__ import annotations

import mmap
import os
import re
import struct
from dataclasses import dataclass, field
from typing import Dict, Optional

from .nlist import iter_nlist
from .objc_model import ObjcMethod

# Header field offsets within the .symbols dyld_cache_header.
_HDR_LOCAL_SYMS_OFF = 0x48   # u64 – file offset of dyld_cache_local_symbols_info
_HDR_LOCAL_SYMS_SIZE = 0x50  # u64 – size of the local-symbols region

_INFO_STRUCT = struct.Struct('<6I')   # nlist/strings/entries offsets + counts
_ENTRY_STRUCT = struct.Struct('<QII')  # dylibOffset, nlistStartIndex, nlistCount

# Matches an Objective-C method symbol, instance ('-') or class ('+'), with an
# optional category:
#   -[ClassName selector:with:args:]
#   +[ClassName xyzType]
#   -[ClassName(Category) selector]
# Block-invoke / thunk symbols start with '_' and are correctly excluded by the
# leading '-['/'+[' anchor.  group(1) is the kind ('-' or '+').
_METHOD_RE = re.compile(rb'^([-+])\[([A-Za-z0-9_]+)(?:\([A-Za-z0-9_]+\))? ([^\]]+)\]$')


@dataclass
class ImageLocalSymbols:
    """Per-image selector lookup tables recovered from the local symbol table.

    ``imp_to_sel`` maps an implementation vmaddr to its selector name, image-wide.
    ``class_to_sels`` maps each class name to its ``{selector: imp}`` dict: a class's
    methods are renamed and completed from it (:func:`apply_to_classes`).

    The ``meta_*`` variants hold the same data for **class methods** (``+[Cls
    sel]``).  These are kept separate because a metaclass shares its instance
    class's name, so grafting them through ``class_to_sels`` would conflate the
    two.  Class methods matter for repeated-field element-type resolution: the
    ``+[Cls xyzType]`` metaclass methods are stripped from the cache's metaclass
    ``baseMethods`` (the pointer is NULL), so the ``.symbols`` table is the only
    source.  See ``proto.repeated._repeated_element_type`` / ``_resolve_repeated_type``.
    """

    imp_to_sel: Dict[int, str] = field(default_factory=dict)
    class_to_sels: Dict[str, Dict[str, int]] = field(default_factory=dict)
    meta_imp_to_sel: Dict[int, str] = field(default_factory=dict)
    meta_to_sels: Dict[str, Dict[str, int]] = field(default_factory=dict)

    def __bool__(self) -> bool:
        return bool(self.imp_to_sel)


def symbols_path_for(main_path: str) -> Optional[str]:
    """Return the ``.symbols`` sibling of *main_path*, or None if absent."""
    candidate = main_path + '.symbols'
    return candidate if os.path.exists(candidate) else None


def _locate_image_nlist(mm, cache_base, mach_header_va):
    """Locate one image's nlist slice in a ``.symbols`` file.

    Returns ``(nlist_base, strings_base, strtab_limit, start_idx, end_idx)`` —
    absolute file offsets and the image's nlist index range — or ``None`` when
    the local-symbols region is unparseable or the image is not listed.  Shared
    by the ObjC method-symbol parse and the raw symbol-address reader."""
    if len(mm) < _HDR_LOCAL_SYMS_SIZE + 8:
        return None
    lso = struct.unpack_from('<Q', mm, _HDR_LOCAL_SYMS_OFF)[0]
    lss = struct.unpack_from('<Q', mm, _HDR_LOCAL_SYMS_SIZE)[0]
    if lso == 0 or lss == 0 or lso + _INFO_STRUCT.size > len(mm):
        return None
    (nlist_off, nlist_cnt, strings_off, strings_size,
     entries_off, entries_cnt) = _INFO_STRUCT.unpack_from(mm, lso)
    nlist_base = lso + nlist_off
    strings_base = lso + strings_off
    entries_base = lso + entries_off
    target_dylib_off = mach_header_va - cache_base
    start_idx = count = None
    for i in range(entries_cnt):
        eo = entries_base + i * _ENTRY_STRUCT.size
        if eo + _ENTRY_STRUCT.size > len(mm):
            break
        dylib_off, nlist_start, nlist_count = _ENTRY_STRUCT.unpack_from(mm, eo)
        if dylib_off == target_dylib_off:
            start_idx, count = nlist_start, nlist_count
            break
    if start_idx is None:
        return None
    end_idx = min(start_idx + count, nlist_cnt)
    return nlist_base, strings_base, strings_base + strings_size, start_idx, end_idx


def load_image_symbol_addrs(
    symbols_path: str,
    cache_base: int,
    mach_header_va: int,
    substrs=None,
) -> Dict[str, int]:
    """Map ``symbol name → vmaddr`` for ONE image's local symbols.

    Unlike :func:`load_image_local_symbols` (which keeps only ``-[Class sel]``
    ObjC method symbols), this returns the *raw* name→``n_value`` table — the
    source the swift-protobuf extractor needs in cache mode, where the per-image
    ``_…_protobuf_nameMap`` / ``…decodeMessage`` static symbols live in this same
    ``.symbols`` nlist rather than an in-binary ``LC_SYMTAB``.

    *substrs*, if given, restricts the result to names containing at least one of
    the substrings (a cheap pre-filter so we don't decode every symbol of a
    several-thousand-entry image).  ``first write wins`` on duplicate names.
    """
    want = [s.encode('utf-8') if isinstance(s, str) else s
            for s in (substrs or [])]
    # (a file that cannot be opened or mapped raises: the caller records it)
    with open(symbols_path, 'rb') as fh:
        mm = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
        try:
            loc = _locate_image_nlist(mm, cache_base, mach_header_va)
            if loc is None:
                return {}
            nlist_base, strings_base, strtab_limit, start_idx, end_idx = loc
            out: Dict[str, int] = {}
            for e in iter_nlist(mm, nlist_base, start_idx, end_idx, strings_base, strtab_limit):
                if e.n_value == 0 or not e.name:
                    continue
                if want and not any(w in e.name for w in want):
                    continue
                out.setdefault(e.name.decode('utf-8', 'replace'), e.n_value)
            return out
        finally:
            mm.close()


def load_image_local_symbols(
    symbols_path: str,
    cache_base: int,
    mach_header_va: int,
) -> Optional[ImageLocalSymbols]:
    """Parse instance-method local symbols for a single image.

    Parameters
    ----------
    symbols_path:
        Path to the ``…arm64.symbols`` file.
    cache_base:
        Unslid base vmaddr of the cache (lowest mapping vmaddr).  The per-image
        entry's ``dylibOffset`` equals ``mach_header_va − cache_base``.
    mach_header_va:
        vmaddr of the target image's Mach-O header (as returned by
        :meth:`DyldCacheReader.find_image_header`).

    Returns
    -------
    ImageLocalSymbols with the image's ``-[Class sel]`` symbols, or None when
    the file has no parseable local-symbol region or the image is not listed.
    Reads the string table lazily via ``mmap`` so the (often several-hundred-MB)
    region is paged in on demand rather than loaded whole.
    """
    with open(symbols_path, 'rb') as fh:      # (raises when it cannot be opened or mapped)
        mm = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
        try:
            return _parse(mm, cache_base, mach_header_va)
        finally:
            mm.close()


def _parse(
    mm: 'mmap.mmap', cache_base: int, mach_header_va: int
) -> Optional[ImageLocalSymbols]:
    loc = _locate_image_nlist(mm, cache_base, mach_header_va)
    if loc is None:
        return None
    nlist_base, strings_base, strtab_limit, start_idx, end_idx = loc
    syms = ImageLocalSymbols()

    for e in iter_nlist(mm, nlist_base, start_idx, end_idx, strings_base, strtab_limit):
        n_value = e.n_value
        if n_value == 0 or not e.name:
            continue
        m = _METHOD_RE.match(e.name)
        if m is None:
            continue
        kind = m.group(1)            # b'-' (instance) or b'+' (class)
        cls_name = m.group(2).decode('ascii', 'replace')
        sel = m.group(3).decode('ascii', 'replace')
        # First write wins: the optimised IMP is unique per function; if a
        # selector appears twice (rare), keep the earliest deterministically.
        if kind == b'+':
            syms.meta_imp_to_sel.setdefault(n_value, sel)
            syms.meta_to_sels.setdefault(cls_name, {}).setdefault(sel, n_value)
        else:
            syms.imp_to_sel.setdefault(n_value, sel)
            syms.class_to_sels.setdefault(cls_name, {}).setdefault(sel, n_value)

    return syms if (syms.imp_to_sel or syms.meta_imp_to_sel) else None


def apply_to_classes(classes, syms: ImageLocalSymbols) -> Dict[str, int]:
    """Correct and complete method names on *classes* using *syms* in place.

    Two passes per class:

    1. **Rename by IMP** — every method whose implementation address the class's own
       symbols (``class_to_sels``) name gets that selector name, where the method list's
       differs or is missing (none on the iPhone 8 and iOS 27 caches: their lists name every
       method).
    2. **Add missing** — selectors present in the symbol table but absent from
       the parsed method list (the optimised list is often a subset) are
       appended as name-only :class:`ObjcMethod` entries so downstream
       getter/setter and ``xAsString:`` detection can see them.

    Metaclasses are handled symmetrically using the ``meta_*`` maps: the
    cache's metaclass ``baseMethods`` pointer is NULL, so a metaclass arrives
    with zero methods, and the ``+[Cls xyzType]`` element-type methods needed by
    repeated-field resolution are grafted on entirely from ``.symbols``.

    Returns a dict of counts: ``renamed`` (null → name), ``corrected``
    (wrong → name), ``added`` (new instance-method entries), ``meta_added``
    (new class-method entries grafted onto metaclasses).
    """
    renamed = corrected = added = meta_added = 0
    for cls in classes:
        is_meta = getattr(cls, 'is_meta', False)
        name_to_sels = syms.meta_to_sels if is_meta else syms.class_to_sels
        # this class's own symbols: an IMP folded into several classes' methods has a symbol
        # per class, and the image-wide map would give one class another's selector
        imp_to_sel = {imp: sel for sel, imp in (name_to_sels.get(cls.name) or {}).items()}

        for m in cls.methods:
            sel = imp_to_sel.get(m.imp)
            if sel is None or sel == m.name:
                continue
            if m.name is None:
                renamed += 1
            else:
                corrected += 1
            m.name = sel

        sels = name_to_sels.get(cls.name)
        if not sels:
            continue
        have_imps = {m.imp for m in cls.methods}
        for sel, imp in sels.items():
            if imp not in have_imps:
                cls.methods.append(
                    ObjcMethod(name=sel, types='', imp=imp, is_relative=True)
                )
                if is_meta:
                    meta_added += 1
                else:
                    added += 1

    return {'renamed': renamed, 'corrected': corrected,
            'added': added, 'meta_added': meta_added}
