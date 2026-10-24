"""
macho/classlist.py — ObjC class list parser for arm64 Mach-O binaries.

Reads __objc_classlist, dereferences class_t / class_ro_t / method_list_t /
ivar_list_t structures and exposes ClassList with find_subclasses() for
discovering GPBMessage subclass hierarchies.

Struct layouts (arm64 LE, all pointers 8 bytes)
------------------------------------------------
class_t (40 bytes):
  [0]  isa            u64
  [8]  superclass     u64  → class_t*
  [16] cache          u64  (skip)
  [24] vtable         u64  (skip)
  [32] data           u64  → class_ro_t* (mask low 3 bits)

class_ro_t (72 bytes):
  [0]  flags          u32
  [4]  instanceStart  u32
  [8]  instanceSize   u32
  [12] reserved       u32
  [16] ivarLayout     u64
  [24] name           u64  → cstring
  [32] baseMethods    u64  → method_list_t*
  [40] baseProtocols  u64
  [48] ivars          u64  → ivar_list_t*
  [56] weakIvarLayout u64
  [64] baseProperties u64

method_list_t header (8 bytes):
  [0] entsizeAndFlags u32  (bit31 = METHOD_FLAG_RELATIVE)
  [4] count           u32

Traditional method_t (24 bytes):  name u64, types u64, imp u64
Relative method_t (12 bytes):     nameOffset s32, typesOffset s32, impOffset s32

ivar_list_t header (8 bytes):     entsizeAndFlags u32, count u32
ivar_t (32 bytes):
  [0]  offset_ptr  u64  → u32 byte-offset within instance
  [8]  name        u64  → cstring
  [16] type        u64  → cstring (type encoding)
  [24] alignment   u32
  [28] size        u32
"""

from __future__ import annotations

import logging

from dataclasses import dataclass
from typing import Callable, Dict, Iterator, List, Optional, Set, Tuple

from .memory import READ_ERRORS, BinaryContext, _ctx_cache, record_unread
from .objc_model import ObjcClass, ObjcIvar, ObjcMethod   # re-exported; see below
from .strings import StringTable
from .objc_abi import (CLASS_T_SUPERCLASS, CLASS_T_DATA, CLASS_RO_FLAGS,
                       CLASS_RO_INSTANCE_SIZE, CLASS_RO_NAME, CLASS_RO_METHODS,
                       CLASS_RO_IVARS, FAST_DATA_MASK, METHOD_FLAG_RELATIVE,
                       MIN_RELATIVE_METHOD_ENTSIZE,
                       is_valid_selector as _is_valid_selector)
from .relative_selector_base import _resolve_relative_selector_base

# ── Constants ─────────────────────────────────────────────────────────────────

RO_META   = 0x0001

_CLASSLIST_SECTIONS = (
    ('__DATA_CONST', '__objc_classlist'),
    ('__DATA',       '__objc_classlist'),
    ('__DATA_DIRTY', '__objc_classlist'),
)

_MIN_IVAR_ENTSIZE   = 32
_MAX_METHODS        = 10_000
log = logging.getLogger(__name__)


# class_ro_t.baseMethods, when dyld's shared-cache builder has PRE-ATTACHED one
# or more categories to a class (a launch-time optimisation: the ObjC runtime
# then skips scanning __objc_catlist for that class), does not point directly
# at a method_list_t.  Instead the decoded vmaddr's bit 0 is set as a tag, and
# the address with that bit cleared points at an entry_list_t: a small header
# (entsize, count) followed by `count` 8-byte little-endian signed entries,
# each packing `image_index:16 | method_list_offset:48` (self-relative to the
# entry's own address).  Confirmed against blacktop/go-macho's
# disablePreattachedCategories (the same struct objc4/dyld use internally) and
# empirically verified against a live macOS dyld_shared_cache_arm64e: every
# resolved entry address matches ipsw's own --objc-derived
# __OBJC_$_INSTANCE_METHODS_<Class>(<Category>...) symbol exactly.  A real
# entry_list_t never has more than a handful of entries (one per attached
# category, plus the base implementation); this cap is a corrupt-input
# backstop only, mirroring _MAX_METHODS.
_ENTRY_LIST_ENTSIZE     = 8   # sizeof(int64_t) — the on-disk entry stride
_MAX_PREATTACHED_ENTRIES = 64


# ── Data classes ─────────────────────────────────────────────────────────────
#
# ObjcMethod / ObjcIvar / ObjcClass are defined in the leaf module
# macho/objc_model.py and imported above.  The split exists so local_symbols --
# which repairs these records from the .symbols sub-cache -- can name them
# without importing this parser; that import closed a
# classlist → memory → dyld_cache → local_symbols → classlist cycle.  They are
# re-exported from here because this is where they are built, so
# `from macho.classlist import ObjcClass` remains correct for the ~20 callers
# that already use the parser.


# ── ClassList ─────────────────────────────────────────────────────────────────

class ClassList:
    """
    Indexed collection of ObjcClass objects.

    find(name)                        → Optional[ObjcClass]
    by_vmaddr(vmaddr)                 → Optional[ObjcClass]
    find_subclasses(name, transitive) → List[ObjcClass]
    __len__ / __iter__ / __contains__
    """

    def __init__(self, classes: List[ObjcClass]) -> None:
        self._classes:   List[ObjcClass]         = classes
        self._by_name:   Dict[str, ObjcClass]    = {}
        self._by_vmaddr: Dict[int, ObjcClass]    = {}
        self._children:  Dict[str, List[str]]    = {}   # parent → [child names]

        for c in classes:
            # _by_vmaddr always indexes by address — every entry is unique.
            self._by_vmaddr[c.vmaddr] = c

            # _by_name: instance classes must always win over metaclasses.
            #
            # In ObjC, a metaclass shares its name with the corresponding
            # instance class (class_ro_t.name is the same string for both).
            # build_class_list adds metaclasses to the list (so that
            # _find_metaclass can resolve them via by_vmaddr), but they must
            # not overwrite instance-class entries in the name index —
            # otherwise cl.find('GEOPDComponent') would return the metaclass,
            # which has is_meta=True, far fewer methods, and the wrong IMPs.
            existing = self._by_name.get(c.name)
            if existing is None or (existing.is_meta and not c.is_meta):
                self._by_name[c.name] = c

        # Build parent→children index (instance classes only to avoid
        # metaclass superclass chains polluting subclass queries).
        for c in classes:
            if c.is_meta:
                continue
            if c.superclass_name:
                self._children.setdefault(c.superclass_name, []).append(c.name)

    def find(self, name: str) -> Optional[ObjcClass]:
        return self._by_name.get(name)

    def by_vmaddr(self, vmaddr: int) -> Optional[ObjcClass]:
        return self._by_vmaddr.get(vmaddr)

    def ancestors(self, cls: ObjcClass) -> Iterator[ObjcClass]:
        """*cls*, then its superclasses as far as they are classes of this image (a cycle,
        malformed, ends it)."""
        seen: Set[int] = set()
        c: Optional[ObjcClass] = cls
        while c is not None and not c.is_meta and c.vmaddr not in seen:
            seen.add(c.vmaddr)
            yield c
            c = self._by_vmaddr.get(c.superclass_vmaddr) if c.superclass_vmaddr else None

    def find_subclasses(
        self, name: str, transitive: bool = True
    ) -> List[ObjcClass]:
        """Return all classes whose superclass chain includes *name*."""
        result: List[ObjcClass] = []
        queue = list(self._children.get(name, []))
        seen: set = set()
        while queue:
            n = queue.pop()
            if n in seen:
                continue
            seen.add(n)
            cls = self._by_name.get(n)
            if cls:
                result.append(cls)
            if transitive:
                queue.extend(self._children.get(n, []))
        return result

    def __len__(self) -> int:
        return len(self._classes)

    def __iter__(self) -> Iterator[ObjcClass]:
        return iter(self._classes)

    def __contains__(self, name: object) -> bool:
        return name in self._by_name

    def __repr__(self) -> str:
        return f"ClassList({len(self)} classes)"


_OBJC_CLASS_SYM_PREFIX = "_OBJC_CLASS_$_"


@dataclass(frozen=True)
class SuperclassChain:
    """The superclasses of an ObjC class, nearest first, as far as they are named.  *end*:
    ``root`` (a null superclass), ``import`` (the last is a class another image defines, bound
    by name: a standalone file goes no further), ``cycle`` (malformed), ``unnamed`` (no name
    is read at *end_va*; *left_file*: it is no address of this file, a pointer into the dyld
    cache a dylib was extracted from) or ``unreadable`` (the superclass slot at *end_va*)."""
    links: Tuple[Tuple[Optional[int], str], ...]   # (class_t vmaddr, None for an import; name)
    end: str
    end_va: Optional[int] = None
    left_file: bool = False

    @property
    def names(self) -> Tuple[str, ...]:
        return tuple(name for _va, name in self.links)


def walk_superclasses(class_va: int, super_at: Callable[[int], int],
                      name_at: Callable[[int], Optional[str]],
                      import_at: Callable[[int], Optional[str]] = lambda slot: None,
                      outside: Callable[[int], bool] = lambda va: False) -> SuperclassChain:
    """The chain from the ``class_t`` at *class_va*: *super_at* (its superclass pointer,
    READ_ERRORS when unreadable), *name_at* (a class's name, None when none is read),
    *import_at* (the symbol a superclass slot is bound to, binary mode) and *outside* (whether
    an address is no address of the file)."""
    links: List[Tuple[Optional[int], str]] = []
    seen, va = {class_va}, class_va
    while True:
        slot = va + CLASS_T_SUPERCLASS
        sym = import_at(slot)
        if sym:
            name = sym[len(_OBJC_CLASS_SYM_PREFIX):] if sym.startswith(_OBJC_CLASS_SYM_PREFIX) else sym
            return SuperclassChain(tuple(links) + ((None, name),), "import")
        try:
            nxt = super_at(va)
        except READ_ERRORS:
            return SuperclassChain(tuple(links), "unreadable", slot)
        if not nxt:
            return SuperclassChain(tuple(links), "root")
        if nxt in seen:
            return SuperclassChain(tuple(links), "cycle", nxt)
        seen.add(nxt)
        name = name_at(nxt)
        if not name:
            return SuperclassChain(tuple(links), "unnamed", nxt, outside(nxt))
        links.append((nxt, name))
        va = nxt


def superclass_chain(ctx: BinaryContext, class_va: int,
                     cl: Optional["ClassList"] = None) -> SuperclassChain:
    """The superclass chain of the class at *class_va*, read through *ctx* (cross-image in a
    cache; a class another image defines named by the symbol its slot is bound to in a
    standalone file); a class of *cl* is read from the class list.  Memoised on *ctx*."""
    held = _ctx_cache(ctx, "_superclass_chains", dict)     # {id(cl): (cl, {va: chain})}
    entry = held.get(id(cl))
    if entry is None or entry[0] is not cl:
        entry = held[id(cl)] = (cl, {})
    memo = entry[1]
    if class_va in memo:
        return memo[class_va]
    cached = getattr(ctx, "is_cache_backed", False)

    def local(va: int) -> Optional[ObjcClass]:
        return cl.by_vmaddr(va) if cl is not None else None

    def super_at(va: int) -> int:
        c = local(va)
        return c.superclass_vmaddr if c is not None else ctx.read_ptr(va + CLASS_T_SUPERCLASS)

    def name_at(va: int) -> Optional[str]:
        c = local(va)
        return c.name if c is not None else class_name_at(ctx, va)

    def outside(va: int) -> bool:
        if cached or local(va) is not None:
            return False
        try:
            ctx.vmaddr_to_offset(va)
            return False
        except READ_ERRORS:
            return True

    memo[class_va] = chain = walk_superclasses(
        class_va, super_at, name_at,
        import_at=(lambda slot: None) if cached else ctx.bind_name_for, outside=outside)
    return chain


def class_name_at(ctx, va: int) -> Optional[str]:
    """``class_ro_t.name`` of the ObjC class whose ``class_t`` is at *va*: ``class_t.data``
    (its low tag bits masked) -> ``class_ro_t`` -> the name, read through *ctx* -- a
    :class:`BinaryContext` (cross-image in cache mode) or a
    :class:`~macho.dyld_cache.DyldCacheReader` itself.  None when the chain does not resolve
    or the name is empty."""
    try:
        ro = ctx.read_ptr(va + CLASS_T_DATA) & FAST_DATA_MASK
        name_va = ctx.read_ptr(ro + CLASS_RO_NAME) if ro else 0
        return (ctx.read_cstring(name_va) or None) if name_va else None
    except READ_ERRORS:
        return None


# ── Builder ───────────────────────────────────────────────────────────────────
# The cache-wide relative-method-selector anchor (the '🤯' base) is resolved
# by macho.relative_selector_base._resolve_relative_selector_base, imported
# above; see that module for the resolution strategy.


def build_class_list(
    ctx: BinaryContext,
    strings: StringTable,
) -> ClassList:
    """Parse __objc_classlist and return a fully indexed ClassList.

    Works for both input modes:

    * **cache-native** (``ctx`` built via :meth:`BinaryContext.from_cache`):
      selector cstrings live in the cache's unified selector pool and are read
      transparently through ``ctx.read_cstring`` (which routes to the cache
      reader).  Names are subsequently corrected/completed from the
      ``.symbols`` local-symbol table by the CLI.
    * **binary-only** (``ctx`` built from a standalone Mach-O file): selectors
      are resolved entirely from the binary's own ``__objc_selrefs`` /
      ``__objc_methname`` sections.
    """
    # Find classlist section
    sect = None
    for segname, sectname in _CLASSLIST_SECTIONS:
        if ctx.has_section(segname, sectname):
            sect = ctx.section(segname, sectname)
            break
    if sect is None or sect.vmsize == 0:
        return ClassList([])

    count = sect.vmsize // 8

    # Resolve the cache-wide relative-method-selector base BEFORE parsing
    # methods, so preoptimized "direct selector" names decode from the binary
    # alone (no .symbols needed).  None in binary mode / when undetermined; the
    # parser then falls back to the existing selref/methname logic.
    ctx._rel_sel_base = _resolve_relative_selector_base(ctx, sect, count)

    raw_classes: List[ObjcClass] = []
    seen_vas: Set[int] = set()

    for i, ptr in enumerate(ctx.iter_ptrs(sect.vmaddr, count)):
        if ptr == 0:                     # (a listed class is never null: its slot is unread)
            record_unread(ctx, "class pointer", f"{sect.vmaddr + 8 * i:#x}",
                          ValueError("__objc_classlist slot reads as 0"))
            continue

        if ptr not in seen_vas:
            seen_vas.add(ptr)
            cls = _parse_class(ctx, ptr, strings)
            if cls is not None:
                raw_classes.append(cls)

        # Follow isa → metaclass.
        #
        # Metaclasses live in __DATA_DIRTY at vmaddrs pointed to by class_t.isa
        # (the first field of the class_t struct).  They are NOT listed in
        # __objc_classlist, so without this step _find_metaclass() cannot
        # resolve them via cl.by_vmaddr() and returns None.  That forces
        # downstream code to use heuristic fallbacks (broad name-suffix
        # matching) for repeated-field element-type resolution, which can pick
        # the wrong class when the suffix is generic (e.g. "Value" matches
        # both GEOPDComponentValue and GEODefaultsDBValue).
        #
        # Adding metaclasses here lets Strategy 1 of _repeated_element_type
        # (the +[Cls xyzType] metaclass-method lookup) work correctly for
        # shared-cache-extracted binaries where metaclasses previously went
        # missing from the ClassList.
        try:
            meta_va = ctx.read_ptr(ptr)   # class_t.isa — offset 0
        except READ_ERRORS as exc:
            record_unread(ctx, "metaclass pointer", f"{ptr:#x}", exc)
            continue
        if meta_va == 0 or meta_va in seen_vas:
            continue
        seen_vas.add(meta_va)
        meta = _parse_class(ctx, meta_va, strings)
        if meta is not None:
            raw_classes.append(meta)

    # Second pass: resolve superclass names
    va_to_name: Dict[int, str] = {c.vmaddr: c.name for c in raw_classes}
    for c in raw_classes:
        if c.superclass_vmaddr:
            c.superclass_name = va_to_name.get(c.superclass_vmaddr)

    return ClassList(raw_classes)


def _resolve_preattached_method_lists(ctx: BinaryContext, tagged_va: int) -> List[int]:
    """Resolve a tagged (bit 0 set) ``baseMethods`` vmaddr to the real
    method_list_t address(es) it stands in for.

    See the comment above ``_ENTRY_LIST_ENTSIZE`` for the on-disk entry_list_t
    layout.  Returns every entry's resolved address, in on-disk order (base
    implementation first, then each pre-attached category) — deliberately
    ALL of them, not just the last: unlike a runtime dispatch table (where a
    later entry could shadow an earlier same-named method and only the
    "winning" one matters), this tool wants every declared method, and
    ``ObjcClass.get_method`` already takes the first name match, so entry
    order here only matters for that rare-override edge case, not for finding
    ``writeTo:``/``readFrom:`` at all.
    """
    base = tagged_va & ~1
    try:
        entsize = ctx.read_u32(base)
        count   = ctx.read_u32(base + 4)
    except READ_ERRORS as exc:
        record_unread(ctx, "pre-attached method lists", f"{base:#x}", exc)
        return []
    if entsize == 0 or count == 0 or count > _MAX_PREATTACHED_ENTRIES:
        return []

    results: List[int] = []
    for i in range(count):
        entry_va = base + 8 + i * entsize
        try:
            entry_val = ctx.read_s64(entry_va)
        except READ_ERRORS as exc:
            record_unread(ctx, "pre-attached method list entry", f"{entry_va:#x}", exc)
            break
        method_list_offset = entry_val >> 16   # arithmetic shift: signed, self-relative
        results.append(entry_va + method_list_offset)
    return results


def _parse_class(
    ctx: BinaryContext, class_va: int, strings: StringTable,
) -> Optional[ObjcClass]:
    """Parse one class_t at *class_va*."""
    try:
        # class_t.data field at offset 32 points to class_ro_t.
        # In iOS 14+ binaries the slot may hold a fixup-encoded pointer; in
        # older binaries it's a raw pointer whose low 3 bits carry Swift/ObjC
        # tag flags.  read_ptr() only ever strips HIGH chain/cache metadata
        # bits (>= bit 36); it never clears the low tag bits, which can be
        # set simultaneously with a high fixup bit.  So always mask them off
        # ourselves after decoding, unconditionally (as class_name_at does).
        ro_va = ctx.read_ptr(class_va + CLASS_T_DATA) & FAST_DATA_MASK
    except READ_ERRORS as exc:
        record_unread(ctx, "class", f"{class_va:#x}", exc)
        return None

    if ro_va == 0:
        return None

    try:
        superclass_va = ctx.read_ptr(class_va + CLASS_T_SUPERCLASS)

        # class_ro_t (72 bytes)
        # Use read_ptr for all pointer fields so that packed-pointer encoding
        # (used in shared-cache-extracted binaries) is transparently decoded.
        ro_flags  = ctx.read_u32(ro_va + CLASS_RO_FLAGS)
        inst_size = ctx.read_u32(ro_va + CLASS_RO_INSTANCE_SIZE)
        name_va    = ctx.read_ptr(ro_va + CLASS_RO_NAME)
        methods_va = ctx.read_ptr(ro_va + CLASS_RO_METHODS)
        ivars_va   = ctx.read_ptr(ro_va + CLASS_RO_IVARS)
    except READ_ERRORS as exc:
        record_unread(ctx, "class", f"{class_va:#x}", exc)
        return None

    # Resolve name
    name = strings.get(name_va) if name_va else None
    if not name:
        try:
            name = ctx.read_cstring(name_va) if name_va else None
        except READ_ERRORS as exc:
            record_unread(ctx, "class name", f"{class_va:#x}", exc)
            return None
    if not name:
        record_unread(ctx, "class name", f"{class_va:#x}", ValueError("empty or null name"))
        return None

    is_meta = bool(ro_flags & RO_META)

    methods: List[ObjcMethod] = []
    if methods_va:
        if methods_va & 1:
            # dyld cache-build-time pre-attached categories (see
            # _resolve_preattached_method_lists); parse + concatenate every
            # resolved method_list_t rather than a single direct list.
            for ml_va in _resolve_preattached_method_lists(ctx, methods_va):
                methods.extend(_parse_methods(ctx, ml_va, strings))
        else:
            methods = _parse_methods(ctx, methods_va, strings)
    ivars = _parse_ivars(ctx, ivars_va, strings) if ivars_va else []

    return ObjcClass(
        vmaddr=class_va,
        name=name,
        is_meta=is_meta,
        superclass_vmaddr=superclass_va,
        superclass_name=None,   # resolved in second pass
        ro_flags=ro_flags,
        instance_size=inst_size,
        methods=methods,
        ivars=ivars,
    )


def _parse_methods(
    ctx: BinaryContext, list_va: int, strings: StringTable,
) -> List[ObjcMethod]:
    try:
        entsize_flags = ctx.read_u32(list_va)
        count         = ctx.read_u32(list_va + 4)
    except READ_ERRORS as exc:
        record_unread(ctx, "method list", f"{list_va:#x}", exc)
        return []

    relative   = bool(entsize_flags & METHOD_FLAG_RELATIVE)
    # METHOD_FLAG_PREOPTIMIZED_RELATIVE_METHOD_SELECTORS (bit 0x40000000):
    # When set, each method entry's nameOffset points DIRECTLY to the selector
    # cstring vmaddr (in the shared cache's unified selector pool) rather than
    # to a selref pointer.  Forwarded to _parse_relative_method so it reads the
    # cstring directly instead of misinterpreting it as a pointer (Format A).
    has_direct = bool(entsize_flags & 0x40000000)
    # Apple's mask for the entsize field in method_list_t.entsizeAndFlags:
    #   ~0xffff0003  (strips 16-bit flag region and lowest 2 flag bits)
    # For relative (small) method lists the entry is always
    #   3 × int32_t = 12 bytes regardless of what the flags encode.
    if relative:
        entsize = MIN_RELATIVE_METHOD_ENTSIZE  # always 12 for relative method_t
    else:
        entsize = max(entsize_flags & 0x0000_FFFC, 24)  # at least 24 for traditional
    entry_va  = list_va + 8

    if entsize == 0:
        return []

    # A real class has far fewer than _MAX_METHODS methods ([cap:INPUT-SANITY]): a count past
    # it is a misdecoded ``baseMethods`` pointer landing on unrelated mapped memory, whose
    # entries would be thousands of garbage methods -- the class gets none, warned.
    if count >= _MAX_METHODS:
        log.warning("method list at %#x claims %d methods (more than %d): taken as a misdecoded "
                    "pointer, the class gets no methods", list_va, count, _MAX_METHODS)
        return []
    methods: List[ObjcMethod] = []

    for _ in range(count):
        try:
            if relative:
                m = _parse_relative_method(
                    ctx, entry_va, strings, has_direct=has_direct
                )
            else:
                m = _parse_traditional_method(ctx, entry_va, strings)
        except READ_ERRORS as exc:
            record_unread(ctx, "method list entry", f"{entry_va:#x} ({len(methods)} of {count})",
                          exc)
            break
        if m is not None:
            methods.append(m)
        entry_va += entsize

    return methods


def _parse_traditional_method(
    ctx: BinaryContext, va: int, strings: StringTable
) -> Optional[ObjcMethod]:
    name_ptr  = ctx.read_ptr(va)
    types_ptr = ctx.read_ptr(va + 8)
    imp       = ctx.read_ptr(va + 16)

    # strings.get() is O(1) and safe.  Fall back to read_cstring only when the
    # table misses, but guard against unmapped addresses — if read_cstring raises
    # ValueError the exception would propagate to _parse_methods' except-clause
    # and break the entire method loop, silently dropping all subsequent methods.
    name = strings.get(name_ptr)
    if not name and name_ptr:
        try:
            name = ctx.read_cstring(name_ptr)
        except (ValueError, UnicodeDecodeError):
            name = None

    types = strings.get(types_ptr) if types_ptr else ''
    if not types and types_ptr:
        try:
            types = ctx.read_cstring(types_ptr)
        except ValueError:
            types = ''

    return ObjcMethod(name=name, types=types, imp=imp, is_relative=False)


def _parse_relative_method(
    ctx: BinaryContext, va: int, strings: StringTable,
    *,
    has_direct: bool = False,
) -> Optional[ObjcMethod]:
    # Each field is a relative s32 offset from its own field address
    name_rel  = ctx.read_s32(va)
    types_rel = ctx.read_s32(va + 4)
    imp_rel   = ctx.read_s32(va + 8)

    # nameOffset decoding — two formats exist in the wild:
    #
    # (A) Non-direct: va + nameOffset → a pointer in __objc_selrefs whose
    #     decoded value is the selector cstring vmaddr (standard linkage).
    #
    # (B) Direct selectors (METHOD_FLAG_PREOPTIMIZED_RELATIVE_METHOD_SELECTORS,
    #     bit 0x40000000 in entsizeAndFlags, forwarded via has_direct=True):
    #     va + nameOffset IS the selector cstring vmaddr in the dyld shared
    #     cache's unified selector-string table — no pointer-dereference step.
    #     In cache-native mode ctx.read_cstring routes through the cache reader
    #     and reaches that pool directly (Step 1b).
    #
    # Selector validation is applied to ALL string reads.  Binary code or
    # packed-pointer data accidentally read as a cstring will contain control
    # characters, high bytes, or non-selector punctuation that fail the check;
    # such results are rejected (name stays None).  For cache-native binaries
    # whose direct-selector names are stripped, the authoritative names are
    # restored afterwards from the .symbols local-symbol table keyed by IMP
    # (see macho.local_symbols.apply_to_classes), so a None here is corrected.
    name: Optional[str] = None

    # Step 0 — preoptimized direct selectors in a dyld shared cache.  The
    # nameOffset is measured from the cache-wide '🤯' selector-base address
    # (resolved once in build_class_list and stashed on ctx), NOT from the
    # method_t field.  When that base is known this is the authoritative
    # source and decodes every direct selector from the binary alone — no
    # .symbols table required.  (Earlier code mis-read va + name_rel here,
    # which overshoots the local __objc_methname into unrelated data, leaving
    # name=None for cache images that lack a .symbols sub-cache.)
    rel_sel_base = getattr(ctx, '_rel_sel_base', None)
    # With the base known it is the only reading of a direct selector: va + nameOffset is then no
    # selector address, and reading a string there picks up the tail of another (iPhone 8
    # GeoServices: 'te', 'on:', 'precated' for long initialiser selectors once rejected).
    from_base = has_direct and rel_sel_base is not None
    if from_base:
        try:
            candidate = ctx.read_cstring(rel_sel_base + name_rel)
            if _is_valid_selector(candidate):
                name = candidate
        except (ValueError, UnicodeDecodeError):
            name = None

    sel_ref_va = va + name_rel
    try:
        # Step 1 — check whether sel_ref_va is directly in __objc_methname
        # (works for both direct and non-direct formats when the selector
        # string has been inlined into the binary's own methname section).
        if name is None and not from_base and ctx.has_section('__TEXT', '__objc_methname'):
            mn = ctx.section('__TEXT', '__objc_methname')
            if mn.vmaddr <= sel_ref_va < mn.vmaddr + mn.vmsize:
                candidate = ctx.read_cstring(sel_ref_va)
                if _is_valid_selector(candidate):
                    name = candidate

        # Step 1b — for has_direct=True, sel_ref_va IS the selector cstring
        # address (in the unified cache pool or another mapped region).  If
        # Step 1 failed because the address falls outside the local
        # __objc_methname section, try reading it directly via ctx.
        #
        # For a cache-native BinaryContext (from_cache), ctx.read_cstring
        # routes through the cache reader and can reach the unified selector
        # pool.  For a plain binary context, addresses outside mapped segments
        # raise ValueError, which the outer except catches (leaving name=None).
        if name is None and has_direct and not from_base:
            candidate = ctx.read_cstring(sel_ref_va)
            if _is_valid_selector(candidate):
                name = candidate

        # Step 2 — Format A: pointer-dereference (non-direct only).
        # For has_direct=True this step is intentionally skipped: sel_ref_va
        # IS the cstring address; treating its bytes as a pointer is wrong and
        # produces garbage even when the address is mapped.
        if name is None and not has_direct:
            name_va = ctx.read_ptr(sel_ref_va)   # may raise ValueError if unmapped
            candidate = strings.get(name_va)
            if candidate is None and name_va:
                candidate = ctx.read_cstring(name_va)  # may raise ValueError
            if _is_valid_selector(candidate):
                name = candidate

    except (ValueError, UnicodeDecodeError):
        name = None   # address unmapped or non-UTF-8; left for .symbols recovery

    types_va = (va + 4) + types_rel
    try:
        types = ctx.read_cstring(types_va) if types_rel != 0 else ''
    except ValueError:
        types = ''

    imp = (va + 8) + imp_rel

    return ObjcMethod(name=name, types=types, imp=imp, is_relative=True)


def _parse_ivars(
    ctx: BinaryContext, list_va: int, strings: StringTable
) -> List[ObjcIvar]:
    try:
        entsize = ctx.read_u32(list_va) & 0xFFFF
        count   = ctx.read_u32(list_va + 4)
    except READ_ERRORS as exc:
        record_unread(ctx, "ivar list", f"{list_va:#x}", exc)
        return []

    entsize = max(entsize, _MIN_IVAR_ENTSIZE)
    if entsize == 0:
        return []

    entry_va = list_va + 8
    # the list lies in one segment of the image: a count that runs past it is misread
    seg = ctx.segment_at(list_va)
    if seg is None or entry_va + count * entsize > seg.vmaddr + seg.vmsize:
        record_unread(ctx, "ivar list", f"{list_va:#x}", ValueError(
            f"{count} ivars of {entsize} bytes run past the segment holding the list"))
        return []
    ivars: List[ObjcIvar] = []

    for _ in range(count):
        try:
            offset_ptr = ctx.read_ptr(entry_va)
            name_ptr   = ctx.read_ptr(entry_va + 8)
            type_ptr   = ctx.read_ptr(entry_va + 16)
            size       = ctx.read_u32(entry_va + 28)

            if offset_ptr and ctx.is_variable(offset_ptr):
                actual_off = None                # (set by the runtime: a Swift class's ivar)
            else:
                actual_off = ctx.read_u32(offset_ptr) if offset_ptr else 0
            name       = strings.get(name_ptr) or ctx.read_cstring(name_ptr)
            type_enc   = ''
            if type_ptr:
                type_enc = strings.get(type_ptr) or ''
                if not type_enc:
                    try:
                        # ivar @encode strings are usually short, but a proto class's
                        # has-bits ivar is one anonymous bitfield per field
                        # (`{?="read_a"b1"read_b"b1…}`) and grows with the field count
                        # — GEOAnalyticsPipelineStateData's (138 fields) is ~4140 bytes,
                        # past the 4096 default, so a truncated read returned '' and the
                        # has-bits ivar leaked into the output as a phantom `bytes`
                        # field.  Read generously so the struct is captured whole and
                        # _is_proto_flags_ivar can recognise it.
                        type_enc = ctx.read_cstring(type_ptr, max_len=65536)
                    except READ_ERRORS as exc:
                        record_unread(ctx, "ivar type", f"{entry_va:#x} ({name})", exc)

            ivars.append(ObjcIvar(
                name=name, type_enc=type_enc,
                offset=actual_off, size=size, offset_slot=offset_ptr,
            ))
        except READ_ERRORS as exc:
            record_unread(ctx, "ivar list entry", f"{entry_va:#x} ({len(ivars)} of {count})", exc)
            break
        entry_va += entsize

    return ivars
