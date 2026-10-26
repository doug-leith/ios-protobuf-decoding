"""
macho/memory.py — BinaryContext: arm64 LE Mach-O binary reader.

Validates 64-bit LE Mach-O (magic 0xFEEDFACF), parses load commands
(:mod:`macho.load_commands`), and provides vmaddr-based read primitives.  Chained
fixup pointer decoding (LC_DYLD_CHAINED_FIXUPS) is handled transparently in
read_ptr / iter_ptrs.
"""

from __future__ import annotations

import logging
import struct
import zlib
from typing import TYPE_CHECKING, Dict, Iterator, List, Optional, Tuple

from .leb import read_uleb
from . import load_commands
from .load_commands import LoadCommands, Section, Segment, parse_load_commands

log = logging.getLogger(__name__)

if TYPE_CHECKING:            # dyld_cache sits ABOVE this module; a runtime
    from .dyld_cache import DyldCacheReader   # import here would be a cycle

# ─── Mach-O constants ────────────────────────────────────────────────────────

ZEROFILL_TYPES = load_commands.ZEROFILL_TYPES      # (re-exported)

MH_MAGIC_64 = 0xFEEDFACF   # arm64 LE
MH_CIGAM_64 = 0xCFFAEDFE   # arm64 BE — rejected
FAT_MAGIC   = 0xBEBAFECA   # fat binary magic read as LE (bytes CA FE BA BE)

CPU_TYPE_ARM64     = 0x0100000C

MH_EXECUTE = 0x2
MH_DYLIB   = 0x6

#: What reading an image can raise: an address no segment or mapping holds (ValueError, its
#: UnicodeDecodeError for a non-UTF-8 string), a read past a buffer (struct.error).  A guard
#: on a read catches these only, so a logic error -- a KeyError, an IndexError -- surfaces;
#: an absent section is asked with :meth:`BinaryContext.has_section` (TODO #137).
READ_ERRORS = (ValueError, struct.error)

#: What an analysis must never take for a fact about the input: an error in this program (a name
#: it lacks, a value of the wrong kind -- a proto.arm64_eval.Sym in arithmetic --, an object
#: without the attribute it is given).  A guard that turns other exceptions into a recorded
#: failure re-raises these first.
PROGRAM_ERRORS = (NameError, ImportError, TypeError, AttributeError)


def decode_function_starts(blob: bytes, text_vmaddr: int) -> List[int]:
    """The function entries an ``LC_FUNCTION_STARTS`` table lists: ULEB128 deltas, the first
    from the ``__TEXT`` segment's start, ending at a zero delta (sorted by construction).  A
    delta still open at the end of *blob* raises ValueError (:func:`macho.leb.read_uleb`)."""
    starts, addr, p = [], text_vmaddr, 0
    while p < len(blob):
        delta, p = read_uleb(blob, p)
        if delta == 0:
            break
        addr += delta
        starts.append(addr)
    return starts

# Chained fixup pointer formats
_DYLD_PTR_ARM64E    = 1
_DYLD_PTR_64        = 2
_DYLD_PTR_64_OFFSET = 6
# arm64e "userland" formats (current toolchain's default for arm64e dylibs and
# executables).  Same bit layout as _DYLD_PTR_ARM64E — 8-byte stride, `next` at
# [61:51], bind = bit 62, auth = bit 63 — but a rebase's target is a VM OFFSET
# from the image base (not a vmaddr), and USERLAND24 widens a bind's ordinal
# from 16 to 24 bits.
_DYLD_PTR_ARM64E_USERLAND   = 9
_DYLD_PTR_ARM64E_USERLAND24 = 12
_ARM64E_FAMILY = (_DYLD_PTR_ARM64E, _DYLD_PTR_ARM64E_USERLAND,
                  _DYLD_PTR_ARM64E_USERLAND24)


#: The sections a program writes -- initialised and zero-fill data, thread-locals: what one holds
#: at run time need not be what the file does.  The rest of a data segment is the linker's and
#: the runtime's (pointers fixed at load, ObjC metadata, CFStrings, constants).
PROGRAM_DATA_SECTIONS = frozenset(("__data", "__bss", "__common", "__thread_vars",
                                   "__thread_data", "__thread_bss"))
#: S_NON_LAZY_SYMBOL_POINTERS, S_LAZY_SYMBOL_POINTERS: the slots dyld binds to imports (in a
#: binary without chained fixups, which says per slot).
_SYMBOL_POINTER_TYPES = (0x6, 0x7)

# ─── Helpers ─────────────────────────────────────────────────────────────────

def _bind_ordinal(raw: int, fmt: int) -> Optional[int]:
    """A chained-fixup value's import ordinal when it is a bind, else None: arm64e formats
    bind at bit 62 with a 16-bit ordinal (24 in USERLAND24), the ptr64 formats at bit 63 with
    a 24-bit one (dyld_chained_ptr_64_bind)."""
    if fmt in _ARM64E_FAMILY:
        if not (raw >> 62) & 1:
            return None
        return raw & (0xFFFFFF if fmt == _DYLD_PTR_ARM64E_USERLAND24 else 0xFFFF)
    if fmt in (_DYLD_PTR_64, _DYLD_PTR_64_OFFSET):
        return raw & 0xFFFFFF if (raw >> 63) & 1 else None
    return None


def _decode_chain_ptr(raw: int, fmt: int, image_base: int) -> int:
    """Decode one chained-fixup pointer value → vmaddr."""
    if fmt in (_DYLD_PTR_ARM64E_USERLAND, _DYLD_PTR_ARM64E_USERLAND24):
        # dyld_chained_ptr_arm64e_rebase:      target:43 high8:8 next:11 bind:1 auth:1
        # dyld_chained_ptr_arm64e_auth_rebase: target:32 diversity:16 addrDiv:1
        #                                      key:2 next:11 bind:1 auth:1
        # Both targets are VM offsets from the image base.  A plain rebase's
        # high8 is the pointer's top byte (never set on the class/method/ivar
        # pointers this tool follows) — dropped, as in the classic arm64e case.
        if (raw >> 62) & 1:
            return 0
        if (raw >> 63) & 1:
            return (raw & 0xFFFFFFFF) + image_base
        return (raw & 0x7FF_FFFF_FFFF) + image_base
    if fmt == _DYLD_PTR_ARM64E:
        auth = (raw >> 63) & 1
        bind = (raw >> 62) & 1
        if bind:
            return 0
        if auth:
            # Authenticated rebase: 32-bit target relative to image base
            return (raw & 0xFFFFFFFF) + image_base
        else:
            # Plain rebase: the 43-bit vmaddr (target:43 high8:8 ...), high8 dropped as above
            return raw & 0x7FF_FFFF_FFFF
    elif fmt in (_DYLD_PTR_64, _DYLD_PTR_64_OFFSET):
        bind = (raw >> 63) & 1
        if bind:
            return 0
        target_low = raw & 0xFFFFFFFFF          # 36-bit target
        high8      = (raw >> 36) & 0xFF
        target     = target_low | (high8 << 56)
        if fmt == _DYLD_PTR_64_OFFSET:
            target += image_base
        return target
    return raw   # unknown format: return verbatim


def _chain_next_stride(raw: int, fmt: int) -> int:
    """Return the byte stride to the next chain entry (0 = end of chain).

    Both arm64e rebase and arm64e-auth-rebase place the 11-bit ``next`` field
    at bits [61:51] of the raw 64-bit value.  Stride unit is 8 bytes.
    ptr64 / ptr64-offset use a 12-bit ``next`` at bits [62:51], stride 4 bytes.
    """
    if fmt in _ARM64E_FAMILY:
        # next field is bits [61:51] in both auth and non-auth arm64e structs
        return ((raw >> 51) & 0x7FF) * 8
    elif fmt in (_DYLD_PTR_64, _DYLD_PTR_64_OFFSET):
        return ((raw >> 51) & 0xFFF) * 4
    return 0


def _ctx_cache(ctx, attr, factory):
    """Return ``getattr(ctx, attr)``, lazily creating it via ``factory()`` and
    memoising it on *ctx* under *attr*.

    Standardises the per-extraction "cache a binary-wide pre-pass / lazily-grown
    container on the context" idiom used across the proto extractors (readFrom core
    index, writeTo helper family, dispatch-arm and wrapper-cluster caches, the
    dictRep-truncated-class set, …).  *factory* is a 0-arg callable: pass a type
    (``dict`` / ``set``) for a container that callers then grow in place, or
    ``lambda: build(...)`` for a build-once result.

    Uses ``is None`` (not truthiness) so an already-cached EMPTY container is returned
    rather than rebuilt.  If *ctx* rejects attribute assignment (e.g. a ``__slots__``
    or read-only stub), the freshly built value is returned UNCACHED so the caller
    still works — just without cross-call memoisation.

    *attr* is registered as a per-extraction cache (:func:`reset_ctx_caches`)."""
    _CTX_CACHE_ATTRS.add(attr)
    val = getattr(ctx, attr, None)
    if val is None:
        val = factory()
        try:
            setattr(ctx, attr, val)
        except (AttributeError, TypeError):
            pass
    return val


#: Every attribute a module has memoised per-extraction state under on a context, recorded
#: when the cache is created (:func:`_ctx_cache`, :func:`_ctx_store`), so
#: :func:`reset_ctx_caches` clears all of them without a hand-kept list that falls behind
#: the code.  A cache never created in this process needs no reset.
_CTX_CACHE_ATTRS: set = set()


def _ctx_store(ctx, attr, value):
    """Store *value* as the per-extraction cache *attr* on *ctx* (for caches built in one
    piece rather than through :func:`_ctx_cache`) and register *attr* for reset."""
    _CTX_CACHE_ATTRS.add(attr)
    try:
        setattr(ctx, attr, value)
    except (AttributeError, TypeError):
        pass
    return value


def unread_input(ctx) -> List[Tuple[str, str, str]]:
    """The structural input of *ctx* that could not be read: ``(what, where, error)``, kept for
    the context's life (:func:`record_unread`)."""
    try:
        return ctx.__dict__.setdefault("_unread_input", [])
    except AttributeError:                       # (a stand-in with no __dict__)
        return []


def record_unread(ctx, what: str, where: str, exc: Exception) -> None:
    """*what* (a class, its method list ...) at *where* could not be read (*exc*): what it
    holds is missing from the output.  Warned the first time each kind of *what* is met; every
    one is in the run summary and counts as an error (``ExtractionDiagnostics.unread``)."""
    seen = unread_input(ctx)
    if any(e[:2] == (what, where) for e in seen):
        return                                   # (read again by another pass)
    if not any(e[0] == what for e in seen):
        log.warning("%s unreadable at %s (%s: %s); what it holds is MISSING from the output "
                    "(every place is listed in the run summary)", what, where,
                    type(exc).__name__, exc)
    seen.append((what, where, f"{type(exc).__name__}: {exc}"))


def reset_ctx_caches(ctx) -> None:
    """Clear every registered per-extraction cache on *ctx*, so a context reused for a second
    extraction cannot serve results memoised by the first."""
    for attr in sorted(_CTX_CACHE_ATTRS):
        try:
            setattr(ctx, attr, None)
        except (AttributeError, TypeError):
            pass


# ─── BinaryContext ────────────────────────────────────────────────────────────

def _within(max_len: Optional[int]) -> str:
    return f"within {max_len} bytes" if max_len is not None else "before the end of its segment"


class BinaryContext:
    """
    Random-access reader over a single-arch arm64 Mach-O binary.

    All public read methods take vmaddr values; file offsets are computed
    internally.  read_ptr / iter_ptrs transparently decode chained fixup
    pointers when the binary includes LC_DYLD_CHAINED_FIXUPS.
    """

    def __init__(self, data: bytes) -> None:
        if len(data) < 32:
            raise ValueError("Binary too short (< 32 bytes)")

        magic = struct.unpack_from('<I', data, 0)[0]
        if magic == FAT_MAGIC:
            raise ValueError("Fat binary detected — extract the desired slice first")
        if magic == MH_CIGAM_64:
            raise ValueError("Big-endian Mach-O is not supported")
        if magic != MH_MAGIC_64:
            raise ValueError(f"Not a 64-bit LE Mach-O (magic=0x{magic:08x})")

        self._data: bytes = data
        self._segments:  List[Segment]               = []
        self._sections:  Dict[Tuple[str,str], Section] = {}
        self._fixup_map: Dict[int, int]              = {}   # vmaddr → decoded vmaddr
        self._bind_name_map: Dict[int, str]          = {}   # vmaddr → import symbol name
        self._bind_slots: set                        = set()  # every chained-fixup bind
        self._chained = False                        # LC_DYLD_CHAINED_FIXUPS present
        self._chained_fixups_lc: Optional[Tuple[int, int]] = None   # its (dataoff, datasize)
        self._imports:   List[str]                   = []   # ordinal → import symbol name
        self._image_base: Optional[int]              = None  # cached after load commands
        # LC_SYMTAB (symoff, nsyms, stroff, strsize) — file offsets into _data.
        # Populated only in binary mode; cache-mode symbols live in the shared
        # LINKEDIT (not addressable through the vmaddr-only cache reader), so it
        # stays None there and iter_symbol_names() yields nothing.
        self._symtab: Optional[Tuple[int, int, int, int]] = None
        # dyld export-trie (file_off, size) — holds *exported* symbol names (incl.
        # Swift protocol-conformance descriptors), which are NOT in the nlist
        # symtab.  Binary mode only; None in cache mode.
        self._export_trie: Optional[Tuple[int, int]] = None
        # LC_FUNCTION_STARTS (file_off, size); binary mode only (function_starts()).
        self._function_starts_lc: Optional[Tuple[int, int]] = None
        self._function_starts: Optional[List[int]] = None

        (_, cputype, cpusubtype, _filetype,
         ncmds, sizeofcmds, _flags, _) = struct.unpack_from('<IIIIIIII', data, 0)

        if len(data) < 32 + sizeofcmds:
            raise ValueError(
                f"Binary truncated: need {32 + sizeofcmds} bytes, "
                f"have {len(data)}"
            )

        if cputype != CPU_TYPE_ARM64:
            # Every decoder here is arm64/arm64e (instruction decode, ObjC ABI, pointer
            # authentication): an x86_64 or arm32 image would "load" and then silently
            # yield no messages, which looks like a clean extraction.
            raise ValueError(
                f"unsupported CPU type {cputype:#x}: this tool decodes arm64/arm64e "
                f"Mach-O images only (for a fat binary pass the arm64 slice, or let the "
                f"loader pick it)")
        self._cache_reader: 'Optional[object]' = None  # set only by from_cache()
        self._cpu_type    = cputype
        self._cpu_subtype = cpusubtype
        self._filetype    = _filetype     # MH_EXECUTE, MH_DYLIB, …
        self._parse_load_commands(ncmds, sizeofcmds)
        self._image_base = self._local_image_base()
        for seg in self._segments:
            if seg.filesize and seg.fileoff + seg.filesize > len(data):
                raise ValueError(
                    f"Binary truncated: segment {seg.name} needs file bytes "
                    f"{seg.fileoff:#x}..{seg.fileoff + seg.filesize:#x}, "
                    f"the file has {len(data):#x}")
        if self._chained_fixups_lc is not None:     # (its rebases are offsets from the base)
            self._parse_chained_fixups_lc(*self._chained_fixups_lc)


    # ── Cache-mode factory ───────────────────────────────────────────────────

    @classmethod
    def from_cache(
        cls,
        reader: DyldCacheReader,        # resolved lazily: __future__ annotations
        mach_header_va: int,
    ) -> 'BinaryContext':
        """
        Create a :class:`BinaryContext` backed by the dyld shared cache.

        All read operations (``read_u64``, ``read_bytes``, ``read_cstring``,
        ``read_ptr``, ``iter_ptrs``) go through *reader* rather than an
        in-memory binary.  No ipsw-extracted binary file is required.

        External class references (e.g. ``NSString``, ``NSData``) are resolved
        live by following the encoded pointer to the external ``class_t`` and
        reading its name from ``class_ro_t.name`` — no bind table needed.

        Parameters
        ----------
        reader:
            An open :class:`DyldCacheReader` with all relevant sub-caches
            loaded (TEXT for code/strings, DATA for class structures).
            The reader must remain open for the entire lifetime of the
            returned context, including any calls to
            :func:`~macho.classlist.build_class_list` and
            :func:`~proto.extractor.extract_all`.
        mach_header_va:
            Absolute cache vmaddr of the framework's Mach-O header, as
            returned by :meth:`DyldCacheReader.find_image_header`.
        """
        # Structural check, not isinstance: dyld_cache imports THIS module's
        # layer, so naming DyldCacheReader at runtime would reintroduce the
        # import cycle (the annotation above resolves via TYPE_CHECKING).  These
        # are the reader's read primitives this class consumes.
        for _attr in ('read_u64', 'read_raw', 'read_cstring', 'decode_ptr', 'read_ptr'):
            assert callable(getattr(reader, _attr, None)), (
                f'from_cache() needs a DyldCacheReader-like object; '
                f'{type(reader).__name__} has no {_attr}()'
            )

        # Bypass __init__ — there are no binary bytes to parse.
        self = cls.__new__(cls)
        self._data           = b''
        self._segments: List[Segment]               = []
        self._sections: Dict[Tuple[str,str], Section] = {}
        self._fixup_map: Dict[int, int]             = {}
        self._bind_name_map: Dict[int, str]         = {}
        self._bind_slots: set                       = set()  # a cache binds nothing at load
        self._chained = False
        self._imports:   List[str]                  = []   # unused in cache mode
        self._symtab:    Optional[Tuple[int, int, int, int]] = None  # see binary __init__
        self._export_trie: Optional[Tuple[int, int]] = None
        self._function_starts_lc: Optional[Tuple[int, int]] = None
        self._function_starts: Optional[List[int]] = None
        self._image_base: Optional[int]             = mach_header_va
        self._cache_reader                          = reader

        # cpu_type / cpu_subtype: not read from a cache image's header (nothing that decodes
        # reads them); arm64, subtype 0 -- also for an arm64e cache.
        self._cpu_type    = CPU_TYPE_ARM64
        self._cpu_subtype = 0
        # Cache images are always shared libraries (frameworks/dylibs).
        self._filetype    = MH_DYLIB

        # The image's segments and sections, so has_section() / section() work as in binary
        # mode; the ones image_sections() lists (a segment that maps something, a section with
        # an address and a size).  Every read goes through the reader, so no file offsets.
        try:
            lc = reader.image_load_commands(mach_header_va)
        except ValueError as exc:
            record_unread(self, "cache image load commands", f"{mach_header_va:#x}", exc)
            lc = LoadCommands()
        for seg in lc.segments:
            if not seg.vmsize:
                continue
            kept = Segment(name=seg.name, vmaddr=seg.vmaddr, vmsize=seg.vmsize,
                           fileoff=0, filesize=seg.vmsize)
            for s in seg.sections:
                if s.vmaddr and s.vmsize:
                    sect = Section(name=s.name, segname=seg.name, vmaddr=s.vmaddr,
                                   vmsize=s.vmsize, file_off=0, flags=s.flags)
                    kept.sections.append(sect)
                    self._sections[(seg.name, s.name)] = sect
            self._segments.append(kept)
        self._cache_errors_seen = 0
        for path, exc in sorted(reader.subcache_errors().items()):
            record_unread(self, "sub-cache file", path, exc)    # (its pages read as unmapped)
        return self

    # ── Properties ──────────────────────────────────────────────────────────

    @property
    def filetype(self) -> int:
        """Mach-O header filetype (MH_EXECUTE, MH_DYLIB, …)."""
        return self._filetype

    @property
    def is_executable(self) -> bool:
        """True for a standalone executable (``MH_EXECUTE``).

        A standalone executable is self-contained — all of its own selector
        strings, value tables, and constant strings live inside the binary — so
        enum extraction that fails for such a binary indicates a tool bug, not
        missing shared-cache data (unlike a dylib extracted from the cache)."""
        return self._filetype == MH_EXECUTE

    @property
    def is_dylib(self) -> bool:
        """True for a shared library / framework image (``MH_DYLIB``)."""
        return self._filetype == MH_DYLIB

    @property
    def cpu_type(self) -> int:
        return self._cpu_type

    @property
    def is_arm64e(self) -> bool:
        """True if cpu_subtype encodes ARM64E (subtype & 0xFF == 2)."""
        return (self._cpu_subtype & 0xFF) == 2

    @property
    def image_base(self) -> int:
        """The vmaddr of the image's Mach-O header (:meth:`_local_image_base`; in a cache, the
        header the image was loaded from)."""
        return self._image_base if self._image_base is not None else 0

    @property
    def segments(self) -> List[Segment]:
        """Read-only view of all parsed segments (use instead of _segments)."""
        return list(self._segments)

    @property
    def image_bytes(self) -> bytes:
        """The image's own bytes in binary mode (the thin slice); ``b''`` cache-native, where
        every read goes through the cache reader."""
        return self._data

    @property
    def is_cache_backed(self) -> bool:
        """True if this context reads through a DyldCacheReader (cache-native mode).

        In cache-native mode ``self._data`` is empty (b'') and all reads are
        routed through the cache reader.  Code that needs to distinguish the
        two modes (e.g. :func:`~macho.disasm.disasm`) uses this property
        rather than testing the private ``_cache_reader`` attribute directly.
        """
        return self._cache_reader is not None

    # ── Section access ───────────────────────────────────────────────────────

    def section(self, segname: str, sectname: str) -> Section:
        key = (segname, sectname)
        if key not in self._sections:
            raise KeyError(f"Section not found: {segname}:{sectname}")
        return self._sections[key]

    def has_section(self, segname: str, sectname: str) -> bool:
        return (segname, sectname) in self._sections

    # ── Core read primitives ─────────────────────────────────────────────────

    def vmaddr_to_offset(self, vmaddr: int, length: int = 1) -> int:
        """
        Translate *vmaddr* to a file offset, validating that the read window
        fits within the mapped segment and within the binary data.

        Raises ValueError for unmapped, zerofill, or overrunning addresses.
        """
        for seg in self._segments:
            if seg.vmaddr <= vmaddr < seg.vmaddr + seg.vmsize:
                if seg.filesize == 0:
                    raise ValueError(
                        f"vmaddr 0x{vmaddr:x} maps to zerofill segment '{seg.name}'"
                    )
                off = seg.fileoff + (vmaddr - seg.vmaddr)
                seg_end = seg.fileoff + seg.filesize
                if off + length > seg_end:
                    raise ValueError(
                        f"Read of {length} bytes at 0x{vmaddr:x} overruns "
                        f"segment '{seg.name}' boundary"
                    )
                if off + length > len(self._data):
                    raise ValueError(
                        f"Read of {length} bytes at 0x{vmaddr:x} exceeds binary size"
                    )
                return off
        raise ValueError(f"vmaddr 0x{vmaddr:x} is not mapped")

    def read_bytes(self, vmaddr: int, length: int) -> bytes:
        if self._cache_reader is not None:
            raw = self._cache_reader.read_raw(vmaddr, length)
            if raw is None or len(raw) < length:
                raise ValueError(
                    f"vmaddr 0x{vmaddr:x} not fully mapped in cache "
                    f"(requested {length}, got {len(raw) if raw else 0})"
                )
            return raw
        off = self.vmaddr_to_offset(vmaddr, length)
        return self._data[off : off + length]

    def read_u32(self, vmaddr: int) -> int:
        if self._cache_reader is not None:
            raw = self._cache_reader.read_raw(vmaddr, 4)
            if raw is None or len(raw) < 4:
                raise ValueError(f"vmaddr 0x{vmaddr:x} not mapped in cache")
            return struct.unpack_from('<I', raw)[0]
        return struct.unpack_from('<I', self._data, self.vmaddr_to_offset(vmaddr, 4))[0]

    def read_u64(self, vmaddr: int) -> int:
        if self._cache_reader is not None:
            val = self._cache_reader.read_u64(vmaddr)
            if val is None:
                raise ValueError(f"vmaddr 0x{vmaddr:x} not mapped in cache")
            return val
        return struct.unpack_from('<Q', self._data, self.vmaddr_to_offset(vmaddr, 8))[0]

    def read_s32(self, vmaddr: int) -> int:
        if self._cache_reader is not None:
            raw = self._cache_reader.read_raw(vmaddr, 4)
            if raw is None or len(raw) < 4:
                raise ValueError(f"vmaddr 0x{vmaddr:x} not mapped in cache")
            return struct.unpack_from('<i', raw)[0]
        return struct.unpack_from('<i', self._data, self.vmaddr_to_offset(vmaddr, 4))[0]

    def read_s64(self, vmaddr: int) -> int:
        if self._cache_reader is not None:
            raw = self._cache_reader.read_raw(vmaddr, 8)
            if raw is None or len(raw) < 8:
                raise ValueError(f"vmaddr 0x{vmaddr:x} not mapped in cache")
            return struct.unpack_from('<q', raw)[0]
        return struct.unpack_from('<q', self._data, self.vmaddr_to_offset(vmaddr, 8))[0]

    def read_cstring(self, vmaddr: int, max_len: Optional[int] = None) -> str:
        """Read a null-terminated C string, clamped to the segment boundary (in a cache, the
        mapping's end), and to *max_len* bytes when given."""
        if self._cache_reader is not None:
            s = self._cache_reader.read_cstring(vmaddr, max_len=max_len)
            if s is None:
                raise ValueError(f"no string at 0x{vmaddr:x}: unmapped, undecodable, or no null "
                                 f"terminator {_within(max_len)}")
            return s
        off     = self.vmaddr_to_offset(vmaddr, 1)
        seg_end = self._segment_end_offset(vmaddr)
        cap     = seg_end if max_len is None else min(off + max_len, seg_end)
        null    = self._data.find(b'\x00', off, cap)
        if null < 0:
            raise ValueError(f"no null terminator {_within(max_len)} of 0x{vmaddr:x}")
        raw = self._data[off:null]
        try:
            return raw.decode('utf-8')
        except UnicodeDecodeError:
            return raw.decode('latin-1')

    def segment_at(self, vmaddr: int) -> Optional[Segment]:
        """The image's segment holding *vmaddr*, or None."""
        return next((s for s in self._segments if s.vmaddr <= vmaddr < s.vmaddr + s.vmsize), None)

    def _segment_end_offset(self, vmaddr: int) -> int:
        seg = self.segment_at(vmaddr)
        return len(self._data) if seg is None else seg.fileoff + seg.filesize

    def _decode_packed_ptr(self, raw: int) -> int:
        """*raw*, a pointer word of a binary extracted from a dyld shared cache, decoded: such a
        binary keeps the cache's packed form, the vmaddr in the low 36 bits and chain /
        authentication metadata above.  Decoded only when bits above 35 are set and the low 36
        bits fall in one of this binary's own segments (an address only the cache maps is not
        resolvable here); else *raw*.  Only for a binary without chained fixups, whose pointers
        :attr:`_fixup_map` holds (:meth:`read_ptr`)."""
        if raw > 0xFFFFFFFFF:          # bits set above bit 35 → possible metadata
            low36 = raw & 0xFFFFFFFFF
            if low36:
                # Accept only when the target is within the binary's own mapped
                # segments (the decode is then verifiable).
                if any(
                    s.vmaddr <= low36 < s.vmaddr + s.vmsize
                    for s in self._segments
                    if s.name != '__PAGEZERO'
                ):
                    return low36
        return raw

    def read_ptr(self, vmaddr: int) -> int:
        """Read a pointer-width value, returning the fixup-decoded vmaddr.

        Resolution order (binary mode):
          1. ``_fixup_map`` (populated from LC_DYLD_CHAINED_FIXUPS).
          2. A chained-fixup bind: its raw value, which is no address of this file (the
             import it binds, :meth:`bind_name_for`, names it).
          3. In a binary with chained fixups, any other word is no pointer: its raw value.
          4. Without them (a binary extracted from a cache): the packed-pointer decode.

        In cache mode: :meth:`DyldCacheReader.read_ptr`.
        """
        if self._cache_reader is not None:
            return self._cache_reader.read_ptr(vmaddr)
        decoded = self._fixup_map.get(vmaddr)
        if decoded is not None:
            return decoded
        raw = self.read_u64(vmaddr)
        return raw if self._chained else self._decode_packed_ptr(raw)

    def is_variable(self, vmaddr: int) -> bool:
        """Whether the file does not give *vmaddr*'s run-time value: it lies in a section the
        program writes (:data:`PROGRAM_DATA_SECTIONS`), or is a slot dyld binds to an import
        (its value is that import's address, in another image: a chained-fixup bind, or a
        symbol-pointer section's slot in a binary without chained fixups).  A dyld cache was
        bound when it was built, so there only the first applies, in whichever image holds
        *vmaddr* (an image whose load commands cannot be read holds none: recorded)."""
        if self._cache_reader is not None:
            reader = self._cache_reader
            out = reader.is_program_data(vmaddr)
            unread = reader.unreadable_images()
            if len(unread) != self._cache_errors_seen:     # (another image found unreadable)
                self._cache_errors_seen = len(unread)
                for mh, exc in sorted(unread.items()):
                    record_unread(self, "cache image load commands", f"{mh:#x}", exc)
            return out
        if vmaddr in self._bind_slots:
            return True
        for sec in self._sections.values():
            if sec.vmaddr <= vmaddr < sec.vmaddr + sec.vmsize:
                return (sec.name in PROGRAM_DATA_SECTIONS or
                        (not self._chained and (sec.flags & 0xFF) in _SYMBOL_POINTER_TYPES))
        return False

    def iter_ptrs(self, vmaddr: int, count: int) -> Iterator[int]:
        """Iterate over *count* consecutive pointer values starting at vmaddr.

        Binary mode: as :meth:`read_ptr` -- fixup-map entries decoded, any other word raw with
        chained fixups, else the packed-pointer decode.  Cache mode: each slot is decoded via
        :meth:`DyldCacheReader.decode_ptr`.
        """
        if self._cache_reader is not None:
            for i in range(count):
                slot = vmaddr + i * 8
                val  = self._cache_reader.read_u64(slot)
                yield self._cache_reader.decode_ptr(val) if val is not None else 0
            return
        off = self.vmaddr_to_offset(vmaddr, count * 8)
        for i in range(count):
            raw  = struct.unpack_from('<Q', self._data, off + i * 8)[0]
            slot = vmaddr + i * 8
            decoded = self._fixup_map.get(slot)
            if decoded is None:
                decoded = raw if self._chained else self._decode_packed_ptr(raw)
            yield decoded

    def bind_name_for(self, vmaddr: int) -> Optional[str]:
        """The symbol the chained-fixup bind at *vmaddr* binds to (``_OBJC_CLASS_$_NSString``),
        or None (no bind there).  Binary mode: the chain walk's table, by slot -- a value
        alone cannot say it is a bind.  A dyld cache was bound when it was built: None (its
        pointers are read through, :meth:`read_ptr`)."""
        return self._bind_name_map.get(vmaddr)

    def iter_symbol_names(self) -> Iterator[str]:
        """Yield every symbol name the binary declares (:meth:`iter_symbols`).
        Names are returned raw (mangled), e.g. the Swift conformance descriptor
        ``_$s14bookdatastored15PBPropertyValueV21InternalSwiftProtobuf7MessageAAMc``
        or the C++ ``__ZN6google8protobuf11MessageLite…``; callers pattern-match.
        """
        for name, _addr in self.iter_symbols():
            yield name

    def iter_symbols(self) -> Iterator[Tuple[str, Optional[int]]]:
        """``(name, address or None)`` for every symbol the binary declares: the ``LC_SYMTAB``
        nlist entries (the address of one defined in a section, else None) and the dyld
        **export trie**, which holds exported symbols such as Swift protocol-conformance
        descriptors that never appear in the nlist table (the image base + its offset; None
        for a re-export).

        Binary mode only — reads straight from ``_data`` at the linkedit file offsets; a no-op
        for a cache image (whose exports :meth:`macho.dyld_cache.DyldCacheReader.image_exports`
        reads from the cache's shared LINKEDIT)."""
        if not self._data:
            return
        if self._symtab:
            symoff, nsyms, stroff, strsize = self._symtab
            data = self._data
            n = len(data)
            str_end = min(stroff + strsize, n)
            if symoff > 0 and stroff > 0 and symoff < n:
                nsyms = min(nsyms, (n - symoff) // 16)
                for i in range(nsyms):
                    n_strx, _type, n_sect, _desc, n_value = struct.unpack_from(
                        '<IBBHQ', data, symoff + i * 16)
                    if n_strx == 0:
                        continue
                    sp = stroff + n_strx
                    if sp >= str_end:
                        continue
                    end = data.find(b'\x00', sp, str_end)
                    if end < 0:
                        end = str_end
                    yield (data[sp:end].decode('utf-8', errors='replace'),
                           n_value if n_sect and n_value else None)
        if self._export_trie:
            from .export_trie import iter_export_trie
            base, size = self._export_trie
            if 0 < base < len(self._data):
                for name, _flags, off in iter_export_trie(
                        self._data[base:min(base + size, len(self._data))]):
                    yield name, (None if off is None else self.image_base + off)

    def function_starts(self) -> List[int]:
        """The image's function entries (``LC_FUNCTION_STARTS``), sorted; ``[]`` without the
        command.  A cache image's table is in the shared ``__LINKEDIT``
        (:meth:`macho.dyld_cache.DyldCacheReader.image_function_starts`).  Read once."""
        if self._function_starts is None:
            if self._cache_reader is not None:
                try:
                    self._function_starts = self._cache_reader.image_function_starts(
                        self.image_base)
                except READ_ERRORS as exc:          # (extents then unknown: reads run on)
                    record_unread(self, "function starts", f"{self.image_base:#x}", exc)
                    self._function_starts = []
            else:
                text = next((s for s in self._segments if s.name == '__TEXT'), None)
                off, size = self._function_starts_lc or (0, 0)
                try:
                    self._function_starts = (decode_function_starts(self._data[off:off + size],
                                                                    text.vmaddr)
                                             if text is not None and size else [])
                except READ_ERRORS as exc:
                    record_unread(self, "function starts", f"{off:#x}", exc)
                    self._function_starts = []
        return self._function_starts

    def find_cstring_in_section(
        self, segname: str, sectname: str, target: str
    ) -> Optional[int]:
        """Return the vmaddr of *target* string within the named section, or None."""
        if not self.has_section(segname, sectname):
            return None
        sect = self.section(segname, sectname)
        if not sect.has_file_content or sect.vmsize == 0:
            return None
        try:
            data = self.read_bytes(sect.vmaddr, sect.vmsize)
        except ValueError:
            return None
        needle = target.encode('utf-8') + b'\x00'
        idx = data.find(needle)
        return None if idx < 0 else sect.vmaddr + idx

    # ── Load command parsing ─────────────────────────────────────────────────

    def _parse_load_commands(self, ncmds: int, sizeofcmds: int) -> None:
        lc = parse_load_commands(self._data[32:32 + sizeofcmds], ncmds)
        self._segments = lc.segments
        for seg in lc.segments:
            for sect in seg.sections:
                self._sections[(sect.segname, sect.name)] = sect
        self._symtab = lc.symtab
        self._function_starts_lc = lc.function_starts
        self._export_trie = lc.export_trie
        self._chained = lc.chained_fixups is not None
        self._chained_fixups_lc = lc.chained_fixups

    def _parse_chained_fixups_lc(self, data_off: int, data_size: int) -> None:
        """Parse the LC_DYLD_CHAINED_FIXUPS data at file range (*data_off*, *data_size*) and
        walk all fixup chains (after the segments and the image base are known).

        Also parses the imports table so that bind entries (external symbol
        references such as ``_OBJC_CLASS_$_NSString``) are recorded in
        ``_bind_name_map`` by their slot vmaddr.  This lets callers identify
        system/Foundation class references that have no entry in the binary's
        own classlist.
        """
        end = data_off + data_size
        if end > len(self._data) or data_size < 28:
            return

        blob = self._data[data_off : data_off + data_size]

        # dyld_chained_fixups_header (28 bytes)
        (_ver, starts_off, imp_off, sym_off,
         imp_cnt, imp_fmt, sym_fmt) = struct.unpack_from('<IIIIIII', blob, 0)

        # ── Parse imports table ──────────────────────────────────────────────
        # Each import maps an ordinal (embedded in bind chain entries) to an external
        # symbol name, an offset into the symbol pool at sym_off (fixup-chains.h):
        #   1 = DYLD_CHAINED_IMPORT          u32: lib_ordinal:8 weak_import:1 name_offset:23
        #   2 = DYLD_CHAINED_IMPORT_ADDEND   the same u32, then an int32 addend
        #   3 = DYLD_CHAINED_IMPORT_ADDEND64 u64: lib_ordinal:16 weak_import:1 reserved:15
        #                                    name_offset:32, then a u64 addend
        # symbols_format 0: the pool as it is; 1: zlib-compressed.
        imports: List[str] = []
        entry_size = {1: 4, 2: 8, 3: 16}.get(imp_fmt, 0)
        pool = blob[sym_off:]
        if sym_fmt == 1:
            try:
                pool = zlib.decompress(pool)
            except zlib.error as exc:
                record_unread(self, "chained-fixup symbol pool", f"{data_off:#x}", exc)
                pool = b""
        elif sym_fmt != 0:
            record_unread(self, "chained-fixup symbol pool", f"{data_off:#x}",
                          ValueError(f"symbols_format {sym_fmt}"))
            pool = b""
        if not entry_size and imp_cnt:
            record_unread(self, "chained-fixup imports", f"{data_off:#x}",
                          ValueError(f"imports_format {imp_fmt}"))
        for i in range(imp_cnt if entry_size else 0):
            entry = imp_off + i * entry_size
            if entry + entry_size > len(blob):
                record_unread(self, "chained-fixup imports", f"{data_off:#x}",
                              ValueError(f"{imp_cnt} imports past the end of the data"))
                break
            if imp_fmt == 3:
                name_off = struct.unpack_from('<Q', blob, entry)[0] >> 32
            else:
                name_off = (struct.unpack_from('<I', blob, entry)[0] >> 9) & 0x7FFFFF
            end_b = pool.find(b'\x00', name_off) if name_off < len(pool) else -1
            imports.append(pool[name_off:end_b].decode('utf-8', errors='replace')
                           if end_b >= 0 else '')

        # Retain the ordinal → symbol-name table (the emulation oracles bind by ordinal).
        self._imports = imports

        if starts_off + 4 > len(blob):
            return
        seg_count = struct.unpack_from('<I', blob, starts_off)[0]
        if seg_count > 256:       # [cap:INPUT-SANITY] the header's segment count (an image has a few)
            return

        for seg_idx in range(seg_count):
            ptr_off = starts_off + 4 + seg_idx * 4
            if ptr_off + 4 > len(blob):
                break
            seg_info_rel = struct.unpack_from('<I', blob, ptr_off)[0]
            if seg_info_rel == 0:
                continue
            seg_info_abs = starts_off + seg_info_rel
            if seg_info_abs + 22 > len(blob):
                continue

            # dyld_chained_starts_in_segment fixed header layout (20 bytes):
            #   uint32  size             offset  0
            #   uint16  page_size        offset  4
            #   uint16  pointer_format   offset  6
            #   uint64  segment_offset   offset  8
            #   uint32  max_valid_pointer offset 16
            #   uint16  page_count       offset 20  ← read below
            #   uint16  page_start[]     offset 22  ← variable-length array
            (_sz, page_size, ptr_fmt, _seg_off,
             _max_ptr) = struct.unpack_from('<IHHQI', blob, seg_info_abs)

            if ptr_fmt == 0 or seg_info_abs + 22 > len(blob):
                continue
            page_count = struct.unpack_from('<H', blob, seg_info_abs + 20)[0]
            # pointer_format is per segment (offset 6, above): the chain walk below uses
            # this segment's.

            if seg_idx >= len(self._segments):
                continue
            seg = self._segments[seg_idx]

            for pg in range(page_count):
                ps_off = seg_info_abs + 22 + pg * 2
                if ps_off + 2 > len(blob):
                    break
                page_start = struct.unpack_from('<H', blob, ps_off)[0]
                if page_start == 0xFFFF:   # DYLD_CHAINED_PTR_START_NONE
                    continue
                chain_va = seg.vmaddr + pg * page_size + page_start
                self._walk_chain(chain_va, ptr_fmt, imports)

    def _local_image_base(self) -> int:
        """The image's base: the vmaddr of the segment holding its header (file offset 0 --
        a dylib's __TEXT is at 0, an executable's after __PAGEZERO), else the lowest segment
        other than __PAGEZERO."""
        for s in self._segments:
            if s.fileoff == 0 and s.filesize > 0:
                return s.vmaddr
        candidates = [s.vmaddr for s in self._segments if s.name != '__PAGEZERO']
        return min(candidates) if candidates else 0

    def _walk_chain(self, vmaddr: int, fmt: int,
                    imports: Optional[List[str]] = None) -> None:
        """Walk one fixup chain, populating ``_fixup_map`` and ``_bind_name_map``.

        Rebase entries (bind=0) are decoded and stored in ``_fixup_map``.  Bind entries (bind=1) have their import symbol name stored in
        ``_bind_name_map`` so callers can identify external class references
        (e.g. slot → ``"_OBJC_CLASS_$_NSString"``).
        """
        seen: set = set()
        base = self._image_base
        while vmaddr not in seen:
            seen.add(vmaddr)
            try:
                off = self.vmaddr_to_offset(vmaddr, 8)
            except ValueError:
                break
            raw = struct.unpack_from('<Q', self._data, off)[0]

            # ── Bind entry: record external symbol name ──────────────────────
            ordinal = _bind_ordinal(raw, fmt)
            if ordinal is not None:
                self._bind_slots.add(vmaddr)
                if imports and 0 <= ordinal < len(imports):
                    sym = imports[ordinal]
                    if sym:
                        self._bind_name_map[vmaddr] = sym
            else:
                decoded = _decode_chain_ptr(raw, fmt, base)
                if decoded:
                    self._fixup_map[vmaddr] = decoded

            stride = _chain_next_stride(raw, fmt)
            if stride == 0:
                break
            vmaddr += stride
