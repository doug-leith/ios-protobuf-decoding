"""
macho/dyld_cache.py
===================
Reads selector strings from a dyld shared cache, including split caches
(iOS 15+ / macOS Ventura+ style with .01, .02, … sub-cache files).

Format notes (verified against real arm64 cache):
  - Main cache file contains the full dyld_cache_header with the sub-cache
    entry array.  Sub-cache files each carry a minimal header (same magic,
    their own mappingOffset/mappingCount) but have subCacheArrayCount=0.
  - Every file maps fileOffset=0 → its vmaddr base, so:
        file_offset = vmaddr − mapping.vmaddr + mapping.file_offset
    reduces to just (vmaddr − mapping.vmaddr) in practice, but the general
    formula is used throughout so non-zero fileOffset values are handled.
  - Sub-cache entry stride is 56 bytes (dyld_subcache_entry_v2):
        uuid[16]  cacheVMOffset u64  fileExtension[32]
    Extensions are zero-padded decimal strings: ".01", ".02", …
  - Each file's sharedRegionStart equals its mapping's vmaddr base; we use
    the mapping entry's address field directly rather than relying on that.

Usage:
    reader = DyldCacheReader('/path/to/dyld_shared_cache_arm64')
    name = reader.read_cstring(0x18251984f)   # → 'readFrom:'
    reader.close()

    # or as a context manager:
    with DyldCacheReader(path) as reader:
        name = reader.read_cstring(vmaddr)
"""

from __future__ import annotations

import bisect
import os
import re
import struct
import sys
import warnings
from typing import Dict, List, Optional, Set, Tuple

from .memory import LC_DYLD_EXPORTS_TRIE, LC_DYLD_INFO, LC_DYLD_INFO_ONLY, LC_SEGMENT_64
from .local_symbols import (
    load_image_local_symbols,
    load_image_symbol_addrs,
    symbols_path_for,
)


# ── Image-name resolution (find_image_header / resolve_image) ────────────────
# Resolving a bare framework name (e.g. 'GeoServices') to an image is done by
# IDENTITY, not substring containment: 'GeoServices' must not silently resolve
# to 'GeoServicesCore' just because it is a substring of that path.  See
# resolve_image() for the tier order.

class ImageResolutionError(Exception):
    """Base class for image-name resolution failures."""


class ImageNotFoundError(ImageResolutionError):
    """No image in the cache matched the requested name."""

    def __init__(self, name: str):
        self.name = name
        super().__init__(f"no image matching {name!r}")


class AmbiguousImageError(ImageResolutionError):
    """The requested name matched more than one image (genuine ambiguity)."""

    def __init__(self, name: str, candidates: List[str]):
        self.name = name
        self.candidates = list(candidates)   # full image paths
        super().__init__(
            f"{name!r} matches {len(self.candidates)} images: "
            + ", ".join(self.candidates)
        )


_FW_PRINCIPAL_RE: Dict[str, "re.Pattern[str]"] = {}


def _is_framework_principal(path: str, name: str) -> bool:
    """True iff *path* is the principal binary of ``<name>.framework``.

    Matches ``.../<name>.framework/<name>`` and the versioned
    ``.../<name>.framework/Versions/<v>/<name>``.  This is the canonical
    "this image IS the framework called <name>" test: it excludes nested
    sub-libraries (``vImage.framework/Libraries/libCGInterfaces.dylib``),
    nested sub-frameworks (which match under their OWN name), non-framework
    bundles (``.axbundle``/``.plugin``), and substring shadows
    (``GeoServicesCore`` for name ``GeoServices``).
    """
    pat = _FW_PRINCIPAL_RE.get(name)
    if pat is None:
        n = re.escape(name)
        pat = re.compile(rf'/{n}\.framework/(?:Versions/[^/]+/)?{n}$')
        _FW_PRINCIPAL_RE[name] = pat
    return pat.search(path) is not None


# ── Header field offsets (all in the dyld_cache_header) ──────────────────────

_HDR_MAGIC          = 0x00   # char[16]
_HDR_MAPPING_OFF    = 0x10   # u32  – file offset of mapping array
_HDR_MAPPING_CNT    = 0x14   # u32  – number of mapping entries
_HDR_SLIDE_OFF_LEGACY  = 0x28   # u64  – slideInfoOffsetUnused: file offset of the single
                                #        legacy slide-info block (headers without a
                                #        mappingWithSlide array)
_HDR_MAPPING_SLIDE_OFF = 0x138  # u32  – file offset of the dyld_cache_mapping_and_slide_info array
_HDR_MAPPING_SLIDE_CNT = 0x13c  # u32  – number of entries in that array
_HDR_SUBCACHE_OFF   = 0x188  # u32  – file offset of sub-cache entry array
_HDR_SUBCACHE_CNT   = 0x18c  # u32  – number of sub-cache entries
_HDR_OBJC_OPTS_OFF  = 0x1d0  # u64  – vmaddr offset (from the cache base) of the
                              #        NEW, cache-header-embedded ObjC optimization
                              #        header (dyld's ObjCOptimizationHeader)
_HDR_OBJC_OPTS_SIZE = 0x1d8  # u64  – size of that header; 0 or "too small" means
                              #        this cache predates/lacks the NEW format

# ── Struct sizes ─────────────────────────────────────────────────────────────

_MAPPING_STRIDE     = 32     # sizeof(dyld_cache_mapping_info)
_MAPPING_SLIDE_STRIDE = 56   # sizeof(dyld_cache_mapping_and_slide_info):
                              #   address, size, fileOffset, slideInfoFileOffset,
                              #   slideInfoFileSize (u64 each), flags u64, maxProt u32, initProt u32
_MAPPING_SLIDE_INFO_OFF = 24  # offset of slideInfoFileOffset within that entry

# Slide-info version 5 (dyld_cache_slide_pointer5, iOS 26+ / macOS 26+ arm64e caches)
# encodes every DATA pointer as runtimeOffset:34 | high8:8 | … | next:11 | auth:1.
# The offset from the cache base is the LOW 34 BITS in both the plain and the
# authenticated form, and these caches exceed 4 GB, so a 32-bit mask truncates
# every target past cache_base + 4 GB.  Older arm64e slide versions (v3) keep a
# 32-bit offset and put the PAC diversity in bits 32-47, so they must stay at 32.
_SLIDE_VERSION_5        = 5
_SLIDE5_OFFSET_MASK     = (1 << 34) - 1
_DEFAULT_OFFSET_MASK    = 0xFFFFFFFF

# Sub-cache entry stride is detected at runtime (_detect_subcache_stride),
# not hardcoded.  Two known layouts exist:
#   v1 (24 bytes): uuid[16]  cacheVMOffset u64          — no extension field
#   v2 (56 bytes): uuid[16]  cacheVMOffset u64  fileExtension[32]
# v1 was a short-lived internal format; all known split-cache releases use v2.
# Detection: in v2 the first byte of fileExtension is always '.' (e.g. ".01");
# in v1 that byte is the first byte of the second entry's uuid (random).
_SUBCACHE_STRIDE_V1 = 24
_SUBCACHE_STRIDE_V2 = 56

# How many bytes of each file we read to parse its header fields.
# The sub-cache entry array starts at 0x2a6b0 in the main file, so the main
# header parse reads that separately via a seek rather than requiring a large
# upfront read.
_HDR_READ_SIZE      = 0x1e0  # covers all fields we need (past _HDR_OBJC_OPTS_SIZE)

# ── NEW-format ObjC optimization header (dyld's ObjCOptimizationHeader) ──────
#
#   uint32_t version;                            // +0   header-LAYOUT version
#   uint32_t flags;                              // +4   (1 or 2 today; unrelated
#   uint64_t headerInfoRoCacheOffset;             // +8    to the on-disk hash-table
#   uint64_t headerInfoRwCacheOffset;             // +16   format version, which is
#   uint64_t selectorHashTableCacheOffset;        // +24   always 16)
#   uint64_t classHashTableCacheOffset;           // +32
#   uint64_t protocolHashTableCacheOffset;        // +40
#   uint64_t relativeMethodSelectorBaseAddressOffset;  // +48
#   // v2 adds two more uint64_t fields here (not needed for the anchor)
#
# _OBJC_OPT_HEADER_V1_SIZE is both the minimum valid ObjcOptsSize (a cache too
# old/small to carry this struct at all reports something smaller — those
# caches use the older, per-dylib objc_opt_t instead; see
# macho.classlist._resolve_relative_selector_base_from_libobjc) and the number
# of bytes we need to read to reach relativeMethodSelectorBaseAddressOffset.
_OBJC_OPT_HEADER_V1_SIZE           = 56
_OBJC_OPT_HEADER_REL_SEL_BASE_POS  = 48

_MAX_MAPPINGS       = 64     # sanity cap per file
# [cap:INPUT-SANITY — leave as-is] Guards against malformed cache headers; never the
# operative limit on a real cache, so cannot affect the descriptor.
#   _MAX_SUBCACHES — used as a *validity check, not a truncation*: `sub_cnt >
#     _MAX_SUBCACHES` REJECTS the header rather than silently capping.  Real caches
#     have a few dozen subcaches; it can only reject absurd input.
_MAX_SUBCACHES      = 256    # sanity cap for total sub-cache count
# [cap:INPUT-SANITY — leave as-is] _MAX_CSTRING_LEN caps the NUL-scan when reading a
# string.  The strings that reach the descriptor (selectors, class/enum names) top out
# around ~100 chars, so this 1024 ceiling never truncates a real one — it only stops a
# runaway read on unterminated bytes.  Huge headroom; leave.
_MAX_CSTRING_LEN    = 1024   # max selector string length we'll return

# ── Image-discovery constants (find_image_header / image_sections) ────────────

# dyld_cache_image_text_info stride (iOS 14+ / macOS Big Sur+):
#   uuid[16]  loadAddress u64  textSegmentSize u32  pathOffset u32
_IMAGES_TEXT_STRIDE = 32
# imagesTextOffset/Count header field offsets (u64 each)
_HDR_IMG_TEXT_OFF   = 0x88
_HDR_IMG_TEXT_CNT   = 0x90
_MAX_IMAGES         = 65536    # sanity cap on imagesTextCount

# Mach-O constants for the image load-command walker (the LC_* command types are memory.py's)
_MH_MAGIC_64        = 0xFEEDFACF  # little-endian 64-bit mach-o magic
# load commands naming a dylib the image links (dylib_command: name offset at +8)
_LC_LINKED_DYLIBS = frozenset((
    0x0C,          # LC_LOAD_DYLIB
    0x80000018,    # LC_LOAD_WEAK_DYLIB
    0x8000001F,    # LC_REEXPORT_DYLIB
    0x80000023,    # LC_LOAD_UPWARD_DYLIB
))
_MAX_SIZEOFCMDS     = 1 << 20     # 1 MB sanity cap on sizeofcmds
# [cap:INPUT-SANITY — leave as-is] Bounds the section-iteration loop against a corrupt
# header `nsects` on the cache-image parse path (the analogue of memory.py's
# _MAX_NSECTS).  Real segments have a handful of sections; never the operative limit
# on well-formed input, so cannot affect the descriptor.
_MAX_LC_SECTIONS    = 512         # sanity cap on sections per LC_SEGMENT_64



def _parse_segment64_lc(
    lc_data: bytes, offset: int
) -> Dict[str, Tuple[int, int]]:
    """
    Parse one ``LC_SEGMENT_64`` load command at *offset* within *lc_data*.

    Returns a dict mapping names to exclusive ``(vm_start, vm_end)`` ranges:

    * ``"<segname>"`` — the segment itself (e.g. ``"__TEXT"``).
    * ``"<segname>/<sectname>"`` — each section within it
      (e.g. ``"__TEXT/__objc_methname"``).

    Sections with ``vmaddr == 0`` or ``vmsize == 0`` are omitted; they are
    zero-fill placeholders or padding entries that carry no useful data.

    ``segment_command_64`` layout (first 72 bytes)::

        cmd u32, cmdsize u32, segname char[16],
        vmaddr u64, vmsize u64, fileoff u64, filesize u64,
        maxprot i32, initprot i32, nsects u32, flags u32

    ``section_64`` layout (80 bytes each, immediately after the segment hdr)::

        sectname char[16], segname char[16], addr u64, size u64,
        offset u32, align u32, reloff u32, nreloc u32,
        flags u32, reserved1 u32, reserved2 u32, reserved3 u32
    """
    if offset + 72 > len(lc_data):
        return {}

    segname = lc_data[offset + 8 : offset + 24].rstrip(b'\x00').decode('utf-8', errors='replace')
    vmaddr  = struct.unpack_from('<Q', lc_data, offset + 24)[0]
    vmsize  = struct.unpack_from('<Q', lc_data, offset + 32)[0]
    nsects  = struct.unpack_from('<I', lc_data, offset + 64)[0]

    result: Dict[str, Tuple[int, int]] = {}
    if vmsize > 0:
        result[segname] = (vmaddr, vmaddr + vmsize)

    sect_base = offset + 72
    for i in range(min(nsects, _MAX_LC_SECTIONS)):
        so = sect_base + i * 80
        if so + 80 > len(lc_data):
            break
        sectname = lc_data[so : so + 16].rstrip(b'\x00').decode('utf-8', errors='replace')
        addr     = struct.unpack_from('<Q', lc_data, so + 32)[0]
        size     = struct.unpack_from('<Q', lc_data, so + 40)[0]
        if addr > 0 and size > 0:
            result[f'{segname}/{sectname}'] = (addr, addr + size)

    return result

def _detect_subcache_stride(raw: bytes) -> int:
    """
    Detect the sub-cache entry stride from the raw entry bytes.

    In v2 (56-byte) entries the ``fileExtension`` field starts at byte 24 and
    always begins with ``'.'`` (e.g. ``".01"``, ``".02"``).  In v1 (24-byte)
    entries there is no extension field and byte 24 is the first byte of the
    *next* entry's uuid — a random value that is not ``'.'``.

    Returns 56 for v2, 24 for v1 (or if the buffer is too short to probe).
    File extensions are synthesised from the entry index when v1 is detected.
    """
    if len(raw) >= _SUBCACHE_STRIDE_V2 and raw[24:25] == b'.':
        return _SUBCACHE_STRIDE_V2
    return _SUBCACHE_STRIDE_V1


# ── Internal mapping record ───────────────────────────────────────────────────

class _Mapping:
    """One contiguous vmaddr→file-offset range inside a single cache file."""

    __slots__ = ('vmaddr', 'vmend', 'path', 'file_offset')

    def __init__(self, vmaddr: int, size: int, path: str, file_offset: int) -> None:
        self.vmaddr      = vmaddr
        self.vmend       = vmaddr + size
        self.path        = path
        self.file_offset = file_offset

    def translate(self, vmaddr: int) -> int:
        """Convert a vmaddr in this range to a byte offset in the file."""
        return self.file_offset + (vmaddr - self.vmaddr)


# ── Public class ─────────────────────────────────────────────────────────────

class DyldCacheReader:
    """
    Resolves vmaddrs to cstrings across a (possibly split) dyld shared cache.

    Parameters
    ----------
    main_path:
        Path to the main cache file (e.g. ``dyld_shared_cache_arm64``).
        Sub-cache files in the same directory are opened automatically based
        on the file-extension field in each sub-cache entry.  Missing
        sub-cache files are skipped with a warning rather than raising.
    verbose:
        When ``True``, print detailed sub-cache loading diagnostics to
        ``stderr``.  Useful for diagnosing why selector names are not being
        resolved: shows each expected sub-cache path, whether it was found,
        how many mappings it contributed, and a directory listing of the
        cache folder when any files are missing.

    Raises
    ------
    ValueError
        If *main_path* does not look like a dyld shared cache.
    OSError
        If *main_path* cannot be opened.
    """

    def __init__(self, main_path: str, *, verbose: bool = False) -> None:
        # path → open binary file handle (lazily populated)
        self._fhs:      Dict[str, object]   = {}
        # sorted by vmaddr for binary search
        self._mappings: List[_Mapping]      = []
        # sub-caches that were listed in the header but whose files were absent
        self._missing_subcaches: List[str]  = []
        self._verbose = verbose
        # store main path for find_image_header (imagesText lives there)
        self._main_path: str = main_path

        main_hdr = self._read_hdr_bytes(main_path)
        self._check_magic(main_hdr, main_path)
        # Parse imagesText metadata so find_image_header() works without
        # re-reading the header.  Must run before _load_mappings overwrites
        # nothing — it is purely a read of the already-buffered header bytes.
        self._img_text_off, self._img_text_cnt = (
            self._load_images_text_meta(main_hdr)
        )
        self._mapping_offset_value, self._objc_opts_offset, self._objc_opts_size = (
            self._load_objc_opts_meta(main_hdr)
        )
        # Slide-info versions seen across every cache file; decides how wide the
        # runtime-offset field of a DATA pointer is (see decode_ptr).
        self._slide_versions: Set[int] = set()
        self._load_mappings(main_hdr, main_path)
        self._load_subcaches(main_hdr, main_path)
        self._mappings.sort(key=lambda m: m.vmaddr)
        # Pre-built key list for O(log n) bisect lookups.
        self._vmaddr_keys: List[int] = [m.vmaddr for m in self._mappings]

    # ── Setup helpers ────────────────────────────────────────────────────────

    def _fh(self, path: str):
        """Return (and cache) an open binary file handle for *path*."""
        if path not in self._fhs:
            self._fhs[path] = open(path, 'rb')
        return self._fhs[path]

    def _read_hdr_bytes(self, path: str) -> bytes:
        """Read the first _HDR_READ_SIZE bytes of *path* for header parsing."""
        fh = self._fh(path)
        fh.seek(0)
        return fh.read(_HDR_READ_SIZE)

    @staticmethod
    def _check_magic(hdr: bytes, path: str) -> None:
        # Magic is "dyld_v1   arm64\0" (arm64) or "dyld_v1  arm64e\0" (arm64e).
        # The first seven bytes are stable across both architectures and versions.
        if len(hdr) < 16 or hdr[:7] != b'dyld_v1':
            raise ValueError(f"Not a dyld shared cache: {path!r}")

    def _load_images_text_meta(
        self, hdr: bytes
    ) -> Tuple[int, int]:
        """
        Extract ``imagesTextOffset`` and ``imagesTextCount`` from the already-read
        cache header bytes.  Both are ``u64`` fields introduced in the iOS 14 /
        macOS Big Sur cache format.

        Returns ``(offset, count)`` or ``(0, 0)`` when the header is too short,
        the fields are absent, or the count exceeds the sanity cap.
        """
        # imagesTextOffset u64 at 0x88, imagesTextCount u64 at 0x90.
        # _HDR_READ_SIZE = 0x1a0 > 0x98, so the header bytes we already read
        # always cover these two fields.
        if len(hdr) < _HDR_IMG_TEXT_CNT + 8:
            return 0, 0
        img_off = struct.unpack_from('<Q', hdr, _HDR_IMG_TEXT_OFF)[0]
        img_cnt = struct.unpack_from('<Q', hdr, _HDR_IMG_TEXT_CNT)[0]
        if img_off == 0 or img_cnt == 0 or img_cnt > _MAX_IMAGES:
            return 0, 0
        return img_off, img_cnt

    def _load_objc_opts_meta(self, hdr: bytes) -> Tuple[int, int, int]:
        """
        Extract ``mappingOffset``, ``objcOptsOffset``, and ``objcOptsSize``
        from the already-read main-cache header bytes.

        ``mappingOffset``'s value doubles as an implicit record of how large
        this cache's on-disk ``dyld_cache_header`` actually is (mappings
        conventionally start immediately after it) — comparing it against
        the byte position of ``objcOptsSize`` tells us whether this cache was
        even built with a header long enough to carry the two NEW-format
        fields at all, before we trust their contents.  Mirrors the gate
        ipsw itself uses (``pkg/dyld/objc.go: getOptimizations``).

        Returns ``(0, 0, 0)`` when the header is too short to read these
        fields; that safely disables :meth:`new_format_relative_selector_base`
        without misreading unrelated bytes as an offset/size.
        """
        if len(hdr) < _HDR_OBJC_OPTS_SIZE + 8:
            return 0, 0, 0
        mapping_offset = struct.unpack_from('<I', hdr, _HDR_MAPPING_OFF)[0]
        objc_opts_offset = struct.unpack_from('<Q', hdr, _HDR_OBJC_OPTS_OFF)[0]
        objc_opts_size = struct.unpack_from('<Q', hdr, _HDR_OBJC_OPTS_SIZE)[0]
        return mapping_offset, objc_opts_offset, objc_opts_size

    def _load_mappings(self, hdr: bytes, path: str) -> None:
        """Parse this file's dyld_cache_mapping_info array and record each entry."""
        if len(hdr) < _HDR_MAPPING_OFF + 8:
            return
        map_off = struct.unpack_from('<I', hdr, _HDR_MAPPING_OFF)[0]
        map_cnt = struct.unpack_from('<I', hdr, _HDR_MAPPING_CNT)[0]

        if map_cnt == 0 or map_cnt > _MAX_MAPPINGS or map_off == 0:
            return

        fh = self._fh(path)
        fh.seek(map_off)
        raw = fh.read(map_cnt * _MAPPING_STRIDE)

        for i in range(map_cnt):
            off = i * _MAPPING_STRIDE
            if off + 24 > len(raw):
                break
            # dyld_cache_mapping_info: address u64, size u64, fileOffset u64, …
            vmaddr, size, file_off = struct.unpack_from('<QQQ', raw, off)
            if size > 0:
                self._mappings.append(_Mapping(vmaddr, size, path, file_off))

        self._load_slide_versions(hdr, path)

    def _load_slide_versions(self, hdr: bytes, path: str) -> None:
        """Record the slide-info version of every slid mapping in this file.

        Headers new enough to carry a ``mappingWithSlide`` array (the array sits
        at/after 0x138, so ``mappingOffset`` is at least 0x140) list one
        ``dyld_cache_mapping_and_slide_info`` per mapping; older headers have a
        single legacy slide-info block at ``slideInfoOffsetUnused``.  Every slide
        info starts with a ``u32 version``.
        """
        if len(hdr) < _HDR_MAPPING_SLIDE_CNT + 4:
            return
        map_off = struct.unpack_from('<I', hdr, _HDR_MAPPING_OFF)[0]
        offsets: List[int] = []
        if map_off >= _HDR_MAPPING_SLIDE_CNT + 4:
            ms_off = struct.unpack_from('<I', hdr, _HDR_MAPPING_SLIDE_OFF)[0]
            ms_cnt = struct.unpack_from('<I', hdr, _HDR_MAPPING_SLIDE_CNT)[0]
            if ms_off and 0 < ms_cnt <= _MAX_MAPPINGS:
                fh = self._fh(path)
                fh.seek(ms_off)
                raw = fh.read(ms_cnt * _MAPPING_SLIDE_STRIDE)
                for i in range(ms_cnt):
                    base = i * _MAPPING_SLIDE_STRIDE + _MAPPING_SLIDE_INFO_OFF
                    if base + 16 > len(raw):
                        break
                    slide_off, slide_size = struct.unpack_from('<QQ', raw, base)
                    if slide_off and slide_size:
                        offsets.append(slide_off)
        else:
            legacy = struct.unpack_from('<Q', hdr, _HDR_SLIDE_OFF_LEGACY)[0]
            if legacy:
                offsets.append(legacy)

        fh = self._fh(path)
        for slide_off in offsets:
            fh.seek(slide_off)
            ver = fh.read(4)
            if len(ver) == 4:
                self._slide_versions.add(struct.unpack('<I', ver)[0])

    @property
    def _runtime_offset_mask(self) -> int:
        """Bit mask extracting the cache-base-relative target from a DATA pointer."""
        if _SLIDE_VERSION_5 in self._slide_versions:
            return _SLIDE5_OFFSET_MASK
        return _DEFAULT_OFFSET_MASK

    def _load_subcaches(self, main_hdr: bytes, main_path: str) -> None:
        """Parse the sub-cache entry array and load each sub-cache's mappings.

        Emits a ``UserWarning`` for every expected sub-cache file that cannot
        be found on disk (missing files silently break selector-name resolution
        for the shared pool).  Pass ``verbose=True`` to the constructor for a
        full diagnostic dump — per-entry paths, existence, mapping counts, a
        hex dump of the raw entry array, and a directory listing — all written
        to ``stderr``.
        """
        if len(main_hdr) < _HDR_SUBCACHE_CNT + 4:
            return
        sub_off = struct.unpack_from('<I', main_hdr, _HDR_SUBCACHE_OFF)[0]
        sub_cnt = struct.unpack_from('<I', main_hdr, _HDR_SUBCACHE_CNT)[0]

        if sub_cnt == 0 or sub_cnt > _MAX_SUBCACHES or sub_off == 0:
            if self._verbose:
                print(
                    f"dyld_cache: {main_path!r}  "
                    f"sub_off=0x{sub_off:x} sub_cnt={sub_cnt} "
                    f"→ single-file cache (no sub-caches)",
                    file=sys.stderr,
                )
            return  # single-file cache or field absent

        fh = self._fh(main_path)
        fh.seek(sub_off)
        raw = fh.read(sub_cnt * _SUBCACHE_STRIDE_V2)  # read enough for v2; v1 uses less

        stride = _detect_subcache_stride(raw)
        stride_label = 'v2/56' if stride == _SUBCACHE_STRIDE_V2 else 'v1/24'

        if self._verbose:
            self._dump_subcache_header(main_path, sub_off, sub_cnt,
                                       stride, stride_label, raw)

        missing: List[str] = []

        for i in range(sub_cnt):
            off = i * stride
            if off + stride > len(raw):
                break

            # Layout (v2, 56 bytes): uuid[16], cacheVMOffset u64, fileExtension[32]
            # Layout (v1, 24 bytes): uuid[16], cacheVMOffset u64  (no extension)
            ext_bytes = raw[off + 24 : off + 56] if stride == _SUBCACHE_STRIDE_V2 else b''
            ext = ext_bytes.split(b'\x00')[0].decode('ascii', errors='replace').strip()
            if not ext:
                ext = f'.{i + 1:02d}'   # v1 or empty: synthesise from index

            sub_path = main_path + ext

            if not os.path.exists(sub_path):
                missing.append(sub_path)
                if self._verbose:
                    self._dump_subcache_entry(i, ext, sub_path, '[MISSING]')
                continue

            # Count mappings added by this sub-cache for verbose reporting.
            maps_before = len(self._mappings)
            try:
                sub_hdr = self._read_hdr_bytes(sub_path)
                self._check_magic(sub_hdr, sub_path)
                self._load_mappings(sub_hdr, sub_path)
            except (ValueError, OSError) as exc:
                warnings.warn(f"dyld_cache: skipping {sub_path!r}: {exc}")
                if self._verbose:
                    self._dump_subcache_entry(i, ext, sub_path, f'[ERROR: {exc}]')
                continue

            if self._verbose:
                maps_added = len(self._mappings) - maps_before
                self._dump_subcache_entry(
                    i, ext, sub_path, f'[ok, +{maps_added} mapping(s)]')

        # ── Store missing list for programmatic callers ───────────────────
        self._missing_subcaches = missing

        # ── Warn about missing files ──────────────────────────────────────
        if missing:
            n_miss = len(missing)
            example = missing[0]
            warnings.warn(
                f"dyld_cache: {n_miss}/{sub_cnt} expected sub-cache file(s) "
                f"not found — selector names from the unified pool will not be "
                f"resolved.\n"
                f"  first missing: {example!r}\n"
                f"  Construct DyldCacheReader(..., verbose=True) for full path "
                f"diagnostics.",
                stacklevel=3,
            )

        if self._verbose:
            self._dump_subcache_result(main_path, sub_cnt, missing)

    # ── Verbose sub-cache diagnostics (stderr only; no effect on parsing) ──────

    def _dump_subcache_header(self, main_path: str, sub_off: int, sub_cnt: int,
                              stride: int, stride_label: str, raw: bytes) -> None:
        """Print the sub-cache header fields + a hex dump of the first few raw
        entries (so the per-entry extension field can be inspected directly)."""
        print(f"\ndyld_cache verbose: loading sub-caches for {main_path!r}",
              file=sys.stderr)
        print(
            f"  header fields : sub_off=0x{sub_off:x}  "
            f"sub_cnt={sub_cnt}  stride={stride} ({stride_label})",
            file=sys.stderr,
        )
        dump_bytes = min(4 * stride, len(raw))
        print(
            f"  raw entries   : first {dump_bytes} bytes "
            f"(file offset 0x{sub_off:x}):",
            file=sys.stderr,
        )
        for chunk_start in range(0, dump_bytes, 16):
            chunk = raw[chunk_start:chunk_start + 16]
            hex_part   = ' '.join(f'{b:02x}' for b in chunk)
            ascii_part = ''.join(chr(b) if 0x20 <= b < 0x7f else '.' for b in chunk)
            print(
                f"    {sub_off + chunk_start:08x}  {hex_part:<47}  |{ascii_part}|",
                file=sys.stderr,
            )
        print("  entries:", file=sys.stderr)

    def _dump_subcache_entry(self, i: int, ext: str, sub_path: str,
                             status: str) -> None:
        """Print one sub-cache entry's resolution outcome (status pre-formatted,
        e.g. ``[MISSING]`` / ``[ERROR: …]`` / ``[ok, +N mapping(s)]``)."""
        print(f"    [{i:02d}] ext={ext!r:12s} → {sub_path!r}  {status}",
              file=sys.stderr)

    def _dump_subcache_result(self, main_path: str, sub_cnt: int,
                              missing: List[str]) -> None:
        """Print the load summary and — when files are missing — a directory
        listing to help locate the expected sub-cache files."""
        n_miss = len(missing)
        n_ok   = sub_cnt - n_miss
        print(
            f"\n  result: {n_ok}/{sub_cnt} sub-cache(s) loaded, "
            f"{n_miss} missing, "
            f"{len(self._mappings)} total mapping(s) so far",
            file=sys.stderr,
        )
        if not missing:
            return
        cache_dir  = os.path.dirname(main_path) or '.'
        cache_base = os.path.basename(main_path)
        print(
            f"\n  directory listing of {cache_dir!r} "
            f"(files starting with {cache_base!r}):",
            file=sys.stderr,
        )
        try:
            all_names = sorted(os.listdir(cache_dir))
        except OSError as exc:
            print(f"    (could not list directory: {exc})", file=sys.stderr)
            return
        matches = [f for f in all_names if f.startswith(cache_base)]
        if not matches:
            print(
                f"    (no files start with {cache_base!r}; "
                f"first 20 entries in dir:)",
                file=sys.stderr,
            )
            for fname in all_names[:20]:
                print(f"    {fname}", file=sys.stderr)
            return
        for fname in matches[:60]:
            full = os.path.join(cache_dir, fname)
            try:
                sz = os.path.getsize(full)
                print(f"    {fname}  ({sz:,} bytes)", file=sys.stderr)
            except OSError:
                print(f"    {fname}", file=sys.stderr)
        if len(matches) > 60:
            print(f"    … and {len(matches) - 60} more", file=sys.stderr)

    # ── Public API ───────────────────────────────────────────────────────────

    def read_u64(self, vmaddr: int) -> Optional[int]:
        """
        Return the little-endian uint64 at *vmaddr* in the cache, or ``None``
        if the address is not mapped or fewer than 8 bytes are available.

        Used to follow pointer entries (e.g. selref slots) that are stored as
        8-byte pointer values rather than raw NUL-terminated strings at the
        ``sel_ref_va`` address resolved from a relative method entry.
        """
        mapping = self._find_mapping(vmaddr)
        if mapping is None:
            return None
        if mapping.vmend - vmaddr < 8:
            return None
        file_off = mapping.translate(vmaddr)
        try:
            fh = self._fh(mapping.path)
            fh.seek(file_off)
            raw = fh.read(8)
            if len(raw) < 8:
                return None
            return struct.unpack_from('<Q', raw)[0]
        except OSError:
            return None

    def read_cstring(self, vmaddr: int, max_len: int = _MAX_CSTRING_LEN) -> Optional[str]:
        """
        Return the null-terminated UTF-8 string at *vmaddr* in the cache, or
        ``None`` if the address is not mapped or the string is not decodable.

        Parameters
        ----------
        vmaddr:
            Virtual address in the shared-cache address space.
        max_len:
            Maximum number of bytes to read before giving up on finding the
            null terminator.
        """
        mapping = self._find_mapping(vmaddr)
        if mapping is None:
            return None

        file_off = mapping.translate(vmaddr)
        # Don't read past the end of the mapping or beyond max_len.
        max_read = min(max_len + 1, mapping.vmend - vmaddr)
        if max_read <= 0:
            return None

        try:
            fh = self._fh(mapping.path)
            fh.seek(file_off)
            raw = fh.read(max_read)
        except OSError:
            return None

        nul = raw.find(b'\x00')
        if nul == -1:
            return None   # no null terminator within max_len bytes

        try:
            return raw[:nul].decode('utf-8')
        except UnicodeDecodeError:
            return None

    def has_vmaddr(self, vmaddr: int) -> bool:
        """Return True if *vmaddr* falls within any mapped region."""
        return self._find_mapping(vmaddr) is not None

    def read_raw(self, vmaddr: int, length: int = 16) -> Optional[bytes]:
        """Return up to *length* raw bytes from *vmaddr* in the cache, or None.

        Unlike read_cstring, no null-terminator search or UTF-8 decode is
        done.  Used to inspect the actual bytes at a vmaddr for diagnostics.
        """
        mapping = self._find_mapping(vmaddr)
        if mapping is None:
            return None
        max_read = min(length, mapping.vmend - vmaddr)
        if max_read <= 0:
            return None
        file_off = mapping.translate(vmaddr)
        try:
            fh = self._fh(mapping.path)
            fh.seek(file_off)
            return fh.read(max_read) or None
        except OSError:
            return None

    def vmaddr_to_file_info(self, vmaddr: int) -> 'Optional[tuple]':
        """Return ``(basename, file_offset)`` for *vmaddr*, or ``None``.

        Useful for diagnostics: shows exactly which file and byte offset a
        vmaddr translates to, so the mapping can be verified independently.
        """
        mapping = self._find_mapping(vmaddr)
        if mapping is None:
            return None
        return (os.path.basename(mapping.path), mapping.translate(vmaddr))

    def mapping_count(self) -> int:
        """Total number of mapped regions across all files."""
        return len(self._mappings)

    def missing_subcache_count(self) -> int:
        """Number of sub-cache files listed in the header that were not found.

        Zero means either no sub-caches are expected (single-file cache) or
        all expected sub-caches were loaded successfully.  A non-zero value
        means selector-name resolution will be incomplete for shared selectors
        in those files.
        """
        return len(self._missing_subcaches)

    def relative_selector_base_candidates(self) -> List[int]:
        """Return the vmaddr(s) of the magic ``🤯`` (U+1F92F) anchor selector.

        dyld places this distinctive selector in the cache's uniqued selector
        string pool and records its address as the *base* for preoptimized
        relative method lists: each such method entry's ``nameOffset`` is the
        distance from this base to the selector cstring (NOT a distance from
        the method_t field, which is the non-cache encoding).  Resolving direct
        selector names therefore requires this base.

        A given cache can contain more than one occurrence of the 4-byte UTF-8
        sequence (one canonical anchor in the selector pool plus the odd stray
        copy in unrelated string data), so this returns every standalone
        occurrence and leaves disambiguation to the caller, which calibrates
        against real method-list offsets (see
        ``macho.classlist._resolve_relative_selector_base``).  Scanned once and
        cached — the result is a cache-wide constant.
        """
        cached = getattr(self, '_rel_sel_base_cands', None)
        if cached is not None:
            return cached
        needle = b'\xf0\x9f\xa4\xaf\x00'    # "🤯\0"
        cands: List[int] = []
        seen_paths: Set[str] = set()
        for m in self._mappings:
            # Each cache file is mapped by several _Mapping entries; scan each
            # file's bytes once regardless of how many mappings reference it.
            if m.path in seen_paths:
                continue
            seen_paths.add(m.path)
            try:
                fh = self._fh(m.path)
                fh.seek(0)
                data = fh.read()
            except OSError:
                continue
            start = 0
            while True:
                idx = data.find(needle, start)
                if idx < 0:
                    break
                # Require a standalone string (preceded by a NUL or at the very
                # start of the file region) so we don't match a suffix.
                if idx == 0 or data[idx - 1] == 0:
                    # Map the file offset back to a vmaddr via the mapping that
                    # covers it (the file holds several mappings).
                    for mm in self._mappings:
                        if mm.path == m.path:
                            rel = idx - mm.file_offset
                            if 0 <= rel < (mm.vmend - mm.vmaddr):
                                cands.append(mm.vmaddr + rel)
                                break
                start = idx + 1
        self._rel_sel_base_cands = cands
        return cands

    def new_format_relative_selector_base(self) -> Optional[int]:
        """Return the relative-selector anchor from the NEW, cache-header-
        embedded ObjC optimization header, or ``None`` if this cache doesn't
        carry a (recognizable) one.

        Newer/larger caches moved the ObjC optimization data that used to live
        inside ``libobjc.A.dylib`` (see
        ``macho.classlist._resolve_relative_selector_base_from_libobjc``, the
        legacy per-dylib form) directly into the ``dyld_cache_header`` itself,
        at ``objcOptsOffset``/``objcOptsSize``.  When present, its
        ``relativeMethodSelectorBaseAddressOffset`` field is a distance from
        the cache's own base vmaddr (:attr:`cache_base`) to the anchor — a
        real value dyld wrote at build time, not scanned or estimated.

        The two legacy/NEW forms are mutually exclusive in practice: a cache
        either carries a big-enough ``objcOptsSize`` here (this method) or it
        doesn't and the anchor instead lives in ``libobjc.A.dylib`` (the other
        method) or must be estimated (see
        ``macho.classlist._resolve_relative_selector_base``, which tries both
        in that order before falling back to a byte-scan estimate).
        """
        if (self._mapping_offset_value <= _HDR_OBJC_OPTS_SIZE
                or self._objc_opts_offset == 0
                or self._objc_opts_size < _OBJC_OPT_HEADER_V1_SIZE):
            return None
        header_va = self.cache_base + self._objc_opts_offset
        data = self.read_raw(header_va, _OBJC_OPT_HEADER_REL_SEL_BASE_POS + 8)
        if data is None or len(data) < _OBJC_OPT_HEADER_REL_SEL_BASE_POS + 8:
            return None
        rel_offset = struct.unpack_from(
            '<Q', data, _OBJC_OPT_HEADER_REL_SEL_BASE_POS
        )[0]
        return (self.cache_base + rel_offset) & 0xFFFFFFFFFFFFFFFF

    def missing_subcache_paths(self) -> List[str]:
        """Paths that were expected but absent.

        Returns a list of the computed sub-cache file paths (``main_path +
        extension``) that ``os.path.exists`` returned ``False`` for.  Useful
        for programmatic diagnostics or for surfacing a targeted error message
        to the user.
        """
        return list(self._missing_subcaches)

    def list_images(self) -> List[Tuple[int, str]]:
        """
        Return ``(load_vmaddr, path)`` for every image in the cache.

        Reads the ``dyld_cache_image_text_info`` array from the main cache
        file.  Results are in the same order as the array (broadly, by
        load address).

        Returns an empty list when the main cache file lacks an imagesText
        array (very old cache format).

        Typical use: ``--list-frameworks`` in the CLI; filtering by
        substring; discovering the exact path to pass to
        :meth:`find_image_header`.
        """
        if not self._img_text_off or not self._img_text_cnt:
            return []
        memo = self.__dict__.get('_images_memo')
        if memo is None:
            memo = self._images_memo = list(self._iter_images())
        return list(memo)

    def _iter_images(self):
        """Yield ``(load_vmaddr, path_str)`` for every imagesText entry."""
        fh = self._fh(self._main_path)
        fh.seek(0)
        main_data = fh.read()
        for i in range(min(self._img_text_cnt, _MAX_IMAGES)):
            off = self._img_text_off + i * _IMAGES_TEXT_STRIDE
            if off + _IMAGES_TEXT_STRIDE > len(main_data):
                break
            load_addr = struct.unpack_from('<Q', main_data, off + 16)[0]
            path_off  = struct.unpack_from('<I', main_data, off + 28)[0]
            if path_off >= len(main_data):
                continue
            nul      = main_data.find(b'\x00', path_off)
            img_path = (main_data[path_off:nul] if nul != -1
                        else main_data[path_off:])
            try:
                yield load_addr, img_path.decode('utf-8')
            except UnicodeDecodeError:
                yield load_addr, img_path.decode('latin-1', errors='replace')

    def resolve_image(self, name: str) -> int:
        """
        Resolve a framework/image *name* to its mach_header vmaddr, by IDENTITY.

        Searches ``dyld_cache_image_text_info`` in tiers, stopping at the first
        tier that yields any candidate:

          1. **exact full path** (``img_path == name``) — scripting escape hatch.
          2. **framework principal binary** — ``name`` names the framework iff the
             path is ``.../<name>.framework/<name>`` (or versioned form), so
             ``'GeoServices'`` resolves to itself and not the substring shadow
             ``GeoServicesCore``.
          3. **unique substring** — keeps partial names / dylibs working when
             unambiguous.

        Returns the mach_header vmaddr (also the start of the image's ``__TEXT``
        segment; can be passed directly to :meth:`image_sections`).

        Raises
        ------
        AmbiguousImageError
            *name* matched more than one image at the tier that resolved it
            (the exception carries the colliding paths).
        ImageNotFoundError
            No image matched, or the cache lacks an imagesText array.
        """
        if not self._img_text_off or not self._img_text_cnt:
            raise ImageNotFoundError(name)
        images = list(self._iter_images())   # [(load_addr, path)]

        # Tier 1: exact full path (paths are unique).
        for load_addr, img_path in images:
            if img_path == name:
                return load_addr

        # Tier 2: framework principal-binary identity.
        principal = [(a, p) for a, p in images if _is_framework_principal(p, name)]
        if len(principal) == 1:
            return principal[0][0]
        if len(principal) > 1:
            raise AmbiguousImageError(name, sorted(p for _, p in principal))

        # Tier 3: unique substring.
        sub = [(a, p) for a, p in images if name in p]
        if len(sub) == 1:
            return sub[0][0]
        if len(sub) > 1:
            raise AmbiguousImageError(name, sorted(p for _, p in sub))

        raise ImageNotFoundError(name)

    def find_image_header(self, name: str) -> Optional[int]:
        """
        Return the mach_header vmaddr for the image identified by *name*, or
        ``None`` if it is not found OR is ambiguous.

        Thin wrapper over :meth:`resolve_image` for callers that pass an
        already-unambiguous name and want an ``Optional[int]`` rather than
        typed exceptions.  Unlike the old substring-first-wins behaviour, an
        ambiguous *name* now returns ``None`` instead of silently picking the
        first array entry — use :meth:`resolve_image` to surface the collision.
        """
        try:
            return self.resolve_image(name)
        except ImageResolutionError:
            return None

    @property
    def cache_base(self) -> int:
        """Unslid base vmaddr of the cache (lowest mapping address).

        Equals the value the per-image local-symbols ``dylibOffset`` is
        measured against (``mach_header_va − cache_base``).
        """
        return self._vmaddr_keys[0] if self._vmaddr_keys else 0

    def image_local_symbols(self, mach_header_va: int):
        """Recover ObjC method names for one image from the ``.symbols`` file.

        Returns an :class:`~macho.local_symbols.ImageLocalSymbols` with
        IMP→selector and class→selectors maps, or ``None`` when no ``.symbols``
        sibling exists or the image has no parseable local symbols.

        The ``.symbols`` sub-cache carries the original ``-[Class selector]``
        local symbols that the preoptimised method lists drop; combined with
        the reliable ``impOffset`` field this yields authoritative selector
        names.  See :mod:`macho.local_symbols`.
        """
        sym_path = symbols_path_for(self._main_path)
        if sym_path is None:
            return None
        return load_image_local_symbols(
            sym_path, self.cache_base, mach_header_va
        )

    def image_symbol_addrs(self, mach_header_va: int, *substrs):
        """Raw ``symbol name → vmaddr`` for one image's ``.symbols`` local
        symbols, optionally pre-filtered to names containing any of *substrs*.

        This is the cache-mode counterpart to an in-binary ``LC_SYMTAB``: the
        swift-protobuf extractor uses it to find each type's ``_protobuf_nameMap``
        static-init / ``decodeMessage`` symbols, which a cache image keeps here
        rather than in its own (shared-LINKEDIT) symbol table.  Returns ``{}``
        when no ``.symbols`` sibling exists or the image has no local symbols.
        """
        sym_path = symbols_path_for(self._main_path)
        if sym_path is None:
            return {}
        return load_image_symbol_addrs(
            sym_path, self.cache_base, mach_header_va, list(substrs) or None
        )

    def image_sections(
        self, mach_header_va: int
    ) -> Dict[str, Tuple[int, int]]:
        """
        Parse the Mach-O load commands at *mach_header_va* and return section
        and segment bounds.

        Returns a dict of exclusive ``(vm_start, vm_end)`` ranges keyed by:

        * ``"<segname>"`` — segment bound, e.g. ``"__TEXT"``.
        * ``"<segname>/<sectname>"`` — section bound,
          e.g. ``"__TEXT/__objc_methname"``.

        Sections with ``vmaddr == 0`` or ``vmsize == 0`` are excluded (those
        are zero-fill / padding entries that hold no binary content).

        Returns an empty dict if *mach_header_va* is not mapped, does not
        start with the 64-bit Mach-O magic (``0xFEEDFACF``), or has
        obviously malformed load commands.

        All returned vmaddrs are absolute cache virtual addresses and can be
        passed to :meth:`read_raw`, :meth:`read_cstring`, etc.

        Notes
        -----
        Obtain *mach_header_va* from :meth:`find_image_header` for a named
        framework, or supply an address found via another mechanism.
        """
        result: Dict[str, Tuple[int, int]] = {}
        for cmd, body in self._image_load_commands(mach_header_va):
            if cmd == LC_SEGMENT_64:
                result.update(_parse_segment64_lc(body, 0))
        return result

    def _image_load_commands(self, mach_header_va: int) -> List[Tuple[int, bytes]]:
        """``[(cmd, command bytes)]`` of the image at *mach_header_va*; ``[]`` if unreadable."""
        hdr = self.read_raw(mach_header_va, 32)
        if not hdr or len(hdr) < 32 or struct.unpack_from('<I', hdr, 0)[0] != _MH_MAGIC_64:
            return []
        ncmds, sizeofcmds = struct.unpack_from('<II', hdr, 16)
        if ncmds == 0 or sizeofcmds < 8 or sizeofcmds > _MAX_SIZEOFCMDS:
            return []
        lc = self.read_raw(mach_header_va + 32, sizeofcmds)
        if not lc:
            return []
        out, pos = [], 0
        for _ in range(ncmds):
            if pos + 8 > len(lc):
                break
            cmd, cmdsize = struct.unpack_from('<II', lc, pos)
            if cmdsize < 8:
                break
            out.append((cmd, lc[pos:pos + cmdsize]))
            pos += cmdsize
        return out

    def image_exports(self, mach_header_va: int) -> Dict[str, int]:
        """``{exported symbol name: vmaddr}`` for the image at *mach_header_va*, from its dyld
        export trie (``LC_DYLD_EXPORTS_TRIE``, else the export range of ``LC_DYLD_INFO``).

        In the cache the trie lives in the shared ``__LINKEDIT``; the load command gives its
        file offset, which maps to a vmaddr through the image's own ``__LINKEDIT`` segment
        (``vmaddr + (offset - fileoff)``).  Names keep their leading underscore
        (``_objc_retain_x2``).  Re-exports are omitted (they name another image's symbol).
        Memoised per image; ``{}`` when the image has no readable trie."""
        memo = self.__dict__.setdefault('_image_exports_memo', {})
        if mach_header_va in memo:
            return memo[mach_header_va]
        from .export_trie import decode_export_trie
        linkedit = trie = None
        for cmd, body in self._image_load_commands(mach_header_va):
            if cmd == LC_SEGMENT_64 and len(body) >= 56 \
                    and body[8:24].rstrip(b'\x00') == b'__LINKEDIT':
                vmaddr, _vmsize, fileoff = struct.unpack_from('<QQQ', body, 24)
                linkedit = (vmaddr, fileoff)
            elif cmd == LC_DYLD_EXPORTS_TRIE and len(body) >= 16:
                trie = struct.unpack_from('<II', body, 8)
            elif cmd in (LC_DYLD_INFO, LC_DYLD_INFO_ONLY) and len(body) >= 48 and trie is None:
                trie = struct.unpack_from('<II', body, 40)
        out: Dict[str, int] = {}
        if linkedit is not None and trie is not None and trie[1]:
            data = self.read_raw(linkedit[0] + (trie[0] - linkedit[1]), trie[1])
            if data:
                out = {name: mach_header_va + off
                       for name, (_flags, off) in decode_export_trie(data).items()}
        memo[mach_header_va] = out
        return out

    def export_name_at(self, vmaddr: int) -> Optional[str]:
        """Name of the symbol some cache image exports at *vmaddr*, or None.

        The image is the one whose ``__TEXT`` segment holds *vmaddr*; its exports are read
        once (:meth:`image_exports`).  Lets a caller name a direct call into another image
        (``bl`` to libobjc's ``objc_retain_x2``), which the cache links without stubs."""
        hit = self._segment_at(vmaddr, '__TEXT')
        if hit is None:
            return None
        names = self.__dict__.setdefault('_export_names_by_addr', {})
        mh = hit[2]
        if mh not in names:
            by_addr: Dict[int, str] = {}
            for name, va in sorted(self.image_exports(mh).items()):
                by_addr.setdefault(va, name)     # aliases (objc_retain = objc_retain_x0): first
            names[mh] = by_addr
        return names[mh].get(vmaddr)

    def image_containing(self, vmaddr: int) -> Optional[Tuple[int, str]]:
        """``(mach_header vmaddr, path)`` of the cache image one of whose segments holds
        *vmaddr*, or None.  Images' segments do not overlap, so the answer is a fact about
        the address, not a choice: following a pointer the cache builder bound (a class
        reference to another image's ``class_t``) and asking this names the image that
        defines the target.  The segment table is built once, on first use."""
        hit = self._segment_at(vmaddr)
        return None if hit is None else (hit[2], hit[3])

    def _segment_at(self, vmaddr: int, segname: Optional[str] = None
                    ) -> Optional[Tuple[int, int, int, str, str]]:
        """``(start, end, mach_header vmaddr, path, segment name)`` of the image segment holding
        *vmaddr* (only segments named *segname*, when given), or None.  One table of every
        image's segments, built on first use (images' segments do not overlap)."""
        tables = self.__dict__.setdefault('_segment_tables', {})
        if segname not in tables:
            segs = []
            for mh, path in self.list_images():
                for key, (start, end) in self.image_sections(mh).items():
                    if '/' not in key and (segname is None or key == segname):
                        segs.append((start, end, mh, path, key))
            segs.sort()
            tables[segname] = (segs, [r[0] for r in segs])
        segs, starts = tables[segname]
        i = bisect.bisect_right(starts, vmaddr) - 1
        if i < 0 or not segs[i][0] <= vmaddr < segs[i][1]:
            return None
        return segs[i]

    def image_dependencies(self, mach_header_va: int) -> List[str]:
        """Install names of the dylibs the image at *mach_header_va* links
        (``LC_LOAD_DYLIB`` / ``_WEAK_`` / ``_REEXPORT_`` / ``_UPWARD_``), in load-command
        order; ``[]`` if its load commands are unreadable."""
        out: List[str] = []
        for cmd, data in self._image_load_commands(mach_header_va):
            if cmd not in _LC_LINKED_DYLIBS or len(data) < 12:
                continue
            name_off = struct.unpack_from('<I', data, 8)[0]
            if name_off >= len(data):
                continue
            name = data[name_off:].split(b'\x00', 1)[0]
            if name:
                out.append(name.decode('utf-8', errors='replace'))
        return out

    def decode_ptr(self, raw: int) -> int:
        """
        Decode a raw DATA-section pointer value from this cache to an absolute vmaddr.

        Cache DATA sections use an internal encoding even when
        ``builtFromChainedFixups=0``: the low bits hold the actual target;
        upper bits carry chain-link / PAC-authentication metadata for the
        boot-time ASLR slide walk.  Two on-disk encodings are known:

        * **plain-arm64 caches** (e.g. the iOS non-e cache this tool was
          originally built against): the low 36 bits of the raw value already
          equal the absolute target vmaddr — no addition needed, because the
          cache's own base fits within those 36 bits.
        * **arm64e caches** (iOS arm64e devices and every Apple Silicon macOS
          system cache): DATA pointers are ``dyld_chained_ptr_arm64e``-style
          entries — both the plain-rebase and *authenticated*-rebase forms
          (auth bit at 63) — where the low 32 bits are an **offset from
          :attr:`cache_base`**, not an absolute address.  Verified empirically
          against a live macOS ``dyld_shared_cache_arm64e`` (GeoServices class_t
          isa/superclass/data fields all decode correctly this way regardless
          of the auth bit).

        Three strategies are tried in order, stopping at the first that lands
        on a mapped address:

        1. **Direct vmaddr** — the raw value itself is already mapped (common
           for pointer values that happen to carry no metadata bits).
        2. **Low-36-bit truncation** — the plain-arm64-cache encoding.
        3. **Low-32-bit offset from cache_base** — the arm64e encoding; widened to
           the low 34 bits for slide-info v5 caches (iOS 26+/macOS 26+), which
           exceed 4 GB (see ``_SLIDE5_OFFSET_MASK``).

        Returns ``0`` if no strategy resolves to a mapped address (this also
        covers bind entries, which are not pointers into this cache at all).
        """
        if not raw:
            return 0
        if self.has_vmaddr(raw):
            return raw
        if raw > 0xFFFFFFFFF:
            low36 = raw & 0xFFFFFFFFF
            if low36 and self.has_vmaddr(low36):
                return low36
        target_off = raw & self._runtime_offset_mask
        if target_off:
            candidate = self.cache_base + target_off
            if self.has_vmaddr(candidate):
                return candidate
        return 0

    def close(self) -> None:
        """Close all open file handles."""
        for fh in self._fhs.values():
            try:
                fh.close()
            except OSError:
                pass
        self._fhs.clear()

    def __enter__(self) -> 'DyldCacheReader':
        return self

    def __exit__(self, *_) -> None:
        self.close()

    # ── Internal helpers ─────────────────────────────────────────────────────

    def _find_mapping(self, vmaddr: int) -> Optional[_Mapping]:
        """
        Binary-search the sorted mapping list for the entry that contains
        *vmaddr*.  Returns ``None`` if no mapping covers the address.
        """
        if not self._mappings:
            return None
        idx = bisect.bisect_right(self._vmaddr_keys, vmaddr) - 1
        if idx >= 0 and self._mappings[idx].vmaddr <= vmaddr < self._mappings[idx].vmend:
            return self._mappings[idx]
        return None
