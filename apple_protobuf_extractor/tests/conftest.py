"""
tests/conftest.py — Shared helpers for macho/* test suites.

Binary builders
---------------
build_binary(segments)            Minimal arm64 Mach-O from segment specs.
build_text_binary(code, vmaddr)   Single __TEXT/__text binary.
build_two_segment_binary(...)     __TEXT + __DATA binary.
build_objc_binary(class_specs)    Binary with __objc_classlist / classnames.

Low-level packers (used by manual builders in test_classlist, test_strings)
---------------------------------------------------------------------------
_pack_header(ncmds, sizeofcmds, filetype)
_pack_segment64(segname, *, vmaddr, vmsize, fileoff, filesize, sections)
_pack_section64(sectname, segname, vmaddr, vmsize, fileoff, flags)

Aliases for test_memory compatibility
--------------------------------------
macho_header  = _pack_header
lc_segment64  = _pack_segment64
_FILE_BASE     = 32 + 72 + 80   (header + one segment LC + one section header)

arm64 instruction encoders
---------------------------
encode_adrp(rd, pages_delta)      → 4 bytes
encode_add_imm64(rd, rn, imm)     → 4 bytes  (imm < 4096)
encode_ldr_imm64(rd, rn, offset)  → 4 bytes  (offset must be 8-byte aligned)
encode_movz(rd, imm16, hw)        → 4 bytes
encode_bl(offset_bytes)           → 4 bytes

Byte literals
--------------
NOP_BYTES   = b'\\x1f\\x20\\x03\\xd5'
RET_BYTES   = b'\\xc0\\x03\\x5f\\xd6'

Helper
-------
ptr64(vmaddr)  → struct.pack('<Q', vmaddr)
"""

from __future__ import annotations

import os
import struct
from typing import List, Optional


# ─── Live-test loudness guardrail ─────────────────────────────────────────────
#
# Why this exists: ~100 live tests in this package gate on the gitignored
# ``iphone8_data/`` dump (dyld cache + device binaries, ~20 GB, 0 files tracked
# by git).  On this dev machine they all run; on a fresh clone / CI / teammate
# machine without the private dump they all skip SILENTLY and the suite still
# reports a green "N passed".  A real production bug once hid for the life of the
# project because a single live test had been silently skipping (stale hardcoded
# path).  This guardrail makes that impossible to miss again — see
# ``notes/silent_skips_audit_2026-07-24.md`` for the full analysis and spec.
#
# Two modes:
#   • Default (no env flag):  if any test skipped, print a loud terminal banner
#     so a green run visibly announces that coverage was only partial.
#   • Strict (MACHO_REQUIRE_LIVE=1):  if any test on the sentinel allowlist below
#     reports skipped, force the whole pytest run to exit NON-ZERO.  For the dev
#     machine that has the corpus and for any CI with the dump mounted.
#
# SENTINEL ALLOWLIST — a short, explicit set of live tests that MUST run for the
# suite to mean anything.  Each entry is a node-id *substring*: matching on a
# substring means renaming the surrounding directory/path cannot silently disarm
# the check, while the class::method tail keeps it specific.  Verified present
# and passing on the dev dump on 2026-07-24 (see audit).  Keep this list SHORT
# and edit it deliberately.
#
#   • TestLiveRemindd::test_nested_type_message  — the swift-protobuf live test
#     class that stands in for the one that masked the original real bug.
#   • TestLiveDPSubmission                        — shape-D corpus restored by
#     commit 3aef94d (whole class; every method is a live sentinel).
#   • TestFieldZeroFlagLive                       — sole coverage of the field-0
#     quirk (test_field_zero.py), single-artifact-gated on NewsTransport.
#   • TestClassNamesLive::test_iter_class_names_finds_place_request — a dyld
#     cache-backed sentinel (test_cache_classlist.py).
_LIVE_SENTINELS = (
    "test_swift_descriptor_extract.py::TestLiveRemindd::test_nested_type_message",
    "test_swift_descriptor_extract.py::TestLiveDPSubmission",
    "test_field_zero.py::TestFieldZeroFlagLive",
    "test_cache_classlist.py::TestClassNamesLive::test_iter_class_names_finds_place_request",
)

# Node-ids of tests that reported skipped this session (populated during the run).
_skipped_nodeids: list[str] = []


def _strict_mode() -> bool:
    """True when MACHO_REQUIRE_LIVE requests strict sentinel enforcement."""
    return os.environ.get("MACHO_REQUIRE_LIVE", "").strip() not in ("", "0", "false", "no")


def _sentinel_skips() -> list[str]:
    """Skipped node-ids that match (by substring) an entry on the allowlist."""
    hits = []
    for nid in _skipped_nodeids:
        if any(sentinel in nid for sentinel in _LIVE_SENTINELS):
            hits.append(nid)
    return sorted(set(hits))


def pytest_runtest_logreport(report):
    """Record every skipped test's node-id (setup- or call-phase skips both).

    xfail results also surface as ``report.skipped``; exclude them via the
    ``wasxfail`` marker so they never count as coverage gaps.
    """
    if report.skipped and not hasattr(report, "wasxfail"):
        _skipped_nodeids.append(report.nodeid)


def pytest_terminal_summary(terminalreporter, exitstatus, config):
    """Print the loud banner (default mode) or the strict-violation report."""
    n_skipped = len(set(_skipped_nodeids))
    if n_skipped == 0:
        return

    tr = terminalreporter
    if _strict_mode():
        offenders = _sentinel_skips()
        if offenders:
            tr.write_sep("=", "MACHO_REQUIRE_LIVE: SENTINEL LIVE TEST(S) SKIPPED", red=True, bold=True)
            tr.write_line(
                "Strict mode requires these live sentinels to RUN, but they skipped "
                "(corpus absent or artifact missing):",
                red=True,
            )
            for nid in offenders:
                tr.write_line(f"    - {nid}", red=True)
            tr.write_line(
                "The run is being FAILED (exit non-zero). Provide the iphone8_data/ "
                "dump, or unset MACHO_REQUIRE_LIVE to allow a partial run.",
                red=True,
            )
            tr.write_sep("=", "", red=True, bold=True)
            return
    # Default (non-strict) mode, or strict mode with no sentinel skips: still make
    # any partial coverage impossible to overlook.
    tr.write_sep("!", "PARTIAL COVERAGE", yellow=True, bold=True)
    tr.write_line(
        f"WARNING: {n_skipped} test(s) skipped — this run did NOT fully exercise the "
        "live extraction layer (device corpus likely absent).",
        yellow=True,
    )
    tr.write_line(
        "A green result here does NOT mean the extractor was tested against real "
        "binaries. Set MACHO_REQUIRE_LIVE=1 with the iphone8_data/ dump present to "
        "enforce the live sentinels.",
        yellow=True,
    )
    tr.write_sep("!", "", yellow=True, bold=True)


def pytest_sessionfinish(session, exitstatus):
    """Force a non-zero process exit when a strict-mode sentinel skipped.

    Setting ``session.exitstatus`` is the supported mechanism for a plugin to
    change pytest's process return code; printing alone would not fail CI.
    """
    if _strict_mode() and _sentinel_skips():
        import pytest
        session.exitstatus = pytest.ExitCode.TESTS_FAILED

# ─── Constants ────────────────────────────────────────────────────────────────

MH_MAGIC_64   = 0xFEEDFACF
CPU_ARM64      = 0x0100000C   # same as macho.memory.CPU_TYPE_ARM64
CPU_SUBTYPE_0  = 0x00000000
MH_EXECUTE    = 0x2
MH_DYLIB      = 0x6
LC_SEGMENT_64 = 0x19

NOP_BYTES = struct.pack('<I', 0xD503201F)   # NOP
RET_BYTES = struct.pack('<I', 0xD65F03C0)   # RET

# File offset where data starts in a build_text_binary() output.
# One __TEXT segment (72 bytes) + one __text section (80 bytes).
_FILE_BASE = 32 + 72 + 80   # = 184


# ─── Helper ───────────────────────────────────────────────────────────────────

class WordCtx:
    """Minimal BinaryContext stand-in serving fixed 4-byte words by address.
    Shared synthetic fixture for the dispatch / enum decoder unit tests.

    ``read_bytes`` also serves multi-word contiguous reads (any length that is
    a multiple of 4, by concatenating consecutive words), which is what
    :func:`macho.disasm.disasm` needs to disassemble more than one instruction
    at a time — it is not restricted to the raw-word decoders' plain
    ``read_bytes(va, 4)`` calls.  A read still fails with ``ValueError`` if any
    4-byte word in the requested range is missing, exactly as a real
    unmapped-memory read would.

    Extra words at addresses outside the ``base``-relative code region (e.g. a
    jump table's own data, placed at an unrelated address) can be added after
    construction via ``ctx._m[addr] = word``.

    ``is_cache_backed = True`` routes :func:`macho.disasm.disasm`'s address
    validation through ``read_bytes`` (which this stand-in supports) instead
    of ``vmaddr_to_offset`` (a real segment-table lookup this stand-in has no
    reason to implement)."""

    is_cache_backed = True

    def __init__(self, base, words):
        self._m = {base + i * 4: w for i, w in enumerate(words)}
        self._text = (base, 4 * len(words))

    # The image the words stand for: they are its ``__TEXT,__text``, with no function index,
    # so a function there runs to the end of the code (proto.function_body.function_end).
    def function_starts(self):
        return []

    def has_section(self, segname, sectname):
        """Only ``__TEXT,__text``: no ``__cfstring``, which routes read_cfstring_text's
        cfstring/direct-C-string dispatch to the direct-pointer branch unconditionally."""
        return (segname, sectname) == ('__TEXT', '__text')

    def section(self, segname, sectname):
        from types import SimpleNamespace
        return SimpleNamespace(vmaddr=self._text[0], vmsize=self._text[1])

    def read_bytes(self, va, length):
        if length <= 0 or length % 4 != 0:
            raise ValueError(f"unsupported read length {length} at {va:#x}")
        out = bytearray()
        for i in range(length // 4):
            addr = va + i * 4
            if addr not in self._m:
                raise ValueError(f"no data at {addr:#x}")
            out += struct.pack('<I', self._m[addr])
        return bytes(out)

    def read_s32(self, va):
        """Signed 32-bit read — used by the ivar-offset-table lookup idiom
        (the table entry IS the ivar's byte offset, stored as data, not an
        instruction immediate)."""
        return struct.unpack('<i', self.read_bytes(va, 4))[0]

    def read_cstring(self, va, max_len=4096):
        """Look up a plain Python string previously registered at *va* via
        ``ctx._strings[addr] = "text"`` (mirrors ``ctx._m[addr] = word`` for
        code/data words above)."""
        s = getattr(self, '_strings', None)
        if s is not None and va in s:
            return s[va]
        raise ValueError(f"no string at {va:#x}")

    def is_variable(self, vmaddr):        # no program data, no binds
        return False

    def read_ptr(self, va):
        """64-bit pointer read from two consecutive words (low word first),
        raising ValueError if either is missing — like an unmapped read.  Data
        is placed with ``ctx._m[va] = lo; ctx._m[va + 4] = hi`` (see the
        ``put_ptr`` helper below)."""
        return struct.unpack('<Q', self.read_bytes(va, 8))[0]

    def bind_name_for(self, vmaddr):
        """Look up a class name previously registered at *vmaddr* via
        ``ctx._binds[addr] = "GEOSomeClass"`` — the classref-slot-to-class-name
        resolution :func:`proto.dispatch._scan_arm_for_core_or_classref` calls
        directly, without needing a real class_ro_t structure behind it."""
        return (getattr(self, '_binds', None) or {}).get(vmaddr)


def put_ptr(ctx, va, value):
    """Store a 64-bit *value* at *va* in a :class:`WordCtx`'s word map, for
    :meth:`WordCtx.read_ptr`."""
    ctx._m[va] = value & 0xFFFFFFFF
    ctx._m[va + 4] = value >> 32


def ptr64(vmaddr: int) -> bytes:
    """Pack *vmaddr* as a little-endian 64-bit pointer."""
    return struct.pack('<Q', vmaddr)


# ─── Low-level packers ────────────────────────────────────────────────────────

def _pack_header(
    ncmds: int,
    sizeofcmds: int,
    filetype: int = MH_EXECUTE,
) -> bytes:
    """Pack a 64-bit Mach-O header (32 bytes)."""
    return struct.pack(
        '<IIIIIIII',
        MH_MAGIC_64,      # magic
        CPU_ARM64,        # cputype
        CPU_SUBTYPE_0,    # cpusubtype
        filetype,         # filetype
        ncmds,            # ncmds
        sizeofcmds,       # sizeofcmds
        0,                # flags
        0,                # reserved
    )


def _pack_section64(
    sectname: str,
    segname:  str,
    vmaddr:   int,
    vmsize:   int,
    fileoff:  int,
    flags:    int = 0,
) -> bytes:
    """
    Pack a section_64 struct (80 bytes).

    section_64 layout (arm64):
      char sectname[16], char segname[16],
      uint64 addr, uint64 size,
      uint32 offset, uint32 align, uint32 reloff, uint32 nreloc,
      uint32 flags, uint32 reserved1, uint32 reserved2, uint32 reserved3
    """
    sn = sectname.encode('ascii')[:16].ljust(16, b'\x00')
    sg = segname.encode('ascii')[:16].ljust(16, b'\x00')
    body = struct.pack(
        '<QQIIIIIIII',
        vmaddr, vmsize,
        fileoff,   # offset
        0,         # align (log2)
        0,         # reloff
        0,         # nreloc
        flags,     # flags
        0,         # reserved1
        0,         # reserved2
        0,         # reserved3
    )
    return sn + sg + body   # 16 + 16 + 48 = 80 bytes


def _pack_segment64(
    segname:  str,
    *,
    vmaddr:   int,
    vmsize:   int,
    fileoff:  int,
    filesize: int,
    sections: Optional[List[bytes]] = None,
) -> bytes:
    """
    Pack an LC_SEGMENT_64 command (72 + 80*nsects bytes).

    *sections* is a list of pre-packed section_64 structs returned by
    _pack_section64().
    """
    if sections is None:
        sections = []
    sections_data = b''.join(sections)
    nsects   = len(sections)
    cmdsize  = 72 + len(sections_data)

    seg_name_bytes = segname.encode('ascii')[:16].ljust(16, b'\x00')
    header = struct.pack('<II', LC_SEGMENT_64, cmdsize) + seg_name_bytes
    # vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, flags
    header += struct.pack('<QQQQIIII', vmaddr, vmsize, fileoff, filesize,
                          7, 5, nsects, 0)
    return header + sections_data


# Aliases used by test_memory.py
macho_header = _pack_header
lc_segment64  = _pack_segment64


# ─── High-level builders ──────────────────────────────────────────────────────

def build_binary(segments: list) -> bytes:
    """
    Build a minimal arm64 Mach-O binary from a list of segment specs.

    Segment spec dict keys
    ----------------------
    name     : str               Segment name, e.g. '__TEXT'
    vmaddr   : int               Base vmaddr for this segment
    vmsize   : int               (optional) Override vmsize; defaults to content size
    sections : list[dict]        List of section specs:
        name    : str            Section name, e.g. '__text'
        content : bytes          Section data
        vmaddr  : int (opt)      Section vmaddr; defaults to seg vmaddr + running offset
        flags   : int (opt)      Section flags (default 0)
    """
    HDR_SIZE = 32
    n_segs   = len(segments)
    n_sects  = sum(len(seg.get('sections', [])) for seg in segments)
    lc_total = n_segs * 72 + n_sects * 80
    data_off = HDR_SIZE + lc_total

    all_lcs  = b''
    all_data = b''

    for seg_spec in segments:
        seg_name     = seg_spec['name']
        seg_vmaddr   = seg_spec.get('vmaddr', 0x1000)
        seg_content  = b''
        section_lcs  = []

        for sect_spec in seg_spec.get('sections', []):
            content     = sect_spec.get('content', b'')
            sect_name   = sect_spec.get('name', '__text')
            sect_vmaddr = sect_spec.get('vmaddr', seg_vmaddr + len(seg_content))
            sect_flags  = sect_spec.get('flags', 0)
            sect_fileoff = data_off + len(all_data) + len(seg_content)

            sect_lc = _pack_section64(
                sect_name, seg_name, sect_vmaddr,
                len(content), sect_fileoff, sect_flags,
            )
            section_lcs.append(sect_lc)
            seg_content += content

        seg_vmsize   = seg_spec.get('vmsize', len(seg_content))
        seg_fileoff  = data_off + len(all_data)
        seg_lc = _pack_segment64(
            seg_name,
            vmaddr=seg_vmaddr, vmsize=seg_vmsize,
            fileoff=seg_fileoff, filesize=len(seg_content),
            sections=section_lcs,
        )
        all_lcs  += seg_lc
        all_data += seg_content

    hdr = _pack_header(ncmds=n_segs, sizeofcmds=len(all_lcs))
    return hdr + all_lcs + all_data


def build_text_binary(
    code:    bytes,
    vmaddr:  int = 0x4000,
) -> bytes:
    """Build a single-segment __TEXT/__text binary containing *code*."""
    HDR      = 32
    LC_SIZE  = 72 + 80
    DATA_OFF = HDR + LC_SIZE

    sect = _pack_section64('__text', '__TEXT', vmaddr, len(code), DATA_OFF)
    seg  = _pack_segment64(
        '__TEXT',
        vmaddr=vmaddr, vmsize=len(code),
        fileoff=DATA_OFF, filesize=len(code),
        sections=[sect],
    )
    hdr = _pack_header(ncmds=1, sizeofcmds=len(seg))
    return hdr + seg + code


def build_objc_binary(
    class_specs: list,
    classlist_segment: str = '__DATA_CONST',
) -> bytes:
    """
    Build a minimal Mach-O with __objc_classlist and classname strings.

    class_specs: list of dicts with keys:
        name      : str   Class name
        superclass: str   Superclass name (optional, default None → root)
        methods   : list  Not encoded (stub implementation)
        ivars     : list  Not encoded (stub implementation)

    Returns a bytes object suitable for BinaryContext().
    """
    # Layout per class:
    #   class_ro_t (72 bytes) + class_t (40 bytes)
    # Class names in __TEXT:__objc_classname
    # Classlist (8*n bytes) in classlist_segment:__objc_classlist

    CLASS_T_SIZE  = 40
    CLASS_RO_SIZE = 72

    TEXT_VA = 0x1000_0000
    DATA_VA = 0x2000_0000

    # Build classname section content
    classnames_bytes = b''
    name_offsets: dict[str, int] = {}
    for spec in class_specs:
        name_offsets[spec['name']] = len(classnames_bytes)
        classnames_bytes += spec['name'].encode('ascii') + b'\x00'

    # Pad to 8 bytes
    if len(classnames_bytes) % 8:
        classnames_bytes += b'\x00' * (8 - len(classnames_bytes) % 8)

    # Build class structs
    struct_block    = b''
    class_vmaddrs   = []

    for spec in class_specs:
        name_va   = TEXT_VA + name_offsets[spec['name']]
        ro_va     = DATA_VA + len(struct_block)
        class_va  = ro_va + CLASS_RO_SIZE

        # class_ro_t (72 bytes): flags(u32), instStart(u32), instSize(u32),
        #   reserved(u32), ivarLayout(u64), name(u64), baseMethods(u64),
        #   baseProtocols(u64), ivars(u64), weakIvarLayout(u64),
        #   baseProperties(u64)
        ro = struct.pack('<IIII', 0, 0, 8, 0)  # flags, instStart, instSize, reserved
        ro += struct.pack('<QQQQQQQ',
                          0,       # ivarLayout
                          name_va, # name
                          0,       # baseMethods
                          0,       # baseProtocols
                          0,       # ivars
                          0,       # weakIvarLayout
                          0,       # baseProperties
                          )
        assert len(ro) == CLASS_RO_SIZE

        # class_t (40 bytes): isa, superclass, cache, vtable, data
        class_t = struct.pack('<QQQQQ',
                              0,      # isa
                              0,      # superclass (external → 0)
                              0,      # cache
                              0,      # vtable
                              ro_va,  # data → class_ro_t
                              )
        assert len(class_t) == CLASS_T_SIZE

        struct_block += ro + class_t
        class_vmaddrs.append(class_va)

    # Classlist: one pointer per class
    classlist_data = b''.join(ptr64(va) for va in class_vmaddrs)

    # ── Build binary ──────────────────────────────────────────────────────
    HDR     = 32
    n_segs  = 2
    n_sects = 2
    LC_SZ   = n_segs * 72 + n_sects * 80
    data_off = HDR + LC_SZ

    text_data = classnames_bytes
    data_block = struct_block + classlist_data

    classlist_va = DATA_VA + len(struct_block)

    s1 = _pack_section64('__objc_classname', '__TEXT',
                         TEXT_VA, len(text_data), data_off)
    sg1 = _pack_segment64('__TEXT',
                          vmaddr=TEXT_VA, vmsize=len(text_data),
                          fileoff=data_off, filesize=len(text_data),
                          sections=[s1])

    s2 = _pack_section64('__objc_classlist', classlist_segment,
                         classlist_va, len(classlist_data),
                         data_off + len(text_data) + len(struct_block))
    sg2 = _pack_segment64(classlist_segment,
                          vmaddr=DATA_VA, vmsize=len(data_block),
                          fileoff=data_off + len(text_data), filesize=len(data_block),
                          sections=[s2])

    hdr = _pack_header(ncmds=2, sizeofcmds=len(sg1) + len(sg2))
    return hdr + sg1 + sg2 + text_data + data_block


# ─── arm64 instruction encoders ───────────────────────────────────────────────

def encode_adrp(rd: int, pages_delta: int) -> bytes:
    """
    Encode ADRP x{rd}, #(current_page + pages_delta * 0x1000).

    The instruction is PC-relative: page = (PC & ~0xFFF) + pages_delta << 12.
    pages_delta is treated as a signed 21-bit value.
    """
    imm21 = pages_delta & 0x1FFFFF   # mask to 21 bits (handles negative)
    immlo = imm21 & 0x3
    immhi = (imm21 >> 2) & 0x7FFFF
    word  = 0x90000000 | (immlo << 29) | (immhi << 5) | (rd & 0x1F)
    return struct.pack('<I', word)


def encode_add_imm64(rd: int, rn: int, imm: int) -> bytes:
    """
    Encode ADD x{rd}, x{rn}, #imm  (64-bit immediate, imm < 4096, shift=0).
    """
    if not (0 <= imm < 4096):
        raise ValueError(f"imm {imm:#x} out of range for shift=0 ADD immediate")
    word = 0x91000000 | (imm << 10) | ((rn & 0x1F) << 5) | (rd & 0x1F)
    return struct.pack('<I', word)


def encode_ldr_imm64(rd: int, rn: int, offset: int) -> bytes:
    """
    Encode LDR x{rd}, [x{rn}, #offset]  (64-bit unsigned-offset).
    offset must be a multiple of 8 and in [0, 32760].
    """
    if offset % 8 != 0 or not (0 <= offset <= 32760):
        raise ValueError(f"offset {offset:#x} invalid for LDR 64-bit unsigned-offset")
    imm12 = offset // 8
    word  = 0xF9400000 | (imm12 << 10) | ((rn & 0x1F) << 5) | (rd & 0x1F)
    return struct.pack('<I', word)


def encode_movz(rd: int, imm16: int, hw: int = 0) -> bytes:
    """Encode MOVZ x{rd}, #imm16 [, LSL #{hw*16}]  (64-bit)."""
    word = 0xD2800000 | ((hw & 0x3) << 21) | ((imm16 & 0xFFFF) << 5) | (rd & 0x1F)
    return struct.pack('<I', word)


def encode_bl(offset_bytes: int) -> bytes:
    """
    Encode BL #(PC + offset_bytes).
    *offset_bytes* is a signed byte offset from the instruction's own PC.
    Must be a multiple of 4 and in ±128 MB.
    """
    imm26 = (offset_bytes // 4) & 0x3FFFFFF
    word  = 0x94000000 | imm26
    return struct.pack('<I', word)


def encode_b(offset_bytes: int) -> bytes:
    """
    Encode B #(PC + offset_bytes)  — unconditional branch (tail call).
    *offset_bytes* is a signed byte offset from the instruction's own PC.
    Must be a multiple of 4 and in ±128 MB.
    """
    imm26 = (offset_bytes // 4) & 0x3FFFFFF
    word  = 0x14000000 | imm26
    return struct.pack('<I', word)
