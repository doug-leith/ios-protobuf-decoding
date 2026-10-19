"""swift_descriptor_extract.py — recover swift-protobuf message field NAMES and
NUMBERS from a Mach-O binary (and enum case names/numbers).

Swift-protobuf messages (types conforming to ``SwiftProtobuf.Message``) carry a
static ``_protobuf_nameMap`` that maps each field number to its proto name,
emitted by ``protoc-gen-swift``.  Unlike Apple ``PBCodable`` (no descriptor — we
reverse-engineer ``writeTo:``/``readFrom:``), the nameMap is a structured table,
so names+numbers are recoverable directly.  The compiler lowers the *same*
generated dictionary-literal source several ways across iOS versions / toolchains
/ optimisation levels; this module handles all of them:

* **A — inline closure** (device / iOS 16 frameworks): a ``swift_once``-guarded
  init closure builds each entry inline with ``mov w,#<num>; str x,[base]`` plus
  ``adr x,<name-cstring>; mov w,#<len>; stp x,x,[entry]``.
* **B — compact single-field tail-call**: the closure passes ``x2=<name>``,
  ``w3=<len>`` to a shared ``_NameMap`` builder; the (single) field number comes
  from the message's ``decodeMessage`` ``cmp x0, #<num>``.
* **C — static object** (newer toolchains): the dictionary literal is
  const-folded into a static ``Array<(Int, _NameDescription)>`` handed to
  ``_swift_initStaticObject``; entries are scanned from the blob as
  ``(number, name-ptr, len, …)`` triples (element stride is version-dependent,
  so we scan rather than assume it).
* **D — shared once-init template** (another newer-toolchain lowering, e.g.
  DPSubmissionService): the getter is just ``adr x0,<once-token>; adr
  x1,<storage-slot>; adr x2,<builder>; b <shared-lazy-init-template>`` — the
  branch target is a generic memoized-value-getter TEMPLATE shared across many
  unrelated types (it carries no type information), but the ``adr x2`` value is
  the type's own builder, which stores each entry as ``mov w,#<num>;
  str x,[base]`` + ``adr x,<name>; mov w,#<len>; stp x,x,[entry]`` — the same
  literal shape as A, just reached by chasing the ``adr`` instead of walking
  the getter inline (:func:`_shared_once_init_targets`).  Some builders are
  themselves only a further arg-setup stub for a *second*, arity-specific
  shared template (:func:`_walk_namemap_builder_hop` reads that template with the
  registers the stub hands it).

* **E — packed bytecode** (newer swift-protobuf / iOS 27 InternalSwiftProtobuf):
  ``_NameMap(bytecode: "<literal>")`` -- the whole (number, name) table is one
  NUL-delimited string literal, reached from a getter of the form ``adrp/add
  x1,<slot>; adrp/add x2,<literal>; mov w3,#<len>; b <template>``.  Decoded by
  :mod:`serializers.swift_namemap_bytecode` (structure-validated: header, opcodes,
  terminators and full consumption, else it declines).  Single-field messages use
  a bare-name literal (no header) and stay with shape B.

TYPES are intentionally NOT recovered here: swift-protobuf encodes them via
generic ``Visitor``/``Decoder`` witness-table calls (``blraa`` / local thunks),
so there is no named ``visit*Field`` symbol to read the wire type from.  Output
lists field names + numbers only.

Works in BOTH modes: from a standalone binary the per-type ``_protobuf_nameMap``
static-init symbols come from ``LC_SYMTAB`` / the dyld export trie; cache-native
they come from the cache's ``.symbols`` sub-cache (same nlist, keyed by vmaddr).
The disassembly-driven decoders are mode-agnostic (all reads route through
``ctx``).

Every shape reads a function's :func:`_listing` (what its entry reaches within its extent,
``LC_FUNCTION_STARTS``) and register values from :class:`proto.arm64_eval.Flow`; a builder's
(number, name) entries are paired by the address they are stored at (:func:`_table_entries`).

The residual swift type/number estimates (and which are flagged) are catalogued
in LIMITATIONS.md (10) / to-do #63a/#63b/#66/#67/#68/#70.
"""
from __future__ import annotations

import bisect
import logging
import re
import struct
from dataclasses import dataclass, field
from collections import Counter
from typing import Dict, List, NamedTuple, Optional, Tuple

from macho.memory import BinaryContext, _ctx_cache
from macho.disasm import disasm, _norm_reg, _parse_imm
from proto.arm64_eval import Flow
from proto.arm64_operands import (COMPARE_BRANCHES, INDIRECT_BRANCHES, RETURNS, is_cond_branch,
                                  parse_mem, split_ops)
from serializers.swift_type_recovery import demangle_idents
from serializers.swift_namemap_bytecode import (
    bytecode_literal_from_getter, call_site_registers, decode_namemap_bytecode)

log = logging.getLogger(__name__)

# Max proto field number (29-bit) and a sane name-length ceiling — used to
# validate candidate (number, name, len) triples when scanning static blobs.
_MAX_FIELD_NUMBER = 0x1FFFFFFF
_MAX_NAME_LEN = 80
_NAMEMAP_MARKER = "17_protobuf_nameMap"
# [cap:INPUT-SANITY] runaway guard on a listing read without a function index (:func:`_listing`;
# with one, the function's extent bounds it) and on the linear decodeMessage / traverse reads.
# A listing that reaches it is marked truncated and the builder numbers read from it are
# reported as estimated.
_INLINE_MAX_INSNS = 4000
# [cap:COSMETIC] instructions disassembled per read while following a path; a path is read
# on until it ends, whatever this is.
_READ_CHUNK = 64


# ── data model ──────────────────────────────────────────────────────────────

@dataclass
class SwiftField:
    number: int
    name: str
    # proto type recovered from Swift field metadata (swift_type_recovery), e.g.
    # "int32", "string", "repeated Foo", "map<string, int32>", or None when not
    # recovered (oneof members, stripped metadata).  The int varint/zigzag/fixed
    # encoding nuance is NOT distinguished (base Swift type only).
    proto_type: Optional[str] = None
    # True when the NUMBER came from a real structural signal (the nameMap closure
    # immediate, the static blob, or a single decodeMessage field-number compare).
    # False only for the shape-B single-field DEFAULT of 1, which is a guess that
    # must surface as "number estimated" rather than being laundered as confirmed.
    number_confirmed: bool = True
    # Set when the recovered proto_type contains a GUESS filler (an Array element /
    # map key-or-value that didn't decode, shown as `bytes`); surfaced as a note so
    # the `bytes` isn't read as certain (#67).
    type_note: Optional[str] = None


@dataclass
class SwiftMessage:
    module: str
    name: str                       # may be dotted for nested types
    fields: List[SwiftField] = field(default_factory=list)
    is_enum: bool = False
    shape: str = ""                 # which lowering produced it (diagnostic)
    # True when no name-map entries were recovered AND Swift reflection independently
    # lists no stored proto field for the struct: the message is genuinely EMPTY (only
    # swift-protobuf's unknownFields), not one whose name map could not be read.
    fieldless: bool = False

    @property
    def qualified(self) -> str:
        return f"{self.module}.{self.name}" if self.module else self.name


# ── symbol table (name → vmaddr), nlist + export trie ─────────────────────────

def symbol_addrs(ctx: BinaryContext) -> Dict[str, int]:
    """Map every declared symbol name → its vmaddr.

    Merges the ``LC_SYMTAB`` nlist (carries ``n_value`` for an image's own
    *internal* symbols, e.g. an app's message types) with the dyld export trie
    (exported symbols such as a framework's public types).

    Cache-native images keep no per-image symbol table in their (shared-LINKEDIT)
    Mach-O; instead the original local symbols — including each type's
    ``…_protobuf_nameMap`` static-init and ``…decodeMessage`` symbols — live in
    the cache's ``.symbols`` sub-cache, keyed by vmaddr.  We read those directly
    so swift-protobuf recovery works cache-native, not just from a standalone
    binary.  Returns ``{}`` when no symbol source is addressable."""
    reader = getattr(ctx, "_cache_reader", None)
    if reader is not None and getattr(ctx, "is_cache_backed", False):
        try:
            return reader.image_symbol_addrs(
                ctx.image_base, _NAMEMAP_MARKER, "13decodeMessage")
        except (NameError, ImportError):
            raise
        except Exception:
            return {}

    out: Dict[str, int] = {}
    data = getattr(ctx, "_data", b"") or b""
    if not data:
        return out
    base = ctx.image_base

    symtab = getattr(ctx, "_symtab", None)
    if symtab:
        symoff, nsyms, stroff, strsize = symtab
        n = len(data)
        str_end = min(stroff + strsize, n)
        if symoff > 0 and stroff > 0 and symoff < n:
            for i in range(min(nsyms, (n - symoff) // 16)):
                b = symoff + i * 16
                n_strx = struct.unpack_from("<I", data, b)[0]
                n_value = struct.unpack_from("<Q", data, b + 8)[0]
                if n_strx == 0 or n_value == 0:
                    continue
                sp = stroff + n_strx
                if sp >= str_end:
                    continue
                end = data.find(b"\x00", sp, str_end)
                if end < 0:
                    end = str_end
                out.setdefault(data[sp:end].decode("utf-8", "replace"), n_value)

    export = getattr(ctx, "_export_trie", None)
    if export:
        tb, sz = export
        end = min(tb + sz, len(data))
        if 0 < tb < len(data):
            out.update(_export_trie_addrs(data, tb, end, base))
    return out


def _uleb(data: bytes, p: int, end: int) -> Tuple[int, int]:
    result = shift = 0
    while p < end:
        b = data[p]
        p += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            break
        shift += 7
        if shift > 63:
            break
    return result, p


def _export_trie_addrs(data: bytes, base: int, end: int, image_base: int) -> Dict[str, int]:
    """DFS the export trie, yielding name → image_base + terminal address."""
    out: Dict[str, int] = {}
    stack = [(base, "")]
    seen = set()
    steps = 0
    while stack and steps < 1_000_000:
        steps += 1
        node, prefix = stack.pop()
        if node < base or node >= end or node in seen:
            continue
        seen.add(node)
        term, p = _uleb(data, node, end)
        if term:
            _flags, q = _uleb(data, p, end)
            addr, _q = _uleb(data, q, end)
            out.setdefault(prefix, image_base + addr)
        children_at = p + term
        if children_at >= end:
            continue
        nchild = data[children_at]
        p = children_at + 1
        for _ in range(nchild):
            z = data.find(b"\x00", p, end)
            if z < 0:
                break
            edge = data[p:z].decode("utf-8", "replace")
            child_off, p = _uleb(data, z + 1, end)
            stack.append((base + child_off, prefix + edge))
    return out


# ── mangled name parsing ──────────────────────────────────────────────────────

def _split_idents(head: str) -> List[str]:
    """Parse a run of Swift length-prefixed identifiers (``6oracle9Ora_Multi``
    → ``["oracle", "Ora_Multi"]``), skipping single-letter nominal-kind tags and
    resolving word-substitution abbreviations (e.g. ``07Google_B4_Any`` →
    ``Google_Protobuf_Any``).  Delegates to the shared demangler in
    :mod:`swift_type_recovery` so the type and name sides agree."""
    return demangle_idents(head)


def _parse_namemap_symbol(sym: str) -> Optional[Tuple[str, str, bool]]:
    """``…_protobuf_nameMap`` symbol -> ``(module, type_name, is_enum)``, or None.
    ``V`` before the marker is a struct (message), ``O`` an enum."""
    m = re.search(r"_\$[sS](.*?)([VO])" + _NAMEMAP_MARKER, sym)
    if not m:
        return None
    idents = _split_idents(m.group(1))
    if len(idents) < 2:
        return None
    return idents[0], ".".join(idents[1:]), m.group(2) == "O"


# ── listings and register values ──────────────────────────────────────────────

# What ends a path through a function: a return, an indirect jump, a trap.
_PATH_ENDS = RETURNS | INDIRECT_BRANCHES | frozenset(("brk", "udf", "hlt"))


class _Listing(list):
    """A function's instructions in address order (:func:`_listing`); *truncated* when the
    read stopped at :data:`_INLINE_MAX_INSNS` with paths still open."""
    truncated = False


_LC_SEGMENT_64, _LC_FUNCTION_STARTS = 0x19, 0x26


def _load_commands(ctx: BinaryContext) -> List[Tuple[int, bytes]]:
    """``(cmd, bytes)`` for each load command of the image."""
    reader = getattr(ctx, "_cache_reader", None)
    if reader is not None and getattr(ctx, "is_cache_backed", False):
        return reader._image_load_commands(ctx.image_base)
    data = getattr(ctx, "_data", b"") or b""
    if len(data) < 32:
        return []
    ncmds, sizeofcmds = struct.unpack_from("<II", data, 16)
    out, pos, end = [], 32, min(32 + sizeofcmds, len(data))
    for _ in range(ncmds):
        if pos + 8 > end:
            break
        cmd, size = struct.unpack_from("<II", data, pos)
        if size < 8:
            break
        out.append((cmd, data[pos:pos + size]))
        pos += size
    return out


def _build_function_starts(ctx: BinaryContext) -> List[int]:
    segs: Dict[str, Tuple[int, int]] = {}
    dataoff = datasize = None
    for cmd, body in _load_commands(ctx):
        if cmd == _LC_SEGMENT_64 and len(body) >= 56:
            name = body[8:24].split(b"\x00", 1)[0].decode("ascii", "replace")
            vmaddr, _vmsize, fileoff = struct.unpack_from("<QQQ", body, 24)
            segs[name] = (vmaddr, fileoff)
        elif cmd == _LC_FUNCTION_STARTS and len(body) >= 16:
            dataoff, datasize = struct.unpack_from("<II", body, 8)
    if dataoff is None or "__TEXT" not in segs or not datasize:
        return []
    if getattr(ctx, "is_cache_backed", False):
        le_vm, le_off = segs["__LINKEDIT"]                 # the shared linkedit, by its segment
        blob = ctx.read_bytes(le_vm + dataoff - le_off, datasize)
    else:
        blob = ctx._data[dataoff:dataoff + datasize]
    starts, addr, p = [], segs["__TEXT"][0], 0
    while p < len(blob):
        delta, p = _uleb(blob, p, len(blob))
        if delta == 0:
            break
        addr += delta
        starts.append(addr)
    return starts


def _function_starts(ctx: BinaryContext) -> List[int]:
    """The image's function entries (``LC_FUNCTION_STARTS``), sorted; empty without the
    command.  Memoised on *ctx*."""
    def build():
        try:
            return _build_function_starts(ctx)
        except (NameError, ImportError):
            raise
        except Exception:
            return []
    return _ctx_cache(ctx, "_swift_function_starts", build)


def _function_end(ctx: BinaryContext, va: int) -> Optional[int]:
    """Where the function at *va* ends: the next function entry after it (None: unknown)."""
    starts = _function_starts(ctx)
    i = bisect.bisect_right(starts, va)
    return starts[i] if i < len(starts) else None


def _branch_target(ins) -> Optional[int]:
    """Target of a direct branch (``b``, ``b.cond``, ``cbz``/``tbz``...): its last operand."""
    ops = split_ops(ins.op_str)
    return _parse_imm(ops[-1]) if ops else None


def _listing(ctx: BinaryContext, va: int) -> _Listing:
    """The instructions of the function at *va* that its entry reaches, in address order:
    both sides of each conditional branch and the target of each ``b`` inside the function
    (its extent: *va* up to the next function entry, :func:`_function_starts`), each path
    on to a return, an indirect jump, or a branch out of the function (a tail call, which
    is not followed).  Calls return.  Without a function index a ``b`` ends its path
    unless it goes to the next instruction.  Raises when *va* itself cannot be read."""
    end = _function_end(ctx, va)

    def inside(t: Optional[int]) -> bool:
        return t is not None and va <= t and (end is None or t < end)

    out: Dict[int, object] = {}
    work = [va]
    while work:
        a = work.pop()
        while a is not None and a not in out and (end is None or a < end):
            try:
                chunk = disasm(ctx, a, max_insns=_READ_CHUNK, stop_at_ret=False)
            except (NameError, ImportError):
                raise
            except Exception:
                if a == va:
                    raise
                break
            if not chunk:
                break
            nxt: Optional[int] = chunk[-1].addr + 4
            for ins in chunk:
                if ins.addr in out or (end is not None and ins.addr >= end):
                    nxt = None
                    break
                if end is None and len(out) >= _INLINE_MAX_INSNS:
                    listing = _Listing(sorted(out.values(), key=lambda i: i.addr))
                    listing.truncated = True
                    return listing
                out[ins.addr] = ins
                mn = ins.mnemonic
                if mn in _PATH_ENDS:
                    nxt = None
                    break
                if mn == "b":
                    t = _branch_target(ins)
                    if inside(t) if end is not None else t == ins.addr + 4:
                        work.append(t)
                    nxt = None
                    break
                if is_cond_branch(mn) or mn in COMPARE_BRANCHES:
                    t = _branch_target(ins)
                    if inside(t):
                        work.append(t)
            a = nxt
    return _Listing(sorted(out.values(), key=lambda i: i.addr))


def _tail_calls(insns) -> List[int]:
    """Indices of the listing's ``b`` instructions to an address outside it."""
    inside = {i.addr for i in insns}
    return [k for k, ins in enumerate(insns)
            if ins.mnemonic == "b" and _branch_target(ins) not in inside]


def _cstr(ctx: BinaryContext, va: Optional[int]) -> Optional[str]:
    if va is None:
        return None
    try:
        s = ctx.read_cstring(va, _MAX_NAME_LEN + 16)
    except (NameError, ImportError):
        raise
    except Exception:
        return None
    return s if s and all(32 <= ord(c) < 127 for c in s) else None


def _constant_addresses(insns) -> List[int]:
    """Every value an ``add Xd, Xn, #imm`` computes from a constant ``Xn`` (an ``adrp`` page,
    by reaching definitions): the data addresses the function materialises."""
    flow = Flow(None, list(insns))
    out: List[int] = []
    for k, ins in enumerate(insns):
        if ins.mnemonic != "add":
            continue
        ops = split_ops(ins.op_str)
        if len(ops) != 3 or not ops[2].startswith("#"):
            continue
        base = flow.const_before(k, _norm_reg(ops[1]) or "")
        off = _parse_imm(ops[2])
        if base is not None and off is not None:
            out.append(base + off)
    return out


# Instructions that only compute registers: what a pure tail-call stub is made of (arm64e signs
# a function pointer in place before passing it: ``paciza x16; mov x2, x16``).
_SETUP = frozenset({"adr", "adrp", "add", "mov", "movz", "movk", "movn", "nop", "paciza", "pacia"})


def _tail_call_args(insns) -> Optional[Dict[str, int]]:
    """The argument registers (x0-x7) known at the tail call of a pure stub -- a listing whose
    instructions before its last, a ``b`` out, only compute registers -- or None for any other
    listing.

    Such a getter / builder holds no table of its own: the (number, name) data is in the
    function it passes (shape D), in a literal it passes (shape E, F) or in a static blob."""
    if (len(insns) < 2 or insns[-1].mnemonic != "b" or _tail_calls(insns) != [len(insns) - 1]
            or any(i.mnemonic not in _SETUP for i in insns[:-1])):
        return None
    k = len(insns) - 1
    regs = Flow(None, list(insns)).propagate({}, at=[k]).get(k, {})
    return {f"x{n}": regs[f"x{n}"] for n in range(8) if f"x{n}" in regs}


def _in_executable_text(ctx: BinaryContext, va: int) -> bool:
    """True when *va* lands inside this image's own executable code section
    (as opposed to a data address, e.g. a once-token or a storage slot)."""
    if not ctx.has_section("__TEXT", "__text"):
        return False
    sec = ctx.section("__TEXT", "__text")
    return sec.vmaddr <= va < sec.vmaddr + sec.vmsize


# ── shape C: static-object blob ───────────────────────────────────────────────

def _name_ptr(ctx: BinaryContext, slot_va: int) -> Optional[int]:
    """The name pointer stored at *slot_va*, through the image's pointer fixups
    (``ctx.read_ptr``: a chained-fixup rebase in a standalone binary, the cache's slide)."""
    try:
        return ctx.read_ptr(slot_va)
    except (NameError, ImportError):
        raise
    except Exception:
        return None


def _parse_enum_blob(ctx: BinaryContext, blob_va: int, buf: bytes,
                     count: int) -> Optional[List[SwiftField]]:
    """Strict reader for a static ``Array<(Int, _NameDescription)>`` of enum cases.

    Elements start right after the 0x20-byte header, each ``(value: Int, name ptr,
    name len, …)`` with a fixed (version-specific) stride.  Unlike the message scan
    this does NOT hunt through neighbouring memory: the first case must sit at +0x20,
    the stride is read off the first two cases, and all ``count`` cases must parse
    -- otherwise None.  (Scanning loosely read an unrelated alias-name array, then
    the next type's cases, as this type's.)"""
    def entry(off: int):
        if off + 24 > len(buf):
            return None
        num = struct.unpack_from("<q", buf, off)[0]
        ln = struct.unpack_from("<Q", buf, off + 16)[0]
        if not (-(1 << 31) <= num < (1 << 31)) or not 1 <= ln <= _MAX_NAME_LEN:
            return None
        nm = _cstr(ctx, _name_ptr(ctx, blob_va + off + 8))
        if not nm or ln != len(nm) or not _IDENT_RE.match(nm):
            return None
        return num, nm

    first = entry(0x20)
    if first is None:
        return None
    out = [SwiftField(*first)]
    if count > 1:
        stride = next((st for st in range(0x18, 0x80, 8) if entry(0x20 + st) is not None), None)
        if stride is None:
            return None
        for i in range(1, count):
            e = entry(0x20 + i * stride)
            if e is None:
                return None
            out.append(SwiftField(*e))
    if len({(f.number, f.name) for f in out}) != len(out):
        return None
    return out


_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")


def _parse_static_blob(ctx: BinaryContext, blob_va: int,
                       enum: bool = False) -> Optional[List[SwiftField]]:
    """Parse a static ``Array<(Int, _NameDescription)>`` storage blob.

    Header is 0x20 bytes (metadata, refcount, count, capacity); the element
    stride depends on ``_NameDescription``'s size (version-specific), so we
    SCAN 8-byte slots for valid ``(number, name-ptr, len)`` triples rather than
    assume the stride.

    *enum*: the entries are enum cases, whose value may be 0 or negative (a signed
    Int in the slot) and may repeat (aliases); a message field number is >= 1 and
    unique.  Enum names must also look like identifiers, and the scan is bounded by
    the header's entry count -- without that bound a blob whose values the field-number
    filter rejects keeps scanning into the NEXT type's data and returns its cases."""
    try:
        count = struct.unpack_from("<Q", ctx.read_bytes(blob_va, 0x20), 0x10)[0]
    except (NameError, ImportError):
        raise
    except Exception:
        return None
    if not (0 < count < 4096):
        return None
    span = 0x20 + count * 0x80
    buf = b""
    for step in range(span, 0x18, -8):
        try:
            buf = ctx.read_bytes(blob_va, step)
            break
        except (NameError, ImportError):
            raise
        except Exception:
            continue
    if not buf:
        return None
    if enum:
        return _parse_enum_blob(ctx, blob_va, buf, count)
    out: List[SwiftField] = []
    seen = set()
    # Real elements start right after the 0x20-byte header.  Message blobs have always
    # been scanned from 0x10 (harmless: nothing there parses as a triple), but for
    # enums the header's `capacity` word at 0x18 can pair with the first slots of an
    # unrelated static array -- e.g. the one-element alias-name array of an enum with
    # aliases looked like case ``(2, "AL_Y2")``.
    off = 0x20 if enum else 0x10
    while off + 24 <= len(buf) and len(out) < count:
        if enum:
            num = struct.unpack_from("<q", buf, off)[0]
            valid = -(1 << 31) <= num < (1 << 31)
        else:
            num = struct.unpack_from("<Q", buf, off)[0]
            valid = 1 <= num <= _MAX_FIELD_NUMBER
        if not valid:
            off += 8
            continue
        ln = struct.unpack_from("<Q", buf, off + 16)[0]
        if 1 <= ln <= _MAX_NAME_LEN:
            nm = _cstr(ctx, _name_ptr(ctx, blob_va + off + 8))
            key = (num, nm) if enum else num
            if (nm and ln == len(nm) and key not in seen
                    and (not enum or _IDENT_RE.match(nm))):
                seen.add(key)
                out.append(SwiftField(num, nm))
                off += 16          # skip the matched (name ptr, len) slots
        off += 8
    return out or None


# ── shapes A/B/C: the (number, name) stores of a name-map builder ────────────

class _Slot(NamedTuple):
    k: int                                  # the store's index in the listing
    addr: Tuple[Tuple[Tuple, ...], int]     # symbolic address (:func:`_sym`)
    value: Optional[int]                    # the stored register's value, if known
    bits: int                               # the stored register's width


def _sym(flow: Flow, k: int, reg: Optional[str], memo: Dict[int, tuple]) -> tuple:
    """*reg* before ``insns[k]`` as a symbolic address ``(atoms, offset)``: a constant plus a
    sum of values the listing cannot know -- a call's result, a field offset loaded from type
    metadata, a register's value on entry -- each an *atom* named by where it comes from.
    Read off the reaching definitions through ``mov`` copies and ``add`` / ``sub``; two
    addresses with the same atoms lie at a known distance from each other."""
    if reg is None:
        return (("?", k, ""),), 0
    c = flow.const_before(k, reg)
    if c is not None:
        return (), c
    defs = flow.defs_before(k, reg)
    if len(defs) != 1:
        return (("join", k, reg),), 0
    (d,) = defs
    if d < 0:
        return (("entry", -1, reg),), 0
    if d in memo:
        return memo[d]
    res = memo[d] = (("def", d, ""),), 0           # also what a cycle (a loop counter) sees
    ins = flow.insns[d]
    ops = split_ops(ins.op_str)
    if ins.mnemonic == "mov" and len(ops) == 2 and not ops[1].startswith("#"):
        res = _sym(flow, d, _norm_reg(ops[1]), memo)
    elif ins.mnemonic in ("add", "sub") and len(ops) == 3:
        a = _sym(flow, d, _norm_reg(ops[1]), memo)
        b = ((), _parse_imm(ops[2])) if ops[2].startswith("#") else \
            _sym(flow, d, _norm_reg(ops[2]), memo)
        if b[1] is not None and ins.mnemonic == "add":
            res = tuple(sorted(a[0] + b[0])), a[1] + b[1]
        elif b[1] is not None and not b[0]:
            res = a[0], a[1] - b[1]
    memo[d] = res
    return res


def _store_slots(flow: Flow, entry: Optional[Dict[str, int]]) -> List[_Slot]:
    """Every 64- / 32-bit register the listing stores outside its frame (``str`` / ``stur`` /
    ``stp``), with its address (:func:`_sym`) and value (:meth:`Flow.propagate` from
    *entry*).  Stores the entry cannot reach are left out."""
    ks = [k for k, ins in enumerate(flow.insns) if ins.mnemonic in ("str", "stur", "stp")]
    vals = flow.propagate(dict(entry or {}), at=ks)
    memo: Dict[int, tuple] = {}
    out: List[_Slot] = []
    for k in ks:
        if k not in vals:
            continue
        ops = split_ops(flow.insns[k].op_str)
        n = 2 if flow.insns[k].mnemonic == "stp" else 1
        if len(ops) < n + 1 or any(r[:1] not in ("x", "w") for r in ops[:n]):
            continue
        pm = parse_mem(ops[n])
        if pm is None or pm.base in (None, "sp", "x29") or pm.index is not None:
            continue                         # the frame, or an indexed store: not a table
        atoms, off = _sym(flow, k, pm.base, memo)
        if len(ops) == n + 1:                # a post-indexed store writes at the base itself
            off += pm.disp
        for r in ops[:n]:
            width = 8 if r.startswith("x") else 4
            v = 0 if r in ("xzr", "wzr") else vals[k].get(_norm_reg(r))
            out.append(_Slot(k, (atoms, off), None if v is None else v & ((1 << 8 * width) - 1),
                             8 * width))
            off += width
    return out


def _table_entries(ctx: BinaryContext, insns, enum: bool, entry: Optional[Dict[str, int]] = None,
                   with_len: bool = False) -> List[SwiftField]:
    """The (number, name) entries a name-map builder stores, paired by ADDRESS.  The name
    pointer of an entry is stored either 8 bytes after its number -- ``stp <num>, <name>``
    (shape A) or two ``str`` (shape B) -- or at the number's address plus one more unknown
    offset (shape C: the number is the ``Int`` of an ``(Int, _NameDescription)`` element and
    the name the first word of its ``_NameDescription``, whose offset in the element the
    runtime type metadata supplies: ``str <num>, [E]`` ... ``add Xd, E, <offset>`` ...
    ``stp <name>, <len>, [Xd]``).  A name pairs only with the one number at such an address,
    and each number with one name; entries come in store order.

    *with_len*: the name must be followed by its length (``stp <name>, <len>``, the inline
    closure).  *enum*: a number is any int32 (the stored register sign-extended), else a field
    number (1 .. 2^29-1).  *entry*: register values on entry (a stub's arguments)."""
    slots = _store_slots(Flow(ctx, list(insns)), entry)
    at: Dict[tuple, Optional[_Slot]] = {}
    for s in slots:
        at[s.addr] = None if s.addr in at else s          # stored twice: not one entry
    numbers: Dict[tuple, int] = {}
    for a, s in at.items():
        if s is None or s.value is None:
            continue
        v = s.value
        if enum:
            v = v - (1 << s.bits) if v >> (s.bits - 1) else v
            if -(1 << 31) <= v < (1 << 31):
                numbers[a] = v
        elif 1 <= v <= _MAX_FIELD_NUMBER:
            numbers[a] = v
    pairs = []
    for (atoms, off), s in at.items():
        if s is None or s.bits != 64:
            continue
        name = _cstr(ctx, s.value)
        if not name:
            continue
        if with_len:
            ln = at.get((atoms, off + 8))
            if ln is None or ln.value != len(name):
                continue
        keys = {(atoms, off - 8)} | {(atoms[:i] + atoms[i + 1:], off) for i in range(len(atoms))}
        hits = [a for a in keys if a in numbers]
        if len(hits) == 1:
            pairs.append((s.k, hits[0], name))
    once = Counter(a for _k, a, _n in pairs)
    return [SwiftField(numbers[a], name) for _k, a, name in sorted(pairs) if once[a] == 1]


def _walk_inline_closure(ctx: BinaryContext, insns, enum: bool = False,
                         entry: Optional[Dict[str, int]] = None) -> List[SwiftField]:
    """Shape A, inline (device / framework closures): each entry is a number store plus
    ``<name>; mov w,#<len>; stp x,x,[entry]`` -- the name pointer with its length, which pins
    names to real entries (:func:`_table_entries` with the length)."""
    return _table_entries(ctx, insns, enum, entry, with_len=True)


def _walk_namemap_builder(ctx: BinaryContext, insns, enum: bool = False,
                          entry: Optional[Dict[str, int]] = None) -> List[SwiftField]:
    """Runtime-built ``_NameMap``: the ``(fieldNumber, name)`` table the cold builder writes
    into its freshly-allocated buffer (:func:`_table_entries`; the length lives in a separate
    ``_NameDescription`` constant, so none is required).  A message keeps the first entry per
    number; an enum case may be 0, negative or repeated (an alias), so it keeps the first per
    (value, name)."""
    out: List[SwiftField] = []
    seen: set = set()
    for f in _table_entries(ctx, insns, enum, entry):
        key = (f.number, f.name) if enum else f.number
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


def _shared_once_init_targets(insns) -> List[int]:
    """Shape D: the getter is only a tail call into a lazy-once-init TEMPLATE shared across
    many unrelated types (device / newer-toolchain ``static let`` lowering), passing a
    once-token, the type's ``_NameMap`` storage slot and the type's own builder function.
    The template carries no type information; the arguments do.  Returns the values of the
    argument registers (:func:`_tail_call_args`); callers keep the code addresses
    (:func:`_in_executable_text`), which drops the token and the slot in ``__DATA``.

    Only a pure stub qualifies: a once-init getter with its own fast / cold path (the
    :func:`_runtime_namemap_fields` shape) branches first, and an address in its cold path is
    not this type's builder (#74: remindd's UnmigrateRequest picked up its sibling `Option`
    enum's builder that way)."""
    args = _tail_call_args(insns)
    return list(args.values()) if args else []


def _tail_callee(ctx: BinaryContext, insns) -> Optional[Tuple[int, Dict[str, int]]]:
    """``(target, registers)`` when the listing ends in exactly one tail call, to code of
    this image: the function it hands its registers to (:meth:`Flow.propagate` at the
    ``b``), e.g. the shared template a builder stub sets up arguments for."""
    tails = _tail_calls(insns)
    if len(tails) != 1:
        return None
    k = tails[0]
    t = _branch_target(insns[k])
    regs = Flow(ctx, list(insns)).propagate({}, at=[k]).get(k)
    if t is None or t == insns[0].addr or regs is None or not _in_executable_text(ctx, t):
        return None
    return t, regs


def _walk_namemap_builder_hop(ctx: BinaryContext, va: int,
                              enum: bool = False) -> List[SwiftField]:
    """Read one builder's (number, name) table.  When the builder is itself only an
    arg-setup stub (``adr x1,<storage>; adr x2,<name>; mov w3,<len>; b <template>``) for a
    second, arity-specific shared template that does the stores, read the template with the
    registers the stub hands it (:func:`_tail_callee`) as its entry values."""
    try:
        body = _listing(ctx, va)
        got = _walk_namemap_builder(ctx, body, enum)
        callee = None if got else _tail_callee(ctx, body)
        if callee is not None:
            got = _walk_namemap_builder(ctx, _listing(ctx, callee[0]), enum, entry=callee[1])
    except (NameError, ImportError):
        raise
    except Exception:
        return []
    return got


def _closure_arg_targets(ctx: BinaryContext, insns) -> List[int]:
    """Code addresses the listing hands a callee as an argument (x0-x7 at a call or tail
    call): the closure a once-init getter passes ``swift_once`` (``adr x1,<closure>``, or
    ``adrp``+``add`` when it is far, as in device / cache images).  Values outside this
    image's executable text -- the once-token, a storage slot -- are not closures."""
    out: List[int] = []
    for _k, regs in call_site_registers(ctx, insns):
        for r in (f"x{n}" for n in range(8)):
            v = regs.get(r)
            if v is not None and v not in out and _in_executable_text(ctx, v):
                out.append(v)
    return out


def _runtime_namemap_fields(ctx: BinaryContext, getter_insns,
                            enum: bool = False) -> List[SwiftField]:
    """The once-initialised ``_NameMap`` lowering: the getter fast-path loads a
    cached ``_NameMap`` from ``__bss`` and a ``cmn x?,#1; b.ne <builder>`` guards
    a cold builder that constructs it once.  Follow the cold path to the builder
    closure and read its literal ``(number, name)`` table (:func:`_walk_namemap_
    builder`).  Returns ``[]`` (so the caller falls through to the shape-B single-
    field path) unless the once-init signature is present AND a builder is found.

    This recovers app types whose nameMap is emitted as a runtime ``_NameMap``
    (e.g. remindd ``StartMigrationRequest.Credential`` — 5 fields that shape-B
    under-reads to just the first), not only the SwiftProtobuf well-known types."""
    # Gate: the lazy-_NameMap guard compares the cached pointer to the -1 sentinel.
    if not any(ins.mnemonic == "cmn" and ins.op_str.strip().endswith("#1")
               for ins in getter_insns):
        return []
    # Candidate builder/closure entry points: branch targets + the closures passed to calls.
    targets: List[int] = []
    for ins in getter_insns:
        if is_cond_branch(ins.mnemonic) or ins.mnemonic in COMPARE_BRANCHES or ins.mnemonic == "b":
            t = _branch_target(ins)
            if t is not None:
                targets.append(t)
    targets += _closure_arg_targets(ctx, getter_insns)
    best: List[SwiftField] = []
    best_truncated = False
    for t in targets:
        try:
            body = _listing(ctx, t)
        except (NameError, ImportError):
            raise
        except Exception:
            continue
        got = _walk_namemap_builder(ctx, body, enum)
        trunc = body.truncated
        if not got:
            # the builder is often reached one hop on, as the closure the cold path passes.
            for ct in _closure_arg_targets(ctx, body):
                try:
                    inner = _listing(ctx, ct)
                except (NameError, ImportError):
                    raise
                except Exception:
                    got = []
                    continue
                got = _walk_namemap_builder(ctx, inner, enum)
                trunc = inner.truncated
                if not got:
                    # the closure may itself be only an arg-setup stub that tail-calls
                    # the real builder (the Google well-known wrappers do)
                    got = _walk_namemap_builder_hop(ctx, ct, enum)
                if got:
                    break
        if len(got) > len(best):
            best = got
            best_truncated = trunc
    # CAUTIOUS: if the builder's listing ran into the runaway guard, its (number, name) store
    # table may be incomplete.  Rather than launder a partial read as ground truth, flag the
    # recovered numbers as estimated (renders "// number estimated").
    if best_truncated:
        for f in best:
            f.number_confirmed = False
    return best


def _single_entry_stub(ctx: BinaryContext, va: int) -> List[SwiftField]:
    """Shape F: a builder that is only an arg-setup stub for the shared SINGLE-entry
    ``_NameMap`` template -- ``adrp/add x1,<slot>; adrp/add x3,<name>; mov w2,#<number>;
    mov w4,#<len>; b <template>``.  The template stores ``x2`` (the field number), ``x3``
    and ``x4`` (name pointer and length) as the one entry, so the number is a literal,
    unlike the shape-B tail call where it must come from ``decodeMessage``.  Accepted only
    when the length matches the name's cstring."""
    try:
        args = _tail_call_args(_listing(ctx, va))
    except (NameError, ImportError):
        raise
    except Exception:
        return []
    if not args or "x2" not in args or "x4" not in args:
        return []
    name, num = _cstr(ctx, args.get("x3")), args["x2"] & 0xFFFFFFFF
    if not name or len(name) != args["x4"] & 0xFFFFFFFF or not 1 <= num <= _MAX_FIELD_NUMBER:
        return []
    return [SwiftField(num, name)]


def _namemap_builder_validated(ctx: BinaryContext, got: List[SwiftField],
                               decode_va: Optional[int],
                               traverse_va: Optional[int],
                               enum: bool = False) -> bool:
    """Guard the runtime-namemap reading against fabrication.

    The cold-builder entry is a ``stp <smallInt>, <namePtr>, [base,#slot]`` pair
    whose small int is AMBIGUOUS: in the older codegen it is the field NUMBER
    (remindd), but in the newer InternalSwiftProtobuf packed-bytecode ``_NameMap``
    it is the name LENGTH (nptocompaniond ErrorResponse: 6=len'domain', 4='code'),
    so :func:`_walk_namemap_builder` would mis-read lengths as numbers.

    Accept only when neither check rejects:
      * the independent ``decodeMessage``/``traverse`` numbers (a different codegen
        path) are a SUBSET of the recovered set — a contradiction means we read the
        wrong thing; and
      * not EVERY entry has ``number == len(name)`` — the signature of the
        ``(length, ptr)`` packed form."""
    if enum:
        # no decodeMessage / traverse for an enum; the (length, ptr) packed-form
        # confusion is a message-field-number artefact.  Case names must all look
        # like identifiers, and at least one entry must exist.
        return bool(got) and all(_IDENT_RE.match(f.name) for f in got)
    recovered = {f.number for f in got}
    oracle: set = set()
    if decode_va is not None:
        oracle |= set(_decode_message_numbers(ctx, decode_va))
    if traverse_va is not None:
        oracle |= set(_traverse_field_numbers(ctx, traverse_va))
    if oracle and not oracle <= recovered:
        return False
    if got and all(f.number == len(f.name) for f in got):
        return False
    return True


def _decode_message_numbers(ctx: BinaryContext, decode_va: int) -> List[int]:
    """Field numbers from a ``decodeMessage`` body, read off its ``cmp x0,#N``
    field-number switch (used to supply the number for the single-field
    tail-call shape, where it is not in the nameMap closure).

    Read linearly from the entry to its first return: past it a dense switch's jump-table
    bound (``sub x8, x0, #1; cmp x8, #14``) would be taken for a field number.  A reading of
    the numbers the switch on ``nextFieldNumber()``'s result distinguishes, jump-table arms
    decoded, would replace this (TODO #95)."""
    nums: List[int] = []
    try:
        insns = disasm(ctx, decode_va, max_insns=_INLINE_MAX_INSNS, stop_at_ret=True)
    except (NameError, ImportError):
        raise
    except Exception:
        return nums
    for ins in insns:
        if ins.mnemonic == "cmp":
            v = _parse_imm(ins.op_str)
            if v is not None and 1 <= v <= _MAX_FIELD_NUMBER and v not in nums:
                nums.append(v)
    return nums


def _traverse_field_numbers(ctx: BinaryContext, traverse_va: int) -> List[int]:
    """Field numbers from a ``traverse(visitor:)`` body, in visit order.

    swift-protobuf's ``traverse`` calls ``visitor.visitSingular<T>Field(value:,
    fieldNumber:)`` (direct ``bl`` or protocol-witness ``blr``) for every set
    field, with the field number a literal ``mov w?,#N`` argument.  ``fieldNumber``
    is the last labelled (Int) argument, so among the scalar immediates loaded
    before each call it lands in the HIGHEST-numbered ``w`` register (the value
    arg, if scalar, takes a lower register; float/double values use FP registers
    and consume none).  A call with no such immediate (retain/release, metadata
    accessor ``…Ma``, the generic-table driver) contributes nothing.

    This is the canonical, complete per-field number source (the swift analog of
    PBCodable ``writeTo:``); the nameMap only supplies names.
    """
    try:
        insns = disasm(ctx, traverse_va, max_insns=_INLINE_MAX_INSNS, stop_at_ret=True)
    except (NameError, ImportError):
        raise
    except Exception:
        return []
    nums: List[int] = []
    pend: Dict[str, int] = {}        # w-register -> immediate, since the last call
    for ins in insns:
        m = ins.mnemonic
        if m in ("mov", "movz") and "," in ins.op_str:
            dst, _, src = ins.op_str.partition(",")
            dst = dst.strip()
            v = _parse_imm(src)
            if v is not None and dst.startswith("w") and 1 <= v <= _MAX_FIELD_NUMBER:
                pend[dst] = v
        elif m in ("bl", "blr"):
            if pend:
                hi = max(pend, key=lambda r: int(re.sub(r"\D", "", r) or "-1"))
                nums.append(pend[hi])
            pend = {}
    return nums


def _single_field_tail_call(ctx: BinaryContext, insns, decode_va: Optional[int],
                            traverse_va: Optional[int] = None) -> List[SwiftField]:
    """Shape B: a compact closure that hands ``x2=<name>``, ``w3=<len>`` to a shared builder
    in a tail call.  The single name is an argument cstring whose length is another argument
    of the same tail call (``b`` out of the listing, or ``br``); the number comes from
    ``decodeMessage`` / ``traverse``."""
    name = None
    for _k, regs in call_site_registers(ctx, insns, tail_only=True):
        args = [regs[r] for r in (f"x{n}" for n in range(8)) if r in regs]
        name = next((s for v in args if (s := _cstr(ctx, v))
                     and any(w & 0xFFFFFFFF == len(s) for w in args)), None)
        if name:
            break
    if not name:
        return []
    # The number is NOT in the closure (it carries only name + len + the field's
    # type metadata).  Two INDEPENDENT structural sources can supply it:
    #   * decodeMessage's field-number switch (cmp x0,#N), and
    #   * traverse's per-field visit number (mov w?,#N before visitSingular*).
    # Each is trusted only when it yields exactly ONE field number (a genuine
    # single-field message).  CONFIRM the number iff the trusted sources agree on
    # exactly one value; otherwise fall back to 1 but mark it UNCONFIRMED — a
    # single field is conventionally #1, but that is a guess.  (When a source
    # yields MANY numbers the message is really multi-field and shape-B has
    # under-extracted it — left to the traverse-driven enumerator, to-do #72.)
    cands: set = set()
    if decode_va is not None:
        dn = _decode_message_numbers(ctx, decode_va)
        if len(dn) == 1:
            cands.add(dn[0])
    if traverse_va is not None:
        tn = _traverse_field_numbers(ctx, traverse_va)
        if len(tn) == 1:
            cands.add(tn[0])
    if len(cands) == 1:
        num, confirmed = cands.pop(), True
    else:
        num, confirmed = 1, False
    return [SwiftField(num, name, number_confirmed=confirmed)]


# ── per-type extraction ───────────────────────────────────────────────────────

def _enum_cases_plausible(got: List[SwiftField]) -> bool:
    """Self-consistency of a recovered enum case table.

    protoc-gen-swift writes an enum's name map sorted by case value (aliases share a
    value), with distinct identifier names.  The loose pairing of separate number /
    name stores can scramble a large table, and an enum has no ``decodeMessage`` to
    cross-check against -- so a table that violates the invariant is rejected rather
    than emitted with wrong values."""
    nums = [f.number for f in got]
    names = [f.name for f in got]
    return (bool(got) and nums == sorted(nums) and len(set(names)) == len(names)
            and all(_IDENT_RE.match(n) for n in names))


def _extract_namemap(ctx: BinaryContext, init_va: int,
                     decode_va: Optional[int],
                     traverse_va: Optional[int] = None,
                     enum: bool = False) -> Tuple[List[SwiftField], str]:
    """See :func:`_extract_namemap_raw`; for an enum the result must also pass
    :func:`_enum_cases_plausible`."""
    got, shape = _extract_namemap_raw(ctx, init_va, decode_va, traverse_va, enum)
    if enum and got and not _enum_cases_plausible(got):
        return [], "none"
    return got, shape


def _extract_namemap_raw(ctx: BinaryContext, init_va: int,
                     decode_va: Optional[int],
                     traverse_va: Optional[int] = None,
                     enum: bool = False) -> Tuple[List[SwiftField], str]:
    """Recover one type's (number, name) entries, auto-detecting the lowering.

    Every shape reads the getter's :func:`_listing` -- what its entry reaches, up to its
    returns and tail calls -- so a stub getter (a tail call) is never read on into the
    next function in memory.

    *enum*: the type is a swift ``enum`` (case value <-> case name) rather than a
    message.  The same lowerings are used, but values may be 0 / negative / repeated
    and there is no ``decodeMessage`` to cross-check or single-field default."""
    try:
        insns = _listing(ctx, init_va)
    except (NameError, ImportError):
        raise
    except Exception:
        return [], "none"

    # C — static object: try each address the getter materialises as a static _NameMap blob.
    best: Optional[List[SwiftField]] = None
    for blob in _constant_addresses(insns):
        got = _parse_static_blob(ctx, blob, enum)
        if got and (best is None or len(got) > len(best)):
            best = got
    if best:
        return best, "static"

    # A — inline, directly in this function, or in the function it tail-calls with its
    # registers (CreateML getters: `adrp; add; b <the closure placed next>`).
    got = _walk_inline_closure(ctx, insns, enum)
    callee = None if got else _tail_callee(ctx, insns)
    if callee is not None:
        try:
            got = _walk_inline_closure(ctx, _listing(ctx, callee[0]), enum, entry=callee[1])
        except (NameError, ImportError):
            raise
        except Exception:
            got = []
    if got:
        return got, "inline"

    # Runtime-built _NameMap (once-init `cmn x?,#1; b.ne <builder>`): follow the
    # cold builder closure and read its literal (number, name) table.  Placed
    # before the shape-B fallback, which would under-read such a message to its
    # first field only (e.g. remindd Credential 5 -> 1).  #72.
    got = _runtime_namemap_fields(ctx, insns, enum)
    if len(got) > (0 if enum else 1) and _namemap_builder_validated(
            ctx, got, decode_va, traverse_va, enum):
        return got, "runtime-namemap"
    # a runtime builder with exactly ONE entry is held back: the shape-B single-field
    # path below can confirm the number from decodeMessage/traverse.  If B finds nothing
    # (the well-known wrappers such as BoolValue), the builder's own literal entry is
    # still exact, so it is used -- under the same oracle validation.
    runtime_single = got if (len(got) == 1 and not enum) else None

    # D — shared once-init template (`adr x0,<token>; adr x1,<storage>;
    # adr x2,<builder>; b <shared-template>`): chase every CODE address the stub
    # passes (skipping the once-token / storage data addresses) and read
    # its literal (number, name) table (:func:`_walk_namemap_builder_hop`,
    # which follows one further tail-call when the builder is itself just an
    # arg-setup stub for a second shared template) -- oracle-validated for
    # the same reason as runtime-namemap.  #74.
    best_shared: List[SwiftField] = []
    shared_shape = "shared-once"
    for t in _shared_once_init_targets(insns):
        if t == init_va or not _in_executable_text(ctx, t):
            continue
        got = _walk_namemap_builder_hop(ctx, t, enum)
        single = False
        if not got and not enum:
            got = _single_entry_stub(ctx, t)
            single = bool(got)
        packed = False
        if not got:
            # iOS 27: the builder is a stub passing the packed bytecode literal (x2) and its
            # length (w3) to the shared template (shape E's data, one hop deeper)
            try:
                lit = bytecode_literal_from_getter(ctx, _listing(ctx, t), enum=enum)
            except (NameError, ImportError):
                raise
            except Exception:
                lit = None
            dec = decode_namemap_bytecode(lit, enum=enum) if lit else None
            if dec:
                got = [SwiftField(n, nm) for n, nm in dec]
                packed = True
        if len(got) > len(best_shared):
            best_shared = got
            shared_shape = ("bytecode" if packed else "single-stub" if single else "shared-once")
    if best_shared and (shared_shape == "bytecode"
                        or _namemap_builder_validated(ctx, best_shared, decode_va, traverse_va, enum)):
        return best_shared, shared_shape

    # E — packed-bytecode `_NameMap(bytecode:)` literal (iOS 27 toolchain): the
    # getter hands a string literal + length to a shared template.  Placed after
    # D (whose targets are code addresses; the literal is data, so the two never
    # collide) and before the shape-B fallback, which would read at most one field.
    lit = bytecode_literal_from_getter(ctx, insns, enum=enum)
    if lit is not None:
        decoded = decode_namemap_bytecode(lit, enum=enum)
        if decoded:
            return [SwiftField(n, nm) for n, nm in decoded], "bytecode"

    # A — inline, in the closure the getter passes a call (device getter → swift_once).
    for t in _closure_arg_targets(ctx, insns):
        if t == init_va:
            continue
        try:
            cl = _listing(ctx, t)
        except (NameError, ImportError):
            raise
        except Exception:
            continue
        got = _walk_inline_closure(ctx, cl, enum)
        if got:
            return got, "inline-closure"
        if enum:
            continue
        # B — single-field tail-call inside the followed closure.
        got = _single_field_tail_call(ctx, cl, decode_va, traverse_va)
        if got:
            return got, "single"

    # B — single-field tail-call directly in this function.  Not for an enum: its
    # single-field number comes from a message's decodeMessage, which an enum lacks.
    if enum:
        return [], "none"
    got = _single_field_tail_call(ctx, insns, decode_va, traverse_va)
    if got:
        return got, "single"
    if runtime_single and _namemap_builder_validated(ctx, runtime_single, decode_va, traverse_va):
        return runtime_single, "runtime-single"
    return [], "none"


# ── top-level ─────────────────────────────────────────────────────────────────

def swift_messages(ctx: BinaryContext) -> List[SwiftMessage]:
    """Recover every swift-protobuf MESSAGE's field names + numbers (and, from
    reflection metadata, types).

    Returns one :class:`SwiftMessage` per struct type with a recovered nameMap,
    sorted by qualified name.  Works both from a standalone binary (LC_SYMTAB /
    export trie) and cache-native (the ``.symbols`` sub-cache); empty only when no
    symbol source resolves the per-type nameMap symbols.  Enums are separate:
    :func:`swift_enums`."""
    return _recover_types(ctx, want_enum=False)


def swift_enums(ctx: BinaryContext) -> List[SwiftMessage]:
    """Recover every swift-protobuf ENUM's cases (``fields`` = (value, name), value
    may be 0, negative, or shared by an alias) with ``is_enum=True``.  Same symbol
    sources and lowerings as :func:`swift_messages`; the enum's case-value table is
    its ``_protobuf_nameMap``."""
    return _recover_types(ctx, want_enum=True)


def _recover_types(ctx: BinaryContext, want_enum: bool) -> List[SwiftMessage]:
    syms = symbol_addrs(ctx)
    if not syms:
        return []

    # init point per type: prefer the `_WZ` static-init function, else the
    # `vgZ` static getter (the device/framework form).
    inits: Dict[Tuple[str, str], Tuple[int, str]] = {}
    decoders: Dict[Tuple[str, str], int] = {}
    traversers: Dict[Tuple[str, str], int] = {}
    for name, va in syms.items():
        if _NAMEMAP_MARKER in name:
            p = _parse_namemap_symbol(name)
            if not p or p[2] != want_enum:
                continue
            parsed = (p[0], p[1])
            if name.endswith("_WZ"):
                inits[parsed] = (va, "WZ")
            elif name.endswith("vgZ") and parsed not in inits:
                inits[parsed] = (va, "vgZ")
        elif want_enum:
            continue
        elif "13decodeMessage" in name and name.endswith("F"):
            parsed = _type_from_namemap_symbol_like(name, "V13decodeMessage")
            if parsed:
                decoders.setdefault(parsed, va)
        elif "V8traverse" in name and name.endswith("F"):
            parsed = _type_from_namemap_symbol_like(name, "V8traverse")
            if parsed:
                traversers.setdefault(parsed, va)

    out: List[SwiftMessage] = []
    for (module, tname), (va, _kind) in inits.items():
        fields, shape = _extract_namemap(ctx, va, decoders.get((module, tname)),
                                         traversers.get((module, tname)),
                                         enum=want_enum)
        out.append(SwiftMessage(module=module, name=tname, fields=fields,
                                is_enum=want_enum, shape=shape))
    if not want_enum:
        _attach_field_types(ctx, out)
    out.sort(key=lambda m: m.qualified)
    return out


def _norm(name: str) -> str:
    """Normalise a field name for the snake_case (nameMap) <-> camelCase (Swift
    field metadata) join: drop underscores, lowercase."""
    return name.replace("_", "").lower()


# Readings with no cross-check of their own (one builder entry / one stub entry): kept only
# when Swift reflection agrees the message has that field.
_REFLECTION_CONFIRMED_SHAPES = frozenset({"runtime-single", "single-stub"})


def _attach_field_types(ctx: BinaryContext, msgs: List[SwiftMessage]) -> None:
    """Recover field TYPES from Swift field metadata and bind them onto the
    name+number fields by normalised field name (best-effort; leaves proto_type
    None where metadata is absent).  ``swift_type_recovery.collect_field_types``
    supplies types from the message struct, its COW ``_StorageClass``, and its
    ``OneOf_*`` enums (#60), so oneof/storage-backed fields are now covered too."""
    try:
        from serializers import swift_type_recovery
        by_type, incomplete, fieldless = swift_type_recovery.collect_field_types(ctx)
    except (NameError, ImportError):
        raise
    except Exception as exc:
        from proto.models import get_diagnostics
        get_diagnostics(ctx).foreign_errors.append(
            ("swift-protobuf", f"field types: {type(exc).__name__}: {exc}"))
        log.warning("swift-protobuf field-type recovery FAILED (%s: %s); field types missing",
                    type(exc).__name__, exc)
        return
    for m in msgs:
        if m.shape in _REFLECTION_CONFIRMED_SHAPES and m.fields:
            # single-entry readings whose only support is the literal itself: the struct's
            # reflection must list that field, or the reading is another type's
            # (e.g. an empty message whose getter reaches a sibling's closure).
            refl = {_norm(k) for k in by_type.get(m.name, {})}
            if _norm(m.fields[0].name) not in refl:
                m.fields, m.shape = [], "none"
        if not m.fields and m.name in fieldless:
            m.fieldless = True
    if not by_type:
        return
    # the type map is keyed by the type's QUALIFIED name (Outer.Inner); look up by
    # the message's full name first.  Fall back to a short-name match ONLY when it
    # is UNAMBIGUOUS — several messages can share a nested short name (e.g.
    # `MigrateResponse.Details` vs `StartMigrationResponse.Details`), and binding to
    # an arbitrary one of them would mis-type fields (#68).
    for m in msgs:
        types = by_type.get(m.name)
        inc = incomplete.get(m.name, set())
        if types is None:
            short = m.name.split(".")[-1]
            cands = [(k, v) for k, v in by_type.items() if k.split(".")[-1] == short]
            if len(cands) == 1:
                types, inc = cands[0][1], incomplete.get(cands[0][0], set())
        if not types:
            continue
        norm = {_norm(k): v for k, v in types.items()}
        norm_inc = {_norm(k) for k in inc}
        for f in m.fields:
            key = _norm(f.name)
            t = norm.get(key)
            if t:
                f.proto_type = t
                if key in norm_inc:
                    f.type_note = ("swift-protobuf: container element/value type "
                                   "not recovered (shown as bytes)")


def _type_from_namemap_symbol_like(sym: str, marker: str) -> Optional[Tuple[str, str]]:
    """``(module, type_name)`` like :func:`_parse_namemap_symbol`, for an arbitrary
    ``V<marker>`` boundary (e.g. ``V13decodeMessage``)."""
    m = re.search(r"_\$[sS](.*?)" + re.escape(marker), sym)
    if not m:
        return None
    idents = _split_idents(m.group(1))
    if len(idents) < 2:
        return None
    return idents[0], ".".join(idents[1:])


# ── emit ──────────────────────────────────────────────────────────────────────

def format_proto(messages: List[SwiftMessage]) -> str:
    """Render recovered messages as a partial ``.proto`` (field names + numbers;
    TYPES are not recovered for swift-protobuf — see module docstring)."""
    lines = [
        "// swift-protobuf schema recovered from the binary.",
        "// Field NAMES and NUMBERS only — wire types are not recoverable from",
        "// swift-protobuf (generic Visitor/Decoder witness calls carry no named",
        "// type symbol).  Types shown as `???`.",
        'syntax = "proto2";',
        "",
    ]
    for m in messages:
        kw = "enum" if m.is_enum else "message"
        if not m.fields:
            lines.append(f"{kw} {m.name} {{}}")
            lines.append("")
            continue
        lines.append(f"{kw} {m.name} {{")
        for f in sorted(m.fields, key=lambda x: x.number):
            est = "" if f.number_confirmed else "  // number estimated"
            if m.is_enum:
                lines.append(f"  {f.name} = {f.number};{est}")
            else:
                lines.append(f"  optional ??? {f.name} = {f.number};{est}")
        lines.append("}")
        lines.append("")
    return "\n".join(lines)


# ── fat-binary slice helper + CLI ─────────────────────────────────────────────

_FAT_MAGIC_BE = 0xCAFEBABE
_FAT_MAGIC_64_BE = 0xCAFEBABF
_CPU_TYPE_ARM64 = 0x0100000C


def load_macho_slice(data: bytes, prefer=("arm64e", "arm64")) -> bytes:
    """Return a single-arch Mach-O slice from *data*, picking the preferred arm64
    slice from a fat binary; returns *data* unchanged if already thin."""
    if len(data) < 8:
        return data
    magic = struct.unpack_from(">I", data, 0)[0]
    if magic not in (_FAT_MAGIC_BE, _FAT_MAGIC_64_BE):
        return data
    wide = magic == _FAT_MAGIC_64_BE
    nfat = struct.unpack_from(">I", data, 4)[0]
    entry = 32 if wide else 20
    best: Optional[Tuple[int, int, int]] = None   # (rank, offset, size)
    for i in range(nfat):
        o = 8 + i * entry
        if o + entry > len(data):
            break
        cputype = struct.unpack_from(">I", data, o)[0]
        cpusub = struct.unpack_from(">I", data, o + 4)[0]
        if wide:
            off = struct.unpack_from(">Q", data, o + 8)[0]
            size = struct.unpack_from(">Q", data, o + 16)[0]
        else:
            off = struct.unpack_from(">I", data, o + 8)[0]
            size = struct.unpack_from(">I", data, o + 12)[0]
        if cputype != _CPU_TYPE_ARM64:
            continue
        is_e = (cpusub & 0x00FFFFFF) == 2
        rank = 0 if (is_e and prefer[0] == "arm64e") else 1
        if best is None or rank < best[0]:
            best = (rank, off, size)
    if best and best[1] + best[2] <= len(data):
        return data[best[1]:best[1] + best[2]]
    return data


def _main(argv: List[str]) -> int:
    import argparse
    ap = argparse.ArgumentParser(
        description="Recover swift-protobuf message field names+numbers from a "
                    "Mach-O binary (types not recovered).")
    ap.add_argument("binary", help="path to a Mach-O (fat or thin)")
    ap.add_argument("--all-shapes", action="store_true",
                    help="annotate each message with the codegen lowering detected")
    args = ap.parse_args(argv)

    with open(args.binary, "rb") as fh:
        data = load_macho_slice(fh.read())
    try:
        ctx = BinaryContext(data)
    except ValueError as e:
        print(f"error: {e}")
        return 2
    msgs = swift_messages(ctx)
    if not msgs:
        print("no swift-protobuf nameMaps found "
              "(not a swift-protobuf binary, or symbols stripped)")
        return 1
    print(format_proto(msgs))
    if args.all_shapes:
        print("// --- shapes ---")
        for m in msgs:
            print(f"//   {m.qualified}: {len(m.fields)} field(s) [{m.shape}]")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(_main(sys.argv[1:]))
