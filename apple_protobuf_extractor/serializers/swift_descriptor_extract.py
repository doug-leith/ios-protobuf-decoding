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
  shared template (:func:`_walk_namemap_builder_hop` follows that one extra
  hop, concatenating the stub's setup with the template's body since the
  template starts with empty register state on its own).

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

The residual swift type/number estimates (and which are flagged) are catalogued
in LIMITATIONS.md (10) / to-do #63a/#63b/#66/#67/#68/#70.
"""
from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from macho.memory import BinaryContext
from macho.disasm import disasm
from serializers.swift_type_recovery import demangle_idents
from serializers.swift_namemap_bytecode import (
    bytecode_literal_from_getter, decode_namemap_bytecode)

# Max proto field number (29-bit) and a sane name-length ceiling — used to
# validate candidate (number, name, len) triples when scanning static blobs.
_MAX_FIELD_NUMBER = 0x1FFFFFFF
_MAX_NAME_LEN = 80
_NAMEMAP_MARKER = "17_protobuf_nameMap"
# Runaway guard for the inline-closure walk; `stop_at_ret` is the real
# terminator and the next-symbol extent tightens this further when known.
_INLINE_MAX_INSNS = 4000


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


def _type_from_namemap_symbol(sym: str) -> Optional[Tuple[str, str]]:
    """``…_protobuf_nameMap`` symbol → ``(module, type_name)`` (type may be
    dotted for nested types), or None."""
    m = re.search(r"_\$[sS](.*?)V" + _NAMEMAP_MARKER, sym)
    if not m:
        return None
    idents = _split_idents(m.group(1))
    if len(idents) < 2:
        return None
    return idents[0], ".".join(idents[1:])


# ── small disasm helpers ──────────────────────────────────────────────────────

def _imm(op_str: str) -> Optional[int]:
    m = re.search(r"#(-?0x[0-9a-fA-F]+|-?\d+)", op_str)
    if not m:
        return None
    v = m.group(1)
    try:
        return int(v, 16) if "0x" in v.lower() else int(v)
    except ValueError:
        return None


def _adr_target(insn) -> Optional[int]:
    if insn.mnemonic in ("adr", "adrp"):
        return _imm(insn.op_str)
    return None


def _cstr(ctx: BinaryContext, va: int) -> Optional[str]:
    for cand in (va, va & 0x7FFFFFFFF):
        try:
            s = ctx.read_cstring(cand, _MAX_NAME_LEN + 16)
        except Exception:
            continue
        if s and all(32 <= ord(c) < 127 for c in s):
            return s
    return None


def _adrp_add_targets(insns) -> List[int]:
    """Every ``adrp Xn,#page`` + ``add Xn,Xn,#off`` page+offset target."""
    out: List[int] = []
    for i, ins in enumerate(insns):
        if ins.mnemonic != "adrp":
            continue
        reg = ins.op_str.split(",", 1)[0].strip()
        page = _adr_target(ins)
        if page is None:
            continue
        for nxt in insns[i + 1:i + 5]:
            if nxt.mnemonic == "add" and nxt.op_str.split(",", 1)[0].strip() == reg:
                off = _imm(nxt.op_str)
                if off is not None:
                    out.append(page + off)
                break
    return out


# ── shape C: static-object blob ───────────────────────────────────────────────

def _parse_enum_blob(ctx: BinaryContext, buf: bytes, count: int) -> Optional[List[SwiftField]]:
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
        nptr = struct.unpack_from("<Q", buf, off + 8)[0]
        ln = struct.unpack_from("<Q", buf, off + 16)[0]
        if not (-(1 << 31) <= num < (1 << 31)) or not 1 <= ln <= _MAX_NAME_LEN:
            return None
        nm = _cstr(ctx, nptr)
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
        except Exception:
            continue
    if not buf:
        return None
    if enum:
        return _parse_enum_blob(ctx, buf, count)
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
        nptr = struct.unpack_from("<Q", buf, off + 8)[0]
        ln = struct.unpack_from("<Q", buf, off + 16)[0]
        if 1 <= ln <= _MAX_NAME_LEN:
            nm = _cstr(ctx, nptr)
            key = (num, nm) if enum else num
            if (nm and ln == len(nm) and key not in seen
                    and (not enum or _IDENT_RE.match(nm))):
                seen.add(key)
                out.append(SwiftField(num, nm))
                off += 16          # skip the matched (name ptr, len) slots
        off += 8
    return out or None


# ── shapes A/B: inline closure / single-field tail-call ───────────────────────

_MOVK_RE = re.compile(r"(\w+),\s*#(-?0x[0-9a-fA-F]+|-?\d+),\s*lsl\s*#(\d+)")


def _movk(reg_imm: Dict[str, int], op_str: str) -> None:
    """``movk wN,#imm,lsl #sh`` -- insert 16 bits into an already-known immediate
    (a value that does not fit one ``mov``, e.g. an enum value of 100000)."""
    m = _MOVK_RE.match(op_str.strip())
    if not m:
        return
    reg = m.group(1).replace("x", "w")
    if reg not in reg_imm:
        return
    sh = int(m.group(3))
    reg_imm[reg] = (reg_imm[reg] & ~(0xFFFF << sh)) | ((int(m.group(2), 0) & 0xFFFF) << sh)


def _walk_inline_closure(ctx: BinaryContext, insns, enum: bool = False) -> List[SwiftField]:
    """Shape A: each entry is ``mov w,#<num>; str x,[base]`` (number stored at
    the entry's slot-0) plus ``<name-load>; mov w,#<len>; stp x,x,[entry]``
    (name pointer + length).  The length-check pins names to real entries.

    The name pointer is loaded either as a single ``adr x,<name>`` (close
    cstrings, the standalone-binary form) OR as ``adrp x,#page; add x,x,#off``
    (the device / cache form, where the name pool is >1 MB away — far beyond
    ``adr`` reach).  Both are resolved here."""
    reg_imm: Dict[str, int] = {}
    reg_str: Dict[str, Optional[str]] = {}
    adrp_page: Dict[str, int] = {}
    entries: List[SwiftField] = []
    cur_num: Optional[int] = None
    for ins in insns:
        m, o = ins.mnemonic, ins.op_str
        if m in ("mov", "movz"):
            parts = o.split(",")
            if len(parts) == 2:
                v = _imm(parts[1])
                if v is not None:
                    dst = parts[0].strip().replace("x", "w")
                    reg_imm[dst] = v
                    adrp_page.pop(dst.replace("w", "x"), None)
        elif m == "movk":
            _movk(reg_imm, o)
        elif m == "adrp":
            reg = o.split(",", 1)[0].strip()
            page = _adr_target(ins)
            if page is not None:
                adrp_page[reg] = page
            reg_str.pop(reg, None)
        elif m == "adr":
            va = _adr_target(ins)
            reg_str[o.split(",", 1)[0].strip().replace("w", "x")] = (
                _cstr(ctx, va) if va is not None else None
            )
        elif m == "add":
            # adrp/add page+offset -> resolve to the name cstring it points at.
            mm = re.match(r"(\w+),\s*(\w+),\s*#(-?0x[0-9a-fA-F]+|-?\d+)$", o)
            if mm and mm.group(2) in adrp_page:
                off = _imm("#" + mm.group(3))
                if off is not None:
                    reg_str[mm.group(1)] = _cstr(ctx, adrp_page[mm.group(2)] + off)
        elif m == "str":
            mm = re.match(r"(\w+),\s*\[(\w+)\]$", o)
            if mm:
                if enum and mm.group(1) in ("xzr", "wzr"):
                    cur_num = 0           # enum value 0 is stored from the zero register
                else:
                    cur_num = reg_imm.get(mm.group(1).replace("x", "w"))
        elif m == "stp":
            mm = re.match(r"(\w+),\s*(\w+),\s*\[(\w+)", o)
            if mm:
                nm = reg_str.get(mm.group(1).replace("w", "x"))
                ln = reg_imm.get(mm.group(2).replace("x", "w"))
                if nm and ln == len(nm) and cur_num is not None:
                    entries.append(SwiftField(cur_num, nm))
    return entries


def _walk_namemap_builder(ctx: BinaryContext, insns, enum: bool = False) -> List[SwiftField]:
    """Runtime-built ``_NameMap``: read the ``(fieldNumber, name)`` table the cold
    builder writes into its freshly-allocated buffer.  swift-protobuf emits the
    entries in (at least) three store shapes, all of which carry the number and the
    name literally — only the instruction encoding differs:

      A. combined ``stp <wNum>, <xName>, [base,#off]`` (number first, name second);
         the per-entry length lives in a separate 16-byte ``_NameDescription`` const.
      B. split ``str <wNum>, [base,#off]`` + ``str <xName>, [base,#off+8]`` (the tail
         entry is sometimes lowered this way instead of a combined ``stp``).
      C. packed/parallel form: ``str <wNum>, [keybase]`` into a number array and a
         separate ``stp <xName>, <wLen>, [namebase]`` (name first, LENGTH second)
         into a parallel name array.

    The ``stp`` cases A and C are disambiguated by OPERAND POSITION (name is the
    2nd operand in A, the 1st in C) — NOT by value, because a field whose number
    equals its name length (e.g. ``Field.name`` = #4, ``len('name')`` = 4) would be
    misclassified otherwise.  A/B entries pair directly; C's separate number stores
    are zipped with its name stores in program order (which the compiler emits
    consistently per field).

    *enum*: the entries are enum cases.  A case value may be 0 (stored from the zero
    register, ``str xzr,[…]``), negative or repeated (an alias), so the field-number
    range filter and the unique-number dedupe do not apply; both are unsafe to relax
    for messages, where a zero store is unrelated bookkeeping."""
    reg_imm: Dict[str, int] = {}
    reg_str: Dict[str, Optional[str]] = {}
    adrp_page: Dict[str, int] = {}
    paired: List[SwiftField] = []        # A/B: number + name bound at the store
    loose_names: List[str] = []          # C: name-only stores (number is separate)
    loose_nums: List[int] = []           # C: standalone number stores
    seen: set = set()

    def _clear(reg: str) -> None:
        rx, rw = reg.replace("w", "x"), reg.replace("x", "w")
        reg_imm.pop(rw, None)
        reg_str.pop(rx, None)
        adrp_page.pop(rx, None)

    def _bind(num, nm) -> None:
        if not nm or num is None:
            return
        if enum:
            ok, key = -(1 << 31) <= num < (1 << 31), (num, nm)
        else:
            ok, key = 1 <= num <= _MAX_FIELD_NUMBER, num
        if ok and key not in seen:
            seen.add(key)
            paired.append(SwiftField(num, nm))

    for ins in insns:
        m, o = ins.mnemonic, ins.op_str
        if m == "movk":
            _movk(reg_imm, o)
        elif m in ("mov", "movz"):
            parts = o.split(",")
            if len(parts) == 2:
                dst_raw, src_raw = parts[0].strip(), parts[1].strip()
                dst = dst_raw.replace("x", "w")
                v = _imm(src_raw)
                if v is not None:
                    _clear(dst)
                    reg_imm[dst] = v
                elif re.fullmatch(r"[wx]\d+", src_raw):
                    # Register-to-register copy (e.g. a callee-saved-register
                    # save at a call site): propagate whichever value the
                    # source register carries so it survives the copy -- some
                    # builders stage the name/len args through a fresh
                    # register before the actual store (shape D, #74).
                    src_x, src_w = src_raw.replace("w", "x"), src_raw.replace("x", "w")
                    _clear(dst)
                    if src_x in reg_str:
                        reg_str[dst.replace("w", "x")] = reg_str[src_x]
                    elif src_w in reg_imm:
                        reg_imm[dst] = reg_imm[src_w]
        elif m == "adrp":
            reg = o.split(",", 1)[0].strip()
            page = _adr_target(ins)
            _clear(reg)
            if page is not None:
                adrp_page[reg] = page
        elif m == "adr":
            reg = o.split(",", 1)[0].strip()
            _clear(reg)
            va = _adr_target(ins)
            reg_str[reg.replace("w", "x")] = _cstr(ctx, va) if va is not None else None
        elif m == "add":
            mm = re.match(r"(\w+),\s*(\w+),\s*#(-?0x[0-9a-fA-F]+|-?\d+)$", o)
            if mm and mm.group(2) in adrp_page:
                off = _imm("#" + mm.group(3))
                if off is not None:
                    s = _cstr(ctx, adrp_page[mm.group(2)] + off)
                    _clear(mm.group(1))
                    reg_str[mm.group(1).replace("w", "x")] = s
        elif m == "stp":
            mm = re.match(r"(\w+),\s*(\w+),\s*\[", o)
            if mm:
                a, b = mm.group(1), mm.group(2)
                a_str, b_str = reg_str.get(a.replace("w", "x")), reg_str.get(b.replace("w", "x"))
                a_imm, b_imm = reg_imm.get(a.replace("x", "w")), reg_imm.get(b.replace("x", "w"))
                if b_str and a_imm is not None:       # A: stp <num>, <name>
                    _bind(a_imm, b_str)
                elif a_str and b_imm is not None:     # C: stp <name>, <len>
                    loose_names.append(a_str)
                elif a_str or b_str:                  # name with no imm partner
                    loose_names.append(a_str or b_str)
        elif m == "str":
            mm = re.match(r"(\w+),\s*\[(\w+)", o)
            if mm and enum and mm.group(2) == "sp":
                continue                              # enum: a stack spill, not a table entry
            if mm:
                r = mm.group(1)
                s = reg_str.get(r.replace("w", "x"))
                v = reg_imm.get(r.replace("x", "w"))
                if enum and r in ("xzr", "wzr"):
                    loose_nums.append(0)              # enum value 0 (zero register)
                elif s is not None:                   # B/C: lone name pointer
                    loose_names.append(s)
                elif v is not None and (enum or 1 <= v <= _MAX_FIELD_NUMBER):
                    loose_nums.append(v)              # B/C: standalone number
    for num, nm in zip(loose_nums, loose_names):      # pair C/B leftovers by order
        _bind(num, nm)
    return paired


def _in_executable_text(ctx: BinaryContext, va: int) -> bool:
    """True when *va* lands inside this image's own executable code section
    (as opposed to a data address, e.g. a once-token or a storage slot)."""
    if not ctx.has_section("__TEXT", "__text"):
        return False
    sec = ctx.section("__TEXT", "__text")
    return sec.vmaddr <= va < sec.vmaddr + sec.vmsize


def _shared_once_init_targets(insns) -> List[int]:
    """Shape D: a short ``adr`` x2/x3 + unconditional-branch dispatch into a
    lazy-once-init TEMPLATE shared across many unrelated types (device /
    newer-toolchain ``static let`` lowering).  The branch target itself
    carries no type information -- it is the same shared function for every
    type -- but one of the ``adr``'d values is the type's own builder
    function (the others are a once-token and the type's ``_NameMap``
    storage slot).

    Only matches the MINIMAL dispatch shape: nothing but straight-line
    address materialisation (``adr``, or ``adrp``+``add`` page+offset) and
    ``nop`` before the tail ``b``.  A once-init getter with its own inline
    fast/cold path (:func:`_runtime_namemap_fields`'s shape) reaches a
    conditional branch (``cmn``/``b.ne`` etc.) first and is rejected here --
    without this gate, an `adr` sitting anywhere later in that LONGER function
    (its cold path, e.g.) would be wrongly treated as a shape-D builder
    reference (#74 regression: remindd's UnmigrateRequest picked up its sibling
    `Option` enum's builder this way).

    The once-token and storage slot live in ``__DATA`` and are routinely out
    of ``adr`` reach (+-1 MB), so the compiler materialises them with
    ``adrp``+``add``; only the builder -- a nearby function -- is a plain
    ``adr``.  A getter such as ``adrp x0; add x0; adrp x1; add x1; adr x2;
    nop; b`` (iOS 16 TrustedPeersHelper) is therefore the same minimal shape.
    The ``adrp``+``add`` results are returned too (a far-away builder is
    materialised the same way); callers filter to code addresses with
    :func:`_in_executable_text`, which drops the data token/slot."""
    out: List[int] = []
    page: Dict[str, int] = {}
    for ins in insns:
        m = ins.mnemonic
        if m == "adr":
            t = _adr_target(ins)
            if t is not None:
                out.append(t)
        elif m == "adrp":
            p = _adr_target(ins)
            if p is not None:
                page[ins.op_str.split(",", 1)[0].strip()] = p
        elif m == "add":
            mm = re.match(r"(\w+),\s*(\w+),\s*#(-?0x[0-9a-fA-F]+|-?\d+)$", ins.op_str)
            if mm and mm.group(2) in page:
                off = _imm("#" + mm.group(3))
                if off is not None:
                    out.append(page[mm.group(2)] + off)
        elif m == "b":
            return out
        elif m != "nop":
            return []   # any other control flow -> not the minimal dispatch shape
    return []


def _walk_namemap_builder_hop(ctx: BinaryContext, va: int,
                              enum: bool = False) -> List[SwiftField]:
    """Read one builder's (number, name) table, following ONE extra tail-call
    hop when the builder is itself just an arg-setup stub (``adr x1,<storage>;
    adr x2,<name>; mov w3,<len>; b <template>``) for a second, arity-specific
    shared template that does the actual stores.  When the template happens
    to sit immediately after the stub in memory, a single ``stop_at_ret``
    disasm from *va* already covers both (the register state flows through
    naturally); when it doesn't, CONCATENATE the stub's own setup
    instructions with the template's body before walking, so the args it
    staged into registers are still live when the template stores them --
    disassembling the template alone starts with empty register state and
    loses them."""
    try:
        body = disasm(ctx, va, max_insns=600, stop_at_ret=True)
    except Exception:
        return []
    got = _walk_namemap_builder(ctx, body, enum)
    if got:
        return got
    setup: List = []
    for ins in body:
        if ins.mnemonic == "b":
            t = _imm(ins.op_str)
            if t is None or t == va:
                return []
            try:
                inner = disasm(ctx, t, max_insns=600, stop_at_ret=True)
            except Exception:
                return []
            return _walk_namemap_builder(ctx, setup + inner, enum)
        setup.append(ins)
        if len(setup) > 12:
            return []
    return []


_RET_MNEMONICS = ("ret", "retab", "retaa")


def _disasm_hit_cap(body, cap: int) -> bool:
    """True when a ``stop_at_ret`` disasm ran to its *cap* WITHOUT reaching a
    ret-family instruction — i.e. the function body extends past what we read, so
    anything decoded from it may be INCOMPLETE.  (A complete function stops at the
    ret, which disasm includes, so it ends on a ret mnemonic and/or is shorter than
    the cap.)"""
    return bool(body) and len(body) >= cap and body[-1].mnemonic not in _RET_MNEMONICS


_CLOSURE_ARG_REGS = ("x1", "x9", "x16")


def _closure_arg_targets(ctx: BinaryContext, insns) -> List[int]:
    """Code addresses an init/once closure is passed in (``x1``/``x9``/``x16``):
    ``adr xN,<closure>`` when it is within +-1 MB, else ``adrp xN,#page; add
    xN,xN,#off`` (device / cache form, where the closure sits far from the
    getter).  ``adrp``+``add`` results are kept only when they land in this
    image's executable text, so a once-token or storage slot in ``__DATA``
    (also materialised that way, usually in ``x0``/``x1``) is never mistaken
    for a builder."""
    out: List[int] = []
    page: Dict[str, int] = {}
    for ins in insns:
        reg = ins.op_str.split(",", 1)[0].strip()
        if ins.mnemonic == "adr" and reg in _CLOSURE_ARG_REGS:
            t = _adr_target(ins)
            if t is not None:
                out.append(t)
        elif ins.mnemonic == "adrp":
            p = _adr_target(ins)
            if p is not None:
                page[reg] = p
        elif ins.mnemonic == "add" and reg in _CLOSURE_ARG_REGS:
            mm = re.match(r"(\w+),\s*(\w+),\s*#(-?0x[0-9a-fA-F]+|-?\d+)$", ins.op_str)
            if mm and mm.group(2) in page:
                off = _imm("#" + mm.group(3))
                if off is not None and _in_executable_text(ctx, page[mm.group(2)] + off):
                    out.append(page[mm.group(2)] + off)
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
    # Candidate builder/closure entry points: cold-path branch targets + any
    # directly-referenced closure address.
    targets: List[int] = []
    for ins in getter_insns:
        if ins.mnemonic.startswith("b.") or ins.mnemonic in ("b", "cbz", "cbnz"):
            t = _imm(ins.op_str)
            if t is not None:
                targets.append(t)
    targets += _closure_arg_targets(ctx, getter_insns)
    best: List[SwiftField] = []
    best_truncated = False
    for t in targets:
        try:
            body = disasm(ctx, t, max_insns=400, stop_at_ret=True)
        except Exception:
            continue
        got = _walk_namemap_builder(ctx, body, enum)
        trunc = _disasm_hit_cap(body, 400)
        if not got:
            # the builder is often reached one hop on, via `adr x1,<closure>`.
            for ct in _closure_arg_targets(ctx, body):
                try:
                    inner = disasm(ctx, ct, max_insns=400, stop_at_ret=True)
                except Exception:
                    got = []
                    continue
                got = _walk_namemap_builder(ctx, inner, enum)
                trunc = _disasm_hit_cap(inner, 400)
                if not got:
                    # the closure may itself be only an arg-setup stub that tail-calls
                    # the real builder (the Google well-known wrappers do)
                    got = _walk_namemap_builder_hop(ctx, ct, enum)
                if got:
                    break
        if len(got) > len(best):
            best = got
            best_truncated = trunc
    # CAUTIOUS: if the builder body overran the disasm window, its (number, name)
    # store table may be incomplete.  Rather than launder a partial read as
    # ground truth, flag the recovered numbers as estimated (renders
    # "// number estimated") so a truncated read is never presented as confirmed.
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
        insns = disasm(ctx, va, max_insns=16, stop_at_ret=False)
    except Exception:
        return []
    page: Dict[str, int] = {}
    regs: Dict[str, int] = {}
    imm: Dict[str, int] = {}
    for ins in insns:
        m, o = ins.mnemonic, ins.op_str
        parts = [x.strip() for x in o.split(",")]
        if m == "adrp":
            page[parts[0]] = _adr_target(ins)
        elif m == "adr":
            regs[parts[0]] = _adr_target(ins)
        elif m == "add":
            mm = re.match(r"(\w+),\s*(\w+),\s*#(-?0x[0-9a-fA-F]+|-?\d+)$", o)
            if mm and page.get(mm.group(2)) is not None:
                regs[mm.group(1)] = page[mm.group(2)] + int(mm.group(3), 0)
        elif m in ("mov", "movz") and len(parts) == 2 and _imm(parts[1]) is not None:
            imm[parts[0]] = _imm(parts[1])
        elif m == "b":
            break
        elif m != "nop":
            return []
    if "x3" not in regs or "w2" not in imm or "w4" not in imm:
        return []
    name = _cstr(ctx, regs["x3"])
    if not name or len(name) != imm["w4"] or not 1 <= imm["w2"] <= _MAX_FIELD_NUMBER:
        return []
    return [SwiftField(imm["w2"], name)]


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
    tail-call shape, where it is not in the nameMap closure)."""
    nums: List[int] = []
    try:
        insns = disasm(ctx, decode_va, max_insns=400, stop_at_ret=True)
    except Exception:
        return nums
    for ins in insns:
        if ins.mnemonic == "cmp":
            v = _imm(ins.op_str)
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
    except Exception:
        return []
    nums: List[int] = []
    pend: Dict[str, int] = {}        # w-register -> immediate, since the last call
    for ins in insns:
        m = ins.mnemonic
        if m in ("mov", "movz") and "," in ins.op_str:
            dst, _, src = ins.op_str.partition(",")
            dst = dst.strip()
            v = _imm(src)
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
    """Shape B: a compact closure that loads ``x2=<name>``, ``w3=<len>`` and
    tail-calls a shared builder.  The single name is the cstring whose length
    matches an immediate; the number comes from ``decodeMessage``.

    The name pointer is loaded either as a single ``adr`` (standalone-binary
    form) or as ``adrp x,#page; add x,x,#off`` (device / cache form) — both are
    collected (cache name pools sit past ``adr`` reach)."""
    # Collect immediates and name cstrings up to the tail branch, THEN pair the
    # name to a length immediate (the `mov #len` may follow the name load).
    imms: set = set()
    names: List[str] = []
    adrp_page: Dict[str, int] = {}
    for ins in insns:
        if ins.mnemonic in ("mov", "movz"):
            v = _imm(ins.op_str.split(",", 1)[1]) if "," in ins.op_str else None
            if v is not None:
                imms.add(v)
        elif ins.mnemonic == "adrp":
            reg = ins.op_str.split(",", 1)[0].strip()
            page = _adr_target(ins)
            if page is not None:
                adrp_page[reg] = page
        elif ins.mnemonic == "adr":
            va = _adr_target(ins)
            s = _cstr(ctx, va) if va is not None else None
            if s:
                names.append(s)
        elif ins.mnemonic == "add":
            mm = re.match(r"(\w+),\s*(\w+),\s*#(-?0x[0-9a-fA-F]+|-?\d+)$", ins.op_str)
            if mm and mm.group(2) in adrp_page:
                off = _imm("#" + mm.group(3))
                if off is not None:
                    s = _cstr(ctx, adrp_page[mm.group(2)] + off)
                    if s:
                        names.append(s)
        elif ins.mnemonic in ("b", "br"):
            break
    name = next((s for s in names if len(s) in imms), None)
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

_STUB_OK = frozenset({"adr", "adrp", "add", "mov", "movz", "movk", "nop", "paciza", "pacia"})


def _is_dispatch_stub(insns, max_len: int = 16) -> bool:
    """True when the function is just straight-line address/constant setup ending in
    a tail-call ``b`` (``adrp/add …; mov w3,#len; b <shared template>``).

    Such a getter contains no table of its own: the (number, name) data is in the
    function it passes (shape D), in a literal it passes (shape E) or in a static
    blob (shape C).  The inline shapes (A, runtime) walk a function 'until ret', and
    a stub has no ``ret`` -- so they would run on into the NEXT function in memory and
    read its table as this type's.  Callers skip those shapes for a stub."""
    for i, ins in enumerate(insns[:max_len]):
        if ins.mnemonic == "b":
            # `b <next instruction>` is a fall-through the linker left behind, not a
            # tail call: the code that follows is this function's own body.
            addr, tgt = getattr(ins, "addr", None), _imm(ins.op_str)
            if addr is not None and tgt == addr + 4:
                continue
            return i > 0
        if ins.mnemonic not in _STUB_OK:
            return False
    return False


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

    *enum*: the type is a swift ``enum`` (case value <-> case name) rather than a
    message.  The same lowerings are used, but values may be 0 / negative / repeated
    and there is no ``decodeMessage`` to cross-check or single-field default."""
    try:
        insns = disasm(ctx, init_va, max_insns=64, stop_at_ret=False)
    except Exception:
        return [], "none"

    # C — static object: try each adrp+add target as a static _NameMap blob.
    best: Optional[List[SwiftField]] = None
    for blob in _adrp_add_targets(insns):
        got = _parse_static_blob(ctx, blob, enum)
        if got and (best is None or len(got) > len(best)):
            best = got
    if best:
        return best, "static"

    # A — inline, directly in this function.  Device / cache inline closures
    # build one entry per ~10 instructions and span well past the 64-insn shape
    # probe, so walk the WHOLE init function — `stop_at_ret` is the principled
    # terminator (the function's own `ret`); the insn cap is only a runaway
    # guard.  (A next-symbol extent bound was tried and rejected: the `.symbols`
    # nlist carries mid-function local symbols, so it truncates real fields.)
    stub = _is_dispatch_stub(insns)
    if not stub:
        try:
            full = disasm(ctx, init_va, max_insns=_INLINE_MAX_INSNS, stop_at_ret=True)
        except Exception:
            full = insns
        got = _walk_inline_closure(ctx, full, enum)
        if got:
            return got, "inline"

    # Runtime-built _NameMap (once-init `cmn x?,#1; b.ne <builder>`): follow the
    # cold builder closure and read its literal (number, name) table.  Placed
    # before the shape-B fallback, which would under-read such a message to its
    # first field only (e.g. remindd Credential 5 -> 1).  #72.
    got = [] if stub else _runtime_namemap_fields(ctx, insns, enum)
    if len(got) > (0 if enum else 1) and _namemap_builder_validated(
            ctx, got, decode_va, traverse_va, enum):
        return got, "runtime-namemap"
    # a runtime builder with exactly ONE entry is held back: the shape-B single-field
    # path below can confirm the number from decodeMessage/traverse.  If B finds nothing
    # (the well-known wrappers such as BoolValue), the builder's own literal entry is
    # still exact, so it is used -- under the same oracle validation.
    runtime_single = got if (len(got) == 1 and not enum) else None

    # D — shared once-init template (`adr x0,<token>; adr x1,<storage>;
    # adr x2,<builder>; b <shared-template>`): chase every `adr`'d CODE
    # address (skipping the once-token / storage data addresses) and read
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
        stub = False
        if not got and not enum:
            got = _single_entry_stub(ctx, t)
            stub = bool(got)
        if len(got) > len(best_shared):
            best_shared = got
            shared_shape = "single-stub" if stub else "shared-once"
    if best_shared and _namemap_builder_validated(ctx, best_shared, decode_va, traverse_va, enum):
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

    # A — inline, reached via an `adr x16,<closure>` (device getter → swift_once).
    for ins in insns:
        if ins.mnemonic == "adr" and ins.op_str.split(",", 1)[0].strip() in ("x16", "x9", "x1"):
            t = _adr_target(ins)
            if t is not None and t != init_va and abs(t - init_va) < 0x8000:
                try:
                    got = _walk_inline_closure(ctx, disasm(ctx, t, max_insns=600, stop_at_ret=True), enum)
                except Exception:
                    got = []
                if got:
                    return got, "inline-closure"
                if enum:
                    continue
                # B — single-field tail-call inside the followed closure.
                try:
                    cl = disasm(ctx, t, max_insns=40, stop_at_ret=False)
                except Exception:
                    cl = []
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
    None where metadata is absent).  ``recover_field_types`` supplies types from
    the message struct, its COW ``_StorageClass``, and its ``OneOf_*`` enums (#60),
    so oneof/storage-backed fields are now covered too."""
    try:
        from serializers import swift_type_recovery
        by_type, incomplete, fieldless = swift_type_recovery._collect_field_types_ex(ctx)
    except Exception:
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
    """Like :func:`_type_from_namemap_symbol` but for an arbitrary ``V<marker>``
    boundary (e.g. ``V13decodeMessage``)."""
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
