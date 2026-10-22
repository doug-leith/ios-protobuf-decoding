"""serializers/protobufc_detect.py — DETECT-ONLY recognition of the protobuf-c runtime.

protobuf-c is the C implementation of protobuf (Apple's MMCS framework uses it).  Its
schema is a static table of ``ProtobufCMessageDescriptor`` / ``ProtobufCEnumDescriptor``
structs in a data segment; each begins with a 32-bit magic::

    ProtobufCMessageDescriptor     ProtobufCEnumDescriptor
      +0  u32 magic 0x28aaeef9       +0  u32 magic 0x114315af
      +8  char *name                 +8  char *name
      +48 u32 n_fields               +40 u32 n_values
      +56 ProtobufCFieldDescriptor*  +48 ProtobufCEnumValue*

so the image can be recognised — and the descriptors counted and named — by scanning its
data sections (``__DATA*`` and arm64e ``__AUTH*``) for 8-byte-aligned magic words and reading the name pointer.  The fields
themselves (72-byte ``ProtobufCFieldDescriptor`` records) are NOT decoded: this tool
reports protobuf-c as detect-only (LIMITATIONS.md item 12).

The scan reads only through the ``BinaryContext`` memory API (``read_bytes`` /
``read_ptr`` / ``read_cstring``), so it works identically for a standalone binary and a
cache-native image — unlike the export-trie / ``LC_SYMTAB`` based detectors, which are
empty for cache images.

A magic hit counts only if its name pointer resolves to a plausible protobuf type name
(a dotted identifier), which rejects the (astronomically unlikely) chance 32-bit match.
"""
from __future__ import annotations

import logging
import re
import struct
from dataclasses import dataclass, field
from typing import List

from macho.memory import READ_ERRORS, record_unread

log = logging.getLogger(__name__)

MESSAGE_MAGIC = 0x28AAEEF9          # PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC
ENUM_MAGIC = 0x114315AF             # PROTOBUF_C__ENUM_DESCRIPTOR_MAGIC

# struct offsets (LP64)
_NAME_OFF = 8
_MSG_N_FIELDS_OFF, _MSG_FIELDS_OFF = 48, 56
_ENUM_N_VALUES_OFF, _ENUM_VALUES_OFF = 40, 48

# n_fields / n_values above this is not a schema table (largest real protobuf messages
# have a few hundred fields); a sanity bound on the struct, not a heuristic on the image.
_MAX_ENTRIES = 1 << 16
_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]*$")
_MAX_NAME = 512

# Descriptors are initialised, relocated data (they hold pointers), so they live in a
# writable-or-const DATA-like segment: ``__DATA``, ``__DATA_CONST``, ``__DATA_DIRTY`` on
# arm64, and ``__AUTH_CONST`` / ``__AUTH`` on arm64e (a message descriptor holds the
# signed ``message_init`` function pointer, so iOS 27's message descriptors sit in
# ``__AUTH_CONST`` while its enum descriptors, which hold none, stay in ``__DATA_CONST``).
# Scan every segment that is not code, link-edit or the null guard rather than listing
# DATA-like names; zerofill sections (no file content) are skipped.
_NOT_DATA_SEGMENTS = frozenset({"__TEXT", "__LINKEDIT", "__PAGEZERO"})

_SYMBOL_TOKEN = "protobuf_c_"           # cache .symbols pre-filter (substring)
_SYMBOL_PREFIX = "_protobuf_c_"         # C symbol, leading underscore (covers _protobuf_c__allocator)


@dataclass
class ProtobufCDescriptors:
    """What the magic scan found in one image."""
    messages: List[str] = field(default_factory=list)    # message names, address order
    enums: List[str] = field(default_factory=list)       # enum names, address order
    rejected: int = 0                                    # magic hits failing validation
    symbols: List[str] = field(default_factory=list)     # protobuf-c API symbols present

    def __bool__(self) -> bool:
        return bool(self.messages or self.enums or self.symbols)


def _read_name(ctx, addr: int):
    try:
        name = ctx.read_cstring(ctx.read_ptr(addr + _NAME_OFF), _MAX_NAME)
    except (NameError, ImportError):
        raise
    except Exception:
        return None
    return name if _NAME_RE.match(name) else None


def _valid_count(ctx, addr: int, n_off: int, ptr_off: int) -> bool:
    try:
        n = ctx.read_u32(addr + n_off)
        return n <= _MAX_ENTRIES and (n == 0 or ctx.read_ptr(addr + ptr_off) != 0)
    except (NameError, ImportError):
        raise
    except Exception:
        return False


def _aligned_hits(data: bytes, base: int, magic: int):
    """Offsets in *data* (mapped at *base*) of 8-byte-aligned little-endian *magic*."""
    pat = struct.pack("<I", magic)
    i = data.find(pat)
    while i >= 0:
        if (base + i) % 8 == 0:
            yield base + i
        i = data.find(pat, i + 1)


def protobufc_symbols(ctx) -> List[str]:
    """``_protobuf_c_*`` runtime symbols the image defines or imports — corroboration
    for the descriptor scan, and the only signal for an image that carries the runtime
    (or links it) but no descriptor tables, e.g. libprotobuf-c itself.

    Binary mode reads ``LC_SYMTAB`` / export trie; cache-native reads the image's
    local symbols from the ``.symbols`` sub-cache (same split as the C++ detector)."""
    reader = getattr(ctx, "_cache_reader", None)
    if reader is not None and getattr(ctx, "is_cache_backed", False):
        try:
            names = reader.image_symbol_addrs(ctx.image_base, _SYMBOL_TOKEN).keys()
        except (OSError, *READ_ERRORS) as exc:
            record_unread(ctx, ".symbols local symbols", f"{ctx.image_base:#x}", exc)
            return []
    else:
        names = ctx.iter_symbol_names()
    return sorted({n for n in names if n.startswith(_SYMBOL_PREFIX)})


def find_protobufc_descriptors(ctx) -> ProtobufCDescriptors:
    """Detect protobuf-c in *ctx*: scan its data sections for message / enum
    descriptors and collect the ``_protobuf_c_*`` runtime symbols."""
    out = ProtobufCDescriptors()
    out.symbols = protobufc_symbols(ctx)
    found_msg, found_enum = {}, {}
    for seg in ctx.segments:
        if seg.name in _NOT_DATA_SEGMENTS:
            continue
        for sec in seg.sections:
            if not sec.has_file_content or sec.vmsize < 8:
                continue
            try:
                data = ctx.read_bytes(sec.vmaddr, sec.vmsize)
            except READ_ERRORS as exc:
                record_unread(ctx, "data section", f"{seg.name},{sec.name}", exc)
                continue
            for addr in _aligned_hits(data, sec.vmaddr, MESSAGE_MAGIC):
                name = _read_name(ctx, addr)
                if name and _valid_count(ctx, addr, _MSG_N_FIELDS_OFF, _MSG_FIELDS_OFF):
                    found_msg[addr] = name
                else:
                    out.rejected += 1
            for addr in _aligned_hits(data, sec.vmaddr, ENUM_MAGIC):
                name = _read_name(ctx, addr)
                if name and _valid_count(ctx, addr, _ENUM_N_VALUES_OFF, _ENUM_VALUES_OFF):
                    found_enum[addr] = name
                else:
                    out.rejected += 1
    out.messages = [found_msg[a] for a in sorted(found_msg)]
    out.enums = [found_enum[a] for a in sorted(found_enum)]
    return out
