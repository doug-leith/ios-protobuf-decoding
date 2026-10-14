"""
macho/strings.py — StringTable: indexed collection of C strings from Mach-O sections.

Scans __cstring, __objc_methnames, and __objc_classname for null-terminated
strings and builds vmaddr ↔ value ↔ section indices for fast look-up.

NOTE: __objc_selrefs is intentionally NOT scanned here.  That section contains
64-bit pointers to selector strings, not the strings themselves.  Scanning it
as a cstring section would yield garbage entries from raw pointer bytes.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Dict, Iterator, List, Optional

from .memory import BinaryContext

# Only sections that actually store null-terminated C strings on disk.
# __objc_selrefs (pointer array) and __objc_classrefs are deliberately excluded.
# NOTE: the Mach-O section name field is 16 bytes.  '__objc_methname' is 15
# chars (+ null); '__objc_methnames' would be 16 chars with no null, but the
# actual on-disk section name is the 15-char form.  Using the wrong spelling
# causes has_section() to always return False, silently skipping the section.
_SCAN_SECTIONS = [
    ('__TEXT', '__cstring'),
    ('__TEXT', '__objc_methname'),    # 15 chars — NOT '__objc_methnames'
    ('__TEXT', '__objc_classname'),
]

_MAX_SECTION_SIZE = 50_000_000   # 50 MB guard against malformed binaries


@dataclass
class StringEntry:
    vmaddr:  int
    section: str   # sectname, e.g. '__cstring'
    value:   str


class StringTable:
    """
    Immutable string table built from a BinaryContext.

    All look-ups are O(1).  Mutation is internal (via _add).
    """

    def __init__(self) -> None:
        self._by_vmaddr:  Dict[int, StringEntry]        = {}
        self._by_value:   Dict[str, List[int]]          = {}
        self._by_section: Dict[str, List[StringEntry]]  = {}

    def _add(self, entry: StringEntry) -> None:
        self._by_vmaddr[entry.vmaddr] = entry
        self._by_value.setdefault(entry.value, []).append(entry.vmaddr)
        self._by_section.setdefault(entry.section, []).append(entry)

    # ── Public API ──────────────────────────────────────────────────────────

    def get(self, vmaddr: int) -> Optional[str]:
        e = self._by_vmaddr.get(vmaddr)
        return e.value if e else None

    def __getitem__(self, vmaddr: int) -> str:
        e = self._by_vmaddr.get(vmaddr)
        if e is None:
            raise KeyError(f"No string at vmaddr 0x{vmaddr:x}")
        return e.value

    def find(self, value: str) -> List[int]:
        """Return all vmaddrs where *value* appears."""
        return list(self._by_value.get(value, []))

    def all_in_section(self, sectname: str) -> List[StringEntry]:
        """Return all entries from *sectname*.  O(k)."""
        return list(self._by_section.get(sectname, []))

    def section_names(self) -> List[str]:
        return list(self._by_section.keys())

    def section_for(self, vmaddr: int) -> Optional[str]:
        e = self._by_vmaddr.get(vmaddr)
        return e.section if e else None

    def __iter__(self) -> Iterator[StringEntry]:
        return iter(self._by_vmaddr.values())

    def __len__(self) -> int:
        return len(self._by_vmaddr)

    def __repr__(self) -> str:
        return (f"StringTable({len(self)} entries, "
                f"sections={self.section_names()})")


# ── Factory ──────────────────────────────────────────────────────────────────

def build_string_table(ctx: BinaryContext) -> StringTable:
    """Scan all known cstring sections in *ctx* and return a populated StringTable."""
    table = StringTable()
    for segname, sectname in _SCAN_SECTIONS:
        if not ctx.has_section(segname, sectname):
            continue
        sect = ctx.section(segname, sectname)
        if sect.size == 0:
            continue
        if sect.size > _MAX_SECTION_SIZE:
            logging.getLogger(__name__).warning(
                "section %s,%s is %d bytes (> %d): its strings are NOT scanned, so selector "
                "or value names stored there may be missing", segname, sectname,
                sect.size, _MAX_SECTION_SIZE)
            continue
        if not sect.has_file_content:
            continue
        try:
            data = ctx.read_bytes(sect.vmaddr, sect.size)
        except ValueError:
            continue
        pos = 0
        while pos < len(data):
            null = data.find(b'\x00', pos)
            if null < 0:
                break
            raw = data[pos:null]
            if raw:
                try:
                    value = raw.decode('utf-8')
                except UnicodeDecodeError:
                    value = raw.decode('latin-1')
                table._add(StringEntry(
                    vmaddr  = sect.vmaddr + pos,
                    section = sectname,
                    value   = value,
                ))
            pos = null + 1
    return table
