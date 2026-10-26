"""
macho/objc_model.py — the parsed ObjC model: method / ivar / class records.

A LEAF module: it holds the record shapes only, and imports nothing from
``macho`` itself.  ``classlist`` builds these records and ``local_symbols`` adds to them
(methods from the ``.symbols`` sub-cache), so both need the shapes; keeping the shapes here
means ``local_symbols`` does not have to import the parser to name its own
inputs (that import would close a ``classlist → memory → dyld_cache → local_symbols →
classlist`` cycle).

``classlist`` re-exports all three names, so ``from macho.classlist import
ObjcClass`` keeps working and remains the natural import for callers that are
already using the parser.

Struct layouts these records are decoded from are documented in
:mod:`macho.classlist`; field semantics are noted inline below.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

__all__ = ['ObjcMethod', 'ObjcIvar', 'ObjcClass']


@dataclass
class ObjcMethod:
    name:        str
    types:       str
    imp:         int        # absolute vmaddr of implementation
    is_relative: bool = False


@dataclass
class ObjcIvar:
    name:     str
    type_enc: str
    # byte offset within instance; None when the runtime sets it (its offset variable is
    # program data: a Swift class's, in __common / __bss)
    offset:   Optional[int]
    size:     int
    # Address of the ivar's OFFSET VARIABLE (ivar_t.offset — what compiled code
    # loads with `adrp; ldrsw` to reach the ivar).  Identifies the ivar by
    # address, unlike `offset`, whose small integer value collides across
    # classes.  0 when unknown (hand-built ivars in tests).
    offset_slot: int = 0


@dataclass
class ObjcClass:
    # pylint: disable=too-many-instance-attributes
    # Nine fields because class_t + class_ro_t carry nine pieces of information
    # this tool uses; the count is the ABI's, not a design choice.
    vmaddr:            int
    name:              str
    is_meta:           bool
    superclass_vmaddr: int           # 0 → root
    superclass_name:   Optional[str]
    ro_flags:          int
    instance_size:     int
    methods: List[ObjcMethod] = field(default_factory=list)
    ivars:   List[ObjcIvar]   = field(default_factory=list)

    def has_method(self, sel: str) -> bool:
        return any(m.name == sel for m in self.methods)

    def get_method(self, sel: str) -> Optional[ObjcMethod]:
        return next((m for m in self.methods if m.name == sel), None)
