"""macho/objc_abi — ObjC 64-bit runtime struct field offsets (single source of truth).

These byte offsets into ``class_t`` and ``class_ro_t`` are part of the stable
arm64 Objective-C ABI and were previously duplicated as inline literals in
``classlist.py`` and as ad-hoc constants in ``cache_classlist.py``.  Centralising
them here removes a real readability trap: ``class_t.data`` and
``class_ro_t.baseMethods`` are BOTH at byte offset 32, so an inline ``+ 32`` was
ambiguous — the named constants below make which-is-which explicit.

Layouts (64-bit):

    class_t          { isa@0; superclass@8; cache@16; vtable@24; data@32 }
    class_ro_t       { flags@0; instanceStart@4; instanceSize@8; reserved@12;
                       ivarLayout@16; name@24; baseMethods@32; baseProtocols@40;
                       ivars@48; … }

``data`` is a tagged pointer: its low 3 bits carry Swift/ObjC flags (the
FAST_DATA_MASK convention), so callers strip them with ``& FAST_DATA_MASK`` when
the slot wasn't already cleaned by the dyld fixup walk.
"""

import re as _re

# class_t
CLASS_T_SUPERCLASS = 8
CLASS_T_DATA       = 32

# class_ro_t
CLASS_RO_FLAGS         = 0
CLASS_RO_INSTANCE_SIZE = 8
CLASS_RO_NAME          = 24
CLASS_RO_METHODS       = 32
CLASS_RO_IVARS         = 48

# Low-3-tag-bit mask applied to class_t.data to recover the class_ro_t vmaddr.
FAST_DATA_MASK = ~0x7

# method_list_t.entsizeAndFlags bit 31: this method list uses the relative
# (32-bit-offset) method_t encoding rather than the traditional 3-pointer one.
METHOD_FLAG_RELATIVE = 0x80000000

# A relative method_t (nameOffset/typesOffset/impOffset, each s32) is always
# 3 x int32 = 12 bytes, regardless of what a method_list_t's entsize field
# encodes.  Shared by macho.classlist (the builder) and
# macho.relative_selector_base (which samples nameOffset values to calibrate
# the selector-base anchor) -- centralised here so neither imports the other.
MIN_RELATIVE_METHOD_ENTSIZE = 12

# Pre-compiled selector-name validator.  A valid ObjC selector contains only
# alphanumerics, underscores, and colons, starts with a letter, underscore or colon
# (a keyword may be empty: UIKitCore's -[_IntArray2D ::newValue:]),
# and has a reasonable length -- or is one of the two clang generates for a class
# with C++ / ARC ivars, ``.cxx_destruct`` and ``.cxx_construct``.  Crucially, binary
# code or data accidentally read as a cstring will contain control characters, high
# bytes, whitespace, or other punctuation that fail this check.
_SELECTOR_RE = _re.compile(r'^(?:[A-Za-z_:][A-Za-z0-9_:]*|\.cxx_(?:destruct|construct))$')


def is_valid_selector(s):
    """Return True if *s* looks like a valid ObjC selector name.

    Single-character selectors such as ``x``, ``y``, ``z`` are legal ObjC
    property-getter selectors and must be accepted; a lower bound of
    ``len > 1`` would incorrectly reject them.  Nor is there an upper bound: a
    many-argument initialiser's selector runs to hundreds of characters (iPhone 8
    GeoServices' -[GEOPDPlaceRequest initWithMerchantCode:...] is over 600).
    """
    return bool(s and _SELECTOR_RE.match(s))
