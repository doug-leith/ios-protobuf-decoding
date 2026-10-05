"""Ground truth for f26_arm64e_fixups/testfx_e — Apple's own
`xcrun dyld_info -fixups testfx_e` output for the built binary (Xcode 15.4),
transcribed verbatim, not anything the extractor produced. The binary's
chained-fixup header declares pointer_format 12
(DYLD_CHAINED_PTR_ARM64E_USERLAND24: authenticated arm64e, 8-byte stride,
rebase targets are VM offsets from the image base, 24-bit bind ordinals)
— confirmed with `dyld_info -fixup_chains`.

Each entry: (slot vmaddr, kind, target).  For a rebase the target is the
VM OFFSET dyld_info prints (the decoded pointer is IMAGE_BASE + offset); for a
bind it is the bare imported symbol (dyld_info also prints the dylib and the
PAC diversifier/key, irrelevant to decoding the target).  Both authenticated
(`div=... ad=... key=...`) and plain rebases occur, as do binds with and
without auth.
"""

IMAGE_BASE = 0x100000000

FIXUPS = [
    (0x100008000, "bind",   "_objc_autoreleaseReturnValue"),
    (0x100008008, "bind",   "_objc_opt_new"),
    (0x100008010, "rebase", 0x0000C0C8),
    (0x10000C018, "rebase", 0x0000406C),
    (0x10000C060, "rebase", 0x0000406C),
    (0x10000C068, "rebase", 0x00004058),   # authenticated
    (0x10000C090, "rebase", 0x0000407B),
    (0x10000C098, "bind",   "_OBJC_CLASS_$_NSMutableArray"),
    (0x10000C0A0, "bind",   "_OBJC_METACLASS_$_NSObject"),   # authenticated
    (0x10000C0A8, "bind",   "_OBJC_METACLASS_$_NSObject"),   # authenticated
    (0x10000C0B0, "bind",   "__objc_empty_cache"),
    (0x10000C0C0, "rebase", 0x0000C000),
    (0x10000C0C8, "rebase", 0x0000C0A0),   # authenticated
    (0x10000C0D0, "bind",   "_OBJC_CLASS_$_NSObject"),       # authenticated
    (0x10000C0D8, "bind",   "__objc_empty_cache"),
    (0x10000C0E8, "rebase", 0x0000C048),   # authenticated
]

CLASSES = ["TestFixupClass"]     # instance class + its metaclass share the name
