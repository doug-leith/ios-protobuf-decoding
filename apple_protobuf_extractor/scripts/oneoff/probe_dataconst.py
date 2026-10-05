#!/usr/bin/env python3
"""
probe_dataconst.py — Definitive diagnostic for the 253-ambiguous-enum cascade.

Loads GeoServices cache-native, walks the raw __DATA_CONST/__objc_const method
list for a chosen proto class, and for every method entry dumps:

  entry_va, raw 12 bytes, field0/1/2 decoded addresses, which section each
  decoded address lands in, and the cstring read at each (via ctx + cache).

This answers an open question from the cache-native selector investigation:
  For a proto-class method entry, what do field0/field1/field2 decode to, and
  does field1 (typesOffset) resolve to a real pool selector?
"""
import os, sys
import artifacts
from macho.dyld_cache import DyldCacheReader
from macho.memory import BinaryContext
from macho.strings import build_string_table
from macho import classlist as CL

CACHE = artifacts.cache_file()
FRAMEWORK = "GeoServices"
# Classes whose enum fields came up ambiguous (from enums_debug.jsonl):
TARGET_CLASSES = {
    "GEOCoarseLocationTerritoryInfo",
}
POOL_VA, POOL_END = 0x18005c000, 0x186d74000


def sect_of(ctx, va):
    for seg in ctx.segments:
        for s in seg.sections:
            if s.vmaddr <= va < s.vmaddr + s.vmsize:
                return f"{s.segname}/{s.name}"
    if POOL_VA <= va < POOL_END:
        return "SELECTOR_POOL"
    return "?"


def safe_cstr(reader_fn, va):
    try:
        s = reader_fn(va)
        return repr(s)
    except Exception as e:
        return f"<err {type(e).__name__}>"


def dump_methods(ctx, cache, cls):
    # re-derive methods_va exactly as _parse_class does
    class_va = cls.vmaddr
    raw_data = ctx.read_u64(class_va + 32)
    ptr_data = ctx.read_ptr(class_va + 32)
    ro_va = ptr_data if ptr_data != raw_data else (raw_data & ~0x7)
    methods_va = ctx.read_ptr(ro_va + 32)
    print(f"\n=== {cls.name} ===")
    print(f"  class_va=0x{class_va:x} ro_va=0x{ro_va:x} methods_va=0x{methods_va:x}"
          f"  [{sect_of(ctx, methods_va)}]")
    fi = cache.vmaddr_to_file_info(methods_va)
    print(f"  methods_va file: {fi}")

    entsize_flags = ctx.read_u32(methods_va)
    count = ctx.read_u32(methods_va + 4)
    relative = bool(entsize_flags & CL.METHOD_FLAG_RELATIVE)
    has_direct = bool(entsize_flags & 0x40000000)
    print(f"  entsizeAndFlags=0x{entsize_flags:08x} count={count} "
          f"relative={relative} has_direct={has_direct}")

    entry_va = methods_va + 8
    for i in range(count):
        raw = ctx.read_bytes(entry_va, 12)
        f0 = ctx.read_s32(entry_va)
        f1 = ctx.read_s32(entry_va + 4)
        f2 = ctx.read_s32(entry_va + 8)
        a0 = entry_va + f0          # nameOffset target
        a1 = (entry_va + 4) + f1    # typesOffset target
        a2 = (entry_va + 8) + f2    # impOffset target
        print(f"\n  [{i}] entry_va=0x{entry_va:x} raw={raw.hex(' ')}")
        print(f"      f0={f0:11d} -> 0x{a0:x} [{sect_of(ctx,a0)}] "
              f"ctx={safe_cstr(ctx.read_cstring,a0)} cache={safe_cstr(cache.read_cstring,a0)}")
        print(f"      f1={f1:11d} -> 0x{a1:x} [{sect_of(ctx,a1)}] "
              f"ctx={safe_cstr(ctx.read_cstring,a1)} cache={safe_cstr(cache.read_cstring,a1)}")
        print(f"      f2(IMP)={f2:11d} -> 0x{a2:x} [{sect_of(ctx,a2)}]")
        entry_va += 12


def main():
    cache = DyldCacheReader(CACHE, verbose=False)
    mach_va = cache.find_image_header(FRAMEWORK)
    ctx = BinaryContext.from_cache(cache, mach_va)
    st = build_string_table(ctx)
    classes = CL.build_class_list(ctx, st)
    by_name = {}
    for c in classes:
        by_name.setdefault(c.name, c)
    for name in TARGET_CLASSES:
        c = by_name.get(name)
        if c is None:
            print(f"!! class {name} not found")
            continue
        # show resolved-vs-null method names for context
        nulls = [m for m in c.methods if m.name is None]
        print(f"{name}: {len(c.methods)} methods, {len(nulls)} null-name")
        for m in c.methods:
            print(f"    name={m.name!r} types={m.types!r} imp=0x{m.imp:x}")
        dump_methods(ctx, cache, c)
    cache.close()


if __name__ == "__main__":
    main()
