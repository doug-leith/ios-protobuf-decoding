#!/usr/bin/env python3
"""
Diagnostic: verify the swapped name/types hypothesis in GeoServices __objc_methlist.

Run from the repo root:
    python3 probe_methlist.py --cache /path/to/dyld_shared_cache_arm64

Reads directly from the split-cache files to confirm that:
  - field 0 (nameOffset) → __objc_methtype (ivar type encoding) for proto entries
  - field 1 (typesOffset) → selector pool for proto entries
  - field 2 (impOffset)   → IMP (always correct)
"""
import argparse, os, struct, sys

# GeoServices segment layout from Hopper
METHLIST_VA   = 0x18d649f18
METHLIST_END  = 0x18d705e5c
METHTYPE_VA   = 0x18da577c7
METHTYPE_END  = 0x18dabdbae
METHNAME_VA   = 0x18d98e846
METHNAME_END  = 0x18da577c7
SUBCACHE_03_VADDR = 0x186d88000
POOL_VADDR        = 0x18005c000
POOL_END          = 0x186d74000

def read_at(path, file_off, length):
    with open(path, 'rb') as f:
        f.seek(file_off)
        return f.read(length)

def read_cstring(data, offset, max_len=256):
    end = data.find(b'\x00', offset, offset + max_len)
    if end < 0:
        return None
    try:
        return data[offset:end].decode('utf-8')
    except UnicodeDecodeError:
        return None

def is_valid_selector(s):
    if not s or not (0 < len(s) <= 200):
        return False
    import re
    return bool(re.match(r'^[A-Za-z_][A-Za-z0-9_:]*$', s))

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--cache', required=True, help='Path to dyld_shared_cache_arm64')
    args = ap.parse_args()
    base = args.cache

    path03 = base + '.03'
    path01 = base + '.01'
    if not os.path.exists(path03):
        print(f"ERROR: {path03} not found")
        sys.exit(1)
    if not os.path.exists(path01):
        print(f"ERROR: {path01} not found")
        sys.exit(1)

    print(f"Reading from {path03} and {path01}")

    # Load entire __objc_methlist section
    methlist_fo = METHLIST_VA - SUBCACHE_03_VADDR
    methlist_sz = METHLIST_END - METHLIST_VA
    methlist_data = read_at(path03, methlist_fo, methlist_sz)
    print(f"\n__objc_methlist: {methlist_sz} bytes = {methlist_sz // 12} potential entries")

    # Load __objc_methtype section
    methtype_fo = METHTYPE_VA - SUBCACHE_03_VADDR
    methtype_sz = METHTYPE_END - METHTYPE_VA
    methtype_data = read_at(path03, methtype_fo, methtype_sz)
    print(f"__objc_methtype: {methtype_sz} bytes")

    # Load selector pool from .01
    print(f"\nLoading .01 selector pool...")
    with open(path01, 'rb') as f:
        pool_data = f.read()
    print(f"Pool size: {len(pool_data):,} bytes")

    # Find key selectors in pool
    print("\nSelector pool lookup:")
    for sel in ['readFrom:', 'writeTo:', 'mergeFrom:', 'readFrom:length:']:
        needle = sel.encode() + b'\x00'
        idx = pool_data.find(needle)
        if idx >= 0:
            va = POOL_VADDR + idx
            print(f"  '{sel}' at pool file_off=0x{idx:x}  vmaddr=0x{va:x}")
        else:
            print(f"  '{sel}' NOT FOUND in pool")

    # Scan methlist for entries with field0 → methtype
    print("\n\nScanning methlist for entries with nameOffset → __objc_methtype...")
    n_entries = methlist_sz // 12
    proto_entries = []
    for i in range(n_entries):
        off = i * 12
        entry_va = METHLIST_VA + off
        nr = struct.unpack_from('<i', methlist_data, off)[0]
        tr = struct.unpack_from('<i', methlist_data, off + 4)[0]
        ir = struct.unpack_from('<i', methlist_data, off + 8)[0]
        sel_ref_va  = entry_va + nr
        types_va    = entry_va + 4 + tr
        imp_addr    = entry_va + 8 + ir
        if METHTYPE_VA <= sel_ref_va < METHTYPE_END:
            proto_entries.append((i, entry_va, nr, sel_ref_va, tr, types_va, ir, imp_addr))

    print(f"  Found {len(proto_entries)} proto-style entries")
    print("\n  First 10 entries with nameOffset → methtype:\n")
    for idx, (i, ev, nr, srv, tr, tv, ir, imp) in enumerate(proto_entries[:10]):
        # Read content at field0 (ivar type string in methtype)
        name0_str = read_cstring(methtype_data, srv - METHTYPE_VA)

        # Read content at field1 as if it's the selector reference
        in_pool_f1 = POOL_VADDR <= tv < POOL_END
        name1_str = None
        if in_pool_f1:
            name1_str = read_cstring(pool_data, tv - POOL_VADDR)

        valid_sel_f0 = is_valid_selector(name0_str)
        valid_sel_f1 = is_valid_selector(name1_str)

        print(f"  Entry {i:5d}  entry_va=0x{ev:x}")
        print(f"    field0(name) → 0x{srv:x} ({('methtype' if METHTYPE_VA<=srv<METHTYPE_END else 'other')}): "
              f"{str(name0_str)[:60]!r}  valid_sel={valid_sel_f0}")
        print(f"    field1(type) → 0x{tv:x} ({('POOL' if in_pool_f1 else 'other')}): "
              f"{name1_str!r}  valid_sel={valid_sel_f1}")
        print(f"    field2(imp)  → IMP=0x{imp:x}")
        print()

    # Summary
    pool_in_f1 = sum(1 for _,_,_,_,_,tv,_,_ in proto_entries if POOL_VADDR <= tv < POOL_END)
    valid_sel_f1 = sum(1 for _,ev,_,srv,tr,tv,_,_ in proto_entries
                       if POOL_VADDR <= tv < POOL_END and
                       is_valid_selector(read_cstring(pool_data, tv - POOL_VADDR)))
    print(f"  Summary: {len(proto_entries)} proto entries total")
    print(f"    field1 → pool: {pool_in_f1}")
    print(f"    field1 → pool AND valid selector: {valid_sel_f1}")
    print(f"\nHypothesis {'CONFIRMED' if valid_sel_f1 > len(proto_entries) * 0.9 else 'REJECTED or needs investigation'}:")
    if valid_sel_f1 > 0:
        print("  field1 (typesOffset position) reliably gives selector names from pool")
        print("  The fix (reading alt_sel_va = (va+4) + read_s32(va+4)) should work")
    else:
        print("  field1 does NOT give pool selector names — different fix needed")

if __name__ == '__main__':
    main()
