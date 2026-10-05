"""Stage-0 probe for the readFrom: dispatch element-type resolver.

Builds the per-binary {ReadAllFrom vmaddr -> class name} index, then walks
GEOPDComponent's readFrom: field-dispatch jump table and prints the resolved
element class per field.  Ground-truth assertion: field 8 (values) ->
GEOPDComponentValue, which the name-suffix heuristics currently mis-resolve to
`repeated bytes`.

Run:  python3 probe_readfrom_resolver.py
"""
import os, sys
import artifacts

from macho.dyld_cache import DyldCacheReader
from macho.memory import BinaryContext
from macho.strings import build_string_table
from macho import classlist as CL
from macho.local_symbols import apply_to_classes
from proto.dispatch import (
    _build_readfrom_core_index,
    _find_readfrom_c_func,
    _readspecified_and_count,
    _decode_readfrom_jumptable,
)
from proto.repeated import _resolve_repeated_via_dispatch

CACHE = artifacts.cache_file()

print("Loading GeoServices from cache …")
reader = DyldCacheReader(CACHE)
mach_va = reader.find_image_header("GeoServices")
ctx = BinaryContext.from_cache(reader, mach_va)
st = build_string_table(ctx)
cl = CL.build_class_list(ctx, st)
apply_to_classes(cl, reader.image_local_symbols(mach_va))

print("Building readFrom core index …")
core_index = _build_readfrom_core_index(ctx, cl)
print(f"  core_index size: {len(core_index)} classes")
# Spot-check the ground-truth element class is in the index by address.
gv = cl.find("GEOPDComponentValue")
gv_core = _find_readfrom_c_func(ctx, gv) if gv else None
print(f"  GEOPDComponentValue ReadAllFrom core: "
      f"{hex(gv_core) if gv_core else None} -> "
      f"{core_index.get(gv_core) if gv_core else None}")

# ── Walk GEOPDComponent's dispatch ────────────────────────────────────────────
cls = cl.find("GEOPDComponent")
assert cls is not None, "GEOPDComponent not found"

rf = _find_readfrom_c_func(ctx, cls)
rs, fc = _readspecified_and_count(ctx, rf) if rf else (None, 0)
arms = _decode_readfrom_jumptable(ctx, rs, fc) if rs else None
print(f"\nGEOPDComponent: readFrom={hex(rf) if rf else None} "
      f"ReadSpecified={hex(rs) if rs else None} field_count={fc}")
print(f"  arms decoded: {len(arms) if arms else None}")
if arms:
    for num in sorted(arms):
        print(f"    field {num:>2}: arm {hex(arms[num])}")

result = _resolve_repeated_via_dispatch(ctx, cls, core_index)
print("\nResolved {field_number: element_class}:")
for num in sorted(result):
    print(f"    field {num:>2} -> {result[num]}")

# ── Map field numbers to ivar names for readability ───────────────────────────
print("\nField-number -> ivar (for cross-reference):")
from proto.extractor import _confirm_field_numbers
from proto.protocore import _is_proto_flags_ivar, _INTERNAL_PB_IVARS
field_ivars = [iv for iv in cls.ivars
               if not _is_proto_flags_ivar(iv) and iv.name
               and iv.name not in _INTERNAL_PB_IVARS]
inst_methods = {m.name for m in cls.methods if m.name}
fnr = _confirm_field_numbers(ctx, cls, field_ivars, inst_methods)
num_to_ivar = {n: name for name, n in fnr.confirmed_numbers.items()}
for num in sorted(result):
    print(f"    field {num:>2}  {num_to_ivar.get(num, '?'):<28} -> {result[num]}")

# ── Ground-truth assertions ───────────────────────────────────────────────────
print("\n" + "=" * 60)
ok = True
if result.get(8) == "GEOPDComponentValue":
    print("PASS: field 8 (values) -> GEOPDComponentValue")
else:
    print(f"FAIL: field 8 -> {result.get(8)!r} (expected GEOPDComponentValue)")
    ok = False

# commingledAttributions: report whatever element class it resolves to.
comming_num = next((n for n, iv in num_to_ivar.items()
                    if iv == "_commingledAttributions"), None)
print(f"commingledAttributions: field={comming_num} "
      f"-> {result.get(comming_num) if comming_num else 'n/a'}")

sys.exit(0 if ok else 1)
