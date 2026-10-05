"""PoC measurement for TODO #60 — size the name-shape dependence of
``_field_label`` and ``_is_real_field_ivar`` (NO production change).

Both functions mix a principled signal (type-encoding shape) with a name-shape
guess (``add<X>:``/``<x>Count``/``has<X>`` selector construction).  Before doing
the writeTo/readFrom-walk replacement, this script measures HOW OFTEN the
name-shape branch actually *decides* the output on the real artifacts — i.e. how
much #60 can change.

For each proto class it classifies every admitted ivar's label by WHICH branch
of ``_field_label`` fired, and every ivar's admission by whether the name signal
*rescued* it from the flags-ivar shape (the only case where the name actually
changes admission, since the function is a union that admits-by-default).

Usage:  ../venv/bin/python3 probe_fieldlabel_60.py GeoServices
        ../venv/bin/python3 probe_fieldlabel_60.py CoreLocationProtobuf
"""
import sys
from collections import Counter

from gt_fields import load
from proto.protocore import (
    _is_real_field_ivar, _is_proto_flags_ivar,
    _is_packed_list_enc, _is_has_bits_name, _proto_name, _setter_for,
    _INTERNAL_PB_IVARS,
)

from proto.protoclass_heuristic import _is_proto_class


def _label_branch(ivar, method_names):
    """Which branch of _field_label decides this ivar's label (mirrors the code)."""
    pname = _proto_name(ivar.name)
    if _is_packed_list_enc(ivar.type_enc):
        return "REPEATED:packed-enc"          # principled (storage shape)
    add_sel = f"add{pname[0].upper()}{pname[1:]}:" if pname else ""
    count_sel = f"{pname}Count"
    if add_sel in method_names and count_sel in method_names:
        return "REPEATED:add+count(NAME)"     # name-shape
    has_sel = f"has{pname[0].upper()}{pname[1:]}" if pname else ""
    if has_sel in method_names:
        return "OPTIONAL:has(NAME-noop)"      # name-shape but == default OPTIONAL
    if ivar.type_enc in ('@"NSArray"', '@"NSMutableArray"'):
        return "REPEATED:nsarray-enc"         # principled (storage shape)
    return "OPTIONAL:default"


def _admission_kind(ivar, method_names):
    """How _is_real_field_ivar decides admission for this ivar."""
    if ivar.name in _INTERNAL_PB_IVARS or _is_has_bits_name(ivar.name):
        return "reject:bookkeeping"
    pname = _proto_name(ivar.name)
    if not pname:
        return "reject:empty-name"
    has_name = bool(method_names) and (
        pname in method_names or _setter_for(ivar.name) in method_names)
    is_flags = _is_proto_flags_ivar(ivar)
    if has_name and is_flags:
        return "admit:NAME-rescues-flags"     # the ONLY case names change admission
    if has_name and not is_flags:
        return "admit:name+shape-agree"
    if not has_name and not is_flags:
        return "admit:shape-default(no-name)"
    return "reject:flags-shape"               # not admitted (flags, no getter)


def main():
    fw = sys.argv[1] if len(sys.argv) > 1 else "GeoServices"
    ctx, st, cl = load(fw)
    classes = [c for c in cl if not c.is_meta and _is_proto_class(c)]
    label_branches = Counter()
    admit_kinds = Counter()
    repeated_name_only = []   # fields labelled REPEATED solely by add+count name-shape
    admit_name_rescue = []    # ivars admitted only because a getter rescued a flags shape
    nclasses = 0
    for c in classes:
        method_names = {m.name for m in c.methods if m.name}
        admitted = []
        for iv in c.ivars:
            ak = _admission_kind(iv, method_names)
            admit_kinds[ak] += 1
            if ak == "admit:NAME-rescues-flags":
                admit_name_rescue.append(f"{c.name}.{iv.name}  enc={iv.type_enc!r}")
            # cross-check against production's own admission
            prod_admit = _is_real_field_ivar(iv, method_names)
            if prod_admit:
                admitted.append(iv)
        if not admitted:
            continue
        nclasses += 1
        for iv in admitted:
            br = _label_branch(iv, method_names)
            label_branches[br] += 1
            if br == "REPEATED:add+count(NAME)":
                repeated_name_only.append(f"{c.name}.{iv.name}  enc={iv.type_enc!r}")

    print(f"\n==== {fw}: {nclasses} proto classes with >=1 admitted field ====")
    print("\n-- _field_label branch frequency (admitted fields) --")
    for k, v in label_branches.most_common():
        print(f"   {v:6d}  {k}")
    print("\n-- _is_real_field_ivar admission kind frequency (all ivars) --")
    for k, v in admit_kinds.most_common():
        print(f"   {v:6d}  {k}")
    # Bucket the name-decided REPEATED set by whether a STORAGE-SHAPE rule would
    # also catch it (NSArray enc, or a ^{struct} array pointer) — i.e. whether the
    # name signal is REDUNDANT (safe to drop) or LOAD-BEARING (needs a principled
    # replacement to keep the REPEATED label).
    import re as _re
    struct_ptr = [s for s in repeated_name_only if _re.search(r"enc='\^\{", s)]
    nsarray = [s for s in repeated_name_only if _re.search(r'NS(Mutable)?Array', s)]
    other = [s for s in repeated_name_only
             if not _re.search(r"enc='\^\{", s) and not _re.search(r'NS(Mutable)?Array', s)]
    redundant_nsarray = nsarray
    print(f"\n-- REPEATED decided SOLELY by name-shape (add+count, not packed-enc): "
          f"{len(repeated_name_only)} --")
    print(f"   {len(redundant_nsarray):4d}  REDUNDANT (enc is NSArray; nsarray-enc branch catches it without the name)")
    print(f"   {len(struct_ptr):4d}  LOAD-BEARING ^{{struct}} array pointer (inline-C struct, #37 — needs a shape rule)")
    print(f"   {len(other):4d}  LOAD-BEARING other enc (needs writeTo-loop / readFrom-append signal)")
    for s in struct_ptr:
        print("     [struct]", s)
    for s in other:
        print("     [other ]", s)
    print(f"\n-- admission decided SOLELY by name (getter rescues flags shape): "
          f"{len(admit_name_rescue)} --")
    for s in admit_name_rescue[:40]:
        print("    ", s)

    # INVARIANT CHECK: is every admitted ``^{struct}`` ivar labelled REPEATED?  If so,
    # a selector-independent ``enc.startswith('^{')`` -> REPEATED rule fully replaces
    # the name signal for the only load-bearing label cases (no singular ^{struct}).
    print("\n-- INVARIANT: admitted ivars with enc starting '^{' (struct-array pointer) --")
    structs = Counter()
    struct_nonrep = []
    for c in classes:
        method_names = {m.name for m in c.methods if m.name}
        for iv in c.ivars:
            if iv.type_enc.startswith('^{') and _is_real_field_ivar(iv, method_names):
                br = _label_branch(iv, method_names)
                structs[br] += 1
                if not br.startswith('REPEATED'):
                    struct_nonrep.append(f"{c.name}.{iv.name}  enc={iv.type_enc!r} -> {br}")
    for k, v in structs.most_common():
        print(f"   {v:4d}  {k}")
    if struct_nonrep:
        print(f"   !! {len(struct_nonrep)} '^{{' ivars are NOT repeated (rule would mislabel):")
        for s in struct_nonrep:
            print("      ", s)
    else:
        print("   OK: every admitted '^{' ivar is REPEATED -> shape rule is safe.")

    # SAFETY CHECK for the proposed shape-only label:
    #   1. packed-list enc -> REPEATED  2. '^{' enc -> REPEATED
    #   3. NSArray enc -> REPEATED      4. else OPTIONAL  (drop add+count / has names)
    # Flag any field whose label would CHANGE, split into corrections vs regressions.
    print("\n-- proposed shape-only label vs current: per-field changes --")
    def shape_label(iv):
        e = iv.type_enc
        if _is_packed_list_enc(e):      return "REPEATED"
        if e.startswith('^{'):          return "REPEATED"
        if e in ('@"NSArray"', '@"NSMutableArray"'): return "REPEATED"
        return "OPTIONAL"
    def cur_label(iv, mn):
        br = _label_branch(iv, mn)
        return "REPEATED" if br.startswith("REPEATED") else "OPTIONAL"
    changes = Counter(); change_list = []
    for c in classes:
        method_names = {m.name for m in c.methods if m.name}
        for iv in c.ivars:
            if not _is_real_field_ivar(iv, method_names):
                continue
            old, new = cur_label(iv, method_names), shape_label(iv)
            if old != new:
                kind = f"{old}->{new}"
                changes[kind] += 1
                change_list.append(f"{kind}  {c.name}.{iv.name}  enc={iv.type_enc!r}")
    for k, v in changes.most_common():
        print(f"   {v:4d}  {k}")
    for s in change_list[:60]:
        print("     ", s)
    if not change_list:
        print("   (none — shape-only label is byte-identical here)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
