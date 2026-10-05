"""Type-axis ground truth: verify each emitted field's TYPE is consistent with
its backing ivar's ObjC @encode (the compiler-emitted storage type = independent
ground truth).  Match field -> ivar by name (the tool names fields after ivars),
read @encode, and flag any emitted type that contradicts it.

Categories from @encode:
  d/f -> double/float ; B/c/C -> bool ; i/I/s/S -> 32-bit int(/enum) ;
  q/Q -> 64-bit int ; @"NSString"->string ; @"NSData"->bytes ;
  @"NS[Mutable]Array"/Set -> repeated ; @"<Other>" -> message ; * -> string/bytes

A "contradiction" = emitted scalar class disagrees with the @encode family
(e.g. ivar is double but field emitted as string).  int32/uint32/enum and
sint/fixed refinements over an integer ivar are NOT contradictions (the @encode
cannot distinguish them — documented tool limitation).

Usage: ../venv/bin/python3 gt_types.py <framework>
"""
import re
import sys
import proto.extractor as E
from gt_fields import load

INT32 = {"int32", "uint32", "sint32", "fixed32", "sfixed32"}
INT64 = {"int64", "uint64", "sint64", "fixed64", "sfixed64"}


def enc_family(enc):
    e = enc.strip()
    if e in ("d",):
        return {"double"}
    if e in ("f",):
        return {"float"}
    if e in ("B", "c", "C"):
        return {"bool"} | INT32     # BOOL often 'c'; signed char may be int8
    if e in ("i", "I", "s", "S"):
        return INT32 | {"enum"} | {"bool"}
    if e in ("q", "Q"):
        return INT64
    if e in ("*",):
        return {"string", "bytes"}
    m = re.match(r'@"([^"]*)"', e)
    if m:
        cls = m.group(1)
        if cls == "NSString":
            return {"string"}
        if cls in ("NSData", "NSMutableData"):
            return {"bytes"}
        if cls in ("NSArray", "NSMutableArray", "NSSet", "NSMutableSet",
                   "NSOrderedSet"):
            return {"__repeated__"}
        if cls in ("NSDictionary", "NSMutableDictionary"):
            return {"__map__"}
        if cls == "":
            return None            # id / unknown
        return {"__message__", cls}
    if e.startswith("@"):
        return None
    if e.startswith("{") or e.startswith("("):
        return {"__struct__"}      # inline C struct (repeated bytes / message)
    return None


def main():
    fw = sys.argv[1]
    ctx, st, cl = load(fw)
    msgs = E.extract_all(ctx, st, cl)
    n_fields = n_check = n_ok = 0
    contradictions = []
    unmatched = 0
    for m in msgs:
        c = cl.find(m.class_name)
        if c is None:
            continue
        ivars = {iv.name: iv for iv in c.ivars}
        for f in m.fields:
            n_fields += 1
            iv = ivars.get("_" + f.name) or ivars.get(f.name)
            if iv is None:
                # try case-insensitive / has-suffix
                cand = [v for k, v in ivars.items()
                        if k.lstrip("_").lower() == f.name.lower()]
                iv = cand[0] if cand else None
            if iv is None:
                unmatched += 1
                continue
            fam = enc_family(iv.type_enc)
            if fam is None:
                continue
            n_check += 1
            tcat = _tool_cat(f)
            ok = _consistent(tcat, fam, f)
            if ok:
                n_ok += 1
            else:
                contradictions.append(
                    (m.class_name, f.name, f.number, f.type_name,
                     f.label.value if hasattr(f.label, "value") else str(f.label),
                     iv.type_enc))
    print(f"\n== {fw}: {n_fields} fields, {n_check} type-checked vs @encode, "
          f"{n_ok} consistent, {len(contradictions)} CONTRADICTIONS, "
          f"{unmatched} ivar-unmatched ==")
    for cls, nm, num, tn, lbl, enc in contradictions:
        print(f"   {cls}.{nm} #{num}: tool={lbl} {tn!r}  vs  ivar @encode {enc!r}")


def _tool_cat(f):
    return f.type_name


def _consistent(tn, fam, f):
    lbl = f.label.value if hasattr(f.label, "value") else str(f.label)
    is_enum = bool(f.type_class and str(f.type_class).startswith("ENUM:"))
    if "__repeated__" in fam:
        return lbl == "repeated" or tn in ("bytes",)  # repeated, elem checked elsewhere
    if "__map__" in fam:
        return True            # map<> not modeled; tool emits bytes/message — accept
    if "__struct__" in fam:
        return True            # inline C struct -> bytes/repeated; accepted
    if "__message__" in fam:
        # ivar is a concrete ObjC class pointer -> message (or string/bytes/enum
        # via a boxed type).  Accept message/enum/string/bytes, reject pure numerics.
        return tn not in ("double", "float", "bool") or tn in fam
    # integer/scalar families: an enum over an int ivar is wire-consistent.
    if is_enum and (fam & (INT32 | INT64)):
        return True
    if tn in fam:
        return True
    return False


if __name__ == "__main__":
    main()
