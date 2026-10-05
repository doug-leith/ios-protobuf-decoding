"""Census for the enum-name selector-confirmation tier (ENUM_NAME_FROM_PREFIX.md).

For every enum where `_enum_name_from_pairs` derives a name different from the
ivar-derived fallback, check whether the binary's global `__objc_methname`
selector pool contains a witnessing selector:
    StringAs<Derived>:   or   <derivedLowerFirst>AsString:

A match means the value-string-prefix derivation is structurally CONFIRMED by a
real generated selector (not just convention). The unmatched remainder is the set
worth flagging.

Run: ./venv/bin/python3 census_enumname.py
"""
import proto.extractor as E
import proto.enums as EN     # patch the override on the module that *calls* it
from validate_lever import _load_cache, _load_binary    # shared artifact loaders


def _witness(st, derived):
    """Selector(s) in the pool that witness `derived` as a type name, or []."""
    lower_first = derived[0].lower() + derived[1:]
    hits = []
    for sel in (f"StringAs{derived}:", f"{lower_first}AsString:"):
        if st.find(sel):
            hits.append(sel)
    return hits


def run(label, loader):
    loaded = loader()
    if loaded is None:
        print(f"\n== {label}: SKIPPED (not found) ==")
        return None
    ctx, st, cl = loaded

    derivations = []  # (fallback, derived)
    # _enum_name_from_pairs is called by _collect_enum_definitions (in proto.enums)
    # via the module global, so the wrapper must replace it on that module — a local
    # rebind here would never reach the real call site.
    _orig = EN._enum_name_from_pairs

    def _wrapped(pairs, fallback):
        out = _orig(pairs, fallback)
        if out != fallback:
            derivations.append((fallback, out))
        return out

    EN._enum_name_from_pairs = _wrapped
    try:
        E.extract_all(ctx, st, cl)
    finally:
        EN._enum_name_from_pairs = _orig

    # Dedup on (fallback, derived) — same enum can be visited per-field.
    uniq = sorted(set(derivations))
    confirmed = []
    unconfirmed = []
    for fb, dv in uniq:
        w = _witness(st, dv)
        (confirmed if w else unconfirmed).append((fb, dv, w))

    total = len(uniq)
    print(f"\n{'='*72}\n== {label} ==\n{'='*72}")
    print(f"distinct derived!=fallback enums: {total}")
    if total:
        print(f"  CONFIRMED by selector pool: {len(confirmed)} "
              f"({100*len(confirmed)//total}%)")
        print(f"  unconfirmed (convention-only): {len(unconfirmed)}")
    if confirmed:
        print("\n  confirmed (sample):")
        for fb, dv, w in confirmed[:15]:
            print(f"    {fb:<28} → {dv:<32} via {w[0]}")
    if unconfirmed:
        print("\n  UNCONFIRMED (sample — these would be flagged):")
        for fb, dv, w in unconfirmed[:25]:
            print(f"    {fb:<28} → {dv}")
    return total, len(confirmed), len(unconfirmed)


def main():
    rs = []
    rs.append(run("GeoServices (cache)", lambda: _load_cache("GeoServices")))
    rs.append(run("locationd (binary)",
                  lambda: _load_binary("MACHO_TEST_LOCATIOND", "locationd")))
    rs.append(run("CoreLocationProtobuf (cache)",
                  lambda: _load_cache("CoreLocationProtobuf")))
    rs = [r for r in rs if r]
    t = sum(r[0] for r in rs)
    c = sum(r[1] for r in rs)
    u = sum(r[2] for r in rs)
    print(f"\n{'='*72}")
    print(f"TOTAL distinct derivations: {t}; confirmed: {c} "
          f"({(100*c//t) if t else 0}%); unconfirmed: {u}")


if __name__ == "__main__":
    main()
