"""
Census of repeated-field element-type resolution paths.

For every repeated field across an entire binary, record WHICH resolver named
its element type, then tally:

    dispatch              — principled readFrom: jump-table walk (by address)
    Strategy1_metaclass   — +[Cls xyzType] metaclass method (structural)
    Strategy2_namesuffix  — unique classlist suffix match (name heuristic)
    repeated_string       — reclassified to `repeated string`
    unresolved_bytes      — stayed `repeated bytes` (the safe fallback)

History: this census (run 2026-06-08 over GeoServices / locationd /
CoreLocationProtobuf) showed the two former name-overlap fallbacks — Pass A
(exact pool-suffix) and Pass B (word-overlap remainder) — resolved ZERO fields
even where their metaclass-pool gate fired.  They were removed from
proto/extractor.py on 2026-06-08; an unresolved repeated field now falls back to
the safe `repeated bytes`.  This script is kept as a re-runnable regression check
that the surviving paths (dispatch / Strategy 1 / Strategy 2) still carry the
load they did before.

Method: monkeypatch the resolution entrypoints to capture provenance, then run
the REAL `extract_all`.  Provenance is keyed by (class, proto-field-name); the
tally is driven off the real emitted fields, so it reflects exactly what the
production loop produced (no re-implementation of the decision tree).

Run:
    python3 census_repeated.py
"""
from collections import Counter, defaultdict

import proto.extractor as E
from proto.models import FieldLabel
from proto.repeated import (_build_meta_type_pool, _repeated_element_type,
                            _resolve_repeated_field_type, _resolve_repeated_via_dispatch)
from validate_lever import _load_cache, _load_binary    # shared artifact loaders

# ── Provenance capture state ──────────────────────────────────────────────────
_CUR = {"cls": None}
_DISPATCH: dict = defaultdict(dict)      # clsname -> {field_number: class}
_RFT: dict = {}                          # (clsname, pname) -> bucket
_POOL = {"built": 0, "nonempty": 0}      # meta-type pool diagnostics


def _classify_rft(ivar, pname, imn, metaclass, cl, ctx, res):
    """Label a _resolve_repeated_field_type outcome by its originating path."""
    if res.type_class:                               # concrete class assigned
        type_sel = _repeated_element_type(ivar, imn, metaclass, cl)
        singular = pname.rstrip("s") if pname.endswith("s") else pname
        is_meta = (type_sel in (f"{singular}Type", f"{pname}Type")
                   and metaclass is not None
                   and any(m.name == type_sel for m in metaclass.methods))
        return "Strategy1_metaclass" if is_meta else "Strategy2_namesuffix"
    if res.type_name == "string":                    # S1-string or write-helper
        return "repeated_string"
    return "unresolved_bytes"


def _install_hooks():
    _o_epm = E.extract_proto_message
    _o_disp = _resolve_repeated_via_dispatch
    _o_rft = _resolve_repeated_field_type
    _o_pool = _build_meta_type_pool

    def build_pool(ctx, st, metaclass, cls, cl):
        r = _o_pool(ctx, st, metaclass, cls, cl)
        _POOL["built"] += 1
        if r:
            _POOL["nonempty"] += 1
        return r

    def epm(ctx, st, cl, cls, **kw):
        _CUR["cls"] = cls.name
        return _o_epm(ctx, st, cl, cls, **kw)

    def disp(ctx, cls, core_index):
        r = _o_disp(ctx, cls, core_index)
        if r:
            _DISPATCH[cls.name] = dict(r)
        return r

    def rft(ivar, pname, imn, metaclass, cl, ctx, pool, string_helper, wt_helpers):
        res = _o_rft(ivar, pname, imn, metaclass, cl, ctx, pool,
                     string_helper, wt_helpers)
        try:
            bucket = _classify_rft(ivar, pname, imn, metaclass, cl, ctx, res)
        except Exception:
            bucket = "unresolved_bytes"
        # Store the heuristic-alone outcome too; the extractor now always runs
        # the heuristic (to protect ABI strings), so a field is attributed to
        # "dispatch" only when the FINAL emitted type differs from this.
        _RFT[(_CUR["cls"], pname)] = (bucket, res.type_name, res.type_class)
        return res

    _build_meta_type_pool = build_pool
    E.extract_proto_message = epm
    _resolve_repeated_via_dispatch = disp
    _resolve_repeated_field_type = rft


def _is_enum_tc(tc):
    return bool(tc) and tc.startswith("ENUM:")


def _bucket_for(clsname, f):
    """Final bucket for one repeated field, driven off the real emitted field.

    The extractor always runs the name heuristic, so attribute a field to
    "dispatch" only when the FINAL emitted type differs from what the heuristic
    alone produced (i.e. dispatch changed or filled it).  Otherwise classify by
    the heuristic's own provenance.  This counts dispatch's NET contribution
    (fields it resolved that the heuristics did not / got differently).
    """
    key = (clsname, f.name)
    if key not in _RFT:
        return "dispatch"
    bucket, h_name, h_class = _RFT[key]
    if (f.type_name, f.type_class) != (h_name, h_class):
        return "dispatch"
    return bucket


# ── Per-binary drivers ────────────────────────────────────────────────────────

def _run_cache_image(image_name):
    loaded = _load_cache(image_name)
    return E.extract_all(*loaded) if loaded else None


def run_geoservices():
    return _run_cache_image("GeoServices")


def run_corelocationprotobuf():
    return _run_cache_image("CoreLocationProtobuf")


def run_locationd():
    loaded = _load_binary("MACHO_TEST_LOCATIOND", "locationd")
    return E.extract_all(*loaded) if loaded else None


# ── Tally + report ────────────────────────────────────────────────────────────

def report(label, msgs, pool_stats=None):
    counts = Counter()
    msg_resolved = Counter()       # only fields that ended as a concrete message
    examples = defaultdict(list)

    for m in msgs:
        for f in m.fields:
            if f.label is not FieldLabel.REPEATED:
                continue
            if _is_enum_tc(f.type_class):
                continue           # repeated enum: skips the resolution block
            b = _bucket_for(m.class_name, f)
            counts[b] += 1
            is_msg = bool(f.type_class) and not _is_enum_tc(f.type_class)
            if is_msg:
                msg_resolved[b] += 1
                if len(examples[b]) < 4:
                    examples[b].append(f"{m.class_name}.{f.name}→{f.type_class}")
    total = sum(counts.values())
    total_msg = sum(msg_resolved.values())
    order = ["dispatch", "Strategy1_metaclass", "Strategy2_namesuffix",
             "repeated_string", "unresolved_bytes"]

    print(f"\n{'='*72}\n{label}: {len(msgs)} messages, "
          f"{total} repeated fields (non-enum)\n{'='*72}")
    print(f"{'bucket':<22}{'all repeated':>14}{'→ message':>12}")
    print("-" * 48)
    for b in order:
        if counts[b] or msg_resolved[b]:
            print(f"{b:<22}{counts[b]:>14}{msg_resolved[b]:>12}")
    print("-" * 48)
    print(f"{'TOTAL':<22}{total:>14}{total_msg:>12}")

    if pool_stats is not None:
        print(f"\nMetaclass-type pool gate: built for {pool_stats['built']} "
              f"classes, non-empty for {pool_stats['nonempty']} (now consulted "
              f"only for the Strategy-1/2 refinement)")

    print(f"\nMessage fields resolved by Strategy2 (name-suffix): "
          f"{msg_resolved['Strategy2_namesuffix']}")
    print(f"Message fields resolved by dispatch (principled):   "
          f"{msg_resolved['dispatch']}")
    print(f"Message fields resolved by Strategy1 (metaclass):   "
          f"{msg_resolved['Strategy1_metaclass']}")

    print("\nExamples per bucket (message-typed):")
    for b in order:
        if examples[b]:
            print(f"  {b}:")
            for e in examples[b]:
                print(f"      {e}")

    print("\n('dispatch' = fields where the principled dispatch produced a type "
          "the name heuristics did not / got differently — its NET contribution.)")


def main():
    _install_hooks()

    print("Loading GeoServices (cache) …", flush=True)
    geo = run_geoservices()
    if geo is None:
        print("  (cache not found — skipping GeoServices)")
    geo_RFT, geo_DISP, geo_POOL = dict(_RFT), dict(_DISPATCH), dict(_POOL)
    _RFT.clear(); _DISPATCH.clear(); _POOL.update(built=0, nonempty=0)

    print("Loading locationd (binary-only) …", flush=True)
    loc = run_locationd()
    if loc is None:
        print("  (locationd not found — skipping)")
    loc_RFT, loc_DISP, loc_POOL = dict(_RFT), dict(_DISPATCH), dict(_POOL)
    _RFT.clear(); _DISPATCH.clear(); _POOL.update(built=0, nonempty=0)

    print("Loading CoreLocationProtobuf (cache) …", flush=True)
    clp = run_corelocationprotobuf()
    if clp is None:
        print("  (CoreLocationProtobuf not found — skipping)")
    clp_RFT, clp_DISP, clp_POOL = dict(_RFT), dict(_DISPATCH), dict(_POOL)

    def _restore(rft, disp):
        _RFT.clear(); _RFT.update(rft)
        _DISPATCH.clear(); _DISPATCH.update(disp)

    if geo is not None:
        _restore(geo_RFT, geo_DISP)
        report("GeoServices (cache-native)", geo, geo_POOL)
    if loc is not None:
        _restore(loc_RFT, loc_DISP)
        report("locationd (binary-only)", loc, loc_POOL)
    if clp is not None:
        _restore(clp_RFT, clp_DISP)
        report("CoreLocationProtobuf (cache-native)", clp, clp_POOL)


if __name__ == "__main__":
    main()
