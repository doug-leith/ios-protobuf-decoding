"""Before/after diff for the adder->ivar lever.

Runs the REAL extract_all with the lever ON (default) and OFF (monkeypatch
_resolve_repeated_via_dispatch_ivars -> {}) over GeoServices / locationd /
CoreLocationProtobuf, then diffs every emitted field.

Pass criteria (precision over recall):
  * 0 type changes that override an existing concrete MESSAGE type with a
    DIFFERENT concrete message (a mis-bind).
  * 0 `repeated string` -> X changes (never break an ABI-confirmed string).
  * every type change is bytes->message OR a Strategy-2 guess replaced by a
    dispatch ground-truth message.
Field-number changes are reported separately (expected: estimated->confirmed,
plus estimated-ordinal reflow).

Run: ./venv/bin/python3 validate_lever.py
"""
import os
import artifacts
import proto.extractor as E
from proto.models import FieldLabel
from proto.repeated import _resolve_repeated_via_dispatch_ivars

# All artifact locations come from the single config module ``artifacts`` (the
# data dir defaults to <repo>/iphone8_data; override via MACHO_DATA_DIR).
_ROOT = artifacts.REPO_ROOT


def _load_cache(image):
    from macho.dyld_cache import DyldCacheReader
    from macho.memory import BinaryContext
    from macho.strings import build_string_table
    from macho import classlist as CL
    from macho.local_symbols import apply_to_classes
    cache = artifacts.cache_file()
    if cache is None:
        return None
    reader = DyldCacheReader(cache)
    mv = reader.find_image_header(image)
    if mv is None:
        return None
    ctx = BinaryContext.from_cache(reader, mv)
    st = build_string_table(ctx)
    cl = CL.build_class_list(ctx, st)
    syms = reader.image_local_symbols(mv)
    if syms:
        apply_to_classes(cl, syms)
    return ctx, st, cl


def _load_binary(envvar, default):
    """Load a standalone Mach-O binary -> (ctx, st, cl).  ``envvar`` overrides the
    default path (``<data_dir>/<default>``).  Shared by the census/probe scripts;
    the artifact location is defined in exactly one place (the ``artifacts`` module)."""
    from macho.memory import BinaryContext
    from macho.strings import build_string_table
    from macho import classlist as CL
    path = os.environ.get(envvar, "").strip() or \
        os.path.join(artifacts.data_dir(), default)
    if not os.path.isfile(path):
        return None
    with open(path, "rb") as fh:
        ctx = BinaryContext(fh.read())
    st = build_string_table(ctx)
    cl = CL.build_class_list(ctx, st)
    return ctx, st, cl


def _load_locationd():
    return _load_binary("MACHO_TEST_LOCATIOND", "locationd")


def _snapshot(loaded):
    """Return {(class, fieldname): (type_name, type_class, number, conf, note)}."""
    if loaded is None:
        return None
    ctx, st, cl = loaded
    # Clear per-ctx caches so ON/OFF runs are independent of prior memoisation.
    for attr in ("_dispatch_arms_cache", "_wrapper_cluster_cache"):
        if hasattr(ctx, attr):
            delattr(ctx, attr)
    msgs = E.extract_all(ctx, st, cl)
    snap = {}
    for m in msgs:
        for f in m.fields:
            snap[(m.class_name, f.name)] = (
                f.type_name, f.type_class, f.number,
                f.number_confirmed, bool(f.type_inference_note))
    return snap


def _is_msg(tc):
    return bool(tc) and not tc.startswith("ENUM:") and tc not in (
        "NSArray", "NSMutableArray")


def run(label, loader):
    loaded = loader()
    if loaded is None:
        print(f"\n== {label}: SKIPPED (not found) ==")
        return
    # OFF
    _orig = _resolve_repeated_via_dispatch_ivars
    _resolve_repeated_via_dispatch_ivars = lambda *a, **k: {}
    off = _snapshot(loaded)
    _resolve_repeated_via_dispatch_ivars = _orig
    # ON
    on = _snapshot(loaded)

    type_changes = []
    num_changes = []
    note_removed = []   # Strategy-2 warning comment dropped (guess → confirmed truth)
    note_added = []     # should be empty — never introduce a guess
    for key in sorted(on):
        o = off.get(key)
        n = on[key]
        if o is None:
            continue
        if (o[0], o[1]) != (n[0], n[1]):
            type_changes.append((key, o, n))
        if (o[2], o[3]) != (n[2], n[3]):
            num_changes.append((key, o, n))
        if o[4] and not n[4]:
            note_removed.append((key, o, n))
        elif not o[4] and n[4]:
            note_added.append((key, o, n))

    # Classify type changes.
    bytes_to_msg = []        # bytes -> concrete message (the prize)
    guess_to_truth = []      # had a note (Strategy 2 guess) -> message, note gone
    bad = []                 # anything else (mis-bind / string broken / regress)
    for key, o, n in type_changes:
        o_tn, o_tc, _, _, o_note = o
        n_tn, n_tc, _, _, n_note = n
        if o_tn == "string" or n_tn == "string":
            bad.append((key, o, n, "string-involved"))
        elif not _is_msg(o_tc) and _is_msg(n_tc):
            (guess_to_truth if o_note else bytes_to_msg).append((key, o, n))
        elif _is_msg(o_tc) and _is_msg(n_tc) and o_tc != n_tc:
            bad.append((key, o, n, "concrete-override"))
        else:
            bad.append((key, o, n, "other"))

    print(f"\n{'='*72}\n== {label} ==\n{'='*72}")
    print(f"type changes: {len(type_changes)}  "
          f"(bytes→msg {len(bytes_to_msg)}, guess→truth {len(guess_to_truth)}, "
          f"BAD {len(bad)})")
    print(f"number changes: {len(num_changes)}")
    if bytes_to_msg:
        print("\n  bytes→message (sample):")
        for key, o, n in bytes_to_msg[:12]:
            print(f"    {key[0]}.{key[1]}: {o[1]} → {n[1]}  (#{o[2]}→#{n[2]})")
    if guess_to_truth:
        print("\n  Strategy-2 guess → dispatch truth (sample):")
        for key, o, n in guess_to_truth[:12]:
            print(f"    {key[0]}.{key[1]}: {o[1]} → {n[1]}")
    if bad:
        print(f"\n  *** BAD CHANGES ({len(bad)}) ***")
        for key, o, n, why in bad[:40]:
            print(f"    [{why}] {key[0]}.{key[1]}: "
                  f"{o[1]}(note={o[4]}) → {n[1]}(note={n[4]})  #{o[2]}→#{n[2]}")
    # Number-change classification.
    n_est_to_conf = sum(1 for _k, o, n in num_changes if not o[3] and n[3])
    n_conf_changed = sum(1 for _k, o, n in num_changes if o[3] and n[3])
    n_reflow = sum(1 for _k, o, n in num_changes if not o[3] and not n[3])
    print(f"\n  number: estimated→confirmed {n_est_to_conf}, "
          f"confirmed→confirmed(value changed!) {n_conf_changed}, "
          f"estimated reflow {n_reflow}")
    print(f"  Strategy-2 warning removed (guess confirmed): {len(note_removed)}; "
          f"warning ADDED (must be 0): {len(note_added)}")
    if note_removed:
        for key, o, n in note_removed[:12]:
            print(f"    note-off {key[0]}.{key[1]}: {n[1]} "
                  f"(#{o[2]}→#{n[2]}, conf {o[3]}→{n[3]})")
    if n_conf_changed:
        print("    *** confirmed-number VALUE changed (investigate): ***")
        for _k, o, n in [x for x in num_changes if x[1][3] and x[2][3]][:20]:
            print(f"      {_k[0]}.{_k[1]}: #{o[2]} → #{n[2]}")
    return len(bad), n_conf_changed, len(note_added)


def main():
    results = []
    results.append(run("GeoServices (cache)", lambda: _load_cache("GeoServices")))
    results.append(run("locationd (binary)", _load_locationd))
    results.append(run("CoreLocationProtobuf (cache)",
                       lambda: _load_cache("CoreLocationProtobuf")))
    print(f"\n{'='*72}")
    bad_total = sum(r[0] for r in results if r)
    conf_total = sum(r[1] for r in results if r)
    addnote_total = sum(r[2] for r in results if r)
    print(f"TOTAL bad type changes: {bad_total}; confirmed-number value changes: "
          f"{conf_total}; warnings added: {addnote_total}")
    ok = bad_total == 0 and conf_total == 0 and addnote_total == 0
    print("PASS" if ok else "FAIL — investigate")


if __name__ == "__main__":
    main()
