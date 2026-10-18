"""Snapshot every emitted proto field across the 3 artifacts, for an empty-diff
proof that a refactor leaves output byte-identical.

Usage:
    ./venv/bin/python3 snapshot_output.py /tmp/snap_before.json
    # ... make changes ...
    ./venv/bin/python3 snapshot_output.py /tmp/snap_after.json
    ./venv/bin/python3 snapshot_output.py --diff /tmp/snap_before.json /tmp/snap_after.json
"""
import json
import sys

import proto.extractor as E
import live_artifacts as V


def _snap_messages(msgs):
    out = {}
    for m in msgs:
        for f in m.fields:
            out[f"{m.class_name}.{f.name}"] = [
                f.type_name, f.type_class, f.number,
                # label (optional/repeated) is part of the field's identity — a
                # repeated->optional flip is a real regression, so snapshot it
                # (the writeTo-swap GEOPDComponent.values flip was invisible without
                # it).  FieldLabel is a str-Enum; store its .value for stable JSON.
                f.label.value if hasattr(f.label, "value") else str(f.label),
                f.number_confirmed, bool(f.type_inference_note),
                bool(getattr(f, "disambiguation_comment", None)),
            ]
            # Recovered map<K, V> (proto.mapfields).  Recorded only for map fields so the
            # golden diff stays a clean list of exactly the affected fields; the key
            # type + value type/class are what a map regression would silently change.
            # Wire encoding of a repeated scalar C-list (packed / expanded / unseen);
            # recorded only for those fields, like the map entry below.
            if getattr(f, "repeated_encoding", None):
                out[f"{m.class_name}.{f.name}.<encoding>"] = f.repeated_encoding
            if getattr(f, "map_key_type", None):
                out[f"{m.class_name}.{f.name}.<map>"] = [
                    f.map_key_type, f.map_value_type, f.map_value_class]
        # Per-message recovered enum value-sets.  The field-level keys above do
        # NOT capture enum VALUES, so an enum-value regression (e.g. the halfword
        # jump-table corruption) is invisible to a field-only snapshot.  Record
        # each enum's sorted value->name pairs plus its confirmed/truncated flags
        # so the golden guards the decoder output itself.  Keyed by the enum's
        # local name (unique per message); values as JSON-stable lists.
        for e in getattr(m, "enums", []):
            out[f"{m.class_name}.<enum:{e.name}>"] = [
                sorted([v.number, v.name] for v in e.values),
                bool(e.values_confirmed),
                bool(e.values_truncated),
            ]
        # Class-level dictRep enum-recovery truncation flag (emits a WARNING
        # comment).  Recorded only when True so the golden diff stays a clean
        # list of exactly the affected classes rather than a False per message.
        if getattr(m, "enum_recovery_truncated", False):
            out[f"{m.class_name}.<enum_recovery_truncated>"] = True
        # Class-level proto-to-proto inheritance note (TODO #46).  Recorded only
        # when set, so a recovered subclass with NO own fields (e.g.
        # GEOSearchRequest) is still visible in the snapshot via this key.
        if getattr(m, "inherits_from", None):
            out[f"{m.class_name}.<inherits_from>"] = m.inherits_from
        # Class-level opaque-passthrough flag (emits the distinct
        # "serializes only PBUnknownFields" comment).  Recorded only when True so
        # the golden diff is a clean list of exactly the flagged classes and a
        # field-less message that is NOT a passthrough still snapshots as before.
        if getattr(m, "opaque_passthrough", False):
            out[f"{m.class_name}.<opaque_passthrough>"] = True
        # Class-level "no writeTo: of its own" (the ancestor whose writeTo: serialises
        # it).  Recorded only when set, like the two flags above.
        if getattr(m, "serialised_by", None):
            out[f"{m.class_name}.<serialised_by>"] = m.serialised_by
        if getattr(m, "writes_no_ivars", False):
            out[f"{m.class_name}.<writes_no_ivars>"] = True
    return out


def capture(path):
    snap = {}
    for label, loaded in [
        ("GeoServices", V.load_cache("GeoServices")),
        ("locationd", V.load_locationd()),
        ("CoreLocationProtobuf", V.load_cache("CoreLocationProtobuf")),
    ]:
        if loaded is None:
            print(f"  {label}: SKIPPED (not found)")
            continue
        ctx, st, cl = loaded
        msgs = E.extract_all(ctx, st, cl)
        snap[label] = _snap_messages(msgs)
        print(f"  {label}: {len(snap[label])} fields")
    with open(path, "w") as fh:
        json.dump(snap, fh, indent=0, sort_keys=True)
    print(f"wrote {path}")


def diff(a_path, b_path):
    a = json.load(open(a_path))
    b = json.load(open(b_path))
    total = 0
    for label in sorted(set(a) | set(b)):
        ka, kb = a.get(label, {}), b.get(label, {})
        keys = set(ka) | set(kb)
        changed = [k for k in sorted(keys) if ka.get(k) != kb.get(k)]
        if changed:
            total += len(changed)
            print(f"\n{label}: {len(changed)} changed")
            for k in changed[:40]:
                print(f"  {k}: {ka.get(k)} -> {kb.get(k)}")
    print(f"\nTOTAL changed fields: {total}")
    print("EMPTY DIFF ✓" if total == 0 else "DIFF NON-EMPTY ✗")
    return total


if __name__ == "__main__":
    if sys.argv[1] == "--diff":
        sys.exit(1 if diff(sys.argv[2], sys.argv[3]) else 0)
    capture(sys.argv[1])
