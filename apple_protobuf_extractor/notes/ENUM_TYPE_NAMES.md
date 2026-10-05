# Why enum *type* names are reconstructed (and why a wrong one is harmless)

Each `enum X { … }` block in the emitted `.proto` carries a reminder comment:

```proto
// type name reconstructed from value-string prefix; may be inexact
// (cosmetic only) — see ENUM_TYPE_NAMES.md
enum MapsResultType {
  MAPS_RESULT_TYPE_UNKNOWN = 0;
  MAPS_RESULT_TYPE_PLACE   = 1;
}
```

This document explains what that means: the enum **type name** is the one part of
a recovered enum that is *not* read from the binary, why that is unavoidable, how
the name is reconstructed, how accurate it is, and why an incorrect name has no
real consequences.

> **One-line summary:** the enum's *values* and their *numbers* are ground truth
> read from the binary; only the enum's *type name* is inferred, and getting it
> wrong costs nothing but a cosmetic label.

---

## 1. The enum type name is not in the binary

Apple's protobuf enums compile to **plain C enums** (`typedef enum { … } SomeType;`).
A C enum type name is a *source-level* construct. Unlike an Objective-C
`@interface` class — which gets a real `__objc_classname` entry and runtime
metadata — a C enum produces **no symbol, no class record, no RTTI**. After
compilation the typedef name is simply gone, and the shipping **dyld shared cache
is stripped**, so the DWARF debug info that *would* carry it isn't present either.

We verified this directly against the GeoServices cache. Searching every string
section for known-correct enum type names:

| type name | found in binary? | where |
|---|---|---|
| `AutocompleteResultHighlightType` | **no** — absent entirely | — |
| `MapsResultType` | only as a **field** name | `StringAsMapsResultType:`, `hasMapsResultType`, … |
| `RealtimeStatus` | only as a **field** name | `StringAsRealtimeStatus:`, `setRealtimeStatus:` |

`AutocompleteResultHighlightType` is a perfectly correct type name that **does not
appear anywhere** in the binary. The other two appear *only* because some class
happens to have a property whose name coincides with the type name — those are
**field** symbols, not a symbol for the enum type itself.

The only enum-related symbols that survive name the **field**, not the type:
the selectors (`resultTypeAsString:`, `StringAsResultType:`) and the ivar
(`_resultType`). A field name like `resultType` is missing the type's
distinguishing qualifier — it cannot tell you the type is `MapsResultType` rather
than some other `…ResultType`.

## 2. How the name is reconstructed

The type's qualifier survives in exactly one place: the **value strings**. Because
`protoc` emits enum value identifiers as `<TYPE_NAME_SCREAMING>_<VALUE>`, the
common prefix of the values *is* the type name, encoded indirectly:

```
values MAPS_RESULT_TYPE_UNKNOWN, MAPS_RESULT_TYPE_PLACE, …
  → common prefix  MAPS_RESULT_TYPE
  → CamelCase       MapsResultType
```

`_enum_name_from_pairs` (in `proto/extractor.py`) inverts that convention. When
the values share no multi-word SCREAMING prefix (≈ ¾ of enums store **bare** value
names like `STATE`, `CITY`, `UNKNOWN`), there is no prefix to invert, so the name
falls back to the class-qualified, field-derived name (e.g.
`CoarseLocationTerritoryInfoTerritoryType`). This is the strongest — and usually
the only — signal available for the type name.

This is a deterministic decode of a real generator convention over ground-truth
strings, **not** a guess matched against a symbol pool. (See also the registry
judgment `enumname-prefix` = INTRINSIC.)

## 3. How accurate it is

Manually adjudicating a stratified sample against the value-string prefix (the
authoritative `protoc` source for the name):

- **Wrong identification (wrong words / wrong type): ~0%.** Every name examined
  faithfully matched the value-string prefix. Where the derived name *differs from
  the class/field* (e.g. values say `PLACE` but the class says `Entity`, or values
  say `TYPE` but the field says `Name`), the derivation is *more* correct — it
  follows the values, which are authoritative for the enum's own name.
- **Cosmetic acronym mis-casing: ~1 in 6.** Leading acronyms get title-cased
  because the SCREAMING value treats them as a single token: `AB`→`Ab`, `AP`→`Ap`,
  `AR`→`Ar`, `POI`→`Poi` (`ApLayout` instead of `APLayout`). The *words* are right;
  only the capitalization of the acronym is off.

So the realistic failure mode is not "wrong enum" — it is "right enum, slightly
ugly name."

## 4. Why a wrong type name is harmless

The enum type name is a **label**. It affects nothing functional:

- **Wire format / semantics — zero impact.** A proto enum field is encoded as a
  varint (the integer *value*) under a field number. The type name never appears
  on the wire. Serialization, deserialization, round-tripping, and interop with
  Apple's real service are identical regardless of what the enum is called. The
  actual enum semantics — the `(value → number)` mapping, e.g. `PLACE = 1` — are
  extracted independently from the value pairs and do not depend on the name.
- **Value labels — unaffected.** Because the type name is *derived from* the value
  prefix, the prefix it generates still matches the values (even mis-cased
  `AbRequestType` yields the correct `AB_REQUEST_TYPE_…` value labels).
- **`protoc` compilation — safe.** The only compile risk is a name collision (two
  enums in one scope sharing a name). The emitter's `_collect_enums` de-collides:
  it groups enums by name and, if same-named enums have *incompatible* values,
  splits them by prefixing the class name. The compatibility test keys on the
  **values**, not the name, so a wrong name can never cause two
  semantically-different enums to be silently merged. Worst case is a redundant
  duplicate or an auto-renamed enum.
- **What you actually lose: readability only.** A misleading identifier in the
  `.proto`. If you `protoc`-generate client code, your local symbol has the wrong
  name but still interoperates byte-for-byte.

Contrast this with a wrong field **number** or a wrong repeated-element **type** —
those *do* corrupt decoding and are treated with much more rigor elsewhere in the
tool. The enum type name sits at the opposite end of the risk spectrum, which is
why it is acceptable to infer it.

## 5. What about the value labels and their prefixes?

The value labels (`MAPS_RESULT_TYPE_PLACE`) and their numbers are **ground truth**
and reliable. The prefix on each label is required by protobuf, not stylistic:
enum value names use **C++ scoping rules** — they are siblings of the enum, living
in the enclosing scope, so they must be unique there. Apple's per-table runtime
representation stores ~¾ of values *bare* (`STATE`) because each `xAsString:`
lookup is its own isolated table with no collision risk; the tool re-synthesizes
the scope-qualifying prefix when flattening everything back into one `.proto`. See
`FIELD_TYPE_INFERENCE.md` for the analogous treatment of field *types*.

## Where this lives in the code

- `proto/extractor.py` — `_enum_name_from_pairs` (prefix → type name),
  `_enum_name_from_methname` / `_qualify_enum_name` (field-derived fallback),
  `_normalize_enum_value_name` (value-label prefixing).
- `proto/emitter.py` — `_ENUM_NAME_RECON_HEADER` (one-time section note) and
  `_ENUM_NAME_RECON_NOTE` (per-enum reminder), emitted in `build_file_text`'s enum
  block; `_collect_enums` / `_enums_compatible` (value-keyed de-collision).
- `proto/models.py` — `ProtoEnum.to_proto`.

See also: `FIELD_TYPE_INFERENCE.md`, `ENUM_NAME_FROM_PREFIX.md`,
`heuristic_registry.py` (id `enumname-prefix`).
