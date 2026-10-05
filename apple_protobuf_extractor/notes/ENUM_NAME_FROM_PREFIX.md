# Enum type-name from value-string prefix: principled status + confirmation-tier task

**Status:** analysis done 2026-06-09, **no code change**. Conclusion: the feature is
already essentially principled (convention-decode on ground-truth strings), NOT a
name-overlap guess. There IS one real upgrade available — a selector-confirmation
tier — written up as a task below.

## What the feature is

`_enum_name_from_pairs` (proto/extractor.py:1632; registry id `enumname-prefix`,
judged INTRINSIC) derives an enum's canonical **type name** from the common
SCREAMING_SNAKE prefix of its value strings:

```
values MAPS_RESULT_TYPE_UNKNOWN, MAPS_RESULT_TYPE_PLACE, …
  → common prefix MAPS_RESULT_TYPE
  → CamelCase  MapsResultType
fallback = ivar-derived name (e.g. _resultType → "ResultType")
```

Guards: ≥2 pairs, ≥2 SCREAMING_SNAKE values, common prefix must be ≥2 words; else
returns the ivar-derived fallback. Applied at extractor.py:3777 (renames the
`ENUM:<name>` tag + updates `seen_enum_names`).

## Why it is NOT a heuristic name-guess (unlike Strategy 2)

- The value strings (`MAPS_RESULT_TYPE_*`) are **ground truth** — the literal
  identifiers the binary's `xAsString:` pointer table returns, read by the
  principled enum-value extraction path.
- protoc / Apple's generator emits enum value identifiers deterministically as
  `<ENUM_TYPE_SCREAMING>_<VALUE>`. The feature inverts that deterministic
  convention. It does not match names against a classlist pool.
- Hence INTRINSIC is the correct registry judgment.

## Empirical: there is NO stronger structural source for the type-name qualifier

Verified on the docstring's own example, `GEOPDMapsResult` (ivar `_resultType`,
values `MAPS_RESULT_TYPE_*`). Its only enum-related code artifacts are
**field-named**:
```
ivar:       _resultType            (off 0x4c, type 'i')
selectors:  resultType, setResultType:, hasResultType, setHasResultType:,
            resultTypeAsString:, StringAsResultType:
```
None carries the `Maps` qualifier. `_enum_name_from_methname` (extractor.py:1609)
keys on `{field}AsString:` / `StringAs{Field}:` — i.e. the FIELD name — so it would
only ever yield `ResultType`. The `Maps` qualifier that distinguishes the enum TYPE
from the field exists **only** inside the value strings. ⇒ the value-string prefix
is the most principled signal available for the type name; every alternative (ivar,
field-named selector) is strictly weaker (loses the qualifier, collapses to the
field name = the existing fallback).

The only genuinely heuristic residue is the prefix-trimming mechanics + guards,
which are conservative (fall back to the field name when unsure).

## TASK — add a selector-CONFIRMATION tier (promote convention-decode → confirmed)

Don't replace the signal (nothing stronger exists); **certify** it against the
binary's global `__objc_methname` selector pool, which contains `StringAs<X>:` /
`<x>AsString:` selectors across ALL classes.

Mechanism:
1. Derive the CamelCase type name from the value prefix (as today) → e.g.
   `MapsResultType`.
2. Look for `StringAs<Derived>:` or `<derivedLowerFirst>AsString:` ANYWHERE in the
   string table (`st.find(...)`). For `MapsResultType`, `StringAsMapsResultType:`
   **does exist** in GeoServices (on some other class with a `mapsResultType`
   field) → the derived type name is structurally **confirmed** by a real generated
   selector, not just convention.
3. If such a selector exists → mark confirmed. If not → keep the derived name but
   treat it as convention-only; optionally flag with an inline comment (mirror the
   Strategy-2 `type_inference_note` / warning-comment pattern) so unconfirmed
   derivations are visible.

This can't surface names the prefix doesn't already produce — it CERTIFIES them and
flags the uncertain ones. Net: turns a convention-decode into a ground-truth match
where a selector witnesses the type name.

See also: `FIELD_TYPE_INFERENCE.md`.
