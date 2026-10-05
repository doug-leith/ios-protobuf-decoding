# Enum type-name from value-string prefix: why it is principled

**Status:** analysis done 2026-06-09. Conclusion: the feature is essentially principled
(convention-decode on ground-truth strings), NOT a name-overlap guess.

## What the feature is

`_enum_name_from_pairs` (`proto/enums.py`) derives an enum's canonical **type name** from the common
SCREAMING_SNAKE prefix of its value strings:

```
values MAPS_RESULT_TYPE_UNKNOWN, MAPS_RESULT_TYPE_PLACE, …
  → common prefix MAPS_RESULT_TYPE
  → CamelCase  MapsResultType
fallback = ivar-derived name (e.g. _resultType → "ResultType")
```

Guards: ≥2 pairs, ≥2 SCREAMING_SNAKE values, common prefix must be ≥2 words; else
returns the ivar-derived fallback. The caller renames the
`ENUM:<name>` tag and updates `seen_enum_names`.

## Why it is NOT a heuristic name-guess (unlike Strategy 2)

- The value strings (`MAPS_RESULT_TYPE_*`) are **ground truth** — the literal
  identifiers the binary's `xAsString:` pointer table returns, read by the
  principled enum-value extraction path.
- protoc / Apple's generator emits enum value identifiers deterministically as
  `<ENUM_TYPE_SCREAMING>_<VALUE>`. The feature inverts that deterministic
  convention. It does not match names against a classlist pool.
- Hence the type name is a genuine reconstruction, not a recoverable proto fact.

## Empirical: there is NO stronger structural source for the type-name qualifier

Verified on the docstring's own example, `GEOPDMapsResult` (ivar `_resultType`,
values `MAPS_RESULT_TYPE_*`). Its only enum-related code artifacts are
**field-named**:
```
ivar:       _resultType            (off 0x4c, type 'i')
selectors:  resultType, setResultType:, hasResultType, setHasResultType:,
            resultTypeAsString:, StringAsResultType:
```
None carries the `Maps` qualifier. `_enum_name_from_methname` (`proto/enums.py`)
keys on `{field}AsString:` / `StringAs{Field}:` — i.e. the FIELD name — so it would
only ever yield `ResultType`. The `Maps` qualifier that distinguishes the enum TYPE
from the field exists **only** inside the value strings. ⇒ the value-string prefix
is the most principled signal available for the type name; every alternative (ivar,
field-named selector) is strictly weaker (loses the qualifier, collapses to the
field name = the existing fallback).

The only genuinely heuristic residue is the prefix-trimming mechanics + guards,
which are conservative (fall back to the field name when unsure).

See also: `FIELD_TYPE_INFERENCE.md`.
