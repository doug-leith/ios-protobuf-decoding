# Enums whose name map is inlined into `_dictionaryRepresentation:` (2026-10-13)

Status: **implemented, uncommitted** — `proto/dictrep_flow.py` (new), `proto/enums.py`
(`_harvest_dictrep_enums` body replaced, dead window helpers removed, caller passes `wanted`),
`tests/test_dictrep_inline_enums.py` + `tests/_a64asm.py` (new), `tests/test_dictrep_enums.py`
(fixtures rebuilt, xAsString-gate tests removed).
`ios_decoder/protos` and the paper were not touched.

## Why the Extractor typed these fields int32

The enum recovery already read `_dictionaryRepresentation:` (`_harvest_dictrep_enums`: jump-table, pointer-table and
compare-chain passes through 16/20-instruction look-back windows).  It returned **0 of the 37** ObjC-class fields in
the 45-field `more_specific_cases.tsv` of the private repo's Codex/Claude descriptor-recovery eval, for four independent reasons:

1. **Field attribution / table base by window.**  The window cannot see a *repeated* field's hoisted page register
   (`adrp x26` before the loop) or hoisted table base (`adrp x28; add x28`), and `find_adrp_add_target` returned the
   *first* pair in the window — the previous field's `csel x3, x9, x8` dictionary key (this alone failed scalar
   `GEOPDExtendedGeoLookupResult.status`).
2. **Hoisted names.**  In a loop the chain/table *selects* a name already in a register (`mov x24, x25; b merge`,
   `mov x24, x28; br x9`); the case block has no `adrp+add` of its own.
3. **Multi-segment sparse enums.**  `GEOPDBatchReverseGeocodingParameters.additionalPlaceTypes` is three dispatch sites
   (`sub w9,w8,#0x23; cmp w9,#0x1e` table, `cmp w8,#4` table, `cmp w8,#0x10`); the first site won and was unbiased
   (TIME_ZONE=0 instead of 35).  The same defect made three **existing** enums wrong (PlaceTypeHint, PlaceTypeLimit,
   VendorSpecific PlaceTypeHint) and two more mis-numbered (Candidate/OverallFilterReason: bias −0x3bc4 materialised in a
   register, values 15300… not 0…).
4. **Single named value.**  `WebModuleConfiguration.type` (WEB_MODULE_TYPE_GENERIC = 0, everything else prints
   `(unknown: %i)`) failed the `len(pairs) >= 2` rule.

Not the cause: the absence of `xAsString:` methods (that is the premise), `ENUM_NAME_FROM_PREFIX`, the seg_incomplete
bias gap.

## How the new recovery works (no windows)

The inlined converter is a function from the loaded int to a CFString, so it is recovered as one:

1. CFG of the dictRep body with jump-table arms injected (`proto/arm64cfg.py`, `_jump_table_arm_addrs`) and
   **reaching definitions**.  A register's constant (table base, hoisted name) is known iff exactly one definition reaches
   the use and it is a constant expression (`adrp`/`add`/`mov`/`movz`/`movk`).
2. **Field identity by use-def chain**: the loaded value's address traces back (through `add`, container deref, `mov`) to
   the `ldrsw` of the ivar-offset slot.  Hoisting no longer matters.
3. **Candidate values** from the comparisons the value takes part in (`V + b` affine tracking through `mov`/`add`/`sub`
   of immediates or constant registers; `sub w9,w8,#35; cmp w9,#30; b.hi` ⇒ 35..65; `cbz` ⇒ 0).
4. Each candidate (and one value outside all of them) is **evaluated** through the CFG (compares, `cbz`/`tbz`,
   `adr`+byte/half table+`br`, pointer-table loads, `csel`, hoisted `mov`) to the first call, stopping early when the
   path returns, tail-calls out, or reaches another field's value load.  At that call the string constant in each
   argument register x0-x7 is read.  Numbers therefore come from the constants the code compares/indexes with, bias
   included, never from name order; a segmented switch is one evaluation per value.  Value 0's pre-loaded name falls out
   of the same evaluation (no prefix guard).
5. **A field is an enum iff some argument register takes at least two different strings across the runs** — that
   register carries the name (two names; or a name and the converter's `"(unknown: %i)"` fallback on newer compilers).
   The dictionary key, selectors and class pointers are the same for every value, and a plain `+[NSNumber
   numberWithInt:]` int gives no string at all.  This covers every compiler shape seen: name in x2 of the dictionary
   call (newer), name in x0 of a retain call (old Xcode-built fixtures f28), and a default that skips the call entirely
   with no `(unknown: %i)` (f19, f24-hybrid).  It replaces the earlier "reaches `(unknown: %i)`" test, which was wrong:
   that fallback is not universal.  A single named value with nothing to vary against and no fallback (one case, rest
   skip the call) is not recognised — the name could be any constant string.

Remaining non-derived items: a safety bound on an ordered gate's span (≤ 2^12, the width of the unshifted `cmp` immediate)
and the enum **type name** (the binary holds only value names): the existing class+field name, refined by
`_enum_name_from_pairs` from the value prefix — a heuristic, as before.

## Results

* **37/37 ObjC-class fields recovered with names AND numbers (0 type-only)**; numbers agree with every Claude/Codex enum
  definition that exists for them.  Negative tests: `GEOPDSearchAddressLabeledToken.labelType` stays `int32`;
  `GEOPDDepartureSequence.operatingHoursCount` is untouched.
* Not in the 37: the 6 classless inline-struct fields (GenericTile.tileType, JunctionElement.type/usage,
  NavigationAudioFeedback.currentRouteTypeAtEndOfNav, Timepoint.type, VLFPositionContextClassification.type) — owned by the
  session "decode inline-struct child messages via parent".
* Golden diff caused by this change alone (same tree, only my files differing; the other session's uncommitted
  `structfields`/`mapfields`/`writeto`/`enums._valid_value_bitmask` edits are in both sides): GeoServices **42 int→enum
  fields (the 37 + 5 same-class: GEOComponentAction.actions, GEOHours.days, GEOSearchAttributionSource.attributionRequirements
  / suppressAttributionLogos, GEOTerritoryDataTerritoryInfo.territoryTypes), 42 new enum entries, 5 existing enums
  corrected (3 PlaceType: right numbers + value 0 `UNKNOWN_PLACE_TYPE`; 2 FilterReason: biased numbers)**; nothing lost.
  locationd and CoreLocationProtobuf **identical**.
* Portability sweep (10 frameworks, final code): 0 contradictions, 0 tool-missed, 42 estimated-flagged — identical to the
  baseline.  the unit suite: 1399 passed, 1 failed (`test_golden_GeoServices`, exactly the 89 keys below).
  Cost: the dictRep harvest over all 1637 GeoServices classes takes ~21 s CPU in total (worst class 2.6 s); the reaching-
  definitions solver sweeps blocks in reverse postorder (a FIFO worklist took 129 s on one 24k-instruction body).
* The golden diff is listed in `DICTREP_INLINE_ENUMS_golden_diff.md`; `tests/golden/GeoServices.json` was NOT regenerated.
* The other session's `_valid_value_bitmask` change once dropped 29 xAsString enums (GEOPDModule ModuleType 43 → 27 values);
  it was fixed on their side (`allow_tbnz=False` default), and the committed golden equals HEAD + their hunks exactly.

## How the enum decision was validated

Not by the `(unknown: %i)` census alone: that string is absent from the older-compiler shapes, which the three
compiled fixtures (`f19_enum_dictrep_switch`, `f24_enum_dictrep_hybrid`, `f28_enum_dictrep_biased`) exercise.  A first
version that required the fallback regressed all three (found only when the work was ported to this repo: the private repo's
`run_tests.py` keeps them in a separate `proto` group that had not been run), hence the value-dependence criterion above.  For newer
compilers the census stands (373 classes / 671 converter-backed properties: the fallback is referenced at most once per
enum property) and the fallback is just one of the ways a string varies with the value.

## Shapes handled

compare chain (`cmp`/`b.eq`/`b.ne`, `cbz`), jump table (byte/half index, `adr` base, `br`), pointer table (with or without
`sub` bias, `lsl`/`sxtw` index), several segments of one switch, sparse tails (isolated compares), hoisted names/tables/
formats in a repeated field's loop, biases ≥ 4096 materialised in a register (`mov w9,#-K; add w9,w8,w9`), one-valued enums.
Open item: with jump-table arm edges injected, 35 of 1637 GeoServices dictRep bodies still have unreachable interior
instructions (3 of the 37 target classes: 1, 2 and 19 instructions); cause not investigated.  Evaluation does not need the
CFG edges (it follows `br` targets itself), only the reaching-definition constants do, so a hole can at worst hide a
constant, never produce a wrong number.
