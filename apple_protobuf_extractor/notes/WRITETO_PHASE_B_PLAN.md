# Phase B plan — retire the forward-scan decoder + delete the writeTo budget caps

**Status:** B0 + cheap wins **(a)+(b)** + **B7 (walk helpers)** + **B8 (walk-only
flip)** all **DONE** (2026-06-10). The CFG walk is now the **sole** writeTo decoder;
the forward scan, the `[cap:AFFECTS-OUTPUT]` budget trio (`_WRITETO_MAX_INSNS` /
`_WRITETO_INSNS_PER_FIELD` / `_writeto_insn_budget`), `_WRITETO_OFFSET_REGS`, and the
Phase-A `_merge_field_numbers` are deleted. The optional **(c)** GEOLPR/GEOPublisher
recognizer was **not** done — its 4-field degradation was accepted as fail-safe.

### B8 — DONE (walk-only flip, raw — accepted the 4-field fail-safe degradation)
- `_extract_writeto_field_numbers` is now walk-only: it returns `{}` when the
  binary-wide indegree pre-pass is absent (no decode, fail-safe) instead of falling
  back to a forward scan. Deleted: `_forward_scan_field_numbers`, the budget trio,
  `_WRITETO_OFFSET_REGS`, `_merge_field_numbers`. Kept: `_writeto_field_number_before`
  (the walk uses it too) and `_WRITETO_TYPE_ENC` / `_WRITETO_EPILOGUE_MNEMONICS`.
- **Robustness fix (`_ensure_writeto_indegree`):** the walk needs the indegree pre-pass
  threaded onto `ctx`, which only `extract_all` built. Standalone `extract_proto_message`
  callers (single-class extraction, unit tests) silently lost all writeTo decoding on the
  flip (4 live tests went red: the wide-oneof field #91, GEOPDComponent `values`,
  `_externalActionDetails`). Fix: `extract_proto_message` now lazily builds + caches the
  pre-pass on first use. In `extract_all` the pre-pass is built up front, so the lazy path
  is a no-op there. This restored all 4 tests — and confirmed the **walk recovers the
  81-field wide-oneof field #91** on its own (the budget deletion lost nothing there).
- **Output delta (full `extract_all`, golden-verified): exactly 9 GeoServices fields**,
  locationd/CLP byte-identical. All 9 are the documented GEOLPR/GEOPublisher residual +
  the 3 `_photoSizeFilters{Count,Space}` backing-store DROP false-positives. Every change
  is correct-or-flagged-safe (degraded fields come back `number_confirmed=False`). The one
  genuine correct→wrong is `GEOLPRRoot.regions` (`1`→`2`, now unconfirmed): the walk
  *binds* `_regions:1` soundly, but the `_confirm_field_numbers` `min_needed` gate discards
  the sub-threshold 1-field result wholesale → ivar-order estimate. Logged as the
  `confirm-gate` heuristic (`heuristic_registry.py`) for a future principled fix
  (per-field adoption of the sound walk result; changes pointer-table-vs-walk precedence
  globally → own golden review).
- **Tests:** removed `TestWriteToInsnBudget` (budget gone); converted
  `test_writeto_walk_coverage.py` from a forward-vs-walk diff into a **decoder-level walk
  binding snapshot** golden (`tests/golden/writeto_walk_*.json`, same `MACHO_UPDATE_GOLDEN`
  workflow) so a `detect_context`/`bind_write` regression is caught at the walk level
  independent of the emitter gate; retired the obsolete `phaseb_scoreboard.py`.

### (historical) B0/B7 findings below

### B7 — DONE (walk captures its own `_out_helpers`)
- `_walk_field_numbers` now populates `{ivar: helper_va}` (the field-write `bl` target);
  `_extract_writeto_field_numbers` fills `_out_helpers` walk-first, forward scan fills
  the walk's misses.
- **Parity check:** 44 walk-vs-forward helper-VA mismatches on GeoServices, but only
  **2 change emitted output — both IMPROVEMENTS** (`GEOPDSearchSubstringDescriptor.spanDatas`,
  `GEOPDSearchAddressLabeledToken.unPaddedDoorNumbers`: `bytes`+unsure-note → `string`).
  Hopper-verified: the string write-helper is `0x18dbdac18`; the walk captures the real
  element-write helper there, while the forward scan had mis-attributed (`0x18dbdabb8`,
  not even in the function) or missed (`0x0`) it. The walk's helper capture is strictly
  *more accurate*. 0 regressions. locationd/CLP: 0 mismatches.
- **B7 result:** the walk can now serve as the sole `_out_helpers` source — the GLOBAL
  flip blocker is cleared. Golden regenerated (+2 string fields). Suite 1065 pass;
  validate_ref 11/14 held.

### Cheap wins (a)+(b) — DONE (verified)
- **(a)** `detect_context` now defaults `self_reg` to `x0` → closed 10 misses
  (the repeated-scalar-via-container group + locationd `_locationFingerprints`).
- **(b)** `bind_write` now traces an S1 hoisted value-load (value in a callee-saved
  reg loaded above the writer-init `bl`, via `_trace_hoisted_self_value`) → closed
  `CLPPressure._timestamp`.
- **Result:** walk residual misses 15 → **4** (only the GEOLPR/GEOPublisher group);
  locationd + CLP now have ZERO walk-misses. **Emitted output byte-identical**
  (the forward scan already covered these in the Phase A merge, so the walk merely
  catches up — zero output risk). Locked in by `tests/test_writeto_walk_coverage.py`
  (the golden net can't see a walk-coverage regression since output doesn't change).
  Forward scan + budget caps retained (per the chosen scope). Full suite green.

---

## B0 RESULTS (measured 2026-06-10 against current production)

Tool: `phaseb_scoreboard.py` (walk-only vs forward-scan-only, per class, all 3
artifacts). **18 misses total: 15 RECOVER + 3 DROP.** Then root-caused each by
dumping the instruction context at the missed write. The picture is **far cheaper
than the original S1–S5 estimate** — one tiny fix closes most of it:

### Finding 1 — a 1-line `detect_context` fix closes 10/15, ZERO regression
The repeated-scalar-via-container group sets the container with `add x20, x0, x8`
using **x0 directly** (self is never copied via `mov xR,x0`), so `detect_context`
returns `self_reg=None`, which *disables* the walk's container tracking (it's gated
on `self_reg is not None`). Defaulting `self_reg = self_reg or 'x0'` (self is always
x0 at entry per the ABI) closes:
- GeoServices (5): `GEOVLPrecision._precisions`, `GEOPDRigMetrics._occlusionScores`,
  `GEOLogMsgEventCuratedCollectionStats._savedCollectionMuids`,
  `GEOLogMsgStateUGCPhoto._photoSources`, `GEORevealedPlaceCardModuleTypeTitle._titleElements`
- locationd (2): `TRANSITPbLocationFingerprints(V1)._locationFingerprints`
- CLP (3): `CLPLOGENTRYVISIONSimdDoubleM/FloatM/VLVectorfM._values`

**Measured global effect of the default: +10 new bindings, 0 conflicts, 0 losses**
across all 3 artifacts (it only affects classes where `detect_context` returned
None, and there x0-tracking is correct). So this is a near-free win — still
golden-gated, but no expected regression.

### Finding 2 — 5 residual RECOVER misses at B0 (now 4 — (b) since closed the S1 one)
- **4 × GEOLPR/GEOPublisher "stack-built sub-writer / clobbered self"**:
  `GEOLPRUser._vehicles`, `GEOLPRRoot._vehicleTypes`,
  `GEOPublisherAttributionManifest._publisherAttributionSources`,
  `GEOPublisherAttributionManifestIndex._publisherToFileIndex`. Here self is moved to
  x19 then OVERWRITTEN with an ivar (`mov x19,x0; … ldr x19,[x19,x8]`), and the field
  is serialised through a sub-writer assembled on the stack — genuinely the hard S3/S4
  case. The only nontrivial recognizer work left.
- **1 × S1 hoisted value-load**: `CLPPressure._timestamp` (value in `d8` loaded above
  the writer-init `bl`).

### Finding 3 — the 3 DROP misses are confirmed false positives
`GEOPDReviewFilter._photoSizeFiltersCount`/`_photoSizeFiltersSpace`,
`GEOPDCaptionedPhotoFilter._photoSizeFiltersCount` are packed-repeated backing-store
ivars (`_fooCount`/`_fooSpace`) the forward scan mis-binds as fields (and at wrong
numbers — GEOPDReviewFilter `_photoSizeFilters` forward=8 vs walk=1). The walk
correctly binds only the real `_photoSizeFilters`. On the flip these 3 simply
disappear from output = an improvement. **B0 to-do still open:** confirm in the
emitter that these are currently emitted as fields (so the flip delta is expected).

### Revised effort
The original "5 recognizers, ~5–7 days" collapses to: **(a)** the self_reg default
(trivial, closes 10), **(b)** S1 hoisted-load (small, closes 1), **(c)** the
GEOLPR/GEOPublisher sub-writer recognizer (the one hard piece, closes 4) — plus B7
(walk helpers) and B8 (flip + delete caps). Realistically **~2–3 days**, and (c) is
the only real uncertainty. The recognizer sections B2–B6 below are superseded by
this finding; treat them as the menu, with (a)/(b)/(c) as the actual work.

---

## REVISED PLAN (supersedes the original B1–B8 structure below)

**Prereq:** Phase A done (`8157052`), cheap wins done (`4c44967`), on `extractor-tidy`.

### Goal
Make the CFG walk **self-sufficient** so the forward scan + its `[cap:AFFECTS-OUTPUT]`
budget trio (`_WRITETO_MAX_INSNS` / `_WRITETO_INSNS_PER_FIELD` / `_writeto_insn_budget`)
can be deleted — collapsing two decoders into one and closing the standing scan-cap
action. **Two blockers remain** (one global, one local):

1. **GLOBAL — `_out_helpers` (the real blocker).** The forward scan is the *sole*
   source of the per-ivar write-helper VA that distinguishes `repeated string` from
   `repeated bytes`/`message`. **Measured:** retiring the forward scan *without* the
   walk capturing helpers flips **37 GeoServices fields `repeated string` → `bytes`**
   (real string arrays: `logoURLs`, `attributionUrls`, `versionDomains`, `keys`, …;
   locationd/CLP = 0). This is corpus-wide, not an edge case → **B7 is mandatory.**
2. **LOCAL — 4 residual walk-misses (the GEOLPR/GEOPublisher group).** Real repeated
   fields the walk still doesn't bind; on a flip they degrade from the forward scan's
   *confirmed* (correct) numbers to ivar-order *estimates* (wrong, flagged unconfirmed)
   — a small but real 4-class regression unless closed (the **(c)** recognizer).

### What B0 + (a)+(b) corrected in the original plan
- **The S1–S5 categorisation was wrong.** Root-causing showed the "15 RECOVER" were
  really: **10** = one cause (`detect_context` returned `self_reg=None` → tracking
  disabled; the originally-hypothesised S2/S3/S4/S5 labels were red herrings), **1** =
  S1 hoist, **4** = the GEOLPR stack-sub-writer pattern (a *single* coherent pattern,
  not the S3/S4/S5 split originally guessed).
- **B1 (the per-edge register-environment rewrite) is NO LONGER NEEDED.** Its whole
  justification was "base tables set up after the 40-insn prologue" feeding S3/S4 — but
  those misses were closed by the trivial `self_reg=x0` default, and the residual 4 are
  about *clobbered self + a stack-built sub-writer*, not late base-reg setup. Dropped.
- **B2–B6 collapsed**: (a)+(b) already closed everything except the 4 GEOLPR misses,
  which are now one recognizer **(c)**, not five.
- The walk's **134 over-binds** (Phase A coverage gains) and the **3 DROP** false
  positives (`_photoSizeFilters{Count,Space}`) are unchanged from B0.

### Remaining work (this is the actual plan now)

**B7 — Walk captures its own `_out_helpers`  — ✅ DONE (see status block above).**
The gate was even better than "empty diff": 2 fields *improved* (the walk's helper
capture is more accurate than the forward scan's), 0 regressions. The GLOBAL flip
blocker is cleared.

**(c) — GEOLPR/GEOPublisher recognizer  (~½–1 day; OPTIONAL) — closes the last 4.**
- Pattern: self moved to a callee-saved reg then OVERWRITTEN with an ivar
  (`mov x19,x0; … ldr x19,[x19,x8]`); the field is serialised through a sub-writer
  assembled on the stack. Needs the walk to (i) keep a handle on the original self
  after it's clobbered, and (ii) bind the field from the ivar load that feeds the
  sub-writer. Verify each of the 4 against Hopper (same bar as Phase A).
- Skip this only if accepting the 4-class fail-safe degradation (see Scope).

**B8 — Flip to walk-only + delete forward scan & budget caps  (~½ day + review).**
- Precondition: B7 done (helpers safe) AND either (c) done OR the 4-field degradation
  accepted. Then: capture a walk-only golden, diff vs the current merge golden — the
  diff must be exactly the 3 DROP removals (+ the 4 GEOLPR degradations *iff* (c)
  skipped) and nothing else. Review; regen goldens.
- Delete `_forward_scan_field_numbers`, the budget trio, and simplify
  `_extract_writeto_field_numbers` to walk-only (drop `_merge_field_numbers`). Fix the
  `__all__` re-exports + the tests importing the deleted symbols
  (`test_confirm_field_numbers`, `test_coverage_gaps`).
- **Retire/realign `wt_reader.py`** (kill the prototype↔production duplication): delete
  it or have it import from `proto.writeto`.
- Open B0 to-do, do it here: confirm the 3 DROP ivars are currently emitted as fields
  (so the removal is the expected, reviewed delta).

### Next step (B7 done): decide (c) vs accept, then B8.
B7 cleared the global blocker. The remaining choice is now clean:
- **Close (c)** — the GEOLPR/GEOPublisher recognizer (4 fields) — for a zero-regression
  walk-only flip; OR
- **Accept the 4** GEOLPR fields degrading to unconfirmed estimates (fail-safe) and flip.
Either way **B8** then deletes the forward scan + budget caps. (c) is the only remaining
real uncertainty; B8 is mechanical + golden-gated.

## Sequencing (revised)

1. **B7** (next) — walk captures its own helpers; gate on EMPTY golden diff (proves
   walk helpers ≡ forward-scan helpers while both still run). Unblocks the flip.
2. **(c)** — GEOLPR recognizer (optional; closes the last 4 for a zero-regression flip).
3. **B8** — flip to walk-only + delete the forward scan & budget caps.

**Flip-readiness gate (for B8):** B7 done AND (the 4 GEOLPR misses closed OR their
fail-safe degradation explicitly accepted). The walk-only golden diff must then be
exactly the 3 DROP removals (+ the 4 degradations iff (c) skipped) — nothing else.

## Risks (revised)

- **R3 (now primary) — B7 helper parity.** The walk's helper VA for a field could differ
  from the forward scan's (e.g. a repeated field's begin-submsg helper vs the element
  helper), shifting `string`/`message`/`bytes` typing. **Gate:** keep both sources during
  B7 and require an EMPTY golden diff (esp. the 37 measured `string` fields) before the
  forward scan is removed in B8.
- **R1 — a (c) recovered binding is mis-attributed.** Value-trace each; Hopper-verify all
  4 (same bar as Phase A's 22+163).
- **R4 — (c) proves too hard.** Then B8 can still flip by accepting the 4 fail-safe
  degradations (wrong-but-unconfirmed numbers, see Goal blocker 2) — a conscious,
  golden-reviewed trade. Do NOT keep a thin forward-scan fallback "for just those 4": the
  forward scan pulls in the whole budget trio, so a partial fallback defeats the
  cap-deletion goal. It's all-walk (accept 4) or close (c).

## Scope options

- **B7 + (c) + B8 (recommended)** — single decoder, caps deleted, ZERO regressions.
  ~1.5–2.5 days. The clean end-state.
- **B7 + B8, accept the 4** — single decoder, caps deleted, but 4 GEOLPR fields degrade
  to unconfirmed estimates (fail-safe). ~1–1.5 days. Take this only if (c) proves hard.
- **B7 only, stop** — walk owns typing, but the forward scan + caps stay (the flip needs
  B8). Lowest value; not recommended as an end-state, only as a checkpoint.

---

## APPENDIX — original B0–B8 breakdown (HISTORICAL, superseded by the REVISED PLAN)

The original plan hypothesised five recognizers (B1 reg-env foundation; B2 S1; B3 S2;
B4 S3 outlined-helper; B5 S4 sorted-dict; B6 S5 unreached-block) over ~5–7 days. B0's
root-causing collapsed this: the bulk was one `self_reg=x0` line, the residual is one
GEOLPR pattern, and B1's reg-env rewrite is unnecessary. Kept here only for provenance;
**do not work from it — use the REVISED PLAN above.**
