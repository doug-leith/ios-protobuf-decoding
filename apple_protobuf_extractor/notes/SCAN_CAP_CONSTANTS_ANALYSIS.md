# Bounded-scan cap constants — portability analysis & pickup notes

**Date:** 2026-06-09. Read-only analysis; **no code changed.** Faithful record for
later pickup.

**Prompt that drove it:** "The code has hard-wired constants (~15), e.g.
`_WRITETO_MAX_INSNS=600`, `_READSPEC_MAX_INSNS=4096`, `_CLUSTER_MAX_SCAN=512`, with
comments like '~2x observed' / '~3x largest observed'. They affect protobuf
decoding. Can any be replaced with principled, portable solutions?"

**Short answer:** Partially — but the constants that *actually affect decoding* (the
serializer-body scans) **cannot be cleanly replaced**, and the obvious replacement
(bound by next function start, via `LC_FUNCTION_STARTS` or next-IMP) was **already
implemented and reverted** — it is empirically unsound for Apple's *outlined*
serializer methods. See `WRITETO_BUDGET_ANALYSIS.md` (2026-06-09 update). The
remaining caps are either terminal/early-feature backstops (already portable in
practice) or input-sanity caps (fine as-is).

---

## The full constant inventory (grep result)

`proto/extractor.py`:
- `_READFROM_MAX_INSNS = 12`            (:609)  — readFrom: wrapper, find tail b/bl to core
- `_ENUM_MAX_INSNS = 80`               (:644)  — xAsString: body, harvest enum ptr table
- ~~`_DICTREP_MAX_INSNS = 8000`~~  → **REPLACED 2026-06-11 (TODO #40 LANDED)** by
  `_DICTREP_PROBE_INSNS` (fast-path probe, COSMETIC) + a value-independent
  `_function_body_extent` bound + `_DICTREP_HARD_CAP=40000` (COSMETIC safety ceiling).
  dictRep is CONTIGUOUS (not outlined), so the function's own last `ret` is a sound,
  magic-count-free bound — see the follow-up section.
- `_DISPATCH_MAX_INSNS = 200`          (:1913) — find table-base adrp+add (preamble)
- `_READSPEC_MAX_INSNS = 4096`         (:2230) — "full arm region (func_end); ~3x largest observed"
- `_ARM_MAX_INSNS = 64`                (:2231) — one dispatch arm before its tail branch
- `_CLUSTER_MAX_SCAN = 512`            (:2232) — "dispatch cluster sits in preamble; ~2x observed"
- `_ADDER_MAX_INSNS = 40`              (:2233) — _addNoFlags<X>: accessor; loads ivar slot early
- `_WRAPPER_CORE_SCAN_MAX = 256`       (:2276) — wrapper→core bl search
- `_WRITETO_MAX_INSNS = 600`           (:3197) — base floor; scaled per field count
- `_WRITETO_LOOK_BACK = 24`            (:3198) — scan back from each BL for field-num mov
- `_WRITETO_INSNS_PER_FIELD = 20`      (:3205) — budget = max(600, n*20)

`macho/`:
- `_DEFAULT_MAX = 512`                 (disasm.py:58)
- `_MAX_SUBCACHES = 256`               (dyld_cache.py:69)
- `_MAX_CSTRING_LEN = 1024`            (dyld_cache.py:70)
- `_MAX_LC_SECTIONS = 512`             (dyld_cache.py:86)
- `_MAX_NCMDS = 1024`                  (memory.py:35)
- `_MAX_NSECTS = 256`                  (memory.py:36)

---

## Tier 1 — "scan the whole serializer body" caps → NO cheap principled replacement

`_WRITETO_MAX_INSNS` / `_WRITETO_INSNS_PER_FIELD` (`proto/extractor.py:3197-3211`),
`_DICTREP_MAX_INSNS=8000` (:1196), `_READSPEC_MAX_INSNS=4096` (:2230).

These are the decode-affecting ones (field numbers, enum-value harvest). The
intuitive fix — "scan to the next function start instead of a magic count" — was
**implemented and reverted** by the other session. Per `WRITETO_BUDGET_ANALYSIS.md`
(⚠️ UPDATE 2026-06-09, lines 8-48):

1. **Next-IMP / function-boundary cap is INVALID in the dyld cache.** Apple
   *outlines* `writeTo:` field-write blocks far from entry, **past other functions'
   IMPs** — and therefore past `LC_FUNCTION_STARTS` entries too (the outlined block
   sits beyond intervening boundaries). Ground-truth: `-[GEONamedFeature writeTo:]`
   (imp `0x18cfe2044`) writes `_name`/`_value` inline, but the *next* method IMP is
   only 30 insns in (`0x18cfe20bc`). Capping there truncated genuine writes →
   **20 confirmed→unconfirmed regressions.** Discarded.
   - ⟹ `LC_FUNCTION_STARTS` (which I was about to recommend as the portable source —
     it IS present in the standalone `GeoServices` and `locationd` files, confirmed
     via `otool -l | grep -c LC_FUNCTION_STARTS` = 1 each) does **not** rescue this,
     because the real code lives past the boundary by construction. The cache path
     also tends to strip per-image function-starts anyway.

2. **The SOUND replacement is a CFG / basic-block walk** (follow branch edges incl.
   `tbz/tbnz` into the outlined blocks; never enter another method IMP; raw-word
   traversal then disasm reachable runs). It is correct (fixes GEOResources #93/#94,
   55→57) BUT exposed a deeper gap: the genuine hot blocks use an
   `adrp+add Xb,<ivar-off-var>; ldrsw x8,[Xb,#k]` **base-register offset** pattern the
   extractor can't decode (it only handles per-write `adrp+ldrsw`), and it revealed
   ~22 *spurious* prior confirmations (old fixed window read past the function into
   foreign code and matched field-writes by ivar-offset **value collision**).
   Implementing CFG + base-register decode together = ~200 fields churned across
   ~100 classes, 78 confirmed→unconfirmed lost, a `validate_ref` regression. It is
   effectively a **rewrite of writeTo: field-number recovery**, needing per-class
   ground-truth validation — its own scoped effort, NOT a drop-in constant swap.

**Verdict:** these magic constants are a known-imperfect stand-in for a hard problem.
The principled solution is the documented CFG rewrite, not a boundary lookup.
**CORRECTION 2026-06-11:** `_DICTREP` is NOT in this outlined family — the earlier
"inherits the same constraint" assumption was wrong.  `_dictionaryRepresentation:` is a
CONTIGUOUS serializer (verified ≥99.6% reachable-fill), so its own last `ret` IS a sound
value-independent bound; TODO #40 landed exactly that (function-extent, not next-IMP) and
removed `_DICTREP_MAX_INSNS` from this AFFECTS-OUTPUT list.  The writeTo: family remains
genuinely outlined and keeps its caps pending the CFG rewrite.
(`_READSPEC_MAX_INSNS` was originally grouped here too, but the 2026-06-11 re-check
reclassified it COSMETIC — it bounds a `func_end` validation boundary, not a value
harvest; perturbation = 0 diffs both ways. See the standing-action list below.)

**Transparency mitigation (important):** writeTo truncation is NOT silently wrong —
missed fields stay `number_confirmed=False` → emitted with `// number estimated`. So
a too-small budget degrades to *flagged* wrong numbers, not hidden ones. The
**enum-value** truncation (`_DICTREP`/`_ENUM`) is the less-transparent case: a
truncated harvest can emit a short enum that still looks "confirmed" (`values_confirmed`
not necessarily cleared). If anything in Tier 1 is worth a cheap fix, it is **adding a
truncation-hit signal to the enum-value scans** (e.g. mark the enum unconfirmed /
comment it when the disasm hit its cap) — pure transparency, no decode change.

### ✅ DONE 2026-06-09 — enum-value (`_ENUM` / jump-table) truncation flag

Implemented the precise half of the mitigation above. New `_disasm_truncated(insns,
cap)` (extractor.py) returns True when a `disasm(..., max_insns=cap)` returns its full
cap WITHOUT ending on a terminal (`ret`/`eret`) — a genuine budget cut-off, distinct
from a method that simply ended and from a sparse-enum *gap*. Threaded through
`_extract_jumptable_enum_values` and `_extract_enum_values` (both now return
`(pairs, confirmed, truncated)`) into a new `ProtoEnum.values_truncated`, which
`to_proto()` renders as a leading `// WARNING: values may be INCOMPLETE …` line.

- **Fires on 16 GeoServices enums** (187–441 values each — large sparse logging enums
  whose `xAsString:` body exceeds the 1000-insn `_SPARSE_MAX_INSNS` budget). Active, not
  just latent insurance.
- **Verified surgical:** before/after across all 3 artifacts — **0 field diffs, 0 enum
  value-set diffs**; exactly 16 enum-text diffs, each *only* the added warning line.
  Full suite 1028 pass; `validate_ref` baselines unchanged (GEOPDComponent 11/14,
  GEOPDPlace 11/13, GEOPDPlaceGlobalCommonResult 1/1).
- The pointer-table path is never budget-truncated (it reads entries directly from
  memory, bounded by the field *count*, not the disasm length) → always `truncated=False`.

### Follow-up — `_DICTREP` truncation now FAILS LOUD (2026-06-11), principled fix = TODO #40

`_dictionaryRepresentation:` truncation hits **9 GeoServices classes** (all bottom out
at the 8000-insn cap). Unlike the jump-table case it does **not** produce a *short*
enum: each switch the walk *did* reach is read in full (via direct memory reads of the
case/table, not the insn stream), so the enums it returns are complete. The loss is
*whole enums* whose switch sits past insn 8000 — those fields silently stayed `int32`.

**Resolved (the "deliberate decision" was made — user asked to add the warning).**
`_harvest_dictrep_enums` now detects budget truncation via `_disasm_truncated`, logs a
warning, and records the class on `ctx._dictrep_truncated_classes` →
`ProtoMessage.enum_recovery_truncated` → a class-level
`// WARNING: enum recovery may be INCOMPLETE …` comment. The over-warn concern raised
here (classes whose untyped ints are genuinely plain ints) is **structurally avoided**:
`_harvest_dictrep_enums` only runs when ≥1 int field is still untyped (caller guard), so
the flag fires on exactly the at-risk classes. Empirically **4 of the 9** truncating
classes warn (`GEOPDSearchQueryIntentMetadata`, `GEOAnalyticsPipelineStateData`,
`GEOLogMsgEventDisplayAnalytic`, `GEOLogMsgStateCuratedCollection`); the other 5 had all
their int fields already typed via `xAsString:`, so nothing is at risk and they are
silently — correctly — not flagged. Field-level output is unchanged (golden diff = the 4
new `<enum_recovery_truncated>` keys only); validated by golden + suite.

**TODO #40 — LANDED 2026-06-11 (commit pending).** The investigation overturned the
premise: the 8000 cap loses **zero** enums (raising it 8000→40000 recovers nothing on all
9 overrunning classes — `dictrep_probe3.py`), because `_dictionaryRepresentation:` is a
**contiguous** serializer (≥99.6% reachable-fill — NOT outlined like writeTo:).  So the
fix is a value-independent **function-extent bound** (`_function_body_extent`:
single linear sweep + forward-branch high-water-mark, cut at the function's own last
`ret`), recomputed only when the cheap 8000 probe doesn't reach the end.  This is the
function's OWN ret, **NOT** a next-IMP / `LC_FUNCTION_STARTS` boundary (still unsound for
the outlined writeTo: family — `_function_body_extent` is explicitly scoped contiguous-only).
Proven output-neutral: golden diff = removal of the 4 false-alarm `<enum_recovery_truncated>`
keys, ZERO field/enum-value change.  A genuine overrun past the 40000 safety ceiling still
fails loud (`enum_recovery_truncated`).  Pre-land gate confirmed 0 real missed enums
(`dictrep_validate.py`/`dictrep_intent.py`; the 64 enum-shaped strings in
`GEOPDSearchQueryIntentMetadata` are `isEqualToString:` sub-object parse logic, no
`_intentType` ivar).

---

## Tier 2 — "feature near entry / terminal-bounded" caps → already effectively portable

`_READFROM_MAX_INSNS=12` (:609), `_DISPATCH_MAX_INSNS=200` (:1913), `_CLUSTER_MAX_SCAN=512`
(:2232), `_WRAPPER_CORE_SCAN_MAX=256` (:2276), `_ARM_MAX_INSNS=64` (:2231),
`_ADDER_MAX_INSNS=40` (:2233), `_ENUM_MAX_INSNS=80` (:644).

These do not scan a whole body — they look for a feature that is structurally early
(a tail `b`/`bl`; an `adrp+add` table base in the preamble; an arm before its tail
branch; an accessor that loads its ivar slot first) and stop at a terminal. `disasm`
already clamps reads to the **segment boundary** (`macho/disasm.py:410`,
`_read_available` binary-search shrink) and stops at `ret`. So the magic number is a
*backstop*, not the decode-determining bound.

- `_DISPATCH_MAX_INSNS=200` looks lower than the "dispatch `br` ≤ 251 observed"
  comment at :2228, but it bounds the **table-base `adrp+add`** (preamble, early),
  not the `br` itself — so not the inconsistency it first appears. Still a backstop.
- Replacing these with a function-extent expression is **cosmetic** (cleanliness, not
  correctness), and for any that *could* be outlined (`_ENUM` on a very large enum)
  a boundary cap carries the same Tier-1 unsoundness risk. **Low value; leave.**

### ⚠️ EMPIRICAL VERIFICATION 2026-06-09 — the "all Tier-2 is cosmetic" claim was WRONG for one

The cosmetic claim above was **tested**, not trusted, by (a) instrumenting actual scan
consumption and (b) perturbing each cap ×8 and diffing the full field+enum descriptor
across all 3 artifacts.  Result:

- **6 of 7 confirmed cosmetic** (×8 → **0 descriptor diffs**): `_READFROM_MAX_INSNS`
  (12→96), `_ENUM_MAX_INSNS` (80→640), `_DISPATCH_MAX_INSNS` (200→1600), `_ARM_MAX_INSNS`
  (64→512), `_CLUSTER_MAX_SCAN` (512→4096), `_WRAPPER_CORE_SCAN_MAX` (256→2048).  The
  ×8-up = 0-diff is a *complete* cosmetic proof: if the value were too small, raising
  would recover more (it doesn't); and 8× larger doesn't introduce mis-binding either.
  (NB: the cheap "is the disasm ever truncated" instrumentation FALSE-positives — all 5
  disasm caps return their full length because the methods are long, but the scans
  consume only early instructions.  Perturbation is the authoritative test.)
- **`_ADDER_MAX_INSNS=40` is NOT cosmetic — it is output-affecting.**  The small window
  deliberately confines the adder→ivar lever to the FIRST (correct) ivar-slot load;
  raising it lets the scan reach a later confounding load and mis-binds.  Measured on
  `GEOPDPlaceCollection.mediaLinks`: `repeated GEOPDMediaLink` at adder ≤64 → **`bytes`
  (element type lost) at adder ≥100**.  The code comment is now tagged
  `[cap:AFFECTS-OUTPUT]`; treat it like a Tier-1 constant (re-validate on any change),
  **not** a free backstop.

Code now carries `[cap:COSMETIC]` / `[cap:AFFECTS-OUTPUT]` tags beside each cap so this
isn't re-litigated.

---

## Tier 3 — genuine input-sanity caps → leave alone (already portable)

`_MAX_NCMDS=1024`, `_MAX_NSECTS=256` (`macho/memory.py:35-36`), `_MAX_LC_SECTIONS=512`,
`_MAX_SUBCACHES=256`, `_MAX_CSTRING_LEN=1024` (`macho/dyld_cache.py:69-86`),
`_DEFAULT_MAX=512` (`macho/disasm.py:58`).

These bound malformed/adversarial input against header-declared counts; the real
values come from the binary, not from observation. They don't affect decode
correctness on well-formed input.

---

## ⚠️ STANDING ACTION ITEM — every Tier-1 / AFFECTS-OUTPUT cap still needs work

All of these constants' *values* change the emitted descriptor, so each is a known
correctness liability, not a settled backstop. None is "done" — every one needs either
**removal** or a **principled, value-independent replacement** (a real CFG / function-
extent bound, or a structural signal), with per-class ground-truth re-validation:

- `_WRITETO_MAX_INSNS`, `_WRITETO_LOOK_BACK`, `_WRITETO_INSNS_PER_FIELD` — emitted field
  NUMBERS (outlined high-tag blocks). Principled fix = the CFG-walk + base-register
  rewrite scoped in `WRITETO_BUDGET_ANALYSIS.md`.
- `_DICTREP_MAX_INSNS` — silently-missed enum fields (stay int32) on 9 GeoServices
  classes. Same outlined-serializer family; needs a real function-extent bound.
- ~~`_READSPEC_MAX_INSNS`~~ — **RE-CHECKED 2026-06-11: reclassified COSMETIC, removed from
  this list.** Perturbation across all 3 artifacts: raise 4096→32768 = 0 diffs; lower
  4096→1300 = 0 diffs (observed max 1223; every ReadSpecified hits `ret` before the cap).
  Value is non-operative at 4096 (3.3× margin); the only failure direction (too-small) is
  conservative — shrinks `func_end`, makes the resolver reject arms → missed resolution,
  never a wrong bind. Keep ≥ ~1300. Not the silently-dropping outlined-block hazard the
  writeTo/dictRep caps were; it only bounds a `func_end` validation boundary.
- `_ADDER_MAX_INSNS` — element TYPE of repeated fields (the adder→ivar lever). A tuned
  window, not a backstop; replace with a structural stop (e.g. bind to the first ivar
  load deterministically) so a magic count isn't load-bearing.
- `_SPARSE_MAX_INSNS = 1000` (local in `_extract_jumptable_enum_values`, :940) — the
  jump-table enum-value harvest budget. Truncates 16 large GeoServices enums (187–441
  values): segments past insn 1000 are never scanned, so the enum is emitted SHORT.
  **Best-behaved tier-1 cap — it FAILS LOUD:** overrun sets `ProtoEnum.values_truncated`,
  emitting the `// WARNING: values may be INCOMPLETE` comment (not a silent short enum,
  unlike `_DICTREP_MAX_INSNS`). Still tier 1 — its value bounds the recovered values.
  Principled fix = a per-method segment-count / true function-extent bound, not a magic
  count. **Do NOT confuse with `_ENUM_MAX_INSNS=80` (:659), which is tier-2 COSMETIC** —
  that one only bounds the pointer-table-base preamble probe and falls through to the
  jump-table path if exceeded; ×8 perturbation gave 0 diffs.

Until then they stay tagged `[cap:AFFECTS-OUTPUT]` in code. Do NOT promote any to
"cosmetic" without the same ×8-perturbation proof the Tier-2 caps got.

## Bottom line

- The constants that read like portability hazards (`~3x observed`, `~2x observed`,
  `n*20`) **are** real hazards, but the clean boundary-based fix is **proven unsound**
  for Apple's outlined serializer methods — `LC_FUNCTION_STARTS` included. The
  principled replacement for that family is the **CFG-walk rewrite already scoped in
  `WRITETO_BUDGET_ANALYSIS.md`**: substantial, validation-heavy, changes a large
  fraction of emitted field numbers. Not a constant swap.
- The remaining caps are terminal/early-feature backstops (already portable in
  practice) or input-sanity caps (fine).
- The only low-risk improvement available *now* without the rewrite is **transparency,
  not portability**: flag enum-value scans that hit their cap (the writeTo case
  already degrades to `// number estimated`; the enum-value case can emit a
  silently-truncated enum). Pure annotation, no decode change.

## What NOT to do (so the next session doesn't repeat it)

- Do **not** "fix" `_WRITETO_*` / `_READSPEC_*` / `_DICTREP_*` by capping at the next
  IMP or `LC_FUNCTION_STARTS` entry. It was tried, caused 20 regressions, reverted.
- If you take on the serializer-scan problem, it is the **CFG-walk + base-register
  (`adrp+add Xb; ldrsw [Xb,#k]`) offset decode** rewrite, gated on per-class
  ground-truth validation — see `WRITETO_BUDGET_ANALYSIS.md` for the pieces that
  already work (raw-word CFG walk; GEONamedFeature / GEOResources ground truth).

## References
- `WRITETO_BUDGET_ANALYSIS.md` — the truncation bug, the reverted next-IMP/CFG
  attempts, and the scoped rewrite (primary source for Tier 1).
- `macho/disasm.py:410` (`_read_available`) — existing segment-boundary clamp.
- `proto/extractor.py:3208` (`_writeto_insn_budget`) — the `max(600, n*20)` budget.
- Memory: `[writeTo budget truncation]`, `[heuristics-audit]` (Tier-3 sanity caps
  noted there as "512 pointer-table cap / 4096 range bounds → keep").
