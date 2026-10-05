# Step 6 plan — swap the writeTo decoder for the CFG-walk reader (Task 32)

**Status:** ✅ **COMPLETE.** Phase A done & verified, and **Phase B (B0 + (a)(b) + B7 +
B8) is now also done** — the CFG walk is the sole writeTo decoder; the forward scan +
budget caps are deleted. See `WRITETO_PHASE_B_PLAN.md`. Only the optional **(c)**
GEOLPR/GEOPublisher recognizer remains (deferred; the 4-field degradation is fail-safe).

### Phase A results (verified)
- Productionised the CFG walk into `proto/writeto.py` (no `proto.extractor`
  dependency); threaded the binary-wide branch-indegree pre-pass through
  `extract_all` onto `ctx` (`_writeto_indeg`/`_writeto_foreign_imps`, declared +
  reset). `_extract_writeto_field_numbers` now = forward-scan ⊕ walk merge
  (`_merge_field_numbers`).
- **Golden review (GeoServices): 239 fields changed, ALL accounted for, ZERO
  regressions** — 0 lost-confirmations, 0 disappeared fields, 0 type changes
  (`_out_helpers` typing preserved as designed). Breakdown: 22 both-confirmed
  number corrections (the verified DISAGREE set) + 163 confirmation gains (97 with
  corrected numbers) + 54 derivative Count/Space renumbers. 0 merge dup-collisions.
- Hopper-spot-verified the two surprising high numbers: `GEOActiveTileGroup.
  hybridUnavailableRegions=56` and `GEOPBTransitLine.operatingHours=26` — both real
  begin-submessage writes with the Issue-B count/array split; walk correct.
- **locationd / CoreLocationProtobuf byte-identical** (walk agrees with the tool →
  merge is a no-op). Full suite **1062 pass**; `validate_ref` GEOPDComponent 11/14
  held. Goldens regenerated to capture the accepted GeoServices changes.
**Branch:** continue on `extractor-tidy` (snapshots `c7b5994`, `a5be032` precede this).
**Prereqs done:** `proto/writeto.py` carved out (output-identical); golden net live.

---

## 1. What this step changes — and why it is NOT a clean drop-in

Task 32 was framed as "drop-in swap + delete budget caps." The audit data says a
*literal* drop-in would **regress output**, so this plan reframes it as a safe,
staged swap. The numbers (BIND walk vs current decoder, per `audit_bind`):

| Artifact | EXACT | DISAGREE (walk≠tool) | walk-more (walk binds, tool didn't) | tool-more (tool binds, walk misses) |
|---|---|---|---|---|
| GeoServices | 1401 | **34** | **74** | **9** |
| locationd | 63 | 0 | 0 | **2** |
| CoreLocationProtobuf | 79 | 0 | 0 | **5** |

Three populations move in **opposite** directions:

- **34 DISAGREE → corrections.** All 34 were Hopper-verified in a prior session:
  the walk number is right, the current decoder is wrong (base-register/stale
  attribution bugs). Swapping *fixes* these. ✅ pure win.
- **74 walk-more → added coverage.** Fields the current decoder never confirmed
  that the walk binds (mostly embedded single-messages + repeated containers).
  Likely real, but **not individually Hopper-verified** — adopting all 74 wholesale
  is the main *risk* (a wrong walk-more = a newly-introduced bad field number).
- **~16 tool-more → walk misses (9+2+5).** The walk *declines* to bind these
  (documented safe-direction misses S1–S5 in `wt_reader.py`). If the walk fully
  *replaces* the current decoder, these fields lose their confirmed number and
  fall back to ivar-order estimation → **regression**. One CLP case
  (`CLPIndoorPressure._has`) is actually a current-decoder *false positive* the
  walk correctly drops — so a handful of "misses" are improvements, but most are
  genuine coverage the walk would lose.

**Conclusion:** a walk-only replacement trades 34 fixes + 74 additions for ~15
regressions. We can do strictly better by *merging* the two decoders.

---

## 2. The `_out_helpers` contract — preserved automatically in Phase A; the walk's own capture is a PHASE B item

Two of the three production call sites pass `_out_helpers` and depend on it:

```
_extract_writeto_field_numbers(ctx, cls, ivars, _out_helpers=helpers)
```

`_out_helpers` is filled with `{ivar_name: write_helper_vmaddr}` — the BL target
of each field's write call. Downstream, the **element-type resolver** uses these
addresses to tell `string` vs `message`/`bytes` repeated fields apart (cache-native
mode has no symbol names). The current decoder captures this via `_parse_imm(ins.op_str)`
on the field-write BL.

**Phase A does NOT need the walk to capture helpers.** Because Phase A keeps the
current decoder running as a contributor (§3), it keeps populating `_out_helpers`
for every ivar it binds — i.e. everything except the 74 walk-more. So:
- all previously-typed fields keep their helper entry → **no typing regression**;
- the 34 DISAGREE ivars are tool-bound, so their helper entry persists (Phase A
  changes only the *number*, not the helper) — typing unchanged from today;
- the 74 *new* walk-more fields get no helper entry, so they fall through to the
  other element-type resolvers (`_resolve_repeated_type`, the readFrom core index,
  the adder→ivar lever). Worst case a brand-new field is typed more coarsely
  (e.g. `bytes` not `string`) — a quality gap on a NEW field, never a regression.

**The walk's own helper capture is therefore a Phase B item.** `bind_all` returns
`(bound, status)` (a diagnostic histogram), not `{ivar: helper_va}`. The walk *has*
each BL target internally, so it's a capture-and-plumb task — but it only becomes
*mandatory* in Phase B, when the current decoder is removed and the walk is the
sole helper source. (Doing it in Phase A is optional and would only improve the 74
new fields' typing.)

---

## 3. Proposed approach — staged, value-first, zero-regression

### Phase A (this step, reviewable): merge walk over the current decoder

New `_extract_writeto_field_numbers` body:

1. Run the **walk** (`bind_all` logic, productionised into `proto/writeto.py`) →
   `walk_nums {ivar: N}` + `walk_helpers {ivar: helper_va}`.
2. Run the **current forward-scan** (today's code, kept) →
   `tool_nums {ivar: N}` + `tool_helpers`.
3. **Merge, walk-wins:**
   - ivar in both → take `walk_nums` (fixes the 34 DISAGREE).
   - ivar only in walk → add it (the 74 walk-more coverage gains).
   - ivar only in tool → keep tool's number (no regression on the ~16 misses).
   - `_out_helpers[ivar]` = walk_helpers if walk bound it, else tool_helpers.
   - Enforce field-number uniqueness on the merged result (drop a walk-more whose
     number collides with a kept tool binding — keep the verified/older one).

This delivers **all 34 corrections + 74 additions with zero regressions**, every
change visible in the golden diff for review. Budget caps stay (the tool path
still uses them) — **not deleted in Phase A**.

### Phase B (later, separate): retire the current decoder + delete the caps

Once the walk's misses are closed — implement the S1–S5 recognizers documented in
`wt_reader.py` (hoisted value-load, repeated-scalar-via-container, outlined helper,
sorted-dict, unreached block) so the walk's tool-more count → 0 — drop the
forward-scan path and delete `_WRITETO_MAX_INSNS` / `_WRITETO_INSNS_PER_FIELD` /
`_writeto_insn_budget`. This is the genuine "delete budget caps" end-state, safe
because the walk is then strictly ≥ the current decoder.

> **DECISION (made):** Phase A — merge, no regressions, caps stay; Phase B (close
> misses, delete caps) later. The walk-only-now and close-misses-first alternatives
> were considered and declined.

---

## 4. Detailed work items (Phase A)

1. **Productionise the prototype into `proto/writeto.py`.** Move from `wt_reader.py`:
   `build_branch_indegree`, `classify_b_target`, `writeto_walk`, `detect_context`,
   `bind_write`, `bind_all`, `_forward_self_load_off`, `_parse_load`,
   `_resolve_offset_addr`, helpers, and the `_is_field_number` spec bound. Strip the
   prototype's `import proto.extractor as E` usage:
   - `E._INTERNAL_PB_IVARS`, `E._is_proto_flags_ivar` → the production caller already
     filters ivars before calling; accept the pre-filtered `field_ivars` and build
     `offset_to_name` from them (no extractor import → no cycle).
   - `E.disasm`-style helpers → import from `macho.disasm` (already where they live).
2. **Thread the branch-indegree pre-pass (REQUIRED for Phase A, but trivial).**
   `build_branch_indegree` is a *binary-wide* pre-pass (scans all methods to find
   shared thunks) that `bind_all` takes as a parameter. The walk runs in Phase A,
   so it needs this in Phase A — but building it *per class* would be correct yet
   O(n²) (a full-binary scan ×~1637 classes), so build it **once** in `extract_all`
   and thread it through (exactly like `readfrom_core_index` / `string_write_helpers`),
   or memoise on `ctx` (declared + reset, per the §3 cache discipline). Pure
   plumbing, no algorithm work.
3. **Rewrite `_extract_writeto_field_numbers`** as the Phase-A merge (§3), keeping
   the current forward-scan as the contributor for walk-misses and as the
   `_out_helpers` source (§2).
4. **Keep the public surface** exactly as re-exported today.
5. **(NOT Phase A — deferred to Phase B) Walk's own `_out_helpers` capture.** Have
   `bind_all` also return `{ivar: helper_va}` from each bound write's BL target.
   Only needed once the current decoder is removed (Phase B); see §2. Optional in
   Phase A purely to improve typing of the 74 new walk-more fields.

## 5. Gating / verification (Phase A)

- **Golden diff is the review artifact, not a pass/fail.** Run
  `snapshot_output.py` before/after; the diff should be **exactly**: the 34
  DISAGREE corrections + the 74 walk-more additions (and their type/notes), and
  **no regressions** (no field that was confirmed becoming unconfirmed/renumbered
  downward). Walk through the diff; spot-check a sample of the 74 walk-more against
  Hopper (they are the unverified population). Accept by regenerating the goldens
  (`MACHO_UPDATE_GOLDEN=1`) — the git diff of `tests/golden/*.json` becomes the
  audited record of every output change.
- **Full suite** green (`run_tests.py`); the `_out_helpers`/element-type tests in
  `proto/test_proto.py` especially must pass (proves the helper contract held).
- **`validate_ref.py`** — expect GEOPDComponent to **improve or hold** at ≥11/14;
  confirm no field regresses.
- **`wt_oracle.py` / `audit_bind`** re-run to confirm the merged decoder now equals
  the walk on the 34+74 and equals the tool on the kept misses.
- Snapshot #3 after Phase A passes review.

## 6. Risks / open questions

- **R1 — the 74 walk-more are not all verified.** Mitigation: golden review +
  Hopper spot-check; if any look wrong, gate walk-more behind "only adopt when the
  number is also produced by the readFrom cross-oracle" (we have `wt_oracle.py`).
- **R2 — `_out_helpers` typing of the 74 new walk-more fields (Phase A: minor).**
  In Phase A the *current* decoder remains the helper source, so existing fields
  are unaffected; the only exposure is that the 74 new fields have no helper entry
  and lean on the other type resolvers — at worst typed coarsely, never a
  regression (see §2). Helper *parity* between walk and tool is a **Phase B**
  concern (when the walk becomes the sole source). Covered by the type-snapshot in
  the golden either way.
- **R3 — indegree pre-pass threading (Phase A, required, trivial).** Must be built
  once in `extract_all` and threaded (item 2) — not a blocker, just plumbing.
  Decide once-in-`extract_all` vs ctx-memo before coding.
- **R4 — number uniqueness conflicts** between a walk-more and a kept tool binding.
  Policy above (keep the verified/older, drop the collider) must be explicit and
  logged.

## 7. Rollback

Each phase is its own commit on `extractor-tidy`. Phase A is reversible to
`a5be032`. If the golden review surfaces unacceptable changes, revert the Phase-A
commit; the carve (snapshot #2) remains intact and output-identical.
