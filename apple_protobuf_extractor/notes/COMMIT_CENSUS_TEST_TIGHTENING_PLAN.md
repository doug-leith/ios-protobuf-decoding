# Test-tightening plan: 44-commit mutation-testing census findings

## Background

A separate blind mutation-testing audit (revert-the-commit's-behavioral-change,
rerun the test, check it fails) ran across a **44/45-commit census sample**
(n=184 tests — one or more tests per sampled commit), independent from the
"CLEAR sample" audit covered by the sibling document
`TEST_TIGHTENING_PLAN.md` in this same directory. Final, fully
independently-re-verified tally:

**164 EFFECTIVE / 14 CHANGE INEFFECTIVE / 4 MISATTRIBUTED / 2 TAUTOLOGICAL**
(one item moved from CHANGE INEFFECTIVE to MISATTRIBUTED during re-verification
after the original note's justification was found to contain a factual error).

Every one of these 20 non-EFFECTIVE findings was independently re-verified in
a second pass (a fresh agent redid the mutation trial from scratch, without
reading the original note first, then compared). 19 of 20 were confirmed as
originally classified, several meaningfully strengthened with new evidence
(exact tracebacks, byte-level instrumentation, full-suite coverage sweeps,
literal-revert-vs-targeted-mutation comparisons). 1 was overturned.

**This document is the actionable list**: all 20 findings, grouped by
root-cause pattern, each with the mutation-testing evidence and a concrete
suggested fix. Unlike the CLEAR-sample plan, none of these were found to be
sampling-granularity artifacts (same-commit sibling pairs) or cross-session
commit-bundling artifacts — these are census findings, sampled at commit
granularity, so those specific failure modes don't apply here. A few *do*
turn out to be masked by a genuine sibling test elsewhere in the same commit
(noted per-test below) — those are lower priority, not exclusions.

## How to verify a fix

Same recipe as the CLEAR-sample plan:
1. Reproduce the ORIGINAL insensitivity first: isolated git worktree
   (`git worktree add --detach /tmp/wr_census_<hash> <hash>`), revert/mutate
   the commit's specific change per the note below, confirm the CURRENT
   (unfixed) test does NOT fail (for CHANGE INEFFECTIVE) or DOES still pass
   under a full revert (for MISATTRIBUTED/TAUTOLOGICAL).
2. Apply your tightening fix, confirm the tightened test now FAILS against
   the same reverted/mutated code.
3. Confirm the tightened test still PASSES against current, unmodified code.
4. Run the full suite (`./venv/bin/python3 -m pytest apple_protobuf_extractor/tests`)
   for regressions — set `MACHO_DATA_DIR=<repo>/iphone8_data` if working from
   an isolated worktree (gitignored real-device fixtures aren't copied by
   `git worktree add`).
5. Clean up worktrees (`rm -rf` + `git worktree prune` — git 2.15.0, no
   `git worktree remove`). Always use `./venv/bin/python3`, never system
   `python3` (lacks capstone, silently fakes results).

Do not weaken or delete any currently-passing assertion while tightening.

---

## Priority 1 — Genuinely uncovered behavior (MISATTRIBUTED, highest value to fix)

### `530db9ef` — `TestDisasmHitCap` (5 test methods)
**The strongest finding in this whole census.** The commit's actual change —
`number_confirmed=False` on truncated builder reads — currently has **zero
test coverage anywhere in the suite**, not just a narrow gap in these 5 tests.
Confirmed by running the entire available swift-related test surface (70
tests across 3 files) against the same integration-deletion mutation: zero
failures, anywhere. Root cause is structural: these 5 tests use bare
`(mnemonic, op_str)` stand-ins that never go through `ctx`/`disasm()` at all
— a one-directional call graph gap, not a fixture-choice problem.
**Fix**: write a new live or synthetic test that actually drives the real
`disasm()`-based code path with a truncated builder read, and confirms
`number_confirmed=False` is set. This is a real, currently-unguarded
behavior — prioritize this one.

### `a95197e9` — `TestNonStructuralDetectionFailsTheRun::test_clean_binary_does_not_raise`
Calls `E._proto_class_set(ctx, cl)` **directly** — never goes through
`extract_all`, which is the only function that wires in
`check_no_heuristic_detection` (the actual enforcement gate this commit
added). Independently hand-verified the test's own docstring claim ("the
check must be inert on a clean set") IS true of the real system by calling
`extract_all` directly on an equipped fixture — so the underlying behavior is
fine, it's just genuinely untested by this specific test.
**Fix**: route the test through `extract_all` (or a thin wrapper that wires
the gate the same way) instead of calling `_proto_class_set` directly.

### `a95197e9` — `TestSingleClassPathFlagsButDoesNotFail::test_no_superclass_single_class_extraction_flags_and_succeeds`
Never calls `extract_proto_message` — the untested claim was independently
proven true by calling it directly on the fixture, so again the behavior is
fine, just uncovered by this test.
**Fix**: route through `extract_proto_message` (or whatever the real
single-class-path entry point is) instead of whatever narrower helper this
test currently calls.

### `284e018d` — `test_field_reg_recovered`
Proved from the diff alone (not just dynamic testing): `_find_field_number_register`
— the only function this test calls — is byte-identical before and after the
commit. Wrong target entirely.
**Fix**: identify what function the commit actually changed (check `git show
284e018d` for the real diff) and retarget the test at that function, or if
no reasonable test can be built for it, note that explicitly rather than
leaving a misleadingly-named test in place.

---

## Priority 2 — Downstream masking guards absorb the commit's own layer

### `3157b8f7` — `TestStaticBlobScan::test_zero_count_returns_none`
Not one masking guard but **two independent** downstream guards both produce
"None" for this input (`off+24<=len(buf)` bound AND `len(out)<count` bound) —
either alone would hide the deleted commit's own bounds check.
**Fix**: construct a fixture where both downstream guards pass (buffer long
enough, count small enough) so only the commit's own check remains as
protection, then verify a revert of just that check produces a wrong value
instead of a safe None.

### `3157b8f7` — `TestStaticBlobScan::test_unreadable_returns_none`
At the specific line the original revert targeted, coverage is literally 0%
— a completely different code path (a `try/except`) is what this test
actually, validly exercises. At whole-function granularity CHANGE INEFFECTIVE
is the right label; at single-line granularity this borders on MISATTRIBUTED.
**Fix**: either accept this test as covering the `try/except` path (rename/
re-document it as such) and write a *separate* new test for the specific
reverted line, or restructure so this test's fixture reaches the reverted
line specifically.

---

## Priority 3 — Fixture didn't pick the sharpest differentiating input (real, fixable gaps — a differential input existed and wasn't used)

### `2e8f4ea6` — `TestIsRealFieldIvar::test_getterless_non_flags_ivar_is_admitted`
The empty `method_names={}` fixture makes non-discrimination guaranteed **by
construction** (short-circuits before inspecting anything field-specific),
not incidental. A fixture with a non-empty, name-matching set was available
and would have discriminated the real change, but wasn't used.
**Fix**: use a non-empty `method_names` set that actually matches the ivar
under test.

### `2e8f4ea6` — `TestFieldLabel::test_value_struct_is_not_repeated`
Same pattern: a genuinely differential input existed
(`{CGSize=dd}` with `method_names={'addSize:','sizeCount'}` would flip
old-vs-new) but the test uses an empty set instead.
**Fix**: swap in the differential input identified above.

### `515ba078` — `TestIsProtoFlagsIvar::test_flags_struct_behind_name_still_detected`
Full revert only survives because the OLD code's looser fallback clause
happens to *also* accept this exact string for an unrelated reason (general
substring matching, not the specific "anywhere opener" generalization this
commit made). Two independently-designed one-line mutations of the *new*
detection expression both kill it cleanly, so the test is well-aimed, just
using an input both old and new code happen to accept.
**Fix**: find or construct a string that the new "anywhere opener"
generalization accepts but the old looser-fallback substring match does not,
and use that as the fixture instead.

### `b21b2f73` — `test_index_scale_lsl3_on_nonfield_reg_does_not_block_fixed`
Full revert passes because old code has **no** `lsl`-by-3 handling at all —
absence, not correct-gating, coincidentally produces the same answer.
Stripping just the new register-gate condition (a harsher, targeted mutation)
does fail it cleanly, so the test is aimed correctly.
**Fix**: lower priority than the others in this group — the "old code" here
isn't really a comparable prior state (the mechanism is wholly new), so
there may not be a cleaner fixture to pick. If you want stronger evidence,
add a second assertion that the register-gate condition itself is honored
(e.g. a case where the register IS the field register, confirming the gate
correctly allows the fixed-point path).

---

## Priority 4 — TAUTOLOGICAL (assertion structurally can never fail — needs a different assertion strategy, not just a different input)

### `b21b2f73` — `test_varint_tag_shift_is_plain`
The function's unconditional fallback default (`'plain'`) and the genuine
terminator match agree for this short 2-instruction input — no mutation
*confined to the new mechanism* can fail it (proven structurally). A compound
mutation of a different, older, pre-existing check does defeat it, but that
collaterally breaks 2 unrelated tests, so it's not a clean fix.
**Fix**: needs a longer/different instruction sequence where the fallback
default and the real terminator-match logic would disagree if the mechanism
were broken — i.e. an input where getting the terminator-match wrong would
NOT coincidentally still land on 'plain'.

### `284e018d` — `test_core_resolves_compare_chain_no_known_cores`
The migrated closure (`field_of`) is never even *called* for this input — the
call site is gated behind `if target in core_index`, always False when
`core_index={}`. Proven via a full-function-replacement mutation (returns a
broken lambda) that still passes because the lambda is constructed but never
invoked.
**Fix**: use a non-empty `core_index` containing `target`, so `field_of` is
actually invoked and its "no known cores" internal logic is exercised rather
than short-circuited before the call.

### `3157b8f7` — `TestFormatProto::test_message_enum_empty` (partial — one sub-claim only)
Most of this test is genuinely EFFECTIVE (3 separate harsh mutations on the
label/enum/empty-message assertions all caught real defects) — **do not
touch those parts**. But the test's own comment claims to also check "fields
sorted by number," and that specific sub-claim is provably TAUTOLOGICAL: every
assertion is `assertIn` against the full rendered text, so no reordering of
fields, however severe, could ever be detected.
**Fix**: add a genuinely order-sensitive assertion for the sorted-by-number
claim specifically — e.g. assert the string *indices* of each field name are
increasing, or parse the rendered output into a list and compare it directly
— without touching the other, already-effective assertions in this test.

---

## Priority 5 — Low priority: mechanism has real coverage via a sibling test in the same commit, or is a test-only/no-diff commit

### `284e018d` — `test_forward_branch_handler_attributed_correctly`
Actually confirmed robust — killed by all 4 escalating mutations tried
(branch-sense inversion, dominance-gate removal, scan-window halving,
full-function stub-replacement). No action needed; only flagged as CHANGE
INEFFECTIVE against the literal single-line revert, but works fine as a
regression guard.

### `284e018d` — `test_addr_before_any_handler_is_unattributed`
Killed by 2 of 4 escalating mutations (dominance-gate removal, full-function
replacement). Real, if narrowly-scoped, coverage of the "nothing dominates
the preamble" gating case. Low priority.

### `284e018d` — `test_core_resolves_compare_chain_end_to_end`
Genuinely exercises the real migrated call site end-to-end; just doesn't
discriminate the specific old-vs-new swap because both mechanisms agree on
this straightforward two-distinct-cores scenario.
**Fix (if you want to strengthen)**: construct a scenario where the
address-range approach and the dominance approach would disagree (e.g.
overlapping/nested candidate ranges), rather than the current
clearly-separated two-cores case.

### `284e018d` — `test_degenerate_partition_rejected`
**The weakest of the census's CHANGE INEFFECTIVE findings** — only 1 of 4
escalating mutations kills it (halving the scan window so the CFG misses a
`bl` target); it survives the full-replacement mutation that killed 3 of its
siblings. Root cause: both probed call sites sit in the *same basic block*,
so the dominance-vs-address-range distinction this commit is about never
actually gets exercised — `field_of`'s answer is identical regardless of
which selection logic is used.
**Fix**: move the two probe call sites into genuinely different basic
blocks so the dominance logic actually has something to decide between.

### `6a4d9982` — `test_ret_words_are_never_mistaken_for_prologue_openers`
Doesn't overlap the pacibsp/autibsp fault line at all (neither word is in
`_is_ret_word`'s set) — but a mutation making `ret` itself falsely match the
prologue-opener check does fail it. The commit is properly protected, just
by 3 sibling tests in the same file, not this one. Low priority — suite-level
coverage is adequate.

### `23255c91` — `test_repeated_label_preserved_when_elem_unrecovered`
The whole failure chain for this specific example (`Google_Protobuf_Type.oneofs`,
mangled type `SaySSG`) is fully printable ASCII with no symbolic-reference
control byte anywhere — both old and new code fail identically on an
unrelated `Sg`-suffix parsing gap, orthogonal to the raw-bytes-vs-cstring
mechanism this commit touches. The mechanism DOES have real coverage, via a
different test in the same commit (`TestCacheGroundTruth::test_message_protection`,
which uses a genuine symbolic reference and correctly discriminates old vs
new). Low priority.

### `65e3a540` — `test_field_zero_raises_valueerror`
This commit has **zero production diff** (test/doc-only, per its own commit
message) — there's no "commit-introduced behavior" to discriminate at all.
The test locks a pre-existing invariant that happens to be masked by a
coincidental downstream exception: removing the guard falls through to
`self.varint()` on an exhausted 1-byte buffer, which raises at
`cpp_descriptor_extract.py`'s `varint()` (a "truncated varint" ValueError),
not the deleted line's own message — so a bare `assertRaises(ValueError)`
can't tell the difference.
**Fix**: assert on the specific exception message the deleted line was
supposed to produce, not just the exception type, so a coincidental
different ValueError from a downstream code path doesn't silently satisfy
the test.

---

## Suggested order of work

1. **`530db9ef` TestDisasmHitCap** — the one case of genuinely zero coverage
   for a real, shipped behavior change. Do this first.
2. The two `a95197e9` MISATTRIBUTED cases and `284e018d`'s
   `test_field_reg_recovered` — clear wrong-target redirects.
3. The `3157b8f7` masking-guard and `2e8f4ea6`/`515ba078` fixture-choice
   cases — mechanical fixture swaps, well-specified above.
4. The 3 TAUTOLOGICAL cases — need a different assertion strategy, not just
   a different input; do these after the above since they require more
   careful test redesign.
5. Priority 5 items — optional; suite-level coverage is already adequate for
   all of these via sibling tests or robust confirmation under harsher
   mutation.

Full re-verification transcripts and additional nuance for every item above
are in the originating session's standing note
`census_failures_and_reverification_notes.md` (in the scratchpad directory of
that session) if more detail is needed than the summaries here.
