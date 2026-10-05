# Test-tightening plan: mutation-testing audit findings (CLEAR sample, n=184)

## Background

A blind test-quality audit ran mutation testing (revert-the-commit's-behavioral-
change, rerun the test, check it fails) across two populations of this
project's tests:

1. A 44/45-commit **census** sample (n=184): 164 EFFECTIVE / 14 CHANGE
   INEFFECTIVE / 4 MISATTRIBUTED / 2 TAUTOLOGICAL.
2. A **CLEAR sample** (n=184): individually-committed tests whose introducing
   commit falls outside the census, drawn by fixed-seed random sampling from
   the full test-to-commit map. Final tally: 148 EFFECTIVE / 29 CHANGE
   INEFFECTIVE / 2 genuine MISATTRIBUTED / 5 commit-mapping lineage artifacts
   (excluded — see below).

Verdict taxonomy used throughout:
- **EFFECTIVE**: test fails when the commit's specific behavioral change is
  reverted (the good case).
- **CHANGE INEFFECTIVE**: the test is genuinely aimed at the right mechanism
  (confirmed via a harsher mutation of the same code path that DOES fail it),
  but its specific fixture/input doesn't discriminate old-code-from-new-code
  for THIS commit's revert.
- **MISATTRIBUTED**: the test structurally never reaches the changed code
  under any input — either a genuine wrong-target test, or (5 cases here) a
  commit-mapping/lineage artifact where the pickaxe-based introducing-commit
  script found a since-deleted prototype file's first appearance of the test
  name rather than its real production introduction. The 5 lineage artifacts
  are a **tooling/attribution problem, not a test-quality problem** — the
  tests themselves are fine, just mis-dated — so they are NOT included in
  this tightening plan. (All 5 trace to commit `c7b5994`'s throwaway
  `wt_reader.py` prototype, later carried into production `proto/writeto.py`
  at `6b50638`/`8157052`.)

**This document is the actionable list**: 31 tests (29 CHANGE INEFFECTIVE + 2
genuine MISATTRIBUTED) whose assertions should be tightened so they actually
discriminate the mechanism they claim to test. Grouped by root-cause pattern,
each with the mutation-testing evidence and a concrete suggested fix.

## UPDATE (post-publication correction — read before working Pattern 1)

Direct `git show <hash>` checks (not just the mutation-testing notes) confirmed
that **every one of the 13 "Pattern 1: negative-control sibling" tests below
has a genuine, already-passing positive-case sibling test added in the SAME
commit, in the SAME file** (e.g. `test_genuine_bytes_not_element_unresolved`
in `6536559` is paired with `test_unresolved_bytes_propagates_element_unresolved`,
also added by `6536559`, which DOES discriminate the commit's change). This
means these 13 aren't real test-suite gaps — they're a sampling-granularity
artifact: the audit draws individual tests, not whole commits, so it can land
on just the negative half of an already-complete pair. The suite as a whole
already has adequate coverage for all 13 of these commits.

**Action: SKIP all 13 Pattern-1 tests below — do not spend time tightening
them.** They were removed from the CLEAR-sample tally for this reason (not
included in this document's 31-test count, which already reflects their
removal down to 18 remaining CHANGE INEFFECTIVE + 2 MISATTRIBUTED = 20... if
you are reading an OLDER cached copy of this file that still lists 13
Pattern-1 entries, ignore that section entirely and treat this update as
authoritative.) If you already tightened one of these 13 before reading this,
no harm done, but it wasn't necessary — feel free to revert that specific
change if you'd rather keep the diff minimal.

## How to verify a fix

For each test you tighten:
1. Reproduce the ORIGINAL insensitivity first: create an isolated git worktree
   (`git worktree add --detach /tmp/wr_tighten_<hash> <hash>`), revert the
   commit's specific behavioral change (see the note per test below), run the
   CURRENT (tightened) test against it — it should now FAIL.
2. Run the tightened test against the current, un-reverted code — it must
   PASS.
3. Run the FULL suite (`./venv/bin/python3 -m pytest apple_protobuf_extractor/tests`)
   to confirm no regressions. This repo's real device data lives in gitignored
   `iphone8_data/` at the repo root; set `MACHO_DATA_DIR=<repo>/iphone8_data`
   (and/or `MACHO_TEST_CACHE`) if working from an isolated worktree, or just
   run from the main checkout.
4. Clean up worktrees: `rm -rf /tmp/wr_tighten_...` then `git worktree prune`
   (this git version is 2.15.0, no `git worktree remove`).
5. NEVER use system `python3` — it lacks `capstone` and silently fakes results.
   Always `./venv/bin/python3`.

Do not weaken or delete any currently-passing assertion while tightening —
add new fixture cases / assertions so the test covers both the case it
already checks AND the case that would have caught the original regression.

---

## Pattern 1 — REMOVED, see UPDATE at top of this document

Was: "negative-control tests missing their positive-case sibling." Direct
`git show` checks confirmed all of these have a real, already-passing positive
sibling in the same commit — not a suite gap, just a sampling artifact. Do not
work this pattern; see the UPDATE section above for the full explanation.

## Pattern 2 — Redundant guard masks the commit's own layer (9)

Two independent mechanisms protect the same invariant; removing only the
commit's own layer doesn't matter because a separate, pre-existing layer
already blocks the bad outcome. To make these tests discriminate the
commit's layer specifically, isolate/bypass the OTHER layer in the fixture
(so only the commit's own guard remains as protection).

| Test | Commit | Redundant layer that masks it | Suggested fix |
|---|---|---|---|
| `tests/test_readfrom_dispatch.py::TestReadFromDispatchLive::test_lever_never_binds_singular_message_field` | `56c0e9c` | A separate gate (arm's second `bl` must land in `core_index` as a ReadAllFrom element AND in `own_imps` as an adder) already blocks singular-field binding in this real binary. | Find or construct a fixture where that second gate does NOT apply, so only the array_offsets-type-check guard under test is protective. |
| `tests/test_backing_store_phantom.py::TestBackingStorePhantom::test_suffix_must_be_a_real_suffix` | `e53c552` | The sibling-ivar dict lookup on an empty-string key already returns None regardless of the `len(name) > len(suffix)` guard. | Add a fixture where the empty-string key WOULD exist in the sibling dict (so only the length guard prevents a false phantom match). |
| `tests/test_arm64cfg_cfg.py::TestBuildBlocks::test_unconditional_b_edge_and_tailcall_dropped` | `3cfb3ef` | `addr_to_block.get(s)` with no default already filters the nonexistent tail-call target regardless of the `lo <= t < hi` range guard. | Construct a CFG where the tail-call target address coincidentally collides with a real (different) block's address, so the `.get()` alone wouldn't catch it and the range guard is load-bearing. |
| `tests/test_opaque_passthrough.py::TestOpaquePassthroughLive::test_flag_implies_field_less` | `23f3e4f` | Two guards (call-site `(not fields) and` AND `_is_opaque_passthrough`'s own structural precheck) both protect the invariant; the call-site guard alone is tautologically sufficient (`False and X` is always `False` regardless of X). Flagged during re-verification as sitting close to the TAUTOLOGICAL boundary. | Test `_is_opaque_passthrough` directly/in isolation (bypassing the call-site guard) with a field-bearing class, asserting it returns False on its own merits — don't rely on the call-site AND alone. |
| `tests/test_dispatch_synthetic.py::TestWiringBugGuard::test_value_error_in_guarded_hop_swallowed` | `d0c95f4` | A pre-existing broad `except` already swallows ValueError; the commit's new guard only added NameError/ImportError handling, a different exception class entirely. | This test is arguably MISATTRIBUTED-adjacent — it documents pre-existing behavior, not this commit's addition. Add a NEW test asserting NameError/ImportError are specifically swallowed (the commit's actual addition), and keep this one as a pre-existing-behavior regression guard with a clarifying comment. |
| `tests/test_enum.py::TestDisasmTruncationDetection::test_empty_is_not_truncated` | `db0b813` | At `cap=10`, `len(insns) >= cap` (0>=10=False) already short-circuits before `insns[-1]` is touched, making the `and bool(insns)` guard dead weight for this fixture. | Use `cap=0` (or any cap the empty list already meets/exceeds) so the length check alone does NOT short-circuit, forcing the `bool(insns)` guard to be load-bearing. |
| `tests/test_global_state_kwargs.py::TestCollectEnumDefinitionsDebugWriterKwarg::test_no_writer_kwarg_emits_nothing_and_does_not_raise` | `1ec059a` | Double-guarded design (outer `if _dbg_w is not None` in enums.py + inner writer-None guard in config.py); commit removed only the module-global fallback, and both guards are no-ops for this "no writer" fixture regardless. | Add a case that supplies a writer object but exercises the config.py-level global-removal specifically (e.g., call the function twice with different explicit writers and assert no cross-call state leaks via the old global). |
| `tests/test_writeto_helper_family.py::TestClassifyWriteHelperOffline::test_none_helper_is_plain` | `48c18fc` | The surrounding try/except in `_classify_write_helper` already catches the `disasm(ctx, None, ...)` TypeError and falls back to `fam="plain"`, regardless of the explicit `if not helper_va: return "plain"` guard. | Bypass the try/except (e.g. call the internal logic directly, or use a helper_va value that's falsy but wouldn't raise in disasm) so the explicit guard is the only thing preventing a crash/wrong classification. |
| `tests/test_memory.py::TestIterSymbolNames::test_out_of_range_offsets_are_safe` | `96739d8` | Single-guard reverts on either the nlist or export-trie clamp are masked by a sibling clamp; only removing both simultaneously crashes. | Split into two tests, each constructing a fixture that exercises ONLY one of the two clamps (nlist out-of-range with a valid export-trie, and vice versa). |

## Pattern 3 — Pure refactor tests that can't see the derivation-path change (5)

The commit's own goal is output-invariance (de-globalize a value, derive X
from Y instead of duplicating it). A test that only checks the resulting
*value* can never discriminate the *mechanism* by which that value was
produced. These need either a mechanism-level assertion (e.g., mock/patch
the removed global and confirm it's genuinely unused) or should be honestly
re-labeled as "value invariant" checks rather than regression tests for the
refactor itself.

| Test | Commit | Note |
|---|---|---|
| `tests/test_proto.py::TestConfigurePrefixes::test_empty_tuple_strips_nothing` | `1ec059a` | Explicit empty tuple never reaches the fallback-to-global/DEFAULT_PREFIXES branch at all. |
| `tests/test_global_state_kwargs.py::TestClassToProtoNamePrefixKwarg::test_no_kwarg_uses_default_prefixes` | `1ec059a` | No code path in this test ever mutates the (now-removed) global, so old/new semantics coincide by construction. |
| `tests/test_prefix_consolidation.py::TestSingleCanonicalSource::test_config_default_derives_from_default_prefixes` | `1ec059a` | The old global was itself initialized from DEFAULT_PREFIXES — value-identical by construction, not just coincidentally. |
| `tests/test_prefix_consolidation.py::TestConfigDefaultPrefixes::test_default_prefix_set_strips_each_default` | `1ec059a` | Same root cause — never calls `configure_prefixes()`/touches the global, so it can't observe its removal. |
| `tests/test_writeto_unit.py::TestOperandToolkit::test_parse_load_is_mem_operand_shim` | `aa7ff5d` | Commit's own stated goal was byte-identical output before/after becoming a thin shim; this test literally confirms invariance, so by design it can't discriminate the refactor. **Recommend leaving as-is** — it correctly verifies output-invariance, which is what the commit promised. |

*For the 4 `1ec059a` tests: consider ONE new test that directly exercises the
removed global's absence — e.g., monkeypatch/assert `proto.config` has no
module-level mutable prefix state, or call `configure_prefixes()` from two
"threads"/contexts and confirm no cross-contamination (which the old global
design would have permitted and the new explicit-param design prevents).*

## Pattern 4 — Commit's actual diff doesn't affect what this test checks (3)

| Test | Commit | Note | Suggested fix |
|---|---|---|---|
| `tests/test_enum_decoders_synthetic.py::TestEnumNameFromPairs::test_single_word_common_prefix_returns_fallback` | `4ea5947` | Test-only commit (no production diff); `capitalize('STATUS')` coincidentally equals the supplied fallback. | Use a common prefix whose capitalized form does NOT equal the fallback string, so the guard's absence would produce a visibly wrong name. |
| `tests/test_emitter.py::TestProtoFileEmit::test_fields_sorted_by_number_in_output` | `3e09d35` | Commit's diff is dead-code removal (`ProtoMessage.to_proto()`); test covers the pre-existing, untouched `_emit_message` sort logic. | Not really a defect in the test — it's just mis-attributed to this commit (should be attributed to whichever commit introduced field-sorting in `_emit_message`). Low priority; consider re-running the commit-mapping script. |
| `tests/test_golden_output.py::TestGoldenOutput::test_golden_CoreLocationProtobuf` | `c7b5994` | The commit's cache-reset fix only matters when a `BinaryContext` is reused across multiple `extract_all` calls; this golden test only ever calls it once per fresh context. | Add a new test that explicitly reuses one `BinaryContext` across two `extract_all` calls on different artifacts and asserts no cross-contamination via `_wrapper_cluster_cache`/`_dispatch_arms_cache` (this is exactly what `test_extract_cache_reset.py` should already cover — verify it does, and if so this golden test needs no change). |

## Pattern 6 — Genuine wrong-target MISATTRIBUTED (2)

These don't need "tightening" so much as **redirecting** — the fixture needs
to change so it actually reaches the code region under test.

| Test | Commit | Problem | Suggested fix |
|---|---|---|---|
| `tests/test_backing_store_phantom.py::TestUnresolvedObjectFieldNote::test_scalar_or_struct_not_annotated` | `59a9c48` | Both fixture inputs (`count="Q"`, `pts="^{GEOPoint=ii}"`) hit `_unresolved_object_field_note`'s very first guard clause (`if not enc.startswith('@"')`) — this predates the commit entirely and is unrelated to the casing-heuristic region the commit changed. | This test is fine as-is for verifying the FIRST guard clause (a real, if unrelated, invariant) — just re-attribute it to whichever commit actually introduced that first guard, rather than `59a9c48`. |
| `tests/test_writeto_helper_family.py::TestClassifyWriteHelperOffline::test_encoders_self_check` | `48c18fc` | Only disassembles the test file's own hand-encoded arm64 bytes (`_enc_lsl`/`_enc_mov`) to sanity-check the TEST's encoder helpers — never calls `proto.extractor._classify_write_helper`, the commit's actual new function. | Rename to clarify it's a test-infrastructure sanity check (e.g. `test_encoder_helpers_produce_expected_mnemonics`), not a regression test for the sint/fixed recovery feature — or add an actual call to `_classify_write_helper` using these same encoded bytes so it also exercises production code. |

---

## Priority suggestion

Start with **Pattern 6** (2 tests) — these are the clearest wrong-target
cases and cheapest to fix (rename + re-attribute, or add one missing call).
Then **Pattern 2** (9 tests) — each needs a fixture change to isolate the
commit's own guard from the redundant one, which is usually a small,
mechanical edit. **Pattern 1** (12 tests) mostly just need a second
(positive-case) assertion added alongside the existing negative one. **Pattern
3** (5 tests, all but one from the same `1ec059a` refactor) and **Pattern 4**
(3 tests) are lower priority — several are arguably fine as-is (see notes)
and mostly reflect that these commits were behavior-preserving by design.

Full per-test mutation-testing evidence (exact lines reverted/mutated, exact
before/after assertions) is available in the audit's working CSVs if more
detail is needed than the summaries above — ask the originating session
(chat history references `clear_all_100.csv`, `clear64_verify_g*.csv`,
`clear20_verify_g*.csv` in that session's scratchpad) if you need the raw
per-test transcripts.
