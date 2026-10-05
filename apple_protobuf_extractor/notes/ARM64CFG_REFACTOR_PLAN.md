# Refactor plan: shared arm64 CFG layer for writeTo + readFrom

**Status:** PLAN ONLY — nothing implemented. Written 2026-06-11.
**Motivates:** TODO #42 (CFG/dominator readFrom dispatch resolver).
**Prereq for landing:** the other session's #39 commit must settle first (high
merge-conflict surface — see Coordination below).

---

## Why

TODO #42 wants to replace the readFrom dispatch resolver's *linear
instruction-pattern matching + address-range attribution* with a proper
CFG/dominator walk — the readFrom analogue of the writeTo CFG-walk (#30–33).

Investigation finding that justifies the work: the linear+address-range pattern
#42 targets is **duplicated three times** today, all running the identical loop
`_func_end → _find_field_number_register → _compare_chain_blocks → raw-word bl
scan → _field_for_addr` (address-range attribution):

1. `dispatch._core_resolves_compare_chain` — the core picker (one of the two
   #39 guards)
2. `repeated._resolve_compare_chain_elements` — field# → element **type**
3. `repeated._resolve_compare_chain_ivars` — field# → element **ivar**

A single principled resolver collapses all three and deletes both #39 guards
(`_degenerate_block_partition`, `_core_resolves_compare_chain`).

### Reuse assessment (writeTo → readFrom)
- **Shared foundation already exists:** both sides import `macho/disasm.py`
  (`disasm`, `Insn`, `_parse_imm`, `_norm_reg`, `find_adrp_*`) and
  `macho/arm64decode.py` (`_decode_cmp_imm`, `_decode_bcond`, `_decode_lsr_imm`,
  `_decode_b_bl_target`, …). The decode layer is not the problem.
- **Reusable infra (~40%):** the BFS block-discovery skeleton in `writeto_walk`
  (leaders / work-list / visited / fall-through-into-leader handoff);
  `build_branch_indegree` + `classify_b_target` (shared-thunk avoidance applies
  identically to reader cores); base-register (`cur_base`) threading; `_next_imp`
  extent bound.
- **Net-new (~60%):** the dispatch *semantics* are inverted (writeTo = `movz
  wN,#field` then `bl helper` with has-bit guards/submsg/offset threading;
  readFrom = `lsr Wf,Wtag,#3` then `cmp Wf,#N; b.eq` spine or jump table, handler
  runs `bl <ReadAllFrom>`). And **dominators do not exist anywhere today** —
  `writeto_walk` deliberately threads the controlling guard along edges instead
  of computing a dominator tree, and never retains an adjacency/CFG structure.

### Capstone note
The native fallback decoder (`macho/disasm.py:497 _native_decode`) returns `unk`
for `cmp` / `b.cond` / `lsr`/`ubfm` — exactly the dispatch-critical instructions.
`writeto_walk` relies on capstone (via `disasm()`) to see `b.cond`; the existing
readFrom code instead reads **raw 32-bit words** + the `arm64decode._decode_*`
family specifically to stay capstone-independent. #42 must pick one model.
Recommendation: the new CFG builder decodes via `disasm()` (capstone path, like
writeTo) since the project runs under `./venv/bin/python3` (capstone installed);
keep the raw-word `_decode_*` helpers available as the capstone-free fallback.

---

## Guiding principle

**Do not touch the byte-identical writeTo decoder.** The refactor only (a)
*lifts* genuinely-pure helpers out of `writeto.py` into a shared module, and (b)
*adds* net-new CFG + dominator infrastructure for readFrom (#42) to consume.
writeTo keeps its current streaming walk verbatim, so the golden gate stays
empty-diff.

---

## New module: `proto/arm64cfg.py`

Pure arm64 / control-flow analysis over `macho.disasm.Insn`. Imports only from
`macho.*` (keeps the existing `proto → macho` direction, no import cycle).

### Tier 1 — lift pure helpers (low risk, pure code-move)
Move these out of `writeto.py` unchanged; `writeto.py` re-imports and
**re-exports** them so `tests/test_writeto_walk_coverage.py` and any
`from proto.writeto import …` keep working:

| Helper | writeto.py line | Why it's generic |
|--------|-----------------|------------------|
| `TERMINALS`, `CONDITIONALS`, `_CALLEE_SAVED` | 98–110 | constants, no writeTo meaning |
| `_is_cond` | 121 | mnemonic test |
| `_parse_load` | 125 | operand parsing |
| `_same_reg` | 144 | register identity (w/x views) |
| `_adrp_page` | 154 | adrp page resolution |
| `_resolve_offset_addr` | 163 | ivar-offset-var address resolver (generic) |
| `_cond_target` | 244 | branch-target extraction (tbz/cbz/b.cc) |
| `_next_imp` | 254 | function-extent bound |

Gate: golden empty-diff + full suite. Move + re-export ⇒ behavior provably
unchanged.

### Tier 2 — generalize the shared-thunk detector (small, ~2 hr)
`build_branch_indegree` (writeto.py:259) is generic except it hardcodes
`get_method("writeTo:")`. Add a selector parameter:

```python
build_branch_indegree(ctx, cl, imps_sorted, selector="writeTo:")
```

`writeto.build_writeto_indegree` calls it with the default; #42 calls it with
`"readFrom:"`. `classify_b_target`'s thunk/follow/foreign logic is generic — the
only writeTo-specific bit is the `_writeto_field_number_before` "is this a
tail-call write?" test, which becomes an **injected predicate** (writeTo passes
its own; readFrom passes one recognizing a tail-call into a ReadAllFrom core).

### Tier 3 — net-new CFG + dominator builders (the #42 enabler; ~1 day, isolated)
Do not exist today. Net-new ⇒ cannot regress existing output.

```python
build_cfg(ctx, entry, *, foreign_imps, indeg, selector_imp) -> Cfg
    # Same leader rules as writeto_walk (cond targets, b targets,
    # fall-through-into-leader), but returns a RETAINED structure:
    #   blocks: list[(start, end, insns)]
    #   succ:   {block_start: [block_start, ...]}
    #   entry:  int
    # Decodes via disasm() (capstone) so cmp/b.cond/lsr are real mnemonics.

build_dominators(cfg) -> {block_start: idom_block_start}
    # iterative dataflow (Cooper-Harvey-Kennedy "A Simple, Fast Dominance
    # Algorithm"); functions here are tens of blocks, so no Lengauer-Tarjan.

dominates(doms, a, b) -> bool
```

Gate: own unit tests **plus** an equivalence check — for a sample of real
`writeTo:` methods, assert `build_cfg`'s discovered blocks/leaders cover exactly
the set `writeto_walk` visits (proves the lifted leader logic matches; no output
change).

---

## What #42 then builds on top (separate effort — NOT this refactor)

A `readfrom_walk` (in `proto/dispatch.py`) that:
- finds the dispatch core **structurally**: a function that extracts
  `Wf = tag>>3` (`lsr`) and branches on `Wf` — excludes accessors by
  construction, removing the need for the `_core_resolves_compare_chain` picker;
- follows the compare-chain **spine** over `cfg.succ` (each block tests a
  distinct constant vs `Wf`; fall-through → next test; eq/ne → handler), stopping
  when the fall-through is no longer a field compare (excludes stray sentinels
  like GERPFeedbackFieldValue's `cmp w1,#1000`);
- attributes each element `bl` to the field whose match-edge **dominates** it
  (`dominates(doms, …)` — exact, replacing `_field_for_addr`'s address-range
  approximation that already needed one patch in #17);
- composes with the already-principled `_decode_readfrom_jumptable`.

Net: *resolves* readers the current guards *bail* on (e.g. GERPFeedbackFieldValue's
21 fields), collapses the three duplicate compare-chain consumers, and deletes
both #39 guards. Likely shares the CFG/indegree machinery built in Tier 3.

---

## Sequencing & effort

1. **Tier 3** first (~1 day, **conflict-free** — all net-new in a new file) —
   `build_cfg` / `build_dominators` + tests + writeTo-equivalence check.
2. **Tier 1** (½ day, low risk) — lift + re-export; golden empty-diff.
3. **Tier 2** (~2 hr) — parameterize indegree/classify.
4. *(then #42 proper consumes all of the above.)*

Tiers 1–3 are independently valuable (dedup + reusable infra) **even if #42 is
never done**.

## Verification gate (every step)
- `./venv/bin/python3 run_tests.py` (full suite)
- `./venv/bin/python3 validate_ref.py` (GEOPDComponent 11/14,
  GEOPDPlaceGlobalCommonResult 1/1)
- golden snapshots in `tests/golden/` (`MACHO_UPDATE_GOLDEN=1` only after
  reviewing the git diff — Tiers 1–3 should produce **empty** golden diff;
  any diff means the lift changed behavior and must be investigated)

## Coordination

`writeto.py`, `dispatch.py`, `repeated.py` are exactly the files the other
session is editing (#39 commit pending; #42 is its task). Tier 1 moves code *out
of* `writeto.py` and Tier 2 edits `build_branch_indegree` — high merge-conflict
surface. **Land only after the #39 commit settles.** Start with Tier 3: the new
`proto/arm64cfg.py` is all net-new, so it conflicts with nothing.

## Key source references (as of 2026-06-11)
- `proto/writeto.py` — `writeto_walk` (299), `build_branch_indegree` (259),
  `classify_b_target` (283), pure helpers (98–256), `detect_context` (457),
  `bind_write` (557), `_walk_field_numbers` (619).
- `proto/dispatch.py` — `_find_field_number_register` (562),
  `_compare_chain_blocks` (589), `_field_for_addr` (636),
  `_core_resolves_compare_chain` (648), `_decode_readfrom_jumptable` (470),
  `_locate_dispatch_arms` (727).
- `proto/repeated.py` — `_resolve_compare_chain_elements` (152),
  `_resolve_compare_chain_ivars` (216), `_degenerate_block_partition` (120).
- `macho/disasm.py` — `disasm` (352), `_native_decode` (497, returns `unk` for
  cmp/b.cond/lsr).
- `macho/arm64decode.py` — raw-word `_decode_*` family (capstone-free path).
