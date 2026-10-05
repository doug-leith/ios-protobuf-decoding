# Heuristic-registry judgment audit & relabels (2026-06-09)

**Status:** APPLIED 2026-06-09 (user-approved). Audit/metadata only — **no behavioral
change**; `heuristic_registry.py` still parses and runs. Rationale kept here so the
relabels aren't reverted by a future session.

## Why this was done

`heuristic_registry.py`'s `judgment` rubric:
- `REPLACE` — a principled signal may be available (the focus)
- `INTRINSIC` — binary genuinely doesn't encode it; heuristic unavoidable
- `PRINCIPLED` — already reads ground truth
- `ISA` — pure ARM64/Mach-O decode (deterministic; not really a heuristic)

The `INTRINSIC` bucket had been conflating two different things: (a) genuinely
unencoded info (proto package name, enum *type* name, name presentation) — correctly
INTRINSIC; and (b) **deterministic decodes that actually read ground truth** —
mislabeled. The tell: the dispatch *readers* (`comparechain`, `walk-arm`,
`fieldreg-uniq`, `typemethod-imp`) were already `PRINCIPLED`, yet the functions that
*feed or outrank them* (jump-table cluster finder, metaclass-pool builder, and
`writeTo:` field-number extraction — which is the field-number authority, more
reliable than the compare-chain, per `COMPARE_CHAIN_FIELDNUM_BUG.md`) were
`INTRINSIC`.

Investigation method: read each candidate function body and classified its inputs as
ground-truth immediate/structure decode vs. name/string convention vs. policy.

## Applied: INTRINSIC → PRINCIPLED (reads a proto fact from ground truth)

| id | function | line | rationale |
|---|---|---|---|
| `writeto-fieldnums` | `_extract_writeto_field_numbers` | 43 | decodes the literal `movz w2,#N` field number the serializer passes + binds via the real `__objc_ivar` offset variable. Verified authoritative in `COMPARE_CHAIN_FIELDNUM_BUG.md`. |
| `enum-bias` | `_find_index_bias` | 39 | decodes the real `sub #N` immediate the runtime uses to rebase a 1-based enum. |
| `dispatch-cluster` | `_find_dispatch_cluster` | 45 | decodes jump-table base/bias/entry-width from real instructions; structural front-end to the already-PRINCIPLED `walk-arm`. |
| `metapool` | `_build_meta_type_pool` | 46 | built by disassembling each `+[Cls xyzType]` IMP via `_class_from_type_method_imp`, which is already PRINCIPLED (`typemethod-imp`). |
| `dictrep-modal` | `_read_dictrep_switch_pairs` | 40 | `(value,name)` pairs come straight from the switch table + CFString payloads; the prefix-guard is a safety cross-check, not a name guess. |
| `empty-enum` | `_enums_compatible` | 62 | data-driven value/number conflict check over extracted pairs. |

## Applied: INTRINSIC → ISA (deterministic format/instruction decode, no proto judgment)

| id | function | line | rationale |
|---|---|---|---|
| `writeto-skipback` | `_writeto_field_number_before` | 44 | skip ≤6 epilogue mnemonics to the field-num imm; mechanical instruction-sequence decode. |
| `enumstr-dual` | `_read_enum_string` | 47 | C-string OR CFString decode per Apple's fixed struct layout + pointer fixups (`max_len=128` is a sanity cap, not a decode choice). |
| `readavail` | `_read_available` | 69 | segment-boundary-respecting, 4-byte-aligned read; pure Mach-O/ARM64 bounds. |

## Left INTRINSIC (per user): `packed-ptr` (`_decode_packed_ptr`)

The low-36-bit cache-pointer decode is ISA, but the segment-membership acceptance
gate is an unavoidable assumption when decoding in isolation without full cache
context. Borderline; not promoted.

## INTRINSIC → PRESENTATION (naming policy over an already-correct fact)

Applied 2026-06-09 (second-pass INTRINSIC review). A new `PRESENTATION` judgment
was added to the rubric for heuristics that are a naming/formatting *policy* over
a fact that is already recovered correctly — being "wrong" is cosmetic (no
wire/value/decoding impact), and there is no ground truth to promote them to.

- `enumval-overlap` (`_normalize_enum_value_name`) — value-label prefix
  presentation (raw value is ground truth; prefix synth is convention).
- `qualify-overlap` (`_qualify_enum_name`) — merges ground-truth class + field
  names into the enum type name via a word-overlap convention.
- `package-prefix` (`package_for_class`) — proto package is **nowhere in the
  binary** (an ~60k-string scan found only bundle IDs / queue labels, none linked
  to a message class; the GEOPD classes have no `GPBDescriptor`). Reconstructed
  from the class-name prefix; a wrong package only namespaces the output.
  Given the full "reconstructed, harmless" treatment 2026-06-09 (docstring +
  emitted `// package reconstructed …` note + `PACKAGE_NAMES.md`), mirroring the
  enum-type-name treatment in `ENUM_TYPE_NAMES.md`.

## Still INTRINSIC — kept (no ground truth, and not mere presentation)

- `enumname-prefix` (`_enum_name_from_pairs`) — enum *type* name is not in the
  binary (C enums leave no symbol; cache stripped). Confirmed by a string scan
  and given the full "reconstructed, harmless" treatment 2026-06-09 (docstring +
  emitted notes + `ENUM_TYPE_NAMES.md`). The previously-queued selector-
  confirmation upgrade was investigated and **rejected** (census: the witness
  selector confirms only ~25% and is uncorrelated with correctness — see
  `census_enumname.py` / `ENUM_NAME_FROM_PREFIX.md`).
- `enumstr-regex` (`_is_valid_enum_string`) — C-identifier sanity *gate*, not an
  extraction; nothing to promote.
- `collect-dictrep` (`_collect_enum_definitions`) — an *orchestrator* (principled
  extraction wrapped in naming + a principled "no `xAsString:` ⇒ revert to scalar"
  gate); not a single relabelable heuristic.
- `packed-ptr` (`_decode_packed_ptr`) — low-36-bit decode bounds-checked against
  the real segment table; arguably ISA, but left INTRINSIC per the earlier
  decision (segment-membership acceptance is an assumption in isolation).

## What is genuinely "replaceable" vs just relabeled

After two passes: **nothing remains to promote or replace.** Every INTRINSIC /
PRESENTATION entry is either (a) a name for info the binary doesn't encode (enum
type name, package — harmless if wrong, now documented), or (b) a validation
gate / orchestrator / bounds-checked format decode. The one queued upgrade
(`enumname-prefix` → selector-confirmation tier) was tested and rejected.

## Open cleanup — DONE 2026-06-09

Removed **four** dead REPLACE rows from `heuristic_registry.py`, not just the one
originally flagged. All four reference the no-symbols cold fallbacks deleted when
the selector-resolution gate landed (Task B); the functions no longer exist and
show 0 calls across GeoServices / locationd / CoreLocationProtobuf:

- `xasstring` → `_extract_enum_for_field`
- `writeto-count` → `_count_field_write_patterns`
- `writeto-pass2` → `_find_writeto_imp_by_pattern`
- `readfrom-pattern` → `_find_readfrom_c_func_by_pattern`

A comment in their place records the removal. The companion
`disambiguation_comment` model field + emitter branches were already removed in
Task B (verified 0 references remain).

Also removed (2026-06-09, second pass) the dead **`protoscore`** dup row — it
named the same function as `protoclass` (`_is_proto_class`) and was double-counted;
its `main()` skip guard went with it. Registry now imports and runs (**41 rows**).

See also: `COMPARE_CHAIN_FIELDNUM_BUG.md`, `ENUM_NAME_FROM_PREFIX.md`,
`heuristics_audit.md`, memory note `heuristic-registry-relabels`.

---

## Second relabel pass — REPLACE bucket + monolith-split paths (2026-06-11)

The 2026-06-09 pass above audited only the INTRINSIC/PRESENTATION buckets ("nothing
remains to promote" was scoped to *those*). The 2026-06-11 pass re-examined the
**REPLACE** bucket against current code (after the writeTo CFG-walk swap and the
`proto.extractor` monolith split) and found three rows whose principled
replacement had already landed but were never relabeled. Verified by reading each
function body, not from memory.

### REPLACE → PRINCIPLED (principled replacement landed)

| id | function (file) | rationale |
|---|---|---|
| `jt-width` | `_decode_readfrom_jumptable` (`proto/dispatch.py`) | the 2/1-byte brute-validate width fallback was **removed** 2026-06-08 (census: 0 fires / 1350 cluster calls; weak guard could admit a wrong adrp target). Table base + entry width now come from the cluster-pinned register's real `adrp+add` + decoded `_decode_ldr_reg_off` width; unpinnable → `None`. Structural decode, same family as the already-PRINCIPLED `dispatch-cluster`/`walk-arm`. Display name updated (no more "brute-validate fallback"). |
| `enumval-regscan` | `_extract_enum_values` (`proto/enums.py`) | the register scan only *locates* the `xAsString:` pointer-table base register (real `adrp+add`/`ldr`); the `(value,name)` pairs are read directly from that table in memory. Budget truncation fails loud via the `truncated` return flag, not a silent wrong value. |
| `dictrep-reg` | `_scan_dictrep_isolated_cmps` (`proto/enums.py`) | recovers sparse enum `(value,name)` from the real `cmp wV,#K` immediates + the cfstring at each branch target; the value-register identity gate is a soundness check (only comparisons on the field's value register count), not a guess. |

Result: REPLACE 21 → 18, PRINCIPLED 11 → 14 (42 rows total).

### File-path refresh (monolith split, no judgment change)

The 2026-06-10 split carved most `proto.extractor` heuristics into focused units.
The registry still pointed every such row at `E = proto/extractor.py`; corrected to
the real defining file so the per-FUNCTION frequency join resolves again:
`proto/repeated.py` (`REP`), `proto/writeto.py` (`WT`), `proto/enums.py` (`EN`),
`proto/dispatch.py` (`DSP`), `proto/protocore.py` (`PC`). Only `_confirm_field_numbers`
still lives in `proto/extractor.py`. Every row's function was verified present in its
claimed file. Also refreshed the stale `writeto-fieldnums` display ("ivar-offset
forward-track" → "CFG-walk binding") — the forward-scan decoder it described was
deleted in writeTo Phase B8.

NOTE: the `/tmp/heur_calls_*.json` frequency snapshots are from Jun 8 (pre-split) and
are now stale — re-run `heuristic_freq.py` over the three artifacts to repopulate the
counts under the corrected paths. The registry file refs (definition sites) are the
source of truth; the counts are a convenience overlay.

### Still REPLACE (genuinely heuristic, principled signal not yet landed)

The 18 remaining REPLACE rows are the real wishlist. The repeated-element name
matchers (`namesuffix-s2`, `resolve-namesuffix`, `pool-suffix`) are exactly what
**TODO #39** (readFrom C-function disasm) replaces; the rest are low-level Mach-O/
ObjC decode heuristics (`adrp-add`, `tagstrip`, `decodeptr`, `latin1`, …) and emitter
merge/naming policies (`enum-severity`, `best-enum`, `enum-split`) with no obviously
stronger structural source today.
