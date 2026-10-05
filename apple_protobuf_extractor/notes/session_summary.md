# Session Summary — Cache-Native Selector Resolution Investigation

> ## ★★★ TAIL-CALL writeTo: FIX + locationd BINARY-ONLY TESTS (2026-06-08 cont.) — 1037 tests pass
>
> **A standalone `locationd` binary (arm64 MH_EXECUTE, in project root, UUID
> `3DE54D44-C608-319E-9B01-0CA5A1ABD4A4`) was added for pure binary-only (path-ii) testing.**
> Binary-only extraction (no cache) works: 65 messages, **0 unresolved refs**, names resolved from the
> binary's own `__objc_methname`. Validating against Hopper surfaced + fixed a real bug.
>
> ### Tail-call writeTo: field-number bug (FIXED)
> The LAST field of many messages is serialised as a **tail-call `b _PBDataWriterWrite…Field`** (not
> `bl`), with the function epilogue (`ldp`/`stp` restores, some rendered `unk` by the mini-decoder)
> hoisted between `mov w2,#N` and the branch. `_extract_writeto_field_numbers` only matched `bl` with
> `mov w2` *immediately* before it, so these fields were missed → mis-numbered by the next_unconfirmed
> filler. Hopper-verified on locationd: `ALSCellTower.psc` (real 12, got 6) and `ALSLocation.infoMask`
> (real 13, got 8). **Fix** (`proto/extractor.py`): new `_writeto_field_number_before(insns, idx)` —
> matches both `bl` and tail-call `b`, looking back past epilogue insns (`ldp`/`stp`/`unk`, bounded 6)
> for the `mov w2/w1,#N`. The skip path only engages when the insn before the call is an epilogue insn,
> so the common `bl` case is unchanged. **Impact:** locationd confirmed field numbers **396→440
> (89%→99%)**, psc/infoMask now correct; GeoServices cache-native **7428→7431** (+3, no regressions —
> reference validation byte-identical, GEOPDComponentValue still 62/88). Monotonic-positive on both paths.
>
> ### Binary-only (path-ii) test coverage — was DORMANT, now live
> Prior gap (analysed this session): ALL 154 skipped tests are GeoServices binary-only live tests that
> need a standalone binary absent from the env — so path (ii) had only synthetic coverage. `locationd`
> fixes this. New `tests/test_live_locationd.py` (9 tests, RUN): pure binary-only `build_class_list`
> (cache=None) + `extract_all`, asserting Hopper-verified field numbers for ALSLocation/ALSCellTower
> (incl. the tail-call anchors infoMask=13, psc=12 must be `number_confirmed`), submessage cross-ref,
> ≥95% confirmed ratio, 0 unresolved refs, UUID-pinned build identity. Plus synthetic
> `TestWriteToFieldNumberBefore` (5 tests, no binary needed) locking `_writeto_field_number_before`.
> Registered in `run_tests.py`.
>
> ### ⚠ NEW FINDING (not yet fixed) — binary-only enum VALUES not recovered
> locationd: all **44 enums are detected but placeholder-only** ("values not recovered from binary"),
> even though `StringAsGender:`-style selectors exist in `__objc_methname`. In cache mode (GeoServices)
> enum values recover fine (685 enums). So binary-only enum-*value* recovery has a gap — likely the
> `xAsString:`/`StringAsX:` IMP→value-table path needs adjusting for this binary's encoding. Separate
> follow-on; the test asserts enum *detection* only.

> ## ★ CACHE-AWARE AMBIGUOUS-ENUM COMMENTS (2026-06-08 cont.) — 1023 tests pass
>
> The ambiguous-enum messages used to unconditionally say "Run with --cache" / "run with --cache to
> resolve" even in cache-native (`--framework`) mode, where a cache is already in use — a no-op
> suggestion. Now cache-aware: `cli.py` calls `configure_cache_active(cache is not None)` on both
> `proto/extractor.py` and `proto/emitter.py` (module-global flag, default False, matching the existing
> `configure_prefixes`/`configure_prefix_packages` pattern). When a cache IS active the wording becomes
> "could not be resolved even with --cache" (per-field) / "unresolvable even with --cache" (header note);
> with no cache the actionable "Run with --cache" suggestion is kept. Both still mention `--cache` (so the
> existing no-cache assertions hold), but no longer suggest a re-run the user already did. (GeoServices
> cache-native currently has 0 ambiguous enums after the metaclass/.symbols work, so neither note appears
> in practice — this is the correct wording for when it does.) Tests: +1 in `test_extract_enum_for_field.py`
> (`test_cache_active_comment_does_not_suggest_rerun`), +2 in `proto/test_emitter.py` (header-note wording).

> ## ★★★★ WRITETO CAP FIX — wide-message field numbers (2026-06-08 cont.) — 1020 tests pass
>
> **Root-caused & fixed a latent bug that silently corrupted field numbers for every message
> wider than ~50 fields.** Found while validating `GEOPDComponentValue` against the reference
> (the "#3" discrepancy: missing tags 89–96, spurious fields in the type gaps 17/18/19/21/28/35,
> and `#42` mis-typed as `TransitPaymentMethodInfo`).
>
> ### Root cause (3-link chain, all verified)
> 1. **Oneofs don't use the pointer-table readFrom path.** `GEOPDComponentValue`'s readFrom
>    (`_GEOPDComponentValueReadAllFrom` @`0x18cc66380`) uses a jump-table dispatch, not the
>    ivar-offset pointer table `_try_pointer_table` expects (`_find_field_count` returns a spurious
>    `9`). → field numbers fall back to `writeTo:` analysis.
> 2. **`writeTo:` analysis was truncated by a fixed `_WRITETO_MAX_INSNS = 600`.** A wide message's
>    highest-tag fields are serialised in out-of-line blocks placed AFTER the epilogue
>    (`stop_at_ret=False` already handles the epilogue, but the 600-insn cap stops first).
>    `-[GEOPDComponentValue writeTo:]` is ~1872 insns (Hopper-confirmed), so tags 89–96 were never
>    reached → 7 ivars left unconfirmed.
> 3. **The `next_unconfirmed` fallback (extractor.py ~3422) assigns the lowest free number,** not the
>    true tag. The 7 unconfirmed ivars grabbed slots 17,18,19,21,28,35,42 — landing in real gaps and
>    displacing tags 89–96. This one mechanism produced ALL three symptoms (incl. `#42`).
>
> ### Fix (`proto/extractor.py`)
> Field-count-aware cap: `_writeto_insn_budget(n) = max(_WRITETO_MAX_INSNS, n * _WRITETO_INSNS_PER_FIELD)`
> with `_WRITETO_INSNS_PER_FIELD = 20` (observed ~11 insns/field; 20 = margin; floor stays 600 for the
> common small case). Used at the `writeTo:` disasm in `_extract_writeto_field_numbers`. Did NOT touch
> the `next_unconfirmed` fallback — the lowest-free heuristic is correct for the common *dense* case,
> and the cap fix fully confirms the wide messages so the fallback no longer fires for them.
>
> ### Impact & verification
> **462 field-number corrections across 12 wide messages** (AnalyticsPipelineStateData 138, ActiveTileGroup
> 67, Route 63, Resources 57, MapServiceTraits 47, …), **0 type changes, 0 fields added/dropped** — pure
> renumbering from dense filler → real sparse protobuf tags. After the fix these messages are ~100%
> writeTo-confirmed (Route 63/63, MapServiceTraits 95/95, ComponentValue 81/81, AnalyticsPipeline 138/139;
> the few residual filler fields are ivars writeTo: doesn't serialise). **Ground-truthed against Hopper:**
> `-[GEOActiveTileGroup writeTo:]` (1872 lines) contains real `mov w2,#N` immediates for tags 1, 72(0x48),
> 97(0x61) — 68 distinct tags up to 0x62 — matching the tool's new numbers. `GEOPDComponentValue` now
> matches the reference on tags 89–96 and emits zero spurious gap fields; the 7 ref fields it still lacks
> (42,44-47,49,90 = offline*/searchEnrichment) have **no backing ivar in this build** (schema-presence,
> not a numbering bug). Tests: `TestWriteToInsnBudget` (3 unit) + live `test_wide_oneof_field_numbers_not_truncated`.
>
> ### Reference validation (full pass, 2026-06-08)
> Tool vs hand-decoded `GEOPDPlaceResponse.proto`: **all 5 enums 100%** (PlaceResponseStatus 9/9,
> MapsResultType 6/6, GEOComponentType 89/89, ComponentStatus 9/9, CacheControlType 3/3 — only enum
> *names* differ by convention). All binary-CONFIRMED reference fields match. Tool **beats** the reference
> in many places (recovers real classes where the ref used `GEOPDGlobalResult_Unknown` placeholders / `*Value`
> guesses the ref's own comments confirm). Harness kept at `validate_ref.py`.

> ## ★★★ METACLASS TYPE-METHOD GRAFTING DONE & VERIFIED (2026-06-08 cont.) — 1016 tests pass
>
> **The Gap-1 follow-on is resolved for the BROAD case** (repeated-field element types),
> though NOT for the two specific motivating fields (`GEOPDComponent.values` /
> `.commingledAttributions`) — see "⚠ still bytes" below. The prior session's proposed fix path
> ("populate metaclass methods, then the existing disasm pool resolves it") was based on a
> **false premise** and is now corrected.
>
> ### Root cause (re-diagnosed with binary ground truth, this session)
> Two distinct facts, both verified against the cache + Hopper:
> 1. **Some** metaclasses have a NULL `baseMethods` pointer in the cache (`ro+32 == 0`) so they
>    arrive with **0 methods** — e.g. `GEOPDComponent`'s metaclass (`methods_va=0x0`). These
>    classes ALSO have **no `+[Cls …]` symbols at all** in `.symbols` (Hopper confirms
>    `+[GEOPDComponent …]` = ∅), so their element-type methods are genuinely unrecoverable.
> 2. **Most** metaclasses DO have binary-parsed methods (e.g. `GEOBusiness` meta = 11), but the
>    preoptimised relative method list strips the **selector NAMES** (same stripping as instance
>    methods) → the `+xyzType` methods existed but were unnamed/garbage, so Strategy-1
>    name-matching (`m.name == "xyzType"`) silently failed. `.symbols` has 2781 `+[…]` class-method
>    symbols incl. the `…Type` element-type methods — but the old `.symbols` recovery **skipped all
>    metaclasses** and its regex only matched `-[…]`.
>
> ### The fix (implemented + tested)
> - **`macho/local_symbols.py`**: `_METHOD_RE` now matches both `-[…]` and `+[…]` (group(1) = kind).
>   `ImageLocalSymbols` gained `meta_imp_to_sel` + `meta_to_sels` (kept SEPARATE from the instance
>   maps because a metaclass shares its instance class's name — conflating them would graft `-`
>   selectors onto the meta). `apply_to_classes` now handles metaclasses symmetrically: rename
>   binary meta methods by IMP via `meta_imp_to_sel`, graft missing `+` methods from `meta_to_sels`.
>   Returns a new `meta_added` count. Instance selectors are still never grafted onto metaclasses.
> - **`cli.py`**: prints the `meta_added` count.
> - **`proto/extractor.py`** `_resolve_repeated_field_type`: **regression fix** — the pool-suffix
>   refinement must NOT override a resolved value of `"string"`. Strategy-1 `"string"` comes from an
>   IMP-confirmed `+xyzType` returning NSString and is authoritative; the old code let a name-suffix
>   pool entry promote it to a message type (`GEOBusiness._categorys`: `categoryType`→NSString was
>   wrongly turned into `GEOCategory`). Guard: `if resolved != "string" and meta_type_pool and cap:`.
>
> ### Measured impact (full GeoServices, cache-native; baseline = old skip-meta behaviour)
> | metric          | before | after | Δ |
> |-----------------|--------|-------|---|
> | repeated bytes  | 487    | 298   | **−189** |
> | repeated message| 424    | 596   | **+172** |
> | fields changed  | —      | —     | **208** (207 `bytes→msg` + 1 legit override) |
>
> The single non-`bytes` override is correct & IMP-confirmed: `ActiveTileGroup.regionalResources`
> `GEORegionalResource`→`GEORegionalResourceSet` (name-suffix heuristic → real `+regionalResourceType`
> return). **0 regressions** after the string guard. Cross-validated vs the hand-decoded
> `GEOPDPlaceResponse.proto`: `legacyPlaceResults`→GEOPDPlace, `mapsResults`→GEOPDMapsResult,
> `dotPlaces`→GEOPDDotPlace all match exactly. `GEOBusiness` witnesses the precision: `_categorys`
> →`string` (its `categoryType`→NSString) while adjacent `_localizedCategories`→`GEOCategory` (its
> `localizedCategoriesType`→GEOCategory) — two different element types from two `+xyzType` methods.
>
> ### Tests (+4 net, all 1016 pass)
> `tests/test_local_symbols.py`: rewrote `test_metaclass_is_skipped` → `…_gets_no_instance_selectors`
> + new `…_gets_class_methods_grafted`; updated `…_untouched` for the `meta_added` key; new live
> `test_class_methods_captured_in_meta_to_sels` + `test_metaclass_type_methods_grafted_and_resolved`.
> `tests/test_refactored_helpers.py`: new `test_resolved_string_not_overridden_by_pool_suffix`.
>
> ### ⚠ `GEOPDComponent.values` / `.commingledAttributions` STILL `bytes` — needs a NEW resolver
> These two have **no `+xyzType` method anywhere** (NULL meta baseMethods + no `+[GEOPDComponent …]`
> symbols), so the type-method route cannot resolve them — the prior "follow-on" hypothesis is dead.
> The element class IS recoverable via a **different, sizeable mechanism** (not yet built): the C
> `_GEOPDComponentReadSpecified` (@`0x18c278410`) dispatches per field tag through a jump table
> (`adr`+`ldrh`+`br` @`0x18c278564`, table @`0x18d85bc44`); field 8 (`values`)'s case block
> (`sub_18c2788e4`) calls **`_GEOPDComponentValueReadAllFrom`** (@`0x18cc66380`) — the callee symbol
> name encodes the element class (`GEOPDComponentValue`). A readFrom-jump-table resolver
> (parse table → per-field `bl _<Class>ReadAllFrom` → derive class from callee symbol) would resolve
> these and any other repeated message field lacking a `+xyzType`. Same complexity class as Gap 2.

> ## ★★ GAP 1 + GAP 2 BOTH DONE & VERIFIED (2026-06-08 cont.) — 1012 tests pass
>
> Both planned extractor extensions are implemented, verified against the binary, and tested.
> Quick status (full GeoServices, cache-native, `--single-file`):
> messages **1437 → 1637**, total fields **7794 → 8009**, unresolved refs **176 → 5**,
> enums **537 → 685**. **1012 tests pass, 0 fail** (was 996).
>
> **Validated against the hand-decoded reference `GEOPDPlaceResponse.proto`** (2026-06-08): tool
> matches the reference on **everything** checked — `PDPlaceResponse` 13/13 field numbers+types,
> `GEOComponentType` 89/89, `MapsResultType` 6/6, `PlaceResponseStatus` 9/9, `ComponentStatus` 9/9
> — except `CacheControlType` value *names*, where the tool reads the literal binary cfstrings
> (`UNKNOWN_CACHEABILITY/UNCACHEABLE/CACHEABLE`) and the reference used semantic guesses
> (`UNKNOWN/NETWORK_LOAD/LOCAL_CACHE`); values 0/1/2 agree, **tool is the ground truth**. The tool
> also beats the reference on `requestType` (resolved as a 59-value enum; reference had `uint32`).
> The validation surfaced one gap — `ComponentStatus` was 3/9 — now **fixed** (hybrid-switch
> support, below).
>
> - **Gap 1 (oneof/wrapper proto detection)** — relaxed `_is_proto_class` gate (drop mandatory
>   `mergeFrom:`). +200 proto classes (incl. `GEOPDComponentValue` 96-field oneof), purely
>   additive, no regressions. Details in the "▶" block below.
> - **Gap 2 (`_dictionaryRepresentation:` enums)** — recover enums with no `xAsString:` selector
>   by disassembling the dictRep dispatch tables. **+148 enums** (537→685) via two forms:
>   **(a) jump-table** (`adr`+`br`) → +17 incl. `GEOComponentType` (89 values, `UNKNOWN=0`…
>   `POI_CLAIM=96`, 8 gaps excluded) and status enums; **(b) pointer-table**
>   (`ldr xR,[table,value,lsl#3]` of direct CFStringRef pointers) → +131 incl. `CacheControlType`
>   and many `*Type`/`*Subtype` enums (e.g. `AutocompleteResultSubtype` 30 vals). **0 enums
>   removed, 0 false positives** (135 new, all clean UPPER_SNAKE; the 1 "changed" is a benign
>   name-collision re-resolution — the emitter qualifies the loser, no data lost). New code in
>   `proto/extractor.py` (`_harvest_dictrep_enums` + helpers, Phase 1.5 in
>   `_collect_enum_definitions`); new `tests/test_dictrep_enums.py` (9 synthetic + 5 live);
>   updated `tests/test_live_enums.py` (`TestPDComponentEnumRevert` → `TestPDComponentDictRepEnums`,
>   old "reverts to int32" assertions are now "recovered as enum"). Full writeup in the
>   "✅ Gap 2 DONE" block below.
>
> Remaining (lower priority): `GEOPDComponent.values` → `repeated bytes` (metaclass-method
> follow-on — `_find_metaclass` returns a 0-method metaclass cache-native, so the `+xyzType`
> element-type pool is empty).

> ## ★ RESOLVED (2026-06-08 session) — ROOT CAUSE FIXED, SHIPPED, TESTED
>
> **Status: implemented and verified.** Result on GeoServices (cache-native):
> ambiguous enums **253 → 0**, enums detected **275 → 537**, unresolved type refs
> **352 → 176**, confirmed fields preserved (**6866 → 6893**, no loss), 36 empty
> messages (legitimately field-less classes, newly detected). **996 tests pass, 0 fail.**
> The previously-ambiguous `int32 + "Run with --cache"` fields now emit proper enum types
> (e.g. `GEORRRequestResponseEvent.eventType` → `RRRequestResponseEventType`).
>
> ### What was implemented
> - **`macho/local_symbols.py`** (new) — parses the `.symbols` local-symbol table scoped to
>   one image via its per-image entry (mmap'd; the ~450 MB string table is paged lazily).
>   Returns `imp_to_sel` and `class_to_sels`. `apply_to_classes()` renames methods by IMP and
>   adds symbol selectors missing from the optimised list (skips metaclasses).
> - **`macho/dyld_cache.py`** — added `cache_base` property and
>   `image_local_symbols(mach_header_va)` accessor.
> - **`cli.py`** — after `build_class_list`, in cache-native mode, calls
>   `image_local_symbols` + `apply_to_classes` (prints "N resolved, M corrected, K added").
> - **`proto/extractor.py`** — `_is_real_field_ivar` is now a **union** (getter/setter OR
>   type-encoding heuristic) so stripped-accessor and getter-name-mismatched real fields are
>   kept; added `_is_has_bits_name` to exclude the plain-integer has-bits ivar (`_hasBits`) by
>   name (the struct form was already caught by `_is_proto_flags_ivar`).
> - **`tests/test_local_symbols.py`** (new, + registered in `run_tests.py`) — 6 synthetic
>   `apply_to_classes` tests + 3 live IMP→selector tests.
>
> The full dyld cache (all 42 sub-caches **plus `.symbols` and `.a2s`**) is in `dylib/`.
> Point the tool at `dylib/dyld_shared_cache_arm64` (the main file, not the folder).
>
> ## ▶ NEXT SESSION — Gap 2 (Gap 1 DONE & VERIFIED 2026-06-08)
>
> A hand-decoded reference (`addon_ios/GEOPDPlaceResponse.proto`, Hopper + live revgeo capture)
> was compared against tool output. **Field numbers: ~100% match** (incl. the reference's
> hand-"corrected" values). **Enums: tool wins** — exact matches on `PlaceResponseStatus`,
> `MapsResultType`; tool independently confirmed `INVALID_REQUEST=5`; resolved `requestType` as a
> 59-value enum (reference had it as `uint32`) and confirmed the reference's commented-out
> `ReferenceFrameType` guess. Tool also confirmed two reference **hallucinations** are not real
> classes (`GEOPDComponentSource`, `GEOPDStructuredAddress`).
>
> ### ✅ Gap 1 — DONE & VERIFIED (2026-06-08): oneof/wrapper proto detection
> Relaxed the method-name fallback gate in `_is_proto_class`: `_REQUIRED_INSTANCE_METHODS` is now
> `{readFrom:, writeTo:}` (was `{readFrom:, writeTo:, mergeFrom:}`); `mergeFrom:` stays a scored
> bonus. oneof classes (`GEOPDComponentValue`) and thin wrappers (`GEOPDAddressObject`) lack
> `mergeFrom:` (nothing to merge) and were silently dropped; now detected. Added test
> `test_oneof_without_mergefrom_detected`. **997 tests pass** (+1). Change is in `proto/extractor.py`
> (the `_REQUIRED_INSTANCE_METHODS` frozenset + two docstrings).
>
> **Measured impact** (full GeoServices, `--single-file`, cache-native), baseline = pre-Gap-1:
> | metric | baseline | Gap 1 |
> |--------|----------|-------|
> | messages | 1437 | 1637 (+200) |
> | total fields | 7794 | 8009 (+215) |
> | empty (0 fields) | 36 | 119 (+83) |
> | unresolved refs | 176 | **5** (−171) |
> | enums | 537 | 537 (same) |
>
> **No regressions**: 0 baseline messages lost fields / became empty / were removed (purely
> additive). The +83 empties are all **legitimate field-less proto classes** — 73 have only the
> excluded `_unknownFields` bookkeeping ivar, 10 have no ivars at all (verified across all 200
> newly-detected classes: 0 had a real field ivar wrongly excluded). Apple emits a proto class per
> message type incl. degenerate leaf filters (e.g. `GEOPDAboutFilter`), so emitting them empty is
> correct and is what collapsed unresolved refs 176→5. `ComponentValue` now extracts as the full
> 96-field oneof; field numbers match the reference's `[CONFIRMED binary]` values exactly (entity=1,
> transitIncident=20, addressObject=31, tip=36, rap=41, venueInfo=48, …) and additionally fill the
> reference's "no named component type" gaps (17,18,19,21,28,35).
>
> ### ⚠ Gap 1 follow-on NOT fixed — `GEOPDComponent.values` still `repeated bytes`
> Detection was necessary but **not sufficient** for the motivating example. `_values`
> (`@"NSMutableArray"`) element type stays `bytes` because (a) suffix `Value` is ambiguous — **13**
> `*Value` classes — so name-suffix Strategy 2 declines; (b) the authoritative resolver is the
> metaclass `+[GEOPDComponent …Type]` type-method pool, but **`_find_metaclass` returns a metaclass
> with 0 methods in cache-native mode** — class (meta) method lists are not populated and `.symbols`
> recovery skips metaclasses (`apply_to_classes` skips `is_meta`). So `_build_meta_type_pool` is empty
> and `_class_from_type_method_imp` (disasms the `adrp/ldr x0/b` type-method to read
> `[GEOPDComponentValue class]`) never runs. **Fix path (separate, medium effort):** populate
> metaclass methods in cache-native classlist parsing (and/or extend `.symbols` recovery to
> metaclasses), then the existing disasm pool resolves `values`, `commingledAttributions`→
> `GEOPDAttribution`, and other ambiguous-suffix repeated fields. Same disasm family as Gap 2.
>
 > ### ✅ Gap 2 — DONE & VERIFIED (2026-06-08): dictRep enum recovery (jump + pointer tables)
> Recovers enums for scalar-int fields with no `xAsString:`/`StringAsX:` companion selector, whose
> int→name map lives in `-[Class _dictionaryRepresentation:]`. **Two dispatch forms** are handled:
> a **jump table** (`adr`+`br` to per-value code blocks) and a **pointer table**
> (`ldr xR,[table,value,lsl#3]` reading direct CFStringRef pointers — `_read_dictrep_pointer_pairs`,
> simpler: every in-range value is named, no gaps/merge to reconcile). **+148 enums** on full
> GeoServices (537→685: jump +17, pointer +131), **0 removed, 0 false positives** (135 new all
> clean; the 1 "changed" enum is benign collision re-resolution by the emitter).
> `GEOComponentType` recovered as 89 values (`UNKNOWN=0`…`POI_CLAIM=96`); the 8 in-range gaps
> (17,18,19,21,28,35,75,80) correctly route to UNKNOWN and are excluded; cross-checked exactly
> against the confirmed `GEOPDComponentValue` field numbers (field# == ComponentType value:
> ENTITY=1, TRANSIT_INCIDENT=20, ADDRESS_OBJECT=31, TIP=36, RAP=41, VENUE_INFO=48). Also 13
> status-code enums + 3 PlaceTypeHint/Limit enums.
>
> **Implementation** (`proto/extractor.py`):
> - `_harvest_dictrep_enums(ctx, cls, st) → {ivar_offset: [(value,name)…]}` — disassembles the
>   dictRep IMP (via `.symbols`/`get_method`), finds each jump-table dispatch (`adr`+`br`), reads
>   the CMP gate for the range, associates the switch to its field via the **last `adrp+ldrsw`
>   ivar-offset load** before the dispatch (`_last_ivar_offset_in_window`), and walks the table.
> - `_decode_ldr_reg_off(word)` — decodes the register-offset table load (`ldrh`/`ldrb`) to get the
>   true **entry width** (the native mini-decoder renders these as `unk`; capstone is absent).
>   Critical: scoring entry-size by hit-count is fooled (a byte-misread of a 16-bit table yields
>   *more* but wrong pairs) — must decode the instruction.
> - `_read_dictrep_switch_pairs(...)` — `case_target = case_base + table[v]*4`. Two no-value
>   targets are excluded: the modal entry (the explicit UNKNOWN block shared by gaps) and the
>   **merge block** (value 0 routes there with UNKNOWN pre-loaded; the merge loads the dict KEY, so
>   reading a string there yields the field name). Merge addr = the `b` target of any real case.
> - `_block_adrp_add_target_in` scans **instruction order** (earliest pair wins) — a fall-through
>   last case (e.g. POI_CLAIM at value 96) loads its value into `x22` then runs into the merge's
>   key in `x3`; a register-numeric scan would wrongly return `x3` (the key).
> - Wired as **Phase 1.5** in `_collect_enum_definitions`: tags untyped int fields with the
>   class-qualified enum name and stashes pairs; Phase 2 picks them up via `dictrep_pairs[fld.name]`
>   so naming/normalisation is identical to the `xAsString:` path. Gated on the class having an
>   untyped int field (skips the large dictRep disasm otherwise; full run +0.9s only).
> - Tests: `tests/test_dictrep_enums.py` (8 synthetic decoder + 4 live), registered in `run_tests.py`.
>
> **Hybrid switch (isolated cmp+b.eq/b.ne) — added 2026-06-08 from reference validation.** Some
> status enums are a *jump table for the dense low range* PLUS *isolated `cmp wV,#K; b.eq/b.ne`*
> comparisons for sparse high values (`ComponentStatus`: table 0/1/2/5, then cmp #0x14/#0x1e/#0x28/
> #0x32/#0x3c → 20/30/40/50/60). `_scan_dictrep_isolated_cmps` scans the field's value register (the
> jump-table index reg) between the dispatch and the merge; b.eq → string at target, b.ne → string
> at fall-through, target block must carry its own cfstring (so b.gt/b.hi range-split guards are
> ignored). Also fixed value 0: the default now uses the *dominant* first-segment prefix (not strict
> LCP) so an odd name like `INVALID_REQUEST` no longer blocks `STATUS_SUCCESS=0`. Result: **13 status
> enums completed 4→9 values**, 0 new/removed enums, 0 false positives; `ComponentStatus` 9/9 vs ref.
>
> Verified addresses (Hopper): `GEOComponentType` jump-table dispatch in `-[GEOPDComponent
> _dictionaryRepresentation:]` @ `0x18c200bd0`, table @ `0x18d85bb7c` (97×u16), case base
> `0x18c200be4`, default block `0x18c200ca4`, merge `0x18c201024`. `CacheControlType` pointer-table
> dispatch @ `0x18c20149c` (`ldr x22,[x9,x8,lsl#3]`), table @ `0x1d5f91690` (3×u64 → CFStringRef*:
> `UNKNOWN_CACHEABILITY=0, UNCACHEABLE=1, CACHEABLE=2`).
>
> Other observed (lower priority): repeated `NSMutableArray` fields whose element class IS proto
> can still fall to `repeated bytes` when element-type inference fails (e.g.
> `GEOPDComponent.commingledAttributions` → `GEOPDAttribution`). Element type isn't in the ivar
> encoding for arrays; inference (writeTo: / name-singularising) has gaps.
>
> --- original diagnosis (now implemented) follows ---
>
> ### Root cause (definitive, measured)
> For cache-native GeoServices, the method-list `nameOffset` field is **100% unusable**.
> `ro_t.baseMethods` (ro+32) points to **`__TEXT/__objc_methlist`** — NOT `__DATA_CONST/__objc_const`
> as the old notes assumed. In that list the three int32 fields decode as standard
> `[nameOffset, typesOffset, impOffset]` (NO swap):
>   - `f1` typesOffset → always valid (`__TEXT/__objc_methtype`) ✓
>   - `f2` impOffset   → always valid (`__TEXT/__text`) ✓
>   - `f0` nameOffset  → **garbage** (lands in `__gcc_except_tab`/`__const`/`__cstring`/unmapped)
>
> Of 60,562 parsed methods: **47,139 got null names + 13,423 got WRONG names = ALL of them.**
> Every "resolved" name was a false positive (e.g. `readFrom:` was being read as `'COMBO'`,
> `.cxx_destruct` as `'ionXPCInterface'`, `description` as `'x'`). The selector strings are
> simply not recoverable from this stripped methlist. The swapped-field fallback in
> `classlist.py` is a dead end (f1 is genuinely the types field).
>
> ### The fix channel: the `.symbols` local-symbol table
> `dyld_shared_cache_arm64.symbols` is the standard dyld **local-symbols subcache** and contains
> the real `-[Class selector]` symbols. The **IMP (f2) is reliable**, so IMP→symbol is a
> 100%-accurate name source. Verified: all 12 methods of `GEOCoarseLocationTerritoryInfo`
> resolve exactly via IMP lookup.
>   - Header: `localSymbolsOffset` @ file offset `0x48` (u64) = `0x4000` here.
>   - At that offset: `dyld_cache_local_symbols_info` = 6×u32
>     `(nlistOffset, nlistCount, stringsOffset, stringsSize, entriesOffset, entriesCount)`.
>   - nlist_64 = `<IBBHQ>` (n_strx u32, n_type u8, n_sect u8, n_desc u16, n_value u64), 16 bytes.
>   - **Per-image entries** (entriesCount=2705) = `<QII>` `(dylibOffset u64, nlistStartIndex u32,
>     nlistCount u32)`. GeoServices = entry #19, `dylibOffset = mach_va − 0x180000000 = 0xc1a7000`,
>     start=492846 count=156733 → jump straight to its nlists (~0.1s; no 8.7M full scan).
>   - 70,045 GeoServices instance-method symbols; per-class map covers 2,611 classes.
>
> ### Measured impact (full extractor, single-file)
> | metric      | baseline | rename-only | rename+add-missing |
> |-------------|----------|-------------|--------------------|
> | ambiguous   | **253**  | **0**       | **0**              |
> | unresolved  | 352      | 11          | 98                 |
> | enums       | 275      | 537         | 537                |
> | fields      | 7662     | 5500        | 6341               |
> | empty msgs  | 0        | 477         | 228                |
>
> The `.symbols` map **eliminates the 253 ambiguous enums and nearly doubles detected enums.**
>
> ### The remaining subtlety (must handle in the fix)
> Many proto classes (e.g. `GEOAttributeKeyValue`, `GEODataSetURLOverride`, `GEOHours`) have
> **no accessor methods at all** — not even in `.symbols` (only `init`/`readFrom:`/`writeTo:`…
> boilerplate). Their fields are inline; only the **ivar type-encoding heuristic** finds them.
> `_is_real_field_ivar` (extractor.py:330) uses that heuristic ONLY when `method_names` is empty.
> Injecting symbol-derived boilerplate makes `method_names` non-empty → flips to strict
> getter/setter mode → with no getters, real fields get dropped (→ 190 classes lose all fields).
> **Remedy:** make `_is_real_field_ivar` a UNION — field is real if (getter/setter present) OR
> (passes type-encoding heuristic). Then accurate names only ADD fields, never remove them.
>
> ### Proposed implementation (ordered)
> 1. New parser: `DyldCacheReader` (or a new `macho/local_symbols.py`) reads the `.symbols`
>    file's local-symbols, scoped to one image via the per-image entry, returns
>    `{imp_va: selector}` and/or `{class_name: {selector: imp}}`.
> 2. After `build_class_list`: rename each method by IMP (fixes the 60,562 wrong/null names),
>    then ADD symbol selectors not already present (by imp) as name-only `ObjcMethod`s.
> 3. Make `_is_real_field_ivar` a union (heuristic OR name) so boilerplate-only classes keep
>    their heuristic fields.
> 4. Re-run; target ambiguous=0, unresolved≈baseline-or-better, fields ≥ baseline, empty≈0.
>    Then run the 921-test suite and reconcile any field-count test deltas.
>
> Probe script: `probe_dataconst.py` (dumps raw methlist field decoding for a class).
> Analysis scratch in `/tmp/full_impact2.py`, `/tmp/analyze_symbols.py`.
>
> --- everything below is the PRIOR (now partly superseded) session's notes ---

# Session Summary — Cache-Native Selector Resolution Investigation

## Goal
Diagnose why 253 proto class fields emit `int32` with "Run with --cache for correct type" even
in cache-native mode, tracing the failure through 4-layer cascade to its binary root cause.

---

## What Was Confirmed This Session

### Cache loading is healthy
All 42 sub-caches load correctly. The unified selector pool (`.01`,
`0x18005c000–0x186d74000`) is fully mapped. `decode_ptr` works correctly for
`has_direct=False` entries — zero failures of that type appear in 200 samples.

### `__objc_methname` is repurposed binary data
Hopper's full segment listing shows GeoServices `__TEXT/__objc_methname`
(`0x18d98e846–0x18da577c7`) contains binary data (ARM64 stubs/code), **not** null-terminated
selector strings. Selector strings live exclusively in the pool. `StringTable` scans of
`__objc_methname` will never find `readFrom:`, `writeTo:`, etc.

There is **no `__EXTRA_OBJC` section** in GeoServices. Previous session notes were wrong.

### GeoServices has a custom `__TEXT/__objc_methlist` section
Hopper shows a non-standard `__TEXT/__objc_methlist` at `0x18d649f18–0x18d705e5c` (64,155
× 12-byte entries, in the executable TEXT segment). This is separate from the
`__DATA_CONST/__objc_const` section where `baseMethods` method list headers point.

### All 200 cache-miss failures are `has_direct=True`, `sel_ref_va` in binary range
Every failure in the 200-sample debug output:
- `has_direct=True`, `in_cache=True`
- `sel_ref_va` lands in GeoServices' own TEXT sections (.03 or .05), **never** in the pool
- Bytes at `sel_ref_va` are ARM64 instructions, C-string fragments, ivar type encodings,
  or null bytes — **never a valid selector**
- Zero `has_direct=False` failures (that path works correctly)

### `probe_methlist.py` scanned the wrong section
The probe read `__TEXT/__objc_methlist` (not `__DATA_CONST/__objc_const`). It found:
- 20,289 entries where `field0 → __objc_methtype` with **short** ObjC type strings
  (`@32@0:8^i16Q24`, `v24@0:8^v16`, `@24@0:8r^v16`) — these are the **types** field, not
  the name field; the methlist has an inverted layout `[typesOffset, ???, impOffset]`.
- `field1 → 0x18c4f...` (3.4 MB into `__TEXT/__text`, code section); **zero** `field1 →
  pool` hits.

**Consequence:** the swapped-name/types hypothesis was rejected for `__TEXT/__objc_methlist`
entries. But `_parse_relative_method` reads from wherever `baseMethods` points
(`__DATA_CONST/__objc_const`, mapped in `.27.dylddata`), which the probe never scanned.
Whether the hypothesis holds for DATA_CONST entries is still unknown.

---

## What Is Still Unknown

The **definitive question** unanswered: for a proto class method entry in
`__DATA_CONST/__objc_const`, what do `field0`, `field1`, and `field2` actually decode to?

Specifically:
- Is `field0` (nameOffset) genuinely pointing to an ivar type encoding string in methtype
  (as `sel_ref_va` evidence suggests)?
- Does `field1` (typesOffset, at `va+4`) decode to a valid pool selector address — i.e.,
  is the name/types swap present in DATA_CONST entries even though it isn't in methlist
  entries?
- What section is `entry_va` actually in? DATA_CONST or methlist or somewhere else?

---

## What Was Changed in This Session

### `macho/classlist.py` — two changes

**1. Swapped-field fallback (last-resort, harmless):**
After all standard paths fail for a `has_direct=True` entry, also tries
`(va + 4) + read_s32(va + 4)` as an alternative selector address. This handles the
hypothetical case where `field0 = typesOffset` and `field1 = nameOffset` in DATA_CONST
proto class entries. Currently a no-op in practice (field1 → code, fails
`_is_valid_selector`) but leaves no incorrect names.

**2. Richer cache-miss sampling:**
The cache miss sample dict now captures:
- `entry_va`: the address of the method entry itself
- `entry_raw`: raw 12 bytes at entry_va (the three int32 fields directly)
- `alt_sel_va`: `(va+4) + read_s32(va+4)` (field1 decoded as a selector address)
- `alt_sel_in_cache`, `cache_read_alt_sel`: whether field1 resolves to a pool selector

### `cli.py` — `_print_cache_miss_samples` rewritten
Now prints per-entry:
```
entry_va=0x1d60xxxxx  raw=[aa bb cc dd  ee ff 00 11  22 33 44 55]
  field0→0x...  field1→0x...  field2(IMP)→0x...
  field0 file: dyld_shared_cache_arm64.NN+0x...
  field1 file: dyld_shared_cache_arm64.NN+0x...  read=<string or None>
has_direct=True  sel_ref_va=0x...  in_cache=True  read=<string>
alt_sel_va=0x...  in_cache=True  read=<string or None>
```

This output directly answers: what section is `entry_va` in, and does `field1` give a pool
selector.

### `probe_methlist.py` (project root)
Standalone diagnostic script. Now correctly identified as scanning `__TEXT/__objc_methlist`
(not the DATA_CONST section where actual proto class entries live). The script is still
useful for understanding the methlist format but needs a v2 to scan `.27.dylddata`.

---

## Immediate Next Step

Re-run `--cache-debug` against GeoServices with the new zip and look at the new output format.
Focus on entries where `sel_ref_va` is in `__objc_methtype` (ivar struct content) — these are
the proto class method entries. The output will show:

1. **`entry_va` file location** — confirms whether entries are in `.27.dylddata` (DATA_CONST)
   or `.03` (methlist or text).
2. **`field1 file: ...  read=...`** — the critical new field. If `read='readFrom:'` (or
   `writeTo:`, `mergeFrom:`), the swapped-field fix already in the code is correct and will
   resolve the 253 ambiguous enum fields. If `read=None` or a non-selector, a different
   approach is needed (likely scanning `__objc_selrefs` to build an IMP→selector map).

---

## Key Constants for Reference

```python
# GeoServices in cache (Hopper-verified)
GEO_TEXT_START      = 0x18c1a7000
GEO_TEXT_END        = 0x18db30000
METHLIST_VA         = 0x18d649f18   # __TEXT/__objc_methlist (custom, 64155 entries)
METHLIST_END        = 0x18d705e5c
METHNAME_VA         = 0x18d98e846   # __TEXT/__objc_methname (REPURPOSED, not selector strings)
METHNAME_END        = 0x18da577c7
METHTYPE_VA         = 0x18da577c7   # __TEXT/__objc_methtype (type encodings incl. ivar structs)
METHTYPE_END        = 0x18dabdbae
OBJC_CONST_VA       = 0x1d603bd90   # __DATA_CONST/__objc_const (method list headers + entries)
OBJC_CONST_END      = 0x1d6187b50
OBJC_SELREFS_VA     = 0x1d6187b50   # __DATA_CONST/__objc_selrefs
OBJC_SELREFS_END    = 0x1d61b7618

# Sub-cache file layout
SUBCACHE_03_VADDR   = 0x186d88000   # .03 contains GeoServices __TEXT
SUBCACHE_27_PATH    = '.27.dylddata' # contains __DATA_CONST (file_off=0x5c000 for main chunk)
SUBCACHE_27_MAP_VA  = 0x1d595c000   # mapping vmaddr for main .27.dylddata chunk
SUBCACHE_27_MAP_OFF = 0x5c000       # file offset for that mapping

# Selector pool
POOL_VA             = 0x18005c000   # .01 sub-cache
POOL_END            = 0x186d74000
readfrom_pool_va    = 0x18251984f   # 'readFrom:' in pool (confirmed by probe)
writeto_pool_va     = 0x1828da8cf   # 'writeTo:' in pool
mergefrom_pool_va   = 0x182e120cf   # 'mergeFrom:' in pool
```

---

## Test Status
(historical) 921 tests passing. **Current: 1012 passing, 0 failed, 154 skipped** after Gap 1
(oneof/wrapper proto detection) and Gap 2 (dictRep jump- + pointer-table enum recovery) on top of
the `.symbols` local-symbol name-recovery fix.
