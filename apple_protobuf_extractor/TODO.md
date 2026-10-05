# TODO — Mach-O / protobuf extractor

**Single canonical to-do list.** Merged from the old project list + the in-session
task list (reconciled 2026-06-13). These numbers are authoritative; the in-session
task tool is just a working mirror of this file. `heuristic_registry.py` and the
memory notes reference the project numbers (#42 readFrom resolver, #45 name-suffix
retirement, #57 enum type-name reconstruction) — those are preserved.

**Campaign goal:** replace heuristics with principled, portable signals; verify every
change (golden empty-diff or accepted-diff + full suite + `validate_ref` + Hopper
ground truth) before landing; surface uncertainty to the user rather than guess.

Standard gate for any change: `./venv/bin/python3 run_tests.py` (full suite),
`./venv/bin/python3 apple_protobuf_extractor/validate_ref.py` (GEOPDComponent 11/14,
GEOPDPlaceGlobalCommonResult 1/1), and the golden snapshots in
`apple_protobuf_extractor/tests/golden/` (`MACHO_UPDATE_GOLDEN=1` to accept an intentional
diff — review the git diff first).

> Renumber map (old session # → here): #43→#42, #45→#53, #48→#54. Session-DONE items
> that clashed with project DONE numbers are archived below as #55/#56.

---

## OPEN

### #42 — CFG/dominator readFrom dispatch resolver  — **DONE 2026-06-13 (commit 3cfb3ef)**
**Landed:** the compare-chain element attribution is now a CFG/dominator pass (`_dominance_field_of`
in `proto/dispatch.py`, engine in `proto/arm64cfg.py`), and the **`degenerate-partition` guard is
deleted** (unnecessary by construction). The first swap attempt regressed 135 fields (→bytes) because
the CFG was incomplete; the fix was a **general `br`-table decoder** (`_jump_table_arm_addrs`) that
injects every jump-table arm edge for CFG completion (the `adr+ldrb/ldrh+add lsl#2+br` idiom), plus
aligning field-reg detection to `lsr #3` only. **Output BYTE-IDENTICAL on all 3 artifacts** — dominance
exactly reproduces production with one fewer heuristic. Pre-swap differential vs the old resolver:
AGREE=400, DISAGREE=0. Full suite 1170/0/0/0; mitm 192; portability 0/0/0 ×10; validate_ref unchanged.
Engine unit-tested in `tests/test_arm64cfg_cfg.py`. **Full write-up: plan §8a–8h.**

**Scope landed = attribution + degenerate-partition only** (the validated part). NOT done / still
REPLACE: `core-picker` (`_core_resolves_compare_chain`) — core SELECTION, out of the PoC's validated
scope, separate follow-up; the name-suffix fallbacks (`namesuffix-s2`/`resolve-namesuffix`/`pool-suffix`/
`s1-selsynth`) — that's **#45**, but note #42 was BYTE-IDENTICAL so it did NOT shrink them (no recovery,
as predicted — #42's value was principled-ness, not new fields). `_compare_chain_blocks`/`_field_for_addr`
are KEPT (core-picker still uses them — not dead). So #45 is unblocked but its premise ("#42 resolves
more structurally") proved moot; re-scope #45 against the byte-identical reality before acting.

Original plan (for the record):
The readFrom field→handler routing is currently recovered by **linear instruction-pattern
matching + address-range attribution** (`_compare_chain_blocks` records any `cmp Wf,#N;
b.eq/ne`; `_field_for_addr` attributes element `bl`s by the address range `[entry,
next_entry)`) plus a **callee body-scan** core finder. Both over-fire, patched by the two
value-independent guards landed in #39: `_degenerate_block_partition` (a jump-table reader
carrying a stray `cmp Wf,#N; b.eq` builds a bogus 1-block partition that swallows every
element `bl` — e.g. GERPFeedbackFieldValue's `cmp w1,#1000`) and `_core_resolves_compare_chain`
(the body-scan accepted `-[GEOPDExternalAction addExternalActionDetail:]`, an *accessor*,
as a core). **Principled replacement — the readFrom analogue of the writeTo CFG-walk
(#30–33):** build the reader's basic-block CFG + dominators; define a dispatch core
structurally as *a function that extracts `Wf = tag>>3` and branches on it* (excludes
accessors by construction); recover the compare chain by **following the spine** (each
block tests a distinct constant vs the field register, fall-through → next test, eq/ne →
handler) and **stop when the fall-through is no longer a field compare** (excludes stray
sentinels); attribute each element `bl` to the field whose match-edge **dominates** it
(exact, vs the address-range approximation that already needed one patch in #17). Compose
with the existing in-memory jump-table decode (`_decode_readfrom_jumptable`, already
principled). Net win: would *resolve* the readers it currently *bails* on (e.g.
GERPFeedbackFieldValue's 21 fields) and never surface a look-alike core — both guards
delete. Likely shares the CFG/indegree machinery already in `proto/writeto.py`. Cost: a
reusable arm64 BB+dominator utility over a stream the native decoder leaves partly
undecoded (jump tables / register-offset loads); regression risk vs the 57 #39 flips →
gate with golden + Hopper as usual. The current guards are correct (no mis-bindings), so
this is an enhancement, not a bug fix. **Highest-leverage remaining task.**

**#42 cluster — the 2026-06-13 deep scan confirms this fix subsumes NINE REPLACE rows**
(all marked `[#42]` in `heuristic_registry.py`):
- GUARDS deleted outright: `degenerate-partition`, `core-picker`.
- name-suffix FALLBACKS that evaporate (cleanup tail = #45): `namesuffix-s2`,
  `resolve-namesuffix`, `pool-suffix` (Strategy-2 base only), `s1-selsynth`.
- SYMPTOMS the resolver shrinks, not separate fixes: `ordinal-fieldnum` (the estimate —
  #42 recovers many real numbers; residual literal-0/map/inline-struct stays estimated),
  `typeref-bytes` (unresolved-class→bytes; recoverable slice is #42/#37, rest = INTRINSIC
  residual), `disp-rr-tiebreak` (precedence patch a reliable resolver makes moot).
The true residual after #42 is metadata-sparse classes (INTRINSIC). Unblocks #45.

### #45 — name-suffix repeated-element guesses  → **MOVED to DEFERRED / LIMITATIONS.md (7) (2026-06-13)**
Re-measured post-#42: NOT resolved and the residual is INTRINSIC (only the ivar/method NAME exposes
the element type; no structural site does). Reclassified as an accepted-limitation-grade flagged
guess. See the DEFERRED section below and `LIMITATIONS.md` (7).

### #51 — gate message: distinguish "no PB messages" from "missing .symbols"  — **DONE 2026-06-14**
The selector-resolution gate (`SelectorsUnresolvedError`) conflated two causes of `resolved == 0` in
one message. **Key correction from the original plan:** the discriminator is NOT proto-class detection
— BOTH `_is_proto_class` AND `_proto_class_set` over-include SymptomNetworkUsage's NSObject classes
(`NWUsage*`, PB-like ivar shape via `_extensionDictionaries`, but no `writeTo:`/`readFrom:` anywhere).
The real discriminator is **image-wide selector-NAME availability**: SymptomNetworkUsage resolves
798/798 (100%) of its method names — `.symbols` is fine; the image just has no PB messages. (And
`st.find("writeTo:")` is useless per-image — it sees the shared cache-wide methname pool, True for
both.) Fix in `_check_selectors_resolved`: when `resolved == 0`, if `named*2 >= total` method names
across the image, warn "N protobuf-shaped class(es) … none implement writeTo:/readFrom: — no decodable
protobuf messages (NOT a missing .symbols / stripped problem)" and RETURN (no raise); only when names
are unavailable do we raise the `.symbols`/stripped diagnostic per input kind. Output-neutral on all
gated artifacts (they resolve > 0 → early return). Live-verified: SymptomNetworkUsage now warns+passes
(was a misleading raise), GeoServices unaffected. Tests: 2 new cases in `tests/test_selectors_gate.py`.
**Related sub-item NOT done (separate, harder):** tightening the detector so it doesn't over-include
NSObject-with-PB-shape classes in the first place — the message fix handles the symptom gracefully.

### #59 — scan-budget / magic-value caps batch (Group C of the 2026-06-13 deep scan)
**Worked 2026-06-13. Outcome: 1 of 6 was a clean output-neutral win; the deep scan's
"a value-independent bound is available, same as the writeTo budget" was optimistic — the
other five are NOT magic-constant swaps.**

**DONE — `cap-indegree`** (`build_branch_indegree`, writeto.py): the `min((end-imp)//4, 4000)`
ceiling was DEAD (max observed writeTo extent = 2131 insns), so the bound was already the
structural next-IMP extent. Dropped the ceiling, added the `[cap:]` tag → PRINCIPLED. Verified
output-neutral (golden 0-diff all 3 artifacts). Registry `cap-indegree` REPLACE→PRINCIPLED.

**DONE — `cap-helper-family`** (`_classify_write_helper`, write_helpers.py) 2026-06-13.
Restructured to "stop when classified": the wire-type family is decided at the helper's TAG-BUILD
instruction — sint value-shift `lsl Rd,w1/x1,#1`, fixed `mov #wt`+`bfi Rd,*,#3`, or the PLAIN
varint tag `lsl Rd,<field#-reg>,#3` (wt 0) — and the scan STOPS there. Added field#-register
tracking (the field# arrives in w2/x2, moved to a callee-saved reg in the prologue) so the plain
tag-build is told from an unrelated `lsl Rs,#3` index-scale. The 48 is demoted to an INPUT-SANITY
backstop (retagged): a helper with no recognized tag-build falls through to `plain` — the safe
no-refinement default — so the budget no longer decides the output. Hopper/disasm-grounded
(plain int32 helper 0x1a47af658: tag at insn 28, no `ret` in 60). Verified OUTPUT-NEUTRAL: golden
0-diff all 3 artifacts; portability 0 contradictions ×10 (sint/fixed type axis unchanged); the 57
sint + 14 fixed GeoServices flips byte-identical. New unit tests prove stop-when-found ≠ budget +
the index-scale gating. Registry `cap-helper-family` REPLACE→PRINCIPLED. Plan:
`notes/TODO59_HELPER_FAMILY_PLAN.md`.

**DONE — `cap-detect-context`** (`detect_context`, writeto.py) 2026-06-13. The "documented
base-table miss" was a FALSE premise (like #40). Probe (monkeypatch the scan, diff the golden):
max_insns 40→**600 = 0 diffs** on 6 frameworks; 40→12 = 0, 40→8 = 2306 (bases land by ~insn 12).
Stronger: returning EMPTY base_regs (seed nothing) = **0 diffs** on GeoServices/CLP/NewsTransport —
the prologue base-register SEED is fully REDUNDANT with `writeto_walk`'s per-block live `cur_base`
tracking (writeto.py:268-302), which is the SOLE base mechanism. So **deleted the capped base-scan
entirely**; detect_context now finds only `self_reg` and `max_insns` is an INPUT-SANITY backstop on
the self-reg disasm window (the scan stops at the first `bl` regardless). Output-neutral: golden
0-diff all 3 artifacts (incl. locationd); writeto unit tests updated (base_regs now always `{}`).
Registry `cap-detect-context` REPLACE→PRINCIPLED.

**Remaining three:**
- `cap-stack-scratch` (`_value_is_stack_scratch`, `window=5`): the tight window is itself the
  SAFETY (scanning further back risks a false `add x1,sp` match); "scan-to-boundary" is a
  behaviour change with false-positive risk, not a clean win. Leave unless a real miss surfaces.
- `cap-sparse-range` (`_SPARSE_MAX_RANGE`, enums.py): **DONE 2026-06-14 — reframed, output-neutral.**
  The "magic 4096" is the **unshifted 12-bit `cmp` immediate ceiling (2^12)**: a contiguous-range
  jump-table gate is `cmp wN,#imm12; b.hi/hs`, whose immediate is ≤0xFFF unshifted, so a real
  contiguous enum range is ≤4096 (largest observed = 4025, right under the ceiling). Larger
  values can only come from a SHIFTED/register compare → already routed to the materialized-value
  path (`_decode_cmp_reg`/`_materialized_value`, int32-bounded; that is how MotionActivityType=90603
  is recovered). So the bound is STRUCTURAL (the instruction encoding), not a domain guess.
  Changes: constant redefined `1 << 12` with the encoding rationale; the two VACUOUS bias-site
  bounds (`0 < b12 < _SPARSE_MAX_RANGE` at the `sub`-imm sites — `b12` is a 12-bit imm so ≤4095
  always) removed; four bare `4096` literals renamed to `_SPARSE_MAX_RANGE`. Value unchanged →
  golden empty-diff (3 passed). Registry REPLACE→PRINCIPLED.
- `cap-ptrtable-512` (`max_val>512` route, `_extract_enum_values`): **DONE 2026-06-14.** Both `512`
  sites (`_extract_enum_values` count pre-route at ~1668, `_harvest_dictrep_enums` pointer-pair range
  at ~1463) → `_SPARSE_MAX_RANGE` (the 12-bit cmp ceiling). Routing was ALREADY by structure — the
  64-bit scaled-index pointer load (`find_indexed_load_base(scale=3)` / `_decode_ldr_reg_off d[0]==8`)
  with a jump-table fallback (`_extract_jumptable_enum_values`) — so the count gate is only a fast
  pre-filter; the magic 512 is replaced by the encoding-derived bound. A genuinely-dense >512-entry
  pointer-table enum is now read in full; a sparse jump-table enum still falls through (no scaled load).
  Golden empty-diff (3 passed) on GeoServices/CLP/locationd. Left the line-103 `512` (debug-sink
  sampling only, not output-affecting). Registry REPLACE→PRINCIPLED. Portability/suite gated.
  (Debug-sink `512` at ~103 is the only remaining literal — diagnostic perf cap, leave.)

### #60 — principled field label + admission (Group D)  — **DONE 2026-06-13**
**Landed:** both `proto/protocore.py` rows are now pure STORAGE SHAPE (selector-independent),
PRINCIPLED in the registry. The PoC (`probe_fieldlabel_60.py`) + Hopper adjudication showed the
signal is the ivar `@encode`, not the writeTo/readFrom walk the original plan imagined — simpler
and lower-risk.
- `_field_label` — REPEATED iff packed C-array (`{?="list"…}`), inline-C-struct array (`^{Struct=…}`),
  or `@"NSArray"`/`@"NSMutableArray"`; else OPTIONAL. Dropped `add<X>:`/`Count`/`has<X>` name
  construction (redundant w/ the NSArray shape rule for object arrays; and it MISLABELLED ~40
  GeoServices `^{struct}` repeated fields as `optional`). `^{`→REPEATED is Hopper-confirmed against
  the writeTo count+buffer+per-element-loop (GEOResource._regions #4 = repeated GEOTileSetRegion;
  GEOCoarseLocationRing._points) — a `^{` pointer is a heap array, a singular struct is stored by
  value (`{…}`).
- `_is_real_field_ivar` — admit unless bookkeeping-name / has-bits / flags-struct shape. The
  getter/setter name union was measured INERT (`NAME-rescues-flags == 0` on GeoServices+CLP).

**Effect:** GeoServices **40 OPTIONAL→REPEATED** corrections (all `^{struct}`, #37 family — now
correctly `repeated bytes`) + **1 element recovery** (`GEORPFeatureHandle.styleAttributes`
bytes→`GEOStyleAttribute`). **0 added/dropped fields** (admission byte-identical), 0 regressions,
locationd/CLP byte-identical. Verified: golden accepted (40 flips, GeoServices.json only);
validate_ref GEOPDComponent 11/14; portability 0/0/0 ×10 (42 estimated unchanged); full suite
1174/0/0/0. Registry `field-label`/`real-field-ivar` REPLACE→PRINCIPLED. Plan + evidence:
`notes/TODO60_FIELDLABEL_ADMISSION_PLAN.md`. NOTE: the 40 corrected fields are the #37 inline-C
cluster — their *label* is now right; the element *type* stays `bytes` (LIMITATIONS.md (2)).

Other non-Group-A REPLACE rows (lower priority): `enumbase-regguess` (native-decoder table-base
guess — #47-style decode; no production-output change since capstone already resolves it) and
`protoclass` (binary-mode ivar-score SEED for the #46 closure; cache-mode is already ground truth).

### #61 — ~~descriptor-table readFrom decoder~~ WITHDRAWN (misdiagnosis) → folded into #42
**WITHDRAWN 2026-06-13, same day.** The "descriptor table" premise was a Hopper MISREAD: the
`bl 0x18db01580` in `_GEORPFeedbackFieldValueReadAllFrom` is `objc_msgSend$raise:format:` (the
exception path) and `0x1d5ff78a0` is its FORMAT STRING, not a `{field,type,offset}` table. **There is
NO descriptor-table mechanism.**

What's actually there: the per-field dispatch for these classes lives in a SEPARATE
`_<Cls>ReadSpecified` core (called from the thin `ReadAllFrom` tag-loop), and that core dispatches by
**jump table** (`adr xT; ldrb wK,[base,idx]; add xT,xT,wK,lsl#2; br xT`) on the field number, routing
to per-field `-[Cls _read<Field>]` methods. Confirmed: `_GEORPFeedbackFieldValueReadSpecified`
(0x18cf22d8c), `_GEOPDComponentReadSpecified` (0x18c278410), `_GEOStructuredAddressReadSpecified`
(0x18c1d0c38) — all jump tables. GEORPFeedbackFieldValue's 21 fields are **jump-table**, not
descriptor-table.

So the "~1187 non-compare-chain classes" are predominantly **jump-table dispatch** (often via
ReadSpecified) — which #42 already plans to handle (§2.5: compose `_decode_readfrom_jumptable` arms
as CFG edges) plus a reliable ReadSpecified descent. **This is part of #42, not a separate task.**
Production already models ReadSpecified (`dispatch._readspecified_and_count`, `read_specified_va`).
Action: extend the #42 PoC with jump-table arm decoding + ReadSpecified descent (closes the 3
DISAGREE in §8b and the bulk of the 1187). No #61.

### #62 — libprotobuf-lite: surface in `--list-serializers` + (maybe) decode  — **NEW 2026-06-14**
Two parts; the first is small and in motion, the second is mostly an INTRINSIC limitation.

**Part A — detection (small, low-risk).** Make `--list-serializers` surface lite as detect-only.
**This is now tracked as its own task #65** (the inventory command stands apart from decoding) — see
#65 below and `notes/LIST_SERIALIZERS_ALL_PLAN.md`.

**Part B — decoding (largely INTRINSIC-limited).** Lite carries no embedded `FileDescriptorProto` —
that is the whole point of `LITE_RUNTIME` — so `cpp_descriptor_extract` (which decodes the descriptor
blob for FULL → exact .proto incl. names) does NOT apply. Recovery would have to walk the GENERATED
serialize/parse code, the PBCodable analogue. What that can and cannot recover:
- **Field NUMBERS — recoverable.** Baked in as immediates: the tag `(number<<3)|wire_type` in
  `_InternalSerialize`/`SerializeWithCachedSizes` and the parser's switch / `TcParseTable` constants.
- **Field TYPES — recoverable to wire type + specific `Write*/Read*` fn**, with the SAME varint
  subtype ambiguity (int32/int64/uint/sint/bool share the varint wire type) the PBCodable path already
  fights — distinguish via the specific helper, not the tag.
- **Message / type NAMES — recoverable** from the C++ mangled symbols (`namespace::Message`), the same
  symbol channel the foreign detector reads.
- **Field NAMES — INTRINSICALLY UNRECOVERABLE.** Lite strips the descriptor that stores field names
  and drops `DebugString`/JSON/reflection, so the names are simply not in the binary. Output would be
  a wire-faithful but ANONYMOUS schema (`field_5`), unless a name leaks opportunistically (a co-located
  full-runtime message embedding the same type, or an error-string literal) — not systematic.
- **Codegen-shape caveat:** lite codegen varies by protobuf version (older `MergeFromCodedStream`
  switch vs newer table-driven `TcParse`); a real implementation must handle both.

**Detection is binary-mode only** (symbol-based `iter_symbol_names` is empty for cache images), so
neither part sees lite via `--framework` (cache-native).

**Prevalence / priority — LOW.** Fresh CLI sweep of all 257 `iphone8_data/libexec/` standalone
binaries found **0** lite (18 PBCodable, 4 C++-full, 2 swift, 3 GPB). Prior (unverified) cache census
≈ 14 lite of ~180 protobuf-bearing images — a small framework minority, absent from daemons. Given
Part B can never recover field names, the realistic outcome is: land Part A (show lite as detect-only),
and treat Part B as DEFERRED / LIMITATIONS-grade unless a concrete need for anonymous lite schemas
arises.

### swift-protobuf extraction accuracy — split into separate to-dos #63a/#63b/#66/#67/#68 (2026-06-14)
A read-through of the committed swift extraction (`swift_descriptor_extract.py`, `swift_type_recovery.py`,
adapter `proto/foreign.py`) found that — UNLIKE the C++ path, which is an exact `FileDescriptorProto`
decode with no inference — swift recovery makes several estimates because swift carries no full
descriptor (schema split across `_protobuf_nameMap` number↔name + `__swift5_fieldmd` name→type, joined
by NAME). Numbers+names are literal/ground-truth; the FIVE estimates below were split into separate
to-dos. All are catalogued in `apple_protobuf_extractor/LIMITATIONS.md` §10 (a–e) and the registry
(`swift-*` rows). **Shared validation** for any of these: swift extraction works binary + cache-native;
fixtures `nptocompaniond`/`remindd` (libexec) + cache `CopresenceCore`/`MessageProtection`; gate with
the foreign-protobuf tests and confirm PBCodable/C++ golden output is untouched (swift-path only). The
standalone `format_proto` emitter is honest (`???`); these only bite the UNIFIED output via
`collect_foreign_messages`/`_swift_field`.

### #63a — swift shape-B single-field number is a DEFAULT (1) but emitted `number_confirmed=True`  — **DONE 2026-06-15** (LIM 10a)
**Tier 1 (honesty):** added `SwiftField.number_confirmed` (default True); `_single_field_tail_call` sets
it False on the `num = 1` default path; `proto/foreign.py::_swift_field` passes it through (was hardcoded
`True`), and `format_proto` appends `// number estimated`. So a defaulted-1 is no longer laundered as
confirmed (the emitter already renders unconfirmed numbers with the marker).
**Tier 2a (recovery):** added `_traverse_field_numbers` — reads the field number from `traverse`'s
per-field visit (`mov w?,#N`, the highest-w-reg immediate before each `visitSingular*` `bl`/witness
`blr`). `_single_field_tail_call` now cross-confirms TWO independent sources (decodeMessage `cmp` +
traverse): confirmed iff they agree on exactly one value, else default 1 + unconfirmed. Flipped
bookdatastored `PBPropertyMarkedAsFinishedParam` False→True; remindd multi-field/generic-table types
correctly stay flagged. `swift-singlefield-num` registry row REPLACE→PRINCIPLED. Tests: offline
`_traverse_field_numbers` (5) + source-combination (4) + live confirmation. Commit pending.
**Residual → #72:** when a source exposes MANY numbers the message is really multi-field (shape-B
under-extraction), left to the traverse-driven enumerator.

### #63b — swift integer subtype COLLAPSED to the base type (wire-incorrect, unflagged)  — **DEFERRED 2026-06-15 / accepted limitation** (LIM 10b)
`swift_type_recovery.py` (`_SWIFT_SCALAR`/`_DIRECT`): `int32`/`sint32`/`sfixed32`/`fixed32` are all
`Int32`/`UInt32` in Swift, so the tool emits the base (`int32`/`uint32`). For genuine `sint*` (zigzag)
or `fixed*`/`sfixed*` (wire type 1/5) fields this is WIRE-INCORRECT and nothing flags it.
`Float`/`Double`/`Bool`/`String`/`Data`/`Array`/`Dictionary` ARE correct — integer-only.
**DEFERRED — unexercised by the data (same disposition as GPB #65 / lite #63).** Investigated 2026-06-15:
the signal is real — `traverse` lowers each field to `ldr x8,[x19,#OFF]; blr x8` where x19 is the Visitor
witness table and the slot OFFSET selects the exact `visitSingular<Type>Field` (sint/fixed/sfixed have
distinct slots; the default-impl symbols e.g. `…visitSingularSFixed64Field…` are present, 10 in remindd).
But it is **not extractable on our inputs**: (a) **cache-mode** `.symbols` carries NO `traverse` symbol, so
the witness-slot map can't be built; (b) **binary-mode** sint/fixed `visitSingular*` calls appear ONLY in
SwiftProtobuf *library plumbing* types (`RepeatedExtensionField` / `ExtensionFieldValueSet` /
`PackedExtensionField`), NEVER in an app/framework schema message — every app schema integer field we
surveyed is a plain `Int32/UInt32/Int64/UInt64` (base int/uint). So there is no app-schema case to fix.
If a future corpus contains a Swift schema with a genuine `sint*`/`fixed*` field AND resolvable `traverse`,
re-open: recover the subtype from the witness-slot map (analogous to PBCodable writeTo-helper family
#38/#44). Until then the base-type emit stays; `swift-int-subtype` registry row remains REPLACE
(principled signal exists) tagged as an accepted limitation, NOT an open silent-guess to fix now.

### #66 — swift undecoded mangling falls back SILENTLY  — **DONE 2026-06-15** (LIM 10c)
`swift_type_recovery.decode_mangled` (~lines 193/202): an Array whose element doesn't decode →
`repeated bytes`; a Dictionary whose key/value don't decode → `map<string, bytes>`. These bytes/string
fillers are guesses with NO flag. Fix: either flag them (cheap honesty) or extend the mangling decoder
to cover the missing forms (the mangling IS in the binary — this is decoder-incompleteness, recoverable).
**CONCRETE CASE FIXED (hand-verified 2026-06-15, ground-truth note Part 3):**
`CoreML_Metadata.userDefined` is `map<string, string>` (mangling `SDyS2SG`: `SD`=Dictionary,
`S2S` = standard-substitution `S`(String) with a RUN-LENGTH count of 2 → two Strings); the tool used to
emit `map<string, bytes>` because the map branch only read the value when the body literally started `SS`.
**FIXED**: added `_runlength_types` (expands the `S<n><char>` run-length standard-substitution form) and
the Dictionary branch now decodes both key/value scalars from it (falling back to structural decode for
symbolic-ref/Data values). `CreateML.CoreML_Metadata.userDefined → map<string, string>`; ground-truth
test flipped to assert it. Tests: `test_runlength_standard_substitution` + ground-truth `CREATEML`.
**RESIDUAL — NOW DONE (2026-06-15)**: the silent `bytes` fillers (Array element / map key-or-value that
truly don't decode) are FLAGGED. `decode_mangled` returns a distinct label (`repeated?` / `map?`) when the
inner is a guess; `_collect_field_types` carries the incomplete field set alongside the type map (public
`recover_field_types` contract unchanged); `_attach_field_types` sets `SwiftField.type_note` and
`_swift_field` surfaces it as an inline `// swift-protobuf: container element/value type not recovered
(shown as bytes)` note. PRECISE: a genuine `[Data]`/`repeated bytes` (element resolves via the
Foundation.Data symbolic ref) is NOT flagged — verified 0 false flags across remindd/Siri/CreateML; only
true unknowns (CreateML 46, Siri 1, remindd 1) are noted. Test: `test_filler_bytes_is_flagged_not_silent`.
(The stale standalone `format_proto` debug dump still prints `optional ???` and is unaffected — the
production output goes through `proto/foreign.py`.)

### #67 — swift type↔field join is by NORMALIZED NAME (can mis-bind/miss, silent)  — **DONE 2026-06-15** (LIM 10d)
`_attach_field_types` binds `__swift5_fieldmd` types onto nameMap fields by normalized name. The real
hazard was the TYPE-MAP keying, not the per-field name match: `recover_field_types` keyed by the type's
SHORT name, so nested types sharing one (remindd has THREE `Details` and THREE `Error` —
Migrate/StartMigration/Unmigrate Response) collided into a single merged entry. That masked a genuine
difference (`UnmigrateResponse.Details` has only `timeElapsed`; the others have 4 fields) and would mis-type
on divergence. **FIXED:** `recover_field_types` now keys by the QUALIFIED name (`_qualified_name` /
`_owner_type_name` walk the descriptor parent chain → `Outer.Inner`), and `_attach_field_types` looks up by
`m.name` first, falling back to a short-name match ONLY when it is UNAMBIGUOUS (exactly one qualified key
ends with that short name) — an ambiguous short name now binds nothing rather than guessing. The
parent-chain qualified key is the structural link the original note wanted (beats normalized-name matching).
remindd typed=87/None=2 unchanged (binding still complete, now per-type-correct); the three `Details`/`Error`
types are distinct map entries. Test: `test_qualified_keys_avoid_short_name_collision`. (Per-field name
normalization within a correctly-keyed type is retained — swift offers no structural number↔type link there,
and it measured correct.)

### #68 — swift repeated field with unrecovered type collapses to `optional bytes` (label lost)  — **DONE 2026-06-15** (LIM 10e)
**ROOT CAUSE (deeper than the label):** `decode_mangled` matched the `Say…G` (Array) and `SD…`/`SDy…`
(Dictionary) structural prefixes against the PRINTABLE cstring, but a generic element/key/value is a
SYMBOLIC REFERENCE whose control byte (`0x01`/`0x02`) is non-printable → `_cstr` returned None → the
prefix was missed → the whole field decoded to `None`, losing BOTH the element type and the `repeated`
label (emitted `optional bytes`). **FIXED:** detect those prefixes from RAW bytes (`read_bytes(va,3)`),
so the Array branch recurses into the symbolic ref and resolves the element. `MPPB_RatchetState.messageKeys`
/ `MPPB_SKIncomingRatchet.messageKeys` now recover as `repeated MPPB_KeyAndIndex` (full element type, not
just the label). When the element genuinely doesn't resolve, the field still degrades to `repeated bytes`
(label preserved) rather than `optional bytes` — e.g. `Google_Protobuf_Type.oneofs`. **Corrected a
ground-truth error:** the element is `MPPB_KeyAndIndex` (the only key type in the image), not the
hand-guessed `MPPB_MessageKey` (which doesn't exist) — the regression net caught the bad pin. Tests:
flipped MESSAGE_PROTECTION pins + `test_repeated_label_preserved_when_elem_unrecovered`.

### #69 — swift word-substitution mangling truncated type/message names  — **DONE 2026-06-15**
Swift mangles identifiers with WORD SUBSTITUTION: a leading `0` marks an identifier whose letters
back-reference earlier-seen words (`13SwiftProtobuf07Google_B4_Any` — `B` = the word "Protobuf" from
"SwiftProtobuf"). The old `_split_idents`/`_idents` parsers ignored this, so every `Google_Protobuf_*`
well-known-type name collapsed: message names showed `Google_._Any`, and the field-TYPE side truncated
`Google_Protobuf_Timestamp` → `Google_` (e.g. bookdatastored `PBPropertyValue.createdAt`). **FIXED**:
added a faithful Swift word-substitution demangler (`swift_type_recovery.demangle_idents` + `_register_words`,
shared into `swift_descriptor_extract._split_idents` so the name and type sides agree). Principled decode,
no guessing; punycode (`00…`) identifiers bail (rare, non-ASCII type names). All 26 remindd
`Google_Protobuf_*` names now correct; `createdAt → Google_Protobuf_Timestamp`. App-type names unchanged
(strictly additive — only leading-`0` identifiers were ever wrong). Tests: `test_word_substitution`,
`test_well_known_type_field_full_name`, `test_word_substituted_wkt_name`.

### #70 — swift Google well-known types recover NO fields (runtime-built static `_NameMap`)  — **DONE 2026-06-15** (LIM 10f)
SwiftProtobuf's bundled well-known types (`Google_Protobuf_{Any,Duration,Empty,Timestamp,FieldMask,
Struct,Value,ListValue,Api,Type,…}` — ~26 of them, common in remindd) were NAMED correctly (#69) but
emitted ZERO fields (or a spurious shape-B single field via #63a). Root cause: unlike app-generated types,
these library types do NOT build their `_protobuf_nameMap` inline. Their `…vgZ` getter is a lazy once-init
that, on the already-initialized fast path, loads a pre-built `_NameMap` struct from `__bss` ZEROFILL,
populated at RUNTIME by the cold builder behind the `cmn x8,#1; b.ne <builder>` once-token branch.
**FIXED via the SAME recognizer as #72** (`_runtime_namemap_fields` + `_walk_namemap_builder`): the cold
builder closure stores the `(fieldNumber, namePtr)` table literally (`stp wNum,xName,[base,#slot]`, length
from a 16-byte `_NameDescription` vector store), so it is RECOVERED — not injected. Independently validated:
the recovered tables reproduce canonical google.protobuf exactly (`Any`=type_url/value; `Duration`/
`Timestamp`=seconds/nanos; `Api`,`Type`,`Method`,`Value`,`EnumValue`,`Mixin`,`Enum`,`Option` all exact —
12 WKTs). **NOW COMPLETE (2026-06-15, unified builder reader):** `_walk_namemap_builder` was rewritten to
handle ALL three builder store-shapes — (A) combined `stp <num>,<name>`, (B) split `str <num>` + `str
<name>` (the tail entry), (C) packed/parallel `str <num>` + `stp <name>,<len>` (newer InternalSwiftProtobuf,
nptocompaniond) — disambiguating A vs C by OPERAND POSITION (name is the 2nd stp operand in A, the 1st in
C), NOT by value (so `Field.name` = #4 with `len('name')`==4 is no longer misclassified). `Google_Protobuf_
Field` now recovers 10/10 (incl. #11 default_value) and nptocompaniond `ErrorResponse` recovers
{1:domain,2:code} directly. All 12 remindd WKTs match canonical google.protobuf EXACTLY (verified field-set
equality incl. Field). Cross-validation guard retained as defense-in-depth. (Field TYPES are still partly
`None` where `__swift5_fieldmd` didn't resolve — #67/#68 territory.) Recognizer GATED on the once-init
`cmn x?,#1` signature; overrides shape-B only when >1 field AND validated. NOT knowledge-injection.

### #72 — swift shape-B under-extracts MULTI-field messages to a single field  — **DONE 2026-06-15** (LIM 10g)
Discovered during #63a Tier-2a. `StartMigrationRequest.Credential` (remindd) read as ONE field (`dsID`)
but truly has 5. **ROOT CAUSE was misdiagnosed as shape-B:** these messages are NOT the compact tail-call
lowering at all — their nameMap getter is the runtime-built `_NameMap` once-init form (`cmn x?,#1;
b.ne <builder>`), the SAME lowering as the #70 well-known types. The 64-insn shape probe spilled past the
getter's `ret` into the cold builder block, caught its `adr x1,<closure>`, and `_single_field_tail_call`
grabbed only the FIRST name. **FIXED (a far stronger result than the planned traverse+fieldmd index-join,
which would have been order-fragile):** the cold builder closure already contains the COMPLETE literal
`(fieldNumber, name)` table — each entry is `mov w?,#N` + name pointer stored together via one
`stp wNum,xName,[base,#slot]` (length from a 16-byte `_NameDescription` vector store). New
`_walk_namemap_builder` reads it directly (both number AND name literal → all confirmed, no inference);
`_runtime_namemap_fields` follows the once-init cold path to reach it, gated on the `cmn x?,#1` signature
and only overriding the shape-B fallback when >1 field is found. Same fix resolves #70 (see above).
**CROSS-VALIDATION GUARD (`_namemap_builder_validated`) — added after a false positive:** the builder
`stp <smallInt>, <namePtr>, [base,#slot]` is AMBIGUOUS — the int is the field NUMBER in the older codegen
(remindd) but the name LENGTH in the newer InternalSwiftProtobuf packed-bytecode `_NameMap`
(nptocompaniond `ErrorResponse`: 6=len'domain', 4=len'code'), so the walker mis-read lengths as numbers.
Guard accepts only when (a) the independent `decodeMessage`/`traverse` numbers are a SUBSET of the
recovered set (a contradiction ⇒ wrong read) AND (b) not every entry has `number == len(name)` (the
length-form signature). npto `ErrorResponse` now correctly stays {1:domain,2:code}; an INCOMPLETE read is
also refused (`Google_Protobuf_Field` recovers 9 of 10 — misses #11 default_value that traverse exposes —
so it is rejected rather than emitting a wrong/partial set). remindd: Credential 1→5 (string×4 + uint32,
all confirmed) and 21 other messages completed (11 WKTs incl. Api/Method/Type/Value/EnumValue all matching
canonical google.protobuf); 0 wrong output anywhere. Tests: `TestRuntimeNameMap`,
`TestNameMapBuilderValidation`, live `test_error_response` + `test_no_decoder_contradictions`. NOTE:
traverse-driven enumeration (original Tier-2b idea) not needed for this class. **UPDATE 2026-06-15: the
packed-bytecode / split-str residual is now DONE** — `_walk_namemap_builder` was rewritten as a unified
reader handling all three builder store-shapes (see #70 above); npto `ErrorResponse` and `Google_Protobuf_
Field` #11 are now recovered directly, so the guard's incomplete-read rejection no longer fires on them.

### #60 — swift oneof members + COW `_storage` field TYPES  — **DONE 2026-06-15** (LIM 10 honest-baseline)
Investigation while starting #68 found the dominant cause of `None` swift field types was NOT the name-join
(#68) but two structural cases `recover_field_types` didn't walk: (1) larger messages move ALL stored
properties into a copy-on-write `_StorageClass` (a CLASS-kind descriptor), so the message struct's own
fieldmd holds only the skipped `_storage`/`unknownFields`; (2) each proto `oneof` is a nested
`OneOf_<name>` ENUM whose cases carry the member name + payload type. **FIXED:** `recover_field_types` now
also harvests class-kind `_StorageClass`/`AnyMessageStorage` and enum-kind `OneOf_*` descriptors, decoding
their fieldmd with the existing `decode_mangled`, and links each back to the OWNING message by walking the
descriptor PARENT chain (`_owner_type_name`, skipping the anonymous/extension contexts swift nests private
types under). `_attach_field_types` then binds by name as before. remindd: None field-types 20+→2 (the 2
are `Google_Protobuf_Any.{type_url,value}` — `AnyMessageStorage` is a SwiftProtobuf-internal helper not
nested in `Any`, and `value` is held as serialized bytes; honest None). All filled types verified correct
(MigrateRequest options=uint32/user_initiated=bool/simulated_error=int32; Value's 6 oneof members match
canonical; Type.fields=repeated Google_Protobuf_Field). Cache frameworks: ProtoTaskFeatureSet #101-105 →
their Proto*TaskFeatureSet messages; CoreML_NearestNeighborsIndex #100/110/200 → LinearIndex/SingleKdTree
Index/SquaredEuclideanDistance — exactly the values the ground-truth pins predicted. The parent-chain link
is MORE principled than the normalized-name join, partially pre-empting #68. Tests: ground-truth
`test_cow_storage_field_types` + `test_oneof_member_types` (remindd) and the flipped SIRI/CREATEML cache
pins. NOTE: nested-message member types are emitted by SHORT name (e.g. `Details`, `Credential`) like all
other message-typed fields — qualified-naming is a separate concern. Parent-chain keys by short name (the
existing convention) → cross-message short-name collision is the #68 robustness item, next.

### #64 — decode GPBMessage (Google ObjC protobuf), currently detect-only  — **NEW 2026-06-14**
GPBMessage subclasses are presently DETECTED but NOT decoded: `google_protobuf_classes(ctx, cl)`
(proto/extractor.py ~620; base anchor `_GPB_RUNTIME_SUFFIX = "GPBMessage"` ~617) finds them by
superclass-name suffix, and `proto/foreign.py::summarize_serializers` emits a
`SerializerSummary(decodable=False)`. There is NO schema extraction. This task adds it.

**Why it's tractable (and high-value).** Unlike PBCodable (hand-emitted writeTo:/readFrom: ARM64 that
must be reverse-engineered) GPBMessage is driven by a STRUCTURED, STATIC descriptor table built at
runtime — closer to the C++ path. Per the census note GPB is the "next-easiest" runtime after C++.
Each generated message class has a `+descriptor` CLASS method that builds and caches a `GPBDescriptor`
by calling `+[GPBDescriptor allocDescriptorForClass:messageName:…fileDescription:…fields:fieldCount:
storageSize:flags:]` (exact selector/param set is RUNTIME-VERSION-DEPENDENT — verify against the
device's GPBDescriptor in Hopper first). The `fields:` argument points at a STATIC C array of
`GPBMessageFieldDescription` structs (a `…WithDefault` variant also exists), `fieldCount:` is the
count. Each struct carries: field **number** (uint32), **GPBDataType** (uint8 — and crucially this
distinguishes the FULL set incl. `SInt32/SInt64/Fixed*/SFixed*/…`, so types are EXACT, unlike swift's
base-type collapse #63b), **flags** (`GPBFieldFlags`: required/repeated/packed/oneof/hasDefault), an
ivar **offset**, and the field **name**.

**What's recoverable:** field numbers (exact), field types incl. integer subtype (exact, from
GPBDataType), labels (from flags), enums (via the per-enum `GPBEnumDescriptor`: values array + names
blob + verifier fn), message/type names (the ObjC class name + `messageName:`).

**Main challenges / where estimates could creep in:**
- **Locate `+descriptor` and read its call args.** Either (a) disassemble the (simple) `+descriptor`
  builder to recover the `adrp/add` pointer to the static `fields` array and the `fieldCount` immediate
  passed to `allocDescriptorForClass:…`, or (b) find the static arrays directly. (a) is the reliable
  route and reuses the existing arm64 helpers.
- **Struct layout is version-dependent.** `GPBMessageFieldDescription` field order/size and the
  `WithDefault` variant differ across protobuf-ObjC versions — derive offsets from the runtime headers
  / Hopper on THIS device, don't hardcode blindly.
- **Field-name compaction.** Some builds strip per-field name C-strings and instead carry a single
  concatenated names blob + `extraTextFormatInfo` (textFormat) decoded by the runtime, gated by
  `GPBDescriptorInitializationFlag` bits. When names are compacted/absent, field names may be only
  partially recoverable (numbers+types stay exact) — flag any synthesized name, mirroring the project's
  surface-uncertainty rule. This is the only place GPB decoding risks a "guess".
- **Adapter:** add a `gpb_messages(ctx, cl)` to `proto/foreign.py` mapping to `ProtoMessage`
  (serializer tag e.g. `GPB_SERIALIZER = "Google protobuf-objc (GPBMessage)"`), set
  `number_confirmed=True` only for fields read from the static table, and route through
  `collect_foreign_messages` + the existing emitter. Flip the `--list-serializers` GPB summary to
  `decodable=True` once it lands.

**Mode note:** descriptor is in static data + an ObjC class method, so this should work in BOTH cache
and binary mode (no symbol-table dependency, unlike swift/C++-symbol detection). Confirm.

**Prevalence / motivation:** libexec GPB users (per #62 census) = `anomalydetectiond`,
`transparencyStaticKey`, `transparencyd` — and transparencyd's base is `TransparencyGPBMessage`
(extractor.py:616). **This directly covers Key Transparency**, which the mitm cross-version analysis
flagged as the ONLY out-of-scope protobuf producer (235 pb messages, currently 0 extractable — see the
iphone12-crossversion-mitm memory). Census-wide ~180 GPBMessage images, so payoff is broad.

**Validation:** the 3 libexec GPB binaries as fixtures; cross-check decoded field numbers/types against
the Key Transparency mitm captures (mitm_traffic_parser) once a message decodes; standard golden +
suite gate; PBCodable/C++/swift output must stay untouched (GPB-path only).

### #65 — `--list-serializers`: report ALL serializers + decodability info message  — **NEW 2026-06-14**
The inventory/detection counterpart to the decode tasks (#62 lite, #64 GPB). **Full plan, exact code
shape, and tests: `notes/LIST_SERIALIZERS_ALL_PLAN.md`** — this entry is the tracking stub.

Today `--list-serializers` lists only serializers the tool can DECODE (+ GPBMessage, already shown
detect-only). It OMITS C++ libprotobuf-**lite** entirely: `proto/foreign.py::summarize_serializers`
emits a C++ entry only when `extract_cpp_protos(data)` decodes descriptors (full); a lite image has
`google::protobuf` symbols (`cpp_protobuf_namespaces(ctx)` non-empty) but NO `descriptor_table_protodef_*`
arrays, so nothing is emitted. (`cpp_protobuf_namespaces` is already imported-but-unused there — the
intended hook.)

Changes (detail in the plan):
- `summarize_serializers`: after the C++-full block, `elif cpp_ns:` → emit a detect-only
  `SerializerSummary(decodable=False)` with a `note` (namespace + symbol count; lite has no message
  names). The `elif` guard is REQUIRED so a full image (which also has these symbols) doesn't also emit
  a lite entry. Add `CPP_LITE_SERIALIZER` label constant.
- `SerializerSummary`: add additive optional `note=None` (lite has no names — render the note instead
  of "0 message(s)"). Backward-compatible default keeps existing callers working (matters w/ concurrent
  editor).
- CLI (`--list-serializers` block): print the note for name-less detect-only entries; add an info
  footer stating which serializers the tool DECODES vs merely DETECTS.
- Cross-task: when #64 (GPB decode) lands, flip the GPB summary to `decodable=True`; keep the footer's
  "decodes" set in sync.

Caveats: symbol-based detection (lite/swift/full-C++) is BINARY-MODE ONLY → cache-native
(`--framework`) still shows only PBCodable + GPB; the footer must say so. No binary-mode lite fixture
exists locally (#62 census: 0 lite in libexec) — carve a known lite dylib from the cache or synthesize
a minimal Mach-O exporting a `…N6google8protobuf…` symbol with no descriptor table to test the path.
**As of 2026-06-14 another session was editing the tool code (foreign.py shifted mid-read) —
coordinate before landing.**

---

### #73 — iOS 27 / macOS 27 recovery gaps: estimated numbers, sfixed32, enums, element types  — **DONE 2026-10-04** (uncommitted)
`GeoServices` on the iOS 27 and macOS 27 caches: 594 / 47 `// number estimated` fields, `LatLngE7` and four more
sfixed32 fields as int32, ~20 enum fields as int32 or partial, 6 classes with `bytes` elements, 17 confirmed-wrong
numbers (65536). Causes and fixes: `notes/descriptor_comparison_2026-10-04/REPORT.md` (walk bounded to the
image `__TEXT` + `udf` stop + FP-value rule for `w1` field numbers in `proto/writeto.py`; fixed-width tag after
the size-test shift in `proto/write_helpers.py`; signed jump-table arms + bitmask-gated pointer tables in
`proto/enums.py` / `macho/arm64decode.jumptable_arm_target`; single-table engine call site in `proto/dispatch.py`).
After: 739 / 739 observed geo/clp fields identical on both OSes, estimates 32 / 29 (iOS 16: 29). iPhone 8 protos
byte-identical (6 images), golden unchanged. **Open:** `PairedDeviceSubscriptionStatesSummary.isUpdateAvailable`,
`SuggestionEntry.iconID` (macOS), `PDDepartureSequence.artwork`, macOS `GEOTF*` (LIMITATIONS 11).

## DEFERRED — accepted limitations (no near-term fix planned)

These are documented as accepted limitations rather than open work — see
[`LIMITATIONS.md`](../apple_protobuf_extractor/LIMITATIONS.md) for full detail, affected fields, and consumer
workarounds. Each degraded field is flagged inline in the descriptor output (except
#35, which has no field to flag); the relevant source sites carry `LIMITATIONS.md`
references. Reclassified from OPEN 2026-06-13.

### #37 — inline-C struct-writer repeated elements (TileSetRegion family)  → LIMITATIONS.md (2)
~17 `repeated msg → bytes` failsafes whose element is serialized by an INLINE C
struct-writer (`_GEOTileSetRegionWriteTo`, bracketed by length-delimited helpers
`0x18dbdab88`/`0x18dbdab94`) rather than a PBCodable `writeTo:`. Hopper-confirmed:
GEOAttribution #8 region = `repeated GEOTileSetRegion`. Mostly TileSetRegion (TileGroup
#11, Resource #4, Attribution #8, TileSetVersion #2…) + a few fixed structs
(UInt128/SessionID/ScreenResolution); also `GEOPDDepartureSequence.operatingHours #3`
= `repeated GEOPDTimeRange`. Flagged inline via the existing `_ELEMENT_UNRESOLVED_NOTE`
(which covers the broader unresolved-repeated-element class, a superset). A future fix
would map `_GEO<Name>WriteTo → <Name>` and extract the struct layout.

### #35 — ivar-less delegated-field gap  → LIMITATIONS.md (3)
GEOPDReverseGeocodingResult.placeContextMetadata #1 — the lone `TOOL MISSING` in
validate_ref. The field is delegated/has no direct ivar, so it is never discovered and
**cannot be flagged inline** (no ProtoField exists); documented in LIMITATIONS.md + a
source comment at the `field_ivars` collection (proto/extractor.py). A full fix is the
readFrom CFG/dominator resolver (#42), which can find field numbers with no matching ivar.

### #52 — writeTo: field number 0 (Apple 0-based; illegal in .proto)  → LIMITATIONS.md (4)
Investigation DONE (Hopper) + flagging DONE 2026-06-13. 42 fields across NewsTransport/
StatusKitAgentCore/BiomeStreams/iCloudDriveCore are written with field# 0 — deliberate
Apple **0-based** numbering, NOT a codegen bug (NTPBCacheHint: writeTo: `mov w2,#0`,
readFrom: `case 0 → _key`, no case 1; runtime special-cases only −1). Field 0 is illegal
in proto2/proto3, so the tool estimates the lowest legal number — which is NOT
wire-accurate. The writeTo: walk now captures literal-0 writes (`zero_writes` in
writeto.py) and the extractor emits `_FIELD_ZERO_NOTE` for the estimate. None occur in
the golden artifacts (GeoServices/locationd/CLP). The number itself is genuinely
unfixable (inexpressible in proto); accepted limitation. Handoff/ground truth:
`notes/TODO52_FIELD_ZERO_HANDOFF.md`. Generality spot-check (1 of 42 Hopper-verified)
remains optional.

### #50 — proto message field inheritance  → LIMITATIONS.md (5)
Proto-to-proto SUBCLASSES (a class whose ObjC superclass is itself a proto message,
e.g. GEOSearchRequest→GEOPlaceSearchRequest, GEOAnalyticsPipelineSharedStateData→…StateData)
carry only their OWN field ivars, so the emitted message omits the parent's fields (the
subclass `writeTo:`/`readFrom:` invoke `[super writeTo:]`); 3 of the 5 recovered GeoServices
classes emit empty. **Accepted as-is (owner decision 2026-06-13): the existing
`// inherits all fields from <Parent>` comment (`ProtoMessage.inherits_from`) is enough** —
it tells the reader where the rest of the fields live. Merging parent fields into the
subclass (the would-be fix) is not pursued for now. Scope: the 5 recovered classes;
generalises to any proto-to-proto subclass.

### #57 — enum TYPE names are a convention-only reconstruction (cosmetic)  → LIMITATIONS.md (6)
Some recovered enum *type names* are derived from the SCREAMING_SNAKE common prefix of their value
strings (`_enum_name_from_pairs`) and are convention-only — not witnessed by a `StringAs<X>:` selector:
220 of 318 GeoServices prefix-overrides are un-witnessed, and a few are un-idiomatic
(`ApLocationprecisiontype` from `AP_LOCATIONPRECISIONTYPE_*`; acronym flattening `AR_…` → `Ar…`). The
enum VALUES, field numbers, and wire encoding are ALL correct — only the displayed type NAME is a soft
reconstruction with no wire/value/decoding impact. **Accepted as cosmetic (owner decision 2026-06-13):
do not flag** (would add noise to a large fraction of enums for a name-only issue).
**Supersedes the withdrawn #48**, whose premise — bind each field to its enum via its own selector so
same-name collisions never arise — was FALSIFIED: `LinkType` is selector-confirmed yet still splits
(the witness is field-name-based, not type-identity-based); the true disambiguator is proto nesting
scope, which the tool flattens. The emitter's same-name reconciliation (`enum-split-detect` PRINCIPLED
+ `enum-split-name` PRESENTATION in the registry) is correct, not a guess. Analysis:
`notes/ENUM_NAME_FROM_PREFIX.md`; census `apple_protobuf_extractor/census_enumname.py`.

### #45 — repeated-element TYPE guessed from the field NAME (no structural signal)  → LIMITATIONS.md (7)
**22 fields** (GeoServices 20, locationd 2, CLP 0) get their repeated-element type from a name-suffix
GUESS (`proto/repeated.py` Strategy 2 in `_repeated_element_type`: strip plural `-s`, capitalise,
accept iff it UNIQUELY matches a classlist name), because no structural site names the element. Drilled
the residual (GEOPDGroundMetadataTile.photoPositions / GEOPDSearchACHintMetadata.*): these classes HAVE
a readFrom but the dispatch resolver returns nothing (no compare chain; jump table doesn't decode), and
the per-field `_read<Field>` method reads the element via a GENERIC reader keyed by a descriptor pointer
(e.g. `_readPhotoPositions` → no `bl _<Element>ReadAllFrom`, no `_OBJC_CLASS_$_<Element>` class-ref,
just a generic helper + descriptor `0x18d8547b4`). So NO structural site exposes the element type —
only the ivar/method NAME does. **Re-measured 2026-06-13 post-#42: NOT shrunk** — #42 was byte-identical
(dominance reproduced production; it never expanded the dispatch resolver's REACH), so the original
"#42 resolves it structurally" premise is moot. The guess is ALREADY guarded (unique-match only) +
flagged inline (`_NAME_SUFFIX_GUESS_NOTE`) → an honest, bounded last resort, not a silent error. The
pool-suffix + write-helper refinements in `_resolve_repeated_field_type` ARE ground-truth (kept); only
the Strategy-2 base candidate is the guess. **Accepted limitation (2026-06-13).** Only speculative
avenue to recover more: decode the generic-reader element descriptor (`0x18d854…` family) — uncertain
payoff, a separate investigation, not #45-as-written.

---

## DONE (this campaign)

- **#41 — `map<K, V>` field recovery (2026-10-03).** New `proto/mapfields.py`. A map field's number and
  key/value types live in `writeTo:`'s per-entry writer — the `enumerateKeysAndObjectsUsingBlock:` block's
  *invoke function* (block literal fn pointer at `block+0x10`, found via the stack-built block in `writeTo:`),
  or an inline enumeration loop — which the field-number walk never entered. The entry body is
  `begin(F) … write(1)=key … write(2)=value … end`: `F` is the MAP field number (confirming it, and fixing
  `GEOLPRRoot.powerTypes/vehicleTypes`, previously ivar-order *estimates* 2/3 whose real numbers are 3/4);
  each write helper's type is the unanimous type of the ivars that use it binary-wide (ground-truth table built
  as each class is extracted); a message value's class comes from the proto class referenced in the OUTERMOST
  `cmp Wf,#F` handler region of `readFrom:` (a map entry's own nested `value = 2` tag compare reuses numbers, so
  `_dominance_field_of`'s deepest-handler rule can't be used; `_compare_handlers` was factored out of it,
  byte-identical). NSNumber unboxing selectors cross-check the helper types. Emitter renders `map<K, V>`; a
  value that would close a `.proto` import cycle (per-class packages, CoreParsec `_CPStruct`↔`_CPValue`) degrades
  to `bytes`, flagged. 9 maps recovered (5 GeoServices + 4 CoreParsec); `PETProtobufRawDecodedMessage`'s 2 have no
  entry writer (empty `writeTo:`) and stay flagged. LIMITATIONS.md (1) rewritten to the residuals. Tests:
  `tests/test_map_fields.py` + golden `<map>` keys.
- **#58 — function-extent bound on the jump-table enum harvest (clears false-alarm INCOMPLETE).** Commit 5c7b37b. The Log/Analytics `…AsString:` methods are ~12k insns, so the fixed 1000-insn probe didn't reach `ret` and `_disasm_truncated` flagged them — yet every value is in the first ~1000. `_extract_jumptable_enum_values` now keeps the cheap probe but, when it doesn't close, recomputes the body via `_function_body_extent(.., _SPARSE_HARD_CAP=40000)` and re-checks truncation. **15 enums flip `values_truncated` True→False, 0 value changes**; locationd/CLP byte-identical; validate_ref unchanged; suite 1165. Conditional → only the ~15 long methods pay (109.6s vs 111.3s, not the +22% of an unconditional extent). Sound: these methods are CONTIGUOUS (extent NOT reused for outlined writeTo:). Guard: `TestLongMethodNotFalselyTruncatedLive`. (15 not 16 — #53 already cleared LogMessageType.)
- **#54 — dictRep-only enum off-by-bias at the pointer-table idiom.** Commit e791b64. A 1-based enum in `_dictionaryRepresentation:` re-bases into the index reg with `sub w<idx>,w<val>,#N`; the harvester emitted the raw 0-based index. New `_sub_imm_to_reg` (register-gated, sibling of #53's `_leading_materialized_bias`) applied at the pointer-table idiom behind two guards: dest==index-reg (no window bleed) + `_field_routes_through_xasstring` (xAsString-routed fields keep bias on that path). **Exactly 3 confirmed enums shift +1** (relationship/tagSource/relationshipTypes); locationd/CLP byte-identical; validate_ref unchanged; suite 1163. Jump-table idiom left UNBIASED (dest-gate not tight enough there — regressed sparse enums +35). Synthetic+live guards in test_dictrep_enums.py. Follow-up (uncertain, out of scope): 3 xAsString-routed enums may be genuinely 1-based → xAsString path, needs Hopper.
- **#53 — recover large negative-add-bias jump-table enum segments.** Commit e6a9b12.
  The >4095 analytics/log enums re-base each sparse sub-range to 0 with a bias too large
  for a 12-bit `sub #imm`, materialised as `mov/movn wRm,#-K; add` (or `movz;sub`) — e.g.
  `LogMessageType` bias 50000 (`mov w8,#-0xc350; add w8,w2,w8; cmp w8,#3`). New
  `_leading_materialized_bias` (proto/enums.py) decodes it, TIED to the segment's compared
  register (no neighbour bleed), wired only into the jump-table idiom-A path. **GeoServices:
  +3492 recovered enum values + 83 previously-WRONG values CORRECTED** (names the bias-0
  decoder mis-placed at low numbers move to their true biased values, e.g. RAP_NEXT 9→10110);
  0 lost; CLP/locationd byte-identical; validate_ref unchanged; suite 1148. Idiom-B
  (comparison-tree) segments were done earlier (commit 65e40a2). Guard tests:
  test_enum_negadd_bias.py + repurposed TestUnattributedSegmentWarnsLive. Golden regenerated.
  **Residual (separate, NOT #53):** the false-alarm `values_truncated` flags it left behind were
  closed by **#58** (function-extent bound; commit 5c7b37b) — see the #58 bullet above.
- **#53b — Idiom-B materialized bias (seg_incomplete bias-gap follow-on) 2026-06-14.** #53 wired
  `_leading_materialized_bias` into Idiom A (the backward-scan) only; the Idiom-B `branch_gates`
  pre-scan (comparison-tree routing, added in 65e40a2) still computed bias with `_leading_sub_bias`
  ALONE and discarded the cmp register. So a comparison-tree-routed segment whose bias is too large
  for a 12-bit `sub` got bias 0, collided with low values, and dropped → the LAST GeoServices
  `seg_incomplete` warning (`GEOTelemetricEntity.eventKeyAsString:` / `TelemetricEntityEventKey`).
  Fix: keep `cmp_rn, imm = cmp` and apply `_leading_sub_bias(...) or _leading_materialized_bias(...,
  cmp_rn)` in `branch_gates`, mirroring Idiom A (same value_reg-dest gate → no neighbour bleed).
  **Effect (golden, 1 enum changed, strict correction):** 7 values moved from WRONG numbers 0–6 to
  their true 60500–60506, value 0 restored to `TELEMETRIC_EVENT_KEY_UNKNOWN` (was clobbered),
  52020–52023 recovered, `values_truncated` True→False. 0 other enums changed; CLP/locationd
  byte-identical. GeoServices now has **0** truncated enum warnings. Guard:
  `test_idiomB_materialized_bias_segment_recovered_not_flagged`. Diagnosis +
  caps census (the budget caps `_SPARSE_MAX_INSNS`/`_SPARSE_HARD_CAP` confirmed still needed but
  orthogonal — 16/709 hit the 1000 probe, max extent 11925 « 40000) in
  `notes/SEG_INCOMPLETE_BIASGAP_PLAN.md`.
- **#47 — jump-table enum table base from the scaled-index load (REPLACE→PRINCIPLED).** Landed
  (verified in `proto/enums.py:457-470`). `_harvest_jumptable_segments` read the enum (value,name)
  pairs from the real jump-table dispatch (ground truth) but LOCATED the table byte-array by an
  x8..x14 register-priority scan — a guess. Replaced with the dictrep-style principled read: decode
  the scaled-index table load (`ldrb/ldrh Wt,[Xbase,Widx]` via `_decode_ldr_reg_off`), take Xbase,
  resolve only that register's `adrp+add`. Resolves 100% of jump-table segments (276/276 across
  GeoServices/CLP/locationd), so the guess was removed OUTRIGHT (no fallback); a segment whose table
  read doesn't decode is skipped. Output byte-identical (golden 0-diff all 3); registry `jt-enum`
  REPLACE→PRINCIPLED.
- **#46 — proto-class detection via the PBCodable superclass chain (ground truth).** Landed
  (verified: `extractor._proto_class_set` @ proto/extractor.py:485; `ProtoMessage.inherits_from`
  @ proto/models.py:154). `_is_proto_class` missed metadata-sparse proto SUBCLASSES. New
  `_proto_class_set(ctx, cl)` forward-scans the PBCodable closure with two value-independent anchors,
  seeded + sanity-checked by the heuristic: (1) name-anchor — walk each superclass chain via
  `read_ptr` to PBCodable/PBRequest/PBResponse (cache mode); (2) VA-cluster — the non-local superclass
  VAs SHARED by heuristic-confirmed classes (all modes; raw bind ordinals in standalone binary).
  **GeoServices 1637→1642** (+5 metadata-sparse subclasses: GEOAnalyticsPipelineSharedStateData +19,
  GEOComposedWaypointEVStop +6, 3 zero-own-field pass-throughs); **CLP 84=84, locationd 65=65
  byte-identical**. The 5 emit `// inherits all fields from <Parent>` (parent fields NOT merged →
  full inheritance = #50). Heuristic RETAINED as binary-mode seed + superset sanity (registry
  `protoclass` stays REPLACE). Memory: `protoclass-superclass-forward-scan`.
- **#49 — chained-fixups pointer format (REPLACE audit; turned out to be dead code).** Landed
  (verified: only comment refs remain in macho/memory.py). The chain walk ALREADY reads
  `pointer_format` PER SEGMENT (`dyld_chained_starts_in_segment` +6) — correct. The `self._fixup_fmt`
  cache of the first non-zero segment's format was WRITTEN-BUT-NEVER-READ; removed the dead field;
  relabelled the registry row REPLACE→ISA. No behaviour change.
- **#44 / #38b — recover fixed32/fixed64/sfixed* from the writeTo helper.** Landed (verified:
  `_classify_write_helper` @ proto/write_helpers.py:214-221). Each fixed helper builds its field tag
  as `mov w_, #wt ; bfi w_, w<field>, #3, #0x1d`, where the immediate `wt` IS the wire type — **5** =
  fixed32, **1** = fixed64 (varint uses `lsl …,#3`, wt 0; lendelim is wt 2). Gate maps signed-ivar→
  `sfixed*`, unsigned→`fixed*`. **14 GeoServices fields, 0 CLP, 0 locationd**: 11 `sfixed32` (E7
  lat/lng coords + GEODirectionsRequest.departureTime), 3 `sfixed64` (GEORouteIncident times). Golden
  diff = exactly those 14 int→sfixed flips; locationd+CLP byte-identical; validate_ref unchanged.
  Scan budget bumped 28→48 (the tag `bfi` lands at insn 28). Memory: `writeto-sint-helper`.
- **#40 — replace the `_DICTREP_MAX_INSNS=8000` budget with a function-extent bound.** Landed
  (verified: `_function_body_extent` @ proto/enums.py:803; `_DICTREP_HARD_CAP=40000` @ :785;
  `_DICTREP_PROBE_INSNS=8000` @ :778). Investigation overturned the premise: the cap loses ZERO enums
  (dictrep is a CONTIGUOUS serializer, not outlined). Fix: high-water-mark function-extent bound cut
  at the function's own last `ret` (value-independent, contiguous-only), recomputed only when the cheap
  8000 probe doesn't reach the end; 40000 is a fail-loud ceiling. Output-neutral: golden diff = removal
  of the 4 false-alarm `<enum_recovery_truncated>` keys only. Memory: `todo40-dictrep-budget`.
- **#38 (sint half) — recover sint32/sint64 from the writeTo: zigzag helper.** Commit 48c18fc
  (verified: `_classify_write_helper` @ proto/write_helpers.py:200-206). `_classify_write_helper`
  follows the 12-byte `adrp/add/br x16` stub into ProtocolBuffer.framework and detects the zigzag
  `lsl (w|x)1,#1` on the value arg — a portable PRESENCE signal. **57 fields flipped, 0 collateral**
  (25 GeoServices + 32 CoreLocationProtobuf; locationd none). Memory: `writeto-sint-helper`.
- **#39 — repeated-message elements via thick-wrapper→compare-chain core readFrom.** Landed
  (commit 7519a68 per memory). Extended the readFrom dispatch resolver to reach two new core shapes:
  (1) a THICK ReadAllFrom wrapper that CALLS a separate compare-chain core, and (2) classes whose
  direct core IS a compare chain. GeoServices: **57 fields `bytes`→`repeated <Message>`** + 8 type
  corrections (Hopper-verified) + 13 note removals; locationd/CLP byte-identical; validate_ref
  unchanged. Two value-independent guards added (`_degenerate_block_partition`,
  `_core_resolves_compare_chain`) — both correct (no mis-bindings); both delete once #42 lands.
- **#55 — enum golden snapshot + harvester refactor.**  [was session #46/#47]
  `snapshot: capture per-message enum value-sets so the golden guards enum recovery` (b8995d5);
  `enums: split the sparse-enum jump-table harvester into focused helpers` (56a1280); plus
  `enums: read jump-table entries at their true width (fix halfword-table corruption)` (d5f81fc) and
  `enums: recover comparison-tree (idiom-B) jump-table segments` (65e40a2). The golden now captures
  enum value-sets so enum recovery is guarded; idiom-B comparison-tree segments are recovered (the
  negative-add-bias residual → #53).
- **#56 — portability / confidence test (never-tuned frameworks).**  [was session #49/#50]
  Added reusable binary-derived oracles `census_protoframeworks.py` + `gt_{fields,dump,compare,
  adjudicate,types}.py` and the ground-truth writeup/baseline under `notes/portability_test/`.
  Verified 10 randomly-sampled frameworks (622 msgs / ~5217 fields): field numbers 100% vs the
  independent writeTo: oracle, types 100% vs ivar @encode, 0 correctness errors. Memory:
  `portability-test-2026-06`. (Recipe to re-run a new tool version or larger sample is in the note.)

- **Heuristics → principled (#1–18, #36):** re-scan + frequency-rank (#1–3); arm field→ivar lever
  (#4); wrapper→core finder (#5); Strategy-2 replacement (#7); selector-resolution gate + remove 3
  no-symbols fallbacks (#9–13); remove dead metaclass fallback / parse_class_at_vmaddr (#14–16);
  compare-chain field-number decoder fix (#17–18); review remaining code heuristics incl. caps (#36).
- **Enum-truncation transparency (#19–22):** `ProtoEnum.values_truncated` + `_DICTREP` fail-loud
  warning.
- **Scan-cap audit (#23–25, #36):** tier-2 cosmetic verified, tier-1 flagged, `_READSPEC`
  reclassified COSMETIC, registry refresh.
- **writeTo CFG-walk decoder (#26–33):** oracle + cross-oracle + indegree map + numbers-only walk +
  per-block ivar binding + Phase A/B merge.
- **writeTo field-number recovery (#34):** GeoServices unconfirmed numbers 161 → 6 — omit 85
  backing-store `…Count`/`…Space` phantoms; track mid-body base-register re-loads; capture late/
  adrp-only bases + thread base state across blocks; w/x hoist tracer fix. The remaining 6 are real
  map<>/inline-struct walk-misses → #41/#37.

> Keep this file in sync when tasks change. Full per-task detail lives in the
> `notes/*.md` design docs.
