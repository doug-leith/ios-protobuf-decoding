# Synthetic ground-truth fixtures

The extractor has no independent ground truth: real Apple `.proto` files
aren't public, captured network traffic covers only some fields, and
`protoc --decode_raw` only checks wire-type-level decoding — not the tool's
actual job (recovering field names/numbers and the true semantic type: is a
length-delimited field a `string`, a nested `message`, or `bytes`; which
concrete class a repeated message field's elements are; and for an enum
field, its recovered value table — names and numbers).

Each fixture here is a tiny, **genuinely-compiled** ObjC `PBCodable`-shaped
Mach-O binary — real clang, real arm64 instructions, not hand-assembled
bytes — whose schema we know exactly because we wrote it. This deliberately
differs from `tests/conftest.py`'s hand-packed byte fixtures used elsewhere in
this repo: those are toolchain-free but can only test "does the decoder
decode what we told it to encode." The value of *this* suite comes
specifically from real compiler-generated instruction shapes, which is where
every one of the gotchas below was discovered.

Binaries are **committed to the repo** (each ~65KB, no proprietary Apple
code) so `tests/test_synthetic_fixtures.py` needs no Xcode/clang at test
time. Only run `build_fixtures.sh` when authoring a new fixture or editing an
existing one's source — then re-verify the disassembly (gotcha 4 below)
before trusting it, and commit the regenerated binary alongside the source
diff so the change is reviewable.

## Toolchain the committed binaries were built with

To regenerate them, use **Xcode 15.4 (build 15F31d)** — Apple clang 15.0.0
(clang-1500.3.9.4), linker `ld` 1053.12, iPhoneOS 17.5 SDK — with the flags in
`build_fixtures.sh` (`-Os -fobjc-arc -miphoneos-version-min=15.0`; `-arch arm64` for
every fixture, plus `-arch arm64e` for the `*_e` binaries of f24, f25, f26 and f27).
`build_fixtures.sh` uses whatever `xcrun` selects, so run `xcode-select -p` /
`xcodebuild -version` first.

What was checked: every fixture executable's `LC_BUILD_VERSION` records tool `LD`
1053.12, SDK 17.5, minimum OS 15.0, platform iOS, for both the arm64 and the arm64e
binaries (`xcrun vtool -show-build <binary>`). The compiler version is not recorded in
a Mach-O, so "clang-1500.3.9.4" is inferred from that linker/SDK pair being Xcode 15.4's
and from the script invoking the default toolchain.

Three fixtures — **f16, f18, f19** — are a hybrid: their `.m` is compiled to an object
file with **Xcode 11.1 (build 11A1027)** — Apple clang 11.0.0 (clang-1100.0.33.8),
`-isysroot iPhoneOS13.1.sdk`, `-miphoneos-version-min=13.0` — and then linked with the
Xcode 15.4 linker above (which is why their `LC_BUILD_VERSION` also reads SDK 17.5).
Xcode 11.1 is needed because its if-conversion heuristics produce the branch shapes
those fixtures test (see gotcha 13); it is not part of a normal install. The script
looks for it at `<repo root>/Xcode11.app` (override with `OLDXC_CLANG` /
`OLDXC_SDK`) and skips those three fixtures, keeping their committed binaries, when it
is absent.

Re-verify after rebuilding with a different Xcode: compiler code shape is not fully
predictable (gotcha 4), so a fixture may stop exhibiting the pattern it exists for. The
tests fail loudly when that happens — do not "fix" them by regenerating `expected.py`.

## Layout

```
shim/pbshim.h, pbshim.m     canonical PBCodable/PBDataWriter/PBDataReader
                             stand-ins + C-linkage field helpers, shared by
                             every fixture
                             (built as libpbshim.dylib for arm64 and
                             libpbshim_e.dylib for arm64e — a shim's
                             architecture must match its client's; only
                             f24/f25/f26 have arm64e builds, `*_e` binaries)
shim/pbwiretypes.h/.s       hand-assembled sint/fixed write-helper functions
                             (f3, f6, f7, f8 — see gotcha 6; linked directly
                             into each of those fixtures' own executables)
build_fixtures.sh           rebuilds shim + fixture binaries from source
f1_writeto_fieldnum/        writeTo: CFG-walk field-number recovery
f2_readfrom_element_type/   readFrom: COMPARE-CHAIN dispatch element-type recovery
f3_write_helper_family/     writeTo: write-helper sint32/64 + fixed32/64 classification
f4_packed_repeated/         packed-repeated scalar detection (pure ivar @encode, no disasm)
f5_jumptable_dispatch/      readFrom: JUMP-TABLE dispatch element-type recovery
f6_geo_route_incident/      REAL extracted message (GEORouteIncident, 19 fields):
                             fixed64 family + nested messages + enum-shaped ints
f7_geo_tf_road_speed/       REAL extracted message (GEOTFRoadSpeed, 14 fields):
                             3 packed-repeated scalar fields + sint64 + bytes
f8_geo_companion_drive_step/ REAL extracted message (GEOCompanionDriveStep, 13
                             fields): 2 distinct repeated-message dispatch arms
                             in one class, real ARM64 jump table
f9_clp_location/            REAL extracted message (CLPLocation, CoreLocation-
                             Protobuf framework, 29 fields): a real message
                             from the OTHER framework this tool targets, one
                             class referenced from 3 distinct singular fields
f10_geo_log_message/        REAL extracted messages (GEOLogMessage + a real
                             subset of GEOLogMsgEvent): extreme sparse field
                             numbers (102/1000/2000), 2-level nested repeated-
                             message dispatch, a HYBRID compare-chain +
                             jump-table dispatch shape in one function
f11_enum_pointer_table/     ENUM VALUE recovery, pointer-table path
                             (proto/enums.py:_extract_enum_values): 0-based
                             baseline + a REAL enum (GEOMapRegionSourceType,
                             13 values, 1-based/bias) — the mechanism that
                             resolves the large majority of real enums, with
                             zero prior synthetic coverage (see "Enum value
                             recovery coverage" below)
f12_repeated_metaclass_type/ Repeated-message element-type recovery via the
                             `+[Cls xyzType]` METACLASS method (Strategy 1,
                             proto/repeated.py:_class_from_type_method_imp)
                             — the DOMINANT real-world path (503/5/16 fields
                             across GeoServices/locationd/CLP per the file's
                             own measured tally), vs. the minority readFrom:
                             dispatch path f2/f5/f8 already cover; zero
                             prior synthetic coverage
f13_writeto_accessor_sourced/ writeTo: field-NUMBER binding for a message-
                             typed field written via its property GETTER
                             (`self.context`, an objc_msgSend dispatch)
                             rather than a direct ivar load — bind_write's
                             accessor-sourced tier
                             (_build_accessor_ivar_map/
                             _trace_accessor_sourced_value/
                             _selector_stub_name/_getter_loads_offset).
                             Real documented bug this fixes: without it the
                             field falls to an ivar-order ESTIMATE and gets
                             the wrong number (file cites a real case,
                             _CPUsageEnvelope.context, estimated 6, actual
                             14); zero prior synthetic coverage
f14_repeated_suffix_ambiguity/ No name-based element-class guessing
                             (proto/repeated.py:_repeated_element_type).
                             Two repeated fields with NO structural evidence
                             (no readFrom:, no +xyzType anywhere): one whose
                             name matches exactly one class suffix and one
                             whose name matches two.  Originally the fixture
                             for the name-suffix matcher (unique suffix ->
                             resolved, ambiguous suffix -> bytes); since
                             2026-10-13 that matcher is deleted, so BOTH are
                             the honest `repeated bytes` -- the guard
                             against re-introducing a guess.
f15_opaque_passthrough/     Opaque-passthrough detector
                             (proto/extractor.py:_is_opaque_passthrough): a
                             field-less class whose writeTo: is a pure
                             tail-call to its `_unknownFields` bag — "0
                             fields" is GROUND TRUTH (78 real GeoServices
                             classes match this shape), not an extraction
                             gap — plus a deliberate lookalike (same one-
                             ivar shape, but writeTo: does one more thing)
                             that must be correctly REJECTED. Zero prior
                             synthetic coverage; extends
                             test_synthetic_fixtures.py itself with an
                             optional `opaque_passthrough` expected-value
                             check (previously unchecked entirely)
f16_enum_isolated_compares/ BRANCH-BASED sparse-enum harvesters
                             (_harvest_isolated_compares,
                             _harvest_cbz_value0). REAL COMPILED CODE
                             (gotcha 13): unreachable via THIS repo's
                             normal (Xcode 15) clang, which always
                             if-converts a plain switch to `csel` — but a
                             much older Apple clang (Xcode 11.1) has
                             different if-conversion heuristics and
                             compiles the exact same switch to genuine
                             `cbz`/`cmp+b.eq`, no hand-asm needed.
                             Confirmed real via a live `locationd` binary
                             before building this (see "Enum value
                             recovery coverage" below); originally
                             hand-written (gotcha 9), rewritten with real
                             compiled code once gotcha 13 was found
f17_repeated_adder_ivar_lever/ Repeated-message element-type resolution via
                             the ADDER->IVAR LEVER
                             (proto/repeated.py:_resolve_repeated_element_ivars)
                             — needs a jump-table arm to `bl` straight into
                             its own class's adder method IMP, bypassing
                             objc_msgSend; unreachable via any message-send
                             syntax, so uses gotcha 10 (a statement-level
                             `__asm__` block calling the adder's real
                             linker symbol directly). Zero prior synthetic
                             coverage
f18_enum_multi_segment/     MULTI-SEGMENT jump-table enum harvest
                             (_harvest_jumptable_segments' Idiom-B
                             branch-gate routing): TWO independent dense
                             jump-table segments (clusters 0-3, 100-103)
                             sharing ONE epilogue — the real shape
                             (confirmed via the real dyld cache earlier
                             this session). REAL COMPILED CODE (gotcha
                             13): THIS repo's normal (Xcode 15) clang
                             tail-duplicates each segment's own `ret`
                             instead — the opposite of the real shape —
                             but Xcode 11.1 compiles a plain switch to
                             exactly the real shared-epilogue shape.
                             Originally hand-written (gotcha 9 extended,
                             gotcha 11), rewritten once gotcha 13 was
                             found; the real multi-cluster case had only
                             a one-off real-binary verification before
                             this, no repeatable fixture
f19_enum_dictrep_switch/    `-[Class _dictionaryRepresentation:]` enum
                             harvest (_harvest_dictrep_enums), BOTH
                             idioms: `category` via the JUMP-TABLE form,
                             `cacheControl` via the POINTER-TABLE form —
                             the LARGEST single gap in enums.py before
                             this fixture (~230 lines), zero prior
                             coverage. HALF real compiled code (gotcha
                             13): `category` is a plain 8-case switch, no
                             hand-asm needed (8 cases required — fewer
                             lowers to isolated compares instead of a
                             jump table). `cacheControl` stays
                             hand-written (gotcha 9/11, real CFString
                             structs in `__DATA_CONST,__cfstring`) — a
                             genuine, thoroughly investigated negative
                             result: 3 C structures x 2 old-clang versions
                             x 4 optimization levels x 2 real field case
                             counts (3 and, separately, a second real
                             pointer-table field with 9 cases) all lower
                             to jump-table/isolated-compares, never a
                             pointer table — the two compilers prefer a
                             different lowering STRATEGY for this shape,
                             not something case count or surrounding C
                             structure changes (see fixture.m's header
                             for the full matrix, including the earlier,
                             wrong "must return immediately" theory it
                             ruled out). Its values are real, not
                             invented — traced directly against the real
                             iphone8_data/dylib cache to find
                             GEOPDComponent's GENUINE pointer-table field
                             (`_cacheControl`, not `_status` as this
                             fixture originally, wrongly, assumed — see
                             fixture.m's header for the trace)
f20_dispatch_wrapper_core_picker/ dispatch.py's THICK-WRAPPER-VS-DIRECT-
                             CORE PICKER (_core_resolves_compare_chain /
                             _find_dispatch_core_via_wrapper) — a repeated
                             field resolved via a compare-chain core only
                             reachable through a padded "thick wrapper",
                             exercising the FULL symmetric two-candidate
                             comparison (found, not designed: a real
                             `_find_field_count` cross-function-boundary
                             quirk — see fixture.m's header). Zero prior
                             synthetic coverage; needed gotcha 10 to be
                             tractable at all
f21_enum_long_body_extent/  `_extract_jumptable_enum_values`'s TODO #58
                             extent-recompute fallback (a >1000-insn
                             `xAsString:` body forces
                             `_function_body_extent` instead of trusting
                             the cheap 1000-insn probe) — zero prior
                             coverage since every other fixture's
                             `xAsString:` body closes on `ret` well under
                             1000 insns. 400 real `pad_sink += 1;`
                             statements on a local `volatile` (REAL
                             COMPILED CODE, gotcha 14 — no hand-asm)
                             pad a real f11-shaped pointer-table switch
                             past the cap. Found, not designed: the recompute
                             fired correctly, but the recomputed body's
                             POINTER-TABLE shape wasn't one the three
                             jump-table harvesters this function calls
                             could read — a real production gap (not a
                             fixture artifact), closed by adding
                             `_try_pointer_table_in`; all 3 values now
                             recover — see fixture.m's header and
                             expected.py
f22_writeto_forward_array_load/ writeto.py's `_forward_self_load_off` (the
                             inline-repeated-message container-array
                             forwarder). Zero prior synthetic coverage —
                             confirmed real via a corpus trace before
                             writing this fixture (80 hits across
                             GeoServices, 0 with a first, broken probe that
                             didn't thread `ctx._writeto_indeg` the way
                             `extract_all` does). Modeled directly on
                             GeoServices' `GEOFlyoverRegionVersions._regions`
                             (inline C-array-of-structs storage via three
                             separate ivars, not the combined-struct shape
                             `f4_packed_repeated` uses for a packed scalar
                             list — tried that first and found it produces
                             offset-only loads the function's own
                             `pl[2] is not None` check rejects). Helper
                             calls live in a separate translation unit
                             (helpers.m) so the compiler can't see they're
                             no-ops and drop the call-site argument setup —
                             confirmed by trying a same-file body first and
                             watching the real shape vanish
f23_writeto_hoisted_value/  writeto.py's `_trace_hoisted_self_value` ("S1"
                             hoisted value-load). Zero prior synthetic
                             coverage — confirmed real via the same corpus
                             trace (6 hits, including CoreLocationProtobuf's
                             `CLPPressure._timestamp`-shaped field, which
                             this fixture's shape is modeled on directly).
                             Reproduces with this repo's normal clang, no
                             old-compiler hybrid needed — a local value read
                             before an opaque call whose return value feeds
                             the rest of the method is enough for `-Os` to
                             choose the same register allocation as the real
                             binary
f24_dictrep_compare_chain/  `dictionaryRepresentation` enum harvest, the
                             COMPARE-CHAIN / compare-TREE idiom a newer
                             toolchain uses instead of a jump table
                             (proto/enums.py:_harvest_dictrep_enums' third
                             pass, commit 9d07d15). Ground truth checked
                             against a hand-authored schema, not real-binary
                             output: a 3-value sparse enum (1/5/60, the real
                             GEOBatchPlaceResult.statusCode values), a 2-value
                             enum (cbz-0 + cmp #1 leaves), a 6-value enum (a
                             cmp TREE) and a plain int32 that must NOT become
                             an enum, all in ONE function, reached both via the
                             real macOS shape (`-dictionaryRepresentation` is a
                             bare `mov w1,#0; b <C function>` wrapper, no
                             `_dictionaryRepresentation:` method) and via a
                             registered `_dictionaryRepresentation:`. Plain
                             Xcode 15 clang, no hand-asm: the `default:` arm's
                             +stringWithFormat: keeps the chain from being
                             if-converted to `csel`. FOUND, NOT DESIGNED: with
                             four gated fields the compiler hoists the has-bits
                             byte and branches on it with a `tbnz` cascade, so
                             the first field's gated block sat OUT OF LINE,
                             after the function's epilogue (a tail `b`) — the harvester's
                             gate-anchored windows never reached its chain and
                             `statusCode` silently stayed int32. Fixed by
                             anchoring each chain on its own ivar-offset lookup
                             instead of its gate; the same fix recovered 3
                             more real enums on iPhone8's classic toolchain
                             (golden regenerated) and 2 on the macOS cache
f25_newer_dispatch_engine/  The newer toolchain's readFrom: dispatch ENGINE
                             (proto/dispatch.py). A thin wrapper (early-return
                             fast path, then an engine call whose data-table
                             argument is picked by `csel` between two `__const`
                             tables); the engine holds TWO jump tables sharing
                             one table-base register (x9: wire type, bias 0;
                             then field number, 1..8, bias 1); the two
                             repeated-message arms load their element class's
                             classref and call only GENERIC ivar-offset helpers
                             (helpers.m) — no own accessor, no per-class
                             ReadAllFrom core. Exercises, on real compiled
                             code: the table-base reaching definition
                             (_decode_readfrom_jumptable), the classref
                             fallback + ownership gate
                             (_scan_arm_for_core_or_classref /
                             _walk_jumptable_arms / _any_arm_loads_known_
                             classref / _call_site_selects_data_table), and
                             _find_dispatch_cluster's function-boundary bound
                             (a short jump-table-free guard function sits
                             immediately before the engine). Schema-level
                             truth is in expected.py; the intermediate
                             structure (cluster shape, arm identities from
                             source-derived `mov w1,#N` immediates, call-site
                             signal) is checked by
                             tests/test_newer_toolchain_fixtures.py. FOUND,
                             NOT DESIGNED: the classref fallback resolved a
                             classref only via ctx.bind_name_for, which in
                             binary mode knows external binds only — a class
                             defined in the SAME image is a plain rebase, so
                             the fallback never fired for a standalone
                             binary/dylib (cache mode was fine). Fixed by
                             following class_t -> class_ro_t.name for the
                             local case (_classref_class_name), as
                             proto/repeated.py already does for +xyzType.
                             Built for BOTH arm64 (testnde) and arm64e
                             (testnde_e): the arm64e build has PAC-signed
                             code, chained-fixup format 12 and the newer
                             toolchain's signed-difference jump table
                             (`ldrsw`, entry size 4, vs arm64's `ldrb`);
                             both pass the same expected.py and the same
                             internal checks. What neither models is
                             the iPhone17,3 / macOS-27 engine shape (a
                             compare TREE on the field number with no range
                             guard, a call-site `csel` between two data
                             tables — see LIMITATIONS.md item 11); it is NOT
                             PAC-authenticated dispatch, which no readFrom
                             engine examined uses. f24 is built for both too
                             (testdcc / testdcc_e); note the arm64e build
                             does NOT lay its gated blocks out of line, so
                             only the arm64 build guards the ivar-lookup
                             anchor fix above
f26_arm64e_fixups/          Chained-fixup FORMAT 12 decode
                             (macho/memory.py:_decode_chain_ptr /
                             _chain_next_stride / _walk_chain). A bare
                             arm64e ObjC class whose 16 fixups (8 rebases,
                             8 binds, plain and PAC-authenticated) are
                             checked against Apple's own
                             `dyld_info -fixups` output, transcribed into
                             expected.py — independent of the extractor.
                             Before format 12 was supported the decoder saw
                             2 of the 16 and no classes at all, so a
                             standalone current-toolchain arm64e Mach-O
                             yielded nothing. Checked by
                             tests/test_chained_fixup_formats.py, which also
                             covers format 9 and the 16- vs 24-bit bind
                             ordinal split on hand-packed values
f27_compare_tree_engine_no_guard/ The newest arm64e engines' shape: a
                             compare TREE on the field number with NO
                             `cmp;b.hi` range guard, reached through a
                             wrapper whose call site `csel`s between two
                             data tables (the iPhone17,3 / macOS 27 shape
                             behind LIMITATIONS.md item 11). Exercises the
                             compare-chain tier of
                             _find_dispatch_core_via_wrapper's relaxed
                             acceptance (call-site csel + independent
                             dispatch check + the class's OWN ivar-offset
                             variables, _core_loads_own_ivar_slot) with one
                             positive and TWO NEGATIVES that must stay
                             `bytes`, each lacking exactly one signal: a
                             plain (non-csel) call site, and a wrapper that
                             calls ANOTHER class's engine (the nested-reader
                             case — the ownership check's whole purpose).
                             Field names are unrelated to the element class
                             names so no name-based match could resolve
                             them behind the tier's back.
                             Built for arm64 and arm64e. FOUND, NOT
                             DESIGNED, while building it: (1) `_func_end`
                             follows a plain-arm64 function's final tail
                             call (`b <stub>`) into the stub island, so the
                             first, naive ownership check credited the engine
                             with the ivar slots of every class laid out after
                             it — fixed with a tight extent (`_core_insns`);
                             (2) two adjacent const tables let the compiler
                             derive the second address from the first's
                             `adrp` (`add x9, x8, #16`), erasing the
                             two-independent-constants call-site shape — the
                             second table is page-aligned; (3) an engine that
                             ignores its table argument has the whole call-site
                             setup optimised away — the argument is passed to
                             an opaque helper. Internal ground truth (no range
                             guard, engine loads exactly its own class's slots
                             and nobody else's) is in
                             tests/test_newer_toolchain_fixtures.py
f24_enum_dictrep_hybrid/    `_dictionaryRepresentation:` enum harvest, HYBRID
                             shape: one switch lowered to a jump table for
                             the dense low values (0,1,2,5) PLUS isolated
                             `cmp #K; b.eq` compares for the sparse high
                             ones (20,30,40,50,60) -- real GEOPDComponent
                             `ComponentStatus` values. Covers
                             `_scan_dictrep_isolated_cmps`, previously only
                             reached by a Live real-cache test (f19's
                             `category` is dense-only). REAL COMPILED CODE
                             (gotcha 13, Xcode 11.1 hybrid), no hand-asm: a
                             plain 9-case switch lowers to exactly this
                             shape first try. Differential-checked:
                             without the sparse harvester only 0,1,2,5
                             recover
f25_enum_large_bias/        `_leading_materialized_bias`: a jump-table
                             segment whose index bias (50000) is too large
                             for `sub #imm12`, so the compiler materialises
                             it (`mov w8,#-0xc350 ; add w8,w2,w8`) -- the
                             >4095 analytics/log enums (TODO #53). No
                             fixture had values that large before. REAL
                             COMPILED CODE (gotcha 13): a two-cluster switch
                             (0-3, 50000-50003), old-clang hybrid so the low
                             cluster keeps f18's shared-epilogue shape.
                             Differential-checked: without the function
                             only 0..3 recover
f28_enum_dictrep_biased/    `_field_routes_through_xasstring`: a 1-based,
                             dictRep-ONLY pointer-table enum (`sub w9,w8,#1`
                             before the indexed name read -- the iOS 16
                             GeoServices shape of GEOPDGroundDataBuild.type)
                             in a binary where a DIFFERENT class defines
                             `typeAsString:`.  The image-wide selector pool
                             made the field look xAsString-routed, so the
                             bias was dropped (1..3 came out 0..2).  Also
                             pins the other side: a field with its own
                             kindAsString: is left to that path (no double
                             bias).  REAL COMPILED CODE, plain build.
                             Differential-checked: with the pool-based gate
                             TestBuildType is 0..2
```

f1-f5 each isolate ONE recovery mechanism in a minimal toy message (1-6
fields) purpose-built to exercise it in isolation. f6-f10 are a different
tier: each is a REAL message this tool has already extracted from a live
binary (GeoServices for f6-f8/f10, CoreLocationProtobuf for f9 — see
`tests/golden/GeoServices.json` / `CoreLocationProtobuf.json`), reimplemented
from scratch as a genuinely-compiled class at its real field count/type mix,
then re-extracted and checked against the original claim field-for-field.
This is a self-consistency check at realistic size and type density (not
just "does mechanism X work in isolation", but "does the combination hold up
on a message shaped like the real ones we report on") — see each fixture's
`fixture.m` header comment for which real message it reimplements and why it
was picked: f6 fixed64 + nested messages; f7 packed-repeated scalars at
scale; f8 two repeated-message dispatch arms in one class (real jump table);
f9 the other framework (CoreLocationProtobuf), one class referenced from 3
distinct singular fields; f10 extreme sparse field numbers + a 2-level
nested repeated-message dispatch chain that compiles to a hybrid
compare-chain/jump-table shape.

f11 is a third tier: it isolates ONE mechanism (like f1-f5) but its second
class reimplements a REAL enum's full value table verbatim (like f6-f10's
"real message" approach, applied to an enum instead of a field set) — see
"Enum value recovery coverage" below for why, and for what's still missing.

Each fixture directory has an `expected.py` with an `EXPECTED` dict — the
ground truth the source was authored to express, documented as plain data,
not a snapshot of whatever the tool currently outputs. A fixture with at
least one ENUM:-tagged field also carries an `"enums"` key per message,
checked against the recovered `ProtoEnum.values` list (names + numbers),
`values_confirmed`, and `values_truncated` — see f11's `expected.py`.

## Enum value recovery coverage (2026-09, f11)

Before f11, `proto/enums.py` (848 statements, the single largest module —
enum-value harvesting + name derivation) had **zero** synthetic coverage:
no fixture f1-f10 has a single `ENUM:`-tagged field, so none of this
machinery ran under a known-correct oracle (real-binary coverage was fine —
85% via the golden/live tests — just never checked against ground truth).

f11 closes the biggest, highest-real-world-usage piece of that gap: the
**dense pointer-table path** (`_extract_enum_values`'s primary branch — a
scaled-index load `ldr x0,[x8,wN,sxtw #3]` into a `char*`/`NSString*`/
`CFStringRef` table), which resolves the large majority of real enums
(587/587 GeoServices/CLP/locationd pointer-table enums per the file's own
measured tally), including the 1-based/bias correction (`_find_index_bias`,
a leading `sub wRd,wRn,#bias`) via a real reimplemented enum
(`GEOMapRegionSourceType`).

**Deliberately NOT covered by a fixture yet** — investigated while building
f11, findings kept here rather than re-discovered later:

* **`_harvest_isolated_compares` and `_harvest_cbz_value0`, RESOLVED (see
  below) — now covered by f16, gotcha 9** (the
  `cmp+b.eq`/`cmp+b.ne` and `cbz`/`cbnz` sparse-enum harvesters) could not be
  triggered with any natural ObjC/C source on THIS Mac's toolchain (Xcode
  15.4, Apple clang 15.0.0, `-Os`/`-O2`/`-O1`/`-Oz` all tried, ARC): every
  attempt at a small sparse case set (as few as 2 values, no dense cluster)
  if-converts to a branchless `csel` select chain instead of real
  conditional branches — tried a `switch`, an if/else chain, `const char*`
  vs `NSString*` returns, and an `asm volatile("")` barrier before each
  return. None produced a `b.eq`/`cbz`; the optimization-level sweep ruled
  out flags as the cause.

  **This does NOT mean the harvesters are unreachable in practice — checked
  against real data and confirmed working.** `locationd` (a standalone
  binary in this repo's `iphone8_data/`, so selectors resolve locally with
  no dyld shared cache needed) has two real small sparse enums,
  `ALSNearbyRequest.technologyAsString:` and `...wifiGranularityAsString:`.
  Disassembling them directly: `wifiGranularityAsString:` compiles to
  genuine `cmp+b.eq`/`b.ne` (exactly `_harvest_isolated_compares`'s target
  shape), and running `_extract_enum_values` against both recovers every
  value (3/3 and 4/4) exactly matching `tests/golden/locationd.json`. So the
  mechanism is real, needed, and correct on real Apple-compiled binaries —
  the gap is specifically that `locationd` was built against a different
  toolchain than is installed here.

  **Ruled out: any reasonably-obtainable public Xcode.** Tried Apple clang
  13.1.6 (Xcode 13.4.1), 14.0.3 (Xcode 14.3.1), and 15.0.0 (Xcode 15.4,
  this Mac's installed default) against the same `TwoVal`/`ZeroPlus`
  probes — all three produce byte-for-byte the same `cmp+csel` shape, no
  branches. Three clang releases spanning ~2021-2023 converging on
  identical codegen for this idiom makes a fourth (even older) download
  unlikely to pay off. `locationd`'s `LC_BUILD_VERSION` records SDK
  16.7.3 (a device-firmware-era build, not tied to any single public
  Xcode's bundled SDK number) — the real explanation is almost certainly
  Apple's INTERNAL (non-public) build toolchain, which diverges from every
  public Xcode release checked here regardless of era, not something a
  developer-facing Xcode download can reproduce.

  **CORRECTION (2026-09, later session): this "ruled out" conclusion was
  wrong** — it only tried clang releases from ~2021-2023 (13-15). A
  developer-facing Xcode download DOES reproduce it: Xcode 11.1 (clang
  11.0.0/clang-1100.0.33.8, 2019) and Xcode 8.0 (clang 8.0.0/clang-800.0.38,
  2016) both compile the exact same probe to genuine `cmp+b.eq`/`cbnz`, no
  `csel` — see gotcha 13 below. The if-conversion heuristic that defeats
  this shape was evidently introduced somewhere between clang 11 and clang
  13 (clang 12.0.0/Xcode 12.1 already if-converts), not something unique to
  Apple's internal toolchain after all. "Three releases spanning several
  years converging" was true but too narrow a sample — they were three
  releases from the SAME post-if-conversion era.

  **RESOLVED by f16_enum_isolated_compares — twice.** Originally via a
  technique one step beyond f3's separate-`.s`-file gotcha 6: GNU C named
  register variables pin a method's argument/return to the exact registers
  real ObjC codegen uses, and a single `__asm__ volatile` block hand-writes
  the branch body between them (gotcha 9). Superseded once gotcha 13 was
  found (see above): the fixture is now REAL COMPILED CODE (an old-clang
  switch statement), not hand-asm — gotcha 9 remains valid documentation
  for cases that genuinely need it (f17/f19/f20's direct-IMP-call gotcha 10
  needs, f21's padding), just no longer for this one.
  `_harvest_isolated_compares` and `_harvest_cbz_value0` both have direct,
  real-instruction-verified coverage (all 3 branch forms — `cbz`, isolated
  `b.eq`, isolated `b.ne` — recovered correctly). `enums.py`: 21% → 34%
  synthetic-only coverage.

* **Multi-segment sparse enums, RESOLVED (see below)**
  (`_harvest_jumptable_segments`, when a `switch` lowers to TWO OR MORE
  separate dense sub-range jump tables in one method — e.g. a real enum
  with two disjoint dense clusters) hit a reproducible issue while probing:
  this toolchain's `-Os` codegen
  tail-duplicates each segment's `ret` rather than funnelling every case to
  one shared epilogue, so the segments are laid out as independent blocks
  each ending in its own early `ret`. `_extract_jumptable_enum_values`'s
  initial disassembly (`disasm(ctx, imp, max_insns=_SPARSE_MAX_INSNS)`) uses
  the default `stop_at_ret=True`, so it stops at the FIRST such `ret` and
  never sees any segment laid out after it — silently, since
  `_disasm_truncated` only fires on a `max_insns` budget overrun, not an
  early-`ret` stop. Confirmed by tracing the decoder against a synthetic
  2-cluster probe (values 0-3 and 100-103): only the first-encountered
  segment's values were recovered, no truncation flag raised.

  Degrades safely at the FIELD level either way (the field keeps its correct
  number/wire type; only the recovered value NAMES are affected) — but
  within the enum's own value list the failure mode can be silent data
  corruption, not just an empty table: in one traced case the dropped
  segment's Idiom-B gate went unmatched, the code fell back to Idiom-A's
  backward scan, which grabbed a NEIGHBOURING segment's unrelated gate, and
  the resulting mis-biased values collided with (and were dedup-dropped
  against) that neighbour's already-recovered values — so the enum silently
  came back with values from only ONE of the two real segments, mislabelled
  as complete (this exact failure shape — a stale/neighbouring gate
  mis-attributing values — is why the file's own Idiom-B code exists at
  all; see its docstring's GEOLogMsgState example).

  **RESOLVED — checked against real data and confirmed NOT a real issue.**
  This repo's `iphone8_data/dylib/dyld_shared_cache_arm64` (+ subcaches +
  `.symbols`) turned out to hold the full dyld shared cache, which resolves
  exactly this: loading GeoServices via `macho.dyld_cache.DyldCacheReader` +
  `BinaryContext.from_cache` + `macho.local_symbols.apply_to_classes` (the
  same path `cli.py --framework GeoServices --cache iphone8_data/dylib`
  uses) fully resolves `GEOTelemetricEntity`'s selectors, and running
  `extract_proto_message` against the REAL `eventKeyAsString:` — the exact
  multi-cluster example named in this function's own docstring, 191 values
  across 10+ disjoint dense clusters — recovers all 191 values, an EXACT
  match against `tests/golden/GeoServices.json` (`gset == rset` verified
  directly). Disassembling it confirms why: every real case block ends in
  `b #<shared-epilogue-address>` (a plain unconditional branch to one common
  tail), never its own `ret`. Real Apple codegen funnels all cases to a
  single shared epilogue; only this repo's specific synthetic-toolchain
  probe (Xcode 15.4/clang 15.0.0) tail-duplicated each segment's `ret`
  independently — a compiler-version-specific artifact of the toy, not
  something real binaries do. No fix needed to the extractor.

  **Now ALSO has a repeatable synthetic fixture: f18_enum_multi_segment.**
  The real cache-extraction check above was a one-off verification against
  a real binary, not something that runs on every CI invocation the way
  this suite's fN_* binaries do. Originally closed that gap by hand-writing
  (gotcha 9 extended) the CORRECT shape directly — this repo's normal
  (Xcode 15.4) toolchain was assumed to be the only option and it
  tail-duplicates each segment's own `ret`, so f18 hand-wrote two
  independent jump-table segments (clusters 0-3 and 100-103) with every
  arm branching to ONE shared epilogue. Found one more gotcha while
  building that version (gotcha 11): the per-segment byte tables must live
  in a genuinely separate section (`.section __TEXT,__const`), not inline
  in the `.text` flow between segments — interleaved table bytes derail
  `disasm`'s linear walk when it crosses from one segment's arms into the
  next segment's raw data, silently truncating the instruction stream
  (confirmed: the probe's own `disasm(..., max_insns=1000)` call returned
  24 instructions instead of the true 45 before this fix).

  **Superseded once gotcha 13 was found (2026-09, later session): REAL
  COMPILED CODE, not hand-asm.** The "Xcode 15.4 is the only option"
  assumption was the same mistake as the isolated-compares "ruled out"
  correction above — Xcode 11.1 compiles the same plain 8-case switch to
  exactly the real shared-epilogue shape, no hand-asm needed. (Xcode 8.0
  does NOT work for this one specifically — it uses a different,
  unrecognised jump-table encoding; see f18's own fixture.m and
  build_fixtures.sh's build_fixture_oldxc for why Xcode 11.1 is
  standardised on.) All 8 values recover correctly.
  `enums.py`: 34% → 43% synthetic-only coverage.

### Detection added for both shapes (2026-09-27)

Even though neither shape has been observed on the real corpus checked so
far, both are now DETECTED (not recovered) so a binary that does hit one
gets a visible `values_truncated=True` — "may be INCOMPLETE" — instead of a
silently-short enum that looks complete:

* `_detect_unrecovered_csel_chain(insns, words)` — flags a `cmp+csel` chain
  (>=2 links, to stay conservative against an isolated unrelated `csel`)
  when no branch-based harvester recovered >=2 pairs. Only ever adds a flag
  to what would otherwise be an unflagged empty enum — cannot change output
  for any enum that already recovers pairs some other way.
* `_detect_unreached_branch_gate(insns, words)` — flags a `cmp+b.ls`/`b.lo`
  gate whose target lies past a window that stopped on `ret` (not the
  budget cap), which is exactly the shape that silently mis-attributed a
  whole segment's values in the traced `TwoClusters` case above (confirmed
  by re-running that exact probe: `truncated` flips `False` -> `True`, see
  `tests/test_enum_decoders_synthetic.py`). Applies regardless of how many
  pairs were already found, since a partial recovery from OTHER reached
  segments can otherwise mask a missed one.

Both are pure functions of `(insns, words)` — no binary/ctx needed — with
direct unit tests (hand-built ARM64 words, no real binary) in
`tests/test_enum_decoders_synthetic.py`. Verified safe against the real
corpus: all 3 golden-output regression tests
(`tests/test_golden_output.py`, exact-snapshot comparisons against
GeoServices/CoreLocationProtobuf/locationd) still pass unchanged, and a
direct census across all three real binaries' extraction confirms neither
detector currently fires anywhere in this repo's available corpus — this
is forward-looking defense for binaries not yet seen, not an active fix.

**Known residual gap, NOT caught by either detector**: a value that is
merely a "hole" inside an already-REACHED single jump table (as opposed to
an unreached SEGMENT) can still be silently dropped with no flag —
observed in one earlier synthetic probe (`TestSparseMsg`, a 30-entry table
where the isolated value `20` sits between reached entries `5` and the
table's end) and reproducible: `pairs=[0,1,2,5]`, `truncated=False`, value
`20` simply missing. Not investigated further — narrower and lower-priority
than the two shapes above, and (like the isolated-compares/csel-chain
finding) not yet confirmed to occur on any real binary checked so far.

### Extent-recompute fallback (TODO #58), f21 (2026-09)

`_extract_jumptable_enum_values` probes an `xAsString:` body with a cheap
1000-instruction `disasm`; if that doesn't close on `ret`, it recomputes the
real extent via `_function_body_extent` (up to a 40000-insn hard cap) rather
than trusting the truncated probe — the real motivating case is the
GeoServices LogMsg-family methods (~12k insns). Every fixture through f20
closes well under 1000 insns, so this path had zero synthetic coverage.

**f21_enum_long_body_extent** pads a real f11-shaped pointer-table switch
past the cap with 400 real, PLAIN C statements (`pad_sink += 1;` on a local
`volatile int32_t`) — REAL COMPILED CODE, no hand-asm at all (gotcha 14;
originally used `.rept 1100 / nop / .endr` hand-asm, gotcha 12, superseded
once the C version was found to work just as well). The recompute mechanism
itself is fully exercised and correct: the probe truncates at exactly 1000,
and `_function_body_extent` finds the true ~1200-insn extent closing on a
real `ret`. Found, not designed, replacing the padding: a GLOBAL padding
variable silently breaks the fixture (its `adrp+add` address collides with
the switch's own pointer-table base register — see gotcha 14); a LOCAL
stack variable doesn't.

**Found, not designed, while verifying this fixture: a real production gap,
not just a coverage gap.** The recomputed body's shape is
`_extract_enum_values`'s PROVEN POINTER-TABLE idiom, not a jump-table/segment
idiom, and none of `_extract_jumptable_enum_values`'s three harvesters
(`_harvest_jumptable_segments`, `_harvest_isolated_compares`,
`_harvest_cbz_value0`) know how to read a pointer table — that logic lived
only in the separate `_extract_enum_values`'s 80-insn primary probe, which
never got a second look at the longer, recomputed body. Net effect before
the fix: the field stayed correctly `ENUM:`-tagged (the selector resolves),
but the enum's value table came back empty with `truncated=False` — not a
lying flag (`truncated` is documented as meaning "the disasm PROBE ran out
of budget", which was false here), but a silently incomplete extraction all
the same, on a real, if untested-until-now, path.

**Closed by adding `_try_pointer_table_in`** (`proto/enums.py`): reuses the
same `_decode_ldr_reg_off`-based pointer-table read `_harvest_dictrep_enums`
already uses elsewhere in this file, applied to the already-disassembled
`insns`/`words` instead of a fresh short probe. The one real wrinkle:
`_find_field_count` and `_find_index_bias` both take a raw start VA and scan
forward a bounded number of words from it — calling them with `imp` (as the
existing pointer-table path does) would scan only the first few hundred
words of padding and never reach the real `cmp`/`sub` gate, so
`_try_pointer_table_in` re-anchors both scans near the LOCATED load instead
(the padding in between is harmless to skip over — neither `cmp` nor `sub`
matches a `nop`). All 3 values now recover correctly; verified end-to-end via
`extract_all`, not just the isolated function. `enums.py`: 74% → 77%
synthetic-only coverage.

## Dispatch core resolution coverage (2026-09, f20)

`proto/dispatch.py`'s thick-wrapper-vs-direct-core picker
(`_core_resolves_compare_chain`, used by `_locate_dispatch_arms` to decide
between a DIRECTLY-found candidate core and one discovered by scanning a
wrapper's body) was initially flagged as too CFG-intricate to attempt —
its confirmation gate (`_func_calls_own_method`) needs the SAME "direct
`bl` to a registered ObjC method's own IMP" shape the adder→ivar lever
needed, which was the whole reason that lever was abandoned in the first
place. Gotcha 10 (found while building f16/f17) unlocked both.

**f20_dispatch_wrapper_core_picker** covers it — and, while building it,
found a real decoder quirk worth documenting precisely: `_find_field_count`
scans up to 256 RAW WORDS from a function's start with no awareness of
function boundaries (no `ret` check at all), so calling it on a short
"thick wrapper" function can silently read straight through the wrapper's
own `ret` into whatever code happens to sit immediately after it in memory
— in this fixture's case, the real dispatch core's own range-check gate,
misattributing it to the wrapper. The net effect is still correct (the
mis-attributed `read_specified_va` gets checked by
`_core_resolves_compare_chain`, correctly fails since the wrapper itself
dispatches nothing, and the wrapper-discovered real core correctly wins)
— so this isn't a bug that changes any current output — but it means f20
ended up exercising the FULL symmetric "compare both candidates" picker
logic (the harder, real `GEOPDExternalAction`-shaped case) rather than the
simpler "trivially None" case it was originally designed around (real
`GEOPDBatchSpatialLookupResult`'s shape) — see f20's own fixture.m header
for the full trace. `dispatch.py`: 78% → 85% synthetic-only coverage.

## Repeated-field element-type recovery coverage (2026-09, f12/f14/f17)

`proto/repeated.py` resolves a repeated-message field's element type via
independent sources: the `+[Cls xyzType]` metaclass method
(dominant real-world path — f12), the readFrom: dispatch
walk (f2/f5/f8, already covered before this session), the element
class-reference lever (live GeoServices/locationd tests; no synthetic
fixture), and the
**adder→ivar lever** (`_resolve_repeated_element_ivars` / `_adder_array_ivar`
— f17, RESOLVED, see below).

**The adder→ivar lever was first tried and abandoned** (three C-level
constructions all failed to produce a `bl` straight to a registered ObjC
method's OWN IMP, bypassing `objc_msgSend`: a normal message send compiles
to a real selector stub, `objc_direct` removes the method from the class's
method list entirely, `-flto` still routes through a PLT-style
`objc_msgSend` stub) — then **RESOLVED by f17_repeated_adder_ivar_lever**
once gotcha 10 was found while building f16: an ObjC method implementation
is a real (if local/non-exported) linker symbol, so a statement-level
`__asm__` block calling it BY NAME from within the same translation unit
bypasses `objc_msgSend` entirely, confirmed by disassembly (`bl` lands
exactly on the real IMP address). Verified directly (not inferred): calling
`_resolve_dispatch_context` on the fixture returns
`dispatch_ivars == {'_items': ('TestAdderElem', 7)}` — the lever's own
internals now run and compute correctly for the first time in this suite.
`repeated.py`: 75% → 84% synthetic-only coverage. See f17's own fixture.m
for the honest caveat about what's observably verified vs. what merely
runs (its single arm also satisfies the already-covered by-field-number
path, which wins ties, so the field's reported TYPE doesn't distinguish
the two paths — only the direct `dispatch_ivars` check does).

## Gotchas (read before writing a new fixture)

These are real, non-obvious requirements discovered while building the first
two fixtures. Skipping any of them produces a fixture that silently degrades
(wrong field numbers, undetected class, etc) rather than an error.

1. **Link against a real (if trivial) dylib**, never `-undefined
   dynamic_lookup`. The latter makes `ld64` emit legacy `LC_DYLD_INFO_ONLY`
   binds instead of `LC_DYLD_CHAINED_FIXUPS`; the extractor's binary-mode
   superclass resolution (`macho/memory.py:import_name_for_bind`) requires
   chained fixups to identify the class's `PBCodable` superclass at all.
   `build_fixtures.sh` always links fixtures against `shim/libpbshim.dylib`.

2. **Has-bits ivar members must be `has_<field>` / `read_<field>`**
   (snake_case, literal underscore). `proto/protocore.py:_is_proto_flags_ivar`
   string-matches the struct encoding's opener; camelCase (`hasField`)
   silently fails detection.

3. **Field write/read calls are plain C-linkage function calls**
   (`x0=writer/self, x1=value, w2=tag`), never ObjC message sends. Confirmed
   by disassembling a real `GEOPDAdamAppIdentifier.writeTo:` from a live
   GeoServices dyld cache: Apple's actual generated code `bl`s a helper
   directly, no `objc_msgSend`. An ObjC message send instead puts the tag in
   `w3`, which `proto/writeto.py`'s field-number walker never reads.

   Symmetrically for `readFrom:`: each class's C-level "ReadAllFrom core"
   must be its own **out-of-line, `__attribute__((noinline))`** function.
   clang at `-Os` will happily inline a small core straight into its ObjC
   `readFrom:` wrapper, erasing the `bl` that
   `proto/dispatch.py:_find_readfrom_c_func` looks for — see
   `f2_readfrom_element_type/testelement.h`.

4. **Compile at real optimization (`-Os`)**, not `-O0`. At `-O0`, ARC
   repeatedly spills/reloads `self` from the stack instead of keeping it
   live in one callee-saved register for the whole method, which breaks the
   CFG walk's ivar-binding logic.

   Even at `-Os`, compiler idiom is not fully predictable: a naive
   single-arm `if (field == N)` check in a readFrom dispatch core gets
   const-folded into a masked compare (`and w8,w0,#~7; cmp w8,#N*8`) instead
   of materializing `lsr Wf,Wtag,#3`, which the dispatch decoders
   (`proto/dispatch.py`) require to see literally. Fix: give the dispatch
   core ≥2 arms plus an opaque fallback call that uses the raw field value
   (see `f2_readfrom_element_type/testcontainer.m`), which gives clang a
   reason to materialize the real shift once and reuse it.

   **Always disassemble a new or edited fixture and visually check it
   against the target code path's expected instruction shape before trusting
   it** — don't assume the C source compiles to the intended pattern. See
   the ad hoc verification snippets used while building f1/f2 (load via
   `swift_descriptor_extract.load_macho_slice` +
   `macho.memory.BinaryContext`, disassemble with `macho.disasm.disasm`).

5. **Always run the extractor via `./venv/bin/python3`** (capstone
   installed), never plain system `python3`. The system interpreter's native
   fallback decoder silently mis-renders `tbz`/`tbnz` and register-offset
   loads as `unk`, breaking CFG traversal with no error message.

6. **Some recovery mechanisms need EXACT instruction shapes clang won't
   reliably reproduce from C source — write those functions in hand-assembled
   arm64 (`.s`, real toolchain-assembled machine code, not hand-packed Mach-O
   bytes) instead.** `proto/write_helpers.py:_classify_write_helper` scans a
   write-helper function's own disassembly for a specific zigzag shift
   (`lsl w1/x1,#1`) or tag-build (`mov w_,#5|#1; bfi w_,w2,#3,#0x1d`) — these
   are Apple runtime internals, not code a fixture's own C source naturally
   produces, and (unlike gotcha 4b, which was fixable by restructuring the C)
   there's no C idiom that reliably forces clang to emit them. `f3_write_
   helper_family` hand-assembles its four helpers (`shim/pbwiretypes.s`) and
   links them **directly into that fixture's own executable**, not the shared
   shim dylib — `_classify_write_helper`'s stub-follow only recognizes
   ProtocolBuffer.framework's specific 12-byte `adrp/add/br` PLT shape, which
   a standard `ld64` cross-dylib call does not produce; keeping the helper
   local exercises the "direct (non-stub) helper" fallback instead, matching
   how standalone `--binary` mode always resolves these in practice (the
   stub-follow path is cache-native-only).

   Not every Tier-3-shaped mechanism needs this treatment, though — jump-
   table dispatch codegen (`f5_jumptable_dispatch`) turned out to compile
   naturally from a real `switch` statement at `-Os` on the first attempt (an
   8-case switch on a densely-numbered field range); it was verified by
   disassembly before being trusted, per gotcha 4b, not assumed. Try real C
   first; only fall back to hand-assembly when disassembly shows the compiler
   won't cooperate.

7. **`extract_all()`'s returned `ProtoMessage.name` has the configured ObjC
   class prefix (`proto/defaults.py:DEFAULT_PREFIXES` — `GEO`/`CLP`/`CLM`/
   `CLN`) already stripped** — a class named `GEORouteIncident` shows up in
   the dict keyed by `m.name` as `"RouteIncident"`, not `"GEORouteIncident"`.
   This tripped up the first `f6` verification run: a lookup by the full
   original class name silently missed, and (because the pre-existing
   `_check_selectors_resolved` warning about `readFrom:` not being locally
   declared looked superficially relevant) it briefly looked like a real
   bug. It wasn't — the extraction was correct throughout; only the lookup
   key was wrong. A FIELD's `type_name`/`type_class` is unaffected (still the
   full original class name, e.g. `"GEOLatLng"`, since that comes straight
   from the referencing ivar's own `@encode`, not from the display-name
   strip) — only the top-level `ProtoMessage.name` for a prefixed class is
   stripped. `expected.py` for a fixture using a real Apple class name must
   key its `EXPECTED` dict by the STRIPPED name.

8. **An enum-typed field's `xAsString:`/`StringAsX:` method must be declared
   as a plain ObjC INSTANCE method on the class itself, not a `+` class
   method on its metaclass** — for a `--binary` (standalone) fixture.
   `proto/protocore.py:_type_from_enc` decides whether a scalar `int32`/
   `uint32` ivar is enum-shaped by checking `instance_method_names`, built
   from `{m.name for m in cls.methods}` — the class's OWN (non-meta)
   `ObjcClass` record. A class method lives on a SEPARATE metaclass
   `ObjcClass` record (`macho/classlist.py` never merges the two lists), so
   a `+xAsString:` there is invisible to this check and the field is never
   tagged `ENUM:` at all — it stays a plain `int32`, and none of
   `proto/enums.py` ever runs. (`_collect_enum_definitions`'s later lookup
   DOES check both `cls.get_method` and `metaclass.get_method` when
   resolving an already-tagged field's method IMP — but by then the ENUM:
   tag must already exist, which only `_type_from_enc`'s instance-method
   check can set for a `--binary` fixture; real GeoServices/CLP/locationd
   binaries are typically extracted in shared-cache mode instead, where a
   separate methname-string-table scan tags the field independent of this
   instance/class distinction — see `_collect_enum_definitions` Phase 1.)
   Verified empirically (a probe binary) before writing f11.

9. **When no C/ObjC source construction produces the instruction shape a
   mechanism needs (compiler if-conversion, missing idiom, etc.), GNU C
   named register variables let you hand-write the exact shape INSIDE a
   normal `@implementation` method body** — a lighter-weight alternative to
   f3's separate hand-assembled `.s` file (gotcha 6), usable whenever the
   target mechanism is a single METHOD's body rather than a helper function
   linked in from outside:

   ```objc
   - (NSString *)statusAsString:(int32_t)value {
       register int32_t v asm("w2") = value;   // pin the arg to its real ABI reg
       register id ret asm("x0");               // pin the return to x0
       __asm__ volatile (
           "cbz %w1, 0f\n"
           ...
           : "=r"(ret) : "r"(v) : "cc"
       );
       return ret;
   }
   ```

   `asm("w2")`/`asm("x0")` pin the variables to the EXACT registers real
   ObjC codegen uses for a 1-int-arg method (self=x0, _cmd=x1, value=w2,
   return=x0, per AAPCS64) — matching every compiler-generated
   `xAsString:` in this suite — so the `__asm__` block can assume they're
   already correctly placed. The compiled method still registers exactly
   like a normal one (`cls.get_method(...)` finds it via the standard
   `@implementation`-driven method-list metadata) — no symbol-name tricks
   needed, unlike gotcha 6b below (which a DIFFERENT constraint — calling
   INTO a method from OUTSIDE it — does need). Any C-level symbol the
   `__asm__` block references by name (e.g. a `static const char[]`
   string constant) needs `__attribute__((used))`: the compiler can't see
   asm-block references and will otherwise dead-strip them, producing a
   confusing "Undefined symbols" LINK error that looks unrelated to the
   real cause. See f19_enum_dictrep_switch for a full working example
   (f16_enum_isolated_compares originally demonstrated this technique too,
   before gotcha 13 replaced it with real compiled code — see that
   fixture's own git history if you need the hand-asm version as a
   reference).

10. **An ObjC method implementation is a real (if usually LOCAL/`t`, not
    exported) linker symbol — `-[ClassName selector:withArgs:]` literally —
    so a `bl` to it FROM WITHIN THE SAME TRANSLATION UNIT can bypass
    `objc_msgSend` entirely, even without `objc_direct`.** Verified via
    `nm`: a normal `@implementation` method shows up as e.g.
    `0000000100004014 t -[TestAsmAdder _addNoFlagsItem:]` — and a
    module-level `__asm__(".globl _foo\n_foo:\n bl \"-[Cls sel:]\"\n
    ret\n")` in the SAME `.m` file resolves that `bl` to the exact IMP
    address, confirmed by disassembly (`bl #<the real IMP>`, not a
    selector-stub trampoline). This does NOT work across separate `.o`
    files (the symbol is local, so a genuinely separate hand-assembled
    `.s` file linked in afterward — f3's style — can't see it; the caller
    must live in the same `.m`). This is the technique three previously
    "impossible via public clang" mechanisms turned out to need — see f17
    (repeated.py's adder→ivar lever) and f20 (dispatch.py's thick-wrapper-
    vs-direct-core picker) for worked examples.

11. **Per-segment jump/lookup TABLE DATA embedded in an `__asm__` block
    must live in a genuinely separate section**
    (`.section __TEXT,__const\n...\n.text\n`), never inline in the `.text`
    flow between two segments' code. `disasm`'s linear walk has no way to
    know raw `.byte` table bytes aren't instructions — crossing from one
    segment's arms into the next segment's inline table data decodes the
    table as garbage instructions and can silently truncate the
    disassembled stream well before the function's real end (confirmed:
    an inline-table draft of f18 made `disasm(ctx, imp,
    max_insns=1000)` return 24 instructions instead of the true 45,
    before this fix — verify with exactly that kind of length check, not
    just "did it build", whenever an `__asm__` block mixes code and data).
    This matches real Apple codegen anyway: a real multi-segment method's
    table `adrp` targets a genuinely different PAGE than its code (verified
    on `GEOTelemetricEntity.eventKeyAsString:` earlier this session), never
    inline data in the same instruction stream.

12. **To force a real disassembly-budget cap (e.g. a >N-instruction probe)
    inside a HAND-WRITTEN `__asm__` sequence**, use the GNU assembler's
    `.rept COUNT` / `.endr` directive — `.rept 1100\n nop\n .endr\n` emits
    exactly 1100 real `nop` instructions from one 3-line source block,
    far cleaner than writing them out by hand. `volatile` prevents `-Os`
    from reordering or eliding it relative to surrounding C code in the
    same function. f21 originally used this (superseded by gotcha 14 —
    real compiled code turned out to work better here); still the right
    tool whenever the padding needs to sit INSIDE a hand-written
    instruction sequence (combine with gotcha 9's named-register
    technique), where plain C statements aren't an option at all.

13. **A shape "unreachable via any C/ObjC source construction on public
    clang" may just mean "on the specific clang version tried"** — the
    isolated-compares and multi-segment findings above both originally
    concluded this was Apple's INTERNAL toolchain diverging from every
    public release (having tried clang 13.1.6/14.0.3/15.0.0, a
    ~2021-2023 span). Wrong: Xcode 11.1 (clang 11.0.0/clang-1100.0.33.8,
    2019) and Xcode 8.0 (clang 8.0.0/clang-800.0.38, 2016) both reproduce
    the real branch/shared-epilogue shapes from a PLAIN switch statement,
    no hand-asm needed — the if-conversion/tail-duplication heuristics
    that defeat these shapes were introduced somewhere between clang 11
    and clang 13 (clang 12.0.0/Xcode 12.1 already if-converts to `csel`),
    not something unique to Apple's non-public build. The lesson: a few
    releases from the SAME few-year window all agreeing is not the same
    evidence as trying something genuinely older. Xcode 11.1 is the
    version actually used (Xcode 8.0 works for isolated-compares but
    produces a different, unrecognised jump-table encoding for the
    multi-segment case — see f18's fixture.m).

    The old clang's OWN linker can't be used, though — it predates
    "chained fixups" (this tool's only supported pointer-fixup format;
    still absent even from Xcode 12.1's linker, checked directly) and
    links with classic bind/rebase opcodes instead, which `macho/memory.py`
    does not parse at all — an old-clang-LINKED executable's
    ivar-offset/superclass pointers come back completely unresolved
    (`superclass_vmaddr == 0`) and `extract_all` refuses to run
    ("proto-class detection FAILED STRUCTURALLY"). Fix: the LINKER decides
    the fixup format, the COMPILER decides instruction-level codegen —
    independent axes — so compile the `.m` to a `.o` with the OLD clang,
    then link that `.o` with THIS environment's normal (modern,
    chained-fixups) clang/ld, never with the old clang's own linker. See
    `build_fixtures.sh`'s `build_fixture_oldxc` for the implementation.

    Verifying against REAL compiled output (not hand-asm that happened to
    sidestep the issue) can surface genuine production gaps hand-asm
    never would have found: building f16/f18 this way found that
    `_harvest_isolated_compares`, `_harvest_cbz_value0`, and
    `_read_case_string` all hardcoded register `x0` for a case block's
    return value, but real ARC codegen often computes it into a
    callee-saved register first (surviving the subsequent
    `objc_autoreleaseReturnValue` call) — see `_isolated_value_target` in
    `proto/enums.py`. And `_writeto_field_number_before` assumed the
    field-number `mov` always immediately precedes a field-write `bl`,
    but an independent instruction scheduler can swap it with the
    adjacent (unrelated) argument-setup `mov` — see the same function in
    `proto/writeto.py`. Both were real, narrow, low-risk widenings
    (verified against the full golden-output regression before trusting
    either), not fixture-specific hacks.

14. **Real C code can pad a function past a length threshold too — no
    `__asm__` needed at all — but a GLOBAL padding variable is a real
    footgun.** A local `volatile int32_t sink = 0;` followed by many
    `sink += 1;` statements forces genuine, unremovable instructions
    (`ldr`/`add`/`str` on the stack, `[sp,#off]`) the same way gotcha 12's
    NOP block does, with zero hand-asm (see f21). But a FILE-SCOPE
    `volatile` global breaks this silently: the compiler addresses a
    global via `adrp xN,#page; add xN,xN,#off` ONCE and reuses that
    register for the rest of the padding, and if the SAME register number
    later gets reused by the real code that follows (e.g. a pointer-table
    base — register allocation, not a deliberate choice), any helper that
    resolves `adrp+add` by "first match in the window" (`find_adrp_add_target`,
    used throughout this codebase) silently returns the PADDING variable's
    address instead of the real target's — no error, no exception, just an
    empty or wrong result. A LOCAL (stack) padding variable never has this
    problem: it never emits `adrp`/`add` at all. Prefer local `volatile`
    padding over global whenever it's an option, and if a fixture's real
    values come back empty or wrong after adding filler code of ANY kind
    (asm or C), check whether the filler and the real logic ended up
    sharing a register before assuming a decoder bug.

## Adding a new fixture

1. Write the `.m`/`.h` source in a new `fN_<name>/` directory, importing
   `pbshim.h`.
2. Add a build target to `build_fixtures.sh`.
3. Build it (`./build_fixtures.sh fN_<name>`) and disassemble the result to
   confirm it matches the intended instruction shape (gotcha 4) — iterate on
   the C source until it does, rather than assuming the first attempt worked.
4. Run the extractor against it directly (`../../cli.py --binary fN_<name>/x
   -v`, via `./venv/bin/python3`) and confirm the output matches your
   intended ground truth before writing `expected.py`.
5. Write `expected.py` as the documented ground truth (not a copy of
   whatever the tool printed).
6. Add the fixture to `_FIXTURES` in `tests/test_synthetic_fixtures.py`.
7. Commit the source AND the compiled binary together.

## Deferred (scoped, not built)

One more mechanism would benefit from a real-compiled fixture but was
judged out of scope for the current pass — noted here so the next session
doesn't have to rediscover the reasoning:

* **~~Enum value-table (dictRep) recovery~~ — RESOLVED by f19, and the
  original framing below was wrong.** This note originally described the
  target as "`+<field>AsString:`/`StringAsX:` ... resolves enum value
  names from an `NSDictionary`-literal construction pattern in the
  metaclass method body" and judged it out of scope as too compiler-
  fragile. That's not what `_harvest_dictrep_enums` actually does (grep
  confirms: no `NSDictionary`/dictionary-literal reference anywhere in
  `proto/enums.py`) — the real mechanism is a JUMP-TABLE or POINTER-TABLE
  dispatch inside `-[Class _dictionaryRepresentation:]` (a *different*,
  unrelated method from `xAsString:`), keyed by the field's IVAR OFFSET
  via the same ivar-offset-table mechanism every other fixture's ivar
  access already relies on — structurally identical to f11/f16/f18's
  already-solved enum harvesters, not compiler-literal-fragile at all.
  f19_enum_dictrep_switch covers both idioms. `enums.py`: 9% → 65%
  synthetic-only coverage across this session (f11, f16, f18, f19).
* **xfail tracker for the known compare-chain field-number mis-attribution
  bug** (see project memory `compare-chain-fieldnum-bug.md`): writeTo:
  numbers are correct, but the compare-chain dispatch *decoder* can
  mis-attribute them on forward-branch layouts (stale `current_field`
  tracking). Currently latent — the one place that consumes compare-chain
  output (the adder→ivar lever) is type-only, not number-consuming — so
  there's no live bug to regress-guard yet. Worth a fixture (and an
  `expectedFailure`) if/when that lever grows a number-consuming caller,
  or if someone wants to fix the decoder proactively.
