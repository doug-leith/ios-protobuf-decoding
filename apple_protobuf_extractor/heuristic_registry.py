"""
Consolidated heuristic registry joined against per-FUNCTION entry counts from
heuristic_freq.py.  Frequency = number of times the enclosing function was
entered (one entry == one consultation of that code path).  Robust to line drift.

Where one function hosts several distinct heuristics, they share the function's
entry count; a note flags that.  judgment:
  REPLACE     — a principled signal may be available (the focus)
  INTRINSIC   — binary genuinely doesn't encode the fact; heuristic unavoidable
  PRESENTATION— a naming/formatting policy applied to an already-recovered fact
                (the data is correct; only the human-facing label is a convention,
                and being "wrong" is cosmetic — no wire/value/decoding impact)
  PRINCIPLED  — already reads ground truth (listed for context)
  ISA         — pure ARM64/Mach-O decode (deterministic; not really a heuristic)
"""
import json
import os
from collections import defaultdict

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # repo root (one above apple_protobuf_extractor/)
E, M = "proto/extractor.py", "proto/emitter.py"
# The proto.extractor monolith was split (2026-06-10) into focused units; the
# functions below moved out of proto/extractor.py.  File refs updated 2026-06-11
# so the per-FUNCTION frequency join (keyed on the function's *defining* file)
# resolves again.  proto.extractor re-imports most of these, so runtime callers
# are unaffected — only this audit table needed the path correction.
REP, WT = "proto/repeated.py", "proto/writeto.py"
EN, DSP = "proto/enums.py", "proto/dispatch.py"
PC = "proto/protocore.py"
# Retired non-structural proto-class detectors, carved out of protocore 2026-07-21.
PCH = "proto/protoclass_heuristic.py"
MEM, DIS = "macho/memory.py", "macho/disasm.py"
CLF, DC = "macho/classlist.py", "macho/dyld_cache.py"
LS, ST = "macho/local_symbols.py", "macho/strings.py"
# Added 2026-06-13 (deep-scan audit): modules that previously had ZERO registry
# rows, plus the proto data/config units.  See DEEP_SCAN below.
WH, CONF = "proto/write_helpers.py", "proto/config.py"
ACFG, AD = "proto/arm64cfg.py", "macho/arm64decode.py"
CCL = "macho/cache_classlist.py"
MOD, DEF = "proto/models.py", "proto/defaults.py"
# Foreign-serializer extractors (added 2026-06-14, swift/C++ deep-scan audit).
# C++ is a LITERAL descriptor decode -> no estimates (one PRINCIPLED context row);
# swift splits number/name (nameMap) from name/type (__swift5_fieldmd), so it makes
# several estimates (LIM 10).  These root-level modules have no freq data -> count 0.
SW, STR = "serializers/swift_descriptor_extract.py", "serializers/swift_type_recovery.py"
CPP, FGN = "serializers/cpp_descriptor_extract.py", "proto/foreign.py"

# id, file, function-name, display-name, judgment, shared?
#
# REPLACE-row taxonomy.  The largest cluster — GROUP A, marked "[#42]" in the
# display name — is the readFrom element-type + estimated-number family.  Its planned
# principled fix, the CFG/dominator readFrom dispatch resolver (TODO #42/#43), LANDED
# 2026-06-13 — but BYTE-IDENTICALLY: dominance reproduced production output exactly and
# did NOT widen the resolver's REACH, so the residual rows survive and are now ACCEPTED
# LIMITATIONS (LIMITATIONS.md), not pending work.  #42 DID delete one guard
# (degenerate-partition, now a PRINCIPLED DONE-breadcrumb), leaving SIX live Group-A
# REPLACE rows in two kinds (the GUARDS kind was fully retired), each tagged in its
# display name with its LIMITATIONS.md entry + to-do:
#   FALLBACKS — name-suffix element-type GUESS when the dispatch yields no signal:
#     namesuffix-s2, resolve-namesuffix, pool-suffix, s1-selsynth  [LIM 7 / to-do #45].
#     Residual = metadata-sparse classes the binary never names at the field site
#     (INTRINSIC); flagged inline in the output.
#   GUARDS — both retired: degenerate-partition DELETED by #42; core-picker became
#     PRINCIPLED 2026-06-14 (the dispatch-core gate IS now the selector — applied
#     symmetrically to both candidate cores; see its row below).
#   SYMPTOMS — emitter/extractor give-ups: ordinal-fieldnum (the estimated field number)
#     [LIM 4 / to-do #52]; typeref-bytes (unresolved class -> bytes) [LIM 1 map residual / #41 +
#     LIM 2 repeated / #37].  (disp-rr-tiebreak was here until 2026-06-14 -> now
#     PRINCIPLED: the precedence keys on _rr provenance, census-verified.)
# Non-Group-A REPLACE rows: the Tier-3 scan-budget caps (cap-*, value-independent-bound
# targets like #40/#58), and the Group-D name-shape rows (field-label, real-field-ivar;
# principled signal = the writeTo/readFrom serialization walk).  (enumbase-regguess was
# here until 2026-06-14 -> removed; the scaled-index decode covers it, 0x firing.)
# (protoclass RETIRED from REPLACE 2026-06-14 -> PRINCIPLED; see its block below.)
#
# REPLACE <-> LIMITATIONS.md cross-ref (KEEP IN SYNC with that file's source-site lines):
#   LIM 1  map<> residuals       (#41) ... typeref-bytes  (map recovery itself is principled: no row)
#   LIM 2  repeated -> bytes     (#37) ... typeref-bytes
#   LIM 4  field# 0 estimate     (#52) ... ordinal-fieldnum
#   LIM 7  name-suffix element   (#45) ... namesuffix-s2, resolve-namesuffix, pool-suffix, s1-selsynth
#   LIM 3 (#35), LIM 5 (#50), LIM 6 (#57) have NO REPLACE row — extractor/emitter-level limits.
#   LIM 10 swift cluster — now largely CLOSED (2026-06-15):
#     10a (#63a) swift-singlefield-num -> PRINCIPLED (two-source cross-confirm).
#     10b (#63b) swift-int-subtype -> the ONLY live swift REPLACE; signal verified
#         (traverse Visitor witness slot) but DEFERRED — unreachable in cache mode
#         (no traverse symbol) and exercised only by SwiftProtobuf library plumbing
#         types in binary mode, never an app schema (like GPB: unexercised by data).
#     10c (#66) swift-mangle-fallback -> INTRINSIC: run-length map decoded (#66) +
#         container fillers now FLAGGED via type_note (#67), no longer silent.
#     10d (#67) swift-name-join -> INTRINSIC: type-map now QUALIFIED-name keyed (#68),
#         collision hazard fixed; per-field name match stays intrinsic.
#     10e (#68) swift-repeated-label -> PRINCIPLED: label preserved + symref elements
#         resolved via raw-byte prefix detect (#69).
#     Plus swift-fieldtypes (PRINCIPLED): COW _StorageClass + OneOf_* type recovery (#60).
#     LIM 8 (GPB) / 9 (lite) are DETECT-ONLY, no schema emitted -> NO row.
#   REPLACE rows with NO LIM (internal residuals): NONE remaining.  Every surviving
#     REPLACE row is tied to a documented accepted limitation (LIM 1/2/4/7 + swift 10b).
# CURRENT LIVE REPLACE COUNT = 7: namesuffix-s2, resolve-namesuffix, pool-suffix,
#   s1-selsynth (LIM 7 / #45 — repeated-element name guess, INTRINSIC residual);
#   typeref-bytes (LIM 1/2 / #41+#37); ordinal-fieldnum (LIM 4 / #52);
#   swift-int-subtype (LIM 10b / #63b, deferred-unexercised).  ALL are accepted
#   limitations with a safe/flagged fallback — none is an open silent-guess to fix.
REGISTRY = [
    # namesuffix-s2 / resolve-namesuffix / pool-suffix (REPLACE-audit 2026-06-12, all
    # STAY REPLACE -> TODO #45): the residual name-suffix GUESS for a repeated field's
    # element type when no readFrom signal exists.  Principled fix = the readFrom
    # dispatch resolver (#42/#43) binds the element type structurally; the true residual
    # after that is metadata-sparse classes (0 ObjC methods) where the binary genuinely
    # doesn't name the element at the field site (INTRINSIC slice — flag it).  NOTE
    # pool-suffix's pool-match + write-helper-string refinements ARE ground truth (keep);
    # only its Strategy-2 base candidate is the guess.
    ("namesuffix-s2", REP, "_repeated_element_type", "[#42] Strategy 2: name-suffix classlist match (repeated element type) [LIM 7 / to-do #45]", "REPLACE", True),
    ("resolve-namesuffix", REP, "_resolve_repeated_type", "[#42] resolves a name-suffix-matched / +xyzType selector to its class (name passthrough or IMP-disasm); safe FLAGGED bytes give-up on failure. (The unguarded name-suffix guess HERE was removed 2026-06-09; uniqueness is guarded in the caller _repeated_element_type.) [LIM 7 / to-do #45]", "REPLACE", False),
    ("pool-suffix", REP, "_resolve_repeated_field_type", "[#42] pool-suffix exact-match refinement + write-helper string [LIM 7 / to-do #45]", "REPLACE", True),
    # protoclass: the DETECTOR is extractor._proto_class_set, a ground-truth
    # PBCodable/PBRequest/PBResponse superclass-chain closure.  RETIRED from REPLACE ->
    # PRINCIPLED 2026-06-14: the name-anchor (closure anchor 1) is now the PRIMARY
    # detector in BOTH modes, so _is_proto_class is no longer load-bearing anywhere —
    # it is retained only as the union floor (never drops a hit) + the sanity superset.
    #   What changed: in binary/standalone mode the superclass slot is an undecoded
    #   chained-fixup BIND whose low bits are the import ordinal; that ordinal resolves
    #   through THIS binary's own LC_DYLD_CHAINED_FIXUPS imports table to the symbol NAME
    #   `_OBJC_CLASS_$_PBCodable` (memory.import_name_for_bind + extractor._resolve_class_name_at).
    #   So the name-anchor now works WITHOUT cross-image reads — identical logic to the
    #   cache-mode anchor, just sourced from the import table.  Verified: with the
    #   _is_proto_class seed DISABLED the name-anchor alone reproduces the full set across
    #   the iphone8 libexec corpus (258 standalone binaries, 391==391, 0 mismatch; geod=0;
    #   locationd 65==65) and all 3 golden artifacts are byte-identical.  (Fixing the bind
    #   path also corrected a pre-existing off-by-one in the import name_offset decode:
    #   >>8 front-truncated every symbol; now >>9 per the lib_ordinal:8,weak_import:1,
    #   name_offset:23 bitfield.)
    #   RESIDUAL (why the heuristic floor is KEPT, not deleted): in pure binary mode the
    #   anchor can only see a class's DIRECT superclass name; it cannot walk into another
    #   framework, so a class whose super is itself an EXTERNAL non-root PBCodable subclass
    #   would be missed by the name path alone.  That case does not occur in the 258-binary
    #   corpus (every proto class subclasses a true root directly), but the ivar-score seed
    #   remains as the safety floor for it.  Earlier related rows still apply: _is_proto_class
    #   primary path = _is_proto_flags_ivar, tightened 2026-06-14 to match the flags-struct
    #   OPENER ({?="has_/{?="read_) not a loose substring (a kernel nstat_* bitfield false-
    #   matched -> seed poison -> VA-cluster blew SymptomNetworkUsage 4->28); the depth=8
    #   walk cap lives on protoclass-gate; the {_reader,_readerLock} proxy is protoclass-reader.
    #   CACHE-MODE MEASUREMENT (2026-07-19): the 258-binary result above only covered binary
    #   mode; ran the equivalent isolation live against the GeoServices CACHE (1642 classes,
    #   the richest corpus this project has). Reimplemented the anchor-1 name/bind walk
    #   standalone — single pass, depth=8, ZERO heuristic seed, ZERO VA-cluster closure at
    #   all (not even the closure-over-anchor1-output that _proto_class_set's own anchor-2
    #   block would still perform when the seed is merely disabled) — and diffed it against
    #   the full union: 1642==1642, 0 missing, 0 extra, and all 5 of the metadata-sparse
    #   subclasses (GEOAnalyticsPipelineSharedStateData, GEOComposedWaypointEVStop, GEOSearch-
    #   Request, GEOSearchResponse, GEOCLPLocationCollectionRequest) that motivated adding the
    #   two anchors in the first place were found by anchor 1 ALONE, no heuristic involved.
    #   So across BOTH datasets ever measured — 391 classes/258 binaries in binary mode, 1642
    #   classes/1 framework in cache mode — the heuristic seed has never once been the reason
    #   a real class got classified as proto; its measured contribution to date is exactly
    #   zero. RUNTIME TRANSPARENCY (added same day): rather than resting on that measurement,
    #   _proto_class_set now also stamps the (so far always empty) sets of classes whose
    #   proto-ness rests on a NON-STRUCTURAL path, and extract_proto_message threads them into
    #   ProtoMessage.class_detected_by_{heuristic,va_cluster} for the emitter to render inline.
    #   So the floor is retained as a safety net AND is no longer a SILENT one: the day a real
    #   binary needs it, the output says so, per the project's general policy of never letting
    #   an estimate/heuristic pass through unflagged. Output-neutral on all 3 golden artifacts
    #   (both flags are false everywhere in them, matching the measurement above).
    #   ESCALATED TO ERROR (2026-07-21, owner request): both paths now emit `// ERROR: ...`
    #   (models.HEURISTIC_CLASS_DETECTION_COMMENT / VA_CLUSTER_CLASS_DETECTION_COMMENT), not an
    #   informational note — given the measurements above, class detection by either path
    #   SHOULD NEVER HAPPEN, so if it does the structural detector has failed and the class may
    #   not be a protobuf message at all. The two causes are stamped SEPARATELY
    #   (ctx._proto_class_heuristic_only = claimed by the _is_proto_class seed alone;
    #   ctx._proto_class_cluster_only = claimed by the anchor-2 VA-cluster closure and never
    #   confirmed by the anchor-1 name walk) so the error names the actual failing path.
    #   NOTE the split changed _proto_class_heuristic_only's meaning: it previously covered
    #   BOTH causes (it was `proto - anchor1_names`), and is now seed-only.
    #   CODE MOVED (same day): both retired detectors now live in proto/protoclass_heuristic.py
    #   — _is_proto_class and va_cluster_closure (anchor 2, lifted out of _proto_class_set)
    #   plus _SYSTEM_ROOT_NAMES and the check_no_heuristic_detection failure gate. Kept, not
    #   deleted: the residual shape below (external non-root PBCodable superclass in binary
    #   mode) is still unproven-absent, so the code stays available for investigation behind
    #   MACHO_ALLOW_HEURISTIC_PROTO_CLASSES=1. What REMAINS in proto/protocore.py is only what
    #   is load-bearing for FIELD work regardless of detection: _is_proto_flags_ivar (also
    #   excludes the has-bits struct from the field set) and _REQUIRED_INSTANCE_METHODS.
    ("protoclass", PCH, "_is_proto_class", "RETIRED detector, moved to proto/protoclass_heuristic.py and now HARD-FAILS the run if it is ever the sole claimant of a class (MACHO_ALLOW_HEURISTIC_PROTO_CLASSES=1 to investigate). Retained union floor + sanity superset for the PBCodable forward scan (no longer the primary detector in any mode — name-anchor via import_name_for_bind is primary in binary mode too as of 2026-06-14). Primary score path = _is_proto_flags_ivar (flags-struct OPENER match).", "PRINCIPLED", True),
    ("protoclass-gate", E, "_proto_class_set", "PBCodable superclass-chain closure gate; magic depth=8 walk cap. Anchor 2 (VA-cluster) moved to protoclass_heuristic.va_cluster_closure and now HARD-FAILS the run if it is the sole claimant of a class", "PRINCIPLED", False),
    ("protoclass-reader", PCH, "_is_proto_class", "tertiary {_reader,_readerLock} ivar-name proxy detection path", "INTRINSIC", True),
    # enumval-regscan: relabeled REPLACE -> PRINCIPLED 2026-06-11.  The "register
    # scan" only *locates* the xAsString: pointer table's base register (real
    # adrp+add/ldr); the (value,name) pairs are read directly from that table in
    # memory (or the cmp-immediate / cfstring for the jump-table fallback).  It
    # reads ground truth, not a guess.  Budget truncation fails loud via the
    # `truncated` return flag, not a silent wrong value.
    #   The PRINCIPLED label now covers the WHOLE pointer-table path: the only
    #   non-principled bit — a register-priority GUESS fallback (tried x8/x9/x10/..
    #   when the scaled-index decode returned None) — was REMOVED 2026-06-14
    #   (enumbase-regguess below).  A magic `max_val > 512` pointer-table ceiling
    #   (enums.py) still routes to the jump-table path — see DEEP_SCAN caps.
    ("enumval-regscan", EN, "_extract_enum_values", "enum pointer-table base-register scan -> read (value,name) from real table", "PRINCIPLED", True),
    # enumbase-regguess: REPLACE -> PRINCIPLED 2026-06-14 (guess DELETED; breadcrumb).
    # Was the register-priority table-base GUESS fallback in _extract_enum_values
    # (x8/x9/x10/x7/x11/x12/x13, accept the first whose first entry reads as a valid
    # enum string) for when the scaled-index decode (enumval-regscan) returned None.
    # Census: it fired 0x under capstone (587/587 pointer-table enums across
    # GeoServices/CLP/locationd resolve via the scaled-index decode) — identical to
    # the jump-table guess removed by #47 (jt-enum).  Removed outright (no fallback),
    # output byte-identical; the no-capstone native decoder loses pointer-table enum
    # recovery (already a degraded, non-correctness-target mode — same as #47).
    ("enumbase-regguess", EN, "_extract_enum_values", "[DONE — removed 2026-06-14] register-priority table-base guess deleted; subsumed by enumval-regscan (scaled-index decode), 0x firing under capstone (same as #47)", "PRINCIPLED", True),
    # jt-enum: TODO #47 DONE 2026-06-12 (REPLACE->PRINCIPLED).  The x8..x14 register-
    # priority scan for the table base was replaced by decoding the actual scaled-index
    # table read (ldrb/ldrh [Xbase,Widx] via _decode_ldr_reg_off) and resolving Xbase's
    # adrp+add — same as enumval-regscan/dictrep-reg.  Measured to resolve 100% of jump-
    # table segments (276/276 across GeoServices/CLP/locationd); the guess was removed
    # outright (no fallback), output byte-identical.  The pairs were always read from the
    # real table (ground truth); now the table BASE is too.
    ("jt-enum", EN, "_extract_jumptable_enum_values", "jump-table enum: table base from the scaled-index load (#47)", "PRINCIPLED", True),
    # jt-seg-bias: a dense jump-table SEGMENT re-bases its sparse sub-range to 0 before the
    # `cmp #range` gate, so the bias must be added back to recover the wire value.  Two
    # lowerings: a literal `sub #imm12` (_leading_sub_bias), or — when the bias exceeds 12
    # bits — a value MATERIALISED into the segment's compared register via `mov #-K; add`
    # (negative-add) / `movz; sub` (_leading_materialized_bias).  #53 (e6a9b12) wired the
    # materialized form into Idiom A (the backward-scan); #53b (2026-06-14) into Idiom B
    # (the comparison-tree branch_gates) — the LAST seg_incomplete enum, GEOTelemetricEntity
    # eventKeyAsString:, whose 52020/60500-base segments were dropping with bias 0.
    # PRINCIPLED: reads the REAL normalising add/sub landing in the gate's value register
    # (the wire contract), dest-register-gated so a neighbour's materialise can't bleed in.
    # A confirmed segment that still attributes nothing trips seg_incomplete -> values_truncated
    # (fail-loud); now 0 across all 900 test enums (GeoServices/CLP/locationd).
    ("jt-seg-bias", EN, "_harvest_jumptable_segments", "dense-segment re-base bias: sub #imm12 or materialized mov#-K;add into the compared reg, Idiom A (#53) + Idiom B (#53b); dest-gated, fail-loud on miss", "PRINCIPLED", True),
    # Removed 2026-06-09: xasstring/_extract_enum_for_field, writeto-count/_count_field_write_patterns,
    # writeto-pass2/_find_writeto_imp_by_pattern, readfrom-pattern/_find_readfrom_c_func_by_pattern —
    # the four no-symbols cold fallbacks deleted when the selector-resolution gate landed (functions
    # no longer exist, 0 calls).
    # dictrep-reg: relabeled REPLACE -> PRINCIPLED 2026-06-11.  Recovers sparse
    # enum (value,name) pairs from the real `cmp wV,#K` immediates + the cfstring
    # at each branch target; the value-register identity gate is a soundness
    # check (only comparisons on the field's value register count), not a guess.
    ("dictrep-reg", EN, "_scan_dictrep_isolated_cmps", "dictrep sparse cmp-immediate + cfstring -> (value,name); value-register gate", "PRINCIPLED", False),
    # jt-width: relabeled REPLACE -> PRINCIPLED 2026-06-11.  The old 2/1-byte
    # brute-validate width fallback was REMOVED 2026-06-08 (census: 0 fires over
    # 1350 cluster calls; weak guard could admit a wrong adrp target).  The table
    # base and entry width now come from the cluster-pinned register's real
    # adrp+add + decoded `_decode_ldr_reg_off` width; unpinnable -> None (other
    # tiers handle it).  Structural decode, same family as dispatch-cluster/walk-arm.
    ("jt-width", DSP, "_decode_readfrom_jumptable", "dispatch table base+width from cluster-pinned register load", "PRINCIPLED", False),

    ("enumstr-regex", EN, "_is_valid_enum_string", "enum-name C-identifier regex + len<=128", "INTRINSIC", False),
    ("enum-bias", EN, "_find_index_bias", "1-based enum bias via SUB-imm before CMP", "PRINCIPLED", False),
    ("dictrep-modal", EN, "_read_dictrep_switch_pairs", "dictrep modal switch-entry + dominant-prefix gate", "PRINCIPLED", True),
    # enumname-prefix: tagged INTRINSIC for *provenance* (it inverts protoc's
    # deterministic `<TYPE_SCREAMING>_<VALUE>` convention from ground-truth value
    # strings — a principled decode, not a free guess). But its *output impact* is
    # COSMETIC, same axis as the PRESENTATION rows below: a wrong result only
    # mis-spells the enum TYPE NAME (e.g. `PlaceResponseStatus` vs
    # `PDPlaceResponseStatus`, `LocationType` vs `GEOLocationType`); the field
    # number and the enum-vs-int32 category stay correct, so there is no
    # wire/value/decoding impact. Confirmed across GeoServices/locationd/CLP
    # validation runs (only the name string differs). See ENUM_NAME_FROM_PREFIX.md.
    ("enumname-prefix", EN, "_enum_name_from_pairs", "common SCREAMING_SNAKE prefix >=2 words", "INTRINSIC", False),
    ("enumval-overlap", EN, "_normalize_enum_value_name", "last-word overlap strip (>=3 chars)", "PRESENTATION", False),
    ("writeto-fieldnums", WT, "_extract_writeto_field_numbers", "CFG-walk binding of writeTo: field number to container ivar", "PRINCIPLED", False),
    ("writeto-skipback", WT, "_writeto_field_number_before", "skip epilogue insns (<=6) for field-num imm", "ISA", False),
    # confirm-gate: RESOLVED 2026-06-10. The all-or-nothing min_needed coverage gate
    # was removed; _confirm_field_numbers adopts the sound CFG-walk field numbers
    # per-field. Removal recovered 264 confirmations + 22 number corrections (incl.
    # GEOLPRRoot.regions 2->1, sparse cases like GEOPDStorefront.bundleIds 1->4), 0
    # regressions, golden-verified. Now PRINCIPLED: reads the literal writeTo field
    # number, value-traced.
    # UPDATE 2026-06-15: the legacy pointer-table gap-fill (_try_pointer_table) was
    # DELETED — the same instrumentation (1201 calls, 0 non-empty on every supported
    # artifact) proved it never contributed a confirmed number, so the writeTo walk
    # is now the sole source (no competing source, no precedence question).
    ("confirm-gate", E, "_confirm_field_numbers", "field number = sound writeTo walk, adopted per-field", "PRINCIPLED", False),
    ("dispatch-cluster", DSP, "_find_dispatch_cluster", "dispatch field bias + recency-windowed cluster", "PRINCIPLED", True),
    ("metapool", REP, "_build_meta_type_pool", "metaclass +[Cls xyzType] element-class pool", "PRINCIPLED", False),
    ("enumstr-dual", EN, "_read_enum_string", "cstring-then-cfstring dual read", "ISA", False),
    ("qualify-overlap", EN, "_qualify_enum_name", "CamelCase word-overlap merge", "PRESENTATION", False),
    ("collect-dictrep", EN, "_collect_enum_definitions", "dictrep enum collection for untyped int fields", "INTRINSIC", False),
    # Removed 2026-06-09: protoscore dup row (same function as `protoclass`; the
    # score path was double-counted). The protoclass=REPLACE row already covers
    # _is_proto_class.

    ("fieldreg-uniq", DSP, "_find_field_number_register", "field-number register uniqueness", "PRINCIPLED", False),
    ("comparechain", REP, "_resolve_compare_chain_elements", "compare-chain bl bound by field-num reg", "PRINCIPLED", False),
    ("walk-arm", DSP, "_walk_jumptable_arms", "first ReadAllFrom bl in jump-table arm", "PRINCIPLED", False),
    ("typemethod-imp", REP, "_class_from_type_method_imp", "adrp+ldr x0 class-from-+xyzType IMP", "PRINCIPLED", False),
    # degenerate-partition / core-picker: the two structural guards added with #39
    # (commit 7519a68).  Both are value-independent bail-out rules — they reject the
    # failure modes of the linear compare-chain matcher + callee body-scan (a stray
    # `cmp Wf,#N; b.eq` building a bogus 1-block partition that swallows every element
    # bl; an accessor mis-accepted as a dispatch core).  Tagged REPLACE because a
    # principled signal IS available: define a core as "extracts Wf=tag>>3 and branches
    # on it" and attribute element bl by dominance, not address range.  BOTH guards are
    # now retired by that signal: degenerate-partition DELETED by #42 (dominance over a
    # complete CFG), and core-picker turned into the symmetric dispatch-core gate
    # (2026-06-14) — the same predicate now SELECTS the core instead of vetoing one.
    # degenerate-partition: DELETED in #42 (commit 3cfb3ef).  The compare-chain
    # attribution is now dominance over a COMPLETE CFG (_dominance_field_of), so a field
    # owns exactly the blocks its match edge dominates — a collapsed jump-table can't lump
    # cores under one field, making the guard unnecessary by construction.  Output
    # byte-identical on all 3 artifacts.  Row kept as a DONE breadcrumb (function gone).
    ("degenerate-partition", REP, "_degenerate_block_partition", "[#42 DONE — deleted] superseded by dominance attribution", "PRINCIPLED", False),
    # core-picker: REPLACE -> PRINCIPLED 2026-06-14.  Was an ASYMMETRIC veto — it gated
    # ONLY the direct core (keep it iff it dispatches) and trusted wcore via its weak
    # discovery gate (fc>0 + calls-own-method).  Now _locate_dispatch_arms applies the
    # SAME structural dispatch-core predicate (_core_resolves_compare_chain: extracts
    # Wf=tag>>3, branches on it, binds >=1 field to a known core, non-degenerate
    # partition) to BOTH candidate cores, preferring the anchored direct core on ties.
    # The selection is now structural/ground-truth, not an after-the-fact picker.
    # Differential output-IDENTICAL on all 3 golden artifacts (GeoServices 7948 / CLP 530
    # / locationd 445 fields, 0 changed); the 79 GeoServices core-choices the symmetric
    # rule flips are all cases where NEITHER core dispatches, so the compare-chain tier
    # resolves nothing either way (moot).
    ("core-picker", DSP, "_core_resolves_compare_chain", "symmetric dispatch-core gate: same structural predicate (Wf=tag>>3 + non-degenerate field->core partition) applied to BOTH the anchored direct core and the wrapper body-scan core; anchored wins ties", "PRINCIPLED", False),

    # emitter — REPLACE-audit 2026-06-12.
    # enum-severity -> PRESENTATION: ERROR-vs-NOTE wording over an already-recovered
    #   fact (unresolved-enum count x extraction mode); no binary signal to recover.
    # best-enum -> PRESENTATION: all members of a compat group are WIRE-EQUIVALENT, so
    #   picking the (confirmed, largest) one only affects which definition is shown — no
    #   wire/value/number impact.
    # enum-split: REPLACE-audit RESOLVED 2026-06-13. _collect_enums
    #   hosts TWO distinct concerns, recorded as two rows sharing the function's entry count
    #   (the dormant shared=True mechanism, first use):
    #     (1) DETECTION — a split fires ONLY on value-set INCOMPATIBILITY (same enum name,
    #         conflicting value->name at a shared index). That is a binary fact, not a guess;
    #         it fires 5x in GeoServices (LinkType/LocationType/ListType/SearchType/
    #         TrafficCameraType), each a genuinely distinct enum. -> PRINCIPLED.
    #     (2) NAMING — which variant keeps the bare name vs gets the {Class}{Enum} qualifier
    #         is a sort tie-break (-size,-values,-confirmed) over an already-recovered fact.
    #         -> PRESENTATION, same character as best-enum.
    #   The old REPLACE premise ("bind each field via its own xAsString:/StringAs<X>: selector
    #   so collisions never arise") is FALSIFIED: the census shows LinkType is selector-CONFIRMED
    #   (StringAsLinkType: exists) yet still splits, because the witness is field-name-based, not
    #   type-identity-based. No principled signal would dissolve the 5 -> out of REPLACE.
    #   (#48 withdrawn — premise falsified; the residual is the cosmetic enum-type-name
    #   reconstruction, now DEFERRED as #57 / LIMITATIONS.md (6).)
    #   See ENUM_NAME_FROM_PREFIX.md and TODO #57.
    ("enum-severity", M, "emit", "ambiguous-enum 3-way severity wording", "PRESENTATION", True),
    ("best-enum", M, "_best_in_compat_group", "pick enum by (confirmed, cardinality)", "PRESENTATION", False),
    ("enum-split-detect", M, "_collect_enums", "split same-name enums on value-set incompatibility (binary fact)", "PRINCIPLED", True),
    ("enum-split-name", M, "_collect_enums", "pick which variant keeps bare name vs {Class}{Enum} rename (sort tie-break)", "PRESENTATION", True),
    ("package-prefix", M, "package_for_class", "package = leading-caps ObjC prefix / fallback", "PRESENTATION", False),
    ("empty-enum", M, "_enums_compatible", "empty enum compatible with anything", "PRINCIPLED", False),

    # memory
    # packed-ptr: ex-cache *dylib* pointer decoder (binary mode only).  Measured
    # 2026-06-09: never reached cache-native; a no-op on standalone executables
    # (0 strips on locationd); the sole real consumer is an MH_DYLIB pulled from
    # the cache and read via --binary (~90% strips on GeoServices).  Low-36-bit
    # strip is ISA; the segment-membership accept is a safety check vs the real
    # segment table — left INTRINSIC per earlier decision.  See _decode_packed_ptr.
    ("packed-ptr", MEM, "_decode_packed_ptr", "ex-cache dylib packed-ptr decode (binary mode only); low-36-bit + segment validate", "INTRINSIC", False),
    # fixup-fmt: REPLACE-audit 2026-06-12 REPLACE->ISA.  Re-reading the code (TODO #49)
    # overturned the registry's old description: the chain walk ALREADY reads
    # pointer_format PER SEGMENT (dyld_chained_starts_in_segment +6) and walks with that
    # local value — already correct.  The `self._fixup_fmt` cache of the first non-zero
    # segment's format was WRITTEN-BUT-NEVER-READ (dead) and has been removed; no global
    # guess remains.  Pure structural Mach-O decode now.
    ("fixup-fmt", MEM, "_parse_chained_fixups_lc", "per-segment pointer_format from dyld_chained_starts_in_segment", "ISA", True),

    # disasm
    ("readavail", DIS, "_read_available", "binary-search shrink read at seg boundary", "ISA", False),
    # adrp-add/adrp-ldr: REPLACE-audit 2026-06-12 REPLACE->ISA.  Pure ARM64 decode —
    # reads the real adrp page + add/ldr operands with mnemonic-clobber detection;
    # the <=4-insn window is a conservative scan bound, not a value guess.
    ("adrp-add", DIS, "find_adrp_add_target", "ADRP->ADD <=4 window + mnemonic clobber detect", "ISA", True),
    ("adrp-ldr", DIS, "find_adrp_ldr_target", "ADRP->LDR window + mnemonic clobber detect", "ISA", True),

    # classlist — all three REPLACE-audit 2026-06-12 REPLACE->ISA: deterministic
    # structural decodes, not guesses.  tagstrip = documented ObjC class_t low-3-bit
    # tag mask (prefers the fixup-decoded value when present).  selregex = the ObjC
    # selector grammar + a len<=200 anti-garbage sanity bound.  relmethod follows the
    # ground-truth has_direct header flag, trying local-methname then deref (robustness
    # ordering, not inference).
    ("tagstrip", CLF, "_parse_class", "class_t data tag-bit strip when fixup absent", "ISA", False),
    ("selregex", CLF, "_is_valid_selector", "selector regex + len<=200", "ISA", False),
    ("relmethod", CLF, "_parse_relative_method", "relative-method selector multi-strategy decode", "ISA", False),

    # dyld_cache — REPLACE-audit 2026-06-12 REPLACE->ISA.  substride = v1/v2 sub-cache
    # struct auto-detect via the documented fileExtension[0]=='.' field.  decodeptr =
    # the documented cache DATA pointer encoding (plain vs low-36-bit-masked) — both
    # cases specified, not a guess.
    ("substride", DC, "_detect_subcache_stride", "subcache v1/v2 stride via byte24=='.'", "ISA", False),
    ("decodeptr", DC, "decode_ptr", "decode_ptr direct-then-masked two-strategy", "ISA", False),

    # local_symbols / strings — REPLACE-audit 2026-06-12.
    # firstwrite -> INTRINSIC: when two nlist symbols name one IMP the binary genuinely
    #   doesn't say which is canonical; first-write-wins is a deterministic tie-break, no
    #   recoverable signal exists.
    # latin1 -> ISA: standard try-UTF-8-then-latin-1 cstring decode (latin-1 never fails);
    #   the encoding isn't a guess, it's the documented fallback.
    ("firstwrite", LS, "_parse", "first-write-wins for duplicate IMP", "INTRINSIC", False),
    ("latin1", ST, "build_string_table", "UTF-8 -> latin-1 decode fallback", "ISA", False),

    # ════════════════════════════════════════════════════════════════════════
    # DEEP_SCAN 2026-06-13 — rows added by the 8-way module audit (this session).
    # The registry previously under-claimed its coverage: proto/extractor.py had 1
    # row for 1502 lines, and write_helpers/arm64cfg/arm64decode/cache_classlist/
    # models/config/defaults had ZERO.  Findings below were each source-verified.
    # Grouped by tier; highest-value (MATERIAL, REPLACE) first.
    # ════════════════════════════════════════════════════════════════════════

    # ── Tier 1: new MATERIAL heuristics, genuinely unregistered ──────────────
    # typeref-bytes: when a field's ObjC type_class was not extracted as a message
    # and isn't a known scalar/builtin, the emitter SILENTLY sets type_name="bytes"
    # (emitter.py:259).  For metadata-sparse/external classes the shape is genuinely
    # absent (INTRINSIC residual), but for inline-C-struct / repeated elements the
    # type is recoverable from readFrom: disasm -> overlaps the readFrom-resolver
    # cluster (#37/#42).  The bytes default is the unprincipled give-up.
    ("typeref-bytes", M, "resolve_type_refs", "[#42] unresolved class -> silent bytes default-type fallback [LIM 1 map residual / to-do #41 + LIM 2 repeated / to-do #37]", "REPLACE", False),
    # ordinal-fieldnum: THE estimated-field-number heuristic.  When a field number is
    # not confirmed by the writeTo: walk, it is assigned next_unconfirmed = ivar
    # declaration order, skipping numbers already taken (extractor.py:1166-1173).
    # confirm-gate covers the CONFIRMED path; this is the estimate it falls back to.
    # The readFrom CFG resolver (#42/#43) recovers the real number for many of these.
    ("ordinal-fieldnum", E, "extract_proto_message", "[#42] unconfirmed field# = ivar-order ordinal fallback (the estimate) [LIM 4 / to-do #52]", "REPLACE", True),
    # disp-rr-tiebreak: REPLACE -> PRINCIPLED 2026-06-14.  When BOTH the readFrom
    # dispatch resolver and the _rr heuristic yield a repeated element type, structural
    # dispatch wins UNLESS _rr is ABI ground truth.  The veto now keys on PROVENANCE
    # (_rr.abi_confirmed — set in the two ground-truth `string` paths: a distinct string
    # write-helper, or an IMP-confirmed +xyzType returning NSString) rather than on the
    # type-name spelling (was `_rr.type_name != "string"`, a magic literal).  A corpus
    # census (GeoServices/CLP/locationd, 1130 tie-break fields) found the ordering
    # already sound: dispatch overrides _rr ONLY when _rr is `bytes` (give-up, 194x) or
    # a name-suffix guess (14x) — NEVER a ground-truth _rr message class (0x); and the
    # abi_confirmed veto is honoured 160x with 0 violations.  So both arms are now
    # provenance-based (structural beats guess/give-up; ABI evidence beats a number-
    # keyed dispatch that can only collide with it).  abi_confirmed <=> old type_name
    # == "string", so the change is output-IDENTICAL.
    ("disp-rr-tiebreak", E, "extract_proto_message", "_disp vs _rr precedence by PROVENANCE: structural dispatch beats _rr unless _rr.abi_confirmed (distinct string write-helper / +xyzType->NSString); census-verified to never override a ground-truth _rr", "PRINCIPLED", True),
    # s1-selsynth: SECOND heuristic in _repeated_element_type (namesuffix-s2 is the
    # first).  Strategy 1 synthesizes the +[Cls xyzType] selector by depluralizing
    # (pname.rstrip("s")) and appending "Type" (repeated.py:59-66) — a naive
    # depluralizer; the matched IMP is ground truth but the selector-NAME match is a
    # guess.  Folds into the same readFrom-resolver fix as the other repeated rows.
    ("s1-selsynth", REP, "_repeated_element_type", "[#42] Strategy 1: depluralize+\"Type\" selector-name synthesis [LIM 7 / to-do #45]", "REPLACE", True),
    # field-label: PRINCIPLED (TODO #60). The label is now decided ENTIRELY by the
    # ivar @encode STORAGE SHAPE — packed C-array {?="list"…}, inline-C-struct array
    # ^{Struct=…}, or @"NSArray"/@"NSMutableArray" -> REPEATED; else OPTIONAL.
    # Selector-independent (works cache-native). The dropped add<X>:/Count/has<X> name
    # construction was redundant with the NSArray shape rule AND mislabelled ~40
    # GeoServices ^{struct} repeated fields as optional. The ^{ -> REPEATED rule is
    # Hopper-confirmed against the writeTo count+buffer+per-element-loop serialization
    # (GEOResource._regions / GEOCoarseLocationRing._points). 40 corrections + 1
    # element-type recovery on GeoServices, byte-identical on locationd/CLP/portability.
    ("field-label", PC, "_field_label", "repeated label via ivar @encode storage shape (packed/^{struct}/NSArray)", "PRINCIPLED", False),
    # real-field-ivar: PRINCIPLED (TODO #60). Admission is now pure STORAGE SHAPE —
    # admit unless the ivar is a named bookkeeping/has-bits ivar or the has-bits struct
    # (_is_proto_flags_ivar). The getter/setter name union was measured INERT
    # (NAME-rescues-flags == 0 on GeoServices+CLP); dropping it is byte-identical.
    ("real-field-ivar", PC, "_is_real_field_ivar", "admit ivar as field by storage shape (not has-bits/bookkeeping)", "PRINCIPLED", False),
    # backing-phantom: DROPS a field if unconfirmed AND uint64 AND name ends Count/Space
    # AND the base ivar is a C-struct-array pointer (extractor.py:838).  The writeTo
    # walk never serializes these (absence = ground truth), but the Count/Space name
    # suffix is the recognizer -> a writeTo-serialization check would be more principled.
    ("backing-phantom", E, "_is_backing_store_phantom", "drop unconfirmed uint64 Count/Space C-array backing ivar (name-suffix)", "INTRINSIC", False),
    # enum-qualify-extract: prefixes a bare enum name with the class proto name to dodge
    # collisions (extractor.py:1153) — may be overridden later by _enum_name_from_pairs.
    # Renames an already-recovered enum; no wire/value impact.  Sibling to enum-split-name.
    ("enum-qualify-extract", E, "extract_proto_message", "qualify bare enum name with class proto name (collision dodge)", "PRESENTATION", True),
    # obj-field-note: classifies an unresolved object ivar by NAME SHAPE (<...>=protocol,
    # NS/CF prefix=Foundation, else unresolved) to drive a // annotation only; never
    # drops or retypes the field (extractor.py:884).
    ("obj-field-note", E, "_unresolved_object_field_note", "name-shape classify of unresolved object ivar -> advisory comment", "PRESENTATION", False),

    # ── Tier 3: output-affecting scan-budget caps (standing [cap:] action) ────
    # Every [cap:AFFECTS-OUTPUT] cap is a standing removal / value-independent-bound
    # target.  These had NO registry row.  #59 (2026-06-13) worked the batch and
    # found the "extent bound is available, same as writeTo" framing TRUE for only
    # ONE of the six — cap-indegree (dead 4000 ceiling; now next-IMP structural,
    # output-neutral, PRINCIPLED).  The other five are NOT clean bound swaps:
    #   cap-helper-family — DONE 2026-06-13 (#59). Now "stop when classified": the
    #     family is decided at the tag-build insn (sint `lsl #1`, fixed `bfi #3`, or the
    #     plain varint `lsl <field#>,#3`); the scan stops there. The 48 is demoted to an
    #     INPUT-SANITY backstop (a no-tag-build helper falls through to plain = the safe
    #     default). Output-neutral (golden 0-diff; portability 0 contradictions). PRINCIPLED.
    #   cap-detect-context — DONE 2026-06-13 (#59). The "documented base-table miss"
    #     was a FALSE premise (probe: scan 40->600 = 0 golden diffs on 6 frameworks).
    #     The prologue base-register SEED was REDUNDANT — writeto_walk re-discovers
    #     every base live (cur_base), so returning empty bases is byte-identical
    #     (verified incl. locationd). Deleted the capped base-scan; detect_context now
    #     only finds self_reg, and max_insns is an INPUT-SANITY backstop. PRINCIPLED.
    #   cap-stack-scratch — DONE 2026-06-14.  The window=5 lookback was replaced by the
    #     REACHING DEFINITION of x1 (scan back to the first insn that writes x1; True iff
    #     it is `add x1, sp`).  Value-independent: a closer writer shadows a stale earlier
    #     `add x1,sp`, so the distance bound is unnecessary.  Differential-verified
    #     output-identical (0 disagreements / 18865 bl sites across the 3 artifacts).
    #     PRINCIPLED.
    #   cap-ptrtable-512 / cap-sparse-range — DONE 2026-06-14 (#59).  Both magic enum
    #     constants reframed to the structural 12-bit cmp ceiling (_SPARSE_MAX_RANGE);
    #     routing is by the scaled-index pointer-load structure, not the count.  Golden
    #     empty-diff.  PRINCIPLED.
    # All six are now PRINCIPLED.  The xAsString: jump-table
    # DISASM-BUDGET caps (_SPARSE_MAX_INSNS / _SPARSE_HARD_CAP) are a SEPARATE concern —
    # cap-sparse-insns below.
    ("cap-helper-family", WH, "_classify_write_helper", "[#59 DONE] wire-type decided at the tag-build insn (stop-when-classified); 48 demoted to INPUT-SANITY backstop", "PRINCIPLED", True),
    ("cap-stack-scratch", WT, "_value_is_stack_scratch", "[DONE 2026-06-14] window=5 -> reaching-definition of x1 (first writer; True iff `add x1,sp`). Value-independent, differential output-identical (0/18865 bl sites).", "PRINCIPLED", False),
    ("cap-detect-context", WT, "detect_context", "[#59 DONE] deleted the redundant prologue base-seed (walk's live cur_base re-discovers it); self_reg only, max_insns now INPUT-SANITY", "PRINCIPLED", False),
    ("cap-indegree", WT, "build_branch_indegree", "[#59 DONE] next-IMP structural extent bound (was min(extent/4,4000); the 4000 ceiling was dead — max writeTo extent 2131)", "PRINCIPLED", False),
    ("cap-ptrtable-512", EN, "_extract_enum_values", "[#59 DONE] 512 ceiling (2 sites) -> _SPARSE_MAX_RANGE (12-bit cmp ceiling). Routing is by STRUCTURE (the 64-bit scaled-index pointer load) with a jump-table fallback; the count gate is now a fast pre-filter bounded by the encoding, not a tuned 512. Golden empty-diff.", "PRINCIPLED", True),
    ("cap-sparse-range", EN, "_harvest_jumptable_segments", "[#59 DONE] _SPARSE_MAX_RANGE reframed = 1<<12, the unshifted 12-bit cmp-immediate ceiling (structural, not a domain magic#); larger values route to the materialized-value path. Vacuous bias bounds removed; output-neutral.", "PRINCIPLED", False),
    # cap-sparse-insns: the xAsString: jump-table DISASM BUDGET (distinct from the enum
    # routing/range caps above — this bounds how far the method body is disassembled, not
    # which idiom is chosen).  Census 2026-06-14 (#53b), 709 GeoServices xAsString methods:
    #   _SPARSE_MAX_INSNS=1000 — COSMETIC cheap probe.  Output-neutral (proven 1000->30000
    #     = 0 value changes) and a perf fast-path: only 16/709 exceed it (693 close within,
    #     max 982), so 693 methods skip the _function_body_extent sweep.
    #   _SPARSE_HARD_CAP=40000 — INPUT-SANITY fail-loud ceiling for _function_body_extent.
    #     Never binds: max real extent 11925 (30% of cap).  A body that fails to close still
    #     trips _disasm_truncated (honest INCOMPLETE), so it's a safety net, not a guess.
    # Neither affects output; with the #53b bias fix the truncated flag is now 0 across all
    # 900 test enums, so the whole values_truncated apparatus is a dormant safety net.
    ("cap-sparse-insns", EN, "_extract_jumptable_enum_values", "[#53b census] _SPARSE_MAX_INSNS=1000 COSMETIC cheap probe (16/709 exceed; output-neutral) + _SPARSE_HARD_CAP=40000 INPUT-SANITY ceiling (never binds, max extent 11925); both retained, neither output-affecting", "INTRINSIC", True),

    # ── Tier 4: previously zero-row modules (mostly ISA decode primitives) ────
    # write_helpers.py — the sint/sfixed/fixed wire-type recovery.  PRINCIPLED: follows
    # the real adrp/add/br x16 stub and reads the wire-type immediate (5/1) spliced into
    # the tag — NOT a guessed VA.  (Cap split out as cap-helper-family above.)
    ("classify-helper", WH, "_classify_write_helper", "wire-type family from real PLT stub + tag wire-type immediate", "PRINCIPLED", True),
    ("string-helper-first", WH, "_identify_string_write_helpers", "first @\"NSString\" ivar's helper wins, one-suffices early-stop (binary-wide invariant)", "PRINCIPLED", False),
    # arm64decode.py — pure ARM64 instruction-field decode.  Two carry real heuristic
    # content beyond deterministic decode:
    ("materialized-value", AD, "_materialized_value", "<=4-insn backward movz/movk peephole + OR-composition for >4095 constants", "ISA", False),
    ("func-prologue", AD, "_is_func_prologue_word", "next-function-opener recognizer (incomplete set) bounds past-ret scan", "ISA", False),
    ("arm64-decode-prims", AD, "_decode_ldr_reg_off", "ARM64 operand decoders (adr/cmp/movz/lsr/ldr-reg-off ...) — deterministic", "ISA", False),
    # arm64cfg.py — CFG / ivar-offset-table base resolution primitives.
    ("offset-base-resolve", ACFG, "_resolve_offset_addr", "ivar-offset base register: local adrp+add preferred over stale prologue", "ISA", False),
    ("last-method-span", ACFG, "_next_imp", "[cap:INPUT-SANITY] _LAST_METHOD_SPAN=0x4000 last-method disasm bound", "ISA", False),
    # cache_classlist.py — cache-native classlist (twin of classlist tagstrip).
    ("cache-tagstrip", CCL, "read_objc_class_name", "class_t data &~0x7 tag strip; valid only for non-chained-fixup caches (assumption)", "ISA", False),

    # ── Tier 5: latent / reproducibility risks ───────────────────────────────
    # disasm-native: capstone-vs-native decoder strategy switch (disasm.py:392).  The
    # pure-Python fallback covers only ~a dozen opcodes and emits 'unk' otherwise, so
    # find_adrp_*/find_indexed_load_base results can SILENTLY DIFFER between environments
    # (a missing ldrsw broke pointer-table analysis until added).  Mitigated by the
    # venv-capstone setup, but environment-dependent and uncatalogued.
    ("disasm-native", DIS, "_disasm_native", "capstone-vs-native decode fallback; partial opcode set can change output across envs", "ISA", False),
    # image-substr: RESOLVED 2026-06-13 (commit d7705aa).  Was REPLACE — substring-
    # first-wins ('GeoServices' silently matched 'GeoServicesCore' by array-order luck).
    # Replaced by DyldCacheReader.resolve_image: a tiered IDENTITY resolver (exact path
    # -> framework-principal `.../<name>.framework/<name>` -> unique substring) that reads
    # the real install path; genuine ambiguity raises AmbiguousImageError listing the
    # colliding paths rather than guessing.  Probed cache: 1997 principals resolve, only
    # 5 honest collisions (now bail), project targets resolve to identical VAs.  PRINCIPLED.
    ("image-resolve", DC, "resolve_image", "tiered identity resolver: exact path / framework-principal / unique substring; ambiguity bails", "PRINCIPLED", False),
    ("section-size-cap", ST, "build_string_table", "magic _MAX_SECTION_SIZE=50MB drop-whole-section bound (not a documented format limit)", "INTRINSIC", False),
    ("scan-sections", ST, "build_string_table", "fixed __objc_methname section allow-list + 15-char spelling assumption", "ISA", False),
    ("image-base-min", MEM, "__init__", "image_base = min non-__PAGEZERO segment vmaddr (lowest-segment assumption)", "ISA", False),
    # local_symbols precedence pair — .symbols is the canonical name source.
    ("symbols-wins", LS, "apply_to_classes", "symbol name unconditionally overrides method-list name (.symbols is ground truth)", "PRINCIPLED", False),
    ("sel-firstwrite", LS, "_parse", "second tie-break: (class,selector)->IMP first-write-wins (distinct from firstwrite)", "INTRINSIC", False),
    # models.py / config.py / defaults.py — naming-convention reconstruction + placeholders.
    ("class-proto-name", CONF, "_class_to_proto_name", "proto message NAME via first-match prefix strip (GEO/CLP/..)", "PRESENTATION", False),
    ("enum-placeholder-name", MOD, "_enum_prefix", "CamelCase->SCREAMING_SNAKE placeholder value name for empty enum", "PRESENTATION", False),
    ("empty-enum-unknown", MOD, "ProtoEnum", "synthesize <PREFIX>_UNKNOWN=0 when no enum values recovered (proto3 needs a 0)", "INTRINSIC", False),
    ("default-prefixes", DEF, "DEFAULT_PREFIXES", "hardcoded ordered prefix seed (GEO/CLP/CLM/CLN) feeding name/package strip", "PRESENTATION", False),

    # ── Foreign serializers (2026-06-14 swift/C++ deep-scan audit) ─────────────
    # C++ libprotobuf-full: a LITERAL FileDescriptorProto decode — every number/
    # type/label/name/enum/nesting read from the descriptor, NO inference (verified
    # field-for-field vs Google descriptor_pb2: 0 mismatch / 2626 fields).  Listed
    # PRINCIPLED for context; the adapter's nesting-flatten + oneof-flatten are
    # PRESENTATION (structure preserved / flagged).  GPBMessage + libprotobuf-lite
    # are DETECT-ONLY (no schema emitted) -> not heuristics; see LIMITATIONS.md 8/9.
    ("cpp-descriptor", CPP, "decode_file_descriptor", "C++ FileDescriptorProto literal decode (numbers/types/labels/names/enums) — NO inference; verified vs descriptor_pb2", "PRINCIPLED", False),
    ("cpp-flatten", FGN, "_cpp_message", "nested Outer.Inner -> Outer_Inner + oneof member flatten (flagged note) — structure preserved", "PRESENTATION", True),
    # swift-protobuf: numbers+names are LITERAL (nameMap closure/runtime-builder mov
    # #N + name cstrings -> ground truth, PRINCIPLED); field TYPES are now recovered
    # from __swift5_fieldmd incl. COW _StorageClass + OneOf_* enums (#60).  The swift
    # LIM 10 cluster is now largely CLOSED — only the integer-subtype collapse (#63b)
    # survives as a live REPLACE, and the data shows it is unexercised (see its note).
    ("swift-namemap", SW, "_extract_namemap", "swift field NUMBERS+NAMES read literally from the _protobuf_nameMap closure / static blob / runtime cold-builder (mov #N + name cstrings); runtime-_NameMap unified reader covers all 3 store-shapes, cross-validated vs decode/traverse — ground truth (#71)", "PRINCIPLED", False),
    ("swift-fieldtypes", SW, "recover_field_types", "swift field TYPES read from __swift5_fieldmd mangled types incl. COW _StorageClass + OneOf_* enums, linked to the owning message by the descriptor parent chain (#60); keyed by QUALIFIED name so same-short-name nested types don't collide (#68)", "PRINCIPLED", False),
    ("swift-singlefield-num", SW, "_single_field_tail_call", "swift shape-B single-field number cross-confirmed from TWO independent structural sources (decodeMessage cmp x0,#N + traverse visit mov w?,#N); confirmed iff they agree on exactly one value, else default 1 emitted number_confirmed=False (honestly flagged, not laundered) [LIM 10a / to-do #63a]", "PRINCIPLED", False),
    ("swift-int-subtype", STR, "decode_mangled", "swift integer subtype collapsed to base (int32 for sint32/sfixed32/fixed32; uint64/int64 analogues) — wire-incorrect, base-only. Principled signal EXISTS (traverse Visitor witness-table slot offset: 0x38=sint32, 0x40=sint64, 0x48=fixed32 …) but DEFERRED 2026-06-15: cache-mode .symbols carries NO traverse symbol (signal unreachable there), and in binary mode sint/fixed appear ONLY in SwiftProtobuf library extension-plumbing types (RepeatedExtensionField / ExtensionFieldValueSet / PackedExtensionField), never an app schema — like GPB, unexercised by the data [LIM 10b / to-do #63b]", "REPLACE", True),
    ("swift-mangle-fallback", STR, "decode_mangled", "Array element / map value that doesn't decode falls back to bytes — NOW FLAGGED, not silent: run-length std-substitution map<string,string> decoded (#66) and the container-filler bytes carry a `type not recovered (shown as bytes)` note via SwiftField.type_note (#67). Symbolic-ref array elements now resolve via raw-byte prefix detect (#69). Residual = extend decoder to further mangled forms; flagged meanwhile [LIM 10c / to-do #66]", "INTRINSIC", True),
    ("swift-name-join", SW, "_attach_field_types", "type<->field bound by per-field NORMALIZED-NAME match (strip _, lowercase) within a type; the type-MAP is now keyed by QUALIFIED name (parent-chain) with an unambiguous-only short-name fallback, so same-short-name nested types no longer collide/mis-bind (#68 DONE). Per-field name match is INTRINSIC (swift exposes no structural number<->type link) and measured correct [LIM 10d / to-do #67]", "INTRINSIC", False),
    ("swift-repeated-label", FGN, "_swift_field", "repeated field with an unrecovered element: the `repeated` label is now PRESERVED (-> `repeated bytes`, not `optional bytes`), and symbolic-ref elements resolve fully (e.g. repeated <Message>) via raw-byte Say/SD prefix detection (#69 DONE). Genuinely-unrecovered elements keep the label + the #67 filler note", "PRINCIPLED", False),
]


def load_calls():
    # NOTE: the /tmp/heur_calls_*.json files are an ephemeral instrumentation
    # artifact keyed on each function's *defining* file:line.  After a code move
    # (e.g. the 2026-06-10 proto.extractor monolith split) they go stale and the
    # join yields 0 for relocated functions until heuristic_freq.py is re-run
    # over the three artifacts.  The REGISTRY file refs above are the current,
    # correct definition sites; the counts are just a convenience overlay.
    per = {}
    for name in ("geoservices", "locationd", "corelocationprotobuf"):
        path = f"/tmp/heur_calls_{name}.json"
        if not os.path.isfile(path):
            per[name] = None
            continue
        agg = defaultdict(int)
        with open(path) as fh:
            for k, v in json.load(fh).items():
                relpath, name_, _line = k.rsplit(":", 2)
                agg[(relpath, name_)] += v
        per[name] = agg
    return per


def count(per, name, file, func):
    d = per.get(name)
    if d is None:
        return None
    return d.get((file, func), 0)


def main():
    per = load_calls()
    rows = []
    seen = set()
    for (hid, file, func, disp, judg, shared) in REGISTRY:
        geo = count(per, "geoservices", file, func)
        loc = count(per, "locationd", file, func)
        clp = count(per, "corelocationprotobuf", file, func)
        total = sum(x for x in (geo, loc, clp) if x)
        rows.append((total, geo, loc, clp, judg, disp, func, file, shared))
    rows.sort(reverse=True, key=lambda r: r[0])

    def fmt(x):
        return "-" if x is None else str(x)

    print(f"{'TOTAL':>9} {'geo':>8} {'loc':>7} {'clp':>6}  {'class':<10} heuristic")
    print("-" * 118)
    for (total, geo, loc, clp, judg, disp, func, file, shared) in rows:
        star = " *" if shared else ""
        print(f"{total:>9} {fmt(geo):>8} {fmt(loc):>7} {fmt(clp):>6}  {judg:<10} {disp}{star}")
    print("\n* = function hosts >1 heuristic; entry count is shared across them.")

    print("\n\n=== REPLACE-class only, ranked by frequency ===")
    print(f"{'TOTAL':>9} {'geo':>8} {'loc':>7} {'clp':>6}  heuristic  [function @ file]")
    print("-" * 118)
    for (total, geo, loc, clp, judg, disp, func, file, shared) in rows:
        if judg != "REPLACE":
            continue
        print(f"{total:>9} {fmt(geo):>8} {fmt(loc):>7} {fmt(clp):>6}  {disp}  [{func} @ {file.split('/')[-1]}]")


if __name__ == "__main__":
    main()
