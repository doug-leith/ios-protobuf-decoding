# `/fb?type=` dispatch RE — smoot feedback upload (2026-06-17)

`fbs.smoot.apple.com/fb?type=<X>` and `api.smoot.apple.com/fb?...` is **polymorphic**: the
`?type=` query param selects a *different message class* per feedback channel. parsecd is the
uploader (the HTTP plumbing), but the payload class is owned by the producing framework. The
`?type=` strings are the `KnownFeedbackType` enum value-names (found as a cstring table in dyld
subcache `.11` near CoreParsec: `KnownFeedbackTypeUnknown, SafariAutoFill, Crowdsourcing,
SpotlightResultFeatures, SafariAutoPlay, Trystero, EngagedCompletionFeatures, ProactiveEventTracker,
PhiDES, UserReport, Usage, FeedbackV2, FeedbackV2PB, ProactiveEventTrackerAggregated, Handwashing,
Experiments, FeatureQuality`). `DuetExpert` is NOT in that enum — it's a separate uploader
(`duetexpertd`) reusing the same `/fb` channel.

## Confirmed type → class map (all verified, no shortcuts)

| `?type=` | class | framework / pkg | how confirmed |
|---|---|---|---|
| `FeedbackV2PB` | `_CPClientSession` | CoreParsec | fuzzy 1 cand @0.800 (discriminating) + prior GT (f4 fixed64, f200 repeated feedbacks) |
| `Usage` | `_CPUsageEnvelope` | CoreParsec | **binary writeTo: field#s** (`gt_fields.py`) + protoc decode |
| `ProactiveEventTracker` | `PETUpload` | ProactiveEventTracker / `pet` | protoc decode (metadata iOS/iPhone13,2/IE/en; isCompressed; compressedMessages) |
| `ProactiveEventTrackerAggregated` | `PETUpload` | ProactiveEventTracker / `pet` | protoc decode (same class; `messageGroup:"_aggregated"`) |
| `DuetExpert` | `ATXNotificationsPBLogWrapper` | AppPredictionInternal / `atx` | protoc decode (periodiclog AppLaunch* feature counts; record MobileSMS events) |

### Key evidence
- **NOT all `_CPClientSession`.** Initial hypothesis (everything is a sparse `_CPClientSession`)
  was a shortcut and WRONG: protoc rejected it (invalid UTF-8 at f1), and the bodies carry a
  device-context envelope, not `agent`-at-f1. Only `FeedbackV2PB` is genuinely `_CPClientSession`.
- **Usage = `_CPUsageEnvelope`**: wire body = `{f1: _CPUsageSinceLookback, f14: _CPDeviceContext,
  f15: uuidBytes}`. The extractor proto had `context` mis-ESTIMATED at field 6; `gt_fields.py`
  reads the real writeTo: numbers from disasm: `1,2,3,4,5`(msg helper e20) `10,11`(64-varint)
  `12,13`(32-varint) **`14`(msg helper e20 = context)** `15`(bytes helper dd8 = uuidBytes). So the
  true layout is `usageSinceLookback=1, propensities=2-5, …, context=14, uuidBytes=15`. → an
  extractor field-number bug for message-typed fields that the linear scan can't follow.
- **DuetExpert = `ATXNotificationsPBLogWrapper`** `{record=1, response=2, grecord=3, periodiclog=4,
  settinglog=5}`. Two observed shapes are just different wrapper fields populated:
  - body w/ top `f4` = `periodiclog` = `ATXNotificationsPBPeriodicLog{userId, periodStart,
    periodEnd, dataUnits[ATXNotificationsPBDataUnit{key:string, value:float}]}` — `AppLaunchDock=5`,
    `NumApps=40`, etc.
  - body w/ top `f1` = `record` = `ATXNotificationsPBRecord{bundleId="com.apple.MobileSMS",
    topic, context, events[…], timezone}`.

## Why the flat fuzzy matcher couldn't do this
Usage/PET/DuetExpert bodies are small and tie 5+ ways at the top level (wire-compatible with many
`_CP*`/`ATX*` messages). Identification required (a) recursive structural decode to leaf level and
(b) cross-framework extraction (PET = ProactiveEventTracker.fw; DuetExpert = AppPredictionInternal.fw,
NOT CoreParsec). The daemons (`proactiveeventtrackerd`, `duetexpertd`) carry NO embedded PB classes —
they link the framework; extract the framework from the cache.

## Production consequence + decoder mechanism (built)
`/fb` cannot be one static table row. It needs a **type-parsing decoder** (parse `?type=`, dispatch
to the per-type class). Only the 5 types above are present in the captures and thus confirmable;
other `KnownFeedbackType` values (SafariAutoFill, Crowdsourcing, Experiments, …) have no wire sample
here — left to raw-decode until observed and verified.

Implemented in PoC `/tmp/discovery_poc/decoders.py` — a **table-directed, framing-aware decoder**
layer. A decoder is `fn(url, body, direction, function_id) -> DecodeResult(type, payload,
provenance, authoritative)`; the resolver runs it as **Tier 0** (before the static table):
- `smoot_fb`: parses `?type=`, maps to the RE'd class (stores the owning FRAMEWORK too, since e.g.
  DuetExpert's `ATXNotificationsPBLogWrapper` lives in AppPredictionInternal, NOT the locator's
  advisory CoreParsec — production must load the right corpus for the descriptor). Asserts the type
  on the URL key directly (like an ARPC functionId), NOT gated on the corpus — the corpus may carry
  the `_CPUsageEnvelope.context` field-number gap, which `_consistent` correctly flags but must not
  veto. Unknown/unverified `?type=` → `type=None` → raw-decode.
- `iad`: strips the 8-byte `<BE32 typeCode><BE32 payloadLen>` preamble (subsumes the old ad-hoc
  `unframe()`); type left to the iAd table rows. Verified: 4034B framed → 4026B inner valid pb.
- `arpc`: de-frames the ARPC header if still present; type left to the functionId tier / response
  rows. Verified: dispatcher.arpc response → GEOPDPlaceResponse.

Result (`eval_twotier.py`): parsecd 991/991 now resolve to a table type, **0 fall-throughs** (the 2
`type=DuetExpert` cases that previously fell to no-match are now resolved). No regression on
geod/locationd/cloudkit/itunescloudd/netproxy. `matcher_table` `/fb` row narrowed to
`type=FeedbackV2PB` (fallback only; the decoder owns all channels).

---

## Extractor fix — message-field accessor binding (2026-06-17, branch extractor-tidy)

ROOT CAUSE of the `context` mis-numbering: message / object fields are serialized
through their property GETTER (an objc selector-stub `bl`), not a direct
`ldr [self,off]`. The writeTo CFG walk DID capture the literal field number
(`mov w2,#N`) for these writes — it just couldn't BIND them to an ivar, because
`bind_write`'s value-load scan only matched a direct self-load. So they fell to the
ivar-order ESTIMATE (context → 6). Worse, a STALE threaded `cont_off` from a prior
scalar field let the container tier (2b) mis-bind context's write to
`_collectionEndTimestamp` before any accessor logic ran.

FIX (`proto/writeto.py`): new binding tier **2d** — trace the helper's value reg
(x1) back through the block to the defining getter `bl <selector-stub>` (following
`mov` chains, skipping ARC retain/autorelease passthroughs), resolve the stub's
selector, map it to the real-field ivar of the same name. CONFIRMED not guessed:
`_build_accessor_ivar_map` admits a selector→ivar pair ONLY when the class's own
getter method disassembly actually loads that ivar's offset (handles the plain
accessor AND the oneof getter, which loads the discriminator then the ivar). Tier
2d runs BEFORE 2b so a stale `cont_off` can't steal a getter-sourced message; safe
to front-run because it resolves ONLY a getter-fed value (a genuine inline repeated
message uses a stack-scratch value and falls straight through to 2b).

RESULT: `_CPUsageEnvelope.context = 14` confirmed (matches wire + gt_fields).
CoreParsec: **101 message-field bindings estimated→confirmed** (87 same-number
certifications + 14 number CORRECTIONS, all 14 verified against the gt_fields
message-write-helper oracle — e.g. `_CPClientSession.usageSinceLookback 6→16,
cohortsFeedback 7→17`; `_CPSearchResultForFeedback.card/inlineCard/compactCard
7/8/9→41/42/43`; `_CPNetworkTimingData.startTimeCounts/stopTimeCounts 1/2→7/8`).
Zero regressions: GeoServices / locationd / CoreLocationProtobuf golden
BYTE-IDENTICAL (they don't use the getter idiom for message writes); no
previously-confirmed field changed; no type/label changes. oneof discriminator
pseudo-fields (`whichKind`, `which*bundleid`) stay FLAGGED-estimated (never
wire-accurate). Tests: `tests/test_writeto_unit.py::TestAccessorBinding` +
`tests/test_writeto_walk_coverage.py::TestAccessorSourcedBinding`.

---

## Productionised into ios_decoder (2026-06-17)

The smoot /fb decoder is now in the **ios_decoder** production package (not just the PoC):
- `ios_decoder/fb.py` — `decode_fb(body, ctx)` reads `ctx.url`, parses `?type=`, dispatches
  via `FB_TYPE_MAP` to `(schema_file, message)`. Unmapped/absent `?type=` → raw decode under
  an explicit note (never guessed).
- `ios_decoder/endpoints.py` — new `Endpoint(r"(fbs|api)\.smoot\.apple\.com/fb\b", Rule(handler=
  fb.decode_fb), None)` (request-only; /fb response is an ack). `DecodeContext` gained a `url`
  field; `ios_decoder/decode.py` sets `ctx.url` per body so URL-polymorphic rules can see it.
- Schemas authored into `addon_ios/` (the proto-dir): `parsec_feedback.proto`
  (`_CPClientSession`, `_CPUsageEnvelope`, `_CPUsageSinceLookback`, `_CPDeviceContext`),
  `pet_upload.proto` (`PETUpload`+deps), `atx_notifications.proto`
  (`ATXNotificationsPBLogWrapper`+deps). Verified fields modelled faithfully; unverified
  sub-messages kept as wire-compatible `bytes`. **Field numbers taken from the FIXED extractor**
  (tier-2d) — `_CPClientSession.usageSinceLookback=16, cohortsFeedback=17` (not the old 6/7),
  `_CPUsageEnvelope.context=14`. The corrected `usageSinceLookback=16` was confirmed against real
  wire: FeedbackV2PB bodies populate field 16 with a full `_CPUsageSinceLookback`.

Per the owner's scope: matcher table + decoder mapping only — **no fuzzy matcher, no locator
table** were added to production.

Tests: `ios_decoder/tests/test_fb.py` — unit (dispatch + unknown→raw, no protoc), real-schema
round-trip (privacy-safe synthetic data, gated on addon_ios), and a **live** test decoding real
/fb bodies from a git-ignored capture (skips cleanly when absent). Full suite: **281 passed**.

Eval (production decode sweep over all 31 captures): **4307 unique bodies, 0 errors/exceptions**;
all **991 /fb bodies** (950 Usage, 35 FeedbackV2PB, 3 ProactiveEventTracker, 1 Aggregated, 2
DuetExpert) decode against their mapped schema with **0 unknown-field notes** (corrected numbers
cover every observed field). No regression elsewhere.

### Schemas switched to UNMODIFIED extractor output + relocated (2026-06-17, owner directive)

Per owner: (i) don't use hand-crafted descriptors — use apple_protobuf_extractor output;
(ii) store the descriptors inside the ios_decoder project; (iii) keep extractor output
unmodified (package names intact) for a clean audit trail.

- The three hand-authored consolidations in `addon_ios/` were DELETED. The smoot /fb schemas are
  now the **unmodified** extractor output committed under **`ios_decoder/protos/`** (12 files: the
  `_cpclientsession`+`_cpusageenvelope` import closure (10), `pet.proto`, `atx.proto`) — package
  names and `// Source:` headers preserved. `paths.py` `DEFAULT_PROTO_DIRS` now lists
  `ios_decoder/protos` first, then `addon_ios`. `.descriptor_cache/` gitignored.
- `fb.FB_TYPE_MAP` references the extractor files with PACKAGE-QUALIFIED messages
  (`_cpclientsession._CPClientSession`, `_cpusageenvelope._CPUsageEnvelope`, `pet.PETUpload`,
  `atx.ATXNotificationsPBLogWrapper`). The extractor's tier-2d field-number fix means these compile
  & decode correctly out of the box (no manual `context=14` / `usageSinceLookback=16` patching).
- **DuetExpert caveat:** the unmodified `atx.proto` currently FAILS protoc compilation — a SECOND,
  separate extractor bug: a reconstructed enum name (`ATXNotificationsPBEvent`, `...PBResponse`)
  collides with a real message of the same name (proto3 forbids it). So DuetExpert degrades to a
  raw decode via the schema rule's SchemaError fallback (honest `// WARNING: schema decode failed
  (... atx.proto ...)` + raw), rather than the named decode. Flagged as an extractor task; auto-
  recovers once the enum-naming is disambiguated. The other 4 channels decode fully.

Eval after the switch: full ios_decoder suite **281 passed**; production sweep over 31 captures =
**4307 bodies, 0 errors**; /fb = 950 Usage + 35 FeedbackV2PB + 3 PET + 1 Aggregated all decoded
against the extractor schema (0 schema warnings), 2 DuetExpert gracefully degraded (atx.proto bug).

### Full per-framework extractions stored + DuetExpert recovered (2026-06-17)

Per owner ("store all the extractions so we have a clear record"): replaced the curated import-
closure subset with the COMPLETE, unmodified extractor output, one subdir per framework:
`ios_decoder/protos/CoreParsec/` (77), `ProactiveEventTracker/` (2), `AppPredictionInternal/` (8) =
87 files. `paths.py` globs each subdir as a search + protoc `-I` include path (root listed first so
the compiled `.descriptor_cache/` lands at `protos/.descriptor_cache`, gitignored). fb.py references
are unchanged (bare filenames resolve within the framework subdirs).

The fresh re-extraction also picked up the concurrent extractor fix for the enum-name collision:
`atx.proto` now suffixes the colliding reconstructed enums (`ATXNotificationsPBEvent` enum →
`ATXNotificationsPBEventEnum`), so it COMPILES and **DuetExpert now decodes fully** (no more graceful
degradation). Sweep: all 5 /fb channels decode against the extractor schema with 0 schema warnings;
281 tests pass; 4307 bodies / 0 errors.
