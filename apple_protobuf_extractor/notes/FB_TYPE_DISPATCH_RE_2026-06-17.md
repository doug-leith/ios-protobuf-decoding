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

## How the decoder uses this

`/fb` cannot be one static table row. `ios_decoder/fb.py` parses `?type=` and dispatches through
`FB_TYPE_MAP` to the per-channel message, using the unmodified extractor output under
`ios_decoder/protos/`. Only the five channels above appear in the captures and could be confirmed.
Any other `KnownFeedbackType` value (`SafariAutoFill`, `Crowdsourcing`, `Experiments`, …) has no wire
sample, so it is shown as a raw decode until one is observed and verified. Measured 2026-06-17 over
all 31 of the author's captures: the 991 `/fb` bodies (950 Usage, 35 FeedbackV2PB, 3
ProactiveEventTracker, 1 ProactiveEventTrackerAggregated, 2 DuetExpert) all decode against their
mapped schema with no unknown-field notes.

## An extractor bug this exposed

Message-valued fields are serialised through their property getter (a selector-stub `bl`), not a
direct `ldr [self,off]`. The `writeTo:` walk captured the literal field number (`mov w2,#N`) but could
not bind it to an ivar, so the field fell back to the ivar-order estimate (`_CPUsageEnvelope.context`
came out as 6; the wire has 14). The tool now traces the helper's value register back to the getter,
maps the selector to the ivar whose offset that getter really loads, and so confirms the number.
CoreParsec: 101 message-field bindings went from estimated to confirmed, 14 of them number
corrections checked against the `gt_fields.py` oracle (for example `_CPClientSession.usageSinceLookback`
6→16 and `cohortsFeedback` 7→17). The golden outputs for GeoServices, locationd and
CoreLocationProtobuf were unchanged, since they do not use the getter idiom for message writes.
