# swift-protobuf extraction — hand verification (2026-06-14)

Goal: independently confirm, by reading the ARM64 binary directly, that the
tool's swift-protobuf recovery (field numbers, names, types) is **correct** for a
standalone binary and for cache frameworks — and that where it cannot recover a
type it is **cautious** (flags it, never guesses). The verified rows below are
the intended regression ground truth (tests added in
`tests/test_swift_descriptor_extract.py`).

NB: the task asked for "locationd". locationd carries **no** swift-protobuf
(PBCodable + C++/AWD only — `swift_messages(locationd)` == 0). A standalone
binary that does use swift-protobuf was substituted: **bookdatastored**
(`PrivateFrameworks/BookDataStore.framework/Support/bookdatastored`).

## Method — three INDEPENDENT sources cross-checked per message

The tool reads numbers+names from the generated `_protobuf_nameMap` static-init
closure. To verify it without circularity, each field was cross-checked against
codegen/metadata the tool does NOT use:

1. **nameMap init closure** (read manually from the disassembly): each entry is
   `mov w,#<number>; str x,[slot]` + `adrp x,#page; add x,#off (=name cstring);
   mov w,#<len>; stp`. The `#len` immediate is cross-checked against the actual
   string length — an internal consistency check that the right cstring was paired.
2. **`traverse(visitor:)`** — the *serialization* path, wholly separate codegen.
   It emits `mov w1/w2,#<fieldNumber>` immediately before each
   `visitSingular*Field` / `visitRepeated*Field` call; the visit-helper address
   also distinguishes the wire type (e.g. int64 helper ≠ string helper).
3. **`__swift5_fieldmd`** reflection metadata — independent of the nameMap; gives
   field name + mangled Swift type (→ proto type).

`decodeMessage` was also inspected; on these toolchains it is a thin tail-call
into a shared nameMap-driven generic decoder (no per-field `cmp #N`), except the
older bookdatastored form which does switch on the numbers.

---

## A. Standalone binary — bookdatastored (arm64e, device form)

### PBPropertyValue  — VERIFIED
nameMap closure @0x10012f65c (via getter 0x10012f9c0 → `adr x16`); decodeMessage
@0x10012f9e4 switches on `cmp #1..#8`.

| # | name | closure | decodeMessage | fieldmd | tool |
|---|------|:--:|:--:|------|------|
| 1 | createdAt | ✓ | ✓ | `Google_` (Timestamp, name truncated) | `Google_` |
| 2 | identifier | ✓ | ✓ | string | string |
| 3 | assetID | ✓ | ✓ | int64 | int64 |
| 4 | noParams | ✓ | ✓ | (oneof `params` member) | `<none>` → bytes+note |
| 5 | floatParam | ✓ | ✓ | (oneof member) | `<none>` |
| 6 | bookReadParams | ✓ | ✓ | (oneof member) | `<none>` |
| 7 | markedAsFinishedParam | ✓ | ✓ | (oneof member) | `<none>` |
| 8 | bookImpressionParam | ✓ | ✓ | (oneof member) | `<none>` |

Numbers 1–8 confirmed by **two** independent sources (closure + decodeMessage).
fieldmd reports the oneof container `params` (kind `OneOf_Params`); fields 4–8 are
its members — the tool surfaces the members with correct numbers/names and
**cautiously** marks the type unrecovered (documented limitation #60). `createdAt`
type is `google.protobuf.Timestamp`; the tool shows `Google_` (well-known-type
name truncation, cosmetic limitation).

### PBPropertyConfiguration — VERIFIED (all four numbers AND types independently)
traverse @0x10012d7ac: `mov w1,#1`→helper …910, `mov w1,#2`→…910, `mov w2,#3`→
…920, `mov w1,#4`→…910. Helper …910 (fields 1,2,4) ≠ …920 (field 3) ⇒ int64 vs
string — matching fieldmd exactly.

| # | name | closure | traverse | fieldmd/visit-helper | tool |
|---|------|:--:|:--:|------|------|
| 1 | ageToExpire | ✓ | ✓ #1 | int64 (…910) | int64 |
| 2 | countLimit | ✓ | ✓ #2 | int64 (…910) | int64 |
| 3 | eventName | ✓ | ✓ #3 | string (…920) | string |
| 4 | recordType | ✓ | ✓ #4 | int64 (…910) | int64 |

### PBPropertyBundle — VERIFIED (message-ref + repeated)
closure: 1 configuration, 2 propertyValues, 3 deletedPropertyValueTimestamps.

| # | name | closure | fieldmd | tool |
|---|------|:--:|------|------|
| 1 | configuration | ✓ | PBPropertyConfiguration | PBPropertyConfiguration |
| 2 | propertyValues | ✓ | repeated PBPropertyValue | repeated PBPropertyValue |
| 3 | deletedPropertyValueTimestamps | ✓ | repeated `Google_` (Timestamp) | repeated `Google_` |

### PBPropertySingleFloatParam — VERIFIED (single-field shape)
decodeMessage @0x10012e280 → `cmp #1`; traverse @0x10012e2f0 → `mov w0,#1` before
the float visit helper. fieldmd: value→float.

| # | name | decodeMessage | traverse | fieldmd | tool |
|---|------|:--:|:--:|------|------|
| 1 | value | ✓ #1 | ✓ #1 | float | float |

### PBPropertyMarkedAsFinishedParam — VERIFIED (single-field enum)
traverse @0x10012f2e0 → `mov w1,#1`. fieldmd: value→MarkedAsFinishedMechanism (enum).

| # | name | traverse | fieldmd | tool |
|---|------|:--:|------|------|
| 1 | value | ✓ #1 | MarkedAsFinishedMechanism | MarkedAsFinishedMechanism |

The tool's single-field default-to-1 is confirmed correct by traverse here.

---

## B. Cache frameworks (cache-native, via `.symbols` nlist)

### CopresenceCore — CP_Record — VERIFIED (full closure assembly read)
nameMap init @0x1a9a77ef8 read directly. Each `mov #N` + `adrp+add <name>` +
`mov #len`; lengths match names (internal consistency): 5=topic, 4=data,
6=seqNum, 0x19=25=destinationParticipantIDs, 0xc=12=encryptionID,
0xf=15=sentEpochMillis. traverse @0x1a9a784ec independently shows `mov w1,#1`
(topic) and `mov w1,#3` (seqNum).

| # | name (len) | closure | traverse | fieldmd | tool |
|---|------|:--:|:--:|------|------|
| 1 | topic (5) | ✓ | ✓ #1 | string | string |
| 2 | data (4) | ✓ | — | bytes | bytes |
| 3 | seqNum (6) | ✓ | ✓ #3 | CP_SequenceNumber | CP_SequenceNumber |
| 4 | destinationParticipantIDs (25) | ✓ | — | (absent from fieldmd) | `<none>` → bytes+note |
| 5 | encryptionID (12) | ✓ | — | CP_EncryptionID | CP_EncryptionID |
| 6 | sentEpochMillis (15) | ✓ | — | uint64 | uint64 |

### CopresenceCore — other messages (fieldmd + closure numbers)
| message | tool | fieldmd cross-check |
|---|------|---|
| CP_KeyValue | 1 key string, 2 dataValue bytes | key→string, dataValue→bytes ✓ |
| CP_SequenceNumber | 1 publisherParticipantID uint64, 2 seqNum uint64 | both uint64 ✓ |
| CP_EncryptionID | 1 uuid bytes | uuid→bytes ✓ (number = single-field default, see below) |

### GAP FOUND + FIXED by this verification: single-field tail-call, cache name-load
`CP_EncryptionID` initially extracted as **EMPTY** cache-native while fieldmd
clearly showed `uuid: bytes`. Root cause: its nameMap init @0x1a9a793a8 is the
single-field tail-call shape (`adrp x2,#page; add x2,#0x814 (="uuid"); mov w3,#4;
b <builder>`), and `_single_field_tail_call` only resolved a single `adr` name
load — the **same `adr`-vs-`adrp+add` cache form** already fixed in
`_walk_inline_closure`, but this helper was missed. Fix applied (adrp+add name
resolution in `_single_field_tail_call`); CopresenceCore went **24 → 28**
messages-with-fields (4 single-field messages were silently empty before). This
is exactly the kind of cache-only miss the hand verification was meant to catch.

Number caveat (transparency): for `CP_EncryptionID` the field NUMBER is the tool's
single-field **default of 1** — there is no `decodeMessage` symbol and `traverse`
is fully inlined, so unlike PBPropertySingleFloatParam (where decodeMessage AND
traverse both confirmed #1) the number here is the convention, not independently
confirmed. The NAME (`uuid`) and TYPE (`bytes`) ARE independently confirmed
(fieldmd). Single-field proto messages use field 1 by overwhelming convention, so
this is low-risk, but it is a heuristic, not a proof.

### MessageProtection — MPPB_KeyAndIndex — VERIFIED
nameMap init @0x1e83ecaac: `mov w8,#1`+name-len-3 "key", `mov w27,#2`+name-len-5
"index". fieldmd: key→bytes, index→uint64.

| # | name (len) | closure | fieldmd | tool |
|---|------|:--:|------|------|
| 1 | key (3) | ✓ | bytes | bytes |
| 2 | index (5) | ✓ | uint64 | uint64 |

---

## Conclusion

- **Correct:** every field number, name, and recovered type matched across all
  available independent sources — 0 discrepancies over 7 messages / 26 fields
  (5 standalone + 2 framework messages fully cross-checked, plus 3 framework
  messages confirmed by fieldmd).
- **Portable:** verified on both a standalone arm64e binary (in-image symbols)
  and two cache-native frameworks (`.symbols` nlist) — same decoders, two symbol
  sources.
- **Robust:** numbers confirmed by ≥2 sources wherever a second codegen path
  exists (closure + decodeMessage or traverse); the `#len` consistency check
  guards name-pairing.
- **Cautious / transparent:** the only fields the tool leaves typed `<none>`
  (→ bytes + `// swift-protobuf: type not recovered`) are exactly the documented
  blind spots — oneof members (PBPropertyValue 4–8) and a COW/absent-from-fieldmd
  field (CP_Record #4) — never a guess. The `Google_` truncation of well-known
  type names is the one cosmetic gap (numbers/structure still correct).

---

# Part 2 — C++ libprotobuf, cache extraction (2026-06-14)

Same exercise for the cache-native C++ decoder (`extract_cpp_protos_from_ctx`,
which reads embedded `FileDescriptorProto` blobs from the image's
`__TEXT,__const`/`__cstring` sections). Standalone-binary C++ is already
descriptor_pb2-verified elsewhere (locationd, 3691/3691); this focuses on the
cache path. Three independent layers:

## Layer 1 — vs Google `descriptor_pb2` (canonical reference decoder)
For each cache framework, extract the FileDescriptorProtos via the tool's cache
path, then parse the SAME blob bytes with Google's `descriptor_pb2` and compare
every message/field/enum field-for-field (number, type, label, type_name, enum
values; recursively through nested types). `descriptor_pb2` is wholly independent
of our hand-rolled decoder.

| framework (cache-native) | protos | fields checked | field mismatch | enum mismatch |
|---|--:|--:|--:|--:|
| GeoServices | 6 | 316 | 0 | 0 |
| DialogEngine | 48 | 812 | 0 | 0 |
| CoreNavigation | 10 | 1166 | 0 | 0 |
| CoreIndoor | 6 | 332 | 0 | 0 |
| **total** | **70** | **2626** | **0** | **0** |

## Layer 2 — vs the publicly-documented `descriptor.proto` schema
GeoServices embeds `google/protobuf/descriptor.proto`; 12 canonical fields were
hand-checked against the protobuf spec's known numbers/types (external ground
truth, independent of *both* decoders):
FileDescriptorProto.name=1/string, .package=2/string, .message_type=4/msg/repeated,
.enum_type=5/msg/repeated; DescriptorProto.field=2/msg/repeated,
.nested_type=3/msg/repeated; FieldDescriptorProto.name=1/string, .number=3/int32,
.label=4/enum, .type=5/enum, .type_name=6/string; EnumDescriptorProto.value=2/repeated.
**12/12 correct.**

## Layer 3 — raw-byte structural spot-check (extraction, not just decode)
GeoServices `path.proto` blob @ `__TEXT,__const` offset 0xd50a8 (vmaddr
0x18d84bf98), len 526. Manual wire decode of the head: field 1 (name) wt2 len10
= "path.proto"; field 2 (package) wt2 len0x14 = "maps.path_codec.geo3" — real
FileDescriptorProto bytes, not a regex false positive. **`descriptor_pb2`
consumed all 526/526 bytes and `re-serialize == original blob`**, proving the
section read + `_blob_end` boundary are exact (no truncation / no trailing
bytes). Messages LatLngE7 / RoutingPathPoint / RoutingPathLeg — tool ==
descriptor_pb2.

## Conclusion (C++ cache)
- **Correct:** 0 discrepancies across 2626 fields / 70 protos / 4 frameworks vs
  the canonical decoder, 12/12 vs the documented schema.
- **Robust extraction:** the section-scanned blobs are byte-exact and complete
  (round-trip identity), so cache-native loses nothing vs the whole-file sweep
  (independently shown identical on GeoServices: 288 field-tuples).
- **Transparent:** C++ output is a direct decode of a self-describing descriptor
  — no inference, nothing to guess; the only thing the tool can't do is
  libprotobuf-**lite** (no embedded descriptors), which it reports rather than
  fabricating.

---

# Part 3 — swift-protobuf ground truth, expanded corpus (2026-06-15)

Goal: accurate, hand-verified ground truth across **more** frameworks and **more
idioms**, to back regression tests + decoder-improvement analysis. Test:
`apple_protobuf_extractor/tests/test_swift_ground_truth.py`.

## Method (per field, independent of the tool's primary path)

For each message I derive `(number, name, type)` from **distinct structural
sources** and require agreement:
- **number + name** ← the inline `_protobuf_nameMap` closure, which is the literal
  proto name table: `mov #N` (number) + `adrp+add <name>; mov #len` (name+length).
  This IS the runtime's number↔name map; reading it is ground truth, not inference.
- **type** ← `__swift5_fieldmd` mangled type, hand-decoded (Si→int64, Su→uint64,
  Sf→float, Sd→double, Sb→bool, SS→string, Data→bytes, `Say…G`→repeated,
  `SD y…G`→map, symbolic 0x01/0x02→message/enum descriptor name).
- **cross-check** the name appears in BOTH the nameMap and fieldmd (validates the
  join); where `traverse`/`decodeMessage` symbols exist, numbers are also confirmed
  against `mov w?,#N` / `cmp x0,#N`.

**Spot-certified against raw disassembly** (the gold standard): e.g.
`ProtoTaskFeatureSet` closure literally stores `mov w8,#1; str` (→#1 `appBundleId`,
`mov #len 0xb`=11) and `mov w9,#0x65(101); …len 0x13`=19 → #101 `startCallFeatureSet`
— so the non-trivial 101-105 oneof numbers are read straight from the table.

## Certified ground truth

### SiriTaskEngagement (cache, 13 messages) — scalars / message / enum / oneof
nameMap is **inline**; `.symbols` carries nameMap only (no traverse/decode). All
`(number, name)` certified from the closure table; types from fieldmd.
- `ProtoDateComponentSignal`: #1 year, #2 month, #3 day, #4 hour, #5 minute,
  #6 second — all **uint32**.
- `ProtoMediaEntitySignal`: #1 adamIdentifier, #2 artist, #3 title, #4 album — **string**.
- `ProtoDateTimeEntitySignal`: #1 datetimeTimestampMs **uint64**.
- `ProtoPlayMediaTaskFeatureSet`: #1 playDurationInSec **double**, #2
  mediaContentLengthInSec **double**, #3 appBundleId **string**, #4 actionState
  **string**, #5 mediaEntity **ProtoMediaEntitySignal** (message-typed).
- `ProtoReminderTaskFeatureSet`: #1 reminderIdentifier string, #2 isSpatialTriggered
  **bool**, #3 isTemporalTriggered bool, #4 startTime / #5 endTime
  **ProtoDateTimeEntitySignal** (message-typed).
- `ProtoSiriTaskInteractionType`: #1–#4 includes{Prompt,Confirm,Disambiguate,
  UnsupportedPrompt} — all **bool**.
- `ProtoSiriTaskEvaluationSummary`: #1 requestIds **repeated** (element type
  unrecovered → emitted `repeated bytes`, gap #68/#39), #2 taskCompletion
  ProtoSiriTaskCompletionType (enum), #3 taskSuccess ProtoSiriTaskSuccessType (enum),
  #4 interactionType ProtoSiriTaskInteractionType (message), #5 startTimestampMs /
  #6 endTimestampMs **uint64**.
- `ProtoTaskFeatureSet` — **oneof + high numbers**: #1 appBundleId string;
  **#101–#105** startCall/sendMessage/alarm/reminder/playMedia FeatureSet are the
  `featureSet` oneof members (numbers+names certified; element TYPES are the
  respective `Proto*TaskFeatureSet` messages but emitted `bytes`/none — oneof gap #60).
- (also: `ProtoAlarmTaskFeatureSet`, `ProtoContactEntitySignal`,
  `ProtoTaskEngagementFeatureSet`, `ProtoSendMessageTaskFeatureSet.contactEntities`
  / `ProtoStartCallTaskFeatureSet.contactEntities` = **repeated ProtoContactEntitySignal**,
  emitted `bytes`/none — repeated-message element unrecovered, gap #68/#39.)

### MessageProtection (cache, 5 messages) — bytes / message / repeated-message
- `MPPB_KeyAndIndex`: #1 key **bytes**, #2 index **uint64**.
- `MPPB_RatchetState`: #1 chainKey **MPPB_KeyAndIndex** (message), #2 messageKeys =
  **repeated MPPB_MessageKey** (unrecovered → bytes/none, gap #68).
- `MPPB_SKOutgoingRatchet`: #1 ratchetState bytes, #2 privateSigningKey bytes,
  #3 currentMessageKey **MPPB_KeyAndIndex**, #4 subscriptionKey **MPPB_KeyAndIndex**.
- `MPPB_SKIncomingRatchet`: #1 ratchetState bytes, #2 messageKeys repeated (unrec.),
  #3 publicSigningKey bytes.
- `MPPB_SKPaddedStatus`: #1 payload bytes, #2 padding bytes.

### CreateML (cache) — map<> + resolved repeated-message  (+ a found bug)
- `CoreML_Metadata`: #1 shortDescription, #2 versionString, #3 author, #4 license —
  string; **#100 userDefined = `map<string, string>`** (mangling `SDyS2SG`:
  `SD`=Dictionary, `S2S` = `S`(String)×2 run-length substitution → key+value both
  String). **TOOL EMITS `map<string, bytes>` — WRONG value type**: `decode_mangled`
  doesn't handle the `S<n><char>` run-length substitution, so the value falls back to
  bytes. New decoder bug → tracked under **#66** (concretely: handle the run-length
  standard-substitution form `S<digit><letter>`).
- `CoreML_NearestNeighborsIndex`: #1 numberOfDimensions **int32**, #2 floatSamples =
  **repeated CoreML_FloatVector** (a resolved repeated-MESSAGE — element type recovered
  ✓); #100 linearIndex / #110 singleKdTreeIndex / #200 squaredEuclideanDistance are
  oneof members (emitted none, gap #60).

### remindd (standalone binary) — runtime-built `_NameMap` (#72/#70 — FIXED 2026-06-15)
- `StartMigrationRequest.Credential` TRUE = **5 fields**: #1 dsID **string**, #2 baseURL
  string, #3 hostname string, #4 mmeAuthToken string, #5 partition **uint32**.
- **ROOT CAUSE (re-diagnosed):** this is NOT the shape-B tail-call lowering. The nameMap
  getter is the runtime-built `_NameMap` once-init form (`cmn x8,#1; b.ne <builder>`); the
  64-insn shape probe spilled past the getter `ret` into the cold builder, caught its
  `adr x1,<closure>`, and the single-field path grabbed only the first name (`dsID`).
- **FIXED:** the cold builder closure carries the COMPLETE literal `(number, name)` table —
  each entry `mov w?,#N` + name pointer stored via one `stp wNum,xName,[base,#slot]` (length
  from a 16-byte `_NameDescription` vector store). `_walk_namemap_builder` reads it directly;
  both number and name are literal, so all fields are CONFIRMED (no inference / index-join).
  Tool now emits all 5 correctly. This is the SAME lowering as the Google WKTs (#70).
- **Same fix recovers the SwiftProtobuf well-known types** (previously empty): the recovered
  tables reproduce canonical google.protobuf exactly — `Any`=type_url(1)/value(2);
  `Duration`/`Timestamp`=seconds(1)/nanos(2); `Api`/`Type`/`Method`/`Value`/`EnumValue`/`Mixin`/
  `Enum`/`Option` all exact (11 WKTs). remindd: 22 messages went from empty/single-field to
  complete, all-number-confirmed.
- **Cross-validation guard** (`_namemap_builder_validated`): the builder `stp <int>,<namePtr>` is
  ambiguous — the int is the field NUMBER in the older codegen but the name LENGTH in the newer
  InternalSwiftProtobuf packed-bytecode form (nptocompaniond `ErrorResponse`: 6=len'domain',
  4=len'code'). Accept only when the independent `decode`/`traverse` numbers ⊆ recovered AND not
  every `number==len(name)`. So npto stays {1:domain,2:code}, and an INCOMPLETE read is refused:
  `Google_Protobuf_Field` recovers 9 of its 10 fields (misses #11 default_value, which traverse
  exposes) → NOT emitted as multi-field rather than emit a wrong/partial set. 0 wrong output.

## Idiom coverage map (for decoder work)
scalar string/uint32/uint64/int32/double/bool ✓ · bytes ✓ · message-typed field ✓ ·
enum-typed field ✓ · repeated scalar (`repeated bytes`, elem unrec) ✓ · repeated
message resolved (`repeated CoreML_FloatVector`) ✓ · repeated message UNrecovered
(contactEntities / messageKeys) ✓ · **map<string,string>** ✓ (currently mis-typed,
#66, FIXED) · oneof + high field numbers (#101-105, #100/#110/#200) ✓ · runtime-built
`_NameMap` multi-field (Credential / Google WKTs, #72/#70, FIXED) ✓.

## Known-degraded fields surfaced (the tracked-not-accepted contract)
| field | true | tool emits | gap |
|---|---|---|---|
| CoreML_Metadata.userDefined | `map<string, string>` | `map<string, string>` ✓ | #66 FIXED 2026-06-15 |
| Credential.{baseURL,hostname,mmeAuthToken,partition} | 4 more fields | recovered ✓ | #72/#70 FIXED 2026-06-15 |
| *.contactEntities / *.messageKeys | repeated `<Message>` | bytes/none | #68/#39 |
| ProtoTaskFeatureSet #101-105 etc. | oneof member messages | none | #60 |
