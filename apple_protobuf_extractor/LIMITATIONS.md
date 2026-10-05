# Known limitations — apple_protobuf_extractor

These are the **accepted limitations** of the `.proto` extractor. They
are documented rather than fixed: each is a small, well-characterised slice of the
output where the recovered schema is incomplete or degraded. Where the limitation
touches a specific emitted field, the descriptor output carries an inline `// …`
comment pointing back here, and the relevant source sites carry a `LIMITATIONS.md`
reference. Items are tagged `to-do #N`: those numbers are identifiers from the project's original
task list (no longer in this repository), kept so the code comments and the heuristic registry still
cross-reference the same limitation.

Several limitations are the residual of a `REPLACE` heuristic that survives because
no principled signal exists for the residual slice; those carry a **Heuristic
registry** line naming the row(s) in `heuristic_registry.py` (tagged there with the
matching `[LIM n / to-do #m]`). Limitations (3), (5), (6), (11) have no registry row — they
are extractor/emitter-level, not heuristic fallbacks. Keep the two files in sync.

The tool's correctness contract is unchanged: it never *silently* emits a wrong
field — every degraded field below is flagged in the output.

---

## 1. `map<>` fields: residual cases that are not typed  — to-do #41 (mostly DONE 2026-10-03)

**What is recovered.** A protobuf `map<K, V>` field is an ObjC `NSMutableDictionary`
ivar with no element type in its `@encode`; it is serialized as repeated `{key = 1,
value = 2}` entries. `proto/mapfields.py` now recovers the field number and the key/value
types from `writeTo:` (the entry writer inside the `enumerateKeysAndObjectsUsingBlock:`
block's invoke function, or the inline enumeration loop) and, for a message value, the value
class from the field's `readFrom:` arm. The field is emitted as a real `map<K, V>` with a
confirmed number and no comment. Recovered on the iPhone 8 images: 5 GeoServices fields (`GEOLPRUser.vehicles`
#1, `GEOLPRRoot.powerTypes` #3 / `vehicleTypes` #4, `GEOPublisherAttributionManifest
.publisherAttributionSources` #1, `GEOPublisherAttributionManifestIndex.publisherToFileIndex`
#2) and 4 CoreParsec fields. (`GEOLPRRoot`'s two maps were previously *mis-numbered* 2/3 —
ivar-order estimates; the block gives 3/4.)

The same recovery was run on the macOS 27 and iOS 27 arm64e dyld caches (newer toolchain: PAC-signed
block invoke pointers, `add`+`ldr` ivar loads, `adrp/add/b` literal-selector stubs): all 7 macOS 27
GeoServices maps (the five above plus two `GEOActiveTileGroup` string→string maps, #100/#101) and 7 of the 8
iOS 27 ones are typed with the same shapes and numbers. Those runs are not golden-guarded (only the iPhone 8
artifacts are).

**Residual cases (each flagged inline, never silently wrong):**

* **No map-entry writer in `writeTo:`** — the field stays `bytes // number estimated;
  map<> field … no map-entry writer found in writeTo:`. Seen on `PETProtobufRawDecodedMessage`
  (`decodedDict`, `nestedFields`, ProactiveEventTracker): its `writeTo:` is a bare `ret`; the
  two ivars are the ObjC decoder's runtime output, not serialized wire fields, so there is
  nothing to recover (the numbers 1/2 are estimates and are not wire evidence).
* **Entry writer found but a type not proven** (key helper not identified as a legal map-key
  type, value helper unseen/conflicting, `writeTo:` and `readFrom:` disagree about the value, or
  an NSNumber unboxing selector contradicts the helper): emitted as `repeated bytes` — every
  entry stays visible as an entry message — with the reason in the comment. A message value
  whose class `readFrom:` does not name emits `map<K, bytes>` plus a note (iOS 27
  `GEOPairedDeviceSubscriptionStatesSummary.subscriptionStates`: that reader core has no unique
  field-number register, so the field-F handler cannot be located).
* **Value message would close a `.proto` import cycle** — per-class packages (CoreParsec) make
  mutually-recursive messages import each other, which `protoc` rejects. The map value is then
  emitted as `bytes` (wire-identical) with a note naming the class and files:
  `_CPStruct.stringKeyFields` / `intKeyFields` (`_CPValue` holds a `_CPStruct`). Only map-value
  edges are ever cut. GeoServices is one package, so it never occurs there.
* **Entry bodies split across basic blocks / other enumeration idioms** (e.g.
  `enumerateKeysAndObjectsWithOptions:usingBlock:`, a conditional inside the entry writer) are
  not recognised and fall back as above. Not seen in the 9 serialized maps measured; the
  analysis is conservative (a body without a matching begin/end mark, or with a repeated or
  foreign sub-field, is rejected rather than interpreted).

**Source sites.** `proto/mapfields.py` (recovery); `proto/extractor.py`
(`_finalize_map_fields`, `_MAP_*_NOTE`); `proto/emitter.py` (`map<>` rendering,
`_break_map_import_cycles`).

**Heuristic registry.** None of the recovery is heuristic: write-helper types are the
unanimous types of the ivars using them binary-wide, the value class is the proto class
referenced inside the field's own `readFrom:` handler region. The legacy `bytes` fallback is
still the `typeref-bytes` row.

---

## 2. Repeated-message elements with an unresolved element type emit as `repeated bytes`  — to-do #37

**Symptom.** A `repeated <Message>` field whose element type can't be bound emits
as `repeated bytes`, flagged inline:

```proto
repeated bytes region = 8;  // element type could not be determined; emitted as bytes — each element may be an unparsed message; see LIMITATIONS.md (2)
```

**Why.** The element type is recovered from the `readFrom:`/`writeTo:` dispatch.
Two cases leave it unresolved:

- **Inline-C struct-writers (the largest known cluster, ~17 fields).** The element
  is serialized by an inline C function (e.g. `_GEOTileSetRegionWriteTo`, bracketed
  by the length-delimited helpers `0x18dbdab88`/`0x18dbdab94`) rather than a
  PBCodable `writeTo:`, so there is no element *class* to name. Mostly the
  `GEOTileSetRegion` family (`GEOTileGroup` #11, `GEOResource` #4,
  `GEOAttribution` #8, `GEOTileSetVersion` #2, …) plus a few fixed structs
  (`UInt128`/`SessionID`/`ScreenResolution`). Hopper-confirmed example:
  `GEOAttribution.region #8` = `repeated GEOTileSetRegion`. Also
  `GEOPDDepartureSequence.operatingHours #3` = `repeated GEOPDTimeRange`.
- **Metadata-sparse element classes.** The element class has no ObjC methods to
  read, so the dispatch has no body to resolve against (this slice is intrinsic —
  the binary genuinely doesn't name the element at the field site).

The field number and the `repeated` label are correct; only the element *type* is
degraded to `bytes`. The inline `// …` note fires for the whole unresolved-element
class (a superset of the inline-C subset above); it is not isolated to the C-struct
cases. (The `repeated` label on the inline-C-struct `^{Struct=…}` fields is derived
from the ivar's pointer-to-struct storage shape.)

**Singular by-value embedded structs (the same `bytes` catch-all).** A *singular*
field whose ivar is a by-value C struct (`@encode {Name=…}`, e.g.
`{GEOSessionID="_high"Q"_low"Q}`, `{GEOTimepoint=…}`, `{GEOPDTimeRange=…}`,
`{GEOECEFCoordinate=…}`) is a length-delimited submessage on the wire, but the tool
does not model the struct's layout, so it reaches the same `("bytes", None)`
catch-all in `_type_from_enc` and emits as a *singular* `bytes`. Flagged inline:

```proto
optional bytes sessionId = 1;  // embedded fixed-struct 'GEOSessionID' emitted as bytes; element type/layout not modelled — see LIMITATIONS.md (2)
```

~37 GeoServices fields (sessionId / timepoint / timeRange / operatingHoursRange /
ecefLocation / representativePoint / screenResolution / …); 0 in locationd /
CoreLocationProtobuf. A genuine `NSData` field (`@encode @"NSData"`) is a real
`bytes` and is deliberately NOT flagged.

**Workaround for consumers.** The element is a length-delimited submessage; identify
its type by hand from the `writeTo:`/`readFrom:` of the owning class.

**Source sites.** `proto/extractor.py` (`_ELEMENT_UNRESOLVED_NOTE`, set where a
repeated field's element resolution returns `element_unresolved`; and
`_embedded_struct_note` for the singular by-value variant);
`proto/repeated.py` (`_resolve_repeated_field_type`).

**Heuristic registry.** `typeref-bytes` (the bytes default-type fallback) —
`heuristic_registry.py`. (Distinct from the *name-suffix* fallback in (7); this one
fires when the type cannot be named at all.)

---

## 3. Ivar-less delegated fields are not discovered  — to-do #35

**Symptom.** A field that has **no backing ivar** (its value is delegated/computed)
is missing entirely from the emitted message — there is no line for it and no inline
comment, because no field object is ever created.

**Why.** Fields are discovered by walking the class's ivars
(`proto/extractor.py`, the `field_ivars` collection → `_is_real_field_ivar`). A
delegated field contributes no ivar, so it is never seen. Recovering it would
require a separate analysis path (walk `readFrom:`/`writeTo:` for field numbers that
have no matching ivar) — that is the planned CFG/dominator `readFrom` resolver
(to-do #42), not part of this accepted-limitation set.

**Known affected fields (GeoServices).** 1 field:
`GEOPDReverseGeocodingResult.placeContextMetadata #1` (found by comparing against a hand-decoded
reference for `GEOPDPlaceResponse`, which is not part of this repository).

**Note on flagging.** Unlike (1) and (2), this limitation **cannot** be flagged in
the descriptor output — the field is absent, so there is nothing to attach a comment
to. It is documented here and at the `field_ivars` source site instead.

**Source site.** `proto/extractor.py` (the `field_ivars` list comprehension).

---

## 4. Fields with wire field number 0 emit an estimated (non-wire-accurate) number  — to-do #52

**Symptom.** Some Apple messages serialize a field with protobuf field number
**0**. Field 0 is illegal in proto2/proto3 (`protoc` rejects `key = 0;`), so the
tool cannot emit it faithfully — it estimates the lowest legal number (gap-fill /
ivar order) and flags it inline:

```proto
string key = 1;  // number estimated; wire field number is 0 (Apple 0-based; illegal in .proto) — this estimated number will NOT match live traffic; see LIMITATIONS.md (4)
```

**Why — this is deliberate 0-based numbering, not a codegen bug.** Hopper-verified
on `NTPBCacheHint` (NewsTransport), both sides agree on field 0:
`-[NTPBCacheHint writeTo:]` writes `_key` with `mov w2,#0`, and
`_NTPBCacheHintReadFrom` dispatches **`case 0 → _key`** with **no case 1**. The
ProtocolBuffer runtime's writer/reader helpers special-case only `−1`/`0xFFFFFFFF`
(the no-tag / packed-element reuse path) — **0 is not special**, so it produces a
real tag byte (`0x02` for the string here) and round-trips in Apple's own runtime.
It is illegal only per the protobuf spec.

**Consequence.** The flag is correct, but a decoder built from the emitted `.proto`
(`key = 1`, tag `0x0a`) would look for field 1 and never match the field-0 bytes
(tag `0x02`) — `_key` would stay empty. **Do not use the estimated number to decode
live traffic for a field carrying this flag.**

**Known affected fields.** ~34 fields, **all in NewsTransport** (the framework uses
0-based proto numbering as a house style). Field 0 occurs only in NewsTransport:
StatusKitAgentCore, BiomeStreams and iCloudDriveCore (133 proto classes between them)
have **zero** field-0 writes. **All 34 are genuine bidirectional 0-based numbering
(writeTo: writes 0 AND readFrom: handles field 0) — 0 off-by-one bugs**, verified by
checking every readFrom dispatch (compare-chain field==0 handler / jump-table
`table[0]` ≠ default / offset-descriptor `descriptor[0]` non-null). So the estimated
number is non-wire-accurate for all of them. **None occur in GeoServices / locationd /
CoreLocationProtobuf**, so this flag does not affect the golden-snapshot artifacts.

**Detection.** The `writeTo:` CFG walk captures top-level writes carrying a literal
field number 0 (`writeto.py`, `zero_writes`), binds them to their ivar, and the
extractor emits `_FIELD_ZERO_NOTE` for any such field that ends up *estimated*
(a field whose number is otherwise confirmed needs no flag). Conservative: only
simple direct-field writes are captured (not nested/submessage writers).

**Heuristic registry.** `ordinal-fieldnum` (the ivar-order estimate the field number
falls back to) — `heuristic_registry.py`.

---

## 5. Proto-to-proto subclasses omit their inherited (parent) fields  — to-do #50

**Symptom.** A proto message whose ObjC superclass is *itself* a proto message emits
only its own fields; the fields it inherits from the parent are not shown. The message
carries a comment naming the parent:

```proto
message GEOSearchRequest {
  // inherits all fields from GEOPlaceSearchRequest
}
```

Three of the five such GeoServices classes emit with no own fields at all (just the
comment).

**Why.** Each ObjC subclass declares only its *own* field ivars; the parent's fields
live on the parent class, and the subclass's `writeTo:`/`readFrom:` serialize them via
`[super writeTo:]`. The extractor recovers fields per class from ivars, so a subclass
message naturally contains only the subclass's own fields.

**Accepted as-is (owner decision).** The inline `// inherits all fields from <Parent>`
comment (`ProtoMessage.inherits_from`) is considered sufficient — it tells the reader
exactly where the remaining fields are defined (the named parent message, which the
tool *does* emit in full). Merging the parent's fields into the subclass message (the
would-be fix) is not pursued: it risks field-number collisions and duplicates a
definition that already exists on the parent. To reconstruct the complete wire layout,
read the subclass's own fields plus the parent message's fields.

**Known affected classes (GeoServices).** The 5 proto-to-proto subclasses recovered by
the PBCodable forward scan — e.g. `GEOSearchRequest` (→ `GEOPlaceSearchRequest`),
`GEOAnalyticsPipelineSharedStateData`, `GEOComposedWaypointEVStop`.

**Source site.** `proto/models.py` / `proto/emitter.py` (`ProtoMessage.inherits_from`
→ the `// inherits all fields from …` comment).


## 6. Recovered enum *type names* are a convention-only reconstruction  — to-do #57

**Symptom.** An enum's emitted TYPE name may be un-idiomatic or may not match Apple's
internal name — e.g.:

```proto
enum ApLocationprecisiontype { … }   // from AP_LOCATIONPRECISIONTYPE_* value strings
```

The enum's VALUES, the field's number, and the wire encoding are all unaffected — only
the type *name* is a best-effort reconstruction.

**Why.** Apple does not store the enum type name in the binary. The extractor derives it
from the common SCREAMING_SNAKE prefix of the value strings (`_enum_name_from_pairs`),
falling back to the field-derived name. ~220 of 318 GeoServices derivations are
convention-only (no `StringAs<Name>:` selector witnesses the name), and a few mangle
acronyms or lose word boundaries (`AP_LOCATIONPRECISIONTYPE_*` → `ApLocationprecisiontype`;
`AR_*` → `Ar…`).

**Accepted as-is (owner decision).** No wire/value/number impact — a wrong type *name*
does not affect decoding. Not flagged inline: it would add noise to a large fraction of
enums for a purely cosmetic issue. Same-name collisions across classes are reconciled
correctly by the emitter (split on value-set incompatibility + rename), which is
principled, not a guess.

**Source site.** `proto/enums.py` (`_enum_name_from_pairs`, `_qualify_enum_name`); the
emitter reconciliation `_collect_enums` / `_best_in_compat_group` (`proto/emitter.py`).
Analysis: `notes/ENUM_NAME_FROM_PREFIX.md`; census `apple_protobuf_extractor/census_enumname.py`.


## 7. A few repeated-element types are inferred from the field *name*  — to-do #45

**Symptom.** For a small number of `repeated <Message>` fields, the element type is
recovered not from the binary's dispatch but from the **field name** (e.g.
`photoPositions` → `GEOPDPhotoPosition`). These are flagged inline:

```proto
repeated GEOPDPhotoPosition photoPositions = 3;  // type guessed from field name (name-suffix heuristic / Strategy 2), unverified — see FIELD_TYPE_INFERENCE.md
```

**Why.** The element type is normally bound from the `readFrom:`/`writeTo:` dispatch.
For these classes that path yields nothing: the class has a `readFrom`, but its
dispatch core does not resolve (no compare chain, and the jump table doesn't decode),
and the per-field reader (`-[Cls _read<Field>]`) reads the element through a **generic
reader keyed by a descriptor pointer** — e.g. `_readPhotoPositions` makes no
`bl _<Element>ReadAllFrom` and carries no `_OBJC_CLASS_$_<Element>` class-ref, only a
generic helper + a descriptor (`0x18d8547b4` family). So **no structural site names the
element type** — only the ivar/method name does. This is intrinsic: the binary genuinely
doesn't encode the element class at the field site.

**How it's recovered (and bounded).** `proto/repeated.py` (`_repeated_element_type`,
Strategy 2) strips a plural `-s`, capitalises, and accepts the result **only if it
uniquely matches a class in the classlist**. It is a guess from convention, so it is
flagged inline rather than presented as confirmed. The companion refinements in
`_resolve_repeated_field_type` (pool-suffix + write-helper string check) are *not*
guesses — they read ground truth — and are unaffected.

**Known affected fields.** 22 fields (GeoServices 20, locationd 2, CoreLocationProtobuf 0),
e.g. `GEOPDGroundMetadataTile.photoPositions`, `GEOPDSearchACHintMetadata.*`.

**Workaround for consumers.** Treat the element type on a flagged field as a best-effort
guess; confirm it by hand against the owning class's `readFrom:`/`writeTo:` (or the
generic-reader descriptor). The field number and `repeated` label are correct.

**Source sites.** The guess is produced in `proto/repeated.py` (`_repeated_element_type`,
Strategy 2); the inline flag `_NAME_SUFFIX_GUESS_NOTE` is defined and attached in
`proto/extractor.py`. Detailed analysis: `notes/FIELD_TYPE_INFERENCE.md`. (Note: this
flag points readers to `FIELD_TYPE_INFERENCE.md` — the dedicated write-up — rather than
back to this file, unlike limitations (1)/(2)/(4).)

**Heuristic registry.** Four rows, all tagged `[LIM 7 / to-do #45]` —
`namesuffix-s2` and `s1-selsynth` (`_repeated_element_type` Strategies 2 and 1),
`resolve-namesuffix` (`_resolve_repeated_type`), and `pool-suffix`
(`_resolve_repeated_field_type`, base-candidate only — its pool-match + write-helper
refinements read ground truth and are NOT part of this limitation).

---

# Foreign-serializer limitations (non-PBCodable)

The extractor also decodes other protobuf runtimes (C++ libprotobuf-full,
swift-protobuf) and detects two more (GPBMessage, libprotobuf-lite). The items
below are their accepted limitations. **C++ libprotobuf-full has none** — it is a
direct decode of the embedded `FileDescriptorProto`, so every field number, type,
label, name, enum, and nesting is read literally from the descriptor (verified
field-for-field against Google's `descriptor_pb2`: 0 mismatches over 2626 fields /
70 protos; see `notes/SWIFT_PROTO_HAND_VERIFICATION.md` Part 2). It makes **no
estimates**.

## 8. GPBMessage (Google protobuf-objc) is detected but not decoded  — to-do #64 (deferred)

**Symptom.** An image using Google's ObjC `GPBMessage` runtime is reported by
`--list-serializers` as `[DETECTED — not decodable by this tool]`; no `.proto`
schema is emitted for its messages.

**Why.** `GPBMessage` subclasses carry their schema in a static
`GPBMessageFieldDescription[]` table built by each class's `+descriptor` method.
Decoding it is tractable (numbers, types incl. integer subtype, labels, enums, and
names are all in the table) but the struct layout is protobuf-objc-version-specific
and some builds compact the field-name strings — a substantial, separate effort.
**Accepted as a deferred limitation.**

**Known affected (libexec).** `anomalydetectiond`, `transparencyStaticKey`,
`transparencyd` (Key Transparency); ~180 GPBMessage images cache-wide. The tool
does **not** silently emit a wrong schema — it reports detect-only.

**Source sites.** `proto/extractor.py` (`google_protobuf_classes`,
`_GPB_RUNTIME_SUFFIX`); `proto/foreign.py` (`summarize_serializers`, the
`decodable=False` GPB summary).

---

## 9. C++ libprotobuf-lite messages are detected but not decoded  — to-do (deferred)

**Symptom.** An image built against `libprotobuf-lite` is reported by
`--list-serializers` as `C++ libprotobuf-lite … [DETECTED — not decodable by this
tool]` with a note; no `.proto` schema is emitted.

**Why — intrinsic.** `LITE_RUNTIME` strips the embedded `FileDescriptorProto` (and
all reflection), which is precisely the structure the full-C++ path decodes. So
the descriptor decode finds nothing. Field **numbers** (tag immediates) and **wire
types** (the `Write*`/`Read*` helper called) and **message type names** (C++
symbols) could in principle be walked out of the generated serialize/parse code,
but **field NAMES are intrinsically unrecoverable** — lite removes the table that
holds them. The realistic output would be a wire-faithful but **anonymous** schema
(`field_5`), of low value, so decode is **accepted as a deferred limitation**.

**Known affected (cache).** 7 images carry `google::protobuf` symbols with 0
descriptors: `MLAssetIO`, `CoreML`, `MIL`, `libCommCenterAWDMetrics`,
`libAWDProtobuf{Location,Bluetooth,Facetime}`, `libprotobuf-lite.dylib`. 0 in
libexec. The tool reports detect-only — never a fabricated schema.

**Source sites.** `proto/extractor.py` (`cpp_protobuf_namespaces`, the symbol
scan); `proto/foreign.py` (`summarize_serializers`, the `CPP_LITE_SERIALIZER`
detect-only summary).

---

## 10. swift-protobuf makes a few type/number estimates  — to-do #63b

Unlike C++ (an exact descriptor decode), swift-protobuf carries **no single
descriptor**: the schema is split across the `_protobuf_nameMap` (number↔name) and
the `__swift5_fieldmd` reflection metadata (name↔type), joined by NAME. Field
**numbers and names are read literally** (closure/blob immediates + cstrings) and
are exact — **except** the cases below. Well-known types built at runtime
(`Google_Protobuf_*`), copy-on-write `_StorageClass` fields and proto `oneof` members
are recovered exactly.

**(a) A single-field message's number can be estimated (flagged).** For the compact
single-field "tail-call" lowering the number is not in the nameMap closure. It is read
from two independent structural sources — `decodeMessage`'s field-number compare and
`traverse`'s per-field visit immediate — and treated as confirmed only when they agree
on exactly one value. When neither yields a single number it falls back to **1** with
`number_confirmed=False`, rendered as `// number estimated`.

**(b) Integer subtype is collapsed to the base type (NOT flagged).** `int32`,
`sint32`, `sfixed32` and `fixed32` are all `Int32` in Swift (likewise the `uint*`/`*64`
analogues), so `swift_type_recovery` emits the base (`int32`/`uint32`/`int64`/
`uint64`). For a genuinely `sint*` (zigzag) or `fixed*`/`sfixed*` (wire type 1/5)
field this is **wire-incorrect**. `Float`/`Double`/`Bool`/`String`/`Data`/`Array`/
`Dictionary` are correct. **Why it is not recovered:** the signal exists (`traverse`
selects the exact `visitSingular<Type>Field` by witness-table slot offset) but is not
extractable on the available inputs: cache-mode `.symbols` carries no `traverse` symbol,
so the slot map cannot be built, and in binary mode the sint/fixed `visitSingular*`
calls appear only in SwiftProtobuf library plumbing types, never in an app or framework
schema message — every application integer field surveyed is a plain
`Int32/UInt32/Int64/UInt64`. No affected field is known; a corpus with a genuine
`sint*`/`fixed*` Swift field and a resolvable `traverse` would need the subtype read
from the witness-slot map.

**(c) Undecoded container element (flagged).** When an Array element or a map
key/value doesn't decode, the field shows a `bytes` filler with an inline
`// swift-protobuf: container element/value type not recovered (shown as bytes)` note.
A genuine `[Data]`/`repeated bytes` is not flagged. The `map<>` value is still commonly
a filler (see (1)).

**Unrecovered types.** A fully-unrecovered type is emitted as `bytes` with the inline
`// swift-protobuf: type not recovered` note rather than a guess.

**Source sites.** `swift_type_recovery.py` (`_SWIFT_SCALAR`/`_DIRECT`,
`decode_mangled`); `swift_descriptor_extract.py` (`_single_field_tail_call`,
`_attach_field_types`); `proto/foreign.py` (`_swift_field`). The integer-subtype
limit is documented in the module docstring.


# Newest-toolchain limitation (arm64e)

## 11. Newest arm64e builds (iPhone17,3, macOS 27, iOS 27): some repeated-message elements degrade

**Status 2026-10-04 (iOS 27, macOS 27 re-run; see `notes/descriptor_comparison_2026-10-04/REPORT.md`).**
Of the classes listed below, the six with a compare-chain engine and a single data table at the call
site (`GEOBatchRevGeocodeResponse`, `GEOLPRWorld`, `GEOPDGroundMetadataTile`,
`GEOPDSearchBrandTriggerInfo`, `GEOSearchAttributionManifest`, `GEOURLPresent`) now resolve: ownership
is accepted from a `__TEXT,__const` table argument (`_call_site_passes_const_table`) together with an
engine that independently dispatches and loads the class's own ivar slots. On macOS 27 the two jump-table
classes and `GEOTFIncident` still degrade (`GEOTFCompactRoadSpeeds`, `GEOTFRoadSpeed`, `GEOTFIncident`), as does
`PDRawAttributeFilter.keys` (`repeated string` emitted as `bytes`); on iOS 27 none of the 1060-message closure of
the decoded geo roots differs from iOS 16 in a field number or an element type except where the later OS is
better. The same session fixed four newer-toolchain shapes that were not element-type problems: a
`writeTo:` tail call into another image made the walk raise and the class fall back to "number estimated"
(594 -> 32 estimates on iOS 27); `lsl field,#3` ahead of the `bfi` hid sfixed32 helpers (`LatLngE7`); enum
`switch` tables with signed `ldrsw` byte-delta entries and bitmask-gated pointer tables left enums as `int32` or partial;
and `mov w1,#0x10000` (`os_unfair_lock` option) was read as a double field number 65536. Tests:
`tests/test_newer_toolchain_ios27.py`. These runs remain outside the golden snapshots.

**Symptom.** On these builds, 13 message-typed GeoServices fields in 10 classes
(iPhone17,3) and 11 in 9 classes (macOS 27), out of ~3,700 compared against the
iPhone8 golden schema, come back as `repeated bytes`, flagged as in (2). A further ~25
(iPhone17,3) / ~20 (macOS 27) fields bind to a wrong class; these have not been
examined.

**Why.** A class's `readFrom:` is a thin wrapper that calls a per-class dispatch
*engine*, choosing one of two data tables with a `csel` at the call site. The engine
dispatches with a compare tree on the field number and has no `cmp Wn,#N; b.hi` range
guard. The extractor accepts such an engine as the class's own only when three things
hold: the call site is that dual-table `csel` (`_call_site_selects_data_table`); the
engine independently dispatches for real (`_core_resolves_compare_chain`); and it loads
one of the class's own ivar-offset variables (`_core_loads_own_ivar_slot` — by slot
address, so an engine belonging to another class is not accepted; it fails closed when
the class's slots are unknown). The classes still degraded fall short of that:

- 6 classes resolve as a compare chain but their call site has no `csel` of two data
  tables, so ownership cannot be confirmed and is deliberately not assumed:
  `GEOBatchRevGeocodeResponse`, `GEOLPRWorld`, `GEOPDGroundMetadataTile`,
  `GEOPDSearchBrandTriggerInfo`, `GEOSearchAttributionManifest`, `GEOURLPresent`;
- 2 classes have a jump-table cluster that is not resolved
  (`GEOTFCompactRoadSpeeds`, `GEOTFRoadSpeed`);
- 1 class has an engine shape that is not understood (`GEOTFIncident`);
- on iPhone17,3 only, `GEOETAResult`, for a reason not identified.

**Pointer authentication is not the cause.** Pointer *encodings* are decoded: in cache
mode by the cache reader, and in binary mode for chained-fixup formats 1, 2, 6, 9 and
12 (12 is `DYLD_CHAINED_PTR_ARM64E_USERLAND24`, what a current toolchain emits for every
arm64e dylib and executable). The signature, key and diversifier of an authenticated
pointer are ignored — only the target is needed. Not decoded: the other chained-fixup
formats (32-bit, e.g. arm64_32; kernel-cache; firmware). PAC-authenticated indirect
*branches* (`braa`/`blraa`) occur in these images only in the runtime's call-stub
islands, which the `writeTo:` helper resolver handles (`proto/write_helpers.py`); none
was found inside a `readFrom:` dispatch function. Whether PAC-authenticated indirect
dispatch exists in some other class has not been measured.

**Implementation note.** `_func_end` (used for arm-range validation and the compare-chain
dominance walk) is CFG-reachability based and counts an in-window tail-call
`b <stub>` as an intra-function edge, so on plain arm64 a function ending in a tail call
is credited with the stub island and every function between. The ownership check does
not use it (it uses the tight extent `_core_insns`); the other users do.

**Source sites.** `proto/dispatch.py` (`_find_dispatch_core_via_wrapper`,
`_core_loads_own_ivar_slot`, `_core_insns`); `proto/arm64cfg.py` (`ivar_slot_loads`);
`macho/classlist.py` / `macho/objc_model.py` (`ObjcIvar.offset_slot`);
`macho/memory.py` (chained-fixup decoders). Ground-truth fixtures:
`tests/synthetic_fixtures/f27_compare_tree_engine_no_guard`, `f25_newer_dispatch_engine`,
`f26_arm64e_fixups`.
