# Known limitations — apple_protobuf_extractor

These are the **accepted limitations** of the `.proto` extractor. They
are documented rather than fixed: each is a small, well-characterised slice of the
output where the recovered schema is incomplete or degraded. Where the limitation
touches a specific emitted field, the descriptor output carries an inline `// …`
comment pointing back here, and the relevant source sites carry a `LIMITATIONS.md`
reference. Items are tagged `to-do #N`: those numbers are identifiers from the project's original
task list (no longer in this repository), kept so the code comments still
cross-reference the same limitation.

Several limitations are the residual of a heuristic that survives because no principled
signal exists for the residual slice; those carry a **Heuristic** line naming the fallback.
Limitations (3), (5), (6), (11), (12) are extractor/emitter-level, not heuristic fallbacks.

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

The iOS 27 and macOS 27 caches are larger than 4 GB and use slide-info version 5, where a data pointer's target is the
low 34 bits (an offset from the cache base). The cache reader reads the slide-info version of each cache file and
uses 34 bits for version 5 (32 bits for older caches). Before this, every image whose data lies past `cache_base + 4 GB`
(about a third of the images, e.g. `MessageProtection` and `TrustedPeers`) returned a wrong ObjC class list with no error,
so a result of "no classes" on a version-5 cache from an older Extractor is not evidence that the classes are absent.

**Residual cases (each flagged inline, never silently wrong):**

* **No map-entry writer in `writeTo:`** — the field stays `bytes // number estimated;
  map<> field … no map-entry writer found in writeTo:`, unless the class's `writeTo:` provably
  never serialises the dictionary, in which case it is not emitted at all
  (`proto/writer_flow.py`).  That was the only case seen: `PETProtobufRawDecodedMessage`
  (`decodedDict`, `nestedFields`, ProactiveEventTracker), whose `writeTo:` is a bare `ret` —
  the two ivars are the ObjC decoder's runtime output, not wire fields; since 2026-10-15 the
  message emits no fields and says that `writeTo:` serialises none of its ivars.
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

**Heuristic.** None of the recovery is heuristic: write-helper types are the
unanimous types of the ivars using them binary-wide, the value class is the proto class
referenced inside the field's own `readFrom:` handler region. The only fallback is the legacy `bytes`
default type.

---

## 2. Sub-messages with no ObjC class: inline C structs (recovered) and unnamed repeated elements (residual)  — to-do #37 (inline structs DONE 2026-10-06)

**What is recovered.** Apple's compiler stores an all-scalar sub-message as a plain C struct
rather than an ObjC object: a *singular* one by value (`@encode` `{GEOPDTimeRange=…}`), a
*repeated* one as an array of them (`^{GEOWiFiQualityTimeRange=II{?=b1b1}}` plus the `_xCount` /
`_xSpace` ivars). `proto/structfields.py` now emits each as a real message, with confirmed
numbers and no comment, from three sources that are all in the binary:

- the struct's **name and member layout** — the ivar `@encode`;
- each member's **field number and wire type** — the struct's C serialiser (`has-bit test ;
  load [struct+offset] ; write(field#)` per member), whether it is a called function or inlined
  between the begin/end marks of the owner's `writeTo:` (the has-bit tests of an inlined struct
  put some members out of line, past the loop's back-edge, so the body is walked as a CFG
  region, with a symbolic base-register tracker that follows the ivar-offset variable);
- each member's **name** — the `@encode` where it names members (`"_duration"I`), otherwise the
  `CFString` keys of the struct's dictionary representation (a called function, or inlined into
  the owner's `_dictionaryRepresentation:`).

A struct is accepted only if the writer's member offsets and load widths equal the `@encode`
layout exactly (every member written once, none at an unknown offset), and every owner of one
struct tag agrees on numbers, names and wire families; otherwise it keeps the flagged `bytes`
fallback below. One message is emitted per struct *tag* (`GEOWiFiQualityTimeRange` →
`WiFiQualityTimeRange`) and carries an `// inline C struct '<tag>' …` comment. On the iPhone 8
GeoServices image this retypes 78 fields (41 arrays, 37 by value) and adds 28 messages.

The struct serialiser is read by data flow: it is evaluated with the struct and the writer as
opaque tokens, a write is a call handed the writer, and its field number (w2; w1 for a
float/double, whose value rides in v0) and member load are found by constant evaluation and
reaching definitions, not by instruction windows. Until 2026-10-16 a backward window was used,
and the newer toolchain (macOS 27 / iOS 27, arm64e) defeated it in three ways:

- the last member's tail call carries the return-address check (`autibsp ; eor x16,x30,x30,lsl #1 ;
  tbz x16,#62 ; brk`) between its argument setup and the branch;
- an inline array element is addressed as `add xS,self,xOff ; ldr xA,[xS] ; add xE,xA,xI,lsl #s`;
- macOS 27 leaves `_dictionaryRepresentation:` out of the method list. Its body is found from
  `-dictionaryRepresentation`'s tail call handed self with the flag 0, or with x1 never written
  (the compiler drops the argument when the body does not read it).

Those builds had left 64 (macOS 27) and 66 (iOS 27) GeoServices struct fields as `bytes`. Now
none is, and every struct the iPhone 8 image also has comes out identical (numbers, names,
types, enums), plus `GEOPBOfflineDataLayerVersion`, which only the newer builds have.

**Residual (still emitted as flagged `bytes`).**

- **`NSMutableArray` elements of an unnamed class** (20 GeoServices fields, e.g. the
  `GEOPDSearchKey…PairList.pairs` family, `GEOPDTileList.tiles`). The ivar is an object array and
  the element class has no ObjC methods to read, so the dispatch has no body to resolve against
  (INTRINSIC — the binary does not name the element at the field site):

```proto
repeated bytes pairs = 1;  // element type could not be determined; emitted as bytes — each element may be an unparsed message; see LIMITATIONS.md (2)
```

  The field number and the `repeated` label are correct; only the element *type* is degraded.
  A genuine `NSData` field (`@encode @"NSData"`) is a real `bytes` and is deliberately NOT flagged.
- **Structs that are not a flat struct of scalars** (a nested struct member, a pointer or object
  member, a bare bitfield) are not modelled and keep `bytes`. None occurs in a serialised
  GeoServices field today (the polyline-range and `GeoCodecs*` structs are not wire messages).

**Naming and typing caveats (all cosmetic or sign-only; numbers and wire forms are exact).**

- The message name is the C struct tag with the class prefix stripped; Apple's own `.proto`
  name for these inline messages is not recorded in the binary.
- Member names come from the `@encode` or, when it names none, from the dictionary
  representation, read at each `setObject:forKey:` call: the key is x3's value there (constant
  propagation over the whole function, once per value of the JSON flag argument, stack spills
  included), the member is the one whose value x2 files (a boxed number traced by use-def, or an
  enum name whose switch run reaches that call). A key chosen at run time
  (`isJSON ? @"startTime" : @"start_time"`) gets the camelCase spelling. A member no source names
  is emitted `field<N>` with an inline note: none in the iPhone 8 protos today. Not traced (the
  member stays unnamed, never given a nearby key): an enum member whose name switch cannot be
  evaluated, and a JSON flag that the function only ever tests after reloading it from the stack.
- `int32` vs `uint32` (and 64-bit) is not recoverable from the `@encode` + helper any more than
  for ordinary fields (see the README caveat); sint/fixed forms are recovered from the write
  helper as usual.
- **Enum-typed members** (`GEOTimepoint.type`, `GEOJunctionElement.type/usage`, `GEOGenericTile.tileType`,
  `GEONavigationAudioFeedback.currentRouteTypeAtEndOfNav`, `GEOVLFPositionContextClassification.type`) are
  recovered as enums from the struct's dictionary representation: a member emitted through the
  compiler-inlined `xAsString:` (a name switch ending in the CFString `"(unknown: %i)"`) is an enum, and
  the switch's compare chain / pointer table gives the values (read by the same readers as the class-level
  `_dictionaryRepresentation:` recovery). The enum TYPE name is reconstructed (it is not in the binary;
  cosmetic). A member that shows the name switch but whose switch is a `br` jump table, or on which owners
  disagree, keeps `int32` with the "unresolved enum" comment. See
  `notes/STRUCT_ENUM_RECOVERY_2026-10-13.md`.

**Source sites.** `proto/structfields.py` (recovery); `proto/extractor.py` (`record_struct_site`
in the field loop, `finalize_struct_fields` at the end of `extract_all`;
`_ELEMENT_UNRESOLVED_NOTE` for the residual); `proto/models.py` (`ProtoMessage.inline_struct`);
`proto/emitter.py` (the provenance comment).

**Heuristic.** The recovery itself is principled. Its only judgement calls are two cosmetic
naming choices (the camelCase key spelling and the `field<N>` placeholder above); the residual
is the `bytes` default-type fallback. (Distinct from the (now removed) name-suffix fallback that used to be limitation (7); this
one fires when the type cannot be named at all.)

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

**Heuristic.** The ivar-order estimate the field number falls back to.

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

All five such GeoServices classes emit with no own fields (just the comment).

**Why.** Each ObjC subclass declares only its *own* field ivars; the parent's fields
live on the parent class, and the subclass's `writeTo:`/`readFrom:` serialize them via
`[super writeTo:]`. The extractor recovers fields per class from ivars, so a subclass
message naturally contains only the subclass's own fields.

**A subclass with no `writeTo:` of its own** (4 of the 5: `GEOSearchRequest`,
`GEOSearchResponse`, `GEOAnalyticsPipelineSharedStateData`, `GEOComposedWaypointEVStop`)
is serialised by the parent's `writeTo:`, which reaches only the parent's ivars, so the
subclass's own ivars are not wire fields at all.  These messages emit no fields and say
so (`// no writeTo: of its own: serialised by <Parent>'s writeTo: …`;
`ProtoMessage.serialised_by`, `proto/extractor.py:_inherited_writeto_owner`).  Until
2026-10-15 their ivars were emitted with ivar-order "number estimated" numbers that
collided with the parent's real fields (AnalyticsPipelineSharedStateData 1-19,
ComposedWaypointEVStop 1-6; found by the whole-image IDA cross-check).  The rule needs
every method name on the subclass resolved, the parent's `writeTo:` in the image, and
that `writeTo:` to send no selector the subclass implements; otherwise the old
behaviour stands.  Not checked: a send made by a function the parent's `writeTo:` calls.

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
→ the `// inherits all fields from …` comment; `ProtoMessage.serialised_by` → the
`// no writeTo: of its own …` comment).


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
Analysis: `notes/ENUM_NAME_FROM_PREFIX.md`.


## 7. ~~A few repeated-element types are inferred from the field *name*~~  — CLOSED 2026-10-13 (to-do #45)

**Status: removed.** Until 2026-10-13 a small number of `repeated <Message>` fields took their
element type from the **field name** ("Strategy 2" in `proto/repeated.py::_repeated_element_type`:
strip the plural `-s`, capitalise, accept the result if it uniquely matched a classlist name's
suffix) and were flagged inline with `// type guessed from field name (name-suffix heuristic /
Strategy 2), unverified`. That matcher is **deleted**, because the binary does encode the answer
and the guess was wrong where it could be checked:

* `GEOPDSSearchEvChargingParameters.networks` and `GEOPDSearchSearchChainInfo.triggers` are
  `repeated string` (their `writeTo:` calls the NSString write helper) but were typed
  `GEOLogMsgEventNetwork` / `GEOPDSearchBrandTrigger`.
* locationd `TRANSITPbLocationFingerprintsV1.locationFingerprints` took the sibling class
  `TRANSITPbLocationFingerprint` (the reader loads `TRANSITPbLocationFingerprintV1`).

**What replaces it** (all read from the binary, none from names):

1. the field's `writeTo:` helper — the NSString helper is checked first and decides `repeated
   string` (`_resolve_repeated_field_type`);
2. the readFrom: dispatch / adder->ivar lever (`proto/dispatch_eval.py`): the element class the
   field's handler allocates (`[[Element alloc] init]`) and hands to the add-accessor, read from
   the call arguments (a method, an `objc_direct` C function or an `_objc_msgSend$<selector>`
   stub alike);
3. the inline-C-struct encoding (`GEORPFeatureHandle.styleAttributes` is now the named struct
   message `RPFeatureHandleStyleAttribute`);
4. otherwise the honest `repeated bytes` plus the "element type could not be determined" flag.

Effect on the iPhone 8 artifacts: GeoServices 18 of 8048 fields changed (2 string fixes, 16 formerly
unresolved `repeated bytes` now typed, e.g. `GEOPDTileList.tiles` -> `GEOTileCoordinate`), locationd 2
of 445, CoreLocationProtobuf 0 of 530. The class-reference lever was calibrated against the
dispatch lever on the fields both resolve: 516 of 516 agree (gated in
`tests/test_repeated_element_types.py`).

**No name matching left.** The exact-suffix refinement against the pool of all `+xyzType`
classes (the pool-suffix match, with `_build_meta_type_pool`) was deleted too: it never fired on any
iPhone 8 image and on iOS 27 it rewrote one field of the resolver's own answer wrongly
(`GEOSpokenGuidance.announcements`, `GEOFormattedString` -> `GEOCompositeAnnouncement`; the
structural lever overrode it, so no emitted output changed anywhere: the deletion is
output-identical). The `+xyzType` lookup itself
(the selector synthesis: depluralise the field name, append `Type`, read the class out of the method's
IMP) is the PB runtime's own lookup (the `ProtocolBuffer` image builds `Type`/`add`/`set`/`Count`
selectors from property names; nothing in the analysed images references them) and agrees with
the structural levers on all 1104 fields both resolve.

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

**(d) Enums.** Enum name maps (case value ↔ case name) are read by the same shapes as
messages, and each enum is written as a proto `enum` that its fields reference. Values
may be 0, negative or large. Two cases sharing a value (an alias) are written as one
value with the alias in a comment, because the flat emitter has no `allow_alias`; names
that `protoc` would reject (equal ignoring case and underscores, or reused by another
enum of the package) are renamed with a comment. No `decodeMessage` exists to
cross-check an enum, so a table is accepted only if it is sorted by value with distinct
identifier names, which is how protoc-gen-swift writes it. Known gaps:

- an enum that fails that check, or whose name map is built at runtime (an enum with
  aliases, in the classic lowering), is reported with no cases, and its fields fall back
  to `int32` with a note, never to wrong cases (about 3% of the enums in the images
  surveyed);
- the packed iOS 27 lowering handles aliases, the classic one does not.

Type references are otherwise resolved so that the output compiles under `protoc`:
a nested type is referenced by its qualified, flattened name
(`EscrowInformation_Metadata_ClientMetadata`); a type that is defined outside the
image's own name maps (another module such as `Ckcode_*`, or the well-known types
`Google_Protobuf_*`) is emitted as `bytes` with an `unresolved:` note. That is
wire-correct for a message but not for an enum from another module.

**(e) Messages with no fields.** Two different things used to be written as
`// (no fields recovered)`. A message is now marked `// opaque passthrough — serializes
only PBUnknownFields (no typed fields in this build)` when no name-map entries were read
**and** Swift reflection independently lists no stored proto field for the struct: it is
genuinely empty (only swift-protobuf's `unknownFields`). `// (no fields recovered)` is
kept for a message whose name map could not be read, so it now means a real miss. In the
30 swift-protobuf images surveyed (2,351 messages), 185 have no fields: 139 are the first
kind and 46 the second (31 of them in `PegasusAPI`, which uses several further getter
lowerings, 5 built inline in `StrokeAnimation`, and a handful elsewhere).

Two readings have no cross-check of their own, a runtime-built name map with exactly one
entry and a one-entry arg-setup stub, so they are accepted only if the struct's
reflection lists a field with that name (a sibling type's closure otherwise gets
read as the message's own).

**Unrecovered types.** A fully-unrecovered type is emitted as `bytes` with the inline
`// swift-protobuf: type not recovered` note rather than a guess.

**Source sites.** `swift_type_recovery.py` (`_SWIFT_SCALAR`/`_DIRECT`,
`decode_mangled`); `swift_namemap_bytecode.py` (the iOS 27 packed name map);
`swift_descriptor_extract.py` (`_single_field_tail_call`,
`_attach_field_types`); `proto/foreign.py` (`_swift_field`). The integer-subtype
limit is documented in the module docstring.


# Newest-toolchain limitation (arm64e)

## 11. Newest arm64e builds (iPhone17,3, macOS 27, iOS 27): readFrom: dispatch  — RESOLVED 2026-10-15 (residuals below)

**Status 2026-10-15.** The readFrom: field dispatch is decoded by evaluation
(`proto/dispatch_eval.py`), not by matching its shape.  Starting from `-readFrom:` with
`self` and the reader as opaque tokens, the core is the function handed this object; each
candidate field number is set where the field number is extracted (`lsr`/`ubfx Rn,#3`)
and run through calls to its handler; the handler's element class, adder and ivar are read
off the call arguments.  Measured over every PBCodable class of three builds against the
iPhone 8 golden schema: no binding lost and none wrong; iPhone 8 and all seven
`ios_decoder/protos` frameworks byte-identical; on macOS 27 the 19 dispatch-caused
`repeated bytes` fields (TFCompactRoadSpeeds / TFRoadSpeed / TFIncident,
PDSearchQueryIntentMetadata x2, PDSearchKey*PairList.pairs x12, PDTileList.tiles,
SupportedTileSets.tileSets) now carry the golden element class, plus 4 newer fields; on
iOS 27 one more map value class.

**What it was.** Not the jump tables, which decoded: the macOS 27 accessors are
`objc_direct` (no method-list IMP), and elements are allocated through a direct `class_t`
address, so every ownership/adder signal keyed on own-method IMPs or classref loads failed
(e.g. GEOTFCompactRoadSpeeds' engine 0x198746638 decoded 10 arms with field 5 ->
TFCompactPredictedSpeed, yet its ownership gate rejected it: no arm calls an own IMP; the
adder is the C function 0x19874757c).

**Residuals.**
- ~60 message-typed fields on these builds are inline C-struct ivars (`{GEOTimepoint=...}`,
  `^{GEOTileSetRegion=...}`): item 2's struct recovery, not dispatch.
- The evaluator's assumptions: a callee handed a frame address writes only at or above it and
  does not keep it; `-init...` and the ARC retain/handshake functions return their argument
  (named only where a standalone binary binds them); an unknown field number behaves as one
  past every compared value.  The CFG is still seeded with the decoded jump tables
  (`proto.dispatch._jump_table_arm_addrs`) plus `and`-masked tables evaluated per index: a
  control `br` ahead of the field-number extraction has an index the propagation cannot know.
- An element core is recognised through the readFrom core index: the function a thin
  `-readFrom:` wrapper hands its object and reader to (decided by data flow; an inline reader,
  or a `-readFrom:` that hands on only the reader, has none), over the image's proto-class set.
  Until 2026-10-15 the index took the first branch target, which put a runtime stub in it for
  every inline reader, and gated on the name heuristic, which left CoreParsec's empty (16
  CoreParsec repeated fields now typed; a 17th, `_CPListValue.values`, stays `bytes` because
  `_CPValue` holds a `_CPListValue`, an import cycle between per-class files).
- Selector names come from `_objc_msgSend$sel` stubs in both forms: the per-selector
  `adrp x1; ldr x1,[x1,#o]` and the shared `adrp x1; add x1,x1,#o; b _objc_msgSend` of iOS 27 /
  macOS 27 (about 52,000 handler sends per build; no output change, since those fields were
  already typed by other evidence).

**Pointer authentication is not a cause.** Pointer *encodings* are decoded: in cache
mode by the cache reader, and in binary mode for chained-fixup formats 1, 2, 6, 9 and
12 (12 is `DYLD_CHAINED_PTR_ARM64E_USERLAND24`, what a current toolchain emits for every
arm64e dylib and executable). The signature, key and diversifier of an authenticated
pointer are ignored — only the target is needed. Not decoded: the other chained-fixup
formats (32-bit, e.g. arm64_32; kernel-cache; firmware). PAC-authenticated indirect
*branches* (`braa`/`blraa`) occur in these images only in the runtime's call-stub
islands, which the `writeTo:` helper resolver handles (`proto/write_helpers.py`).

**Source sites.** `proto/dispatch_eval.py`; `proto/dictrep_flow.py` (`Flow.run_from`,
`Flow.propagate`, `_Machine`'s opaque values / object-escape rule); `proto/dispatch.py`
(`_build_readfrom_core_index`, `_jump_table_arm_addrs`); `proto/repeated.py` and
`proto/mapfields.py` (its consumers).  Tests: `tests/test_dispatch_eval.py`,
`tests/test_newer_toolchain_fixtures.py`; fixtures `f25_newer_dispatch_engine`,
`f26_arm64e_fixups`, `f27_compare_tree_engine_no_guard`.

---

## 12. protobuf-c (the C runtime) messages are detected but not decoded  — to-do (deferred)

**Symptom.** An image that embeds protobuf-c schema tables is reported by
`--list-serializers` as `protobuf-c (C runtime) … [DETECTED — not decodable by this
tool]`, listing each message descriptor's package-qualified name (`chunkserver.ChunkInfo`)
with a note giving the message / enum descriptor counts and the number of
`_protobuf_c_*` runtime symbols. It is also named in the single consolidated foreign-protobuf
warning. No `.proto` schema is emitted; the field names, numbers, types and enum values
are not read.

**Why.** protobuf-c schemas are static `ProtobufCMessageDescriptor` /
`ProtobufCEnumDescriptor` structs, so detection and naming are cheap and exact: each
begins with a 32-bit magic (`0x28aaeef9` / `0x114315af`) and holds the type name at +8.
Decoding the fields means walking 72-byte `ProtobufCFieldDescriptor` records (name, id,
label, type, default, and a descriptor pointer for message / enum types), which is
tractable (a short script reads them for MMCS) — but no image in either cache outside Apple's MMCS, TouchML and BiomeStreams uses the runtime, so
it was not built. **Accepted as a deferred limitation.**

**Detection.** The data segments are scanned for 8-byte-aligned magic words through the
`BinaryContext` memory API (`serializers/protobufc_detect.py`), so it works the same on a
standalone binary and a cache image. `__TEXT`, `__LINKEDIT` and `__PAGEZERO` are skipped;
every other segment is read, including `__AUTH_CONST` — on arm64e a message descriptor
holds a signed `message_init` pointer, so iOS 27's message descriptors are there while its
enum descriptors (no function pointer) stay in `__DATA_CONST`. A hit counts only if its
name pointer resolves to a dotted identifier and its entry count is sane; the count of
hits that fail this is kept in `ProtobufCDescriptors.rejected` and was 0 on every image
scanned. `_protobuf_c_*` symbols (binary mode: symbol table / export trie; cache-native:
the `.symbols` sub-cache) are reported as corroboration and are the only signal for an
image that carries the runtime but no descriptors; they are absent from stripped images
such as TouchML.

**Known affected.** iPhone 8 (iOS 16.7.11) cache, 2705 images: `MMCS` (48 messages,
1 enum) and `TouchML` (10 messages, 1 enum); 2 images. iOS 27 cache, 4695 images: `MMCS`
(52 / 1), `TouchML` (10 / 1) and `BiomeStreams` (232 / 57); 3 images. Binary mode over the
extracted iPhone 8 files (`libexec/`, the daemon binaries and `dylib/System`, 2607 binaries) gives the
same two frameworks and nothing else. No other image — GeoServices, locationd, CloudKit and the C++ /
swift-protobuf images included — produced a hit or a rejected magic word.

**Source sites.** `serializers/protobufc_detect.py` (`find_protobufc_descriptors`,
`protobufc_symbols`); `proto/extractor.py` (`protobufc_descriptors`,
`_warn_if_foreign_protobuf`); `proto/foreign.py` (`summarize_serializers`, the
`PROTOBUFC_SERIALIZER` detect-only summary); `cli.py` (`--list-serializers`).
Tests: `tests/test_protobufc_detect.py`.
