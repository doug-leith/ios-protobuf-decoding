# GEOPDReverseGeocodingResult is an OPAQUE PASSTHROUGH, not a typed wrapper

**Date:** 2026-06-17  •  **Binary:** GeoServices (iphone8 dyld cache, arm64)  •  Read-only analysis.

## TL;DR — the premise was half-right and half-wrong

The wire path `PDPlaceResponse.globalResult{3} → PDPlaceGlobalResult.reverseGeocodingResult{4}
→ PDReverseGeocodingResult { 100: 1 … }` decodes **correctly**. `PDReverseGeocodingResult`
really is field-less, so `// (no fields recovered)` is the **ground truth**, not an extractor
gap.

BUT it is **not** a "thin delegating wrapper to a typed inner message." It is a
**zero-field opaque passthrough**: a `PBCodable` subclass whose only ivar is the standard
`_unknownFields` (`PBUnknownFields`). Its `writeTo:`/`readFrom:` shuttle the entire wire body
through that generic unknown-field bag. **There is no inner typed class to resolve.**
**Field 100 is genuinely unmodeled by the GeoServices client** — it is the server's data that
this iOS build's client never introspects.

The "0x178" from the prior Hopper note is **not an instance byte-offset**; it is the *index into
the ivar-offset table* (`__objc_ivar` base `0x1e1dd8000` + `0x178`). The 4-byte value stored
there is **0x8** — i.e. the real instance offset of `_unknownFields`.

## Evidence (all re-derived from the cache, read-only)

### writeTo: @ 0x18c7e466c  (= classlist IMP for GEOPDReverseGeocodingResult)
```
adrp  x8, #0x1e1dd8000
ldrsw x8, [x8, #0x178]      ; x8 = *(i32*)(0x1e1dd8178) = 0x8  (ivar offset value, NOT 0x178)
ldr   x0, [x0, x8]          ; x0 = self->_unknownFields
b     #0x18db2fbc0          ; tail-call objc_msgSend$writeTo:  (sel 'writeTo:', _objc_msgSend 0x1800ba400)
```
`*(i32*)0x1e1dd8178 == 0x8`, and `_unknownFields` sits at instance offset `0x8`
(classlist: instance_size `0x10`, single ivar `_unknownFields @0x8 enc=@"PBUnknownFields"`).
So `writeTo:` ≡ `return [self->_unknownFields writeTo:stream]`.

### readFrom: @ 0x18c7e4660 → _GEOPDReverseGeocodingResultReadAllFrom @ 0x18c788cc8
A **generic** PB tag loop. It does **no** per-field-number dispatch (no compare-chain, no jump
table). For every tag it lazily allocs the inner bag and feeds the field through it:
```
ldrsw x8, [x24, #0x178]     ; x24=0x1e1dd8000 → x8 = 0x8 (same _unknownFields offset)
ldr   x0, [x20, x8]         ; existing self->_unknownFields
cbnz  x0, …                 ; if nil:
adrp  x8, #0x1dcfa5000
ldr   x0, [x8, #0xab0]      ; classref *(0x1dcfa5ab0) -> _OBJC_CLASS_$_PBUnknownFields
bl    …new                  ; self->_unknownFields = [PBUnknownFields new]
…
lsr   x1, x26, #3           ; x1 = tag>>3 = field number
mov   x2, x21               ; x2 = wire type
mov   x3, x19               ; x3 = reader
bl    #0x18dbdae88          ; [-_unknownFields readUnknownField:type:from:]
```
**The classref at `0x1dcfa5ab0` dereferences to `PBUnknownFields`** (confirmed two ways:
`bind_name_for` and `read_objc_class_name` on the decoded class_t at `0x1e1d7c638`). The read
helper `0x18dbdae88` takes `(field#, wiretype, reader)` — the canonical "absorb one unknown
field" entry point. Nothing types field 100.

## Survey — how common is this shape? (Task 3)

Scanned all **1637** GeoServices classes with a `writeTo:`. The "single-ivar load + tail-call
`writeTo:`" signature matches **78 classes**, and **all 78 load `_unknownFields`
(`PBUnknownFields`)**. **Zero** load a typed GEO/PB message.

> **There are no genuine "thin delegating wrappers to a typed inner message" in GeoServices.**
> The structural signature the task hypothesized exists, but every instance is an opaque
> passthrough, not a type alias. A general "wrapper→inner type" resolver would resolve to
> `PBUnknownFields` 78/78 times — i.e. it would recover nothing.

The 78 are mostly `…Filter` (request-side, e.g. `GEOPDAddressFilter`, `GEOPDBoundsFilter`),
`…Result`/`…LookupResult` (response-side, e.g. `GEOPDPlaceLookupResult`,
`GEOPDNearbySearchResult`, `GEOPDReverseGeocodingResult`,
`GEOPDBatchReverseGeocodingResult`), and a few `GEORP…Feedback` classes. All emit
`// (no fields recovered)` today (spot-checked 5/78). They are a subset of the 122
`(no fields recovered)` messages in `ios_decoder/protos/GeoServices/geo.proto`.

Contrast: the **request** twin `PDReverseGeocodingParameters` has real fields
(`locations`, `placeTypeLimit`, …). Only the **result** is opaque.

## Recommendation for ios_decoder (Task 4)

Neither option as originally framed applies:

- **(b) map the wrapper field to an inner message** — *not possible*. There is no inner typed
  message; the "inner class" is `PBUnknownFields`. Mapping field 100 to some other GEO message
  by structural guess would violate "leave unprovable mappings to raw-decode rather than
  guessing" (the wire content is a lone `100: varint`, far too thin to match anything).
- **(a) emit a delegates-to-`<Inner>` type-alias marker** — *not possible as a type alias*,
  because `<Inner>` is `PBUnknownFields`. The salvageable kernel of (a) is an **informational
  opaque-passthrough marker** (see below), not an alias.

**Recommended:**

1. **Keep raw-decoding the sub-message (status quo). It is already correct and complete.**
   `PDReverseGeocodingResult { 100: 1 … }` is the right output; field 100 is genuinely unknown
   to the client. This is *not* a decode gap and should stop being counted as one.

2. **(Optional, principled, extractor-side — low blast radius) Distinguish "opaque passthrough"
   from "extraction-incomplete."** Both currently print `// (no fields recovered)`, but they
   mean opposite things. A passthrough is structurally detectable with certainty:
   `instance_size == 0x10`, exactly one ivar `_unknownFields : PBUnknownFields @0x8`, and
   `writeTo:` is the 4-insn load-`_unknownFields`+tail-call-`writeTo:` stub. For those, emit
   e.g. `// opaque passthrough — serializes only PBUnknownFields; no typed fields in this build`.
   This tells humans and ios_decoder that raw bytes are the *complete* answer, not a TODO.
   (Do **not** implement now — concurrent session may be editing the extractor.)

3. **(Optional, ios_decoder-side) Reclassify the unknown-field note** for these known-opaque
   message types from "unknown field (gap)" to "expected (opaque container)", so the gap report
   (`mitm_traffic_parser`/decode notes) stops flagging `reverseGeocodingResult.100` as a miss.

## Uncertainties / flags

- I did **not** prove what field 100 *means* on the server side. It is provably unmodeled by
  the client; its semantics would require server-side schema, not this binary. Per project
  policy, that stays raw-decoded.
- Survey detector matched two writeTo shapes (offset-table-indirected "A", direct-immediate
  "B"); all 78 hits were shape "A". A handful of classes whose `writeTo:` is non-trivial but
  still ultimately field-less (e.g. group-encoded) would not match this signature — the 78 is a
  lower bound on "opaque", but it is the exact set matching the *task's* "load-one-ivar +
  tail-call" signature.

## Implementation status — option 2 DONE (2026-06-17)

Extractor-side opaque-passthrough marker implemented (option 2). Option 3
(ios_decoder unknown-field note reclassification) is a separate session.

- `proto/extractor.py`: `_is_opaque_passthrough(ctx, cls)` (+ `_writeto_self_load_offset`)
  — purely structural detector (single `_unknownFields:PBUnknownFields` ivar AND a
  leaf `writeTo:` that loads it and tail-calls `writeTo:`); wired into both
  `extract_proto_message` returns (the field-less early return is the live path).
- `proto/models.py` + `proto/emitter.py`: new `ProtoMessage.opaque_passthrough`
  flag → emits `// opaque passthrough — serializes only PBUnknownFields (no typed
  fields in this build)` instead of `// (no fields recovered)`.
- `snapshot_output.py`: records `<opaque_passthrough>` (golden now guards the set).
- Tests: `tests/test_opaque_passthrough.py` (live) + 2 emitter tests.

**Verification:** flags exactly **78** GeoServices classes (== the survey set),
incl. GEOPDReverseGeocodingResult; 44 field-less classes correctly KEEP
`(no fields recovered)`. locationd/CLP: 0 flagged → golden byte-identical. Golden
diff = **+78 `<opaque_passthrough>` keys, 0 removals, 0 field-tuple changes** →
wire-neutral. (Gotcha fixed during impl: `disasm(stop_at_ret=True)` does NOT stop
at an unconditional `b`, so the window must be truncated at the first `b`/`ret`.)

## Repro
`./venv/bin/python3` probes in `/tmp/probe_revgeo.py`, `/tmp/probe2.py`, `/tmp/survey.py`
(load GeoServices via `validate_lever._load_cache`-style `DyldCacheReader` + `BinaryContext`,
then `read_ptr`/`read_s32`/`disasm`).
