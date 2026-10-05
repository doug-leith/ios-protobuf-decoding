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

## Survey — how common is this shape?

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

## What the extractor does with it

The extractor detects this shape structurally (`_is_opaque_passthrough` in `proto/extractor.py`: a
single `_unknownFields : PBUnknownFields` ivar, and a leaf `writeTo:` that loads it and tail-calls
`writeTo:`) and emits `// opaque passthrough — serializes only PBUnknownFields (no typed fields in
this build)` instead of `// (no fields recovered)`. The two mean opposite things: for a passthrough
the raw bytes are the complete answer, while a message with no recovered fields because extraction
was incomplete is a gap. The detector flags exactly the 78 GeoServices classes above; 44 other
field-less classes keep `(no fields recovered)`; locationd and CoreLocationProtobuf have none.

For the decoder, raw-decoding the sub-message is correct and complete:
`PDReverseGeocodingResult { 100: 1 … }` is the right output, because field 100 is unmodeled by the
client. Mapping it to another message would be a structural guess the wire content (a lone
`100: varint`) cannot support.

## Uncertainties / flags

- I did **not** prove what field 100 *means* on the server side. It is provably unmodeled by
  the client; its semantics would require server-side schema, not this binary. Per project
  policy, that stays raw-decoded.
- Survey detector matched two writeTo shapes (offset-table-indirected "A", direct-immediate
  "B"); all 78 hits were shape "A". A handful of classes whose `writeTo:` is non-trivial but
  still ultimately field-less (e.g. group-encoded) would not match this signature — the 78 is a
  lower bound on "opaque", but it is the exact set matching the "load-one-ivar +
  tail-call" signature.
