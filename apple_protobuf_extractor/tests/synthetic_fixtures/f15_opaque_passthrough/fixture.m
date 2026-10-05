#import "pbshim.h"

// Ground truth (see expected.py). This fixture covers proto/extractor.py's
// OPAQUE PASSTHROUGH detector (_is_opaque_passthrough), which had zero
// synthetic coverage before this fixture. Real, surveyed pattern: some
// PBCodable subclasses declare NO wire fields of their own — their only
// ivar is the inherited `_unknownFields` bag, and `writeTo:` just tail-calls
// its writeTo:. For these, "0 fields recovered" is GROUND TRUTH (the schema
// is empty BY DESIGN), not a sign the extractor missed something — the
// detector lets the emitter say so instead of implying an extraction gap.
// 78 real GeoServices classes match this exact shape (see
// notes/REVGEO_OPAQUE_PASSTHROUGH_2026-06-17.md, referenced from
// _is_opaque_passthrough's own docstring).
//
//   message TestOpaquePassthrough {
//     // no fields — opaque_passthrough=True
//   }
//
//   message TestNotOpaque {
//     // no RECOVERED fields either, but opaque_passthrough=False: this is
//     // a deliberate lookalike, not the real pattern (see below)
//   }
//
// PBUnknownFields is declared locally (fixture-only, not added to the
// shared shim — no other fixture needs it).
//
// TestOpaquePassthrough matches the real shape exactly: `writeTo:` is a
// pure `[_unknownFields writeTo:writer]` tail call with nothing else in the
// method body. Verified by disassembly (gotcha 4) AND by calling
// _is_opaque_passthrough directly: the compiled writeTo: is precisely
// `adrp+ldrsw` (ivar-offset-table load) + `ldr x0,[x0,x8]` (load the one
// ivar into x0) + a bare `b` (tail-call, no stack frame, no bl/ret/stp) —
// exactly the structural shape the detector requires, and it returns True.
//
// TestNotOpaque is the SAME one-ivar shape but does ONE more thing after
// delegating (an extra field-write call) — deliberately NOT opaque, to
// exercise the detector's rejection path too (mirrors f14's
// success-plus-ambiguity pairing). This forces a real stack frame and a
// `bl` where the true pattern has neither, so
// `_is_opaque_passthrough` correctly returns False — verified directly,
// not assumed.

@interface PBUnknownFields : NSObject {
  @public
    NSData *_raw;
}
- (void)writeTo:(PBDataWriter *)writer;
@end

@implementation PBUnknownFields

- (void)writeTo:(PBDataWriter *)writer {
    if (_raw) PBWriteBytesField(writer, _raw, 0);
}

@end

@interface TestOpaquePassthrough : PBCodable {
  @public
    PBUnknownFields *_unknownFields;
}
@end

@implementation TestOpaquePassthrough

- (void)writeTo:(PBDataWriter *)writer {
    [_unknownFields writeTo:writer];
}

@end

@interface TestNotOpaque : PBCodable {
  @public
    PBUnknownFields *_unknownFields;
}
@end

@implementation TestNotOpaque

- (void)writeTo:(PBDataWriter *)writer {
    [_unknownFields writeTo:writer];
    PBHandleUnknownField(self, 0);
}

@end

int main(void) { return 0; }
