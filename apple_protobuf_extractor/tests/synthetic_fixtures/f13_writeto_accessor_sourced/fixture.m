#import "pbshim.h"

// Ground truth (see expected.py). Written for the writeTo: walk (deleted
// 2026-10-19, TODO #85; expected.py says what covers it now). It covered proto/writeto.py's
// ACCESSOR-SOURCED value-binding tier (bind_write's "2d": _selector_stub_name,
// _getter_loads_offset, _build_accessor_ivar_map, _trace_accessor_sourced_value),
// which had ZERO synthetic coverage before this fixture. Real, documented bug
// this fixes (see _build_accessor_ivar_map's neighbouring comment in
// writeto.py): a message-typed field written via its property GETTER rather
// than a direct ivar load — `PBWriteMessageField(writer, self.context, N)`
// instead of `PBWriteMessageField(writer, _context, N)` — has NO direct
// [self,off] load for the field-number walk's normal (2a) tier to find, so
// without this tier the field silently falls through to an ivar-order
// ESTIMATE and gets the WRONG number (the file cites a real measured case:
// `_CPUsageEnvelope.context` estimated 6, actually 14).
//
//   message TestGetterElem {
//     string value = 1;
//   }
//
//   message TestGetterContainer {
//     TestGetterElem context = 9;   // written via self.context, not _context
//   }
//
// `context`'s getter is a plain accessor (`return _context;`) — real Apple
// codegen for PBCodable message-typed fields commonly routes writeTo: through
// the property getter rather than the ivar directly (unlike scalar fields,
// which always load [self,off] straight). Field number 9 is confirmed
// independently by the writeTo: CFG walk regardless of HOW the value is
// sourced (see f2's docstring: writeTo: gives the number, never the type) —
// this fixture is about getting bind_write to resolve WHICH ivar the write
// belongs to, not about number confirmation itself.
//
// Verified by disassembly (gotcha 4) AND by instrumenting bind_write
// directly: the `context` field resolves with status EXACTLY `'ok-accessor'`
// (not 'ok'/'ok-repeated'/'ok-hoisted' — confirmed empirically before
// writing this fixture, not assumed from the source alone). The compiled
// writeTo: calls `self.context`'s selector stub unconditionally near the
// function's entry (ARC evaluates+retains the property value ahead of the
// has-bit branch), then an ARC `objc_retain` passthrough on the writer
// parameter — both are exactly the shapes _selector_stub_name/
// _trace_accessor_sourced_value are designed to tell apart (a real selector
// stub vs. an ARC runtime passthrough that returns x0 unchanged).

@interface TestGetterElem : PBCodable {
  @public
    NSString *_value;
    struct { unsigned has_value:1; } _has;
}
@end

@implementation TestGetterElem

- (void)writeTo:(PBDataWriter *)writer {
    if (_has.has_value) PBWriteStringField(writer, _value, 1);
    [super writeTo:writer];
}

@end

@interface TestGetterContainer : PBCodable {
  @public
    TestGetterElem *_context;
    struct { unsigned has_context:1; } _has;
}
- (TestGetterElem *)context;
@end

@implementation TestGetterContainer

- (TestGetterElem *)context { return _context; }

- (void)writeTo:(PBDataWriter *)writer {
    if (_has.has_context) PBWriteMessageField(writer, self.context, 9);
    [super writeTo:writer];
}

@end

int main(void) { return 0; }
