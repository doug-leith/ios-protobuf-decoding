#import "pbshim.h"

// Ground truth (see expected.py). This fixture covers proto/writeto.py's
// _trace_hoisted_self_value ("S1" hoisted value-load), previously ZERO
// synthetic coverage (confirmed by a corpus trace before writing this
// fixture: 6 real hits across GeoServices/CoreLocationProtobuf, including
// CLPPressure._timestamp -- the exact class this fixture's shape is modeled
// on directly, from CoreLocationProtobuf).
//
//   message TestHoistContainer {
//     double a = 1;
//     double b = 2;
//   }
//
// REAL Apple shape confirmed by direct disassembly of CoreLocationProtobuf's
// CLPPressure.writeTo: (3 double fields, no `_has` bitfield -- always
// written): its FIRST field's value is loaded into a CALLEE-SAVED fp
// register (d8) BEFORE an opaque call (returns a value used as the writer
// for every subsequent write, including this field's own), then moved into
// d0 and written just after. bind_write's ordinary value-load scan
// (`pre`, bounded to "since the previous bl") cannot see the load -- it is
// on the FAR side of that intervening call -- so it falls through to
// _trace_hoisted_self_value, which searches the WIDER, unbounded block
// prefix instead, relying on d8 being guaranteed to survive the call
// (callee-saved) to safely cross it.
//
// Reproduces cleanly with a single ordinary opaque call, no special
// compiler version needed (this repo's normal clang, unlike the
// isolated-compares/jump-table shapes elsewhere in this suite): a local
// `double a = _a;` read before a call whose return value is used as the
// writer for the rest of the method is enough for -Os to choose exactly
// this register allocation, confirmed by disassembling the built binary
// below (not assumed).
//
// TestHoistHelper is `noinline` so the compiler can't inline it away
// entirely (tried without: it did, and the whole hoisted-value shape
// vanished). A same-file trivial body is fine here, unlike f22's helper --
// the RETURN value is actually used by the following writes, so the call
// itself can't be eliminated even though the compiler proves the `self`
// argument is unused and stops bothering to set it up correctly (harmless:
// extraction never inspects the callee's argument values, only the shape
// around the call).

__attribute__((noinline)) id TestHoistHelper(id self) {
    (void)self;
    return nil;
}

@interface TestHoistContainer : PBCodable {
  @public
    double _a;
    double _b;
}
@end

@implementation TestHoistContainer

- (void)writeTo:(PBDataWriter *)writer {
    double a = _a;
    PBDataWriter *w2 = (PBDataWriter *)TestHoistHelper(self);
    PBWriteDoubleField(w2, a, 1);
    PBWriteDoubleField(w2, _b, 2);
    [super writeTo:writer];
}

@end

int main(void) { return 0; }
