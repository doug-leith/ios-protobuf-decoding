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
// register (d8) BEFORE a call (there `objc_retain_x2`, the ARC retain of the
// writer), then moved into d0 and written just after.  The value must be
// traced across that call: d8 survives it because it is callee-saved.
//
// Reproduced with one opaque call between the load and the writes:
// TestHoistHelper sends a message, so the compiler cannot prove it leaves
// `_a` alone and must load `_a` before the call; -Os keeps it in d8 and the
// writer in a callee-saved register across the call (confirmed by
// disassembling the built binary, not assumed).  `noinline` keeps the call.
// Until 2026-10-19 the helper returned the writer the fields were written
// to (nil), which the real code never does: a value the writer is not.

__attribute__((noinline)) void TestHoistHelper(id self) {
    [self self];
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
    TestHoistHelper(self);
    PBWriteDoubleField(writer, a, 1);
    PBWriteDoubleField(writer, _b, 2);
    [super writeTo:writer];
}

@end

int main(void) { return 0; }
