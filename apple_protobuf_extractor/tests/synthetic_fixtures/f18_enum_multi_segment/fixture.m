#import "pbshim.h"

// Ground truth (see expected.py). This fixture covers proto/enums.py's
// MULTI-SEGMENT jump-table harvest (_harvest_jumptable_segments' Idiom-B
// branch-gate routing: a `switch` lowering to TWO OR MORE separate dense
// sub-range jump tables in one method) — see ../README.md's "Multi-segment
// sparse enums" note: the real multi-cluster example
// (GEOTelemetricEntity.eventKeyAsString:, 191 values/10+ clusters) was
// checked against the real dyld shared cache and confirmed exact-match
// correct — every real segment ends in a plain `b <shared-epilogue>`,
// never its own `ret`.
//
// REAL COMPILED CODE (gotcha 13), not hand-assembly. This repo's normal
// (Xcode 15) clang tail-duplicates each segment's `ret` independently
// instead of funnelling every case to ONE shared epilogue — the OPPOSITE
// of what real Apple code does. An old-clang-frontend/modern-linker hybrid
// build fixes that: the plain switch below compiles to exactly the real
// shape — two independently-gated `adrp+add` (table base) / `adr`
// (case base) / `ldrb` (byte entry) jump tables, every arm branching to
// ONE shared `bl objc_autoreleaseReturnValue` exit.
//
// NOTE (found, not designed): Xcode 8.0 (clang 8.0.0/clang-800.0.38)
// specifically does NOT work here — it compiles this same switch to a
// DIFFERENT jump-table encoding (adrp+add table base doubling as case
// base, `ldrsw` 4-byte relative entries) that _harvest_jumptable_segments
// doesn't recognise at all. Xcode 11.1 (build 11A1027, clang 11.0.0 /
// clang-1100.0.33.8) uses the adrp+add-table/separate-adr-case/ldrb-entry
// shape real Apple binaries use, so build_fixtures.sh's
// build_fixture_oldxc standardises on that exact version for every
// old-codegen fixture, not just this one — see that function's own
// comment.
//
//   message TestMultiSeg {
//     enum Status {
//       ZERO=0; ONE=1; TWO=2; THREE=3;              // segment A (cluster 0-3)
//       HUNDRED=100; HUNDRED_ONE=101;
//       HUNDRED_TWO=102; HUNDRED_THREE=103;          // segment B (cluster 100-103)
//     }
//     Status status = 3;
//   }
//
// Verified by disassembly (gotcha 4) AND end-to-end extraction before
// writing expected.py: all 8 values recover correctly
// (values_confirmed=False, values_truncated=False). Also surfaced a real
// production gap while verifying: the per-case-block string reader
// (_read_case_string) hardcoded x0 for the return value, same as
// _harvest_isolated_compares before it — real ARC codegen computes the
// value into a callee-saved register (x19) that survives the
// subsequent objc_autoreleaseReturnValue call. Fixed by reusing
// proto/enums.py's _isolated_value_target (already built for the same
// issue in f16) here too.

@interface TestMultiSeg : PBCodable {
  @public
    int32_t _status;
    struct { unsigned has_status:1; } _has;
}
- (NSString *)statusAsString:(int32_t)value;
@end

@implementation TestMultiSeg

- (NSString *)statusAsString:(int32_t)value {
    switch (value) {
        case 0: return @"TEST_MULTISEG_ZERO";
        case 1: return @"TEST_MULTISEG_ONE";
        case 2: return @"TEST_MULTISEG_TWO";
        case 3: return @"TEST_MULTISEG_THREE";
        case 100: return @"TEST_MULTISEG_HUNDRED";
        case 101: return @"TEST_MULTISEG_HUNDRED_ONE";
        case 102: return @"TEST_MULTISEG_HUNDRED_TWO";
        case 103: return @"TEST_MULTISEG_HUNDRED_THREE";
        default: return nil;
    }
}

- (void)writeTo:(PBDataWriter *)writer {
    if (_has.has_status) PBWriteInt32Field(writer, _status, 3);
}

@end

int main(void) { return 0; }
