#import "pbshim.h"

// Ground truth (see expected.py). This fixture covers proto/enums.py's
// BRANCH-BASED sparse-enum harvesters — _harvest_isolated_compares
// (cmp+b.eq/b.ne) and _harvest_cbz_value0 (cbz/cbnz).
//
// REAL COMPILED CODE (gotcha 13), not hand-assembly. Originally this fixture
// hand-wrote the branch body via named-register variables + inline asm,
// because no C/ObjC source construction tried against this repo's normal
// (Xcode 15, clang 15.0.0) toolchain produces these shapes — every attempt
// if-converts to a branchless `csel` chain instead (confirmed across clang
// 13.1.6/14.0.3/15.0.0 too). A MUCH OLDER Apple clang has different
// if-conversion heuristics and does NOT do this: the plain switch below
// compiles to genuine `cmp+b.eq`/`cbnz`, no `csel` anywhere. Xcode 11.1
// (build 11A1027, clang 11.0.0 / clang-1100.0.33.8) is the exact version
// build_fixtures.sh actually uses (Xcode 8.0's clang 8.0.0/clang-800.0.38
// produces the identical shape here, but Xcode 11.1 is standardised on
// across every old-codegen fixture in this suite — see f18's fixture.m
// for why); Xcode 12.1 (clang 12.0.0/clang-1200.0.32.21) is already back
// to if-converting to `csel`, so the usable window is narrow.
//
// That old clang's OWN linker can't be used, though — it predates "chained
// fixups" entirely and links with classic bind/rebase opcodes instead, which
// this tool's macho/memory.py does not parse (ivar-offset/superclass
// pointers come back unresolved, and extract_all refuses to run at all). The
// linker decides the fixup format; the compiler decides instruction-level
// codegen — independent axes — so build_fixtures.sh's build_fixture_oldxc
// compiles this file's .o with the old clang, then links it with THIS
// environment's normal (modern, chained-fixups) clang/ld. See that
// function's own comment and ../README.md gotcha 13 for the full mechanism.
//
//   message TestAsmEnum {
//     enum Status {
//       STATUS_UNKNOWN = 0;   // cbz special case
//       STATUS_ALPHA   = 1;   // isolated b.ne (fall-through string)
//       STATUS_BETA    = 5;   // isolated b.eq (branch-to string)
//     }
//     Status status = 3;
//   }
//
// Verified by disassembly (gotcha 4) AND end-to-end extraction before
// writing expected.py: the compiled `statusAsString:` is `cmp w2,#5;b.eq`
// (value 5) / `cmp w2,#1;b.eq` (value 1 — a genuine isolated b.eq here,
// not the b.ne-fall-through shape the old hand-asm version used; both
// idioms are the same harvester, just the OTHER branch sense) / `cbnz w2`
// (value 0, fall-through when zero) — no `csel` anywhere. The value string
// lands in a CALLEE-SAVED register (x19), not x0 — real ARC codegen
// computes the return value into a register that survives the subsequent
// `objc_autoreleaseReturnValue` call, only moving it to x0 at the very end
// — which `_harvest_isolated_compares`/`_harvest_cbz_value0` didn't handle
// before this fixture (see proto/enums.py's `_isolated_value_target`,
// added alongside this fixture): a real production gap, not just a fixture
// artifact, found by testing against real compiler output instead of
// hand-crafted asm that happened to sidestep it. All 3 values recover
// correctly (values_confirmed=False, as always for the branch-based
// fallback path; values_truncated=False).

@interface TestAsmEnum : PBCodable {
  @public
    int32_t _status;
    struct { unsigned has_status:1; } _has;
}
- (NSString *)statusAsString:(int32_t)value;
@end

@implementation TestAsmEnum

- (NSString *)statusAsString:(int32_t)value {
    switch (value) {
        case 0: return @"TEST_STATUS_UNKNOWN";
        case 1: return @"TEST_STATUS_ALPHA";
        case 5: return @"TEST_STATUS_BETA";
        default: return nil;
    }
}

- (void)writeTo:(PBDataWriter *)writer {
    if (_has.has_status) PBWriteInt32Field(writer, _status, 3);
    [super writeTo:writer];
}

@end

int main(void) { return 0; }
