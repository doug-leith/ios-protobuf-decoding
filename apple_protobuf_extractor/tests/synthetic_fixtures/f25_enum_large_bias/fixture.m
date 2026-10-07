#import "pbshim.h"

// Ground truth (see expected.py). Covers proto/enums.py's
// _leading_materialized_bias: the index bias of a jump-table segment whose
// values are too large for a 12-bit `sub #imm`, so the compiler materialises
// it in a register first. Real Apple enums above 4095 (the analytics/log
// enums, TODO #53; e.g. LogMessageType, bias 50000) compile this way; no
// fixture here had values that large, so the function had no synthetic
// coverage.
//
//   message TestBias {
//     enum Kind {
//       TEST_BIAS_ZERO = 0;  TEST_BIAS_ONE = 1;
//       TEST_BIAS_TWO = 2;   TEST_BIAS_THREE = 3;
//       TEST_BIAS_A = 50000; TEST_BIAS_B = 50001;
//       TEST_BIAS_C = 50002; TEST_BIAS_D = 50003;
//     }
//     Kind kind = 3;
//   }
//
// REAL COMPILED CODE, no hand-asm. A plain switch with a low cluster (0-3) and
// a high cluster (50000-50003) compiles, with both old and modern clang, to
//   mov w8,#-0xc350 ; add w8,w2,w8 ; cmp w8,#3 ; b.hi default ; <jump table>
// for the high cluster (disassembly checked before writing expected.py). Built
// with the old-clang-frontend/modern-linker hybrid (gotcha 13) so the low
// cluster keeps the shared-epilogue shape f18 relies on; this repo's normal
// clang drops the low segment, exactly as it does for f18.
//
// Value names are invented (mechanism-isolation tier, like f1-f5); only the
// 50000 bias magnitude is taken from the real LogMessageType enum.

@interface TestBias : PBCodable {
  @public
    int32_t _kind;
    struct { unsigned has_kind:1; } _has;
}
- (NSString *)kindAsString:(int32_t)value;
@end

@implementation TestBias

- (NSString *)kindAsString:(int32_t)value {
    switch (value) {
        case 0: return @"TEST_BIAS_ZERO";
        case 1: return @"TEST_BIAS_ONE";
        case 2: return @"TEST_BIAS_TWO";
        case 3: return @"TEST_BIAS_THREE";
        case 50000: return @"TEST_BIAS_A";
        case 50001: return @"TEST_BIAS_B";
        case 50002: return @"TEST_BIAS_C";
        case 50003: return @"TEST_BIAS_D";
        default: return nil;
    }
}

- (void)writeTo:(PBDataWriter *)writer {
    if (_has.has_kind) PBWriteInt32Field(writer, _kind, 3);
    [super writeTo:writer];
}

@end

int main(void) { return 0; }
