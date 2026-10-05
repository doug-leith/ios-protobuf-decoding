#import "pbshim.h"

// Ground truth (see expected.py). Covers the THIRD pass of
// proto/enums.py:_harvest_dictrep_enums (commit 9d07d15): recovering an
// enum's value table from a has-bit-gated COMPARE CHAIN / compare TREE
// inside `dictionaryRepresentation`, the shape a newer Apple toolchain
// (observed on a macOS system dyld cache's GeoServices, e.g.
// GEOBatchPlaceResult.statusCode) uses instead of the classic
// `adr`+`br` jump table (f19) or `xAsString:` selector (f11/f16/f18).
//
//   message TestNewEnums {
//     enum StatusCode {                 // 3 sparse values -> a cmp+b.eq chain
//       TEST_NEW_STATUS_FAILED = 1;
//       TEST_NEW_STATUS_INVALID_REQUEST = 5;
//       TEST_NEW_STATUS_VERSION_MISMATCH = 60;
//     }
//     optional StatusCode statusCode = 1;
//
//     enum Mode { TEST_NEW_MODE_OFF = 0; TEST_NEW_MODE_ON = 1; }   // cbz-0 leaf
//     optional Mode mode = 2;
//
//     enum Tier {                       // 6 sparse values -> a cmp TREE
//       TEST_NEW_TIER_A = 10; TEST_NEW_TIER_B = 20; TEST_NEW_TIER_C = 30;
//       TEST_NEW_TIER_D = 40; TEST_NEW_TIER_E = 50; TEST_NEW_TIER_F = 60;
//     }
//     optional Tier tier = 3;
//
//     optional int32 count = 4;         // plain int32, NOT an enum
//   }
//
//   message TestDirectEnum {            // same, but dictRep is a REGISTERED
//     enum Level {                      // `_dictionaryRepresentation:` method,
//       TEST_DIRECT_LEVEL_LOW = 3;      // not reached through a public wrapper
//       TEST_DIRECT_LEVEL_HIGH = 9;
//     }
//     optional Level level = 1;
//   }
//
// None of these fields has an xAsString:/StringAsX: companion, so their
// enum-ness can ONLY be recovered from the dictionaryRepresentation body.
// `count` sits in the same function as the three enum chains and must NOT
// be reported as an enum (nor absorb another field's chain).
//
// Real compiled code, this repo's normal (Xcode 15) clang at -Os: the
// `default:` arm calls +stringWithFormat:, which stops the compiler
// if-converting the chain into a branchless `csel` (contrast f16's
// gotcha 13). Verified by disassembly (README gotcha 4) -- see the
// README's f24 entry for the exact shape.
//
// TestNewEnums reproduces the REAL macOS shape of the public entry point:
// `-dictionaryRepresentation` is a bare `mov w1,#0; b <internal C function>`
// tail-branch wrapper and there is NO registered
// `-_dictionaryRepresentation:` method at all (_find_dictrep_c_func's
// tail-call-following branch). TestDirectEnum instead registers
// `_dictionaryRepresentation:` itself (its direct branch).

@interface TestNewEnums : PBCodable {
  @public
    int32_t _statusCode;
    int32_t _mode;
    int32_t _tier;
    int32_t _count;
    struct { unsigned has_statusCode:1; unsigned has_mode:1;
             unsigned has_tier:1; unsigned has_count:1; } _has;
}
@end

extern __attribute__((noinline)) id TestNewEnumsDictRep(TestNewEnums *self, id arg);

@implementation TestNewEnums

- (id)dictionaryRepresentation { return TestNewEnumsDictRep(self, nil); }

- (void)writeTo:(PBDataWriter *)writer {
    if (_has.has_statusCode) PBWriteInt32Field(writer, _statusCode, 1);
    if (_has.has_mode) PBWriteInt32Field(writer, _mode, 2);
    if (_has.has_tier) PBWriteInt32Field(writer, _tier, 3);
    if (_has.has_count) PBWriteInt32Field(writer, _count, 4);
    [super writeTo:writer];
}

@end

id TestNewEnumsDictRep(TestNewEnums *self, id arg) {
    NSMutableDictionary *d = [NSMutableDictionary new];

    if (self->_has.has_statusCode) {
        NSString *s;
        switch (self->_statusCode) {
            case 1: s = @"TEST_NEW_STATUS_FAILED"; break;
            case 5: s = @"TEST_NEW_STATUS_INVALID_REQUEST"; break;
            case 60: s = @"TEST_NEW_STATUS_VERSION_MISMATCH"; break;
            default: s = [NSString stringWithFormat:@"(unknown: %i)", self->_statusCode]; break;
        }
        [d setObject:s forKey:@"statusCode"];
    }
    if (self->_has.has_mode) {
        NSString *s;
        switch (self->_mode) {
            case 0: s = @"TEST_NEW_MODE_OFF"; break;
            case 1: s = @"TEST_NEW_MODE_ON"; break;
            default: s = [NSString stringWithFormat:@"(unknown: %i)", self->_mode]; break;
        }
        [d setObject:s forKey:@"mode"];
    }
    if (self->_has.has_tier) {
        NSString *s;
        switch (self->_tier) {
            case 10: s = @"TEST_NEW_TIER_A"; break;
            case 20: s = @"TEST_NEW_TIER_B"; break;
            case 30: s = @"TEST_NEW_TIER_C"; break;
            case 40: s = @"TEST_NEW_TIER_D"; break;
            case 50: s = @"TEST_NEW_TIER_E"; break;
            case 60: s = @"TEST_NEW_TIER_F"; break;
            default: s = [NSString stringWithFormat:@"(unknown: %i)", self->_tier]; break;
        }
        [d setObject:s forKey:@"tier"];
    }
    if (self->_has.has_count) {
        [d setObject:[NSNumber numberWithInt:self->_count] forKey:@"count"];
    }
    return d;
}

@interface TestDirectEnum : PBCodable {
  @public
    int32_t _level;
    struct { unsigned has_level:1; } _has;
}
@end

@implementation TestDirectEnum

- (id)_dictionaryRepresentation:(id)arg {
    NSMutableDictionary *d = [NSMutableDictionary new];
    if (_has.has_level) {
        NSString *s;
        switch (_level) {
            case 3: s = @"TEST_DIRECT_LEVEL_LOW"; break;
            case 9: s = @"TEST_DIRECT_LEVEL_HIGH"; break;
            default: s = [NSString stringWithFormat:@"(unknown: %i)", _level]; break;
        }
        [d setObject:s forKey:@"level"];
    }
    return d;
}

- (void)writeTo:(PBDataWriter *)writer {
    if (_has.has_level) PBWriteInt32Field(writer, _level, 1);
    [super writeTo:writer];
}

@end

int main(void) { return 0; }
