#import "pbshim.h"

// Ground truth (see expected.py). Covers the HYBRID `_dictionaryRepresentation:`
// enum shape: a dense low range lowered to a jump table PLUS sparse high values
// lowered to isolated `cmp #K; b.eq` compares, in ONE switch. Before this
// fixture proto/enums.py's _scan_dictrep_isolated_cmps (the sparse half) had no
// fixture coverage: f19's `category` is dense-only and its `cacheControl` is a
// pointer table, so neither reaches it.
//
//   message TestHybrid {
//     enum Status {
//       STATUS_SUCCESS = 0;  STATUS_FAILED = 1;  STATUS_INCOMPLETE = 2;
//       INVALID_REQUEST = 5;                               // dense low range
//       FAILED_NO_RESULT = 20;  NEEDS_REFINEMENT = 30;     // sparse high range
//       FAILED_NOT_AUTHORIZED = 40;  STATUS_DEDUPED = 50;
//       VERSION_MISMATCH = 60;
//     }
//     Status status = 3;
//   }
//
// The values are REAL: GEOPDComponent's ComponentStatus (`_status`), which the
// real GeoServices binary also compiles to a jump table for 0,1,2,5 and
// isolated compares for 20..60 (traced against the real dyld cache; see the
// "Live" test test_status_full_hybrid_switch in tests/test_dictrep_enums.py,
// which previously was the only coverage of this shape).
//
// REAL COMPILED CODE, no hand-asm (gotcha 13): a plain 9-case switch built with
// the old-clang-frontend/modern-linker hybrid (Xcode 11.1). Disassembly checked
// before writing expected.py: `cmp w8,#0x1d; b.gt <sparse tree>` splits the
// value range, the low half indexes a byte jump table (`cmp w8,#5; b.hi
// default; ... ldrb; br`), and the high half is a compare tree
// (`cmp #0x1e; b.eq`, `cmp #0x28; b.ne`, `cmp #0x32; b.eq`, `cmp #0x3c;
// b.ne`) -- the shape _scan_dictrep_isolated_cmps targets, first try.
//
// Value strings are real `@"..."` literals, so their CFStrings are genuine.
// Emitted enum value names are the tool's normalised form (the prefix
// TEST_HYBRID_STATUS_ is prepended, with the overlapping leading STATUS_
// stripped): see _normalize_enum_value_name, whose docstring uses this exact
// STATUS_SUCCESS example.

@interface TestHybrid : PBCodable {
  @public
    int32_t _status;
    struct { unsigned has_status:1; } _has;
}
@end

@implementation TestHybrid

- (id)_dictionaryRepresentation:(id)arg {
    NSMutableDictionary *d = [NSMutableDictionary new];
    switch (_status) {
        case 0:  d[@"status"] = @"STATUS_SUCCESS"; break;
        case 1:  d[@"status"] = @"STATUS_FAILED"; break;
        case 2:  d[@"status"] = @"STATUS_INCOMPLETE"; break;
        case 5:  d[@"status"] = @"INVALID_REQUEST"; break;
        case 20: d[@"status"] = @"FAILED_NO_RESULT"; break;
        case 30: d[@"status"] = @"NEEDS_REFINEMENT"; break;
        case 40: d[@"status"] = @"FAILED_NOT_AUTHORIZED"; break;
        case 50: d[@"status"] = @"STATUS_DEDUPED"; break;
        case 60: d[@"status"] = @"VERSION_MISMATCH"; break;
    }
    return d;
}

- (void)writeTo:(PBDataWriter *)writer {
    if (_has.has_status) PBWriteInt32Field(writer, _status, 3);
    [super writeTo:writer];
}

@end

int main(void) { return 0; }
