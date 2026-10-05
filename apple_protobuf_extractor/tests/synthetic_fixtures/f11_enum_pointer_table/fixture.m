#import "pbshim.h"

// Ground truth (see expected.py). This fixture covers proto/enums.py's
// PRIMARY, highest-real-world-usage enum-value recovery path
// (_extract_enum_values' pointer-table branch), which had ZERO synthetic
// coverage before this fixture despite resolving the overwhelming majority
// of real enums (587/587 GeoServices/CLP/locationd pointer-table enums per
// the file's own measured tally — see proto/enums.py's module docstring
// area). No existing fixture (f1-f10) has a single enum-typed field.
//
// Two classes, isolating the mechanism's two sub-cases:
//
//   message TestEnumStatus {
//     enum Status {           // 0-based, no bias — the base case
//       STATUS_UNKNOWN = 0;
//       STATUS_OK = 1;
//       STATUS_FAIL = 2;
//     }
//     Status status = 7;
//   }
//
//   message TestEnumSourceType {
//     enum SourceType {       // 1-based — exercises _find_index_bias's
//       ...                   // leading `sub wRd,wRn,#1` bias-correction,
//     }                       // real values from GEOMapRegionSourceType
//     SourceType sourceType = 11;  // (tests/golden/GeoServices.json)
//   }
//
// TestEnumSourceType reimplements the REAL GEOMapRegionSourceType enum
// (13 values, 1-13) verbatim — same rationale as f6-f10's "real extracted
// message" fixtures, but for an enum's VALUE TABLE rather than a message's
// FIELD SET. Field numbers (7, 11) are arbitrary/non-monotonic on purpose,
// matching f1's convention, though with only one field per class here the
// writeTo: walk trivially confirms them regardless.
//
// The `xAsString:` method here is a plain ObjC INSTANCE method (not a
// metaclass `+` method): proto/protocore.py:_type_from_enc only consults
// the class's OWN instance_method_names when deciding whether a scalar int
// ivar is enum-shaped in --binary (standalone) mode — a class method lives
// on a separate metaclass ObjcClass record and isn't in that set. (Real
// GeoServices enums are recovered via the shared-cache methname-scan phase
// instead, which doesn't have this instance/class distinction — see
// _collect_enum_definitions Phase 1 — so this is a standalone-mode-specific
// requirement, verified empirically before writing this fixture.)
//
// Verified by disassembly (gotcha 4): both methods compile at -Os to the
// exact scaled-index pointer-table load the decoder looks for —
// `ldr x0, [x8, w2, sxtw #3]` — with TestEnumSourceType additionally
// showing a `sub w8, w2, #1` bias instruction ahead of the range check.

@interface TestEnumStatus : PBCodable {
    int32_t _status;
    struct { unsigned has_status:1; } _has;
}
- (NSString *)statusAsString:(int32_t)value;
@end

@implementation TestEnumStatus

- (NSString *)statusAsString:(int32_t)value {
    switch (value) {
        case 0: return @"STATUS_UNKNOWN";
        case 1: return @"STATUS_OK";
        case 2: return @"STATUS_FAIL";
        default: return nil;
    }
}

- (void)writeTo:(PBDataWriter *)writer {
    if (_has.has_status) PBWriteInt32Field(writer, _status, 7);
    [super writeTo:writer];
}

@end

@interface TestEnumSourceType : PBCodable {
    int32_t _sourceType;
    struct { unsigned has_sourceType:1; } _has;
}
- (NSString *)sourceTypeAsString:(int32_t)value;
@end

@implementation TestEnumSourceType

- (NSString *)sourceTypeAsString:(int32_t)value {
    switch (value) {
        case 1:  return @"MAP_REGION_SOURCE_TYPE_UNKNOWN";
        case 2:  return @"MAP_REGION_SOURCE_TYPE_BASEMAP_CURATED";
        case 3:  return @"MAP_REGION_SOURCE_TYPE_REV_POLYGON_PADDED";
        case 4:  return @"MAP_REGION_SOURCE_TYPE_REV_POINT_PADDED";
        case 5:  return @"MAP_REGION_SOURCE_TYPE_GEMINI_CURATED";
        case 6:  return @"MAP_REGION_SOURCE_TYPE_GEMINI_POINT_PADDED";
        case 7:  return @"MAP_REGION_SOURCE_TYPE_PLACES_POINT_PADDED";
        case 8:  return @"MAP_REGION_SOURCE_TYPE_DISPATCHER_CALCULATED";
        case 9:  return @"MAP_REGION_SOURCE_TYPE_ROUTING_CALCULATED";
        case 10: return @"MAP_REGION_SOURCE_TYPE_SEARCH_CALCULATED";
        case 11: return @"MAP_REGION_SOURCE_TYPE_ROUTING_FALLBACK";
        case 12: return @"MAP_REGION_SOURCE_TYPE_REV_POLYGON_FIT";
        case 13: return @"MAP_REGION_SOURCE_TYPE_GEMINI_POLYGON_FIT";
        default: return nil;
    }
}

- (void)writeTo:(PBDataWriter *)writer {
    if (_has.has_sourceType) PBWriteInt32Field(writer, _sourceType, 11);
    [super writeTo:writer];
}

@end

int main(void) { return 0; }
