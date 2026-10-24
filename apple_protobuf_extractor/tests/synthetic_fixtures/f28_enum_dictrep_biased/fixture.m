#import "pbshim.h"

// Ground truth (see expected.py).  Regression fixture for the shared-selector-
// pool false positive in proto/enums.py:_field_routes_through_xasstring.
//
// Apple's PBCodable generator writes a 1-based enum field's name lookup in
// -[Class _dictionaryRepresentation:] as an indexed read of a static name table
// after re-basing the value:
//
//     sub w9, w8, #1 ; cmp w9, #N ; b.hs default ; ldr x, [table, w9, sxtw #3]
//
// (real example: GEOPDGroundDataBuild.type, iOS 16.7.11 GeoServices, 1..3).
// The harvester reads the table by index and must add the `sub` immediate back.
// It skips that correction for a field that "routes through xAsString:" — the
// xAsString: path owns the bias there.  That test used to consult the image-wide
// __objc_methname pool, which holds every class's selectors, so a field named
// `type` was judged to route through xAsString: merely because SOME OTHER class
// has typeAsString:.  This fixture therefore has:
//
//   TestBuild      field `type`, 1-based {T300=1,T400=2,T392C=3}, dictRep ONLY
//                  (no typeAsString:) — must come out 1..3 (was 0..2).
//   TestOther      unrelated class that DOES define typeAsString: — puts the
//                  selector in the shared pool.  Not an enum owner itself.
//   TestKind       field `kind`, 1-based, with its OWN kindAsString: AND the same
//                  dictRep table idiom — owned by the xAsString: path, so the
//                  dictRep harvest must stay unbiased (no double bias).
//
// Field numbers are arbitrary/non-monotonic, as in the other fixtures.

@interface TestBuild : PBCodable {
  @public
    int32_t _type;
    struct { unsigned has_type:1; } _has;
}
@end

@implementation TestBuild

- (id)_dictionaryRepresentation:(id)arg {
    static NSString *const names[3] = { @"T300", @"T400", @"T392C" };
    NSMutableDictionary *d = [NSMutableDictionary new];
    NSString *s;
    unsigned idx = (unsigned)_type - 1;
    if (idx < 3) s = names[idx];
    else s = [NSString stringWithFormat:@"(unknown: %i)", _type];
    d[@"type"] = s;
    return d;
}

- (void)writeTo:(PBDataWriter *)writer {
    if (_has.has_type) PBWriteInt32Field(writer, _type, 6);
}

@end

@interface TestOther : PBCodable {
    int32_t _type;
    struct { unsigned has_type:1; } _has;
}
- (NSString *)typeAsString:(int32_t)value;
@end

@implementation TestOther

- (NSString *)typeAsString:(int32_t)value {
    switch (value) {
        case 0: return @"OTHER_TYPE_NONE";
        case 1: return @"OTHER_TYPE_SOME";
        case 2: return @"OTHER_TYPE_MORE";
        default: return nil;
    }
}

- (void)writeTo:(PBDataWriter *)writer {
    if (_has.has_type) PBWriteInt32Field(writer, _type, 3);
}

@end

@interface TestKind : PBCodable {
  @public
    int32_t _kind;
    struct { unsigned has_kind:1; } _has;
}
- (NSString *)kindAsString:(int32_t)value;
@end

@implementation TestKind

- (NSString *)kindAsString:(int32_t)value {
    static NSString *const names[3] = { @"KIND_ALPHA", @"KIND_BETA", @"KIND_GAMMA" };
    unsigned idx = (unsigned)value - 1;
    return idx < 3 ? names[idx] : [NSString stringWithFormat:@"(unknown: %i)", value];
}

- (id)_dictionaryRepresentation:(id)arg {
    static NSString *const names[3] = { @"KIND_ALPHA", @"KIND_BETA", @"KIND_GAMMA" };
    NSMutableDictionary *d = [NSMutableDictionary new];
    NSString *s;
    unsigned idx = (unsigned)_kind - 1;
    if (idx < 3) s = names[idx];
    else s = [NSString stringWithFormat:@"(unknown: %i)", _kind];
    d[@"kind"] = s;
    return d;
}

- (void)writeTo:(PBDataWriter *)writer {
    if (_has.has_kind) PBWriteInt32Field(writer, _kind, 9);
}

@end

int main(void) { return 0; }
