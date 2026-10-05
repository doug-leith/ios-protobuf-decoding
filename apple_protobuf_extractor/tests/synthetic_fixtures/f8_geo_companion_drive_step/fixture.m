#import "nested.h"
#import "pbwiretypes.h"

// GROUND TRUTH — a REAL message extracted from a live GeoServices dyld cache
// (tests/golden/GeoServices.json, `GEOCompanionDriveStep.*`), reimplemented
// as a genuinely-compiled clean-room PBCodable class. Same rationale as
// f6/f7. This one's focus is TWO DISTINCT repeated-MESSAGE fields resolved
// in a single class's readFrom: dispatch core — f2/f5 each isolate ONE such
// field in a toy message; a real message with several nested-message-typed
// fields side by side (some singular, some repeated, different element
// classes) is exactly the case those mechanisms have to hold up under.
//
//   message GEOCompanionDriveStep {
//     int32                maneuverType     = 4;   // real enum — see f6 note
//     string               shield           = 6;
//     sint32               shieldType       = 7;
//     int32                junctionType     = 8;   // real enum — see f6 note
//     repeated bytes       junctionElements = 9;
//     repeated GEONameInfoList maneuverNames = 10;
//     repeated GEONameInfo signposts        = 11;
//     bool                 toFreeway        = 12;
//     GEONameInfo          exitNumber       = 13;
//     int32                drivingSide      = 14;  // real enum — see f6 note
//     GEOPBTransitArtwork  artworkOverride  = 15;
//     GEOEVChargeInfo      chargingInfo     = 16;
//     GEOEVStepInfo        evInfo           = 17;
//   }
//
// Field numbers 4,6-17 (no 1/2/3/5) — real gaps (the real class inherits a
// numbering range from a broader step hierarchy that predates this
// subclass's own fields), left as-is rather than renumbered.
//
// exitNumber (13) reuses GEONameInfo — the SAME class also used as
// signposts' repeated element (11). This is deliberately realistic: a class
// commonly appears both as a singular field's type (resolved trivially from
// the ivar's own `@"GEONameInfo"` @encode) and as a repeated field's element
// type (resolvable ONLY via readFrom: dispatch) in the same message, and the
// two resolution paths must agree.

@interface GEOCompanionDriveStep : PBCodable {
    int32_t _maneuverType;
    NSString *_shield;
    int32_t _shieldType;
    int32_t _junctionType;
    NSMutableArray *_junctionElements;
  @public
    NSMutableArray *_maneuverNames;
    NSMutableArray *_signposts;
  @protected
    BOOL _toFreeway;
    GEONameInfo *_exitNumber;
    int32_t _drivingSide;
    GEOPBTransitArtwork *_artworkOverride;
    GEOEVChargeInfo *_chargingInfo;
    GEOEVStepInfo *_evInfo;
    struct {
        unsigned has_maneuverType:1;
        unsigned has_shield:1;
        unsigned has_shieldType:1;
        unsigned has_junctionType:1;
        unsigned has_toFreeway:1;
        unsigned has_exitNumber:1;
        unsigned has_drivingSide:1;
        unsigned has_artworkOverride:1;
        unsigned has_chargingInfo:1;
        unsigned has_evInfo:1;
    } _has;
}
@end

extern __attribute__((noinline)) void GEOCompanionDriveStepReadFrom_core(
    GEOCompanionDriveStep *self, PBDataReader *reader);

@implementation GEOCompanionDriveStep

- (void)writeTo:(PBDataWriter *)writer {
    if (_has.has_maneuverType) PBWriteInt32Field(writer, _maneuverType, 4);
    if (_has.has_shield)       PBWriteStringField(writer, _shield, 6);
    if (_has.has_shieldType)   PBWriteSInt32Field(writer, _shieldType, 7);
    if (_has.has_junctionType) PBWriteInt32Field(writer, _junctionType, 8);
    for (id je in _junctionElements) PBWriteBytesField(writer, je, 9);
    for (id mn in _maneuverNames)    PBWriteMessageField(writer, mn, 10);
    for (id sp in _signposts)        PBWriteMessageField(writer, sp, 11);
    if (_has.has_toFreeway)      PBWriteBoolField(writer, _toFreeway, 12);
    if (_has.has_exitNumber)     PBWriteMessageField(writer, _exitNumber, 13);
    if (_has.has_drivingSide)    PBWriteInt32Field(writer, _drivingSide, 14);
    if (_has.has_artworkOverride) PBWriteMessageField(writer, _artworkOverride, 15);
    if (_has.has_chargingInfo)   PBWriteMessageField(writer, _chargingInfo, 16);
    if (_has.has_evInfo)         PBWriteMessageField(writer, _evInfo, 17);
    [super writeTo:writer];
}

- (BOOL)readFrom:(PBDataReader *)reader {
    GEOCompanionDriveStepReadFrom_core(self, reader);
    return YES;
}

@end

// A dense 1..17 switch (filler arms for the numbers this class doesn't
// itself use: 1,2,3,5) — matches f5_jumptable_dispatch's approach of giving
// the table enough entries to compile as a real ARM64 jump table rather than
// degenerating to a 2-3 arm if/else compare chain (README.md gotcha 4b:
// verify by disassembly, don't assume either shape). The two REAL dispatch
// arms (10, 11) are the ones under test; every other arm is an unknown-field
// filler, exactly as in f2/f5.
__attribute__((noinline)) void GEOCompanionDriveStepReadFrom_core(
    GEOCompanionDriveStep *self, PBDataReader *reader) {
    uint32_t tag = PBReadTag(reader);
    uint32_t field = tag >> 3;
    switch (field) {
        case 1: PBHandleUnknownField(self, field); break;
        case 2: PBHandleUnknownField(self, field); break;
        case 3: PBHandleUnknownField(self, field); break;
        case 4: PBHandleUnknownField(self, field); break;
        case 5: PBHandleUnknownField(self, field); break;
        case 6: PBHandleUnknownField(self, field); break;
        case 7: PBHandleUnknownField(self, field); break;
        case 8: PBHandleUnknownField(self, field); break;
        case 9: PBHandleUnknownField(self, field); break;
        case 10: {
            GEONameInfoList *e = [GEONameInfoList new];
            GEONameInfoListReadFrom_core(e, reader);
            if (self->_maneuverNames == nil) {
                self->_maneuverNames = [NSMutableArray new];
            }
            [self->_maneuverNames addObject:e];
            break;
        }
        case 11: {
            GEONameInfo *e = [GEONameInfo new];
            GEONameInfoReadFrom_core(e, reader);
            if (self->_signposts == nil) {
                self->_signposts = [NSMutableArray new];
            }
            [self->_signposts addObject:e];
            break;
        }
        case 12: PBHandleUnknownField(self, field); break;
        case 13: PBHandleUnknownField(self, field); break;
        case 14: PBHandleUnknownField(self, field); break;
        case 15: PBHandleUnknownField(self, field); break;
        case 16: PBHandleUnknownField(self, field); break;
        case 17: PBHandleUnknownField(self, field); break;
        default: PBHandleUnknownField(self, field); break;
    }
}

int main(void) { return 0; }
