#import "nested.h"
#import "pbwiretypes.h"

// GROUND TRUTH — a REAL message extracted from a live GeoServices dyld cache
// (tests/golden/GeoServices.json / `GEORouteIncident.*`), reimplemented here
// as a genuinely-compiled clean-room PBCodable class. Unlike f1-f5 (each of
// which isolates ONE recovery mechanism in a toy 1-6 field message), this
// fixture's job is checking the decoder against a REAL message's full field
// mix at REAL size — sanity-checking that the extraction we already trust
// (this is the schema we published) is genuinely self-consistent: implement
// the schema for real, recompile, re-extract, and confirm we get the same
// answer back.
//
//   message GEORouteIncident {
//     GEOLatLng           position           = 1;
//     string              incidentId         = 2;
//     string              info               = 3;
//     int32               type               = 4;   // real enum RouteIncidentType — see note below
//     string              street             = 5;
//     string              crossStreet        = 6;
//     sfixed64            startTime          = 7;
//     sfixed64            endTime            = 8;
//     sfixed64            updateTime         = 9;
//     int32               laneClosureType    = 10;  // real enum RouteIncidentLaneClosureType
//     uint32              laneClosureCount   = 11;
//     bool                endTimeReliable    = 12;
//     int32               significance       = 13;  // real enum RouteIncidentSignificance
//     GEORestrictionInfo  restrictionInfo    = 14;
//     uint32              userReportsCount   = 15;
//     bool                shouldDisplayOnMap = 16;
//     repeated string     userReportIds      = 17;
//     uint32              delaySeconds       = 18;
//     GEOPBTransitArtwork artwork            = 19;
//   }
//
// NOTE on the three enum-shaped fields (type/laneClosureType/significance):
// the real binary recovers qualified enum type names (e.g. "RouteIncidentType")
// via a SEPARATE mechanism — the metaclass `+xyzAsString:`/`+StringAsXyz:`
// dictRep value-table (proto/enums.py) — which README.md's "Deferred" section
// already scoped OUT of this fixture suite as too compiler/SDK-version-
// sensitive to reliably reproduce from C source. Reproducing the qualified
// name here without actually building that mechanism would mean writing
// expected.py from what the tool currently prints rather than from an
// independently-authored ground truth — exactly what this suite exists to
// avoid. So these three ivars are declared as plain `int32_t` with NO
// `<field>AsString:` selector: the honest, correct decode for a class that
// carries no enum accessor is the canonical scalar default, `int32`.
//
// startTime/endTime/updateTime exercise the SAME fixed64-family write-helper
// signal as f3 (`_classify_write_helper`), at real field numbers (7/8/9) in a
// real 19-field message instead of a 6-field toy one — this is the point of
// this fixture tier: prove the mechanism holds up at realistic size/density,
// not just in isolation. Field numbers 1-19 are monotonic/contiguous (unlike
// f1's deliberately-scrambled numbering) because that is what the real
// message actually looks like; f1 already covers the non-monotonic case.

@interface GEORouteIncident : PBCodable {
    GEOLatLng *_position;
    NSString *_incidentId;
    NSString *_info;
    int32_t _type;
    NSString *_street;
    NSString *_crossStreet;
    int64_t _startTime;
    int64_t _endTime;
    int64_t _updateTime;
    int32_t _laneClosureType;
    uint32_t _laneClosureCount;
    BOOL _endTimeReliable;
    int32_t _significance;
    GEORestrictionInfo *_restrictionInfo;
    uint32_t _userReportsCount;
    BOOL _shouldDisplayOnMap;
    NSMutableArray *_userReportIds;
    uint32_t _delaySeconds;
    GEOPBTransitArtwork *_artwork;
    struct {
        unsigned has_position:1;
        unsigned has_incidentId:1;
        unsigned has_info:1;
        unsigned has_type:1;
        unsigned has_street:1;
        unsigned has_crossStreet:1;
        unsigned has_startTime:1;
        unsigned has_endTime:1;
        unsigned has_updateTime:1;
        unsigned has_laneClosureType:1;
        unsigned has_laneClosureCount:1;
        unsigned has_endTimeReliable:1;
        unsigned has_significance:1;
        unsigned has_restrictionInfo:1;
        unsigned has_userReportsCount:1;
        unsigned has_shouldDisplayOnMap:1;
        unsigned has_delaySeconds:1;
        unsigned has_artwork:1;
    } _has;
}
@end

@implementation GEORouteIncident

- (void)writeTo:(PBDataWriter *)writer {
    if (_has.has_position)         PBWriteMessageField(writer, _position, 1);
    if (_has.has_incidentId)       PBWriteStringField(writer, _incidentId, 2);
    if (_has.has_info)             PBWriteStringField(writer, _info, 3);
    if (_has.has_type)             PBWriteInt32Field(writer, _type, 4);
    if (_has.has_street)           PBWriteStringField(writer, _street, 5);
    if (_has.has_crossStreet)      PBWriteStringField(writer, _crossStreet, 6);
    if (_has.has_startTime)        PBWriteFixed64Field(writer, (uint64_t)_startTime, 7);
    if (_has.has_endTime)          PBWriteFixed64Field(writer, (uint64_t)_endTime, 8);
    if (_has.has_updateTime)       PBWriteFixed64Field(writer, (uint64_t)_updateTime, 9);
    if (_has.has_laneClosureType)  PBWriteInt32Field(writer, _laneClosureType, 10);
    if (_has.has_laneClosureCount) PBWriteUInt32Field(writer, _laneClosureCount, 11);
    if (_has.has_endTimeReliable)  PBWriteBoolField(writer, _endTimeReliable, 12);
    if (_has.has_significance)     PBWriteInt32Field(writer, _significance, 13);
    if (_has.has_restrictionInfo)  PBWriteMessageField(writer, _restrictionInfo, 14);
    if (_has.has_userReportsCount) PBWriteUInt32Field(writer, _userReportsCount, 15);
    if (_has.has_shouldDisplayOnMap) PBWriteBoolField(writer, _shouldDisplayOnMap, 16);
    for (id rid in _userReportIds) PBWriteStringField(writer, rid, 17);
    if (_has.has_delaySeconds)     PBWriteUInt32Field(writer, _delaySeconds, 18);
    if (_has.has_artwork)          PBWriteMessageField(writer, _artwork, 19);
    [super writeTo:writer];
}

@end

int main(void) { return 0; }
