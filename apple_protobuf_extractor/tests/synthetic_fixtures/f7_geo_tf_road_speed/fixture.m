#import "pbwiretypes.h"

// GROUND TRUTH — a REAL message extracted from a live GeoServices dyld cache
// (tests/golden/GeoServices.json, `GEOTFRoadSpeed.*`), reimplemented as a
// genuinely-compiled clean-room PBCodable class. Same rationale as
// f6_geo_route_incident: check that a schema we already claim to have
// extracted, when actually implemented for real and re-extracted, comes back
// identical. This one's focus is scalar PACKED-repeated fields at real size
// (3 of them, 2 different element types, in one class) plus sint64 — distinct
// coverage from f6 (fixed64 + singular nested messages) and f8 (repeated
// MESSAGE dispatch).
//
//   message GEOTFRoadSpeed {
//     sint64          geoid                     = 1;
//     float           startOffset               = 3;
//     float           endOffset                 = 4;
//     bool            hidden                    = 5;
//     repeated bytes  predictedSpeeds           = 6;
//     int32           color                     = 7;   // real enum TFRoadSpeedColor — see f6 note
//     uint32          speedKph                  = 8;
//     bytes           zilch                     = 9;
//     uint32          decayTimeWindowInMinutes  = 10;
//     float           confidence                = 11;
//     repeated float  latitudeCoordinates       = 12 [packed=true];
//     repeated float  longitudeCoordinates      = 13 [packed=true];
//     repeated int64  geoIds                    = 14 [packed=true];
//     bytes           openlr                    = 15;
//   }
//
// Field numbers 1,3-15 (no field 2) — a real gap, not scrambled ordering
// (f1 already covers genuinely-scrambled numbering); this is the more common
// real-world case of a field that existed once and was removed/reserved.
//
// `color` is a real Apple enum (TFRoadSpeedColor) in the original schema but
// is declared here as plain int32 with no `AsString:` selector — see
// f6_geo_route_incident/fixture.m's header comment for why (qualified enum
// name recovery is a separately-scoped, deliberately-deferred mechanism).

@interface GEOTFRoadSpeed : PBCodable {
    int64_t _geoid;
    float _startOffset;
    float _endOffset;
    BOOL _hidden;
    NSMutableArray *_predictedSpeeds;
    int32_t _color;
    uint32_t _speedKph;
    NSData *_zilch;
    uint32_t _decayTimeWindowInMinutes;
    float _confidence;
    struct { float *list; unsigned long long count; unsigned long long size; } _latitudeCoordinates;
    struct { float *list; unsigned long long count; unsigned long long size; } _longitudeCoordinates;
    struct { int64_t *list; unsigned long long count; unsigned long long size; } _geoIds;
    NSData *_openlr;
    struct {
        unsigned has_geoid:1;
        unsigned has_startOffset:1;
        unsigned has_endOffset:1;
        unsigned has_hidden:1;
        unsigned has_color:1;
        unsigned has_speedKph:1;
        unsigned has_zilch:1;
        unsigned has_decayTimeWindowInMinutes:1;
        unsigned has_confidence:1;
        unsigned has_latitudeCoordinates:1;
        unsigned has_longitudeCoordinates:1;
        unsigned has_geoIds:1;
        unsigned has_openlr:1;
    } _has;
}
@end

@implementation GEOTFRoadSpeed

- (void)writeTo:(PBDataWriter *)writer {
    if (_has.has_geoid)       PBWriteSInt64Field(writer, _geoid, 1);
    if (_has.has_startOffset) PBWriteFloatField(writer, _startOffset, 3);
    if (_has.has_endOffset)   PBWriteFloatField(writer, _endOffset, 4);
    if (_has.has_hidden)      PBWriteBoolField(writer, _hidden, 5);
    for (id ps in _predictedSpeeds) PBWriteBytesField(writer, ps, 6);
    if (_has.has_color)       PBWriteInt32Field(writer, _color, 7);
    if (_has.has_speedKph)    PBWriteUInt32Field(writer, _speedKph, 8);
    if (_has.has_zilch)       PBWriteBytesField(writer, _zilch, 9);
    if (_has.has_decayTimeWindowInMinutes)
        PBWriteUInt32Field(writer, _decayTimeWindowInMinutes, 10);
    if (_has.has_confidence)  PBWriteFloatField(writer, _confidence, 11);
    if (_has.has_latitudeCoordinates)
        PBWritePackedFloatField(writer, _latitudeCoordinates.list, 12);
    if (_has.has_longitudeCoordinates)
        PBWritePackedFloatField(writer, _longitudeCoordinates.list, 13);
    if (_has.has_geoIds)
        PBWritePackedInt64Field(writer, _geoIds.list, 14);
    if (_has.has_openlr)      PBWriteBytesField(writer, _openlr, 15);
}

@end

int main(void) { return 0; }
