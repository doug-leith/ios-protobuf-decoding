#import "nested.h"

// GROUND TRUTH — a REAL message extracted from a live CoreLocationProtobuf
// framework (tests/golden/CoreLocationProtobuf.json, `CLPLocation.*`),
// reimplemented as a genuinely-compiled clean-room PBCodable class. Same
// rationale as the GeoServices f6-f8 tier (self-consistency check on a real
// message's full field mix at real size), but for the OTHER framework this
// tool targets — CLPLocation is CoreLocationProtobuf's core location-fix
// record, not a GeoServices message, so this also exercises the extractor
// against a second binary/serializer surface, not just a second message.
//
//   message CLPLocation {
//     double   latitude                            = 1;
//     double   longitude                            = 2;
//     float    horizontalAccuracy                   = 3;
//     // (no field 4 — real gap, not renumbered)
//     float    altitude                              = 5;
//     float    verticalAccuracy                      = 6;
//     float    speed                                 = 7;
//     float    course                                = 8;
//     double   timestamp                             = 9;
//     int32    context                               = 10;  // real enum — see f6 note
//     int32    motionActivityType                    = 11;  // real enum
//     int32    motionActivityConfidence               = 12;  // real enum
//     int32    provider                               = 13;  // real enum
//     int32    floor                                  = 14;
//     repeated string appBundleIdIndices              = 15;
//     bool     motionVehicleConnectedStateChanged      = 16;
//     bool     motionVehicleConnected                  = 17;
//     CLPMotionActivity rawMotionActivity              = 18;
//     CLPMotionActivity motionActivity                 = 19;
//     CLPMotionActivity dominantMotionActivity          = 20;
//     float    courseAccuracy                          = 21;
//     float    speedAccuracy                           = 22;
//     int32    modeIndicator                           = 23;  // real enum LocationModeIndicator
//     float    horzUncSemiMaj                          = 24;
//     float    horzUncSemiMin                          = 25;
//     float    horzUncSemiMajAz                        = 26;
//     CLPSatelliteReport satReport                     = 27;
//     bool     isFromLocationController                = 28;
//     CLPPipelineDiagnosticReport pipelineDiagnosticReport = 29;
//     CLPBaroCalibrationIndication baroCalibrationIndication = 30;
//   }
//
// Six int32 fields (context/motionActivityType/motionActivityConfidence/
// provider/modeIndicator) are real Apple enums in the original schema but
// are declared plain int32 here with no `AsString:` selector — see
// f6_geo_route_incident/fixture.m's header comment for why. No field here
// is repeated-MESSAGE (only appBundleIdIndices, repeated STRING), so — like
// f6/f7 — no readFrom: dispatch core is needed; field NUMBER recovery comes
// entirely from the writeTo: CFG walk, and every field's TYPE comes straight
// from its ivar's own @encode.

@interface CLPLocation : PBCodable {
    double _latitude;
    double _longitude;
    float _horizontalAccuracy;
    float _altitude;
    float _verticalAccuracy;
    float _speed;
    float _course;
    double _timestamp;
    int32_t _context;
    int32_t _motionActivityType;
    int32_t _motionActivityConfidence;
    int32_t _provider;
    int32_t _floor;
    NSMutableArray *_appBundleIdIndices;
    BOOL _motionVehicleConnectedStateChanged;
    BOOL _motionVehicleConnected;
    CLPMotionActivity *_rawMotionActivity;
    CLPMotionActivity *_motionActivity;
    CLPMotionActivity *_dominantMotionActivity;
    float _courseAccuracy;
    float _speedAccuracy;
    int32_t _modeIndicator;
    float _horzUncSemiMaj;
    float _horzUncSemiMin;
    float _horzUncSemiMajAz;
    CLPSatelliteReport *_satReport;
    BOOL _isFromLocationController;
    CLPPipelineDiagnosticReport *_pipelineDiagnosticReport;
    CLPBaroCalibrationIndication *_baroCalibrationIndication;
    struct {
        unsigned has_latitude:1;
        unsigned has_longitude:1;
        unsigned has_horizontalAccuracy:1;
        unsigned has_altitude:1;
        unsigned has_verticalAccuracy:1;
        unsigned has_speed:1;
        unsigned has_course:1;
        unsigned has_timestamp:1;
        unsigned has_context:1;
        unsigned has_motionActivityType:1;
        unsigned has_motionActivityConfidence:1;
        unsigned has_provider:1;
        unsigned has_floor:1;
        unsigned has_motionVehicleConnectedStateChanged:1;
        unsigned has_motionVehicleConnected:1;
        unsigned has_rawMotionActivity:1;
        unsigned has_motionActivity:1;
        unsigned has_dominantMotionActivity:1;
        unsigned has_courseAccuracy:1;
        unsigned has_speedAccuracy:1;
        unsigned has_modeIndicator:1;
        unsigned has_horzUncSemiMaj:1;
        unsigned has_horzUncSemiMin:1;
        unsigned has_horzUncSemiMajAz:1;
        unsigned has_satReport:1;
        unsigned has_isFromLocationController:1;
        unsigned has_pipelineDiagnosticReport:1;
        unsigned has_baroCalibrationIndication:1;
    } _has;
}
@end

@implementation CLPLocation

- (void)writeTo:(PBDataWriter *)writer {
    if (_has.has_latitude)  PBWriteDoubleField(writer, _latitude, 1);
    if (_has.has_longitude) PBWriteDoubleField(writer, _longitude, 2);
    if (_has.has_horizontalAccuracy) PBWriteFloatField(writer, _horizontalAccuracy, 3);
    if (_has.has_altitude)  PBWriteFloatField(writer, _altitude, 5);
    if (_has.has_verticalAccuracy) PBWriteFloatField(writer, _verticalAccuracy, 6);
    if (_has.has_speed)     PBWriteFloatField(writer, _speed, 7);
    if (_has.has_course)    PBWriteFloatField(writer, _course, 8);
    if (_has.has_timestamp) PBWriteDoubleField(writer, _timestamp, 9);
    if (_has.has_context)   PBWriteInt32Field(writer, _context, 10);
    if (_has.has_motionActivityType) PBWriteInt32Field(writer, _motionActivityType, 11);
    if (_has.has_motionActivityConfidence) PBWriteInt32Field(writer, _motionActivityConfidence, 12);
    if (_has.has_provider)  PBWriteInt32Field(writer, _provider, 13);
    if (_has.has_floor)     PBWriteInt32Field(writer, _floor, 14);
    for (id b in _appBundleIdIndices) PBWriteStringField(writer, b, 15);
    if (_has.has_motionVehicleConnectedStateChanged)
        PBWriteBoolField(writer, _motionVehicleConnectedStateChanged, 16);
    if (_has.has_motionVehicleConnected) PBWriteBoolField(writer, _motionVehicleConnected, 17);
    if (_has.has_rawMotionActivity) PBWriteMessageField(writer, _rawMotionActivity, 18);
    if (_has.has_motionActivity)    PBWriteMessageField(writer, _motionActivity, 19);
    if (_has.has_dominantMotionActivity) PBWriteMessageField(writer, _dominantMotionActivity, 20);
    if (_has.has_courseAccuracy) PBWriteFloatField(writer, _courseAccuracy, 21);
    if (_has.has_speedAccuracy)  PBWriteFloatField(writer, _speedAccuracy, 22);
    if (_has.has_modeIndicator)  PBWriteInt32Field(writer, _modeIndicator, 23);
    if (_has.has_horzUncSemiMaj) PBWriteFloatField(writer, _horzUncSemiMaj, 24);
    if (_has.has_horzUncSemiMin) PBWriteFloatField(writer, _horzUncSemiMin, 25);
    if (_has.has_horzUncSemiMajAz) PBWriteFloatField(writer, _horzUncSemiMajAz, 26);
    if (_has.has_satReport) PBWriteMessageField(writer, _satReport, 27);
    if (_has.has_isFromLocationController)
        PBWriteBoolField(writer, _isFromLocationController, 28);
    if (_has.has_pipelineDiagnosticReport)
        PBWriteMessageField(writer, _pipelineDiagnosticReport, 29);
    if (_has.has_baroCalibrationIndication)
        PBWriteMessageField(writer, _baroCalibrationIndication, 30);
}

@end

int main(void) { return 0; }
