#import "nested.h"

@implementation CLPMotionActivity
- (void)writeTo:(PBDataWriter *)writer {
    if (_has.has_activityType) PBWriteInt32Field(writer, _activityType, 1);
    [super writeTo:writer];
}
@end

@implementation CLPSatelliteReport
- (void)writeTo:(PBDataWriter *)writer {
    if (_has.has_satelliteCount) PBWriteUInt32Field(writer, _satelliteCount, 1);
    [super writeTo:writer];
}
@end

@implementation CLPPipelineDiagnosticReport
- (void)writeTo:(PBDataWriter *)writer {
    if (_has.has_diagnosticCode) PBWriteStringField(writer, _diagnosticCode, 1);
    [super writeTo:writer];
}
@end

@implementation CLPBaroCalibrationIndication
- (void)writeTo:(PBDataWriter *)writer {
    if (_has.has_isCalibrated) PBWriteBoolField(writer, _isCalibrated, 1);
    [super writeTo:writer];
}
@end
