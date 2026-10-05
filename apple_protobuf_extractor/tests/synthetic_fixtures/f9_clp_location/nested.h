#import "pbshim.h"

// Minimal stand-in classes CLPLocation references (see
// f6_geo_route_incident/nested.h for the rationale — a SINGULAR message
// field's type resolves straight from the ivar's own `@"ClassName"`
// @encode, so these don't need real internal schemas or dispatch cores).
// CLPMotionActivity is notable: the real CLPLocation references it from
// THREE distinct fields (rawMotionActivity/motionActivity/
// dominantMotionActivity) — the same class, three separate ivars — which
// this fixture keeps intact since it is a real, recurring shape (unlike a
// repeated field, resolving a class used multiple times as different
// SINGULAR fields needs nothing special, but it is still worth exercising
// for real rather than assuming it "obviously" works).

@interface CLPMotionActivity : PBCodable {
  @public
    int32_t _activityType;
    struct { unsigned has_activityType:1; } _has;
}
@end

@interface CLPSatelliteReport : PBCodable {
  @public
    uint32_t _satelliteCount;
    struct { unsigned has_satelliteCount:1; } _has;
}
@end

@interface CLPPipelineDiagnosticReport : PBCodable {
  @public
    NSString *_diagnosticCode;
    struct { unsigned has_diagnosticCode:1; } _has;
}
@end

@interface CLPBaroCalibrationIndication : PBCodable {
  @public
    BOOL _isCalibrated;
    struct { unsigned has_isCalibrated:1; } _has;
}
@end
