#import "pbshim.h"

// Minimal stand-in classes GEOCompanionDriveStep references. Their own
// internal schema is not under test (see f6_geo_route_incident/nested.h for
// the same rationale). GEONameInfo and GEONameInfoList additionally need a
// noinline C-level ReadAllFrom core (gotcha 3b) because they are each used
// as the ELEMENT type of a REPEATED message field (signposts / maneuverNames
// respectively) — resolving that element type requires
// GEOCompanionDriveStep's own readFrom: dispatch core to statically
// reference the element class's reader, which is exactly what this fixture
// is built to exercise. GEOPBTransitArtwork/GEOEVChargeInfo/GEOEVStepInfo
// are only ever referenced SINGULARLY, so their concrete class name already
// comes straight from the ivar's own `@"ClassName"` @encode — no dispatch
// core needed for them.

@interface GEONameInfo : PBCodable {
  @public
    NSString *_text;
    struct { unsigned has_text:1; } _has;
}
@end
extern __attribute__((noinline)) BOOL GEONameInfoReadFrom_core(GEONameInfo *self, PBDataReader *reader);

@interface GEONameInfoList : PBCodable {
  @public
    NSString *_primaryText;
    struct { unsigned has_primaryText:1; } _has;
}
@end
extern __attribute__((noinline)) BOOL GEONameInfoListReadFrom_core(GEONameInfoList *self, PBDataReader *reader);

@interface GEOPBTransitArtwork : PBCodable {
  @public
    NSString *_artworkId;
    struct { unsigned has_artworkId:1; } _has;
}
@end

@interface GEOEVChargeInfo : PBCodable {
  @public
    uint32_t _connectorType;
    struct { unsigned has_connectorType:1; } _has;
}
@end

@interface GEOEVStepInfo : PBCodable {
  @public
    float _batteryPercentage;
    struct { unsigned has_batteryPercentage:1; } _has;
}
@end
