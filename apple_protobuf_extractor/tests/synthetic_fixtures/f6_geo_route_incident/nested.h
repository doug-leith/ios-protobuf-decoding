#import "pbshim.h"

// Minimal stand-in classes for the message-typed fields GEORouteIncident
// references (position/restrictionInfo/artwork). Their OWN internal schema
// is not under test here — only that GEORouteIncident.<field>'s type_name/
// type_class resolves to the right CLASS NAME, which for a SINGULAR message
// field comes straight from the ivar's own `@"ClassName"` @encode
// (proto/protocore.py:_type_from_enc's generic `@"..."` branch) with no
// disassembly dependency at all. Each still carries one real field so it is
// a genuine, non-degenerate PBCodable subclass.

@interface GEOLatLng : PBCodable {
  @public
    double _latitude;
    struct { unsigned has_latitude:1; } _has;
}
@end

@interface GEORestrictionInfo : PBCodable {
  @public
    NSString *_restrictionDescription;
    struct { unsigned has_restrictionDescription:1; } _has;
}
@end

@interface GEOPBTransitArtwork : PBCodable {
  @public
    NSString *_artworkId;
    struct { unsigned has_artworkId:1; } _has;
}
@end
