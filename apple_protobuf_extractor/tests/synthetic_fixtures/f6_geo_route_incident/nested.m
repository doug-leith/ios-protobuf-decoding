#import "nested.h"

@implementation GEOLatLng
- (void)writeTo:(PBDataWriter *)writer {
    if (_has.has_latitude) PBWriteDoubleField(writer, _latitude, 1);
}
@end

@implementation GEORestrictionInfo
- (void)writeTo:(PBDataWriter *)writer {
    if (_has.has_restrictionDescription) PBWriteStringField(writer, _restrictionDescription, 1);
}
@end

@implementation GEOPBTransitArtwork
- (void)writeTo:(PBDataWriter *)writer {
    if (_has.has_artworkId) PBWriteStringField(writer, _artworkId, 1);
}
@end
