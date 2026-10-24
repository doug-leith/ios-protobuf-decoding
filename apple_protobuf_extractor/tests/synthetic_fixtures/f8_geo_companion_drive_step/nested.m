#import "nested.h"

@implementation GEONameInfo
- (void)writeTo:(PBDataWriter *)writer {
    if (_has.has_text) PBWriteStringField(writer, _text, 1);
}
- (BOOL)readFrom:(PBDataReader *)reader {
    return GEONameInfoReadFrom_core(self, reader);
}
@end

__attribute__((noinline)) BOOL GEONameInfoReadFrom_core(GEONameInfo *self, PBDataReader *reader) {
    (void)reader;
    self->_has.has_text = 1;
    return YES;
}

@implementation GEONameInfoList
- (void)writeTo:(PBDataWriter *)writer {
    if (_has.has_primaryText) PBWriteStringField(writer, _primaryText, 1);
}
- (BOOL)readFrom:(PBDataReader *)reader {
    return GEONameInfoListReadFrom_core(self, reader);
}
@end

__attribute__((noinline)) BOOL GEONameInfoListReadFrom_core(GEONameInfoList *self, PBDataReader *reader) {
    (void)reader;
    self->_has.has_primaryText = 1;
    return YES;
}

@implementation GEOPBTransitArtwork
- (void)writeTo:(PBDataWriter *)writer {
    if (_has.has_artworkId) PBWriteStringField(writer, _artworkId, 1);
}
@end

@implementation GEOEVChargeInfo
- (void)writeTo:(PBDataWriter *)writer {
    if (_has.has_connectorType) PBWriteUInt32Field(writer, _connectorType, 1);
}
@end

@implementation GEOEVStepInfo
- (void)writeTo:(PBDataWriter *)writer {
    if (_has.has_batteryPercentage) PBWriteFloatField(writer, _batteryPercentage, 1);
}
@end
