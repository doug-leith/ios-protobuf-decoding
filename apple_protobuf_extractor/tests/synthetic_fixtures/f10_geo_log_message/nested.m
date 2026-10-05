#import "nested.h"

@implementation GEOLogMsgState
- (void)writeTo:(PBDataWriter *)writer {
    if (_has.has_stateOrigin) PBWriteStringField(writer, _stateOrigin, 1);
    [super writeTo:writer];
}
- (BOOL)readFrom:(PBDataReader *)reader {
    return GEOLogMsgStateReadFrom_core(self, reader);
}
@end

__attribute__((noinline)) BOOL GEOLogMsgStateReadFrom_core(GEOLogMsgState *self, PBDataReader *reader) {
    (void)reader;
    self->_has.has_stateOrigin = 1;
    return YES;
}

@implementation GEOLogMsgEventId
- (void)writeTo:(PBDataWriter *)writer {
    if (_has.has_high) PBWriteUInt64Field(writer, _high, 1);
    if (_has.has_low)  PBWriteUInt64Field(writer, _low, 2);
    if (_has.has_deanonymizeId) PBWriteUInt32Field(writer, _deanonymizeId, 3);
    [super writeTo:writer];
}
@end

@implementation GEOLogMsgEventUserAction
- (void)writeTo:(PBDataWriter *)writer {
    if (_has.has_userActionEventKey) PBWriteStringField(writer, _userActionEventKey, 1);
    [super writeTo:writer];
}
@end

@implementation GEOLogMsgEventStateTiming
- (void)writeTo:(PBDataWriter *)writer {
    if (_has.has_durationInOldState) PBWriteDoubleField(writer, _durationInOldState, 2);
    [super writeTo:writer];
}
@end

@implementation GEOLogMsgEventNetwork
- (void)writeTo:(PBDataWriter *)writer {
    if (_has.has_requestDataSize) PBWriteInt32Field(writer, _requestDataSize, 2);
    [super writeTo:writer];
}
@end

@implementation GEOLogMsgEventMapLaunch
- (void)writeTo:(PBDataWriter *)writer {
    if (_has.has_sourceAppId) PBWriteStringField(writer, _sourceAppId, 1);
    [super writeTo:writer];
}
@end
