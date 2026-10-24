#import "nested.h"

// GROUND TRUTH — two REAL messages from GeoServices' analytics/logging
// pipeline (tests/golden/GeoServices.json), reimplemented as genuinely-
// compiled clean-room PBCodable classes:
//
//   message GEOLogMessage {
//     repeated GEOLogMsgEvent logMsgEvents = 102;
//     int32                   logMessageType = 1000;  // real enum — see f6 note
//     uint32                  groupRetryCount = 2000;
//   }
//
// GEOLogMessage itself is genuinely tiny (3 fields) but structurally unusual
// versus f6-f9: its field numbers are EXTREME and widely spaced (102, 1000,
// 2000) rather than dense/contiguous — a real Apple idiom (small "envelope"
// numbers reserved 1-100ish, payload numbers starting at a big round base),
// stress-testing the writeTo: CFG walk's tag-immediate handling at magnitudes
// f1-f9 never reached (a `mov w2,#1000`/`#2000` immediate doesn't fit the
// same encoding shape as `mov w2,#5`), and testing whether readFrom:
// dispatch resolution still works when only ONE of the switch's real cases
// is message-typed (102) with the others being plain scalars needing no
// dispatch handling at all.
//
//   message GEOLogMsgEvent {              // REPRESENTATIVE SUBSET — see below
//     repeated GEOLogMsgState        logMsgStates    = 1;
//     GEOLogMsgEventId                analyticTag     = 2;
//     string                           mapsEnvironment = 3;
//     int32                            eventType       = 100;  // real enum
//     GEOLogMsgEventUserAction        userActionEvent  = 101;
//     GEOLogMsgEventStateTiming       stateTimingEvent = 102;
//     GEOLogMsgEventNetwork           networkEvent     = 106;
//     GEOLogMsgEventMapLaunch         mapLaunchEvent   = 117;
//   }
//
// The REAL GEOLogMsgEvent has 59 fields — almost all like
// userActionEvent/stateTimingEvent/networkEvent/mapLaunchEvent above, one
// message type per log-event variant (a oneof-shaped "envelope + N optional
// payloads" idiom, the same shape GEOLogMessage itself uses one level up).
// Reimplementing all 59 would not test anything the 8 chosen here don't
// already cover once: this fixture picks a REAL subset (exact field numbers,
// not renumbered) spanning the SAME sparse 1..117 range the real class uses,
// which is the point under test — sparse/high field-number recovery plus a
// SECOND, independent level of repeated-message dispatch (field 1,
// logMsgStates -> GEOLogMsgState) nested one level inside the first
// (GEOLogMessage's own dispatch for field 102). GEOLogMsgEvent's dispatch
// core is EXPECTED to compile to a COMPARE-CHAIN, not a jump table — 8 case
// values spread from 1 to 117 make a dense jump table wildly wasteful, so
// clang should reject it — but this is VERIFIED by disassembly at authoring
// time (README.md gotcha 4b), not assumed; see the fixture-authoring note in
// this repo's session history for the actual otool -tV check.

@interface GEOLogMsgEvent : PBCodable {
  @public
    NSMutableArray *_logMsgStates;
  @protected
    GEOLogMsgEventId *_analyticTag;
    NSString *_mapsEnvironment;
    int32_t _eventType;
    GEOLogMsgEventUserAction *_userActionEvent;
    GEOLogMsgEventStateTiming *_stateTimingEvent;
    GEOLogMsgEventNetwork *_networkEvent;
    GEOLogMsgEventMapLaunch *_mapLaunchEvent;
    struct {
        unsigned has_analyticTag:1;
        unsigned has_mapsEnvironment:1;
        unsigned has_eventType:1;
        unsigned has_userActionEvent:1;
        unsigned has_stateTimingEvent:1;
        unsigned has_networkEvent:1;
        unsigned has_mapLaunchEvent:1;
    } _has;
}
@end

extern __attribute__((noinline)) void GEOLogMsgEventReadFrom_core(
    GEOLogMsgEvent *self, PBDataReader *reader);

@implementation GEOLogMsgEvent

- (void)writeTo:(PBDataWriter *)writer {
    for (id s in _logMsgStates) PBWriteMessageField(writer, s, 1);
    if (_has.has_analyticTag)      PBWriteMessageField(writer, _analyticTag, 2);
    if (_has.has_mapsEnvironment)  PBWriteStringField(writer, _mapsEnvironment, 3);
    if (_has.has_eventType)        PBWriteInt32Field(writer, _eventType, 100);
    if (_has.has_userActionEvent)  PBWriteMessageField(writer, _userActionEvent, 101);
    if (_has.has_stateTimingEvent) PBWriteMessageField(writer, _stateTimingEvent, 102);
    if (_has.has_networkEvent)     PBWriteMessageField(writer, _networkEvent, 106);
    if (_has.has_mapLaunchEvent)   PBWriteMessageField(writer, _mapLaunchEvent, 117);
}

- (BOOL)readFrom:(PBDataReader *)reader {
    GEOLogMsgEventReadFrom_core(self, reader);
    return YES;
}

@end

__attribute__((noinline)) void GEOLogMsgEventReadFrom_core(
    GEOLogMsgEvent *self, PBDataReader *reader) {
    uint32_t tag = PBReadTag(reader);
    uint32_t field = tag >> 3;
    switch (field) {
        case 1: {
            GEOLogMsgState *e = [GEOLogMsgState new];
            GEOLogMsgStateReadFrom_core(e, reader);
            if (self->_logMsgStates == nil) {
                self->_logMsgStates = [NSMutableArray new];
            }
            [self->_logMsgStates addObject:e];
            break;
        }
        case 2: PBHandleUnknownField(self, field); break;
        case 3: PBHandleUnknownField(self, field); break;
        case 100: PBHandleUnknownField(self, field); break;
        case 101: PBHandleUnknownField(self, field); break;
        case 102: PBHandleUnknownField(self, field); break;
        case 106: PBHandleUnknownField(self, field); break;
        case 117: PBHandleUnknownField(self, field); break;
        default: PBHandleUnknownField(self, field); break;
    }
}

@interface GEOLogMessage : PBCodable {
  @public
    NSMutableArray *_logMsgEvents;
  @protected
    int32_t _logMessageType;
    uint32_t _groupRetryCount;
    struct {
        unsigned has_logMessageType:1;
        unsigned has_groupRetryCount:1;
    } _has;
}
@end

extern __attribute__((noinline)) void GEOLogMessageReadFrom_core(
    GEOLogMessage *self, PBDataReader *reader);

@implementation GEOLogMessage

- (void)writeTo:(PBDataWriter *)writer {
    for (id e in _logMsgEvents) PBWriteMessageField(writer, e, 102);
    if (_has.has_logMessageType)  PBWriteInt32Field(writer, _logMessageType, 1000);
    if (_has.has_groupRetryCount) PBWriteUInt32Field(writer, _groupRetryCount, 2000);
}

- (BOOL)readFrom:(PBDataReader *)reader {
    GEOLogMessageReadFrom_core(self, reader);
    return YES;
}

@end

// Only ONE case here is message-typed (102, under test); 1000/2000 need no
// dispatch handling at all (their numbers already come from the writeTo:
// walk). A second filler arm + default is kept anyway — matching f2's
// pattern — so clang has a reason to materialize the real `lsr Wf,Wtag,#3`
// tag-decode instead of const-folding a single `field==102` compare into a
// masked equality check (README.md gotcha 4b).
__attribute__((noinline)) void GEOLogMessageReadFrom_core(
    GEOLogMessage *self, PBDataReader *reader) {
    uint32_t tag = PBReadTag(reader);
    uint32_t field = tag >> 3;
    switch (field) {
        case 102: {
            GEOLogMsgEvent *e = [GEOLogMsgEvent new];
            GEOLogMsgEventReadFrom_core(e, reader);
            if (self->_logMsgEvents == nil) {
                self->_logMsgEvents = [NSMutableArray new];
            }
            [self->_logMsgEvents addObject:e];
            break;
        }
        case 200: PBHandleUnknownField(self, field); break;
        default: PBHandleUnknownField(self, field); break;
    }
}

int main(void) { return 0; }
