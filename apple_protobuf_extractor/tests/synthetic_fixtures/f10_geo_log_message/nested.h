#import "pbshim.h"

// Support classes GEOLogMessage / GEOLogMsgEvent reference.
//
// GEOLogMsgState is the ELEMENT of GEOLogMsgEvent.logMsgStates (a repeated
// message field) — resolving that element type needs GEOLogMsgEvent's own
// readFrom: dispatch core to statically reference GEOLogMsgState's reader
// (gotcha 3b), so it needs a noinline ReadAllFrom core like f2/f5/f8's
// element classes. It is otherwise a minimal stand-in (the real class has
// 55 fields; only field 1, `stateOrigin`, is reimplemented here — see
// GEOLogMsgEvent's own header comment for why this fixture uses a
// REPRESENTATIVE SUBSET rather than full-fidelity leaves).
@interface GEOLogMsgState : PBCodable {
  @public
    NSString *_stateOrigin;
    struct { unsigned has_stateOrigin:1; } _has;
}
@end
extern __attribute__((noinline)) BOOL GEOLogMsgStateReadFrom_core(GEOLogMsgState *self, PBDataReader *reader);

// GEOLogMsgEventId is only ever referenced SINGULARLY (GEOLogMsgEvent.
// analyticTag) and is small in reality (3 fields) — reimplemented in full.
@interface GEOLogMsgEventId : PBCodable {
  @public
    uint64_t _high;
    uint64_t _low;
    uint32_t _deanonymizeId;
    struct {
        unsigned has_high:1;
        unsigned has_low:1;
        unsigned has_deanonymizeId:1;
    } _has;
}
@end

// The remaining four are event-payload leaves referenced SINGULARLY from
// GEOLogMsgEvent's real sparse field numbers (101/102/106/117) — minimal
// stand-ins, same rationale as GEOLogMsgState's single-field treatment.
@interface GEOLogMsgEventUserAction : PBCodable {
  @public
    NSString *_userActionEventKey;
    struct { unsigned has_userActionEventKey:1; } _has;
}
@end

@interface GEOLogMsgEventStateTiming : PBCodable {
  @public
    double _durationInOldState;
    struct { unsigned has_durationInOldState:1; } _has;
}
@end

@interface GEOLogMsgEventNetwork : PBCodable {
  @public
    int32_t _requestDataSize;
    struct { unsigned has_requestDataSize:1; } _has;
}
@end

@interface GEOLogMsgEventMapLaunch : PBCodable {
  @public
    NSString *_sourceAppId;
    struct { unsigned has_sourceAppId:1; } _has;
}
@end
