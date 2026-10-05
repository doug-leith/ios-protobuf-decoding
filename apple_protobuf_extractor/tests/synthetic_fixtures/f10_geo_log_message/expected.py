"""Ground truth for f10_geo_log_message/testlm — authored by hand from
fixture.m/nested.m, cross-checked field-for-field against the REAL extracted
schema this fixture reimplements (tests/golden/GeoServices.json,
``GEOLogMessage.*`` and a real subset of ``GEOLogMsgEvent.*``), not derived
from this fixture's own tool output.

GEOLogMsgEventReadFrom_core compiles to a HYBRID dispatch shape (verified via
otool -tV at authoring time): a compare-chain for the low sparse case values
(1, 2, 3) and the far outlier (117), falling through to a small real ARM64
JUMP TABLE for the dense 100-106 cluster (`sub w8,w1,#0x64; cmp w8,#0x6;
b.hi oob; adr; ldrb; add; br`) — neither pure f2-style compare-chain nor pure
f5/f8-style jump table, but a genuine third shape clang produces for a case
set with one dense cluster plus sparse outliers. Field 1 (the one under
test, logMsgStates -> GEOLogMsgState) resolves via the compare-chain half;
proto/dispatch.py's two decoders (_dominance_field_of / _find_dispatch_cluster)
are independent and this fixture confirms the compare-chain one (dominance
attribution over a complete CFG) still finds its arm correctly when a jump
table is also present later in the same function.

eventType is a real Apple enum (LogMsgEventType) in the original schema but
is declared plain int32 here with no `AsString:` selector — see
f6_geo_route_incident/fixture.m's header comment for why. Likewise
logMessageType (GEOLogMessage, real enum LogMessageType).

GEOLogMsgEvent is a REPRESENTATIVE SUBSET of the real 59-field class (8 real
fields, at their real field numbers, spanning the same 1..117 sparse range)
— see fixture.m's header comment for why reimplementing all 59 would not add
coverage. GEOLogMsgState is similarly a minimal stand-in for the real
55-field class (field 1 only).
"""

EXPECTED = {
    "LogMessage": {
        "fields": [
            {"name": "logMsgEvents", "number": 102, "type_name": "GEOLogMsgEvent",
             "type_class": "GEOLogMsgEvent", "label": "repeated"},
            {"name": "logMessageType", "number": 1000, "type_name": "int32", "label": "optional"},
            {"name": "groupRetryCount", "number": 2000, "type_name": "uint32", "label": "optional"},
        ],
    },
    "LogMsgEvent": {
        "fields": [
            {"name": "logMsgStates", "number": 1, "type_name": "GEOLogMsgState",
             "type_class": "GEOLogMsgState", "label": "repeated"},
            {"name": "analyticTag", "number": 2, "type_name": "GEOLogMsgEventId",
             "type_class": "GEOLogMsgEventId", "label": "optional"},
            {"name": "mapsEnvironment", "number": 3, "type_name": "string", "label": "optional"},
            {"name": "eventType", "number": 100, "type_name": "int32", "label": "optional"},
            {"name": "userActionEvent", "number": 101, "type_name": "GEOLogMsgEventUserAction",
             "type_class": "GEOLogMsgEventUserAction", "label": "optional"},
            {"name": "stateTimingEvent", "number": 102, "type_name": "GEOLogMsgEventStateTiming",
             "type_class": "GEOLogMsgEventStateTiming", "label": "optional"},
            {"name": "networkEvent", "number": 106, "type_name": "GEOLogMsgEventNetwork",
             "type_class": "GEOLogMsgEventNetwork", "label": "optional"},
            {"name": "mapLaunchEvent", "number": 117, "type_name": "GEOLogMsgEventMapLaunch",
             "type_class": "GEOLogMsgEventMapLaunch", "label": "optional"},
        ],
    },
    "LogMsgState": {
        "fields": [
            {"name": "stateOrigin", "number": 1, "type_name": "string", "label": "optional"},
        ],
    },
    "LogMsgEventId": {
        "fields": [
            {"name": "high", "number": 1, "type_name": "uint64", "label": "optional"},
            {"name": "low", "number": 2, "type_name": "uint64", "label": "optional"},
            {"name": "deanonymizeId", "number": 3, "type_name": "uint32", "label": "optional"},
        ],
    },
    "LogMsgEventUserAction": {
        "fields": [
            {"name": "userActionEventKey", "number": 1, "type_name": "string", "label": "optional"},
        ],
    },
    "LogMsgEventStateTiming": {
        "fields": [
            {"name": "durationInOldState", "number": 2, "type_name": "double", "label": "optional"},
        ],
    },
    "LogMsgEventNetwork": {
        "fields": [
            {"name": "requestDataSize", "number": 2, "type_name": "int32", "label": "optional"},
        ],
    },
    "LogMsgEventMapLaunch": {
        "fields": [
            {"name": "sourceAppId", "number": 1, "type_name": "string", "label": "optional"},
        ],
    },
}
