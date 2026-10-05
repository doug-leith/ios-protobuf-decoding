"""Ground truth for f8_geo_companion_drive_step/testcds — authored by hand
from fixture.m/nested.m, cross-checked field-for-field against the REAL
extracted schema this fixture reimplements (tests/golden/GeoServices.json,
``GEOCompanionDriveStep.*``), not derived from this fixture's own tool
output.

maneuverType/junctionType/drivingSide are real Apple enums in the original
schema but are declared plain int32 here with no `AsString:` selector — see
f6_geo_route_incident/fixture.m's header comment for why.

GEOCompanionDriveStepReadFrom_core disassembles to a real ARM64 jump table
(verified via otool -tV at authoring time: `sub w8,w1,#1; cmp w8,#0x10;
b.hi oob; adr; ldrb; add; br`), the same mechanism as f5_jumptable_dispatch
but now resolving TWO distinct repeated-message element types (cases 10 and
11) in one dispatch, plus GEONameInfo appearing as both a repeated element
(signposts, case 11) and a singular field's type (exitNumber, field 13,
resolved trivially from its own ivar @encode — no dispatch involved for that
occurrence).
"""

EXPECTED = {
    "CompanionDriveStep": {
        "fields": [
            {"name": "maneuverType", "number": 4, "type_name": "int32", "label": "optional"},
            {"name": "shield", "number": 6, "type_name": "string", "label": "optional"},
            {"name": "shieldType", "number": 7, "type_name": "sint32", "label": "optional"},
            {"name": "junctionType", "number": 8, "type_name": "int32", "label": "optional"},
            {"name": "junctionElements", "number": 9, "type_name": "bytes", "label": "repeated"},
            {"name": "maneuverNames", "number": 10, "type_name": "GEONameInfoList",
             "type_class": "GEONameInfoList", "label": "repeated"},
            {"name": "signposts", "number": 11, "type_name": "GEONameInfo",
             "type_class": "GEONameInfo", "label": "repeated"},
            {"name": "toFreeway", "number": 12, "type_name": "bool", "label": "optional"},
            {"name": "exitNumber", "number": 13, "type_name": "GEONameInfo",
             "type_class": "GEONameInfo", "label": "optional"},
            {"name": "drivingSide", "number": 14, "type_name": "int32", "label": "optional"},
            {"name": "artworkOverride", "number": 15, "type_name": "GEOPBTransitArtwork",
             "type_class": "GEOPBTransitArtwork", "label": "optional"},
            {"name": "chargingInfo", "number": 16, "type_name": "GEOEVChargeInfo",
             "type_class": "GEOEVChargeInfo", "label": "optional"},
            {"name": "evInfo", "number": 17, "type_name": "GEOEVStepInfo",
             "type_class": "GEOEVStepInfo", "label": "optional"},
        ],
    },
    "NameInfo": {
        "fields": [
            {"name": "text", "number": 1, "type_name": "string", "label": "optional"},
        ],
    },
    "NameInfoList": {
        "fields": [
            {"name": "primaryText", "number": 1, "type_name": "string", "label": "optional"},
        ],
    },
    "PBTransitArtwork": {
        "fields": [
            {"name": "artworkId", "number": 1, "type_name": "string", "label": "optional"},
        ],
    },
    "EVChargeInfo": {
        "fields": [
            {"name": "connectorType", "number": 1, "type_name": "uint32", "label": "optional"},
        ],
    },
    "EVStepInfo": {
        "fields": [
            {"name": "batteryPercentage", "number": 1, "type_name": "float", "label": "optional"},
        ],
    },
}
