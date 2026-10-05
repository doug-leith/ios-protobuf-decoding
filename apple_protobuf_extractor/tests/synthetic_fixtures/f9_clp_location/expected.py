"""Ground truth for f9_clp_location/testcl — authored by hand from
fixture.m/nested.m, cross-checked field-for-field against the REAL extracted
schema this fixture reimplements (tests/golden/CoreLocationProtobuf.json,
``CLPLocation.*``), not derived from this fixture's own tool output.

"CLP" is stripped from the message name the same way "GEO" is (see
f6_geo_route_incident's gotcha-7 note — CLP is also in
proto/defaults.py:DEFAULT_PREFIXES), so the dict key is "Location", not
"CLPLocation". Field type_class still carries the full class name
("CLPMotionActivity" etc).

context/motionActivityType/motionActivityConfidence/provider/modeIndicator
are real Apple enums in the original schema but are declared plain int32
here with no `AsString:` selector — see f6_geo_route_incident/fixture.m's
header comment for why.
"""

EXPECTED = {
    "Location": {
        "fields": [
            {"name": "latitude", "number": 1, "type_name": "double", "label": "optional"},
            {"name": "longitude", "number": 2, "type_name": "double", "label": "optional"},
            {"name": "horizontalAccuracy", "number": 3, "type_name": "float", "label": "optional"},
            {"name": "altitude", "number": 5, "type_name": "float", "label": "optional"},
            {"name": "verticalAccuracy", "number": 6, "type_name": "float", "label": "optional"},
            {"name": "speed", "number": 7, "type_name": "float", "label": "optional"},
            {"name": "course", "number": 8, "type_name": "float", "label": "optional"},
            {"name": "timestamp", "number": 9, "type_name": "double", "label": "optional"},
            {"name": "context", "number": 10, "type_name": "int32", "label": "optional"},
            {"name": "motionActivityType", "number": 11, "type_name": "int32", "label": "optional"},
            {"name": "motionActivityConfidence", "number": 12, "type_name": "int32", "label": "optional"},
            {"name": "provider", "number": 13, "type_name": "int32", "label": "optional"},
            {"name": "floor", "number": 14, "type_name": "int32", "label": "optional"},
            {"name": "appBundleIdIndices", "number": 15, "type_name": "string", "label": "repeated"},
            {"name": "motionVehicleConnectedStateChanged", "number": 16, "type_name": "bool", "label": "optional"},
            {"name": "motionVehicleConnected", "number": 17, "type_name": "bool", "label": "optional"},
            {"name": "rawMotionActivity", "number": 18, "type_name": "CLPMotionActivity",
             "type_class": "CLPMotionActivity", "label": "optional"},
            {"name": "motionActivity", "number": 19, "type_name": "CLPMotionActivity",
             "type_class": "CLPMotionActivity", "label": "optional"},
            {"name": "dominantMotionActivity", "number": 20, "type_name": "CLPMotionActivity",
             "type_class": "CLPMotionActivity", "label": "optional"},
            {"name": "courseAccuracy", "number": 21, "type_name": "float", "label": "optional"},
            {"name": "speedAccuracy", "number": 22, "type_name": "float", "label": "optional"},
            {"name": "modeIndicator", "number": 23, "type_name": "int32", "label": "optional"},
            {"name": "horzUncSemiMaj", "number": 24, "type_name": "float", "label": "optional"},
            {"name": "horzUncSemiMin", "number": 25, "type_name": "float", "label": "optional"},
            {"name": "horzUncSemiMajAz", "number": 26, "type_name": "float", "label": "optional"},
            {"name": "satReport", "number": 27, "type_name": "CLPSatelliteReport",
             "type_class": "CLPSatelliteReport", "label": "optional"},
            {"name": "isFromLocationController", "number": 28, "type_name": "bool", "label": "optional"},
            {"name": "pipelineDiagnosticReport", "number": 29, "type_name": "CLPPipelineDiagnosticReport",
             "type_class": "CLPPipelineDiagnosticReport", "label": "optional"},
            {"name": "baroCalibrationIndication", "number": 30, "type_name": "CLPBaroCalibrationIndication",
             "type_class": "CLPBaroCalibrationIndication", "label": "optional"},
        ],
    },
    "MotionActivity": {
        "fields": [
            {"name": "activityType", "number": 1, "type_name": "int32", "label": "optional"},
        ],
    },
    "SatelliteReport": {
        "fields": [
            {"name": "satelliteCount", "number": 1, "type_name": "uint32", "label": "optional"},
        ],
    },
    "PipelineDiagnosticReport": {
        "fields": [
            {"name": "diagnosticCode", "number": 1, "type_name": "string", "label": "optional"},
        ],
    },
    "BaroCalibrationIndication": {
        "fields": [
            {"name": "isCalibrated", "number": 1, "type_name": "bool", "label": "optional"},
        ],
    },
}
