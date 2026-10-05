"""Ground truth for f7_geo_tf_road_speed/testrs — authored by hand from
fixture.m, cross-checked field-for-field against the REAL extracted schema
this fixture reimplements (tests/golden/GeoServices.json,
``GEOTFRoadSpeed.*``), not derived from this fixture's own tool output.

`color` is a real Apple enum (TFRoadSpeedColor) in the original schema but is
declared plain int32 here with no `AsString:` selector — see
f6_geo_route_incident/fixture.m's header comment for why (qualified enum
name recovery is a separately-scoped, deliberately-deferred mechanism; int32
is the correct, honest decode for a class with no enum accessor).
"""

EXPECTED = {
    "TFRoadSpeed": {
        "fields": [
            {"name": "geoid", "number": 1, "type_name": "sint64", "label": "optional"},
            {"name": "startOffset", "number": 3, "type_name": "float", "label": "optional"},
            {"name": "endOffset", "number": 4, "type_name": "float", "label": "optional"},
            {"name": "hidden", "number": 5, "type_name": "bool", "label": "optional"},
            {"name": "predictedSpeeds", "number": 6, "type_name": "bytes", "label": "repeated"},
            {"name": "color", "number": 7, "type_name": "int32", "label": "optional"},
            {"name": "speedKph", "number": 8, "type_name": "uint32", "label": "optional"},
            {"name": "zilch", "number": 9, "type_name": "bytes", "label": "optional"},
            {"name": "decayTimeWindowInMinutes", "number": 10, "type_name": "uint32", "label": "optional"},
            {"name": "confidence", "number": 11, "type_name": "float", "label": "optional"},
            {"name": "latitudeCoordinates", "number": 12, "type_name": "float", "label": "repeated"},
            {"name": "longitudeCoordinates", "number": 13, "type_name": "float", "label": "repeated"},
            {"name": "geoIds", "number": 14, "type_name": "int64", "label": "repeated"},
            {"name": "openlr", "number": 15, "type_name": "bytes", "label": "optional"},
        ],
    },
}
