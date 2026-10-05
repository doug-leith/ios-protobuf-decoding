"""Ground truth for f6_geo_route_incident/testri — authored by hand from
fixture.m/nested.m, cross-checked field-for-field against the REAL extracted
schema this fixture reimplements (tests/golden/GeoServices.json,
``GEORouteIncident.*``), not derived from this fixture's own tool output.

extract_all() strips the configured ObjC class prefix (proto/defaults.py
DEFAULT_PREFIXES includes "GEO") when forming a ProtoMessage's ``.name`` —
this is why the dict keys below are "RouteIncident"/"LatLng"/etc, not
"GEORouteIncident"/"GEOLatLng"; a FIELD's type_name/type_class still carries
the class's full original name (e.g. "GEOLatLng"), since that is the literal
ivar `@encode` class name, unaffected by the message-name display strip.

Three fields (type/laneClosureType/significance) are real Apple enums in the
original schema (RouteIncidentType/RouteIncidentLaneClosureType/
RouteIncidentSignificance) but are declared here as plain int32 with NO
`<field>AsString:` selector — see fixture.m's header comment: qualified enum
NAME recovery is a separate mechanism (metaclass dictRep value table) that
README.md's "Deferred" section already scoped out of this fixture suite as
too compiler/SDK-version-sensitive to reproduce reliably from C source.
Reproducing "RouteIncidentType" here without building that mechanism for
real would mean copying the answer from current tool output rather than
authoring an independent ground truth. int32 is the correct, honest decode
for a class with no enum accessor.
"""

EXPECTED = {
    "RouteIncident": {
        "fields": [
            {"name": "position", "number": 1, "type_name": "GEOLatLng",
             "type_class": "GEOLatLng", "label": "optional"},
            {"name": "incidentId", "number": 2, "type_name": "string", "label": "optional"},
            {"name": "info", "number": 3, "type_name": "string", "label": "optional"},
            {"name": "type", "number": 4, "type_name": "int32", "label": "optional"},
            {"name": "street", "number": 5, "type_name": "string", "label": "optional"},
            {"name": "crossStreet", "number": 6, "type_name": "string", "label": "optional"},
            {"name": "startTime", "number": 7, "type_name": "sfixed64", "label": "optional"},
            {"name": "endTime", "number": 8, "type_name": "sfixed64", "label": "optional"},
            {"name": "updateTime", "number": 9, "type_name": "sfixed64", "label": "optional"},
            {"name": "laneClosureType", "number": 10, "type_name": "int32", "label": "optional"},
            {"name": "laneClosureCount", "number": 11, "type_name": "uint32", "label": "optional"},
            {"name": "endTimeReliable", "number": 12, "type_name": "bool", "label": "optional"},
            {"name": "significance", "number": 13, "type_name": "int32", "label": "optional"},
            {"name": "restrictionInfo", "number": 14, "type_name": "GEORestrictionInfo",
             "type_class": "GEORestrictionInfo", "label": "optional"},
            {"name": "userReportsCount", "number": 15, "type_name": "uint32", "label": "optional"},
            {"name": "shouldDisplayOnMap", "number": 16, "type_name": "bool", "label": "optional"},
            {"name": "userReportIds", "number": 17, "type_name": "string", "label": "repeated"},
            {"name": "delaySeconds", "number": 18, "type_name": "uint32", "label": "optional"},
            {"name": "artwork", "number": 19, "type_name": "GEOPBTransitArtwork",
             "type_class": "GEOPBTransitArtwork", "label": "optional"},
        ],
    },
    "LatLng": {
        "fields": [
            {"name": "latitude", "number": 1, "type_name": "double", "label": "optional"},
        ],
    },
    "RestrictionInfo": {
        "fields": [
            {"name": "restrictionDescription", "number": 1, "type_name": "string", "label": "optional"},
        ],
    },
    "PBTransitArtwork": {
        "fields": [
            {"name": "artworkId", "number": 1, "type_name": "string", "label": "optional"},
        ],
    },
}
