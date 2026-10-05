"""Ground truth for f11_enum_pointer_table/testenum — authored by hand in
fixture.m, not derived from any tool output (except the enum type-name
strings, which are the tool's own documented, harmless best-effort
reconstruction from the value-string common prefix — see
proto/enums.py:_enum_name_from_pairs and ENUM_TYPE_NAMES.md; verified once
against the actual run, not re-derived by hand).

    message TestEnumStatus {
      enum TestEnumStatus {              // 0-based, no bias
        TEST_ENUM_STATUS_UNKNOWN = 0;
        TEST_ENUM_STATUS_OK = 1;
        TEST_ENUM_STATUS_FAIL = 2;
      }
      TestEnumStatus status = 7;
    }

    message TestEnumSourceType {
      enum MapRegionSourceType {         // 1-based -- real GEOMapRegionSourceType
        MAP_REGION_SOURCE_TYPE_UNKNOWN = 1;
        MAP_REGION_SOURCE_TYPE_BASEMAP_CURATED = 2;
        MAP_REGION_SOURCE_TYPE_REV_POLYGON_PADDED = 3;
        MAP_REGION_SOURCE_TYPE_REV_POINT_PADDED = 4;
        MAP_REGION_SOURCE_TYPE_GEMINI_CURATED = 5;
        MAP_REGION_SOURCE_TYPE_GEMINI_POINT_PADDED = 6;
        MAP_REGION_SOURCE_TYPE_PLACES_POINT_PADDED = 7;
        MAP_REGION_SOURCE_TYPE_DISPATCHER_CALCULATED = 8;
        MAP_REGION_SOURCE_TYPE_ROUTING_CALCULATED = 9;
        MAP_REGION_SOURCE_TYPE_SEARCH_CALCULATED = 10;
        MAP_REGION_SOURCE_TYPE_ROUTING_FALLBACK = 11;
        MAP_REGION_SOURCE_TYPE_REV_POLYGON_FIT = 12;
        MAP_REGION_SOURCE_TYPE_GEMINI_POLYGON_FIT = 13;
      }
      MapRegionSourceType sourceType = 11;
    }

Both AsString: methods were disassembled and confirmed (build_fixtures.sh /
gotcha 4) to compile to the exact scaled-index pointer-table load
_extract_enum_values' primary branch looks for (`ldr x0,[x8,wN,sxtw #3]`),
with TestEnumSourceType additionally showing the `sub w8,w2,#1` bias
instruction _find_index_bias reads. Both enums extract fully
(values_confirmed=True) since every table entry was read cleanly.
"""

_STATUS_VALUES = [
    (0, "TEST_ENUM_STATUS_UNKNOWN"),
    (1, "TEST_ENUM_STATUS_OK"),
    (2, "TEST_ENUM_STATUS_FAIL"),
]

_SOURCE_TYPE_VALUES = [
    (1,  "MAP_REGION_SOURCE_TYPE_UNKNOWN"),
    (2,  "MAP_REGION_SOURCE_TYPE_BASEMAP_CURATED"),
    (3,  "MAP_REGION_SOURCE_TYPE_REV_POLYGON_PADDED"),
    (4,  "MAP_REGION_SOURCE_TYPE_REV_POINT_PADDED"),
    (5,  "MAP_REGION_SOURCE_TYPE_GEMINI_CURATED"),
    (6,  "MAP_REGION_SOURCE_TYPE_GEMINI_POINT_PADDED"),
    (7,  "MAP_REGION_SOURCE_TYPE_PLACES_POINT_PADDED"),
    (8,  "MAP_REGION_SOURCE_TYPE_DISPATCHER_CALCULATED"),
    (9,  "MAP_REGION_SOURCE_TYPE_ROUTING_CALCULATED"),
    (10, "MAP_REGION_SOURCE_TYPE_SEARCH_CALCULATED"),
    (11, "MAP_REGION_SOURCE_TYPE_ROUTING_FALLBACK"),
    (12, "MAP_REGION_SOURCE_TYPE_REV_POLYGON_FIT"),
    (13, "MAP_REGION_SOURCE_TYPE_GEMINI_POLYGON_FIT"),
]

EXPECTED = {
    "TestEnumStatus": {
        "fields": [
            {"name": "status", "number": 7, "type_name": "TestEnumStatus",
             "label": "optional", "number_confirmed": True,
             "type_class": "ENUM:TestEnumStatus"},
        ],
        "enums": {
            "TestEnumStatus": {
                "values": _STATUS_VALUES,
                "values_confirmed": True,
                "values_truncated": False,
            },
        },
    },
    "TestEnumSourceType": {
        "fields": [
            {"name": "sourceType", "number": 11, "type_name": "MapRegionSourceType",
             "label": "optional", "number_confirmed": True,
             "type_class": "ENUM:MapRegionSourceType"},
        ],
        "enums": {
            "MapRegionSourceType": {
                "values": _SOURCE_TYPE_VALUES,
                "values_confirmed": True,
                "values_truncated": False,
            },
        },
    },
}
