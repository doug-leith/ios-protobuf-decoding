"""Ground truth for f24_enum_dictrep_hybrid/testedh -- authored by hand in
fixture.m, not derived from any tool output.

    message TestHybrid {
      enum Status {
        STATUS_SUCCESS = 0;  STATUS_FAILED = 1;  STATUS_INCOMPLETE = 2;
        INVALID_REQUEST = 5;
        FAILED_NO_RESULT = 20;  NEEDS_REFINEMENT = 30;
        FAILED_NOT_AUTHORIZED = 40;  STATUS_DEDUPED = 50;
        VERSION_MISMATCH = 60;
      }
      Status status = 3;
    }

The enum has no xAsString: companion, so its values can only come from the
class's own _dictionaryRepresentation:, where the switch compiles to a jump
table for 0..5 and isolated compares for 20..60 (see fixture.m).

The authored value strings are the raw `@"..."` literals above. The tool
normalises them into the enum's own namespace (prefix TEST_HYBRID_STATUS_,
overlapping leading STATUS_ stripped): that is the documented behaviour of
proto.enums._normalize_enum_value_name, so the names below are the
normalised forms of the authored strings, not different values.
"""

_STATUS_VALUES = [
    (0, "TEST_HYBRID_STATUS_SUCCESS"),
    (1, "TEST_HYBRID_STATUS_FAILED"),
    (2, "TEST_HYBRID_STATUS_INCOMPLETE"),
    (5, "TEST_HYBRID_STATUS_INVALID_REQUEST"),
    (20, "TEST_HYBRID_STATUS_FAILED_NO_RESULT"),
    (30, "TEST_HYBRID_STATUS_NEEDS_REFINEMENT"),
    (40, "TEST_HYBRID_STATUS_FAILED_NOT_AUTHORIZED"),
    (50, "TEST_HYBRID_STATUS_DEDUPED"),
    (60, "TEST_HYBRID_STATUS_VERSION_MISMATCH"),
]

EXPECTED = {
    "TestHybrid": {
        "fields": [
            {"name": "status", "number": 3, "type_name": "TestHybridStatus",
             "label": "optional", "number_confirmed": True,
             "type_class": "ENUM:TestHybridStatus"},
        ],
        "enums": {
            "TestHybridStatus": {
                "values": _STATUS_VALUES,
                "values_confirmed": False,
                "values_truncated": False,
            },
        },
    },
}
