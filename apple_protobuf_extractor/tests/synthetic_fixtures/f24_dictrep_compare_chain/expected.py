"""Ground truth for f24_dictrep_compare_chain/testdcc — authored by hand in
fixture.m, not derived from any tool output (except the enum TYPE names, the
tool's own documented best-effort reconstruction from each value-string's
common SCREAMING_SNAKE prefix, verified before writing this file).

    message TestNewEnums {
      enum TestNewStatus {              // 3 sparse values: cmp+b.eq chain
        TEST_NEW_STATUS_FAILED = 1;
        TEST_NEW_STATUS_INVALID_REQUEST = 5;
        TEST_NEW_STATUS_VERSION_MISMATCH = 60;
      }
      optional TestNewStatus statusCode = 1;

      enum TestNewMode {                // 2 values: cbz-0 leaf + cmp #1 leaf
        TEST_NEW_MODE_OFF = 0;
        TEST_NEW_MODE_ON = 1;
      }
      optional TestNewMode mode = 2;

      enum TestNewTier {                // 6 sparse values: a cmp TREE
        TEST_NEW_TIER_A = 10; TEST_NEW_TIER_B = 20; TEST_NEW_TIER_C = 30;
        TEST_NEW_TIER_D = 40; TEST_NEW_TIER_E = 50; TEST_NEW_TIER_F = 60;
      }
      optional TestNewTier tier = 3;

      optional int32 count = 4;         // plain int32 — must NOT become an enum
    }

    message TestDirectEnum {            // dictRep is a registered method
      enum TestDirectLevel {
        TEST_DIRECT_LEVEL_LOW = 3;
        TEST_DIRECT_LEVEL_HIGH = 9;
      }
      optional TestDirectLevel level = 1;
    }

No field has an xAsString:/StringAsX: companion, so every enum here can ONLY
be recovered from the dictionaryRepresentation body — the compare-chain
harvest (_harvest_dictrep_enums' third pass). All four fields of TestNewEnums
sit in ONE function, so this also checks each chain is attributed to its OWN
ivar: a mis-anchored window would hand a chain to the wrong field (or, as
found while building this fixture, lose it entirely — the first field's gated
block is laid out out of line, after the function's epilogue (a tail branch), because the
compiler hoists the has-bits byte and branches on it with a `tbnz` cascade).

values_confirmed=False as for every non-xAsString: enum path.
"""

EXPECTED = {
    "TestNewEnums": {
        "fields": [
            {"name": "statusCode", "number": 1, "type_name": "TestNewStatus",
             "label": "optional", "number_confirmed": True,
             "type_class": "ENUM:TestNewStatus"},
            {"name": "mode", "number": 2, "type_name": "TestNewMode",
             "label": "optional", "number_confirmed": True,
             "type_class": "ENUM:TestNewMode"},
            {"name": "tier", "number": 3, "type_name": "TestNewTier",
             "label": "optional", "number_confirmed": True,
             "type_class": "ENUM:TestNewTier"},
            {"name": "count", "number": 4, "type_name": "int32",
             "label": "optional", "number_confirmed": True},
        ],
        "enums": {
            "TestNewStatus": {
                "values": [
                    (1, "TEST_NEW_STATUS_FAILED"),
                    (5, "TEST_NEW_STATUS_INVALID_REQUEST"),
                    (60, "TEST_NEW_STATUS_VERSION_MISMATCH"),
                ],
                "values_confirmed": False,
                "values_truncated": False,
            },
            "TestNewMode": {
                "values": [
                    (0, "TEST_NEW_MODE_OFF"),
                    (1, "TEST_NEW_MODE_ON"),
                ],
                "values_confirmed": False,
                "values_truncated": False,
            },
            "TestNewTier": {
                "values": [
                    (10, "TEST_NEW_TIER_A"), (20, "TEST_NEW_TIER_B"),
                    (30, "TEST_NEW_TIER_C"), (40, "TEST_NEW_TIER_D"),
                    (50, "TEST_NEW_TIER_E"), (60, "TEST_NEW_TIER_F"),
                ],
                "values_confirmed": False,
                "values_truncated": False,
            },
        },
    },
    "TestDirectEnum": {
        "fields": [
            {"name": "level", "number": 1, "type_name": "TestDirectLevel",
             "label": "optional", "number_confirmed": True,
             "type_class": "ENUM:TestDirectLevel"},
        ],
        "enums": {
            "TestDirectLevel": {
                "values": [
                    (3, "TEST_DIRECT_LEVEL_LOW"),
                    (9, "TEST_DIRECT_LEVEL_HIGH"),
                ],
                "values_confirmed": False,
                "values_truncated": False,
            },
        },
    },
}
