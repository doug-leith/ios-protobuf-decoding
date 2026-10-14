"""Ground truth for f28_enum_dictrep_biased/testbiased — authored by hand in
fixture.m (see its header for the mechanism under test).

    message TestBuild {
      enum TestBuildType {           // 1-based, dictRep-ONLY (no typeAsString:)
        TEST_BUILD_TYPE_T300 = 1;
        TEST_BUILD_TYPE_T400 = 2;
        TEST_BUILD_TYPE_T392C = 3;
      }
      TestBuildType type = 6;
    }
    message TestOther {              // unrelated class that defines typeAsString:
      enum OtherType { OTHER_TYPE_NONE = 0; OTHER_TYPE_SOME = 1; OTHER_TYPE_MORE = 2; }
      OtherType type = 3;
    }
    message TestKind {               // 1-based, has its OWN kindAsString:
      enum TestKind { KIND_ALPHA = 1; KIND_BETA = 2; KIND_GAMMA = 3; }
      TestKind kind = 9;
    }

TestBuild.type is the regression: the shared `__objc_methname` pool holds
`typeAsString:` (from TestOther), and the dictRep bias gate used to read that
as "this field routes through xAsString:", so the `sub #1` bias was dropped and
the values came out 0..2 instead of 1..3 (real case: GEOPDGroundDataBuild.type
on iOS 16.7.11).  TestKind pins the other side of the gate: a field that really
has its own xAsString: is owned by that path (values_confirmed=True, no double
bias).  Value names are `<ENUM-PREFIX>_<NAME>`: `T392C` stays `T392C` -- the
table is all caps, so case marks no word boundary (it used to be split to
`T392_C`; see ``proto/enums.py``).
"""

EXPECTED = {
    "TestBuild": {
        "fields": [
            {"name": "type", "number": 6, "type_name": "TestBuildType",
             "label": "optional", "number_confirmed": True,
             "type_class": "ENUM:TestBuildType"},
        ],
        "enums": {
            "TestBuildType": {
                "values": [
                    (1, "TEST_BUILD_TYPE_T300"),
                    (2, "TEST_BUILD_TYPE_T400"),
                    (3, "TEST_BUILD_TYPE_T392C"),
                ],
                "values_confirmed": False,
                "values_truncated": False,
            },
        },
    },
    "TestOther": {
        "fields": [
            {"name": "type", "number": 3, "type_name": "OtherType",
             "label": "optional", "number_confirmed": True,
             "type_class": "ENUM:OtherType"},
        ],
        "enums": {
            "OtherType": {
                "values": [
                    (0, "OTHER_TYPE_NONE"),
                    (1, "OTHER_TYPE_SOME"),
                    (2, "OTHER_TYPE_MORE"),
                ],
                "values_confirmed": True,
                "values_truncated": False,
            },
        },
    },
    "TestKind": {
        "fields": [
            {"name": "kind", "number": 9, "type_name": "TestKind",
             "label": "optional", "number_confirmed": True,
             "type_class": "ENUM:TestKind"},
        ],
        "enums": {
            "TestKind": {
                "values": [
                    (1, "TEST_KIND_ALPHA"),
                    (2, "TEST_KIND_BETA"),
                    (3, "TEST_KIND_GAMMA"),
                ],
                "values_confirmed": True,
                "values_truncated": False,
            },
        },
    },
}
