"""Ground truth for f18_enum_multi_segment/testems — authored by hand in
fixture.m, not derived from any tool output (except the enum type-name
string, the tool's own documented best-effort reconstruction from the
value-string common prefix).

    message TestMultiSeg {
      enum TestMultiseg {
        TEST_MULTISEG_ZERO = 0;             // segment A (cluster 0-3)
        TEST_MULTISEG_ONE = 1;
        TEST_MULTISEG_TWO = 2;
        TEST_MULTISEG_THREE = 3;
        TEST_MULTISEG_HUNDRED = 100;        // segment B (cluster 100-103)
        TEST_MULTISEG_HUNDRED_ONE = 101;
        TEST_MULTISEG_HUNDRED_TWO = 102;
        TEST_MULTISEG_HUNDRED_THREE = 103;
      }
      TestMultiseg status = 3;
    }

statusAsString: is a plain C `switch` — REAL COMPILED CODE (gotcha 13: an
old-clang-frontend/modern-linker hybrid build, see fixture.m and
../README.md), not hand-assembly. It compiles to TWO independent
jump-table segments sharing ONE epilogue — the real shape confirmed on
GEOTelemetricEntity.eventKeyAsString: via the real dyld cache, not the
disjoint-per-segment-ret artifact this repo's normal (Xcode 15) clang
produces from the same source. All 8 values recover
(values_confirmed=False, as always for this fallback path;
values_truncated=False).
"""

_STATUS_VALUES = [
    (0,   "TEST_MULTISEG_ZERO"),
    (1,   "TEST_MULTISEG_ONE"),
    (2,   "TEST_MULTISEG_TWO"),
    (3,   "TEST_MULTISEG_THREE"),
    (100, "TEST_MULTISEG_HUNDRED"),
    (101, "TEST_MULTISEG_HUNDRED_ONE"),
    (102, "TEST_MULTISEG_HUNDRED_TWO"),
    (103, "TEST_MULTISEG_HUNDRED_THREE"),
]

EXPECTED = {
    "TestMultiSeg": {
        "fields": [
            {"name": "status", "number": 3, "type_name": "TestMultiseg",
             "label": "optional", "number_confirmed": True,
             "type_class": "ENUM:TestMultiseg"},
        ],
        "enums": {
            "TestMultiseg": {
                "values": _STATUS_VALUES,
                "values_confirmed": False,
                "values_truncated": False,
            },
        },
    },
}
