"""Ground truth for f25_enum_large_bias/testelb -- authored by hand in
fixture.m, not derived from any tool output.

    message TestBias {
      enum Kind {
        TEST_BIAS_ZERO = 0;  TEST_BIAS_ONE = 1;
        TEST_BIAS_TWO = 2;   TEST_BIAS_THREE = 3;
        TEST_BIAS_A = 50000; TEST_BIAS_B = 50001;
        TEST_BIAS_C = 50002; TEST_BIAS_D = 50003;
      }
      Kind kind = 3;
    }

Covers proto/enums.py's _leading_materialized_bias (an index bias too large for
`sub #imm12`, materialised with `mov w8,#-0xc350 ; add w8,w2,w8`). Differential
check: with that function disabled only 0..3 are recovered and the high cluster
(50000..50003) is lost entirely (see fixture.m for the disassembly).
"""

_KIND_VALUES = [
    (0,     "TEST_BIAS_ZERO"),
    (1,     "TEST_BIAS_ONE"),
    (2,     "TEST_BIAS_TWO"),
    (3,     "TEST_BIAS_THREE"),
    (50000, "TEST_BIAS_A"),
    (50001, "TEST_BIAS_B"),
    (50002, "TEST_BIAS_C"),
    (50003, "TEST_BIAS_D"),
]

EXPECTED = {
    "TestBias": {
        "fields": [
            {"name": "kind", "number": 3, "type_name": "TestBias",
             "label": "optional", "number_confirmed": True,
             "type_class": "ENUM:TestBias"},
        ],
        "enums": {
            "TestBias": {
                "values": _KIND_VALUES,
                "values_confirmed": False,
                "values_truncated": False,
            },
        },
    },
}
