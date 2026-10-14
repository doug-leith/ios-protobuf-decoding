"""Ground truth for f16_enum_isolated_compares/testeic — authored by hand
in fixture.m, not derived from any tool output (except the enum type-name
string, the tool's own documented best-effort reconstruction from the
value-string common prefix — see proto/enums.py:_enum_name_from_pairs).

    message TestAsmEnum {
      enum TestStatus {
        TEST_STATUS_UNKNOWN = 0;   // cbz special case
        TEST_STATUS_ALPHA   = 1;   // isolated b.ne (fall-through string)
        TEST_STATUS_BETA    = 5;   // isolated b.eq (branch-to string)
      }
      TestStatus status = 3;
    }

statusAsString: is a plain C `switch` — REAL COMPILED CODE (gotcha 13: an
Xcode-8-frontend/modern-linker hybrid build, see fixture.m and
../README.md), not hand-assembly. Verified by disassembly before writing
this file: `cmp w2,#5;b.eq` (value 5) / `cmp w2,#1;b.eq` (value 1) /
`cbnz w2,<default>` (value 0, fall-through when zero) — no `csel`
anywhere. The value string lands in a callee-saved register (x19), not
x0 — see proto/enums.py's `_isolated_value_target`. All 3 values recover
(every value evaluated cleanly, so values_confirmed=True).
"""

_STATUS_VALUES = [
    (0, "TEST_STATUS_UNKNOWN"),
    (1, "TEST_STATUS_ALPHA"),
    (5, "TEST_STATUS_BETA"),
]

EXPECTED = {
    "TestAsmEnum": {
        "fields": [
            {"name": "status", "number": 3, "type_name": "TestStatus",
             "label": "optional", "number_confirmed": True,
             "type_class": "ENUM:TestStatus"},
        ],
        "enums": {
            "TestStatus": {
                "values": _STATUS_VALUES,
                "values_confirmed": True,
                "values_truncated": False,
            },
        },
    },
}
