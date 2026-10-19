"""Ground truth for f21_enum_long_body_extent/testlbe — authored by hand in
fixture.m, not derived from any tool output.

    message TestLongBodyEnum {
      enum Mode {
        TEST_LONG_MODE_ALPHA = 0;
        TEST_LONG_MODE_BRAVO = 1;
        TEST_LONG_MODE_CHARLIE = 2;
      }
      Mode mode = 3;
    }

This fixture proves _extract_jumptable_enum_values' TODO #58 extent-recompute
fallback (a >1000-insn xAsString: body forces _function_body_extent instead
of trusting the cheap 1000-insn probe): disasm(ctx, imp, max_insns=1000)
confirms truncated at exactly 1000 insns, and the recompute finds the real
~1200-insn extent closing on `ret`. The padding is REAL COMPILED CODE (400
plain `pad_sink += 1;` statements on a local `volatile int32_t`, see
fixture.m) — not hand-asm; see fixture.m's header for a real footgun found
replacing the original NOP-hand-asm padding with code: a GLOBAL padding
variable collides with the switch's own pointer-table base register and
silently breaks the fixture, a local stack variable doesn't.

FOUND, NOT DESIGNED, while verifying this fixture: the recomputed body's real
shape is f11's PROVEN POINTER-TABLE idiom (`ldr x0,[x8,w2,sxtw #3]`), not a
jump-table/segment idiom, so _extract_jumptable_enum_values' three original
harvesters (_harvest_jumptable_segments, _harvest_isolated_compares,
_harvest_cbz_value0) came back with nothing -- none of them read a pointer
table, and that read logic lived only in the SEPARATE _extract_enum_values
function's 80-insn primary probe, which never got a second look at the
longer, recomputed body. A real production gap, not a fixture artifact:
_try_pointer_table_in was added to close it -- it reuses the exact same
_decode_ldr_reg_off-based pointer-table read _harvest_dictrep already
uses elsewhere in this file, anchored on the recomputed insns/words instead
of a fresh short probe, with _find_field_count/_find_index_bias re-anchored
near the LOCATED load (not `imp`) since the load can be thousands of
instructions past the function start -- exactly this fixture's shape.

Verified end-to-end (not just the isolated function) before writing this
file: extract_all on the built binary now reports field `mode` as
ENUM:TestLongMode (the enum-name derivation upgrades from the field-name
fallback to the value-string-derived name once real values exist, matching
every other working fixture) with the full 3-value table recovered and
values_confirmed=True: _try_pointer_table_in cross-checks
len(pairs)==max_val (max_val from the re-anchored _find_field_count) exactly
like _extract_enum_values' own primary-path return does -- all 3 entries
here matched, so confirmed is True, not a hardcoded value.
"""

_MODE_VALUES = [
    (0, "TEST_LONG_MODE_ALPHA"),
    (1, "TEST_LONG_MODE_BRAVO"),
    (2, "TEST_LONG_MODE_CHARLIE"),
]

EXPECTED = {
    "TestLongBodyEnum": {
        "fields": [
            {"name": "mode", "number": 3, "type_name": "TestLongMode",
             "label": "optional", "number_confirmed": True,
             "type_class": "ENUM:TestLongMode"},
        ],
        "enums": {
            "TestLongMode": {
                "values": _MODE_VALUES,
                "values_confirmed": True,
                "values_truncated": False,
            },
        },
    },
}
