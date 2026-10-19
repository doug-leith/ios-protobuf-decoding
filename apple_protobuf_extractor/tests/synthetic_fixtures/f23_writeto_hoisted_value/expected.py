"""Ground truth for f23_writeto_hoisted_value/testhoist — authored by hand in
fixture.m, not derived from any tool output.

    message TestHoistContainer {
      double a = 1;
      double b = 2;
    }

Covers proto/writeto.py's _trace_hoisted_self_value ("S1" hoisted value
load), previously ZERO synthetic coverage (confirmed by a corpus trace
before writing this fixture: 6 real hits, including CoreLocationProtobuf's
CLPPressure.writeTo:, which this fixture's shape is modeled on directly --
see fixture.m's header).

Differential-verified this fixture actually depends on the function under
test: monkeypatching _trace_hoisted_self_value to always return None
leaves field `a`'s NUMBER unchanged (1) but flips number_confirmed to
False -- the ivar binding is lost even though the literal field-number
immediate is still readable, exactly what the function exists to recover.
Re-verified on the 2026-10-19 rebuild, which writes to the real writer
(see fixture.m's header).
"""

EXPECTED = {
    "TestHoistContainer": {
        "fields": [
            {"name": "a", "number": 1, "type_name": "double",
             "label": "optional", "number_confirmed": True},
            {"name": "b", "number": 2, "type_name": "double",
             "label": "optional", "number_confirmed": True},
        ],
    },
}
