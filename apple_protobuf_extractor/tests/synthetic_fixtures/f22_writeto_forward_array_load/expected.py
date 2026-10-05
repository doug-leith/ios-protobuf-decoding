"""Ground truth for f22_writeto_forward_array_load/testfwd — authored by hand
in fixture.m, not derived from any tool output.

    message TestForwardContainer {
      message TestForwardElem {
        int32 a = 1;
      }
      repeated TestForwardElem items = 1;
    }

Covers proto/writeto.py's _forward_self_load_off, previously ZERO synthetic
coverage (confirmed by a corpus trace before writing this fixture: see
fixture.m's header). The element type degrades to `bytes` (an inline
C-array-of-structs field, not an NSMutableArray one -- protocore.py's
packed-list-shape detector only names scalar element types); that
degradation is a separate, already-accepted limitation and not what this
fixture is checking.

Differential-verified this fixture actually depends on the function under
test, not just incidentally passes: monkeypatching _forward_self_load_off
to always return None changes the recovered output to
`{itemsCount: 1 (confirmed), items: 2 (estimated)}` -- the exact
count-vs-array mis-binding the function's own docstring (Issue B)
describes. With it enabled, `items` binds correctly to field 1, confirmed.
"""

EXPECTED = {
    "TestForwardContainer": {
        "fields": [
            {"name": "items", "number": 1, "type_name": "bytes",
             "label": "repeated", "number_confirmed": True},
        ],
    },
}
