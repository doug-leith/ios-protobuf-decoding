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
fixture.m's header). The element is an inline C struct, not an NSMutableArray
one. Until 2026-10-06 its type degraded to `bytes`; proto/structfields.py
(to-do #37) now recovers it as a message from the struct's @encode and its
serialiser in writeTo: -- number 1 and int32 match the hand-authored `int32 a
= 1` above. The member NAME `a` is not recoverable here (the @encode names no
members and the fixture has no _dictionaryRepresentation:), so it is emitted
as the flagged placeholder `field1`.

Differential-verified this fixture actually depends on the function under
test, not just incidentally passes: monkeypatching _forward_self_load_off
to always return None changes the recovered output to
`{itemsCount: 1 (confirmed), items: 2 (estimated)}` -- the exact
count-vs-array mis-binding the function's own docstring (Issue B)
describes. With it enabled, `items` binds correctly to field 1, confirmed.

Since 2026-10-19 (TODO #85) the walk is replaced by proto.writer_flow: the
begin mark binds the ivar the values written inside the marks derive from,
and those derive from `_items` alone (the count only bounds the loop).
"""

EXPECTED = {
    "TestForwardContainer": {
        "fields": [
            {"name": "items", "number": 1, "type_name": "TestForwardElem",
             "label": "repeated", "number_confirmed": True},
        ],
    },
    "TestForwardElem": {
        "fields": [
            {"name": "field1", "number": 1, "type_name": "int32",
             "label": "optional", "number_confirmed": True},
        ],
    },
}
