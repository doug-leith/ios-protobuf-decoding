"""Ground truth for f17_repeated_adder_ivar_lever/testrail — authored by
hand in fixture.m, not derived from any tool output.

    message TestAdderElem { string value = 1; }

    message TestAdderContainer {
      repeated TestAdderElem items = 7;
    }

`items`' element type resolves correctly regardless of which of two
independent mechanisms is asked (see fixture.m's "HONESTY NOTE"): the
already-covered by-field-number dispatch path, AND (verified separately,
by calling _resolve_dispatch_context directly before writing this file)
the adder->ivar lever (_resolve_repeated_element_ivars), which returns
dispatch_ivars == {'_items': ('TestAdderElem', 7)} — its own internals
run and compute the correct binding for the first time in this suite,
even though the final reported field type happens to come from the
other (already-covered) path in this particular fixture.
"""

EXPECTED = {
    "TestAdderElem": {
        "fields": [
            {"name": "value", "number": 1, "type_name": "string",
             "label": "optional", "number_confirmed": True},
        ],
    },
    "TestAdderContainer": {
        "fields": [
            {"name": "items", "number": 7, "type_name": "TestAdderElem",
             "label": "repeated", "number_confirmed": True,
             "type_class": "TestAdderElem"},
        ],
    },
}
