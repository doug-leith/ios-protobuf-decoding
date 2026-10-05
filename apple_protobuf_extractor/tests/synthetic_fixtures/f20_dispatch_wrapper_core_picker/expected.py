"""Ground truth for f20_dispatch_wrapper_core_picker/testdwp — authored by
hand in fixture.m, not derived from any tool output.

    message TestPickerElem { string value = 1; }

    message TestPickerContainer {
      repeated TestPickerElem children = 5;
    }

`children`'s element type can ONLY resolve to `TestPickerElem` if
proto/dispatch.py's thick-wrapper-vs-direct-core picker
(_core_resolves_compare_chain / _find_dispatch_core_via_wrapper) correctly
rejects the wrapper as a direct dispatcher and adopts the real
compare-chain core discovered via the wider wrapper scan instead --
confirmed directly (not just via the field's final type) by calling
_locate_dispatch_arms on the built binary before writing this file:
core_va comes back pointing exactly at the real compare-chain core's
address. See fixture.m's header for the full trace, including a real
decoder quirk found along the way (_find_field_count's raw-word scan
bleeding across the wrapper/core function boundary).
"""

EXPECTED = {
    "TestPickerElem": {
        "fields": [
            {"name": "value", "number": 1, "type_name": "string",
             "label": "optional", "number_confirmed": True},
        ],
    },
    "TestPickerContainer": {
        "fields": [
            {"name": "children", "number": 5, "type_name": "TestPickerElem",
             "label": "repeated", "number_confirmed": True,
             "type_class": "TestPickerElem"},
        ],
    },
}
