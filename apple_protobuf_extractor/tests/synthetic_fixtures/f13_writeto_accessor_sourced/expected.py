"""Ground truth for f13_writeto_accessor_sourced/testgac — authored by hand
in fixture.m, not derived from any tool output.

    message TestGetterElem {
      string value = 1;
    }

    message TestGetterContainer {
      TestGetterElem context = 9;
    }

`context` is written in writeTo: via `self.context` (a property getter
call through objc_msgSend), not a direct `_context` ivar load — the only
path that can bind this write back to the `_context` ivar (and so confirm
its field number) is proto/writeto.py's accessor-sourced tier
(_build_accessor_ivar_map + _trace_accessor_sourced_value +
_selector_stub_name + _getter_loads_offset). Confirmed by instrumenting
bind_write directly before writing this file: the `context` field
resolves with status exactly 'ok-accessor'.
"""

EXPECTED = {
    "TestGetterElem": {
        "fields": [
            {"name": "value", "number": 1, "type_name": "string",
             "label": "optional", "number_confirmed": True},
        ],
    },
    "TestGetterContainer": {
        "fields": [
            {"name": "context", "number": 9, "type_name": "TestGetterElem",
             "label": "optional", "number_confirmed": True,
             "type_class": "TestGetterElem"},
        ],
    },
}
