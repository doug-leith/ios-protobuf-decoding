"""Ground truth for f12_repeated_metaclass_type/testrmt — authored by hand
in fixture.m, not derived from any tool output.

    message TestRepElem {
      string value = 1;
    }

    message TestRepContainer {
      repeated TestRepElem items = 6;
    }

TestRepContainer declares no readFrom: override, so the readFrom: dispatch
element-type resolver cannot contribute here — the only path that can
resolve `items`' element type to TestRepElem is the `+(Class)itemType`
metaclass method (proto/repeated.py Strategy 1,
_class_from_type_method_imp). Verified by disassembly (build_fixtures.sh /
gotcha 4): +itemType compiles to the documented classref-table load
(`adrp x8,<page>; ldr x0,[x8,#off]; b <thunk>`).
"""

EXPECTED = {
    "TestRepElem": {
        "fields": [
            {"name": "value", "number": 1, "type_name": "string",
             "label": "optional", "number_confirmed": True},
        ],
    },
    "TestRepContainer": {
        "fields": [
            {"name": "items", "number": 6, "type_name": "TestRepElem",
             "label": "repeated", "number_confirmed": True,
             "type_class": "TestRepElem"},
        ],
    },
}
