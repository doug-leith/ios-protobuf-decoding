"""Ground truth for f25_newer_dispatch_engine/testnde — authored by hand in
fixture.m/helpers.m, not derived from any tool output.

    message TestNtElemA { optional string value = 1; }
    message TestNtElemB { optional string label = 1; }
    message TestNtContainer {
      repeated TestNtElemA alphas = 5;
      repeated TestNtElemB betas  = 6;
    }

The container's element types are recoverable ONLY through the newer-toolchain
path: its readFrom: is a thin wrapper whose engine call selects a data table
by `csel`, the engine holds two jump tables sharing one table-base register,
and neither repeated-field arm calls an own-class accessor or `bl`s a per-class
ReadAllFrom core — each loads the element class's classref and calls the
generic helpers in helpers.m instead. With any of the three mechanisms
missing (table-base reaching-definition, classref fallback / ownership gate)
both fields degrade to the `bytes` fallback.

Internal ground truth for the same binary (the engine's cluster shape, the
short guard function's lack of one) is checked by
tests/test_newer_toolchain_fixtures.py.
"""

EXPECTED = {
    "TestNtContainer": {
        "fields": [
            {"name": "alphas", "number": 5, "type_name": "TestNtElemA",
             "label": "repeated", "type_class": "TestNtElemA",
             "number_confirmed": True},
            {"name": "betas", "number": 6, "type_name": "TestNtElemB",
             "label": "repeated", "type_class": "TestNtElemB",
             "number_confirmed": True},
        ],
    },
    "TestNtElemA": {
        "fields": [
            {"name": "value", "number": 1, "type_name": "string",
             "label": "optional", "number_confirmed": True},
        ],
    },
    "TestNtElemB": {
        "fields": [
            {"name": "label", "number": 1, "type_name": "string",
             "label": "optional", "number_confirmed": True},
        ],
    },
}
