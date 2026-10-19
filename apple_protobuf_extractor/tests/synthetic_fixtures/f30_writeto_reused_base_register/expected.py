"""Ground truth for f30_writeto_reused_base_register/testrb (and its arm64e twin
testrb_e) -- authored by hand in fixture.m, not derived from any tool output.

    message TestReusedBase {
      repeated int64 values = 1;
      repeated bytes items = 2;
    }

`items` is an NSArray whose element class the binary does not show, so it is
`repeated bytes` (LIMITATIONS.md (7)).

Differential-checked (TODO #81 (2)): with the first-adrp+add base resolver
(d7e55516's _resolve_offset_addr) both numbers come out number_confirmed=False
(ivar order); with the nearest-definition base both are read from the binary.
"""

EXPECTED = {
    "TestReusedBase": {
        "fields": [
            {"name": "values", "number": 1, "type_name": "int64",
             "label": "repeated", "number_confirmed": True},
            {"name": "items", "number": 2, "type_name": "bytes",
             "label": "repeated", "number_confirmed": True},
        ],
    },
}
