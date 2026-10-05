"""Ground truth for f1_writeto_fieldnum/testmsg — authored by hand in
fixture.m, not derived from any tool output. Field numbers are deliberately
non-monotonic relative to ivar declaration order (first=5, second=2, third=9)
so a naive ivar-order fallback (1,2,3) would be caught immediately.

    message TestMessage {
      string first  = 5;
      string second = 2;
      string third  = 9;
    }
"""

EXPECTED = {
    "TestMessage": {
        "fields": [
            {"name": "first",  "number": 5, "type_name": "string",
             "label": "optional", "number_confirmed": True},
            {"name": "second", "number": 2, "type_name": "string",
             "label": "optional", "number_confirmed": True},
            {"name": "third",  "number": 9, "type_name": "string",
             "label": "optional", "number_confirmed": True},
        ],
    },
}
