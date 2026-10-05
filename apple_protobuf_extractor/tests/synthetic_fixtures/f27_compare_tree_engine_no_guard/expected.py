"""Ground truth for f27_compare_tree_engine_no_guard/testgr(_e) — authored by
hand in fixture.m, not derived from any tool output.

    message TestGrElemA { optional string value = 1; }
    message TestGrElemB { optional string label = 1; }

    message TestGrContainer {
      repeated TestGrElemA alphas = 5;
      repeated TestGrElemB betas  = 6;
    }
    message TestGrPlainCall {
      repeated TestGrElemA gammas = 5;
    }
    message TestGrForeignEngine {
      repeated TestGrElemA deltas = 5;
    }

TestGrContainer's element types are recoverable ONLY through the compare-chain
tier accepting a guard-less engine (call-site csel + independent dispatch check
+ the class's own ivar-offset variables).  TestGrPlainCall and
TestGrForeignEngine are the two NEGATIVES that must keep degrading to the
`bytes` fallback — each lacks exactly one of those signals (see fixture.m) —
even though every one of these classes really does contain a TestGrElemA:
the tool must not claim what it cannot confirm.
"""

EXPECTED = {
    "TestGrContainer": {
        "fields": [
            {"name": "alphas", "number": 5, "type_name": "TestGrElemA",
             "label": "repeated", "type_class": "TestGrElemA",
             "number_confirmed": True},
            {"name": "betas", "number": 6, "type_name": "TestGrElemB",
             "label": "repeated", "type_class": "TestGrElemB",
             "number_confirmed": True},
        ],
    },
    "TestGrPlainCall": {
        "fields": [
            {"name": "gammas", "number": 5, "type_name": "bytes",
             "label": "repeated", "number_confirmed": True},
        ],
    },
    "TestGrForeignEngine": {
        "fields": [
            {"name": "deltas", "number": 5, "type_name": "bytes",
             "label": "repeated", "number_confirmed": True},
        ],
    },
    "TestGrElemA": {
        "fields": [
            {"name": "value", "number": 1, "type_name": "string",
             "label": "optional", "number_confirmed": True},
        ],
    },
    "TestGrElemB": {
        "fields": [
            {"name": "label", "number": 1, "type_name": "string",
             "label": "optional", "number_confirmed": True},
        ],
    },
}
