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

TestGrContainer's element types are recoverable only by following the guard-less
engine its readFrom: hands itself to (proto.dispatch_eval: the call handed self,
then each field number evaluated through the compare tree).

TestGrForeignEngine is the NEGATIVE that must keep degrading to the `bytes`
fallback: it hands itself to TestGrContainer's engine, whose handlers fill
TestGrContainer's ivars through TestGrContainer's ivar-offset variables -- the
dispatch is not this class's, so the tool must not claim it.

TestGrPlainCall was a negative too until 2026-10-15: the call-site-shape decoder
could not confirm its engine (a plain call with one table, no `csel`) and left
`gammas` as `bytes`.  Its engine is its own (handed self, fills its own ivar), so
the evaluator confirms the field's real type, the one declared above:
`repeated TestGrElemA gammas = 5` (fixture.m's "stays bytes" comments describe
the old decoder).
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
            {"name": "gammas", "number": 5, "type_name": "TestGrElemA",
             "label": "repeated", "type_class": "TestGrElemA",
             "number_confirmed": True},
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
