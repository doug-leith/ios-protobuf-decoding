"""Ground truth for f3_write_helper_family/testwt — authored by hand in
fixture.m, not derived from any tool output.

    message TestWireTypes {
      sint32   sVal32  = 1;
      sint64   sVal64  = 2;
      fixed32  fVal32  = 3;
      sfixed32 sfVal32 = 4;
      fixed64  fVal64  = 5;
      sfixed64 sfVal64 = 6;
    }

All six ivars decode to the same canonical @encode default (int32/uint32/
int64/uint64) — the true wire-type family can ONLY come from disassembling
the per-field write-helper each field's writeTo: call invokes
(proto/write_helpers.py:_classify_write_helper: sint32/64 zigzag `lsl
w|x1,#1`, fixed32/64 tag-build `mov w_,#5|#1; bfi w_,w2,#3,#0x1d`), with
signed vs unsigned ivar storage then picking sfixed vs fixed
(proto/extractor.py:_refine_int_wire_form). A tool that only read the ivar
@encode would get every one of these fields wrong (or at best "int32/
uint32/int64/uint64", never recovering zigzag or fixed-width semantics).
"""

EXPECTED = {
    "TestWireTypes": {
        "fields": [
            {"name": "sVal32",  "number": 1, "type_name": "sint32",
             "label": "optional", "number_confirmed": True},
            {"name": "sVal64",  "number": 2, "type_name": "sint64",
             "label": "optional", "number_confirmed": True},
            {"name": "fVal32",  "number": 3, "type_name": "fixed32",
             "label": "optional", "number_confirmed": True},
            {"name": "sfVal32", "number": 4, "type_name": "sfixed32",
             "label": "optional", "number_confirmed": True},
            {"name": "fVal64",  "number": 5, "type_name": "fixed64",
             "label": "optional", "number_confirmed": True},
            {"name": "sfVal64", "number": 6, "type_name": "sfixed64",
             "label": "optional", "number_confirmed": True},
        ],
    },
}
