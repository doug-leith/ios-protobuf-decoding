"""Ground truth for f4_packed_repeated/testpr — authored by hand in
fixture.m, not derived from any tool output.

    message TestPackedList {
      repeated int32 values = 7 [packed = true];
    }

Apple's packed-repeated scalar storage is a C-array struct ivar shaped
`{?="list"^i"count"Q"size"Q}`. proto/protocore.py:_is_packed_list_enc
recognizes this SHAPE alone — no writeTo:/readFrom: disassembly needed for
the type or REPEATED label, unlike every other fixture in this suite. The
field NUMBER (7) still comes from the ordinary writeTo: CFG walk.
"""

EXPECTED = {
    "TestPackedList": {
        "fields": [
            {"name": "values", "number": 7, "type_name": "int32",
             "label": "repeated", "number_confirmed": True},
        ],
    },
}
