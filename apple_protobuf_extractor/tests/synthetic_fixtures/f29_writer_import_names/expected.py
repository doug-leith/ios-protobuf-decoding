"""Ground truth for f29_writer_import_names/testwn -- authored by hand in fixture.m.

The int fields' encodings come only from the NAME of the ProtocolBuffer.framework writer
each one's writeTo: call imports (the writer's code is not in a standalone binary); the
ivar @encode says only int32/uint32/int64/uint64.  ``other`` is written through a helper
whose name shows no encoding, so its storage default is emitted and flagged.  ``num``
(NSNumber; the emitter writes it as bytes) and ``obj`` (bare id) name no wire type: flagged.
"""

_INT_NOTE = "integer encoding not confirmed"
_OPAQUE_NOTE = "names no wire type"


def _f(name, number, type_name, note=None):
    return {"name": name, "number": number, "type_name": type_name, "label": "optional",
            "number_confirmed": True, "note": note}


EXPECTED = {
    "TestWriterNames": {
        "fields": [
            _f("i32", 1, "int32"), _f("u32", 2, "uint32"),
            _f("s32", 3, "sint32"), _f("s64", 4, "sint64"),
            _f("f32", 5, "fixed32"), _f("sf32", 6, "sfixed32"),
            _f("f64", 7, "fixed64"), _f("sf64", 8, "sfixed64"),
            _f("i64", 9, "int64"), _f("u64", 10, "uint64"),
            _f("other", 11, "int32", _INT_NOTE),
            _f("num", 12, "NSNumber", _OPAQUE_NOTE),     # the emitter writes it as bytes
            _f("obj", 13, "bytes", _OPAQUE_NOTE),
        ],
    },
}
