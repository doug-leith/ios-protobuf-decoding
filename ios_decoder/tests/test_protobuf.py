"""Core decode behaviour: named, partial-schema (unknown fields kept), and raw."""

import pytest

from google.protobuf import descriptor_pb2, descriptor_pool, message_factory

from ios_decoder.protobuf import decode_to_text, DecodeError


def test_raw_decode_no_schema():
    # field 1 varint=150, field 3 string "hello"
    data = bytes.fromhex("089601") + bytes.fromhex("1a0568656c6c6f")
    out = decode_to_text(data)
    assert "1: 150" in out
    assert '3: "hello"' in out


def test_raw_decode_recurses_nested_message():
    # field 4 = a nested message { field 1 varint = 7 }
    data = bytes.fromhex("22020807")
    out = decode_to_text(data)
    assert "4 {" in out
    assert "1: 7" in out


def test_invalid_wire_bytes_raise():
    # a lone tag for a length-delimited field with no length/body -> truncated
    with pytest.raises(DecodeError):
        decode_to_text(bytes.fromhex("0a"))


def test_empty_input_is_empty_output():
    assert decode_to_text(b"") == ""


def _msg_with_message_fields():
    """A message M { S s = 1; repeated S rs = 2; } with S { int32 x = 1; }."""
    fdp = descriptor_pb2.FileDescriptorProto(name="m.proto", syntax="proto2")
    s = fdp.message_type.add(name="S")
    s.field.add(name="x", number=1, label=1, type=5)            # optional int32
    m = fdp.message_type.add(name="M")
    m.field.add(name="s", number=1, label=1, type=11, type_name=".S")   # optional S
    m.field.add(name="rs", number=2, label=3, type=11, type_name=".S")  # repeated S
    pool = descriptor_pool.DescriptorPool(); pool.Add(fdp)
    return message_factory.GetMessageClass(pool.FindMessageTypeByName("M"))


def test_message_typed_known_field_with_nested_unknown():
    """The splice: known message fields (singular + repeated) render via text_format,
    and an unknown field nested *inside* a known message renders protoc-style."""
    M = _msg_with_message_fields()
    # s = { x:7, <unknown 9 varint=99> } ; rs = [{x:1},{x:2}]
    data = (bytes.fromhex("0a04") + bytes.fromhex("0807") + bytes.fromhex("4863")
            + bytes.fromhex("1202") + bytes.fromhex("0801")
            + bytes.fromhex("1202") + bytes.fromhex("0802"))
    out = decode_to_text(data, M)
    assert out == (
        "s {\n"
        "  x: 7\n"
        "  9: 99\n"
        "}\n"
        "rs {\n"
        "  x: 1\n"
        "}\n"
        "rs {\n"
        "  x: 2\n"
        "}"
    )


def test_nested_unknown_field_count_sees_unknowns_inside_known_submessages():
    from ios_decoder.protobuf import (nested_unknown_field_count, parse,
                                      unknown_field_numbers)
    M = _msg_with_message_fields()
    data = (bytes.fromhex("0a04") + bytes.fromhex("0807") + bytes.fromhex("4863")
            + bytes.fromhex("1202") + bytes.fromhex("0801")
            + bytes.fromhex("1202") + bytes.fromhex("0802"))
    msg = parse(data, M)
    assert unknown_field_numbers(msg) == []        # nothing unknown at the TOP level
    assert nested_unknown_field_count(msg) == 1     # field 9 hidden inside the known submessage s
