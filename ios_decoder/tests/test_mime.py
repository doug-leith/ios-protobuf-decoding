"""Content-Type dispatch: json/form/text/gzip + protobuf single/array/gRPC framings."""

import gzip
import struct

from ios_decoder.mime import (
    decode_by_content_type,
    decode_protobuf_array,
    decode_protobuf_payload,
    decode_grpc,
)
from ._arpc_fixtures import PROTOBUF_150


def test_json_pretty_printed():
    out = decode_by_content_type(b'{"a":1,"b":[2,3]}', "application/json")
    assert out is not None and '"a": 1' in out


def test_form_urlencoded():
    out = decode_by_content_type(b"name=a%20b&x=1", "application/x-www-form-urlencoded")
    assert out == "name=a b&x=1"


def test_text_plain():
    assert decode_by_content_type(b"hello", "text/plain; charset=utf-8") == "hello"


def test_protobuf_single():
    out = decode_by_content_type(PROTOBUF_150, "application/x-protobuf")
    assert out is not None and "1: 150" in out


def test_protobuf_array_needs_two_elements():
    framed = (b"\x03" + PROTOBUF_150) * 2          # <len=3><msg> twice
    out = decode_protobuf_array(framed)
    assert out is not None and "[1]" in out and "[2]" in out
    # a single length-prefixed message must NOT be announced as an array
    assert decode_protobuf_array(b"\x03" + PROTOBUF_150) is None


def test_grpc_frame():
    frame = struct.pack("!B", 0) + struct.pack("!I", len(PROTOBUF_150)) + PROTOBUF_150
    out = decode_grpc(frame)
    assert out is not None and "1: 150" in out


def test_grpc_rejects_non_grpc():
    assert decode_grpc(b"not a grpc frame at all") is None


def test_inferred_array_framing_is_flagged():
    # single-message decode fails, so the array framing is inferred -> output says so
    framed = (b"\x03" + PROTOBUF_150) * 2
    out = decode_protobuf_payload(framed)
    assert out is not None and "[1]" in out
    assert "framing inferred by structural fit" in out


def test_single_message_payload_not_flagged_as_inferred():
    # a plain single message decodes directly — no inferred-framing note
    out = decode_protobuf_payload(PROTOBUF_150)
    assert out is not None and "1: 150" in out
    assert "inferred" not in out


def test_magic_override_notes_a_contradicting_content_type():
    # a zip body wrongly labelled application/json -> magic wins, but the disagreement is noted
    import io, zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("a.txt", "hi")
    out = decode_by_content_type(buf.getvalue(), "application/json")
    assert out is not None
    assert "dispatched by zip magic bytes" in out and "disagrees" in out


def test_magic_override_silent_when_content_type_generic():
    # generic octet-stream is not a contradiction -> no note
    import io, zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("a.txt", "hi")
    out = decode_by_content_type(buf.getvalue(), "application/octet-stream")
    assert out is not None and "dispatched by" not in out


def test_gzip_inner_protobuf():
    out = decode_by_content_type(gzip.compress(PROTOBUF_150), "application/gzip")
    assert out is not None and "gunzipped" in out and "1: 150" in out


def test_unknown_content_type_returns_none():
    assert decode_by_content_type(b"\x00\x01\x02binary", "image/png") is None


def test_empty_body_returns_none():
    assert decode_by_content_type(b"", "application/json") is None
