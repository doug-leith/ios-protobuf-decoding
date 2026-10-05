"""Recursive nested decoder: container parse, cautious expansion, identifier extraction."""

import base64
import gzip
import json

from ios_decoder import nested


def _pb_binary():
    # field1 varint=150, field2 fixed64, field3 varint=300 — mostly non-printable => protobuf
    return bytes.fromhex("089601") + b"\x11" + b"\xaa" * 8 + bytes.fromhex("18ac02")


def test_parse_container_json_and_plist():
    assert nested.parse_container(b'{"a":1}', "application/json")[0] == "json"
    pl = b'<?xml version="1.0"?><!DOCTYPE plist><plist><dict></dict></plist>'
    assert nested.parse_container(pl, "application/x-apple-plist")[0] == "plist"
    assert nested.parse_container(b"not a container", "") is None


def test_render_plain_json():
    out = nested.render({"a": 1, "b": [True, None], "c": "hi"})
    assert "a: 1" in out and "b: [" in out and "true" in out and "null" in out
    assert 'c: "hi"' in out


def test_base64_protobuf_is_expanded():
    blob = base64.b64encode(_pb_binary()).decode()
    out = nested.render({"metadata": blob})
    assert "<base64 → protobuf?>" in out      # "?" flags the structural (unverified) match
    assert "1: 150" in out and "3: 300" in out


def test_json_in_string_is_expanded():
    out = nested.render({"adResult": json.dumps({"impressionId": "abc", "n": 1})})
    assert "<json>" in out
    assert 'impressionId: "abc"' in out


def test_cautious_opaque_base64_stays_a_string():
    # 16 bytes that are neither text nor valid protobuf (leading field-0 tag) => not expanded
    opaque = base64.b64encode(b"\x07\x91\x83\xf2\x44\x9c\x0e\xd5" * 2).decode()
    out = nested.render({"token": opaque})
    assert "<base64" not in out          # left as-is, not guessed
    assert opaque in out                  # original string preserved


def test_gzip_json_blob_expands_with_chain_label():
    inner = gzip.compress(b'{"x": 5}')
    out = nested.render({"d": inner})     # bytes leaf (e.g. plist <data>)
    assert "<gzip → json>" in out and "x: 5" in out


def test_clean_text_base64_is_text_not_protobuf():
    blob = base64.b64encode(b"this is just readable ascii text").decode()
    out = nested.render({"v": blob})
    assert "<base64 → utf8>" in out
    assert "readable ascii text" in out


def test_extract_identifiers_including_json_in_string():
    tree = {
        "events": [{"eventType": "click", "dsId": "D1", "clientId": "C1", "count": 7}],
        "ad": {"meta": {"adResult": json.dumps({"impressionId": "I1", "name": "x"})}},
    }
    found = {k: v for _, k, v in nested.extract_identifiers(tree)}
    assert found["dsId"] == "D1" and found["clientId"] == "C1"
    assert found["impressionId"] == "I1"   # descended into the JSON-in-string
    assert "count" not in found and "name" not in found


def test_is_identifier_key_patterns():
    for k in ["dsId", "clientEventId", "impressionId", "cppIds", "guid", "userNs"]:
        assert nested.is_identifier_key(k)
    for k in ["eventType", "count", "name", "postTime"]:
        assert not nested.is_identifier_key(k)
