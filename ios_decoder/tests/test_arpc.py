"""ARPC adapter: header strip, decompression-failure + length-mismatch warnings."""

from ios_decoder import arpc
from ._arpc_fixtures import build_request, build_response, PROTOBUF_150


def test_strip_request_clean():
    body = build_request(function_id=60, payload=PROTOBUF_150)
    hdr, payload, warn = arpc.strip_request(body)
    assert hdr is not None and hdr.function_id == 60
    assert payload == PROTOBUF_150
    assert warn is None


def test_strip_request_not_arpc_returns_none():
    hdr, payload, warn = arpc.strip_request(b"\xff\xff not arpc")
    assert hdr is None and warn is None
    assert payload == b"\xff\xff not arpc"


def test_strip_request_length_mismatch_warns():
    # declare more bytes than are present -> must be flagged, not silent
    body = build_request(payload=PROTOBUF_150, declared_len=len(PROTOBUF_150) + 10)
    hdr, payload, warn = arpc.strip_request(body)
    assert hdr is not None
    assert warn is not None and "length mismatch" in warn


def test_strip_request_bad_lz4_warns():
    # v2 declares LZ4 but the payload isn't a valid bvx frame
    body = build_request(version=2, algo="LZ4", payload=b"not-a-bvx-frame")
    hdr, payload, warn = arpc.strip_request(body)
    assert hdr is not None and hdr.compression_algo == "LZ4"
    assert warn is not None and "decompression failed" in warn


def test_strip_response_clean():
    body = build_response(response_type=7, payload=PROTOBUF_150)
    hdr, payload, warn = arpc.strip_response(body)
    assert hdr is not None and hdr.response_type == 7
    assert payload == PROTOBUF_150 and warn is None


def test_strip_response_trailing_bytes_warns():
    # bytes after the declared payload are dropped — surface it (parity with strip_request)
    body = build_response(payload=PROTOBUF_150)
    hdr, payload, warn = arpc.strip_response(body + b"\x99\x99\x99")
    assert hdr is not None and payload == PROTOBUF_150
    assert warn is not None and "trailing" in warn


def test_format_headers_are_summaries():
    req = arpc.parse_request_header(build_request(app="com.apple.geod", function_id=3))
    assert "com.apple.geod" in arpc.format_request_header(req)
    assert "requestType=3" in arpc.format_request_header(req)
    resp = arpc.parse_response_header(build_response(response_type=3))
    assert "responseType=3" in arpc.format_response_header(resp)
