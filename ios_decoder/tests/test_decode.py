"""Body dispatch: generic ARPC fallback never silently drops a detected payload."""

from ios_decoder.decode import decode_request_body, decode_response_body
from ios_decoder.endpoints import DecodeContext, EndpointTable
from ._arpc_fixtures import build_request, build_response, PROTOBUF_150


class _NoSchemas:
    def decode_with_coverage(self, *a):  # pragma: no cover - unused in these tests
        raise AssertionError("generic path should not touch schemas")


EMPTY_TABLE = EndpointTable([])
CTX = DecodeContext(schemas=_NoSchemas())


def test_arpc_request_without_rule_is_generic_decoded():
    body = build_request(app="com.apple.geod", payload=PROTOBUF_150)
    out = decode_request_body("https://x/y", body, EMPTY_TABLE, CTX)
    assert out is not None
    assert "apple arpc header" in out and "1: 150" in out


def test_arpc_payload_that_fails_is_reported_not_dropped():
    # valid ARPC header, but the inner bytes are not valid protobuf
    body = build_request(payload=b"\x0a")  # truncated length-delimited field
    out = decode_request_body("https://x/y", body, EMPTY_TABLE, CTX)
    assert out is not None                       # <- must NOT be None
    # the no-rule fallback shares endpoints.decode_arpc_or_raw, so the failure is
    # surfaced with the same "[undecodable: …]" note as the table-driven generic endpoints
    assert "[undecodable:" in out
    assert "apple arpc header" in out            # header still shown above the note


def test_non_protobuf_non_arpc_returns_none():
    out = decode_request_body("https://x/y", b"just some text, not protobuf at all",
                              EMPTY_TABLE, CTX)
    assert out is None


def test_labelled_content_type_vetoes_protobuf_sniff():
    # PNG magic happens to pass the protobuf sniff; the image/png label must veto it
    png = b"\x89PNG\r\n\x1a\n\x00\x01"
    assert decode_request_body("https://x/y", png, EMPTY_TABLE, CTX, "image/png") is None


def test_sniff_runs_when_content_type_absent_or_generic():
    # the same bytes, unlabelled or octet-stream, may still be sniff-decoded
    png = b"\x89PNG\r\n\x1a\n\x00\x01"
    assert decode_request_body("https://x/y", png, EMPTY_TABLE, CTX, "") is not None
    assert decode_request_body("https://x/y", png, EMPTY_TABLE, CTX,
                               "application/octet-stream") is not None


def test_sniff_decode_is_labelled_as_a_guess():
    # a sniff-only decode must carry a provenance note — it is NOT schema/ARPC-confirmed, and
    # the reader shouldn't mistake a coincidental wire-format match for a real decode
    png = b"\x89PNG\r\n\x1a\n\x00\x01"
    out = decode_request_body("https://x/y", png, EMPTY_TABLE, CTX, "")
    assert out is not None
    assert out.startswith("// note:") and "not schema- or ARPC-confirmed" in out


def test_empty_body_returns_none():
    assert decode_request_body("https://x/y", b"", EMPTY_TABLE, CTX) is None


def test_arpc_response_generic():
    body = build_response(response_type=1, payload=PROTOBUF_150)
    out = decode_response_body("https://x/y", body, EMPTY_TABLE, CTX)
    assert out is not None and "1: 150" in out
