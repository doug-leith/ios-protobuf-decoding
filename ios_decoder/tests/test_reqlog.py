"""+++REQUEST / +++REQHEADERS line generation, hashing, and content sizing."""

from ios_decoder import reqlog


def test_content_sum_headers_plus_body():
    headers = [("a", "12345"), ("b", "x")]
    assert reqlog.content_sum(headers, b"hello") == 5 + 1 + 5


def test_hash_long_string():
    assert reqlog.hash_long_string("short") == "short"
    long = "x" * 200
    out = reqlog.hash_long_string(long)
    assert out.startswith("sha256#") and len(out) == len("sha256#") + 64


def test_request_log_emits_two_markers():
    headers = [("User-Agent", "geod/1"), ("Host", "x")]
    ms = reqlog.request_log("https://x/y", headers, b"body", 1780000000.5, "geod/1")
    assert len(ms) == 2
    req, hdr = ms[0].line(), ms[1].line()
    assert req == "+++REQUEST https://x/y 11 1780000000.5"   # 6(UA)+1(Host)+4(body)=11
    assert hdr.startswith("+++REQHEADERS https://x/y € User-Agent='geod/1' € ")


def test_header_summary_surfaces_interesting_and_splits_cookies():
    headers = [("authorization", "secret-token"),
               ("cookie", "a=1 b=2"),
               ("Accept", "*/*")]
    hdr = reqlog.request_log("https://x/y", headers, b"", 1.0)[1].line()
    assert "authorization=secret-token~" in hdr
    assert "cookie=a=1~" in hdr and "cookie=b=2~" in hdr
    assert "Accept=*/*~" in hdr


def test_long_header_value_is_hashed():
    headers = [("x-apple-baa-signature", "S" * 300)]
    hdr = reqlog.request_log("https://x/y", headers, b"", 1.0)[1].line()
    assert "x-apple-baa-signature=sha256#" in hdr
    assert "S" * 300 not in hdr
