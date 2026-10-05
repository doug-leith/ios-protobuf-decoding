"""Pre-decode flow filters: User-Agent prefix + start/end time bounds.

Parity with the old addon: the UA filter is an anchored (start-of-string), case-insensitive
prefix match, and the time bounds drop flows outside [start, end] by request timestamp.
Tested against the extracted ``_flow_passes_filters`` predicate with lightweight fakes (no
mitmproxy / capture needed).
"""

import re
from types import SimpleNamespace

from ios_decoder.report import _content, _flow_passes_filters


def _http(ua="", ts=1000.0, url="https://x/y"):
    headers = {"user-agent": ua} if ua else {}
    return SimpleNamespace(request=SimpleNamespace(
        pretty_url=url, timestamp_start=ts, headers=headers))


def _tcp(sni="guzzoni.apple.com", port=443, ts=1000.0):
    sc = SimpleNamespace(sni=sni, peername=(sni, port), address=(sni, port))
    return SimpleNamespace(server_conn=sc,
                           client_conn=SimpleNamespace(timestamp_start=ts))


# --- user-agent prefix ---

def test_ua_prefix_matches_at_start():
    f = _http(ua="com.apple.geod/1 CFNetwork/1410")
    assert _flow_passes_filters(f, False, None, "com.apple.geod", None, None)


def test_ua_prefix_is_case_insensitive():
    f = _http(ua="LocationD/2643.0.16")
    assert _flow_passes_filters(f, False, None, "locationd", None, None)


def test_ua_prefix_rejects_midstring_match():
    # 'geod' appears, but not at the start → filtered out (prefix, not substring search)
    f = _http(ua="com.apple.geod/1")
    assert not _flow_passes_filters(f, False, None, "geod", None, None)


def test_ua_filter_drops_flow_with_no_user_agent():
    assert not _flow_passes_filters(_http(ua=""), False, None, "com.apple", None, None)


def test_no_ua_filter_passes_everything():
    assert _flow_passes_filters(_http(ua="whatever/1"), False, None, None, None, None)


# --- time bounds ---

def test_start_time_drops_earlier_flows():
    assert not _flow_passes_filters(_http(ts=500.0), False, None, None, 1000.0, None)
    assert _flow_passes_filters(_http(ts=1500.0), False, None, None, 1000.0, None)


def test_end_time_drops_later_flows():
    assert not _flow_passes_filters(_http(ts=1500.0), False, None, None, None, 1000.0)
    assert _flow_passes_filters(_http(ts=500.0), False, None, None, None, 1000.0)


def test_start_and_end_window():
    assert _flow_passes_filters(_http(ts=1000.0), False, None, None, 500.0, 1500.0)
    assert not _flow_passes_filters(_http(ts=2000.0), False, None, None, 500.0, 1500.0)


# --- TCP flows: no UA, URL matched against the endpoint ---

def test_tcp_skips_ua_filter():
    # a UA prefix is set, but a TCP (Siri) flow has no UA — it must NOT be dropped on that
    assert _flow_passes_filters(_tcp(), True, None, "com.apple", None, None)


def test_tcp_url_filter_matches_endpoint():
    f = _tcp(sni="guzzoni.apple.com")
    assert _flow_passes_filters(f, True, re.compile("guzzoni"), None, None, None)
    assert not _flow_passes_filters(f, True, re.compile("nomatch"), None, None, None)


def test_tcp_time_bounds_use_client_conn_timestamp():
    assert not _flow_passes_filters(_tcp(ts=400.0), True, None, None, 1000.0, None)
    assert _flow_passes_filters(_tcp(ts=1200.0), True, None, None, 1000.0, None)


# --- content-decoding fallback is reported, not silent ---

class _GoodMsg:
    content = b"plain body"


class _BadEncodingMsg:
    raw_content = b"\x1f\x8bgarbage"           # still-encoded bytes

    @property
    def content(self):                         # decoding the Content-Encoding raises
        raise ValueError("unknown content-encoding")


def test_content_decodes_normally():
    body, fell_back = _content(_GoodMsg())
    assert body == b"plain body" and fell_back is False


def test_content_falls_back_to_raw_and_flags_it():
    body, fell_back = _content(_BadEncodingMsg())
    assert body == b"\x1f\x8bgarbage" and fell_back is True   # caller turns this into a // note
