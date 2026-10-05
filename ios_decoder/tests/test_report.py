"""report.run plumbing: the per-flow isolation guard and --decoded-only suppression.

These are load-bearing design promises — a single malformed body must not abort the whole
capture, and --decoded-only must hide flows that produced no decode — but were untested.
Exercised against the extracted ``_process_one_flow`` / ``_print_flow`` with lightweight
fakes (no mitmproxy / capture needed).
"""

from types import SimpleNamespace

from ios_decoder import report
from ios_decoder.report import _FlowOutput, _print_flow, _process_one_flow
from ios_decoder.endpoints import DecodeContext
from ios_decoder.bodies import BodyDisplayOptions


class _Schemas:
    def decode_with_coverage(self, *a):       # pragma: no cover
        raise AssertionError("unused")


def _ctx():
    return DecodeContext(schemas=_Schemas())


def _http_flow(url="https://example.com/x"):
    return SimpleNamespace(request=SimpleNamespace(
        pretty_url=url, method="POST", timestamp_start=1000.0,
        headers={}, query={}, content=b"", raw_content=b""), response=None)


# --- per-flow isolation guard -------------------------------------------------

def test_process_one_flow_isolates_http_failure(monkeypatch, capsys):
    monkeypatch.setattr(report, "_print_flow",
                        lambda *a, **k: (_ for _ in ()).throw(ValueError("bad body")))
    flow = _http_flow("https://api.example/oops")
    ok = _process_one_flow(flow, False, None, _ctx(), False, BodyDisplayOptions(), True)
    assert ok is False                        # error swallowed, treated as not-decoded
    err = capsys.readouterr().err
    assert "ERROR decoding flow https://api.example/oops" in err
    assert "ValueError: bad body" in err


def test_tcp_endpoint_handles_missing_server_conn():
    # used inside the per-flow error handler, so it must never raise on a malformed flow
    from ios_decoder.report import _tcp_endpoint
    assert _tcp_endpoint(SimpleNamespace(server_conn=None)) == "?:?"
    assert _tcp_endpoint(SimpleNamespace()) == "?:?"


def test_process_one_flow_isolates_tcp_failure(monkeypatch, capsys):
    monkeypatch.setattr(report, "_print_tcp_flow",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("tcp boom")))
    sc = SimpleNamespace(sni="guzzoni.apple.com", peername=("guzzoni.apple.com", 443),
                         address=None)
    flow = SimpleNamespace(server_conn=sc)
    ok = _process_one_flow(flow, True, None, _ctx(), False, BodyDisplayOptions(), True)
    assert ok is False
    assert "ERROR decoding flow guzzoni.apple.com:443" in capsys.readouterr().err


def test_process_one_flow_returns_print_result(monkeypatch):
    monkeypatch.setattr(report, "_print_flow", lambda *a, **k: True)
    assert _process_one_flow(_http_flow(), False, None, _ctx(), False,
                             BodyDisplayOptions(), True) is True
    monkeypatch.setattr(report, "_print_flow", lambda *a, **k: False)
    assert _process_one_flow(_http_flow(), False, None, _ctx(), False,
                             BodyDisplayOptions(), True) is False


# --- --decoded-only suppression ----------------------------------------------

def _undecoded():
    return _FlowOutput(geo_findings=[], req_out=None, res_out=None, req_ct="", res_ct="",
                       rbody=b"", sbody=b"", decoded_any=False, notes=[])


def test_decoded_only_suppresses_undecoded_flow(monkeypatch, capsys):
    monkeypatch.setattr(report, "_decode_flow", lambda *a: _undecoded())
    printed = _print_flow(_http_flow(), None, _ctx(), decoded_only=True,
                          body_opts=BodyDisplayOptions(), request_log=False)
    assert printed is False
    assert capsys.readouterr().out == ""      # nothing emitted under --decoded-only


def test_normal_mode_surfaces_undecoded_flow(monkeypatch, capsys):
    monkeypatch.setattr(report, "_decode_flow", lambda *a: _undecoded())
    printed = _print_flow(_http_flow("https://example.com/y"), None, _ctx(),
                          decoded_only=False, body_opts=BodyDisplayOptions(),
                          request_log=False)
    assert printed is False                   # nothing decoded, but...
    assert "https://example.com/y" in capsys.readouterr().out   # ...still surfaced
