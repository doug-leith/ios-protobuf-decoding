"""DNS-over-HTTPS decoding (application/dns-message bodies + ?dns= GET param)."""

import base64

import pytest

from ios_decoder import doh

dns = pytest.importorskip("dns.message", reason="dnspython not installed")
import dns.flags
import dns.rdatatype
import dns.message
import dns.rrset


def _query_wire(qname="example.com.", rdtype="A"):
    m = dns.message.make_query(qname, rdtype)
    m.id = 0
    return m.to_wire()


def _response_wire(qname="example.com.", ip="93.184.216.34"):
    q = dns.message.make_query(qname, "A")
    q.id = 0
    r = dns.message.make_response(q)
    r.answer.append(dns.rrset.from_text(qname, 300, "IN", "A", ip))
    r.flags |= dns.flags.RA
    return r.to_wire()


def test_decode_query():
    out = doh.decode_dns_message(_query_wire())
    assert out.startswith("DNS query (id 0)")
    assert "question: example.com. IN A" in out


def test_decode_response_with_answer():
    out = doh.decode_dns_message(_response_wire())
    assert out.startswith("DNS response (id 0, NOERROR)")
    assert "RA" in out                                   # recursion-available flag surfaced
    assert "question: example.com. IN A" in out
    assert "answers:" in out
    assert "example.com. 300 A 93.184.216.34" in out


def test_decode_cname_chain():
    q = dns.message.make_query("www.example.com.", "A")
    q.id = 0
    r = dns.message.make_response(q)
    r.answer.append(dns.rrset.from_text("www.example.com.", 60, "IN", "CNAME", "cdn.example.net."))
    r.answer.append(dns.rrset.from_text("cdn.example.net.", 60, "IN", "A", "1.2.3.4"))
    out = doh.decode_dns_message(r.to_wire())
    assert "CNAME cdn.example.net." in out and "A 1.2.3.4" in out


def test_doh_get_param():
    wire = _query_wire("gateway.icloud.com.", "A")
    param = base64.urlsafe_b64encode(wire).decode().rstrip("=")
    out = doh.doh_request_summary(f"https://8.8.8.8/dns-query?dns={param}")
    assert out is not None and "gateway.icloud.com." in out


def test_doh_get_param_absent_returns_none():
    assert doh.doh_request_summary("https://8.8.8.8/dns-query") is None
    assert doh.doh_request_summary("https://example.com/foo?bar=1") is None


def test_bad_body_reports_error_not_crash():
    out = doh.decode_dns_message(b"\x00\x01\x02not-dns")
    assert out.startswith("// ERROR: DNS decode failed")


def test_looks_like_dns_message():
    assert doh.looks_like_dns_message("application/dns-message")
    assert not doh.looks_like_dns_message("application/json")
