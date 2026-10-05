"""DNS-over-HTTPS (RFC 8484) decoding — ``application/dns-message`` bodies + ``?dns=`` GET.

Captures carry a lot of DoH traffic (to ``8.8.8.8/dns-query`` etc.): the question rides
either a POST body (``application/dns-message``) or a GET ``?dns=`` base64url parameter, and
the answer always comes back as an ``application/dns-message`` body.  We decode the wire
format with ``dnspython`` (handles name compression, EDNS, and modern record types like
HTTPS/SVCB that a hand-rolled parser would get wrong), and render a compact summary showing
the question and the resolved records — i.e. which domains the device looked up.

(The module is named ``doh`` rather than ``dns`` so it can't shadow the dnspython ``dns``
package.)  ``dnspython`` is imported lazily, so the rest of the tool runs without it; if it's
absent the decoders return a clear one-line note (cautious degradation) rather than failing.
"""

from __future__ import annotations

import base64
import urllib.parse
from typing import Optional

__all__ = ["decode_dns_message", "doh_request_summary", "looks_like_dns_message"]


def looks_like_dns_message(content_type: str) -> bool:
    return "dns-message" in (content_type or "").lower()


def decode_dns_message(body: bytes) -> str:
    """Decode an ``application/dns-message`` body (query or response) to a summary."""
    mod = _dns()
    if mod is None:
        return "// DNS not decoded: dnspython not installed (pip install dnspython)"
    try:
        msg = mod.message.from_wire(body)
    except Exception as e:                       # dnspython raises various dns.exception types
        return f"// ERROR: DNS decode failed: {type(e).__name__}: {e}"
    return _format_message(msg, mod)


def doh_request_summary(url: str) -> Optional[str]:
    """If ``url`` is a DoH GET (``?dns=<base64url>``), decode the carried query; else None.

    POST DoH requests carry the query in the body (handled by :func:`decode_dns_message` via
    the Content-Type); this covers the GET form, whose body is empty.
    """
    query = urllib.parse.urlparse(url).query
    param = urllib.parse.parse_qs(query).get("dns", [None])[0]
    if not param:
        return None
    try:
        raw = base64.urlsafe_b64decode(param + "=" * (-len(param) % 4))
    except Exception:
        return None
    return decode_dns_message(raw)


# --- rendering ---------------------------------------------------------------

def _format_message(msg, mod) -> str:
    is_response = bool(msg.flags & mod.flags.QR)
    header = "DNS response" if is_response else "DNS query"
    bits = [name for name, on in (
        ("AA", msg.flags & mod.flags.AA), ("TC", msg.flags & mod.flags.TC),
        ("RD", msg.flags & mod.flags.RD), ("RA", msg.flags & mod.flags.RA)) if on]
    extra = f", {mod.rcode.to_text(msg.rcode())}" if is_response else ""
    flagstr = f" [{' '.join(bits)}]" if bits else ""
    lines = [f"{header} (id {msg.id}{extra}){flagstr}"]

    for r in msg.question:
        lines.append(f"  question: {r.name.to_text()} "
                     f"{mod.rdataclass.to_text(r.rdclass)} {mod.rdatatype.to_text(r.rdtype)}")
    lines += _section("answers", msg.answer, mod)
    lines += _section("authority", msg.authority, mod)
    lines += _section("additional", msg.additional, mod)
    return "\n".join(lines)


def _section(label: str, rrsets, mod) -> list[str]:
    out: list[str] = []
    for rrset in rrsets:
        for rdata in rrset:
            out.append(f"    {rrset.name.to_text()} {rrset.ttl} "
                       f"{mod.rdatatype.to_text(rrset.rdtype)} {rdata.to_text()}")
    if out:
        out.insert(0, f"  {label}:")
    return out


# --- lazy dependency ---------------------------------------------------------

_dns_mod = None


def _dns():
    """Import dnspython lazily; return the ``dns`` package or None if unavailable."""
    global _dns_mod
    if _dns_mod is None:
        try:
            import dns.message, dns.flags, dns.rcode, dns.rdatatype, dns.rdataclass
            _dns_mod = dns
        except ImportError:
            _dns_mod = False
    return _dns_mod or None
