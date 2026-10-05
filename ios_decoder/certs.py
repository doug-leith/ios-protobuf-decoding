"""X.509 certificate + OCSP-response decoding, via ``cryptography`` (no subprocess).

Replaces the old addon's three tangled paths — PEM certs shelled out to ``openssl x509``,
DER chains hand-walked into ``cryptography``, and OCSP dumped via a reflective
``dump_object`` — with one tidy module: PEM *and* DER chains through the same formatter,
and OCSP fields pulled out explicitly.  Pure: ``bytes`` in, readable ``str`` out.
"""

from __future__ import annotations

# `cryptography` is an OPTIONAL dependency (like dnspython for doh / cbor2 for archives):
# import it lazily so a host without it still loads the rest of the tool. Public entry points
# guard on _HAVE_CRYPTO and degrade to a clear note instead of crashing the whole CLI. (The
# annotations below are strings — `from __future__ import annotations` — so referencing x509
# in a signature is safe even when the import failed.)
try:
    from cryptography import x509
    from cryptography.x509 import ocsp
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    _HAVE_CRYPTO = True
except ImportError:                          # pragma: no cover - exercised only without the dep
    _HAVE_CRYPTO = False

__all__ = ["decode_certificates", "decode_ocsp", "looks_like_certificates",
           "try_decode_embedded_certificates"]

_NO_CRYPTO = "// not decoded: the 'cryptography' package is not installed"


def looks_like_certificates(data: bytes) -> bool:
    """True if ``data`` looks like PEM or DER X.509 certificate(s)."""
    return b"-----BEGIN CERTIFICATE-----" in data[:64] or data[:2] == b"\x30\x82"


def _load_chain(data: bytes) -> tuple[list[x509.Certificate], str | None]:
    """Load certificates from PEM or concatenated-DER bytes.

    Returns ``(chain, note)`` — ``note`` is a transparency line when the DER walk stopped
    before consuming the input (a malformed/truncated chain that would otherwise look
    complete), else ``None``."""
    if b"-----BEGIN CERTIFICATE-----" in data:
        return list(x509.load_pem_x509_certificates(data)), None
    certs, trailing = _split_der_chain(data)
    note = (f"// note: {trailing} trailing byte(s) after the last parsed certificate "
            f"(chain may be truncated or contain a malformed cert)") if trailing else None
    return certs, note


def _der_element_len(data: bytes, pos: int) -> int | None:
    """Total byte length (header + content) of the DER element at ``pos`` (a SEQUENCE)."""
    if pos + 2 > len(data):
        return None
    b = data[pos + 1]
    if b < 0x80:                       # short-form length
        return 2 + b
    n = b & 0x7F                       # long-form: n length-of-length bytes follow
    if pos + 2 + n > len(data):
        return None
    return 2 + n + int.from_bytes(data[pos + 2:pos + 2 + n], "big")


_MAX_INTERCERT_GAP = 32  # bytes of framing tolerated between chain entries (e.g. a
                          # TLS-style length prefix), before giving up on a next cert


def _split_der_chain(data: bytes) -> tuple[list[x509.Certificate], int]:
    """Split concatenated DER certificates by walking the ASN.1 SEQUENCE lengths.

    Certificates in a chain are usually back-to-back, but some framings (e.g. a
    TLS-style length-prefixed certificate list) insert a few non-DER bytes between
    entries — so after each cert, if the very next byte isn't a SEQUENCE tag, re-scan
    a short lookahead for the next ``30 82`` marker rather than stopping there. A
    match that doesn't parse as a valid certificate still ends the walk as before, so
    this can only recover more certs, never mis-parse.

    Returns ``(certs, trailing)`` — ``trailing`` is the count of unparsed bytes left after
    the last successfully-parsed certificate (>0 means the walk stopped early on a
    malformed/over-long element), so the caller can flag a possibly-truncated chain."""
    out: list[x509.Certificate] = []
    pos = data.find(b"\x30\x82")       # first SEQUENCE-with-2-byte-length (a cert)
    if pos < 0:
        return out, 0
    while pos < len(data) and data[pos] == 0x30:
        total = _der_element_len(data, pos)
        if total is None or pos + total > len(data):
            break
        try:
            out.append(x509.load_der_x509_certificate(data[pos:pos + total]))
        except ValueError:
            break
        pos += total
        if pos < len(data) and data[pos] != 0x30:
            next_pos = data.find(b"\x30\x82", pos, pos + _MAX_INTERCERT_GAP)
            if next_pos < 0:
                break
            pos = next_pos
    return out, (len(data) - pos if out else 0)


def _oid_name(oid) -> str:
    return getattr(oid, "_name", None) or oid.dotted_string


def _format_cert(cert: x509.Certificate, idx: int) -> str:
    lines = [f"Certificate {idx + 1}:",
             f"  subject:  {cert.subject.rfc4514_string()}",
             f"  issuer:   {cert.issuer.rfc4514_string()}",
             f"  serial:   {cert.serial_number:x}",
             f"  validity: {cert.not_valid_before_utc} .. {cert.not_valid_after_utc}",
             f"  sig alg:  {_oid_name(cert.signature_algorithm_oid)}",
             f"  pubkey:   {type(cert.public_key()).__name__.lstrip('_')}"]
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        names = san.value.get_values_for_type(x509.DNSName)
        if names:
            lines.append(f"  SAN:      {', '.join(names)}")
    except x509.ExtensionNotFound:
        pass
    return "\n".join(lines)


def decode_certificates(data: bytes) -> str:
    """Decode PEM or DER X.509 certificate(s) to a readable per-cert summary."""
    if not _HAVE_CRYPTO:
        return f"{_NO_CRYPTO} ({len(data)} bytes of X.509 certificate data)"
    try:
        chain, note = _load_chain(data)
    except Exception as e:             # cryptography raises various ValueError subclasses
        return f"// ERROR: certificate decode failed: {type(e).__name__}: {e}"
    if not chain:
        return f"// no X.509 certificates found ({len(data)} bytes)"
    body = "\n".join(_format_cert(c, i) for i, c in enumerate(chain))
    return (note + "\n" + body) if note else body


def try_decode_embedded_certificates(data: bytes) -> str | None:
    """Find and decode an X.509 chain embedded anywhere in ``data``, or ``None``.

    Unlike :func:`decode_certificates` (report a "no certificates found" note when the
    buffer isn't one), this is for callers deciding *whether* to treat some otherwise-
    unrecognized bytes as certificate data — e.g. a wrapper/envelope format that carries a
    raw DER chain after a few header bytes we don't understand (``_split_der_chain``
    already scans for the first SEQUENCE marker at any offset, so this works without
    knowing the wrapper). Returns ``None`` unless a real certificate was actually parsed —
    a content check (decoding either succeeds or it doesn't), not a byte-shape guess, so
    it can't mislabel non-certificate data the way a heuristic can.
    """
    if not _HAVE_CRYPTO:
        return None
    try:
        chain, note = _load_chain(data)
    except Exception:
        return None
    if not chain:
        return None
    body = "\n".join(_format_cert(c, i) for i, c in enumerate(chain))
    return (note + "\n" + body) if note else body


def _ocsp_issuer_ca(resp) -> str | None:
    """Readable name of the CA whose certificate is being checked, or ``None``.

    On the wire OCSP names the issuer only by hash (``issuer_key_hash`` /
    ``issuer_name_hash``), but the response usually embeds the responder's cert
    chain.  The responder is a delegate *issued by* that same CA, so the responder
    cert's issuer DN names the CA.  Cautious: returns ``None`` unless we can pick the
    responder cert with confidence (OCSP-signing EKU, else the chain leaf), so we
    never label the check with the wrong CA.  (The app's own bundle id is NOT present
    in OCSP — it identifies a certificate by issuer-hash + serial only.)
    """
    certs = list(resp.certificates)
    if not certs:
        return None
    signers = [c for c in certs if _is_ocsp_signer(c)]
    inferred = False
    if not signers:                              # fall back to the chain leaf (weaker signal)
        inferred = True
        issuers = {c.issuer for c in certs}
        signers = [c for c in certs if c.subject not in issuers]
    if len(signers) != 1:                        # ambiguous — stay silent
        return None
    cn = signers[0].issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
    name = cn[0].value if cn else signers[0].issuer.rfc4514_string()
    # tag the weaker provenance: a chain-leaf guess vs a confident OCSP-signing-EKU match
    return f"{name} (inferred from chain leaf)" if inferred else name


def _is_ocsp_signer(cert: x509.Certificate) -> bool:
    try:
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
    except x509.ExtensionNotFound:
        return False
    return ExtendedKeyUsageOID.OCSP_SIGNING in eku.value


def decode_ocsp(data: bytes) -> str:
    """Decode a DER OCSP response to its status + revocation fields."""
    if not _HAVE_CRYPTO:
        return f"{_NO_CRYPTO} ({len(data)} bytes of OCSP response data)"
    try:
        resp = ocsp.load_der_ocsp_response(data)
    except Exception as e:
        return f"// ERROR: OCSP decode failed: {type(e).__name__}: {e}"
    lines = [f"OCSP response status: {resp.response_status.name}"]
    if resp.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
        return "\n".join(lines)
    issuer_ca = _ocsp_issuer_ca(resp)
    if issuer_ca:
        lines.append(f"  issuer CA:    {issuer_ca}")
    lines += [
        f"  cert serial:  {resp.serial_number:x}",
        f"  cert status:  {resp.certificate_status.name}",
        f"  this update:  {resp.this_update_utc}",
        f"  next update:  {resp.next_update_utc}",
    ]
    if resp.certificate_status == ocsp.OCSPCertStatus.REVOKED:
        lines.append(f"  revoked at:   {resp.revocation_time_utc}")
        if resp.revocation_reason is not None:
            lines.append(f"  reason:       {resp.revocation_reason.name}")
    return "\n".join(lines)
