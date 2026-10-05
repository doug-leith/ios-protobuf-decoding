"""Certificate (PEM + DER chain) and OCSP decoding."""

import datetime

import pytest

from cryptography import x509
from cryptography.x509 import ocsp
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from ios_decoder import certs


@pytest.fixture(scope="module")
def two_certs():
    """A small self-signed cert chain (two distinct certs) to decode."""
    out = []
    for cn in ("leaf.example.com", "Issuing CA"):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
        not_before = datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc)
        builder = (x509.CertificateBuilder()
                   .subject_name(name).issuer_name(name)
                   .public_key(key.public_key()).serial_number(0xABCDEF)
                   .not_valid_before(not_before)
                   .not_valid_after(not_before + datetime.timedelta(days=365)))
        if cn.startswith("leaf"):
            builder = builder.add_extension(
                x509.SubjectAlternativeName([x509.DNSName("leaf.example.com")]), critical=False)
        out.append(builder.sign(key, hashes.SHA256()))
    return out


def test_decode_pem_chain(two_certs):
    pem = b"".join(c.public_bytes(serialization.Encoding.PEM) for c in two_certs)
    out = certs.decode_certificates(pem)
    assert "Certificate 1:" in out and "Certificate 2:" in out
    assert "CN=leaf.example.com" in out
    assert "serial:   abcdef" in out
    assert "SAN:      leaf.example.com" in out


def test_decode_der_chain(two_certs):
    der = b"".join(c.public_bytes(serialization.Encoding.DER) for c in two_certs)
    out = certs.decode_certificates(der)
    assert "Certificate 1:" in out and "Certificate 2:" in out
    assert "CN=Issuing CA" in out
    assert "trailing byte" not in out          # a clean chain carries no truncation note


def test_decode_der_chain_trailing_bytes_noted(two_certs):
    der = b"".join(c.public_bytes(serialization.Encoding.DER) for c in two_certs)
    out = certs.decode_certificates(der + b"\x00\x01\x02\x03")   # junk after the last cert
    assert "Certificate 1:" in out and "Certificate 2:" in out
    assert "trailing byte(s) after the last parsed certificate" in out


def test_decode_der_chain_with_intercert_framing(two_certs):
    # some framings (e.g. a TLS-style length-prefixed certificate list) insert a few
    # non-DER bytes between chain entries; the walk should still find the next cert.
    c1, c2 = (c.public_bytes(serialization.Encoding.DER) for c in two_certs)
    out = certs.decode_certificates(c1 + b"\x00\x00\x00\x00\x00" + c2)
    assert "Certificate 1:" in out and "Certificate 2:" in out
    assert "CN=Issuing CA" in out
    assert "trailing byte" not in out

    # a gap too large to be plausible framing should not be bridged
    out = certs.decode_certificates(c1 + b"\x00" * 33 + c2)
    assert "Certificate 2:" not in out
    assert "trailing byte(s) after the last parsed certificate" in out


def test_degrades_gracefully_without_cryptography(monkeypatch):
    # cryptography is an OPTIONAL dep — without it the module must still load and return a
    # clear note, not crash the whole CLI (it's imported transitively via mime/report)
    monkeypatch.setattr(certs, "_HAVE_CRYPTO", False)
    assert "not installed" in certs.decode_certificates(b"\x30\x82\x00\x00")
    assert "not installed" in certs.decode_ocsp(b"\x30\x03\x0a\x01\x00")


def test_decode_certificates_bad_input():
    assert "no X.509 certificates" in certs.decode_certificates(b"not a cert at all")


def test_looks_like_certificates(two_certs):
    assert certs.looks_like_certificates(two_certs[0].public_bytes(serialization.Encoding.DER))
    assert certs.looks_like_certificates(b"-----BEGIN CERTIFICATE-----\nabc")
    assert not certs.looks_like_certificates(b"\x00\x01\x02")


def test_decode_ocsp_bad_input():
    out = certs.decode_ocsp(b"\x30\x03\x0a\x01\x06")   # malformed/unsuccessful-ish
    assert out.startswith("OCSP response status:") or out.startswith("// ERROR")


def _self_signed(cn, key, *, eku=None):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    nb = datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc)
    b = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
         .public_key(key.public_key()).serial_number(1)
         .not_valid_before(nb).not_valid_after(nb + datetime.timedelta(days=365)))
    if eku:
        b = b.add_extension(x509.ExtendedKeyUsage(eku), critical=False)
    return b.sign(key, hashes.SHA256())


def _issued_by(cn, key, ca_cert, ca_key, *, eku=None):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    nb = datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc)
    b = (x509.CertificateBuilder().subject_name(name).issuer_name(ca_cert.subject)
         .public_key(key.public_key()).serial_number(2)
         .not_valid_before(nb).not_valid_after(nb + datetime.timedelta(days=365)))
    if eku:
        b = b.add_extension(x509.ExtendedKeyUsage(eku), critical=False)
    return b.sign(ca_key, hashes.SHA256())


def test_decode_ocsp_surfaces_issuer_ca():
    """A SUCCESSFUL response with an embedded responder cert names the issuing CA."""
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca = _self_signed("Apple System Integration CA 4", ca_key)
    resp_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    responder = _issued_by("Apple ... OCSP Responder", resp_key, ca, ca_key,
                           eku=[ExtendedKeyUsageOID.OCSP_SIGNING])
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf = _issued_by("leaf.apple.com", leaf_key, ca, ca_key)

    now = datetime.datetime(2024, 6, 1, tzinfo=datetime.timezone.utc)
    builder = (ocsp.OCSPResponseBuilder()
               .add_response(cert=leaf, issuer=ca, algorithm=hashes.SHA1(),
                             cert_status=ocsp.OCSPCertStatus.GOOD,
                             this_update=now,
                             next_update=now + datetime.timedelta(days=1),
                             revocation_time=None, revocation_reason=None)
               .responder_id(ocsp.OCSPResponderEncoding.NAME, responder)
               .certificates([responder]))
    der = builder.sign(resp_key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)

    out = certs.decode_ocsp(der)
    assert "OCSP response status: SUCCESSFUL" in out
    assert "issuer CA:    Apple System Integration CA 4" in out
    assert "cert status:  GOOD" in out


def test_decode_ocsp_no_embedded_cert_omits_issuer_ca():
    """No responder cert embedded → no issuer-CA line (cautious: never guess)."""
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca = _self_signed("Some CA", ca_key)
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf = _issued_by("leaf", leaf_key, ca, ca_key)

    now = datetime.datetime(2024, 6, 1, tzinfo=datetime.timezone.utc)
    builder = (ocsp.OCSPResponseBuilder()
               .add_response(cert=leaf, issuer=ca, algorithm=hashes.SHA1(),
                             cert_status=ocsp.OCSPCertStatus.GOOD,
                             this_update=now, next_update=None,
                             revocation_time=None, revocation_reason=None)
               .responder_id(ocsp.OCSPResponderEncoding.HASH, ca))
    der = builder.sign(ca_key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)

    out = certs.decode_ocsp(der)
    assert "OCSP response status: SUCCESSFUL" in out
    assert "issuer CA:" not in out
