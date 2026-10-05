"""Siri TCP decoding — ACE stream + HTTP/2/gRPC.

Unit tests build their own ACE / HTTP-2 byte streams (no captured device data), so they
are portable and self-contained.  A separate live-gated test exercises the decoder on the
real extracted fixtures when they're present (regenerate with
``python -m ios_decoder.tests.extract_tcp_samples``).
"""

import gzip
import json
import plistlib
import struct
import zlib
from pathlib import Path

import pytest

from ios_decoder import siri

# --- helpers: synthesize ACE / HTTP-2 byte streams ---------------------------


def ace_packet(ptype: int, payload: bytes = b"") -> bytes:
    return bytes([ptype]) + struct.pack("!I", len(payload)) + payload


def ace_stream(packets: bytes, comptype: int = 2,
               preamble: bytes = b"HTTP/1.1 200 OK\r\n\r\n") -> bytes:
    body = packets if comptype == 0 else zlib.compress(packets)
    return preamble + siri.ACE_MAGIC + bytes([comptype]) + body


def ace_plist(obj: dict) -> bytes:
    return ace_packet(siri._ACE_PLIST, plistlib.dumps(obj, fmt=plistlib.FMT_BINARY))


def h2_frame(ftype: int, flags: int, sid: int, payload: bytes) -> bytes:
    return struct.pack("!I", len(payload))[1:] + bytes([ftype, flags]) + \
        struct.pack("!I", sid) + payload


def h2_headers(encoder, sid: int, headers, end_stream=False) -> bytes:
    flags = 0x4 | (0x1 if end_stream else 0)        # END_HEADERS [+ END_STREAM]
    return h2_frame(siri._FRAME_HEADERS, flags, sid, encoder.encode(headers))


def h2_data(sid: int, data: bytes, end_stream=True) -> bytes:
    return h2_frame(siri._FRAME_DATA, 0x1 if end_stream else 0, sid, data)


def grpc_msg(payload: bytes, gzip_it=False) -> bytes:
    if gzip_it:
        payload = gzip.compress(payload)
    return bytes([1 if gzip_it else 0]) + struct.pack("!I", len(payload)) + payload


# --- transport detection -----------------------------------------------------


def test_detection():
    assert siri.looks_like_ace(b"ACE /ace HTTP/1.0\r\nHost: guzzoni.apple.com\r\n")
    assert not siri.looks_like_ace(b"GET /foo HTTP/1.1\r\n")
    assert siri.looks_like_h2(siri.H2_PREFACE + b"\x00\x00")
    assert not siri.looks_like_h2(b"ACE /ace HTTP/1.0")


def test_non_siri_returns_none():
    # genuine unrelated TCP (neither ACE request line nor H2 preface) must be rejected
    messages = [(True, b"\xed\x45\x00\x01\x00\x00\x06\x08"), (False, b"\x00\x006\x1a4")]
    assert siri.decode_tcp_flow(messages) is None


def test_decode_tcp_flow_names_ace_transport():
    # the decoded output names which transport was used (was previously unstated)
    client = (b"ACE /ace HTTP/1.0\r\nHost: guzzoni.apple.com\r\n\r\n"
              + siri.ACE_MAGIC + bytes([2]) + zlib.compress(ace_plist({"k": "v"})))
    out = siri.decode_tcp_flow([(True, client), (False, b"")])
    assert out is not None and "// transport: ACE stream (Siri)" in out


# --- ACE stream --------------------------------------------------------------


def test_ace_plist_packet_renders_class_and_fields():
    pkt = ace_plist({"$class": "CreateSessionInfoRequest",
                     "$group": "com.apple.ace.system",
                     "$v": 13,
                     "aceId": "ABC-123",
                     "deviceAuthVersion": 1})
    client = b"ACE /ace HTTP/1.0\r\nHost: guzzoni.apple.com\r\n\r\n" + ace_stream(pkt)
    out = siri.decode_tcp_flow([(True, client), (False, b"")])
    assert out is not None
    assert "ACE CreateSessionInfoRequest" in out
    assert "group=com.apple.ace.system" in out and "v=13" in out
    assert 'aceId: "ABC-123"' in out
    assert "deviceAuthVersion: 1" in out


def test_ace_nested_protobuf_field_expands():
    # a plist <data> field that is clearly-binary protobuf should expand inline
    # (a mostly-printable blob would render as utf8 — nested.py's cautious ordering)
    pb = b"\x08\x96\x01"                          # field 1 = varint 150
    pkt = ace_plist({"$class": "X", "$group": "g", "speechId": pb})
    client = b"ACE /ace HTTP/1.0\r\n\r\n" + ace_stream(pkt)
    out = siri.decode_ace_flow(client, b"")
    assert "protobuf" in out and "150" in out


def test_ace_trivial_packets():
    pkts = ace_packet(siri._ACE_NOP, b"\x00") + ace_packet(siri._ACE_PING, b"\x00") \
        + ace_packet(siri._ACE_PONG, b"\x00")
    out = siri.decode_ace_flow(b"ACE /ace HTTP/1.0\r\n\r\n" + ace_stream(pkts), b"")
    assert "nop" in out and "ping" in out and "pong" in out


def test_ace_uncompressed_comptype_zero():
    pkt = ace_plist({"$class": "Plain", "$group": "g"})
    client = b"ACE /ace HTTP/1.0\r\n\r\n" + ace_stream(pkt, comptype=0)
    out = siri.decode_ace_flow(client, b"")
    assert "ACE Plain" in out


def test_ace_unknown_packet_type_is_flagged_not_guessed():
    bad = bytes([99]) + struct.pack("!I", 3) + b"abc"
    out = siri.decode_ace_flow(b"ACE /ace HTTP/1.0\r\n\r\n" + ace_stream(bad), b"")
    assert "unknown ACE packet type 99" in out


def test_ace_truncated_packet_flagged():
    truncated = bytes([siri._ACE_PLIST]) + struct.pack("!I", 999) + b"short"
    out = siri.decode_ace_flow(b"ACE /ace HTTP/1.0\r\n\r\n" + ace_stream(truncated), b"")
    assert "truncated ACE packet" in out


def test_ace_speech_summary():
    # verified layout: <refId len><refId><2B BE seq><2B BE nframes><[2B BE len][frame]…>
    ref = b"refABC"
    body = bytes([len(ref)]) + ref + struct.pack("!H", 6) + struct.pack("!H", 2) \
        + struct.pack("!H", 3) + b"aaa" + struct.pack("!H", 2) + b"bb"
    pkt = ace_packet(siri._ACE_SPEECH, body)
    out = siri.decode_ace_flow(b"ACE /ace HTTP/1.0\r\n\r\n" + ace_stream(pkt), b"")
    assert "refABC" in out and "seq=6" in out
    assert "2/2 opus frames" in out and "5 audio bytes" in out


def test_ace_bad_compression_reported():
    stream = b"ACE /ace HTTP/1.0\r\n\r\n" + siri.ACE_MAGIC + bytes([2]) + b"not-zlib-data"
    out = siri.decode_ace_flow(stream, b"")
    assert "ERROR: ACE decompress failed" in out


# --- HTTP/2 + gRPC -----------------------------------------------------------


def test_h2_grpc_protobuf_decodes():
    from hpack import Encoder
    enc_c, enc_s = Encoder(), Encoder()
    client = siri.H2_PREFACE
    client += h2_headers(enc_c, 1, [(":method", "POST"),
                                    (":path", "/svc.Method"),
                                    ("content-type", "application/grpc"),
                                    ("grpc-encoding", "gzip")])
    client += h2_data(1, grpc_msg(b"\x0a\x05hello", gzip_it=True))
    server = h2_headers(enc_s, 1, [(":status", "200")])
    server += h2_data(1, grpc_msg(b"\x12\x03bye"))
    out = siri.decode_tcp_flow([(True, client), (False, server)])
    assert "stream 1: POST /svc.Method → 200" in out
    assert "hello" in out and "bye" in out


def test_h2_non_protobuf_falls_back_to_hex_with_hint():
    from hpack import Encoder
    enc = Encoder()
    fb = b"\x08\x00\x00\x00\x04\x00\x04\x00\x04\x00\x00\x00"   # real Siri-shaped flatbuffer
    client = siri.H2_PREFACE
    client += h2_headers(enc, 1, [(":method", "POST"), (":path", "/auth/GetCertificate")])
    client += h2_data(1, grpc_msg(fb))
    out = siri.decode_h2_flow(client, b"")
    assert "not protobuf" in out and "FlatBuffers" in out and "heuristic" in out
    assert "08 00 00 00" in out


def test_h2_certificate_in_flatbuffer_envelope_is_decoded_not_hex_dumped():
    # AuthSession GetCertificate wraps its DER cert chain in a small FlatBuffers-shaped
    # envelope. The envelope alone would pass _looks_flatbuffer, but real content (an
    # actual certificate) must win over the shape-based guess: content-check first.
    import datetime
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "leaf.example.com")])
    nb = datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(0xABCDEF)
            .not_valid_before(nb).not_valid_after(nb + datetime.timedelta(days=365))
            .sign(key, hashes.SHA256()))
    der = cert.public_bytes(serialization.Encoding.DER)

    fb_envelope = b"\x08\x00\x00\x00\x04\x00\x04\x00\x04\x00\x00\x00"  # real Siri-shaped flatbuffer
    assert siri._looks_flatbuffer(fb_envelope)          # the envelope alone looks like FlatBuffers
    wrapped = fb_envelope + der

    from hpack import Encoder
    enc = Encoder()
    client = siri.H2_PREFACE
    client += h2_headers(enc, 1, [(":method", "POST"), (":path", "/auth/GetCertificate")])
    client += h2_data(1, grpc_msg(wrapped))
    out = siri.decode_h2_flow(client, b"")

    assert "CN=leaf.example.com" in out                  # the real cert was decoded
    assert "FlatBuffers" not in out                       # not mislabelled/hidden behind the guess


def test_flatbuffer_detector_strict():
    # accepts the real Siri AuthSession GetCertificate flatbuffer ...
    assert siri._looks_flatbuffer(b"\x08\x00\x00\x00\x04\x00\x04\x00\x04\x00\x00\x00")
    # ... and rejects a plausible-but-bogus blob a loose leading-offset test would accept
    assert not siri._looks_flatbuffer(b"\x08\x00\x00\x00" + b"\xff" * 20)
    assert not siri._looks_flatbuffer(b"\x00" * 16)


def test_h2_header_continuation():
    # split a header block across HEADERS (no END_HEADERS) + CONTINUATION
    from hpack import Encoder
    enc = Encoder()
    block = enc.encode([(":method", "POST"), (":path", "/p"), (":status", "x")])
    half = len(block) // 2
    client = siri.H2_PREFACE
    client += h2_frame(siri._FRAME_HEADERS, 0x0, 1, block[:half])        # no END_HEADERS
    client += h2_frame(siri._FRAME_CONTINUATION, 0x4, 1, block[half:])   # END_HEADERS
    out = siri.decode_h2_flow(client, b"")
    assert "/p" in out


# --- isolation: no shared state across flows ---------------------------------


def test_flows_are_independent():
    a = b"ACE /ace HTTP/1.0\r\n\r\n" + ace_stream(ace_plist({"$class": "A", "$group": "g"}))
    b = b"ACE /ace HTTP/1.0\r\n\r\n" + ace_stream(ace_plist({"$class": "B", "$group": "g"}))
    out_a = siri.decode_tcp_flow([(True, a), (False, b"")])
    out_b = siri.decode_tcp_flow([(True, b), (False, b"")])
    assert "ACE A" in out_a and "ACE B" not in out_a
    assert "ACE B" in out_b and "ACE A" not in out_b


# --- live-gated: real extracted fixtures -------------------------------------

_FIX = Path(__file__).parent / "fixtures" / "siri_real"


def _load_real(name):
    d = _FIX / name
    meta = json.loads((d / "meta.json").read_text())
    return [(s["dir"] == "C", (d / f"{s['i']:03d}_{s['dir']}.bin").read_bytes())
            for s in meta["segments"]]


@pytest.mark.skipif(not (_FIX / "manifest.json").exists(),
                    reason="real siri fixtures absent (run extract_tcp_samples)")
def test_real_fixtures_decode():
    manifest = json.loads((_FIX / "manifest.json").read_text())
    by_name = {m["name"]: m for m in manifest}
    for name in by_name:
        out = siri.decode_tcp_flow(_load_real(name))
        if name.startswith("guzzoni-speech"):
            # real voice flow: ACE messages + decoded speech packets
            assert out is not None and "ACE " in out, name
            assert "<speech:" in out and "opus frames" in out, name
        elif name.startswith("guzzoni"):
            assert out is not None and "ACE " in out, name
        elif name.startswith("swallow"):
            assert out is not None and "stream" in out, name
        elif name.startswith("non-siri"):
            assert out is None, name
