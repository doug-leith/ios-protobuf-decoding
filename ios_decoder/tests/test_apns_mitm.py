"""Regression tests for apns_mitm.py (APNs decoder, mitmproxy addon, offline modes) and its use in
ios_decoder.report, on synthetic data only.  Addon tests are skipped when mitmproxy is missing.
"""
import json
import struct
from types import SimpleNamespace

import pytest

from ios_decoder import apns_mitm as am


def serial_msg(cmd: int, fields: list[tuple[int, bytes]]) -> bytes:
    body = b"".join(bytes([n]) + struct.pack(">H", len(v)) + v for n, v in fields)
    return bytes([cmd]) + struct.pack(">I", len(body)) + body


CONNECT_RESPONSE = serial_msg(0x08, [(1, b"\x00"), (4, struct.pack(">H", 5120)), (5, b"\x00\x0a"),
                                     (10, struct.pack(">Q", 1792242105031)), (11, b"IE"),
                                     (19, bytes([192, 0, 2, 1]))])
KEEP_ALIVE = serial_msg(0x0C, [(1, b"WiFi"), (5, b"10"), (6, b"600")])
KEEP_ALIVE_ACK = serial_msg(0x16, [])


def fields_of(msg) -> dict:
    return {name: v.value for _, name, v in msg.fields}


# --------------------------------------------------------------------------- primitives

def test_hpack_int_rfc7541_example():
    # RFC 7541 C.1.2: 1337 with a 5-bit prefix
    assert am.read_hpack_int(bytes([0x1F, 0x9A, 0x0A]), 0, 5) == (1337, 3)
    assert am.read_hpack_int(bytes([0x0A]), 0, 5) == (10, 1)
    with pytest.raises(am.Truncated):
        am.read_hpack_int(bytes([0x1F, 0x9A]), 0, 5)


def test_value_table_evicts_oldest_and_counts_33_bytes_per_entry():
    t = am.PackedTables(max_size=2 * (30 + am.ENTRY_OVERHEAD))
    for i in range(3):
        t.add_value(am.Value("data", bytes([i]) * 30, 30))
    assert [v.value[0] for v in t.values] == [2, 1]         # newest first, oldest evicted
    assert t.size == 2 * (30 + am.ENTRY_OVERHEAD)


# --------------------------------------------------------------------------- serial

def test_serial_connect_response_names_and_types():
    (msg,) = am.StreamDecoder("s2c", "serial").feed(CONNECT_RESPONSE)
    f = fields_of(msg)
    assert msg.name == "ConnectResponse"
    assert f["ConnectedResponse"] == 0 and f["MessageSize"] == 5120 and f["GeoRegion"] == "IE"
    assert f["ServerTime"] == 1792242105031
    assert f["attr5"] == b"\x00\x0a"                         # unnamed in apsd: shown by number
    assert f["ClientIPAddress"] == bytes([192, 0, 2, 1])


def test_serial_stream_split_at_every_byte():
    stream = CONNECT_RESPONSE + KEEP_ALIVE_ACK
    d = am.StreamDecoder("s2c", "serial")
    msgs = [m for i in range(len(stream)) for m in d.feed(stream[i:i + 1])]
    assert [m.name for m in msgs] == ["ConnectResponse", "KeepAliveAck"]
    assert d.offset == len(stream) and not d.buf


def test_keepalive_field_names():
    (msg,) = am.StreamDecoder("c2s", "serial").feed(KEEP_ALIVE)
    assert fields_of(msg) == {"Carrier": "WiFi", "KeepAliveInterval": "10", "DelayedResponseInterval": "600"}


def test_protocol_error_reports_offset():
    bad = KEEP_ALIVE_ACK + bytes([0x16]) + struct.pack(">I", 0x80000000)
    d = am.StreamDecoder("s2c", "serial")
    assert [m.name for m in d.feed(bad)] == ["KeepAliveAck"]
    assert d.broken and f"offset {len(KEEP_ALIVE_ACK)}" in d.broken
    assert d.feed(KEEP_ALIVE_ACK) == []                      # stays stopped


# --------------------------------------------------------------------------- packed

def test_packed_sign_magnitude_width_and_small_ints():
    # start of a real packed ConnectResponse (report Figure "packed", panel c)
    body = bytes.fromhex("0180" "04a11400" "058a" "0683" "08a93800")
    (msg,) = am.StreamDecoder("s2c", "packed").feed(bytes([0x08, len(body)]) + body)
    f = fields_of(msg)
    assert f["ConnectedResponse"] == 0 and f["MessageSize"] == 5120 and f["Capabilities"] == 3
    assert f["attr5"] == 10
    assert f["LargeMessageSize"] == 51200                    # -14336 on the wire, 16-bit field


def test_packed_value_table_reference():
    token = bytes(range(32))
    first = bytes([0x41, 0x20]) + token                      # field 1, literal + index, 32 bytes
    second = bytes([0x81, 0x00])                             # field 1, value table[0]
    d = am.StreamDecoder("c2s", "packed")
    m1, m2 = d.feed(bytes([0x07, len(first)]) + first + bytes([0x07, len(second)]) + second)
    (_, _, v1), (_, _, v2) = m1.fields[0], m2.fields[0]
    assert v1.value == v2.value == token
    assert (v1.how, v2.how) == ("literal+index", "table[0]")
    assert d.tables.values[0].how == "literal"               # the table entry itself is not altered


def test_packed_extended_field_number_goes_to_key_table():
    # K=0,E=1: one byte field number (19) follows; then K=1 refers to it by key-table index 0
    body1 = bytes([0x10, 19, 0x04]) + b"\xc0\x00\x02\x01"
    body2 = bytes([0x20, 0x04]) + b"\x0a\x00\x00\x01"
    d = am.StreamDecoder("s2c", "packed")
    m1, m2 = d.feed(bytes([0x08, len(body1)]) + body1 + bytes([0x08, len(body2)]) + body2)
    assert m1.fields[0][:2] == (19, "ClientIPAddress") and m2.fields[0][:2] == (19, "ClientIPAddress")


def test_framing_from_alpn():
    assert am.framing_from_alpn(b"apns-pack-v1:4096:2048") == ("packed", 4096, 2048)
    assert am.framing_from_alpn(b"") == ("serial", 0, 0)
    assert am.framing_from_alpn(None) == ("serial", 0, 0)


# --------------------------------------------------------------------------- presentation

def test_redaction_shortens_bytes_and_salt():
    d = am.StreamDecoder("c2s", "serial")
    (msg,) = d.feed(serial_msg(0x20, [(2, bytes(range(32))), (3, struct.pack(">Q", 7012345678901234567))]))
    short, full = am.format_message(msg), am.format_message(msg, redact_data=False)
    assert "0001...1e1f (32B)" in short and "70...67" in short
    assert bytes(range(32)).hex() in full and "7012345678901234567" in full


# --------------------------------------------------------------------------- addon

@pytest.fixture
def addon_ctx():
    pytest.importorskip("mitmproxy")
    from mitmproxy.test import taddons
    a = am.APNS()
    with taddons.context(a) as tctx:
        yield a, tctx


def courier_flow(chunks, alpn=b""):
    from mitmproxy import tcp
    from mitmproxy.test import tflow
    f = tflow.ttcpflow()
    msgs = [tcp.TCPMessage(from_client, data) for from_client, data in chunks]
    f.messages = []
    f.client_conn.sni = f.server_conn.sni = "courier2.push.apple.com"
    f.server_conn.address = f.server_conn.peername = ("17.57.146.13", 5223)
    f.client_conn.alpn = f.server_conn.alpn = alpn
    return f, msgs


def run_flow(a, f, msgs):
    a.tcp_start(f)
    for m in msgs:
        f.messages.append(m)
        a.tcp_message(f)
    a.tcp_end(f)


def test_addon_metadata_and_jsonl(addon_ctx, tmp_path, capsys):
    a, tctx = addon_ctx
    log = tmp_path / "log.jsonl"
    tctx.configure(a, apns_log=str(log))
    chunks = [(True, KEEP_ALIVE[:3]), (True, KEEP_ALIVE[3:]), (False, CONNECT_RESPONSE + KEEP_ALIVE_ACK)]
    f, msgs = courier_flow(chunks)
    run_flow(a, f, msgs)

    meta = f.metadata["apns"]
    assert meta["framing"] == "serial" and [m["name"] for m in meta["messages"]] == \
        ["KeepAlive", "ConnectResponse", "KeepAliveAck"]
    recs = [json.loads(line) for line in log.read_text().splitlines()]
    assert [r["kind"] for r in recs] == ["flow", "raw", "raw", "message", "raw", "message", "message", "end"]
    assert bytes.fromhex(recs[1]["hex"]) == KEEP_ALIVE[:3]

    # the JSONL alone re-decodes to the same output as decoding the chunks directly
    am.decode_jsonl_file(str(log), full=True)
    from_log = capsys.readouterr().out.splitlines()[1:]
    assert from_log == am.decode_chunks([(m.timestamp, m.content) for m in msgs if m.from_client],
                                        [(m.timestamp, m.content) for m in msgs if not m.from_client],
                                        "serial", 0, 0, True)


def test_addon_ignores_non_courier_flows(addon_ctx):
    a, _ = addon_ctx
    f, msgs = courier_flow([(True, b"GET / HTTP/1.1\r\n\r\n")])
    f.client_conn.sni = "example.com"
    run_flow(a, f, msgs)
    assert "apns" not in f.metadata


def test_addon_raises_default_tcp_timeout_only(addon_ctx):
    a, tctx = addon_ctx
    a.running()
    assert tctx.options.tcp_timeout == am.APNS_TCP_TIMEOUT
    tctx.configure(a, tcp_timeout=900)
    a.running()
    assert tctx.options.tcp_timeout == 900


def test_addon_drops_pack_alpn_upstream(addon_ctx):
    a, _ = addon_ctx
    data = SimpleNamespace(client_hello=SimpleNamespace(alpn_protocols=[b"apns-security-v3", b"apns-pack-v1"],
                                                        sni="courier2.push.apple.com"),
                           context=SimpleNamespace(server=SimpleNamespace(alpn_offers=())))
    a.tls_clienthello(data)
    assert data.context.server.alpn_offers == (b"apns-security-v3",)


def test_cli_jsonl_and_usage(addon_ctx, tmp_path, capsys):
    a, tctx = addon_ctx
    log = tmp_path / "log.jsonl"
    tctx.configure(a, apns_log=str(log))
    f, msgs = courier_flow([(False, CONNECT_RESPONSE)])
    run_flow(a, f, msgs)
    am.main(["--jsonl", str(log)])
    out = capsys.readouterr().out
    assert "ConnectResponse(0x08)" in out and "GeoRegion=IE" in out
    with pytest.raises(SystemExit):
        am.main([])


# --------------------------------------------------------------------------- ios_decoder.report

def test_report_decodes_apns_tcp_flow(capsys):
    pytest.importorskip("mitmproxy")
    from ios_decoder import report
    from ios_decoder.bodies import BodyDisplayOptions
    f, msgs = courier_flow([(True, KEEP_ALIVE), (False, CONNECT_RESPONSE + KEEP_ALIVE_ACK)])
    f.messages = msgs
    assert report._print_tcp_flow(f, decoded_only=True, body_opts=BodyDisplayOptions())
    out = capsys.readouterr().out
    assert "TCP courier2.push.apple.com:5223  (APNs, serial encoding)" in out
    assert "-> KeepAlive(0x0c)" in out and "<- ConnectResponse(0x08)" in out and "<- KeepAliveAck(0x16)" in out
    assert "ClientIPAddress=c0000201 (4B)" in out              # ios_decoder prints values in full


def test_report_other_tcp_still_summarised(capsys):
    pytest.importorskip("mitmproxy")
    from ios_decoder import report
    from ios_decoder.bodies import BodyDisplayOptions
    f, msgs = courier_flow([(True, b"\x00\x01binary")])
    f.messages = msgs
    f.client_conn.sni = f.server_conn.sni = "example.com"
    assert not report._print_tcp_flow(f, decoded_only=False, body_opts=BodyDisplayOptions())
    assert "(not Siri or APNs)" in capsys.readouterr().out
    assert not report._print_tcp_flow(f, decoded_only=True, body_opts=BodyDisplayOptions())
    assert capsys.readouterr().out == ""
