"""Decode Apple Push Notification service (APNs) traffic: a mitmproxy addon and an offline decoder,
in one self-contained file (Python standard library only, plus mitmproxy for the addon).

Live capture, alongside normal HTTPS (phone traffic to tcp/5223 must reach mitmproxy too):

    mitmdump --mode transparent --showhost --ssl-insecure -w capture.mitm -s apns_mitm.py

Stop with Ctrl-C (not kill -9), so the still-open APNs connection is written to capture.mitm.

Reading the saved files later:

    python apns_mitm.py capture.mitm [--full]                 # APNs connections in a .mitm capture
    python apns_mitm.py --jsonl apns_decoded.jsonl [--full]   # from the addon's log; no mitmproxy needed
    mitmdump -n --set flow_detail=0 -r capture.mitm -s apns_mitm.py

Printed byte values (tokens, certificates...) are shortened unless --full; the files keep full values.

What the addon does
-------------------
* ALPN: the handset offers "apns-security-v3" and "apns-pack-v1"; Apple answers "apns-pack-v1"
  with "apns-pack-v1:4096:4096", which the handset never offered.  The handset accepts that, but
  OpenSSL (mitmproxy's side towards Apple) rejects it (BAD_EXTENSION).  The addon therefore offers
  Apple only "apns-security-v3"; the server then selects no protocol and both ends use the simple
  serial encoding.  (The packed encoding is decoded too, for traffic recorded on the handset.)
* Decoding: mitmproxy keeps the APNs connection as a raw TCP flow; the addon decodes each
  direction as it arrives, logs the messages, stores them in flow.metadata["apns"] (saved in the
  .mitm file next to the raw bytes, readable without the addon) and appends them to apns_log.
* apns_log (default apns_decoded.jsonl; --set apns_log= turns it off) is written as traffic
  arrives and also holds the raw bytes, so it survives a crash; mitmdump itself writes a TCP flow
  to the .mitm file only when the connection closes or mitmdump exits cleanly.  When mitmdump only
  replays a file (-r), the log is written only if apns_log is set explicitly.  One JSON object per
  line, by "kind": flow (connection start), raw (one TCP chunk: dir, t, hex), message (one decoded
  message), end (connection end).
* tcp_timeout: the APNs connection is silent between keep-alives (10 or 15 minutes), and
  mitmproxy's default 600 s idle timeout closes it just before the first one.  The addon raises
  tcp_timeout to 3600 s unless it was set explicitly.
* apns_redact (default on) shortens byte values in the console log only.
* Instead of --ssl-insecure, --set ssl_verify_upstream_trusted_ca=BUNDLE.pem, with BUNDLE.pem
  holding certifi's roots plus Apple Root CA (some courier servers chain to it), keeps upstream
  certificate checks on.
* On the phone, apsd must accept the proxy's certificate.  Stock SSL Kill Switch 3 breaks apsd
  (no push connection at all); a fixed build is in ssl-kill-switch3-DL at
  https://github.com/doug-leith/poor-privacy-practices-of-the-apple-app-store

Other offline mode: python apns_mitm.py --streams DIR [--serial] decodes DIR/<name>.c2s.bin and
<name>.s2c.bin, each the plaintext bytes of one direction (e.g. recorded inside apsd with Frida).

Protocol
--------
Every message is a command: [cmd u8] followed by fields, each with a field number.
  * serial (ALPN "apns-security-v3"):  [cmd u8][len u32 BE] then [field u8][len u16 BE][value]...
  * packed (ALPN "apns-pack-v1:<enc>:<dec>"): [cmd u8][len: HPACK int, 8-bit prefix][fields];
    remembered-value and key tables mean a decoder must see a whole connection, in order, with
    one decoder per direction.
Names and formats were recovered from apsd itself (iOS 16.7.11): field names by running apsd's
parser and builders on test input, the packed format by having apsd's APNSPackEncoder encode and
APNSPackDecoder decode test values.
"""
from __future__ import annotations

import datetime
import glob
import json
import logging
import os
import plistlib
import struct
import sys

try:                                    # the decoder and the offline modes work without mitmproxy
    from mitmproxy import ctx, tcp, tls
    HAVE_MITMPROXY = True
except ImportError:
    HAVE_MITMPROXY = False

# --------------------------------------------------------------------------- names

# 0x0D/0x16/0x17 named after the handlers APSCourier dispatches them to
# (_handleKeepAliveResponseMessage: / _handleKeepAliveAckMessage: / _handleRedirectMessage:)
CMD_NAMES = {
    0x07: "Connect", 0x08: "ConnectResponse", 0x09: "Filter", 0x0A: "PushNotification",
    0x0B: "PushAck", 0x0C: "KeepAlive", 0x0D: "KeepAliveResponse", 0x0E: "NoStorage",
    0x0F: "Flush", 0x10: "FlushResponse", 0x11: "TokenGenerate", 0x12: "TokenGenerateResponse",
    0x13: "SetActiveInterval", 0x14: "SetActiveState", 0x15: "TransportAck", 0x16: "KeepAliveAck",
    0x17: "Redirect", 0x18: "TaskControl", 0x19: "TaskNotification", 0x1B: "MessageTracingAck",
    0x1D: "PubSub", 0x1E: "PubSubUpdate", 0x20: "PresenceTracking",
}

# server -> client: names from -[APSProtocolParser setSerialItemInParameters:...] /
# APNSPackDecoder, (cmd, attr) -> (name, type).  type: data|str|date|bool|uint (any width)|u8..u64
S2C = {
    0x07: {1: ("Token", "data"), 2: ("PresenceStatus", "uint")},
    # attrs 5 and 12 are sent by the server but dropped by apsd's parser (serial sweep, and the live
    # packed parse); 12 has carried the same value as ServerTime, 5 has always been 10
    0x08: {1: ("ConnectedResponse", "u8"), 2: ("ServerMetadata", "str"), 3: ("Token", "data"),
           4: ("MessageSize", "u16"), 6: ("Capabilities", "u32"), 7: ("ServerTimeForBadNonce", "u64"),
           8: ("LargeMessageSize", "u16"), 9: ("RedirectReason", "str"), 10: ("ServerTime", "u64"),
           11: ("GeoRegion", "str"), 16: ("MinKeepAliveInterval", "uint"),
           17: ("ExpectedKeepAliveInterval", "uint"), 18: ("MaxKeepAliveInterval", "uint"),
           19: ("ClientIPAddress", "data")},
    0x0A: {1: ("Token", "data"), 2: ("TopicHash", "data"), 3: ("Payload", "data"), 4: ("MessageID", "data"),
           5: ("MessageExpiry", "date"), 6: ("MessageTimestamp", "u64"), 9: ("MessageStorageFlags", "u8"),
           13: ("MessagePriority", "u8"), 15: ("BaseToken", "data"), 21: ("MessageTracingUUID", "data"),
           24: ("MessageCorrelationIdentifier", "str"), 26: ("MessageAPNFlags", "u32"),
           28: ("MessagePushType", "u16"), 29: ("MessagePubSubInfo", "data")},
    0x0B: {6: ("AckTimestamp", "u64"), 8: ("DeliveryStatus", "u8")},
    0x0D: {1: ("KeepAliveResponse", "u8")},
    0x0E: {1: ("Destination", "data")},
    0x0F: {1: ("FlushWantPadding", "u16")},
    0x12: {1: ("AppTokenGenerateResponse", "u8"), 2: ("AppTokenGenerateResponseToken", "data"),
           3: ("AppTokenGenerateResponseTopicHash", "data"), 4: ("AppTokenGenerateResponseAppId", "u16")},
    0x17: {2: ("ServerMetadata", "str"), 9: ("RedirectReason", "str")},
    0x18: {1: ("TaskMessageId", "uint"), 2: ("TaskControlPayload", "data"), 3: ("TaskStatus", "uint")},
    0x19: {1: ("TaskMessageId", "uint"), 2: ("TaskNotificationPayload", "data"), 3: ("TaskStatus", "uint")},
    0x1D: {1: ("PubSubMessageID", "uint"), 2: ("PubSubPayload", "data"), 3: ("PubSubToken", "data"),
           4: ("PubSubStatus", "uint"), 5: ("PubSubTimeout", "uint")},
    0x1E: {1: ("PubSubUpdateMessageID", "uint"), 2: ("PubSubUpdatePayload", "data"),
           3: ("PubSubUpdateToken", "data"), 4: ("PubSubUpdateTimestamp", "uint")},
    0x20: {1: ("PresenceActivityMessageID", "uint"), 2: ("PresenceActivityPushToken", "data"),
           3: ("PresenceActivityStatus", "uint")},
}

# client -> server: attribute ids and types from apsd's APSProtocolParser copy*Message builders;
# names from the builder's selector arguments / getters.
C2S = {
    # Connect: ids/types from the builder; names from its selector arguments, confirmed by hooking the
    # builder's arguments on a live connection
    0x07: {1: ("Token", "data"), 2: ("State", "u8"), 5: ("Flags", "u32"), 6: ("Interface", "u8"),
           7: ("ActiveInterval", "u32"), 8: ("Carrier", "str"), 9: ("SoftwareVersion", "str"),
           10: ("SoftwareBuild", "str"), 11: ("HardwareVersion", "str"), 12: ("Certificate", "data"),
           13: ("Nonce", "data"), 14: ("Signature", "data"), 16: ("ProtocolVersion", "u16"),
           17: ("RedirectCount", "u16"), 19: ("DNSResolveTimeMs", "u16"), 20: ("TLSHandshakeTimeMs", "u16"),
           21: ("ConnectionFailureReason", "data"), 22: ("LastConnected", "u64"),
           25: ("TCPHandshakeTimeMs", "u16"), 26: ("DisconnectReason", "u32")},
    # the builder writes each hash of the five lists (selector-argument order enabled, ignored,
    # opportunistic, nonWaking, paused) under 2-6 if it is at most 31 bytes, else under 7-11 (a block
    # in copyFilterMessageWith...: [hash length] > 0x1f -> deferred to the second set)
    0x09: {1: ("Token", "data"), 2: ("EnabledTopicHash", "data"), 3: ("IgnoredTopicHash", "data"),
           4: ("OpportunisticTopicHash", "data"), 6: ("NonWakingTopicHash", "data"), 5: ("PausedTopicHash", "data"),
           7: ("EnabledTopicHashLong", "data"), 8: ("IgnoredTopicHashLong", "data"), 9: ("OpportunisticTopicHashLong", "data"),
           11: ("NonWakingTopicHashLong", "data"), 10: ("PausedTopicHashLong", "data")},
    0x0A: {1: ("TopicHash", "data"), 2: ("Token", "data"), 3: ("Payload", "data"), 4: ("MessageID", "uint"),
           25: ("LastRTT", "uint")},
    0x0B: {1: ("Token", "data"), 4: ("MessageID", "uint"), 8: ("Status", "uint")},
    0x0C: {1: ("Carrier", "str"), 2: ("SoftwareVersion", "str"), 3: ("SoftwareBuild", "str"),
           4: ("HardwareVersion", "str"), 5: ("KeepAliveInterval", "str"), 6: ("DelayedResponseInterval", "str"),
           8: ("UsingServerStats", "uint"), 9: ("State", "uint"), 10: ("SubState", "uint")},
    0x0F: {1: ("WantPaddingLength", "uint"), 2: ("Padding", "data")},
    0x10: {2: ("Padding", "data")},
    0x11: {1: ("BaseToken", "data"), 2: ("TopicHash", "data"), 3: ("AppId", "uint"), 4: ("ExpirationTTL", "uint"),
           5: ("Type", "uint"), 6: ("VapidPublicKeyHash", "data")},
    0x13: {1: ("ActiveInterval", "uint")},
    0x14: {1: ("ActiveState", "uint"), 2: ("ActiveInterval", "uint")},
    0x18: {1: ("TaskMessageId", "uint"), 2: ("TaskControlPayload", "data")},
    0x1B: {1: ("TopicHash", "data"), 2: ("TracingUUID", "data"), 3: ("Status", "uint"), 4: ("Token", "data")},
    0x1D: {1: ("PubSubMessageID", "u32"), 2: ("ChannelListPayload", "data"), 3: ("BaseToken", "data")},
    0x20: {1: ("MessageID", "u32"), 2: ("PushToken", "data"), 3: ("Salt", "u64"), 4: ("TrackingFlag", "u32"),
           5: ("Timestamp", "u64")},
}


def field_name(direction: str, cmd: int, attr) -> tuple[str, str | None]:
    tab = (C2S if direction == "c2s" else S2C).get(cmd, {})
    if isinstance(attr, int) and attr in tab:
        return tab[attr]
    return (f"attr{attr}", None)


# --------------------------------------------------------------------------- primitives

class Truncated(Exception):
    """Not enough bytes yet: wait for more stream data."""


class ProtocolError(Exception):
    pass


def read_hpack_int(buf: bytes, pos: int, prefix_bits: int) -> tuple[int, int]:
    """HPACK integer (RFC 7541 5.1). `pos` points at the byte holding the prefix."""
    if pos >= len(buf):
        raise Truncated
    mask = (1 << prefix_bits) - 1
    v = buf[pos] & mask
    pos += 1
    if v < mask:
        return v, pos
    shift = 0
    while True:
        if pos >= len(buf):
            raise Truncated
        b = buf[pos]
        pos += 1
        v += (b & 0x7F) << shift
        shift += 7
        if not b & 0x80:
            return v, pos


def take(buf: bytes, pos: int, n: int) -> tuple[bytes, int]:
    if pos + n > len(buf):
        raise Truncated
    return buf[pos:pos + n], pos + n


# --------------------------------------------------------------------------- packed (apns-pack-v1)

ENTRY_OVERHEAD = 33     # value-table entry size = content bytes + 33 (measured against apsd's encoder)
KEY_TABLE_MAX = 32      # key index is 5 bits; the 33rd-newest key is never referenced


class Value:
    """One decoded value.  (A plain class, not a dataclass: mitmproxy runs addon scripts without
    registering them in sys.modules, which @dataclass relies on.)"""
    __slots__ = ("kind", "value", "size", "how")

    def __init__(self, kind: str, value: object, size: int = 0, how: str = "literal"):
        self.kind = kind        # data|str|uint|int|bool|date|dict|array
        self.value = value
        self.size = size        # bytes counted against the packed value table
        self.how = how          # packed only: literal | literal+index | table[i]

    def replace(self, **changes) -> "Value":
        return Value(**{**{k: getattr(self, k) for k in self.__slots__}, **changes})

    def __repr__(self):
        return f"Value({self.kind}, {self.value!r}, size={self.size}, how={self.how})"


class PackedTables:
    def __init__(self, max_size: int):
        self.max_size = max_size
        self.keys: list[bytes] = []         # newest first
        self.values: list[Value] = []       # newest first
        self.size = 0

    def add_key(self, k: bytes):
        self.keys.insert(0, k)
        del self.keys[KEY_TABLE_MAX:]

    def add_value(self, v: Value):
        need = v.size + ENTRY_OVERHEAD
        # apsd (apnspack::Queue::ValueEvictionPolicy::add, 0x10000e3a0) admits an entry if
        # (type byte + content) + 32 <= max, i.e. content + 33, and evicts oldest-first while the total
        # exceeds max.  A too-large value is rejected (not added); whether apsd then also clears the
        # table is NOT established -- the clearing below follows HPACK and is untested.
        if need > self.max_size:
            self.values.clear(); self.size = 0
            return
        while self.values and self.size + need > self.max_size:
            old = self.values.pop()
            self.size -= old.size + ENTRY_OVERHEAD
        self.values.insert(0, v)
        self.size += need


def parse_value(buf: bytes, pos: int, tables: PackedTables) -> tuple[Value, int]:
    if pos >= len(buf):
        raise Truncated
    t = buf[pos]
    if t >> 6 == 0:                                         # 00LLLLLL  bytes
        n, pos = read_hpack_int(buf, pos, 6)
        b, pos = take(buf, pos, n)
        return Value("data", b, n), pos
    if t >> 5 == 0b010:                                     # 010LLLLL  UTF-8 string
        n, pos = read_hpack_int(buf, pos, 5)
        b, pos = take(buf, pos, n)
        return Value("str", b.decode("utf-8", "replace"), n), pos
    if t >> 5 == 0b100:                                     # 100VVVVV  unsigned 0..31
        return Value("uint", t & 0x1F, 1), pos + 1
    if t >> 4 == 0b1010:                                    # 1010SNNN  signed int, N+1 bytes BE magnitude
        n = (t & 7) + 1
        b, pos = take(buf, pos + 1, n)
        v = int.from_bytes(b, "big")
        return Value("int", -v if t & 8 else v, n), pos
    if t >> 4 == 0b1100:                                    # 1100CCCC  dictionary
        count, pos = read_hpack_int(buf, pos, 4)
        d = {}
        for _ in range(count):
            k, v, pos = parse_entry(buf, pos, tables, in_dict=True)
            d[k] = v
        return Value("dict", d), pos
    if t >> 4 == 0b1101:                                    # 1101CCCC  array
        count, pos = read_hpack_int(buf, pos, 4)
        a = []
        for _ in range(count):
            v, pos = parse_value(buf, pos, tables)
            a.append(v)
        return Value("array", a), pos
    if t in (0xE0, 0xE1):                                   # 1110000B  bool
        return Value("bool", bool(t & 1), 1), pos + 1
    raise ProtocolError(f"invalid value prefix 0x{t:02x}")


def parse_entry(buf: bytes, pos: int, tables: PackedTables, in_dict: bool):
    """One attribute (message level) or dictionary entry: header byte MMKEIIII, then the value.
    MM: 00 literal, 01 literal + add value to table, 10 value from table (HPACK int, 8-bit prefix).
    K=1: key = key table[IIIII] (5 bits).  K=0,E=1: literal key of (4-bit-prefix int)+1 bytes,
    added to the key table (a big-endian attribute id, or a UTF-8 dict key).  K=0,E=0: id IIII."""
    if pos >= len(buf):
        raise Truncated
    h = buf[pos]
    mode = h >> 6
    if mode == 3:
        raise ProtocolError(f"invalid attribute prefix 0x{h:02x}")
    if h & 0x20:
        idx = h & 0x1F
        if idx >= len(tables.keys):
            raise ProtocolError(f"key index {idx} beyond key table ({len(tables.keys)})")
        kraw = tables.keys[idx]
        pos += 1
    elif h & 0x10:
        n, pos = read_hpack_int(buf, pos, 4)
        kraw, pos = take(buf, pos, n + 1)
        tables.add_key(kraw)
    else:
        kraw = None
        pos += 1
    if kraw is None:
        key = h & 0x0F
    elif in_dict:
        key = kraw.decode("utf-8", "replace")
    else:
        key = int.from_bytes(kraw, "big")
    if mode == 2:
        idx, pos = read_hpack_int(buf, pos, 8)
        if idx >= len(tables.values):
            raise ProtocolError(f"value index {idx} beyond value table ({len(tables.values)})")
        return key, tables.values[idx].replace(how=f"table[{idx}]"), pos
    v, pos = parse_value(buf, pos, tables)
    if mode == 1:
        tables.add_value(v)
        v = v.replace(how="literal+index")
    return key, v, pos


def parse_packed(buf: bytes, tables: PackedTables):
    """Parse one packed message from the start of buf -> (cmd, [(attr, Value)], consumed).
    Raises Truncated if buf does not yet hold a whole message (tables are left untouched)."""
    if len(buf) < 2:
        raise Truncated
    cmd = buf[0]
    length, pos = read_hpack_int(buf, 1, 8)
    if pos + length > len(buf):
        raise Truncated
    body = buf[pos:pos + length]
    attrs, p = [], 0
    while p < len(body):
        try:
            k, v, p = parse_entry(body, p, tables, in_dict=False)
        except Truncated:
            raise ProtocolError("attribute runs past end of message")
        attrs.append((k, v))
    return cmd, attrs, pos + length


# --------------------------------------------------------------------------- serial (apns-security-v3)

def parse_serial(buf: bytes):
    if len(buf) < 5:
        raise Truncated
    cmd = buf[0]
    (length,) = struct.unpack_from(">I", buf, 1)
    if length & 0x80000000:
        raise ProtocolError("serial length has the top bit set")
    if 5 + length > len(buf):
        raise Truncated
    body, items, p = buf[5:5 + length], [], 0
    while p < len(body):
        if p + 3 > len(body):
            raise ProtocolError("item header runs past end of message")
        iid = body[p]
        (n,) = struct.unpack_from(">H", body, p + 1)
        if p + 3 + n > len(body):
            raise ProtocolError("item runs past end of message")
        items.append((iid, Value("data", body[p + 3:p + 3 + n], n)))
        p += 3 + n
    return cmd, items, 5 + length


WIDTH = {"u8": 8, "u16": 16, "u32": 32, "u64": 64}


def apply_width(v: Value, want: str | None) -> Value:
    """Packed integers are sign-and-magnitude, so the sender decides the sign; apsd stores them in
    fixed-width fields, so e.g. the server's -14336 (magnitude 0x3800) for the 16-bit
    LargeMessageSize becomes 0xC800 = 51200, which is what apsd uses."""
    if want in WIDTH and v.kind == "int" and v.value < 0:
        return v.replace(kind="uint", value=v.value & ((1 << WIDTH[want]) - 1))
    return v


def retype_serial(v: Value, want: str | None) -> Value:
    """Serial items are untyped bytes; apply the type apsd's parser/builders use for that field."""
    b = v.value
    if (want == "uint" or want in WIDTH) and len(b) in (1, 2, 4, 8):
        return Value("uint", int.from_bytes(b, "big"), len(b))
    if want == "date" and len(b) in (4, 8):
        return Value("date", int.from_bytes(b, "big"), len(b))
    if want == "str":
        return Value("str", b.decode("utf-8", "replace"), len(b))
    return v


# --------------------------------------------------------------------------- stream decoder

class Message:
    def __init__(self, direction: str, cmd: int, raw: bytes = b""):
        self.direction = direction      # c2s | s2c
        self.cmd = cmd
        self.raw = raw
        self.fields: list[tuple[int, str, Value]] = []      # (field number, name, value)

    @property
    def name(self) -> str:
        return CMD_NAMES.get(self.cmd, f"cmd0x{self.cmd:02x}")


def framing_from_alpn(alpn: str | bytes | None):
    """-> ("packed", enc_table, dec_table) | ("serial", 0, 0).  apsd splits the ALPN on ':' and passes
    components 1 and 2 as maxEncoderTableSize / maxDecoderTableSize (both 4096 in every capture)."""
    if isinstance(alpn, bytes):
        alpn = alpn.decode("ascii", "replace")
    if alpn and alpn.startswith("apns-pack-v1"):
        parts = alpn.split(":")
        enc = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 4096
        dec = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else enc
        return "packed", enc, dec
    return "serial", 0, 0


class StreamDecoder:
    """Decodes one direction of one courier connection.  feed() bytes as they arrive."""

    def __init__(self, direction: str, framing: str = "packed", table_size: int = 4096):
        self.direction, self.framing = direction, framing
        self.tables = PackedTables(table_size)
        self.buf = b""
        self.offset = 0                 # stream bytes consumed so far
        self.broken: str | None = None

    def feed(self, data: bytes) -> list[Message]:
        if self.broken:
            return []
        self.buf += data
        out = []
        while self.buf:
            try:
                if self.framing == "packed":
                    cmd, attrs, n = parse_packed(self.buf, self.tables)
                else:
                    cmd, attrs, n = parse_serial(self.buf)
            except Truncated:
                break
            except ProtocolError as e:
                self.broken = f"{e} at stream offset {self.offset}; {len(self.buf)} bytes undecoded"
                break
            msg = Message(self.direction, cmd, raw=self.buf[:n])
            for attr, v in attrs:
                name, want = field_name(self.direction, cmd, attr)
                v = retype_serial(v, want) if self.framing == "serial" else apply_width(v, want)
                msg.fields.append((attr, name, v))
            out.append(msg)
            self.buf = self.buf[n:]
            self.offset += n
        return out


# --------------------------------------------------------------------------- presentation

REDACT_NUMBERS = {"Salt"}     # numeric fields that are per-device values


def redact(b: bytes, keep: int = 2) -> str:
    """Shorten a byte value for display: first/last 2 bytes (1 byte for values under 8 bytes, so a
    4-byte IP address is not shown whole); 1-2 byte values are kept."""
    h = b.hex()
    if len(b) <= 2:
        return h
    k = keep if len(b) >= 8 else 1
    return f"{h[:2 * k]}...{h[-2 * k:]}"


def _bytes_json(b: bytes, redact_data: bool) -> dict:
    return {"hex": redact(b) if redact_data else b.hex(), "len": len(b)}


def to_jsonable(v: Value, redact_data: bool):
    if v.kind == "data":
        if v.value[:8] == b"bplist00":
            try:
                return {"bplist": _plain(plistlib.loads(v.value), redact_data)}
            except Exception:
                pass
        return _bytes_json(v.value, redact_data)
    if v.kind == "dict":
        return {k: to_jsonable(x, redact_data) for k, x in v.value.items()}
    if v.kind == "array":
        return [to_jsonable(x, redact_data) for x in v.value]
    if v.kind == "date":
        return datetime.datetime.fromtimestamp(v.value, datetime.timezone.utc).isoformat()
    return v.value


def _plain(o, redact_data):
    if isinstance(o, dict):
        return {k: _plain(x, redact_data) for k, x in o.items()}
    if isinstance(o, list):
        return [_plain(x, redact_data) for x in o]
    if isinstance(o, bytes):
        return _bytes_json(o, redact_data)
    if isinstance(o, (datetime.datetime, datetime.date)):
        return o.isoformat()
    return o


def message_to_dict(m: Message, redact_data: bool = True) -> dict:
    return {"dir": m.direction, "cmd": m.cmd, "name": m.name, "len": len(m.raw),
            "fields": [{"attr": a, "name": n, "type": v.kind, "how": v.how,
                        "value": to_jsonable(v, redact_data)} for a, n, v in m.fields]}


def format_message(m: Message, redact_data: bool = True) -> str:
    arrow = "->" if m.direction == "c2s" else "<-"
    parts = []
    for a, n, v in m.fields:
        j = to_jsonable(v, redact_data)
        if redact_data and n in REDACT_NUMBERS and isinstance(j, int):
            j = f"{str(j)[:2]}...{str(j)[-2:]}"
        if isinstance(j, dict) and "hex" in j and len(j) == 2:
            j = f"{j['hex']} ({j['len']}B)"
        parts.append(f"{n}={j}")
    return f"{arrow} {m.name}(0x{m.cmd:02x}) " + ", ".join(parts)


# =========================================================================== mitmproxy addon

APNS_LOG_DEFAULT = "apns_decoded.jsonl"
APNS_TCP_TIMEOUT = 3600     # above apsd's keep-alive intervals (10 and 15 min seen)
COURIER_SUFFIX = "push.apple.com"
COURIER_PORTS = (5223, 443)


def flow_alpn(flow: tcp.TCPFlow) -> bytes:
    return flow.server_conn.alpn or flow.client_conn.alpn or b""


def is_courier(flow: tcp.TCPFlow) -> bool:
    """An APNs courier connection: an apns-* ALPN, or (when no ALPN was negotiated, as through the
    addon) a courier server name on the APNs ports."""
    if flow_alpn(flow).startswith(b"apns-"):
        return True
    sni = flow.client_conn.sni or flow.server_conn.sni or ""
    port = flow.server_conn.address[1] if flow.server_conn.address else None
    return sni.endswith(COURIER_SUFFIX) and "courier" in sni and port in COURIER_PORTS


class APNS:
    def __init__(self):
        self.state = {}      # flow.id -> {"c2s": StreamDecoder, "s2c": StreamDecoder}
        self.out = None

    def load(self, loader):
        loader.add_option("apns_log", str, APNS_LOG_DEFAULT,
                          "Append decoded APNs messages and raw courier bytes (JSONL) to this file; empty: off. "
                          "Not written by default when replaying a file with -r.")
        loader.add_option("apns_redact", bool, True, "Shorten byte values (tokens, certificates...) in the console log.")

    def configure(self, updated):
        if "apns_log" in updated or "rfile" in updated:
            path = ctx.options.apns_log
            if path == APNS_LOG_DEFAULT and getattr(ctx.options, "rfile", None):
                path = ""       # replaying a saved file: only log if asked for explicitly
            if self.out:
                self.out.close()
            self.out = open(path, "a") if path else None

    def running(self):
        if not ctx.options.has_changed("tcp_timeout") and ctx.options.tcp_timeout < APNS_TCP_TIMEOUT:
            logging.info(f"[apns] tcp_timeout raised from {ctx.options.tcp_timeout} to {APNS_TCP_TIMEOUT} s "
                         f"so the idle courier connection is not closed between keep-alives")
            ctx.options.update(tcp_timeout=APNS_TCP_TIMEOUT)

    def tls_clienthello(self, data: tls.ClientHelloData):
        offers = data.client_hello.alpn_protocols
        if any(o.startswith(b"apns-pack") for o in offers):
            data.context.server.alpn_offers = tuple(o for o in offers if not o.startswith(b"apns-pack"))
            logging.info(f"[apns] courier ClientHello sni={data.client_hello.sni} alpn={offers}: "
                         f"offering upstream {data.context.server.alpn_offers}")

    def tcp_start(self, flow: tcp.TCPFlow):
        if not is_courier(flow):
            return
        alpn = flow_alpn(flow)
        framing, enc, dec = framing_from_alpn(alpn)
        self.state[flow.id] = {"c2s": StreamDecoder("c2s", framing, enc), "s2c": StreamDecoder("s2c", framing, dec)}
        info = {"framing": framing, "tables": [enc, dec], "alpn": alpn.decode("ascii", "replace"),
                "sni": flow.client_conn.sni}
        flow.metadata["apns"] = dict(info, messages=[])
        self._write(dict(info, kind="flow", flow=flow.id, t=flow.client_conn.timestamp_start,
                         server=list(flow.server_conn.address or [])))
        logging.info(f"[apns] courier flow {flow.server_conn.address} sni={flow.client_conn.sni} "
                     f"alpn={alpn!r} -> {framing} framing")

    def tcp_message(self, flow: tcp.TCPFlow):
        st = self.state.get(flow.id)
        if st is None:
            return
        m = flow.messages[-1]
        direction = "c2s" if m.from_client else "s2c"
        self._write({"kind": "raw", "flow": flow.id, "dir": direction, "t": m.timestamp, "hex": m.content.hex()})
        d = st[direction]
        for msg in d.feed(m.content):
            rec = message_to_dict(msg, redact_data=False)
            rec["t"] = m.timestamp
            flow.metadata["apns"]["messages"].append(rec)
            self._write(dict(rec, kind="message", flow=flow.id, server=list(flow.server_conn.address or [])))
            logging.info("[apns] " + format_message(msg, ctx.options.apns_redact))
        if d.broken and not flow.metadata["apns"].get("error"):
            flow.metadata["apns"]["error"] = f"{d.direction}: {d.broken}"
            logging.warning(f"[apns] decoder stopped on flow {flow.id}: {d.direction}: {d.broken}")

    def tcp_end(self, flow: tcp.TCPFlow):
        self._end(flow, flow.metadata.get("apns", {}).get("error"))

    def tcp_error(self, flow: tcp.TCPFlow):
        if flow.id in self.state:
            logging.warning(f"[apns] courier flow error: {flow.error}")
        self._end(flow, str(flow.error))

    def _end(self, flow: tcp.TCPFlow, error: str | None):
        if self.state.pop(flow.id, None) is not None:
            self._write({"kind": "end", "flow": flow.id, "error": error,
                         "t": flow.server_conn.timestamp_end or flow.client_conn.timestamp_end})

    def _write(self, rec: dict):
        if self.out:
            self.out.write(json.dumps(rec) + "\n")
            self.out.flush()


if HAVE_MITMPROXY:
    addons = [APNS()]


# =========================================================================== offline decoding

def decode_chunks(c2s_chunks, s2c_chunks, framing: str, enc: int, dec: int, full: bool = False) -> list[str]:
    """chunks: [(timestamp, bytes)].  Decodes each direction in order -> output lines, merged by
    time (a decoder that stopped is reported first)."""
    lines, out = [], []
    for direction, chunks, size in (("c2s", c2s_chunks, enc), ("s2c", s2c_chunks, dec)):
        d = StreamDecoder(direction, framing, size)
        for t, b in chunks:
            out += [(t, m) for m in d.feed(b)]
        if d.broken:
            lines.append(f"   !! {direction} decoder stopped: {d.broken}")
    return lines + [f"   {t:.3f} " + format_message(m, redact_data=not full)
                    for t, m in sorted(out, key=lambda x: x[0])]


def decode_flow(flow: tcp.TCPFlow, full: bool = False) -> tuple[str, list[str]]:
    """Decode one saved courier TCPFlow (e.g. from a .mitm file) -> (framing, output lines).
    Used by this file's .mitm mode and by ios_decoder.report."""
    framing, enc, dec = framing_from_alpn(flow_alpn(flow))
    return framing, decode_chunks([(m.timestamp, m.content) for m in flow.messages if m.from_client],
                                  [(m.timestamp, m.content) for m in flow.messages if not m.from_client],
                                  framing, enc, dec, full)


def print_lines(lines: list[str]):
    for line in lines:
        print(line)


def decode_mitm_file(path: str, full: bool):
    """Every APNs courier flow in a .mitm capture (needs mitmproxy)."""
    from mitmproxy import io
    with open(path, "rb") as f:
        for fl in io.FlowReader(f).stream():
            if not (isinstance(fl, tcp.TCPFlow) and is_courier(fl)):
                continue
            framing, lines = decode_flow(fl, full)
            print(f"== flow {fl.id} {fl.server_conn.address} sni={fl.client_conn.sni or ''} alpn={flow_alpn(fl)!r} -> {framing}")
            print_lines(lines)


def decode_jsonl_file(path: str, full: bool):
    """The raw records of the addon's apns_log; covers connections missing from the .mitm file."""
    flows, raw = {}, {}
    with open(path) as f:
        for line in f:
            r = json.loads(line)
            if r.get("kind") == "flow":
                flows[r["flow"]] = r
            elif r.get("kind") == "raw":
                raw.setdefault(r["flow"], {"c2s": [], "s2c": []})[r["dir"]].append((r["t"], bytes.fromhex(r["hex"])))
    for fid, chunks in raw.items():
        info = flows.get(fid)
        if info is None:
            print(f"== flow {fid}: no flow record, skipped")
            continue
        enc, dec = info["tables"]
        print(f"== flow {fid} {tuple(info['server'])} sni={info['sni']} alpn={info['alpn']!r} -> {info['framing']}")
        print_lines(decode_chunks(chunks["c2s"], chunks["s2c"], info["framing"], enc, dec, full))


def decode_streams_dir(path: str, framing: str, full: bool):
    """DIR/<name>.{c2s,s2c}.bin: the plaintext bytes of each direction of one connection."""
    def read(p):
        with open(p, "rb") as f:
            return f.read()
    for c2s in sorted(glob.glob(os.path.join(path, "*.c2s.bin"))):
        s2c = c2s.replace(".c2s.bin", ".s2c.bin")
        print(f"== {os.path.basename(c2s)[:-8]} ({framing})")
        print_lines(decode_chunks([(0, read(c2s))], [(1, read(s2c))] if os.path.exists(s2c) else [],
                                  framing, 4096, 4096, full))


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(prog="apns_mitm.py", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("capture", nargs="?", help="a .mitm capture file")
    src.add_argument("--jsonl", metavar="FILE", help="the addon's apns_log (raw records); no mitmproxy needed")
    src.add_argument("--streams", metavar="DIR", help="DIR/<name>.{c2s,s2c}.bin: plaintext of each direction")
    ap.add_argument("--serial", action="store_true", help="with --streams: serial instead of packed encoding")
    ap.add_argument("--packed", action="store_true", help=argparse.SUPPRESS)   # the default; old flag
    ap.add_argument("--full", action="store_true", help="print byte values in full instead of shortened")
    a = ap.parse_args(argv)
    if a.jsonl:
        decode_jsonl_file(a.jsonl, a.full)
    elif a.streams:
        decode_streams_dir(a.streams, "serial" if a.serial else "packed", a.full)
    else:
        if not HAVE_MITMPROXY:
            ap.error("reading a .mitm file needs mitmproxy (or use --jsonl)")
        decode_mitm_file(a.capture, a.full)


if __name__ == "__main__":
    main()
