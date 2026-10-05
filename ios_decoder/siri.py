"""Siri TCP-flow decoding — the ACE stream + HTTP/2/gRPC transports.

Siri does not ride normal HTTP; mitmproxy records it as a raw ``TCPFlow``.  This module
replaces the old addon's tangled ``Siri`` / ``decodeSiri`` classes, fixing their three
structural faults:

  1. **Detect on content, not IP.**  The old code keyed on guzzoni's literal IP.  Here a
     flow is recognised from its *client* stream prefix — ``ACE /ace HTTP/1`` for the ACE
     stream, the ``PRI * HTTP/2.0`` preface for HTTP/2 — so it is portable and never
     mis-decodes the unrelated TCP flows that share a capture.
  2. **Work per direction, not per TCP segment.**  Each direction is concatenated and
     decoded as one stream (the ``AA CC EE`` magic can straddle a segment boundary, and a
     zlib / HPACK stream is inherently per-direction and stateful).
  3. **No shared state.**  All decoder state is local to one call, so concurrent
     connections in a capture can never corrupt each other.

Public entry point: :func:`decode_tcp_flow` — give it a flow's ``(from_client, bytes)``
segments; it returns decoded text, or ``None`` if the flow isn't Siri (caller dumps raw).
"""

from __future__ import annotations

import gzip
import plistlib
import struct
import zlib
from typing import Optional

from . import certs, nested, protobuf
from .httputil import indent

__all__ = ["decode_tcp_flow", "decode_ace_flow", "decode_h2_flow",
           "looks_like_ace", "looks_like_h2", "split_directions"]

# --- transport detection (portable: content, not address) --------------------

H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
ACE_MAGIC = bytes([0xAA, 0xCC, 0xEE])


def looks_like_h2(client_stream: bytes) -> bool:
    """True if the client opened an HTTP/2 connection (the fixed preface)."""
    return client_stream.startswith(H2_PREFACE)


def looks_like_ace(client_stream: bytes) -> bool:
    """True if the client opened a Siri ACE stream (``ACE /ace HTTP/1.x`` request line)."""
    return client_stream[:20].startswith(b"ACE /ace HTTP/1")


def split_directions(messages) -> tuple[bytes, bytes]:
    """Concatenate a TCP flow's segments into (client→server, server→client) byte streams.

    Both Siri transports compress each direction independently, so decoding works on the
    per-direction concatenation rather than individual segments.
    """
    client = b"".join(c for from_client, c in messages if from_client)
    server = b"".join(c for from_client, c in messages if not from_client)
    return client, server


def decode_tcp_flow(messages) -> Optional[str]:
    """Decode a Siri TCP flow, or return ``None`` if it isn't Siri.

    ``messages`` is an ordered list of ``(from_client: bool, content: bytes)`` segments
    (e.g. ``[(m.from_client, m.content) for m in tcpflow.messages]``).
    """
    client, server = split_directions(messages)
    h2, ace = looks_like_h2(client), looks_like_ace(client)
    if h2 and ace:
        # both transport signatures present — shouldn't happen; flag rather than silently pick
        return ("// WARNING: client stream matches BOTH HTTP/2 and ACE signatures; "
                "decoding as HTTP/2\n" + decode_h2_flow(client, server))
    if h2:
        return "// transport: HTTP/2 gRPC (Siri)\n" + decode_h2_flow(client, server)
    if ace:
        return "// transport: ACE stream (Siri)\n" + decode_ace_flow(client, server)
    return None


# --- ACE stream --------------------------------------------------------------

# ACE packet type byte (first byte of each 5-byte packet header).
_ACE_NOP, _ACE_PLIST, _ACE_PING, _ACE_PONG, _ACE_SPEECH = 0, 2, 3, 4, 7
_ACE_TRIVIAL = {_ACE_NOP: "nop", _ACE_PING: "ping", _ACE_PONG: "pong"}


def decode_ace_flow(client: bytes, server: bytes) -> str:
    """Decode both directions of an ACE stream to readable text."""
    out = []
    for label, stream in (("client → server", client), ("server → client", server)):
        out.append(f"  {label}:")
        out.append(_decode_ace_direction(stream))
    return "\n".join(out)


def _decode_ace_direction(stream: bytes) -> str:
    body = _strip_http_preamble(stream)
    i = body.find(ACE_MAGIC)
    if i < 0:
        return "    (no ACE stream header found)"
    comptype = body[i + 3]
    raw = body[i + 4:]
    data, warn = _ace_decompress(raw, comptype)
    if data is None:
        return f"    // ERROR: ACE decompress failed (comptype={comptype}): {warn}"
    lines = []
    if warn:
        lines.append(f"    // WARNING: {warn}")
    consumed = 0
    for pkt in _iter_ace_packets(data):
        if pkt[0] == "unknown":
            lines.append(f"    // WARNING: unknown ACE packet type {pkt[1]} at "
                         f"offset {pkt[2]}; stopping (cannot trust framing)")
            break
        if pkt[0] == "truncated":
            lines.append(f"    // WARNING: truncated ACE packet "
                         f"(declared {pkt[1]}B, have {pkt[2]}B)")
            break
        ptype, payload, consumed = pkt
        lines.append(_render_ace_packet(ptype, payload))
    if consumed < len(data):
        lines.append(f"    // note: {len(data) - consumed} trailing byte(s) "
                     f"after last packet (possible second stream / partial capture)")
    return "\n".join(lines) if lines else "    (empty stream)"


def _strip_http_preamble(stream: bytes) -> bytes:
    """Drop the ``ACE /ace …`` request / ``HTTP/1.1 200`` response headers (up to CRLFCRLF)."""
    j = stream.find(b"\r\n\r\n")
    return stream[j + 4:] if j >= 0 else stream


def _ace_decompress(raw: bytes, comptype: int) -> tuple[Optional[bytes], str]:
    """Decompress an ACE payload.  ``comptype`` 0 = none; otherwise sniff zlib/gzip.

    Returns ``(data, warning)``; ``data`` is None only on hard failure.  Content sniffing
    (not the comptype number) drives the choice, so it's robust to a new comptype value.
    """
    if comptype == 0:
        # declared uncompressed — flag if the bytes nonetheless carry a compression signature
        if raw[:2] == b"\x1f\x8b":
            return raw, "comptype=0 (uncompressed) but payload has a gzip signature"
        if len(raw) >= 2 and raw[0] == 0x78 and raw[1] in (0x01, 0x9C, 0xDA):
            return raw, "comptype=0 (uncompressed) but payload has a zlib signature"
        return raw, ""
    try:
        if raw[:2] == b"\x1f\x8b":
            return gzip.decompress(raw), ""
        # zlib stream (78 xx); decompressobj tolerates trailing bytes
        return zlib.decompressobj().decompress(raw), ""
    except (zlib.error, OSError) as e:
        return None, f"{type(e).__name__}: {e}"


def _iter_ace_packets(data: bytes):
    """Yield ACE packets ``(ptype, payload, end_offset)`` from the decompressed stream.

    On a bad type byte or a length that overruns the buffer, yields a sentinel
    (``("unknown", ptype, off)`` / ``("truncated", declared, have)``) and stops — we never
    guess past framing we can't trust.
    """
    p = 0
    n = len(data)
    while p + 5 <= n:
        ptype = data[p]
        plen = struct.unpack("!I", data[p + 1:p + 5])[0]
        if ptype not in (_ACE_NOP, _ACE_PLIST, _ACE_PING, _ACE_PONG, _ACE_SPEECH):
            yield ("unknown", ptype, p)
            return
        end = p + 5 + plen
        if end > n:
            yield ("truncated", plen, n - (p + 5))
            return
        yield (ptype, data[p + 5:end], end)
        p = end


def _render_ace_packet(ptype: int, payload: bytes) -> str:
    if ptype in _ACE_TRIVIAL:
        return f"    {_ACE_TRIVIAL[ptype]}"
    if ptype == _ACE_PLIST:
        return _render_ace_object(payload)
    if ptype == _ACE_SPEECH:
        return _render_speech(payload)
    return f"    <packet type {ptype}, {len(payload)} bytes>"


def _render_ace_object(payload: bytes) -> str:
    """Render an ACE plist packet: surface ``$class``/``$group``/``$v``, expand fields."""
    try:
        obj = plistlib.loads(payload)
    except Exception as e:                       # plistlib raises various types
        return f"    // ERROR: ACE plist parse failed: {type(e).__name__}: {e}"
    obj = _unwrap_keyed_archiver(obj)
    if not isinstance(obj, dict):
        return "    plist: " + nested.render(obj, indent=2)
    cls = obj.get("$class", "<object>")
    meta = []
    if obj.get("$group"):
        meta.append(f"group={obj['$group']}")
    if "$v" in obj:
        meta.append(f"v={obj['$v']}")
    header = f"    ACE {cls}" + (f" ({', '.join(meta)})" if meta else "")
    fields = {k: v for k, v in obj.items() if k not in ("$class", "$group", "$v")}
    if not fields:
        return header
    return header + " " + nested.render(fields, indent=2)


def _unwrap_keyed_archiver(obj):
    """If ``obj`` is an NSKeyedArchiver graph, resolve it to the top object; else return as-is.

    Siri's ACE plists are the flat ``$class``/``$group`` format, not NSKeyedArchiver — but
    handle the archiver form too so a stray one renders cleanly rather than as UID soup.
    """
    if not (isinstance(obj, dict) and obj.get("$archiver") == "NSKeyedArchiver"):
        return obj
    objects = obj.get("$objects", [])

    def resolve(node, seen):
        if isinstance(node, plistlib.UID):
            idx = node.data
            if idx in seen or idx >= len(objects):     # cycle / out of range guard
                return None
            return resolve(objects[idx], seen | {idx})
        if isinstance(node, dict):
            return {k: resolve(v, seen) for k, v in node.items() if k != "$class"}
        if isinstance(node, list):
            return [resolve(v, seen) for v in node]
        return node

    top = obj.get("$top", {})
    resolved = resolve(top.get("root", top), set()) if isinstance(top, dict) else None
    return resolved if resolved is not None else obj


def _render_speech(payload: bytes) -> str:
    """Summarize a speech packet: refId + Opus-frame count / size.

    Layout (verified against captured Siri voice traffic — 120/120 packets consume
    exactly): ``<1B refId len><refId><2B BE seq><2B BE nframes><nframes × (2B BE len +
    opus frame)>``.  ``seq`` is a cumulative frame index (steps by ``nframes`` per packet);
    frames are raw Opus (we count/size them rather than decode audio).
    """
    try:
        ref_len = payload[0]
        ref_id = payload[1:1 + ref_len].decode("utf-8", "replace")
        q = 1 + ref_len
        seq = int.from_bytes(payload[q:q + 2], "big")
        nframes = int.from_bytes(payload[q + 2:q + 4], "big")
        q += 4
        frames = 0
        total = 0
        for _ in range(nframes):
            if q + 2 > len(payload):
                break
            ln = int.from_bytes(payload[q:q + 2], "big")
            q += 2
            if q + ln > len(payload):
                break
            frames += 1
            total += ln
            q += ln
        # the loop breaks early on a short buffer; say so rather than showing a clean count
        trunc = "  (TRUNCATED — declared frames not all present)" if frames < nframes else ""
        return (f"    <speech: refId={ref_id!r}, seq={seq}, {frames}/{nframes} "
                f"opus frames, {total} audio bytes>{trunc}")
    except Exception:
        return f"    <speech: {len(payload)} bytes, structure unrecognized>"


# --- HTTP/2 + gRPC (passive frame + HPACK parser) ----------------------------

# Frame type bytes.
_FRAME_DATA, _FRAME_HEADERS, _FRAME_CONTINUATION = 0x0, 0x1, 0x9
# Flags.
_FLAG_END_HEADERS, _FLAG_PADDED, _FLAG_PRIORITY = 0x4, 0x8, 0x20


def decode_h2_flow(client: bytes, server: bytes) -> str:
    """Decode an HTTP/2 (gRPC) flow passively: HPACK headers + gRPC DATA per stream.

    Uses a hand-rolled frame parser rather than the ``h2`` library, which rejects captured
    byte streams (it enforces the active-connection state machine — flow control, settings
    ACKs, stream lifecycle).  We only need to read frames, so a passive parser is both
    simpler and robust.
    """
    try:
        from hpack import Decoder
    except ImportError:                          # pragma: no cover - dependency present
        return "  // HTTP/2 flow not decoded: hpack library not installed"

    req = _decode_h2_direction(client[len(H2_PREFACE):] if looks_like_h2(client) else client,
                               Decoder())
    res = _decode_h2_direction(server, Decoder())

    stream_ids = sorted(set(req.headers) | set(res.headers)
                        | set(req.data) | set(res.data))
    if not stream_ids:
        return "  (no HTTP/2 streams decoded)"
    out = []
    for sid in stream_ids:
        out.append(_render_h2_stream(sid, req, res))
    return "\n".join(out)


class _H2Side:
    """Decoded one direction of an HTTP/2 connection: per-stream headers + DATA."""

    def __init__(self):
        self.headers: dict[int, list[tuple[str, str]]] = {}
        self.data: dict[int, bytearray] = {}


def _decode_h2_direction(data: bytes, decoder) -> _H2Side:
    side = _H2Side()
    pending_sid: Optional[int] = None
    pending_block = bytearray()

    def emit_headers(sid: int, block: bytes):
        try:
            hdrs = decoder.decode(bytes(block))
        except Exception as e:                   # HPACK desync / bad data
            side.headers.setdefault(sid, []).append(("// hpack-error", f"{type(e).__name__}"))
            return
        side.headers.setdefault(sid, []).extend(
            (_as_str(k), _as_str(v)) for k, v in hdrs)

    for typ, flags, sid, payload in _iter_h2_frames(data):
        if typ == _FRAME_HEADERS:
            block = _strip_header_padding(payload, flags)
            if flags & _FLAG_END_HEADERS:
                emit_headers(sid, block)
            else:
                pending_sid, pending_block = sid, bytearray(block)
        elif typ == _FRAME_CONTINUATION and pending_sid == sid:
            pending_block.extend(payload)
            if flags & _FLAG_END_HEADERS:
                emit_headers(sid, pending_block)
                pending_sid = None
        elif typ == _FRAME_DATA:
            block = payload
            if flags & _FLAG_PADDED:
                pad = block[0]
                block = block[1:len(block) - pad]
            side.data.setdefault(sid, bytearray()).extend(block)
    return side


def _iter_h2_frames(data: bytes):
    """Yield ``(type, flags, stream_id, payload)`` for each complete HTTP/2 frame."""
    p = 0
    n = len(data)
    while p + 9 <= n:
        length = int.from_bytes(data[p:p + 3], "big")
        typ = data[p + 3]
        flags = data[p + 4]
        sid = int.from_bytes(data[p + 5:p + 9], "big") & 0x7FFFFFFF
        if p + 9 + length > n:                    # truncated final frame
            return
        yield typ, flags, sid, data[p + 9:p + 9 + length]
        p += 9 + length


def _strip_header_padding(payload: bytes, flags: int) -> bytes:
    block = payload
    if flags & _FLAG_PADDED:
        pad = block[0]
        block = block[1:len(block) - pad]
    if flags & _FLAG_PRIORITY:
        block = block[5:]                         # 4-byte stream dep + 1-byte weight
    return block


def _as_str(v) -> str:
    return v.decode("utf-8", "replace") if isinstance(v, (bytes, bytearray)) else str(v)


def _render_h2_stream(sid: int, req: _H2Side, res: _H2Side) -> str:
    lines = []
    rh = dict(req.headers.get(sid, []))
    sh = dict(res.headers.get(sid, []))
    method = rh.get(":method", "?")
    path = rh.get(":path", "?")
    status = sh.get(":status", "?")
    lines.append(f"  stream {sid}: {method} {path} → {status}")
    if req.data.get(sid):
        lines.append("    request:")
        lines.append(_render_grpc(bytes(req.data[sid])))
    if res.data.get(sid):
        lines.append("    response:")
        lines.append(_render_grpc(bytes(res.data[sid])))
    grpc_status = sh.get("grpc-status")
    if grpc_status not in (None, "0"):
        lines.append(f"    // grpc-status: {grpc_status} "
                     f"{sh.get('grpc-message', '')}".rstrip())
    return "\n".join(lines)


def _render_grpc(data: bytes) -> str:
    """Render the gRPC length-prefixed messages in a DATA stream.

    Most Siri gRPC bodies are protobuf, but some sidecar methods (AuthSession
    GetCertificate / CreateSession) carry **FlatBuffers**, not protobuf.  When the protobuf
    decode fails we surface the decompressed bytes (with a format hint) rather than only an
    error — the analyst still sees the payload.  Compression is detected from the gzip magic
    (and the gRPC compressed-flag), so a ``grpc-encoding`` header isn't needed.
    """
    out = []
    for compressed, msg in _iter_grpc_messages(data):
        if compressed or msg[:2] == b"\x1f\x8b":
            try:
                msg = gzip.decompress(msg)
            except OSError as e:
                out.append(f"      // ERROR: gRPC gunzip failed: {e}")
                continue
        if not msg:
            out.append("      (empty message)")
            continue
        try:
            text = protobuf.decode_to_text(msg)
            out.append(indent(text, 6) if text.strip() else "      (empty message)")
        except protobuf.DecodeError:
            out.append(_render_non_protobuf(msg))
    if not out:
        out.append(f"      <{len(data)} bytes, no gRPC frame>")
    return "\n".join(out)


def _render_non_protobuf(msg: bytes) -> str:
    """A gRPC message that isn't protobuf: try a real decode before ever guessing a format.

    The AuthSession sidecar methods (``GetCertificate``/``CreateSession``) wrap their
    payload in a small non-protobuf envelope — often FlatBuffers-*shaped* — but the actual
    content of interest (an X.509 certificate chain) is real DER data embedded a few bytes
    in, not something the envelope's shape can tell you. Content-check for that first: a
    successful certificate decode is proof, not a guess, and it means we never hide
    genuinely-decodable data behind a "not decoded" hex dump just because the wrapper looks
    like something else. Only once no known structure is actually found do we fall back to
    the FlatBuffers-shape hint, which stays a labelled estimate (never a decode) since we
    don't have Apple's ``.fbs`` schema to decode FlatBuffers for real.
    """
    embedded = certs.try_decode_embedded_certificates(msg)
    if embedded is not None:
        return (f"      // not protobuf — X.509 certificate(s) found inside a "
                 f"{len(msg)}-byte non-protobuf envelope:\n" + indent(embedded, 6))
    hint = " — appears to be FlatBuffers (heuristic, not decoded)" \
        if _looks_flatbuffer(msg) else " — unrecognized binary format"
    return (f"      // not protobuf{hint}; {len(msg)} bytes shown as hex:\n"
            + _hex_preview(msg, 6))


def _looks_flatbuffer(b: bytes) -> bool:
    """Heuristic FlatBuffers check (estimate, not proof).

    Validates the root structure, not just a leading offset: the root ``uint32`` must point
    to a table whose backward ``soffset`` lands on a self-consistent, in-bounds vtable
    (``vtable_size``/``table_size`` even, ≥4, within the buffer).  This rejects the random
    binary that a bare leading-offset test would mislabel, so the output hint is trustworthy.
    Verified to accept the real Siri AuthSession FlatBuffers and reject arbitrary blobs.
    """
    n = len(b)
    if n < 12:
        return False
    root = int.from_bytes(b[:4], "little")
    if root % 4 or not (4 <= root <= n - 4):
        return False
    soffset = int.from_bytes(b[root:root + 4], "little", signed=True)
    vt = root - soffset
    if not (0 <= vt <= n - 4):
        return False
    vt_size = int.from_bytes(b[vt:vt + 2], "little")
    tbl_size = int.from_bytes(b[vt + 2:vt + 4], "little")
    return not (vt_size < 4 or vt_size % 2 or vt + vt_size > n
                or tbl_size < 4 or root + tbl_size > n)


def _hex_preview(b: bytes, indent: int, max_bytes: int = 64) -> str:
    pad = " " * indent
    shown = b[:max_bytes]
    rows = []
    for off in range(0, len(shown), 16):
        chunk = shown[off:off + 16]
        hexpart = " ".join(f"{c:02x}" for c in chunk)
        ascii_part = "".join(chr(c) if 0x20 <= c < 0x7F else "." for c in chunk)
        rows.append(f"{pad}{off:04x}  {hexpart:<47}  {ascii_part}")
    if len(b) > max_bytes:
        rows.append(f"{pad}… ({len(b) - max_bytes} more bytes)")
    return "\n".join(rows)


def _iter_grpc_messages(data: bytes):
    """Yield ``(compressed_flag, message_bytes)`` for each gRPC length-prefixed message."""
    p = 0
    n = len(data)
    while p + 5 <= n:
        compressed = data[p]
        length = int.from_bytes(data[p + 1:p + 5], "big")
        if p + 5 + length > n:
            return
        yield bool(compressed & 1), data[p + 5:p + 5 + length]
        p += 5 + length


