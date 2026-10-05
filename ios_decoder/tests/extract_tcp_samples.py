#!/usr/bin/env python3
"""Extract representative TCP flows from .mitm captures into test fixtures.

Siri rides raw TCP (mitmproxy records it as a ``TCPFlow``, not an ``HTTPFlow``),
in two distinct transports — and captures also contain *unrelated* TCP flows that
must NOT be mistaken for Siri.  This tool curates a small, category-labelled set so
the decoder can be built and verified against real bytes:

  * ``guzzoni-ace``   — the ACE stream protocol (magic ``AA CC EE``, per-direction
                        zlib, plist/ping/pong/speech packets);
  * ``swallow-h2``    — HTTP/2 + gRPC (the Siri sidecar auth / instrumentation);
  * ``guzzoni-plain`` — a guzzoni TCP flow with NO ACE magic (edge case);
  * ``non-siri``      — genuine unrelated TCP (the contamination to reject).

The extracted bytes contain real device identifiers / auth material, so the output
dir is git-ignored (like the .mitm captures themselves).  This script is committed
and deterministic, so the fixtures can always be regenerated:

    ./venv/bin/python3 -m ios_decoder.tests.extract_tcp_samples

Each flow is written as ``<category>__<n>/`` containing ``meta.json`` plus one file
per TCP segment, ``NNN_<C|S>.bin`` (C = client→server, S = server→client), so both
the concatenated per-direction stream *and* the original segmentation (for
chunk-boundary tests) are preserved.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from mitmproxy import io
from mitmproxy.tcp import TCPFlow

PRI = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
ACE = bytes([0xAA, 0xCC, 0xEE])

# Captures known to hold each category (relative to repo root). Kept explicit and
# small so extraction is fast and deterministic rather than scanning multi-GB files.
CAPTURES = [
    "iphone12_data/captures/mitm_24feb.mitm",
    "iphone12_data/captures/mitm_24feb_cont2.mitm",
    "iphone12_data/captures/cookies_default_5dec2025_cont5.mitm",
    "iphone12_data/captures/cookies_default_7dec2025_cont6.mitm",
    "iphone8_data/captures/doug_voice_tcp.mitm",   # ACE flow with speech packets
]

# How many flows to keep per category, and the byte ceiling (smallest first) so
# fixtures stay lightweight.  ``guzzoni-speech`` = an ACE flow that carries voice (type-7)
# packets, kept separately so the speech path is always covered by a real fixture.
PER_CATEGORY = {"guzzoni-ace": 2, "guzzoni-speech": 1, "swallow-h2": 2,
                "guzzoni-plain": 1, "non-siri": 2}
MAX_BYTES = 60_000


def _host(flow: TCPFlow) -> str:
    sc = flow.server_conn
    sni = getattr(sc, "sni", None)
    if isinstance(sni, bytes):
        sni = sni.decode("ascii", "replace")
    addr = sc.peername or sc.address
    return sni or (addr[0] if addr else "?")


def _has_speech(flow: TCPFlow) -> bool:
    """True if the ACE flow's client stream carries a voice (type-7) packet."""
    from ios_decoder import siri
    client = b"".join(m.content for m in flow.messages if m.from_client)
    body = client[client.find(b"\r\n\r\n") + 4:]
    i = body.find(ACE)
    if i < 0:
        return False
    data, _ = siri._ace_decompress(body[i + 4:], body[i + 3])
    if data is None:
        return False
    return any(pkt[0] == siri._ACE_SPEECH for pkt in siri._iter_ace_packets(data))


def _classify(flow: TCPFlow) -> str:
    from ios_decoder import siri
    host = _host(flow)
    client = b"".join(m.content for m in flow.messages if m.from_client)
    if siri.looks_like_h2(client):
        return "swallow-h2" if "swallow" in host else "h2-other"
    if siri.looks_like_ace(client):
        if "guzzoni" not in host:
            return "ace-other"
        return "guzzoni-speech" if _has_speech(flow) else "guzzoni-ace"
    if "guzzoni" in host:
        return "guzzoni-plain"
    return "non-siri"


def _total(flow: TCPFlow) -> int:
    return sum(len(m.content) for m in flow.messages)


def collect(repo: Path) -> dict[str, list[TCPFlow]]:
    by_cat: dict[str, list[TCPFlow]] = {}
    for rel in CAPTURES:
        path = repo / rel
        if not path.exists():
            print(f"  (skip, not present: {rel})", file=sys.stderr)
            continue
        with open(path, "rb") as fh:
            for flow in io.FlowReader(fh).stream():
                if not isinstance(flow, TCPFlow) or not flow.messages:
                    continue
                cat = _classify(flow)
                if cat not in PER_CATEGORY or _total(flow) > MAX_BYTES:
                    continue
                flow._origin = rel  # type: ignore[attr-defined]
                by_cat.setdefault(cat, []).append(flow)
    # smallest first, capped per category
    for cat, flows in by_cat.items():
        flows.sort(key=_total)
        by_cat[cat] = flows[: PER_CATEGORY[cat]]
    return by_cat


def write_flow(flow: TCPFlow, dest: Path) -> dict:
    dest.mkdir(parents=True, exist_ok=True)
    seg_meta = []
    for i, m in enumerate(flow.messages):
        side = "C" if m.from_client else "S"
        (dest / f"{i:03d}_{side}.bin").write_bytes(m.content)
        seg_meta.append({"i": i, "dir": side, "len": len(m.content)})
    meta = {
        "host": _host(flow),
        "port": (flow.server_conn.peername or flow.server_conn.address or [None, None])[1],
        "origin": getattr(flow, "_origin", "?"),
        "segments": seg_meta,
        "client_bytes": sum(len(m.content) for m in flow.messages if m.from_client),
        "server_bytes": sum(len(m.content) for m in flow.messages if not m.from_client),
    }
    (dest / "meta.json").write_text(json.dumps(meta, indent=2))
    return meta


def main() -> None:
    repo = Path(__file__).resolve().parents[2]
    out = repo / "ios_decoder" / "tests" / "fixtures" / "siri_real"
    out.mkdir(parents=True, exist_ok=True)
    by_cat = collect(repo)
    manifest = []
    for cat, flows in sorted(by_cat.items()):
        for n, flow in enumerate(flows):
            name = f"{cat}__{n}"
            meta = write_flow(flow, out / name)
            manifest.append({"name": name, **meta})
            print(f"  {name:18s} {meta['host']:28s} "
                  f"C={meta['client_bytes']:6d} S={meta['server_bytes']:6d} "
                  f"segs={len(meta['segments'])}  ({meta['origin']})")
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2))
    print(f"\n{len(manifest)} flow(s) -> {out}")


if __name__ == "__main__":
    main()
