#!/usr/bin/env python3
"""Extract a small, representative set of real request bodies from .mitm captures.

Two kinds are written, so the live-gated tests no longer have to scan whole captures:

  * ``fixtures/arpc_real/``  — LZ4-compressed ARPC requests (``hvr`` uploads).  Consumed by
    ``test_arpc_decompress.py``: every body must decompress cleanly into genuine protobuf.
    Multi-block uploads (the inter-block-dictionary path) are always kept.
  * ``fixtures/fb_real/``    — ``fbs.smoot.apple.com/fb`` request bodies.  Consumed by
    ``test_fb.py`` and ``test_matcher_crosscheck.py``.  A few distinct bodies per ``?type=``
    channel, spread across the size range.

The output dirs are committed and the captures themselves stay git-ignored.  Bodies that look
like personal activity are excluded before selection (see :func:`personal_reason`: location
fixes, Wi-Fi/MAC fields, non-Apple URLs), so what is committed is plain telemetry.  Selection
is deterministic, so the fixtures can always be regenerated:

    ./venv/bin/python3 -m ios_decoder.tests.extract_request_samples [--root DIR]

``--root`` is the directory that holds ``iphone8_data/captures``, ``iphone12_data/captures``
and ``ios_decoder/comparison`` (default: this repo's root).  Each output dir gets a
``manifest.json`` recording, per body, the URL, size and source capture file name.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import re
import sys
import tempfile
import urllib.parse
from pathlib import Path

from mitmproxy import io

from ios_decoder import arpc, fb, rawproto
from ios_decoder.decode import decode_request_body
from ios_decoder.endpoints import DecodeContext, default_table
from ios_decoder.paths import DEFAULT_PROTO_DIRS
from ios_decoder.schemas import SchemaRegistry

# How many distinct bodies to keep.  /fb: per ?type= channel; ARPC: per URL path.
FB_PER_TYPE = {"FeedbackV2PB": 6, "Usage": 2, "ProactiveEventTracker": 3,
               "DuetExpert": 2, "ProactiveEventTrackerAggregated": 1}
FB_DEFAULT = 2
ARPC_PER_URL = 12
# Fixtures are committed, so skip any single body larger than this.
MAX_BYTES = 30_000


def _capture_paths(root: Path) -> list[str]:
    return (sorted(glob.glob(str(root / "ios_decoder" / "comparison" / "*.mitm")))
            + sorted(glob.glob(str(root / "iphone8_data" / "captures" / "*.mitm")))
            + sorted(glob.glob(str(root / "iphone12_data" / "captures" / "*.mitm"))))


# lat/lon-like numbers (>= 6 decimals, not embedded in a longer number such as a version string)
_COORDS = re.compile(r"(?<![\d.])-?\d{1,3}\.\d{6,}(?!\d)")
_WIFI_FIELD = re.compile(r"(?i)\b(bssid|macid|mac)\b")
# a MAC address value: padded (aa:bb:..., aa-bb-...) or unpadded (a:b:c:d:e:f)
_MAC_VALUE = re.compile(r"(?i)(?<![0-9a-f:-])(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}(?![0-9a-f])"
                        r"|(?<![0-9a-f:])(?:[0-9a-f]{1,2}:){5}[0-9a-f]{1,2}(?![0-9a-f:])")
_URL = re.compile(r"https?://[A-Za-z0-9._~:/?#@!$&'()*+,;=%-]{4,}")


def personal_reason(url: str, body: bytes, ctx, table) -> str | None:
    """Why this body looks like personal activity, or None if it is plain telemetry.

    Excluded so the committed fixtures stay boring: location fixes (coordinate-like numbers),
    Wi-Fi/MAC fields, and anything that records browsing (a URL whose host is not Apple's).
    Checked on the decoded text, so named fields inside compressed ARPC payloads are seen too.
    """
    try:
        text = decode_request_body(url, body, table, ctx) or ""
    except Exception:
        text = ""
    if _COORDS.search(text):
        return "coordinate-like numbers"
    if _WIFI_FIELD.search(text) or _MAC_VALUE.search(text):
        return "Wi-Fi/MAC field or value"
    for u in _URL.findall(text) + [m.decode("latin1") for m in re.findall(rb"https?://[ -~]{4,}", body)]:
        host = urllib.parse.urlsplit(u).hostname or ""
        if not (host == "apple.com" or host.endswith(".apple.com")):
            return f"non-Apple URL ({host})"
    return None


def _filter_plain(cands: list[dict]) -> tuple[list[dict], dict[str, int]]:
    ctx = DecodeContext(schemas=SchemaRegistry(list(DEFAULT_PROTO_DIRS), cache_dir=tempfile.mkdtemp()))
    table = default_table()
    kept, dropped = [], {}
    for r in cands:
        why = personal_reason(r["url"], r["body"], ctx, table)
        if why is None:
            kept.append(r)
        else:
            key = why.split(" (")[0]
            dropped[key] = dropped.get(key, 0) + 1
    return kept, dropped


def _spread(items: list[dict], n: int) -> list[dict]:
    """n items spread evenly across the size range, always including the smallest and largest."""
    items = sorted(items, key=lambda r: (r["bytes"], r["capture"], r["idx"]))
    if len(items) <= n:
        return items
    if n == 1:
        return [items[len(items) // 2]]
    picks = {round(i * (len(items) - 1) / (n - 1)) for i in range(n)}
    return [items[i] for i in sorted(picks)]


def collect(root: Path) -> tuple[list[dict], list[dict]]:
    """(arpc candidates, fb candidates): each a dict with url/body/bytes/capture/idx (+extras),
    de-duplicated by (url, body)."""
    arpc_c: dict[tuple, dict] = {}
    fb_c: dict[tuple, dict] = {}
    for cap in _capture_paths(root):
        name = os.path.basename(cap)
        try:
            fh = open(cap, "rb")
        except OSError:
            continue
        with fh:
            try:
                for idx, flow in enumerate(io.FlowReader(fh).stream()):
                    req = getattr(flow, "request", None)
                    if req is None:
                        continue
                    body = req.content or b""
                    if not body or len(body) > MAX_BYTES:
                        continue
                    url = req.pretty_url
                    rec = {"url": url, "body": body, "bytes": len(body), "capture": name, "idx": idx}
                    if "smoot.apple.com/fb" in url:
                        rec["type"] = fb.fb_type(url)
                        fb_c.setdefault((url, body), rec)
                    hdr = arpc.parse_request_header(body)
                    if hdr is not None and hdr.compression_algo:
                        pay = body[hdr.payload_offset:]
                        rec["function_id"] = hdr.function_id
                        rec["bv41_blocks"] = pay.count(b"bv41")
                        arpc_c.setdefault((url, body), rec)
            except Exception as e:                       # truncated capture etc.
                print(f"  (stopped reading {name}: {e!r})", file=sys.stderr)
    return list(arpc_c.values()), list(fb_c.values())


def select_arpc(cands: list[dict]) -> list[dict]:
    by_url: dict[str, list[dict]] = {}
    for r in cands:
        by_url.setdefault(r["url"], []).append(r)
    out = []
    for url in sorted(by_url):
        rs = by_url[url]
        multi = [r for r in rs if r["bv41_blocks"] > 1]          # always keep these
        rest = [r for r in rs if r["bv41_blocks"] <= 1]
        out += multi + _spread(rest, max(ARPC_PER_URL - len(multi), 1))
    return out


def select_fb(cands: list[dict]) -> list[dict]:
    by_type: dict[str, list[dict]] = {}
    for r in cands:
        by_type.setdefault(str(r["type"]), []).append(r)
    out = []
    for t in sorted(by_type):
        out += _spread(by_type[t], FB_PER_TYPE.get(t, FB_DEFAULT))
    return out


def write(out_dir: Path, picks: list[dict], extra_keys: tuple[str, ...]) -> list[dict]:
    out_dir.mkdir(parents=True, exist_ok=True)
    for old in out_dir.glob("*.bin"):
        old.unlink()
    manifest = []
    for i, r in enumerate(picks):
        fname = f"{i:03d}.bin"
        (out_dir / fname).write_bytes(r["body"])
        manifest.append({"file": fname, "url": r["url"], "bytes": r["bytes"], "capture": r["capture"],
                         **{k: r[k] for k in extra_keys if k in r}})
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    repo = Path(__file__).resolve().parents[2]
    ap.add_argument("--root", type=Path, default=repo, help="dir holding the capture directories")
    args = ap.parse_args(argv)
    fixtures = repo / "ios_decoder" / "tests" / "fixtures"

    arpc_cands, fb_cands = collect(args.root)
    print(f"candidates (distinct): ARPC-compressed={len(arpc_cands)}  fb={len(fb_cands)}")
    if not arpc_cands and not fb_cands:
        print("no captures found under", args.root, file=sys.stderr)
        return 1
    arpc_cands, dropped_a = _filter_plain(arpc_cands)
    fb_cands, dropped_f = _filter_plain(fb_cands)
    print(f"excluded as personal-looking: ARPC {dropped_a or 0}  fb {dropped_f or 0}")

    rc = 0
    picks = select_arpc(arpc_cands)
    man = write(fixtures / "arpc_real", picks, ("function_id", "bv41_blocks"))
    for m, r in zip(man, picks):
        hdr, payload, warn = arpc.strip_request(r["body"])
        ok = hdr is not None and warn is None and bool(payload) and rawproto.is_valid_protobuf(payload)
        rc |= 0 if ok else 1
        print(f"  arpc {m['file']} {m['bytes']:6d}B blocks={r['bv41_blocks']} {'OK' if ok else 'FAIL: ' + str(warn)}")
    print(f"{len(man)} ARPC fixture(s), {sum(m['bytes'] for m in man)} bytes -> {fixtures / 'arpc_real'}")

    picks = select_fb(fb_cands)
    man = write(fixtures / "fb_real", picks, ("type",))
    for m in man:
        print(f"  fb   {m['file']} {m['bytes']:6d}B type={m['type']}")
    print(f"{len(man)} fb fixture(s), {sum(m['bytes'] for m in man)} bytes -> {fixtures / 'fb_real'}")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
