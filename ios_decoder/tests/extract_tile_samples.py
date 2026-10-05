#!/usr/bin/env python3
"""Extract one real tile body of each type from .mitm captures into test fixtures.

The committed tile parsers were largely tested against synthetic data; this pulls a real
example of every tile type out of the captures so the live regression tests decode *actual*
Apple tile responses.  The bodies carry crowd-sourced location data; the output dir is
committed (the author judged it not sensitive; the captures themselves stay git-ignored).
This script is deterministic, so the fixtures can always be regenerated:

    ./venv/bin/python3 -m ios_decoder.tests.extract_tile_samples

Each found type is written to ``tests/fixtures/tiles_real/<type>.bin`` and validated by
decoding it through :func:`ios_decoder.tiles.decode_tile` (so a parser that breaks on real
data is caught here, not silently).  Output dir + manifest.json record source capture/URL.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

from mitmproxy import http, io

from ios_decoder import tiles

# tile type (registry name) → request-URL regex
PATTERNS = {
    "wifi":        r"cl2\.apple\.com/1/v1/[0-9]",
    "hrse":        r"cl3\.apple\.com/2/v1/[0-9]",
    "gsmcell":     r"cl2\.apple\.com/3/v1/[0-9]",
    "cldem":       r"cl3\.apple\.com/3/v2/[0-9]",
    "ltecell":     r"cl2\.apple\.com/4/v1/[0-9]",
    "global_gsm":  r"cl2\.apple\.com/6/v1/[0-9]",
    "global_cdma": r"cl2\.apple\.com/7/v1/[0-9]",
    "global_lte":  r"cl2\.apple\.com/8/v1/[0-9]",
    "global_5g":   r"cl2\.apple\.com/11/v1/[0-9]",
    "clsef":       r"cl3\.apple\.com/1/v2/clsef",
    "cldavl":      r"cl3\.apple\.com/3/v2/cldavl",
}

# Captures scanned, richest first (mitm_17feb_cont5 carries every tile type).
CAPTURES = [
    "iphone8_data/captures/mitm_17feb_cont5.mitm",
    "iphone8_data/captures/mitm_5mar_cont.mitm",
    "ios_decoder/comparison/subset_large.mitm",
    "iphone12_data/captures/cookies_default_7dec2025_cont6.mitm",
]

# Fixtures are committed, so keep them reasonably small; the cap only avoids an
# absurdly large body. The global cell tiles are inherently big (global_cdma ≈ 1 MB).
MAX_BYTES = 2_000_000


def collect(repo: Path) -> dict[str, tuple[bytes, str, str]]:
    """type -> (body, capture, url) for the first acceptable match of each type."""
    wanted = {k: re.compile(v) for k, v in PATTERNS.items()}
    out: dict[str, tuple[bytes, str, str]] = {}
    for rel in CAPTURES:
        if not wanted:
            break
        path = repo / rel
        if not path.exists():
            print(f"  (skip, not present: {rel})", file=sys.stderr)
            continue
        with open(path, "rb") as fh:
            for flow in io.FlowReader(fh).stream():
                if not (isinstance(flow, http.HTTPFlow) and flow.response):
                    continue
                try:
                    body = flow.response.content or b""
                except Exception:
                    continue
                if not body or len(body) > MAX_BYTES:
                    continue
                url = flow.request.pretty_url
                for name, rx in list(wanted.items()):
                    if rx.search(url):
                        out[name] = (body, rel, url)
                        del wanted[name]
                        break
    return out


def main() -> int:
    repo = Path(__file__).resolve().parents[2]
    out_dir = repo / "ios_decoder" / "tests" / "fixtures" / "tiles_real"
    out_dir.mkdir(parents=True, exist_ok=True)
    found = collect(repo)
    manifest = []
    rc = 0
    for name in PATTERNS:
        if name not in found:
            print(f"  {name:12s} NOT FOUND in any scanned capture")
            continue
        body, cap, url = found[name]
        (out_dir / f"{name}.bin").write_bytes(body)
        result = tiles.decode_tile(name, body)
        status = "OK" if result.error is None else f"DECODE-ERROR: {result.error}"
        if result.error is not None:
            rc = 1
        mk = [m.line() for m in result.markers]
        print(f"  {name:12s} {len(body):7d}B  {status}  markers={len(mk)}  ({cap.split('/')[-1]})")
        manifest.append({"name": name, "bytes": len(body), "capture": cap, "url": url,
                         "decode_ok": result.error is None, "markers": mk})
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2))
    print(f"\n{len(manifest)} tile fixture(s) -> {out_dir}")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
