"""Loader for the committed real request-body extracts (see ``extract_request_samples.py``).

``load_real("arpc_real")`` / ``load_real("fb_real")`` return ``[(url, body), ...]`` read from
``tests/fixtures/<kind>/manifest.json``, or ``[]`` if the extracts are absent (the live tests
then skip).  No capture file is needed.
"""

from __future__ import annotations

import json
from pathlib import Path

_FIXTURES = Path(__file__).parent / "fixtures"


def load_real(kind: str) -> list[tuple[str, bytes]]:
    d = _FIXTURES / kind
    manifest = d / "manifest.json"
    if not manifest.exists():
        return []
    return [(m["url"], (d / m["file"]).read_bytes()) for m in json.loads(manifest.read_text())]
