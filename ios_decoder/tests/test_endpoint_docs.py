"""The README's generated endpoint tables and examples, and the quick-start example capture.

* every endpoint in the decoder's URL table has a description, and the README block built from them
  is current (run ``python3 -m ios_decoder.endpoint_docs --write`` after changing either);
* the README quick start (``ios_decoder.report examples/example.mitm | diff - examples/example_output.txt``)
  really prints the committed expected output;
* the example capture holds no real MAC addresses or locations: its Wi-Fi addresses are in the range
  reserved for documentation and its coordinates are those of a public landmark.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from ios_decoder import endpoint_docs

REPO = Path(__file__).resolve().parents[2]
EXAMPLES = REPO / "examples"


def test_every_endpoint_has_a_description_and_vice_versa():
    assert endpoint_docs.problems() == []


def test_readme_generated_blocks_are_up_to_date():
    readme = (REPO / "README.md").read_text()
    assert endpoint_docs.render_readme(readme) == readme, (
        "README.md is out of date; run: python3 -m ios_decoder.endpoint_docs --write")


@pytest.mark.skipif(shutil.which("protoc") is None, reason="protoc is needed to compile the schemas")
def test_quick_start_output_matches_the_committed_expected_output():
    out = subprocess.run([sys.executable, "-m", "ios_decoder.report", "examples/example.mitm"],
                         cwd=REPO, capture_output=True, text=True, check=True).stdout
    assert out == (EXAMPLES / "example_output.txt").read_text()


def test_example_capture_decodes_the_three_endpoints_with_named_fields():
    out = (EXAMPLES / "example_output.txt").read_text()
    for url in ("gs-loc.apple.com/clls/wloc", "gsp10-ssl.apple.com/hvr/trc", "gsp64-ssl.ls.apple.com/hvr/v3/use"):
        assert f"POST https://{url}" in out
    # named fields from the schemas, not "1: ..." raw numbers
    for field in ("wirelessAPs {", "macID:", "events {", "INDOOR_EVENT_TYPE_LOCATION", "logMsgEvents {"):
        assert field in out


def test_example_capture_has_no_real_macs_or_locations():
    out = (EXAMPLES / "example_output.txt").read_text()
    macs = set(re.findall(r"\b(?:[0-9a-fA-F]{1,2}:){5}[0-9a-fA-F]{1,2}\b", out))
    assert macs and all(m.lower().startswith("00:00:5e:00:53:") for m in macs), macs
    # every coordinate-like decimal is near Apple Park, Cupertino (37.33, -122.01)
    for m in re.finditer(r"(?:latitude|longitude): (-?\d+\.\d+)", out):
        value = float(m.group(1))
        assert abs(value - 37.3349) < 0.01 or abs(value + 122.0090) < 0.01, m.group(0)
