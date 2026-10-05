#!/usr/bin/env python3
"""Build ``examples/example.mitm``, a tiny capture used by the README quick start.

It holds three flows that show how an iPhone talks to Apple's location services:

  * ``gs-loc.apple.com/clls/wloc``  - locationd sends a Wi-Fi MAC address and gets back the
    positions of nearby access points.  SYNTHETIC: built here from the real ``als.proto`` schema.
  * ``gsp10-ssl.apple.com/hvr/trc`` - locationd uploads a sensor trace (locations, pressure).
    SYNTHETIC: built here from the real ``clp.proto`` schema.
  * ``gsp64-ssl.ls.apple.com/hvr/v3/use`` - geod uploads usage telemetry.  A REAL request body
    (one of the plain ones committed under ``ios_decoder/tests/fixtures/arpc_real``).

No value in the two synthetic flows comes from a real device: the MAC addresses are in the
range reserved for documentation (RFC 7042, ``00-00-5E-00-53-xx``) and the coordinates are those
of a public landmark (Apple Park, Cupertino).  The messages are real wire format, so the decoder
output shows the genuine field names.

Rebuild both files with::

    ./venv/bin/python3 examples/make_example_capture.py

which rewrites ``examples/example.mitm`` and ``examples/example_output.txt``.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

from mitmproxy import http, io
from mitmproxy.test import tflow

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from ios_decoder import arpc                              # noqa: E402
from ios_decoder.paths import DEFAULT_PROTO_DIRS          # noqa: E402
from ios_decoder.schemas import SchemaRegistry            # noqa: E402
from ios_decoder.tests._arpc_fixtures import build_request, build_response   # noqa: E402

OUT_DIR = Path(__file__).resolve().parent
FIXTURES = REPO / "ios_decoder" / "tests" / "fixtures" / "arpc_real"

# Apple Park, Cupertino (a public landmark), and documentation-range MAC addresses (RFC 7042).
LAT, LON = 37.3349, -122.0090
MACS = [f"00:00:5e:00:53:{n:02x}" for n in (1, 2, 3, 4)]

UA_LOCATIOND = "locationd/2787.0.5 CFNetwork/1410.1 Darwin/22.6.0"
UA_GEOD = "geod/1 CFNetwork/1410.1 Darwin/22.6.0"
OS_BUILD = "16.7.11.20H360"


def _msg(reg: SchemaRegistry, schema_file: str, name: str):
    return reg.message_class(schema_file, name)()


def wloc_flow(reg: SchemaRegistry):
    """A Wi-Fi location lookup: the handset sends one MAC address, Apple replies with the
    positions of that access point and three neighbours."""
    req = _msg(reg, "als.proto", "als.ALSLocationRequest")
    req.wirelessAPs.add().macID = MACS[0]
    req.numberOfSurroundingWifis = 100
    req.surroundingWifiBands.append(1)                    # K2DOT4_GHZ
    req.wifiAltitudeScale = 2                             # K_WIFI_ALTITUDE_SCALE10TO_THE2
    req.meta.softwareBuild = "iPhone OS16.7.11/20H360"
    req.meta.productId = "iPhone10,1"

    resp = _msg(reg, "als.proto", "als.ALSLocationResponse")
    for i, mac in enumerate(MACS):
        ap = resp.wirelessAPs.add()
        ap.macID = mac
        ap.location.latitude = round((LAT + 0.0004 * i) * 1e8)      # degrees * 1e8
        ap.location.longitude = round((LON - 0.0003 * i) * 1e8)
        ap.location.accuracy = 20 + 5 * i
        ap.location.locationType = 3
        ap.location.altitude = 48
        ap.location.verticalAccuracy = 1000
        ap.location.score = 53
        ap.location.reach = 89
        ap.channel = (1, 6, 11, 36)[i]
    body = build_request(locale="en_US", app="com.apple.locationd", osv=OS_BUILD,
                         function_id=1, payload=req.SerializeToString())
    reply = build_response(response_type=1, payload=resp.SerializeToString())
    return ("https://gs-loc.apple.com/clls/wloc", UA_LOCATIOND, body, reply)


def trace_flow(reg: SchemaRegistry):
    """A sensor-trace upload: three GPS fixes and a barometric pressure reading."""
    t = _msg(reg, "clp.proto", "clp.TraceCollectionRequest")
    t.meta.productId = "D20AP"
    t.meta.softwareVersion = "iPhone OS16.7.11/20H360"
    t.type = 1                                            # RANDOM_COLLECTION
    t0 = 802283024.0
    for i in range(3):
        ev = t.events.add()
        ev.type = 3                                       # LOCATION
        loc = ev.location
        loc.latitude = LAT + 0.0001 * i
        loc.longitude = LON - 0.0001 * i
        loc.horizontalAccuracy = 5.0
        loc.altitude = 61.5
        loc.verticalAccuracy = 4.0
        loc.speed = 1.5
        loc.course = 110.0
        loc.timestamp = t0 + i
        loc.provider = 1
    ev = t.events.add()
    ev.type = 5                                           # PRESSURE
    ev.pressure.timestamp = t0 + 3
    ev.pressure.pressure = 101.2
    ev.pressure.temperature = 21.5
    body = build_request(locale="en_US", app="com.apple.locationd", osv=OS_BUILD,
                         function_id=109, payload=t.SerializeToString())
    return ("https://gsp10-ssl.apple.com/hvr/trc", UA_LOCATIOND, body, build_response(response_type=0))


def use_flow():
    """A real geod telemetry upload: the smallest committed real body from an iPhone 8 on iOS
    16.7.11 (build 20H360) that is large enough to carry a full network event."""
    manifest = json.loads((FIXTURES / "manifest.json").read_text())
    for m in sorted(manifest, key=lambda m: m["bytes"]):
        body = (FIXTURES / m["file"]).read_bytes()
        hdr = arpc.parse_request_header(body)
        if "hvr/v3/use" in m["url"] and m["bytes"] >= 300 and hdr and hdr.os_version == OS_BUILD:
            return (m["url"], UA_GEOD, body, build_response(response_type=1017))
    raise SystemExit("no suitable hvr/v3/use fixture found")


def make_flow(n: int, url: str, ua: str, body: bytes, reply: bytes, content_type: str) -> http.HTTPFlow:
    f = tflow.tflow()
    f.id = f"00000000-0000-0000-0000-{n:012d}"
    f.client_conn.id = f"00000000-0000-0000-0001-{n:012d}"      # fixed ids: the file is reproducible
    f.server_conn.id = f"00000000-0000-0000-0002-{n:012d}"
    ts = 1_780_000_000.0 + 60 * n
    f.request = http.Request.make("POST", url, body, {"User-Agent": ua, "Content-Type": content_type,
                                                       "Accept": "*/*"})
    f.request.timestamp_start, f.request.timestamp_end = ts, ts + 0.05
    f.response = http.Response.make(200, reply, {"Content-Type": "application/octet-stream"})
    f.response.timestamp_start, f.response.timestamp_end = ts + 0.2, ts + 0.25
    return f


def main() -> int:
    reg = SchemaRegistry(list(DEFAULT_PROTO_DIRS), cache_dir=tempfile.mkdtemp())
    specs = [(*wloc_flow(reg), "application/x-www-form-urlencoded"),
             (*trace_flow(reg), "application/x-www-form-urlencoded"),
             (*use_flow(), "application/octet-stream")]
    mitm = OUT_DIR / "example.mitm"
    with open(mitm, "wb") as fh:
        w = io.FlowWriter(fh)
        for n, (url, ua, body, reply, ctype) in enumerate(specs, start=1):
            w.add(make_flow(n, url, ua, body, reply, ctype))
    # the expected output of the README quick start
    out = subprocess.run([sys.executable, "-m", "ios_decoder.report", str(mitm.relative_to(REPO))],
                         cwd=REPO, capture_output=True, text=True, check=True).stdout
    (OUT_DIR / "example_output.txt").write_text(out)
    print(f"wrote {mitm.relative_to(REPO)} ({mitm.stat().st_size} bytes) and examples/example_output.txt "
          f"({len(out.splitlines())} lines)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
