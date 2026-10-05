"""Geographic info recovered from request URLs and headers → analysis markers.

Apple Maps/location requests encode the tile being fetched in the URL path/query or in
``maps-tile-*`` / ``X-tilekey`` headers.  The old addon decoded these to ``+++XYZ`` /
``+++LATLON`` marker lines; this ports that, routing every marker through
:mod:`ios_decoder.markers` (so the ``+++XYZ`` form is the unified ``(x,y,z)`` — no spaces,
which also keeps each marker a single awk field).

Pure: ``(url, headers, query)`` in, structured findings out — no mitmproxy.  Gloria tile-id
math is the vendored :mod:`ios_decoder.gloria_tile_id` (a committed copy of the reverse-
engineered helper, so this works without the external addon_ios oracle).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from . import gloria_tile_id, markers
from .httputil import header_get_ci as _get
from .markers import Marker

__all__ = ["GeoFinding", "request_findings", "tile_xy_to_lat_lng", "decode_gloria_tile_id"]


@dataclass
class GeoFinding:
    """A decoded geographic fact: a human-readable line plus its ``+++`` marker."""
    description: str
    marker: Marker


def tile_xy_to_lat_lng(x: int, y: int, zoom: int) -> tuple[float, float]:
    """(tile x, y, zoom) → (lat, lng) in degrees (Web Mercator inverse)."""
    return gloria_tile_id.tile_xy_to_lat_lng(x, y, zoom)


def decode_gloria_tile_id(tilekey: int) -> tuple[int, int, int]:
    """Gloria tile-id integer → (tile x, tile y, zoom)."""
    return gloria_tile_id.decode_gloria_tile_id(tilekey)


def _xyz_finding(source: str, x: int, y: int, z: int, note: str) -> GeoFinding:
    try:
        lat, lng = tile_xy_to_lat_lng(x, y, z)
        if not (-90.0 <= lat <= 90.0 and -180.0 <= lng <= 180.0):
            # a malformed tile id can decode to nonsensical coords; reject rather than print them
            desc = f"{note}: tile ({x},{y},{z}) [lat/lng ({lat},{lng}) out of range — rejected]"
        else:
            # the lat/lng is the tile's NW corner under the assumed Web-Mercator inverse, not a point
            desc = f"{note}: tile ({x},{y},{z}) -> lat/lng ({lat},{lng}) [tile NW corner, Web-Mercator]"
    except Exception as e:
        desc = f"{note}: tile ({x},{y},{z}) [lat/lng conversion failed: {type(e).__name__}]"
    return GeoFinding(desc, markers.xyz(source, x, y, z))


def _header_findings(url: str, headers) -> list[GeoFinding]:
    """``maps-tile-*`` and ``X-tilekey`` header recognisers (each fault-isolated)."""
    out: list[GeoFinding] = []
    if _get(headers, "maps-tile-x") is not None:
        try:
            x = int(_get(headers, "maps-tile-x"))
            y = int(_get(headers, "maps-tile-y"))
            z = int(_get(headers, "maps-tile-z"))
            style = _get(headers, "maps-tile-style") or ""
            out.append(_xyz_finding(f"{url}:{style}:maps-tile-x-y-z", x, y, z, "maps-tile header"))
        except (TypeError, ValueError):
            pass
    if _get(headers, "X-tilekey") is not None:
        try:
            x, y, z = decode_gloria_tile_id(int(_get(headers, "X-tilekey")))
            out.append(_xyz_finding(f"{url}:X-tilekey", x, y, z, "X-tilekey header"))
        except (TypeError, ValueError):
            pass
    return out


# --- URL recognisers: each returns a finding or None; narrow per-recogniser except, so a
#     malformed value in one branch can't mask the others (the old shared try/except did). ---

def _finding_tilevf(url: str, query) -> "GeoFinding | None":
    if not re.search(r"gspe\d+-ssl\.ls\.apple\.com/tile\.vf", url):
        return None
    try:
        x, y, z = int(query["x"]), int(query["y"]), int(query["z"])
    except (KeyError, TypeError, ValueError):
        return None
    return _xyz_finding(url, x, y, z, "tile.vf query")


def _finding_tilekey_url(url: str, query) -> "GeoFinding | None":
    # gloria tile-id carried in the URL path: 72/v2/72/<id> or 65/v1/zoom/<id>.png
    if re.search(r"gspe\d+-ssl\.ls\.apple\.com/72/v2/72", url):
        token = url.rstrip("/").split("/")[-1]
    elif re.search(r"gspe\d+-ssl\.ls\.apple\.com/65/v1/zoom", url):
        token = url.split("/")[-1].split(".")[0]
    else:
        return None
    try:
        x, y, z = decode_gloria_tile_id(int(token))
    except (TypeError, ValueError, IndexError):
        return None
    return _xyz_finding(url, x, y, z, "X-tilekey (URL)")


def _finding_cl_latlon(url: str, query) -> "GeoFinding | None":
    if not re.search(r"cl[23]\.apple\.com/\d+/v[12]/\d+", url):
        return None
    try:
        field = url.split("/")[-1].split(".")[0]
        a, b = field.split("_")[:2]
        lat = int(a) / 10000 - 90.0
        lon = int(b) / 10000 - 180.0
    except (TypeError, ValueError, IndexError):
        return None
    # the /10000 scale and -90/-180 origin are RE-derived assumptions about the cl* URL encoding
    return GeoFinding(
        f"URL lat/lng ({lat},{lon}) [assumed /10000 grid, -90/-180 origin]",
        markers.latlon(url, lat, lon))


_URL_RECOGNISERS = (_finding_tilevf, _finding_tilekey_url, _finding_cl_latlon)


def request_findings(url: str, headers, query) -> list[GeoFinding]:
    """All geographic findings for a request, from its headers and URL.

    ``headers`` is a list of (name, value) pairs; ``query`` is a dict of query params.
    Each recogniser is fault-isolated: a malformed value is skipped (best-effort parse of
    an external URL/header), never raised. The URL recognisers are mutually exclusive
    (first match wins), as in the addon.
    """
    out = _header_findings(url, headers)
    for recognise in _URL_RECOGNISERS:
        finding = recognise(url, query)
        if finding is not None:
            out.append(finding)
            break
    return out
