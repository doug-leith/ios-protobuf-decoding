"""URL/header geo marker recovery (+++XYZ / +++LATLON)."""

from ios_decoder import geo


def _markers(findings):
    return [f.marker.line() for f in findings]


def test_cl_url_latlon():
    url = "https://cl2.apple.com/3/v1/142/172/1420000_1720000_0000000001100001.gz"
    f = geo.request_findings(url, [], {})
    assert _markers(f) == [f"+++LATLON {url} (52.0,-8.0)"]


def test_maps_tile_headers_xyz():
    url = "https://example.com/tile"
    headers = [("maps-tile-x", "100"), ("maps-tile-y", "200"),
               ("maps-tile-z", "13"), ("maps-tile-style", "road")]
    f = geo.request_findings(url, headers, {})
    assert _markers(f) == [f"+++XYZ {url}:road:maps-tile-x-y-z (100,200,13)"]


def test_tile_vf_query_xyz():
    url = "https://gspe1-ssl.ls.apple.com/tile.vf"
    f = geo.request_findings(url, [], {"x": "5", "y": "6", "z": "7"})
    assert _markers(f) == [f"+++XYZ {url} (5,6,7)"]


def test_no_geo_info_is_empty():
    assert geo.request_findings("https://example.com/whatever", [], {}) == []


def test_malformed_header_is_skipped_not_raised():
    headers = [("maps-tile-x", "not-an-int"), ("maps-tile-y", "1"), ("maps-tile-z", "1")]
    assert geo.request_findings("https://x/y", headers, {}) == []


def test_xtilekey_header_via_gloria():
    # exercises the vendored gloria decoder (a committed dependency now, so no skip); assert it
    # yields one +++XYZ marker (values are gloria-derived, so check shape not exact numbers)
    f = geo.request_findings("https://x/y", [("X-tilekey", "81606573")], {})
    assert len(f) == 1 and f[0].marker.tag == "XYZ"
    assert "X-tilekey" in f[0].marker.fields[0]


def test_cl3_host_latlon():
    # the recogniser regex allows both cl2 and cl3 hosts; cl3 was previously untested
    url = "https://cl3.apple.com/2/v1/142/172/1420000_1720000_00.gz"
    f = geo.request_findings(url, [], {})
    assert _markers(f) == [f"+++LATLON {url} (52.0,-8.0)"]
    # the description states the projection/origin are assumed, not measured
    assert "assumed" in f[0].description


def test_tilekey_in_72_v2_url():
    url = "https://gspe1-ssl.ls.apple.com/72/v2/72/81606573"
    f = geo.request_findings(url, [], {})
    assert len(f) == 1 and f[0].marker.tag == "XYZ"
    assert f[0].marker.fields[0] == url           # source is the URL


def test_tilekey_in_65_v1_url():
    url = "https://gspe1-ssl.ls.apple.com/65/v1/zoom/81606573.png"
    f = geo.request_findings(url, [], {})
    assert len(f) == 1 and f[0].marker.tag == "XYZ"


def test_nonpositive_tilekey_yields_no_finding_not_garbage():
    # a malformed X-tilekey must not fabricate a confident garbage coordinate
    assert geo.request_findings("https://x/y", [("X-tilekey", "-5")], {}) == []
    assert geo.request_findings("https://x/y", [("X-tilekey", "0")], {}) == []


def test_malformed_url_value_isolated_not_raised():
    # tile.vf matches but the query is malformed -> that recogniser yields nothing and
    # never raises (per-recogniser fault isolation), and no other branch fires
    url = "https://gspe1-ssl.ls.apple.com/tile.vf"
    assert geo.request_findings(url, [], {"x": "nope", "y": "1", "z": "1"}) == []


def test_header_and_url_findings_both_surface():
    url = "https://cl2.apple.com/3/v1/142/172/1420000_1720000.gz"
    headers = [("maps-tile-x", "1"), ("maps-tile-y", "2"), ("maps-tile-z", "3")]
    tags = {f.marker.tag for f in geo.request_findings(url, headers, {})}
    assert tags == {"XYZ", "LATLON"}
