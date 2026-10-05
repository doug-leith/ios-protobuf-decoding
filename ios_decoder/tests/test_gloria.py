"""The vendored gloria_tile_id math + the report schema-dir resolution.

gloria_tile_id was migrated into the committed package (from the gitignored addon_ios oracle)
so geo marker decoding needs nothing external; these pin the round-trips and the graceful,
transparent handling of a missing .proto schema dir.
"""

import pytest

from ios_decoder import gloria_tile_id as g
from ios_decoder import report
from ios_decoder.paths import DEFAULT_PROTO_DIRS


def test_decode_rejects_nonpositive_tile_id():
    # a tile id is a positive Morton code; 0/negative is malformed -> raise (was a
    # negative-shift crash for 0, and silent garbage x/y for negatives)
    for bad in (0, -1, -5):
        with pytest.raises(ValueError, match="positive"):
            g.decode_gloria_tile_id(bad)


def test_encode_decode_roundtrip_recovers_tile():
    # encode a known lat/lng/zoom, decode back to x/y/zoom, re-encode → same key
    key = g.gloria_tile_id(37.3318, -122.0312, 15)
    x, y, z = g.decode_gloria_tile_id(key)
    assert z == 15
    assert g.gloria_tile_id(*g.tile_xy_to_lat_lng(x, y, z), z) == key


def test_tile_xy_to_lat_lng_is_tile_centre():
    # zoom 1: tile (0,0) is the NW quadrant. Longitude centre is exactly -90; latitude is the
    # Web-Mercator centre of the northern half (~66.5°, NOT the linear 45°).
    lat, lng = g.tile_xy_to_lat_lng(0, 0, 1)
    assert abs(lng - (-90.0)) < 1e-9
    assert abs(lat - 66.51) < 0.1


def test_decode_to_lat_lng_matches_encode_within_half_tile():
    lat, lng, zoom = 51.5074, -0.1278, 12          # London
    key = g.gloria_tile_id(lat, lng, zoom)
    dlat, dlng, dz = g.decode_gloria_tile_id_to_lat_lng(key)
    assert dz == zoom
    tile_deg = 360.0 / (1 << zoom)
    assert abs(dlat - lat) < tile_deg and abs(dlng - lng) < tile_deg


def test_resolve_proto_dirs_uses_default_when_present(tmp_path):
    dirs, note = report._resolve_proto_dirs([tmp_path])
    assert dirs == [tmp_path] and note is None          # an existing dir → no note


def test_resolve_proto_dirs_notes_when_all_absent(tmp_path):
    missing = tmp_path / "nope"
    dirs, note = report._resolve_proto_dirs([missing])
    assert dirs == [missing]
    assert note is not None and "--proto-dir" in note   # transparent: tells the user why + how


def test_resolve_proto_dirs_defaults_to_paths_constant():
    dirs, _ = report._resolve_proto_dirs(None)
    assert dirs == list(DEFAULT_PROTO_DIRS)              # None → the documented default
