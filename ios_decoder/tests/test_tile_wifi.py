"""Migrated wifi tile tool: uniform parse/render/bounds/tile_xyz + CLI + live tile."""

import gzip
import json
import struct

import pytest

from ios_decoder import tiles
from ios_decoder.tile_tools import Bounds, wifi
from ._tile_fixtures import saved_tile, section


def _build_wifi(sw_lat=53.1, sw_lon=-6.5, d_lat=0.05, d_lon=0.05,
                tile_y=1431000, tile_x=1735000,
                aps=((b"\xaa\xbb\xcc\xdd\xee\xff", 0, 65535),)) -> bytes:
    hdr = bytearray(192)
    struct.pack_into(">II", hdr, 4, tile_y, tile_x)
    struct.pack_into(">ff", hdr, 16, sw_lat, sw_lon)
    struct.pack_into(">ff", hdr, 24, d_lat, d_lon)
    s1 = section(1, bytes(hdr))
    entries = b"".join(mac + struct.pack(">HH", lr, lo) for mac, lr, lo in aps)
    s3 = section(3, struct.pack(">II", len(aps), 10), entries)
    return s1 + s3


def test_parse_header_and_aps():
    tile = wifi.parse(_build_wifi())
    assert tile.header.tile_y == 1431000 and tile.header.tile_x == 1735000
    assert abs(tile.header.sw_lat - 53.1) < 1e-4
    assert len(tile.aps) == 1
    ap = tile.aps[0]
    assert ap.mac == "aa:bb:cc:dd:ee:ff"
    assert abs(ap.lat - 53.1) < 1e-4                 # lat_raw 0 → SW corner
    assert abs(ap.lon - (-6.45)) < 1e-4              # lon_raw 65535 → +d_lon


def test_parse_gunzips():
    assert wifi.parse(gzip.compress(_build_wifi())).header.tile_x == 1735000


def test_render_is_json():
    obj = json.loads(wifi.render(wifi.parse(_build_wifi())))
    assert obj["tile_x"] == 1735000
    assert obj["aps"][0]["mac"] == "aa:bb:cc:dd:ee:ff"


def test_bounds_is_the_tile_box():
    b = wifi.bounds(wifi.parse(_build_wifi()))
    assert isinstance(b, Bounds)
    assert abs(b.sw_lat - 53.1) < 1e-4 and abs(b.ne_lat - 53.15) < 1e-4
    assert abs(b.sw_lon - (-6.5)) < 1e-4 and abs(b.ne_lon - (-6.45)) < 1e-4


def test_tile_xyz_for_marker():
    assert wifi.tile_xyz(wifi.parse(_build_wifi())) == (1735000, 1431000, 13)


def test_no_tile_header_raises():
    # an index section (allowed before the header) but no header → reaches the end check
    with pytest.raises(ValueError, match="No TileHeader"):
        wifi.parse(section(2, struct.pack(">II", 0, 10)))


def test_truncated_ap_table_surfaced_in_band():
    # AP section declares 3 entries but only 1 is present -> a // WARNING that reaches the
    # rendered output AND the adapter (previously this went only to stderr and was discarded)
    hdr = bytearray(192)
    struct.pack_into(">II", hdr, 4, 1431000, 1735000)
    struct.pack_into(">ff", hdr, 16, 53.1, -6.5)
    struct.pack_into(">ff", hdr, 24, 0.05, 0.05)
    one_entry = b"\xaa\xbb\xcc\xdd\xee\xff" + struct.pack(">HH", 0, 0)
    raw = section(1, bytes(hdr)) + section(3, struct.pack(">II", 3, 10), one_entry)
    tile = wifi.parse(raw)
    assert len(tile.aps) == 1
    assert any("truncated" in w for w in tile.warnings)
    out = wifi.render(tile)
    assert out.startswith("// WARNING:") and "truncated" in out
    assert "// WARNING:" in tiles.decode_tile("wifi", raw).text


def test_unknown_section_surfaced_in_band():
    hdr = bytearray(192)
    struct.pack_into(">ff", hdr, 16, 53.1, -6.5)
    struct.pack_into(">ff", hdr, 24, 0.05, 0.05)
    raw = section(1, bytes(hdr)) + section(9, b"\x00\x00\x00\x00")    # unknown section id 9
    assert any("unknown sectionId 9" in w for w in wifi.parse(raw).warnings)


def test_adapter_emits_xyz_then_boundbox():
    r = tiles.decode_tile("wifi", _build_wifi())
    assert r.error is None
    lines = [m.line() for m in r.markers]
    assert lines[0] == "+++XYZ wifi_tile (1735000,1431000,13)"
    # float32 of 53.1 is 53.0999…; just confirm the boundbox marker is second
    assert lines[1].startswith("+++LATLON_BOUNDBOX wifi_tile (53.0")


def test_cli_json(tmp_path, capsys):
    p = tmp_path / "tile.bin"
    p.write_bytes(_build_wifi())
    assert wifi.main([str(p), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["tile_x"] == 1735000


@pytest.mark.skipif(saved_tile("wifi") is None,
                    reason="no extracted wifi tile (run extract_tile_samples)")
def test_real_wifi_tile_decodes():
    r = tiles.decode_tile("wifi", saved_tile("wifi"))
    assert r.error is None
    obj = json.loads(r.text)
    assert "aps" in obj and obj["d_lat"] > 0
    lines = [m.line() for m in r.markers]
    assert any(line.startswith("+++XYZ wifi_tile") for line in lines)
    assert any(line.startswith("+++LATLON_BOUNDBOX wifi_tile") for line in lines)
