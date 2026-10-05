"""Migrated cldem tile tool: uniform parse/render/bounds + CLI + live tile."""

import struct

import pytest

from ios_decoder import tiles
from ios_decoder.tile_tools import Bounds, cldem
from ._tile_fixtures import saved_tile


def _build_cldem(ncols=2, nrows=2, lat_ll=53.1, lon_ll=-6.5, cellsize=0.001,
                 max_alt=800.0, min_alt=100.0, grid=b"\x00\x80\xff\x40",
                 data_size=None) -> bytes:
    outer = struct.pack(">HHII", cldem.OUTER_MAGIC, cldem.OUTER_TYPE_DEM, 0xB0, len(grid))
    h = bytearray(cldem.CLDEM_HDR_SIZE)
    h[0:5] = b"CLDEM"
    h[5] = 0x0A                                           # subtype
    h[14] = cldem.CLDEM_VERSION                           # version
    h[15] = cldem.CLDEM_HDR_SIZE                          # headerLength
    h[16] = 0xFF                                          # no-data value
    struct.pack_into(">H", h, 44, ncols)
    struct.pack_into(">H", h, 46, nrows)
    struct.pack_into(">I", h, 48, ncols * nrows if data_size is None else data_size)
    struct.pack_into(">d", h, 56, lat_ll)
    struct.pack_into(">d", h, 64, lon_ll)
    struct.pack_into(">d", h, 72, cellsize)
    struct.pack_into(">f", h, 80, max_alt)
    struct.pack_into(">f", h, 84, min_alt)
    return outer + bytes(h) + grid


def test_parse_header():
    tile = cldem.parse(_build_cldem())
    assert tile.header.version == 2 and tile.header.ncols == 2 and tile.header.nrows == 2
    assert abs(tile.header.lat_ll - 53.1) < 1e-6
    assert tile.header.max_alt == 800.0 and tile.header.min_alt == 100.0


def test_altitude_scaling():
    tile = cldem.parse(_build_cldem(grid=b"\x00\x80\xff\x40"))
    assert tile._raw_to_altitude(0) == 100.0                 # min
    assert tile._raw_to_altitude(0xFF) is None               # no-data
    assert abs(tile._raw_to_altitude(0x80) - (128 * 700 / 255 + 100)) < 1e-3


def test_render_has_header_and_samples():
    out = cldem.render(cldem.parse(_build_cldem()))
    assert out.startswith("<CLDEMTile 2×2 cells")
    assert "=== CLDEM Tile Header ===" in out
    assert "Elevation samples across tile" in out


def test_datasize_mismatch_surfaced_in_band():
    # data_size (6) disagrees with ncols*nrows (4) -> a // WARNING that reaches the rendered
    # output AND the adapter pipeline (previously this went only to stderr and was discarded)
    raw = _build_cldem(grid=b"\x10\x20\x30\x40\x50\x60", data_size=6)
    tile = cldem.parse(raw)
    assert any("dataSize" in w for w in tile.warnings)
    assert "// WARNING:" in cldem.render(tile)
    assert "// WARNING:" in tiles.decode_tile("cldem", raw).text


def test_get_altitude_reports_fallback_method():
    # all four corners present -> bilinear; a no-data corner -> nearest-neighbour fallback,
    # so render can flag which samples weren't true interpolations
    full = cldem.parse(_build_cldem(grid=b"\x00\x80\x40\x60"))           # no 0xFF
    lat = full.header.lat_ll + 0.5 * full.header.cellsize
    lon = full.header.lon_ll + 0.5 * full.header.cellsize
    assert full.get_altitude(lat, lon)[2] == "bilinear"
    holed = cldem.parse(_build_cldem(grid=b"\x00\x80\xff\x60"))          # cell(1,0) no-data
    assert holed.get_altitude(lat, lon)[2] == "nearest-neighbour (corner no-data)"


def test_render_flags_edge_clamped_samples():
    # the far-edge samples interpolate against a +1 neighbour off the grid (clamped) -> tagged
    out = cldem.render(cldem.parse(_build_cldem(grid=b"\x00\x80\x40\x60")))
    assert "[bilinear (edge-clamped)]" in out


def test_bounds_is_extent():
    b = cldem.bounds(cldem.parse(_build_cldem()))
    assert isinstance(b, Bounds)
    assert abs(b.sw_lat - 53.1) < 1e-6
    assert abs(b.ne_lat - (53.1 + 2 * 0.001)) < 1e-6


def test_zero_cellsize_raises_descriptively():
    # a 0° cell would divide-by-zero in get_altitude; fail noisily at parse instead
    with pytest.raises(ValueError, match="cellsize"):
        cldem.parse(_build_cldem(cellsize=0.0))
    # and the adapter surfaces it as a clean per-tile error, not a crash
    assert tiles.decode_tile("cldem", _build_cldem(cellsize=0.0)).error is not None


def test_bad_outer_magic_raises():
    with pytest.raises(ValueError, match="outer magic"):
        cldem.parse(b"\x00\x00" + b"\x00" * 20)


def test_tile_url_helper():
    assert cldem.CLDEMTile.tile_url(52.5, -7.1) == \
        "https://cl3.apple.com/3/v2/142/172/1425000_1729000.gz"


def test_adapter_emits_boundbox():
    r = tiles.decode_tile("cldem", _build_cldem())
    assert r.error is None
    assert [m.line() for m in r.markers][0].startswith("+++LATLON_BOUNDBOX cldem_tile (53.1")


def test_cli(tmp_path, capsys):
    p = tmp_path / "cldem.bin"
    p.write_bytes(_build_cldem())
    assert cldem.main([str(p)]) == 0
    assert "=== CLDEM Tile Header ===" in capsys.readouterr().out


@pytest.mark.skipif(saved_tile("cldem") is None,
                    reason="no extracted cldem tile (run extract_tile_samples)")
def test_real_cldem_tile_decodes():
    r = tiles.decode_tile("cldem", saved_tile("cldem"))
    assert r.error is None and r.text.startswith("<CLDEMTile")
    assert any(m.line().startswith("+++LATLON_BOUNDBOX cldem_tile") for m in r.markers)
