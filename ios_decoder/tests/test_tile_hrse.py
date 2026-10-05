"""Migrated hrse tile tool: uniform parse/render/bounds + CRC check + CLI + live tile."""

import struct
import zlib

import pytest

from ios_decoder import tiles
from ios_decoder.tile_tools import Bounds, hrse
from ._tile_fixtures import saved_tile


def _build_hrse(nrows=2, ncols=2, min_lat=53.1, min_lon=-6.5, cellsize=0.01,
                grid=b"\x12\x34") -> bytes:
    h = bytearray(hrse.HEADER_LEN)
    h[0:8] = b"CLHRSE\n\x00"
    struct.pack_into(">H", h, 8, 1)                       # version
    struct.pack_into(">I", h, 10, hrse.HEADER_LEN)        # headerLength
    struct.pack_into(">I", h, 28, nrows)
    struct.pack_into(">I", h, 32, ncols)
    struct.pack_into(">d", h, 36, min_lon)               # xllcorner
    struct.pack_into(">d", h, 44, min_lat)               # yllcorner
    struct.pack_into(">f", h, 52, cellsize)
    struct.pack_into(">I", h, 68, (nrows * ncols) // 2)  # data_size_bytes
    region = bytes(h) + grid
    struct.pack_into(">I", h, 64, zlib.crc32(region) & 0xFFFFFFFF)  # crc over zeroed-crc region
    return bytes(h) + grid


def test_parse_header():
    tile = hrse.parse(_build_hrse())
    assert tile.header.version == 1
    assert tile.header.nrows == 2 and tile.header.ncols == 2
    assert abs(tile.header.min_lat - 53.1) < 1e-6
    assert abs(tile.header.min_lon - (-6.5)) < 1e-6


def test_render_has_header_and_histogram():
    out = hrse.render(hrse.parse(_build_hrse()))
    assert isinstance(out, str)
    assert "== CLHRSE tile ==" in out
    assert "signal-environment histogram" in out
    assert "ascii preview" in out


def test_bounds_is_coverage_box():
    b = hrse.bounds(hrse.parse(_build_hrse()))
    assert isinstance(b, Bounds)
    assert abs(b.sw_lat - 53.1) < 1e-6 and abs(b.ne_lat - (53.1 + 2 * 0.01)) < 1e-6
    assert abs(b.sw_lon - (-6.5)) < 1e-6


def test_crc_mismatch_raises():
    body = bytearray(_build_hrse())
    body[64] ^= 0xFF                                      # corrupt the CRC field
    with pytest.raises(hrse.HRSEError, match="CRC mismatch"):
        hrse.parse(bytes(body))


def test_adapter_emits_boundbox():
    r = tiles.decode_tile("hrse", _build_hrse())
    assert r.error is None
    assert [m.line() for m in r.markers][0].startswith("+++LATLON_BOUNDBOX hrse_tile (53.1")


def test_cli(tmp_path, capsys):
    p = tmp_path / "hrse.bin"
    p.write_bytes(_build_hrse())
    assert hrse.main([str(p)]) == 0
    assert "== CLHRSE tile ==" in capsys.readouterr().out


@pytest.mark.skipif(saved_tile("hrse") is None,
                    reason="no extracted hrse tile (run extract_tile_samples)")
def test_real_hrse_tile_decodes():
    r = tiles.decode_tile("hrse", saved_tile("hrse"))
    assert r.error is None and "== CLHRSE tile ==" in r.text
    assert [m.line() for m in r.markers][0].startswith("+++LATLON_BOUNDBOX hrse_tile")
