"""Migrated gsmcell tile tool: uniform parse/render/bounds + lookup + CLI + live tile."""

import struct

import pytest

from ios_decoder import tiles
from ios_decoder.tile_tools import Bounds, gsmcell
from ._tile_fixtures import saved_tile, section


def _build_gsmcell(sw_lat=52.0, sw_lon=-8.0, d_lat=2.0, d_lon=2.0,
                   records=((1, 100, 0, 32768, 3, 0),)) -> bytes:
    meta = bytearray(184)
    struct.pack_into(">III", meta, 0, 381, 1420000, 1720000)
    struct.pack_into(">ffff", meta, 12, sw_lat, sw_lon, d_lat, d_lon)
    struct.pack_into(">I", meta, 32, 1780299406)
    s5 = section(gsmcell.SEC_TILE_HEADER, bytes(meta))
    rec_data = b"".join(struct.pack(">IIHHBB", lac, cid, lf, lo, unc, fl)
                        for lac, cid, lf, lo, unc, fl in records)
    s7 = section(gsmcell.SEC_RECORDS, struct.pack(">II", len(records), 14), rec_data)
    return s5 + s7


def test_parse_and_lookup():
    tile = gsmcell.parse(_build_gsmcell())
    assert tile.header.version == 381 and tile.header.tile_y == 1420000
    assert len(tile.records) == 1
    loc = tile.location_of(1, 100)
    assert loc is not None
    lat, lon, unc = loc
    assert abs(lat - 52.0) < 1e-4                          # lat_frac 0 → SW corner
    assert abs(lon - (-7.0)) < 1e-4                        # lon_frac 32768/65536 → +1.0
    assert unc == 3000                                     # byte * 1000 = metres


def test_render():
    out = gsmcell.render(gsmcell.parse(_build_gsmcell()))
    assert "Tile header" in out and "tileY=1420000" in out
    assert "Cell records    : 1" in out


def test_bounds_is_the_tile_box():
    b = gsmcell.bounds(gsmcell.parse(_build_gsmcell()))
    assert isinstance(b, Bounds)
    assert abs(b.sw_lat - 52.0) < 1e-4 and abs(b.ne_lat - 54.0) < 1e-4
    assert abs(b.sw_lon - (-8.0)) < 1e-4 and abs(b.ne_lon - (-6.0)) < 1e-4


def test_wildcard_record():
    tile = gsmcell.parse(_build_gsmcell(records=((5, 0xFFFFFFFF, 0, 0, 1, 0),)))
    assert tile.records[0].is_wildcard
    assert "wildcard" in gsmcell.render(tile)


def test_overclaimed_record_count_truncates_and_warns():
    # one real 14-byte record, but the section header claims 5: keep the valid one and flag
    # the shortfall in the output instead of overrunning into an opaque struct error.
    meta = bytearray(184)
    struct.pack_into(">III", meta, 0, 381, 1420000, 1720000)
    struct.pack_into(">ffff", meta, 12, 52.0, -8.0, 2.0, 2.0)
    struct.pack_into(">I", meta, 32, 1780299406)
    s5 = section(gsmcell.SEC_TILE_HEADER, bytes(meta))
    one_record = struct.pack(">IIHHBB", 1, 100, 0, 0, 3, 0)
    s7 = section(gsmcell.SEC_RECORDS, struct.pack(">II", 5, 14), one_record)  # header lies: 5
    blob = s5 + s7

    tile = gsmcell.parse(blob)
    assert len(tile.records) == 1                            # only the record that fit
    assert "// WARNING:" in gsmcell.render(tile) and "truncated" in gsmcell.render(tile)
    r = tiles.decode_tile("gsmcell", blob)
    assert r.error is None and "truncated" in r.text        # surfaced, not crashed


def test_no_header_raises():
    with pytest.raises(ValueError, match="no TileHeader"):
        gsmcell.parse(section(7, struct.pack(">II", 0, 14)))


def test_adapter_emits_boundbox():
    r = tiles.decode_tile("gsmcell", _build_gsmcell())
    assert r.error is None
    assert [m.line() for m in r.markers][0].startswith("+++LATLON_BOUNDBOX gsmcell_tile (52.0")
    assert "tileY=1420000" in r.text


def test_cli_lookup(tmp_path, capsys):
    p = tmp_path / "gsm.bin"
    p.write_bytes(_build_gsmcell())
    assert gsmcell.main([str(p), "--lookup", "1", "100"]) == 0
    out = capsys.readouterr().out
    assert "Tile header" in out and "lookup lac=1 cid=100" in out


@pytest.mark.skipif(saved_tile("gsmcell") is None,
                    reason="no extracted gsm cell tile (run extract_tile_samples)")
def test_real_gsmcell_tile_decodes():
    r = tiles.decode_tile("gsmcell", saved_tile("gsmcell"))
    assert r.error is None and "Tile header" in r.text and "Cell records" in r.text
    assert any(m.line().startswith("+++LATLON_BOUNDBOX gsmcell_tile") for m in r.markers)
