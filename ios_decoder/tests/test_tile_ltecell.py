"""Migrated ltecell tile tool: uniform parse/render/bounds + lookup + CLI."""

import struct

import pytest

from ios_decoder import tiles
from ios_decoder.tile_tools import Bounds, ltecell
from ._tile_fixtures import saved_tile


def _meta_section(sw_lat=52.0, sw_lon=-8.0, d_lat=2.0, d_lon=2.0) -> bytes:
    block = bytearray(184)
    struct.pack_into(">H", block, 2, 7)                  # tile_version
    struct.pack_into(">II", block, 4, 1420000, 1720000)
    struct.pack_into(">ffff", block, 12, sw_lat, sw_lon, d_lat, d_lon)
    struct.pack_into(">I", block, 32, 1780299406)        # timestamp
    struct.pack_into("<I", block, 44, 16)                # grid_rows
    struct.pack_into("<I", block, 48, 16)                # grid_cols
    return struct.pack(">HHII", 0xABBA, 5, 184, 0) + bytes(block)


def _data_section(entries) -> bytes:
    body = b"".join(struct.pack(">HHIHH", 0, tac, cid, gy, gx) + struct.pack("<H", acc)
                    for tac, cid, gy, gx, acc in entries)
    primary = struct.pack(">HHI", 0, len(entries), 14)
    return struct.pack(">HHII", 0xABBA, 7, len(primary), len(body)) + primary + body


def _build_ltecell(entries=((40100, 292352, 0, 32768, 2),)) -> bytes:
    return _meta_section() + _data_section(entries)


def test_parse_metadata_and_entry():
    tile = ltecell.parse(_build_ltecell())
    assert tile.metadata.tile_version == 7
    assert abs(tile.metadata.sw_lat - 52.0) < 1e-4 and abs(tile.metadata.ne_lat - 54.0) < 1e-4
    assert len(tile.entries) == 1
    e = tile.entries[0]
    assert e.tac == 40100 and e.cid == 292352
    assert abs(e.lat - 52.0) < 1e-4                      # grid_y 0 → SW corner
    assert abs(e.lon - (-7.0)) < 1e-4                    # grid_x 32768/65536 → +1.0
    assert e.accuracy == 2


def test_lookup():
    tile = ltecell.parse(_build_ltecell())
    assert tile.lookup(40100, 292352).cid == 292352
    assert tile.lookup(40100, 999) is None


def test_overclaimed_data_count_truncates_and_warns():
    # one real 14-byte entry, but the primary header claims 5: keep the one and flag the rest
    one = struct.pack(">HHIHH", 0, 40100, 292352, 0, 0) + struct.pack("<H", 2)
    primary = struct.pack(">HHI", 0, 5, 14)                 # header lies: 5 entries
    data_sec = struct.pack(">HHII", 0xABBA, 7, len(primary), len(one)) + primary + one
    blob = _meta_section() + data_sec

    tile = ltecell.parse(blob)
    assert len(tile.entries) == 1                           # only the entry that fit
    assert "// WARNING:" in ltecell.render(tile) and "truncated" in ltecell.render(tile)
    r = tiles.decode_tile("ltecell", blob)
    assert r.error is None and "truncated" in r.text        # surfaced, not crashed


def test_unknown_cid():
    tile = ltecell.parse(_build_ltecell(entries=((1, 0xFFFFFFFF, 0, 0, 150),)))
    assert tile.entries[0].cid_unknown
    assert "UNKNOWN" in ltecell.render(tile)


def test_render():
    out = ltecell.render(ltecell.parse(_build_ltecell()))
    assert "1 data entries" in out and "First 1 cell entries:" in out
    assert "CellEntry(tac=40100" in out


def test_bounds_is_the_tile_box():
    b = ltecell.bounds(ltecell.parse(_build_ltecell()))
    assert isinstance(b, Bounds)
    assert abs(b.sw_lat - 52.0) < 1e-4 and abs(b.ne_lat - 54.0) < 1e-4


def test_no_metadata_raises():
    with pytest.raises(ValueError, match="No Metadata"):
        ltecell.parse(b"\x00" * 8)                          # no sections at all
    with pytest.raises(ValueError, match="before Metadata"):
        ltecell.parse(_data_section([(1, 1, 0, 0, 1)]))     # data section with no metadata


def test_adapter_emits_boundbox():
    r = tiles.decode_tile("ltecell", _build_ltecell())
    assert r.error is None
    assert [m.line() for m in r.markers][0].startswith("+++LATLON_BOUNDBOX ltecell_tile (52.0")
    assert "CellEntry(tac=40100" in r.text


def test_cli_lookup(tmp_path, capsys):
    p = tmp_path / "lte.bin"
    p.write_bytes(_build_ltecell())
    assert ltecell.main([str(p), "--lookup", "40100", "292352"]) == 0
    out = capsys.readouterr().out
    assert "data entries" in out and "lookup tac=40100 cid=292352" in out


@pytest.mark.skipif(saved_tile("ltecell") is None,
                    reason="no extracted lte cell tile (run extract_tile_samples)")
def test_real_ltecell_tile_decodes():
    r = tiles.decode_tile("ltecell", saved_tile("ltecell"))
    assert r.error is None and "data entries" in r.text
    assert any(m.line().startswith("+++LATLON_BOUNDBOX ltecell_tile") for m in r.markers)
