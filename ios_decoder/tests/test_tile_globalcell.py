"""Migrated globalcell tile tool: uniform parse/render(kind)/bounds + lookup + CLI.

Covers the four global-cell endpoints (GSM/CDMA/LTE/5G) which share this one parser and
differ only in the CID column label (passed via the adapter's render_kwargs).
"""

import struct

import pytest

from ios_decoder import tiles
from ios_decoder.tile_tools import Bounds, globalcell
from ._tile_fixtures import saved_tile, section


def _build_globalcell(sw_lat=52.0, sw_lon=-8.0, lat_ext=2.0, lon_ext=2.0,
                      cells=((272, 1, 12345, 0, 32768, 4),)) -> bytes:
    hmeta = bytearray(36)
    struct.pack_into(">I", hmeta, 0, 1)                    # version
    struct.pack_into(">ffff", hmeta, 12, sw_lat, sw_lon, lat_ext, lon_ext)
    struct.pack_into(">I", hmeta, 32, 1780299406)         # timestamp
    s5 = section(globalcell.SECT_HEADER, bytes(hmeta))
    idata = b"".join(struct.pack(">HHII", mcc, mnc, cid, i)
                     for i, (mcc, mnc, cid, *_rest) in enumerate(cells))
    s6 = section(globalcell.SECT_INDEX, struct.pack(">II", len(cells), 12), idata)
    ddata = b"".join(struct.pack(">HHI", mcc, mnc, cid) + struct.pack(">HH", lf, lo)
                     + struct.pack("<I", acc)
                     for mcc, mnc, cid, lf, lo, acc in cells)
    s7 = section(globalcell.SECT_DATA, struct.pack(">II", len(cells), 16), ddata)
    return s5 + s6 + s7


def test_short_tile_header_raises_descriptively():
    # a header section shorter than the fixed layout must fail noisily (ValueError), not raise
    # an opaque struct.error — matching gsmcell's guard
    raw = section(globalcell.SECT_HEADER, b"\x00" * 10)
    with pytest.raises(ValueError, match="too short"):
        globalcell.parse(raw)


def test_parse_and_lookup():
    tile = globalcell.parse(_build_globalcell())
    assert tile.header.version == 1
    assert abs(tile.header.ne_lat - 54.0) < 1e-4
    assert len(tile.data) == 1
    c = tile.lookup(272, 1, 12345)
    assert c is not None
    assert abs(c.lat - 52.0) < 1e-3                        # lat_frac 0 → SW (cell centre + .5/65536)
    assert abs(c.lon - (-7.0)) < 1e-3                      # lon_frac 32768/65536 → +1.0
    assert c.accuracy_code == 4


def test_lookup_miss():
    assert globalcell.parse(_build_globalcell()).lookup(0, 0, 0) is None


def test_render_uses_kind_label():
    out = globalcell.render(globalcell.parse(_build_globalcell()), kind="GSM CellID")
    assert "GSM CellID" in out
    assert "Version    : 1" in out and "1 rows" in out


def test_bounds_is_the_tile_box():
    b = globalcell.bounds(globalcell.parse(_build_globalcell()))
    assert isinstance(b, Bounds)
    assert abs(b.sw_lat - 52.0) < 1e-4 and abs(b.ne_lat - 54.0) < 1e-4


def test_missing_section_raises():
    s5_only = _build_globalcell()[:0] + section(globalcell.SECT_HEADER, bytes(36))
    with pytest.raises(ValueError, match="index"):
        globalcell.parse(s5_only)


_ENDPOINTS = [
    ("global_gsm", "GSM CellID"),
    ("global_cdma", "CDMA Base Stn ID"),
    ("global_lte", "LTE Global CellID"),
    ("global_5g", "5G NR CellID"),
]


@pytest.mark.parametrize("name,kind", _ENDPOINTS)
def test_adapter_passes_kind_and_emits_boundbox(name, kind):
    r = tiles.decode_tile(name, _build_globalcell())
    assert r.error is None
    assert kind in r.text                                  # render_kwargs reached render()
    assert [m.line() for m in r.markers][0].startswith(f"+++LATLON_BOUNDBOX {name}_tile")


@pytest.mark.parametrize("name,kind", _ENDPOINTS)
def test_real_global_tile_decodes(name, kind):
    body = saved_tile(name)
    if body is None:
        pytest.skip(f"no extracted {name} tile (run extract_tile_samples)")
    r = tiles.decode_tile(name, body)
    assert r.error is None and kind in r.text
    assert any(m.line().startswith(f"+++LATLON_BOUNDBOX {name}_tile") for m in r.markers)


def test_cli_lookup(tmp_path, capsys):
    p = tmp_path / "gc.bin"
    p.write_bytes(_build_globalcell())
    assert globalcell.main([str(p), "--lookup", "272", "1", "12345"]) == 0
    out = capsys.readouterr().out
    assert "Version" in out and "MCC=272 MNC=1 CID=12345" in out
