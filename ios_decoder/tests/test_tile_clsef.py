"""Migrated clsef tile tool: uniform parse/render/bounds + lookup + CLI.

A minimal synthetic tile necessarily mismatches the (huge) expected data_size, so the parser
records an integrity anomaly that render() surfaces as an in-band `// WARNING:` line (a stored
CRC of 0 means the field is unused, so it is NOT flagged — real Apple tiles ship crc=0).
"""

import struct

import pytest

from ios_decoder import tiles
from ios_decoder.tile_tools import clsef
from ._tile_fixtures import saved_tile


def _build_clsef(min_lat=0, max_lat=1, payload=b"\x21" * 16, crc=0) -> bytes:
    h = bytearray(clsef.HDR_TOTAL_SIZE)
    h[0:5] = b"CLSEF"
    h[clsef.HDR_VERSION_OFF] = 1
    h[clsef.HDR_HDRLEN_OFF] = clsef.HDR_TOTAL_SIZE
    struct.pack_into("b", h, clsef.HDR_MINLAT_OFF, min_lat)
    struct.pack_into("b", h, clsef.HDR_MAXLAT_OFF, max_lat)
    struct.pack_into(">f", h, clsef.HDR_BINSIZE_OFF, 0.05)
    struct.pack_into(">d", h, clsef.HDR_TIMESTAMP_OFF, 700_000_000.0)
    struct.pack_into(">i", h, clsef.HDR_EXPIRY_OFF, 86_400)
    struct.pack_into(">i", h, clsef.HDR_DATASIZE_OFF, len(payload))
    struct.pack_into(">I", h, clsef.HDR_CRC_OFF, crc)
    return bytes(h) + payload


def test_parse_header():
    p = clsef.parse(_build_clsef())
    assert p.header.version == 1
    assert p.header.min_lat == 0 and p.header.max_lat == 1
    assert abs(p.header.binsize - 0.05) < 1e-6
    assert p.header.ncols == 7200


def test_get_signal_environment():
    p = clsef.parse(_build_clsef(payload=b"\x21" * 16))   # low nibble 1, high nibble 2
    # cell (0,0) is nibble_idx 0 → low nibble of byte 0 = 1 = Rural
    nibble, name = p.get_signal_environment(0.0, -180.0)
    assert nibble == 1 and name == "Rural"


def test_render():
    out = clsef.render(clsef.parse(_build_clsef()))
    assert "CLSEFHeader:" in out
    assert "First 32 entries from the RF signal-environment raster:" in out
    assert "Rural" in out and "Urban" in out
    # ncols is hardcoded (not in the CLSEF header) — the output must say it's assumed
    assert "ncols" in out and "ASSUMED" in out


def test_data_size_mismatch_is_surfaced_in_output():
    # the tiny synthetic payload can't match the full-raster size → an in-band warning line
    out = clsef.render(clsef.parse(_build_clsef()))
    assert "// WARNING: data_size mismatch" in out


def test_crc_zero_is_not_flagged():
    # stored CRC 0 = field unused (real Apple tiles), so it must NOT produce a CRC mismatch...
    out = clsef.render(clsef.parse(_build_clsef(crc=0)))
    assert "CRC mismatch" not in out
    # ...but the output must say integrity was NOT verified (parallel to HRSE's "verified")
    assert "stored CRC is 0" in out and "integrity NOT verified" in out


def test_bad_crc_is_surfaced_in_output():
    # a non-zero CRC that doesn't match the data is real corruption → flagged in the output
    out = clsef.render(clsef.parse(_build_clsef(crc=0xDEADBEEF)))
    assert "// WARNING: CRC mismatch" in out
    assert "may be corrupt" in out


def test_short_data_size_does_not_crash_render():
    # payload (4 bytes) is shorter than a 32-entry render needs -> must bound the read, not
    # raise an opaque IndexError mid-render (the data_size the warning already flags)
    raw = _build_clsef(payload=b"\x21" * 4)
    out = clsef.render(clsef.parse(raw))
    assert "CLSEFHeader:" in out
    assert tiles.decode_tile("clsef", raw).error is None      # adapter sees clean text, no crash


def test_bounds_is_none_global_raster():
    assert clsef.bounds(clsef.parse(_build_clsef())) is None


def test_bad_magic_raises():
    with pytest.raises(ValueError, match="magic not found"):
        clsef.parse(b"\x00" * 200)


def test_lat_out_of_range_raises():
    p = clsef.parse(_build_clsef())
    with pytest.raises(ValueError, match="out of range"):
        p.get_nibble(50.0, 0.0)                            # tile only covers lat [0, 1)


def test_adapter_no_markers():
    r = tiles.decode_tile("clsef", _build_clsef())
    assert r.error is None and r.markers == []
    assert "CLSEFHeader:" in r.text


def test_cli_lookup(tmp_path, capsys):
    p = tmp_path / "clsef.bin"
    p.write_bytes(_build_clsef())
    assert clsef.main([str(p), "--lookup", "0.0", "-180.0"]) == 0
    out = capsys.readouterr().out
    assert "CLSEFHeader:" in out and "Rural" in out


@pytest.mark.skipif(saved_tile("clsef") is None,
                    reason="no extracted clsef tile (run extract_tile_samples)")
def test_real_clsef_tile_decodes():
    r = tiles.decode_tile("clsef", saved_tile("clsef"))
    assert r.error is None and "CLSEFHeader:" in r.text
    assert r.markers == []                                # global raster → no boundbox
