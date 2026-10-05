"""Migrated cldavl tile tool: uniform parse/render/bounds API + CLI + adapter wiring."""

import gzip
import struct

import pytest

from ios_decoder import tiles
from ios_decoder.tile_tools import Bounds, cldavl
from ._tile_fixtures import saved_tile


def _build_cldavl(bitmap=b"\x05\x00", min_lat=0, max_lat=1, prefix=b"") -> bytes:
    """A minimal valid cldavl body: optional prefix + 132-byte header + bitmap."""
    reserved = b"(c) test copyright"
    reserved += b"\x00" * (99 - len(reserved))
    header = (
        b"CLAVL" + reserved
        + bytes([1])                       # version
        + bytes([132])                     # header_length
        + struct.pack(">b", min_lat)
        + struct.pack(">b", max_lat)
        + struct.pack(">f", 0.1)           # bin_size
        + struct.pack(">d", 700_000_000.0)  # timestamp (CFAbsoluteTime)
        + struct.pack(">I", 2_419_200)     # expiration_age
        + struct.pack(">I", len(bitmap))   # data_size
        + struct.pack(">I", 0)             # crc32
    )
    assert len(header) == 132, len(header)
    return prefix + header + bitmap


def test_parse_from_bytes():
    avl = cldavl.parse(_build_cldavl())
    assert avl.header.magic == b"CLAVL"
    assert avl.header.version == 1
    assert avl.header.min_lat == 0 and avl.header.max_lat == 1
    assert abs(avl.header.bin_size - 0.1) < 1e-6
    assert avl.bitmap == b"\x05\x00"


def test_parse_gunzips():
    body = _build_cldavl()
    assert cldavl.parse(gzip.compress(body)).header.magic == b"CLAVL"


def test_parse_finds_magic_after_prefix():
    # the real file has a 12-byte outer wrapper before CLAVL; the scanner skips it
    avl = cldavl.parse(_build_cldavl(prefix=b"\xab\xba" + b"\x00" * 10))
    assert avl.header.magic == b"CLAVL"


def test_render_returns_string_with_header_and_tiles():
    out = cldavl.render(cldavl.parse(_build_cldavl()))
    assert isinstance(out, str)
    assert "cldavl.avl — Apple DEM Tile Availability File" in out
    assert "First 32 available DEM tiles:" in out
    # bitmap 0x05 → bits 0 and 2 set → cells at (0.0, 0.0) and (0.0, 0.2)
    assert "(0.00,0.00)" in out and "(0.00,0.20)" in out


def test_bounds_is_none_for_global_raster():
    assert cldavl.bounds(cldavl.parse(_build_cldavl())) is None


def test_lookup_and_iter():
    avl = cldavl.parse(_build_cldavl())
    assert cldavl.is_tile_available(avl, 0.0, 0.0) is True
    assert cldavl.is_tile_available(avl, 0.0, 0.1) is False
    assert list(cldavl.iter_available_tiles(avl)) == [(0.0, 0.0), (0.0, 0.2)]


def test_cli_prints_render(tmp_path, capsys):
    path = tmp_path / "cldavl.avl"
    path.write_bytes(_build_cldavl())
    rc = cldavl.main([str(path), "--count"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "cldavl.avl — Apple DEM Tile Availability File" in out
    assert "Available tiles : 2" in out


def test_adapter_drives_module_without_shim():
    # the tiles adapter must decode cldavl via the uniform API (no tempfile / stdout capture)
    result = tiles.decode_tile("cldavl", _build_cldavl())
    assert result.error is None
    assert "First 32 available DEM tiles:" in result.text
    assert result.markers == []          # global raster → no bounds marker


def test_bounds_type_is_exported():
    assert Bounds(1.0, 2.0, 3.0, 4.0).ne_lat == 2.0


@pytest.mark.skipif(saved_tile("cldavl") is None,
                    reason="no extracted cldavl tile (run extract_tile_samples)")
def test_real_cldavl_tile_decodes():
    r = tiles.decode_tile("cldavl", saved_tile("cldavl"))
    assert r.error is None
    assert "cldavl.avl — Apple DEM Tile Availability File" in r.text
    assert r.markers == []                                # global raster → no boundbox
