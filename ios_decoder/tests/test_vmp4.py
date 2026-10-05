"""Detector for SmartInterfaceSelectionTile-layout protobuf tiles (ios_decoder.vmp4).

The function was formerly called ``is_vmp4``: these style-72 ``/72/v2/72/<quadkey>``
bodies are protobuf, not Apple's VMP4 container (``tile.vf``), which starts with the
bytes ``VMP4``.  See the vmp4.py module docstring.
"""

import gzip
import struct

from ios_decoder import vmp4

detect = vmp4.is_smart_interface_selection_tile


def _tile_body(origin1=0x00100000, origin2=0x00120000, n_features=2):
    """A minimal well-formed style-72 tile body: two fixed32 origins, a section, repeated f10."""
    b = bytes([0x0D]) + struct.pack("<I", origin1)      # field 1 fixed32
    b += bytes([0x15]) + struct.pack("<I", origin2)     # field 2 fixed32
    b += bytes([0x1A, 0x01, 0x00])                      # field 3 len-delim (section)
    for _ in range(n_features):
        b += bytes([0x52, 0x01, 0x00])                  # field 10 len-delim (feature), repeated
    return b


def _vmp4_container_body():
    """A minimal real VMP4 container (tile.vf): magic, 2 zero bytes, section count, one entry."""
    entry_off = 8 + 10 + 1                              # header + 1 table entry + 1 pad byte
    b = b"VMP4" + b"\x00\x00" + struct.pack("<H", 1)
    b += struct.pack("<HII", 1, entry_off, 2)           # type 1, offset, size
    b += b"\x00"                                        # the n bytes between table and sections
    b += b"\x00\x00"                                    # section 1 data (flag byte 0)
    return b


def test_detects_raw_tile_body():
    assert detect(_tile_body())


def test_detects_gzip_wrapped_tile_body():
    # real v2 tile bodies are gzip-encoded; the detector must gunzip transparently
    assert detect(gzip.compress(_tile_body()))


def test_rejects_real_vmp4_container():
    # genuine VMP4 (tile.vf) starts with the bytes "VMP4" and is not protobuf
    assert not detect(_vmp4_container_body())
    assert not detect(gzip.compress(_vmp4_container_body()))


def test_rejects_ordinary_protobuf():
    assert not detect(b"\x08\x96\x01")                 # field 1 varint — not a leading fixed32
    assert not detect(b"\x12\x03abc")                   # field 2 len-delim


def test_rejects_degenerate_origin():
    # a leading fixed32 of zero is not a plausible tile origin
    assert not detect(_tile_body(origin1=0))
    assert not detect(_tile_body(origin1=0xFFFFFFFF, origin2=0xFFFFFFFF))


def test_rejects_too_few_feature_fields():
    # the features are a repeated field 10; a single one is not enough signal
    assert not detect(_tile_body(n_features=1))


def test_rejects_non_protobuf_and_short():
    assert not detect(b"Not Found")
    assert not detect(b"")
    assert not detect(b"\x0d\x00\x00")                 # too short for the fixed-offset check


def test_protobuf_top_fields_roundtrip():
    fields = vmp4.protobuf_top_fields(_tile_body())
    assert fields[0] == (1, 5) and fields[1] == (2, 5)
    assert sum(1 for fn, _ in fields if fn == 10) == 2
    assert vmp4.protobuf_top_fields(b"\x08") is None    # truncated -> not clean protobuf
