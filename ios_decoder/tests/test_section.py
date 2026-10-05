"""The shared tile primitives in ``tile_tools/_section.py``.

These back all eight tile parsers, so the 0xABBA framing semantics (especially strict vs
lenient EOF handling) are pinned here once rather than re-derived per tool.
"""

import gzip
import struct
import warnings

import pytest

from ios_decoder.tile_tools import _section
from ._tile_fixtures import section


def test_iter_sections_yields_meta_and_data_blocks():
    blob = section(5, b"META", b"DATA") + section(6, b"", b"xy")
    secs = list(_section.iter_sections(blob))
    assert [(s.id, s.meta, s.data) for s in secs] == [
        (5, b"META", b"DATA"), (6, b"", b"xy")]
    assert secs[0].body == b"METADATA"            # body = meta + data, for tiles that merge them


def test_strict_clean_framing_consumes_to_eof():
    blob = section(5, b"ab") + section(7, b"cd")
    assert len(list(_section.iter_sections(blob))) == 2   # exact tail → no raise


def test_strict_raises_on_bad_signature():
    bad = struct.pack(">HHII", 0x1234, 5, 0, 0)
    with pytest.raises(ValueError, match="bad section signature"):
        list(_section.iter_sections(bad))


def test_strict_raises_on_body_past_eof():
    blob = struct.pack(">HHII", 0xABBA, 5, 0, 99)         # claims 99 data bytes, none present
    with pytest.raises(ValueError, match="runs past EOF"):
        list(_section.iter_sections(blob))


def test_strict_raises_on_midstream_trailing_bytes():
    # one good section, then a partial tail (1..11 bytes) = truncated framing
    blob = section(5, b"ab") + b"\x00\x00\x00"
    with pytest.raises(ValueError, match="trailing byte"):
        list(_section.iter_sections(blob))


def test_strict_short_garbage_is_not_a_trailing_error():
    # a buffer too short for even one section yields nothing and does NOT raise, so each
    # parser can report its own "required section not found" instead (e.g. ltecell/gsmcell)
    assert list(_section.iter_sections(b"\x00" * 8)) == []


def test_lenient_stops_on_bad_signature_and_tolerates_tail():
    blob = section(1, b"hdr") + b"\xff\xff" + b"trailing padding"
    secs = list(_section.iter_sections(blob, lenient=True))
    assert [s.id for s in secs] == [1]            # stops at the non-0xABBA padding, no raise


def test_lenient_clamps_past_eof_and_warns():
    blob = struct.pack(">HHII", 0xABBA, 2, 0, 99) + b"short"
    seen = []
    secs = list(_section.iter_sections(blob, lenient=True, warn=seen.append))
    assert secs[0].data == b"short"               # clamped to what's there
    assert seen and "clamping" in seen[0]


def test_maybe_gunzip_roundtrips_and_passes_through():
    assert _section.maybe_gunzip(gzip.compress(b"hello")) == b"hello"
    assert _section.maybe_gunzip(b"not gzip") == b"not gzip"


def test_find_magic_bounded_and_full_fallback():
    blob = b"\x00\x00\x00CLXYZ rest"
    assert _section.find_magic(blob, b"CLXYZ", 256) == 3
    far = b"\x00" * 300 + b"CLXYZ"
    with pytest.raises(ValueError, match="magic not found"):
        _section.find_magic(far, b"CLXYZ", 256)                  # outside the window
    assert _section.find_magic(far, b"CLXYZ", 256, full_fallback=True) == 300


def test_find_magic_uses_custom_exception():
    class Boom(Exception):
        pass
    with pytest.raises(Boom):
        _section.find_magic(b"nope", b"CLXYZ", 256, exc=Boom)


def test_crc32_zeroed_ignores_the_crc_slot():
    buf = bytearray(b"\x01\x02\x03\x04ABCD")       # CRC field at offset 4
    a = _section.crc32_zeroed(bytes(buf), 4)
    buf[4:8] = b"ZZZZ"                             # changing only the CRC slot must not matter
    assert _section.crc32_zeroed(bytes(buf), 4) == a


def test_cf_to_utc_epoch():
    # CFAbsoluteTime 0 == 2001-01-01T00:00:00Z
    dt = _section.cf_to_utc(0)
    assert (dt.year, dt.month, dt.day, dt.hour) == (2001, 1, 1, 0)


def test_clsef_warns_not_raises_left_to_parsers():
    # sanity: _section itself emits no warnings on the happy path
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        list(_section.iter_sections(section(5, b"ab")))
