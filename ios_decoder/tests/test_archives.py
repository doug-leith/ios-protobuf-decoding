"""zip / cbor / img4 decoding (with graceful degradation for optional deps)."""

import io
import zipfile

from ios_decoder import archives


def test_decode_zip_lists_entries_and_decodes_plist():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("a.bin", bytes(range(256)))          # opaque binary, no printable text
        zf.writestr("info.plist",
                    b'<?xml version="1.0"?><!DOCTYPE plist><plist><dict>'
                    b"<key>k</key><string>v</string></dict></plist>")
    out = archives.decode_zip(buf.getvalue())
    assert "zip archive: 2 file(s)" in out
    assert "a.bin (256 bytes)  (not decoded)" in out     # opaque member flagged, not silent
    assert "info.plist" in out and 'k: "v"' in out      # plist member decoded


def test_decode_zip_shows_generic_text_member():
    # a non-plist, non-JSON text member (e.g. the generic XML used by .c3h archives) is
    # shown verbatim rather than hidden behind "(not decoded)"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("map.xml", b"<s3d><tile id='1'/></s3d>")
    out = archives.decode_zip(buf.getvalue())
    assert "map.xml (25 bytes)" in out
    assert "<s3d><tile id='1'/></s3d>" in out
    assert "(not decoded)" not in out


def test_decode_zip_recurses_into_nested_zip():
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w") as zf:
        zf.writestr("leaf.txt", b"deep content")
    outer = io.BytesIO()
    with zipfile.ZipFile(outer, "w") as zf:
        zf.writestr("nested.zip", inner.getvalue())
    out = archives.decode_zip(outer.getvalue())
    assert "nested.zip" in out
    assert "zip archive: 1 file(s)" in out               # the nested listing, rendered inline
    assert "leaf.txt" in out and "deep content" in out


def _zip_of(name: str, payload: bytes) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(name, payload)
    return buf.getvalue()


def test_decode_zip_stops_at_max_nesting_depth():
    """Nesting deeper than the cap is reported, not followed.

    `data` is untrusted capture bytes, so without a cap a self-referential or very
    deeply nested archive recurses without bound.
    """
    blob = b"bottom content"
    for i in range(archives._MAX_ZIP_DEPTH + 2):
        blob = _zip_of(f"level{i}.zip", blob)
    out = archives.decode_zip(blob)
    assert f"nesting deeper than {archives._MAX_ZIP_DEPTH} levels" in out
    assert "bottom content" not in out          # the deep payload is never reached


def test_decode_zip_nesting_within_cap_still_decodes():
    """The cap must not break the nesting Apple actually uses (.c3h within .c3h)."""
    out = archives.decode_zip(_zip_of("nested.zip", _zip_of("leaf.txt", b"deep content")))
    assert "deep content" in out


def test_member_starting_with_pk_but_not_a_zip_falls_through_to_text():
    """A text member that merely starts with a PK signature must not be claimed by the
    zip branch: it is recognized structurally, so it falls through to the text decoder
    instead of reporting "not a valid zip archive"."""
    member = b"PK\x07\x08 this is really just text, not an archive at all\n" * 2
    out = archives.decode_zip(_zip_of("decoy.txt", member))
    assert "not a valid zip" not in out
    assert "really just text" in out


def test_is_zip_rejects_local_header_without_central_directory():
    """A truncated fragment carrying only a local file header is not a listable zip."""
    truncated = _zip_of("x.txt", b"payload")[:20]
    assert truncated[:4] == b"PK\x03\x04"      # the prefix a magic check would trust
    assert archives._is_zip(truncated) is False


def test_decode_zip_bad_input():
    assert "ERROR: not a valid zip" in archives.decode_zip(b"not a zip")


def test_decode_cbor_graceful_or_decoded():
    # cbor for {"a": 1}: a1 61 61 01
    data = bytes.fromhex("a1616101")
    out = archives.decode_cbor(data)
    # either decoded (cbor2 present) or a clear note (absent) — never a crash
    assert ("a: 1" in out) or ("cbor2 not installed" in out)


def test_looks_like_img4():
    assert archives.looks_like_img4(b"\x30\x82\x01\x00\x00\x00IM4P")
    assert not archives.looks_like_img4(b"\x30\x82\x01\x00\x00\x00XXXX")


def test_decode_img4_unrecognised_magic():
    assert "unrecognised magic" in archives.decode_img4(b"\x30\x82\x01\x00\x00\x00ZZZZ")
