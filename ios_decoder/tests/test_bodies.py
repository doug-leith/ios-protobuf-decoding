"""Undecoded-body display: placeholders, repr vs hex, truncation vs full."""

from ios_decoder.bodies import (
    BodyDisplayOptions,
    summarize_undecoded,
    hexdump,
    placeholder_kind,
)


# --- placeholders ------------------------------------------------------------

def test_image_is_a_placeholder():
    out = summarize_undecoded(b"\x89PNG" + b"\x00" * 5000, "image/png")
    assert out == "<image: image/png, 5004 bytes>"


def test_video_is_a_placeholder():
    out = summarize_undecoded(b"\x00" * 999999, "video/mp4")
    assert out == "<video: video/mp4, 999999 bytes>"


def test_placeholder_kind_classification():
    assert placeholder_kind("image/heic") == "image"
    assert placeholder_kind("audio/aac") == "audio"
    assert placeholder_kind("font/woff2") == "font"
    assert placeholder_kind("application/mp4") == "video"
    assert placeholder_kind("application/json") is None
    assert placeholder_kind("") is None


def test_placeholder_ignores_preview_flags():
    # even with --full / --hex an image stays a one-line placeholder
    opts = BodyDisplayOptions(hexdump=True, full=True)
    assert summarize_undecoded(b"\xff" * 100, "image/png", opts) == "<image: image/png, 100 bytes>"


# --- repr vs hex, truncation vs full -----------------------------------------

def test_repr_preview_truncates_by_default():
    out = summarize_undecoded(b"A" * 200, "application/cbor")
    assert "(not decoded: application/cbor, 200 bytes)" in out
    assert "first 64 of 200 bytes" in out
    assert "A" * 200 not in out


def test_full_disables_truncation():
    out = summarize_undecoded(b"A" * 200, "application/cbor", BodyDisplayOptions(full=True))
    assert "A" * 200 in out
    assert "first" not in out          # no truncation note


def test_hexdump_mode():
    out = summarize_undecoded(b"hello\x00world", "application/octet-stream",
                              BodyDisplayOptions(hexdump=True))
    assert "0000" in out               # offset column
    assert "68 65 6c 6c 6f" in out     # "hello" in hex
    assert "|hello.world|" in out      # ascii gutter (NUL shown as '.')


def test_hexdump_layout():
    out = hexdump(bytes(range(16)))
    # offset, 16 hex cells grouped 8+8, ascii gutter
    assert out.startswith("   0000  ")
    assert "00 01 02 03 04 05 06 07" in out
    assert "08 09 0a 0b 0c 0d 0e 0f" in out
    assert out.rstrip().endswith("|")


def test_no_content_type_label():
    assert "no content-type" in summarize_undecoded(b"\x00\x01", "")
