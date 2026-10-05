"""rawproto must match `protoc --decode_raw` byte-for-byte (tested against protoc itself)."""

import shutil
import struct
import subprocess

import pytest

from ios_decoder import rawproto

_HAS_PROTOC = shutil.which("protoc") is not None
protoc_only = pytest.mark.skipif(not _HAS_PROTOC, reason="protoc not installed")


def _tag(field, wt):
    v = (field << 3) | wt
    out = b""
    while True:
        b = v & 0x7F; v >>= 7
        out += bytes([b | 0x80]) if v else bytes([b])
        if not v:
            return out


def _varint(n):
    out = b""
    while True:
        b = n & 0x7F; n >>= 7
        out += bytes([b | 0x80]) if n else bytes([b])
        if not n:
            return out


def _protoc_decode_raw(data: bytes) -> str:
    p = subprocess.run(["protoc", "--decode_raw"], input=data, capture_output=True)
    return p.stdout.decode("utf-8", "replace").rstrip("\n")


# A spread of wire shapes that exercise every render branch + the string/message rule.
CASES = {
    "varint":           _tag(1, 0) + _varint(150),
    "varint_big":       _tag(1, 0) + _varint(4632701970978117693),
    "fixed64":          _tag(1, 1) + struct.pack("<Q", 0x404AA9E5C267183D),
    "fixed64_neg1":     _tag(1, 1) + struct.pack("<q", -1),
    "fixed32":          _tag(1, 5) + struct.pack("<I", 0x12345678),
    "string":           _tag(1, 2) + bytes([5]) + b"hello",
    "empty_string":     _tag(1, 2) + bytes([0]),
    "nested_message":   _tag(1, 2) + bytes([2]) + _tag(1, 0) + _varint(7),
    "ascii_not_msg":    _tag(1, 2) + bytes([10]) + b"analyticsd",
    "non_utf8":         _tag(1, 2) + bytes([3]) + b"\xff\x01\x02",
    "escapes":          _tag(1, 2) + bytes([7]) + b'a"\'\\\t\nb',
    "repeated":         _tag(1, 0) + _varint(1) + _tag(1, 0) + _varint(2),
    "high_field":       _tag(10000, 0) + _varint(48),
    "deep_nest":        _tag(1, 2) + bytes([4]) + _tag(1, 2) + bytes([2]) + _tag(1, 0) + _varint(9),
}


@protoc_only
@pytest.mark.parametrize("name", list(CASES))
def test_matches_protoc(name):
    data = CASES[name]
    assert rawproto.decode_raw(data) == _protoc_decode_raw(data), name


def test_invalid_bytes_raise():
    with pytest.raises(rawproto.RawDecodeError):
        rawproto.decode_raw(bytes.fromhex("0a"))   # length-delimited tag, no body


def test_cescape_rules():
    assert rawproto.cescape(b'a"b') == 'a\\"b'
    assert rawproto.cescape(b"a\x7fb") == "a\\177b"
    assert rawproto.cescape(b"\x00\x80") == "\\000\\200"
    assert rawproto.cescape(b"plain text 123") == "plain text 123"


def test_fixed64_is_hex():
    out = rawproto.decode_raw(_tag(3, 1) + struct.pack("<Q", 0xDEADBEEFCAFEBABE))
    assert out == "3: 0xdeadbeefcafebabe"


# --- protoc-matching float/double formatting --------------------------------

def test_format_double_whole_numbers_have_no_decimal():
    assert rawproto.format_double(0.0) == "0"
    assert rawproto.format_double(-1.0) == "-1"
    assert rawproto.format_double(360.0) == "360"


def test_format_double_roundtrips_protoc_strings():
    # synthetic doubles whose 15-digit rendering does not round-trip; 16 digits would, but
    # protobuf skips 16 and emits 17 (protoc's %.15g/%.17g ladder), so the double each
    # string denotes must format back to the same string
    for s in ["200.21223433024821", "-203.39225197451671", "200.92667969248109",
              "202.58895753294581", "-204.68312991907609"]:
        assert rawproto.format_double(float(s)) == s


_DOUBLE_FLOAT_PROTO = """syntax = "proto2";
message DF { optional double d = 1; optional float f = 2; }
"""


@protoc_only
def test_double_and_float_match_protoc_decode(tmp_path):
    """Encode crafted double/float wire bytes, decode with the protoc binary against a
    schema, and confirm our formatters reproduce protoc's exact text."""
    proto = tmp_path / "df.proto"
    proto.write_text(_DOUBLE_FLOAT_PROTO)
    values = [0.0, -1.0, 360.0, 200.21223433024821, -203.39225197451671,
              200.92667969248109, 1.5, 3.1415927]
    for v in values:
        wire = _tag(1, 1) + struct.pack("<d", v) + _tag(2, 5) + struct.pack("<f", v)
        p = subprocess.run(["protoc", "--decode=DF", "-I", str(tmp_path), "df.proto"],
                           input=wire, capture_output=True)
        protoc_out = p.stdout.decode().rstrip("\n")
        f32 = struct.unpack("<f", struct.pack("<f", v))[0]
        ours = f"d: {rawproto.format_double(v)}\nf: {rawproto.format_float(f32)}"
        assert ours == protoc_out, f"v={v!r}\n ours={ours!r}\n protoc={protoc_out!r}"


def test_is_valid_protobuf_detects_clean_wire():
    # a clean varint field (8: 150) and a length-delimited field are protobuf
    assert rawproto.is_valid_protobuf(b"\x08\x96\x01")
    assert rawproto.is_valid_protobuf(_tag(1, 2) + b"\x03abc")
    # min_fields gate: a single-field body fails a 2-field requirement
    assert not rawproto.is_valid_protobuf(b"\x08\x96\x01", min_fields=2)


def test_is_valid_protobuf_rejects_non_protobuf():
    assert not rawproto.is_valid_protobuf(b"")                 # empty
    assert not rawproto.is_valid_protobuf(b"\x08")             # truncated varint
    assert not rawproto.is_valid_protobuf(b"\x00\x01")         # field number 0
    assert not rawproto.is_valid_protobuf(b"{\"json\": 1}")    # JSON, not wire
    assert not rawproto.is_valid_protobuf(_tag(1, 3))          # top-level group => not clean
