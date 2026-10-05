"""Vendored ARPC payload decompression: Apple bvx/LZ4 framing + gzip.

This machinery moved into ios_decoder.arpc (it was re-exported from
mitm_traffic_parser before the decoupling), so ios_decoder owns its coverage now:
the bvx block framing (bv41/bv4-/bv4$), the inter-block LZ4 preset dictionary,
the size caps, the error paths, and gzip.  The synthetic tests pin the framing
deterministically; the live test decompresses REAL ARPC uploads from a git-ignored
capture when one is present (else skips — no device data is committed).
"""

from __future__ import annotations

import glob
import gzip
import struct
from pathlib import Path

import pytest

from ios_decoder import arpc, rawproto

_REPO = Path(__file__).resolve().parents[2]


# --- Apple bvx / LZ4 framing -------------------------------------------------

def test_decompress_bvx_stored_block():
    # bv4- stored (uncompressed) block, then the end marker.
    raw = b"hello world, stored block payload"
    stream = b"bv4-" + struct.pack("<I", len(raw)) + raw + b"bv4$"
    assert arpc.decompress_bvx(stream) == raw


def test_decompress_bvx_compressed_block_roundtrip():
    lz4block = pytest.importorskip("lz4.block")
    raw = b"GEOLogMessage payload " * 40  # compressible
    comp = lz4block.compress(raw, store_size=False)
    stream = (b"bv41" + struct.pack("<I", len(raw)) + struct.pack("<I", len(comp))
              + comp + b"bv4$")
    assert arpc.decompress_bvx(stream) == raw


def test_decompress_bvx_multiblock_uses_inter_block_dict():
    # Apple bvx CHAINS blocks: block 2's LZ4 matches can back-reference block 1's
    # output, so the decompressor must hand the prior output to lz4 as a preset dict.
    # Without it block 2 fails with an lz4 "insufficient space" error and large hvr
    # uploads stay raw — this is the exact bug the dict= fix closed.
    lz4b = pytest.importorskip("lz4.block")
    b1 = b"the quick brown fox " * 60
    b2 = b"the quick brown fox " * 40 + b"TAIL"
    c1 = lz4b.compress(b1, store_size=False)
    c2 = lz4b.compress(b2, store_size=False, dict=b1)     # block 2 encoded against block 1
    stream = (b"bv41" + struct.pack("<I", len(b1)) + struct.pack("<I", len(c1)) + c1
              + b"bv41" + struct.pack("<I", len(b2)) + struct.pack("<I", len(c2)) + c2
              + b"bv4$")
    assert arpc.decompress_bvx(stream) == b1 + b2


def test_decompress_bvx_mixed_compressed_and_stored():
    lz4block = pytest.importorskip("lz4.block")
    a = b"first compressed segment " * 8
    comp = lz4block.compress(a, store_size=False)
    b = b"STORED-SEGMENT"
    stream = (b"bv41" + struct.pack("<I", len(a)) + struct.pack("<I", len(comp)) + comp
              + b"bv4-" + struct.pack("<I", len(b)) + b
              + b"bv4$")
    assert arpc.decompress_bvx(stream) == a + b


def test_decompress_bvx_error_paths():
    with pytest.raises(arpc.DecompressError):                 # unknown magic
        arpc.decompress_bvx(b"XXXX\x00\x00\x00\x00")
    with pytest.raises(arpc.DecompressError):                 # truncated bv41 header
        arpc.decompress_bvx(b"bv41\x10\x00")
    with pytest.raises(arpc.DecompressError):                 # truncated bv4- header
        arpc.decompress_bvx(b"bv4-\x10")
    with pytest.raises(arpc.DecompressError):                 # bv41 block shorter than enc_size
        arpc.decompress_bvx(b"bv41" + struct.pack("<I", 10) + struct.pack("<I", 10) + b"abc")
    with pytest.raises(arpc.DecompressError):                 # bv4- stored block truncated
        arpc.decompress_bvx(b"bv4-" + struct.pack("<I", 50) + b"short")


def test_decompress_bvx_corrupt_block_is_wrapped():
    # valid bv41 framing but a garbage compressed block -> wrapped as DecompressError,
    # never a raw lz4 library exception leaking to the caller.
    bad = (b"bv41" + struct.pack("<I", 100) + struct.pack("<I", 5)
           + b"\xff\xff\xff\xff\xff" + b"bv4$")
    with pytest.raises(arpc.DecompressError):
        arpc.decompress_bvx(bad)


def test_decompress_bvx_size_caps():
    # oversized bv41 decoded-size and bv4- stored-size are both rejected (alloc guard)
    with pytest.raises(arpc.DecompressError):
        arpc.decompress_bvx(b"bv41" + struct.pack("<I", 999_999_999)
                            + struct.pack("<I", 1) + b"\x00" + b"bv4$", max_output=1024)
    with pytest.raises(arpc.DecompressError):
        arpc.decompress_bvx(b"bv4-" + struct.pack("<I", 999_999_999) + b"\x00",
                            max_output=1024)


def test_looks_compressed():
    assert arpc.looks_compressed(b"bv41xxxx")
    assert arpc.looks_compressed(b"bv4-xxxx")
    assert not arpc.looks_compressed(b"\x08\x01")
    assert not arpc.looks_compressed(b"")


def test_decompress_payload_passthrough_and_unsupported():
    assert arpc.decompress_payload(b"abc", "") == b"abc"          # no algo = passthrough
    with pytest.raises(arpc.DecompressError):
        arpc.decompress_payload(b"abc", "ZSTD")                   # unsupported algo


# --- gzip --------------------------------------------------------------------

def test_looks_gzip():
    assert arpc.looks_gzip(gzip.compress(b"anything"))
    assert arpc.looks_gzip(b"\x1f\x8b\x08\x00")
    assert not arpc.looks_gzip(b"\x08\x01")
    assert not arpc.looks_gzip(b"\x1f")        # too short for the 2-byte magic
    assert not arpc.looks_gzip(b"")


def test_decompress_gzip_roundtrip():
    raw = b"GEOWiFiQualityServiceRequest payload " * 20   # compressible
    assert arpc.decompress_gzip(gzip.compress(raw)) == raw


def test_decompress_gzip_error_paths():
    with pytest.raises(arpc.DecompressError):                 # not gzip at all
        arpc.decompress_gzip(b"not gzip bytes")
    with pytest.raises(arpc.DecompressError):                 # valid magic, corrupt stream
        arpc.decompress_gzip(b"\x1f\x8b\x08\x00\xff\xff\xff\xff")
    # output exceeding the cap is rejected (gzip-bomb guard), not silently truncated
    with pytest.raises(arpc.DecompressError):
        arpc.decompress_gzip(gzip.compress(b"A" * 4096), max_output=16)


# --- v2-compressed header round-trip through strip_request -------------------

def test_strip_request_decompresses_lz4_payload():
    """A v2 ARPC header declaring LZ4 must strip AND decompress in one call."""
    lz4block = pytest.importorskip("lz4.block")
    inner = b"\x08\x96\x01" + b"\x12\x05hello"        # a small real protobuf body
    comp = lz4block.compress(inner, store_size=False)
    bvx = (b"bv41" + struct.pack("<I", len(inner)) + struct.pack("<I", len(comp))
           + comp + b"bv4$")
    # build a v2 request header by hand: version=2, three strings, algo="LZ4", fid, len
    def s(b):
        return struct.pack("!H", len(b)) + b
    header = (struct.pack("!H", 2) + s(b"en_US") + s(b"com.apple.geod") + s(b"17.0")
              + s(b"LZ4") + struct.pack("!I", 1017) + struct.pack("!I", len(bvx)))
    hdr, payload, warn = arpc.strip_request(header + bvx)
    assert hdr is not None and hdr.compression_algo == "LZ4" and hdr.function_id == 1017
    assert payload == inner and warn is None
    assert rawproto.is_valid_protobuf(payload)        # the recovered bytes really are protobuf


# --- live: decompress REAL ARPC uploads from a git-ignored capture -----------

def _compressed_arpc_requests():
    """(url, body) for every LZ4-compressed ARPC request across available captures,
    or [] if none is present (then the live test skips). No device data is committed."""
    pytest.importorskip("mitmproxy")
    from mitmproxy import io as mio
    caps = (sorted(glob.glob(str(_REPO / "ios_decoder" / "comparison" / "*.mitm")))
            + sorted(glob.glob(str(_REPO / "iphone8_data" / "captures" / "*.mitm")))
            + sorted(glob.glob(str(_REPO / "iphone12_data" / "captures" / "*.mitm"))))
    out = []
    for cap in caps:
        try:
            with open(cap, "rb") as fh:
                flows = list(mio.FlowReader(fh).stream())
        except Exception:
            continue
        for fl in flows:
            if getattr(fl, "request", None) is None:
                continue
            body = fl.request.content or b""
            hdr = arpc.parse_request_header(body)
            if hdr is not None and hdr.compression_algo:
                out.append((fl.request.pretty_url, body))
        if out:
            break          # one capture with compressed ARPC traffic is enough
    return out


def test_live_compressed_arpc_decompresses_to_protobuf():
    bodies = _compressed_arpc_requests()
    if not bodies:
        pytest.skip("no git-ignored capture with LZ4-compressed ARPC requests present")
    pytest.importorskip("lz4.block")
    checked = 0
    for url, body in bodies:
        hdr, payload, warn = arpc.strip_request(body)
        assert hdr is not None and hdr.compression_algo == "LZ4", url
        # real Apple uploads must decompress cleanly (no warning)...
        assert warn is None, f"{url}: {warn}"
        # ...into genuine, non-empty protobuf wire.  A clean decompress of a large
        # multi-block upload is exactly the inter-block-dictionary path; small
        # uploads ride a single stored block — both must end up as valid protobuf.
        assert payload, f"{url}: empty payload after decompression"
        assert rawproto.is_valid_protobuf(payload), f"{url}: decompressed body is not protobuf"
        checked += 1
    assert checked > 0
