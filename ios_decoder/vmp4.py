"""Detect protobuf-framed ``/{style}/v2/{style}/{quadkey}`` map-tile bodies.

CORRECTION (2026-10-04).  This module was written on the belief that these
bodies are Apple's **VMP4** vector-tile format, and its function (formerly
``is_vmp4``, now ``is_smart_interface_selection_tile``) and CLI said so.
Measurements on the iphone8 capture corpus show that belief is wrong:

* VMP4 is the format of the ``gspe19-ssl.ls.apple.com/tile.vf`` responses.  All
  159 successful (HTTP 200) ``tile.vf`` responses in the iphone8 captures begin
  with the ASCII bytes ``VMP4`` (after optional gzip).  They are *not*
  protobuf-framed.  The layout, as described by Spangenberger (2020,
  digitalforensics.io, "iOS Forensics: VMP4 File format") and by the ``vmp4-dump``
  tool, and checked on those 159 bodies, is::

      bytes 0-3    "VMP4"
      bytes 4-5    00 00                          (always zero in our captures)
      bytes 6-7    n, number of sections          (uint16, little-endian)
      bytes 8..    n section-table entries of 10 bytes: type (uint16), offset
                   (uint32), size (uint32), all little-endian
      (then n further bytes before the first section, purpose unknown)

  In every one of the 159 bodies the entries lie inside the file, the sections
  are contiguous and the last one ends at end of file.  A section's data starts
  with a flag byte: 0 means the data follows as-is, 1 means a uint32 length
  follows and then a zlib stream (all 593 flagged sections inflate to exactly
  that length).  25 section types occur.  The expansion of the name "VMP4" is not
  documented anywhere we could find.

* ``is_smart_interface_selection_tile`` does **not** match any of those 159 bodies.  The 13 bodies it does
  match in the iphone8 captures are all ``gspe79-ssl.ls.apple.com/72/v2/72/<quadkey>``
  responses (style 72).  They begin with protobuf field 1 ``fixed32`` (tag 0x0d),
  contain no ``VMP4`` bytes anywhere, and validate as protobuf with the layout
  below.  They parse cleanly as the ``SmartInterfaceSelectionTile`` protobuf
  (``addon_ios/SmartInterfaceSelection.proto``: checksum, cell ids, network id
  hash), confirmed by the project owner on 2026-06-17.  That descriptor is
  hand-crafted (reverse engineered from a decoder, not extracted from PBCodable
  metadata).  So these bodies are protobuf tiles, and the claim that they are the
  VMP4 container of ``tile.vf`` is refuted.

So ``is_smart_interface_selection_tile`` means "looks like a SmartInterfaceSelectionTile
protobuf tile", not "is VMP4".  A real VMP4 check is ``body[:4] == b"VMP4"`` after
gunzip.  The module file keeps the name ``vmp4.py`` so the import path is unchanged.

Protobuf layout that ``is_smart_interface_selection_tile`` tests for::

    field 1         fixed32  ┐  large projected integers (tile origin x, y?)
    field 2         fixed32  ┘
    field 3         length-delimited  (first payload/section block)
    fields 4-9      length-delimited  (further blocks)
    field 10        length-delimited, repeated

Leading with *two* ``fixed32`` fields is what separates these bodies from
arbitrary protobuf; almost nothing else starts that way.

GeoServices side (from earlier binary analysis, not re-verified here): the tile
is fetched by a ``GEOVoltaireTileRequester`` (wrapped raw into a non-protobuf
``GEOTileData`` container) and decoded by ``GEOVectorTileDecoder decodeTile:forKey:``
-> ``-[GEOVectorTile initWithVMP4:localizationData:tileKey:]`` (GeoCodecs).
``GEOVectorTile`` is not a PBCodable class (no ``readFrom:``/``writeTo:``), so
VMP4 is hand-parsed and there is no generated ``.proto`` for it.  Which request
URLs reach that decoder was inferred, not measured, which is how the style-72
tiles came to be mislabelled as VMP4.

URL shapes (host ``gspe*-ssl.ls.apple.com``):
  * ``/{style}/v2/{style}/{quadkey}``: single gzip body; this detector's target.
  * ``/{style}/v1/zoom{z}/{quad}.tar.gz``: gzip -> tar -> a "bdb" key/value store
    whose values are per-feature protobuf records.  Not targeted.
  * ``/tile.vf``: genuine VMP4 (see above).  Not targeted.

Accuracy of the *protobuf-layout* test (measured earlier on the bundled iphone8 +
iphone12 corpora, two devices / regions / iOS versions; the iphone8 row was
re-run on 2026-10-04 and gives the same 13):

==========  ===========  ====================  ===============================
corpus      v2 bodies    detected (recall)     false positives
==========  ===========  ====================  ===============================
iphone8     13           13  (100%)            0 / 311 other protobuf bodies
iphone12    12           12  (100%)            0 / 479 other protobuf bodies
ALL         25           25  (100%)            0 / 790 other protobuf bodies
==========  ===========  ====================  ===============================

Plus 0 spurious matches across 15,178 non-protobuf bodies.  Recall held at 100%
on iphone12 (a different region, so different origin coordinates), which is why
the plausibility check below is deliberately *loose* (non-degenerate) rather than
a geographic value range: a tight range would overfit the capture location.

The core ``is_smart_interface_selection_tile(bytes)`` has no third-party dependencies (only ``gzip`` /
``struct``).  The ``__main__`` capture scanner additionally needs ``mitmproxy``.

Provenance: copied verbatim from the retired ``mitm_traffic_parser.vmp4`` so
ios_decoder owns the detector with no cross-tool dependency.  See
``notes/VMP4_TILE_FORMAT.md`` (corrected 2026-10-04) for the full writeup.
"""

from __future__ import annotations

import gzip
import struct
from typing import List, Optional, Tuple


def _maybe_gunzip(b: bytes) -> bytes:
    """Transparently inflate a gzip-wrapped body (style-72 v2 bodies are gzipped)."""
    if b[:2] == b"\x1f\x8b":
        try:
            return gzip.decompress(b)
        except OSError:
            pass
    return b


def _read_varint(b: bytes, i: int) -> Tuple[int, int]:
    shift = val = 0
    while True:
        if i >= len(b):
            raise IndexError
        x = b[i]
        i += 1
        val |= (x & 0x7F) << shift
        shift += 7
        if not x & 0x80:
            return val, i


def protobuf_top_fields(buf: bytes) -> Optional[List[Tuple[int, int]]]:
    """Strictly scan *buf* as a protobuf message.

    Returns the ordered list of top-level ``(field_number, wire_type)`` pairs, or
    ``None`` if *buf* is not a clean, fully-consumed protobuf message.  Wire types
    3/4 (groups) and 6/7 (reserved) are treated as "not modern protobuf".
    """
    i = 0
    out: List[Tuple[int, int]] = []
    try:
        while i < len(buf):
            tag, i = _read_varint(buf, i)
            fn, wt = tag >> 3, tag & 7
            if fn == 0 or wt in (3, 4, 6, 7):
                return None
            if wt == 0:
                _, i = _read_varint(buf, i)
            elif wt == 1:
                i += 8
            elif wt == 5:
                i += 4
            elif wt == 2:
                ln, i = _read_varint(buf, i)
                if i + ln > len(buf):
                    return None
                i += ln
            out.append((fn, wt))
    except IndexError:
        return None
    return out if i == len(buf) else None


def _plausible_origin(f1: int, f2: int) -> bool:
    """Sanity-check the two leading fixed32s as tile-origin coordinates.

    Deliberately loose: tile origins are large projected integers that vary with
    location, so we only reject *degenerate* values (zero / all-ones fills, or the
    clearly-non-coordinate case where both are tiny).  A geographic value range
    would overfit the capture region and reject tiles elsewhere on Earth.
    """
    for v in (f1, f2):
        if v in (0, 0xFFFFFFFF):
            return False
    if f1 < (1 << 16) and f2 < (1 << 16):
        return False
    return True


def is_smart_interface_selection_tile(body: bytes) -> bool:
    """Return True if *body* (raw or gzip-encoded) has the protobuf tile layout in
    the module docstring.

    This is NOT a VMP4 test: genuine VMP4 bodies (``tile.vf``) start with the
    bytes ``VMP4`` and are not protobuf, so they return False.  What matches are
    the style-72 ``/72/v2/72/<quadkey>`` tiles (SmartInterfaceSelectionTile
    protobuf).  Detection is purely structural.
    """
    b = _maybe_gunzip(body)
    # Fast reject on the fixed-offset tag bytes: f1=fixed32 (0x0d) at 0, f2=fixed32
    # (0x15) at 5 (=tag + 4 data bytes), f3=len-delim (0x1a) at 10.
    if len(b) < 11 or b[0] != 0x0D or b[5] != 0x15 or b[10] != 0x1A:
        return False
    fields = protobuf_top_fields(b)
    if not fields:
        return False
    if fields[0] != (1, 5) or fields[1] != (2, 5) or fields[2][1] != 2:
        return False
    if sum(1 for fn, _ in fields if fn == 10) < 2:   # repeated feature field
        return False
    f1 = struct.unpack_from("<I", b, 1)[0]
    f2 = struct.unpack_from("<I", b, 6)[0]
    return _plausible_origin(f1, f2)


# ── CLI: classify a body file, or scan a .mitm capture ────────────────────────

def _main(argv: List[str]) -> int:
    import argparse

    ap = argparse.ArgumentParser(
        description="Detect SmartInterfaceSelectionTile-layout protobuf tile bodies (see module docstring)."
    )
    ap.add_argument("path", help="a response-body file, or a .mitm capture with --scan")
    ap.add_argument("--scan", action="store_true",
                    help="treat PATH as a mitmproxy capture and report every matching flow")
    args = ap.parse_args(argv)

    if not args.scan:
        with open(args.path, "rb") as fh:
            data = fh.read()
        verdict = is_smart_interface_selection_tile(data)
        print("SmartInterfaceSelectionTile layout" if verdict else "no match")
        fields = protobuf_top_fields(_maybe_gunzip(data))
        if fields is not None:
            print("  top-level fields (num,wt):", fields[:16],
                  "…" if len(fields) > 16 else "")
        return 0 if verdict else 1

    from mitmproxy import io as mio   # noqa: WPS433 (optional dep, CLI-only)
    n = hit = 0
    with open(args.path, "rb") as fh:
        for f in mio.FlowReader(fh).stream():
            if f.__class__.__name__ != "HTTPFlow" or not f.response:
                continue
            body = f.response.raw_content
            if not body:
                continue
            n += 1
            if is_smart_interface_selection_tile(body):
                hit += 1
                print(f"MATCH  {f.request.pretty_url}")
    print(f"\n{hit} matching tile(s) of {n} response bodies in {args.path}")
    return 0


if __name__ == "__main__":
    import sys
    raise SystemExit(_main(sys.argv[1:]))
