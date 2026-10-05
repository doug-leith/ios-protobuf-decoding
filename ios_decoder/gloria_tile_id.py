"""
gloria_tile_id.py

Computes the Gloria tile key integer from a latitude, longitude, and zoom level.
Reverse-engineered from WiFiPolicy / GeoServices binaries via Hopper.

Pipeline (matching the binary exactly):
  1. gloria::TileCoordinate::FromLatLng  — clamp coords, Web Mercator → tile x/y
  2. gloria::MortonUtils::XYToQuadId    — bit-interleave x/y into a Morton code
  3. gloria::TileId::GetEncodedTileId   — OR in a zoom-level leading-bit sentinel
"""

import math
import sys

# ---------------------------------------------------------------------------
# Constants (loaded from binary data segment)
# ---------------------------------------------------------------------------

_LAT_MAX =  85.05112877980659   # double_value_85_0511
_LAT_MIN = -85.05112877980659   # double_value_minus_85_0511
_LNG_MAX =  180.0               # double_value_180
_LNG_MIN = -180.0               # double_value_minus_180


# ---------------------------------------------------------------------------
# Step 1 – TileCoordinate::FromLatLng
# ---------------------------------------------------------------------------

def _lat_lng_to_tile_xy(lat: float, lng: float, zoom: int) -> tuple[int, int]:
    """
    Mirrors gloria::TileCoordinate::FromLatLng(lat, lng, zoom).

    ARM assembly key operations:
      x_frac = (lng + 180) / 360
      lat_rad = lat * π / 180
      sin_lat = sin(lat_rad)                  ← thunk loc_1c2d3d334 = sin()
      ratio   = (1 + sin_lat) / (1 - sin_lat)
      merc_y  = log(ratio) / (-4π)            ← thunk loc_1c2d3ced8 = log()
      x_tile  = floor(x_frac      * numTiles)   (fcvtmu)
      y_tile  = floor((merc_y + 0.5) * numTiles) (fcvtmu)
      both clamped to [0, numTiles - 1]
    """
    # Clamp inputs (fmaxnm / fminnm in the assembly)
    lng = max(_LNG_MIN, min(_LNG_MAX, lng))
    lat = max(_LAT_MIN, min(_LAT_MAX, lat))

    num_tiles = 1 << zoom   # 2^zoom  (lsl x9, x9, x8 in assembly)

    # X tile – straightforward longitude mapping
    x_frac = (lng + 180.0) / 360.0
    x_tile = int(x_frac * num_tiles)            # fcvtmu (floor toward -inf)

    # Y tile – Web Mercator via sin + log
    # Equivalent to the standard OSM formula:
    #   y_frac = (1 - log(tan(π/4 + lat_rad/2)) / π) / 2
    # but expressed as the binary computes it:
    #   merc_y = log((1 + sin(lat_rad)) / (1 - sin(lat_rad))) / (−4π)
    lat_rad = lat * math.pi / 180.0
    sin_lat = math.sin(lat_rad)
    merc_y  = math.log((1.0 + sin_lat) / (1.0 - sin_lat)) / (-4.0 * math.pi)
    y_tile  = int((merc_y + 0.5) * num_tiles)   # fcvtmu

    # Clamp to [0, numTiles - 1]  (csel instructions)
    x_tile = min(x_tile, num_tiles - 1)
    y_tile = min(y_tile, num_tiles - 1)

    return x_tile, y_tile


# ---------------------------------------------------------------------------
# Step 2 – MortonUtils::XYToQuadId
# ---------------------------------------------------------------------------

def _spread_bits(n: int) -> int:
    """
    Spread the 32 bits of n into even bit positions (0, 2, 4, …).
    Mirrors the NEON bit-spreading in XYToQuadId — confirmed by reading
    the inverse in ToXYZ which does:
        and v0.16b, v0.16b, #0x5555…   ← recovers x (even bits)
        (morton >> 1) & 0x5555…        ← recovers y (odd bits)
    """
    n &= 0x00000000FFFFFFFF
    n  = (n | (n << 16)) & 0x0000FFFF0000FFFF
    n  = (n | (n <<  8)) & 0x00FF00FF00FF00FF
    n  = (n | (n <<  4)) & 0x0F0F0F0F0F0F0F0F
    n  = (n | (n <<  2)) & 0x3333333333333333
    n  = (n | (n <<  1)) & 0x5555555555555555
    return n


def _xy_to_quad_id(x_tile: int, y_tile: int) -> int:
    """
    Mirrors gloria::MortonUtils::XYToQuadId(x, y).
    x bits → even positions; y bits → odd positions.
    Confirmed by ToXYZ which reconstructs with:
        fmov d0, morton; mov v0.d[1], morton>>1
        and both lanes with 0x5555…, then de-spreads identically.
    """
    return _spread_bits(x_tile) | (_spread_bits(y_tile) << 1)


# ---------------------------------------------------------------------------
# Step 3 – TileId::GetEncodedTileId
# ---------------------------------------------------------------------------

def _get_encoded_tile_id(morton: int, zoom: int) -> int:
    """
    Mirrors gloria::TileId::GetEncodedTileId().

    Assembly:
        ldrb  w9, [x0, #8]              ; zoom
        ldr   x8, [LEADING_BITS_LUT + zoom*8]  ; = 1 << (2*zoom) = 4^zoom
        ldr   x9, [x0]                  ; morton code
        orr   x0, x9, x8               ; encoded = morton | leading_bit

    The leading bit sentinel is confirmed by Zoom() which recovers zoom as:
        clz(encoded_id) → MSB position = 2*zoom → zoom = MSB_pos >> 1
    So the MSB must sit at bit 2*zoom, i.e. leading_bit = 1 << (2*zoom).
    """
    leading_bit = 1 << (2 * zoom)   # 4^zoom
    return morton | leading_bit


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def gloria_tile_id(lat: float, lng: float, zoom: int) -> int:
    """
    Return the Gloria-encoded tile key integer for (lat, lng, zoom).

    This matches the value placed into the X-tilekey HTTP header by
    GEOWiFiQualityTileRequester, originating from:
      TBGloriaTile.initWithLat:lng:zoom: → key → TBTileItemDescriptor
      → GEOWiFiQualityServiceRemoteProxy → XPC wifitk → geod
      → GEOWiFiQualityTileRequester.startWithQueue:completion:
      → [headers setObject:tileKey forKey:@"X-tilekey"]

    Args:
        lat:  Latitude  in degrees  [-85.051, +85.051]
        lng:  Longitude in degrees  [-180,    +180   ]
        zoom: Zoom level (0–22 typical)

    Returns:
        64-bit Gloria tile ID integer.

    Example:
        >>> gloria_tile_id(37.3318, -122.0312, 15)
    """
    x_tile, y_tile = _lat_lng_to_tile_xy(lat, lng, zoom)
    morton         = _xy_to_quad_id(x_tile, y_tile)
    return         _get_encoded_tile_id(morton, zoom)


# ---------------------------------------------------------------------------
# Decode (mirrors ToXYZ + inverse Mercator, useful for verification)
# ---------------------------------------------------------------------------

def decode_gloria_tile_id(encoded: int) -> tuple[int, int, int]:
    """
    Decode a Gloria tile ID back to (x_tile, y_tile, zoom).
    Mirrors gloria::TileId::ToXYZ and gloria::TileId::Zoom.

    Raises ``ValueError`` for a non-positive id: a tile id is a positive Morton code with a
    set leading bit, so 0/negative is malformed input (it would otherwise hit a negative-shift
    crash or fabricate a garbage x/y) — fail noisily so the caller can flag/skip it.
    """
    if encoded <= 0:
        raise ValueError(f"gloria tile id must be a positive integer, got {encoded}")
    # Zoom: MSB position / 2  (from Zoom() assembly: ubfx w0, MSB_pos, #1, #8)
    msb_pos = encoded.bit_length() - 1
    zoom    = msb_pos >> 1

    # Strip the leading bit to recover the raw morton code
    morton  = encoded ^ (1 << (2 * zoom))

    # De-interleave: x at even bits, y at odd bits
    x_tile = _compact_bits(morton)
    y_tile = _compact_bits(morton >> 1)

    return x_tile, y_tile, zoom


def _compact_bits(n: int) -> int:
    """Inverse of _spread_bits — collapse even-position bits back to contiguous."""
    n &= 0x5555555555555555
    n  = (n | (n >>  1)) & 0x3333333333333333
    n  = (n | (n >>  2)) & 0x0F0F0F0F0F0F0F0F
    n  = (n | (n >>  4)) & 0x00FF00FF00FF00FF
    n  = (n | (n >>  8)) & 0x0000FFFF0000FFFF
    n  = (n | (n >> 16)) & 0x00000000FFFFFFFF
    return n


# ---------------------------------------------------------------------------
# Tile x/y/zoom → lat/lng  (inverse of _lat_lng_to_tile_xy)
# ---------------------------------------------------------------------------

def tile_xy_to_lat_lng(x_tile: int, y_tile: int, zoom: int) -> tuple[float, float]:
    """
    Decode tile (x_tile, y_tile, zoom) back to (latitude, longitude) in degrees.

    Inverse of gloria::TileCoordinate::FromLatLng:

      Encoding was:
        x_frac  = (lng + 180) / 360
        x_tile  = floor(x_frac * N)          → lng = x_tile / N * 360 - 180

        merc_y  = log((1 + sin(lat_rad)) / (1 - sin(lat_rad))) / (-4π)
        y_tile  = floor((merc_y + 0.5) * N)  → merc_y = y_tile / N - 0.5

      Inverting merc_y back to lat:
        -4π * merc_y = log((1 + sin) / (1 - sin))
        k = exp(-4π * merc_y)    where k = (1 + sin) / (1 - sin)
        sin(lat_rad) = (k - 1) / (k + 1)
        lat = asin((k - 1) / (k + 1))

      (Equivalent to the standard OSM form: lat = atan(sinh(π*(1 - 2*y/N))))

    Returns the lat/lng at the *centre* of the tile.
    """
    num_tiles = 1 << zoom  # 2^zoom

    # Longitude: centre of tile (add 0.5 to land in the middle)
    lng = (x_tile + 0.5) / num_tiles * 360.0 - 180.0

    # Latitude: invert Web Mercator
    merc_y = (y_tile + 0.5) / num_tiles - 0.5
    k      = math.exp(-4.0 * math.pi * merc_y)
    lat    = math.degrees(math.asin((k - 1.0) / (k + 1.0)))

    #lat = math.atan(math.sinh(math.pi * (1 - 2 * merc_y / num_tiles))) * 180/math.pi

    return lat, lng


def decode_gloria_tile_id_to_lat_lng(encoded: int) -> tuple[float, float, int]:
    """
    Convenience: decode a Gloria tile ID all the way to (lat, lng, zoom).

    Returns the lat/lng at the centre of the tile.
    """
    x_tile, y_tile, zoom = decode_gloria_tile_id(encoded)
    lat, lng = tile_xy_to_lat_lng(x_tile, y_tile, zoom)
    return lat, lng, zoom

def tile_size_meters(zoom: int, lat: float) -> tuple[float, float]:
    """
    Returns (width_m, height_m) of a Gloria tile at the given zoom and latitude.
    
    Width varies with latitude (cos correction); height is constant per zoom.
    """
    R = 6_378_137.0  # WGS-84 equatorial radius in metres
    tile_deg = 360.0 / (1 << zoom)          # degrees per tile (same for x and y)
    lat_rad  = math.radians(lat)

    width_m  = tile_deg * (math.pi / 180) * R * math.cos(lat_rad)
    height_m = tile_deg * (math.pi / 180) * R   # no cos — latitude spacing is uniform

    return width_m, height_m


def decode_gloria(tile_id):
        dec_lat, dec_lng, dec_zoom = decode_gloria_tile_id_to_lat_lng(tile_id)
        # Error is at most ±half a tile width, not zero, because we snap to tile centre
        tile_size_deg_lng = 360.0 / (1 << dec_zoom)
        tile_size_m = tile_size_meters(dec_zoom,dec_lat)
        return f"{tile_id:>10} {dec_lat:>10.4f} {dec_lng:>10.4f} {dec_zoom:>5} (tile width ≈ {tile_size_deg_lng:.4f}° or w={tile_size_m[0]:.0f}, h={tile_size_m[1]:.0f} metres)"

# ---------------------------------------------------------------------------
# Quick self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    if len(sys.argv)>1:
        #print(sys.argv)
        print("Decoding tile ID → lat/lng (tile centre)")
        print(f"{'tile_id':>10} {'dec_lat':>10} {'dec_lng':>10} {'zoom':>5}")
        for a in sys.argv[1:]:
            try:
                tile_id = int(a)
            except Exception as e:
                print(e)
                exit()
            print(decode_gloria(tile_id))
    else:
        tests = [
            (0.0,     0.0,      0),   # zoom 0 – single tile
            (0.0,     0.0,      1),   # zoom 1 – equator/prime meridian
            (51.5074, -0.1278,  10),  # London
            (37.3318, -122.0312, 15), # Apple Park
            (35.6762,  139.6503, 12), # Tokyo
        ]

        print("Encode lat/lng/zoom → tile ID:")
        print(f"{'lat':>10} {'lng':>10} {'zoom':>5}  {'tile_id':>20}")
        print("-" * 55)
        for lat, lng, zoom in tests:
            tile_id = gloria_tile_id(lat, lng, zoom)
            print(f"{lat:>10.4f} {lng:>10.4f} {zoom:>5}  {tile_id:>20}")

        print()
        print("Decode tile ID → lat/lng (tile centre), round-trip error:")
        print(f"{'tile_id':>20}  {'dec_lat':>10} {'dec_lng':>10} {'zoom':>5}  {'Δlat°':>9} {'Δlng°':>9}")
        print("-" * 80)
        for lat, lng, zoom in tests:
            tile_id = gloria_tile_id(lat, lng, zoom)
            dec_lat, dec_lng, dec_zoom = decode_gloria_tile_id_to_lat_lng(tile_id)
            # Error is at most ±half a tile width, not zero, because we snap to tile centre
            tile_size_deg_lng = 360.0 / (1 << zoom)
            print(f"{tile_id:>20}  {dec_lat:>10.4f} {dec_lng:>10.4f} {dec_zoom:>5}  "
                  f"{abs(dec_lat-lat):>9.5f} {abs(dec_lng-lng):>9.5f}"
                  f"  (tile width ≈ {tile_size_deg_lng:.4f}°)")
