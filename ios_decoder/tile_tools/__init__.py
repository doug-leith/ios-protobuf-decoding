"""Apple map/location tile parsers, as a uniform committed library.

The ``addon_ios/parse_*.py`` tools each grew their own calling convention (three load
idioms, five render-fn names, ``print``-based output), which forced ``ios_decoder.tiles`` to
wrap them in a tempfile + stdout-capture shim.  These migrated modules instead present **one
small contract**, so the decoder drives them directly — and each keeps a CLI for standalone
use (``python -m ios_decoder.tile_tools.<name> FILE``):

    parse(data: bytes) -> Tile      # raw body in (gunzips if needed); parsed object out
    render(tile) -> str             # human-readable text — returned, never printed
    bounds(tile) -> Bounds | None   # uniform geographic extent for +++ markers, or None

Tools are migrated one at a time; ``ios_decoder.tiles`` keeps the legacy shim for the
not-yet-migrated ones during the transition.
"""

from __future__ import annotations

from dataclasses import dataclass

__all__ = ["Bounds"]


@dataclass(frozen=True)
class Bounds:
    """A geographic bounding box in degrees (south-west and north-east corners).

    Returned by a tool's ``bounds()`` so marker extraction is uniform instead of ad-hoc; a
    tool whose tile has no single meaningful box (e.g. a global availability raster) returns
    ``None`` instead.
    """
    sw_lat: float
    ne_lat: float
    sw_lon: float
    ne_lon: float
