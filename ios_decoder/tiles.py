"""Uniform driver for the committed tile parsers in :mod:`ios_decoder.tile_tools`.

Each tile tool exposes one small contract — ``parse(bytes) -> tile``, ``render(tile) -> str``,
``bounds(tile) -> Bounds | None`` (plus an optional ``tile_xyz`` for the ``+++XYZ`` marker) —
so a :class:`TileAdapter` drives any of them with no tempfile and no stdout capture.  One
:func:`decode_tile` returns a uniform :class:`TileResult`.

Failures are surfaced, never swallowed: a parse/render exception becomes ``TileResult.error``
(and the per-flow guard in the reader keeps one bad tile from aborting a capture).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from . import markers, rules
from .markers import Marker

__all__ = ["TileResult", "TileAdapter", "decode_tile", "tile_rule", "available_tiles"]


@dataclass
class TileResult:
    """Outcome of decoding one tile body: rendered text, markers, and any error."""
    text: str = ""
    markers: list[Marker] = field(default_factory=list)
    error: Optional[str] = None

    def render(self, include_markers: bool = True) -> str:
        """Flatten to a single string (markers first, then error note, then body).

        ``include_markers=False`` omits the marker lines — used when the reporter has
        already collected them into a :class:`~ios_decoder.markers.MarkerSink` and will
        emit them itself, so they aren't duplicated in the body text.
        """
        out: list[str] = [m.line() for m in self.markers] if include_markers else []
        if self.error:
            out.append(f"// ERROR: tile decode failed: {self.error}")
        if self.text:
            out.append(self.text.rstrip("\n"))
        return "\n".join(out)


@dataclass
class TileAdapter:
    """Drives one :mod:`ios_decoder.tile_tools` module through the uniform contract.

    ``module`` provides ``parse``/``render``/``bounds`` (and optionally ``tile_xyz``);
    ``render_kwargs`` passes extra args to ``render`` (the global-cell ``kind`` label).
    Parse/render failures surface as :attr:`TileResult.error`; a marker failure is noted in
    the body but never aborts the decode.
    """
    name: str
    module: Any
    render_kwargs: Optional[dict] = None

    def decode(self, data: bytes) -> TileResult:
        m = self.module
        try:
            tile = m.parse(data)
        except Exception as e:  # noqa: BLE001 - tool boundary; report, don't crash
            return TileResult(error=f"load: {type(e).__name__}: {e}")
        try:
            text = m.render(tile, **(self.render_kwargs or {}))
        except Exception as e:  # noqa: BLE001
            return TileResult(error=f"render: {type(e).__name__}: {e}")
        marker_list: list[Marker] = []
        try:
            label = f"{self.name}_tile"
            # optional xyz tile id (e.g. wifi) is emitted before the bounding box,
            # matching the legacy marker order
            xyz = getattr(m, "tile_xyz", lambda _t: None)(tile)
            if xyz is not None:
                marker_list.append(markers.xyz(label, *xyz))
            box = m.bounds(tile)
            if box is not None:
                marker_list.append(markers.boundbox(label, box.sw_lat, box.ne_lat,
                                                    box.sw_lon, box.ne_lon))
        except Exception as e:  # noqa: BLE001 - keep the body; flag the marker failure
            text += (f"\n// WARNING: tile marker extraction failed: "
                     f"{type(e).__name__}: {e}")
        return TileResult(text=text, markers=marker_list)


# --- per-tool render / marker helpers ---------------------------------------

def _build_adapters() -> dict[str, TileAdapter]:
    """Construct the adapter registry from the migrated tile_tools modules.

    Every tool is now a committed :mod:`ios_decoder.tile_tools` module driven through the
    uniform ``parse``/``render``/``bounds`` contract — no tempfile, no stdout capture, and no
    import from the (git-ignored) ``addon_ios`` oracle.  The four global-cell endpoints share
    one parser and differ only in the CID column label, passed via ``render_kwargs``.
    """
    from .tile_tools import (cldavl, cldem, clsef, globalcell, gsmcell, hrse,
                             ltecell, wifi)

    def _global(name: str, kind: str) -> TileAdapter:
        return TileAdapter(name, module=globalcell, render_kwargs={"kind": kind})

    adapters = [
        TileAdapter("wifi", module=wifi),
        TileAdapter("hrse", module=hrse),
        TileAdapter("gsmcell", module=gsmcell),
        TileAdapter("ltecell", module=ltecell),
        TileAdapter("cldem", module=cldem),
        TileAdapter("clsef", module=clsef),
        TileAdapter("cldavl", module=cldavl),
        _global("global_gsm", "GSM CellID"),
        _global("global_cdma", "CDMA Base Stn ID"),
        _global("global_lte", "LTE Global CellID"),
        _global("global_5g", "5G NR CellID"),
    ]
    return {a.name: a for a in adapters}


_ADAPTERS: Optional[dict[str, TileAdapter]] = None


def _adapters() -> dict[str, TileAdapter]:
    global _ADAPTERS
    if _ADAPTERS is None:
        _ADAPTERS = _build_adapters()
    return _ADAPTERS


def available_tiles() -> list[str]:
    """Names of the registered tile types."""
    return sorted(_adapters())


def decode_tile(tile_type: str, data: bytes) -> TileResult:
    """Decode ``data`` as ``tile_type``; an unknown type is a surfaced error, not a crash."""
    try:
        adapters = _adapters()
    except Exception as e:  # noqa: BLE001 - a tool failed to import
        return TileResult(error=f"tile tools unavailable: {type(e).__name__}: {e}")
    adapter = adapters.get(tile_type)
    if adapter is None:
        return TileResult(error=f"unknown tile type {tile_type!r} "
                                f"(known: {', '.join(sorted(adapters))})")
    return adapter.decode(data)


def tile_rule(tile_type: str) -> "rules.Rule":
    """A :class:`~ios_decoder.rules.Rule` that decodes this tile type.

    Location markers are emitted to the context's :class:`~ios_decoder.markers.MarkerSink`
    (so the reporter prints them in one place); the returned text is the tile body only.
    Without a sink (direct use) the markers are inlined instead.
    """
    def handler(body: bytes, ctx: "rules.DecodeContext") -> str:
        result = decode_tile(tile_type, body)
        sink = getattr(ctx, "markers", None)
        if sink is not None:
            sink.emit(*result.markers)
            return result.render(include_markers=False)
        return result.render()
    return rules.Rule(handler=handler)
