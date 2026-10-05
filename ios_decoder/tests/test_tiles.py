"""The uniform tile-adapter driver: module contract, markers, error surfacing."""

import types

from ios_decoder import markers
from ios_decoder.tiles import TileAdapter, TileResult, available_tiles, decode_tile
from ios_decoder.tile_tools import Bounds


def _module(parse=None, render=None, bounds=None, tile_xyz=None):
    """A stand-in tile_tools module (parse/render/bounds [+ optional tile_xyz])."""
    ns = types.SimpleNamespace()
    ns.parse = parse or (lambda data: {"n": len(data)})
    ns.render = render or (lambda tile, **kw: f"records: {tile['n']}")
    ns.bounds = bounds or (lambda tile: None)
    if tile_xyz is not None:
        ns.tile_xyz = tile_xyz
    return ns


def test_module_parse_and_render():
    r = TileAdapter("synthetic", module=_module()).decode(b"abcd")
    assert r.error is None
    assert "records: 4" in r.text
    assert r.markers == []                                  # bounds None → no marker


def test_bounds_emits_boundbox():
    a = TileAdapter("t", module=_module(bounds=lambda tile: Bounds(1.0, 2.0, 3.0, 4.0)))
    assert [m.line() for m in a.decode(b"x").markers] == \
        ["+++LATLON_BOUNDBOX t_tile (1.0,2.0,3.0,4.0)"]


def test_tile_xyz_emitted_before_boundbox():
    a = TileAdapter("t", module=_module(bounds=lambda tile: Bounds(1.0, 2.0, 3.0, 4.0),
                                        tile_xyz=lambda tile: (10, 20, 13)))
    lines = [m.line() for m in a.decode(b"x").markers]
    assert lines[0] == "+++XYZ t_tile (10,20,13)"
    assert lines[1].startswith("+++LATLON_BOUNDBOX t_tile")


def test_render_kwargs_passed_through():
    a = TileAdapter("g", module=_module(render=lambda tile, kind="CID": f"col={kind}"),
                    render_kwargs={"kind": "GSM CellID"})
    assert "col=GSM CellID" in a.decode(b"x").text


def test_parse_failure_is_surfaced_not_raised():
    def boom(_):
        raise ValueError("bad magic")
    r = TileAdapter("x", module=_module(parse=boom)).decode(b"...")
    assert r.error is not None and "bad magic" in r.error
    assert r.text == ""


def test_render_failure_is_surfaced():
    def boom(tile, **kw):
        raise RuntimeError("kaboom")
    r = TileAdapter("x", module=_module(render=boom)).decode(b"...")
    assert r.error is not None and "kaboom" in r.error


def test_marker_failure_warns_in_text_but_keeps_body():
    def boom(tile):
        raise KeyError("no header")
    r = TileAdapter("x", module=_module(bounds=boom)).decode(b"...")
    assert "records:" in r.text
    assert "marker extraction failed" in r.text             # surfaced in the body
    assert r.markers == []                                  # marker list stays clean


def test_result_render_orders_markers_error_then_text():
    r = TileResult(text="the body", markers=[markers.custom("M", "1")], error="oops")
    out = r.render()
    assert out.index("+++M 1") < out.index("// ERROR:") < out.index("the body")


def test_unknown_tile_type_is_an_error():
    r = decode_tile("nope", b"data")
    assert r.error is not None and "unknown tile type" in r.error


def test_real_registry_builds():
    names = available_tiles()
    for expected in ("wifi", "hrse", "gsmcell", "ltecell", "cldem", "clsef", "cldavl",
                     "global_gsm", "global_cdma", "global_lte", "global_5g"):
        assert expected in names
