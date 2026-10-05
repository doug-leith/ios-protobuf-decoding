"""Marker formatting (the awk contract) + the collection sink."""

from ios_decoder import markers
from ios_decoder.markers import Marker, MarkerSink


def test_xyz_format():
    assert markers.xyz("wifi_tile", 142, 172, 5).line() == "+++XYZ wifi_tile (142,172,5)"


def test_latlon_format():
    assert markers.latlon("gs-loc", 53.41, -7.38).line() == "+++LATLON gs-loc (53.41,-7.38)"


def test_boundbox_format():
    m = markers.boundbox("cldem_tile", 52.0, 54.0, -8.0, -6.0)
    assert m.line() == "+++LATLON_BOUNDBOX cldem_tile (52.0,54.0,-8.0,-6.0)"


def test_custom_and_tagonly():
    assert markers.custom("XP", "report").line() == "+++XP report"
    assert Marker("AMP_REQ").line() == "+++AMP_REQ"


def test_request_and_reqheaders():
    assert markers.request("https://x/y", 103, 1780.5).line() == \
        "+++REQUEST https://x/y 103 1780.5"
    assert markers.reqheaders("https://x/y", "User-Agent='geod'", "Host=x~").line() == \
        "+++REQHEADERS https://x/y € User-Agent='geod' € Host=x~"


def test_str_equals_line():
    m = markers.xyz("t", 1, 2, 3)
    assert str(m) == m.line()


def test_markers_are_value_equal():
    assert markers.xyz("t", 1, 2, 3) == markers.xyz("t", 1, 2, 3)


def test_sink_collects_and_emits_in_order():
    sink = MarkerSink()
    sink.emit(markers.xyz("a", 1, 2, 3))
    sink.emit(markers.latlon("b", 4, 5), markers.custom("C"))
    assert len(sink) == 3 and bool(sink) is True
    assert sink.lines() == ["+++XYZ a (1,2,3)", "+++LATLON b (4,5)", "+++C"]


def test_sink_clear():
    sink = MarkerSink()
    sink.emit(markers.custom("X"))
    sink.clear()
    assert not sink and sink.lines() == []
