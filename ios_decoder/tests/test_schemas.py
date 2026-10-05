"""Schema registry: protoc-as-compiler + pure-Python decode, incl. partial schemas.

Uses a small self-contained ``.proto`` fixture (not a checked-in schema) so the
registry mechanism is tested portably — independent of the extractor output and with
no ``addon_ios`` dependency.
"""

import shutil

import pytest

from ios_decoder.schemas import SchemaRegistry, SchemaError

pytestmark = pytest.mark.skipif(shutil.which("protoc") is None, reason="protoc not installed")

# A tiny schema standing in for an endpoint message (an ALS-like request).
_FIXTURE_PROTO = """\
syntax = "proto2";
message ALSLocationRequest {
  repeated ALSWirelessAP wireless_aps = 2;
  optional int32 number_of_surrounding_cells = 3;
}
message ALSWirelessAP { optional bytes bssid = 1; }
"""


@pytest.fixture
def registry(tmp_path):
    d = tmp_path / "protos"
    d.mkdir()
    (d / "wloc.proto").write_text(_FIXTURE_PROTO)
    return SchemaRegistry([d], cache_dir=tmp_path / "cache")


def test_loads_named_message(registry):
    cls = registry.message_class("wloc.proto", "ALSLocationRequest")
    names = {f.name for f in cls.DESCRIPTOR.fields}
    assert "wireless_aps" in names


def test_partial_schema_keeps_unknown_fields(registry):
    # field 3 (number_of_surrounding_cells, a known int32) = 5  -> named
    # field 1000 varint = 42                                   -> unknown, by number
    known = bytes.fromhex("1805")
    unknown = bytes([0xC0, 0x3E, 0x2A])  # tag=1000<<3|0, value=42
    out, unknown_nums, nested = registry.decode_with_coverage(
        "wloc.proto", "ALSLocationRequest", known + unknown)
    assert "number_of_surrounding_cells: 5" in out
    assert "1000: 42" in out
    assert 1000 in unknown_nums          # coverage reports the by-number top-level field
    assert nested == 0                   # the unknown is top-level, not nested


def test_descriptor_set_is_cached(registry):
    registry.message_class("wloc.proto", "ALSLocationRequest")
    cached = registry.cache_dir / "wloc.pb"
    assert cached.is_file()


def test_unknown_message_name_raises(registry):
    with pytest.raises(SchemaError):
        registry.message_class("wloc.proto", "NoSuchMessage")


def test_unknown_proto_file_raises(registry):
    with pytest.raises(SchemaError):
        registry.message_class("does_not_exist.proto", "Whatever")


def test_cache_invalidated_when_an_import_changes(tmp_path):
    """Editing an *imported* .proto must invalidate the cache (not just the top file)."""
    import os

    d = tmp_path / "protos"
    d.mkdir()
    (d / "common.proto").write_text(
        'syntax = "proto2";\nmessage Common { optional int32 a = 1; }\n')
    (d / "top.proto").write_text(
        'syntax = "proto2";\nimport "common.proto";\n'
        'message Top { optional Common c = 1; }\n')

    reg = SchemaRegistry([d], cache_dir=tmp_path / "cache")
    reg.message_class("top.proto", "Top")          # compiles top.proto + its import
    cache = reg.cache_dir / "top.pb"
    assert reg._cache_is_fresh(cache, "top.proto")

    # make the imported file newer than the cached descriptor set
    newer = cache.stat().st_mtime + 10
    os.utime(d / "common.proto", (newer, newer))
    assert not reg._cache_is_fresh(cache, "top.proto")
