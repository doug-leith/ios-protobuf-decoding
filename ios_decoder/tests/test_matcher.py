"""The standalone structural matcher (ios_decoder.matcher), ported from the retired
mitm_traffic_parser. Wire-compat table + wire-tree parsing need no protoc; the fit/
rank and descriptor-set compilation are gated on protoc."""

import shutil

import pytest

from ios_decoder import matcher
from ios_decoder.matcher import FieldDescriptor as FD

requires_protoc = pytest.mark.skipif(shutil.which("protoc") is None, reason="protoc not installed")

_PROTO = """\
syntax = "proto3";
package t;
message Inner { uint32 a = 1; }
message Outer { uint32 x = 1; Inner inner = 2; string s = 3; }
message Other { fixed64 z = 1; }
"""

# Outer wire body: x=1 (varint), inner={a:1}, s="hi"
_OUTER_BODY = bytes.fromhex("0801") + bytes.fromhex("12020801") + b"\x1a\x02hi"


def test_wire_compatible_exact_and_packed():
    class F:                       # minimal stand-in carrying just .type
        def __init__(self, t): self.type = t
    assert matcher.wire_compatible(F(FD.TYPE_UINT32), matcher.WIRE_VARINT)     # exact
    assert matcher.wire_compatible(F(FD.TYPE_STRING), matcher.WIRE_LEN)        # exact
    assert matcher.wire_compatible(F(FD.TYPE_FIXED64), matcher.WIRE_I64)       # exact
    assert matcher.wire_compatible(F(FD.TYPE_UINT32), matcher.WIRE_LEN)        # packed repeated
    # a string/message field can NEVER ride a varint -> the discriminating contradiction
    assert not matcher.wire_compatible(F(FD.TYPE_STRING), matcher.WIRE_VARINT)
    assert not matcher.wire_compatible(F(FD.TYPE_FIXED64), matcher.WIRE_VARINT)


def test_parse_tree_rejects_non_protobuf():
    with pytest.raises(matcher.MatchError):
        matcher.parse_tree(b"")                    # empty
    with pytest.raises(matcher.MatchError):
        matcher.parse_tree(b"\x08")                # truncated varint
    tree = matcher.parse_tree(_OUTER_BODY)
    assert [wf.number for wf in tree] == [1, 2, 3]
    assert tree[1].message is not None             # field 2 parsed as a sub-message


@requires_protoc
def test_fit_feasible_recurses_into_submessage(tmp_path):
    (tmp_path / "t.proto").write_text(_PROTO)
    ds = matcher.load_descriptor_set(str(tmp_path))
    outer = ds.resolve("Outer")
    matched, observed, violations = matcher.fit(matcher.parse_tree(_OUTER_BODY), outer)
    assert violations == 0
    assert observed == 4 and matched == 4         # 3 top-level + 1 nested (Inner.a)


@requires_protoc
def test_fit_excludes_wire_type_contradiction(tmp_path):
    (tmp_path / "t.proto").write_text(_PROTO)
    ds = matcher.load_descriptor_set(str(tmp_path))
    # s (field 3) is a string but here rides a varint -> impossible for Outer
    conflict = matcher.parse_tree(b"\x18\x01")     # field 3, wire 0
    _, _, violations = matcher.fit(conflict, ds.resolve("Outer"))
    assert violations >= 1
    # Other defines field 1 as fixed64; the same varint body contradicts it too
    _, _, v2 = matcher.fit(matcher.parse_tree(b"\x08\x01"), ds.resolve("Other"))
    assert v2 >= 1


@requires_protoc
def test_match_tree_ranks_outer_first(tmp_path):
    (tmp_path / "t.proto").write_text(_PROTO)
    ds = matcher.load_descriptor_set(str(tmp_path))
    res = matcher.match_tree(matcher.parse_tree(_OUTER_BODY), ds)
    assert res.best is not None and res.best.message == "Outer"


@requires_protoc
def test_load_descriptor_set_drops_and_reports_bad_file(tmp_path):
    # a valid file plus one protoc REJECTS (zero-less proto3 enum) -> good kept, bad reported
    (tmp_path / "good.proto").write_text(_PROTO)
    (tmp_path / "bad.proto").write_text(
        'syntax = "proto3";\npackage b;\nenum E { ONE = 1; }\nmessage B { E e = 1; }\n')
    ds = matcher.load_descriptor_set(str(tmp_path))
    assert ds.resolve("Outer") is not None         # the good file still compiled
    assert any(f == "bad.proto" for f, _ in ds.skipped)   # the bad file is surfaced, not hidden


@requires_protoc
def test_committed_appprediction_set_compiles_completely():
    """Every committed AppPredictionInternal .proto compiles -- nothing is dropped.

    This used to assert the opposite: atxmpb.proto was committed a few hours before the
    extractor's proto3-enum fix landed, so it carried zero-less proto3 enums and had to be
    dropped. The protos have since been regenerated, so the assertion is inverted into a
    guard: if stale extractor output is ever committed here again, `skipped` stops being
    empty and this fails. The matcher's drop-and-report behaviour itself is covered
    synthetically by test_load_descriptor_set_drops_and_reports_bad_file, which does not
    depend on a real defect staying unfixed.
    """
    from . import matcher_harness as H
    d = H.committed_descriptor_dir("AppPredictionInternal")
    if d is None:
        pytest.skip("no committed AppPredictionInternal descriptors")
    ds = matcher.load_descriptor_set(str(d))
    assert ds.resolve("ATXNotificationsPBLogWrapper") is not None
    assert not ds.skipped, f"committed protos no longer compile: {ds.skipped}"
