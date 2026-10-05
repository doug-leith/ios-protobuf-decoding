"""OPTIONAL cross-check of the endpoint table against the fuzzy matcher.

These tests double-check that the messages the URL table claims are at least
*consistent* with the structural matcher run over the framework's extracted
descriptor set (the locator step (i) replaced by a manually-named framework — see
ios_decoder/tests/matcher_harness.py and notes/LOCATOR_STEP1_FINDINGS.md).

The matcher is now native to ios_decoder (ios_decoder.matcher) — no cross-tool
dependency. These tests SKIP rather than fail when an input is absent:
  * protoc must be installed (to compile the descriptor set),
  * the framework's descriptors must be committed under ios_decoder/protos/,
  * the live test additionally needs a git-ignored capture.

What they assert is only the RELIABLE signal — *exclusion*: a table mapping whose
message the matcher proves impossible for a real body is a regression.  Ranking is
reported (via -s) but never asserted (small payloads can tie).
"""

from __future__ import annotations

import glob
import os
import tempfile

import pytest

from ios_decoder import fb
from . import matcher_harness as H

pytestmark = H.requires_harness        # whole module skips if the matcher deps are absent


def _framework_dir_for(proto_file: str):
    """Committed descriptor dir holding `proto_file` (e.g. CoreParsec), or None."""
    hits = glob.glob(str(H._PROTOS_ROOT / "*" / proto_file))
    return os.path.dirname(hits[0]) if hits else None


# all (type, proto_file, message, framework_dir) the /fb table claims
_FB_TABLE = [
    (t, pf, msg, _framework_dir_for(pf))
    for t, (pf, msg) in sorted(fb.FB_TYPE_MAP.items())
]


# --- structural sanity: every table message exists in its descriptor set -----

@pytest.mark.parametrize("t,proto_file,message,fw_dir", _FB_TABLE,
                         ids=[t for t, _, _, _ in _FB_TABLE])
def test_fb_table_message_is_in_descriptor_set(t, proto_file, message, fw_dir):
    """A table mapping must reference a message the extractor actually produced."""
    if fw_dir is None:
        pytest.skip(f"no committed descriptors for {proto_file}")
    descriptors = H.load_corpus(fw_dir)
    leaf = H._leaf(message)
    assert descriptors.resolve(leaf) is not None, (
        f"/fb type {t!r} maps to {leaf!r}, absent from the {os.path.basename(fw_dir)} "
        f"descriptor set — a stale table entry or a renamed/removed message")


# --- the cross-check has teeth (deterministic, no capture needed) -------------

def test_crosscheck_excludes_wire_type_conflict():
    """Prove the matcher would catch a wrong mapping: a body that contradicts a
    defined field's wire type must EXCLUDE the claimed message, while a clean
    serialization stays feasible.  _CPUsageEnvelope field 14 (context) is a
    sub-message (wire type 2)."""
    fw_dir = _framework_dir_for("_cpusageenvelope.proto")
    if fw_dir is None:
        pytest.skip("no committed CoreParsec descriptors")
    # field 14 as a VARINT (wire 0) contradicts the message-typed field -> excluded
    conflict = b"\x70\x05"                 # tag=(14<<3)|0, varint 5
    v_bad = H.crosscheck(conflict, fw_dir, "_cpusageenvelope._CPUsageEnvelope")
    assert v_bad.excluded and v_bad.violations >= 1, v_bad.summary()
    # field 14 as an (empty) sub-message (wire 2) is consistent -> feasible
    clean = b"\x72\x00"                    # tag=(14<<3)|2, len 0  (empty context message)
    v_ok = H.crosscheck(clean, fw_dir, "_cpusageenvelope._CPUsageEnvelope")
    assert v_ok.feasible and v_ok.violations == 0, v_ok.summary()


def test_crosscheck_roundtrip_body_is_feasible():
    """A real serialized _CPUsageEnvelope must be feasible against CoreParsec — the
    table↔descriptor agreement for the Usage channel, end to end."""
    fw_dir = _framework_dir_for("_cpusageenvelope.proto")
    if fw_dir is None or not _have_protoc():
        pytest.skip("no committed CoreParsec descriptors or protoc")
    from ios_decoder.schemas import SchemaRegistry
    from ios_decoder.paths import DEFAULT_PROTO_DIRS
    reg = SchemaRegistry(list(DEFAULT_PROTO_DIRS), cache_dir=tempfile.mkdtemp())
    Env = reg.message_class("_cpusageenvelope.proto", "_cpusageenvelope._CPUsageEnvelope")
    msg = Env()
    msg.context.country = "ZZ"
    msg.uuidBytes = b"\x01" * 16
    msg.usageSinceLookback.context.deviceModel = "iPhoneTEST,1"
    v = H.crosscheck(msg.SerializeToString(), fw_dir,
                     "_cpusageenvelope._CPUsageEnvelope", direction="request")
    assert v.feasible and v.observed > 0, v.summary()


# --- live: real /fb bodies keep their table message feasible -----------------

def test_fb_table_messages_feasible_on_live_bodies(capsys):
    """For every real /fb body in a capture, the message the table maps its
    ?type= channel to must NOT be excluded by the matcher.  Reports rank/confidence
    for inspection (pytest -s); asserts only on exclusion."""
    bodies = H.capture_bodies("smoot.apple.com/fb")
    if not bodies:
        pytest.skip("no git-ignored capture with smoot /fb traffic present")
    checked = 0
    report = []
    for url, body, direction in bodies:
        if direction != "request":
            continue
        t = fb.fb_type(url)
        if t not in fb.FB_TYPE_MAP:
            continue                       # unmapped channel -> raw decode, nothing to check
        proto_file, message = fb.FB_TYPE_MAP[t]
        fw_dir = _framework_dir_for(proto_file)
        if fw_dir is None:
            continue
        try:
            v = H.crosscheck(body, fw_dir, message, direction="request")
        except ValueError:
            continue                       # non-protobuf body (already handled elsewhere)
        report.append(f"{t}: {v.summary()}")
        assert not v.excluded, (
            f"/fb type {t!r} body EXCLUDES table message {v.expected!r} "
            f"({v.violations} wire-type contradictions) — the table mapping is "
            f"inconsistent with the wire:\n  {url}\n  {v.summary()}")
        checked += 1
    if not checked:
        pytest.skip("no mapped /fb request bodies in the available captures")
    with capsys.disabled():
        print("\n[matcher cross-check] /fb table vs wire:")
        for line in report:
            print("  " + line)


def _have_protoc():
    import shutil
    return shutil.which("protoc") is not None
