"""Decoder-level walk-binding snapshot for the writeTo CFG walk.

Phase B8 made the CFG walk the *sole* writeTo decoder (the forward scan + its
budget were deleted).  The emitted-output golden (``test_golden_output``) now
reflects the walk — but only *after* the ``_confirm_field_numbers`` coverage gate
and the ivar-order estimate fallback, either of which can MASK a walk-level
coverage regression (e.g. a class whose walk result the gate already discards, or
a lost binding whose estimate coincidentally matches).

This test locks the walk's bindings at the DECODER level, before any of that: for
each artifact it snapshots ``{Class.ivar: field_number}`` for every binding the
walk produces across all proto classes, and asserts byte-equality with a committed
golden.  A regression in ``detect_context`` / ``bind_write`` / ``writeto_walk``
that drops (or wrongly adds) a binding fails here directly; an intentional coverage
change (e.g. closing the deferred GEOLPR/GEOPublisher misses) is accepted the same
way as the other goldens::

    MACHO_UPDATE_GOLDEN=1 ./venv/bin/python3 -m pytest tests/test_writeto_walk_coverage.py

Review the git diff of tests/golden/writeto_walk_<artifact>.json before committing.

Live-gated like the other real-binary tests (skips when an artifact is absent or
no golden has been committed yet).
"""
import json
import os
import unittest

from proto.protocore import _is_real_field_ivar
from proto.protoclass_heuristic import _is_proto_class
import proto.writeto as W
import live_artifacts as V

_GOLDEN_DIR = os.path.join(os.path.dirname(__file__), "golden")
_UPDATE = os.environ.get("MACHO_UPDATE_GOLDEN") == "1"
_MAX_SHOWN = 30

_ARTIFACTS = [
    ("GeoServices", lambda: V.load_cache("GeoServices")),
    ("locationd", V.load_locationd),
    ("CoreLocationProtobuf", lambda: V.load_cache("CoreLocationProtobuf")),
]


def _field_ivars(cls):
    names = {m.name for m in cls.methods if m.name}
    return [iv for iv in cls.ivars if _is_real_field_ivar(iv, names)]


def _walk_bindings(ctx, cl):
    """``{f"{Class}.{ivar}": field_number}`` for every walk binding in *cl*."""
    indeg, foreign = W.build_writeto_indegree(ctx, cl)
    out = {}
    for cls in cl:
        if cls.is_meta or not _is_proto_class(cls):
            continue
        m = cls.get_method("writeTo:")
        fi = _field_ivars(cls)
        if m is None or m.imp == 0 or not fi:
            continue
        walk = W._walk_field_numbers(ctx, cls, fi, indeg, foreign).numbers
        for ivar, num in walk.items():
            out[f"{cls.name}.{ivar}"] = num
    return out


def _golden_path(label):
    return os.path.join(_GOLDEN_DIR, f"writeto_walk_{label}.json")


class TestWriteToWalkCoverage(unittest.TestCase):
    def _check(self, label, loader):
        loaded = loader()
        if loaded is None:
            self.skipTest(f"{label}: artifact not available")
        ctx, _st, cl = loaded
        current = _walk_bindings(ctx, cl)
        path = _golden_path(label)

        if _UPDATE:
            os.makedirs(_GOLDEN_DIR, exist_ok=True)
            with open(path, "w") as fh:
                json.dump(current, fh, indent=0, sort_keys=True)
            self.skipTest(f"{label}: walk golden UPDATED ({len(current)} bindings)")

        if not os.path.exists(path):
            self.skipTest(
                f"{label}: no walk golden committed — run "
                f"`MACHO_UPDATE_GOLDEN=1 ./venv/bin/python3 -m pytest "
                f"tests/test_writeto_walk_coverage.py` to create "
                f"tests/golden/writeto_walk_{label}.json"
            )

        with open(path) as fh:
            golden = json.load(fh)

        keys = set(golden) | set(current)
        changed = sorted(k for k in keys if golden.get(k) != current.get(k))
        if changed:
            shown = "\n".join(
                f"  {k}: {golden.get(k)} -> {current.get(k)}"
                for k in changed[:_MAX_SHOWN]
            )
            more = "" if len(changed) <= _MAX_SHOWN else \
                f"\n  ... and {len(changed) - _MAX_SHOWN} more"
            self.fail(
                f"{label}: {len(changed)} walk binding(s) differ from golden "
                f"({len(golden)} golden / {len(current)} current). If intentional "
                f"(detect_context/bind_write coverage change), accept with "
                f"MACHO_UPDATE_GOLDEN=1 and review the git diff of "
                f"tests/golden/writeto_walk_{label}.json:\n{shown}{more}"
            )


def _make(label, loader):
    def test(self):
        self._check(label, loader)
    test.__name__ = f"test_walk_coverage_{label}"
    return test


for _label, _loader in _ARTIFACTS:
    setattr(TestWriteToWalkCoverage, f"test_walk_coverage_{_label}",
            _make(_label, _loader))


class TestAccessorSourcedBinding(unittest.TestCase):
    """Real-cache lock for the message-field accessor-binding fix
    (notes/FB_TYPE_DISPATCH_RE_2026-06-17.md): message/object fields serialized via
    their property getter must bind to the right ivar+number, not the stale
    ivar-order estimate.  _CPUsageEnvelope.context is the proven case (estimated 6,
    real 14 — verified via gt_fields message-write helper AND live wire traffic)."""

    def test_cpusageenvelope_message_fields(self):
        loaded = V.load_cache("CoreParsec")
        if loaded is None:
            self.skipTest("CoreParsec cache not available")
        ctx, _st, cl = loaded
        cls = cl.find("_CPUsageEnvelope")
        if cls is None:
            self.skipTest("_CPUsageEnvelope not present")
        indeg, foreign = W.build_writeto_indegree(ctx, cl)
        walk = W._walk_field_numbers(ctx, cls, _field_ivars(cls), indeg, foreign).numbers
        # The accessor-sourced message fields and (regression guard) the scalars.
        self.assertEqual(walk.get("_context"), 14)              # was estimated 6
        self.assertEqual(walk.get("_usageSinceLookback"), 1)
        self.assertEqual(walk.get("_safariUsagePropensity"), 2)
        self.assertEqual(walk.get("_newsUsagePropensity"), 5)
        self.assertEqual(walk.get("_collectionEndTimestamp"), 11)
        self.assertEqual(walk.get("_uuidBytes"), 15)


class TestSameReg(unittest.TestCase):
    """_same_reg treats the w/x views of a GPR as the same register (the int32/enum
    hoist loads `ldr w20,[self,off]` but moves `mov x1, x20`), while keeping the
    SIMD d/s registers distinct (offline; no cache needed)."""

    def test_wx_views_equal(self):
        self.assertTrue(W._same_reg('w20', 'x20'))
        self.assertTrue(W._same_reg('x20', 'w20'))
        self.assertTrue(W._same_reg('x1', 'x1'))

    def test_different_gprs_not_equal(self):
        self.assertFalse(W._same_reg('x20', 'x21'))
        self.assertFalse(W._same_reg('w20', 'x19'))

    def test_simd_exact_match_only(self):
        self.assertTrue(W._same_reg('d8', 'd8'))
        self.assertFalse(W._same_reg('d8', 's8'))   # both _norm_reg->None; names differ
        self.assertFalse(W._same_reg('d8', 'd9'))


if __name__ == "__main__":
    unittest.main()
