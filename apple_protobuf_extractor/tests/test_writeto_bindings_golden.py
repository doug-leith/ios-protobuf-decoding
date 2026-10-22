"""Decoder-level snapshot of the writeTo: field-number bindings
(:func:`proto.writeto._extract_writeto_field_numbers`, from the writer flow's write sites).

The emitted-output golden (``test_golden_output``) reflects the bindings only *after* the
ivar-order estimate fallback, which can MASK a lost binding whose estimate coincidentally
matches.  This test locks them at the DECODER level: for each artifact it snapshots
``{Class.ivar: field_number}`` for every binding across all proto classes, and asserts
equality with a committed golden.  (The goldens were the writeTo: walk's; the write sites
reproduce them unchanged, TODO #85.)  An intentional coverage change is accepted the same
way as the other goldens::

    MACHO_UPDATE_GOLDEN=1 ./venv/bin/python3 -m pytest tests/test_writeto_bindings_golden.py

Review the git diff of tests/golden/writeto_bindings_<artifact>.json before committing.

Live-gated like the other real-binary tests (skips when an artifact is absent or
no golden has been committed yet).
"""
import json
import os
import unittest

from proto.protocore import _is_real_field_ivar
from proto.protoclass_heuristic import _is_proto_class
import proto.writeto as W
from proto.write_helpers import _ensure_writeto_prepass
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
    return [iv for iv in cls.ivars if _is_real_field_ivar(iv)]


def _bindings(ctx, cl):
    """``{f"{Class}.{ivar}": field_number}`` for every writeTo: binding in *cl*."""
    _ensure_writeto_prepass(ctx, cl)
    out = {}
    for cls in cl:
        if cls.is_meta or not _is_proto_class(cls):
            continue
        m = cls.get_method("writeTo:")
        fi = _field_ivars(cls)
        if m is None or m.imp == 0 or not fi:
            continue
        numbers = W._extract_writeto_field_numbers(ctx, cls, fi).numbers
        for ivar, num in numbers.items():
            out[f"{cls.name}.{ivar}"] = num
    return out


def _golden_path(label):
    return os.path.join(_GOLDEN_DIR, f"writeto_bindings_{label}.json")


class TestWriteToBindingsGolden(unittest.TestCase):
    def _check(self, label, loader):
        loaded = loader()
        if loaded is None:
            self.skipTest(f"{label}: artifact not available")
        ctx, _st, cl = loaded
        current = _bindings(ctx, cl)
        path = _golden_path(label)

        if _UPDATE:
            os.makedirs(_GOLDEN_DIR, exist_ok=True)
            with open(path, "w") as fh:
                json.dump(current, fh, indent=0, sort_keys=True)
            self.skipTest(f"{label}: bindings golden UPDATED ({len(current)} bindings)")

        if not os.path.exists(path):
            self.skipTest(
                f"{label}: no bindings golden committed — run "
                f"`MACHO_UPDATE_GOLDEN=1 ./venv/bin/python3 -m pytest "
                f"tests/test_writeto_bindings_golden.py` to create "
                f"tests/golden/writeto_bindings_{label}.json"
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
                f"{label}: {len(changed)} binding(s) differ from golden "
                f"({len(golden)} golden / {len(current)} current). If intentional, "
                f"accept with MACHO_UPDATE_GOLDEN=1 and review the git diff of "
                f"tests/golden/writeto_bindings_{label}.json:\n{shown}{more}"
            )


def _make(label, loader):
    def test(self):
        self._check(label, loader)
    test.__name__ = f"test_bindings_{label}"
    return test


for _label, _loader in _ARTIFACTS:
    setattr(TestWriteToBindingsGolden, f"test_bindings_{_label}",
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
        _ensure_writeto_prepass(ctx, cl)
        got = W._extract_writeto_field_numbers(ctx, cls, _field_ivars(cls)).numbers
        # The accessor-sourced message fields and (regression guard) the scalars.
        self.assertEqual(got.get("_context"), 14)               # was estimated 6
        self.assertEqual(got.get("_usageSinceLookback"), 1)
        self.assertEqual(got.get("_safariUsagePropensity"), 2)
        self.assertEqual(got.get("_newsUsagePropensity"), 5)
        self.assertEqual(got.get("_collectionEndTimestamp"), 11)
        self.assertEqual(got.get("_uuidBytes"), 15)


if __name__ == "__main__":
    unittest.main()
