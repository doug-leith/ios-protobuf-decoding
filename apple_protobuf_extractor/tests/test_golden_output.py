"""Golden-output regression net for the proto extractor.

This is the field-by-field safety net for larger changes (e.g. swapping the
writeTo field-number decoder for the CFG-walk prototype): it runs the *whole*
extractor over each available real artifact and asserts that every emitted
field's (type_name, type_class, number, label, number_confirmed, has-note,
has-disambiguation) tuple is byte-identical to a committed golden snapshot.

Design notes
------------
* **Live-gated, like the other real-binary tests.** Each artifact test skips when
  its binary/cache is not present (``validate_lever`` loaders return ``None``) and
  when no golden file has been committed yet — so the offline suite stays green.
* **Reuses ``snapshot_output._snap_messages``** so this test and the manual
  ``snapshot_output.py`` before/after tool can never disagree on what a snapshot
  contains.
* **Updating the golden after an *intentional* output change** (the normal
  golden-test workflow — e.g. accepting the field-number fixes the prototype
  merge introduces) is explicit and reviewable::

      MACHO_UPDATE_GOLDEN=1 ./venv/bin/python3 -m pytest tests/test_golden_output.py

  That regenerates ``tests/golden/<artifact>.json`` from current output and
  reports the per-artifact field count instead of asserting.  Review the git
  diff of the golden file before committing it — that diff *is* the list of
  every output change your change caused.

The golden files are derived data (not the binaries themselves), stored one key
per line (``indent=0``, ``sort_keys=True``) so a git diff reads as a clean list
of changed ``Class.field`` entries.
"""
import json
import os
import unittest

import proto.extractor as E
import validate_lever as V
from snapshot_output import _snap_messages

_GOLDEN_DIR = os.path.join(os.path.dirname(__file__), "golden")
_UPDATE = os.environ.get("MACHO_UPDATE_GOLDEN") == "1"

# (label, loader) — loaders return (ctx, st, cl) or None when the artifact is
# absent.  CoreLocationProtobuf and GeoServices come from the dyld cache in
# ./dylib/; locationd is a standalone binary in the project root.
_ARTIFACTS = [
    ("GeoServices", lambda: V._load_cache("GeoServices")),
    ("locationd", V._load_locationd),
    ("CoreLocationProtobuf", lambda: V._load_cache("CoreLocationProtobuf")),
]

# Show at most this many differing fields in a failure message (the full set is
# always available by re-running with MACHO_UPDATE_GOLDEN=1 and diffing git).
_MAX_SHOWN = 30


def _capture(loaded):
    ctx, st, cl = loaded
    return _snap_messages(E.extract_all(ctx, st, cl))


def _golden_path(label):
    return os.path.join(_GOLDEN_DIR, f"{label}.json")


class TestGoldenOutput(unittest.TestCase):
    """One generated test method per artifact (see bottom of module)."""

    def _check(self, label, loader):
        loaded = loader()
        if loaded is None:
            self.skipTest(f"{label}: artifact not available")
        current = _capture(loaded)
        path = _golden_path(label)

        if _UPDATE:
            os.makedirs(_GOLDEN_DIR, exist_ok=True)
            with open(path, "w") as fh:
                json.dump(current, fh, indent=0, sort_keys=True)
            self.skipTest(f"{label}: golden UPDATED ({len(current)} fields)")

        if not os.path.exists(path):
            self.skipTest(
                f"{label}: no golden committed — run "
                f"`MACHO_UPDATE_GOLDEN=1 ./venv/bin/python3 -m pytest "
                f"tests/test_golden_output.py` to create tests/golden/{label}.json"
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
                f"{label}: {len(changed)} field(s) differ from golden "
                f"({len(golden)} golden / {len(current)} current). "
                f"If intentional, accept with MACHO_UPDATE_GOLDEN=1 and review "
                f"the git diff of tests/golden/{label}.json:\n{shown}{more}"
            )


def _make_test(label, loader):
    def test(self):
        self._check(label, loader)
    test.__name__ = f"test_golden_{label}"
    test.__doc__ = f"Extractor output for {label} matches tests/golden/{label}.json"
    return test


for _label, _loader in _ARTIFACTS:
    setattr(TestGoldenOutput, f"test_golden_{_label}",
            _make_test(_label, _loader))

# NOTE (mutation-testing audit, c7b5994): test_golden_CoreLocationProtobuf was
# flagged as unable to discriminate c7b5994's BinaryContext cache-reset fix
# (_wrapper_cluster_cache/_dispatch_arms_cache) because each generated golden
# test here loads a FRESH context and calls extract_all() exactly once -- the
# reset fix only matters when one context is reused across two extract_all
# calls. Verified: tests/test_extract_cache_reset.py::TestExtractAllResetsCaches
# ::test_stale_caches_are_reset does exactly that (stale cache manually seeded,
# one ctx, extract_all() called, caches asserted reset) -- so no change needed
# here; the mechanism has real coverage elsewhere.


if __name__ == "__main__":
    unittest.main()
