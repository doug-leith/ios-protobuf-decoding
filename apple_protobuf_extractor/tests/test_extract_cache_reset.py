"""Per-extraction cache lifecycle (regression net for the §3 quick-win fix).

`proto.extractor` memoises two things on the shared `BinaryContext` during a run:
`_wrapper_cluster_cache` and `_dispatch_arms_cache`.  These used to be lazily
monkey-patched and never cleared, so reusing one context across two extractions
leaked stale results.  The fix:

  1. both attrs are DECLARED on `BinaryContext.__init__` (initialised to None), and
  2. `extract_all` RESETS them to None at the top of every run.

These tests lock in both halves with a synthetic binary (no real artifact needed).
"""
from __future__ import annotations

from macho.memory import BinaryContext
from macho.strings import StringTable
from macho.classlist import ClassList
import proto.extractor as E
from tests.conftest import build_text_binary

TEXT_VA = 0x100000000
NOP = b"\x1f\x20\x03\xd5"

_CACHE_ATTRS = ("_wrapper_cluster_cache", "_dispatch_arms_cache")


def _ctx():
    return BinaryContext(build_text_binary(NOP, vmaddr=TEXT_VA))


class TestExtractionCacheDeclaration:
    def test_caches_declared_and_none_on_construction(self):
        ctx = _ctx()
        for attr in _CACHE_ATTRS:
            assert hasattr(ctx, attr), f"{attr} not declared on BinaryContext"
            assert getattr(ctx, attr) is None, f"{attr} should init to None"


class TestExtractAllResetsCaches:
    def test_stale_caches_are_reset(self):
        ctx = _ctx()
        # Simulate stale state left over from a prior extraction on this ctx.
        ctx._wrapper_cluster_cache = {"stale": object()}
        ctx._dispatch_arms_cache = {"stale": object()}

        # Empty class list → extract_all does its pre-passes and returns [].
        # The selector gate returns early (no proto classes), the reset loop
        # runs, then the (empty) extraction loop runs.
        result = E.extract_all(ctx, StringTable(), ClassList([]))

        assert result == []
        for attr in _CACHE_ATTRS:
            assert getattr(ctx, attr) is None, (
                f"{attr} not reset by extract_all — stale cache would leak "
                f"across extractions on a reused BinaryContext"
            )
