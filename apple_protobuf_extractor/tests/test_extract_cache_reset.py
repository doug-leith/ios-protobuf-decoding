"""Per-extraction cache lifecycle.

`proto.*` memoises per-extraction state on the shared `BinaryContext` (core index, dispatch
evaluations, callee names, writer flow, ...).  Reusing one context across two extractions
must not serve the first run's results.  The mechanism:

  1. every cache is created through `macho.memory._ctx_cache` or `_ctx_store`, which record
     its attribute name, and
  2. `extract_all` calls `macho.memory.reset_ctx_caches`, which clears every recorded name.

A hand-kept list of attribute names used to do (2); it fell behind as caches were added
(code review 2026-10-18).  These tests check the mechanism with a synthetic binary, and that
no module stores a cache on a context directly, outside the two helpers.
"""
from __future__ import annotations

import os
import re

from macho.memory import BinaryContext, _ctx_cache, _ctx_store, _CTX_CACHE_ATTRS, reset_ctx_caches
from macho.strings import StringTable
from macho.classlist import ClassList
import proto.extractor as E
from tests.conftest import build_text_binary

TEXT_VA = 0x100000000
NOP = b"\x1f\x20\x03\xd5"

_PKG = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

#: Attributes a module may set directly on a context: properties of the binary, computed once
#: while parsing it, not per-extraction caches.
_NOT_CACHES = set()


def _ctx():
    return BinaryContext(build_text_binary(NOP, vmaddr=TEXT_VA))


class TestRegistry:
    def test_ctx_cache_registers_its_attribute(self):
        ctx = _ctx()
        _ctx_cache(ctx, "_test_registry_cache", dict)["k"] = 1
        assert "_test_registry_cache" in _CTX_CACHE_ATTRS

    def test_ctx_store_registers_and_stores(self):
        ctx = _ctx()
        assert _ctx_store(ctx, "_test_registry_store", (1,)) == (1,)
        assert ctx._test_registry_store == (1,)
        assert "_test_registry_store" in _CTX_CACHE_ATTRS

    def test_reset_clears_every_registered_cache(self):
        ctx = _ctx()
        _ctx_cache(ctx, "_test_reset_a", dict)["stale"] = object()
        _ctx_store(ctx, "_test_reset_b", frozenset({"stale"}))
        reset_ctx_caches(ctx)
        assert ctx._test_reset_a is None and ctx._test_reset_b is None
        # rebuilt empty on the next use, not served stale
        assert _ctx_cache(ctx, "_test_reset_a", dict) == {}


class TestExtractAllResetsCaches:
    def test_stale_caches_are_reset(self):
        ctx = _ctx()
        # Stale state left by a prior extraction on this context, in caches of the kinds
        # the readFrom: evaluator, callee naming and the writer flow keep.
        for attr in ("_dispatch_eval_cache", "_callee_names", "_function_entries"):
            _ctx_cache(ctx, attr, dict)["stale"] = object()
        stale_flow = _ctx_store(ctx, "_writer_flow", object())

        # Empty class list: extract_all runs its pre-passes and returns [].
        cl = ClassList([])
        result = E.extract_all(ctx, StringTable(), cl)

        assert result == []
        for attr in ("_dispatch_eval_cache", "_callee_names", "_function_entries"):
            assert not getattr(ctx, attr), (
                f"{attr} not reset by extract_all: a stale cache would leak "
                f"across extractions on a reused BinaryContext")
        # the writeTo: pre-pass builds this extraction's own writer flow
        assert ctx._writer_flow is not stale_flow and ctx._writer_flow.cl is cl


class TestNoDirectCacheStores:
    def test_ctx_attributes_are_set_through_the_helpers(self):
        """A per-extraction cache stored with ``ctx._name = ...`` is never registered, so
        extract_all would not clear it.  Every such store must go through _ctx_cache /
        _ctx_store (or be listed in _NOT_CACHES as a binary property)."""
        pat = re.compile(r"\bctx\.(_[a-z][a-z0-9_]*)\s*=(?!=)")
        offenders = []
        for sub in ("proto", "macho", "serializers"):
            for root, _dirs, files in os.walk(os.path.join(_PKG, sub)):
                for fn in files:
                    if not fn.endswith(".py"):
                        continue
                    path = os.path.join(root, fn)
                    with open(path, encoding="utf-8") as fh:
                        for n, line in enumerate(fh, 1):
                            for m in pat.finditer(line):
                                if m.group(1) not in _NOT_CACHES:
                                    offenders.append(f"{os.path.relpath(path, _PKG)}:{n}: {line.strip()}")
        assert not offenders, "direct ctx cache stores:\n" + "\n".join(offenders)
