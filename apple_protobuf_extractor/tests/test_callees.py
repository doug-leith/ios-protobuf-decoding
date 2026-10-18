"""proto/callees.py: callee naming must not hide wiring bugs.

``callee_name`` used to catch AttributeError, so a renamed or missing reader method turned
into "no name", which in turn relaxed the objc_msgSend check of the shared selector stub
(:func:`proto.callees.stub_selector`; code review 2026-10-18).  A context that has no names
still gets None; a broken reader raises.
"""
import unittest

from proto.callees import callee_name


class _NoNamesCtx:
    """A context-like stub with no cache reader and no import stubs (as unit tests use)."""
    is_cache_backed = True
    _cache_reader = None


class _Reader:
    def __init__(self, names):
        self.names = names

    def export_name_at(self, va):
        return self.names.get(va)


class _CacheCtx:
    is_cache_backed = True

    def __init__(self, reader):
        self._cache_reader = reader


class TestCalleeName(unittest.TestCase):
    def test_none_address(self):
        self.assertIsNone(callee_name(_NoNamesCtx(), None))

    def test_context_without_reader_has_no_names(self):
        self.assertIsNone(callee_name(_NoNamesCtx(), 0x1000))

    def test_exported_name(self):
        ctx = _CacheCtx(_Reader({0x1000: "_objc_msgSend"}))
        self.assertEqual(callee_name(ctx, 0x1000), "_objc_msgSend")

    def test_memoised(self):
        reader = _Reader({0x1000: "_objc_retain"})
        ctx = _CacheCtx(reader)
        callee_name(ctx, 0x1000)
        reader.names.clear()
        self.assertEqual(callee_name(ctx, 0x1000), "_objc_retain")

    def test_wiring_bug_is_not_swallowed(self):
        class Broken:                               # the reader lost its export_name_at
            pass
        with self.assertRaises(AttributeError):
            callee_name(_CacheCtx(Broken()), 0x1000)


if __name__ == "__main__":
    unittest.main()
