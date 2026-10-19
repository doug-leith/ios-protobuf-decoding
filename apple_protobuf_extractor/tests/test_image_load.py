"""macho.load — the one front end of every image extraction (the CLI, the cross-image
resolver's extraction of a defining image, the validation tools).

  - load_classes on the compiled f1 fixture (binary mode): the same string table and class
    list as building them directly; no .symbols step outside a cache; the step hook wraps
    each stage.
  - load_classes with a cache reader: the .symbols names are applied and counted, and an
    image the .symbols sub-cache does not list is reported as such (symbol_counts None).
  - proto.cross_image.extract_cache_image extracts through load_cache_image and warns when
    the defining image has no local symbols.
"""
from __future__ import annotations

import os
import unittest
from contextlib import contextmanager
from unittest import mock

from macho.classlist import build_class_list
from macho.load import LoadedImage, load_classes
from macho.memory import BinaryContext
from macho.strings import build_string_table
from tests.test_synthetic_fixtures import _FIXTURES_DIR, load_macho_slice

_FIXTURE = os.path.join(_FIXTURES_DIR, 'f1_writeto_fieldnum', 'testmsg')


@unittest.skipUnless(os.path.exists(_FIXTURE), 'synthetic fixture binary not built')
class TestLoadClasses(unittest.TestCase):

    def _ctx(self):
        with open(_FIXTURE, 'rb') as fh:
            return BinaryContext(load_macho_slice(fh.read()))

    def test_binary_mode_matches_building_directly(self):
        img = load_classes(self._ctx())
        ctx = self._ctx()
        cl = build_class_list(ctx, build_string_table(ctx))
        self.assertEqual([(c.name, [m.name for m in c.methods]) for c in img.cl],
                         [(c.name, [m.name for m in c.methods]) for c in cl])
        self.assertIsNone(img.symbol_counts)

    def test_each_stage_runs_inside_the_step_hook(self):
        seen = []

        @contextmanager
        def step(label):
            seen.append(label)
            yield
        load_classes(self._ctx(), step=step)
        self.assertEqual(seen, ["building string table", "parsing ObjC class list"])

    def test_cache_mode_applies_and_counts_the_local_symbols(self):
        ctx = self._ctx()

        class Reader:
            def __init__(self, syms):
                self.syms = syms

            def image_local_symbols(self, mach_va):
                return self.syms

        counts = {'renamed': 1, 'corrected': 0, 'added': 0, 'meta_added': 0}
        with mock.patch('macho.load.apply_to_classes', return_value=counts) as applied:
            img = load_classes(ctx, Reader(object()), 0x1000)
        applied.assert_called_once()
        self.assertEqual(img.symbol_counts, counts)
        self.assertIsNone(load_classes(self._ctx(), Reader(None), 0x1000).symbol_counts)


class TestCrossImageExtractsThroughTheLoader(unittest.TestCase):

    def test_extract_cache_image_uses_load_cache_image_and_warns_without_symbols(self):
        from proto import cross_image
        img = LoadedImage(ctx=object(), st=object(), cl=object(), symbol_counts=None)

        class Reader:
            def image_containing(self, va):
                return (va, '/System/Library/Frameworks/X.framework/X')

        with mock.patch('macho.load.load_cache_image', return_value=img) as loaded, \
                mock.patch('proto.extractor.extract_all', return_value=['m']) as extracted, \
                self.assertLogs('proto.cross_image', 'WARNING') as logs:
            msgs, ctx = cross_image.extract_cache_image(Reader(), 0x1000, prefixes=('GEO',))
        loaded.assert_called_once()
        extracted.assert_called_once_with(img.ctx, img.st, img.cl, prefixes=('GEO',))
        self.assertEqual((msgs, ctx), (['m'], img.ctx))
        self.assertIn('X.framework/X has no .symbols local symbols', logs.output[0])


if __name__ == '__main__':
    unittest.main()
