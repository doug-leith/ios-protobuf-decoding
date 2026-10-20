"""``BinaryContext.function_starts``: the image's ``LC_FUNCTION_STARTS`` table, from the binary's
own linkedit or, for a cache image, the cache's shared ``__LINKEDIT``
(``DyldCacheReader.image_function_starts``).  Checked against an independent source: every
function the symbol table or the class list names starts there."""
import os
import unittest

from serializers import swift_descriptor_extract as SW


def _oracle():
    try:
        import artifacts
        p = artifacts.swift_oracle_path()
        return p if os.path.isfile(p) else None
    except Exception:
        return None


def _cache():
    try:
        import artifacts
        return artifacts.cache_file()
    except Exception:
        return None


@unittest.skipUnless(_oracle(), "swift oracle fixture not present")
class TestBinaryFunctionStarts(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        from macho.memory import BinaryContext
        cls.ctx = BinaryContext(SW.load_macho_slice(open(_oracle(), "rb").read()))

    def test_every_function_symbol_starts_a_function(self):
        text = self.ctx.section("__TEXT", "__text")
        starts = set(self.ctx.function_starts())
        syms = {a for _n, a in self.ctx.iter_symbols()
                if a and text.vmaddr <= a < text.vmaddr + text.vmsize}
        self.assertGreater(len(syms), 1000)
        self.assertEqual(syms - starts, set())

    def test_sorted_inside_text(self):
        starts = self.ctx.function_starts()
        self.assertEqual(starts, sorted(starts))
        self.assertGreaterEqual(starts[0], self.ctx.section("__TEXT", "__text").vmaddr)


@unittest.skipUnless(_cache() and os.path.isfile(_cache()), "dyld shared cache not present")
class TestCacheFunctionStarts(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        from macho.dyld_cache import DyldCacheReader
        from macho.load import load_cache_image
        reader = DyldCacheReader(_cache())
        img = load_cache_image(reader, reader.find_image_header("GeoServices"))
        cls.ctx, cls.cl = img.ctx, img.cl

    def test_every_method_imp_starts_a_function(self):
        starts = set(self.ctx.function_starts())
        imps = {m.imp for c in self.cl for m in c.methods if m.imp}
        self.assertGreater(len(imps), 10000)
        self.assertEqual(imps - starts, set())


if __name__ == "__main__":
    unittest.main()
