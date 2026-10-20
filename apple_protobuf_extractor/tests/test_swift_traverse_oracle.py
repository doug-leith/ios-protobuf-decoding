"""The swift name-map reading checked against an independent oracle (tests/_traverse_oracle.py):
the field number ``traverse`` visits a storage location with, and the stored property that
location belongs to (its getter, or the field record its metadata offset indexes).  Every
(number, name) the oracle derives must be in the reading, under that number and that name."""
import os
import unittest

from tests import _traverse_oracle as O
from tests.test_newer_toolchain_ios27 import _ios27_cache_dir
from tests.test_swift_descriptor_extract import _data_path, _load_ctx
from serializers import swift_descriptor_extract as S

_IPHONE8_STANDALONE = (("DPSubmissionService",), ("libexec", "nptocompaniond"))
_IOS27_IMAGES = ("AONSense.dylib", "/BiomeStreams")
_INTERNAL_SWIFT_PROTOBUF = ("dylib", "System", "Library", "PrivateFrameworks",
                            "InternalSwiftProtobuf.framework", "InternalSwiftProtobuf")


def _compare(ctx, names):
    """(agreements, [problems]) between the reading and the oracle for one image."""
    reading = {}
    for m in S.swift_messages(ctx):
        reading[m.qualified] = {f.number: f.name for f in m.fields}
    agree, problems = 0, []
    for (module, typ), fields in O.oracle(ctx, names).items():
        got = reading.get(f"{module}.{typ}")
        if got is None:
            continue
        for num, prop in sorted(fields.items()):
            if num not in got:
                problems.append(f"{typ}: field {num} ({prop}) not read; read {sorted(got.items())}")
            elif not O.same_name(got[num], prop):
                problems.append(f"{typ}: field {num} read as {got[num]!r}, stores {prop!r}")
            else:
                agree += 1
    return agree, problems


def _binary_names(ctx):
    return {n: a for n, a in ctx.iter_symbols() if a}


class TestTraverseOracleStandalone(unittest.TestCase):
    def test_standalone_binaries(self):
        paths = [p for p in (_data_path(*rel) for rel in _IPHONE8_STANDALONE) if p]
        if not paths:
            self.skipTest("no iPhone 8 standalone swift binary available")
        total = 0
        for p in paths:
            ctx = _load_ctx(p)
            agree, problems = _compare(ctx, _binary_names(ctx))
            self.assertEqual(problems, [], os.path.basename(p))
            total += agree
        self.assertGreaterEqual(total, 40)       # 44 when both are present (17 at #105)

    def test_internal_swift_protobuf_wrappers(self):
        # Int32Value / Int64Value / UInt32Value / UInt64Value / BytesValue: the `value` record's
        # type is a reference outside the image that the extracted file no longer names.  The
        # record still counts for the fieldless test and the one-entry reading (TODO #106).
        p = _data_path(*_INTERNAL_SWIFT_PROTOBUF)
        if not p:
            self.skipTest("extracted InternalSwiftProtobuf not available")
        ctx = _load_ctx(p)
        agree, problems = _compare(ctx, _binary_names(ctx))
        self.assertGreaterEqual(agree, 20)       # 22 (17 at #107)
        self.assertEqual(problems, [])


@unittest.skipUnless(_ios27_cache_dir(), "iOS 27 cache not present")
class TestTraverseOracleIos27(unittest.TestCase):
    def test_cache_images(self):
        from macho.dyld_cache import DyldCacheReader
        from macho.memory import BinaryContext
        reader = DyldCacheReader(os.path.join(_ios27_cache_dir(), "dyld_shared_cache_arm64e"))
        try:
            total, seen = 0, set()
            for va, path in reader.list_images():
                image = next((i for i in _IOS27_IMAGES if path.endswith(i)), None)
                if image is None:
                    continue
                seen.add(image)
                ctx = BinaryContext.from_cache(reader, va)
                names = reader.image_symbol_addrs(va, "V8traverse", "vg", "CMn", "VMn", "Wvd")
                agree, problems = _compare(ctx, names)
                self.assertEqual(problems, [], path)
                total += agree
        finally:
            reader.close()
        self.assertEqual(seen, set(_IOS27_IMAGES))
        self.assertGreaterEqual(total, 900)      # 930 (184 at #105)


if __name__ == "__main__":
    unittest.main()
