"""The method names the class-list parser reads, against the dyld cache's ``.symbols`` local
symbols (``-[Class sel]`` / ``+[Class sel]`` at each IMP), per image.

    python -m oracles.method_names CACHE IMAGE..."""
import collections
import sys

from macho import classlist as CL
from macho.memory import BinaryContext
from macho.strings import build_string_table


class Result(collections.namedtuple("Result", "methods agree unnamed wrong no_symbol examples")):
    """Counts over an image's methods: named as ``.symbols`` names them, left unnamed, named
    otherwise, or with no ``.symbols`` name to compare; ``examples`` of the unnamed and wrong."""


def compare(reader, image):
    """:class:`Result` for *image* in the cache *reader*, or None when the cache has no
    ``.symbols`` for it."""
    va = reader.find_image_header(image)
    syms = reader.image_local_symbols(va)
    if not syms:
        return None
    ctx = BinaryContext.from_cache(reader, va)
    counts = collections.Counter()
    examples = collections.defaultdict(list)
    for c in CL.build_class_list(ctx, build_string_table(ctx)):
        truth = (syms.meta_to_sels if c.is_meta else syms.class_to_sels).get(c.name, {})
        by_imp = {imp: sel for sel, imp in truth.items()}
        for m in c.methods:
            counts["methods"] += 1
            t = by_imp.get(m.imp)
            if t is None:
                counts["no_symbol"] += 1
            elif m.name is None:
                counts["unnamed"] += 1
                examples["unnamed"].append((c.name, hex(m.imp), t))
            elif m.name != t:
                counts["wrong"] += 1
                examples["wrong"].append((c.name, hex(m.imp), m.name, t))
            else:
                counts["agree"] += 1
    return Result(counts["methods"], counts["agree"], counts["unnamed"], counts["wrong"],
                  counts["no_symbol"], dict(examples))


def main(argv):
    from macho.dyld_cache import DyldCacheReader
    reader = DyldCacheReader(argv[0])
    for image in argv[1:]:
        res = compare(reader, image)
        if res is None:
            print(image, "no .symbols")
            continue
        print("%-24s methods %6d agree %6d unnamed %4d WRONG %4d (no .symbols name %d)"
              % (image, res.methods, res.agree, res.unnamed, res.wrong, res.no_symbol))
        for kind, rows in res.examples.items():
            for row in rows[:8]:
                print("     ", kind, row)


if __name__ == "__main__":
    main(sys.argv[1:])
