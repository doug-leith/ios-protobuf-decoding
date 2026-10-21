"""The methods and ivars the class-list parser reads, against the dyld cache's ``.symbols`` local
symbols, per image: each method named as the ``-[Class sel]`` / ``+[Class sel]`` at its IMP, each
class's method list read whole (as many methods as its header counts: a method ``.symbols`` names
but no list holds is an ``objc_direct`` one), and each ``_OBJC_IVAR_$_Class.ivar`` offset variable
an ivar of that name of that class, at that offset.

    python -m oracles.method_names CACHE IMAGE..."""
import collections
import sys

from macho import classlist as CL
from macho.memory import BinaryContext
from macho.strings import build_string_table


class Result(collections.namedtuple("Result", "methods agree unnamed wrong no_symbol examples "
                                                 "missed ivars ivars_wrong swift_thunks")):
    """Counts over an image's methods: named as ``.symbols`` names them, left unnamed, named
    otherwise, or with no ``.symbols`` name to compare (a Swift ``@objc`` thunk's IMP is named by
    its mangled ``...To`` symbol instead: *swift_thunks*); the classes with fewer or more methods
    than their method list's header counts (*missed*); the ivar offset variables, and those the
    parser has under another name, class or offset (*ivars_wrong*); ``examples`` of each kind."""


def _listed(ctx, cls_va):
    """The count in the header of the method list of the class (or metaclass) at *cls_va*, read
    from ``class_t`` / ``class_ro_t`` here; None when it has a list of lists (low bit set)."""
    data = ctx.read_ptr(cls_va + 32) & 0x00007FFFFFFFFFF8   # class_t.bits: the ro pointer
    methods = ctx.read_ptr(data + 32)                       # class_ro_t.baseMethods
    if methods & 1:
        return None
    return ctx.read_u32(methods + 4) if methods else 0


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
    classes = {}
    thunks = {a for n, a in reader.image_symbol_addrs(va, "To").items()
              if n.startswith("_$s") and n.endswith("To")}
    for c in CL.build_class_list(ctx, build_string_table(ctx)):
        truth = (syms.meta_to_sels if c.is_meta else syms.class_to_sels).get(c.name, {})
        by_imp = {imp: sel for sel, imp in truth.items()}
        for m in c.methods:
            counts["methods"] += 1
            t = by_imp.get(m.imp)
            if t is None and m.imp in thunks:     # a Swift @objc thunk: no -[C sel] to compare
                counts["swift_thunks"] += 1
            elif t is None:
                counts["no_symbol"] += 1
                examples["no_symbol"].append((c.name, hex(m.imp), m.name))
            elif m.name is None:
                counts["unnamed"] += 1
                examples["unnamed"].append((c.name, hex(m.imp), t))
            elif m.name != t:
                counts["wrong"] += 1
                examples["wrong"].append((c.name, hex(m.imp), m.name, t))
            else:
                counts["agree"] += 1
        listed = _listed(ctx, c.vmaddr)         # what the class's own method list says it holds
        if listed is not None and listed != len(c.methods):
            counts["missed"] += 1
            examples["missed"].append((c.name, listed, len(c.methods)))
        if not c.is_meta:
            classes[c.name] = c
    for name, va_ in reader.image_symbol_addrs(va, "_OBJC_IVAR_$_").items():
        cls_name, _, ivar = name[len("_OBJC_IVAR_$_"):].partition(".")
        counts["ivars"] += 1
        c = classes.get(cls_name)
        iv = next((i for i in c.ivars if i.name == ivar), None) if c else None
        offset = int.from_bytes(ctx.read_bytes(va_, 4), "little")
        if iv is None or iv.offset != offset or (iv.offset_slot and iv.offset_slot != va_):
            counts["ivars_wrong"] += 1
            examples["ivars_wrong"].append((name, hex(va_), offset, iv and (iv.offset,
                                                                            hex(iv.offset_slot))))
    return Result(counts["methods"], counts["agree"], counts["unnamed"], counts["wrong"],
                  counts["no_symbol"], dict(examples), counts["missed"], counts["ivars"],
                  counts["ivars_wrong"], counts["swift_thunks"])


def main(argv):
    from macho.dyld_cache import DyldCacheReader
    reader = DyldCacheReader(argv[0])
    for image in argv[1:]:
        res = compare(reader, image)
        if res is None:
            print(image, "no .symbols")
            continue
        print("%-24s methods %6d agree %6d unnamed %4d WRONG %4d (no .symbols name %d) missed %d"
              " ivars %d WRONG %d" % (image, res.methods, res.agree, res.unnamed, res.wrong,
                                     res.no_symbol, res.missed, res.ivars, res.ivars_wrong))
        for kind, rows in res.examples.items():
            for row in rows[:8]:
                print("     ", kind, row)


if __name__ == "__main__":
    main(sys.argv[1:])
