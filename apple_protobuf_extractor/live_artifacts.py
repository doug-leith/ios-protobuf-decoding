"""Load the Apple artifacts the live tests analyse (a dyld-cache image or a standalone binary).

Each loader returns ``(ctx, string_table, class_list)``, or ``None`` when the artifact is not
present, so a test can skip cleanly.  All artifact locations come from the single config module
``artifacts`` (the data dir defaults to ``<repo>/iphone8_data``; override with ``MACHO_DATA_DIR``,
or a per-artifact variable such as ``MACHO_TEST_CACHE`` / ``MACHO_TEST_LOCATIOND``).
"""
import os

import artifacts


def load_cache(image):
    from macho.dyld_cache import DyldCacheReader
    from macho.memory import BinaryContext
    from macho.strings import build_string_table
    from macho import classlist as CL
    from macho.local_symbols import apply_to_classes
    cache = artifacts.cache_file()
    if cache is None:
        return None
    reader = DyldCacheReader(cache)
    mv = reader.find_image_header(image)
    if mv is None:
        return None
    ctx = BinaryContext.from_cache(reader, mv)
    st = build_string_table(ctx)
    cl = CL.build_class_list(ctx, st)
    syms = reader.image_local_symbols(mv)
    if syms:
        apply_to_classes(cl, syms)
    return ctx, st, cl


def load_binary(envvar, default):
    """Load a standalone Mach-O binary -> (ctx, st, cl).  ``envvar`` overrides the
    default path (``<data_dir>/<default>``).  The artifact location is defined in exactly one place (the ``artifacts`` module)."""
    from macho.memory import BinaryContext
    from macho.strings import build_string_table
    from macho import classlist as CL
    path = os.environ.get(envvar, "").strip() or \
        os.path.join(artifacts.data_dir(), default)
    if not os.path.isfile(path):
        return None
    with open(path, "rb") as fh:
        ctx = BinaryContext(fh.read())
    st = build_string_table(ctx)
    cl = CL.build_class_list(ctx, st)
    return ctx, st, cl


def load_locationd():
    return load_binary("MACHO_TEST_LOCATIOND", "locationd")
