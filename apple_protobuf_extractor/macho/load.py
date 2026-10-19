"""macho/load — the one front end every extraction of an image runs: string table, ObjC
class list and, for a dyld-cache image, the method names the ``.symbols`` sub-cache restores.

``cli.main`` (``--framework`` / ``--binary``), the cross-image resolver
(:func:`proto.cross_image.extract_cache_image`, which extracts the image defining a
referenced class) and the validation tools all load an image this way, so a message pulled
in from another image is extracted exactly as ``--framework <that image>`` would extract it.
"""
from __future__ import annotations

from contextlib import nullcontext
from dataclasses import dataclass
from typing import Callable, ContextManager, Dict, Optional

from macho.classlist import ClassList, build_class_list
from macho.local_symbols import apply_to_classes
from macho.memory import BinaryContext
from macho.strings import StringTable, build_string_table


@dataclass
class LoadedImage:
    """An image ready for :func:`proto.extractor.extract_all`."""
    ctx: BinaryContext
    st: StringTable
    cl: ClassList
    # Cache images only: what the .symbols local symbols changed (apply_to_classes' counts),
    # or None when the .symbols sub-cache does not list the image -- its method names are
    # then only what the (possibly preoptimised, name-stripped) method lists say.
    symbol_counts: Optional[Dict[str, int]] = None


def load_classes(ctx: BinaryContext, reader=None, mach_va: Optional[int] = None,
                 step: Optional[Callable[[str], ContextManager]] = None) -> LoadedImage:
    """String table and class list of *ctx*; for a cache image (*reader*, *mach_va*) the
    method names restored from the ``.symbols`` sub-cache: a preoptimised "direct selector"
    method list strips the selector name field, and the local symbols ``-[Class sel]`` are
    keyed by the reliable IMP.  *step(label)*, when given, wraps each stage (progress
    output)."""
    step = step or (lambda _label: nullcontext())
    with step("building string table"):
        st = build_string_table(ctx)
    with step("parsing ObjC class list"):
        cl = build_class_list(ctx, st)
    counts = None
    if reader is not None and mach_va is not None:
        with step("recovering method names from .symbols"):
            syms = reader.image_local_symbols(mach_va)
            if syms:
                counts = apply_to_classes(cl, syms)
    return LoadedImage(ctx, st, cl, counts)


def load_cache_image(reader, mach_va: int) -> LoadedImage:
    """:func:`load_classes` for the dyld-cache image whose Mach-O header is at *mach_va*."""
    return load_classes(BinaryContext.from_cache(reader, mach_va), reader, mach_va)
