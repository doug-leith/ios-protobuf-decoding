"""The image a test stand-in context does not model.

A stand-in context answers the reads its test is about; for everything else it is an image
with nothing there, answered the way :class:`macho.memory.BinaryContext` answers for an
image without it: no section, no function index, and an address no segment holds
(``ValueError``).  The extractor guards reads against those errors only
(:data:`macho.memory.READ_ERRORS`), so a stand-in missing a method fails loudly instead of
reading as an empty image.
"""
from types import SimpleNamespace


class NoImage:
    """Its keyword arguments become attributes: ``NoImage(segments=[...])``."""
    is_cache_backed = False
    segments = ()
    image_bytes = b""

    def __init__(self, **attrs):
        self.__dict__.update(attrs)

    def has_section(self, segname, sectname):
        return False

    def is_variable(self, vmaddr):
        return False

    def bind_name_for(self, vmaddr):            # (no chained-fixup binds)
        return None

    def function_starts(self):
        return []

    def iter_symbols(self):                     # (no symbol table)
        return iter(())

    def iter_symbol_names(self):
        return iter(())

    def vmaddr_to_offset(self, vmaddr, length=1):
        raise ValueError(f"vmaddr {vmaddr:#x} not in any segment")


class TextImage(NoImage):
    """An image with code: its ``__TEXT,__text`` is *text* ``(lo, hi)`` and its
    LC_FUNCTION_STARTS *starts* (what bounds a function, :func:`proto.function_body.function_end`)."""

    def __init__(self, text=(0x1000, 0x100000), starts=(), **attrs):
        super().__init__(**attrs)
        self._text, self._starts = text, sorted(starts)

    def has_section(self, segname, sectname):
        return (segname, sectname) == ('__TEXT', '__text')

    def section(self, segname, sectname):
        lo, hi = self._text
        return SimpleNamespace(vmaddr=lo, vmsize=hi - lo)

    def function_starts(self):
        return list(self._starts)
