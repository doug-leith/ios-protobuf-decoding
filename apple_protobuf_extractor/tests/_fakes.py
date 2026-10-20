"""The image a test stand-in context does not model.

A stand-in context answers the reads its test is about; for everything else it is an image
with nothing there, answered the way :class:`macho.memory.BinaryContext` answers for an
image without it: no section, no function index, and an address no segment holds
(``ValueError``).  The extractor guards reads against those errors only
(:data:`macho.memory.READ_ERRORS`), so a stand-in missing a method fails loudly instead of
reading as an empty image.
"""


class NoImage:
    """Its keyword arguments become attributes: ``NoImage(segments=[])``."""
    is_cache_backed = False

    def __init__(self, **attrs):
        self.__dict__.update(attrs)

    def has_section(self, segname, sectname):
        return False

    def function_starts(self):
        return []

    def vmaddr_to_offset(self, vmaddr, length=1):
        raise ValueError(f"vmaddr {vmaddr:#x} not in any segment")
