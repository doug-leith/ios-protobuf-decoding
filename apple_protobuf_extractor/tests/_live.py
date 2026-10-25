"""tests/_live.py -- one extraction of an iPhone 8 dyld-cache image, shared by the test classes
that read it.

Extracting GeoServices takes some three minutes; the classes that need its messages read them
from here, once per process, instead of extracting it each in their own ``setUpClass``.  They
only read the result: a test that changes what it holds (a message, the context's state) must
extract its own.  Under pytest-xdist they share a worker (``pytest.mark.xdist_group``).
"""
from __future__ import annotations

import functools
from typing import List, NamedTuple, Optional


class Extracted(NamedTuple):
    ctx: object
    st: object
    cl: object
    messages: List[object]


@functools.lru_cache(maxsize=None)
def extracted(image: str = "GeoServices") -> Optional[Extracted]:
    """*image* of the iPhone 8 cache, loaded (``live_artifacts.load_cache``: the ``.symbols``
    method names restored) and extracted; None when the cache or the image is not present."""
    import live_artifacts as V
    from proto.extractor import extract_all
    loaded = V.load_cache(image)
    if loaded is None:
        return None
    ctx, st, cl = loaded
    return Extracted(ctx, st, cl, extract_all(ctx, st, cl))
