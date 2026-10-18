"""proto/callees.py -- the symbol name of the function a call reaches.

A call into another image is named by that image's ABI: the exported symbol it lands on
(``_objc_retain_x2``, ``_PBDataWriterWriteInt32Field``, ``_objc_msgSend``).  These names are
fixed by the Objective-C runtime / ProtocolBuffer ABI, the same in every binary, so code may
rely on them the way it relies on the ``writeTo:`` selector.

* dyld shared cache: the cache links calls directly (or through a stub island) to the
  callee's code; the name comes from the exporting image's export trie
  (:meth:`macho.dyld_cache.DyldCacheReader.export_name_at`).
* standalone binary: a call goes through an import stub whose GOT slot the binary binds by
  name (:func:`proto.dispatch_eval._import_name`).

A function of the image itself (not exported) has no name here: None.
"""
from __future__ import annotations

from typing import Optional

from macho.memory import BinaryContext, _ctx_cache


def callee_name(ctx: BinaryContext, va: Optional[int]) -> Optional[str]:
    """Exported (cache) or imported (binary) symbol name of the function a ``bl`` / ``b`` to
    *va* reaches, or None.  Memoised on *ctx*."""
    if va is None:
        return None
    memo = _ctx_cache(ctx, "_callee_names", dict)
    if va in memo:
        return memo[va]
    name: Optional[str] = None
    try:
        if getattr(ctx, "is_cache_backed", False):
            reader = getattr(ctx, "_cache_reader", None)
            if reader is not None:                   # (a cache context always has one)
                from proto.write_helpers import _helper_real_target   # (import cycle via writeto)
                name = reader.export_name_at(va)
                if name is None:
                    real = _helper_real_target(ctx, va)
                    if real != va:
                        name = reader.export_name_at(real)
        else:
            from proto.dispatch_eval import _import_name
            name = _import_name(ctx, va)
    except (ValueError, KeyError, IndexError):
        name = None                                  # unreadable bytes at va: no name
    memo[va] = name
    return name
