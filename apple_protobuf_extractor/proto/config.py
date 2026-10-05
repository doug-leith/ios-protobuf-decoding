"""proto/config — pure extraction-settings helpers.

Carved from proto.extractor (#11 split, step 5a): the ObjC class-prefix stripper and
the enum-fallback debug sink.  Both knobs are threaded as **explicit parameters** from
the public entry points (``extract_all(prefixes=…, enum_debug_writer=…)`` →
``extract_proto_message`` → ``_collect_enum_definitions``); there is no module-level
mutable state.  When a caller omits a value, the prefix stripper falls back to the
canonical ``DEFAULT_PREFIXES`` and the debug sink is simply absent (a no-op).  Imports
only proto.defaults.
"""
from typing import Any, Callable, Dict, Optional, Tuple
from proto.defaults import DEFAULT_PREFIXES


def _class_to_proto_name(
    class_name: str,
    prefixes: Optional[Tuple[str, ...]] = None,
) -> str:
    """
    Strip the ObjC class prefix to get the proto message name.

    *prefixes* is the prefix list to try, highest-priority first.  Pass ``None``
    (the default) to use the canonical :data:`proto.defaults.DEFAULT_PREFIXES`
    (``GEO``, ``CLP``, ``CLM``, ``CLN``); pass an explicit tuple — e.g. from the
    CLI ``--prefix`` flag — to strip a different set.

    e.g. 'GEOAPSessionData' → 'APSessionData'
         'CLPLocation'      → 'Location'
         'APPLFoo'          → 'Foo'  (with prefixes=('APPL',))
    """
    for prefix in (prefixes if prefixes is not None else DEFAULT_PREFIXES):
        if class_name.startswith(prefix):
            return class_name[len(prefix):]
    return class_name


def _dbg_enum(record: Dict[str, Any], *, writer=None) -> None:
    """Emit one enum-fallback debug record to *writer* (no-op when ``writer`` is
    ``None`` — i.e. ``--debug-enums`` was not supplied).  The writer is threaded
    explicitly from :func:`cli.main` through ``extract_all`` — there is no global
    sink."""
    if writer is not None:
        writer(record)
