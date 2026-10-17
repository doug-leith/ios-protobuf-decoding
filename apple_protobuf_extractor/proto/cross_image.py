"""
proto/cross_image.py
====================
Resolve message fields whose type is a PBCodable class defined in ANOTHER image of the
dyld shared cache, by extracting that class from the image that defines it.

The extractor recovers one image at a time, so a field typed by a class from elsewhere
(CloudKitDaemon's ``CKDPRecord.recordIdentifier`` is a ``CKDPRecordIdentifier``, defined in
CloudKit.framework) used to fall back to ``bytes  // unresolved: <Class>``.  In the cache
the owning image is not a guess:

1. **Class reference** (exact).  Code that creates or tests an instance of the class goes
   through a slot in the referencing image's ``__objc_classrefs`` / ``__objc_superrefs``,
   and the cache builder has bound that slot to the class's ``class_t``.  The image whose
   segments hold that address defines the class.
2. **Linked dylibs** (by name), only when no slot names the class (an ivar type encoding is
   just a name).  The ObjC runtime would find the class by name among the loaded images,
   and the images the referencing image is guaranteed to have loaded are its
   ``LC_LOAD_DYLIB`` closure.  Exactly one image in that closure defining the name is the
   answer; none, or more than one, leaves the field unresolved, with the reason reported.

The defining image is then extracted with the same pipeline as the requested one
(:func:`proto.extractor.extract_all`), and the referenced message joins the output together
with everything IT references, transitively (resolved the same way, relative to the image
it came from).  Each such message carries ``defined_in`` (emitted as a comment), and is
grouped by package like any other: the output stays one self-contained set of files for
the requested image, so it compiles without another framework's files on the include path
(two frameworks' outputs may share file names — CloudKit and CloudKitDaemon both have a
``ckdp.proto``).

A referenced class that is defined in the referencing image itself is never looked up
elsewhere: if it is missing there (filtered out, or its extraction failed) that is a fact
about this image, and the field stays ``bytes``.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Set, Tuple

from macho.cache_classlist import (class_names_defined_by_image, class_refs_for_image,
                                   superclass_chain_names)
from proto.emitter import package_for_class, referenced_message_class
from proto.models import ProtoMessage, get_diagnostics
from proto.protoclass_set import _PB_ROOT_NAMES

log = logging.getLogger(__name__)

VIA_CLASSREF = "resolved through a class reference"
VIA_LINKED_DYLIB = "the only linked image defining this class name"
VIA_SAME_IMAGE = "referenced by another message from that image"


@dataclass
class CrossImageResult:
    """What :func:`resolve_cross_image` added, and what it could not resolve."""
    added: List[ProtoMessage] = field(default_factory=list)
    # class name -> why it stays unresolved (the field keeps `bytes  // unresolved: X`)
    unresolved: Dict[str, str] = field(default_factory=dict)
    # image path -> error, for a defining image whose extraction raised
    image_errors: Dict[str, str] = field(default_factory=dict)


def extract_cache_image(reader, mach_va: int, prefixes=None) -> Tuple[List[ProtoMessage], object]:
    """Extract the PBCodable messages of the cache image at *mach_va* exactly as the CLI
    does for ``--framework`` (string table, class list, ``.symbols`` method names,
    :func:`extract_all`).  Returns ``(messages, ctx)``; the ctx carries the run's
    diagnostics."""
    from macho.classlist import build_class_list
    from macho.local_symbols import apply_to_classes
    from macho.memory import BinaryContext
    from macho.strings import build_string_table
    from proto.extractor import extract_all

    ctx = BinaryContext.from_cache(reader, mach_va)
    st = build_string_table(ctx)
    cl = build_class_list(ctx, st)
    syms = reader.image_local_symbols(mach_va)
    if syms:
        apply_to_classes(cl, syms)
    return extract_all(ctx, st, cl, prefixes=prefixes), ctx


class _Locator:
    """Answers "which cache image defines class C, as referenced from image R"."""

    def __init__(self, reader):
        self.reader = reader
        self._paths: Dict[str, int] = {path: va for va, path in reader.list_images()}
        self._classrefs: Dict[int, Dict[str, int]] = {}
        self._defined: Dict[int, Dict[str, int]] = {}
        self._closure: Dict[int, List[int]] = {}

    def path_of(self, mach_va: int) -> str:
        hit = self.reader.image_containing(mach_va)
        return hit[1] if hit else f"<image @ {mach_va:#x}>"

    def defined_by(self, mach_va: int) -> Dict[str, int]:
        if mach_va not in self._defined:
            self._defined[mach_va] = class_names_defined_by_image(self.reader, mach_va)
        return self._defined[mach_va]

    def linked_closure(self, mach_va: int) -> List[int]:
        """Images *mach_va* links, transitively (breadth-first, itself excluded).  An
        install name the cache does not hold is skipped (a weak link may be absent)."""
        if mach_va not in self._closure:
            seen, order, queue = {mach_va}, [], [mach_va]
            while queue:
                for name in self.reader.image_dependencies(queue.pop(0)):
                    dep = self._paths.get(name)
                    if dep is not None and dep not in seen:
                        seen.add(dep)
                        order.append(dep)
                        queue.append(dep)
            self._closure[mach_va] = order
        return self._closure[mach_va]

    def locate(self, ref_va: int, class_name: str) -> Tuple[Optional[int], Optional[int], str]:
        """``(defining image mach_va, class_t vmaddr, how)``, or ``(None, None, why not)``."""
        if ref_va not in self._classrefs:
            self._classrefs[ref_va] = class_refs_for_image(self.reader, ref_va)
        class_va = self._classrefs[ref_va].get(class_name)
        if class_va is not None:
            hit = self.reader.image_containing(class_va)
            if hit is None:
                return None, None, (f"its class reference points at {class_va:#x}, "
                                    f"which no cache image holds")
            return hit[0], class_va, VIA_CLASSREF
        owners = [va for va in self.linked_closure(ref_va) if class_name in self.defined_by(va)]
        if len(owners) == 1:
            return owners[0], self.defined_by(owners[0])[class_name], VIA_LINKED_DYLIB
        if owners:
            return None, None, ("defined by several linked images: "
                                + ", ".join(sorted(self.path_of(va) for va in owners)))
        return None, None, "not referenced by a class reference, nor defined by any linked image"


def resolve_cross_image(
    reader,
    mach_va: int,
    messages: List[ProtoMessage],
    *,
    prefixes=None,
    extract: Optional[Callable[[object, int], Tuple[List[ProtoMessage], object]]] = None,
) -> CrossImageResult:
    """Find every class that *messages* (extracted from the image at *mach_va*) reference
    as a message type but that is not among them, extract it from the image that defines
    it, and return the messages to add (transitively closed).  *messages* is not changed.

    *extract* (``(reader, mach_va) -> (messages, ctx)``) defaults to
    :func:`extract_cache_image` with *prefixes*; tests substitute it."""
    if extract is None:
        def extract(rd, va):
            return extract_cache_image(rd, va, prefixes=prefixes)

    loc = _Locator(reader)
    result = CrossImageResult()
    known: Set[str] = {m.class_name for m in messages}
    taken: Set[Tuple[str, str]] = {(m.package or package_for_class(m.class_name), m.name)
                                   for m in messages}
    # image mach_va -> {class_name: message} (None while/if its extraction failed)
    by_image: Dict[int, Optional[Dict[str, ProtoMessage]]] = {mach_va: None}
    failed_in: Dict[int, Dict[str, str]] = {}
    pending: List[Tuple[int, ProtoMessage]] = [(mach_va, m) for m in messages]
    attempted: Set[str] = set()

    def image_messages(va: int) -> Optional[Dict[str, ProtoMessage]]:
        if va not in by_image:
            path = loc.path_of(va)
            try:
                msgs, ctx = extract(reader, va)
            except (NameError, ImportError):
                raise                   # a wiring bug, not something about the image
            except Exception as exc:
                result.image_errors[path] = f"{type(exc).__name__}: {exc}"
                log.warning("cross-image: extracting %s failed: %s", path, exc)
                by_image[va] = None
                return None
            by_image[va] = {m.class_name: m for m in msgs}
            failed_in[va] = dict(get_diagnostics(ctx).failed_classes) if ctx is not None else {}
        return by_image[va]

    def add(owner_va: int, msg: ProtoMessage, via: str) -> None:
        msg.defined_in = loc.path_of(owner_va)
        msg.defined_in_via = via
        known.add(msg.class_name)
        taken.add((msg.package or package_for_class(msg.class_name), msg.name))
        result.added.append(msg)
        pending.append((owner_va, msg))

    while pending:
        ref_va, ref_msg = pending.pop(0)
        for fld in ref_msg.fields:
            cname = referenced_message_class(fld)
            if not cname or cname in known or cname in attempted:
                continue
            attempted.add(cname)
            # A class the referencing (non-primary) image itself defines and extracted.
            own = by_image.get(ref_va)
            if own and cname in own:
                owner_va, via = ref_va, VIA_SAME_IMAGE
            else:
                owner_va, class_va, via = loc.locate(ref_va, cname)
                if owner_va is None:
                    result.unresolved[cname] = via
                    continue
                if owner_va == ref_va or owner_va == mach_va:
                    role = ("the image being extracted" if owner_va == mach_va
                            else "the referencing image")
                    result.unresolved[cname] = (
                        f"defined in {loc.path_of(owner_va)}, {role}, "
                        f"which did not yield it as a message")
                    continue
                # The same structural test the extractor applies (proto.protoclass_set):
                # a message class descends from a PB root.  Checked on the class itself
                # before paying for extracting a whole image that may hold no message.
                chain = superclass_chain_names(reader, class_va)
                if not _PB_ROOT_NAMES.intersection(chain):
                    result.unresolved[cname] = (
                        f"defined in {loc.path_of(owner_va)}, but not a protobuf message "
                        f"(superclass chain: {' → '.join(chain) or 'none'})")
                    continue
            msgs = image_messages(owner_va)
            target = msgs.get(cname) if msgs else None
            if target is None:
                path = loc.path_of(owner_va)
                err = failed_in.get(owner_va, {}).get(cname)
                result.unresolved[cname] = (
                    f"defined in {path}, whose extraction failed" if msgs is None else
                    f"defined in {path}, but its extraction raised: {err}" if err else
                    f"defined in {path}, but not a PBCodable message there")
                continue
            key = (target.package or package_for_class(target.class_name), target.name)
            if key in taken:
                result.unresolved[cname] = (
                    f"defined in {loc.path_of(owner_va)}, but its message name "
                    f"{key[0]}.{key[1]} is already taken by another message")
                continue
            add(owner_va, target, via)
    return result


__all__ = ["CrossImageResult", "resolve_cross_image", "extract_cache_image",
           "VIA_CLASSREF", "VIA_LINKED_DYLIB", "VIA_SAME_IMAGE"]
