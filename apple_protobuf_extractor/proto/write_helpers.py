"""writeTo: write-helper identification and wire-type-family classification.

Carved out of ``proto/extractor.py`` (output-identical move).  Apple's PB runtime
emits a small set of per-binary *write helpers* — the functions a ``writeTo:`` IMP
calls to encode each field.  Which helper a field uses is a structural signal the
ivar ``@encode`` cannot carry:

  * **string vs bytes** — string and message fields use *different* helpers, so a
    ``repeated NSArray`` field that decoded to ``bytes`` can be reclassified to
    ``string`` when its helper matches the binary's string helper
    (:func:`_identify_string_write_helpers` / :func:`_find_string_write_helper`).
  * **wire-type family** — the helper a field calls selects the actual wire form
    (sint32/sint64 zigzag, fixed32/fixed64), recovering distinctions that all
    collapse to the canonical ``int32`` default in ``protocore._type_from_enc``
    (:func:`_classify_write_helper`, TODO #38/#44).

The two ``_ensure_*`` functions lazily build + cache the binary-wide pre-passes on
``ctx`` so a standalone :func:`proto.extractor.extract_proto_message` call (single
class, unit tests) gets the same result as a full :func:`extract_all` run.

Layering: depends on ``macho.*`` and the ``proto`` analyses below it (the writer flow, the
evaluator, :mod:`proto.function_body`), never on ``proto.extractor`` -- no import cycle.
"""
from __future__ import annotations

import logging
from typing import Dict, FrozenSet, List, Optional, Set

from macho.memory    import READ_ERRORS, BinaryContext, _ctx_cache, _ctx_store, PROGRAM_ERRORS
from macho.classlist import ClassList, ObjcIvar

from proto.writeto   import _extract_writeto_field_numbers
from proto.writer_flow import WriterFlow
from proto.dispatch  import _jump_table_arm_addrs, build_function_index, function_entries
from proto.function_body import function_body
from proto.callees   import import_name, real_target
from proto.models    import record_failed_pass
from proto.protocore import (
    _is_proto_flags_ivar, _type_from_enc, _INTERNAL_PB_IVARS,
)

from proto.protoclass_set import _proto_class_set

log = logging.getLogger(__name__)


# ── String write-helper identification ────────────────────────────────────────


def _identify_string_write_helpers(
    ctx: BinaryContext,
    cl: 'ClassList',
) -> Set[int]:
    """The write helpers (their real targets) the image's ``@"NSString"`` /
    ``@"NSMutableString"`` ivars are written with -- the runtime writes a string field with
    another helper than a message field, and every proto class of an image shares them, so one
    string ivar suffices.  A repeated NSArray field whose ``writeTo:`` helper is one of them is
    ``repeated string`` (:func:`proto.repeated._resolve_repeated_field_type`), where no
    metaclass ``+xyzType`` names its element (``GEOPDComponent.versionDomains``)."""
    # The writeTo: bindings need the binary-wide pre-pass on ctx; ensure it exists so a
    # standalone caller (one that builds this set before extract_all has run)
    # gets real helpers instead of an empty set.
    _ensure_writeto_prepass(ctx, cl)

    string_helpers: Set[int] = set()
    proto_classes = _proto_class_set(ctx, cl)

    for cls in cl:
        if cls.is_meta or cls.name not in proto_classes:
            continue

        # Quick check: does this class have any @"NSString" ivar?
        string_enc = ('@"NSString"', '@"NSMutableString"')
        str_ivars = [iv for iv in cls.ivars if iv.type_enc in string_enc and iv.name]
        if not str_ivars:
            continue

        # Run writeTo: helper extraction using all field ivars so the offset
        # matching works (writeTo: uses the same ivar-offset variables).
        all_field_ivars = [iv for iv in cls.ivars if not _is_proto_flags_ivar(iv)
                           and iv.name and iv.name not in _INTERNAL_PB_IVARS]
        helpers = _extract_writeto_field_numbers(ctx, cls, all_field_ivars).helpers

        for iv in str_ivars:
            h = helpers.get(iv.name)
            if h:
                string_helpers.add(real_target(ctx, h))

        if string_helpers:
            # All classes share the same helpers; stop after first hit.
            return string_helpers

    return string_helpers


def _find_string_write_helper(
    helpers: Dict[str, int],
    field_ivars: List[ObjcIvar],
    instance_method_names: Set[str],
) -> Optional[int]:
    """
    Return the write-helper VA for string-typed ivars in *this* class, or None.

    For classes that *do* have a singular ``@"NSString"`` ivar (e.g.
    ``GEOPDPlaceResponse._displayRegion``), the helper can be identified
    locally without needing the binary-wide pre-pass.  Used as a fast path
    inside :func:`proto.extractor.extract_proto_message`.

    Falls back to None when no confirmed string helper is found locally,
    letting the caller fall back to the binary-wide set from
    :func:`_identify_string_write_helpers`.
    """
    for iv in field_ivars:
        type_name, _ = _type_from_enc(iv.type_enc, iv.name, instance_method_names)
        if type_name == "string":
            h = helpers.get(iv.name)
            if h:
                return h
    return None


# The arguments a write helper is run with (:func:`_family_by_evaluation`): a field number
# and a value no helper computes on its own.  The value's low word is negative as an int32,
# so its sign- and zero-extensions to 64 bits differ.
_PROBE_FIELD = 0x1A5A5A5
_PROBE_VALUE = 0x9234567887654321
_MASK32, _MASK64 = (1 << 32) - 1, (1 << 64) - 1


def _zigzag(v: int, bits: int) -> int:
    """The zigzag encoding of the *bits*-bit two's-complement value *v* (sint32 / sint64)."""
    v &= (1 << bits) - 1
    signed = v - (1 << bits) if v >> (bits - 1) else v
    return ((signed << 1) ^ (signed >> (bits - 1))) & ((1 << bits) - 1)


def _family_by_evaluation(ctx: BinaryContext, target: int) -> str:
    """The wire-type family the write helper at *target* encodes, from what it computes when
    run (:meth:`proto.arm64_eval.Flow.propagate` over
    :func:`proto.function_body.function_body`) with :data:`_PROBE_FIELD` as its field number
    and :data:`_PROBE_VALUE` as its value, where the writer ABI puts them:
    ``(writer, value x1, field w2)``, or for a floating-point writer ``(writer, value v0,
    field w1)``.

    It is ``sint64`` / ``sint32`` when it computes the zigzag of the value / of its low word
    (the sint encoding, whatever builds the tag).  Otherwise the tag it builds,
    ``field << 3 | wire type``, gives the wire type: 5 ``fixed32``, 1 ``fixed64``, 2
    (length-delimited) ``plain``, 0 a varint -- ``int32`` / ``uint32`` when the low word is
    sign- / zero-extended to the 64-bit varint value (an int32's negative values take 10
    bytes), else ``plain`` (a 64-bit varint, a bool).  ``"unknown"`` when it computes
    neither.  How the compiler spells any of this (``lsl`` /
    ``bfi`` / ``orr``, in which order, through which registers) does not matter."""
    from proto.arm64_eval import Flow, Sym
    body = function_body(ctx, target, function_entries(ctx))
    if not body:
        return "unknown"
    flow = Flow(ctx, list(body), br_arms=_jump_table_arm_addrs(ctx, list(body), per_br=True))

    def computed(entry):
        regs = flow.propagate(entry, range(len(flow.insns)))
        return {v for r in regs.values() for v in r.values() if not isinstance(v, Sym)}

    seen = computed({'x1': _PROBE_VALUE, 'x2': _PROBE_FIELD})
    low = _PROBE_VALUE & _MASK32
    if _zigzag(_PROBE_VALUE, 64) in seen:
        return "sint64"
    if _zigzag(low, 32) in seen:
        return "sint32"
    wire = {v & 7 for v in seen if v >> 3 == _PROBE_FIELD}
    if not wire:                                    # a floating-point writer's field is w1
        wire = {v & 7 for v in computed({'x1': _PROBE_FIELD}) if v >> 3 == _PROBE_FIELD}
        if not wire:
            return "unknown"
    if 5 in wire:
        return "fixed32"
    if 1 in wire:
        return "fixed64"
    if 2 in wire:
        return "plain"
    if (low | (_MASK64 ^ _MASK32)) in seen:
        return "int32"
    if low in seen:
        return "uint32"
    return "plain"


#: The note on an int field whose writer shows no encoding (family ``"unknown"``).
INT_ENCODING_NOTE = "integer encoding not confirmed (int / sint / fixed not told apart)"

#: ProtocolBuffer.framework's field writers, by the wire-type family each encodes (the int
#: ones; the others leave the type alone).  A standalone binary calls them through import
#: stubs, which name them.
_WRITER_FAMILY = {
    "Int32": "int32", "Uint32": "uint32", "Sint32": "sint32", "Sint64": "sint64",
    "Fixed32": "fixed32", "Sfixed32": "fixed32", "Fixed64": "fixed64", "Sfixed64": "fixed64",
    "Int64": "plain", "Uint64": "plain",
}


def _family_from_import(ctx: BinaryContext, va: int) -> Optional[str]:
    """The family of the ``_PBDataWriterWrite<Type>Field`` writer the import stub at *va*
    calls, by its bound name; None when *va* is not such a stub."""
    name = import_name(ctx, va) or ""
    if name.startswith("_PBDataWriterWrite") and name.endswith("Field"):
        return _WRITER_FAMILY.get(name[len("_PBDataWriterWrite"):-len("Field")], "plain")
    return None


def _classify_write_helper(ctx: BinaryContext, helper_va: Optional[int]) -> str:
    """Classify a ``writeTo:`` field-write helper by the proto *wire-type family* it encodes:
    ``"sint32"``, ``"sint64"``, ``"fixed32"``, ``"fixed64"``, ``"int32"`` / ``"uint32"`` (a plain
    varint of a 32-bit value, by how it is widened), ``"plain"`` (a varint read as such, or a
    non-int writer: no refinement), or ``"unknown"`` (no helper, or one whose encoding neither
    its code nor its import name shows: the field is flagged).  An ivar's ``@encode`` records
    only its width, so int32 / uint32 / sint32 / [s]fixed32 look alike there; the helper selects
    the wire form.

    By evaluation: the stub followed to the real helper (:func:`proto.callees.real_target`) and
    run with probe arguments (:func:`_family_by_evaluation`): the tag it computes gives the wire
    type, the zigzag of the value a sint, the widening of a 32-bit value int32 / uint32.
    fixed32 / fixed64 are shared with float / double, whose ivars never reach this int-only
    caller, so they mean an integer field -- sfixed vs. fixed picked from the ivar sign.  In
    ``--binary`` mode the helper is an import stub into ProtocolBuffer.framework, its code not in
    the binary: the stub's bound name names the writer (:func:`_family_from_import`).  Memoised
    on ``ctx``."""
    if not helper_va:
        return "unknown"
    cache = _ctx_cache(ctx, "_writeto_helper_family", dict)
    if helper_va in cache:
        return cache[helper_va]

    fam = "unknown"
    try:
        target = real_target(ctx, helper_va)
        named = _family_from_import(ctx, target)
        if named is not None:
            cache[helper_va] = named
            return named
        fam = _family_by_evaluation(ctx, target)
    except READ_ERRORS as exc:
        # Unreadable helper: its fields are flagged as an unconfirmed integer encoding.
        log.debug("write-helper classify failed at 0x%x: %s", helper_va or 0, exc)
        fam = "unknown"
    cache[helper_va] = fam
    return fam


def _refine_scalar_by_family(type_name: str, fam: str, where: str = "") -> str:
    """Refine a canonical int type (``int32``/``int64``/``uint32``/``uint64``) by the
    wire-type family its write helper encodes (:func:`_classify_write_helper`): zigzag
    ``sint32``/``sint64``; ``[s]fixed32``/``[s]fixed64``, the SIGN half (fixed vs sfixed)
    coming from the storage type; and ``int32``/``uint32`` for a 32-bit plain varint, which
    the writer decides (it IS the encoding: the int32 writer sign-extends a negative value
    to 10 bytes).  A writer that disagrees with the storage type's sign is logged
    (*where* names the field).  Unchanged for ``plain`` or any non-int type."""
    if type_name in ("int32", "int64", "uint32", "uint64"):
        if fam in ("sint32", "sint64"):
            return fam
        if fam in ("int32", "uint32"):
            if type_name in ("int32", "uint32"):
                if fam != type_name:
                    log.warning("%s: the writeTo: writer encodes %s but the storage type is "
                                "%s; emitting the writer's %s", where or "a field", fam,
                                type_name, fam)
                return fam
            log.warning("%s: a 32-bit %s writer for %s storage; type left as %s",
                        where or "a field", fam, type_name, type_name)
            return type_name
        if fam == "fixed32":
            return "sfixed32" if type_name == "int32" else "fixed32"
        if fam == "fixed64":
            return "sfixed64" if type_name == "int64" else "fixed64"
    return type_name


# ── Lazy binary-wide pre-passes (cached on ctx) ───────────────────────────────


def _ensure_writeto_prepass(ctx: BinaryContext, cl: ClassList) -> None:
    """Lazily build + cache the binary-wide ``writeTo:`` pre-pass on ``ctx``: the image's
    :class:`proto.writer_flow.WriterFlow` (``_writer_flow``, which the bindings
    :func:`_extract_writeto_field_numbers` read) and the image's function index
    (:func:`proto.dispatch.build_function_index`: the method IMPs, which bound the map /
    struct / enum passes' function extents beside ``LC_FUNCTION_STARTS``).

    :func:`proto.extractor.extract_all` builds it once up front, but
    :func:`proto.extractor.extract_proto_message` may also be called standalone
    (single-class extraction, unit tests) without ``extract_all`` — so build it on
    first use here too; without this, a standalone call would silently get NO writeTo
    decoding.  Rebuilt for a different class list."""
    wf = getattr(ctx, "_writer_flow", None)
    if wf is None or wf.cl is not cl:
        _ctx_store(ctx, "_writer_flow", WriterFlow(ctx, cl))
    if getattr(ctx, "_function_entries", None) is None:
        build_function_index(ctx, cl)


def _ensure_string_write_helpers(ctx: BinaryContext, cl: ClassList) -> "FrozenSet[int]":
    """Lazily build + cache the binary-wide string-write-helper VA set on ``ctx``.

    Mirrors :func:`_ensure_writeto_prepass`: ``extract_all`` builds this once and
    passes it explicitly, but a standalone :func:`proto.extractor.extract_proto_message`
    caller that omits the kwarg would otherwise silently lose ``repeated string`` vs
    ``repeated bytes`` typing. Cached so the binary-wide scan runs at most once per
    context. An empty result is a valid build (cached, not retried)."""
    cached = getattr(ctx, "_string_write_helpers", None)
    if cached is not None:
        return cached
    try:
        helpers = frozenset(_identify_string_write_helpers(ctx, cl))
    except PROGRAM_ERRORS:
        raise
    except Exception as exc:
        record_failed_pass(ctx, "string write helper", exc,
                           "repeated string fields are not told from repeated bytes")
        helpers = frozenset()
    _ctx_store(ctx, "_string_write_helpers", helpers)
    return helpers
