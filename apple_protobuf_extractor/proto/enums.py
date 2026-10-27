"""proto/enums — enum-value harvesting + enum-name derivation.

The number->name maps are recovered by evaluating the code that
produces the names (:mod:`proto.dictrep_flow`) for both sources: the ``xAsString:`` method
(:func:`_extract_xasstring`) and the converter inlined into ``_dictionaryRepresentation:``
(:func:`_harvest_dictrep`).  Imports macho.* + protocore + dispatch + config (never
proto.extractor) -> cycle-free; extractor re-imports the surface so call sites +
tests are unchanged.

The ``--debug-enums`` diagnostic record builders (xAsString/methname candidate
scanning, Mode A/B/C record assembly) are proto.enums_debug's; this module's
``_collect_enum_definitions`` imports it lazily (function-local, only when a debug sink is
supplied), since enums_debug imports from here.
"""
from __future__ import annotations
import logging
import re
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, NamedTuple, Optional, Sequence, Set, Tuple

from macho.memory     import READ_ERRORS, BinaryContext, record_unread, PROGRAM_ERRORS
from macho.strings    import StringTable
from macho.classlist  import ObjcClass
from proto.models     import (ProtoEnum, ProtoEnumValue, ProtoField, _enum_prefix, get_diagnostics,
                              retag_enums)
from proto.protocore  import _SCALAR_ENC, _proto_name, enum_base_name, enum_selectors
from proto.dispatch   import _jump_table_arm_addrs, function_entries
from proto.dictrep_flow import Flow
from proto.callees import text_holding
from proto.eval_tokens import SELF, OPAQUE, opaque
from proto.function_body import FunctionBody, function_listing
from proto.arm64_operands import CALLS, PATH_ENDS, first_end
from proto.config     import _class_to_proto_name
from proto.defaults    import DEFAULT_PREFIXES

log = logging.getLogger(__name__)


def _is_valid_enum_string(s: str) -> bool:
    """Return True if *s* looks like a valid enum value name (a C identifier).

    This is purely a **sanity check**, not a decision-maker.  It does NOT pick
    between storage formats — :func:`macho.strings.read_cfstring_text` dispatches
    on section membership for that — and it is not load-bearing on the structured read path
    (which already yields real strings).  Its only job is to reject garbage for
    the *probe-and-filter* callers that legitimately can't know in advance whether
    a candidate pointer targets a string at all: the data-flow evaluator's
    argument probe (:mod:`proto.dictrep_flow`).  A False result
    therefore means "this candidate isn't a string", never "decode it a different
    way".
    """
    return bool(s and re.match(r'^[A-Za-z_][A-Za-z0-9_]*$', s))


def _normalize_enum_value_name(enum_name: str, raw: str, camel: Optional[bool] = None) -> str:
    """
    Build a proto enum value name (SCREAMING_SNAKE_CASE) from *raw*.

    Prepends the canonical enum prefix unless *raw* already starts with it.

    **Last-word overlap stripping**: when the enum name is class-qualified
    (e.g. ``PDPlaceResponseStatus`` → prefix ``PD_PLACE_RESPONSE_STATUS``),
    the raw value string often already carries the *last word* of that prefix
    (e.g. ``"STATUS_SUCCESS"``).  Without stripping, the result would be the
    redundant ``PD_PLACE_RESPONSE_STATUS_STATUS_SUCCESS``.  We detect this
    by checking whether *raw* starts with ``<last_word>_`` and, if so, strip
    that overlap before prepending the full prefix.

    Examples::
        ("FeedbackType", "UNKNOWN")                   → "FEEDBACK_TYPE_UNKNOWN"
        ("FeedbackType", "FEEDBACK_TYPE_POSITIVE")    → "FEEDBACK_TYPE_POSITIVE"
        ("FeedbackType", "FeedbackType_Unknown")      → "FEEDBACK_TYPE_UNKNOWN"
        ("PDPlaceResponseStatus", "STATUS_SUCCESS")   → "PD_PLACE_RESPONSE_STATUS_SUCCESS"
        ("ETAResponseStatus", "STATUS_UNKNOWN_FAILURE") → "ETA_RESPONSE_STATUS_UNKNOWN_FAILURE"
        ("WaypointStatus",  "STATUS_INACTIVE")        → "WAYPOINT_STATUS_INACTIVE"
    """
    prefix = _enum_prefix(enum_name)

    # Word boundaries are inferred from case only in a camelCase table.  A table with no
    # lower-case letter is already SCREAMING_SNAKE: splitting it would break "3RD" / "7M" /
    # "1X" / "3D" into "3_RD" / "7_M" / "1_X" / "3_D".  *camel* is decided per table by the
    # caller (:func:`_enum_values_from_pairs`); None: by this string alone.
    s = raw
    if camel if camel is not None else any(ch.islower() for ch in raw):
        s = re.sub(r'([A-Z]+)([A-Z][a-z])', r'\1_\2', s)
        s = re.sub(r'([a-z\d])([A-Z])', r'\1_\2', s)
    s = re.sub(r'[^A-Z0-9a-z]+', '_', s)
    s = re.sub(r'_+', '_', s).strip('_').upper()

    if s == prefix or s.startswith(prefix + '_'):
        return s

    # Strip last-word overlap before prepending the full prefix.
    # Guard: only strip when the last word is ≥ 3 characters so we don't
    # accidentally eat short words like "IS", "TO", "BY".
    sep = prefix.rfind('_')
    if sep >= 0:
        last_word = prefix[sep + 1:]
        if len(last_word) >= 3 and s.startswith(last_word + '_'):
            s = s[len(last_word) + 1:]

    return f"{prefix}_{s}"


# ══════════════════════════════════════════════════════════════════════════════
# Function bodies of the enum methods (xAsString:, _dictionaryRepresentation:)
# ══════════════════════════════════════════════════════════════════════════════


def _find_dictrep_c_func(ctx: BinaryContext, cls: ObjcClass) -> Optional[int]:
    """Return the IMP whose disassembly holds the real ``_dictionaryRepresentation:``
    switch-table body, or ``None``.

    Normally ``-[cls _dictionaryRepresentation:]`` is itself a registered ObjC
    method (found directly).  Some toolchains (a macOS 27 system dyld cache's
    GeoServices) instead leave it out of the method list: the body is a plain internal
    function, reached only by a tail branch from the public, no-arg wrappers, with the
    JSON flag in w1::

        -[cls dictionaryRepresentation]:   mov w1, #0 ; b body
        -[cls jsonRepresentation]:         mov w1, #1 ; b body

    and when the body never reads the flag the compiler drops the argument (a bare
    ``b body``, x1 left as it came in; GEOCoarseLocationRing on macOS 27, fixture f24).

    Decided by data flow (:func:`_wrapper_tail`), not by the wrapper's shape: the body is
    the target of the tail call ``-dictionaryRepresentation`` opens with, handed self, into
    this image's own code, with x1 = 0 or x1 still its entry value (``_cmd``, never written
    on the way: the argument dropped).  Any other x1 -- a nonzero constant, another value
    the wrapper computed -- is not this call.

    A ``dictionaryRepresentation`` that is a genuine, self-contained implementation opens
    with a frame and a call that is not a tail call: it builds the dictionary itself, so
    its own IMP is the body (iOS 16 CoreDuet's ``_DKPRValueType``, whose only dictRep is
    the no-arg one; iOS locationd's ``ALSNr5GCellTower``).  Its internal branches are
    never followed; :func:`_dictrep_body` reads it like any other body."""
    m = cls.get_method('_dictionaryRepresentation:')
    if m is not None and m.imp != 0:
        return m.imp
    tail = _wrapper_tail(ctx, cls, 'dictionaryRepresentation')
    if tail is not None:
        target, flag = tail
        return target if flag in (0, _ARG_UNTOUCHED) else None
    first = _wrapper_first_call(ctx, cls, 'dictionaryRepresentation')
    if first is not None and not first[0].tail:
        return cls.get_method('dictionaryRepresentation').imp
    return None


# :func:`_wrapper_tail`'s x1 when the wrapper never wrote it (it still holds the method's
# ``_cmd``): the callee's argument dropped.
_ARG_UNTOUCHED = 'untouched'


def _wrapper_first_call(ctx: BinaryContext, cls: ObjcClass, selector: str):
    """``(call, flow)``: the first call ``-[cls selector]`` makes, evaluated up to that call
    or its first unconditional terminator, whichever comes first, with x0 = self (an opaque
    token), and the Flow it ran in.  ``None`` when the method is absent, cannot be read
    (recorded: :func:`macho.memory.record_unread`), or makes no call there."""
    m = cls.get_method(selector)
    if m is None or m.imp == 0:
        return None
    try:
        insns = function_listing(ctx, m.imp, function_entries(ctx))
    except READ_ERRORS as exc:
        record_unread(ctx, "method body", f"-[{cls.name} {selector}] {m.imp:#x}", exc)
        return None
    end = first_end(insns, PATH_ENDS | CALLS | {'b'})
    if end is None:
        return None
    try:
        flow = Flow(ctx, insns[:end + 1])
        region = flow.run_from(0, {'x0': SELF}, objects=OPAQUE)
    except READ_ERRORS as exc:
        record_unread(ctx, "method body", f"-[{cls.name} {selector}] {m.imp:#x}", exc)
        return None
    if not region.calls:
        return None
    return region.calls[0], flow


def _wrapper_tail(ctx: BinaryContext, cls: ObjcClass,
                  selector: str) -> Optional[Tuple[int, Optional[int]]]:
    """``(target, x1)`` of the tail call ``-[cls selector]`` opens with -- evaluated up to its
    first unconditional terminator with x0 = self (an opaque token): the first call must be
    a tail call handed self, into this image's ``__text``.  *x1* is its constant value at the
    call, :data:`_ARG_UNTOUCHED` if it still holds its entry value (reaching definitions),
    else ``None``.  ``None`` for any other opening."""
    first = _wrapper_first_call(ctx, cls, selector)
    if first is None:
        return None
    c, flow = first
    if not c.tail or c.args.get('x0') != SELF or text_holding(ctx, c.target) is None:
        return None
    x1 = c.args.get('x1')
    if x1 is not None and not opaque(x1):
        return c.target, x1
    return c.target, (_ARG_UNTOUCHED if flow.entry_arg(c.k, 'x1') == 'x1' else None)


def _dictrep_body(ctx: BinaryContext, imp: int) -> FunctionBody:
    """The dictRep function at *imp* as the linear listing of its extent
    (:func:`proto.function_body.function_listing`: *imp* up to the next function entry).

    A dictRep leaves by a tail call (``b objc_autoreleaseReturnValue``) or ends in a noreturn
    call, never a `ret` of its own, so a read to the first `ret` runs on into the following
    functions: on the iPhone 8 iOS 16 cache every one of the 1,641 harvested bodies did
    (550,916 foreign instructions in all).  Reachability within the extent is left to
    :class:`proto.dictrep_flow.Flow`, which walks from the entry and resolves `br` targets by
    evaluation: pruning the extent to a static CFG first drops jump-table arms only that
    evaluation finds (iOS 27 GEOPDSUserActionMetadataElement lost 8 values that way)."""
    return function_listing(ctx, imp, function_entries(ctx))


class DictrepHarvest(NamedTuple):
    """What a class's ``_dictionaryRepresentation:`` says of its enums (:func:`_harvest_dictrep`)."""
    enums: Dict[int, List[Tuple[int, str]]]
    incomplete: Dict[int, str]
    unevaluated: Dict[int, str]
    truncated: bool = False          # the body was read only in part: enums may be missing


def _harvest_dictrep(
    ctx: BinaryContext, cls: ObjcClass, wanted: Optional[Set[int]] = None,
) -> DictrepHarvest:
    """``(enums, incomplete, unevaluated, truncated)``, the first three keyed by ivar offset.

    *enums* is ``{ivar_offset: [(value, name), …]}`` for each enum field whose int→name map
    is recovered (empty when the method is absent); *wanted* (ivar offsets) only limits the
    work to those fields, never changes a result.  *incomplete* maps a RECOVERED enum
    to why some of its values may be missing (a value that could not be evaluated, a table
    gate too wide to enumerate).  *unevaluated* maps an enum-like switch that yielded
    nothing to why: that field may be an enum and stays an untyped int."""
    result: Dict[int, List[Tuple[int, str]]] = {}
    imp = _find_dictrep_c_func(ctx, cls)
    if imp is None:
        return DictrepHarvest(result, {}, {})
    try:
        insns = _dictrep_body(ctx, imp)
    except READ_ERRORS as exc:
        record_unread(ctx, "method body", f"-[{cls.name} _dictionaryRepresentation:] {imp:#x}",
                      exc)
        return DictrepHarvest(result, {}, {})
    if not insns:
        return DictrepHarvest(result, {}, {})

    # Fail loud on a body read only in part: with no known extent (no function entry above
    # it and no __text) the read stops at a runaway guard.  Flag the whole class (``truncated``
    # -> ProtoMessage.enum_recovery_truncated -> emitted comment) rather than silently drop
    # tail enums.  Only called when >=1 int field is still untyped (caller guard).
    if insns.truncated:
        log.warning(
            "enum recovery for %s may be INCOMPLETE: the extent of "
            "-[%s _dictionaryRepresentation:] is not known and its read stopped early; "
            "switch-table enums past that point are not recovered, so some int32 fields "
            "may actually be enums.", cls.name, cls.name)

    # The field's int is driven through the function's own code, value by value, to the
    # CFString it hands to the dictionary -- see proto/dictrep_flow.py.
    flow = Flow(ctx, insns, jump_table_arms=_jump_table_arm_addrs(ctx, insns))
    got = flow.enum_maps({iv.offset_slot: iv.offset for iv in cls.ivars
                          if iv.offset is not None and iv.offset_slot}, wanted)
    return DictrepHarvest(got.maps, got.incomplete, got.unevaluated, insns.truncated)


def _enum_name_from_methname(ivar_name: str, st: StringTable) -> Optional[str]:
    """
    Return the enum name (CapitalizedIvarName) if the binary's
    ``__objc_methname`` section contains an ``xAsString:`` or
    ``StringAsX:`` selector matching this ivar.

    The fallback for a class whose method names are not taken as known (none is a core
    proto selector: :func:`proto.extractor.extract_proto_message`); the selector strings
    are in the binary's own ``__objc_methname`` section, indexed by ``build_string_table``.
    """
    pname = _proto_name(ivar_name)
    if not pname or len(pname) < 2:
        return None
    if any(st.find(sel) for sel in enum_selectors(pname)):
        return enum_base_name(pname)
    return None


def _enum_name_from_pairs(
    pairs: List[Tuple[int, str]],
    fallback: str,
) -> str:
    """
    Derive a CamelCase enum name from the common SCREAMING_SNAKE prefix of
    extracted value strings.

    Ivar-derived names can differ from the binary's own enum prefix.  For
    example, ``GEOPDMapsResult._resultType`` → ivar-derived name
    ``"ResultType"``, but the actual strings are ``MAPS_RESULT_TYPE_UNKNOWN``,
    ``MAPS_RESULT_TYPE_PLACE``, … → common prefix ``MAPS_RESULT_TYPE`` →
    canonical name ``"MapsResultType"``.

    Returns *fallback* (the ivar-derived name) when:
    * fewer than two pairs are available,
    * the strings share no useful common underscore-delimited prefix, or
    * the common prefix is only a single word (e.g. ``"STATUS"`` → no
      benefit over the ivar-derived ``"Status"``).

    The enum TYPE name is never stored in the binary (Apple's proto enums
    compile to plain C enums with no symbol for the type — see LIMITATIONS.md
    #6, TODO #57), so this is a best-effort reconstruction from the value-string
    prefix, the only surviving signal.  A wrong result is harmless: the type
    name never appears on the wire, value labels stay correct (they're derived
    from the same prefix), and ``emitter._collect_enums`` de-collides by value
    compatibility, not by name, so two enums can never be silently merged.
    Full accuracy analysis and rationale: notes/ENUM_TYPE_NAMES.md.
    """
    if len(pairs) < 2:
        return fallback

    # Only consider values that are SCREAMING_SNAKE (all-caps with underscores).
    names = [raw for _, raw in pairs
             if raw and re.match(r'^[A-Z][A-Z0-9_]*$', raw)]
    if len(names) < 2:
        return fallback

    # Iteratively trim the common prefix at underscore boundaries.
    common = names[0]
    for n in names[1:]:
        while n != common and not n.startswith(common + '_'):
            if '_' not in common:
                return fallback   # no shared prefix
            common = common[:common.rfind('_')]

    if not common:
        return fallback

    # Require ≥ 2 words so a single-word prefix like "STATUS" does not
    # silently override the ivar-derived name.  (They would be equivalent
    # in CamelCase anyway, so there is nothing to gain.)
    parts = [p for p in common.strip('_').split('_') if p]
    if len(parts) < 2:
        return fallback

    return ''.join(p.capitalize() for p in parts)


@dataclass
class XasResult:
    """The enum recovered from one ``xAsString:`` method."""
    pairs: List[Tuple[int, str]]
    confirmed: bool            # every value evaluated cleanly and the body closed
    truncated: bool            # some value may be missing (see *reason*)
    reason: Optional[str] = None


def _xasstring_flow(ctx: BinaryContext, imp: int) -> Tuple[Optional[Flow], bool]:
    """``(flow, truncated)`` of the ``xAsString:`` body at *imp*, the linear listing of its
    extent (:func:`proto.function_body.function_listing`; ``(None, False)`` when it is
    empty); raises when it cannot be disassembled."""
    insns = function_listing(ctx, imp, function_entries(ctx))
    if not insns:
        return None, False
    return Flow(ctx, insns, jump_table_arms=_jump_table_arm_addrs(ctx, insns)), insns.truncated


def _extract_xasstring(ctx: BinaryContext, imp: int) -> XasResult:
    """Recover ``(value, name)`` pairs from ``-[C xAsString:]`` at *imp*.

    The method IS the function from the enum value (``w2``) to its name: the value is driven
    through its code with every constant it is compared or indexed against (plus one outside
    them) and the string reaching the call / return is read -- see
    :class:`proto.dictrep_flow.Flow`.  Whatever the compiler made of the switch (pointer
    table, byte/halfword jump-table segments with biases, compare chains, bitmask-gated
    tables, ``cbz`` for value 0) needs no separate decoder, and a value the evaluation could
    not settle is reported rather than dropped."""
    if imp == 0:
        return XasResult([], False, False)
    try:
        flow, truncated = _xasstring_flow(ctx, imp)
    except PROGRAM_ERRORS:
        raise
    except Exception as exc:
        log.warning("xAsString: at 0x%x could not be disassembled (%s); its enum values "
                    "are not recovered", imp, exc)
        return XasResult([], False, True, f"the method could not be disassembled ({exc})")
    if flow is None:
        return XasResult([], False, False)
    res = flow.analyse_root(-1, 'x2', 4, frozenset(), direct=True)
    problems = list(res.problems)
    if truncated:
        problems.append("the method body was read only in part (no known extent, or a word "
                        "that does not decode)")
    pairs = sorted(res.pairs.items())
    return XasResult(pairs, bool(pairs) and not problems, bool(problems),
                     "; ".join(problems[:3]) if problems else None)


def _qualify_enum_name(cls_proto: str, base_enum: str) -> str:
    """
    Return ``"{cls_proto}{base_enum}"`` with CamelCase word-overlap trimmed.

    When the last CamelCase word(s) of *cls_proto* equal the first word(s) of
    *base_enum*, the overlapping words are merged rather than repeated.

    Examples::

        ("PDPlaceResponse",          "Status")        → "PDPlaceResponseStatus"
        ("Request",                  "Status")        → "RequestStatus"
        ("DirectionsRequestFeedback","FeedbackType")  → "DirectionsRequestFeedbackType"
        ("PDMapsResult",             "MapsResultType")→ "PDMapsResultType"

    The last example is important: ``GEOPDMapsResult`` has a ``_resultType``
    ivar whose value strings (``MAPS_RESULT_TYPE_*``) would normally override
    to ``"MapsResultType"`` via ``_enum_name_from_pairs``.  Without overlap
    trimming the intermediate qualified name would be
    ``"PDMapsResultMapsResultType"`` — ugly even though it only exists
    transiently.  With trimming it is ``"PDMapsResultType"`` — cleaner even
    if the override fires and replaces it with ``"MapsResultType"``.
    """
    # Split both into CamelCase words: [A-Z][a-z0-9]* (single uppercase followed
    # by lowercase chars) or a lone uppercase letter for abbreviations like "PD".
    _WORD_RE = re.compile(r'[A-Z][a-z0-9]*|[A-Z]')
    cls_words  = _WORD_RE.findall(cls_proto)
    enum_words = _WORD_RE.findall(base_enum)

    # Find the largest k such that the last k words of cls_proto equal the
    # first k words of base_enum.
    overlap = 0
    for k in range(1, min(len(cls_words), len(enum_words)) + 1):
        if cls_words[-k:] == enum_words[:k]:
            overlap = k

    if overlap:
        # Keep all but the last `overlap` words of cls_proto, then append base_enum.
        prefix = "".join(cls_words[:-overlap])
        return f"{prefix}{base_enum}"
    return f"{cls_proto}{base_enum}"


# Inline-comment text attached to a field that carried an enum value-string
# selector (``xAsString:`` / ``StringAsX:``) but whose enum *values* could not be
# recovered, so it is emitted as a bare ``int32``.  The ``int32`` is wire-honest
# (proto enums are varint-encoded identically), but the field is really an
# UNRESOLVED ENUM, not a plain integer — flagged so the reader does not trust the
# scalar type.  This is a degraded-input fallback (it does not fire on a fully
# resolved binary); reviving the comment makes that degradation visible instead of
# silent.  Drives the per-field ``//`` note (models/emitter) and the ``n_ambiguous``
# count → mode-aware file-header severity (see emitter.py).
_ENUM_UNRESOLVED_COMMENT = (
    "enum value-string selector present but its values could not be recovered; "
    "emitted as its integer type (wire-compatible) — this is an unresolved enum, not a "
    "plain integer"
)


def _enum_values_from_pairs(enum_name: str, pairs: Sequence[Tuple[int, str]]
                            ) -> List[ProtoEnumValue]:
    """The :class:`ProtoEnumValue` list for recovered ``(number, raw name)`` *pairs*: names
    normalised to ``<ENUM_PREFIX>_<NAME>``.  When the binary gives two values the SAME name
    (``ARTWORK_USE_UNKNOWN`` for 0, 2 and 8) the later ones get ``_<number>`` appended and a
    comment saying so -- a name that is not the binary's must never look like it is."""
    values: List[ProtoEnumValue] = []
    seen: Set[str] = set()
    # The naming convention belongs to the table, not to one string: in a camelCase table
    # (``_2DWeak``, ``_3D``, ``_3DStrong``) an all-caps member is split like its siblings.
    camel = any(ch.islower() for _, raw_name in pairs for ch in raw_name)
    for val, raw_name in pairs:
        name = _normalize_enum_value_name(enum_name, raw_name, camel)
        comment = None
        if name in seen:
            name = f"{name}_{val}"
            comment = f"the binary names this value identically to an earlier one; suffixed _{val}"
        seen.add(name)
        values.append(ProtoEnumValue(name=name, number=val, comment=comment))
    return values


class EnumDefinitions(NamedTuple):
    """A class's enums (:func:`_collect_enum_definitions`)."""
    enums: List[ProtoEnum]
    dictrep_truncated: bool          # its _dictionaryRepresentation: was read only in part


def _collect_enum_definitions(
    ctx: BinaryContext,
    cls: ObjcClass,
    fields: List[ProtoField],
    st: StringTable,
    instance_method_names: Set[str],
    metaclass: Optional[ObjcClass],
    *,
    prefixes: Optional[Tuple[str, ...]] = None,
    enum_debug_writer: Optional[Callable[[Dict[str, Any]], None]] = None,
) -> "EnumDefinitions":
    """Extract :class:`ProtoEnum` definitions for all ``ENUM:``-tagged fields, and whether the
    class's ``_dictionaryRepresentation:`` was read only in part (some int fields may then be
    enums not recovered).

    In order:

    **Phase 1 — shared-cache methname scan** (only when *instance_method_names*
    is empty, :func:`_tag_methname_enums`):  Scan ``__objc_methname`` for
    ``xAsString:``/``StringAsX:`` patterns for each ``int32``/``uint32`` field that has no
    ``ENUM:`` tag yet.  Matching fields are tagged with ``ENUM:<qualified>``.

    **Phase 1.5 — _dictionaryRepresentation: enums** for int fields with no xAsString:
    (:func:`_tag_dictrep_enums`).

    **Phase 2 — enum extraction loop**:  For each ``ENUM:``-tagged field, find
    and extract the ``xAsString:`` method implementation (:func:`_recover_enum_values`).
    On success a :class:`ProtoEnum` is among the returned enums.  On failure (no
    resolvable ``xAsString:`` method for the field) the ``ENUM:`` tag is reverted
    and the field is left as its raw scalar type (``int32``/``uint32``).

    Mutates *fields* in place (adding / removing ``ENUM:`` tags).  The caller
    must :meth:`list.sort` *fields* before calling this function.
    """
    _pfx   = prefixes if prefixes is not None else DEFAULT_PREFIXES
    _dbg_w = enum_debug_writer
    if _dbg_w is not None:
        # Deferred import: proto.enums_debug imports back from this module at
        # its own module scope, so importing it at proto.enums' module load
        # time would cycle. Safe here because by the time this FUNCTION runs,
        # proto.enums has already finished initializing.
        from proto.enums_debug import _emit_mode_c_debug

    if not instance_method_names:
        _tag_methname_enums(ctx, cls, fields, st, _pfx, _dbg_w)
    dictrep_pairs, dictrep_incomplete, dictrep_truncated = _tag_dictrep_enums(
        ctx, cls, fields, _pfx)

    enums: List[ProtoEnum] = []
    seen_enum_names: Set[str] = set()
    for fld in fields:
        if not (fld.type_class and fld.type_class.startswith("ENUM:")):
            continue
        enum_name = fld.type_class[5:]   # strip "ENUM:" prefix
        if enum_name in seen_enum_names:
            continue
        seen_enum_names.add(enum_name)

        as_method, recovered = _recover_enum_values(
            ctx, cls, metaclass, fld, dictrep_pairs, dictrep_incomplete)
        if recovered is None:
            # No xAsString: enum method resolved for this field → revert it to
            # the raw scalar type.  (When selectors are wholly unresolved
            # the run errors/warns up front in extract_all; see
            # :func:`_check_selectors_resolved` — so reaching here with a
            # resolved binary just means this particular field has no enum
            # companion method, which is normal for plain int fields.)
            if _dbg_w is not None:
                _emit_mode_c_debug(ctx, cls, fld, st, enum_name, as_method,
                                   instance_method_names, _dbg_w)
            _revert_enum(fields, enum_name, cls)
            seen_enum_names.discard(enum_name)
            continue
        pairs, confirmed, truncated, incomplete_reason = recovered

        # ── Derive canonical enum name from value string prefix ───────────────
        # NB: the enum TYPE name is not stored in the binary; this is a best-
        # effort reconstruction and a wrong result is harmless (no wire/value/
        # compilation impact).  See _enum_name_from_pairs' docstring and
        # ENUM_TYPE_NAMES.md before worrying about this.
        if pairs:
            derived_name = _enum_name_from_pairs(pairs, enum_name)
            if derived_name != enum_name:
                retag_enums(fields, {enum_name: derived_name})
                seen_enum_names.discard(enum_name)
                seen_enum_names.add(derived_name)
                enum_name = derived_name

        enum_values = _enum_values_from_pairs(enum_name, pairs) if pairs else []

        enums.append(ProtoEnum(
            name=enum_name,
            values=enum_values,
            values_confirmed=confirmed,
            values_truncated=truncated,
            incomplete_reason=incomplete_reason,
        ))

    return EnumDefinitions(enums, dictrep_truncated)


def _is_untyped_int(fld: ProtoField) -> bool:
    """A scalar int field no enum is attached to (yet)."""
    return fld.type_name in ("int32", "uint32") and fld.type_class is None


def _tag_enum(fld: ProtoField, qualified: str) -> None:
    fld.type_name  = qualified
    fld.type_class = f"ENUM:{qualified}"


def _revert_enum(fields: List[ProtoField], enum_name: str, cls: ObjcClass) -> None:
    """Every field of enum *enum_name* is its ivar's integer type again (``int32``, or
    ``uint32`` for an unsigned ivar), flagged: a value-string selector exists but its values
    could not be recovered, so the integer is a degraded fallback, not a true scalar
    (transparency: surface it instead of degrading silently)."""
    encs = {_proto_name(iv.name): iv.type_enc for iv in cls.ivars}
    for f in fields:
        if f.type_class == f"ENUM:{enum_name}":
            f.type_class = None
            f.type_name  = "uint32" if _SCALAR_ENC.get(encs.get(f.name) or "") == "uint32" \
                else "int32"
            f.disambiguation_comment = _ENUM_UNRESOLVED_COMMENT


def _tag_methname_enums(ctx: BinaryContext, cls: ObjcClass, fields: List[ProtoField],
                        st: StringTable, prefixes: Tuple[str, ...], dbg_w) -> None:
    """Phase 1, shared-cache methname-based enum detection: an untyped int field whose
    ``xAsString:`` / ``StringAsX:`` selector ``__objc_methname`` lists is tagged ``ENUM:``."""
    if dbg_w is not None:
        from proto.enums_debug import _emit_mode_b_debug   # (see _collect_enum_definitions)
    cls_prefix = _class_to_proto_name(cls.name, prefixes)
    for fld in fields:
        if _is_untyped_int(fld):
            base = _enum_name_from_methname(fld.name, st)
            if base:
                _tag_enum(fld, _qualify_enum_name(cls_prefix, base))
            elif dbg_w is not None:
                _emit_mode_b_debug(ctx, cls, fld, st, dbg_w)


def _tag_dictrep_enums(ctx: BinaryContext, cls: ObjcClass, fields: List[ProtoField],
                       prefixes: Tuple[str, ...]
                       ) -> Tuple[Dict[str, List[Tuple[int, str]]], Dict[str, str], bool]:
    """Phase 1.5, ``_dictionaryRepresentation:`` switch-table enums: ``(pairs, incomplete)``
    by field name, and whether the body was read only in part.

    Recover enums for scalar-int fields that have NO xAsString:/StringAsX: companion
    selector.  Apple stores their int→name map in the class's
    -[Class _dictionaryRepresentation:] switch table instead (e.g. GEOComponentType /
    ComponentStatus on GEOPDComponent).  Only run when at least one int field is still
    untyped, so the (potentially large) dictRep disassembly is skipped for classes with
    nothing to gain.

    The field is tagged with the class-qualified enum name (as the ``__objc_methname`` path
    does) and its recovered pairs returned; the Phase 2 loop picks them up and applies the
    same name-refinement / value-normalisation as the xAsString: path, keeping naming
    uniform (e.g. the COMPONENT_TYPE_* prefix collapses to ``ComponentType``).  *incomplete*:
    recovered, but some value could not be evaluated."""
    dictrep_pairs: Dict[str, List[Tuple[int, str]]] = {}
    dictrep_incomplete: Dict[str, str] = {}
    if not any(_is_untyped_int(f) for f in fields):
        return dictrep_pairs, dictrep_incomplete, False
    ivar_off_by_pname = {_proto_name(iv.name): iv.offset for iv in cls.ivars
                         if iv.name and iv.offset is not None}
    untyped_offsets = {ivar_off_by_pname[f.name] for f in fields
                       if _is_untyped_int(f) and f.name in ivar_off_by_pname}
    dr_enums, dr_incomplete, dr_unevaluated, truncated = _harvest_dictrep(
        ctx, cls, wanted=untyped_offsets)
    if dr_enums:
        cls_prefix = _class_to_proto_name(cls.name, prefixes)
        for fld in fields:
            if not _is_untyped_int(fld):
                continue
            off = ivar_off_by_pname.get(fld.name)
            if off is None or off not in dr_enums:
                continue
            pairs = dr_enums[off]
            if not pairs:
                continue
            _tag_enum(fld, _qualify_enum_name(cls_prefix, enum_base_name(fld.name)))
            dictrep_pairs[fld.name] = pairs
            if off in dr_incomplete:
                dictrep_incomplete[fld.name] = dr_incomplete[off]
    # An enum-like switch that could not be evaluated leaves its field an untyped int:
    # say so on the field and in the run summary instead of staying quiet.
    for fld in fields:
        off = ivar_off_by_pname.get(fld.name)
        if off in dr_unevaluated and _is_untyped_int(fld) and fld.name in ivar_off_by_pname:
            reason = dr_unevaluated[off]
            if not fld.type_inference_note:
                fld.type_inference_note = (
                    "may be an enum: a switch over this field's value in "
                    "_dictionaryRepresentation: could not be evaluated (" + reason + ")")
            get_diagnostics(ctx).unevaluated_switches.append((cls.name, fld.name, reason))
    return dictrep_pairs, dictrep_incomplete, truncated


def _recover_enum_values(ctx: BinaryContext, cls: ObjcClass, metaclass: Optional[ObjcClass],
                         fld: ProtoField, dictrep_pairs: Dict[str, List[Tuple[int, str]]],
                         dictrep_incomplete: Dict[str, str]):
    """``(xAsString: method, (pairs, confirmed, truncated, incomplete reason))`` of the enum
    field *fld*: from its ``xAsString:`` (on the class or the metaclass), else the pairs
    ``_dictionaryRepresentation:`` gave (:func:`_tag_dictrep_enums`); the second item is None
    when neither source exists."""
    as_string_sel = enum_selectors(fld.name)[0]
    as_method = cls.get_method(as_string_sel)
    if as_method is None and metaclass is not None:
        as_method = metaclass.get_method(as_string_sel)
    if as_method is not None and as_method.imp != 0:
        xr = _extract_xasstring(ctx, as_method.imp)
        return as_method, (xr.pairs, xr.confirmed, xr.truncated,
                           xr.reason if xr.truncated else None)
    if fld.name in dictrep_pairs:
        # (no xAsString: companion selector exists for this field)
        return as_method, (dictrep_pairs[fld.name], False, fld.name in dictrep_incomplete,
                           dictrep_incomplete.get(fld.name))
    if as_method is not None:                          # declared, no implementation
        return as_method, ([], False, False, None)
    return as_method, None
