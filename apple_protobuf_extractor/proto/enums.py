"""proto/enums — enum-value harvesting + enum-name derivation.

Carved from proto.extractor (#11 split, step 5b, final): enum-value recovery and
enum-name derivation.  The number->name maps are recovered by evaluating the code that
produces the names (:mod:`proto.dictrep_flow`) for both sources: the ``xAsString:`` method
(:func:`_extract_xasstring`) and the converter inlined into ``_dictionaryRepresentation:``
(:func:`_harvest_dictrep`).  Imports macho.* + protocore + dispatch + config (never
proto.extractor) -> cycle-free; extractor re-imports the surface so call sites +
tests are unchanged.

The ``--debug-enums`` diagnostic record builders (xAsString/methname candidate
scanning, Mode A/B/C record assembly) have moved to proto.enums_debug — this
module's ``_collect_enum_definitions`` imports it lazily (function-local, only
when a debug sink is actually supplied) to avoid a cycle, since enums_debug
imports back from here.
"""
from __future__ import annotations
import logging
import re
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple

from macho.memory     import BinaryContext, _ctx_cache, _ctx_store
from macho.strings    import StringTable
from macho.classlist  import ObjcClass
from macho.disasm     import disasm, Insn, _STOP_MNEMONICS
from proto.models     import ProtoEnum, ProtoEnumValue, ProtoField, _enum_prefix, get_diagnostics
from proto.protocore  import _proto_name
from proto.dispatch   import _jump_table_arm_addrs
from proto.dictrep_flow import Flow
from proto.dispatch_eval import _in_image_text
from proto.eval_tokens import SELF, OPAQUE, opaque
from proto.arm64cfg   import _next_imp
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
    return bool(s and len(s) <= 128
                and re.match(r'^[A-Za-z_][A-Za-z0-9_]*$', s))


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


def _disasm_truncated(insns: List[Insn], cap: int) -> bool:
    """Return True if a ``disasm(..., max_insns=cap)`` result was budget-truncated.

    ``disasm`` stops at the first terminal (``ret``/``eret``) or after *cap*
    instructions, whichever comes first.  So a result of length ``cap`` whose
    last instruction is NOT a terminal ran out of budget before the method
    ended — any enum values encoded past that point are missing.  This
    distinguishes a genuine tool-budget truncation (worth flagging) from a
    method that simply ended within the cap, and from a sparse-enum gap (an
    undefined value, which is not a truncation at all)."""
    return (len(insns) >= cap
            and bool(insns)
            and insns[-1].mnemonic not in _STOP_MNEMONICS)


# ══════════════════════════════════════════════════════════════════════════════
# Function bodies of the enum methods (xAsString:, _dictionaryRepresentation:)
# ══════════════════════════════════════════════════════════════════════════════


# [cap:COSMETIC — verified 2026-06-11, TODO #40] Fast-path probe length only; its value
# does NOT determine the harvest result.  _harvest_dictrep first decodes this many
# instructions (stop_at_ret); if the body closed (ret reached) that IS the whole
# serializer.  If not, it recomputes the body by its true FUNCTION EXTENT
# (_function_body_extent) — so 8000 only chooses fast-path-vs-extent, and both yield
# identical enums (proven: harvest(8000) == harvest(full extent) on all 9 overrunning
# GeoServices classes; raising the cap recovers 0 enums — dictrep_probe3.py).
_DICTREP_PROBE_INSNS = 8000
# [cap:COSMETIC] Pure safety ceiling for the extent sweep.  -[cls _dictionaryRepresentation:]
# is a CONTIGUOUS serializer (verified >=99.6% reachable-fill — UNLIKE the OUTLINED writeTo:
# family, whose field-write blocks sit past other function boundaries), so it closes on its
# own `ret` well below this (max observed extent ~24.6k insns).  If a future body fails to
# close under this ceiling the harvest still fails loud (_disasm_truncated ->
# enum_recovery_truncated), preserving the honest signal for a genuine overrun.
_DICTREP_HARD_CAP = 40000

# [cap:INPUT-SANITY — TODO #58] Safety ceiling for the xAsString: jump-table
# function-extent fallback (below).  Only reached when the cheap 1000-insn probe
# didn't close on `ret`; the LogMsg-family methods that trigger it are ~12k insns
# and close well under this (the 2026-06-13 sweep saw every method close ≤30k).
# Like _DICTREP_HARD_CAP it is a fail-loud bound: a body that doesn't close under
# it still trips _disasm_truncated, preserving the honest INCOMPLETE signal.
_SPARSE_HARD_CAP = 40000


def _direct_branch_target(ins: "Insn") -> Optional[int]:
    """PC-relative target of a DIRECT branch (b / b.<cond> / cbz / cbnz / tbz / tbnz),
    or None.  Excludes bl/blr (calls) and br (indirect jump-table dispatch) so a tail call
    or switch does not extend the function extent."""
    m = ins.mnemonic
    if m == 'b' or m.startswith('b.') or m in ('cbz', 'cbnz', 'tbz', 'tbnz'):
        for tok in reversed(ins.op_str.replace(',', ' ').split()):
            tok = tok.strip('#')
            try:
                return int(tok, 16) if tok.lower().startswith('0x') else int(tok)
            except ValueError:
                continue
    return None


def _function_body_extent(
    ctx: BinaryContext, imp: int, hard_cap: int
) -> "List[Insn]":
    """Instructions of the CONTIGUOUS function at *imp*, bounded by its own last `ret`
    (the first terminal that no earlier forward branch jumps past), via a single linear
    sweep + forward-branch high-water-mark.

    Value-independent: the cut-off is the function's structure, not a magic count.
    *hard_cap* is only a safety ceiling — when the function fails to close under it the
    full hard_cap-length sweep is returned (last insn NOT a terminal) so the caller's
    _disasm_truncated check still fires (fail-loud on a genuine overrun).

    SOUND ONLY for contiguous bodies (verified for _dictionaryRepresentation:,
    >=99.6% reachable-fill — matches a full reachability walk on all 9 overrunning
    classes, dictrep_probe5.py).  Do NOT reuse for the OUTLINED writeTo: family, whose
    field-write blocks sit past other function boundaries — a forward branch into an
    outlined block would drag the sweep through foreign code."""
    try:
        insns = disasm(ctx, imp, max_insns=hard_cap, stop_at_ret=False)
    except (NameError, ImportError):
        raise
    except Exception:
        return []
    hi = imp
    span = hard_cap * 4
    for k, ins in enumerate(insns):
        t = _direct_branch_target(ins)
        if t is not None and imp <= t < imp + span and t > hi:
            hi = t
        if ins.mnemonic in _STOP_MNEMONICS and ins.addr >= hi:
            return insns[:k + 1]
    return insns


# [cap:INPUT-SANITY] a runaway backstop for reading a representation wrapper's opening (it
# is cut at its first call or unconditional terminator; the wrappers seen are 1-2
# instructions, a self-contained implementation's first call comes within ~10).
_DICTREP_WRAPPER_INSNS = 16


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
    never followed; :func:`_dictrep_body` bounds it like any other body."""
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
    token), and the Flow it ran in.  ``None`` when the method is absent, cannot be
    evaluated, or makes no call there."""
    m = cls.get_method(selector)
    if m is None or m.imp == 0:
        return None
    try:
        insns = disasm(ctx, m.imp, max_insns=_DICTREP_WRAPPER_INSNS, stop_at_ret=False)
    except (NameError, ImportError):
        raise
    except Exception:
        return None
    end = next((k for k, i in enumerate(insns)
                if i.mnemonic in ('b', 'br', 'braa', 'brab', 'ret', 'retaa', 'retab', 'udf',
                                  'bl', 'blr', 'blraa', 'blrab')), None)
    if end is None:
        return None
    try:
        flow = Flow(ctx, insns[:end + 1])
        region = flow.run_from(0, {'x0': SELF}, objects=OPAQUE)
    except (NameError, ImportError):
        raise
    except Exception:
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
    if not c.tail or c.args.get('x0') != SELF or not _in_image_text(ctx, c.target):
        return None
    x1 = c.args.get('x1')
    if x1 is not None and not opaque(x1):
        return c.target, x1
    return c.target, (_ARG_UNTOUCHED if flow.entry_arg(c.k, 'x1') == 'x1' else None)


def _dictrep_body(ctx: BinaryContext, imp: int) -> Optional[List[Insn]]:
    """The dictRep function at *imp* as the linear range ``[imp, next method IMP)`` -- or
    None when the method-IMP set is not on *ctx* (it is built once by ``extract_all``;
    see proto.write_helpers._ensure_writeto_prepass).

    Bound by structure, not by a count or by a `ret`: the next method IMP is a hard upper
    bound on the function (as for the writeTo: pre-scan).  A dictRep leaves by a tail
    call (``b objc_autoreleaseReturnValue``) or ends in a noreturn call, never a `ret` of
    its own, so the stop-at-ret probe / _function_body_extent ran on into the following
    functions: on the iPhone 8 iOS 16 cache every one of the 1,641 harvested bodies did
    (550,916 foreign instructions in all), and no body reaches code past the next method
    IMP.  Reachability within the range is left to :class:`proto.dictrep_flow.Flow`, which
    walks from the entry and resolves `br` targets by evaluation: pruning the range to a
    static CFG first drops jump-table arms only that evaluation finds (iOS 27
    GEOPDSUserActionMetadataElement lost 8 values that way)."""
    imps = getattr(ctx, "_method_imps", None)
    if not imps:
        return None
    memo = getattr(ctx, "_dictrep_imps_sorted", None)
    if memo is None or memo[0] is not imps:
        memo = (imps, sorted(imps))
        _ctx_store(ctx, "_dictrep_imps_sorted", memo)
    end = _next_imp(memo[1], imp)
    return disasm(ctx, imp, max_insns=max(1, (end - imp) // 4), stop_at_ret=False)


def _harvest_dictrep(
    ctx: BinaryContext, cls: ObjcClass, st: Optional[StringTable],
    wanted: Optional[Set[int]] = None,
) -> Tuple[Dict[int, List[Tuple[int, str]]], Dict[int, str], Dict[int, str]]:
    """``(enums, incomplete, unevaluated)``, each keyed by ivar offset.

    *enums* is ``{ivar_offset: [(value, name), …]}`` for each enum field whose int→name map
    is recovered (empty when the method is absent); *wanted* (ivar offsets) only limits the
    work to those fields, never changes a result.  *incomplete* maps a RECOVERED enum
    to why some of its values may be missing (a value that could not be evaluated, a table
    gate too wide to enumerate).  *unevaluated* maps an enum-like switch that yielded
    nothing to why: that field may be an enum and stays an untyped int."""
    result: Dict[int, List[Tuple[int, str]]] = {}
    imp = _find_dictrep_c_func(ctx, cls)
    if imp is None:
        return result, {}, {}
    try:
        body = _dictrep_body(ctx, imp)
        insns = body if body is not None else disasm(ctx, imp, max_insns=_DICTREP_PROBE_INSNS)
    except (NameError, ImportError):
        raise
    except Exception as exc:
        log.warning("-[%s _dictionaryRepresentation:] could not be disassembled (%s); "
                    "enum recovery from it is skipped", cls.name, exc)
        return result, {}, {}
    if not insns:
        return result, {}, {}

    # Without the method-IMP set (a bare call outside extract_all): if the cheap probe
    # didn't reach a `ret`, widen it to _function_body_extent.  Both run past the
    # function's own end -- it leaves by a tail call, never a `ret` of its own -- into the
    # functions that follow (see _dictrep_body), so this is only the fallback.
    if body is None and _disasm_truncated(insns, _DICTREP_PROBE_INSNS):
        body = _function_body_extent(ctx, imp, _DICTREP_HARD_CAP)
        if body:
            insns = body

    # Fail loud ONLY on a genuine overrun: the function failed to close even under the
    # safety ceiling.  None do today; if one ever does, flag the whole class (caller ->
    # ProtoMessage.enum_recovery_truncated -> emitted comment) and log a warning rather
    # than silently drop tail enums.  Only called when >=1 int field is still untyped
    # (caller guard), so this is always relevant when it fires.
    if _disasm_truncated(insns, _DICTREP_HARD_CAP):
        log.warning(
            "enum recovery for %s may be INCOMPLETE: "
            "-[%s _dictionaryRepresentation:] did not close within the %d-instruction "
            "safety ceiling; switch-table enums past that point are not recovered, so "
            "some int32 fields may actually be enums (see TODO #40).",
            cls.name, cls.name, _DICTREP_HARD_CAP)
        _ctx_cache(ctx, "_dictrep_truncated_classes", set).add(cls.name)

    # The field's int is driven through the function's own code, value by value, to the
    # CFString it hands to the dictionary -- see proto/dictrep_flow.py.  This replaces the
    # earlier look-back-window passes (jump table / pointer table / compare chain).
    flow = Flow(ctx, insns, jump_table_arms=_jump_table_arm_addrs(ctx, insns))
    enums = flow.enum_maps({iv.offset for iv in cls.ivars}, wanted)
    return enums, flow.incomplete, flow.unevaluated


def _enum_name_from_methname(ivar_name: str, st: StringTable) -> Optional[str]:
    """
    Return the enum name (CapitalizedIvarName) if the binary's
    ``__objc_methname`` section contains an ``xAsString:`` or
    ``StringAsX:`` selector matching this ivar.

    This is a fallback for shared-cache-extracted binaries where the
    preoptimised relative method lists store selector references into
    the shared cache's unified string pool (outside the binary's own
    vmaddr range), making per-class method-name resolution impossible.
    The selector strings themselves remain in the binary's own
    ``__objc_methname`` section and are indexed by ``build_string_table``.
    """
    pname = _proto_name(ivar_name)
    if not pname or len(pname) < 2:
        return None
    cap = pname[0].upper() + pname[1:]
    for sel in (f"{pname}AsString:", f"StringAs{cap}:"):
        if st.find(sel):
            return cap
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


# ObjC type encodings that identify a genuine ``xAsString:`` method.
# An xAsString: method for an int32/uint32 enum field takes (self @0, SEL @8,
# enum_value i/I @16) and returns id (@), giving a total frame of 20 bytes.
# Requiring this encoding eliminates short stub methods, getters (@16@0:8),
# void setters (v24@0:8@16), and other false-positive candidates whose IMP
# happens to be adjacent to the real enum method in memory, causing the
# linear-disassembly pattern scan to pick up the pointer-table code that
# belongs to the real method.
#
# Solely consumed by proto.enums_debug now (imported from there) — no
# production code in this module still references it.
_ASSTRING_INT_TYPES: frozenset = frozenset({
    "@20@0:8i16",  # standard: returns id, frame 20, int32 arg
    "@20@0:8I16",  # unsigned int32 variant
    "@24@0:8i16",  # 24-byte frame (some ABI variants)
    "@24@0:8I16",
})


@dataclass
class XasResult:
    """The enum recovered from one ``xAsString:`` method."""
    pairs: List[Tuple[int, str]]
    confirmed: bool            # every value evaluated cleanly and the body closed
    truncated: bool            # some value may be missing (see *reason*)
    reason: Optional[str] = None


# [cap:COSMETIC] cheap first probe of an xAsString: body; a longer body is re-read by its
# function extent (see _function_body_extent), so this chooses only fast-path-vs-extent.
_XAS_PROBE_INSNS = 1000


def _branches_past_end(insns: List[Insn]) -> bool:
    """True if a CONDITIONAL branch in *insns* targets an address beyond the last decoded
    instruction: the body continues past the ``ret`` the decode stopped at (an out-of-line
    default / case block).  Unconditional ``b`` is excluded: a tail call into
    ``objc_retainAutoreleaseReturnValue`` is a ``b`` to another function."""
    end = insns[-1].addr
    return any(i.mnemonic != 'b' and (t := _direct_branch_target(i)) is not None and t > end
               for i in insns)


def _xasstring_flow(ctx: BinaryContext, imp: int) -> Tuple[Optional[Flow], bool]:
    """``(flow, truncated)`` of the ``xAsString:`` body at *imp* (``(None, False)`` when it
    is empty); raises when it cannot be disassembled."""
    insns = disasm(ctx, imp, max_insns=_XAS_PROBE_INSNS)
    if not insns:
        return None, False
    truncated = _disasm_truncated(insns, _XAS_PROBE_INSNS)
    if truncated or _branches_past_end(insns):
        # the probe stopped at the budget, or at a `ret` that a branch jumps over (out-of-line
        # default / case blocks): re-read the method by its true extent (SOUND for xAsString:
        # bodies, which are contiguous)
        body = _function_body_extent(ctx, imp, _SPARSE_HARD_CAP)
        if body:
            insns = body
            truncated = _disasm_truncated(insns, _SPARSE_HARD_CAP)
    return Flow(ctx, insns, jump_table_arms=_jump_table_arm_addrs(ctx, insns)), truncated


def _xasstring_gate_span(ctx: BinaryContext, imp: int) -> int:
    """Number of values the widest ordered gate on the argument of ``-[C xAsString:]`` at
    *imp* (``w2``) admits, along the CFG from the entry (:meth:`Flow.candidates`):
    ``cmp w2, #N ; b.hi`` admits N + 1, ``b.hs`` N, a bias (``sub w8, w2, #k``) shifts the
    range without widening it.  0 when no gate guards the value."""
    if imp == 0:
        return 0
    flow, _ = _xasstring_flow(ctx, imp)
    if flow is None:
        return 0
    scan = flow.candidates(-1, 'x2', (-(1 << 31), 1 << 31))
    return max((hi - lo + 1 for lo, hi in scan.intervals), default=0)


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
    except (NameError, ImportError):
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
        problems.append("the method body exceeded the disassembly budget")
    pairs = sorted(res.pairs.items())
    return XasResult(pairs, bool(pairs) and not problems, bool(problems),
                     "; ".join(problems[:3]) if problems else None)


def _extract_enum_values(
    ctx: BinaryContext,
    imp: int,
    st: Optional[StringTable] = None,
) -> Tuple[List[Tuple[int, str]], bool, bool]:
    """``(pairs, confirmed, truncated)`` of the ``xAsString:`` method at *imp*
    (:func:`_extract_xasstring` without the reason)."""
    r = _extract_xasstring(ctx, imp)
    return r.pairs, r.confirmed, r.truncated


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
    "emitted as int32 (wire-compatible) — this is an unresolved enum, not a plain "
    "integer; do not rely on the int32 type"
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
) -> List[ProtoEnum]:
    """Extract :class:`ProtoEnum` definitions for all ``ENUM:``-tagged fields.

    In order:

    **Phase 1 — shared-cache methname scan** (only when *instance_method_names*
    is empty):  Scan ``__objc_methname`` for ``xAsString:``/``StringAsX:``
    patterns for each ``int32``/``uint32`` field that has no ``ENUM:`` tag yet.
    Matching fields are tagged with ``ENUM:<qualified>``.

    **Phase 1.5 — _dictionaryRepresentation: enums** for int fields with no xAsString:.

    **Phase 2 — enum extraction loop**:  For each ``ENUM:``-tagged field, find
    and extract the ``xAsString:`` method implementation.  On success a
    :class:`ProtoEnum` is appended to the returned list.  On failure (no
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
        from proto.enums_debug import _emit_mode_b_debug, _emit_mode_c_debug

    # ── Phase 1: shared-cache methname-based enum detection ──────────────────
    if not instance_method_names:
        cls_prefix = _class_to_proto_name(cls.name, _pfx)
        for fld in fields:
            if fld.type_name in ("int32", "uint32") and fld.type_class is None:
                base = _enum_name_from_methname(fld.name, st)
                if base:
                    qualified      = _qualify_enum_name(cls_prefix, base)
                    fld.type_name  = qualified
                    fld.type_class = f"ENUM:{qualified}"
                elif _dbg_w is not None:
                    _emit_mode_b_debug(ctx, cls, fld, st, _dbg_w)

    enums: List[ProtoEnum] = []
    seen_enum_names: Set[str] = set()

    # ── Phase 1.5: _dictionaryRepresentation: switch-table enums ──────────────
    # Recover enums for scalar-int fields that have NO xAsString:/StringAsX:
    # companion selector.  Apple stores their int→name map in the class's
    # -[Class _dictionaryRepresentation:] switch table instead (e.g.
    # GEOComponentType / ComponentStatus on GEOPDComponent).  Only run when at
    # least one int field is still untyped, so the (potentially large) dictRep
    # disassembly is skipped for classes with nothing to gain.
    #
    # The field is tagged with the class-qualified enum name (as the
    # ``__objc_methname`` path does) and its recovered pairs are stashed in
    # *dictrep_pairs*; the Phase 2 loop below picks them up and applies the same
    # name-refinement / value-normalisation as the xAsString: path, keeping
    # naming uniform (e.g. the COMPONENT_TYPE_* prefix collapses to ``ComponentType``).
    dictrep_pairs: Dict[str, List[Tuple[int, str]]] = {}
    dictrep_incomplete: Dict[str, str] = {}  # recovered, but some value could not be evaluated
    if any(f.type_name in ("int32", "uint32") and f.type_class is None
           for f in fields):
        ivar_off_by_pname = {
            _proto_name(iv.name): iv.offset
            for iv in cls.ivars if iv.name
        }
        untyped_offsets = {ivar_off_by_pname[f.name] for f in fields
                           if f.type_name in ("int32", "uint32") and f.type_class is None
                           and f.name in ivar_off_by_pname}
        dr_enums, dr_incomplete, dr_unevaluated = _harvest_dictrep(
            ctx, cls, st, wanted=untyped_offsets)
        if dr_enums:
            cls_prefix = _class_to_proto_name(cls.name, _pfx)
            for fld in fields:
                if fld.type_name not in ("int32", "uint32") or fld.type_class is not None:
                    continue
                off = ivar_off_by_pname.get(fld.name)
                if off is None or off not in dr_enums:
                    continue
                pairs = dr_enums[off]
                if not pairs:
                    continue
                qualified = _qualify_enum_name(
                    cls_prefix, fld.name[0].upper() + fld.name[1:])
                fld.type_name  = qualified
                fld.type_class = f"ENUM:{qualified}"
                dictrep_pairs[fld.name] = pairs
                if off in dr_incomplete:
                    dictrep_incomplete[fld.name] = dr_incomplete[off]
        # An enum-like switch that could not be evaluated leaves its field an untyped int:
        # say so on the field and in the run summary instead of staying quiet.
        for fld in fields:
            off = ivar_off_by_pname.get(fld.name)
            if (off in dr_unevaluated and fld.type_name in ("int32", "uint32")
                    and fld.type_class is None and fld.name in ivar_off_by_pname):
                reason = dr_unevaluated[off]
                if not fld.type_inference_note:
                    fld.type_inference_note = (
                        "may be an enum: a switch over this field's value in "
                        "_dictionaryRepresentation: could not be evaluated (" + reason + ")")
                get_diagnostics(ctx).unevaluated_switches.append((cls.name, fld.name, reason))

    for fld in fields:
        if not (fld.type_class and fld.type_class.startswith("ENUM:")):
            continue
        enum_name = fld.type_class[5:]   # strip "ENUM:" prefix
        if enum_name in seen_enum_names:
            continue
        seen_enum_names.add(enum_name)

        # Look for the AsString method on both instance class and metaclass.
        as_string_sel = f"{fld.name}AsString:"
        as_method = cls.get_method(as_string_sel)
        if as_method is None and metaclass is not None:
            as_method = metaclass.get_method(as_string_sel)

        pairs: List[Tuple[int, str]] = []
        confirmed   = False
        truncated   = False   # True when the value-string scan hit its disasm cap
        incomplete_reason: Optional[str] = None
        method_exists: bool = as_method is not None

        if as_method is not None and as_method.imp != 0:
            xr = _extract_xasstring(ctx, as_method.imp)
            pairs, confirmed, truncated = xr.pairs, xr.confirmed, xr.truncated
            incomplete_reason = xr.reason if xr.truncated else None
        elif fld.name in dictrep_pairs:
            # Enum recovered from -[Class _dictionaryRepresentation:] switch table
            # (no xAsString: companion selector exists for this field).
            pairs = dictrep_pairs[fld.name]
            confirmed = False
            method_exists = True
            truncated = fld.name in dictrep_incomplete   # some value could not be evaluated
            incomplete_reason = dictrep_incomplete.get(fld.name)

        if not method_exists:
            # No xAsString: enum method resolved for this field → revert it to
            # the raw scalar type below.  (When selectors are wholly unresolved
            # the run errors/warns up front in extract_all; see
            # :func:`_check_selectors_resolved` — so reaching here with a
            # resolved binary just means this particular field has no enum
            # companion method, which is normal for plain int fields.)
            if _dbg_w is not None:
                _emit_mode_c_debug(ctx, cls, fld, st, enum_name, as_method,
                                   instance_method_names, _dbg_w)
            for f2 in fields:
                if f2.type_class == f"ENUM:{enum_name}":
                    f2.type_class = None
                    f2.type_name  = "int32"
                    # Transparency: this field was flagged as an enum (a value-
                    # string selector exists) but its values could not be
                    # recovered, so the int32 is a degraded fallback, not a true
                    # scalar.  Surface it instead of degrading silently.
                    f2.disambiguation_comment = _ENUM_UNRESOLVED_COMMENT
            seen_enum_names.discard(enum_name)
            continue

        # ── Derive canonical enum name from value string prefix ───────────────
        # NB: the enum TYPE name is not stored in the binary; this is a best-
        # effort reconstruction and a wrong result is harmless (no wire/value/
        # compilation impact).  See _enum_name_from_pairs' docstring and
        # ENUM_TYPE_NAMES.md before worrying about this.
        if pairs:
            derived_name = _enum_name_from_pairs(pairs, enum_name)
            if derived_name != enum_name:
                for f2 in fields:
                    if f2.type_class == f"ENUM:{enum_name}":
                        f2.type_class = f"ENUM:{derived_name}"
                        f2.type_name  = derived_name
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

    return enums
