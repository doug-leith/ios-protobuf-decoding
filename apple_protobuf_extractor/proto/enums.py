"""proto/enums — enum-value harvesting + enum-name derivation.

Carved from proto.extractor (#11 split, step 5b, final): enum-value recovery and
enum-name derivation.  The number->name maps are recovered by evaluating the code that
produces the names (:mod:`proto.dictrep_flow`) for both sources: the ``xAsString:`` method
(:func:`_extract_xasstring`) and the converter inlined into ``_dictionaryRepresentation:``
(:func:`_harvest_dictrep`).  Imports macho.* + arm64decode + protocore + dispatch + config (never
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

from macho.memory     import BinaryContext, _ctx_cache
from macho.strings    import StringTable
from macho.classlist  import ObjcClass
from macho.disasm     import disasm, Insn, _parse_imm
from proto.models     import ProtoEnum, ProtoEnumValue, ProtoField, _enum_prefix, get_diagnostics
from proto.protocore  import _proto_name
from proto.dispatch   import _jump_table_arm_addrs
from proto.dictrep_flow import Flow
from proto.config     import _class_to_proto_name
from proto.defaults    import DEFAULT_PREFIXES

log = logging.getLogger(__name__)


def _is_valid_enum_string(s: str) -> bool:
    """Return True if *s* looks like a valid enum value name (a C identifier).

    This is purely a **sanity check**, not a decision-maker.  It does NOT pick
    between storage formats — :func:`_read_enum_string` dispatches on section
    membership for that — and it is not load-bearing on the structured read path
    (which already yields real strings).  Its only job is to reject garbage for
    the *probe-and-filter* callers that legitimately can't know in advance whether
    a candidate pointer targets a string at all: the data-flow evaluator's
    argument probe (:mod:`proto.dictrep_flow`).  A False result
    therefore means "this candidate isn't a string", never "decode it a different
    way".
    """
    return bool(s and len(s) <= 128
                and re.match(r'^[A-Za-z_][A-Za-z0-9_]*$', s))


def _normalize_enum_value_name(enum_name: str, raw: str) -> str:
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

    s = re.sub(r'([A-Z]+)([A-Z][a-z])', r'\1_\2', raw)
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


def _read_enum_string(ctx: BinaryContext, ptr: int) -> Optional[str]:
    """
    Read the string value from an enum pointer-table entry.

    Two storage formats are used in Apple's ObjC proto runtime, distinguished
    **structurally by which section *ptr* lands in** rather than by trial-and-error:

    1. **CFStringRef pointer** — *ptr* points to a ``__cfstring`` constant-string
       struct (``isa, flags, cstring_ptr, length``, 8 bytes each); the
       ``cstring_ptr`` field is decoded through :meth:`BinaryContext.read_ptr`.
       Shared-cache-extracted dylibs (e.g. GeoServices) place these in
       ``__DATA_CONST/__cfstring``; standalone binaries (e.g. locationd) use
       ``__DATA/__cfstring``.
    2. **Direct C-string pointer** — *ptr* points straight at the UTF-8 bytes in
       ``__TEXT/__cstring`` or ``__objc_methname`` (the else case).

    Dispatching on section membership avoids misreading a CFString struct as a
    direct C-string (that read would land on the struct's ``isa`` field and
    return ``''``); ``_is_valid_enum_string`` is only a final sanity check, not
    the format selector.  Returns None when *ptr* resolves to no valid enum string.
    """
    # CFStringRef struct?  Decide by section membership before reading.
    for seg in ("__DATA_CONST", "__DATA", "__AUTH_CONST"):
        if ctx.has_section(seg, "__cfstring"):
            sec = ctx.section(seg, "__cfstring")
            if sec.vmaddr <= ptr < sec.vmaddr + sec.vmsize:
                try:
                    real_ptr = ctx.read_ptr(ptr + 16)   # cstring_ptr field
                    s = ctx.read_cstring(real_ptr, max_len=128)
                except (ValueError, UnicodeDecodeError, KeyError):
                    return None
                return s if _is_valid_enum_string(s) else None

    # Otherwise: a direct C-string pointer.
    try:
        s = ctx.read_cstring(ptr, max_len=128)
    except (ValueError, UnicodeDecodeError):
        return None
    return s if _is_valid_enum_string(s) else None


# Mnemonics that legitimately end a method body (mirrors macho.disasm._STOP_MNEMONICS,
# at which `disasm` stops early).  A bounded disassembly that returns its full
# instruction cap WITHOUT ending on one of these was cut off mid-method.
_TERMINAL_MNEMONICS = frozenset(('ret', 'retaa', 'retab', 'eret'))


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
            and insns[-1].mnemonic not in _TERMINAL_MNEMONICS)


# ══════════════════════════════════════════════════════════════════════════════
# Sparse-enum harvesters — three independent passes over the same disassembly,
# each adding (value, name) pairs via the shared ``add`` callback.  Carved out of
# _extract_jumptable_enum_values (output-identical) so each LLVM lowering of a
# sparse xAsString: method is a self-contained, separately-testable unit.
# ══════════════════════════════════════════════════════════════════════════════


# [cap:COSMETIC — verified 2026-06-11, TODO #40] Fast-path probe length only; its value
# does NOT determine the harvest result.  _harvest_dictrep_enums first decodes this many
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
    except Exception:
        return []
    hi = imp
    span = hard_cap * 4
    for k, ins in enumerate(insns):
        t = _direct_branch_target(ins)
        if t is not None and imp <= t < imp + span and t > hi:
            hi = t
        if ins.mnemonic in _TERMINAL_MNEMONICS and ins.addr >= hi:
            return insns[:k + 1]
    return insns


def _read_cfstring_text(ctx: BinaryContext, va: int) -> Optional[str]:
    """Raw text of the string constant at *va* (up to 128 characters, the same bound as
    :func:`_read_enum_string` / :func:`_is_valid_enum_string`): a CFString (32-byte struct: isa, flags,
    cstring pointer at +16, length at +24) or, in a binary with no ``__cfstring`` section,
    a direct C string (the same two storage formats :func:`_read_enum_string` reads).
    Unlike that function it does NOT require an identifier-shaped string, so it can read
    format strings such as ``"(unknown: %i)"``.  None if *va* holds neither."""
    has_cfstrings = False
    for seg in ("__DATA_CONST", "__DATA", "__AUTH_CONST"):
        if ctx.has_section(seg, "__cfstring"):
            has_cfstrings = True
            sec = ctx.section(seg, "__cfstring")
            if sec.vmaddr <= va < sec.vmaddr + sec.vmsize:
                try:
                    return ctx.read_cstring(ctx.read_ptr(va + 16), max_len=128)
                except (ValueError, UnicodeDecodeError, KeyError):
                    return None
    if has_cfstrings:
        return None                  # a binary with CFStrings: a pointer elsewhere is not one
    try:
        return ctx.read_cstring(va, max_len=128)
    except (ValueError, UnicodeDecodeError, KeyError):
        return None


def _find_dictrep_c_func(ctx: BinaryContext, cls: ObjcClass) -> Optional[int]:
    """Return the IMP whose disassembly holds the real ``_dictionaryRepresentation:``
    switch-table body, or ``None``.

    Normally ``-[cls _dictionaryRepresentation:]`` is itself a registered ObjC
    method (found directly).  Some toolchains (observed on a macOS system dyld
    cache's GeoServices) instead compile it as a plain internal function with
    no class_ro_t entry of its own — reached only via a tail branch from the
    *public*, no-arg ``-[cls dictionaryRepresentation]`` wrapper, e.g.::

        -[cls dictionaryRepresentation]:
            mov w1, #0
            b   _real_dictionaryRepresentation_body   ; not a separate method

    Mirrors :func:`proto.dispatch._find_readfrom_c_func`'s tail-call-following
    for ``readFrom:``/its C core — but unlike ``readFrom:`` (always a thin
    wrapper on every corpus this tool has seen), ``dictionaryRepresentation``
    is sometimes a genuine, self-contained implementation (confirmed: iOS
    locationd's ``ALSNr5GCellTower``), so the tail-call shape must be
    positively confirmed, not assumed — an unconditional ``b`` preceded only
    by argument-setup ``mov``s.  Anything else first (a real prologue:
    ``pacibsp``/``stp``/``sub sp``/…) means this IS the real implementation,
    just not registered as ``_dictionaryRepresentation:`` for some other
    reason, and following an unrelated internal branch inside it would
    disassemble garbage."""
    m = cls.get_method('_dictionaryRepresentation:')
    if m is not None and m.imp != 0:
        return m.imp
    wrapper = cls.get_method('dictionaryRepresentation')
    if wrapper is None or wrapper.imp == 0:
        return None
    try:
        insns = disasm(ctx, wrapper.imp, max_insns=4, stop_at_ret=False)
    except Exception:
        return None
    for ins in insns:
        if ins.mnemonic == 'b':
            return _parse_imm(ins.op_str)
        if ins.mnemonic not in ('mov', 'movz', 'movk', 'movn'):
            return None
    return None


def _harvest_dictrep_enums(
    ctx: BinaryContext, cls: ObjcClass, st: Optional[StringTable],
    wanted: Optional[Set[int]] = None,
) -> Dict[int, List[Tuple[int, str]]]:
    """Extract the enums inlined into ``-[cls _dictionaryRepresentation:]``.

    Returns ``{ivar_offset: [(value, name), …]}`` for each enum field whose
    int→name map is recovered.  Empty when the method is absent or has no
    recoverable switches.  *wanted* (ivar offsets) only limits the work to those
    fields; it never changes a result.  (:func:`_harvest_dictrep` also reports what
    could not be settled.)"""
    return _harvest_dictrep(ctx, cls, st, wanted)[0]


def _harvest_dictrep(
    ctx: BinaryContext, cls: ObjcClass, st: Optional[StringTable],
    wanted: Optional[Set[int]] = None,
) -> Tuple[Dict[int, List[Tuple[int, str]]], Dict[int, str], Dict[int, str]]:
    """``(enums, incomplete, unevaluated)``, each keyed by ivar offset.

    *enums* is :func:`_harvest_dictrep_enums`'s result.  *incomplete* maps a RECOVERED enum
    to why some of its values may be missing (a value that could not be evaluated, a table
    gate too wide to enumerate).  *unevaluated* maps an enum-like switch that yielded
    nothing to why: that field may be an enum and stays an untyped int."""
    result: Dict[int, List[Tuple[int, str]]] = {}
    imp = _find_dictrep_c_func(ctx, cls)
    if imp is None:
        return result, {}, {}
    try:
        insns = disasm(ctx, imp, max_insns=_DICTREP_PROBE_INSNS)
    except Exception as exc:
        log.warning("-[%s _dictionaryRepresentation:] could not be disassembled (%s); "
                    "enum recovery from it is skipped", cls.name, exc)
        return result, {}, {}
    if not insns:
        return result, {}, {}

    # If the cheap probe didn't reach the method's end, recompute the body by its TRUE
    # function extent.  -[cls _dictionaryRepresentation:] is a CONTIGUOUS serializer
    # (verified, UNLIKE outlined writeTo:), so its own last `ret` is a value-independent
    # bound — no magic instruction count.  Proven output-neutral: the extent body yields
    # the same enums as the 8000 probe on every overrunning class (raising the cap
    # recovers nothing, dictrep_probe3.py); it simply stops flagging those classes as
    # truncated.
    if _disasm_truncated(insns, _DICTREP_PROBE_INSNS):
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
    flow = Flow(ctx, insns, _jump_table_arm_addrs(ctx, insns))
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
        insns = disasm(ctx, imp, max_insns=_XAS_PROBE_INSNS)
    except (NameError, ImportError):
        raise
    except Exception as exc:
        log.warning("xAsString: at 0x%x could not be disassembled (%s); its enum values "
                    "are not recovered", imp, exc)
        return XasResult([], False, True, f"the method could not be disassembled ({exc})")
    if not insns:
        return XasResult([], False, False)
    truncated = _disasm_truncated(insns, _XAS_PROBE_INSNS)
    if truncated or _branches_past_end(insns):
        # the probe stopped at the budget, or at a `ret` that a branch jumps over (out-of-line
        # default / case blocks): re-read the method by its true extent (SOUND for xAsString:
        # bodies, which are contiguous)
        body = _function_body_extent(ctx, imp, _SPARSE_HARD_CAP)
        if body:
            insns = body
            truncated = _disasm_truncated(insns, _SPARSE_HARD_CAP)
    flow = Flow(ctx, insns, _jump_table_arm_addrs(ctx, insns))
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
    for val, raw_name in pairs:
        name = _normalize_enum_value_name(enum_name, raw_name)
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

    Two sub-phases, executed in order:

    **Phase 1 — shared-cache methname scan** (only when *instance_method_names*
    is empty):  Scan ``__objc_methname`` for ``xAsString:``/``StringAsX:``
    patterns for each ``int32``/``uint32`` field that has no ``ENUM:`` tag yet.
    Matching fields are tagged with ``ENUM:<qualified>``.

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

    # ── Phase 2: enum extraction loop ────────────────────────────────────────
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
