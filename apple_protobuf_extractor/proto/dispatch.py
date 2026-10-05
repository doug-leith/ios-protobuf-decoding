"""proto/dispatch — readFrom: dispatch-table / jump-table / compare-chain mechanism.

Carved from ``proto.extractor`` (#11 monolith split, step 3): locating the C-level
ReadFrom core, decoding its pointer/byte jump table and compare-chain blocks, and
reading the per-field dispatch arms. The repeated-type and enum concerns build ON
this. Imports only macho.* + arm64decode + protocore (never proto.extractor), so it
stays cycle-free; extractor re-imports the surface so call sites + tests are unchanged.
"""
from __future__ import annotations
import struct
import logging
import re
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

from macho.memory    import BinaryContext, _ctx_cache
from macho.classlist import ClassList, ObjcClass
from macho.objc_abi  import CLASS_T_DATA, CLASS_RO_NAME, FAST_DATA_MASK
from macho.disasm   import (disasm, Insn, find_adrp_add_target, _parse_imm,
                             _norm_reg, iter_bl_targets, iter_branch_targets)
from macho.arm64decode import (
    _decode_adr, _decode_b_bl_target, _decode_bcond,
    _decode_cmp_imm, _decode_ldr_reg_off, _decode_lsr_imm, _decode_sub_imm,
    _is_br_insn, _is_bl_word, _is_func_prologue_word, _is_ret_word,
    _COND_EQ, _COND_NE, _COND_HI, _COND_HS, range_from_unsigned_gate)
from proto.arm64cfg import ivar_slot_loads
from proto.protoclass_heuristic import _is_proto_class

log = logging.getLogger(__name__)

# [cap:COSMETIC — verified 2026-06-09] The readFrom: wrapper's tail b/bl sits in the
# first ~2 instructions, so this cap is a non-binding upper bound.  Raising ×8
# (12→96) gave 0 descriptor diffs across all 3 artifacts.  Value is cosmetic.
_READFROM_MAX_INSNS = 12


def _find_readfrom_c_func(
    ctx: BinaryContext, cls: ObjcClass
) -> Optional[int]:
    """
    Locate the C ReadFrom helper called by the ObjC -[Cls readFrom:] method.

    The ObjC method is always a one-or-two-instruction wrapper:
        mov x1, x2
        b   _ClsReadFrom        ; or: bl _ClsReadFrom

    Returns the vmaddr of the C ReadFrom function, or None.
    """
    method = cls.get_method("readFrom:")
    if method is None or method.imp == 0:
        return None

    try:
        insns = disasm(ctx, method.imp, max_insns=_READFROM_MAX_INSNS)
    except Exception:
        return None

    # iter_branch_targets captures both 'b' (tail call) and 'bl' forms.
    # The old iter_bl_targets missed tail-call wrappers that use 'b'.
    targets = list(iter_branch_targets(insns))
    if not targets:
        return None
    return targets[0]


# _COND_EQ/NE/HI/HS are imported from macho.arm64decode (canonical set).


def _read_raw_word(ctx: BinaryContext, va: int) -> Optional[int]:
    """Read a 4-byte little-endian word at va, returning None on error."""
    try:
        raw = ctx.read_bytes(va, 4)
        return struct.unpack_from("<I", raw)[0]
    except (ValueError, struct.error):
        return None


def _find_field_count(ctx: BinaryContext, func_va: int) -> int:
    """
    Find the proto field count for a C ReadFrom function by scanning its raw
    instruction stream for the `cmp wN, #N ; b.hi/b.hs` dispatch gate.

    Returns 0 if the count cannot be determined.
    """
    MAX_SCAN = 256
    va = func_va
    for _ in range(MAX_SCAN):
        word = _read_raw_word(ctx, va)
        if word is None:
            break
        result = _decode_cmp_imm(word)
        if result is not None:
            _, imm = result
            next_word = _read_raw_word(ctx, va + 4)
            if next_word is not None:
                cond = _decode_bcond(next_word)
                if cond in (_COND_HS, _COND_HI):   # same gate convention as
                    return range_from_unsigned_gate(cond, imm)  # _find_dispatch_cluster
        va += 4
    return 0


# `_try_pointer_table` (the C-ReadFrom pointer-table dispatch reader) was removed
# 2026-06-15: it returned nothing on every supported artifact (1201 calls, 0
# non-empty), so the writeTo CFG walk is the sole field-number source.  Its only
# consumer was `extractor._confirm_field_numbers`.


# Bounded-scan caps.  The sizing rationale (defensive margin over the largest
# observed real PB reader) is unchanged; what each one's *value* does to the
# descriptor was audited 2026-06-09 (SCAN_CAP_CONSTANTS_ANALYSIS.md).  Observed
# across GeoServices (1309 readers): ReadSpecified ≤ 1223 insns, dispatch `br`
# ≤ 251 insns from the entry.
#
# [cap:COSMETIC — verified 2026-06-11] _READSPEC_MAX_INSNS bounds the disasm used to
#   compute `func_end` (the arm-range validator `arm_base <= arm < func_end`) in
#   _decode_*_jumptable / _func_end.  PERTURBED 2026-06-11 across all 3 artifacts
#   (GeoServices/locationd/CoreLocationProtobuf): raising 4096->32768 = 0 descriptor
#   diffs (nothing past the cap to recover), and lowering 4096->1300 = 0 diffs (every
#   ReadSpecified terminates at `ret` before the cap; observed max 1223).  So the value
#   is NON-OPERATIVE at 4096 (3.3x margin over observed).  Its only failure direction is
#   conservative: a too-small cap shrinks func_end and makes the resolver REJECT arms
#   (missed resolution -> other tiers), never a wrong bind.  Keep >= ~1300; do NOT drop
#   below the observed-max margin.
_READSPEC_MAX_INSNS = 4096   # full arm region (func_end); ~3x largest observed (1223)


#
# [cap:COSMETIC — verified 2026-06-09] _ARM_MAX_INSNS / _CLUSTER_MAX_SCAN: the scan
#   finds its feature (an arm's tail branch; the dispatch cluster in the preamble)
#   in the first few instructions, so the cap is a non-binding upper bound.  Proof:
#   raising each ×8 (64→512, 512→4096) gave 0 descriptor diffs across all 3
#   artifacts.  The exact magnitude is cosmetic — nothing to worry about here.
_ARM_MAX_INSNS      = 64     # one dispatch arm before its tail branch


_CLUSTER_MAX_SCAN   = 512    # dispatch cluster sits in the preamble; ~2x observed


def _readspecified_and_count(
    ctx: BinaryContext, readfrom_va: int
) -> Tuple[Optional[int], int]:
    """
    From the C ReadFrom entry (tail target of ``-[Cls readFrom:]``) locate the
    field-dispatch core that owns the ``cmp wN,#count; b.hi`` gate and return
    ``(read_specified_va, field_count)``.

    Two shapes:

      * ``readfrom_va`` already *is* the dispatch core (its body has the gate) —
        :func:`_find_field_count` returns > 0 directly.
      * ``readfrom_va`` is a thin ``ReadAllFrom`` wrapper that BL-calls the
        dispatch core (the "ReadAllFrom hop") — probe each BL target until one
        has a field-count gate.

    Returns ``(None, 0)`` when no dispatch core can be found.
    """
    fc = _find_field_count(ctx, readfrom_va)
    if fc > 0:
        return readfrom_va, fc
    try:
        for candidate_va in iter_bl_targets(disasm(ctx, readfrom_va, max_insns=20)):
            cfc = _find_field_count(ctx, candidate_va)
            if cfc > 0:
                return candidate_va, cfc
    except (NameError, ImportError):
        raise   # wiring/refactor bug — surface, don't mask as "hop failed"
    except Exception as exc:
        log.debug("ReadAllFrom hop failed at 0x%x: %s", readfrom_va, exc)
    return None, 0


# How far into a ReadAllFrom wrapper to scan for the call to its dispatch core.
# The hop can sit well past the wrapper's early-return fast path (e.g.
# GEOPDDepartureSequence's `bl <core>` is ~76 instructions in), so this is much
# larger than the 20-insn field-count hop above.
# [cap:COSMETIC — verified 2026-06-09] The `bl <core>` is found at its real offset
# (≤~76 insns observed) well within the cap, so the exact value is a non-binding
# backstop.  Raising ×8 (256→2048) gave 0 descriptor diffs across all 3 artifacts.
_WRAPPER_CORE_SCAN_MAX = 256


def _arm_calls_own_method(
    ctx: BinaryContext, arm_va: int, own_imps: "FrozenSet[int]"
) -> bool:
    """True if the jump-table arm at *arm_va* ``bl``s into one of *own_imps* — the
    method IMPs of the class under analysis.  Used to confirm a candidate core
    belongs to *this* class (its arms call its own add/set accessors), not to a
    nested message whose reader the wrapper merely calls."""
    try:
        arm_insns = disasm(ctx, arm_va, max_insns=_ARM_MAX_INSNS, stop_at_ret=False)
    except Exception:
        return False
    for insn in arm_insns:
        if insn.mnemonic in ('b', 'br', 'ret', 'retaa', 'retab'):
            break
        if insn.mnemonic == 'bl':
            t = _parse_imm(insn.op_str)
            if t is not None and t in own_imps:
                return True
    return False


def _func_calls_own_method(
    ctx: BinaryContext, func_va: int, own_imps: "FrozenSet[int]",
    max_words: int = 600,
) -> bool:
    """True if the function at *func_va* ``bl``s into one of *own_imps* anywhere in
    its body.  Whole-function analogue of :func:`_arm_calls_own_method`, used to
    confirm that a candidate **compare-chain** dispatch core (which has no jump-table
    arms to check) belongs to THIS class — its field handlers invoke the class's own
    add/set accessors — and is not a nested message's core that the wrapper merely
    calls.  Bounded to the function via the same next-prologue-after-ret stop as the
    wrapper-body scan (a compare-chain core has interleaved rets, so we can't stop at
    the first one)."""
    if not own_imps:
        return False
    saw_ret = False
    for i in range(max_words):
        word = _read_raw_word(ctx, func_va + i * 4)
        if word is None:
            break
        if i > 0 and saw_ret and _is_func_prologue_word(word):
            break
        if _is_ret_word(word):
            saw_ret = True
            continue
        t = _decode_b_bl_target(word, func_va + i * 4)
        if t is not None and t in own_imps:
            return True
    return False


def _section_name(ctx: BinaryContext, va: int) -> Optional[str]:
    """Name of the section containing *va*, or ``None`` if unmapped."""
    for seg in ctx.segments:
        if seg.vmaddr <= va < seg.vmaddr + seg.vmsize:
            for sec in seg.sections:
                if sec.vmaddr <= va < sec.vmaddr + sec.vmsize:
                    return sec.name
            return None
    return None


def _call_site_selects_data_table(ctx: BinaryContext, call_va: int) -> bool:
    """True when the ``bl`` at *call_va* sets up one of its argument registers
    via ``csel Xd, Xn, Xm, cond`` where BOTH ``Xn`` and ``Xm`` are themselves
    populated by their own ``adrp+add`` into an address outside ``__text``
    (i.e. a literal data/const table, not code).

    This is the structural signature of a newer Apple-internal toolchain's
    outlined per-class dispatch "engine" (see the difference-table jump-table
    idiom documented on :func:`_jump_table_arm_addrs`, part of the same
    architecture): ``-[cls readFrom:]``'s C core calls the engine with one of
    two candidate per-class dispatch tables selected by this exact ``csel``,
    e.g. ``adrp x8,#p; add x8,x8,#o1; adrp x9,#p; add x9,x9,#o2;
    csel x2,x9,x8,cond``.

    Deliberately narrower than "any call site with a literal/constant
    argument" — checked directly on GEOPDActionLink's readFrom core: 3 of its
    13 ``bl``s pass a literal address (a ``__cfstring`` error message, an
    error-format string) directly via ``adrp+add``, none of which are the
    engine.  An ordinary call never needs to CHOOSE between two literal
    addresses at its own call site; only this specific dual-table-select shape
    does.  Verified at corpus scale (500 GeoServices classes): never matches
    more than one candidate per class, and never fires on the documented
    nested-reader counter-example (``TRANSITPbLocationFingerprintsV1`` calling
    ``TRANSITPbMacModePair``'s reader) in the locationd fixture."""
    try:
        insns = disasm(ctx, max(0, call_va - 40), max_insns=12, stop_at_ret=False)
    except Exception:
        return False
    insns = [i for i in insns if i.addr <= call_va]
    if not insns or insns[-1].addr != call_va:
        return False
    for w in reversed(insns[:-1]):
        if w.mnemonic != 'csel':
            continue
        o = [t.strip() for t in w.op_str.split(',')]
        if len(o) != 4 or o[0] not in ('x0', 'x1', 'x2', 'x3'):
            continue
        ta = find_adrp_add_target(insns, o[1])
        tb = find_adrp_add_target(insns, o[2])
        if ta is None or tb is None:
            return False
        return (_section_name(ctx, ta) != '__text'
                and _section_name(ctx, tb) != '__text')
    return False


def _call_site_passes_const_table(ctx: BinaryContext, call_va: int) -> bool:
    """True when the ``bl`` at *call_va* passes one literal address in ``__TEXT,__const``
    as an argument (``adrp xN,#p ; add xN,xN,#o`` with N in 0..3 and no ``csel``).

    The single-table counterpart of :func:`_call_site_selects_data_table`: a class whose
    readers differ in nothing but the data table has no second table to choose between,
    so its outlined dispatch "engine" is called with just the one, e.g. ``GEOLPRWorld``
    (``adrp x2,#p ; add x2,x2,#o ; mov x0,x19 ; mov x1,x20 ; bl engine``).  By itself
    this is weaker evidence than the dual-table ``csel`` — an ordinary call can pass a
    constant — so :func:`_find_dispatch_core_via_wrapper` accepts it only together with
    an engine that really reads that table (:func:`_core_reads_table_arg`), independently
    dispatches, and loads THIS class's own ivar slots.  (The f27 fixture's ``TestGrPlainCall``
    is the negative: its engine receives a constant and only forwards it.)  The
    other literal arguments in these readers (error-message cfstrings and C strings) live
    in other sections, so the ``__const`` test separates them."""
    try:
        insns = disasm(ctx, max(0, call_va - 40), max_insns=12, stop_at_ret=False)
    except Exception:
        return False
    insns = [i for i in insns if i.addr <= call_va]
    if not insns or insns[-1].addr != call_va:
        return False
    return any(
        (t := find_adrp_add_target(insns[:-1], reg)) is not None
        and _section_name(ctx, t) == '__const'
        for reg in ('x0', 'x1', 'x2', 'x3'))


def _core_reads_table_arg(ctx: BinaryContext, core_va: int) -> bool:
    """True when the function at *core_va* loads from its THIRD argument (``x2``) — i.e.
    it uses the data table the call site passed it, rather than merely forwarding it.

    The dispatch "engine" indexes its table (``mov x21,x2 ; … ; ldr w12,[x21,x8,lsl #2]``);
    a function that is handed some constant and passes it on is not that engine.  This is the
    corroboration :func:`_call_site_passes_const_table` needs in place of the second table of
    the ``csel`` form.  Follows ``mov xN,x2`` copies; stops following a register once it is
    overwritten."""
    alias = {'x2'}
    for ins in _core_insns(ctx, core_va):
        ops = [o.strip() for o in ins.op_str.split(',')]
        if ins.mnemonic.startswith('ldr') or ins.mnemonic.startswith('ldp'):
            m = re.search(r'\[\s*(x\d+)', ins.op_str)
            if m and m.group(1) in alias:
                return True
        dst = ops[0] if ops else ''
        if ins.mnemonic == 'mov' and len(ops) == 2 and ops[1] in alias:
            alias.add(dst)
        elif dst in alias and not ins.mnemonic.startswith(('st', 'cmp', 'cmn', 'tst', 'b', 'cb', 'tb')):
            alias.discard(dst)                       # overwritten
    return False


_TERMINATORS = frozenset(('ret', 'retaa', 'retab', 'b', 'br', 'braa', 'braaz',
                          'brab', 'brabz'))
_COND_BRANCHES = frozenset(('cbz', 'cbnz', 'tbz', 'tbnz'))


def _core_insns(ctx: BinaryContext, func_va: int) -> List[Insn]:
    """The instructions of the function starting at *func_va*, bounded TIGHTLY.

    Scan linearly and end at the first ``ret``/unconditional-branch terminator
    that lies at or beyond every forward CONDITIONAL branch target seen so far —
    the standard function-extent rule.  Out-of-line blocks that some earlier
    conditional branch jumps to (a compiler often lays gated blocks after the
    epilogue) are therefore kept, while a final tail call (``b _objc_release``)
    ends the function instead of dragging in whatever follows it.

    Unconditional ``b`` targets are deliberately NOT added to the frontier: they
    are either merge points already covered by a conditional target, or tail
    calls into ANOTHER function.  The cost of that choice is only an under-run
    (a block reached solely by an unconditional ``b`` is left out) — the safe
    direction for a caller that wants evidence to be OURS.

    This differs from :func:`_func_end`, whose CFG counts an in-window tail-call
    ``b`` as an intra-function edge: a plain-arm64 function ending in
    ``b <stub>`` is thereby credited with the stub island and every function in
    between — harmless for the arm-range validation that uses it, but fatal for
    a claim of the form "this function loads OUR ivars"."""
    try:
        insns = disasm(ctx, func_va, max_insns=_READSPEC_MAX_INSNS, stop_at_ret=False)
    except Exception:
        return []
    frontier = func_va
    for k, ins in enumerate(insns):
        m = ins.mnemonic
        if m in _TERMINATORS:
            if ins.addr >= frontier:
                return insns[:k + 1]
            continue
        if m.startswith('b.') or m in _COND_BRANCHES:
            t = _parse_imm(ins.op_str.split(',')[-1])
            if t is not None and t > frontier:
                frontier = t
    return insns


def _core_loads_own_ivar_slot(
    ctx: BinaryContext, core_va: int, own_ivar_slots: "FrozenSet[int]",
) -> bool:
    """True when the function at *core_va* loads at least one of THIS class's own
    ivar-offset variables (``adrp; ldrsw Xm,[Xn,#off]`` landing on an
    ``ivar_t.offset`` slot in *own_ivar_slots*) — i.e. it stores into this
    class's own instance, which a nested/sibling message's reader cannot.

    Identity is by slot ADDRESS, not by the offset value it holds (small offsets
    like 8/16/24 collide across classes), over the function's tight extent
    (:func:`_core_insns`).  Fails closed: an empty *own_ivar_slots* (the class's
    slots unknown) is never a confirmation.

    This is the ownership corroboration for a compare-chain core that has no
    ``cmp;b.hi`` range guard (``_find_field_count == 0``): the newest arm64e
    toolchain's per-class engines dispatch with a compare TREE on the field
    number and have none, so the guard can no longer stand as the second signal
    beside the call-site data-table ``csel``."""
    if not own_ivar_slots:
        return False
    return any(slot in own_ivar_slots
               for _i, slot in ivar_slot_loads(_core_insns(ctx, core_va)))


def _find_dispatch_core_via_wrapper(
    ctx: BinaryContext, anchor_va: int, own_imps: "FrozenSet[int]" = frozenset(),
    core_index: Dict[int, str] = None,
    own_ivar_slots: "FrozenSet[int]" = frozenset(),
) -> Tuple[Optional[int], Optional[Dict[int, int]]]:
    """Locate the field-dispatch core that a thin **ReadAllFrom wrapper** only
    *calls* (rather than containing itself), returning ``(core_va, arms)``.

    Some classes (e.g. GEOPDDepartureSequence) have a two-level readFrom: shape —
    ``-[readFrom:]`` tail-calls a ReadAllFrom wrapper that, past its early-return
    fast path, ``bl``s a *separate* ReadSpecified core holding the real jump
    table.  :func:`_readspecified_and_count` misses this (its field-count raw scan
    runs past the short wrapper and its BL hop only looks 20 insns deep), so the
    direct jump-table decode yields nothing and these fields fall to the
    name-suffix heuristic.

    Selection is **principled, not by name**: scan the wrapper body (bounded to
    the wrapper function) for ``bl``/``b`` callees and accept one whose *own* body
    decodes into a validated field-dispatch jump table
    (:func:`_find_dispatch_cluster` → :func:`_decode_readfrom_jumptable`).  A
    wrapper can also call a *nested* message's reader (which has its own valid
    jump table), so the candidate is additionally confirmed to belong to THIS
    class: at least one of its arms must ``bl`` into *own_imps* (the class's own
    method IMPs).  This rejects nested-message cores — e.g. it stops
    ``TRANSITPbLocationFingerprintsV1`` from binding to the ``TRANSITPbMacModePair``
    reader it calls.

    For a compare-chain candidate, ownership additionally accepts
    :func:`_call_site_selects_data_table` (the call site itself, not the
    candidate's own body) as an alternative to :func:`_func_calls_own_method`:
    a newer toolchain's outlined dispatch "engine" never calls a named
    accessor at all, so the named-accessor check can never confirm it even
    when correct.  This alternative additionally REQUIRES
    :func:`_core_resolves_compare_chain` to independently agree the candidate
    genuinely dispatches — the structural call-site shape alone confirms the
    call is to an "engine" of THIS toolchain's kind, but only the dominance
    walk confirms it dispatches correctly, so both must hold before accepting.
    *core_index* is required for that check; without it this alternative is
    skipped (falls back to :func:`_func_calls_own_method` only).  ``(None,
    None)`` when no own-core is found.
    """
    # Scan raw words (not a capstone disasm) for the wrapper's b/bl callees: this
    # runs for every class that lacked a direct jump table, so it must stay cheap.
    # Bound the scan to the wrapper function — because the core call sits past an
    # early `ret`, we can't stop at the first `ret`; instead stop once we cross
    # into the NEXT function (a prologue word appearing after a `ret`).  Without
    # this the window runs into neighbouring functions and would pick up an
    # unrelated class's dispatch core.
    # Memoise cluster lookups across classes for this extraction: a wrapper's
    # b/bl callees are mostly shared runtime helpers (no cluster), each otherwise
    # re-scanned (512 words) for every class that calls it.  Caching the negative
    # results collapses that to one scan per unique callee.
    cluster_cache = _ctx_cache(ctx, "_wrapper_cluster_cache", dict)

    seen: Set[int] = set()
    saw_ret = False
    cc_core: Optional[int] = None     # compare-chain core fallback (no jump table)
    for i in range(_WRAPPER_CORE_SCAN_MAX):
        va = anchor_va + i * 4
        word = _read_raw_word(ctx, va)
        if word is None:
            break
        if i > 0 and saw_ret and _is_func_prologue_word(word):
            break
        if _is_ret_word(word):
            saw_ret = True
            continue
        target = _decode_b_bl_target(word, va)
        if target is None or target == anchor_va or target in seen:
            continue
        seen.add(target)
        if target in cluster_cache:
            cluster, arms, fc = cluster_cache[target]
        else:
            cluster = _find_dispatch_cluster(ctx, target)
            arms = None
            if cluster is not None:
                _ab, _ct, _tr, _es, _bi, _brva = cluster
                if _ct > 0 and _bi >= 1:
                    arms = _decode_readfrom_jumptable(ctx, target, _ct,
                                                      cluster=cluster)
            # field-count gate (present in BOTH jump-table and compare-chain cores)
            fc = _find_field_count(ctx, target)
            cluster_cache[target] = (cluster, arms, fc)
        if cluster is not None and arms:
            _arm_base, count, _treg, _esz, bias, _br_va = cluster
            if count > 0 and bias >= 1 and (
                    (not own_imps or any(
                        _arm_calls_own_method(ctx, arm_va, own_imps)
                        for arm_va in arms.values()))
                    or (core_index and _call_site_selects_data_table(ctx, va)
                        and _any_arm_loads_known_classref(ctx, arms, core_index))):
                # Confirm the core belongs to THIS class: at least one arm calls one
                # of the class's own method IMPs (rejects a nested message's reader
                # the wrapper happens to call).  Jump-table core — preferred.
                #
                # A call-site-selects-data-table alternative symmetric to the
                # compare-chain tier below was first tried here alone (no
                # classref confirmation) and measured directly on GeoServices:
                # 101 WRONG bindings vs only 62 correct.  Root cause (confirmed
                # by direct disassembly of GEOPDBusinessHours,
                # GEOPDActionData, GEOPBTransitIncident, GEOIndexQueryNode):
                # many of this toolchain's jump-table arms funnel (directly, or
                # via a shared fallthrough tail) into one GENERIC,
                # dynamically-typed "read an embedded message" runtime helper
                # rather than a specific class's own ReadAllFrom core, so an
                # `arm bl target -> core_index` lookup resolves to whatever
                # class happens to collide with that shared helper's address —
                # a different failure mode than the compare-chain tier's engine
                # (which genuinely bl's the correct nested class's own core
                # directly).  `_any_arm_loads_known_classref` sidesteps this: it
                # reads the class the arm itself loads a classref for and would
                # allocate (`[ElementClass alloc]`, the other half of the
                # element-creation idiom :func:`_resolve_repeated_via_dispatch`
                # already documents) rather than the shared helper's address, so
                # it carries no collision risk from that helper being reused
                # across unrelated classes.
                return target, arms
        elif cc_core is None and (
                (fc > 0 and _func_calls_own_method(ctx, target, own_imps))
                or (core_index
                    and _call_site_selects_data_table(ctx, va)
                    and _core_resolves_compare_chain(ctx, target, core_index)
                    and (fc > 0
                         or _core_loads_own_ivar_slot(ctx, target, own_ivar_slots)))
                or (core_index
                    and _call_site_passes_const_table(ctx, va)
                    and _core_reads_table_arg(ctx, target)
                    and _core_resolves_compare_chain(ctx, target, core_index)
                    and _core_loads_own_ivar_slot(ctx, target, own_ivar_slots))):
            # A compare-chain core has no jump-table cluster.  Remember the first
            # that belongs to THIS class; the caller runs the compare-chain tier on
            # it.  Two ways to be confirmed as ours:
            #   * classic toolchain: it has the field-count gate (`cmp;b.hi`) AND
            #     its body calls an own add/set accessor;
            #   * newer toolchain: the call site is this toolchain's
            #     data-table-selecting "engine" call (csel of two data tables) AND
            #     the core independently dispatches for real, AND — since the
            #     newest arm64e engines dispatch with a compare TREE and have no
            #     range guard — either it has the guard or it demonstrably loads
            #     this class's own ivar-offset variables.  Measured on the
            #     iPhone17,3 and macOS 27 GeoServices (golden as ground truth): 128
            #     and 130 fields recovered, 0 regressions, and every newly accepted
            #     engine (534 / 528) loads own ivar slots and none loads another
            #     class's.
            cc_core = target
    return (cc_core, None) if cc_core is not None else (None, None)


def _find_dispatch_cluster(
    ctx: BinaryContext, func_va: int
) -> Optional[Tuple[int, int, int, int, int, int]]:
    """
    Scan the raw instruction stream of *func_va* for the jump-table dispatch
    cluster and return
    ``(ARM_BASE, field_count, table_reg, entry_size, bias, br_va)``,
    or ``None`` if no such cluster is present (e.g. pointer-table dispatch).

    ``br_va`` (the cluster's own ``br`` instruction address) anchors a caller's
    search for THIS cluster's table-base ``adrp+add`` to a local window: a
    function commonly holds several independent jump tables reusing the same
    scratch register for their own ``adrp+add`` (observed directly: one
    ReadSpecified engine had three ``br`` clusters, each with its own
    ``adrp x17 / add x17`` five instructions before its own ``br``, spaced ~75-
    95 instructions apart) — a whole-function scan for "the adrp+add on
    register N" would always resolve to the FIRST cluster's table regardless of
    which cluster is actually being decoded.

    The cluster is::

        sub  Wi, Wt, #bias                 ; idx = (tag>>3) - bias  => arm i = field bias+i
        cmp  Wi, #<count-1> ; b.hi <oob>   ; field-count gate (count = imm + 1)
        adr  Rbase, #ARM_BASE
        ldrh Roff, [Rtab, Xi, lsl #1]      ; Rtab = table reg, ldrh => 2-byte entries
        add  Rbase, Rbase, Roff, lsl #2
        br   Rbase

    Recovered from raw words (the mini-decoder leaves ``adr``/register-offset
    ``ldrh`` undecoded), anchored on the ``br``: its preceding window holds the
    ``adr`` (→ ``ARM_BASE``), the ``cmp; b.hi/b.hs`` gate (→ ``field_count`` +
    gate register), the table load (→ ``table_reg``/``entry_size`` via
    :func:`_decode_ldr_reg_off`), and the feeding ``sub Wi,Wt,#bias`` (→
    ``bias``).  ``table_reg``/``entry_size`` fall back to ``-1``/``0`` when the
    load can't be pinned (caller falls back to a width search).

    The **bias** matters because a jump table only covers a contiguous field
    range starting at ``bias`` (e.g. ALSLocationResponse's high cell-tower-
    subtype table starts at field 0x15, bias 21); arm *i* serves field
    ``bias + i``.  ``bias`` is ``0`` when no feeding ``sub`` is found, and the
    caller then bails rather than risk a wrong arm→field-number join.

    ``field_count`` is derived from the gate adjacent to this dispatch, not from
    :func:`_find_field_count` (whose first ``cmp; b.hi`` match is usually the
    varint-length guard, not the field gate); it is ``0`` if the gate is absent.
    """
    recent_adr:  List[Tuple[int, int]] = []        # (word_index, adr_target)
    recent_gate: List[Tuple[int, int, int]] = []   # (word_index, field_count, gate_rn)
    recent_load: List[Tuple[int, int, int, int]] = []  # (word_index, table_reg, entry_size, idx_reg)
    recent_sub:  List[Tuple[int, int, int]] = []   # (word_index, sub_rd, bias)
    # A function can hold several br-based tables: real per-field dispatch(es)
    # PLUS an unrelated internal bookkeeping table using the exact same
    # instruction shape (observed directly: a newer toolchain's has-bits
    # bookkeeping loop matches _decode_clamped_gate's pattern too, just with
    # no feeding `sub` -- bias 0).  Every caller of this function already
    # requires bias >= 1 to trust the arm->field join, so a bias-0 match is
    # never useful on its own; remember it as a fallback but keep scanning for
    # a later, bias >= 1 table rather than returning on the first (possibly
    # unrelated) match.
    fallback: Optional[Tuple[int, int, int, int, int, int]] = None
    saw_ret = False
    for i in range(_CLUSTER_MAX_SCAN):
        va = func_va + i * 4
        word = _read_raw_word(ctx, va)
        if word is None:
            break
        if i > 0 and saw_ret and _is_func_prologue_word(word):
            break
        if _is_ret_word(word):
            saw_ret = True
            continue
        adr = _decode_adr(word, va)
        if adr is not None:
            recent_adr.append((i, adr[1]))
            continue
        cmp_imm = _decode_cmp_imm(word)
        if cmp_imm is not None:
            nxt = _read_raw_word(ctx, va + 4)
            cond = _decode_bcond(nxt) if nxt is not None else None
            gate_count = range_from_unsigned_gate(cond, cmp_imm[1])
            if gate_count:        # HS → imm, HI → imm+1; other conds → no gate
                recent_gate.append((i, gate_count, cmp_imm[0]))
            continue
        sub_imm = _decode_sub_imm(word)
        if sub_imm is not None:
            recent_sub.append((i, sub_imm[0], sub_imm[2]))
            continue
        load = _decode_ldr_reg_off(word)
        if load is not None:
            entry_size, rn, rm, _rt = load
            recent_load.append((i, rn, entry_size, rm))
            continue
        if _is_br_insn(word):
            arm_base = next((t for adr_i, t in reversed(recent_adr)
                             if 0 <= i - adr_i <= 4), None)
            if arm_base is None:
                continue
            load_hit = next(
                ((l_i, reg, esz, idx) for l_i, reg, esz, idx in reversed(recent_load)
                 if 0 <= i - l_i <= 4), None)
            table_reg, entry_size = (load_hit[1], load_hit[2]) if load_hit else (-1, 0)

            gate = next(((c, rn) for g_i, c, rn in reversed(recent_gate)
                         if 0 <= i - g_i <= 8), None)
            result = None
            if gate is not None:
                count, gate_rn = gate
                # Bias: the `sub Wi,Wt,#bias` whose Rd feeds the gate register.
                bias = next((b for s_i, rd, b in reversed(recent_sub)
                             if rd == gate_rn and 0 <= i - s_i <= 8), 0)
                result = (arm_base, count, table_reg, entry_size, bias, va)
            elif load_hit is not None and load_hit[2] == 4:
                # Classic tight-window gate lookup failed.  A newer toolchain's
                # index-clamp idiom (see _decode_clamped_gate) pushes the real
                # gate further back than any distance window should reach for —
                # try recognising that specific instruction chain structurally
                # instead of widening the window.  Only applies to the ldrsw
                # (4-byte, signed difference-table) entry form this idiom uses.
                clamped = _decode_clamped_gate(
                    ctx, func_va + load_hit[0] * 4, load_hit[3])
                if clamped is not None:
                    count, bias = clamped
                    result = (arm_base, count, table_reg, entry_size, bias, va)

            if result is not None:
                if result[4] >= 1:
                    return result
                if fallback is None:
                    fallback = result
            continue
    return fallback


def _decode_clamped_gate(
    ctx: BinaryContext, load_va: int, idx_reg: int,
) -> Optional[Tuple[int, int]]:
    """Recover ``(field_count, bias)`` for a jump-table cluster whose gate sits
    further back from its ``ldrsw``/``br`` than the classic toolchain's shape,
    separated by an extra index-clamp: a newer Apple-internal toolchain
    (observed on a macOS system dyld cache's GeoServices) re-compares the
    index in its 64-bit form and clamps it before the table load, e.g.::

        cmp   Wg, #N-1 ; b.hi <oob>   ; the REAL gate (may be preceded by
                                        `sub Wg,Wt,#bias`)
        mov   ...                      ; 0+ unrelated filler movs
        cmp   Xi, #N-1                 ; the SAME bound, re-tested in 64-bit
        csel  Xi, Xi, xzr, ls          ; clamp: keep Xi only if in range
        adrp Rtab,#page ; add Rtab,Rtab,#off  ; table base (interleaved here)
        ldrsw Xi, [Rtab, Xi, lsl #2]   ; <load_va> -- the table load itself

    This is a STRUCTURAL match, not a wider distance window: every step must
    be the exact expected instruction acting on the exact expected register,
    and the clamp's bound (``N`` in its ``cmp``) must EQUAL the real gate's
    bound -- they are the same range check done twice, so a real match is
    self-consistent; an unrelated ``cmp``/``csel`` pair would not by
    coincidence share both the register-flow chain AND the immediate.  Filler
    ``mov``s are the only instruction allowed between the gate's ``b.hi/b.hs``
    and the clamp ``cmp``, and only ``adrp``/``add`` (the table-base
    computation, on a DIFFERENT register than the index) are allowed between
    the clamp ``csel`` and the load -- anything else fails the match.  ``None``
    when the chain doesn't structurally hold.
    """
    try:
        insns = disasm(ctx, max(0, load_va - 80), max_insns=30, stop_at_ret=False)
    except Exception:
        return None
    insns = [i for i in insns if i.addr <= load_va]
    if not insns or insns[-1].addr != load_va:
        return None
    insns = insns[:-1]     # everything strictly before the load

    idx = _wname("w%d" % idx_reg)

    # 1. The clamp csel populating the load's index register.  The table-base
    #    `adrp`/`add` (a different register) can sit between it and the load —
    #    skip over those specifically, nothing else.
    j = len(insns) - 1
    while j >= 0 and insns[j].mnemonic in ('adrp', 'add') and _wname(
            insns[j].op_str.split(',')[0].strip()) != idx:
        j -= 1
    if j < 0 or insns[j].mnemonic != 'csel':
        return None
    o = [t.strip() for t in insns[j].op_str.split(',')]
    if len(o) != 4 or _wname(o[0]) != idx:
        return None
    insns = insns[:j]

    # 2. The immediately preceding cmp sets the flags the csel consumes.
    if not insns or insns[-1].mnemonic != 'cmp':
        return None
    o = [t.strip() for t in insns[-1].op_str.split(',')]
    if len(o) != 2 or not o[1].startswith('#'):
        return None
    clamp_n = _imm_tok(o[1])
    if clamp_n is None:
        return None
    insns = insns[:-1]

    # 3. Skip 0+ filler `mov`s back to the gate's conditional branch.
    j = len(insns) - 1
    while j >= 0 and insns[j].mnemonic == 'mov':
        j -= 1
    if j < 0 or insns[j].mnemonic not in ('b.hi', 'b.hs'):
        return None
    cond = insns[j].mnemonic
    j -= 1

    # 4. The real gate: cmp/subs Wg,#N immediately before that branch, N
    #    matching the clamp's bound exactly (self-consistency check).
    if j < 0 or insns[j].mnemonic not in ('cmp', 'subs'):
        return None
    o = [t.strip() for t in insns[j].op_str.split(',')]
    if len(o) != 2 or not o[1].startswith('#'):
        return None
    gate_n = _imm_tok(o[1])
    if gate_n is None or gate_n != clamp_n:
        return None
    gate_reg = o[0]
    field_count = gate_n if cond == 'b.hs' else gate_n + 1
    j -= 1

    # 5. Optional `sub Wg,Wt,#bias` feeding the gate register, immediately
    #    before it.
    bias = 0
    if j >= 0 and insns[j].mnemonic == 'sub':
        o = [t.strip() for t in insns[j].op_str.split(',')]
        if len(o) == 3 and _wname(o[0]) == _wname(gate_reg) and o[2].startswith('#'):
            b = _imm_tok(o[2])
            if b is not None:
                bias = b

    return (field_count, bias)


def _decode_readfrom_jumptable(
    ctx: BinaryContext, read_specified_va: int, field_count: int,
    cluster: Optional[Tuple[int, int, int, int, int, int]] = None,
) -> Optional[Dict[int, int]]:
    """
    Decode the field-dispatch jump table in a ReadSpecified core and return
    ``{field_number: arm_vmaddr}`` for the tags the table dispatches, or ``None``
    when the function does not use this jump-table shape (caller falls back to
    the name-suffix heuristics).

    Recovery is validation-driven so it needs no decoding of the
    register-offset ``ldrh`` / shifted ``add`` (which the native decoder cannot
    handle):

      1. ``ARM_BASE``, the true ``count`` and the field-number ``bias`` from the
         dispatch cluster (:func:`_find_dispatch_cluster`).  The cluster's
         ``cmp`` gate is the authoritative field count; the *field_count*
         argument is only a hint used when the gate cannot be read.  ``bias`` is
         the ``sub`` offset, so table entry *i* serves field ``bias + i``.
      2. ``func_end`` from disassembling to the terminating ``ret``.
      3. Table base from the pinned table register's own ``adrp+add``, found in
         a small window ending at this cluster's own ``br`` (its address is
         part of the cluster) -- never the whole function, since other
         clusters may reuse the same register for their own, different table.
      4. Read ``count`` entries.  Two encodings, matching
         :func:`_jump_table_arm_addrs`'s two idioms: a 1/2-byte entry is an
         UNSIGNED index needing the classic ``*4`` scale
         (``arm[i] = ARM_BASE + entry[i] * 4``); a 4-byte entry (``ldrsw``) is
         already a SIGNED ``(arm - ARM_BASE)`` byte delta needing no further
         scale (``arm[i] = ARM_BASE + entry[i]``) — read SIGNED, since a
         negative delta is a real, common target position, not a decode
         error.  Accept
         only when *every* arm is 4-byte aligned and lies in
         ``[ARM_BASE, func_end)``.

    Bails (``None``) when ``bias < 1`` — without the feeding ``sub`` the arm →
    field-number join can't be trusted (precision over recall).
    """
    # The caller may supply an already-computed cluster (the wrapper→core finder
    # does) to avoid re-scanning; otherwise derive it here.
    if cluster is None:
        cluster = _find_dispatch_cluster(ctx, read_specified_va)
    if cluster is None:
        return None
    arm_base, gate_count, table_reg, entry_size, bias, br_va = cluster
    count = gate_count if gate_count > 0 else field_count
    if count <= 0 or bias < 1:
        return None
    try:
        insns = disasm(ctx, read_specified_va, max_insns=_READSPEC_MAX_INSNS)
    except Exception:
        return None
    if not insns:
        return None
    func_end = insns[-1].addr + 4

    def _read_arms(table_va: int, width: int) -> Optional[Dict[int, int]]:
        # width==4 (ldrsw) is the signed difference-table idiom (entry IS the
        # byte delta, no further scale); width 1/2 (ldrb/ldrh) is the classic
        # unsigned index-table idiom (entry needs the *4 instruction-align
        # scale) -- see _jump_table_arm_addrs's docstring for the same split.
        signed = width == 4
        scale = 1 if signed else 4
        arms: Dict[int, int] = {}
        for i in range(count):
            try:
                raw = ctx.read_bytes(table_va + i * width, width)
            except ValueError:
                return None
            arm = arm_base + int.from_bytes(raw, "little", signed=signed) * scale
            if arm % 4 != 0 or not (arm_base <= arm < func_end):
                return None
            arms[bias + i] = arm        # table entry i serves field bias + i
        return arms

    # Preferred path: the register-offset load pins the exact table register and
    # entry width, so resolve the table base directly from that register's
    # adrp+add and read with the decoded width.
    #
    # The resolved adrp+add is the LAST one that populates table_reg at or
    # before THIS cluster's own `br` (br_va) -- a register's value at a given
    # point is whatever it was most recently assigned, not whatever it was
    # FIRST assigned in the function.  This matters because an engine commonly
    # holds several independent jump-table clusters that all reuse the same
    # scratch register for their own table-base adrp+add (confirmed by direct
    # disassembly of GEORPFeedbackDetails's ReadSpecified engine: three separate
    # br clusters, each with its own `adrp x17`/`add x17` a few instructions
    # before its own br).  find_adrp_add_target alone always returns the FIRST
    # match scanning from the start of whatever instruction list it is given;
    # passing it the whole function always resolved the first cluster's table
    # regardless of which cluster was being decoded -- the table register was
    # pinned correctly but the table's DATA was read from a different
    # cluster's table, silently misreading every arm.
    if table_reg >= 0 and entry_size > 0:
        prefix = [i for i in insns if i.addr <= br_va]
        table_va = None
        for k in range(len(prefix) - 1, -1, -1):
            if prefix[k].mnemonic != 'adrp':
                continue
            table_va = find_adrp_add_target(prefix[k:], f"x{table_reg}")
            if table_va is not None:
                break
        if table_va is not None:
            arms = _read_arms(table_va, entry_size)
            if arms is not None:
                return arms

    # The cluster pins the table register and entry width from the actual
    # register-offset load (`_decode_ldr_reg_off`), so the preferred path above
    # resolves every jump table that resolves at all.  A former fallback here —
    # trying all 31 registers' adrp+add targets against both 2- and 1-byte
    # widths and accepting the first whose arms validated — was removed
    # 2026-06-08: a census over GeoServices / locationd / CoreLocationProtobuf
    # (1350 cluster calls) showed it fired ZERO times, and its weak "all arms
    # aligned and in range" guard could admit a wrong adrp target.  When the load
    # can't be pinned, return None and let the caller's other tiers (compare
    # chain, Strategy 1/2) handle the field.
    return None


def _func_end(ctx: BinaryContext, func_va: int) -> Optional[int]:
    """Return the address one past the last instruction reachable from
    *func_va*, or None.

    A function's real extent is exactly the set of instructions reachable
    from its entry via intra-procedural control flow (conditional/
    unconditional branches and fall-through) — never through a ``bl``/``blr``
    call, which leaves the function entirely.  Computed structurally: build
    the CFG (:func:`proto.arm64cfg.build_blocks`, which already classifies
    edges this way — a plain ``b``/conditional target only becomes an edge
    when it lands inside the disassembled window, a ``bl``/``blr`` only ever
    contributes its fall-through) over a generous linear disassembly from
    *func_va*, then take the highest address among the blocks actually
    reachable from the entry block by graph traversal.

    This replaces an earlier "stop at the next function's prologue" textual
    heuristic.  That heuristic under-ran on ``readFrom:`` cores from a newer
    Apple-internal toolchain (observed on a macOS system dyld cache's
    GeoServices) whose per-field compare-chain body is reached only via a
    forward branch past the entry preamble's own ``ret`` — and, worse, whose
    *individual field-handler arms* can each open their own local stack frame
    (their own ``pacibsp``/``sub sp``/``stp`` sequence), so the same "looks
    like a new function" pattern recurs *inside* one real function, not just
    at its true end.  Textual pattern-matching can't tell those apart from a
    genuinely different function; graph reachability doesn't need to —
    everything the entry's control flow can reach IS the function, full stop.
    """
    from proto.arm64cfg import build_blocks

    try:
        insns = disasm(ctx, func_va, max_insns=_READSPEC_MAX_INSNS, stop_at_ret=False)
    except Exception:
        return None
    if not insns:
        return None

    cfg = build_blocks(insns)
    if cfg.entry is None:
        return None

    reachable: Set[int] = set()
    stack = [cfg.entry]
    while stack:
        b = stack.pop()
        if b in reachable:
            continue
        reachable.add(b)
        for s in cfg.succ.get(b, []):
            if s not in reachable:
                stack.append(s)
    if not reachable:
        return None
    last_addr = max(cfg.blocks[b][-1].addr for b in reachable)
    return last_addr + 4


def _find_field_number_register(
    ctx: BinaryContext, func_va: int, func_end: int
) -> Optional[int]:
    """
    Return the register index holding ``field# = tag >> 3`` in a reader core, or
    ``None`` when absent or ambiguous.

    Every generated protobuf reader extracts the field number from the wire tag
    with a single ``lsr Wf, Wtag, #3``.  We scan the function body (raw words,
    since the native mini-decoder leaves UBFM as ``unk``) for ``lsr …,#3`` sites;
    if they all target the **same** destination register we return it, otherwise
    ``None`` (precision over recall — an ambiguous field-number register would
    risk mis-binding).
    """
    dests: Set[int] = set()
    va = func_va
    while va < func_end:
        word = _read_raw_word(ctx, va)
        if word is None:
            break
        decoded = _decode_lsr_imm(word)
        if decoded is not None and decoded[2] == 3:
            dests.add(decoded[0])
        va += 4
    return next(iter(dests)) if len(dests) == 1 else None


# ── Dominance attribution (compare-chain field routing) ──────────────────────
# The old address-range decoder (_compare_chain_blocks / _field_for_addr) was
# retired once _dominance_field_of below -- exact dominance over a complete CFG,
# the same mechanism proto.repeated's element/ivar resolvers already used --
# became the sole compare-chain field-attribution mechanism (its one remaining
# production caller, _core_resolves_compare_chain, was migrated onto it).

def _imm_tok(tok: str) -> Optional[int]:
    tok = tok.strip().lstrip('#')
    try:
        return int(tok, 16) if tok.lower().startswith('0x') else int(tok)
    except ValueError:
        return None


def _wname(reg: str) -> str:
    reg = reg.strip()
    return 'w' + reg[1:] if reg and reg[0] in 'xX' else reg


def _jump_table_arm_addrs(ctx: BinaryContext, insns: List["Insn"]) -> set:
    """Arm-target addresses of EVERY ``br Xn`` jump table built by either of two
    compiler idioms:

      * index table  — ``adr xT,#base; ldrb/ldrh wK,[xtable,widx]; add xT,xT,wK,lsl#s; br xT``.
        Each entry is a small unsigned INDEX; the shift in the final ``add``
        scales it to the real instruction-aligned byte offset.
      * difference table — ``adr xT,#base; ldrsw xK,[xtable,widx,lsl#2]; add xT,xT,xK; br xT``.
        Each entry is a SIGNED 32-bit ``(arm - base)`` byte delta already, so the
        final ``add`` carries no shift and the entry must be sign-extended, not
        read as unsigned (a negative delta is a real, common target position —
        the anchor sits inside the dispatch, not before every arm).  Observed on
        a newer Apple-internal toolchain's outlined per-class dispatch "engine"
        (a macOS system dyld cache's GeoServices): the compare-chain field
        dispatch shares its function with an internal (non-field) bookkeeping
        jump table using exactly this shape, and without recognising it the CFG
        stays disconnected past the ``br`` — dominance then can't reach the real
        field handlers at all, even though they sit later in the same function.

    A GENERAL CFG-completion decoder (NOT the proto-field-specific
    :func:`_decode_readfrom_jumptable`): it recovers arm targets for any such ``br`` so
    :func:`proto.arm64cfg.dominators` can reach jump-table handler blocks.  Without it a
    reader whose field dispatch is a compare chain SHARING the function with a control
    ``br`` (e.g. GEOHours) leaves most blocks unreachable → dominance returns None.
    Read-only; returns in-range arm addresses."""
    if ctx is None or not insns:
        return set()
    ins = sorted(insns, key=lambda i: i.addr)
    lo, hi = ins[0].addr, ins[-1].addr + 4
    arms: set = set()
    for k, br in enumerate(ins):
        if br.mnemonic != 'br':
            continue
        reg = br.op_str.strip()
        win = ins[max(0, k - 24):k]
        scale = kreg = base_reg = None
        for w in reversed(win):
            if w.mnemonic != 'add':
                continue
            o = [t.strip() for t in w.op_str.split(',')]
            if len(o) == 4 and o[0] == reg and any(s in o[3] for s in ('lsl', 'sxtw', 'uxtw')):
                try:
                    scale = 1 << int(o[3].split('#')[1])
                except Exception:
                    scale = 4
                kreg = o[2]
                base_reg = reg          # classic idiom: xT self-accumulates arm_base + offset
                break
            if len(o) == 3 and o[0] == reg:
                # Difference-table idiom: no shift here because the table entry
                # (read as ldrsw below) IS the byte delta already.  Unlike the
                # classic idiom, arm_base lives in its OWN register (o[1]), not
                # the br register itself — e.g. `adr x17,#base; add x16,x17,x16;
                # br x16` (x16 only ever holds the loaded offset, never the base).
                scale = 1
                kreg = o[2]
                base_reg = o[1]
                break
        if kreg is None:
            continue
        arm_base = None
        for w in reversed(win):
            if w.mnemonic == 'adr':
                o = [t.strip() for t in w.op_str.split(',')]
                if len(o) == 2 and o[0] == base_reg:
                    arm_base = _imm_tok(o[1])
                    break
        if arm_base is None:
            continue
        kre = _wname(kreg)
        table_reg = idx_reg = width = None
        signed = False
        for w in reversed(win):
            if w.mnemonic in ('ldrb', 'ldrh', 'ldrsw'):
                p = w.op_str.split(',', 1)
                if len(p) != 2 or _wname(p[0]) != kre:
                    continue
                mem = p[1].strip()
                if '[' not in mem or ']' not in mem:
                    continue
                inner = [q.strip() for q in mem[mem.index('[') + 1:mem.rindex(']')].split(',')]
                table_reg = inner[0]
                idx_reg = inner[1] if len(inner) > 1 else None
                width = {'ldrb': 1, 'ldrh': 2, 'ldrsw': 4}[w.mnemonic]
                signed = w.mnemonic == 'ldrsw'
                break
        if table_reg is None:
            continue
        table_va = find_adrp_add_target(win, table_reg)
        if table_va is None:
            continue
        count = None
        idxn = _wname(idx_reg) if idx_reg else None
        for j in range(len(win) - 1, -1, -1):
            w = win[j]
            if w.mnemonic in ('cmp', 'subs'):
                o = [t.strip() for t in w.op_str.split(',')]
                if len(o) >= 2 and o[1].startswith('#') and (idxn is None or _wname(o[0]) == idxn):
                    n = _imm_tok(o[1])
                    if n is None:
                        continue
                    nb = win[j + 1].mnemonic if j + 1 < len(win) else ''
                    count = n if nb == 'b.hs' else n + 1
                    break
        if not count or count <= 0 or count > 4096:
            continue
        try:
            raw = ctx.read_bytes(table_va, count * width)
        except Exception:
            continue
        for v in range(count):
            ent = int.from_bytes(raw[v * width:(v + 1) * width], 'little', signed=signed)
            arm = arm_base + ent * scale
            if lo <= arm < hi:
                arms.add(arm)
    return arms


def _compare_handlers(
    ctx: BinaryContext, core_va: int, func_end: int, field_reg: int,
):
    """Build the core's COMPLETE basic-block CFG + dominator tree and list every
    compare-chain handler: returns ``(cfg, idom, handlers)`` with ``handlers`` the
    ``[(field_number, handler_block), ...]`` of EVERY ``cmp Wf,#N; b.eq/b.ne`` site in
    address order — or ``None`` for an empty function.  The same field number can
    appear more than once (a map entry's own nested ``key = 1`` / ``value = 2`` tag
    compares reuse numbers).  Shared by :func:`_dominance_field_of` (deepest
    dominating handler owns an instruction) and :mod:`proto.mapfields` (the OUTERMOST
    handler of one field number and everything it dominates)."""
    from proto.arm64cfg import (build_blocks, dominators, inject_arm_edges, split_ops)

    try:
        insns = [i for i in disasm(ctx, core_va, max_insns=max(1, (func_end - core_va) // 4),
                                   stop_at_ret=False) if core_va <= i.addr < func_end]
    except Exception:
        insns = []
    if not insns:
        return None

    cfg = build_blocks(insns)
    inject_arm_edges(cfg, _jump_table_arm_addrs(ctx, insns))   # CFG completion
    idom = dominators(cfg)
    wf = "w%d" % field_reg

    handlers: List[Tuple[int, int]] = []
    for b in cfg.order:
        body = cfg.blocks[b]
        for k, ins in enumerate(body):
            if ins.mnemonic not in ("cmp", "subs"):
                continue
            ops = split_ops(ins.op_str)
            if len(ops) < 2 or _wname(ops[0]) != wf or not ops[1].startswith("#"):
                continue
            n = _imm_tok(ops[1])
            if n is None or n < 1:
                continue
            for j in range(k + 1, min(k + 3, len(body))):
                mj = body[j].mnemonic
                if mj in ("b.eq", "b.ne"):
                    tgt = _imm_tok(body[j].op_str)
                    tgt_blk = cfg.addr_to_block.get(tgt)
                    ft_blk = _fallthrough_block(cfg, b)
                    handler = tgt_blk if mj == "b.eq" else ft_blk
                    if handler is not None:
                        handlers.append((n, handler))
                    break
    return cfg, idom, handlers


def _dominance_field_of(
    ctx: BinaryContext, core_va: int, func_end: int, field_reg: int,
):
    """Build the core's COMPLETE basic-block CFG + dominator tree and return a
    ``field_of(addr) -> Optional[int]`` closure that attributes an instruction to the
    field whose compare-chain handler block **dominates** it (exact), replacing
    ``_compare_chain_blocks`` + address-range ``_field_for_addr``.

    Handler = the block reached by ``cmp Wf,#N; b.eq`` (target) / ``b.ne`` (fall-through),
    gathered from EVERY such site (not a fall-through spine: readers run a preamble).
    The CFG is COMPLETED with every ``br`` jump-table's arm edges
    (:func:`_jump_table_arm_addrs`) so handler blocks reached only through an indirect
    dispatch are reachable — without this, hybrid compare-chain+jump-table readers leave
    handlers unreachable and dominance loses the field.  Dominance is exact, so a
    neighbour / stray sentinel can never swallow another field's calls — the
    ``degenerate-partition`` guard is unnecessary by construction.  Returns a closure
    answering ``None`` for an empty CFG (caller degrades to "nothing attributed")."""
    from proto.arm64cfg import dominates, dom_depth

    built = _compare_handlers(ctx, core_va, func_end, field_reg)
    if built is None:
        return lambda addr: None
    cfg, idom, handlers = built

    handler_block: Dict[int, int] = {}
    for n, handler in handlers:
        handler_block.setdefault(n, handler)

    def field_of(addr: int) -> Optional[int]:
        blk = cfg.addr_to_block.get(addr)
        if blk is None:
            return None
        best_fn = None
        best_depth = -1
        for fn, hblk in handler_block.items():
            if dominates(idom, hblk, blk):
                d = dom_depth(idom, hblk)
                if d > best_depth:
                    best_depth, best_fn = d, fn
        return best_fn

    return field_of


def _fallthrough_block(cfg, block: int) -> Optional[int]:
    """Block entry immediately following *block* in address order."""
    order = cfg.order
    try:
        i = order.index(block)
    except ValueError:
        return None
    return order[i + 1] if i + 1 < len(order) else None


def _core_resolves_compare_chain(
    ctx: BinaryContext, core_va: int, core_index: Dict[int, str]
) -> bool:
    """True when *core_va* is itself a real compare-chain dispatcher that binds at
    least one field to a known ReadAllFrom core, with a NON-degenerate partition.

    This is the **dispatch-core gate** (registry id ``core-picker``, PRINCIPLED).
    :func:`_locate_dispatch_arms` applies it SYMMETRICALLY to both candidate cores —
    the anchored direct core (``read_specified_va``) and the wrapper-body-scan core
    (``wcore``) — and prefers the anchored core on ties.  A core is accepted only when
    it genuinely dispatches (e.g. GEOPDExternalAction's own ReadSpecified); a thick
    wrapper whose direct path holds no usable dispatch (e.g. GEOPDBatchSpatialLookup-
    Result) falls through to its separately-called ``wcore``; a body-scan look-alike
    (an accessor or sibling core) is rejected by the same predicate rather than by an
    after-the-fact picker.  Attribution goes through :func:`_dominance_field_of`
    (exact dominance over a COMPLETE CFG), the same mechanism
    :func:`proto.repeated._resolve_compare_chain_elements` uses — this used to run
    its own address-range approximation (the retired ``_compare_chain_blocks`` /
    ``_field_for_addr``) before both call sites were unified on the more precise
    dominance attribution.  Conservative: any failure → False."""
    func_end = _func_end(ctx, core_va)
    if func_end is None:
        return False
    field_reg = _find_field_number_register(ctx, core_va, func_end)
    if field_reg is None:
        return False
    field_of = _dominance_field_of(ctx, core_va, func_end, field_reg)
    by_field: Dict[int, Set[int]] = {}
    va = core_va
    while va < func_end:
        word = _read_raw_word(ctx, va)
        if word is None:
            break
        if _is_bl_word(word):                          # bl
            target = _decode_b_bl_target(word, va)
            if target in core_index:
                fn = field_of(va)
                if fn is not None:
                    by_field.setdefault(fn, set()).add(target)
        va += 4
    if not by_field:
        return False
    # Degenerate partition (a field credited ≥2 distinct element cores) ⇒ not a real
    # compare chain — treat as "does not resolve" so the caller prefers wcore.
    return not any(len(targets) >= 2 for targets in by_field.values())


def _walk_jumptable_arms(
    ctx: BinaryContext, arms: Optional[Dict[int, int]], core_index: Dict[int, str],
) -> Dict[int, str]:
    """Resolve ``{field_number: element_class}`` from decoded jump-table arms by
    taking each arm's first ``bl`` target that is a known ReadAllFrom core, or
    (when no such ``bl`` exists in the arm) the ObjC class it loads a classref
    to and allocates.

    Two structural guards, both needed on a newer Apple-internal toolchain
    (observed on a macOS system dyld cache's GeoServices) whose arms can be
    considerably closer together than the classic toolchain's:

    1. Two DIFFERENT field numbers sharing the exact same arm address is real
       (a genuinely ambiguous dispatch slot — verified directly: e.g. two
       distinct fields both landing on one address), but a single arm's
       resolved class cannot soundly stand for two different fields of
       different real types, so neither is trusted.
    2. Without a next-arm boundary, scanning "until the first unconditional
       terminator" over-runs into a LATER arm when consecutive arms share a
       fallthrough tail with no intervening branch — checked directly: one
       arm's first ``bl`` lands inside what is structurally the NEXT arm's own
       body, several fields downstream.  Bounding the scan by the next
       distinct arm start (in addition to the existing terminator check)
       prevents this regardless of which shape a given pair of arms takes.

    The classref fallback: as this module's own docstring for
    :func:`_resolve_repeated_via_dispatch` already observes, ``readFrom:`` must
    *create* each element, so it statically references the element class
    either as ``ElementClassReadAllFrom`` (a direct ``bl`` to a known core — the
    primary signal above) or as ``[ElementClass alloc]`` (a classref load).  A
    newer Apple-internal toolchain generates the latter shape exclusively for
    many classes: confirmed by direct disassembly (GEOPDBusinessHours,
    GEOPDActionData, GEOPBTransitIncident, GEOIndexQueryNode) that these arms
    call a GENERIC, ivar-offset-parameterized append/set helper — shared across
    unrelated classes/fields, so a ``bl``-target lookup against *core_index*
    never matches — but every one of them loads an explicit
    ``adrp+ldr`` classref for the element class immediately beforehand, which
    ``ctx.bind_name_for`` resolves directly by name (no address collision is
    possible: it reads the class's own compiled name, not a shared helper's
    address).  Accepted only when the resolved name is itself a known proto
    class (``core_index``'s own value set) — a bounded chance of landing on an
    unrelated classref cached for another purpose in the same arm, but ruling
    out anything that isn't a real message class in this binary.
    """
    if not arms:
        return {}
    va_counts: Dict[int, int] = {}
    for arm_va in arms.values():
        va_counts[arm_va] = va_counts.get(arm_va, 0) + 1
    starts = sorted(set(arms.values()))
    known_classes = set(core_index.values())

    out: Dict[int, str] = {}
    for field_number, arm_va in arms.items():
        if va_counts[arm_va] > 1:
            continue    # ambiguous: shared by >=2 different field numbers
        boundary = next((s for s in starts if s > arm_va), None)
        core_hit, classref_hit = _scan_arm_for_core_or_classref(
            ctx, arm_va, boundary, core_index, known_classes)
        name = core_hit if core_hit is not None else classref_hit
        if name is not None:
            out[field_number] = name
    return out


def _classref_class_name(ctx: BinaryContext, slot_va: int) -> Optional[str]:
    """Bare ObjC class name a classref slot (``__objc_classrefs`` entry) points
    at, or ``None``.

    Two shapes, matching :func:`proto.repeated._class_from_type_method_imp`'s
    own resolution of a ``+xyzType`` classref:

    * an EXTERNAL class (or, in cache mode, any class in any image): the slot
      is a bind / cache pointer that ``ctx.bind_name_for`` names directly;
    * a class defined in THIS image (binary mode): the slot is a plain rebase
      to the local ``class_t``, which ``bind_name_for`` knows nothing about — so
      follow ``class_t.data -> class_ro_t.name`` instead.  Without this the
      classref fallback of :func:`_walk_jumptable_arms` silently never fires
      for a standalone binary/dylib whose element classes are its own (found by
      the f25 synthetic fixture; cache mode was unaffected)."""
    name = ctx.bind_name_for(slot_va)
    if name:
        prefix = "_OBJC_CLASS_$_"
        return name[len(prefix):] if name.startswith(prefix) else name
    try:
        class_va = ctx.read_ptr(slot_va)
        if not class_va:
            return None
        ro_va = ctx.read_ptr(class_va + CLASS_T_DATA) & FAST_DATA_MASK
        name_va = ctx.read_ptr(ro_va + CLASS_RO_NAME) if ro_va else 0
        return ctx.read_cstring(name_va) if name_va else None
    except (ValueError, KeyError, UnicodeDecodeError):
        return None


def _scan_arm_for_core_or_classref(
    ctx: BinaryContext, arm_va: int, boundary: Optional[int],
    core_index: Dict[int, str], known_classes: Set[str],
) -> Tuple[Optional[str], Optional[str]]:
    """Bounded single-arm scan (see :func:`_walk_jumptable_arms`) returning
    ``(core_bl_class, classref_class)``: the class name from the arm's first
    ``bl`` into a known ReadAllFrom core (the strong, primary signal), and
    separately the class name from the first classref it loads and would
    allocate (the fallback signal for a generic, non-``core_index`` arm) — see
    :func:`_walk_jumptable_arms` for why both exist.  Either may be ``None``.
    """
    try:
        arm_insns = disasm(ctx, arm_va, max_insns=_ARM_MAX_INSNS, stop_at_ret=False)
    except Exception:
        return None, None
    # Bound the scan to this arm: stop at the first unconditional terminator
    # (b / br / ret) — arms enter by `br`, exit by a tail `b` — or at the next
    # arm's own start, whichever comes first.
    adrp_targets: Dict[str, int] = {}   # register -> page, this arm only
    classref_hit: Optional[str] = None
    for insn in arm_insns:
        if boundary is not None and insn.addr >= boundary:
            break
        if insn.mnemonic in ('b', 'br', 'ret', 'retaa', 'retab'):
            break
        if insn.mnemonic == 'adrp':
            parts = insn.op_str.split(',', 1)
            if len(parts) == 2:
                reg = _norm_reg(parts[0].strip())
                page = _parse_imm(parts[1])
                if reg is not None and page is not None:
                    adrp_targets[reg] = page
            continue
        if insn.mnemonic == 'ldr' and classref_hit is None:
            parts = insn.op_str.split(',', 1)
            mem = parts[1].strip() if len(parts) == 2 else ''
            if mem.startswith('['):
                base_reg = _norm_reg(mem[1:].split(',')[0].strip())
                page = adrp_targets.get(base_reg) if base_reg else None
                if page is not None:
                    off = _parse_imm(mem.split(',', 1)[1]) if ',' in mem else 0
                    name = _classref_class_name(ctx, page + (off or 0))
                    if name in known_classes:
                        classref_hit = name
            continue
        if insn.mnemonic == 'bl':
            t = _parse_imm(insn.op_str)
            if t is not None and t in core_index:
                return core_index[t], classref_hit
    return None, classref_hit


def _any_arm_loads_known_classref(
    ctx: BinaryContext, arms: Dict[int, int], core_index: Dict[int, str],
) -> bool:
    """True if any of *arms* loads a classref resolving to a known proto class
    (``core_index``'s own value set) — see :func:`_walk_jumptable_arms`'s
    docstring.  Used as a jump-table ownership signal alongside
    :func:`_call_site_selects_data_table`, for the newer toolchain's classes
    whose arms never call a named accessor at all (so
    :func:`_arm_calls_own_method` can never confirm them)."""
    if not arms:
        return False
    starts = sorted(set(arms.values()))
    known_classes = set(core_index.values())
    for arm_va in set(arms.values()):
        boundary = next((s for s in starts if s > arm_va), None)
        _core_hit, classref_hit = _scan_arm_for_core_or_classref(
            ctx, arm_va, boundary, core_index, known_classes)
        if classref_hit is not None:
            return True
    return False


def _locate_dispatch_arms(
    ctx: BinaryContext,
    cls: ObjcClass,
    core_index: Dict[int, str],
) -> Tuple[Optional[Dict[int, int]], Optional[int], Optional[int]]:
    """Locate *cls*'s readFrom: jump-table arms once and return
    ``(arms, core_va, readfrom_va)``.

    ``arms`` is ``{field_number: arm_vmaddr}`` from the directly-anchored core or,
    failing that, from the wrapper→separate-core finder; ``None`` when no jump
    table is found.  ``core_va`` is the function the arms live in (used by the
    compare-chain tier), ``readfrom_va`` the readFrom: anchor.  The result is
    memoised per class on *ctx* so the two dispatch resolvers (by-number and
    by-ivar) share one decode.
    """
    cache = _ctx_cache(ctx, "_dispatch_arms_cache", dict)
    if cls.vmaddr in cache:
        return cache[cls.vmaddr]

    readfrom_va = _find_readfrom_c_func(ctx, cls)
    if readfrom_va is None:
        result = (None, None, None)
        cache[cls.vmaddr] = result
        return result

    read_specified_va, field_count = _readspecified_and_count(ctx, readfrom_va)
    arms: Optional[Dict[int, int]] = None
    core_va = read_specified_va
    if read_specified_va is not None and field_count > 0:
        arms = _decode_readfrom_jumptable(ctx, read_specified_va, field_count)
    # Wrapper→core fallback: only when the direct decode found no jump table.  The
    # finder returns a jump-table core (with arms) OR a compare-chain core
    # (wcore set, warms None).
    #
    #   * jump-table wcore (warms set) — always adopt: the direct path found no
    #     table, so this only adds coverage.
    #   * compare-chain wcore (warms None) — choose between it and the anchored
    #     direct core by a SYMMETRIC dispatch-core gate: apply the same structural
    #     predicate (_core_resolves_compare_chain — extracts Wf=tag>>3, branches on
    #     it, binds >=1 field to a known core, non-degenerate partition) to BOTH
    #     candidates, and prefer the anchored direct core on ties.  So: keep the
    #     direct core when IT dispatches (e.g. GEOPDExternalAction, where the wrapper
    #     body-scan can surface a WRONG sibling core); adopt wcore only when the
    #     direct core does NOT dispatch and wcore does (e.g. the genuine thick
    #     wrapper GEOPDBatchSpatialLookupResult, where read_specified_va is None).
    #     When neither dispatches the choice is moot (the compare-chain tier resolves
    #     nothing on a non-dispatcher either way) — keep the anchored direct core.
    #     [Was core-picker, an ASYMMETRIC veto that gated only the direct core and
    #     trusted wcore via its weak discovery gate; the symmetric form is
    #     output-identical on the 3 golden artifacts.]
    if not arms:
        own_imps = frozenset(m.imp for m in cls.methods if m.imp)
        own_ivar_slots = frozenset(iv.offset_slot for iv in cls.ivars if iv.offset_slot)
        wcore, warms = _find_dispatch_core_via_wrapper(
            ctx, readfrom_va, own_imps, core_index, own_ivar_slots)
        if warms:
            core_va = wcore
            arms = warms
        elif wcore is not None:
            d_ok = read_specified_va is not None and _core_resolves_compare_chain(
                ctx, read_specified_va, core_index)
            if not d_ok and _core_resolves_compare_chain(ctx, wcore, core_index):
                core_va = wcore

    result = (arms, core_va, readfrom_va)
    cache[cls.vmaddr] = result
    return result


def _build_readfrom_core_index(
    ctx: BinaryContext,
    cl: 'ClassList',
) -> Dict[int, str]:
    """
    Binary-wide pre-pass: map every proto class's ReadAllFrom C-core address to
    its class name — ``{ReadAllFrom_vmaddr: class_name}``.

    The ReadAllFrom core is the tail target of ``-[Cls readFrom:]`` (recovered by
    :func:`_find_readfrom_c_func`) — exactly the address a *parent* class's
    readFrom: dispatch arm ``bl``-calls when parsing an embedded ``<Cls>``
    element.  :func:`_resolve_repeated_via_dispatch` uses this index to name a
    repeated field's element class **by the call-target address** of its dispatch
    arm, which works in cache-native mode where symbol names are stripped.

    Mirrors :func:`_identify_string_write_helpers`: one cheap pass over the
    classlist whose result is threaded through to every
    :func:`extract_proto_message` call.

    Collisions (two+ classes sharing one core address) are NOT rare: measured
    live on GeoServices, 38 of 1599 resolved cores are shared, all collapsing
    onto one address (a trivial/opaque-passthrough ``ReadAllFrom`` body common
    to many near-empty proto classes — see the project's opaque-passthrough
    census). The first class encountered wins (see the loop below) and every
    other class sharing that core silently loses its own identity in this
    index for the lifetime of the run. This matters because
    :func:`_resolve_repeated_via_dispatch` names repeated-message fields BY
    this index's call-target address: a real field whose element embeds via
    one of the 38 collided cores gets attributed to whichever class happened
    to be inserted first, not necessarily its true element type. Keep-first
    (rather than e.g. refusing to resolve on collision) is a deliberate
    precision/recall tradeoff, not an oversight — but it is not the "rare
    aliasing" edge case it might look like from the code alone.
    """
    index: Dict[int, str] = {}
    for cls in cl:
        if cls.is_meta or not _is_proto_class(cls):
            continue
        core = _find_readfrom_c_func(ctx, cls)
        if core is None:
            continue
        prev = index.get(core)
        if prev is None:
            index[core] = cls.name
        elif prev != cls.name:
            log.debug("readFrom core 0x%x maps to both %s and %s; keeping %s",
                      core, prev, cls.name, prev)
    return index
