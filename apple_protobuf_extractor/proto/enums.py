"""proto/enums — enum-value harvesting + enum-name derivation.

Carved from proto.extractor (#11 split, step 5b, final): the jump-table and dictrep
enum-value harvesters and enum-name derivation — the single largest concern in the
old monolith. Imports macho.* + arm64decode + protocore + dispatch + config (never
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
from collections import Counter
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from macho.memory     import BinaryContext, _ctx_cache
from macho.strings    import StringTable
from macho.classlist  import ObjcClass
from macho.disasm     import (disasm, Insn, _parse_imm, _norm_reg,
                              find_adrp_add_target, find_indexed_load_base)
from proto.arm64cfg   import (parse_adrp, split_ops, mem_operand, _CALLEE_SAVED,
                              ivar_slot_loads)
from macho.arm64decode import (jumptable_arm_target, _bcond_branch_target, _decode_cmp_reg, _materialized_value,
    _decode_adr, _decode_bcond, _decode_cmp_imm, _decode_ldr_reg_off, _decode_sub_imm,
    _is_br_insn, _COND_EQ, _COND_NE, _COND_LO, _COND_LS,
    _SUB_W_IMM_MASK, _SUB_W_IMM_PATTERN, range_from_unsigned_gate)
from proto.models     import ProtoEnum, ProtoEnumValue, ProtoField, _enum_prefix
from proto.protocore  import _proto_name
from proto.dispatch   import _find_field_count, _read_raw_word
from proto.config     import _class_to_proto_name
from proto.defaults    import DEFAULT_PREFIXES

log = logging.getLogger(__name__)


# [cap:COSMETIC — verified 2026-06-09] Bounds the search for the pointer-table base
# (an adrp+add in the method preamble).  If not found within the cap the code falls
# through to the jump-table path, never to a wrong answer.  Raising ×8 (80→640) gave
# 0 descriptor diffs across all 3 artifacts.  Value is cosmetic.  (Distinct from the
# enum-value *harvest*, which is bounded by field COUNT and, for the jump-table path,
# flagged when it overruns via ProtoEnum.values_truncated.)
_ENUM_MAX_INSNS = 80


def _is_valid_enum_string(s: str) -> bool:
    """Return True if *s* looks like a valid enum value name (a C identifier).

    This is purely a **sanity check**, not a decision-maker.  It does NOT pick
    between storage formats — :func:`_read_enum_string` dispatches on section
    membership for that — and it is not load-bearing on the structured read path
    (which already yields real strings).  Its only job is to reject garbage for
    the *probe-and-filter* callers that legitimately can't know in advance whether
    a candidate pointer targets a string at all: the jump-table scan
    (:func:`_extract_jumptable_enum_values`), the dictrep walkers, and the
    table-base register probe in :func:`_extract_enum_values`.  A False result
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


# _SUB_W_IMM_MASK / _SUB_W_IMM_PATTERN are imported from macho.arm64decode (the
# single home for the `sub wRd,wRn,#imm12` word shape; the bias scanners below
# match the field bits directly rather than calling _decode_sub_imm).

# Jump-table / isolated-value range ceiling shared by the sparse-enum harvesters
# below.  This is NOT a tuned/domain magic number (#59): it is the **unshifted
# 12-bit ``cmp`` immediate ceiling** (2^12).  The contiguous-range jump-table path
# consumes a ``cmp wN, #imm12 ; b.hi/hs`` gate, whose immediate is at most 0xFFF
# (4095) when unshifted — so a real contiguous enum range is ≤ 4096 (range = imm+1).
# A larger range/value can only come from a SHIFTED (``#imm,lsl#12``) or register
# compare; those are deliberately routed to the materialized-value path instead
# (``_decode_cmp_reg`` / ``_materialized_value``, bounded by the proto int32 range —
# that is how values like MotionActivityType=90603 are recovered).  So the bound is
# structural (the instruction encoding), and value-independent in meaning.  Verified
# against the artifacts: the largest contiguous (non-materialized) enum value is 4025
# — i.e. real data sits right under the 12-bit ceiling, exactly as the encoding
# predicts; raising the ceiling recovers nothing, lowering it drops real enums.
_SPARSE_MAX_RANGE  = 1 << 12       # 2^12 — the unshifted 12-bit cmp-immediate ceiling
# _COND_EQ/NE/LO/LS/HI/HS are imported from macho.arm64decode (canonical set).


def _find_index_bias(ctx: BinaryContext, func_va: int) -> int:
    """
    Scan the function body for a ``sub wRd, wRn, #N`` instruction that
    appears **before** the first CMP gate.  Returns ``N`` (the bias) or 0.

    Apple's ``xAsString:`` methods for 1-based enums (e.g.
    ``mapRegionSourceTypeAsString:`` with values 1-13) often start with::

        sub  w8, w2, #1      ; adjust 1-based enum value to 0-based table index
        cmp  w8, #13
        b.hs default_label
        adrp x9, page
        add  x9, x9, #offset
        ldr  x0, [x9, x8, lsl #3]

    Detecting the SUB lets us shift extracted pair values back by +bias so
    they match the proto enum numbering.
    """
    MAX_SCAN = 24
    va = func_va
    for _ in range(MAX_SCAN):
        word = _read_raw_word(ctx, va)
        if word is None:
            break
        if _decode_cmp_imm(word) is not None:
            break                          # reached the CMP — stop scanning
        sub = _decode_sub_imm(word)        # (rd, rn, imm); imm already shift-applied
        if sub is not None and 0 < sub[2] < 256:   # shifted imm is ≥4096 → excluded
            return sub[2]
        va += 4
    return 0


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


def _sub_imm_bias(insns, words, lo: int, hi: int, *,
                  dest_reg: Optional[int] = None, first: bool = False) -> int:
    """Immediate of a ``sub wRd, wRn, #imm12`` (shift 0) in ``insns[lo:hi]``, else 0.

    A SUB before a value test re-bases the enum (the compare runs on
    ``value - imm``), so ``imm`` is added back to recover the wire value.  b12 is
    a 12-bit immediate with shift 0 → already ≤ 0xFFF, so no range ceiling is
    needed (the encoding bounds it; #59).

    ``dest_reg`` — when ``None`` (the xAsString:/jump-table path) ANY ``sub #imm12``
    counts; this is deliberately UN-gated (gating it regressed #53).  When given
    (the dictRep path, #54) only a SUB whose DESTINATION is that register counts:
    the dictRep harvester scans a ~20-insn window that overlaps the neighbouring
    field's dispatch, so the dest==index-reg guard rejects a neighbour's ``sub``
    bleeding in (the ``GEOPD…SpellCorrection.spellerRankerModelType`` false
    positive — its window holds ``resultStatus``'s ``sub #1`` on another register).

    ``first`` — return the FIRST match (isolated-compare / cbz tight pre-window)
    vs the LAST (jump-table arm: the SUB nearest the CMP gate wins).

    Sibling of :func:`_leading_materialized_bias`, which models the larger-bias
    ``mov+add`` / ``movz+sub`` forms a 12-bit ``sub #imm`` cannot hold."""
    bias = 0
    for k in range(lo, hi):
        wk = words.get(insns[k].addr, 0)
        if (wk & _SUB_W_IMM_MASK) != _SUB_W_IMM_PATTERN:
            continue
        if (wk >> 22) & 0x3 != 0:            # shift != 0 → not a small (≤0xFFF) bias
            continue
        imm = (wk >> 10) & 0xFFF
        if imm <= 0:
            continue
        if dest_reg is not None and (wk & 0x1F) != dest_reg:
            continue
        bias = imm
        if first:
            break
    return bias


_MATERIALIZED_BIAS_MAX = 1 << 24   # sanity ceiling for a recovered large bias


def _regnum(tok: str):
    """Register number of a ``wN``/``xN`` token, or None (zr / non-reg)."""
    tok = tok.strip()
    return int(tok[1:]) if len(tok) > 1 and tok[0] in 'wx' and tok[1:].isdigit() else None


def _leading_materialized_bias(insns, lo: int, hi: int, value_reg: int) -> int:
    """Large index bias materialised in a register, then add/sub-ed INTO
    ``value_reg`` (the register the segment's ``cmp`` then tests), in
    ``insns[lo:hi]``; else 0.  The >4095 analytics/log enums (TODO #53) encode a
    sub-range bias this way because a 12-bit ``sub #imm`` cannot hold it:

      • ``mov/movn wRm, #-K ; add value_reg, wRn, wRm`` — NEGATIVE-ADD
        (``value + (-K)``); e.g. ``LogMessageType`` bias 50000 via
        ``mov w8,#-0xc350; add w8,w2,w8``.
      • ``movz/movk wRm, #K ; sub value_reg, wRn, wRm`` — materialised positive
        constant subtracted (same family; defensive).

    The result must land in ``value_reg`` (the gate's compared register), so a
    neighbouring segment's materialise+add — which targets a DIFFERENT register —
    cannot be mis-read as this segment's bias (that bug shifted low values like 9
    in the LogMsg* enums).  LAST match wins (nearest the gate).  Used ONLY by the
    jump-table segment path; the isolated-compare / cbz arms never bias their
    directly-materialised value."""
    bias = 0
    regvals: dict = {}   # reg token -> immediate from a recent mov/movz/movn
    for k in range(lo, hi):
        ins = insns[k]
        mn = ins.mnemonic
        ops = [o.strip() for o in ins.op_str.split(',')]
        if mn in ('mov', 'movz', 'movn') and len(ops) == 2 and ops[1].startswith('#'):
            try:
                regvals[ops[0]] = int(ops[1][1:], 0)
            except ValueError:
                pass
        elif mn in ('add', 'adds', 'sub', 'subs') and len(ops) == 3 \
                and not ops[2].startswith('#') and _regnum(ops[0]) == value_reg:
            rn, rm = ops[1], ops[2]
            cand = None
            if mn in ('add', 'adds'):          # value + (negative const) == value - K
                for r in (rm, rn):
                    v = regvals.get(r)
                    if v is not None and v < 0:
                        cand = -v
                        break
            else:                              # sub: value - (positive const)
                v = regvals.get(rm)
                if v is not None and v > 0:
                    cand = v
            if cand is not None and 0 < cand < _MATERIALIZED_BIAS_MAX:
                bias = cand
    return bias


def _field_routes_through_xasstring(cls, st, ivar_name: str) -> bool:
    """True if ``ivar_name``'s field has an ``xAsString:``/``StringAsX:`` selector.

    Such a field's enum is recovered (and bias-corrected) by the xAsString: path,
    so the dictRep harvester must NOT also apply a leading-sub bias to it — doing
    so would double-bias or mis-bias an enum the xAsString path already owns.
    This is the exact dictRep-vs-xAsString discriminator the #54 census used to
    isolate the 3 confirmed dictRep-only biased enums; checks both the resolved
    method list and the raw selector pool (cache-native runs may not name-resolve
    the method but the selector string is still in ``__objc_methname``)."""
    pname = _proto_name(ivar_name)
    if not pname:
        return False
    cap = pname[:1].upper() + pname[1:]
    for sel in (f"{pname}AsString:", f"StringAs{cap}:"):
        if cls.get_method(sel):
            return True
        if st is not None and st.find(sel):
            return True
    return False


# Unconditional terminals that END a jump-table case block — used to truncate the
# case-block disassembly so it never spills into the adjacent block in memory.
_CASE_TERMINALS = frozenset(('b', 'br', 'ret', 'retaa', 'retab', 'eret'))


def _iter_table_loads(window, words):
    """Yield ``(entry_width, base_reg, index_reg)`` for every register-offset table
    load (``ldrb/ldrh/ldr Wt,[Xbase,Widx]``) in *window*, decoded from the real load
    via :func:`_decode_ldr_reg_off`.  The two jump-table harvesters share this decode
    but collect it differently (a width-sorted list vs a base-keyed dict), so the
    iteration is factored out and the collection is left to each caller."""
    for ins in window:
        d = _decode_ldr_reg_off(words.get(ins.addr, 0))
        if d is not None:
            esz, rn, rm, _rt = d
            yield esz, rn, rm


def _read_case_string(ctx, case_target, *, max_insns: int = 6):
    """Disassemble a jump-table case block at *case_target*; return ``(name, insns)``.

    The block is TRUNCATED at its first unconditional terminal so a bare
    ``b tail_call`` case does not let ``disasm`` run linearly into the next case
    block in memory and mis-read THAT block's string — e.g. in
    ``-[GEOPDPlaceResponse statusAsString:]`` case 0 is a bare ``b`` (its value,
    STATUS_SUCCESS, is pre-loaded into x0), and without truncation disasm would
    read case 2's STATUS_INCOMPLETE and map it to value 0.  *name* is the first
    ``adrp+add x0`` cfstring in the truncated block, or ``None``; *insns* is
    returned so the caller can spot a bare-terminal block that should inherit a
    pre-loaded default string instead."""
    case_insns = []
    for ci in disasm(ctx, case_target, max_insns=max_insns):
        case_insns.append(ci)
        if ci.mnemonic in _CASE_TERMINALS:
            break
    # x0 first, callee-saved fallback (see _isolated_value_target's docstring
    # for why: real ARC codegen doesn't always land the return value in x0
    # directly).
    t = _isolated_value_target(case_insns)
    name = _read_enum_string(ctx, t) if t else None
    return name, case_insns


def _harvest_jumptable_segments(ctx, insns, words, add) -> bool:
    """Harvest pairs from dense sub-range JUMP-TABLE segments.

    Returns ``True`` when a confirmed ``adr+br`` segment (one that passed the
    range and table-base checks) contributed ZERO new values — the signature of a
    gate we could not attribute (e.g. a large negative-add bias the decoder does
    not yet model).  The caller surfaces it as ``values_truncated`` so the enum
    is flagged "may be INCOMPLETE" rather than silently short.


    Each segment is anchored by an ``adr Xb, #cases`` paired with a ``br Xb`` a
    few instructions later.  The table base (``ldrb``/``ldrh`` register-offset
    load → adrp+add) sits just before it; each table entry is followed to its
    case block to read the returned string.

    The ``cmp wN, #range`` gate (with optional ``sub #bias``) is attributed two
    ways.  **Idiom A** (linear fall-through) — ``cmp; b.hi/b.hs default; <table>``
    — is found by scanning backward from the ``adr``.  **Idiom B** (comparison
    tree) — a sparse method splits its value space with a binary search whose
    leaves are reached by ``cmp wN,#K; b.ls/b.lo <segment>``; here the gate is at
    the routing BRANCH, not immediately before the table.  Without idiom B the
    backward scan grabs the neighbouring fall-through gate and mis-biases the
    segment, so its values collide with another segment's and dedup-drop (e.g.
    GEOLogMsgState stateTypeAsString: silently lost stateType 401-407)."""
    seen_case_bases: Set[int] = set()

    # Idiom-B pre-scan: comparison-tree gates that route in-range values to a
    # segment via a forward conditional branch.  `cmp wN,#K; b.ls tgt` covers K+1
    # values (≤K); `b.lo/b.cc tgt` covers K (<K).  Map branch target → (range, bias).
    branch_gates: Dict[int, Tuple[int, int]] = {}
    for idx in range(len(insns) - 1):
        cmp = _decode_cmp_imm(words.get(insns[idx].addr, 0))
        if cmp is None:
            continue
        cmp_rn, imm = cmp
        if imm == 0 or imm > _SPARSE_MAX_RANGE:
            continue
        cond = _decode_bcond(words.get(insns[idx + 1].addr, 0))
        if cond == _COND_LS:
            rng = imm + 1
        elif cond == _COND_LO:
            rng = imm
        else:
            continue
        tgt = _bcond_branch_target(words.get(insns[idx + 1].addr, 0), insns[idx + 1].addr)
        if tgt is None:
            continue
        # Bias the same way Idiom A does (line ~573): a literal `sub #imm12`, or —
        # when the bias is too large for a 12-bit immediate — a value materialised
        # into the compared register via `mov #-K; add` / `movz; sub`.  Without the
        # materialised fallback a comparison-tree-routed high-value segment (e.g.
        # GEOTelemetricEntity.eventKeyAsString: values 60500+/52020+) gets bias 0,
        # collides with the low segments, and dedup-drops → seg_incomplete.  Safe by
        # the same value_reg-dest gate that protects Idiom A: a neighbour's add into
        # a different register cannot be mis-read as this segment's bias.
        branch_gates[tgt] = (rng, _sub_imm_bias(insns, words, max(0, idx - 4), idx,
                                                    first=False)
                             or _leading_materialized_bias(insns, max(0, idx - 4), idx,
                                                           cmp_rn))

    incomplete = False   # a confirmed segment we could not attribute → flag enum
    for i, ins in enumerate(insns):
        w = words.get(ins.addr, 0)
        adr_result = _decode_adr(w, ins.addr)
        if adr_result is None:
            continue
        _, case_base = adr_result
        if case_base in seen_case_bases:
            continue

        # Confirm: `br` within the next 5 instructions
        if not any(
            _is_br_insn(words.get(insns[j].addr, 0))
            for j in range(i, min(i + 6, len(insns)))
        ):
            continue
        seen_case_bases.add(case_base)

        bias = 0
        range_val = 0
        cmp_idx: int = -1   # instruction index that bounds the table-search window
        # Idiom B: this segment's setup (the few insns before the adr) is the
        # target of a routing branch — prefer its gate over the linear scan.
        gateB = next((branch_gates[ins.addr - off]
                      for off in (0, 4, 8, 12, 16)
                      if (ins.addr - off) in branch_gates), None)
        if gateB is not None:
            range_val, bias = gateB
            cmp_idx = i - 6          # table base sits just before the adr
        else:
            # Idiom A: scan backward for the fall-through CMP gate + SUB bias.
            for j in range(i - 1, max(i - 24, -1), -1):
                wj = words.get(insns[j].addr, 0)
                cmp = _decode_cmp_imm(wj)
                if cmp is None:
                    continue
                cmp_rn, imm = cmp
                if imm == 0 or imm > _SPARSE_MAX_RANGE:
                    break
                if j + 1 < len(insns):
                    wn = words.get(insns[j + 1].addr, 0)
                    range_val = range_from_unsigned_gate(_decode_bcond(wn), imm)
                # SUB nearest the CMP gives the index bias (last-in-window wins);
                # fall back to a register-materialised large bias (mov #-K; add /
                # movz; sub) landing in the compared register, for the >4095
                # analytics/log sub-ranges (TODO #53).
                bias = _sub_imm_bias(insns, words, max(0, j - 4), j, first=False) \
                    or _leading_materialized_bias(insns, max(0, j - 4), j, cmp_rn)
                cmp_idx = j
                break
        if range_val < 2 or range_val > _SPARSE_MAX_RANGE:
            continue

        # Find the jump-table byte array (ADRP+ADD in the window between the
        # CMP and the ADR — a wider window risks a previous segment's table).
        seg_start = max(0, cmp_idx)
        seg_insns = insns[seg_start: i + 2]
        # Principled table base (TODO #47): the register that is the BASE of
        # the scaled-index table read (`ldrb/ldrh Wt, [Xbase, Widx]`), decoded
        # from the actual load — NOT a register-priority guess.  Mirrors the
        # dictrep path (_decode_ldr_reg_off → adrp+add on that base); prefer the
        # narrowest read (byte table before halfword).  This REPLACES the former
        # x8..x14 priority scan: measured to resolve 100% of jump-table segments
        # across GeoServices/CLP/locationd (276/276), so the guess is removed
        # entirely.  A segment whose table read doesn't decode is skipped (no
        # silent wrong table), consistent with the function's other bail-outs.
        table_va: Optional[int] = None
        entry_sz = 1     # jump-table entry width in bytes (ldrb=1, ldrh=2)
        load_bases = [(esz, rn) for esz, rn, _ in _iter_table_loads(seg_insns, words)]
        for _esz, base_rn in sorted(load_bases):
            t = find_adrp_add_target(seg_insns, f"x{base_rn}")
            if t is not None:
                table_va = t
                entry_sz = _esz   # honour the ACTUAL width of the chosen table
                break
        if table_va is None:
            continue

        # Pre-loaded default: some jump-table methods set x0 to a default return
        # value BEFORE the dispatch, then let "fall-through" cases branch to the
        # tail call without overwriting x0 (statusAsString: case 0 = STATUS_SUCCESS
        # is a bare "b").  Detect that adrp+add x0 in seg_insns; a bare-terminal
        # case block with no string of its own inherits this pre-loaded string.
        pre_loaded_str: Optional[str] = None
        pre_loaded_target = find_adrp_add_target(seg_insns, 'x0')
        if pre_loaded_target is not None:
            pre_loaded_str = _read_enum_string(ctx, pre_loaded_target)

        seg_added = 0
        for k in range(range_val):
            try:
                # Read one entry at the table's ACTUAL width (ldrb→1, ldrh→2, ldrsw→4).
                # A halfword table read as bytes mis-strides every entry and
                # corrupts the whole enum (e.g. GEOTileSet styleAsString:, whose
                # 100-case block region exceeds 1 KB so offsets need 2 bytes).
                arm = jumptable_arm_target(
                    case_base, entry_sz, ctx.read_bytes(table_va + k * entry_sz, entry_sz))
                name, case_insns = _read_case_string(ctx, arm)
                if name:
                    seg_added += add(bias + k, name)
                elif (pre_loaded_str and len(case_insns) == 1
                      and case_insns[0].mnemonic in _CASE_TERMINALS):
                    seg_added += add(bias + k, pre_loaded_str)
            except (ValueError, IndexError):
                pass
        # A real jump-table segment always encodes ≥1 value.  Contributing none
        # means we mis-attributed its gate (wrong bias/range) → the enum may be
        # missing this segment's values.
        if seg_added == 0:
            incomplete = True

    return incomplete


def _isolated_value_target(ci) -> Optional[int]:
    """Resolve the ``adrp+add`` value address in a tiny (<=6-insn) isolated-case
    block, used by :func:`_harvest_isolated_compares`, :func:`_harvest_cbz_value0`,
    and :func:`_read_case_string` (the jump-table segment harvester's own
    per-case-block string reader) — the same register-uncertainty affects all
    three, since all three read a "compute this value and return/branch to
    shared exit" case block.

    Tries ``x0`` first (unchanged from before this helper existed — the value
    sits there directly for both the hand-written fixtures and the real
    ``locationd`` binary's ``ALSNearbyRequestTechnology``/``WifiGranularity``
    enums this harvester is verified against). Only if that fails does it
    fall back to the callee-saved range (``x19``-``x28``): real ARC-compiled
    code doesn't necessarily return the string straight into x0 — a plain
    ``return @"X";`` computes the value into a callee-saved register first so
    it survives the subsequent ``objc_autoreleaseReturnValue`` call, only
    moving it into x0 at the function's very end (confirmed via a genuinely
    Xcode-8/11-compiled isolated-compares probe this session: the value
    landed in x19, and `find_adrp_add_target(ci, 'x0')` alone found nothing).
    x0 is tried first and short-circuits, so every previously-matched case
    (including the real locationd binary) resolves identically to before —
    this is a pure widening, never a narrowing, of what can match."""
    t = find_adrp_add_target(ci, 'x0')
    if t is not None:
        return t
    for reg in sorted(_CALLEE_SAVED):   # deterministic order (frozenset is not)
        t = find_adrp_add_target(ci, reg)
        if t is not None:
            return t
    return None


def _harvest_isolated_compares(ctx, insns, words, add) -> None:
    """Harvest isolated single-value enum cases (``cmp + b.eq`` / ``cmp + b.ne``).

    Two compare forms feed this arm:
      • immediate  ``cmp wN, #imm12``  — values ≤ 4095 (12-bit immediate).
      • register   ``cmp wN, wReg``    — values > 4095: too large for the 12-bit
          immediate, so the compiler materialises the constant with
          ``movz wReg, #lo16``[``; movk wReg, #hi16, lsl #16``] and compares
          register-to-register.  Without this every enum value above 4095 (e.g.
          HKWorkout-derived motion-activity types) is dropped."""
    for i in range(len(insns) - 1):
        w0 = words.get(insns[i].addr, 0)
        w1 = words.get(insns[i + 1].addr, 0)
        cmp = _decode_cmp_imm(w0)
        if cmp is not None:
            _, imm = cmp
            if imm == 0 or imm > _SPARSE_MAX_RANGE:
                continue
        else:
            reg = _decode_cmp_reg(w0)
            if reg is None:
                continue
            _, rm = reg
            # Bound by the proto int32 range, NOT _SPARSE_MAX_RANGE — large
            # values are the entire reason this register arm exists.
            mval = _materialized_value(insns, words, i, rm)
            if mval is None or not (0 < mval < (1 << 31)):
                continue
            imm = mval
        cond = _decode_bcond(w1)
        if cond not in (_COND_EQ, _COND_NE):
            continue

        if cond == _COND_EQ:
            # String is at the b.eq branch target.
            string_va = _bcond_branch_target(w1, insns[i + 1].addr)
        else:
            # b.ne: string is at the fall-through (insns[i+2]).
            if i + 2 >= len(insns):
                continue
            string_va = insns[i + 2].addr

        try:
            ci = disasm(ctx, string_va, max_insns=6)
            t  = _isolated_value_target(ci)
            if t:
                s = _read_enum_string(ctx, t)
                if s:
                    # First preceding SUB gives the index bias.
                    bias = _sub_imm_bias(insns, words, max(0, i - 4), i,
                                             first=True)
                    add(bias + imm, s)
        except Exception:
            pass


def _harvest_cbz_value0(ctx, insns, words, add) -> None:
    """Harvest the value-0 case from a ``cbz``/``cbnz`` dispatch.

    The smallest enums compile to a compare-and-branch-zero for value 0 rather
    than ``cmp+b.eq``::

        cbz  w2, L0        ; value 0 → case block at L0
        cmp  w2, #1        ; value 1 handled by _harvest_isolated_compares
        b.ne default
        ...                ; value-1 string (fall-through)
      L0: adrp x0, ...     ; value-0 string

    ``cbz wN, L`` puts the value-0 case at L; ``cbnz wN, L`` makes value 0 the
    fall-through.  Without this the value-0 arm (commonly UNKNOWN) is missed,
    leaving a 2-value enum with <2 pairs → dropped entirely."""
    for i, ins in enumerate(insns):
        if ins.mnemonic not in ('cbz', 'cbnz'):
            continue
        target = _parse_imm(ins.op_str)
        if target is None:
            continue
        if ins.mnemonic == 'cbz':
            string_va = target
        elif i + 1 < len(insns):
            string_va = insns[i + 1].addr   # cbnz: value 0 falls through
        else:
            continue
        # A preceding SUB means the register tested for zero is biased, so
        # the original enum value is the bias (e.g. sub w8,w2,#1; cbz w8 → 1).
        bias = _sub_imm_bias(insns, words, max(0, i - 4), i, first=True)
        try:
            ci = disasm(ctx, string_va, max_insns=6)
            t  = _isolated_value_target(ci)
            if t:
                s = _read_enum_string(ctx, t)
                if s:
                    add(bias, s)
        except Exception:
            pass


def _detect_unreached_branch_gate(insns, words) -> bool:
    """True if the disassembled window stopped on a ``ret`` (not the budget
    cap) while a ``cmp+b.ls``/``b.lo`` gate inside it still points PAST the
    window's end — i.e. this method's own dispatch logic routes to a
    segment that was never actually disassembled, so
    :func:`_harvest_jumptable_segments` could not have seen it.

    This is the layout :func:`_extract_jumptable_enum_values`'s initial
    ``disasm(..., stop_at_ret=True)`` call is vulnerable to when a switch
    lowers to multiple jump-table segments and the compiler tail-duplicates
    each segment's own ``ret`` instead of funnelling every case to one
    shared epilogue. Confirmed to be a synthetic-toolchain-only artifact of
    this repo's installed Xcode (15.4 / clang 15.0.0), not something real
    binaries do: checked against the actual multi-cluster example named in
    :func:`_harvest_jumptable_segments`'s own docstring
    (`GEOTelemetricEntity.eventKeyAsString:`, 191 values/10+ clusters, via
    the real dyld shared cache in `iphone8_data/`) — every real segment
    ends in a plain `b <shared-epilogue>`, never its own early `ret`, and
    the 191/191 real values extract with an exact match against
    `tests/golden/GeoServices.json` (see
    tests/synthetic_fixtures/README.md). So this is forward-looking
    detection for a binary this repo hasn't seen yet, not a live gap in the
    current corpus. Detection only: does not attempt to disassemble the
    unreached segment."""
    if not insns or insns[-1].mnemonic not in _TERMINAL_MNEMONICS:
        return False
    window_end = insns[-1].addr
    for idx in range(len(insns) - 1):
        cmp = _decode_cmp_imm(words.get(insns[idx].addr, 0))
        if cmp is None:
            continue
        _, imm = cmp
        if imm == 0 or imm > _SPARSE_MAX_RANGE:
            continue
        cond = _decode_bcond(words.get(insns[idx + 1].addr, 0))
        if cond not in (_COND_LO, _COND_LS):
            continue
        tgt = _bcond_branch_target(words.get(insns[idx + 1].addr, 0), insns[idx + 1].addr)
        if tgt is not None and tgt > window_end:
            return True
    return False


def _detect_unrecovered_csel_chain(insns, words) -> bool:
    """True if the disassembly holds a ``cmp <value>; csel`` CHAIN (2 or more
    links) that none of the three harvesters above can decode.

    LLVM sometimes if-converts a small sparse-enum ``xAsString:`` into a
    branchless select DAG instead of the ``cmp+b.eq``/``cbz`` idiom
    :func:`_harvest_isolated_compares`/:func:`_harvest_cbz_value0` scan for::

        adrp x8,pageA; add x8,x8,#offA   ; candidate string A
        cmp w2,#imm1
        csel x8,x8,xzr,eq                ; first link
        adrp x9,pageB; add x9,x9,#offB   ; candidate string B
        cmp w2,#imm2
        csel x0,x9,x8,eq                 ; second link, chains onto x8

    This shape is REAL — confirmed via a real ``locationd`` binary's
    ``ALSNearbyRequestTechnology``/``WifiGranularity`` enums compiling to
    genuine branches on one Apple-internal toolchain, but this repo's
    installed Xcode (15.4 / clang 15.0.0) reliably csel-folds the same
    source instead (see tests/synthetic_fixtures/README.md's "isolated-
    compares" finding) — so a binary built with whichever toolchain does
    fold will hit exactly this gap. No decoder for the chain exists yet
    (see the README); this is DETECTION only, so a caller with pairs
    already recovered from elsewhere can flag the enum as possibly
    incomplete rather than reporting a short list as if it were complete.

    Requires >=2 links (an actual CHAIN) rather than firing on any lone
    ``cmp+csel`` pair, which is common in unrelated ARC/bounds-check code
    with nothing to do with an enum's value table — keeps this conservative
    against false positives in ordinary compare-then-select logic."""
    links = 0
    for i in range(len(insns) - 1):
        if insns[i + 1].mnemonic != 'csel':
            continue
        w = words.get(insns[i].addr, 0)
        cmp = _decode_cmp_imm(w)
        if cmp is None:
            cmp = _decode_cmp_reg(w)
        if cmp is None:
            continue
        _, val = cmp
        if val == 0 or val > _SPARSE_MAX_RANGE:
            continue
        links += 1
        if links >= 2:
            return True
    return False


def _valid_value_bitmask(insns: List[Insn]) -> Optional[int]:
    """The validity bitmask of a sparse-enum pointer table, or None.

    The newer toolchain gates a pointer table that has HOLES (values the enum does not
    declare) with a constant bitmask instead of a dense range::

        cmp  w2,#0x1c ; b.hi default
        mov  w8,#0x7fff ; movk w8,#0x1fff,lsl #16     ; mask = 0x1fff7fff
        lsr  w8,w8,w2 ; tbz w8,#0,default             ; bit v clear -> not a value
        ldr  x0,[x8,w2,uxtw #3]

    The holes' table slots are empty, so reading the table until the first empty slot (as
    for a dense table) stopped at the first hole.  Returns the mask (bit v set = value v
    is declared) when the ``lsr`` + ``tbz #0`` gate is present."""
    consts: Dict[int, int] = {}                # register number -> constant built so far
    for i, ins in enumerate(insns):
        ops = split_ops(ins.op_str)
        if ins.mnemonic in ('mov', 'movz') and len(ops) == 2 and ops[1].startswith('#'):
            r, v = _regnum(ops[0]), _parse_imm(ops[1])
            if r is not None and v is not None:
                consts[r] = v
        elif ins.mnemonic == 'movk' and len(ops) == 3 and ops[2].startswith('lsl'):
            r, v, sh = _regnum(ops[0]), _parse_imm(ops[1]), _parse_imm(ops[2].split()[-1])
            if r is not None and v is not None and sh is not None and r in consts:
                consts[r] = (consts[r] & ~(0xFFFF << sh)) | (v << sh)
        elif ins.mnemonic == 'lsr' and len(ops) == 3 and i + 1 < len(insns):
            src, dst = _regnum(ops[1]), _regnum(ops[0])
            nxt = insns[i + 1]
            nops = split_ops(nxt.op_str)
            if (src in consts and nxt.mnemonic == 'tbz' and len(nops) == 3
                    and _regnum(nops[0]) == dst and _parse_imm(nops[1]) == 0):
                return consts[src]
    return None


def _try_pointer_table_in(
    ctx: BinaryContext,
    imp: int,
    insns: List[Insn],
    words: Dict[int, int],
) -> Tuple[List[Tuple[int, str]], bool]:
    """Read a scaled-index POINTER TABLE (``ldr xT,[xB,wI,sxtw #3]``) directly
    out of an ALREADY-DISASSEMBLED instruction list, rather than a fresh short
    probe from *imp*.

    This is :func:`_extract_enum_values`' primary-branch decode (same
    ``_decode_ldr_reg_off``-based technique :func:`_harvest_dictrep_enums`'
    pointer-table idiom already uses), reused here for one specific case:
    :func:`_extract_jumptable_enum_values`' TODO #58 extent-recompute
    fallback can hand back a body whose real dispatch is a POINTER TABLE, not
    a jump-table/segment shape — e.g. a long ``xAsString:`` body (found via
    f21_enum_long_body_extent) whose padding pushes the table past BOTH
    :func:`_extract_enum_values`' cheap 80-insn window and
    :func:`_find_field_count`'s 256-raw-word cmp-gate scan when anchored at
    *imp*.  Re-anchoring both scans near the LOCATED load (instead of *imp*)
    fixes that without duplicating the read logic.

    Returns ``(pairs, confirmed)``.  Mirrors :func:`_extract_enum_values`'
    own primary-path return exactly: *confirmed* is True only when every
    entry up to the gate's own count (``max_val``, from the re-anchored
    :func:`_find_field_count`) was read cleanly — the same
    ``len(pairs) == max_val`` cross-check, just computed against the
    re-anchored count instead of one taken at *imp*.  ``([], False)`` when no
    such load is present, or the table read comes back empty (never raises —
    mirrors the primary branch's own failure handling).
    """
    for ins in insns:
        d = _decode_ldr_reg_off(words.get(ins.addr, 0))
        if d is None or d[0] != 8:        # need a 64-bit (pointer) scaled load
            continue
        table_va = find_adrp_add_target(insns, f"x{d[1]}")
        if table_va is None:
            continue
        # Re-anchor both raw-word scans near the LOCATED load rather than
        # *imp* — the function start is potentially thousands of instructions
        # away (that's exactly why this path is reached at all).  24 words
        # covers the `sub(bias)/cmp/b.hi/adrp/add/ldr` idiom with margin;
        # any padding in between is harmless (neither cmp nor sub matches it).
        gate_scan_start = ins.addr - 24 * 4
        max_val = _find_field_count(ctx, gate_scan_start)
        if max_val <= 0 or max_val > _SPARSE_MAX_RANGE:
            continue
        bias = _find_index_bias(ctx, gate_scan_start)
        pairs: List[Tuple[int, str]] = []
        for i in range(max_val):
            try:
                ptr = ctx.read_ptr(table_va + i * 8)
                name = _read_enum_string(ctx, ptr)
            except (ValueError, UnicodeDecodeError):
                break
            if name is None:
                break
            pairs.append((i + bias, name))
        if pairs:
            return pairs, (len(pairs) == max_val)
    return [], False


def _extract_jumptable_enum_values(
    ctx: BinaryContext,
    imp: int,
    st: StringTable,
) -> Tuple[List[Tuple[int, str]], bool, bool]:
    """
    Extract ``(int_value, string_name)`` pairs from a **jump-table** implementation
    of an ``xAsString:`` method.

    LLVM compiles sparse enums (few defined values spread over a larger range)
    into dense sub-range jump tables — a single method may hold multiple such
    segments (one per contiguous block of valid values) plus isolated
    ``cmp+b.eq``/``cmp+b.ne`` checks and a ``cbz`` special case for value 0.
    Each concern is harvested independently against the same disassembly; see
    :func:`_harvest_jumptable_segments`, :func:`_harvest_isolated_compares`, and
    :func:`_harvest_cbz_value0` for the exact idioms each recognises.

    Returns ``(pairs, confirmed, truncated)``.  *confirmed* is always False
    (gap entries — undefined enum values — are silently skipped).  *truncated*
    is True when the method body overran the disassembly budget, so *pairs* may
    be missing high values (surfaced as an "may be INCOMPLETE" comment rather
    than a silent short enum).
    """
    if imp == 0:
        return [], False, False

    # [cap:WARNING-ONLY — re-measured 2026-06-13] The jump-table enum-value harvest
    # budget.  EARLIER PREMISE ("past insn 1000 the enum ends up SHORT; raise it to
    # recover values") is FALSE and was MEASURED to be false — do NOT re-attempt the
    # bump:
    #   • Swept 1000 → 4000 → 30000 over GeoServices (752 enums, 14900 values).
    #     Recovered enum values were IDENTICAL at every cap (0 enums gained a single
    #     value).  All harvestable (value,name) pairs live in the first ~1000 insns;
    #     the rest of each xAsString: body is dispatch/default/formatting code with
    #     no further pairs.
    #   • What the cap DOES change is only the WARNING count, not the data: of the 17
    #     "may be INCOMPLETE" flags at 1000, 16 are `_disasm_truncated` FALSE ALARMS
    #     (the LogMsg-family methods are ~11.9k insns, so they just hadn't reached
    #     `ret` by 1000 — every value was already captured).  Raising to 30000 lets
    #     them close on `ret`, dropping the count to 10; the 10 residual flags are all
    #     `seg_incomplete` DECODER GAPS (a confirmed segment that contributed 0 values,
    #     see _harvest_jumptable_segments) which NO budget can fix.
    #   • Cost of 30000 vs 1000: +7% wall (101.6s→108.9s), RSS flat — mild, not "a lot".
    # So this cap does NOT affect the recovered descriptor's values, only whether a
    # (mostly false-alarm) warning fires.  TODO #58 (DONE, below): keep the cheap 1000
    # probe but, when it doesn't close on `ret`, recompute the body by its FUNCTION
    # EXTENT (_function_body_extent) so _disasm_truncated fires only on a genuine
    # overrun — killing the 16 false alarms with 0 value change.  Real missing values
    # (if any) are the `seg_incomplete` cases, a decoder problem (closed for the negadd
    # idiom by #53).  Full sweep + methodology in SCAN_CAP_CONSTANTS_ANALYSIS.md.
    _SPARSE_MAX_INSNS = 1000   # cheap probe; all harvestable pairs land well within it

    try:
        insns = disasm(ctx, imp, max_insns=_SPARSE_MAX_INSNS)
        if not insns:
            return [], False, False
        truncated = _disasm_truncated(insns, _SPARSE_MAX_INSNS)

        # [TODO #58] The probe ran out of budget before the method's `ret` — but a long
        # method is not necessarily an INCOMPLETE one (the LogMsg-family xAsString:
        # bodies are ~12k insns yet hold every value in the first ~1000).  Recompute the
        # body by its true function extent so the truncation signal reflects the method's
        # real boundary, not a magic count.  SOUND here: xAsString: jump-table methods are
        # CONTIGUOUS (verified byte-identical output across all 752 GeoServices enums), so
        # the extent sweep never over-reads into foreign code — UNLIKE the outlined
        # writeTo: family, for which _function_body_extent must NOT be used.  Done only on
        # a truncated probe, so the 736 methods that close by 1000 pay nothing.
        if truncated:
            body = _function_body_extent(ctx, imp, _SPARSE_HARD_CAP)
            if body:
                insns = body
                truncated = _disasm_truncated(insns, _SPARSE_HARD_CAP)

        # Pre-cache raw words for every instruction address
        words: Dict[int, int] = {}
        for ins in insns:
            w = _read_raw_word(ctx, ins.addr)
            if w is not None:
                words[ins.addr] = w

        all_pairs: List[Tuple[int, str]] = []
        seen_values: Set[int] = set()

        def _add(val: int, name: str) -> bool:
            if val not in seen_values and _is_valid_enum_string(name):
                seen_values.add(val)
                all_pairs.append((val, name))
                return True
            return False

        # Three independent sparse-enum passes over the same disassembly, each
        # adding (value, name) via the shared `_add` callback.  The segment pass
        # reports whether a confirmed segment was left unattributed (contributed
        # no values) → flag the enum INCOMPLETE so the user is warned.
        seg_incomplete = _harvest_jumptable_segments(ctx, insns, words, _add)
        _harvest_isolated_compares(ctx, insns, words, _add)
        _harvest_cbz_value0(ctx, insns, words, _add)

        # A method-internal gate routes to a segment past where the window
        # stopped (on `ret`, not the budget cap) — that segment's values,
        # if any, were never seen by any harvester above, regardless of how
        # many pairs the REACHED segments already contributed (see
        # _detect_unreached_branch_gate's docstring: this is the one real
        # shape that can make a partial recovery look complete).
        unreached_gate = _detect_unreached_branch_gate(insns, words)
        if unreached_gate:
            log.debug(
                "Enum extraction at 0x%x: a branch gate targets an address "
                "past the disassembled window (stopped on ret) — a "
                "jump-table segment may have been missed", imp)
        truncated = truncated or seg_incomplete or unreached_gate

        if len(all_pairs) < 2:
            # Nothing recovered by any branch/jump-table harvester — before
            # reporting a clean empty enum, try reading this AS a POINTER
            # TABLE (see _try_pointer_table_in's docstring: TODO #58's
            # extent-recompute can hand back a body whose real dispatch is
            # _extract_enum_values' primary-branch shape, which none of the
            # three harvesters above understand). `ptr_confirmed` is the same
            # len(pairs)==max_val cross-check _extract_enum_values' own
            # primary path returns — a direct memory read, so trustworthy on
            # the same terms, not weaker just because it took this path.
            ptr_pairs, ptr_confirmed = _try_pointer_table_in(ctx, imp, insns, words)
            if ptr_pairs:
                ptr_pairs.sort(key=lambda p: p[0])
                return ptr_pairs, ptr_confirmed, False
            # Still nothing — check for the one real shape none of the above
            # can decode: a branchless csel-chain (see
            # _detect_unrecovered_csel_chain's docstring). Only affects
            # methods that would otherwise return an unflagged empty enum —
            # cannot change output for any method that already recovers >=2
            # pairs, so this is a pure incompleteness-visibility addition.
            if _detect_unrecovered_csel_chain(insns, words):
                log.debug(
                    "Enum extraction at 0x%x: found a csel-chain shape "
                    "(cmp+csel, >=2 links) with no decodable pairs — "
                    "values likely exist but are not recoverable by the "
                    "current branch-based harvesters", imp)
                return [], False, True
            return [], False, truncated

        all_pairs.sort(key=lambda x: x[0])
        return all_pairs, False, truncated

    except (NameError, ImportError):
        raise   # wiring/refactor bug — surface, don't mask as "extraction failed"
    except Exception as exc:
        log.debug("Jump-table enum extraction failed at 0x%x: %s", imp, exc)
        return [], False, False


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


def _block_adrp_add_target_in(
    ctx: BinaryContext, insns: list, segname: str, sectname: str
) -> Optional[int]:
    """Return the adrp+add target that lands inside the given section, scanning
    in INSTRUCTION order (earliest pair wins), or None.

    Instruction order matters: a fall-through value case block loads its value
    string first (``adrp/add x22, <value>``) and then runs into the merge block
    which loads the dictionary KEY (``adrp/add x3, <key>``).  A register-ordered
    scan would return the lower-numbered key register; the instruction-ordered
    scan correctly returns the value loaded first."""
    if not ctx.has_section(segname, sectname):
        return None
    sec = ctx.section(segname, sectname)
    lo, hi = sec.vmaddr, sec.vmaddr + sec.vmsize
    pending: Dict[str, int] = {}
    for ins in insns:
        if ins.mnemonic == 'adrp':
            pa = parse_adrp(ins.op_str)
            if pa is not None:
                pending[pa[0]] = pa[1]
        elif ins.mnemonic == 'add':
            ap = split_ops(ins.op_str)
            if len(ap) >= 3:
                r = _norm_reg(ap[0])
                if r is not None and r == _norm_reg(ap[1]) and r in pending:
                    off = _parse_imm(ap[2])
                    if off is not None and lo <= pending[r] + off < hi:
                        return pending[r] + off
    return None


def _block_cfstring_target(
    ctx: BinaryContext, insns: list
) -> Optional[int]:
    """First adrp+add target (any GPR) pointing into the cfstring section.

    Shared-cache-extracted dylibs normally place ``__cfstring`` in
    ``__DATA_CONST``; an arm64e cache (e.g. the macOS system cache) instead
    places it in ``__AUTH_CONST`` (mirrors the section search in
    :func:`_read_enum_string`).  Both are tried, first match wins."""
    for segname in ("__DATA_CONST", "__AUTH_CONST"):
        target = _block_adrp_add_target_in(ctx, insns, segname, "__cfstring")
        if target is not None:
            return target
    return None


def _last_ivar_offset_in_window(
    ctx: BinaryContext, win: list
) -> Optional[int]:
    """Return the byte offset value referenced by the LAST ``adrp+ldrsw`` pair in
    *win* (the ivar-offset global feeding the switch), or None.

    Each enum switch is immediately preceded by loading its field's ivar-offset
    variable via ``adrp Xn,#page; ldrsw Xn,[Xn,#off]``; the slot at ``page+off``
    holds the ivar byte offset.  Taking the closest such pair before the dispatch
    selects this field's ivar (earlier pairs load the has-bits ``_flags`` ivar)."""
    pages: Dict[str, int] = {}
    last_slot: Optional[int] = None
    for ins in win:
        if ins.mnemonic == 'adrp':
            pa = parse_adrp(ins.op_str)
            if pa is not None:
                pages[pa[0]] = pa[1]
        elif ins.mnemonic == 'ldrsw':
            mo = mem_operand(ins.op_str)        # immediate/no-offset form only
            if mo is not None and mo[2] is None and mo[1] in pages:
                last_slot = pages[mo[1]] + mo[3]
    if last_slot is None:
        return None
    try:
        return ctx.read_s32(last_slot)
    except (ValueError, KeyError):
        return None


def _ivar_offset_lookups(
    ctx: BinaryContext, insns: list
) -> List[Tuple[int, int]]:
    """Return ``[(insn_index, ivar_byte_offset), …]`` for every ivar-offset-
    variable load in *insns*: ``adrp Xn,#page; ldrsw Xm,[Xn,#off]`` where the
    slot at ``page+off`` holds a field's ivar byte offset (see
    :func:`_last_ivar_offset_in_window`).  ``insn_index`` is the ``ldrsw``.

    Unlike :func:`_last_ivar_offset_in_window` the ``adrp`` need not lie
    inside the same window as the ``ldrsw`` — a compiler may hoist one page
    register across several lookups."""
    out: List[Tuple[int, int]] = []
    for i, slot in ivar_slot_loads(insns):
        try:
            out.append((i, ctx.read_s32(slot)))
        except (ValueError, KeyError):
            pass
    return out


def _longest_common_prefix(strs: List[str]) -> str:
    """Return the longest common character prefix of *strs* (``""`` if none)."""
    if not strs:
        return ""
    pre = strs[0]
    for s in strs[1:]:
        while not s.startswith(pre):
            pre = pre[:-1]
            if not pre:
                return ""
    return pre


def _read_dictrep_switch_pairs(
    ctx: BinaryContext,
    case_base: int,
    table_va: int,
    entry_size: int,
    range_val: int,
    default_name: Optional[str],
) -> Tuple[List[Tuple[int, str]], Optional[int]]:
    """Walk a dictRep jump table and return ``(pairs, merge_target)``.

    ``case_target = case_base + table[value] * 4`` (a 4-byte ``ldrsw`` entry is instead
    a signed byte delta, unscaled — :func:`macho.arm64decode.jumptable_arm_target`).  Gap values and the default
    all route to one shared merge block (the most common table entry); those are
    identified by that modal entry and skipped — every other value has its own
    case block whose first ``adrp+add`` cfstring is its name.  The lowest
    merge-routed value (usually 0) inherits *default_name*, but only when it
    shares the value names' common prefix, which rejects the dictionary-key
    string (e.g. the field name ``"status"``) picked up at the merge block.

    ``merge_target`` (the convergence address shared by the case blocks) is also
    returned so the caller can bound an isolated-comparison scan for sparse
    high values."""
    # Read the whole index table first so the shared merge target can be found.
    entries: List[int] = []        # arm ADDRESSES, one per value (modal one = default)
    for v in range(range_val):
        try:
            raw = ctx.read_bytes(table_va + v * entry_size, entry_size)
        except (ValueError, IndexError):
            break
        entries.append(jumptable_arm_target(case_base, entry_size, raw))
    if len(entries) < 2:
        return [], None

    # Two targets carry no value string: the explicit default block shared by
    # the in-range gap values (the modal entry, count ≥ 2) and the merge block
    # that value 0 routes to directly (UNKNOWN is pre-loaded).  The merge block
    # loads the dictionary KEY, so reading a string there yields the field name
    # — both must be excluded.  The merge address is the unconditional-branch
    # target of any real case block.
    counts = Counter(entries)
    modal_entry, modal_count = counts.most_common(1)[0]
    default_entry = modal_entry if modal_count >= 2 else None

    # Read each case block up to its OWN terminal instruction (same idiom as
    # _read_case_string below), not a fixed instruction count: a case block
    # is exactly as long as it needs to be -- e.g. it may reload the
    # dictionary KEY string (a second adrp+add) before the merge branch, on
    # top of the VALUE cfstring's own adrp+add, so a block can legitimately
    # run to 5+ instructions. A hardcoded small cap (this used max_insns=4)
    # can cut off before reaching the block's own `b`, silently returning
    # merge_target=None even though the block ends in a perfectly ordinary
    # branch -- found via f19_enum_dictrep_switch's real compiled `category`
    # field, whose case blocks are genuinely 5 instructions long. max_insns
    # here is now just a generous safety cap, not the actual stop condition.
    merge_target: Optional[int] = None
    for entry in entries:
        if entry == default_entry:
            continue
        try:
            blk0 = disasm(ctx, entry, max_insns=8)
        except Exception:
            continue
        for ci in blk0:
            if ci.mnemonic in _CASE_TERMINALS:
                if ci.mnemonic == 'b':
                    merge_target = _parse_imm(ci.op_str)
                break
        if merge_target is not None:
            break

    named: List[Tuple[int, str]] = []
    seen: Set[int] = set()
    default_idx: Optional[int] = None
    for v, entry in enumerate(entries):
        case_target = entry
        if entry == default_entry or case_target == merge_target:
            if default_idx is None:
                default_idx = v
            continue
        try:
            # A real case block is `adrp/add Xr, <value cfstring>` then either a
            # `b merge` or a fall-through into the merge; the value string is the
            # FIRST adrp+add, so a short window suffices and avoids the merge key.
            blk = disasm(ctx, case_target, max_insns=4)
        except Exception:
            continue
        cf = _block_cfstring_target(ctx, blk)
        if cf is not None:
            name = _read_enum_string(ctx, cf)
            if name and v not in seen:
                seen.add(v)
                named.append((v, name))

    # Value 0 / first merge-routed value inherits the pre-loaded default string,
    # but only when it shares the *dominant* first-segment prefix of the named
    # values (guards against dict-key contamination — the field-name string used
    # as the dictionary key).  A dominant prefix (rather than the strict longest
    # common prefix) tolerates an odd value name that breaks the LCP, e.g. a
    # ``STATUS_*`` enum that also contains ``INVALID_REQUEST`` still admits
    # ``STATUS_SUCCESS`` as value 0.
    if (default_idx is not None and default_name
            and default_idx not in seen and len(named) >= 2):
        seg_counts: "Counter[str]" = Counter()
        for _, n in named:
            sep = n.find('_')
            if sep > 0:
                seg_counts[n[:sep]] += 1
        dom = seg_counts.most_common(1)[0][0] if seg_counts else ''
        if len(dom) >= 3 and default_name.startswith(dom):
            named.append((default_idx, default_name))

    named.sort(key=lambda p: p[0])
    return named, merge_target


def _read_dictrep_pointer_pairs(
    ctx: BinaryContext, table_va: int, range_val: int,
) -> List[Tuple[int, str]]:
    """Read a dictRep *pointer* table and return ``(value, name)`` pairs.

    Unlike the jump-table form, some enum fields are serialised as a direct
    pointer table::

        cmp  wN, #range ; b.hs default          ; out-of-range → "(unknown: %i)"
        adrp xT, page ; add xT, #off             ; table base
        ldr  xR, [xT, wN, lsl #3]                ; table[value] = CFStringRef*

    Each 8-byte entry is a (chained-fixup) pointer straight to the value's
    CFStringRef, so every in-range value is named — there are no gaps or a
    pre-loaded default to reconcile."""
    pairs: List[Tuple[int, str]] = []
    seen: Set[int] = set()
    for v in range(range_val):
        try:
            ptr = ctx.read_ptr(table_va + v * 8)
        except (ValueError, KeyError):
            break
        if not ptr:
            continue
        name = _read_enum_string(ctx, ptr)
        if name and v not in seen:
            seen.add(v)
            pairs.append((v, name))
    pairs.sort(key=lambda p: p[0])
    return pairs


def _scan_dictrep_isolated_cmps(
    ctx: BinaryContext, insns: list, words: Dict[int, int],
    value_reg: int, start_idx: int, end_addr: int,
) -> List[Tuple[int, str]]:
    """Recover sparse enum values encoded as isolated ``cmp wV,#K`` + ``b.eq``/
    ``b.ne`` comparisons rather than dense jump-table entries.

    Apple emits these for the high, sparse values of a status enum (e.g.
    ``ComponentStatus`` 20/30/40/50/60) alongside a small jump table for the
    dense low range.  For ``b.eq`` the value string is at the branch target; for
    ``b.ne`` it is at the fall-through.  Only comparisons on *value_reg* (the
    field's value register) within ``[start_idx, end_addr)`` are considered, and
    the target block must carry its own cfstring — so range-split guards
    (``b.gt``/``b.hi``) and unrelated comparisons are ignored."""
    pairs: List[Tuple[int, str]] = []
    seen: Set[int] = set()
    for j in range(start_idx, len(insns)):
        if insns[j].addr >= end_addr:
            break
        cmp = _decode_cmp_imm(words.get(insns[j].addr, 0))
        if cmp is None:
            continue
        reg, imm = cmp
        if reg != value_reg or imm <= 0 or imm > _SPARSE_MAX_RANGE:
            continue
        if j + 1 >= len(insns):
            continue
        cond = _decode_bcond(words.get(insns[j + 1].addr, 0))
        if cond == _COND_EQ:
            blk_addr = _bcond_branch_target(words.get(insns[j + 1].addr, 0),
                                            insns[j + 1].addr)
        elif cond == _COND_NE:
            if j + 2 >= len(insns):
                continue
            blk_addr = insns[j + 2].addr
        else:
            continue
        try:
            blk = disasm(ctx, blk_addr, max_insns=4)
        except Exception:
            continue
        cf = _block_cfstring_target(ctx, blk)
        if cf is None:
            continue
        name = _read_enum_string(ctx, cf)
        if name and imm not in seen:
            seen.add(imm)
            pairs.append((imm, name))
    return pairs


def _dictrep_cmp_range(
    insns: list, words: Dict[int, int], dispatch_idx: int,
) -> int:
    """Scan back from *dispatch_idx* for the ``cmp wN, #K`` + ``b.hi``/``b.hs``
    gate and return the entry count (``K+1`` for HI, ``K`` for HS), or 0."""
    for j in range(dispatch_idx - 1, max(dispatch_idx - 16, -1), -1):
        cmp = _decode_cmp_imm(words.get(insns[j].addr, 0))
        if cmp is None:
            continue
        _, imm = cmp
        if imm <= 0 or imm > _SPARSE_MAX_RANGE:
            return 0
        nb = (_decode_bcond(words.get(insns[j + 1].addr, 0))
              if j + 1 < len(insns) else None)
        return range_from_unsigned_gate(nb, imm)
    return 0


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
    ctx: BinaryContext, cls: ObjcClass, st: Optional[StringTable]
) -> Dict[int, List[Tuple[int, str]]]:
    """Extract switch-table enums from ``-[cls _dictionaryRepresentation:]``.

    Returns ``{ivar_offset: [(value, name), …]}`` for each enum field whose
    int→name map is recovered.  Empty when the method is absent or has no
    recoverable switches."""
    result: Dict[int, List[Tuple[int, str]]] = {}
    imp = _find_dictrep_c_func(ctx, cls)
    if imp is None:
        return result
    try:
        insns = disasm(ctx, imp, max_insns=_DICTREP_PROBE_INSNS)
    except Exception:
        return result
    if not insns:
        return result

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

    words: Dict[int, int] = {}
    for ins in insns:
        w = _read_raw_word(ctx, ins.addr)
        if w is not None:
            words[ins.addr] = w

    valid_offsets = {iv.offset for iv in cls.ivars}

    for i, ins in enumerate(insns):
        adr = _decode_adr(words.get(ins.addr, 0), ins.addr)
        if adr is None:
            continue
        _, case_base = adr
        # Confirm a `br` within the next few instructions (jump-table dispatch).
        if not any(
            _is_br_insn(words.get(insns[j].addr, 0))
            for j in range(i, min(i + 6, len(insns)))
        ):
            continue

        win = insns[max(0, i - 20): i + 2]

        # CMP gate → range (number of table entries); record its index so the
        # default-string search can be confined to the tight pre-dispatch region.
        range_val = 0
        cmp_idx = -1
        for j in range(i - 1, max(i - 16, -1), -1):
            cmp = _decode_cmp_imm(words.get(insns[j].addr, 0))
            if cmp is None:
                continue
            _, imm = cmp
            if imm <= 0 or imm > _SPARSE_MAX_RANGE:
                break
            nb = (_decode_bcond(words.get(insns[j + 1].addr, 0))
                  if j + 1 < len(insns) else None)
            range_val = range_from_unsigned_gate(nb, imm)
            cmp_idx = j
            break
        if range_val < 2 or range_val > _SPARSE_MAX_RANGE:
            continue

        # ivar offset feeding the switch (association key)
        ivar_off = _last_ivar_offset_in_window(ctx, win)
        if ivar_off is None or ivar_off not in valid_offsets:
            continue
        if ivar_off in result:
            continue

        # Pre-loaded default/UNKNOWN string: the cfstring loaded in the tight
        # region between the CMP gate and the dispatch (avoids the earlier
        # dictionary-key cfstring for this field).
        tight = insns[cmp_idx: i + 1] if cmp_idx >= 0 else win
        cf_def = _block_cfstring_target(ctx, tight)
        default_name = _read_enum_string(ctx, cf_def) if cf_def is not None else None

        # Resolve the true entry width from the register-offset table load
        # (ldrb→1, ldrh→2): map each load's base register to (width, index_reg).
        # The index register is the field's value register — needed for the
        # isolated-comparison scan below.
        load_info: Dict[int, Tuple[int, int]] = {
            rn: (esz, rm) for esz, rn, rm in _iter_table_loads(win, words)}

        # The table base is an adrp+add target whose register also serves as the
        # base of a register-offset load (the table read); its width gives the
        # entry size unambiguously — no guessing.
        best: List[Tuple[int, str]] = []
        best_merge: Optional[int] = None
        best_vreg: Optional[int] = None
        # Anchor on the registers that ACTUALLY serve as a table-load base (from
        # load_info), rather than scanning every register: each such base — with
        # its decoded entry width and index (value) register — is a concrete
        # table candidate, and its adrp+add target is the table base.  (Sorted by
        # register number so ties resolve to the lowest, matching the prior
        # x0..x28 scan order.)
        for base_rn, (esize, vreg) in sorted(load_info.items()):
            if esize not in (1, 2, 4):     # ldrb / ldrh / ldrsw tables (ldr x = pointer table)
                continue
            table_va = find_adrp_add_target(win, f"x{base_rn}")
            if table_va is None or table_va == cf_def:
                continue
            pr, mt = _read_dictrep_switch_pairs(
                ctx, case_base, table_va, esize, range_val, default_name)
            if len(pr) > len(best):
                best, best_merge, best_vreg = pr, mt, vreg
        if len(best) >= 2:
            # NOTE (TODO #54): the jump-table path deliberately does NOT apply a
            # leading-sub bias.  A bias here is only correct for a DENSE 0-based
            # table; but `best_vreg` is a low register (x8…) that the 20-instruction
            # window reuses across several fields, so a neighbour's `sub #imm` passes
            # the dest-register gate and wrongly shifts SPARSE enums (observed live on
            # GeoServices: PlaceTypeHint/PlaceTypeLimit shifted +35, LaneClosureType
            # +1).  The window-bleed guard that suffices for the pointer-table idiom
            # below is not tight enough here, and no confirmed biased enum uses this
            # path — the 3 known cases are all pointer-table.  Left unbiased on
            # purpose; revisit only with a dominator-scoped sub search.
            # Sparse high values may be encoded as isolated cmp+b.eq/b.ne
            # comparisons between the dispatch and the merge block.
            if best_merge is not None and best_vreg is not None:
                have = {v for v, _ in best}
                for v, nm in _scan_dictrep_isolated_cmps(
                        ctx, insns, words, best_vreg, i, best_merge):
                    if v not in have:
                        best.append((v, nm))
                        have.add(v)
                best.sort(key=lambda p: p[0])
            result[ivar_off] = best

    # ── Pointer-table dispatch (e.g. CacheControlType) ────────────────────────
    # A second idiom loads the value string directly from an 8-byte pointer table
    # (`ldr xR, [table, value, lsl #3]`) instead of jumping to a per-value code
    # block.  Anchor on that 64-bit register-offset load.
    for i, ins in enumerate(insns):
        d = _decode_ldr_reg_off(words.get(ins.addr, 0))
        if d is None or d[0] != 8:        # need a 64-bit (pointer) load
            continue
        _esz, rn, idx_reg, _rt = d        # idx_reg = the value register feeding the table

        range_val = _dictrep_cmp_range(insns, words, i)
        # Upper bound is the 12-bit cmp-immediate ceiling (#59): the range comes
        # from the same `cmp wN,#imm12; b.hi` gate the jump-table path uses, so a
        # pointer table is structurally bounded by 2^12, not a tuned 512.  The
        # route itself is by STRUCTURE (the 64-bit scaled load above), so a larger
        # bound only lets a genuinely-dense pointer-table enum be read in full.
        if range_val < 2 or range_val > _SPARSE_MAX_RANGE:
            continue

        lo = max(0, i - 16)
        win = insns[lo: i + 1]
        ivar_off = _last_ivar_offset_in_window(ctx, win)
        if ivar_off is None or ivar_off not in valid_offsets or ivar_off in result:
            continue

        table_va = find_adrp_add_target(win, f"x{rn}")
        if table_va is None:
            continue

        pairs = _read_dictrep_pointer_pairs(ctx, table_va, range_val)
        if len(pairs) >= 2:
            # A biased (e.g. 1-based) enum subtracts the bias into the index
            # register before the table read: ``sub w<idx>, w<value>, #bias``.
            # The pointer pairs are 0-based table indices, so add the bias back to
            # recover the real enum values (TODO #54).  TWO guards keep this to the
            # 3 census-confirmed cases:
            #   • idx_reg gate — the sub's dest must be THIS load's index register,
            #     so a neighbouring field's sub in the window can't bleed in.
            #   • xAsString gate — a field with an xAsString:/StringAsX: selector has
            #     its bias handled by that path; biasing it here would double-/mis-
            #     bias it (e.g. resultStatus/laneClosureType have xAsString and are
            #     NOT dictRep-only, so they stay out).
            ivar_name = next((iv.name for iv in cls.ivars
                              if iv.offset == ivar_off and iv.name), None)
            if ivar_name and not _field_routes_through_xasstring(cls, st, ivar_name):
                bias = _sub_imm_bias(insns, words, lo, i, dest_reg=idx_reg)
                if bias:
                    pairs = [(v + bias, nm) for v, nm in pairs]
            result[ivar_off] = pairs

    # ── Compare-chain / binary-search dispatch (newer toolchain) ──────────────
    # A third idiom (observed on a macOS system dyld cache's GeoServices, e.g.
    # GEOBatchPlaceResult/GEOETAResult, in a build otherwise identical to this
    # session's other jump-table fixes) has no `adr`/`br` jump table at all: the
    # int value is compared directly against a BINARY-SEARCH TREE of range and
    # exact immediates (`cmp w8,#N; b.le/b.gt/b.eq/b.ne target`), each leaf
    # loading its cfstring the same way the jump-table case's arms do.  The
    # leaf-level pairs are exactly what `_harvest_isolated_compares`/
    # `_harvest_cbz_value0` already extract from a `xAsString:` method's OWN
    # compare chain — reused verbatim here since both scan flat instruction
    # pairs and don't care about the surrounding tree shape.
    #
    # Each field's chain is anchored on its OWN ivar-offset lookup
    # (`adrp; ldrsw Xn,[Xn,#off]` — the value load's address computation),
    # NOT on its has-bits `tbz`/`tbnz` gate.  The gate is a poor anchor for
    # two reasons, both confirmed directly:
    #   * not every `tbz`/`tbnz` is a field gate (some are unrelated, e.g. a
    #     pointer-authentication bit-62 test), and splitting on every one can
    #     produce an over-wide block that runs into a LATER field's own lookup
    #     (GEOBatchPlaceResult misattributed its `_statusCode` chain to
    #     `_placeResult`'s offset this way);
    #   * a compiler that hoists the has-bits byte and tests every field's bit
    #     in one `tbnz` cascade lays each field's gated block OUT OF LINE, so
    #     the chain is not adjacent to (or after) its own gate in linear
    #     order at all — found by the f24 synthetic fixture: with four gated
    #     fields the first field's chain sat after the function's epilogue (a
    #     tail `b`, so the linear scan runs on past it), and
    #     the gate-anchored window for it held an unrelated field's tail.
    # The ivar-offset lookup has neither problem: it is what selects the
    # field, and it always immediately precedes the value load the chain
    # compares.  The chain itself is pure compare/branch/cfstring-address
    # logic with no `bl` calls (the runtime helpers that consume the matched
    # string, or handle the "value not in the table" default, are only
    # reached AFTER the chain converges) — verified directly
    # (GEOBatchPlaceResult's chain: 53 instructions, zero `bl`s, then a `bl`
    # at the merge point) — so each block runs from its lookup to the first
    # `bl` or the next lookup, whichever is first, i.e. exactly one field's
    # own chain.  Verified against golden and the macOS system cache
    # (GEOBatchPlaceResult.statusCode: all 9 values recovered exactly,
    # including 1/5/60 → STATUS_FAILED/INVALID_REQUEST/VERSION_MISMATCH).
    lookups = _ivar_offset_lookups(ctx, insns)
    for bi, (start, ivar_off) in enumerate(lookups):
        next_lookup = lookups[bi + 1][0] if bi + 1 < len(lookups) else len(insns)
        stop = next(
            (j for j in range(start, next_lookup) if insns[j].mnemonic == 'bl'),
            next_lookup)
        block = insns[start:stop]
        if len(block) < 4:
            continue
        if ivar_off not in valid_offsets or ivar_off in result:
            continue
        pairs: List[Tuple[int, str]] = []
        seen_values: Set[int] = set()

        def _add(value: int, name: str) -> None:
            if value not in seen_values:
                seen_values.add(value)
                pairs.append((value, name))

        _harvest_isolated_compares(ctx, block, words, _add)
        _harvest_cbz_value0(ctx, block, words, _add)
        if len(pairs) >= 2:
            pairs.sort(key=lambda p: p[0])
            result[ivar_off] = pairs

    return result


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


def _extract_enum_values(
    ctx: BinaryContext,
    imp: int,
    st: StringTable,
) -> Tuple[List[Tuple[int, str]], bool, bool]:
    """
    Try to extract (int_value, string_name) pairs from an ``xAsString:`` method.

    Returns (pairs, confirmed, truncated).  confirmed=True means every expected
    value was cleanly extracted from a pointer table.  truncated=True (only from
    the jump-table fallback) means the method body overran the disassembly budget
    so high values may be missing — the pointer-table path itself reads entries
    directly from memory and is never budget-truncated, so it returns False.

    Supports two pointer-table encodings:
    - Direct ``char *`` entries (standalone binaries)
    - ``NSString *`` / ``CFStringRef`` entries (shared-cache dylibs)

    Also detects a ``sub wRd, wRn, #bias`` instruction before the CMP gate,
    which indicates a 1-based enum whose table is 0-indexed.  The bias is
    added back to each pair's value number so the output matches the proto
    wire encoding (e.g. GEOMapRegionSourceType values 1–13).

    When the pointer-table pattern is not found, falls back to
    ``_extract_jumptable_enum_values`` for sparse/LLVM jump-table implementations.
    """
    if imp == 0:
        return [], False, False

    try:
        max_val = _find_field_count(ctx, imp)
        if max_val == 0 or max_val > _SPARSE_MAX_RANGE:
            # Beyond the 12-bit cmp-immediate ceiling (#59): a contiguous count
            # this large cannot come from the `cmp #imm12` gate a pointer table
            # uses, so route straight to the jump-table path.  Routing is by
            # STRUCTURE below (the scaled-index pointer load); this count gate is
            # only a fast pre-filter, bounded by the encoding rather than a tuned
            # 512.  A real >512-entry pointer-table enum is now read in full, and
            # a jump-table enum still falls through (no scaled load found).
            return _extract_jumptable_enum_values(ctx, imp, st)

        bias = _find_index_bias(ctx, imp)

        insns = disasm(ctx, imp, max_insns=_ENUM_MAX_INSNS)
        if not insns:
            return [], False, False

        table_va: Optional[int] = None

        # Principled: the table base is the base register of the scaled-index
        # load that reads table[idx], e.g. `ldr x0, [x8, w2, sxtw #3]` → x8.
        # This reads the dispatch the method actually performs rather than
        # guessing which register holds the table.  Needs a decoder that resolves
        # register-offset loads — capstone does; the native mini-decoder emits
        # `unk`, so base_reg is None there and pointer-table enum recovery falls
        # through to the jump-table path (the native decoder is a degraded mode and
        # not a correctness target — see the venv/capstone requirement).
        #
        # A register-priority GUESS fallback (try x8/x9/x10/x7/x11/x12/x13, accept
        # the first whose first entry reads as a valid enum string) was removed
        # 2026-06-14: a census found it fired 0× under capstone (587/587 pointer-
        # table enums across GeoServices/CLP/locationd resolve via the scaled-index
        # decode), exactly as the identical guess was removed from the jump-table
        # path by #47.  Output byte-identical.
        base_reg = find_indexed_load_base(insns, scale=3)
        if base_reg is not None:
            table_va = find_adrp_add_target(insns, base_reg)

        if table_va is None:
            # Pointer-table not found; try the jump-table (sparse enum) path.
            return _extract_jumptable_enum_values(ctx, imp, st)

        # A bitmask-gated (sparse) table declares which indices are values; the others are
        # holes, skipped.  A dense table has no mask and stops at its first empty slot.
        mask = _valid_value_bitmask(insns)
        pairs: List[Tuple[int, str]] = []
        n_declared = 0
        for i in range(max_val):          # max_val is the COUNT of valid entries
            if mask is not None and not (mask >> i) & 1:
                continue
            n_declared += 1
            try:
                ptr  = ctx.read_ptr(table_va + i * 8)
                name = _read_enum_string(ctx, ptr)
                if name is None:
                    break
                pairs.append((i + bias, name))
            except (ValueError, UnicodeDecodeError):
                break

        if not pairs:
            return [], False, False

        return pairs, (len(pairs) == (n_declared if mask is not None else max_val)), False

    except (NameError, ImportError):
        raise   # wiring/refactor bug — surface, don't mask as "extraction failed"
    except Exception as exc:
        log.debug("Enum extraction failed at 0x%x: %s", imp, exc)
        return [], False, False


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
    if any(f.type_name in ("int32", "uint32") and f.type_class is None
           for f in fields):
        dr_enums = _harvest_dictrep_enums(ctx, cls, st)
        if dr_enums:
            ivar_off_by_pname = {
                _proto_name(iv.name): iv.offset
                for iv in cls.ivars if iv.name
            }
            cls_prefix = _class_to_proto_name(cls.name, _pfx)
            for fld in fields:
                if fld.type_name not in ("int32", "uint32") or fld.type_class is not None:
                    continue
                off = ivar_off_by_pname.get(fld.name)
                if off is None or off not in dr_enums:
                    continue
                pairs = dr_enums[off]
                if len(pairs) < 2:
                    continue
                qualified = _qualify_enum_name(
                    cls_prefix, fld.name[0].upper() + fld.name[1:])
                fld.type_name  = qualified
                fld.type_class = f"ENUM:{qualified}"
                dictrep_pairs[fld.name] = pairs

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
        method_exists: bool = as_method is not None

        if as_method is not None and as_method.imp != 0:
            pairs, confirmed, truncated = _extract_enum_values(ctx, as_method.imp, st)
        elif fld.name in dictrep_pairs:
            # Enum recovered from -[Class _dictionaryRepresentation:] switch table
            # (no xAsString: companion selector exists for this field).
            pairs = dictrep_pairs[fld.name]
            confirmed = False
            method_exists = True

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

        enum_values: List[ProtoEnumValue] = []
        if pairs:
            seen_names: Set[str] = set()
            for val, raw_name in pairs:
                name = _normalize_enum_value_name(enum_name, raw_name)
                if name in seen_names:
                    name = f"{name}_{val}"
                seen_names.add(name)
                enum_values.append(ProtoEnumValue(name=name, number=val))

        enums.append(ProtoEnum(
            name=enum_name,
            values=enum_values,
            values_confirmed=confirmed,
            values_truncated=truncated,
        ))

    return enums
