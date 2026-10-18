"""proto/dispatch -- the readFrom: anchors the dispatch evaluator starts from.

Carved from ``proto.extractor`` (#11 monolith split, step 3).  What is left here after the
dispatch idioms were retired (2026-10-15; the field dispatch itself is decoded by evaluation
in :mod:`proto.dispatch_eval`):

* :func:`_find_readfrom_c_func` / :func:`_build_readfrom_core_index` -- the ReadAllFrom core
  each proto class's ``-readFrom:`` tail-calls, indexed by address (an element core a parent's
  handler calls names the element class);
* :func:`_jump_table_arm_addrs` -- decoded ``br`` jump tables, the CFG completion every
  :class:`proto.dictrep_flow.Flow` user seeds its graph with;
* :func:`_find_field_count` -- the ``cmp wN,#N ; b.hi`` gate reader (enum diagnostics).

Imports only macho.* + arm64decode + protoclass_heuristic (never proto.extractor), so it stays
cycle-free.
"""
from __future__ import annotations
import struct
import logging
from typing import Dict, List, Optional

from macho.memory    import BinaryContext, _ctx_cache
from macho.classlist import ObjcClass
from macho.disasm   import disasm, Insn, find_adrp_add_target
from macho.arm64decode import (_decode_bcond, _decode_cmp_imm, _COND_HI, _COND_HS,
                               range_from_unsigned_gate)
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
    The C ReadFrom core ``-[Cls readFrom:]`` is a thin wrapper around, or None.

    The thin wrapper hands its object and its reader straight on::

        mov x1, x2              ; (mov w2, #0)
        b   _ClsReadFrom        ; or: bl _ClsReadFrom ... ret

    Decided by data flow, not by "the first branch": the wrapper (up to its first
    unconditional terminator) is run with x0 = self and x2 = the reader as opaque tokens
    (:mod:`proto.dispatch_eval`), and its first call must be handed both (x0 = self, x1 =
    reader).  So an inline reader -- ``-readFrom:`` holding the dispatch itself, whose first
    call retains the reader -- has no C core (a parent cannot ``bl`` one; it messages
    ``readFrom:``), and a ``-readFrom:`` that hands only the reader to a shared function
    (a field-less filter's skip-everything helper) has none either.  Before 2026-10-15 the
    first branch target was taken whatever it was, which put a runtime stub into the core
    index for every inline reader (37-40 classes per build, all named after the first).
    """
    from proto.dictrep_flow import Flow
    from proto.dispatch_eval import SELF, READER, _opaque
    method = cls.get_method("readFrom:")
    if method is None or method.imp == 0:
        return None

    try:
        insns = disasm(ctx, method.imp, max_insns=_READFROM_MAX_INSNS, stop_at_ret=False)
    except Exception:
        return None
    end = next((k for k, i in enumerate(insns)
                if i.mnemonic in ('b', 'br', 'ret', 'retaa', 'retab', 'udf')), None)
    insns = insns[:end + 1] if end is not None else insns
    if not insns:
        return None
    region = Flow(ctx, insns).run_from(0, {'x0': SELF, 'x2': READER}, opaque=_opaque)
    if not region.calls:
        return None
    first = region.calls[0]
    if first.args.get('x0') == SELF and first.args.get('x1') == READER:
        return first.target
    return None


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
                if cond in (_COND_HS, _COND_HI):
                    return range_from_unsigned_gate(cond, imm)
        va += 4
    return 0


# `_try_pointer_table` (the C-ReadFrom pointer-table dispatch reader) was removed
# 2026-06-15: it returned nothing on every supported artifact (1201 calls, 0
# non-empty), so the writeTo CFG walk is the sole field-number source.  Its only
# consumer was `extractor._confirm_field_numbers`.


def _section_name(ctx: BinaryContext, va: int) -> Optional[str]:
    """Name of the section containing *va*, or ``None`` if unmapped."""
    for seg in ctx.segments:
        if seg.vmaddr <= va < seg.vmaddr + seg.vmsize:
            for sec in seg.sections:
                if sec.vmaddr <= va < sec.vmaddr + sec.vmsize:
                    return sec.name
            return None
    return None


def _imm_tok(tok: str) -> Optional[int]:
    tok = tok.strip().lstrip('#')
    try:
        return int(tok, 16) if tok.lower().startswith('0x') else int(tok)
    except ValueError:
        return None


def _wname(reg: str) -> str:
    reg = reg.strip()
    return 'w' + reg[1:] if reg and reg[0] in 'xX' else reg


def _jump_table_arm_addrs(ctx: BinaryContext, insns: List["Insn"], per_br: bool = False):
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

    A GENERAL CFG-completion decoder: it recovers arm targets for any such ``br`` so a CFG
    (and :func:`proto.arm64cfg.dominators`) reaches the blocks behind it.  Without it a
    reader whose field dispatch shares its function with a control ``br`` ahead of the
    field-number extraction (e.g. GEOHours) has that extraction unreachable.
    Read-only; returns in-range arm addresses -- with *per_br*, as ``{br address: its arms}``."""
    if ctx is None or not insns:
        return {} if per_br else set()
    ins = sorted(insns, key=lambda i: i.addr)
    lo, hi = ins[0].addr, ins[-1].addr + 4
    arms: set = set()
    by_br: Dict[int, set] = {}
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
                by_br.setdefault(br.addr, set()).add(arm)
    return by_br if per_br else arms


def build_function_index(ctx: BinaryContext, cl: 'ClassList') -> None:
    """Record on *ctx* every method IMP of the image (``_function_entries``) and every ivar's
    offset-variable address (``_ivar_offset_slots``).  The readFrom: evaluator
    (:mod:`proto.dispatch_eval`) uses the IMPs, with the ReadAllFrom cores, as function
    boundaries and tail-call targets, and the slots to tell this class's ivars from others'.
    Built once per extraction; :func:`_build_readfrom_core_index` calls it."""
    entries = _ctx_cache(ctx, "_function_entries", set)
    ivar_slots = _ctx_cache(ctx, "_ivar_offset_slots", set)
    for cls in cl:
        entries.update(m.imp for m in cls.methods if m.imp)
        ivar_slots.update(iv.offset_slot for iv in cls.ivars if iv.offset_slot)


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
    from proto.protoclass_set import _proto_class_set
    index: Dict[int, str] = {}
    build_function_index(ctx, cl)
    # The image's proto classes: the PBCodable superclass closure as well as the name
    # heuristic (CoreParsec's ``_CP...`` classes are proto only through the closure).
    proto_classes = _proto_class_set(ctx, cl)
    for cls in cl:
        if cls.is_meta or not (cls.name in proto_classes or _is_proto_class(cls)):
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
