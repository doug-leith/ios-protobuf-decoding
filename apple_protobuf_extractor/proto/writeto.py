"""proto/writeto.py — writeTo: field-number extraction.

Recovers confirmed protobuf field numbers from a class's ``-[Cls writeTo:]`` serializer
body.  Imports only ``macho.*`` and the shared ``proto.arm64*`` helpers (never
``proto.extractor``).

The decoder is the **CFG walk** (``_walk_field_numbers`` + ``writeto_walk`` +
binding): a sound reachability walk over ``-[Cls writeTo:]``'s basic blocks that binds each field-write to its
container ivar by tracing the value/offset registers.  It yields both the confirmed
``{ivar: field_number}`` map and ``_out_helpers`` (the per-ivar write-helper address
used downstream to tell ``repeated string`` from ``repeated message/bytes``).

The walk only runs when the binary-wide branch-indegree pre-pass has been threaded
onto ``ctx`` by ``extract_all`` (see ``build_writeto_indegree``); a bare call with
no pre-pass (e.g. a direct unit test) returns ``{}`` (no decode, fail-safe).

The walk binds nothing for a map
field written inside an ``enumerateKeysAndObjectsUsingBlock:`` block (the number lives in
the block's invoke function — 5 GeoServices ivars); :mod:`proto.mapfields` recovers
those from the block, and any it cannot degrade to a flagged ivar-order estimate —
fail-safe, never a confident error.
"""
from typing import Dict, List, Optional, Set, Tuple

from macho.memory import BinaryContext, _is_in_any_section
from macho.classlist import ClassList, ObjcClass, ObjcIvar
from macho.disasm import disasm, find_mov_imm, _parse_imm, _norm_reg
# Tier-1 shared arm64 helpers, lifted to proto/arm64cfg.py.
# Re-imported (hence re-exported) here so
# writeto_walk's own callers and tests/test_writeto_walk_coverage.py
# (`import proto.writeto as W`) keep working unchanged — a pure code move.
from proto.arm64cfg import (              # noqa: F401  (re-export)
    TERMINALS, _CALLEE_SAVED,
    _is_cond, _parse_load, _same_reg, _adrp_page, _resolve_offset_addr,
    _cond_target, _next_imp, LazyWalk,
    split_ops, dst_reg, mem_operand, parse_adrp,
)

from proto.callees import stub_selector
import logging
import re

log = logging.getLogger(__name__)


# Function-epilogue instructions the compiler may hoist between the field-number
# load (`mov w2,#N`) and a tail-call (`b`) to the write helper.  ``unk`` is
# included because the native mini-decoder renders some ldp/stp variants
# (post-indexed `ldp x22,x21,[sp],#0x30`, etc.) as ``unk``; in the epilogue gap
# those are restores, not field-relevant instructions.
_WRITETO_EPILOGUE_MNEMONICS = frozenset({'ldp', 'stp', 'unk'})


# Operand 0 naming FP/SIMD register 0 in any width/arrangement (`d0`, `s0`, `v0.16b`, …):
# the first floating-point argument register.  The newer toolchain copies a spilled double
# into it with `mov v0.16b, v8.16b` where the old one wrote `fmov d0, d8`.
_FP_ARG0 = re.compile(r'\s*[dsvqhb]0(?![0-9])')
_NO_DEST_MNEMONICS = frozenset(('cmp', 'cmn', 'tst', 'fcmp', 'fcmpe', 'tbz', 'tbnz', 'cbz', 'cbnz'))


def _sets_up_fp_value(insns: List, idx: int) -> bool:
    """True when the call at ``insns[idx]`` has a floating-point value argument: some
    instruction since the previous ``bl`` writes ``d0`` or ``s0`` (``ldr d0,[..]``,
    ``fmov d0,x8``, ``scvtf d0,..``).

    A double/float field is written as ``(writer, field#, value in d0/s0)`` — the field
    number goes in ``w1``, not ``w2``.  An integer-argument call whose ``w1`` merely holds
    a constant (``os_unfair_lock_lock_with_options(lock, 0x10000)`` in the newer
    toolchain's serializers) has no FP value, and ``w1`` is not a field number there."""
    for k in range(idx - 1, -1, -1):
        ins = insns[k]
        if ins.mnemonic == 'bl':
            return False
        if ins.mnemonic.startswith('st') or ins.mnemonic in _NO_DEST_MNEMONICS:
            continue                          # stores / compares: operand 0 is read, not written
        if _FP_ARG0.match(ins.op_str):
            return True
    return False


def _field_number_imm(cand: List, insns: List, idx: int) -> Optional[int]:
    """The field-number immediate set up by the single instruction in *cand* for the call
    at ``insns[idx]``: ``mov w2,#N``, or ``mov w1,#N`` when (and only when) the call
    passes an FP value in d0/s0 (:func:`_sets_up_fp_value`)."""
    n = find_mov_imm(cand, 'w2')
    if n is None:
        n = find_mov_imm(cand, 'w1')
        if n is not None and not _sets_up_fp_value(insns, idx):
            return None
    return n


def _writeto_field_number_before(insns: List, idx: int) -> Optional[int]:
    """Return the proto field number for the field-write call at ``insns[idx]``.

    The field number is the immediate of the ``mov/movz w2,#N`` (or ``w1`` for
    double/float fields, whose value occupies ``d0``) that sets up the call.  It
    is normally the instruction immediately before the call, but for a tail-call
    (`b`) write the compiler hoists the function epilogue (``ldp``/``stp``
    restores, some rendered ``unk``) in between — so skip those when looking
    back.  Returns None when no field-number immediate precedes the call (e.g. a
    control-flow ``b``).

    The skip path only engages when the instruction immediately before the call
    is an epilogue insn; a normal ``bl`` field write has ``movz w2,#N`` directly
    before it, so this never alters that (common) case.
    """
    j = idx - 1
    skipped = 0
    while (j >= 0 and skipped < 6
           and insns[j].mnemonic in _WRITETO_EPILOGUE_MNEMONICS):
        j -= 1
        skipped += 1
    if j < 0:
        return None
    if skipped:
        # Tail-call epilogue-hoisted case: the one instruction only (the epilogue skip keeps
        # its own 6-instruction bound).
        return _field_number_imm([insns[j]], insns, idx)
    # A plain call: insns[j] first, then up to two more back -- an older scheduler can put
    # one unrelated argument setup between the call's two movs (`mov w2,#N; mov x0,<writer>;
    # bl`).  Any `bl` on the way, insns[j] included, ends the search: it is a preceding
    # call's (`mov w2,#1; bl f; b target`), and its `mov w2` is not this site's number.
    for k in range(j, max(-1, j - 3), -1):
        if insns[k].mnemonic == 'bl':
            break
        n = _field_number_imm([insns[k]], insns, idx)
        if n is not None:
            return n
    return None


# ════════════════════════════════════════════════════════════════════════════
# CFG-walk decoder (productionised from wt_reader.py — see that file's module
# docstring for the full design, contract, and the S1–S5 known-miss catalogue).
# Sound reachability walk over -[Cls writeTo:] basic blocks, binding each
# field-write to its container ivar by tracing the value/offset registers.
# ════════════════════════════════════════════════════════════════════════════

# protobuf wire-format field-number range (spec): 1 .. 2^29-1.  Principled
# validity test on the `mov w2,#N` immediate (the wire spec, not a tuned cap).
_MAX_PROTO_FIELD_NUMBER = (1 << 29) - 1

_VALUE_REGS = frozenset(('w1', 'x1', 'd0', 's0'))   # write-helper value arg (raw)
_LOAD_MNEMONICS = ('ldr', 'ldrb', 'ldrh', 'ldrsw', 'ldrsb', 'ldrsh')


# The field# a ProtocolBuffer write helper takes to mean "write the bare value, NO
# tag": every PB element writer opens with ``cmn w<field>,#1 ; b.eq <skip-tag>``.
# writeTo: passes it for each element of a PACKED repeated field, which it writes
# between a length-delimited begin-mark (``PBDataWriterPlaceMark``, carrying the real
# field#, wire type 2) and its recall-mark — so that no-tag call is the field's
# element writer, the one whose wire family (sint/fixed/plain) types the elements.
_NO_TAG_FIELD_NUMBER = -1


def _is_field_number(n) -> bool:
    return n is not None and 1 <= n <= _MAX_PROTO_FIELD_NUMBER


# Instructions whose first operand is NOT a register they write (so they don't
# define x1): stores (st*), compares, and branches.  Used by the reaching-definition
# scan in _value_is_stack_scratch.
_NON_DEF_MNEMONICS = frozenset((
    'cmp', 'cmn', 'tst', 'b', 'bl', 'br', 'ret', 'retaa', 'retab',
    'cbz', 'cbnz', 'tbz', 'tbnz',
))


def _value_is_stack_scratch(blk, k):
    """True if the write-helper value arg x1 at insn *k* is a STACK SCRATCH
    (`add x1, sp, #imm`, or `sub x1, x29, #imm` when the function addresses its locals
    from the frame pointer) — the begin/end-length-delimited-submessage idiom for an
    INLINE repeated message field.  begin has a field# before it; end does not.

    Value-independent (no lookback window): take the REACHING DEFINITION of x1 —
    the first instruction, scanning back from *k*, that writes x1 — and report
    whether it is `add x1, sp`.  A closer writer shadows any stale earlier
    `add x1, sp`, so this needs no magic distance bound (the old window=5 cap).
    Differential-verified output-identical to that cap across the corpus (0
    disagreements / 18865 bl sites)."""
    for j in range(k - 1, -1, -1):
        ins = blk[j]
        mn = ins.mnemonic
        if mn.startswith('st') or mn in _NON_DEF_MNEMONICS:
            continue                                   # does not define x1
        p = split_ops(ins.op_str)
        if not p or _norm_reg(p[0]) != 'x1':
            continue                                   # writes some other register
        # First (reaching) definition of x1 — decide on it and stop.
        if len(p) < 3:
            return False
        base = _norm_reg(p[1])
        return (mn == 'add' and base == 'sp') or (mn == 'sub' and base == 'x29')
    return False


def _forward_self_load_off(blk, k, self_reg, base_regs):
    """Offset address of the CONTAINER array for a begin-submessage at index *k*.

    Apple's inline-repeated-message idiom loads the COUNT in the preheader (the loop
    bound) BEFORE the `begin` write, then the ARRAY pointer in the loop body JUST
    AFTER it — so the container ivar is the first `ldr Xd,[self,Xoff]` (or
    `add Xd,self,Xoff` for a packed scalar) AFTER the begin, not the count carried
    in (Issue B: count-vs-array).  Bound structurally: scan to the next `bl`."""
    if self_reg is None:
        return None
    for j in range(k + 1, len(blk)):
        ins = blk[j]
        if ins.mnemonic == 'bl':
            break
        if ins.mnemonic == 'ldr':                 # repeated MESSAGE: array ptr load
            pl = _parse_load(ins.op_str)
            if pl and pl[1] in (self_reg, 'x0') and pl[2] is not None and pl[0].startswith('x'):
                off_addr = _resolve_offset_addr(blk[:j], pl[2], base_regs)
                if off_addr is not None:
                    return off_addr
        elif ins.mnemonic == 'add':               # PACKED scalar: addr of {ptr,count}
            p = split_ops(ins.op_str)
            if (len(p) == 3 and _norm_reg(p[1]) in (self_reg, 'x0')
                    and not p[2].startswith('#')):
                offreg = _norm_reg(p[2])
                if offreg is not None:
                    off_addr = _resolve_offset_addr(blk[:j], offreg, base_regs)
                    if off_addr is not None:
                        return off_addr
    return None


def build_branch_indegree(ctx: BinaryContext, cl: ClassList,
                          imps_sorted: List[int]) -> Dict[int, Set[int]]:
    """Map ``b TARGET`` -> set of distinct source-method imps, scanning each
    writeTo: body up to its next method imp.  A target branched-to from >= 2
    distinct methods is a shared return/cleanup thunk (don't follow); a target
    referenced from one method is that function's own outlined block (follow)."""
    indeg: Dict[int, Set[int]] = {}
    for cls in cl:
        if cls.is_meta:
            continue
        m = cls.get_method("writeTo:")
        if m is None or m.imp == 0:
            continue
        # [cap:INPUT-SANITY — #59] Bound the indegree pre-scan by the method's
        # STRUCTURAL extent: the next IMP is a hard upper bound on this writeTo:
        # body, so (next_imp - imp)//4 instructions is the value-independent cap.
        # The old `min(.., 4000)` magic ceiling was dead (max observed writeTo
        # extent = 2131 insns; the ceiling never bound anything) — removed.  The
        # `max(64, ..)` floor only guards a degenerate end==imp.
        end = _next_imp(imps_sorted, m.imp)
        cap = max(64, (end - m.imp) // 4)
        insns = disasm(ctx, m.imp, max_insns=cap, stop_at_ret=False)
        for ins in insns:
            if ins.mnemonic == 'b':
                t = _parse_imm(ins.op_str)
                if t is not None:
                    indeg.setdefault(t, set()).add(m.imp)
    return indeg


def _image_text_range(ctx):
    """``(lo, hi)`` of the image's own ``__TEXT`` segment, or None when the context
    does not expose one (a unit-test stub) — then nothing is treated as out-of-image.

    A ``writeTo:`` body never leaves its own image's ``__TEXT``.  The newer toolchain
    (iOS 27, macOS 27) makes this matter: a tail call such as ``b <objc_sync_exit>`` goes
    straight to a function in another image (the old toolchain branched to a stub in the
    image's own ``__stubs``), and it is branched to from only one method, so the in-degree
    test below mistook it for the method's own outlined block and the walk ran off into
    the foreign image, raised, and the whole class fell back to ivar-order estimates."""
    try:
        for seg in ctx.segments:
            if seg.name == "__TEXT" and seg.vmsize:
                return seg.vmaddr, seg.vmaddr + seg.vmsize
    except AttributeError:
        pass
    return None


def classify_b_target(blk, k, target, foreign_imps, indeg, imp, text_range=None):
    """Classify an unconditional ``b TARGET`` reached during the walk.
    Returns ('write', N) | ('foreign', None) | ('thunk', None) | ('follow', None).
    ``text_range`` is the image's ``(lo, hi)`` ``__TEXT`` span (:func:`_image_text_range`);
    a target outside it is another image's code."""
    fn = _writeto_field_number_before(blk, k)
    if _is_field_number(fn):
        return ('write', fn)               # tail-call field write (helper)
    if target is None:
        return ('foreign', None)
    if target in foreign_imps:
        return ('foreign', None)           # tail-call into another method
    if text_range is not None and not (text_range[0] <= target < text_range[1]):
        return ('foreign', None)           # tail-call into another image
    srcs = indeg.get(target)
    if srcs is not None and len(srcs - {imp}) >= 1:
        return ('thunk', None)             # shared thunk (>=2 distinct methods)
    return ('follow', None)                # our own outlined block


def _make_write(n, addr, block, guard, cont_off, pre, srcblk, srck, base_regs, helper_va):
    """Build one write-event record.  Single constructor shared by the ``bl`` and
    tail-call ``b`` field-write paths in :func:`writeto_walk` so the record shape
    is defined in exactly one place.  ``base_regs`` is snapshotted (copied) here.

    ``bracket`` marks a begin-mark write (a length-delimited bracket opened with a
    stack-scratch mark: a packed repeated field or an inline sub-message), whose
    ``helper_va`` is the begin-mark, not a value writer.  ``elem_helper_vas`` is filled
    only for a bracket: the distinct no-tag element-writer VAs called directly inside
    it — the element writer of a packed repeated field (see
    :data:`_NO_TAG_FIELD_NUMBER`)."""
    return dict(n=n, write_addr=addr, block=block, guard=guard, cont_off=cont_off,
                pre=pre, srcblk=srcblk, srck=srck, base_regs=dict(base_regs),
                helper_va=helper_va, bracket=False, elem_helper_vas=[])


def writeto_walk(ctx, imp, foreign_imps, indeg, blk_cap=400, max_blocks=2000,
                 self_reg=None, base_regs=None):
    """Sound CFG walk from imp.  Returns (writes, flags) where writes is a list of
    dicts {n, write_addr, block, guard, cont_off, pre} in discovery order.

    [cap:INPUT-SANITY] blk_cap/max_blocks are runaway backstops, not tuned values.
    See wt_reader.py for the full contract (SOUND; COMPLETE for has-bit dispatch;
    KNOWN inline-submessage over-collection that the binding phase drops).

    Block discovery/traversal is driven by :class:`proto.arm64cfg.LazyWalk` — the
    writeTo-body-safe lazy CFG mode (see its module docstring for why the eager
    build_blocks() mode used by the readFrom side cannot be used here, since
    writeTo: bodies can be outlined past other functions' boundaries).  This
    function owns only the per-instruction value/offset tracing and field-write
    recording; LazyWalk owns the worklist / visited / known-leader bookkeeping."""
    base_regs = base_regs or {}     # honour the None default before snapshotting it
    walker = LazyWalk(
        ctx, imp,
        lambda c, a: disasm(c, a, max_insns=blk_cap, stop_at_ret=False),
        initial_state=(imp, None, dict(base_regs), ()),   # (guard, cont_off, base, brackets)
        max_blocks=max_blocks,
    )
    text_range = _image_text_range(ctx)
    writes = []
    seen_writes = set()             # (n) first-wins
    zero_writes = []                # top-level fields written with literal field# 0
    # Every call the visited code makes (see :func:`writeto_sent_selectors`): `bl` and
    # tail-`b` targets, `blr` (target unknown), and the shared thunks the walk does not
    # enter (their code is not examined).
    call_targets = []
    x1_loads = []                   # addresses `ldr x1,[adrp page + k]` reads
    indirect_calls = 0
    unexamined_thunks = 0
    while True:
        popped = walker.next_block()
        if popped is None:
            break
        blk, start, (guard, cont_off, in_base, brackets) = popped
        cur_guard = guard               # controlling has-bit test for fall-through
        cur_off = cont_off              # container ivar-offset addr threaded along edge
        cur_base = dict(in_base)        # live ivar-offset-table bases, threaded per edge
        # Open length-delimited brackets (begin-mark .. recall-mark), innermost last,
        # threaded along CFG edges: a packed field's element loop is its own block (the
        # loop back-edge target), so the bracket must survive the block boundary.  Each
        # entry is the begin-mark's write record, or None for a bracket not recorded as
        # a field (nested / already seen).  Immutable tuple: per-edge snapshots are free.
        adrp_pg = {}                    # pending `adrp` page per reg, for re-load detect
        submsg_depth = 0                # inside inline-expanded submessage(s)?
        last_bl = -1                    # index of most recent bl (bounds value-load ctx)
        for k, ins in enumerate(blk):
            a = ins.addr
            if walker.is_visited(a):
                break
            if walker.is_leader_handoff(a, start):
                # fall-through into a known block boundary: hand off our context
                walker.push_front(a, (cur_guard, cur_off, dict(cur_base), brackets))
                break
            walker.mark_visited(a)
            mn = ins.mnemonic
            if mn in TERMINALS:
                break
            if mn == 'udf':
                # Permanently-undefined trap: the compiler pads a no-return call (`bl
                # _Unwind_Resume`) and the gap before the next method with these, so
                # execution never falls through one — without this stop the walk read on
                # into the NEXT method's body and could take its writes for this one's.
                break
            # Maintain the LIVE ivar-offset-table base registers (`cur_base`).
            # This is the SOLE source of base tracking (TODO #59: detect_context no
            # longer seeds bases — its capped prologue scan was redundant with this).
            # It captures bases that are (a) set up anywhere in the body (incl. after
            # the readAll:/lock prologue, the old detect_context cap's blind spot) or
            # (b) `adrp`-only (the page is the base and the offset-load supplies the
            # displacement).  It can also be RE-LOADED mid-body to a different table
            # (x22 0x780 -> 0x784).  Track all of this here, scoped to callee-saved
            # GPRs (the regs that survive the calls and hold a persistent base):
            #   adrp xR,#page            -> cur_base[xR] = page  (adrp-only base)
            #   add  xR,xR,#imm          -> cur_base[xR] = page + imm  (refine)
            #   any other write of xR    -> drop xR (no longer a table base, e.g.
            #                               `mov x22, x0`) UNLESS it was a stable
            #                               prologue capture (base_regs), which the
            #                               re-load case legitimately overwrites.
            if mn == 'adrp':
                pa = parse_adrp(ins.op_str)
                if pa is not None and pa[0] in _CALLEE_SAVED:
                    adrp_pg[pa[0]] = pa[1]
                    cur_base[pa[0]] = pa[1]
            elif mn == 'add':
                _ad = split_ops(ins.op_str)
                if (len(_ad) == 3 and _ad[2].startswith('#')
                        and _norm_reg(_ad[0]) in _CALLEE_SAVED
                        and _norm_reg(_ad[0]) == _norm_reg(_ad[1])
                        and _norm_reg(_ad[0]) in adrp_pg):
                    _aim = _parse_imm(_ad[2])
                    if _aim is not None:
                        cur_base[_norm_reg(_ad[0])] = adrp_pg[_norm_reg(_ad[0])] + _aim
            elif mn in ('mov', 'movz', 'ldr', 'ldrsw', 'ldrb', 'ldrh', 'ldrsh',
                        'ldrsb', 'ldp'):
                # destination clobber: a base reg overwritten with a non-table value.
                _dst = dst_reg(ins.op_str)
                if _dst in cur_base and _dst not in base_regs:
                    cur_base.pop(_dst, None); adrp_pg.pop(_dst, None)
            # Track the enum-loop CONTAINER offset, threaded into the loop body.
            if self_reg is not None and mn == 'ldr':
                pl = _parse_load(ins.op_str)
                if pl and pl[1] in (self_reg, 'x0') and pl[2] is not None and pl[0].startswith('x'):
                    off_addr = _resolve_offset_addr(blk[:k], pl[2], cur_base)
                    if off_addr is not None:
                        cur_off = off_addr
            elif self_reg is not None and mn == 'add':
                p = split_ops(ins.op_str)
                if (len(p) == 3 and _norm_reg(p[1]) in (self_reg, 'x0')
                        and not p[2].startswith('#')):
                    offreg = _norm_reg(p[2])
                    if offreg is not None:
                        off_addr = _resolve_offset_addr(blk[:k], offreg, cur_base)
                        if off_addr is not None:
                            cur_off = off_addr
            if mn == 'ldr' and _norm_reg(dst_reg(ins.op_str) or '') == 'x1':
                # The selector of a plain `objc_msgSend` call (no selector stub) is
                # loaded into x1 from its __objc_selrefs slot (`adrp; ldr x1,[xN,#k]`).
                _m = mem_operand(ins.op_str)
                if _m is not None and _m[2] is None:
                    _pg = _adrp_page(blk[:k], _m[1])
                    if _pg is not None:
                        x1_loads.append(_pg + _m[3])
            if mn == 'blr':
                indirect_calls += 1
            if mn == 'bl':
                call_targets.append(_parse_imm(ins.op_str))
                pre = list(blk[last_bl + 1:k + 1])   # since the previous call
                last_bl = k
                fn = _writeto_field_number_before(blk, k)
                scratch = _value_is_stack_scratch(blk, k)
                if scratch and fn is None:
                    submsg_depth = max(0, submsg_depth - 1)   # END-submessage
                    brackets = brackets[:-1]
                    continue
                if fn == _NO_TAG_FIELD_NUMBER and not scratch:
                    # a bare (untagged) value written directly inside the innermost
                    # bracket: that bracket is a packed field and this is its element
                    # writer.  Recorded only on a bracket recorded as a field.
                    if brackets and brackets[-1] is not None:
                        ev = _parse_imm(ins.op_str)
                        if ev is not None and ev not in brackets[-1]['elem_helper_vas']:
                            brackets[-1]['elem_helper_vas'].append(ev)
                    continue
                if not _is_field_number(fn):
                    # field# 0 is illegal in proto but Apple emits deliberate
                    # 0-based fields (TODO #52 / LIMITATIONS.md (4)).  Capture the
                    # top-level literal-0 write so the estimate can be flagged as
                    # NOT wire-accurate; skip nested/scratch writes (conservative —
                    # bind only the simple direct-field case, like NTPBCacheHint._key).
                    if fn == 0 and not scratch and submsg_depth == 0:
                        zero_writes.append(_make_write(
                            fn, a, start, cur_guard, cur_off, pre, blk, k, cur_base,
                            _parse_imm(ins.op_str)))
                    continue
                write_off = cur_off
                if scratch:                                    # BEGIN-submessage
                    record = (submsg_depth == 0)               # only the container field
                    if record:
                        arr = _forward_self_load_off(blk, k, self_reg, cur_base)
                        if arr is not None:
                            write_off = arr
                    submsg_depth += 1
                elif submsg_depth > 0:
                    continue                                   # element sub-field — skip
                else:
                    record = True
                rec = None
                if record and fn not in seen_writes:
                    seen_writes.add(fn)
                    rec = _make_write(fn, a, start, cur_guard, write_off, pre,
                                      blk, k, cur_base, _parse_imm(ins.op_str))
                    rec['bracket'] = scratch
                    writes.append(rec)
                if scratch:
                    brackets = brackets + (rec,)
                continue
            if _is_cond(mn):
                t = _cond_target(ins)
                if (t is not None and t not in foreign_imps and t != imp
                        and (text_range is None or text_range[0] <= t < text_range[1])):
                    walker.push(t, (a, cur_off, dict(cur_base), brackets))   # thread guard+cont+base
                cur_guard = a               # controls subsequent fall-through writes
                continue                    # fall through too
            if mn == 'b':
                t = _parse_imm(ins.op_str)
                kind, fn = classify_b_target(blk, k, t, foreign_imps, indeg, imp,
                                           text_range)
                if kind == 'write':
                    if fn not in seen_writes:
                        seen_writes.add(fn)
                        writes.append(_make_write(fn, a, start, cur_guard, cur_off,
                                                  list(blk[last_bl + 1:k + 1]),
                                                  blk, k, cur_base, t))
                    break                   # tail-call ends this path
                if kind == 'follow':
                    walker.push(t, (cur_guard, cur_off, dict(cur_base), brackets))
                elif kind == 'thunk':
                    unexamined_thunks += 1
                else:
                    call_targets.append(t)  # tail call out of the function
                break                       # unconditional: no fall-through
            # any other insn: keep decoding this block
        else:
            # ran to blk_cap with no terminal/branch -> continue linearly
            walker.push_continue(blk[-1].addr + 4, (cur_guard, cur_off, dict(cur_base),
                                                 brackets))
    return writes, dict(truncated=walker.truncated, blocks=walker.blocks_seen,
                        zero_writes=zero_writes, call_targets=call_targets,
                        x1_loads=x1_loads, indirect_calls=indirect_calls,
                        unexamined_thunks=unexamined_thunks)


def detect_context(ctx, imp, max_insns=40):
    """From the prologue: the self register (dest of `mov xR, x0` before the first
    bl).  Returns ``(self_reg, {})`` — the second element (the ivar-offset-table
    base registers) is now ALWAYS EMPTY (TODO #59, see below).

    The self register DEFAULTS to ``x0``: per the arm64 ABI self arrives in x0 and
    many writeTo: bodies use it directly (``add x20, x0, x8`` for the container)
    without ever copying it to a callee-saved register — in which case there is no
    ``mov xR, x0`` to find.  Returning x0 (rather than None) keeps the walk's
    offset tracking enabled for those functions; the tracking already matches both
    x0 and the moved register, and self is live in x0 until the first field op, so
    this is safe (measured: +10 recovered bindings, 0 conflicts/losses across the
    three corpora).  When self IS copied (`mov xR, x0` before the first bl), that
    callee-saved register is used instead.

    TODO #59 — the prologue base-register SEED is removed.  It used to scan for
    ``adrp+add`` into a callee-saved reg, capped at the first ``max_insns`` insns
    (the old ``[cap:AFFECTS-OUTPUT]`` — a base set up past the cap, e.g. the
    sorted-dictionary path, was missed).  That seed is REDUNDANT: :func:`writeto_walk`
    re-discovers every ivar-offset-table base LIVE per block (its ``cur_base``
    tracking handles adrp-only bases, mid-body setup, re-loads and clobbers), so
    returning empty bases is byte-identical on every artifact (verified 0-diff on
    GeoServices / CoreLocationProtobuf / NewsTransport, and the golden snapshot).
    Dropping it deletes the only output-affecting cap here.

    [cap:INPUT-SANITY] max_insns bounds the self-register prologue disasm window;
    the scan stops at the first ``bl`` regardless, so this is a runaway backstop,
    not an output-deciding bound."""
    insns = disasm(ctx, imp, max_insns=max_insns, stop_at_ret=False)
    self_reg = None
    for ins in insns:
        if ins.mnemonic == 'bl':
            break
        if ins.mnemonic == 'mov':
            p = split_ops(ins.op_str)
            if len(p) == 2 and _norm_reg(p[1]) == 'x0':
                self_reg = _norm_reg(p[0]); break
    return (self_reg or 'x0'), {}


def _addr_to_name(ctx, addr, offset_to_name):
    """Read the u32 ivar byte-offset at *addr* and map to an ivar name.  The
    map-membership check IS the validator (a stray read almost never equals a byte
    offset this class declares), so no hard section gate is needed."""
    if addr is None:
        return None
    try:
        return offset_to_name.get(ctx.read_u32(addr))
    except (NameError, ImportError):
        raise
    except Exception:
        return None


# Callee-saved registers whose value is preserved across a `bl`: an ivar value
# loaded into one of these BEFORE the writer-init call survives it (S1 hoist).
_CALLEE_SAVED_VALUE = (
    frozenset(f'd{i}' for i in range(8, 16)) | frozenset(f's{i}' for i in range(8, 16))
    | frozenset(f'x{i}' for i in range(19, 29)) | frozenset(f'w{i}' for i in range(19, 29))
)


def _trace_hoisted_self_value(ctx, pre, full_prefix, self_reg, base_regs, offset_to_name):
    """S1 — the field's value was loaded into a callee-saved register ABOVE the
    writer-init `bl`, then moved into the helper's value arg just before the write
    (`ldr d8,[self,off]; bl <init>; … ; fmov d0,d8; mov w1,#N; bl <write>`).  The
    stop-at-bl value search in :func:`bind_write` cannot see the load (it is before
    the init call), so follow the data dependency: find the value-reg ← callee-reg
    move in ``pre``, then that callee reg's ``ldr …,[self,off]`` in the full block
    prefix.  Callee-saved regs survive the call, so crossing it here is sound."""
    src = None
    for ins in reversed(pre):
        if ins.mnemonic in ('fmov', 'mov'):
            p = split_ops(ins.op_str)
            if len(p) == 2 and p[0] in _VALUE_REGS and p[1] in _CALLEE_SAVED_VALUE:
                src = p[1]
                break
    if src is None:
        return None
    for i in range(len(full_prefix) - 1, -1, -1):
        ins = full_prefix[i]
        if ins.mnemonic in _LOAD_MNEMONICS:
            parsed = _parse_load(ins.op_str)
            # match w/x views: an int32/enum value is loaded as `ldr w20,[self,off]`
            # but moved as `mov x1, x20`, so the load dest (w20) and the mov source
            # (x20) are the same physical reg.
            if (parsed and _same_reg(parsed[0], src) and parsed[1] in (self_reg, 'x0')
                    and parsed[2] is not None):
                addr = _resolve_offset_addr(full_prefix[:i], parsed[2], base_regs)
                name = _addr_to_name(ctx, addr, offset_to_name)
                if name is not None:
                    return name
    return None


# ── Accessor-sourced (property getter) value binding ────────────────────────
# Message / object fields are serialized through their property GETTER rather
# than a direct `ldr [self,off]`:  the getter (an objc "selector stub" that loads
# the SEL and tail-jumps through objc_msgSend) returns the submessage, optionally
# behind a oneof presence check or ARC retain.  bind_write's self-load scan finds
# nothing for these (the value comes from a call, not a load), so they go unbound
# and degrade to a flagged ivar-order ESTIMATE — landing the wrong field number on
# message-typed fields (e.g. _CPUsageEnvelope.context estimated 6, real 14).  The
# helpers below trace the value register back to the getter `bl`, resolve its
# selector, and map it to the real-field ivar of the same name — CONFIRMED against
# the getter's own disassembly (it must load that ivar's offset), never a guess.


def _getter_loads_offset(ctx, imp, want_off, max_insns=24):
    """True if the getter method at *imp* loads the ivar at byte offset *want_off*
    from self (``ldr xD,[x0, xOff]`` with xOff an offset-global value, or the direct
    ``ldr xD,[x0,#want_off]``).  This is the CONFIRMATION that a selector→ivar
    name match is real: the getter must actually return that ivar (covers the plain
    accessor and the oneof getter, which loads the discriminator then the ivar)."""
    try:
        insns = disasm(ctx, imp, max_insns=max_insns, stop_at_ret=True)
    except (NameError, ImportError):
        raise
    except Exception:
        return False
    base = {}
    for k, ins in enumerate(insns):
        mn = ins.mnemonic
        if mn == 'adrp':
            pa = parse_adrp(ins.op_str)
            if pa is not None:
                base[pa[0]] = pa[1]
            continue
        if mn in ('ldr', 'ldrsw'):
            m = mem_operand(ins.op_str)
            if m is None or m[1] != 'x0':
                continue
            if m[2] is not None:                         # register-indexed: [x0, xOff]
                off_addr = _resolve_offset_addr(insns[:k], m[2], base)
                if off_addr is not None:
                    try:
                        if ctx.read_u32(off_addr) == want_off:
                            return True
                    except (NameError, ImportError):
                        raise
                    except Exception:
                        pass
            elif m[3] == want_off:                       # direct [x0, #want_off]
                return True
    return False


def _build_accessor_ivar_map(ctx, cls, field_ivars):
    """``{getter_selector: ivar_name}`` for OBJECT-typed real-field ivars whose
    getter method CONFIRMS the binding by loading that ivar's offset.

    Object/message fields serialize through their property getter, so this lets the
    walk bind the getter call back to the ivar.  Restricted to object ivars
    (``type_enc`` starts with ``@``) — scalars always bind via the direct self-load
    tier and never reach the accessor path, so building/confirming their getters
    would be wasted work."""
    out = {}
    for iv in field_ivars:
        if not iv.name or not iv.type_enc or not iv.type_enc.startswith('@'):
            continue
        sel = iv.name[1:] if iv.name.startswith('_') else iv.name
        if not sel:
            continue
        m = cls.get_method(sel)
        if m is None or not m.imp:
            continue
        if _getter_loads_offset(ctx, m.imp, iv.offset):
            out[sel] = iv.name
    return out


def _trace_accessor_sourced_value(ctx, full_prefix, sel_to_ivar):
    """Bind a message/object field write whose value came from a property getter.

    Trace the helper's value register (x1) back through the block to the defining
    getter ``bl <selector-stub>`` — following ``mov`` chains and skipping ARC
    retain/autorelease passthroughs (a `bl` that is not a selector stub returns its
    x0 argument unchanged) — then map the resolved selector to its confirmed ivar.
    Returns the ivar name, or None when the value is not getter-sourced."""
    cur = 'x1'                                     # object-field value arg
    for i in range(len(full_prefix) - 1, -1, -1):
        ins = full_prefix[i]
        mn = ins.mnemonic
        if mn == 'bl':
            if cur != 'x0':
                continue                           # call doesn't define our value reg
            sel = stub_selector(ctx, _parse_imm(ins.op_str))
            if sel is None:
                cur = 'x0'                         # ARC passthrough (retain/autorelease)
                continue
            return sel_to_ivar.get(sel)
        d = dst_reg(ins.op_str)
        if d is None or _norm_reg(d) != cur:
            continue                               # doesn't define our value reg
        if mn == 'mov':
            p = split_ops(ins.op_str)
            src = _norm_reg(p[1]) if len(p) == 2 else None
            if src is not None and src.startswith('x'):
                cur = src                          # follow the mov chain
                continue
        return None                                # defined by an insn we can't follow
    return None


def bind_write(ctx, w, self_reg, base_regs, offset_to_name, sel_to_ivar=None):
    """Resolve a write event to its container ivar name, or a reason it didn't.
    Returns (ivar_name | None, status)."""
    pre = w['pre']
    # 1. value load feeding the helper (last [base,off] load into w1/x1/d0/s0).
    # Scan back from the write bl but STOP at the previous `bl`: each field's value
    # setup lives between its own write and the prior one.
    vload = None
    for ins in reversed(pre[:-1]):
        if ins.mnemonic == 'bl':
            break
        if ins.mnemonic in _LOAD_MNEMONICS:
            parsed = _parse_load(ins.op_str)
            if parsed and parsed[0] in _VALUE_REGS:
                vload = parsed; break

    # 2a. scalar/double field: value loaded directly from self[ivar_off].
    if vload is not None and vload[1] in (self_reg, 'x0') and vload[2] is not None:
        name = _addr_to_name(ctx, _resolve_offset_addr(pre, vload[2], base_regs),
                             offset_to_name)
        if name is not None:
            return name, 'ok'

    # 2d. accessor-sourced message/object field: the value came from a property
    # GETTER call (objc selector stub), not a self-load — trace it to the getter and
    # map the confirmed selector back to its ivar.  Tried BEFORE the cont_off
    # container tier (2b): a STALE threaded cont_off left by a prior scalar field
    # would otherwise mis-bind this getter-sourced message (e.g. _CPUsageEnvelope
    # .context grabbing _collectionEndTimestamp's offset).  Safe to front-run — it
    # resolves ONLY a getter `bl` feeding x1, so a genuine inline repeated message
    # (whose value is a stack scratch, not a getter) falls straight through to 2b.
    if vload is None and sel_to_ivar:
        srcblk, srck = w.get('srcblk'), w.get('srck')
        if srcblk is not None and srck is not None:
            name = _trace_accessor_sourced_value(ctx, srcblk[:srck], sel_to_ivar)
            if name is not None:
                return name, 'ok-accessor'

    # 2b. repeated / embedded-message / packed field: value from a STACK SCRATCH
    # (begin-submessage idiom — vload is None) or an ELEMENT/CONTAINER pointer
    # (vload base != self) — bind the CONTAINER via the threaded cont_off.
    # GUARD: a SCALAR whose value IS a self-load but whose offset failed to resolve
    # must NOT fall through here (would mis-bind to a low-offset internal ivar).
    is_container_write = (vload is None) or (vload[1] not in (self_reg, 'x0'))
    if is_container_write:
        name = _addr_to_name(ctx, w.get('cont_off'), offset_to_name)
        if name is not None:
            return name, 'ok-repeated'

    if vload is None:
        # 2c. S1 hoisted value-load: no value-load in `pre` and no container — the
        # value may have been loaded into a callee-saved reg above the writer-init
        # bl.  Trace the dependency through the full block prefix before giving up.
        srcblk, srck = w.get('srcblk'), w.get('srck')
        if srcblk is not None and srck is not None:
            name = _trace_hoisted_self_value(ctx, pre, srcblk[:srck],
                                             self_reg, base_regs, offset_to_name)
            if name is not None:
                return name, 'ok-hoisted'
        return None, 'no-value-load'
    if vload[1] not in (self_reg, 'x0'):
        return None, 'nested'
    return None, 'unresolved-offset'


def build_writeto_indegree(ctx: BinaryContext,
                           cl: ClassList) -> Tuple[Dict[int, Set[int]], Set[int]]:
    """Binary-wide pre-pass for the CFG walk: build the branch-target in-degree map
    (shared-thunk detector) and the set of all method IMPs (foreign-call detector).

    Run ONCE per extraction in :func:`extract_all` and threaded onto ``ctx``; the
    walk consumes it per class.  Returns ``(indeg, foreign_imps)``."""
    foreign_imps = {m.imp for c in cl for m in c.methods if m.imp}
    indeg = build_branch_indegree(ctx, cl, sorted(foreign_imps))
    return indeg, foreign_imps


def _walk_field_numbers(ctx, cls, field_ivars, indeg, foreign_imps,
                        _out_helpers=None, _out_zero_fields=None,
                        _out_writes=None) -> Dict[str, int]:
    """CFG-walk ``{ivar_name: field_number}`` for *cls*.  ``field_ivars`` is the
    caller's already-filtered real-field ivar list (so no internal/has-bit ivar can
    be bound); ``indeg``/``foreign_imps`` come from :func:`build_writeto_indegree`.

    If ``_out_helpers`` is not None it is populated with ``{ivar_name: helper_va}``
    (the field-write ``bl`` target) for every bound field — the same per-ivar
    write-helper address the forward scan captures, so the walk can serve as the
    sole ``_out_helpers`` source once the forward scan is retired (B8).  Likewise
    ``_out_writes`` receives ``{ivar_name: write_event}`` (the raw walk record, with its
    source block) — what :mod:`proto.mapfields` reads to analyse an inline map loop."""
    m = cls.get_method("writeTo:")
    if m is None or m.imp == 0:
        return {}
    offset_to_name = {iv.offset: iv.name for iv in field_ivars
                      if iv.offset != 0 and iv.name}
    if not offset_to_name:
        return {}
    self_reg, base_regs = detect_context(ctx, m.imp)
    # Confirmed {getter_selector: ivar} for object/message fields — they serialize
    # via their property getter, so the walk binds the getter call back to the ivar.
    sel_to_ivar = _build_accessor_ivar_map(ctx, cls, field_ivars)
    writes, _flags = writeto_walk(ctx, m.imp, foreign_imps - {m.imp}, indeg,
                                  self_reg=self_reg, base_regs=base_regs)
    bound: Dict[str, int] = {}
    for w in writes:                 # discovery order: container field wins (first)
        # use the live ivar-offset-table base captured at this write (handles a base
        # register reloaded mid-writeTo:), falling back to the prologue capture.
        name, _st = bind_write(ctx, w, self_reg, w.get('base_regs') or base_regs,
                               offset_to_name, sel_to_ivar)
        if name is not None and name not in bound:
            bound[name] = w['n']
            if _out_helpers is not None and w.get('helper_va') is not None:
                _out_helpers[name] = w['helper_va']
            if _out_writes is not None:
                _out_writes[name] = w
    # Apple 0-based fields (field# 0, illegal in proto): bind them to their ivar so
    # the caller can flag the estimate as NOT wire-accurate (TODO #52).  Only ivars
    # the walk did NOT already bind to a legal number qualify.
    if _out_zero_fields is not None:
        for zw in _flags.get('zero_writes', ()):
            name, _st = bind_write(ctx, zw, self_reg, zw.get('base_regs') or base_regs,
                                   offset_to_name, sel_to_ivar)
            if name is not None and name not in bound:
                _out_zero_fields.add(name)
    return bound


def _extract_writeto_field_numbers(
    ctx: BinaryContext,
    cls: ObjcClass,
    field_ivars: List[ObjcIvar],
    _out_helpers: Optional[Dict[str, int]] = None,
    _out_zero_fields: Optional[Set[str]] = None,
    _out_writes: Optional[Dict[str, dict]] = None,
) -> Dict[str, int]:
    """Confirmed ``{ivar_name: field_number}`` from -[Cls writeTo:], via the CFG
    walk (:func:`_walk_field_numbers`).

    The walk is the sole decoder (Phase B8): it binds each field-write to its
    container ivar by tracing the value/offset registers, and is sound — every
    binding is value-traced, never positional.  It only runs when ``extract_all``
    has threaded the binary-wide branch-indegree pre-pass onto ``ctx``
    (``ctx._writeto_indeg`` / ``ctx._writeto_foreign_imps``).  A bare call without
    that pre-pass (e.g. a direct unit test, or ``ctx is None``) returns ``{}`` —
    no decode, fail-safe; the caller then falls back to its own estimate.

    ``_out_helpers`` (per-ivar write-helper VA, used downstream to tell
    ``repeated string`` from ``repeated bytes``/``message``) is populated by the
    walk for every ivar it binds.

    For the GEOLPR/GEOPublisher classes whose map fields are written inside an
    ``enumerateKeysAndObjectsUsingBlock:`` block (the field number lives in the block's
    invoke function, not in ``writeTo:``) the walk binds nothing for the map ivar;
    :mod:`proto.mapfields` recovers those numbers from the block, and anything it cannot
    recover degrades to a flagged ivar-order estimate upstream — fail-safe, never a
    confident error."""
    indeg = getattr(ctx, "_writeto_indeg", None)
    foreign_imps = getattr(ctx, "_writeto_foreign_imps", None)
    if indeg is None or foreign_imps is None:
        return {}
    try:
        return _walk_field_numbers(ctx, cls, field_ivars, indeg, foreign_imps,
                                   _out_helpers=_out_helpers,
                                   _out_zero_fields=_out_zero_fields,
                                   _out_writes=_out_writes)
    except (NameError, ImportError):
        raise                       # our own wiring bug — never mask it
    except Exception as exc:
        # Bad binary input → per-class fail-safe (flagged ivar-order estimate).
        log.debug("writeTo walk failed for %s: %s", getattr(cls, "name", "?"), exc)
        return {}


def writeto_sent_selectors(ctx: BinaryContext, imp: int) -> Optional[frozenset]:
    """Every selector the ``writeTo:`` at *imp* sends, or None when that cannot be told.

    Read off the code the CFG walk visits: a ``bl`` / tail-``b`` to an
    ``objc_msgSend$<sel>`` stub sends ``<sel>``, and a selector loaded into x1 from
    ``__objc_selrefs`` is the selector of a plain ``objc_msgSend`` call (counted whether
    or not the call follows — an over-count only makes the caller more cautious).
    None when the walk did not see all of the method: it was truncated, made an
    indirect call (``blr``), or branched into a shared thunk it does not enter; or when
    the binary-wide walk pre-pass is absent."""
    indeg = getattr(ctx, "_writeto_indeg", None)
    foreign_imps = getattr(ctx, "_writeto_foreign_imps", None)
    if indeg is None or foreign_imps is None or not imp:
        return None
    try:
        _writes, flags = writeto_walk(ctx, imp, foreign_imps - {imp}, indeg)
    except (NameError, ImportError):
        raise
    except Exception as exc:
        log.debug("writeTo walk failed at %#x: %s", imp, exc)
        return None
    if flags['truncated'] or flags['indirect_calls'] or flags['unexamined_thunks']:
        return None
    sels = {stub_selector(ctx, t) for t in flags['call_targets']}
    selrefs = [s for (_seg, name), s in getattr(ctx, "_sections", {}).items()
               if name == "__objc_selrefs"]
    for slot in flags['x1_loads']:
        if _is_in_any_section(slot, selrefs):
            try:
                sels.add(ctx.read_cstring(ctx.read_ptr(slot)))
            except (NameError, ImportError):
                raise
            except Exception:
                return None             # a selector slot we cannot read: cannot tell
    sels.discard(None)
    return frozenset(sels)
