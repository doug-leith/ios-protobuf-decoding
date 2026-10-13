"""proto/repeated — repeated-field element-type resolution.

Carved from ``proto.extractor`` (#11 monolith split, step 4): given a class's readFrom
dispatch (from proto.dispatch) and metaclass type-pool, resolve the element type of a
repeated field — via the readFrom dispatch arms, the compare-chain, the adder->ivar
lever, or the name-suffix fallback. Imports macho.* + arm64decode + protocore + dispatch
(never proto.extractor) -> cycle-free; extractor re-imports the surface.
"""
from __future__ import annotations
import logging
from dataclasses import dataclass
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

from macho.memory    import BinaryContext, _ctx_cache
from macho.strings   import StringTable
from macho.classlist import ClassList, ObjcClass, ObjcIvar
from macho.disasm    import disasm, _parse_imm, _norm_reg
from proto.arm64cfg  import parse_adrp, mem_operand
from macho.arm64decode import _decode_b_bl_target, _is_bl_word
from proto.protocore import _proto_name, _CLASS_TO_PROTO
from proto.dispatch  import (_ARM_MAX_INSNS, _dominance_field_of,
    _find_field_number_register, _func_end, _locate_dispatch_arms, _read_raw_word,
    _walk_jumptable_arms)

log = logging.getLogger(__name__)

def _repeated_element_type(
    ivar: ObjcIvar,
    instance_methods: Set[str],
    metaclass: Optional[ObjcClass],
) -> str:
    """
    For a repeated field, find the selector of the ``+[Cls xyzType]`` metaclass method
    that names the element type, or ``"bytes"`` when there is none.

    The metaclass exposes a selector like ``mapsResultsType`` whose body returns
    ``[GEOPDMapsResult class]``; the field name is depluralised (``mapsResults`` ->
    ``mapsResult``) and ``Type`` appended to form the candidate selector.  The class
    itself is read out of the method's IMP by :func:`_resolve_repeated_type`, so only the
    SELECTOR is chosen here.

    There is deliberately NO fallback that guesses the element class from the field
    name (the former "Strategy 2": strip the plural ``-s``, capitalise, accept a unique
    classlist name ending with the result).  It typed fields wrongly --
    ``GEOPDSSearchEvChargingParameters.networks`` (a repeated string) became
    ``GEOLogMsgEventNetwork`` and ``TRANSITPbLocationFingerprintsV1`` took the sibling
    class -- and everything it resolved is now recovered from the binary:
    the readFrom: dispatch / adder->ivar lever (``_resolve_repeated_via_dispatch_ivars``),
    the element class-reference lever (``_resolve_repeated_via_classrefs``), the write
    helper (string), or the inline-struct encoding.  A field none of them resolves stays
    the honest ``repeated bytes`` (flagged by the caller).
    """
    pname = _proto_name(ivar.name)
    singular = pname.rstrip("s") if pname.endswith("s") else pname
    type_sel = f"{singular}Type"
    type_sel_plural = f"{pname}Type"

    # +[Cls xyzType] metaclass method
    for sel in (type_sel, type_sel_plural):
        if metaclass and any(m.name == sel for m in metaclass.methods):
            return sel

    return "bytes"


#
# [cap:INPUT-SANITY] _ADDER_MAX_INSNS bounds the disasm of an _addNoFlags<X>:
#   accessor body.  It used to be [cap:AFFECTS-OUTPUT] at 40 — a deliberately tiny
#   window that confined the adder→ivar lever to the FIRST ivar-slot load (raising it
#   reached a later confounding array-offset load and dropped the binding, e.g.
#   GEOPDPlaceCollection.mediaLinks -> bytes at >=100).  `_adder_array_ivar` now takes
#   the FIRST array-offset load structurally (the accessor loads its own backing array
#   before any confounder), so the OUTPUT no longer depends on this value: it is just a
#   generous runaway guard for a pathological / tail-called accessor with no `ret`.
_ADDER_MAX_INSNS    = 256    # runaway guard only; first-match returns well before this


# ObjC type encodings for the NSArray-backed ivar of a repeated field.  Used by
# the adder→ivar lever to pick the backing array ivar an add-accessor appends to
# (excluding the flags/has-bits struct ivar the same accessor also touches).
_ARRAY_IVAR_ENCS = ('@"NSArray"', '@"NSMutableArray"')


# _degenerate_block_partition (registry `degenerate-partition`, REPLACE) was DELETED in
# TODO #42: dominance attribution (_dominance_field_of, over a COMPLETE CFG) makes the
# bail-out unnecessary by construction — each field owns exactly the blocks its match
# edge dominates, so a collapsed jump-table / stray sentinel can no longer lump multiple
# element cores under one field.


def _resolve_compare_chain_elements(
    ctx: BinaryContext, read_specified_va: int, core_index: Dict[int, str],
) -> Dict[int, str]:
    """
    Resolve ``{field_number: element_class}`` from a reader core that dispatches
    fields with an explicit **compare chain** rather than a jump table.

    This is the small-/few-field encoding of the very same field→handler dispatch
    the jump table expresses for larger messages (and the form used for the low
    fields of a hybrid reader, e.g. ALSLocationResponse's fields 1/2 alongside a
    jump table for 21-24).  The idiom is::

        lsr  Wf, Wtag, #3              ; field# = tag >> 3   (Wf = field-number reg)
        ...
        cmp  Wf, #N ; b.cond TGT       ; routes field N to its handler block
        ...
        bl   _<ElementClass>ReadAllFrom

    Principled, not a blind ``bl`` scan: handler blocks are located by control
    flow (:func:`_compare_chain_blocks` — ``b.eq`` → target, ``b.ne`` →
    fall-through), and an element ``bl`` to a known ReadAllFrom core is attributed
    to the field whose block address-range contains it.  A ``bl`` outside every
    field block (e.g. a runtime helper in the preamble) is ignored.

    Returns ``{}`` when the field-number register can't be uniquely identified or
    no guarded element call is found.
    """
    if not core_index:
        return {}
    func_end = _func_end(ctx, read_specified_va)
    if func_end is None:
        return {}
    field_reg = _find_field_number_register(ctx, read_specified_va, func_end)
    if field_reg is None:
        return {}
    # TODO #42: attribute each element bl by DOMINANCE (exact) rather than the old
    # _compare_chain_blocks + address-range _field_for_addr.  _dominance_field_of builds
    # the COMPLETE CFG (br jump-table arms injected) so handlers reached via an indirect
    # dispatch are reachable; dominance then makes the degenerate-partition guard
    # unnecessary by construction (a field owns exactly the blocks its match edge
    # dominates, so a collapsed jump-table / stray sentinel can't lump cores under it).
    field_of = _dominance_field_of(ctx, read_specified_va, func_end, field_reg)
    result: Dict[int, str] = {}
    va = read_specified_va
    while va < func_end:
        word = _read_raw_word(ctx, va)
        if word is None:
            break
        if _is_bl_word(word):                          # bl
            target = _decode_b_bl_target(word, va)
            if target in core_index:
                fn = field_of(va)
                if fn is not None:
                    result.setdefault(fn, core_index[target])
                    log.debug("dispatch(cmp-chain): field %d -> %s (-> 0x%x)",
                              fn, core_index[target], target)
        va += 4
    return result


def _resolve_compare_chain_ivars(
    ctx: BinaryContext, read_specified_va: int, core_index: Dict[int, str],
    cls: ObjcClass,
) -> Dict[str, Tuple[str, int]]:
    """Adder→ivar lever for the **compare-chain** reader shape — the small-message
    counterpart of :func:`_resolve_repeated_element_ivars`.

    A compare-chain block that handles a repeated-message field N holds both the
    element parse and the append::

        cmp  Wf, #N ; b.cond TGT
        ...
        bl   _<ElementClass>ReadAllFrom     ; parse element  (∈ core_index)
        ...
        bl   -[Cls _addNoFlags<X>:]         ; append it      (∈ own_imps)

    Both ``bl``s are attributed to N's handler block (located by control flow via
    :func:`_compare_chain_blocks`, not linear adjacency), yielding
    ``{ivar_name: (element_class, field_number)}`` bound to the EXACT backing ivar
    (via :func:`_adder_array_ivar`).  Applied without needing the field number to
    be write-confirmed, so it reaches classes whose compare chain knows the
    element type but whose ivar number the writeTo:/pointer-table pass left
    unconfirmed (e.g. GEOPDExternalAction).  Returns ``{}`` when the field-number
    register is ambiguous or no element+adder pair is found.
    """
    if not core_index:
        return {}
    own_imps: FrozenSet[int] = frozenset(m.imp for m in cls.methods if m.imp)
    array_offsets: FrozenSet[int] = frozenset(
        iv.offset for iv in cls.ivars if iv.type_enc in _ARRAY_IVAR_ENCS)
    if not own_imps or not array_offsets:
        return {}
    off_to_ivar: Dict[int, ObjcIvar] = {iv.offset: iv for iv in cls.ivars}
    func_end = _func_end(ctx, read_specified_va)
    if func_end is None:
        return {}
    field_reg = _find_field_number_register(ctx, read_specified_va, func_end)
    if field_reg is None:
        return {}
    # TODO #42: dominance attribution (exact, COMPLETE CFG) replaces _compare_chain_blocks
    # + address-range _field_for_addr; the degenerate-partition guard is unnecessary by
    # construction (each field owns exactly the blocks its match edge dominates).
    field_of = _dominance_field_of(ctx, read_specified_va, func_end, field_reg)

    # Collect, per field block, the first element-core bl and the first adder bl.
    by_field: Dict[int, Dict[str, Any]] = {}
    va = read_specified_va
    while va < func_end:
        word = _read_raw_word(ctx, va)
        if word is None:
            break
        if _is_bl_word(word):                          # bl
            target = _decode_b_bl_target(word, va)
            fn = field_of(va)
            if fn is not None and target is not None:
                slot = by_field.setdefault(fn, {})
                if target in core_index:
                    slot.setdefault("element", core_index[target])
                elif target in own_imps:
                    slot.setdefault("adder", target)
        va += 4

    out: Dict[str, Tuple[str, int]] = {}
    for fn, slot in by_field.items():
        element = slot.get("element")
        adder = slot.get("adder")
        if element is None or adder is None:
            continue
        off = _adder_array_ivar(ctx, adder, array_offsets)
        if off is None:
            continue
        # off is always a key of off_to_ivar: array_offsets (which bounds
        # _adder_array_ivar's return value) is built from the same cls.ivars.
        out.setdefault(off_to_ivar[off].name, (element, fn))
    return out


def _adder_array_ivar(
    ctx: BinaryContext, imp_va: int, array_offsets: "FrozenSet[int]"
) -> Optional[int]:
    """Return the instance-ivar byte offset that the add-accessor at *imp_va*
    appends to, identified **by the ivar-offset variable it loads** — not by name.

    A generated ``-_addNoFlags<X>:`` accessor reads its backing array through the
    runtime ivar-offset table::

        adrp  x20, <page>
        ldrsw x8,  [x20, #off]     ; x8 = OBJC_IVAR_$_Cls._xs  (the byte offset)
        ldr   x9,  [x19, x8]       ; x9 = self->_xs            (register-offset)

    The constant at the ``adrp+ldrsw`` slot **is** the ivar's byte offset, so we
    read that 4-byte slot and match it against *array_offsets* (the class's
    NSArray/NSMutableArray field-ivar offsets).  Matching against array offsets
    excludes the flags/has-bits ivar the accessor also stores into (a struct
    ivar, never in *array_offsets*) and any singular message ivar.

    Returns the **first** array-ivar offset the accessor loads — structurally that
    is its OWN backing array (an ``-_addNoFlags<X>:`` accessor loads the array it
    appends to before any other ivar), so taking the first match binds the right
    ivar and stops before any later confounding array-offset load.  ``None`` if the
    accessor references no array offset.  This first-match rule is what makes the
    result independent of ``_ADDER_MAX_INSNS`` (now only a runaway guard).
    """
    if imp_va == 0 or not array_offsets:
        return None
    try:
        insns = disasm(ctx, imp_va, max_insns=_ADDER_MAX_INSNS, stop_at_ret=True)
    except Exception:
        return None
    adrp_page: Dict[str, int] = {}
    for ins in insns:
        if ins.mnemonic == 'adrp':
            pa = parse_adrp(ins.op_str)
            if pa is not None:
                adrp_page[pa[0]] = pa[1]
            continue
        # The ivar-offset load is a sign-extending word load (offsets are 32-bit);
        # a 64-bit `ldr` here is a pointer/singleton load, not an ivar offset.
        if ins.mnemonic == 'ldrsw':
            mo = mem_operand(ins.op_str)        # immediate/no-offset form only
            if mo is None or mo[2] is not None or mo[1] not in adrp_page:
                continue
            slot_va = adrp_page[mo[1]] + mo[3]
            try:
                val = int.from_bytes(ctx.read_bytes(slot_va, 4), 'little')
            except Exception:
                continue
            if val in array_offsets:
                return val          # first array-offset load = the accessor's own ivar
    return None


def _resolve_repeated_element_ivars(
    ctx: BinaryContext,
    cls: ObjcClass,
    arms: Dict[int, int],
    core_index: Dict[int, str],
) -> Dict[str, Tuple[str, int]]:
    """Bind ``{ivar_name: (element_class, field_number)}`` directly from the
    readFrom: jump-table arms — the **adder→ivar lever**.

    The field-number-keyed resolver (:func:`_resolve_repeated_via_dispatch`) is
    only safe to apply when a field's number is *confirmed* (writeTo:/pointer
    table), because an unconfirmed ordinal can attach a sibling's type.  This
    resolver sidesteps the number entirely: each repeated-message arm carries the
    field→ivar binding directly, so the element type is attached to the exact
    ivar with no ordinal guess.

    Per arm we read two ``bl`` targets:

      * **element class** — the arm's ``bl`` whose target is a known ReadAllFrom
        core (``∈ core_index``).
      * **backing ivar** — the arm's ``bl`` into one of *this class's* method IMPs
        (the ``_addNoFlags<X>:`` accessor); the accessor's ivar-offset variable
        pins the exact array ivar (:func:`_adder_array_ivar`).

    An arm with both is an unambiguous repeated-message field.  Arms with only an
    element ``bl`` (a *singular* message field — it has a setter, not an adder)
    are intentionally not bound here, which is exactly what prevents the
    singular-vs-repeated mis-binding the field-number ordinal hit (e.g.
    GEOETARequest's singular field-3 ``GEOWaypoint`` vs repeated field-4
    ``destinations``).  The jump-table index is returned alongside the type as
    the *dispatch's* field number, but the caller treats only the **type** as
    authoritative — the index is informational, since some readers yield an
    unreliable index and the writeTo:/pointer-table pass owns number confirmation.
    """
    if not arms:
        return {}
    own_imps: FrozenSet[int] = frozenset(m.imp for m in cls.methods if m.imp)
    if not own_imps:
        return {}
    array_offsets: FrozenSet[int] = frozenset(
        iv.offset for iv in cls.ivars if iv.type_enc in _ARRAY_IVAR_ENCS)
    if not array_offsets:
        return {}
    off_to_ivar: Dict[int, ObjcIvar] = {iv.offset: iv for iv in cls.ivars}

    out: Dict[str, Tuple[str, int]] = {}
    for field_number, arm_va in arms.items():
        element: Optional[str] = None
        adder_imp: Optional[int] = None
        try:
            arm_insns = disasm(ctx, arm_va, max_insns=_ARM_MAX_INSNS,
                               stop_at_ret=False)
        except Exception:
            continue
        for insn in arm_insns:
            if insn.mnemonic in ('b', 'br', 'ret', 'retaa', 'retab'):
                break
            if insn.mnemonic != 'bl':
                continue
            t = _parse_imm(insn.op_str)
            if t is None:
                continue
            if element is None and t in core_index:
                element = core_index[t]
            elif adder_imp is None and t in own_imps:
                adder_imp = t
        if element is None or adder_imp is None:
            continue
        off = _adder_array_ivar(ctx, adder_imp, array_offsets)
        if off is None:
            continue
        # off is always a key of off_to_ivar: array_offsets (which bounds
        # _adder_array_ivar's return value) is built from the same cls.ivars.
        out.setdefault(off_to_ivar[off].name, (element, field_number))
    return out


def _resolve_repeated_via_dispatch_ivars(
    ctx: BinaryContext,
    cls: ObjcClass,
    core_index: Dict[int, str],
) -> Dict[str, Tuple[str, int]]:
    """Public entry for the adder→ivar lever: bind ``{ivar_name: (element_class,
    field_number)}`` from this class's readFrom: dispatch, reading BOTH encodings.

    The jump-table form (:func:`_resolve_repeated_element_ivars`) takes precedence;
    the compare-chain form (:func:`_resolve_compare_chain_ivars`) fills the
    small-message readers a jump table doesn't cover.  Both bind the element type
    to the exact backing ivar via the ``_addNoFlags<X>:`` accessor's ivar-offset
    variable, so the result is safe to apply even when the field number is not
    write-confirmed.  Empty when neither encoding yields an element+adder pair."""
    if not core_index:
        return {}
    arms, core_va, readfrom_va = _locate_dispatch_arms(ctx, cls, core_index)
    if readfrom_va is None:
        return {}
    out: Dict[str, Tuple[str, int]] = {}
    if arms:
        out.update(_resolve_repeated_element_ivars(ctx, cls, arms, core_index))
    # Compare-chain fill (runs on the dispatch core when located, else the
    # readFrom: entry itself).  setdefault → jump table wins on any overlap.
    chain_core = core_va if core_va is not None else readfrom_va
    for ivn, val in _resolve_compare_chain_ivars(
            ctx, chain_core, core_index, cls).items():
        out.setdefault(ivn, val)
    return out


def _classref_name(ctx: BinaryContext, cl: ClassList, slot_va: int) -> Optional[str]:
    """Name of the class whose ``__objc_classrefs`` slot is at *slot_va*, or None.

    A binary-local class resolves through ``cl.by_vmaddr``; an external class (a
    chained-fixup bind) through :meth:`BinaryContext.bind_name_for`.  Returns None
    when the slot is not a class reference at all (a selector reference, an ivar
    offset slot, ...), which is how a class-ref load is told from other ``ldr``s."""
    try:
        v = ctx.read_ptr(slot_va)
        if v:
            c = cl.by_vmaddr(v)
            if c is not None and not c.is_meta:
                return c.name
        b = ctx.bind_name_for(slot_va)
        if b and b.startswith("_OBJC_CLASS_$_"):      # not an _OBJC_IVAR_$_ offset slot
            return b[len("_OBJC_CLASS_$_"):]
    except Exception:
        pass
    return None


def _selref_name(ctx: BinaryContext, slot_va: int) -> Optional[str]:
    """Selector string of the ``__objc_selrefs`` slot at *slot_va*, or None."""
    try:
        v = ctx.read_ptr(slot_va)
        return ctx.read_cstring(v) if v else None
    except Exception:
        return None


def _msgsend_stub_selector(ctx: BinaryContext, va: int) -> Optional[str]:
    """Selector baked into the ``_objc_msgSend$<selector>`` stub at *va*, or None.

    The linker emits one such stub per selector a binary messages::

        adrp  x1, <page>
        ldr   x1, [x1, #off]      ; the __objc_selrefs slot  -> x1 = the selector
        adrp  x16, ... ; ldr x16, [x16, ...] ; br x16     ; tail to objc_msgSend

    so a ``bl`` to it is a message send of that selector.  Memoised on *ctx*."""
    cache = _ctx_cache(ctx, "_msgsend_stub_sel", dict)
    if va in cache:
        return cache[va]
    sel: Optional[str] = None
    try:
        ins = disasm(ctx, va, max_insns=2, stop_at_ret=False)
        if (len(ins) == 2 and ins[0].mnemonic == 'adrp' and ins[1].mnemonic == 'ldr'):
            pa = parse_adrp(ins[0].op_str)
            mo = mem_operand(ins[1].op_str)
            if (pa is not None and mo is not None and mo[2] is None
                    and mo[1] == pa[0] and _norm_reg(mo[0]) == 'x1'):
                sel = _selref_name(ctx, pa[1] + mo[3])
    except Exception:
        sel = None
    cache[va] = sel
    return sel


def _classref_windows(
    ctx: BinaryContext, cl: ClassList, insns: List[Any],
    adder_ivar: Dict[int, str], adder_sel: Dict[str, str], *, is_arm: bool,
) -> List[Tuple[str, Tuple[str, ...]]]:
    """Walk *insns* in order and return ``[(ivar_name, class_refs_seen)]``: one entry
    per call of an add-accessor, holding every class reference loaded since the
    previous add-accessor call (or the start of the stream).

    A call is a direct ``bl`` to the accessor's IMP (``adder_ivar``), or, for readers
    that message it, a ``bl`` to the accessor's ``_objc_msgSend$<selector>`` stub or a
    load of its selector reference (``adder_sel``).  A dispatch arm (*is_arm*) ends at
    its first branch/return, exactly as the adder->ivar lever reads one."""
    pages: Dict[str, int] = {}
    recent: List[str] = []
    out: List[Tuple[str, Tuple[str, ...]]] = []
    for ins in insns:
        mn = ins.mnemonic
        if is_arm and mn in ('b', 'br', 'ret', 'retaa', 'retab'):
            break
        if mn == 'adrp':
            pa = parse_adrp(ins.op_str)
            if pa is not None:
                pages[pa[0]] = pa[1]
        elif mn == 'ldr':
            mo = mem_operand(ins.op_str)
            if mo is None or mo[2] is not None:
                continue
            dest = _norm_reg(ins.op_str.split(',')[0].strip())
            if mo[1] in pages and dest is not None and dest.startswith('x'):
                slot = pages[mo[1]] + mo[3]
                name = _classref_name(ctx, cl, slot)
                if name is not None:
                    recent.append(name)
                else:
                    sel = _selref_name(ctx, slot)
                    if sel is not None and sel in adder_sel:
                        out.append((adder_sel[sel], tuple(recent)))
                        recent = []
            pages.pop(dest, None)       # dest now holds a loaded value, not a page
        elif mn == 'bl':
            t = _parse_imm(ins.op_str)
            if t in adder_ivar:
                out.append((adder_ivar[t], tuple(recent)))
                recent = []
            elif adder_sel and t is not None:
                sel = _msgsend_stub_selector(ctx, t)
                if sel is not None and sel in adder_sel:
                    out.append((adder_sel[sel], tuple(recent)))
                    recent = []
    return out


def _resolve_repeated_via_classrefs(
    ctx: BinaryContext,
    cls: ObjcClass,
    cl: ClassList,
    core_index: Dict[int, str],
) -> Dict[str, Tuple[str, int]]:
    """Bind ``{ivar_name: (element_class, field_number)}`` from the **element class
    reference** the reader loads next to the add-accessor call -- the class-ref
    counterpart of the adder->ivar lever.

    A generated reader builds each repeated-message element with
    ``[[ElementClass alloc] init]``, reads it, then appends it with the field's own
    ``-add<X>:`` accessor.  The element class therefore appears in the binary as a
    class-reference load immediately before the accessor call, whatever helper does
    the reading.  This is the structural source for readers that do NOT call a
    ``<Class>ReadAllFrom`` core (which :func:`_resolve_repeated_element_ivars`
    keys on), e.g. the small inline-reader messages (``GEOPDTileList.tiles`` ->
    ``GEOTileCoordinate``) and the old-style classes that message the accessor via
    ``objc_msgSend`` (locationd ``TRANSITPbLocationFingerprints*``).

    The accessor is identified structurally (the own IMP whose body loads the
    backing array's ivar offset, :func:`_adder_array_ivar`), never by the ivar name;
    its selector is used only to spot an ``objc_msgSend`` call site.  Streams read:
    every dispatch arm, the C read function, the dispatch core and the ObjC
    ``readFrom:`` body.

    Strict by construction (precision over recall): an ivar is bound only if EVERY
    call site of its accessor has exactly one distinct class reference in its
    window and all sites agree, and that class is a binary-local class.  Zero or
    several candidates, or disagreeing sites, bind nothing.  The result is an
    element TYPE only (the field number is informational)."""
    array_offsets: FrozenSet[int] = frozenset(
        iv.offset for iv in cls.ivars if iv.type_enc in _ARRAY_IVAR_ENCS)
    if not array_offsets:
        return {}
    off_to_ivar: Dict[int, ObjcIvar] = {iv.offset: iv for iv in cls.ivars}
    adder_ivar: Dict[int, str] = {}
    adder_sel: Dict[str, str] = {}
    for m in cls.methods:
        if not m.imp:
            continue
        # With resolved selector names, restrict to the add-accessors themselves
        # (other own methods -- readFrom:, writeTo:, copyWithZone: -- also touch the
        # array).  Without names the structural test below is all there is.
        if m.name is not None and not (m.name.startswith('add')
                                       or m.name.startswith('_addNoFlags')):
            continue
        off = _adder_array_ivar(ctx, m.imp, array_offsets)
        if off is None:
            continue
        adder_ivar[m.imp] = off_to_ivar[off].name
        if m.name is not None:
            adder_sel[m.name] = off_to_ivar[off].name
    if not adder_ivar:
        return {}

    arms, core_va, readfrom_va = _locate_dispatch_arms(ctx, cls, core_index)
    streams: List[Tuple[int, bool, int]] = []        # (start_va, is_arm, field_number)
    seen: Set[int] = set()
    for va in (readfrom_va, core_va,
               next((m.imp for m in cls.methods if m.name == 'readFrom:' and m.imp), None)):
        if va and va not in seen:
            seen.add(va)
            streams.append((va, False, 0))
    for fn, av in (arms or {}).items():
        streams.append((av, True, fn))

    sites: Dict[str, List[Tuple[str, ...]]] = {}
    field_of: Dict[str, int] = {}
    for va, is_arm, fn in streams:
        try:
            if is_arm:
                insns = disasm(ctx, va, max_insns=_ARM_MAX_INSNS, stop_at_ret=False)
            else:
                end = _func_end(ctx, va)
                if end is None:
                    continue
                insns = disasm(ctx, va, max_insns=max(1, (end - va) // 4),
                               stop_at_ret=False)
        except Exception:
            continue
        for ivn, window in _classref_windows(ctx, cl, insns, adder_ivar, adder_sel,
                                             is_arm=is_arm):
            sites.setdefault(ivn, []).append(window)
            if is_arm:
                field_of.setdefault(ivn, fn)

    out: Dict[str, Tuple[str, int]] = {}
    for ivn, windows in sites.items():
        # every site must name exactly one class, and the same one
        verdicts = {(w[0] if len(set(w)) == 1 else None) for w in windows}
        if len(verdicts) != 1 or None in verdicts:
            continue
        name = next(iter(verdicts))
        c = cl.find(name)
        if c is None or c.is_meta:           # external / system class: not an element message
            continue
        out[ivn] = (name, field_of.get(ivn, 0))
    return out


def _resolve_repeated_via_dispatch(
    ctx: BinaryContext,
    cls: ObjcClass,
    core_index: Dict[int, str],
) -> Dict[int, str]:
    """
    Resolve ``repeated <message>`` element classes for *cls* by reading its
    readFrom: field dispatch and matching each field handler's ``bl`` target
    against *core_index* (``{ReadAllFrom_vmaddr: class_name}``).

    Why readFrom: and not writeTo: — element message *types* are intrinsically
    a READ-side fact.  ``writeTo:`` serialises objects that already exist: every
    message field (singular or repeated, any element class) goes through the
    SAME generic sub-message write helper, which dispatches ``[element writeTo:]``
    on the object's runtime type — it never reveals *which* class, only that a
    field *is* a message.  ``readFrom:`` must *create* the elements, so it
    statically references the element class (``[ElementClass alloc]`` /
    ``ElementClassReadAllFrom``) — the information this resolver reads.  So the
    writeTo CFG-walk is the sole decoder for field NUMBERS, but element TYPES
    require this resolver; it is not removable.  (Exception: an inline-C struct
    element, serialised via a named C writer — see TODO #37.)

    Two dispatch encodings of the same field→handler routing are read, both
    principled (they read the binary's own dispatch constants, never names): a
    **jump table** (:func:`_decode_readfrom_jumptable`, used by large messages —
    each arm's element ``bl`` names the field's class) and a **compare chain**
    (:func:`_resolve_compare_chain_elements`, used by few-field messages and the
    low fields of a hybrid reader).  The jump table takes precedence; the
    compare chain fills any field it doesn't cover.

    Returns ``{field_number: element_class_name}`` for every field whose handler
    calls a known proto class's ReadAllFrom core; fields calling no known core
    (scalar/string/enum) are simply absent (caller falls back to other
    heuristics).  Empty dict when the dispatch can't be followed at all
    (precision over recall).

    Results are keyed by field NUMBER, which the caller may only trust when it
    is *confirmed* (:func:`_confirm_field_numbers`) or the message has a single
    field — an unconfirmed ordinal must not be used to bind a type to an ivar
    (a whole-binary diff caught exactly this mis-binding for wrapper→separate-
    core classes like GEOPDDepartureSequence, which are therefore NOT resolved
    here; see the application site in :func:`extract_proto_message`).
    """
    if not core_index:
        return {}
    arms, core_va, readfrom_va = _locate_dispatch_arms(ctx, cls, core_index)
    if readfrom_va is None:
        return {}

    result: Dict[int, str] = {}

    # ── Jump-table tier ───────────────────────────────────────────────────────
    # `arms` come from the directly-anchored core or the wrapper→separate-core
    # finder (e.g. GEOPDDepartureSequence) — see :func:`_locate_dispatch_arms`.
    if arms:
        result.update(_walk_jumptable_arms(ctx, arms, core_index))

    # ── Compare-chain tier (fills fields the table doesn't cover) ─────────────
    # Run on the dispatch core when located, else the readFrom entry itself
    # (table-less readers may have no field-count gate, so core_va is None — the
    # compare-chain walk doesn't need the count).
    chain_core = core_va if core_va is not None else readfrom_va
    for field_number, name in _resolve_compare_chain_elements(
            ctx, chain_core, core_index).items():
        result.setdefault(field_number, name)

    return result


def _class_from_type_method_imp(
    ctx: BinaryContext,
    imp: int,
    cl: ClassList,
) -> Optional[str]:
    """
    Given the IMP of a ``+[Cls xyzType]`` metaclass method, disassemble it
    and return the ObjC class name it returns, or None.

    Apple's runtime ``+xyzType`` methods are always a simple two-instruction
    sequence::

        adrp  x8, <page>         ; address of class reference in __DATA_CONST
        ldr   x0, [x8, #<off>]  ; load the decoded class pointer into x0
        b     <return_thunk>     ; tail-call ret

    Note the **cross-register** pattern: ADRP writes a scratch register (e.g.
    ``x8``) while LDR loads the class pointer *into* ``x0`` (the return
    register) *from* that scratch register — a dedicated scan is needed since
    ADRP and LDR use different registers here.

    For binary-local classes: ``read_ptr`` decodes the class pointer and
    ``cl.by_vmaddr`` resolves it to the ``ObjcClass`` record.  For external /
    system classes (e.g. NSString, NSData): the slot is a chained-fixup bind
    entry, whose symbol name was recorded in ``ctx._bind_name_map`` during
    binary construction and is returned directly (e.g. ``"NSString"``),
    letting callers map it to a proto scalar via :data:`_CLASS_TO_PROTO`.

    This fallback is essential for shared-cache-extracted binaries (like
    GeoServices) where preoptimised relative method lists render selector names
    unresolvable: name-based resolution fails for fields whose ivar name
    doesn't directly suffix-match the element class (e.g.
    ``_legacyPlaceResults`` → element class ``GEOPDPlace``, not
    ``GEOPDLegacyPlaceResult``).
    """
    if imp == 0:
        return None
    try:
        insns = disasm(ctx, imp, max_insns=8)
    except Exception:
        return None

    # Scan for: adrp xN, page  ...  ldr x0, [xN, #off]
    # Collect the ADRP page for each base register seen.
    adrp_page: Dict[str, int] = {}
    for ins in insns:
        if ins.mnemonic == 'adrp':
            pa = parse_adrp(ins.op_str)
            if pa is not None:
                adrp_page[pa[0]] = pa[1]
            continue

        if ins.mnemonic == 'ldr':
            mo = mem_operand(ins.op_str)        # immediate/no-offset form only
            if mo is not None and mo[2] is None:
                # Accept any LDR into x0 whose base register has a known ADRP page
                if _norm_reg(mo[0]) == 'x0' and mo[1] in adrp_page:
                    slot_va = adrp_page[mo[1]] + mo[3]
                    try:
                        class_va = ctx.read_ptr(slot_va)
                        if class_va:
                            obj_cls = cl.by_vmaddr(class_va)
                            if obj_cls is not None and not obj_cls.is_meta:
                                return obj_cls.name
                        # ── Bind table fallback for external / system classes ──
                        # When cl.by_vmaddr() fails, the slot may be a bind entry
                        # for an external class (NSString, NSData, …).  The symbol
                        # name was recorded in _bind_name_map during fixup parsing.
                        bind_sym = ctx.bind_name_for(slot_va)
                        if bind_sym:
                            # "_OBJC_CLASS_$_NSString" → "NSString"
                            if '_OBJC_CLASS_$_' in bind_sym:
                                return bind_sym.split('_OBJC_CLASS_$_', 1)[1]
                            return bind_sym
                    except (ValueError, KeyError):
                        pass

    return None


def _resolve_repeated_type(type_sel: str, metaclass: Optional[ObjcClass],
                            cl: ClassList,
                            ctx: Optional[BinaryContext] = None
                            ) -> Tuple[str, bool]:
    """
    Try to map a '+[Cls xyzType]' selector name to a proto type name.

    Returns ``(type_name, element_unresolved)``.  ``element_unresolved`` is
    ``True`` only when the result is the give-up ``"bytes"`` fallback (no
    element type could be determined); ``False`` for any resolved outcome,
    including a genuine ``"bytes"`` from a resolved ``NSData`` element.

    When ``ctx`` is provided and the method is found by selector name, its IMP
    is disassembled via :func:`_class_from_type_method_imp` to resolve the class
    directly — covering the ``--cache`` path where NSString isn't in the
    binary's own classlist.  Failure falls back to ``"bytes"``
    (``element_unresolved=True``); it does NOT guess by name suffix.
    """
    if metaclass is None:
        return ("bytes", True)
    m = next((m for m in metaclass.methods if m.name == type_sel), None)
    if m is None:
        return ("bytes", True)

    # ── IMP-based resolution (handles external / system classes) ─────────────
    # When ctx is available, disassemble the method body to find the actual
    # class reference.  This succeeds for both binary-local classes AND system
    # classes (NSString etc.) identified via the bind table.
    if ctx is not None and m.imp:
        cls_name = _class_from_type_method_imp(ctx, m.imp, cl)
        if cls_name:
            # Resolved (incl. a genuine NSData → "bytes"), so NOT element_unresolved.
            return (_CLASS_TO_PROTO.get(cls_name, cls_name), False)

    # IMP resolution failed (rare: the +xyzType method exists but its body
    # couldn't be disassembled).  Fall back to the SAFE "bytes" rather than
    # guessing the element class by name suffix.
    #
    # A name-suffix guess HERE was removed 2026-06-09: it was unguarded (first
    # class whose name ended with the field-name suffix won — no uniqueness
    # check) and unflagged (emitted as if it were a principled, confirmed type),
    # so it could silently install a wrong message type.  It fired 0x on every
    # supported artifact (IMP resolution always succeeds when the method exists),
    # so deleting it is output-identical there.  "bytes" is wire-honest, and the
    # give-up is surfaced via element_unresolved → the caller attaches
    # `_ELEMENT_UNRESOLVED_NOTE` so the degradation is visible.  (The guarded,
    # flagged name-suffix matcher that used to live in `_repeated_element_type` was
    # removed too -- see that function's docstring.)
    return ("bytes", True)


@dataclass
class _RepeatedTypeResult:
    """Return value of :func:`_resolve_repeated_field_type`."""
    type_name:        str
    type_class:       Optional[str]
    abi_confirmed:    bool = False   # True → element type is ABI ground truth (a
                                     # distinct write-helper / +xyzType→NSString), so
                                     # it must NOT be overridden by a number-keyed
                                     # readFrom-dispatch hit (which can only be an
                                     # ordinal collision against it).  Set only on the
                                     # `string` outcomes; see the disp-vs-dispatch
                                     # tie-break in extractor.extract_proto_message.
    element_unresolved: bool = False # True → `bytes` is a give-up fallback (the


def _resolve_repeated_field_type(
    ivar: ObjcIvar,
    pname: str,
    instance_method_names: Set[str],
    metaclass: Optional[ObjcClass],
    cl: ClassList,
    ctx: BinaryContext,
    string_helper: Optional[int],
    wt_helpers: Dict[str, int],
) -> _RepeatedTypeResult:
    """Determine the concrete element type for one repeated NSArray field.

    Implements, in order:

    1. **Write-helper string check** (ABI evidence, checked FIRST): if the ivar's
       write-helper address matches the binary-wide string write-helper, the field
       is definitively ``"string"`` -- the NSString writer is never used for a
       message element.  This outranks every class-naming path below, so a
       name-based guess (Strategy 2) can no longer turn a string into a message
       (``GEOPDSSearchEvChargingParameters.networks`` was typed
       ``GEOLogMsgEventNetwork`` because the check only ran once a guess had
       failed).  Previously also needed when no ``+versionDomainType``-style
       method exists (``GEOPDComponent.versionDomains``) or the method returns
       the external NSString (``GEOPDPlaceResponse.displayLanguages``).

    2. The ``+[Cls xyzType]`` metaclass method via :func:`_repeated_element_type` +
       :func:`_resolve_repeated_type` (the class is read out of the method's IMP).
       When that resolves to a concrete class (not ``"bytes"``), return it.

    3. Otherwise the field stays as ``"bytes"`` (the safe fallback), flagged by the
       caller as an unresolved element; the caller's readFrom: dispatch / adder->ivar
       lever and element class-reference lever may still supply the class first.

    The former name-suffix guess (Strategy 2) and the pool-suffix refinement (an
    exact suffix match against the pool of all ``+xyzType`` classes, applied on top of
    the resolved class) are gone: the refinement never fired on any iPhone 8 image and
    rewrote one iOS 27 resolver answer wrongly (``GEOSpokenGuidance.announcements``;
    masked by the structural lever, so deleting it changed no emitted field).  The older
    Pass A / Pass B name-overlap fallbacks were removed 2026-06-08 (zero fields).
    """
    # ABI evidence first: the string write helper is never used for a message
    # element, so it decides the kind before any class-naming path runs.
    if string_helper is not None and wt_helpers.get(ivar.name) == string_helper:
        log.debug("%s: repeated string via writeTo: helper 0x%x",
                  pname, string_helper)
        return _RepeatedTypeResult(type_name="string", type_class=None,
                                   abi_confirmed=True)

    type_sel = _repeated_element_type(ivar, instance_method_names, metaclass)
    resolved, elem_unresolved = _resolve_repeated_type(type_sel, metaclass, cl, ctx=ctx)

    if resolved != "bytes":
        # The +xyzType method resolved to a concrete class (or NSString).
        type_class = resolved if resolved not in ("string", "bytes") else None
        # A `string` outcome is ABI-confirmed (an IMP-confirmed +xyzType returning
        # NSString) -- mark it so the tie-break never lets dispatch override it.
        return _RepeatedTypeResult(
            type_name       = resolved,
            type_class      = type_class,
            abi_confirmed   = resolved == "string",
        )

    # ── resolved == "bytes" ───────────────────────────────────────────────────

    # No principled signal — fall back to the safe `repeated bytes`.  Carry the
    # element_unresolved flag so the caller can flag a give-up bytes (element type
    # undetermined) while leaving a genuine NSData byte-array unflagged.
    return _RepeatedTypeResult(type_name="bytes", type_class=None,
                               element_unresolved=elem_unresolved)
