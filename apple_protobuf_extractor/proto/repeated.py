"""proto/repeated — repeated-field element-type resolution.

Carved from ``proto.extractor`` (#11 monolith split, step 4): resolve the element type of a
repeated field from the class's readFrom: dispatch -- decoded by evaluation in
:mod:`proto.dispatch_eval` (element class per field number, and per ivar through the
accessor its handler appends with) -- or from the metaclass ``+xyzType`` method / writeTo:
helper.  Imports macho.* + arm64cfg + protocore (never proto.extractor) -> cycle-free;
extractor re-imports the surface.
"""
from __future__ import annotations
import logging
from dataclasses import dataclass
from typing import Dict, FrozenSet, Optional, Set, Tuple

from macho.memory    import BinaryContext
from macho.classlist import ClassList, ObjcClass, ObjcIvar
from macho.disasm    import disasm, _norm_reg
from proto.arm64cfg  import parse_adrp, mem_operand
from proto.protocore import _proto_name, _CLASS_TO_PROTO

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
    the write helper (string), or the inline-struct encoding.  A field none of them resolves stays
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
# The readFrom: dispatch idioms that used to live here and in proto.dispatch -- jump-table
# cluster decoding, the clamped-gate matcher, compare-chain dominance attribution, the
# wrapper->core scan with its ownership signals, the arm walkers, the class-reference windows
# -- were retired 2026-10-15 for proto.dispatch_eval, which runs the dispatch for each field
# number instead of matching its shape.


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

    The scan ends at the next known function entry (every method IMP and ReadAllFrom
    core, stamped on *ctx* by :func:`proto.dispatch._build_readfrom_core_index`): a
    setter that ends in a tail branch rather than ``ret`` would otherwise run on into
    the next method -- e.g. CoreParsec ``-[_CPVisibleResultsFeedback setGoTakeoverResult:]``
    into ``setUniqueIdsOfVisibleButtons:``, binding a singular field's setter to an array.
    """
    from proto.dispatch import function_entries
    if imp_va == 0 or not array_offsets:
        return None
    try:
        insns = disasm(ctx, imp_va, max_insns=_ADDER_MAX_INSNS, stop_at_ret=True)
    except (NameError, ImportError):
        raise
    except Exception:
        return None
    nxt = function_entries(ctx).next_after(imp_va)
    if nxt is not None:
        insns = [ins for ins in insns if ins.addr < nxt]
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
            except (NameError, ImportError):
                raise
            except Exception:
                continue
            if val in array_offsets:
                return val          # first array-offset load = the accessor's own ivar
    return None


def _resolve_repeated_via_dispatch_ivars(
    ctx: BinaryContext,
    cls: ObjcClass,
    core_index: Dict[int, str],
) -> Dict[str, Tuple[str, int]]:
    """Bind ``{ivar_name: (element_class, field_number)}`` from this class's readFrom:
    dispatch: for each field the evaluator (:mod:`proto.dispatch_eval`) finds, the array ivar
    its handler appends the element to -- the accessor it hands (self, element), method IMP or
    objc_direct C function alike, identified by the ivar-offset variable it loads; or
    ``[self->_array addObject:element]``.  Keyed by IVAR, so safe to apply even when the field
    number is not write-confirmed.  Empty when nothing binds."""
    if not core_index:
        return {}
    from proto.dispatch_eval import evaluate_class
    return evaluate_class(ctx, cls, core_index).ivars()


def _resolve_repeated_via_dispatch(
    ctx: BinaryContext,
    cls: ObjcClass,
    core_index: Dict[int, str],
) -> Dict[int, str]:
    """
    Resolve ``{field_number: element_class}`` for *cls* by running its readFrom: dispatch for
    each field number (:mod:`proto.dispatch_eval`): the class each field's handler builds --
    the ReadAllFrom core it calls on a new object, or the class it allocates.

    Why readFrom: and not writeTo: -- element message *types* are intrinsically
    a READ-side fact.  ``writeTo:`` serialises objects that already exist: every
    message field (singular or repeated, any element class) goes through the
    SAME generic sub-message write helper, which dispatches ``[element writeTo:]``
    on the object's runtime type -- it never reveals *which* class, only that a
    field *is* a message.  ``readFrom:`` must *create* the elements, so it
    statically references the element class -- the information read here.  (Exception: an
    inline-C struct element, serialised via a named C writer -- see TODO #37.)

    The dispatch is decoded by evaluation, whatever its encoding (jump table, clamped gate,
    compare chain or tree, a mix): which function dispatches is decided by data flow (the one
    handed this object), not by call-site shape.  Results are keyed by field NUMBER, which the
    caller may only trust when it is *confirmed* (:func:`_confirm_field_numbers`) or the
    message has a single field.  Empty dict when the dispatch can't be followed.
    """
    if not core_index:
        return {}
    from proto.dispatch_eval import evaluate_class
    return evaluate_class(ctx, cls, core_index).elements()


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
    except (NameError, ImportError):
        raise
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
       lever may still supply the class first.

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
