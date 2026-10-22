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
from typing import Dict, FrozenSet, Optional, Tuple

from macho.memory    import READ_ERRORS, BinaryContext
from macho.classlist import ClassList, ObjcClass, ObjcIvar, class_name_at
from macho.disasm    import _parse_imm
from proto.arm64_operands import RETURNS, mem_regs, split_ops
from proto.callees   import callee_name, real_target, RETURNS_ARGUMENT
from proto.protocore import _proto_name, _CLASS_TO_PROTO

log = logging.getLogger(__name__)

#: ProtocolBuffer.framework's field writers (ABI names ``_PBDataWriterWrite<T>Field``) by
#: the proto type of the one value each serialises.  ``Submessage`` is not here: its
#: element class comes from the class-naming paths.
_WRITER_ELEMENT_TYPE = {
    "BOOL": "bool", "Int32": "int32", "Int64": "int64", "Uint32": "uint32",
    "Uint64": "uint64", "Sint32": "sint32", "Sint64": "sint64", "Fixed32": "fixed32",
    "Fixed64": "fixed64", "Sfixed32": "sfixed32", "Sfixed64": "sfixed64",
    "Float": "float", "Double": "double", "String": "string", "Data": "bytes",
}


def _writer_element_type(ctx: BinaryContext, helper_va: Optional[int]) -> Optional[str]:
    """The proto type the ProtocolBuffer field writer at *helper_va* serialises, by its ABI
    name (:func:`proto.callees.callee_name`: a cache export, or a standalone binary's
    import); None for an unnamed helper or a writer with no one value type."""
    name = callee_name(ctx, helper_va) if helper_va else None
    if not name or not (name.startswith("_PBDataWriterWrite") and name.endswith("Field")):
        return None
    return _WRITER_ELEMENT_TYPE.get(name[len("_PBDataWriterWrite"):-len("Field")])

def _repeated_element_type(ivar: ObjcIvar, metaclass: Optional[ObjcClass]) -> str:
    """
    For a repeated field, find the selector of the ``+[Cls xyzType]`` metaclass method
    that names the element type, or ``"bytes"`` when there is none.

    The metaclass exposes a selector like ``mapsResultsType`` whose body returns
    ``[GEOPDMapsResult class]``; the field name is depluralised (``mapsResults`` ->
    ``mapsResult``) and ``Type`` appended to form the candidate selector.  The class
    itself is read out of the method's IMP by :func:`_resolve_repeated_type`, so only the
    SELECTOR is chosen here.  The element class is never guessed from the field name.
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
    accessor references no array offset.

    The accessor is what its entry reaches inside its extent
    (:func:`proto.function_body.function_body`): a setter that ends in a tail branch rather
    than ``ret`` would otherwise run on into the next method -- e.g. CoreParsec
    ``-[_CPVisibleResultsFeedback setGoTakeoverResult:]`` into
    ``setUniqueIdsOfVisibleButtons:``, binding a singular field's setter to an array.
    """
    from proto.dispatch import function_entries, listing_flow
    from proto.function_body import function_body
    if imp_va == 0 or not array_offsets:
        return None
    try:
        insns = function_body(ctx, imp_va, function_entries(ctx))
    except READ_ERRORS:
        return None
    if not insns:
        return None
    flow = listing_flow(ctx, list(insns))
    for k in range(len(flow.insns)):
        slot_va = flow.slot_load_address(k)
        if slot_va is None:
            continue
        try:
            val = int.from_bytes(ctx.read_bytes(slot_va, 4), 'little')
        except READ_ERRORS:
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


#: Tail calls that return the class they are handed in x0: the ARC return-value handshake,
#: and ``objc_opt_class`` (a class object's class is itself).
_RETURNS_CLASS_ARGUMENT = RETURNS_ARGUMENT | {'_objc_opt_class'}


def _returned_class_ref(ctx: BinaryContext, imp: int) -> Optional[Tuple[str, int]]:
    """How the method at *imp* returns a class in x0, by x0's reaching definition at every
    exit -- a ``ret``, or a tail call to a function that returns the class it is handed
    (:data:`_RETURNS_CLASS_ARGUMENT`): ``("slot", addr)`` when x0 is loaded from the
    class-reference slot at *addr* (``adrp ; ldr x0, [x8, #off]``), ``("class", addr)`` when
    x0 is the class's own address (``adrp ; add x0, x8, #off``, iOS 27).  None when an exit
    returns anything else or the exits disagree.  The method is what its entry reaches
    inside its extent (:func:`proto.function_body.function_body`)."""
    from proto.dispatch import function_entries, listing_flow
    from proto.function_body import function_body
    insns = list(function_body(ctx, imp, function_entries(ctx)))
    if not insns:
        return None
    flow = listing_flow(ctx, insns)
    own = {i.addr for i in insns}
    refs = set()
    for k, ins in enumerate(insns):
        if ins.mnemonic == 'b':
            if _parse_imm(ins.op_str) in own:
                continue                                    # a block of this method
        elif ins.mnemonic not in RETURNS:
            continue
        d = _x0_source(ctx, flow, k)
        if d is _UNREACHED:
            continue                                        # not code of this method
        if d is None or (ins.mnemonic == 'b' and callee_name(ctx, _parse_imm(ins.op_str))
                         not in _RETURNS_CLASS_ARGUMENT):
            return None
        ops = split_ops(insns[d].op_str)
        if insns[d].mnemonic == 'ldr' and len(ops) == 2:
            m = mem_regs(ops[1])
            base = flow.const_before(d, m[0]) if m and m[0] and m[1] is None else None
            if base is None:
                return None
            refs.add(("slot", base + m[2]))
        else:
            v = flow.const_before(d + 1, 'x0')
            if v is None:
                return None
            refs.add(("class", v))
    return refs.pop() if len(refs) == 1 else None


_UNREACHED = object()


def _x0_source(ctx: BinaryContext, flow, k: int):
    """Index of the instruction whose x0 the exit ``insns[k]`` returns, through calls that
    return the class they are handed (``bl _objc_opt_class ; bl
    _objc_claimAutoreleasedReturnValue ; ret``); :data:`_UNREACHED` when no path from the
    entry reaches ``insns[k]``, None when x0 has more than one source or is the entry's."""
    seen = set()
    while k not in seen:
        seen.add(k)
        defs = flow.defs_before(k, 'x0')
        if not defs:
            return _UNREACHED
        if len(defs) != 1 or min(defs) < 0:
            return None
        (d,) = defs
        ins = flow.insns[d]
        if ins.mnemonic != 'bl':
            return d
        if callee_name(ctx, _parse_imm(ins.op_str)) not in _RETURNS_CLASS_ARGUMENT:
            return None
        k = d                                               # x0 before that call
    return None


def _class_from_type_method_imp(
    ctx: BinaryContext,
    imp: int,
    cl: ClassList,
) -> Optional[str]:
    """The ObjC class a ``+[Cls xyzType]`` metaclass method returns, or None.  The method
    returns a class reference (:func:`_returned_class_ref`)::

        adrp  x8, <page>          ; iPhone 8: a class-reference slot in __DATA_CONST
        ldr   x0, [x8, #<off>]
        b     _objc_opt_class

        adrp  x8, <page>          ; iOS 27: the class itself
        add   x0, x8, #<off>
        b     _objc_opt_class

    A class pointer names its class through the image's class list, else its ``class_t``
    (:func:`macho.classlist.class_name_at`: another image's class in the dyld cache).  A slot
    that holds no pointer is a chained-fixup bind for an external / system class (NSString,
    NSData): its symbol name (``ctx._bind_name_map``) names it, letting callers map it to a
    proto scalar via :data:`_CLASS_TO_PROTO`.

    This is essential for shared-cache-extracted binaries (like GeoServices) where
    preoptimised relative method lists render selector names unresolvable: name-based
    resolution fails for fields whose ivar name doesn't directly suffix-match the element
    class (e.g. ``_legacyPlaceResults`` → element class ``GEOPDPlace``, not
    ``GEOPDLegacyPlaceResult``)."""
    if imp == 0:
        return None
    try:
        ref = _returned_class_ref(ctx, imp)
        if ref is None:
            return None
        kind, va = ref
        class_va = ctx.read_ptr(va) if kind == "slot" else va
        if class_va:
            obj_cls = cl.by_vmaddr(class_va)
            if obj_cls is not None and not obj_cls.is_meta:
                return obj_cls.name
            name = class_name_at(ctx, class_va)
            if name:
                return name
        if kind == "slot":
            bind_sym = ctx.bind_name_for(va)
            if bind_sym:
                # "_OBJC_CLASS_$_NSString" → "NSString"
                if '_OBJC_CLASS_$_' in bind_sym:
                    return bind_sym.split('_OBJC_CLASS_$_', 1)[1]
                return bind_sym
    except (NameError, ImportError):
        raise
    except READ_ERRORS:
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

    # IMP resolution failed (the +xyzType method exists but its body could not be read):
    # "bytes", flagged by the caller as an unresolved element.
    return ("bytes", True)


@dataclass
class _RepeatedTypeResult:
    """Return value of :func:`_resolve_repeated_field_type`."""
    type_name:        str
    type_class:       Optional[str]
    # the element type is ABI ground truth (the string write helper): a number-keyed
    # readFrom: dispatch hit must not override it
    abi_confirmed:    bool = False
    # `bytes` is a give-up fallback: the caller flags the field
    element_unresolved: bool = False


def _resolve_repeated_field_type(
    ivar: ObjcIvar,
    pname: str,
    metaclass: Optional[ObjcClass],
    cl: ClassList,
    ctx: BinaryContext,
    string_helper: Optional[int],
    wt_helpers: Dict[str, int],
) -> _RepeatedTypeResult:
    """Determine the concrete element type for one repeated NSArray field.

    Implements, in order:

    1. **Write-helper check** (ABI evidence, checked FIRST): if the ivar's write-helper
       address matches the binary-wide string write-helper, the field is definitively
       ``"string"`` -- the NSString writer is never used for a message element, so it
       outranks the class-naming path below; likewise a write helper that is a named
       ProtocolBuffer scalar writer (``_PBDataWriterWriteUint64Field`` ...) writes one
       element of that type per call (:func:`_writer_element_type`).

    2. The ``+[Cls xyzType]`` metaclass method via :func:`_repeated_element_type` +
       :func:`_resolve_repeated_type` (the class is read out of the method's IMP).
       When that resolves to a concrete class (not ``"bytes"``), return it.

    3. Otherwise the field stays as ``"bytes"`` (the safe fallback), flagged by the
       caller as an unresolved element; the caller's readFrom: dispatch / adder->ivar
       lever may still supply the class first.
    """
    # ABI evidence first: the string write helper is never used for a message
    # element, so it decides the kind before any class-naming path runs.
    mine = wt_helpers.get(ivar.name)
    if string_helper is not None and mine is not None and (
            mine == string_helper or (ctx is not None and
                                      real_target(ctx, mine) == real_target(ctx, string_helper))):
        log.debug("%s: repeated string via writeTo: helper 0x%x",
                  pname, string_helper)
        return _RepeatedTypeResult(type_name="string", type_class=None,
                                   abi_confirmed=True)
    written = _writer_element_type(ctx, wt_helpers.get(ivar.name))
    if written is not None:
        log.debug("%s: repeated %s via writeTo: writer", pname, written)
        return _RepeatedTypeResult(type_name=written, type_class=None, abi_confirmed=True)

    type_sel = _repeated_element_type(ivar, metaclass)
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
