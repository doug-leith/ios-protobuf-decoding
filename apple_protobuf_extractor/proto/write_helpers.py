"""writeTo: write-helper identification and wire-type-family classification.

Carved out of ``proto/extractor.py`` (output-identical move).  Apple's PB runtime
emits a small set of per-binary *write helpers* — the functions a ``writeTo:`` IMP
calls to encode each field.  Which helper a field uses is a structural signal the
ivar ``@encode`` cannot carry:

  * **string vs bytes** — string and message fields use *different* helpers, so a
    ``repeated NSArray`` field that decoded to ``bytes`` can be reclassified to
    ``string`` when its helper matches the binary's string helper
    (:func:`_identify_string_write_helpers` / :func:`_find_string_write_helper`).
  * **wire-type family** — the helper a field calls selects the actual wire form
    (sint32/sint64 zigzag, fixed32/fixed64), recovering distinctions that all
    collapse to the canonical ``int32`` default in ``protocore._type_from_enc``
    (:func:`_classify_write_helper`, TODO #38/#44).

The two ``_ensure_*`` functions lazily build + cache the binary-wide pre-passes on
``ctx`` so a standalone :func:`proto.extractor.extract_proto_message` call (single
class, unit tests) gets the same result as a full :func:`extract_all` run.

Layering: depends only on ``macho.*`` + ``proto.protocore`` / ``proto.writeto`` /
``proto.arm64cfg`` (never on ``proto.extractor``) — no import cycle.
"""
from __future__ import annotations

import logging
from typing import Dict, List, Optional, Set

from macho.memory    import BinaryContext, _ctx_cache, _ctx_store
from macho.classlist import ClassList, ObjcIvar
from macho.disasm    import disasm, _parse_imm

from proto.writeto   import _extract_writeto_field_numbers
from proto.writer_flow import WriterFlow
from proto.arm64cfg  import split_ops
from proto.arm64_operands import NO_DEST, RETURNS, BLOCK_ENDS
from proto.callees   import import_name, real_target
from proto.models    import record_failed_pass
from proto.protocore import (
    _is_proto_flags_ivar, _type_from_enc, _INTERNAL_PB_IVARS,
)

from proto.protoclass_set import _proto_class_set

log = logging.getLogger(__name__)


# ── String write-helper identification ────────────────────────────────────────


def _identify_string_write_helpers(
    ctx: BinaryContext,
    cl: 'ClassList',
) -> Set[int]:
    """
    Binary-wide pre-pass: return the set of write-helper VMAs used for
    ``@"NSString"`` / ``@"NSMutableString"`` ivars.

    Apple's proto runtime uses **different** write-helper functions for string
    fields vs. message fields.  By finding the helper address for at least one
    known-string ivar (a singular ``@"NSString"`` typed field in any proto
    class), we obtain the string-helper address.  All proto classes in the same
    binary share the same set of write helpers, so one example suffices.

    The result is consumed by :func:`proto.extractor.extract_proto_message` to
    reclassify ``repeated NSArray`` fields that resolved to ``"bytes"`` but whose
    ``writeTo:`` write-helper matches the string helper → ``"string"``.

    This is the primary fix for fields such as ``GEOPDComponent.versionDomains``
    (no ``+versionDomainType`` metaclass method exists) and
    ``GEOPDPlaceResponse.displayLanguages`` / ``spokenLanguages`` (the
    ``+xyzType`` method returns NSString, an external class not in the
    binary-local classlist).
    """
    # The writeTo: bindings need the binary-wide pre-pass on ctx; ensure it exists so a
    # standalone caller (one that builds this set before extract_all has run)
    # gets real helpers instead of an empty set.
    _ensure_writeto_prepass(ctx, cl)

    string_helpers: Set[int] = set()
    proto_classes = _proto_class_set(ctx, cl)

    for cls in cl:
        if cls.is_meta or cls.name not in proto_classes:
            continue

        # Quick check: does this class have any @"NSString" ivar?
        string_enc = ('@"NSString"', '@"NSMutableString"')
        str_ivars = [iv for iv in cls.ivars if iv.type_enc in string_enc and iv.name]
        if not str_ivars:
            continue

        # Run writeTo: helper extraction using all field ivars so the offset
        # matching works (writeTo: uses the same ivar-offset variables).
        all_field_ivars = [iv for iv in cls.ivars if not _is_proto_flags_ivar(iv)
                           and iv.name and iv.name not in _INTERNAL_PB_IVARS]
        helpers = _extract_writeto_field_numbers(ctx, cls, all_field_ivars).helpers

        for iv in str_ivars:
            h = helpers.get(iv.name)
            if h:
                string_helpers.add(h)

        if string_helpers:
            # All classes share the same helpers; stop after first hit.
            return string_helpers

    return string_helpers


def _find_string_write_helper(
    helpers: Dict[str, int],
    field_ivars: List[ObjcIvar],
    instance_method_names: Set[str],
) -> Optional[int]:
    """
    Return the write-helper VA for string-typed ivars in *this* class, or None.

    For classes that *do* have a singular ``@"NSString"`` ivar (e.g.
    ``GEOPDPlaceResponse._displayRegion``), the helper can be identified
    locally without needing the binary-wide pre-pass.  Used as a fast path
    inside :func:`proto.extractor.extract_proto_message`.

    Falls back to None when no confirmed string helper is found locally,
    letting the caller fall back to the binary-wide set from
    :func:`_identify_string_write_helpers`.
    """
    for iv in field_ivars:
        type_name, _ = _type_from_enc(iv.type_enc, iv.name, instance_method_names)
        if type_name == "string":
            h = helpers.get(iv.name)
            if h:
                return h
    return None


# [cap:INPUT-SANITY] _HELPER_FAMILY_MAX_INSNS — a runaway backstop, NOT a tuned bound
# (TODO #59).  The wire-type family is decided STRUCTURALLY at the helper's tag-build
# instruction (sint value-shift `lsl #1`, fixed `mov #wt`+`bfi #3`, or the plain varint
# tag `lsl <field#>,#3`), every one of which lands within ~30 insns; the scan stops the
# moment it classifies.  A helper with no recognized tag-build is "unknown" (the field is
# flagged), so this bound cannot silently decide the output.
_HELPER_FAMILY_MAX_INSNS = 48


def _reg_num(reg: str):
    """Numeric index of an ARM64 GPR token ('w21'/'x21' -> 21); None for sp/zr/imm."""
    reg = reg.strip()
    if len(reg) >= 2 and reg[0] in "wx" and reg[1:].isdigit():
        return int(reg[1:])
    return None


def _varint32_value_extension(insns) -> Optional[str]:
    """``"int32"`` / ``"uint32"`` for a plain-varint write helper whose FIRST read of its
    value argument (``x1``, usually copied to a callee-saved register in the prologue)
    widens it to the 64-bit varint value: ``sxtw xD, wV`` (sign-extend: an ``int32``, whose
    negative values take 10 bytes) or ``mov wD, wV`` (a 32-bit move zero-extends: a
    ``uint32``).  None for any other first read -- a 64-bit varint uses the register as is
    (``cmp xV, #0x80``), a bool stores its byte (``strb wV``) -- or when there is none.
    PB ``0x1a47ae8cc`` (int32/enum) does ``mov x20,x1 ; ... ; sxtw x8,w20``,
    ``0x1a47af658`` (uint32) ``mov x20,x1 ; ... ; mov w8,w20``."""
    vals = {1}                                   # GPR indices holding the value argument
    for ins in insns:
        mn, ops = ins.mnemonic, split_ops(ins.op_str)
        if mn == "mov" and len(ops) == 2 and _reg_num(ops[1]) in vals:
            if ops[0].startswith("x") and ops[1].startswith("x"):
                vals.add(_reg_num(ops[0]))       # 64-bit copy: still the value
                continue
            if ops[0].startswith("w") and ops[1].startswith("w"):
                return "uint32"                  # 32-bit move: zero-extends
        if mn == "sxtw" and len(ops) == 2 and _reg_num(ops[1]) in vals:
            return "int32"
        srcs = ops if mn in NO_DEST else ops[1:]
        if any(_reg_num(o.strip("[]! ")) in vals for o in srcs):
            return None                          # first read is not a 32-bit widening
        if mn not in NO_DEST and ops:
            vals.discard(_reg_num(ops[0]))       # overwritten (e.g. `csel x1, …`)
        if mn in RETURNS or mn in ('b', 'br'):
            return None
    return None


#: The note on an int field whose writer shows no encoding (family ``"unknown"``).
INT_ENCODING_NOTE = "integer encoding not confirmed (int / sint / fixed not told apart)"

#: ProtocolBuffer.framework's field writers, by the wire-type family each encodes (the int
#: ones; the others leave the type alone).  A standalone binary calls them through import
#: stubs, which name them.
_WRITER_FAMILY = {
    "Int32": "int32", "Uint32": "uint32", "Sint32": "sint32", "Sint64": "sint64",
    "Fixed32": "fixed32", "Sfixed32": "fixed32", "Fixed64": "fixed64", "Sfixed64": "fixed64",
    "Int64": "plain", "Uint64": "plain",
}


def _family_from_import(ctx: BinaryContext, va: int) -> Optional[str]:
    """The family of the ``_PBDataWriterWrite<Type>Field`` writer the import stub at *va*
    calls, by its bound name; None when *va* is not such a stub."""
    name = import_name(ctx, va) or ""
    if name.startswith("_PBDataWriterWrite") and name.endswith("Field"):
        return _WRITER_FAMILY.get(name[len("_PBDataWriterWrite"):-len("Field")], "plain")
    return None


def _classify_write_helper(ctx: BinaryContext, helper_va: Optional[int]) -> str:
    """Classify a ``writeTo:`` field-write helper by the proto *wire-type family* it
    encodes: ``"sint32"``, ``"sint64"``, ``"fixed32"``, ``"fixed64"``, ``"int32"`` /
    ``"uint32"`` (a plain varint of a 32-bit value, by how it is widened -- see
    :func:`_varint32_value_extension`), ``"plain"`` (a varint read as such, or a
    non-int writer: no refinement), or ``"unknown"`` (no helper, or one whose encoding
    neither its code nor its import name shows: the field is flagged).

    Why this exists (TODO #38/#44): ivar ``@encode`` only records storage width, so
    ``int32``/``uint32``/``sint32``/``[s]fixed32`` all collapse to the canonical
    ``int32`` default (:func:`proto.protocore._type_from_enc`).  The **helper** a
    field's ``writeTo:`` calls selects the actual wire form, and the writeTo CFG
    bindings already capture it per ivar (``WriteBindings.helpers``) — so this is a cheap
    post-pass, mirroring the string-helper reclassification
    (:func:`_find_string_write_helper`).

    Mechanism — ground-truthed, structural, no hardcoded VA: GeoServices'
    ``0x18dbda*`` helpers are 12-byte ``adrp x16,#p ; add x16,x16,#o ; br x16``
    stubs into ProtocolBuffer.framework; follow the stub to the real helper
    (:func:`proto.callees.real_target`, which also follows the newer per-callsite
    arm64e stub island of the iOS 27 / macOS 27 caches, and leaves a helper called
    directly as it is).  Two
    value-independent signals, checked at the helper's tag-build instruction
    (whichever appears first wins — no scan budget decides the answer):

    * **zigzag (sint)** — the encoder shifts the value argument with
      ``lsl (w|x)1, #1`` (textbook ``(n<<1) ^ (n>>k)``); ``w1`` vs ``x1`` gives
      the width (confirmed: PB ``0x1a47b2dd0``=sint32, ``0x1a47b2ee4``=sint64).
    * **fixed** — the helper builds the tag as ``mov w_,#wt ; bfi w_,w<field>,
      #3,#0x1d`` where ``wt`` IS the wire type: ``5``=fixed32, ``1``=fixed64.
      Plain varint instead builds the tag via ``lsl w_,w<field>,#3`` (wt 0); wire
      type 2 (length-delimited) is left ``plain``.  The newer toolchain also emits
      that ``lsl`` first in a fixed-width helper (the tag-size test), so after it the
      scan continues to the end of the block looking for the ``bfi``.  Shared with float/double, but
      those ivars decode to float/double and never reach this int-only caller,
      so fixed32/fixed64 here always means an integer field — sfixed vs. fixed
      is then picked from the ivar sign, exactly like int32↔uint32.

    In standalone ``--binary`` mode the helper is an import stub into ProtocolBuffer.framework,
    whose code is not in the binary; the stub's bound name names the writer
    (:func:`_family_from_import`).  Memoised on ``ctx``."""
    if not helper_va:
        return "unknown"
    cache = _ctx_cache(ctx, "_writeto_helper_family", dict)
    if helper_va in cache:
        return cache[helper_va]

    fam = "unknown"
    try:
        target = real_target(ctx, helper_va)
        named = _family_from_import(ctx, target)
        if named is not None:
            cache[helper_va] = named
            return named
        # The family is decided at the helper's TAG-BUILD instruction (#59): whichever
        # of {sint value-shift, fixed bfi, plain varint tag} appears first wins, and we
        # STOP there — no scan budget decides the answer.  The field# is the 3rd arg
        # (w2/x2) and is moved into a callee-saved reg in the prologue; track it so the
        # plain varint tag-build (`lsl <field#>,#3`) can be told from an unrelated shift.
        movs: Dict[str, int] = {}          # most-recent `mov Rd,#imm` (fixed wire-type const)
        field_regs = {2}                   # GPR indices currently holding the field# arg
        tag_shift_seen = False             # saw `lsl <field#>,#3` (see below)
        insns = disasm(ctx, target, max_insns=_HELPER_FAMILY_MAX_INSNS, stop_at_ret=True)
        for ins in insns:
            mn = ins.mnemonic
            ops = split_ops(ins.op_str)
            # lsl <Rd>, <value-arg>, #1  — zigzag shift of the value argument (sint).
            # (Not looked for once the plain tag shift has been seen: only a fixed-width
            # `bfi` can still change a verdict then — see below.)
            if (not tag_shift_seen and mn == "lsl" and len(ops) == 3
                    and _parse_imm(ops[2]) == 1):
                if ops[1] == "w1":
                    fam = "sint32"
                    break
                if ops[1] == "x1":
                    fam = "sint64"
                    break
            # lsl <Rd>, <field#-reg>, #3  — the PLAIN varint tag build (tag = field#<<3,
            # wire-type 0).  Gated on the field# reg so a `lsl Rs,#3` index-scale can't
            # mis-fire.  This is the structural "plain" terminator (#59) that replaces
            # running the scan to the budget and defaulting to plain.
            #
            # The NEWER toolchain (iOS 27, macOS 27) computes that same `lsl <field#>,#3`
            # first for EVERY helper — it is the tag's size test (`cmp w,#0x80`) — and
            # only then builds a fixed-width helper's tag (`mov w,#5 ; bfi w,<field>,#3,
            # #0x1d`) a few instructions later in the same block.  So the shift is not the
            # end of the evidence: note it, keep reading to the end of the block (the
            # first branch/call/return), and let a following wire-type `bfi` decide.
            # Without one, the helper is plain, as before.  (The sint helpers of that
            # toolchain still hit their zigzag shift before this one, so that signal is
            # not needed here — and is deliberately not read past the plain tag shift,
            # where an unrelated `lsl #1` in the varint body would misfire.)
            if (mn == "lsl" and len(ops) == 3 and _parse_imm(ops[2]) == 3
                    and _reg_num(ops[1]) in field_regs):
                tag_shift_seen = True
                continue
            # end of the straight-line block after the tag shift, with no wire-type
            # `bfi` in it: this is the plain varint tag build.
            if tag_shift_seen and (mn in BLOCK_ENDS or mn.startswith("b.")):
                break
            if mn == "mov" and len(ops) == 2:
                src = _reg_num(ops[1])
                if src is not None and src in field_regs:
                    # mov Rd, <field#-reg>  — propagate the field# to the new reg.
                    dst = _reg_num(ops[0])
                    if dst is not None:
                        field_regs.add(dst)
                elif ops[1].startswith("#"):
                    # mov Rd, #imm  — remember; may be a fixed tag wire-type constant.
                    movs[ops[0]] = _parse_imm(ops[1])
            # bfi <Rd>, <field-reg>, #3, #0x1d  — tag = (field << 3) | wt, wt in Rd.
            if mn == "bfi" and len(ops) == 4 and _parse_imm(ops[2]) == 3:
                wt = movs.get(ops[0])
                if wt == 5:
                    fam = "fixed32"
                    break
                if wt == 1:
                    fam = "fixed64"
                    break
                if wt in (0, 2):
                    fam = "plain"      # a varint or length-delimited tag: no int refinement
                    break
        if fam == "unknown" and tag_shift_seen:
            fam = "plain"              # the plain varint tag build, with no wire-type bfi after it
        if fam == "plain":
            # A plain varint helper: the signedness of a 32-bit value is in how it is
            # widened to the 64-bit varint (sxtw = int32, 32-bit mov = uint32).
            fam = _varint32_value_extension(insns) or "plain"
    except (NameError, ImportError):
        raise                       # our own wiring bug — never mask it
    except Exception as exc:
        # Unreadable helper: its fields are flagged as an unconfirmed integer encoding.
        log.debug("write-helper classify failed at 0x%x: %s", helper_va or 0, exc)
        fam = "unknown"
    cache[helper_va] = fam
    return fam


def _refine_scalar_by_family(type_name: str, fam: str, where: str = "") -> str:
    """Refine a canonical int type (``int32``/``int64``/``uint32``/``uint64``) by the
    wire-type family its write helper encodes (:func:`_classify_write_helper`): zigzag
    ``sint32``/``sint64``; ``[s]fixed32``/``[s]fixed64``, the SIGN half (fixed vs sfixed)
    coming from the storage type; and ``int32``/``uint32`` for a 32-bit plain varint, which
    the writer decides (it IS the encoding: the int32 writer sign-extends a negative value
    to 10 bytes).  A writer that disagrees with the storage type's sign is logged
    (*where* names the field).  Unchanged for ``plain`` or any non-int type."""
    if type_name in ("int32", "int64", "uint32", "uint64"):
        if fam in ("sint32", "sint64"):
            return fam
        if fam in ("int32", "uint32"):
            if type_name in ("int32", "uint32"):
                if fam != type_name:
                    log.warning("%s: the writeTo: writer encodes %s but the storage type is "
                                "%s; emitting the writer's %s", where or "a field", fam,
                                type_name, fam)
                return fam
            log.warning("%s: a 32-bit %s writer for %s storage; type left as %s",
                        where or "a field", fam, type_name, type_name)
            return type_name
        if fam == "fixed32":
            return "sfixed32" if type_name == "int32" else "fixed32"
        if fam == "fixed64":
            return "sfixed64" if type_name == "int64" else "fixed64"
    return type_name


# ── Lazy binary-wide pre-passes (cached on ctx) ───────────────────────────────


def _ensure_writeto_prepass(ctx: BinaryContext, cl: ClassList) -> None:
    """Lazily build + cache the binary-wide ``writeTo:`` pre-pass on ``ctx``: the image's
    :class:`proto.writer_flow.WriterFlow` (``_writer_flow``, which the bindings
    :func:`_extract_writeto_field_numbers` read) and the set of every method IMP
    (``_method_imps``, the method extents the map / struct / enum passes use).

    :func:`proto.extractor.extract_all` builds it once up front, but
    :func:`proto.extractor.extract_proto_message` may also be called standalone
    (single-class extraction, unit tests) without ``extract_all`` — so build it on
    first use here too; without this, a standalone call would silently get NO writeTo
    decoding.  Rebuilt for a different class list."""
    wf = getattr(ctx, "_writer_flow", None)
    if wf is None or wf.cl is not cl:
        _ctx_store(ctx, "_writer_flow", WriterFlow(ctx, cl))
    if getattr(ctx, "_method_imps", None) is None:
        _ctx_store(ctx, "_method_imps", {m.imp for c in cl for m in c.methods if m.imp})


def _ensure_string_write_helpers(ctx: BinaryContext, cl: ClassList) -> "FrozenSet[int]":
    """Lazily build + cache the binary-wide string-write-helper VA set on ``ctx``.

    Mirrors :func:`_ensure_writeto_prepass`: ``extract_all`` builds this once and
    passes it explicitly, but a standalone :func:`proto.extractor.extract_proto_message`
    caller that omits the kwarg would otherwise silently lose ``repeated string`` vs
    ``repeated bytes`` typing. Cached so the binary-wide scan runs at most once per
    context. An empty result is a valid build (cached, not retried)."""
    cached = getattr(ctx, "_string_write_helpers", None)
    if cached is not None:
        return cached
    try:
        helpers = frozenset(_identify_string_write_helpers(ctx, cl))
    except (NameError, ImportError):
        raise
    except Exception as exc:
        record_failed_pass(ctx, "string write helper", exc,
                           "repeated string fields are not told from repeated bytes")
        helpers = frozenset()
    _ctx_store(ctx, "_string_write_helpers", helpers)
    return helpers
