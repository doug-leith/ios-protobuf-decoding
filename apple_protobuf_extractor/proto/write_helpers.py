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

from macho.memory    import BinaryContext, _ctx_cache
from macho.classlist import ClassList, ObjcIvar
from macho.disasm    import disasm, find_adrp_add_target, _parse_imm, _first_reg

from proto.writeto   import _extract_writeto_field_numbers, build_writeto_indegree
from proto.arm64cfg  import split_ops
from proto.protocore import (
    _is_proto_flags_ivar, _type_from_enc, _INTERNAL_PB_IVARS,
)

from proto.protoclass_heuristic import _is_proto_class

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
    # The writeTo decoder (CFG walk) needs the binary-wide indegree pre-pass on
    # ctx; ensure it exists so a standalone caller (one that builds this
    # set before extract_all has run) gets real helpers instead of an empty set.
    _ensure_writeto_indegree(ctx, cl)

    string_helpers: Set[int] = set()

    for cls in cl:
        if cls.is_meta or not _is_proto_class(cls):
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
        helpers: Dict[str, int] = {}
        _extract_writeto_field_numbers(ctx, cls, all_field_ivars, _out_helpers=helpers)

        for iv in str_ivars:
            h = helpers.get(iv.name)
            if h:
                string_helpers.add(h)

        if string_helpers:
            # All classes share the same helpers; stop after first hit.
            return string_helpers

    return string_helpers


def _identify_message_write_helper(ctx: BinaryContext, cl: 'ClassList') -> Optional[int]:
    """Binary-wide pre-pass: the write-helper VA used for a singular proto-MESSAGE
    ivar (``@"<proto class>"``), or None.

    The counterpart of :func:`_identify_string_write_helpers`: a message-typed ivar's
    ``writeTo:`` call goes through the one message helper that every message field in
    the binary shares (GeoServices: 1965 of 1965 singular message ivars use the same
    helper; the string and bytes helpers are different).  Knowing it lets a caller tell
    a field written as a sub-message from one written as bytes or a string -- e.g. to
    accept an element class recovered from a class-reference only for message-written
    fields.  Stops at the first class that yields a helper."""
    _ensure_writeto_indegree(ctx, cl)
    for cls in cl:
        if cls.is_meta or not _is_proto_class(cls):
            continue
        cands = []
        for iv in cls.ivars:
            enc = iv.type_enc or ""
            if iv.name and enc.startswith('@"') and enc.endswith('"'):
                target = cl.find(enc[2:-1])
                if target is not None and not target.is_meta and _is_proto_class(target):
                    cands.append(iv)
        if not cands:
            continue
        all_field_ivars = [iv for iv in cls.ivars if not _is_proto_flags_ivar(iv)
                           and iv.name and iv.name not in _INTERNAL_PB_IVARS]
        helpers: Dict[str, int] = {}
        _extract_writeto_field_numbers(ctx, cls, all_field_ivars, _out_helpers=helpers)
        for iv in cands:
            h = helpers.get(iv.name)
            if h:
                return h
    return None


def _ensure_message_write_helper(ctx: BinaryContext, cl: 'ClassList') -> Optional[int]:
    """Lazily build + cache :func:`_identify_message_write_helper` on ``ctx`` (same
    contract as :func:`_ensure_string_write_helpers`; a built-but-empty result is
    cached as ``(None,)`` and not retried)."""
    cached = getattr(ctx, "_message_write_helper", None)
    if cached is not None:
        return cached[0]
    try:
        helper = _identify_message_write_helper(ctx, cl)
    except Exception as exc:
        log.debug("message-write-helper lazy pre-pass failed (%s)", exc)
        helper = None
    try:
        ctx._message_write_helper = (helper,)
    except Exception:
        pass
    return helper


def _same_write_helper(ctx: BinaryContext, a: Optional[int], b: Optional[int]) -> bool:
    """True iff *a* and *b* are the same write helper: equal addresses, or equal real
    targets (a per-callsite stub island has a different VA at every call site but one
    shared target, see :func:`_helper_real_target`).  False if either is unknown."""
    if not a or not b:
        return False
    if a == b:
        return True
    try:
        return _helper_real_target(ctx, a) == _helper_real_target(ctx, b)
    except Exception:
        return False


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


# [cap:AFFECTS-OUTPUT] _HELPER_STUB_INSNS=3 — the adrp/add/br x16 PLT-style stub is
# exactly 3 insns.
_HELPER_STUB_INSNS = 3
# A newer per-callsite "objc_msgSend stub island" shape (arm64e-authenticated,
# seen on a macOS system dyld cache's GeoServices — a different, more recent
# Apple-internal toolchain than the one this tool was originally built
# against): adrp+add materialise a GOT-slot address into x17 (arm64 IP1, the
# ABI-reserved indirect-branch scratch register), `ldr x16,[x17]` dereferences
# it, and `braa x16,x17` (PAC-authenticated indirect branch) jumps there.
# Unlike the plain 3-insn PLT stub (whose target IS the real helper, just one
# indirection away), this stub's *own* address is unique PER CALL SITE — every
# writeTo: field-write gets its own freshly emitted stub instance pointing at
# the same shared real helper — so following it is required for both wire-type
# classification here and any helper-address-equality comparison elsewhere
# (e.g. :func:`_find_string_write_helper`).
_STUB_ISLAND_INSNS = 4
_STUB_ISLAND_BRANCH_MNEMONICS = frozenset(('braa', 'brab', 'br'))

# Mnemonics that end a straight-line block while reading a write helper's tag build.
_BLOCK_END_MNEMONICS = frozenset(('b', 'bl', 'br', 'blr', 'braa', 'brab', 'blraa', 'blrab',
                                  'cbz', 'cbnz', 'tbz', 'tbnz', 'ret', 'retaa', 'retab'))
# [cap:INPUT-SANITY] _HELPER_FAMILY_MAX_INSNS — a runaway backstop, NOT a tuned bound
# (TODO #59).  The wire-type family is decided STRUCTURALLY at the helper's tag-build
# instruction (sint value-shift `lsl #1`, fixed `mov #wt`+`bfi #3`, or the plain varint
# tag `lsl <field#>,#3`), every one of which lands within ~30 insns; the scan stops the
# moment it classifies.  A helper with no recognized tag-build falls through to "plain"
# — the safe no-refinement default — so this bound never decides the output, it only
# stops a pathological non-terminating scan.
_HELPER_FAMILY_MAX_INSNS = 48


def _reg_num(reg: str):
    """Numeric index of an ARM64 GPR token ('w21'/'x21' -> 21); None for sp/zr/imm."""
    reg = reg.strip()
    if len(reg) >= 2 and reg[0] in "wx" and reg[1:].isdigit():
        return int(reg[1:])
    return None


def _resolve_stub_island(ctx: BinaryContext, helper_va: int) -> Optional[int]:
    """Follow a per-callsite ``objc_msgSend`` stub-island veneer to its real
    target, or return ``None`` if *helper_va* isn't one (see
    :data:`_STUB_ISLAND_INSNS`).

    Structural, no hardcoded VA: reads the GOT-slot address off the stub's own
    ``adrp+add`` (whichever GPR it uses — Apple's ABI convention is x16/x17,
    but the register is taken from the instructions themselves, not assumed),
    then dereferences that slot through :meth:`BinaryContext.read_ptr` — the
    same cache-aware pointer decode every other pointer field in this tool
    goes through, so an arm64e-authenticated GOT entry resolves correctly.
    """
    try:
        stub = disasm(ctx, helper_va, max_insns=_STUB_ISLAND_INSNS, stop_at_ret=False)
    except Exception:
        return None
    if (len(stub) < _STUB_ISLAND_INSNS
            or stub[0].mnemonic != "adrp"
            or stub[2].mnemonic != "ldr"
            or stub[3].mnemonic not in _STUB_ISLAND_BRANCH_MNEMONICS):
        return None
    reg = _first_reg(stub[0].op_str)
    if reg is None:
        return None
    got_slot = find_adrp_add_target(stub[:3], reg)
    if got_slot is None:
        return None
    try:
        return ctx.read_ptr(got_slot) or None
    except ValueError:
        return None


def _helper_real_target(ctx: BinaryContext, helper_va: int) -> int:
    """The real function behind a ``writeTo:`` field-write helper: follow a 3-insn
    PLT-style ``adrp/add/br x16`` stub once, else a newer per-callsite stub-island
    veneer (:func:`_resolve_stub_island`), else *helper_va* itself (a direct, non-stub
    helper).  The canonical identity of "which write helper is this" — a per-callsite
    island has a different VA at every call site but one shared real target.  Raises
    on an unreadable address (the callers decide how to degrade)."""
    stub = disasm(ctx, helper_va, max_insns=_HELPER_STUB_INSNS, stop_at_ret=False)
    target = None
    if (len(stub) >= 3 and stub[0].mnemonic == "adrp"
            and stub[2].mnemonic == "br"):
        target = find_adrp_add_target(stub, "x16")   # follow the PLT-style stub
    if target is None:
        target = _resolve_stub_island(ctx, helper_va)  # follow the newer stub-island form
    if target is None:
        target = helper_va                            # direct (non-stub) helper
    return target


def _classify_write_helper(ctx: BinaryContext, helper_va: Optional[int]) -> str:
    """Classify a ``writeTo:`` field-write helper by the proto *wire-type family* it
    encodes: ``"sint32"``, ``"sint64"``, ``"fixed32"``, ``"fixed64"``, or ``"plain"``
    (plain varint / length-delim / unrecognised — no refinement).

    Why this exists (TODO #38/#44): ivar ``@encode`` only records storage width, so
    ``int32``/``uint32``/``sint32``/``[s]fixed32`` all collapse to the canonical
    ``int32`` default (:func:`proto.protocore._type_from_enc`).  The **helper** a
    field's ``writeTo:`` calls selects the actual wire form, and the writeTo CFG
    walk already captures it per ivar (``_out_helpers``) — so this is a cheap
    post-pass, mirroring the string-helper reclassification
    (:func:`_find_string_write_helper`).

    Mechanism — ground-truthed, structural, no hardcoded VA: GeoServices'
    ``0x18dbda*`` helpers are 12-byte ``adrp x16,#p ; add x16,x16,#o ; br x16``
    stubs into ProtocolBuffer.framework; follow the stub once to the real helper
    (also covers binaries that call a local helper directly).  A newer
    per-callsite ``objc_msgSend`` stub-island form (arm64e-authenticated GOT
    dereference + ``braa``, seen on a macOS system cache's GeoServices) is
    followed the same way via :func:`_resolve_stub_island`.  Two
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

    Returns ``"plain"`` for anything unrecognised (safe no-op), including a
    genuine int32/uint32 tie.  Cache-native only: in standalone ``--binary``
    mode the stub's cross-image target can't be followed, so the field keeps
    its canonical int default (unrefined, never wrong).  Memoised on ``ctx``."""
    if not helper_va:
        return "plain"
    cache = _ctx_cache(ctx, "_writeto_helper_family", dict)
    if helper_va in cache:
        return cache[helper_va]

    fam = "plain"
    try:
        target = _helper_real_target(ctx, helper_va)
        # The family is decided at the helper's TAG-BUILD instruction (#59): whichever
        # of {sint value-shift, fixed bfi, plain varint tag} appears first wins, and we
        # STOP there — no scan budget decides the answer.  The field# is the 3rd arg
        # (w2/x2) and is moved into a callee-saved reg in the prologue; track it so the
        # plain varint tag-build (`lsl <field#>,#3`) can be told from an unrelated shift.
        movs: Dict[str, int] = {}          # most-recent `mov Rd,#imm` (fixed wire-type const)
        field_regs = {2}                   # GPR indices currently holding the field# arg
        tag_shift_seen = False             # saw `lsl <field#>,#3` (see below)
        for ins in disasm(ctx, target, max_insns=_HELPER_FAMILY_MAX_INSNS, stop_at_ret=True):
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
            if tag_shift_seen and (mn in _BLOCK_END_MNEMONICS or mn.startswith("b.")):
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
                    try:
                        movs[ops[0]] = _parse_imm(ops[1])
                    except Exception:
                        pass
            # bfi <Rd>, <field-reg>, #3, #0x1d  — tag = (field << 3) | wt, wt in Rd.
            if mn == "bfi" and len(ops) == 4 and _parse_imm(ops[2]) == 3:
                wt = movs.get(ops[0])
                if wt == 5:
                    fam = "fixed32"
                    break
                if wt == 1:
                    fam = "fixed64"
                    break
    except (NameError, ImportError):
        raise                       # our own wiring bug — never mask it
    except Exception as exc:
        # Bad/odd binary input → safe `plain` default, but log so a real logic
        # bug here (mislabelling sint/fixed as plain varint) is at least traceable.
        log.debug("write-helper classify failed at 0x%x: %s", helper_va or 0, exc)
        fam = "plain"
    cache[helper_va] = fam
    return fam


def _refine_scalar_by_family(type_name: str, fam: str) -> str:
    """Refine a canonical int type (``int32``/``int64``/``uint32``/``uint64``) by the
    wire-type family its write helper encodes (:func:`_classify_write_helper`): zigzag
    ``sint32``/``sint64``, or ``[s]fixed32``/``[s]fixed64`` — the SIGN half (fixed vs
    sfixed) coming from the storage type, exactly like int32↔uint32.  Unchanged for
    ``plain`` or any non-int type."""
    if type_name in ("int32", "int64", "uint32", "uint64"):
        if fam in ("sint32", "sint64"):
            return fam
        if fam == "fixed32":
            return "sfixed32" if type_name == "int32" else "fixed32"
        if fam == "fixed64":
            return "sfixed64" if type_name == "int64" else "fixed64"
    return type_name


# ── Lazy binary-wide pre-passes (cached on ctx) ───────────────────────────────


def _ensure_writeto_indegree(ctx: BinaryContext, cl: ClassList) -> None:
    """Lazily build + cache the writeTo CFG-walk indegree pre-pass on ``ctx``.

    The walk decoder (:func:`_extract_writeto_field_numbers`) needs the binary-wide
    branch-indegree map + writeTo-IMP set threaded onto ``ctx``.
    :func:`proto.extractor.extract_all` builds it once up front, but
    :func:`proto.extractor.extract_proto_message` may also be called standalone
    (single-class extraction, unit tests) without ``extract_all`` — so build it on
    first use here too.  Cached on ``ctx`` (the binary-wide build runs at most once
    per context); without this, a standalone call would silently get NO writeTo
    decoding (the walk's no-pre-pass path returns ``{}``).

    Builds only when absent; on a (real-world-unseen) build failure it leaves the
    attrs ``None``, so a persistently failing context retries — acceptable, since
    the pre-pass succeeds on every supported artifact."""
    if (getattr(ctx, "_writeto_indeg", None) is not None
            and getattr(ctx, "_writeto_foreign_imps", None) is not None):
        return
    try:
        indeg, foreign = build_writeto_indegree(ctx, cl)
        ctx._writeto_indeg = indeg
        ctx._writeto_foreign_imps = foreign
    except Exception as exc:
        log.debug("writeTo indegree lazy pre-pass failed (%s); CFG walk disabled "
                  "for this call", exc)


def _ensure_string_write_helpers(ctx: BinaryContext, cl: ClassList) -> "FrozenSet[int]":
    """Lazily build + cache the binary-wide string-write-helper VA set on ``ctx``.

    Mirrors :func:`_ensure_writeto_indegree`: ``extract_all`` builds this once and
    passes it explicitly, but a standalone :func:`proto.extractor.extract_proto_message`
    caller that omits the kwarg would otherwise silently lose ``repeated string`` vs
    ``repeated bytes`` typing. Cached so the binary-wide scan runs at most once per
    context. An empty result is a valid build (cached, not retried)."""
    cached = getattr(ctx, "_string_write_helpers", None)
    if cached is not None:
        return cached
    try:
        helpers = frozenset(_identify_string_write_helpers(ctx, cl))
    except Exception as exc:
        log.debug("string-write-helper lazy pre-pass failed (%s)", exc)
        helpers = frozenset()
    try:
        ctx._string_write_helpers = helpers
    except Exception:
        pass
    return helpers
