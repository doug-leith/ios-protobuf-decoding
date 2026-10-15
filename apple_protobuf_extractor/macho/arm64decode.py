"""proto/arm64decode helpers — pure ARM64 instruction-word decoders.

Carved verbatim from ``proto.extractor`` (#11 monolith split, step 1). Every
function here is a pure ``word:int -> value`` decoder (or a small word predicate)
with NO dependency on ``ctx``, the binary, or any proto concept — only the ARM64
encoding. ``proto.extractor`` re-imports the whole surface so existing call sites
and tests are unchanged.
"""
from typing import Dict, Optional, Tuple

def _decode_adr(word: int, va: int) -> Optional[Tuple[int, int]]:
    """
    Decode ``adr Xd, label`` → ``(Rd, target_vmaddr)``, or ``None``.

    ADR encoding (A64):
        [31]    = 0  (op; 1 = ADRP)
        [30:29] = immlo (2 bits)
        [28:24] = 10000 (fixed)
        [23:5]  = immhi (19 bits)
        [4:0]   = Rd
    """
    if (word & 0x9F000000) != 0x10000000:
        return None
    rd    =  word & 0x1F
    immlo = (word >> 29) & 0x3
    immhi = (word >> 5)  & 0x7FFFF
    imm21 = (immhi << 2) | immlo
    if imm21 & (1 << 20):       # sign-extend 21-bit field
        imm21 -= (1 << 21)
    return (rd, va + imm21)


def _is_br_insn(word: int) -> bool:
    """Return True if *word* is a ``br Xn`` instruction (unconditional indirect branch)."""
    # BR encoding: 1101 0110 0001 1111 0000 00xx xxxxx xxxxx
    # Fixed mask:  0xFFFFFC1F  Fixed pattern: 0xD61F0000
    return (word & 0xFFFFFC1F) == 0xD61F0000


def _decode_ldr_reg_off(word: int) -> Optional[Tuple[int, int, int, int]]:
    """Decode an integer ``LDR(B/H/W/X)`` or ``LDRSW`` *register-offset* load.

    Returns ``(entry_size_bytes, Rn, Rm, Rt)``, or ``None``.  Used to read the
    true jump-table entry width (1 byte for ``ldrb`` tables, 2 for ``ldrh``, 4
    for ``ldr w``/``ldrsw``) because the native mini-decoder renders these
    instructions as ``unk``.

    Two encodings share the same field layout (load/store register, register
    offset, V=0) and differ only in ``opc``:

        size(2) 111 0 00 opc(2) 1 Rm(5) option(3) S(1) 10 Rn(5) Rt(5)

    ``opc=01`` is the zero-extending form (``ldrb``/``ldrh``/``ldr w``/``ldr
    x``; entry width from ``size``).  ``opc=10`` with ``size=10`` is
    ``ldrsw`` — a newer Apple-internal toolchain's outlined per-class dispatch
    "engine" (observed on a macOS system dyld cache's GeoServices) uses this
    sign-extending form for its 4-byte jump-table entries (a signed
    ``(arm - base)`` byte delta, needing 64-bit sign-extension into the index
    register); entry width is fixed at 4 since size is pinned to 10 for this
    form (there is no 32-bit-destination ``ldrsw``).
    """
    if (word & 0x3FE00C00) == 0x38600800:              # opc=01, any size
        size = (word >> 30) & 0x3
        return (1 << size, (word >> 5) & 0x1F, (word >> 16) & 0x1F, word & 0x1F)
    if (word & 0xFFE00C00) == 0xB8A00800:               # opc=10, size=10 (ldrsw)
        return (4, (word >> 5) & 0x1F, (word >> 16) & 0x1F, word & 0x1F)
    return None


def jumptable_arm_target(base: int, width: int, raw: bytes) -> int:
    """Address of the jump-table arm whose table entry is *raw* (``width`` bytes).

    Two table idioms, told apart by the entry width of the register-offset load
    that reads the table (the same convention ``proto.dispatch`` uses):

    * ``ldrb`` / ``ldrh`` (width 1 / 2) — the classic toolchain's unsigned INDEX
      table: ``adr xB,#arms ; ldrh w,[table,idx,lsl#1] ; add xB,xB,w,lsl #2 ; br``,
      so the arm is ``base + entry * 4`` (arms are 4-byte aligned).
    * ``ldrsw`` (width 4) — the newer toolchain's (iOS 27 / macOS 27) signed
      DIFFERENCE table: ``adr xB,. ; ldrsw x,[table,idx,lsl#2] ; add xB,xB,x ; br``,
      so the entry is already a signed byte delta from ``base`` (negative deltas are
      common) and is not scaled.
    """
    signed = width == 4
    entry = int.from_bytes(raw[:width], "little", signed=signed)
    return base + entry * (1 if signed else 4)


_CMP_MASK    = 0xFF00001F


_CMP_PATTERN = 0x7100001F


def _decode_cmp_imm(word: int) -> Optional[Tuple[int, int]]:
    """
    Decode a `cmp wN, #imm` instruction word.
    Returns (Rn, immediate) or None if not a CMP-immediate.
    """
    if (word & _CMP_MASK) != _CMP_PATTERN:
        return None
    rn    = (word >> 5) & 0x1F
    imm12 = (word >> 10) & 0xFFF
    shift = (word >> 22) & 0x3
    imm   = imm12 << (shift * 12)
    return (rn, imm)


# cmp wN, wM  ==  SUBS wzr, wN, wM (shifted-register form, Rd = 31).
#   31  30 29  28..24   23 22  21  20..16  15..10  9..5  4..0
#    0   1  1  0 1011    shift   0    Rm     imm6    Rn    Rd(=11111)
_CMP_REG_MASK    = 0xFF20001F


_CMP_REG_PATTERN = 0x6B00001F


def _decode_cmp_reg(word: int) -> Optional[Tuple[int, int]]:
    """
    Decode a 32-bit ``cmp wN, wM`` (SUBS wzr, wN, wM, shifted-register, no shift).
    Returns ``(Rn, Rm)`` or ``None``.

    The immediate form (:func:`_decode_cmp_imm`) can only hold a 12-bit value
    (≤ 0xFFF = 4095); the compiler materializes any larger enum constant into a
    register with ``movz``[/``movk``] and emits this register compare instead.
    See :func:`_materialized_value`.
    """
    if (word & _CMP_REG_MASK) != _CMP_REG_PATTERN:
        return None
    rn = (word >> 5)  & 0x1F
    rm = (word >> 16) & 0x1F
    return (rn, rm)


# 32-bit MOVZ/MOVK: 0 opc 100101 hw imm16 Rd.  opc=10 → MOVZ, opc=11 → MOVK.
_MOV_IMM_MASK = 0x7F800000


_MOVZ_PATTERN = 0x52800000


_MOVK_PATTERN = 0x72800000


def _decode_movz(word: int) -> Optional[Tuple[int, int, int]]:
    """Decode 32-bit ``movz wRd, #imm16{, lsl #sh}`` → ``(Rd, imm16, shift)``."""
    if (word & _MOV_IMM_MASK) != _MOVZ_PATTERN:
        return None
    rd    = word & 0x1F
    imm16 = (word >> 5) & 0xFFFF
    hw    = (word >> 21) & 0x3
    return (rd, imm16, hw * 16)


def _decode_movk(word: int) -> Optional[Tuple[int, int, int]]:
    """Decode 32-bit ``movk wRd, #imm16{, lsl #sh}`` → ``(Rd, imm16, shift)``."""
    if (word & _MOV_IMM_MASK) != _MOVK_PATTERN:
        return None
    rd    = word & 0x1F
    imm16 = (word >> 5) & 0xFFFF
    hw    = (word >> 21) & 0x3
    return (rd, imm16, hw * 16)


def _materialized_value(
    insns: list, words: Dict[int, int], cmp_idx: int, reg: int
) -> Optional[int]:
    """
    Recover the 32-bit constant materialized into *reg* by the ``movz``[/``movk``]
    pair in the (≤ 4) instructions preceding *cmp_idx*.  Returns the composed
    value, or ``None`` if no ``movz`` writing *reg* is found.

    ARM64 ``cmp wN, #imm`` can only encode a 12-bit immediate, so a larger enum
    constant is loaded as ``movz wReg, #lo16``  plus an optional
    ``movk wReg, #hi16, lsl #16`` and compared register-to-register.  The two
    halves are **OR-composed** — ``movz`` writes bits [15:0], ``movk`` writes
    [31:16]; neither may overwrite the other (composing in the wrong order yields
    e.g. 25067 instead of 90603 for ``0x61eb | (1<<16)``).
    """
    lo: Optional[int] = None
    hi = 0
    for j in range(cmp_idx - 1, max(cmp_idx - 5, -1), -1):
        w = words.get(insns[j].addr, 0)
        mz = _decode_movz(w)
        if mz is not None and mz[0] == reg:
            _, imm16, shift = mz
            if shift == 0:
                lo = imm16
            else:                       # rare: movz directly into the high half
                hi = imm16 << shift
            break                        # movz is the base; stop scanning
        mk = _decode_movk(w)
        if mk is not None and mk[0] == reg:
            _, imm16, shift = mk
            if shift >= 16:
                hi = imm16 << shift
            else:
                lo = imm16
    if lo is None and hi == 0:
        return None
    return (lo or 0) | hi


# 32-bit ``sub wRd, wRn, #imm12`` (ADD/SUB immediate, sf=0 op=1 S=0): the top 9
# bits select the opcode; the immediate / Rn / Rd occupy the low bits.  Exposed
# as named constants because several enum-bias scanners match this word shape
# directly on the field bits (shift, imm12) without calling _decode_sub_imm.
_SUB_W_IMM_MASK    = 0xFF800000
_SUB_W_IMM_PATTERN = 0x51000000


def _decode_sub_imm(word: int) -> Optional[Tuple[int, int, int]]:
    """
    Decode a 32-bit ``sub wRd, wRn, #imm`` (immediate) instruction word.
    Returns ``(Rd, Rn, immediate)`` or ``None``.

    Used to read the **field-number bias** of a readFrom: jump table: the
    dispatch indexes its table with ``idx = (tag>>3) - bias`` via a
    ``sub Wi, Wt, #bias`` immediately before the field-count gate, so arm *i*
    serves field number ``bias + i`` (e.g. bias 1 for a table starting at field
    1, bias 0x15 for ALSLocationResponse's high cell-tower-subtype fields).

    Encoding (ADD/SUB immediate, sf=0 op=1 S=0): ``0 1 0 100010 sh imm12 Rn Rd``.
    """
    if (word & _SUB_W_IMM_MASK) != _SUB_W_IMM_PATTERN:
        return None
    rd    = word & 0x1F
    rn    = (word >> 5) & 0x1F
    imm12 = (word >> 10) & 0xFFF
    shift = (word >> 22) & 0x1
    return (rd, rn, imm12 << (12 if shift else 0))


def _decode_lsr_imm(word: int) -> Optional[Tuple[int, int, int]]:
    """
    Decode an ``lsr xRd, xRn, #shift`` immediate (a UBFM alias) instruction word.
    Returns ``(Rd, Rn, shift)`` or ``None``.

    The protobuf **field-number extraction** has this shape: every generated reader
    computes ``field# = tag >> 3`` with a single ``lsr Wf, Wtag, #3`` (the readFrom:
    dispatch evaluator, proto.dispatch_eval, sets Wf there to each field number).

    UBFM/LSR encoding: 64-bit ``(w & 0xFFC00000)==0xD3400000`` with ``imms==63``;
    32-bit ``(w & 0xFFC00000)==0x53000000`` with ``imms==31``.  ``immr`` is the
    shift amount.
    """
    if (word & 0xFFC00000) == 0xD3400000:        # 64-bit UBFM
        if ((word >> 10) & 0x3F) != 63:
            return None
    elif (word & 0xFFC00000) == 0x53000000:      # 32-bit UBFM
        if ((word >> 10) & 0x3F) != 31:
            return None
    else:
        return None
    rd    = word & 0x1F
    rn    = (word >> 5) & 0x1F
    shift = (word >> 16) & 0x3F
    return (rd, rn, shift)


_BCOND_MASK    = 0xFF000010


_BCOND_PATTERN = 0x54000000


def _decode_bcond(word: int) -> Optional[int]:
    """
    If word is a B.cond instruction, return the condition code (low 4 bits).
    Returns None otherwise.
    """
    if (word & _BCOND_MASK) != _BCOND_PATTERN:
        return None
    return word & 0xF


# Canonical ARM64 B.cond condition codes (the value :func:`_decode_bcond`
# returns).  Single source of truth — callers (enums.py / dispatch.py) import
# these instead of re-declaring the subset each needs.
_COND_EQ = 0x0   # equal
_COND_NE = 0x1   # not equal
_COND_HS = 0x2   # unsigned >=  (a.k.a. CS)
_COND_LO = 0x3   # unsigned <   (a.k.a. CC)
_COND_HI = 0x8   # unsigned >
_COND_LS = 0x9   # unsigned <=


def range_from_unsigned_gate(cond: Optional[int], imm: int) -> int:
    """Number of contiguous table entries a jump-table `cmp wN,#imm; b.<cond>`
    range gate covers, using the unsigned default-branch convention shared by
    every jump-table decoder in the codebase.

    The gate compares the (already bias-subtracted) index against ``imm`` and the
    conditional branch jumps to the *default/out-of-range* handler:

      * ``b.hi`` (index > imm → default)  ⇒ valid indices are 0..imm  ⇒ ``imm + 1``
      * ``b.hs`` (index >= imm → default) ⇒ valid indices are 0..imm-1 ⇒ ``imm``

    Any other condition is not a range gate → ``0``.  Single source of truth so
    the off-by-one convention is fixed in ONE place (it was previously inlined in
    the former readFrom: dispatch-cluster decoder, the jump-table enum harvester, and the dictRep
    harvester; a divergence here silently drops the last enum value / dispatch
    arm).  Note: this is the default-branch sense; the comparison-tree *routing*
    gate (b.ls/b.lo into a segment) has the inverse polarity and is handled at
    its own site."""
    if cond == _COND_HI:
        return imm + 1
    if cond == _COND_HS:
        return imm
    return 0


def _decode_bcond_target(word: int, va: int) -> Optional[int]:
    """Return the branch target VA of a ``b.cond`` (PC-relative imm19) at *va*,
    or ``None`` if *word* is not a B.cond."""
    if (word & _BCOND_MASK) != _BCOND_PATTERN:
        return None
    imm19 = (word >> 5) & 0x7FFFF
    if imm19 & 0x40000:            # sign-extend the 19-bit immediate
        imm19 -= 0x80000
    return va + imm19 * 4


def _decode_b_bl_target(word: int, va: int) -> Optional[int]:
    """Return the target VA of a ``b``/``bl`` (PC-relative imm26) at *va*, else None."""
    if (word & 0xFC000000) not in (0x14000000, 0x94000000):   # B / BL
        return None
    imm26 = word & 0x03FFFFFF
    if imm26 & 0x02000000:
        imm26 -= 0x04000000
    return va + imm26 * 4


_BL_MASK    = 0xFC000000
_BL_PATTERN = 0x94000000   # BL opcode (vs 0x14000000 = B); top-6-bit selector


def _is_bl_word(word: int) -> bool:
    """True for a ``bl`` (branch-with-link / call) instruction word — the
    forward-scan dispatch resolvers anchor element/handler calls on this."""
    return (word & _BL_MASK) == _BL_PATTERN


def _is_ret_word(word: int) -> bool:
    """True for ``ret`` / ``retaa`` / ``retab``."""
    return word in (0xD65F03C0, 0xD65F0BFF, 0xD65F0FFF)


def _is_func_prologue_word(word: int) -> bool:
    """True if *word* is a function-prologue opener — used to detect the start of
    the NEXT function when bounding a past-the-ret raw-word scan.

    Recognises the common arm64 openers: ``sub sp, sp, #imm`` (frame allocation),
    ``stp …, [sp, #-imm]!`` (pre-indexed register save) and the PAC
    ``pacibsp``/``paciasp`` sign.
    """
    if word in (0xD503237F, 0xD503233F):                      # pacibsp / paciasp
        return True
    if (word & 0xFF8003FF) == 0xD10003FF:                     # sub sp, sp, #imm
        return True
    if (word & 0xFFC003E0) == 0xA98003E0:                     # stp …, [sp, #-imm]!
        return True
    return False
