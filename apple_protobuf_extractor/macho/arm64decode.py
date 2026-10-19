"""Pure ARM64 instruction-word decoders for the jump-table range gate.

``cmp wN, #imm ; b.<cond>`` read from raw words: :func:`_decode_cmp_imm`,
:func:`_decode_bcond` and :func:`range_from_unsigned_gate` (used by
``proto.dispatch._find_field_count``).  No dependency on ``ctx``, the binary, or
any proto concept — only the ARM64 encoding.
"""
from typing import Optional, Tuple


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
