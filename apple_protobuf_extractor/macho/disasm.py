"""
macho/disasm.py — arm64 disassembler and instruction-stream analysis.

Architecture
------------
* disasm(ctx, vmaddr, max_insns, stop_at_ret) → List[Insn]
  Disassembles arm64 code starting at vmaddr with capstone (required: a partial
  decoder would silently change what the analysis sees).
  By default stops at the first ret-family instruction or after max_insns
  instructions.  Pass stop_at_ret=False to continue past ret (needed when
  scanning writeTo: methods whose out-of-line field blocks follow the main
  function epilogue).

* Analysis primitives operate on List[Insn] — no BinaryContext needed.
  All pattern matching is structural (mnemonic + op_str regex); no hardcoded
  addresses are ever used.  The same code works across any arm64 binary.

Public API
----------
    disasm(ctx, vmaddr, max_insns=512, stop_at_ret=True) → List[Insn]

Register values (an adrp+add address, a loaded slot, a movz constant) are read by
:class:`proto.arm64_eval.Flow`, not here.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional

from .memory import BinaryContext

# ─── Public types ─────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Insn:
    """One decoded arm64 instruction."""
    addr:     int    # vmaddr
    mnemonic: str    # lower-case, e.g. "adrp", "bl", "ret"
    op_str:   str    # operand string, e.g. "x8, #0x5000"
    size:     int    # always 4 on arm64
    raw:      bytes  # 4 raw bytes (little-endian)

    def __str__(self) -> str:
        return f"0x{self.addr:x}:  {self.mnemonic:<8} {self.op_str}"


# ─── Constants ────────────────────────────────────────────────────────────────

_STOP_MNEMONICS  = frozenset(('ret', 'retaa', 'retab', 'eret'))
# [cap:INPUT-SANITY — leave as-is] Only the *default* max_insns for callers that don't
# pass one.  Every decode-critical disassembly in the extractor passes an EXPLICIT cap
# (the proto/extractor.py Tier-1/2 constants), so this default governs only don't-care
# / early-terminating reads and is never the binding limit for any field/enum/number.
_DEFAULT_MAX     = 512

# Mnemonics whose first register operand is a SOURCE (read), not a destination
# ('str x8, [x9]' reads x8; 'cmp x8, #0' reads x8): proto.arm64_operands.writes.
_SOURCE_FIRST_MNEMONICS = frozenset({
    'str',  'strb',  'strh',  'stur',  'sturb',  'sturh',
    'sttr', 'sttrb', 'sttrh',
    'stp',  'stnp',
    'stxr', 'stxrb', 'stxrh', 'stlxr', 'stlxrb', 'stlxrh',
    'stlr', 'stlrb', 'stlrh',
    'cmp',  'cmn',   'tst',
    'cbz',  'cbnz',
    'tbz',  'tbnz',
    'blr',  'br',
    'blraa', 'blrab', 'blraaz', 'blrabz',     # arm64e: through a pointer-authenticated
    'braa',  'brab',  'braaz',  'brabz',      # register (the second operand: its modifier)
    'ret',  'retaa', 'retab',
})

# ─── Register helpers ─────────────────────────────────────────────────────────

_REG_RE  = re.compile(r'^[xwXW](\d+)$')
_IMM_RE  = re.compile(r'#(-?0x[0-9a-fA-F]+|-?\d+)')

def _norm_reg(name: str) -> Optional[str]:
    """Normalise an arm64 register name to 'xN' form.

    'x8' → 'x8', 'w8' → 'x8', 'sp' → 'sp', 'xzr'/'wzr' → 'xzr'.
    Returns None for unrecognised names.
    """
    name = name.strip().lower()
    if name == 'sp':
        return 'sp'
    if name in ('xzr', 'wzr'):
        return 'xzr'
    m = _REG_RE.match(name)
    return f'x{m.group(1)}' if m else None


def _parse_imm(s: str) -> Optional[int]:
    """Extract the first immediate value from an op_str fragment."""
    m = _IMM_RE.search(s)
    if not m:
        return None
    val = m.group(1)
    try:
        return int(val, 16) if '0x' in val.lower() else int(val)
    except ValueError:
        return None


def disasm(
    ctx: BinaryContext,
    vmaddr: int,
    max_insns: int = _DEFAULT_MAX,
    stop_at_ret: bool = True,
) -> List[Insn]:
    """
    Disassemble arm64 instructions starting at *vmaddr* in *ctx*.

    Decodes with capstone; raises ImportError when it is not installed.

    When *stop_at_ret* is True (the default) the scan halts at the first
    ret-family instruction and includes it in the result.  Pass
    ``stop_at_ret=False`` when you need to read past a function epilogue —
    for example, when analysing writeTo: methods that place some field-write
    blocks in out-of-line sections *after* the main ``ret``.

    Raises ValueError if *vmaddr* is not 4-byte aligned or cannot be read.
    """
    if vmaddr & 3:
        raise ValueError(
            f"vmaddr 0x{vmaddr:x} is not 4-byte aligned (arm64 requires 4-byte)"
        )

    # Validate that vmaddr is readable — raises ValueError for unmapped addresses.
    # This is intentional: callers should not silently proceed with bad IMPs.
    #
    # Binary mode: vmaddr_to_offset validates against segment bounds and the
    #   in-memory binary data.  Cheap (no data copy).
    #
    # Cache-native mode: ctx._data is empty (b'') so vmaddr_to_offset's final
    #   guard ("off + length > len(self._data)") fires for EVERY non-zero
    #   vmaddr — even fully valid ones — because len(b'') == 0.  In cache mode
    #   we validate by attempting an actual 4-byte read through the cache
    #   reader, which raises ValueError for truly unmapped addresses.
    #
    # getattr with a default of False makes this duck-type-safe: test stubs
    # that implement the BinaryContext interface without inheriting from it
    # (e.g. _FakeCtx in test_proto.py) fall through to vmaddr_to_offset as
    # normal and continue working without needing to add is_cache_backed.
    if getattr(ctx, "is_cache_backed", False):
        try:
            ctx.read_bytes(vmaddr, 4)
        except ValueError:
            raise ValueError(
                f"vmaddr 0x{vmaddr:x} not readable in cache"
            )
    else:
        ctx.vmaddr_to_offset(vmaddr, 4)

    data = _read_available(ctx, vmaddr, max_insns * 4)
    if not data:
        return []

    return _disasm_capstone(data, vmaddr, max_insns, stop_at_ret)


def _read_available(ctx: BinaryContext, vmaddr: int, want: int) -> bytes:
    """
    Read up to *want* bytes from *vmaddr*, gracefully shrinking the request
    when the read window extends past the segment boundary.

    Returns empty bytes if even a single instruction cannot be read.
    """
    # Fast path: the common case where the method is far from the segment end
    try:
        return ctx.read_bytes(vmaddr, want)
    except ValueError:
        pass
    # Binary-search for the largest 4-byte-aligned read that succeeds
    lo, hi = 4, want - 4
    best   = b''
    while lo <= hi:
        mid = ((lo + hi) // 2) & ~3   # keep 4-byte aligned
        if mid < 4:
            break
        try:
            best = ctx.read_bytes(vmaddr, mid)
            lo   = mid + 4
        except ValueError:
            hi  = mid - 4
    return best


# ── capstone backend ──────────────────────────────────────────────────────────

_CS = None     # the one capstone decoder: building one costs more than most decodes


def _decoder():
    global _CS
    if _CS is None:
        try:
            import capstone
        except ImportError as exc:
            raise ImportError("capstone is required to disassemble arm64 code "
                              "(pip install capstone; see requirements.txt)") from exc
        _CS = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    return _CS


def _disasm_capstone(data: bytes, vmaddr: int, max_insns: int,
                     stop_at_ret: bool = True) -> List[Insn]:
    result: List[Insn] = []
    for ci in _decoder().disasm(data, vmaddr):
        insn = Insn(
            addr     = ci.address,
            mnemonic = ci.mnemonic,
            op_str   = ci.op_str,
            size     = ci.size,
            raw      = bytes(ci.bytes),
        )
        result.append(insn)
        if stop_at_ret and ci.mnemonic in _STOP_MNEMONICS:
            break
        if len(result) >= max_insns:
            break
    return result
