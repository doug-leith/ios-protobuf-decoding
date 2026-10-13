"""A tiny arm64 assembler + fake binary context for the synthetic enum-recovery tests.

Covers only the instruction forms the ``_dictionaryRepresentation:`` fixtures need, with
label-resolved branches, so a fixture reads as the code it models instead of a column of hex
words.  Every encoding is checked against capstone by ``TestAssemblerMatchesCapstone``
(tests/test_dictrep_inline_enums.py), so a mistake here cannot silently bless a wrong fixture.

Not a general assembler: unsupported text raises ``ValueError``.
"""
import re
import struct

from tests.conftest import WordCtx

_COND = {'eq': 0, 'ne': 1, 'hs': 2, 'cs': 2, 'lo': 3, 'cc': 3, 'mi': 4, 'pl': 5,
         'hi': 8, 'ls': 9, 'ge': 10, 'lt': 11, 'gt': 12, 'le': 13}


def _reg(tok):
    m = re.fullmatch(r'[xw](\d+)', tok.strip())
    if not m:
        raise ValueError(f'register {tok!r}')
    return int(m.group(1))


def _imm(tok):
    return int(tok.strip().lstrip('#'), 0)


def _split(ops):
    out, depth, cur = [], 0, ''
    for ch in ops:
        if ch == '[':
            depth += 1
        elif ch == ']':
            depth -= 1
        if ch == ',' and depth == 0:
            out.append(cur.strip())
            cur = ''
        else:
            cur += ch
    if cur.strip():
        out.append(cur.strip())
    return out


def _mem(tok):
    parts = [p.strip() for p in tok.strip()[1:-1].split(',')]
    return parts


def assemble(base, lines):
    """Assemble *lines* (instruction strings and ``label:`` lines) placed at *base*.

    Returns ``(words, labels)``; branch operands may be a label or ``#0xADDR``."""
    labels, code, pc = {}, [], base
    for ln in lines:
        ln = ln.split(';')[0].strip()
        if not ln:
            continue
        if ln.endswith(':'):
            labels[ln[:-1]] = pc
            continue
        code.append((pc, ln))
        pc += 4
    words = []
    for pc, ln in code:
        mn, _, rest = ln.partition(' ')
        ops = _split(rest)

        def target(tok):
            return labels[tok] if tok in labels else _imm(tok)

        def rel(tok, bits):
            off = (target(tok) - pc) >> 2
            return off & ((1 << bits) - 1)

        if mn == 'adrp':
            page = (_imm(ops[1]) - (pc & ~0xFFF)) >> 12
            w = 0x90000000 | ((page & 3) << 29) | (((page >> 2) & 0x7FFFF) << 5) | _reg(ops[0])
        elif mn == 'add' and ops[2].startswith('#'):
            w = 0x91000000 | (_imm(ops[2]) << 10) | (_reg(ops[1]) << 5) | _reg(ops[0])
        elif mn == 'sub' and ops[2].startswith('#') and ops[0].startswith('w'):
            w = 0x51000000 | (_imm(ops[2]) << 10) | (_reg(ops[1]) << 5) | _reg(ops[0])
        elif mn == 'ldrsw' and ops[1].startswith('[') and _mem(ops[1])[1].startswith('#'):
            m = _mem(ops[1])
            w = 0xB9800000 | ((_imm(m[1]) // 4) << 10) | (_reg(m[0]) << 5) | _reg(ops[0])
        elif mn in ('ldr', 'ldrb', 'ldrsw') and ops[1].startswith('[') \
                and len(_mem(ops[1])) >= 2 and not _mem(ops[1])[1].startswith('#'):
            m = _mem(ops[1])                         # ldr rt, [xn, rm{, lsl|sxtw #s}]
            base_op = {('ldr', 'w'): 0xB8600800, ('ldr', 'x'): 0xF8600800,
                       ('ldrb', 'w'): 0x38600800, ('ldrsw', 'x'): 0xB8A00800}[(mn, ops[0][0])]
            ext = m[2].split()[0] if len(m) > 2 else 'lsl'
            scaled = len(m) > 2 and _imm(m[2].split()[1]) != 0
            option = {'lsl': 3, 'sxtw': 6, 'uxtw': 2}[ext]
            w = base_op | (_reg(m[1]) << 16) | (option << 13) | (int(scaled) << 12) \
                | (_reg(m[0]) << 5) | _reg(ops[0])
        elif mn == 'ldr' and ops[1].startswith('['):
            m = _mem(ops[1])                         # ldr rt, [xn{, #imm}]
            imm = _imm(m[1]) if len(m) > 1 else 0
            if ops[0].startswith('x'):
                w = 0xF9400000 | ((imm // 8) << 10) | (_reg(m[0]) << 5) | _reg(ops[0])
            else:
                w = 0xB9400000 | ((imm // 4) << 10) | (_reg(m[0]) << 5) | _reg(ops[0])
        elif mn == 'add' and not ops[2].startswith('#'):
            sh = _imm(ops[3].split()[1]) if len(ops) > 3 else 0     # add xd, xn, xm{, lsl #s}
            w = 0x8B000000 | (_reg(ops[2]) << 16) | (sh << 10) | (_reg(ops[1]) << 5) | _reg(ops[0])
        elif mn == 'adr':
            off = target(ops[1]) - pc
            w = 0x10000000 | ((off & 3) << 29) | (((off >> 2) & 0x7FFFF) << 5) | _reg(ops[0])
        elif mn == 'br':
            w = 0xD61F0000 | (_reg(ops[0]) << 5)
        elif mn == 'cmp' and not ops[1].startswith('#'):
            w = (0x6B00001F if ops[0].startswith('w') else 0xEB00001F) \
                | (_reg(ops[1]) << 16) | (_reg(ops[0]) << 5)
        elif mn == 'cmp' and ops[1].startswith('#'):
            w = 0x7100001F | (_imm(ops[1]) << 10) | (_reg(ops[0]) << 5)
        elif mn.startswith('b.'):
            w = 0x54000000 | (rel(ops[0], 19) << 5) | _COND[mn[2:]]
        elif mn == 'cbz':
            w = 0x34000000 | (rel(ops[1], 19) << 5) | _reg(ops[0])
        elif mn == 'cbnz':
            w = 0x35000000 | (rel(ops[1], 19) << 5) | _reg(ops[0])
        elif mn in ('tbz', 'tbnz'):
            w = (0x36000000 if mn == 'tbz' else 0x37000000) | (_imm(ops[1]) << 19) \
                | (rel(ops[2], 14) << 5) | _reg(ops[0])
        elif mn == 'b':
            w = 0x14000000 | rel(ops[0], 26)
        elif mn == 'bl':
            w = 0x94000000 | rel(ops[0], 26)
        elif mn == 'mov' and not ops[1].startswith('#'):
            w = 0xAA0003E0 | (_reg(ops[1]) << 16) | _reg(ops[0])
        elif mn == 'mov':
            w = (0x52800000 if ops[0].startswith('w') else 0xD2800000) \
                | (_imm(ops[1]) << 5) | _reg(ops[0])
        elif mn == 'ret':
            w = 0xD65F03C0
        elif mn == 'nop':
            w = 0xD503201F
        else:
            raise ValueError(f'cannot assemble {ln!r}')
        words.append(w)
    return words, labels


class FlowCtx(WordCtx):
    """``WordCtx`` plus what the data-flow evaluator reads: byte/halfword reads inside the
    word store, and direct C-strings standing in for CFStrings (``ctx._strings``)."""

    def read_bytes(self, va, length):
        if length % 4 == 0:
            return super().read_bytes(va, length)
        out = bytearray()
        for a in range(va, va + length):
            word = self._m[a & ~3]
            out.append(struct.pack('<I', word)[a & 3])
        return bytes(out)

    def put_bytes(self, va, data):
        """Store *data* at *va* (little-endian words; the tail is zero-padded)."""
        data = bytes(data) + b'\0' * (-len(data) % 4)
        for i in range(0, len(data), 4):
            self._m[va + i] = struct.unpack('<I', data[i:i + 4])[0]

    def put_ptr(self, va, value):
        self._m[va] = value & 0xFFFFFFFF
        self._m[va + 4] = value >> 32
