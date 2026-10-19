"""Hand-built arm64 instruction listings for the offline tests (no binary): ``Insn`` lists
from ``(mnemonic, op_str)`` pairs or ``'mnemonic ops'`` lines, and a drop-in for
``macho.disasm.disasm`` over them."""
from macho.disasm import Insn, _STOP_MNEMONICS


def insns(pairs, base=0x1000):
    """``Insn`` list of ``(mnemonic, op_str)`` *pairs* at sequential addresses from *base*."""
    return [Insn(addr=base + 4 * i, mnemonic=mn, op_str=op, size=4, raw=b'\x00' * 4)
            for i, (mn, op) in enumerate(pairs)]


def text_listing(*lines, base=0x1000):
    """``(insns, labels)`` for *lines* (``'mnemonic ops'`` or ``'label:'``) placed at *base*;
    ``@label`` operands become addresses."""
    labels, code, pc = {}, [], base
    for ln in lines:
        if ln.endswith(':'):
            labels[ln[:-1]] = pc
        else:
            code.append((pc, ln))
            pc += 4
    out = []
    for a, ln in code:
        mn, _, ops = ln.partition(' ')
        for name, addr in labels.items():
            ops = ops.replace('@' + name, hex(addr).replace('0x', '#0x'))
        out.append(Insn(addr=a, mnemonic=mn, op_str=ops, size=4, raw=b'\x00' * 4))
    return out, labels


def layout(*blocks):
    """Lay out ``(base, [(mnemonic, op_str), ...])`` blocks; return ``(insn_list, fake_disasm)``:
    every instruction in order, and a drop-in for ``macho.disasm.disasm`` over that memory
    (which, like it, stops after a ret-family instruction when *stop_at_ret*)."""
    mem, order = {}, []
    for base, lines in blocks:
        for ins in insns(lines, base):
            mem[ins.addr] = ins
            order.append(ins)

    def fake_disasm(ctx, addr, max_insns=400, stop_at_ret=True):
        out, a = [], addr
        while len(out) < max_insns and a in mem:
            ins = mem[a]
            out.append(ins)
            if stop_at_ret and ins.mnemonic in _STOP_MNEMONICS:
                break
            a += 4
        return out
    return order, fake_disasm
