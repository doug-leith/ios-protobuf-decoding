"""proto/dictrep_flow.py -- enum (value -> name) recovery from ``_dictionaryRepresentation:`` by
data-flow analysis, not by instruction windows.

An enum field with no ``xAsString:`` converter has the converter INLINED into the class's
``-_dictionaryRepresentation:``: the field's int is loaded from its ivar, run through a switch
(compare chain, jump table, pointer table, or a mix, possibly in several segments and possibly
inside the loop that walks a repeated field) to a CFString, and the CFString is handed to the
dictionary / array by the next call.  Whatever the shape, that is a *function from the int to a
CFString*, so this module recovers it as one:

1. :class:`proto.arm64_eval.Flow` (this module's ``Flow`` extends it) builds the function's
   CFG (jump-table arms injected) and its **reaching definitions**.  A register's constant (a table base, a name hoisted out of a loop) is known
   iff exactly one definition reaches the use and that definition is a constant expression.
2. The field is identified by **use-def chain**: the loaded value's address register traces back,
   through ``add`` / container-deref / ``mov``, to the ``ldrsw`` of the ivar-offset slot.
3. **Candidate values** are read off the comparisons the loaded value actually takes part in
   (``V + b`` affine form, so ``sub w9, w8, #0x23; cmp w9, #0x1e`` yields V in [35, 65]).
4. Each candidate is **evaluated** concretely through the CFG up to the first call; the CFString
   in the first-argument register at that call is the name (or ``"(unknown: %i)"``).

Numbers therefore come from the constants the code compares/indexes with, never from name order,
and a segmented sparse switch is just one evaluation per value.  A field is an enum iff it yields
a name AND the outcome depends on the value: two different names, or a name and the converter's
``"(unknown: %i)"`` fallback (newer compilers), or a name and *no dictionary entry at all* (older
compilers simply omit a value that has no name).  A constant string, or an int handed to
``+[NSNumber numberWithInt:]``, never varies that way.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

from proto.arm64_eval import Flow as _EvalFlow
from proto.arm64_eval import _Abort, _ENTRY, _LOADS, _MAX_GATE_SPAN, _norm_reg, mem_regs, split_ops

log = logging.getLogger(__name__)

# The CFString the compiler-inlined converter falls back to for a value with no name.
UNKNOWN_ENUM_FORMAT = "(unknown: %i)"


class Flow(_EvalFlow):
    """:class:`proto.arm64_eval.Flow` plus the enum recovery: the field roots a function
    loads (:meth:`value_loads`) and the value -> name map each one is run through."""

    def value_loads(self) -> List[Tuple[int, int]]:
        """``[(insn index, ivar offset)]`` for every load whose address derives from an
        ivar-offset slot (the field-value loads, and the container derefs/counts behind them)."""
        out = []
        for k, ins in enumerate(self.insns):
            if ins.mnemonic not in _LOADS or k not in self._block_of:
                continue
            ops = split_ops(ins.op_str)
            if len(ops) != 2:
                continue
            m = mem_regs(ops[1])
            if not m or m[0] is None:
                continue
            offs = {o for o in (self.ivar_of_reg(k, m[0]),
                                self.ivar_of_reg(k, m[1]) if m[1] else None) if o is not None}
            if len(offs) == 1:
                out.append((k, next(iter(offs))))
        return out

    def analyse_root(self, k: int, dest: str, size: int, stop: FrozenSet[int],
                     direct: bool = False) -> "RootResult":
        """Drive the integer loaded into *dest* by ``insns[k]`` (``k == -1``: the function's
        entry, the value arriving in *dest*) through the code with every candidate value and one
        value outside all of them, and read what each run hands to its first call.

        The NAME register is one whose string takes at least two different values across the
        runs (two names, or a name and the converter's ``"(unknown: %i)"`` fallback): the
        dictionary key, selectors and class pointers are the same for every value.  No such
        register means no enum -- a constant string, or an int handed to
        ``+[NSNumber numberWithInt:]``, never varies.  *size* is the load width in bytes (the
        value's domain); *stop* holds the other fields' value loads, where a run has left this
        field's code."""
        domain = (0, 1 << (8 * size)) if size < 4 else (-(1 << 31), 1 << 31)   # int32 is signed
        scan = self.candidates(k, dest, domain)
        cands = scan.values
        problems: List[str] = []
        if scan.gate_capped:
            problems.append(f"a table gate is wider than {_MAX_GATE_SPAN} values")
        probe = next((v for v in range(max(cands) + 1, domain[1]) if v not in cands), None)
        if probe is None:
            problems.append("no value outside the candidates to probe")
            values = sorted(cands)
        else:
            values = sorted(cands | {probe})
        seen: Dict[int, Dict[str, str]] = {}
        stops: Dict[int, int] = {}
        for v in values:
            where: List[int] = []
            try:
                seen[v] = self.evaluate(k, dest, v, stop, direct, where)
            except _Abort as exc:
                problems.append(f"value {v}: {exc}")
            if where and v in seen:
                stops[v] = where[0]
        best: Dict[int, str] = {}
        best_reg: Optional[str] = None
        for reg in sorted({r for obs in seen.values() for r in obs}):   # sorted: ties must not depend on hash order
            # A converter (k == _ENTRY: the value arrives as its argument) has no constant
            # string argument of its own: a run either returns the name (x0 at the tail call)
            # or stops at the formatter with the "(unknown: %i)" format in another register.
            # So a register holding a string in some runs and none in others varies with the
            # value too -- the only variation a converter with ONE named value shows
            # (`cbz w2, name ; <format>`).  Not so in a _dictionaryRepresentation:, whose key
            # register is loaded for the named runs only.
            texts = {obs.get(reg) for obs in seen.values()} if k == _ENTRY \
                else {obs[reg] for obs in seen.values() if reg in obs}
            if len(texts) < 2:
                continue                              # same string for every value
            names = {v: obs[reg] for v, obs in seen.items()
                     if v in cands and reg in obs and _is_enum_name(obs[reg])}
            if len(set(names.values())) > len(set(best.values())):
                best, best_reg = names, reg
        return RootResult(best, problems, len(cands), best_reg,
                          {v: stops[v] for v in best if v in stops})

    def enum_of_load(self, k: int, stop: FrozenSet[int] = frozenset()) -> Optional["RootResult"]:
        """:meth:`analyse_root` for the integer loaded by ``insns[k]`` -- a struct member's
        value, whose root is given rather than found through an ivar slot.  ``None`` when
        ``insns[k]`` does not load an integer of at most 4 bytes."""
        ins = self.insns[k]
        ops = split_ops(ins.op_str)
        if ins.mnemonic not in _LOADS or len(ops) != 2:
            return None
        dest = _norm_reg(ops[0])
        size = _LOADS[ins.mnemonic] or (4 if ops[0].startswith('w') else 8)
        if dest is None or size == 8:
            return None
        return self.analyse_root(k, dest, size, stop)

    def enum_maps(self, valid_offsets: Set[int], wanted: Optional[Set[int]] = None
                  ) -> Dict[int, List[Tuple[int, str]]]:
        """``{ivar offset: [(value, name), ...]}`` for every field of the function that is an
        enum (see :meth:`analyse_root` for the decision).  *wanted* only limits the work to
        those ivars; it never changes a result."""
        out: Dict[int, Dict[int, str]] = {}
        # What the evaluation could NOT settle, by ivar offset -- reported, never silent:
        #   incomplete:  a field that WAS recovered as an enum but some value could not be
        #                evaluated (or a table gate was too wide to enumerate): values may be
        #                missing from it
        #   unevaluated: an enum-like switch (two or more compare constants / table indices)
        #                that yielded nothing: the field may be an enum that stays untyped
        self.incomplete: Dict[int, str] = {}
        self.unevaluated: Dict[int, str] = {}
        roots = self.value_loads()
        every_root = frozenset(k for k, _ in roots)
        for k, off in roots:
            if off not in valid_offsets or (wanted is not None and off not in wanted):
                continue
            ins = self.insns[k]
            ops = split_ops(ins.op_str)
            dest = _norm_reg(ops[0])
            size = _LOADS[ins.mnemonic] or (4 if ops[0].startswith('w') else 8)
            if size == 8 or dest is None:
                continue                                  # a pointer load, not an enum value
            res = self.analyse_root(k, dest, size, every_root - {k})
            if res.pairs:
                tgt = out.setdefault(off, {})
                for v, nm in res.pairs.items():
                    tgt.setdefault(v, nm)
                if res.problems:
                    self.incomplete.setdefault(off, "; ".join(res.problems[:3]))
            elif res.problems and res.n_candidates >= 3:
                self.unevaluated.setdefault(off, "; ".join(res.problems[:3]))
        for off in out:
            self.unevaluated.pop(off, None)
        return {off: sorted(m.items()) for off, m in out.items()}


@dataclass
class RootResult:
    """What :meth:`Flow.analyse_root` found for one integer value."""
    pairs: Dict[int, str]          # value -> name; empty: not an enum (or not evaluable)
    problems: List[str]            # values/gates the evaluation could not settle
    n_candidates: int              # how many distinct values the code compares / indexes with
    name_reg: Optional[str] = None  # the argument register that carries the name
    stops: Dict[int, int] = field(default_factory=dict)   # value -> index of the call its run reached


def _is_enum_name(text: str) -> bool:
    """A recovered string is a value name if it is an identifier (and not the fallback)."""
    from proto.enums import _is_valid_enum_string
    return text != UNKNOWN_ENUM_FORMAT and _is_valid_enum_string(text)
