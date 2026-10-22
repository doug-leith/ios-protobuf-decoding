"""proto/eval_tokens.py -- the opaque values the evaluator's users run code with.

``self``, a reader / writer argument, a call's result and ``self->ivar`` stand for objects the
analysis cannot see into: :class:`proto.arm64_eval._Machine` carries them through register
copies and treats every other use as unknown.  Shared by the readFrom: dispatch evaluator
(:mod:`proto.dispatch_eval`), the readFrom: core finder (:mod:`proto.dispatch`), the enum
wrapper reader (:mod:`proto.enums`) and the struct writer decoder (:mod:`proto.structfields`).
"""
from __future__ import annotations

from typing import Optional

from proto.arm64_eval import Objects, Sym
from proto.callees import callee_name, RETURNS_ARGUMENT

# objects (proto.arm64_eval.Sym, kind "token"): no constant is taken for one
SELF = Sym("token", "self")
READER = Sym("token", "reader")


def opaque(v) -> bool:
    """SELF, READER, call results and self's ivar values are objects, not numbers."""
    return isinstance(v, Sym) and v.kind == "token"


def field_value(obj, off: int) -> Optional[Sym]:
    """``self->ivar`` at byte offset *off* (the array a reader appends to with addObject:)."""
    return Sym("token", ("field", off)) if obj == SELF and 0 <= off < (1 << 24) else None


def field_offset(v) -> Optional[int]:
    """The byte offset of the ``self->ivar`` value *v* is (:func:`field_value`), else None."""
    return v.ident[1] if opaque(v) and isinstance(v.ident, tuple) and v.ident[0] == "field" \
        else None


def ret_value(k: int) -> Sym:
    """The result of the call at instruction index *k*."""
    return Sym("token", ("ret", k))


def call_result(ctx):
    """``call_result`` for :meth:`proto.arm64_eval.Flow.run_from` / ``propagate``: a call to a
    runtime function that returns its argument keeps x0; any other call's result is a fresh
    token."""
    def result(k: int, target: Optional[int], x0: Optional[int]) -> Optional[int]:
        if x0 is not None and opaque(x0) and callee_name(ctx, target) in RETURNS_ARGUMENT:
            return x0
        return ret_value(k)
    return result


#: Runs that only need to tell the tokens from numbers.
OPAQUE = Objects(opaque=opaque)


def object_model(ctx) -> Objects:
    """The full object model of the readFrom: dispatch evaluator: tokens, ``self->ivar``
    values, call results, and the object-escape stack rule."""
    return Objects(opaque=opaque, field_value=field_value, call_result=call_result(ctx),
                   object_escape=True)
