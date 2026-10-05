"""Pure-Python protobuf decoding — the core of ios_decoder, no ``protoc`` at runtime.

Output is rendered to match ``protoc`` (the reference the tool replaces):

* **known fields** are rendered by ``text_format`` (per-field, via ``PrintField``) — names,
  enum labels, typed values, exactly as before;
* **unknown fields** (present on the wire but absent from the descriptor — the common
  partial-schema case) are rendered by :mod:`ios_decoder.rawproto` to match
  ``protoc --decode_raw`` exactly: ``0x``-hex for fixed64/32, protoc's "parse-fully-or-
  string" rule and C-escaping for length-delimited fields;
* **no schema at all** goes straight through :func:`rawproto.decode_raw` — the full
  ``protoc --decode_raw`` equivalent.

So the three cases (full / partial / no schema) all produce protoc-faithful text, and the
by-number unknown fields are the transparency signal that the schema didn't cover them
(:func:`unknown_field_numbers` lets callers state it explicitly).
"""

from __future__ import annotations

import io as _io

from google.protobuf import descriptor_pb2, descriptor_pool, message_factory
from google.protobuf import text_format
from google.protobuf.descriptor import FieldDescriptor
from google.protobuf.message import DecodeError, Message
from google.protobuf.unknown_fields import UnknownFieldSet

from . import rawproto

__all__ = [
    "DecodeError",
    "parse",
    "to_text",
    "decode_to_text",
    "render_message",
    "unknown_field_numbers",
]


def _build_empty_message_class() -> type[Message]:
    """A message type with zero fields, in its own private pool (schema-free parsing)."""
    fdp = descriptor_pb2.FileDescriptorProto()
    fdp.name = "ios_decoder/_raw.proto"
    fdp.syntax = "proto2"
    fdp.message_type.add().name = "Raw"
    pool = descriptor_pool.DescriptorPool()
    pool.Add(fdp)
    return message_factory.GetMessageClass(pool.FindMessageTypeByName("Raw"))


_RAW_MESSAGE_CLASS = _build_empty_message_class()


def parse(data: bytes, message_cls: type[Message] | None = None) -> Message:
    """Parse ``data`` into ``message_cls`` (or the schema-free raw message).

    Raises :class:`DecodeError` if ``data`` is not valid protobuf wire bytes.
    """
    if message_cls is None:
        message_cls = _RAW_MESSAGE_CLASS
    msg = message_cls()
    msg.ParseFromString(data)
    return msg


# --- rendering ---------------------------------------------------------------

def _is_map_field(field: FieldDescriptor) -> bool:
    return (field.type == FieldDescriptor.TYPE_MESSAGE
            and field.message_type.GetOptions().map_entry)


def _is_repeated(field: FieldDescriptor) -> bool:
    """Repeated-ness across protobuf backends (the upb C backend has no ``.label``)."""
    rep = getattr(field, "is_repeated", None)
    if rep is not None:
        return rep
    return field.label == FieldDescriptor.LABEL_REPEATED


def _render_unknown(ufs: UnknownFieldSet, level: int) -> str:
    """Render an UnknownFieldSet exactly like ``protoc --decode_raw``.

    The varint/fixed/length-delimited wire-type dispatch is the same one
    :func:`rawproto.render_fields` already implements, so each non-group field is normalised
    to a ``(number, wire_type, value)`` tuple and rendered through it — a single source of
    truth for the wire-type formatting.  Groups (wire-type 3, whose data is itself a nested
    UnknownFieldSet) have no tuple form and are recursed here.
    """
    out = []
    for f in ufs:
        wt = f.wire_type
        if wt == 3:        # start group: f.data is a nested UnknownFieldSet
            pad = "  " * level
            out.append(f"{pad}{f.field_number} {{")
            inner = _render_unknown(f.data, level + 1)
            if inner:
                out.append(inner)
            out.append(f"{pad}}}")
            continue
        val = f.data
        if wt == 1:        # fixed64 — UnknownField.data may be signed; render unsigned
            val &= 0xFFFFFFFFFFFFFFFF
        elif wt == 5:      # fixed32
            val &= 0xFFFFFFFF
        out.append(rawproto.render_fields([(f.field_number, wt, val)], level))
    return "\n".join(out)


def _print_scalar(field: FieldDescriptor, value, level: int) -> str:
    """Render one non-message field value exactly as ``protoc`` would.

    double/float fields are formatted via :mod:`rawproto` (protoc's DoubleToBuffer /
    FloatToBuffer ladder) since text_format renders them differently (``0.0`` vs ``0``,
    16- vs 17-digit precision).  Everything else goes through ``text_format.PrintField``
    with ``as_utf8=False`` so non-ASCII string/bytes octal-escape like protoc.
    """
    if field.cpp_type == FieldDescriptor.CPPTYPE_DOUBLE:
        return "  " * level + f"{field.name}: {rawproto.format_double(value)}"
    if field.cpp_type == FieldDescriptor.CPPTYPE_FLOAT:
        return "  " * level + f"{field.name}: {rawproto.format_float(value)}"
    buf = _io.StringIO()
    text_format.PrintField(field, value, buf, indent=2 * level, as_utf8=False)
    return buf.getvalue().rstrip("\n")


def _embedded_message(field: FieldDescriptor, value: bytes, embedded) -> Message | None:
    """The parsed message carried inside a ``bytes`` field, if ``embedded`` names its type.

    ``embedded`` is a callable ``field -> message class | None`` (or ``None`` for no
    embedding).  Some Apple protobufs carry another protobuf's serialised bytes in a ``bytes``
    field (geod's real-time traffic probe holds a CoreLocationProtobuf
    ``LocationCollectionRequest`` in ``locationCollection``); naming that field's type lets the
    reader see the named fields instead of an octal-escaped byte string.  A value that does not
    parse as that message is left as bytes (``None`` here).
    """
    if embedded is None or field.type != FieldDescriptor.TYPE_BYTES:
        return None
    cls = embedded(field)
    if cls is None:
        return None
    try:
        return parse(value, cls)
    except DecodeError:
        return None


def render_message(msg: Message, level: int = 0, embedded=None) -> str:
    """Render a parsed message: known fields via text_format, unknown via rawproto.

    Field iteration mirrors ``text_format._Printer.PrintMessage`` exactly (maps via
    ``GetEntryClass``, repeated fields element-by-element), so repeated scalars/enums/
    bytes and maps format identically.  Message-typed values are recursed into *here*
    (rather than by text_format) so unknown fields nested inside *known* sub-messages
    are rendered protoc-style too.  Unknown fields are appended last, in wire order.
    """
    pad = "  " * level
    out = []
    for field, value in msg.ListFields():
        if _is_map_field(field):
            for key in sorted(value):
                entry = value.GetEntryClass()(key=key, value=value[key])
                out.append(f"{pad}{field.name} {{")
                inner = render_message(entry, level + 1, embedded)
                if inner:
                    out.append(inner)
                out.append(f"{pad}}}")
        elif field.type == FieldDescriptor.TYPE_MESSAGE:
            elems = value if _is_repeated(field) else [value]
            for e in elems:
                out.append(f"{pad}{field.name} {{")
                inner = render_message(e, level + 1, embedded)
                if inner:
                    out.append(inner)
                out.append(f"{pad}}}")
        else:
            for element in (value if _is_repeated(field) else [value]):
                inner_msg = _embedded_message(field, element, embedded)
                if inner_msg is None:
                    out.append(_print_scalar(field, element, level))
                    continue
                out.append(f"{pad}{field.name} {{")
                inner = render_message(inner_msg, level + 1, embedded)
                if inner:
                    out.append(inner)
                out.append(f"{pad}}}")
    ufs = UnknownFieldSet(msg)
    if len(ufs):
        out.append(_render_unknown(ufs, level))
    return "\n".join(out)


def to_text(msg: Message, embedded=None) -> str:
    """Render a parsed message to protoc-faithful text (known named, unknown by number)."""
    return render_message(msg, embedded=embedded)


def unknown_field_numbers(msg: Message) -> list[int]:
    """Sorted, de-duplicated TOP-LEVEL field numbers present on the wire but not in the
    descriptor.  Empty when the schema fully covered the top level.  (Unknowns nested inside
    known sub-messages are NOT here — see :func:`nested_unknown_field_count`.)"""
    return sorted({f.field_number for f in UnknownFieldSet(msg)})


def nested_unknown_field_count(msg: Message, embedded=None) -> int:
    """Count unknown (by-number) fields inside KNOWN sub-messages, recursively — the partial-
    schema unknowns that :func:`unknown_field_numbers` (top-level only) misses.  Mirrors
    :func:`render_message`'s recursion so the count matches what the rendered output shows."""
    total = 0
    for field, value in msg.ListFields():
        if _is_map_field(field):
            for key in value:
                entry = value.GetEntryClass()(key=key, value=value[key])
                total += len(UnknownFieldSet(entry)) + nested_unknown_field_count(entry, embedded)
        elif field.type == FieldDescriptor.TYPE_MESSAGE:
            for e in (value if _is_repeated(field) else [value]):
                total += len(UnknownFieldSet(e)) + nested_unknown_field_count(e, embedded)
        else:
            for element in (value if _is_repeated(field) else [value]):
                inner_msg = _embedded_message(field, element, embedded)
                if inner_msg is not None:      # embedded protobuf: its unknowns are rendered too
                    total += len(UnknownFieldSet(inner_msg)) + nested_unknown_field_count(inner_msg, embedded)
    return total


def decode_to_text(data: bytes, message_cls: type[Message] | None = None) -> str:
    """Decode ``data`` to protoc-faithful text.  ``message_cls=None`` => schema-free
    (``protoc --decode_raw`` equivalent).  Raises :class:`DecodeError` on invalid bytes."""
    if message_cls is None:
        try:
            return rawproto.decode_raw(data)
        except rawproto.RawDecodeError as e:
            raise DecodeError(str(e)) from e
    return render_message(parse(data, message_cls))
