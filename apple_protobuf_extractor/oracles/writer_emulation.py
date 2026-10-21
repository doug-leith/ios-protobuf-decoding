"""The ObjC messages the extractor emits against concrete runs of each class's ``-writeTo:`` in an
emulator (Unicorn): what really reaches the ``PBDataWriter``.

A run calls ``-[Cls writeTo:]`` on a stand-in ``self`` built in memory -- every has-bit set, no
reader it was read lazily from and no unknown fields (``PBDataReader`` / ``PBUnknownFields`` ivars
nil), the other object ivars distinct stand-in objects, whose repeated C arrays (``{list, count,
size}``) hold two elements and whose scalars are small numbers. The ProtocolBuffer runtime's C
functions record what they are handed -- ``PBDataWriterWrite<T>Field(writer, value, tag)``, by
AAPCS64 the value in x1 (v0 for a float / double, the tag then in x1) and the tag in x2;
``PBDataWriterPlaceMark (writer, &mark, tag)`` opens a length-delimited field (a submessage, a
packed array) that ``PBDataWriterRecallMark`` closes; ``PBDataWriterWriteSubmessage(writer,
message, tag)`` writes a submessage whole. ``objc_msgSend`` to ``self`` runs the class's own method
(its superclasses' in the image); to a stand-in object it answers ``writeTo:`` (a submessage),
``count`` / ``objectAtIndex:`` / fast enumeration (two elements, themselves stand-ins) and
``enumerateKeysAndObjectsUsingBlock:`` (the block run for two entries). Any other call returns 0;
the ARC calls return their argument (``objc_retain_xN``: xN), a release nothing.

Which ivar a tag's value comes from: a stand-in object is its ivar's (an element, its array's);
a scalar's is found by a second run with that ivar alone changed -- the tags whose writes change
depend on it.

Each tag written must be a field of the emitted message: that number, a type the writer function
writes (``Int32`` an int32 or an enum, ``String`` a string, a submessage a message, ...), the name
of the ivar it comes from, and repeated when it is written more than once.

    python -m oracles.writer_emulation BINARY"""
import collections
import random
import struct
import sys

from unicorn import UcError, UC_HOOK_CODE
from unicorn import arm64_const as A

from oracles.flow_emulation import RET_SENTINEL, make_machine
from proto.callees import RETURNS_ARGUMENT

OBJ_BASE, OBJ_SIZE, OBJ_STRIDE = 0x700000000, 0x400000, 0x100   # the stand-in objects
SELF = 0x780000000
TRAMPOLINE = 0x7b0000000             # code that calls a block for each entry of a dictionary
LITERAL = TRAMPOLINE + 0x100
NO_TAG = 0xFFFFFFFF                  # a writer's field number -1: the value alone (a packed element)
WRITER = 0x790000000
_X = [getattr(A, f"UC_ARM64_REG_X{i}") for i in range(29)]
_D0 = A.UC_ARM64_REG_D0

# the writer function -> the proto types a field it writes may have (a message: any message)
_WRITES = {"Int32": {"int32"}, "Int64": {"int64"}, "Uint32": {"uint32"}, "Uint64": {"uint64"},
           "Sint32": {"sint32"}, "Sint64": {"sint64"}, "Fixed32": {"fixed32"},
           "Fixed64": {"fixed64"}, "Sfixed32": {"sfixed32"}, "Sfixed64": {"sfixed64"},
           "Float": {"float"}, "Double": {"double"}, "BOOL": {"bool"}, "String": {"string"},
           "Data": {"bytes"}}
_FLOATING = ("Float", "Double")
# a repeated C array's element, by its type encoding -> struct format
_ELEMENT = {"i": "i", "I": "I", "q": "q", "Q": "Q", "f": "f", "d": "d", "c": "b", "B": "B",
            "s": "h", "S": "H", "l": "i", "L": "I"}
_SCALARS = set().union(*_WRITES.values())


class Write(collections.namedtuple("Write", "tag kind value")):
    """One thing written: *kind* the writer function's type (``Int32`` ...), ``message`` (a
    stand-in's ``writeTo:`` inside a mark) or ``packed`` (bare varints inside a mark)."""


class Run:
    """One ``writeTo:`` run on a stand-in ``self`` of *cls* (its ivars *ivars*; *changed*, one
    of them, given other bytes).  Repeatable: the same seed, the same memory."""

    def __init__(self, machine, cl, cls, ivars, changed=None, seed=0, budget=200_000,
                 setting=None):
        self.m, self.cl, self.cls, self.budget = machine, cl, cls, budget
        self.writes, self.marks, self.unanswered = [], [], collections.Counter()
        self.objects = {}                       # stand-in address -> what it stands for
        self.enumerated = {}
        uc = self.uc = machine.reset(random.Random(seed))
        _ensure_regions(machine)
        uc.mem_write(OBJ_BASE, bytes(OBJ_SIZE))
        image = bytearray(max(cls.instance_size, 8))
        struct.pack_into("<Q", image, 0, cls.vmaddr)
        for iv, val in _values(self, ivars, changed):
            if setting is not None and iv is setting[0]:
                val = setting[1].to_bytes(len(val), "little")
            if iv.offset + len(val) <= len(image):
                image[iv.offset:iv.offset + len(val)] = val
        uc.mem_write(SELF, bytes(image) + bytes(0x100))

    def obj(self, what):
        """A stand-in object for *what* (``('ivar', name)``, ``('element', name, i)``)."""
        for a, w in self.objects.items():
            if w == what:
                return a
        a = OBJ_BASE + (len(self.objects) + 1) * OBJ_STRIDE
        self.objects[a] = what
        return a

    # ── the imports ──────────────────────────────────────────────────────────

    def _call(self, uc, name):
        x = [uc.reg_read(r) for r in _X[:6]]
        if name and name.startswith("_PBDataWriterWrite") and name.endswith("Field"):
            kind = name[len("_PBDataWriterWrite"):-len("Field")]
            if kind in _FLOATING:
                value = uc.reg_read(_D0) & (0xFFFFFFFF if kind == "Float" else (1 << 64) - 1)
                tag = x[1] & 0xFFFFFFFF
            else:
                value, tag = x[1], x[2] & 0xFFFFFFFF
            self._record(Write(tag, kind, value))
        elif name in ("_PBDataWriterWriteSubmessage", "_PBDataWriterWriteSubgroup"):
            self._record(Write(x[2] & 0xFFFFFFFF, "message", x[1]))
        elif name == "_PBDataWriterPlaceMark":
            self.marks.append((x[2] & 0xFFFFFFFF, []))
        elif name == "_PBDataWriterRecallMark":
            if self.marks:
                self._close(*self.marks.pop())
        elif name == "_PBDataWriterWriteBareVarint":
            self._record(Write(None, "varint", x[1]))
        elif name == "_objc_msgSend":
            self._send(uc, x)
            return
        elif name in RETURNS_ARGUMENT or (name or "").startswith("_objc_release"):
            return                              # x0 is kept (a release returns nothing)
        elif (name or "").startswith(("_objc_retain_x", "_objc_retainAutorelease_x")):
            reg = int(name.rsplit("_x", 1)[1])  # libobjc: retains xN and returns it in x0
            uc.reg_write(_X[0], uc.reg_read(_X[reg]))
            return
        else:
            self.unanswered[name] += 1
        uc.reg_write(_X[0], 0)

    def _record(self, w):
        (self.marks[-1][1] if self.marks else self.writes).append(w)

    def _close(self, tag, inner):
        """A length-delimited field written between a mark and its recall: a submessage by its
        own ``writeTo:``, a packed array (bare varints, or values each written with no tag), else a
        nested message written in place
        (an inline C struct, a map entry) -- *inner*, its own writes."""
        if any(w.kind == "writeTo:" for w in inner):
            for w in inner:
                if w.kind == "writeTo:":
                    self._record(Write(tag, "message", w.value))
        elif inner and all(w.kind == "varint" for w in inner):
            for w in inner:
                self._record(Write(tag, "packed", w.value))
        elif inner and all(w.tag == NO_TAG for w in inner):  # elements written bare, by type
            for w in inner:
                self._record(Write(tag, "packed", w.value))
                self._record(Write(tag, w.kind, w.value))
        else:
            self._record(Write(tag, "nested", tuple(inner)))

    def _send(self, uc, x):
        recv, sel_ptr = x[0], x[1]
        try:
            sel = self.m.ctx.read_cstring(sel_ptr)
        except Exception:
            sel = None
        if recv == SELF:
            imp = _method(self.cl, self.cls, sel)
            if imp is not None:
                uc.reg_write(A.UC_ARM64_REG_PC, imp)       # run it; it returns to the caller
                return
            self.unanswered["-[self %s]" % sel] += 1
            uc.reg_write(_X[0], 0)
            return
        what = self.objects.get(recv)
        if what is None:
            self.unanswered["-[? %s]" % sel] += 1
            uc.reg_write(_X[0], 0)
            return
        result = 0
        if sel == "writeTo:":
            self._record(Write(None, "writeTo:", recv))
        elif sel == "count":
            result = 2
        elif sel == "objectAtIndex:":
            result = self.obj(("element", what[1], x[2]))
        elif sel == "countByEnumeratingWithState:objects:count:":
            state, buf = x[2], x[3]
            done = self.enumerated.get((recv, state), False)
            if not done:
                elems = [self.obj(("element", what[1], i)) for i in range(2)]
                uc.mem_write(buf, struct.pack("<2Q", *elems))
                uc.mem_write(state, struct.pack("<QQQ", 1, buf, OBJ_BASE))   # state, items, mutations
                self.enumerated[(recv, state)] = True
                result = 2
        elif sel == "enumerateKeysAndObjectsUsingBlock:":
            self._enumerate(uc, recv, what, x[2])
            return
        elif sel in ("length", "isEqual:", "isEqualToString:"):
            result = 1
        elif sel and sel.endswith("Value") and sel[0].islower():   # NSNumber: intValue ...
            result = 2
            uc.reg_write(_D0, struct.unpack("<Q", struct.pack("<d", 2.0))[0])
        else:
            self.unanswered["-[obj %s]" % sel] += 1
        uc.reg_write(_X[0], result)

    def _enumerate(self, uc, recv, what, block):
        """``[dictionary enumerateKeysAndObjectsUsingBlock:block]`` over two entries (stand-ins):
        a trampoline calls the block's invoke (``block + 16``) with (block, key, value, &stop)
        for each, then returns to the send's caller."""
        lr = uc.reg_read(A.UC_ARM64_REG_X30)
        invoke = struct.unpack("<Q", bytes(uc.mem_read(block + 16, 8)))[0]
        data = TRAMPOLINE + 0x200
        stop = data + 0x60
        entries = [(self.obj(("key", what[1], i)), self.obj(("value", what[1], i))) for i in range(2)]
        blob = b"".join(struct.pack("<QQQQ", block, k, v, stop) for k, v in entries)
        uc.mem_write(data, blob + struct.pack("<QQQ", invoke, lr, 0))
        code = []
        for i in range(2):
            code += [_ldr_literal(9, TRAMPOLINE + 4 * len(code), LITERAL),
                     _ldp(0, 1, 9, 32 * i), _ldp(2, 3, 9, 32 * i + 16),
                     _ldr(16, 9, 64), 0xD63F0200]                       # blr x16
        code += [_ldr_literal(9, TRAMPOLINE + 4 * len(code), LITERAL), _ldr(30, 9, 72),
                 0xD65F03C0]                                              # ret
        uc.mem_write(TRAMPOLINE, struct.pack("<%dI" % len(code), *code))
        uc.mem_write(LITERAL, struct.pack("<Q", data))
        uc.reg_write(A.UC_ARM64_REG_PC, TRAMPOLINE)

    def go(self):
        uc = self.uc
        hook = self.m.hook_calls(uc, self._call)
        writeto = _method(self.cl, self.cls, "writeTo:")
        uc.reg_write(_X[0], SELF)
        uc.reg_write(_X[2], WRITER)
        uc.reg_write(A.UC_ARM64_REG_X30, RET_SENTINEL)
        try:
            uc.emu_start(writeto, RET_SENTINEL, count=self.budget)
            self.ended = "returned" if uc.reg_read(A.UC_ARM64_REG_PC) == RET_SENTINEL else "budget"
        except UcError as e:
            self.ended = "fault: %s" % e
        finally:
            if hook is not None:
                uc.hook_del(hook)
        return self


def _ensure_regions(machine):
    if getattr(machine, "_writer_regions", False):
        return
    uc = machine.uc
    for base, size in ((OBJ_BASE, OBJ_SIZE), (SELF, 0x100000), (WRITER, 0x1000),
                       (TRAMPOLINE, 0x1000)):
        uc.mem_map(base, size)
    # (each import's block starts with a ret: a call into it returns once the hook has answered)
    machine._writer_regions = True


def _ldr_literal(rt, pc, target):
    """``ldr x<rt>, <target>`` (PC-relative literal) at *pc*."""
    return 0x58000000 | (((target - pc) // 4) & 0x7FFFF) << 5 | rt


def _ldp(rt, rt2, rn, off):
    """``ldp x<rt>, x<rt2>, [x<rn>, #off]``."""
    return 0xA9400000 | ((off // 8) & 0x7F) << 15 | rt2 << 10 | rn << 5 | rt


def _ldr(rt, rn, off):
    """``ldr x<rt>, [x<rn>, #off]``."""
    return 0xF9400000 | (off // 8) << 10 | rn << 5 | rt


def _method(cl, cls, sel):
    """The IMP of instance method *sel* of *cls* or the nearest superclass in the image."""
    c = cls
    while c is not None:
        for m in c.methods:
            if m.name == sel:
                return m.imp
        c = cl.find(c.superclass_name) if c.superclass_name else None
        if c is not None and c.is_meta:
            c = None
    return None


def _all_ivars(cl, cls):
    out, c = [], cls
    while c is not None:
        out = list(c.ivars) + out
        c = cl.find(c.superclass_name) if c.superclass_name else None
    return out


def _values(run_obj, ivars, changed=None):
    """Each ivar's bytes: has-bit structs all set, objects stand-ins, repeated C arrays two
    elements, scalars small numbers; *changed* (an ivar) gets other bytes."""
    vals = []
    for i, iv in enumerate(ivars):
        enc, size, bump = iv.type_enc, max(iv.size, 1), iv is changed
        if enc in _NOT_BUILT:                              # a message built in memory has none
            vals.append((iv, bytes(8)))
        elif enc.startswith("@"):
            vals.append((iv, struct.pack("<Q", run_obj.obj(("ivar", iv.name, bump)))))
        elif enc.startswith("{") and "b" in enc.split("=", 1)[-1] and '"' in enc and \
                all(t.startswith("b") for t in enc.split('"')[2::2] if t):
            vals.append((iv, b"\xff" * size))                    # has-bits: every field present
        elif enc.startswith("{") and "^" in enc:          # {list, count, size}
            buf = OBJ_BASE + OBJ_SIZE - (i + 1) * 0x40
            elem = enc[enc.index("^") + 1]
            fmt = _ELEMENT.get(elem, "q")
            elems = [i + 2 + 0x10 * bump, i + 3 + 0x10 * bump]
            run_obj.uc.mem_write(buf, struct.pack("<2" + fmt, *elems).ljust(0x40, b"\0"))
            vals.append((iv, struct.pack("<QQQ", buf, 2, 2)[:size]))
        elif enc in ("d",):
            vals.append((iv, struct.pack("<d", 1.5 + i + (100.0 if bump else 0))))
        elif enc in ("f",):
            vals.append((iv, struct.pack("<f", 1.5 + i + (100.0 if bump else 0))))
        elif enc in ("c", "B", "C"):
            vals.append((iv, bytes([0 if bump else 1])))
        else:
            n = (i + 2 + (0x55 if bump else 0)) & ((1 << (8 * min(size, 8))) - 1)
            vals.append((iv, n.to_bytes(min(size, 8), "little") + bytes(max(size - 8, 0))))
    return vals


def observe(machine, cl, cls, seed=0):
    """``(tags, runs)``: each tag written -> (kinds, count in the base run, ivars it depends on)."""
    ivars = _all_ivars(cl, cls)

    def one(changed=None):
        return Run(machine, cl, cls, ivars, changed, seed).go()

    base = one()
    tags = {}
    for w in base.writes:
        kinds, n, deps = tags.get(w.tag, (set(), 0, set()))
        kinds.add(w.kind)
        if w.kind == "message" or (isinstance(w.value, int) and w.value in base.objects):
            what = base.objects.get(w.value)
            if what:
                deps.add(what[1])
        tags[w.tag] = (kinds, n + 1, deps)
    by_tag = lambda run: collections.Counter((w.tag, w.kind, w.value) for w in run.writes)
    base_writes = by_tag(base)
    for iv in ivars:
        if iv.type_enc.startswith("@"):
            continue                           # an object is its stand-in's (above)
        run = one(iv)
        other = by_tag(run)
        for w in run.writes:                   # a case the change selected (a oneof's): written
            if w.tag not in tags:
                tags[w.tag] = ({w.kind}, sum(1 for x in run.writes if x.tag == w.tag), set())
                base.writes.extend(x for x in run.writes if x.tag == w.tag and x.kind == "nested")
        changed = {t for (t, _k, _v) in (base_writes - other) + (other - base_writes)}
        for t in changed:
            if t in tags:
                tags[t][2].add(iv.name)
    return tags, base


_INTEGERS = set("cCsSiIlLqQ")
# what a message read lazily from data keeps (its reader, the fields it did not know): nil in a
# message built in memory, whose writeTo: then writes its fields rather than copying its bytes
_NOT_BUILT = ('@"PBDataReader"', '@"PBUnknownFields"')


def cover(machine, cl, cls, tags, wanted, seed=0):
    """More runs for the fields *wanted* that no run wrote yet -- a oneof's other cases, a field
    written for some values only: each integer ivar in turn set to 0..32 (the rest as before),
    until every one is written.  What a run writes is added to *tags* (without the ivar it
    comes from: only its number, type and label are checked)."""
    ivars = _all_ivars(cl, cls)
    for iv in ivars:
        if not wanted - set(tags):
            return
        if iv.type_enc not in _INTEGERS:
            continue
        for v in range(33):
            run = Run(machine, cl, cls, ivars, seed=seed, setting=(iv, v)).go()
            for w in run.writes:
                if w.tag in wanted and w.tag not in tags:
                    tags[w.tag] = ({x.kind for x in run.writes if x.tag == w.tag},
                                   sum(1 for x in run.writes if x.tag == w.tag), set())
            if not wanted - set(tags):
                return


def _field_name(ivar):
    return ivar[1:] if ivar.startswith("_") else ivar


def compare(ctx, st, cl, messages=None, report=None, known=None):
    """Findings for every emitted ObjC message (of *messages*, default all) whose class has a
    ``writeTo:`` in the image; *known*, the messages a nested field may name (default the same)."""
    from oracles.flow_emulation import Report
    from proto import extractor as E
    report = report or Report()
    machine = make_machine(ctx)
    msgs = messages if messages is not None else E.extract_all(ctx, st, cl)
    by_name = {k: m for m in (known or msgs) for k in (m.class_name, m.name)}
    for msg in msgs:
        cls = cl.find(msg.class_name)
        if cls is None or _method(cl, cls, "writeTo:") is None:
            continue
        report.stats["messages"] += 1
        report.stats["map fields emitted"] += sum(1 for f in msg.fields if f.map_key_type)
        report.stats["inline struct messages emitted"] += bool(msg.inline_struct)
        try:
            tags, base = observe(machine, cl, cls)
            cover(machine, cl, cls, tags, {f.number for f in msg.fields} - set(tags))
        except Exception as e:
            report.stats["not run: %s" % type(e).__name__] += 1
            continue
        report.stats["runs " + base.ended.split(":")[0]] += 1
        for name, n in base.unanswered.items():
            report.unanswered[name] += n
        # a subclass the extractor emits as serialised by its superclass's message: those fields
        owner = by_name.get(msg.serialised_by) if msg.serialised_by and not msg.fields else None
        fields = {f.number: f for f in (owner or msg).fields}
        for tag, (kinds, count, deps) in sorted(tags.items(), key=lambda t: (t[0] is None, t[0] or 0)):
            report.stats["tags written"] += 1
            f = fields.get(tag)
            where = "%s #%s" % (msg.class_name, tag)
            if f is None:
                report.find("a written tag the message lacks", 0, "%s (%s)" % (where, sorted(kinds)),
                            key=where)
                continue
            if "nested" in kinds:
                _check_nested(report, where, f, nested_writes(base, tag), by_name)
            if kinds == {"message"} and f.type_name == "bytes" and f.type_inference_note:
                report.stats["a submessage emitted as flagged bytes (LIMITATIONS.md (2))"] += 1
            elif not _type_agrees(f, kinds):
                report.find("a type the writer does not write", 0,
                            "%s %s: %s, written by %s" % (where, f.name, _type_of(f), sorted(kinds)),
                            key=where)
            if len(deps) == 1:
                (iv,) = deps
                if f.name != _field_name(iv):
                    report.find("a name other than its ivar's", 0,
                                "%s: %s, written from %s" % (where, f.name, iv), key=where)
            elif not deps:
                report.stats["tags from no ivar"] += 1
            repeated = f.label.value == "repeated" if hasattr(f.label, "value") else \
                str(f.label) == "repeated"
            if count > 1 and not repeated and not f.map_key_type and "packed" not in kinds:
                report.find("written twice, not repeated", 0, "%s %s" % (where, f.name), key=where)
        for num, f in fields.items():
            if num not in tags:
                report.stats["fields not written in the run"] += 1
    return report


def nested_writes(run, tag):
    """The inner writes of each nested write of *tag* in *run*."""
    return [w.value for w in run.writes if w.tag == tag and w.kind == "nested"]


def _check_nested(report, where, f, entries, by_name):
    """A field written in place inside a mark: a map's entries are its key (1) and value (2), of
    its key and value types; a nested message's (an inline C struct's) writes are its fields."""
    report.stats["nested fields"] += 1
    if f.map_key_type:
        fields = {1: SimpleField(f.map_key_type, None), 2: SimpleField(f.map_value_type or "",
                                                                       f.map_value_class)}
    else:
        nested = by_name.get(f.type_name.rsplit(".", 1)[-1]) or by_name.get(f.type_name)
        if nested is None:
            report.find("a field written in place whose message is not emitted", 0,
                        "%s %s: %s" % (where, f.name, f.type_name), key=where)
            return
        fields = {g.number: g for g in nested.fields}
    for inner in entries:
        for w in inner:
            report.stats["nested writes"] += 1
            g = fields.get(w.tag)
            if g is None:
                report.find("a tag written in place that its message lacks", 0,
                            "%s %s: inner #%s (%s)" % (where, f.name, w.tag, w.kind),
                            key=(where, w.tag))
            elif not _type_agrees(g, {w.kind}):
                report.find("a type written in place that its field does not have", 0,
                            "%s %s: inner #%s %s, written by %s" % (where, f.name, w.tag,
                                                                  g.type_name, w.kind),
                            key=(where, w.tag))


class SimpleField(collections.namedtuple("SimpleField", "type_name type_class")):
    """A map entry's key or value, as a field for :func:`_type_agrees`."""


def _type_of(f):
    return f.type_name


def _type_agrees(f, kinds):
    t = f.type_name
    for k in kinds:
        if k == "message":
            if t in _SCALARS:
                return False
        elif k == "packed":                     # any numeric scalar (its writer says which)
            if t in ("string", "bytes") or (t not in _SCALARS and
                                            not (f.type_class or "").startswith("ENUM:")):
                return False
        elif k in _WRITES:
            if t in _WRITES[k]:
                continue
            if k == "Int32" and (f.type_class or "").startswith("ENUM:"):
                continue
            return False
    return True


def main(argv):
    from macho.memory import BinaryContext
    from serializers.swift_descriptor_extract import load_macho_slice
    from macho.load import load_classes
    with open(argv[0], "rb") as fh:
        img = load_classes(BinaryContext(load_macho_slice(fh.read())))
    rep = compare(img.ctx, img.st, img.cl)
    print(dict(rep.stats))
    print("unanswered", rep.unanswered.most_common(15))
    for kind, rows in rep.findings.items():
        print("==", kind, rep.stats[kind])
        for row in rows[:15]:
            print("   ", row[1])


if __name__ == "__main__":
    main(sys.argv[1:])
