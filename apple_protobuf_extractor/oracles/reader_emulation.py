"""The ObjC messages the extractor emits against concrete runs of each class's ``-readFrom:`` in an
emulator (Unicorn): where the class itself puts each field it reads.

For each emitted field a run hands ``-[Cls readFrom:]`` a stand-in ``PBDataReader`` holding a
message of that field alone (twice when it is repeated), encoded as the emitted type says: a
varint (zigzag for ``sint``), 4 or 8 fixed bytes, or a length-delimited string, bytes or empty
submessage.  The reader's ivars are where its imported offset variables
(``_OBJC_IVAR_$_PBDataReader._bytes`` ...) say; the ProtocolBuffer runtime's C functions do what
their names say -- ``PBReaderReadString`` / ``ReadData`` take a length-delimited value (a stand-in
object), ``PBReaderPlaceMark`` / ``RecallMark`` bound a submessage, ``PBReaderSkipValueWithTag``
skips a field the class does not read, ``PBRepeated<T>Add`` appends to a C array, another image's
``<Message>ReadFrom`` succeeds (its bytes are its mark's); ``objc_alloc`` / ``objc_alloc_init`` and
the class constructors (``alloc``, ``new``, ``array``, ...) make a stand-in instance of the class
handed, ``objc_storeStrong`` / ``objc_setProperty_*`` store, ``objc_msgSend`` to self runs the
class's own method and to a stand-in answers ``init`` / ``readFrom:`` / ``addObject:`` / ``copy``.

What must hold for each field: the class reads it (does not skip it), into the ivar the field is
named for; a scalar decodes to the value encoded (a field read as another integer encoding or
width lands as another value); a message field allocates the class the field's type names; a
repeated field is appended to, twice.

    python -m oracles.reader_emulation BINARY"""
import collections
import struct
import sys

from unicorn import UcError, UC_HOOK_CODE
from unicorn import arm64_const as A

from oracles.flow_emulation import BIND_BASE, BIND_STRIDE, RET_SENTINEL, Report, make_machine
from oracles.writer_emulation import (OBJ_BASE, OBJ_SIZE, OBJ_STRIDE, SELF, _D0, _X,
                                      _all_ivars, _ensure_regions, _field_name, _method)
from proto.callees import RETURNS_ARGUMENT

READER = 0x790000000
BUF = 0x7a0000000
_READER_IVARS = {"_bytes": 8, "_pos": 16, "_length": 24, "_error": 32}
_VARINT = {"int32", "int64", "uint32", "uint64", "bool", "sint32", "sint64"}
_FIXED32 = {"fixed32", "sfixed32", "float"}
_FIXED64 = {"fixed64", "sfixed64", "double"}
VALUE = 0x55
# class methods that make an instance ([NSMutableArray array] for a repeated field's array)
_CONSTRUCTORS = ("alloc", "new", "array", "arrayWithCapacity:", "dictionary",
                 "dictionaryWithCapacity:", "set")


def _varint(n):
    out = bytearray()
    n &= (1 << 64) - 1
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def _zigzag(n):
    return (n << 1) ^ (n >> 63)


def _is_enum(f):
    return (f.type_class or "").startswith("ENUM:")


def encode(f):
    """``(wire bytes of one value, the value an ivar should hold)`` for field *f* as emitted."""
    t, tag = f.type_name, f.number
    if t in _VARINT or _is_enum(f):
        v = 1 if t == "bool" else VALUE
        raw = _varint(_zigzag(v) if t.startswith("sint") else v)
        return _varint(tag << 3) + raw, v
    if t in _FIXED32:
        raw = struct.pack("<f", 1.5) if t == "float" else struct.pack("<I", VALUE)
        return _varint(tag << 3 | 5) + raw, struct.unpack("<I", raw)[0]
    if t in _FIXED64:
        raw = struct.pack("<d", 1.5) if t == "double" else struct.pack("<Q", VALUE)
        return _varint(tag << 3 | 1) + raw, struct.unpack("<Q", raw)[0]
    body = b"s" if t == "string" else b"\x01\x02" if t == "bytes" else b""
    return _varint(tag << 3 | 2) + _varint(len(body)) + body, None


class Run:
    """``-readFrom:`` of a stand-in ``self`` of *cls* on a reader holding *message*."""

    def __init__(self, machine, cl, cls, message, seed=0, budget=200_000):
        import random
        self.m, self.cl, self.cls, self.budget = machine, cl, cls, budget
        self.objects, self.appended, self.repeated = {}, [], []
        self.skipped, self.unanswered = [], collections.Counter()
        uc = self.uc = machine.reset(random.Random(seed))
        _ensure_regions(machine)
        _ensure_reader(machine)
        uc.mem_write(OBJ_BASE, bytes(OBJ_SIZE))
        image = bytearray(max(cls.instance_size, 8) + 0x100)
        struct.pack_into("<Q", image, 0, cls.vmaddr)
        uc.mem_write(SELF, bytes(image))
        self.before = bytes(image)
        uc.mem_write(BUF, message.ljust(0x100, b"\0"))
        self.layout = machine.reader_layout
        reader = bytearray(0x80)
        for field, v in (("_bytes", BUF), ("_pos", 0), ("_length", len(message))):
            struct.pack_into("<Q", reader, self.layout[field], v)
        uc.mem_write(READER, bytes(reader))
        for field, slot in machine.reader_ivar_slots.items():   # each offset variable we chose
            uc.mem_write(slot, struct.pack("<i", self.layout[field]))

    def obj(self, what):
        a = OBJ_BASE + (len(self.objects) + 1) * OBJ_STRIDE
        self.objects[a] = what
        return a

    def _get(self, field):
        return struct.unpack("<Q", bytes(self.uc.mem_read(READER + self.layout[field], 8)))[0]

    def _set(self, field, v):
        self.uc.mem_write(READER + self.layout[field], struct.pack("<Q", v))

    def _read_varint(self):
        pos, n, shift = self._get("_pos"), 0, 0
        while True:
            b = self.uc.mem_read(BUF + pos, 1)[0]
            pos += 1
            n |= (b & 0x7F) << shift
            shift += 7
            if not b & 0x80:
                break
        self._set("_pos", pos)
        return n

    def _call(self, uc, name):
        x = [uc.reg_read(r) for r in _X[:6]]
        result = 0
        if name in ("_PBReaderReadString", "_PBReaderReadData"):
            n = self._read_varint()
            self._set("_pos", self._get("_pos") + n)
            result = self.obj((name[9:], None))
        elif name == "_PBReaderPlaceMark":
            n = self._read_varint()
            uc.mem_write(x[1], struct.pack("<QQ", self._get("_length"), self._get("_pos")))
            self._set("_length", self._get("_pos") + n)
            result = 1
        elif name == "_PBReaderRecallMark":
            saved = struct.unpack("<Q", bytes(uc.mem_read(x[1], 8)))[0]
            self._set("_pos", self._get("_length"))
            self._set("_length", saved)
        elif name == "_PBReaderSkipValueWithTag":
            self.skipped.append((x[1], x[2]))
            wire = x[2] & 7
            if wire == 0:
                self._read_varint()
            elif wire in (1, 5):
                self._set("_pos", self._get("_pos") + (8 if wire == 1 else 4))
            elif wire == 2:
                n = self._read_varint()
                self._set("_pos", self._get("_pos") + n)
            result = 1
        elif name and name.startswith("_PBRepeated") and name.endswith("Add"):
            kind = name[len("_PBRepeated"):-len("Add")]
            v = uc.reg_read(_D0) if kind in ("Double", "Float") else x[1]
            self.repeated.append((x[0] - SELF, kind, v))
        elif name in ("_objc_alloc", "_objc_alloc_init", "_objc_opt_new"):
            result = self.obj(("instance", self._class_name(x[0])))
        elif name == "_objc_storeStrong":
            uc.mem_write(x[0], struct.pack("<Q", x[1]))
        elif name and name.startswith("_objc_setProperty"):
            uc.mem_write(x[0] + x[3], struct.pack("<Q", x[2]))
        elif name == "_objc_msgSend":
            self._send(uc, x)
            return
        elif name and name.endswith("ReadFrom"):  # another image's message reader: its bytes
            result = 1                              # are its mark's, which recall skips
        elif name in RETURNS_ARGUMENT or (name or "").startswith("_objc_release"):
            return
        elif (name or "").startswith(("_objc_retain_x", "_objc_retainAutorelease_x")):
            uc.reg_write(_X[0], uc.reg_read(_X[int(name.rsplit("_x", 1)[1])]))
            return
        else:
            self.unanswered[name] += 1
        uc.reg_write(_X[0], result)

    def _class_name(self, va):
        """The class at *va*: the image's own, another image's in the cache, or an import's
        (by the name of the import whose block it is)."""
        c = self.cl.by_vmaddr(va)
        if c is not None:
            return c.name
        if getattr(self.m.ctx, "is_cache_backed", False):
            from macho.classlist import class_name_at
            return class_name_at(self.m.ctx, va)
        name = self.m.callee_name(va)
        return name.replace("_OBJC_CLASS_$_", "") if name else None

    def _send(self, uc, x):
        recv = x[0]
        try:
            sel = self.m.ctx.read_cstring(x[1])
        except Exception:
            sel = None
        result = 0
        if recv == SELF:
            imp = _method(self.cl, self.cls, sel)
            if imp is not None:
                uc.reg_write(A.UC_ARM64_REG_PC, imp)
                return
            self.unanswered["-[self %s]" % sel] += 1
        elif recv in self.objects:
            if sel in ("init", "copy", "mutableCopy", "autorelease", "retain"):
                result = recv
            elif sel == "readFrom:":
                result = 1
            elif sel == "addObject:":
                self.appended.append((recv, x[2]))
            else:
                self.unanswered["-[obj %s]" % sel] += 1
        elif sel in _CONSTRUCTORS and self._class_name(recv):
            result = self.obj(("instance", self._class_name(recv)))
        else:
            self.unanswered["-[? %s]" % sel] += 1
        uc.reg_write(_X[0], result)

    def go(self):
        uc = self.uc
        hook = self.m.hook_calls(uc, self._call)
        uc.reg_write(_X[0], SELF)
        uc.reg_write(_X[2], READER)
        uc.reg_write(A.UC_ARM64_REG_X30, RET_SENTINEL)
        try:
            uc.emu_start(_method(self.cl, self.cls, "readFrom:"), RET_SENTINEL, count=self.budget)
            self.ended = "returned" if uc.reg_read(A.UC_ARM64_REG_PC) == RET_SENTINEL else "budget"
        except UcError as e:
            self.ended = "fault: %s" % e
        finally:
            if hook is not None:
                uc.hook_del(hook)
        self.after = bytes(uc.mem_read(SELF, len(self.before)))
        return self


def _ensure_reader(machine):
    """Where the stand-in reader's ivars are: in a binary, where the offsets we write into its
    imported ``_OBJC_IVAR_$_PBDataReader.*`` variables say; in a dyld cache, where
    ProtocolBuffer.framework's own variables say (each run reads them from the cache)."""
    if getattr(machine, "reader_ivar_slots", None) is not None:
        return
    machine.uc.mem_map(BUF, 0x10000)
    slots, layout = {}, dict(_READER_IVARS)
    if getattr(machine.ctx, "is_cache_backed", False):
        r = machine.ctx._cache_reader
        exports = r.image_exports(r.find_image_header("ProtocolBuffer"))
        for field in _READER_IVARS:
            va = exports.get("_OBJC_IVAR_$_PBDataReader." + field)
            if va is not None:
                layout[field] = struct.unpack("<i", r.read_raw(va, 4))[0]
    else:
        for i, name in enumerate(machine.ctx._imports):
            if name.startswith("_OBJC_IVAR_$_PBDataReader."):
                field = name.rsplit(".", 1)[1]
                if field in _READER_IVARS:
                    slots[field] = BIND_BASE + i * BIND_STRIDE
    machine.reader_ivar_slots, machine.reader_layout = slots, layout


def _has_bits(iv):
    enc = iv.type_enc
    return enc.startswith("{") and '"' in enc and all(
        t.startswith("b") for t in enc.split('"')[2::2] if t)


def landed(run, ivars):
    """``{ivar name: (bytes after, objects it holds)}`` of the ivars the run changed (has-bits
    aside)."""
    out = {}
    for iv in ivars:
        if _has_bits(iv):
            continue
        a, b = run.before[iv.offset:iv.offset + iv.size], run.after[iv.offset:iv.offset + iv.size]
        if a != b:
            out[iv.name] = b
    return out


def compare(ctx, st, cl, messages=None, report=None):
    from proto import extractor as E
    report = report or Report()
    machine = make_machine(ctx)
    msgs = messages if messages is not None else E.extract_all(ctx, st, cl)
    for msg in msgs:
        cls = cl.find(msg.class_name)
        if cls is None or _method(cl, cls, "readFrom:") is None:
            continue
        ivars = _all_ivars(cl, cls)
        by_name = {iv.name: iv for iv in ivars}
        report.stats["messages"] += 1
        for f in msg.fields:
            if f.map_key_type:
                report.stats["map fields not run"] += 1
                continue
            rep_label = str(getattr(f.label, "value", f.label)) == "repeated"
            if f.type_name == "bytes" and f.type_inference_note:
                report.stats["a flagged bytes filler not run (LIMITATIONS.md (2))"] += 1
                continue
            one, want = encode(f)
            run = Run(machine, cl, cls, one * (2 if rep_label else 1)).go()
            where = "%s #%d %s (%s)" % (msg.class_name, f.number, f.name, f.type_name)
            report.stats["fields run"] += 1
            report.stats["runs " + run.ended.split(":")[0]] += 1
            for n, c in run.unanswered.items():
                report.unanswered[n] += c
            if run.skipped:
                report.find("an emitted field the class skips", 0, where, key=where)
                continue
            changed = landed(run, ivars)
            ivar = "_" + f.name if "_" + f.name in by_name else f.name
            if ivar not in changed and not (rep_label and (run.repeated or run.appended)):
                report.find("a field read into another ivar (or none)", 0,
                            "%s: changed %s" % (where, sorted(changed)), key=where)
                continue
            iv = by_name.get(ivar)
            if want is not None and not rep_label and iv is not None:
                got = int.from_bytes(changed[ivar][:8], "little")
                if got != want & ((1 << (8 * min(iv.size, 8))) - 1):
                    report.find("a value the class decodes differently", 0,
                                "%s: encoded %#x, the ivar holds %#x" % (where, want, got),
                                key=where)
            if rep_label:
                n = len(run.repeated) or sum(1 for _a, _o in run.appended)
                if n != 2:
                    report.find("a repeated field not appended twice", 0, "%s: %d" % (where, n),
                                key=where)
                vals = [v for _o, _k, v in run.repeated]
                if want is not None and vals and any(v & 0xFFFFFFFF != want & 0xFFFFFFFF
                                                     for v in vals):
                    report.find("a value the class decodes differently", 0,
                                "%s: encoded %#x, appended %s" % (where, want, [hex(v) for v in vals]),
                                key=where)
            made = [w[1] for w in run.objects.values() if w[0] == "instance"]
            if f.type_class and not _is_enum(f) and f.type_name not in _VARINT | _FIXED32 | \
                    _FIXED64 | {"string", "bytes"}:
                report.stats["message fields"] += 1
                if f.type_class not in made:
                    report.find("a message field that allocates another class", 0,
                                "%s: type %s, allocated %s" % (where, f.type_class, made),
                                key=where)
    return report


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
