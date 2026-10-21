"""The Swift type recovery's stored fields and field types (``collect_field_types``), and the types
of the fields the Swift serializer emits (``swift_messages``, each paired with its property by
name, compared as the Swift type tells it: ``fixed64`` is a ``UInt64``), against Apple's
Swift Remote Mirror -- ``libswiftRemoteMirror``, the reflection library behind lldb and
``swift-inspect`` -- served from a dyld cache, for every message the Swift serializer emits.
Field numbers are not in the layout: they are checked by decoding real traffic (ios_decoder).

The library comes from a swift.org toolchain (6.2: ``swift-6.2-RELEASE-osx.pkg``, at
``usr/lib/swift/macosx/libswiftRemoteMirror.dylib`` in its payload; Xcode no longer ships it):
``MACHO_REMOTE_MIRROR``, else the repository's default (:func:`artifacts.remote_mirror_lib`). It
reads the target's memory through callbacks; here they read the cache, with its slide info's
pointer chains applied (:mod:`oracles.cache_memory`).

For each message: the image and every image it links are in one reflection context; a
copy-on-write message's fields are its ``_StorageClass``'s (a private class, whose mangled name
carries a discriminator, so they are asked of a stand-in instance whose isa is the class
metadata); a oneof (a property of an optional enum whose cases carry payloads: ``OneOf_X`` in the
message, or a type of its own) contributes its property and its cases.  Not compared: a message with a
one-case oneof -- a one-case enum is laid out as its payload, and Remote Mirror gives the
payload's fields, not the case.

    python -m oracles.swift_mirror CACHE IMAGE..."""
import bisect
import collections
import ctypes as C
import re
import struct
import sys

import artifacts
import serializers.swift_descriptor_extract as SW
from oracles.cache_memory import SlideInfo
import serializers.swift_type_recovery as TR
from macho.dyld_cache import DyldCacheReader
from macho.load import load_cache_image

# ── the library ──────────────────────────────────────────────────────────────

_READ = C.CFUNCTYPE(C.c_void_p, C.c_void_p, C.c_uint64, C.c_uint64, C.POINTER(C.c_void_p))
_FREE = C.CFUNCTYPE(None, C.c_void_p, C.c_void_p, C.c_void_p)
_STRLEN = C.CFUNCTYPE(C.c_uint64, C.c_void_p, C.c_uint64)
_SYMADDR = C.CFUNCTYPE(C.c_uint64, C.c_void_p, C.c_char_p, C.c_uint64)
_LAYOUT = C.CFUNCTYPE(C.c_int, C.c_void_p, C.c_int, C.c_void_p, C.c_void_p)

STRUCT_LAYOUT = 4                  # swift_layout_kind_t SWIFT_STRUCT


class _TypeInfo(C.Structure):
    _fields_ = [("Kind", C.c_int), ("Size", C.c_uint), ("Alignment", C.c_uint),
                ("Stride", C.c_uint), ("NumFields", C.c_uint)]


class _ChildInfo(C.Structure):
    _fields_ = [("Name", C.c_char_p), ("Offset", C.c_uint), ("Kind", C.c_int), ("TR", C.c_uint64)]


_RM = None


def library():
    """The loaded ``libswiftRemoteMirror`` (its signatures declared), or None when absent."""
    global _RM
    if _RM is None:
        import os
        path = artifacts.remote_mirror_lib()
        if not os.path.isfile(path):
            return None
        rm = C.CDLL(path)
        for fn, res, args in (
                ("swift_reflection_createReflectionContextWithDataLayout", C.c_void_p,
                 [C.c_void_p, _LAYOUT, _FREE, _READ, _STRLEN, _SYMADDR]),
                ("swift_reflection_addImage", C.c_int, [C.c_void_p, C.c_uint64]),
                ("swift_reflection_typeRefForMangledTypeName", C.c_uint64,
                 [C.c_void_p, C.c_char_p, C.c_uint64]),
                ("swift_reflection_infoForTypeRef", _TypeInfo, [C.c_void_p, C.c_uint64]),
                ("swift_reflection_childOfTypeRef", _ChildInfo, [C.c_void_p, C.c_uint64, C.c_uint]),
                ("swift_reflection_infoForInstance", _TypeInfo, [C.c_void_p, C.c_uint64]),
                ("swift_reflection_childOfInstance", _ChildInfo, [C.c_void_p, C.c_uint64, C.c_uint]),
                ("swift_reflection_copyNameForTypeRef", C.c_void_p,
                 [C.c_void_p, C.c_uint64, C.c_bool])):
            getattr(rm, fn).restype, getattr(rm, fn).argtypes = res, args
        _RM = rm
    return _RM


# ── the cache as Remote Mirror's memory ──────────────────────────────────────

FAKE_OBJECT = 0x7ff000000000       # no cache mapping lies here: a stand-in instance's address


class CacheMirror:
    """One reflection context over a dyld cache; images are added with :meth:`add`."""

    def __init__(self, cache_path):
        self.rm = rm = library()
        self.reader = reader = DyldCacheReader(cache_path)
        self.added = set()
        self.fake_isa = 0
        slide = SlideInfo(reader)
        keep = {}

        def read(_c, addr, size, out_free):
            if addr == FAKE_OBJECT:
                raw = struct.pack("<Q", self.fake_isa)[:size].ljust(size, b"\0")
            else:
                raw = reader.read_raw(addr, size)
                if raw is None or len(raw) < size:
                    return None
                raw = slide.apply(addr, raw)
            b = C.create_string_buffer(raw, size)
            p = C.addressof(b)
            keep[p] = b
            out_free[0] = C.c_void_p(p)
            return p

        def free(_c, _bytes, ctxp):
            keep.pop(ctxp, None)

        def strlen(_c, addr):
            s = reader.read_cstring(addr, None)
            return len(s.encode()) if s is not None else 0

        def symaddr(_c, _name, _n):
            return 0

        def layout(_c, query, _inbuf, outbuf):
            if query in (0, 1):                # pointer size, size_t size
                C.cast(outbuf, C.POINTER(C.c_uint8))[0] = 8
            elif query == 2:                   # pointer-authentication mask
                C.cast(outbuf, C.POINTER(C.c_uint64))[0] = 0x0000000FFFFFFFFF
            elif query == 3:                   # ObjC reserved low bits
                C.cast(outbuf, C.POINTER(C.c_uint8))[0] = 0
            elif query == 4:                   # least valid pointer
                C.cast(outbuf, C.POINTER(C.c_uint64))[0] = 0x100000000
            elif query == 5:                   # ObjC interop
                C.cast(outbuf, C.POINTER(C.c_bool))[0] = True
            else:
                return 0
            return 1

        self._callbacks = (_LAYOUT(layout), _FREE(free), _READ(read), _STRLEN(strlen),
                           _SYMADDR(symaddr))
        self.rc = rm.swift_reflection_createReflectionContextWithDataLayout(None, *self._callbacks)

    def add(self, image):
        """Add *image* and every image it links (transitively)."""
        todo = [image]
        while todo:
            name = todo.pop()
            if name in self.added:
                continue
            self.added.add(name)
            va = self.reader.find_image_header(name)
            if va:
                self.rm.swift_reflection_addImage(self.rc, va)
                todo.extend(d.rsplit("/", 1)[-1] for d in self.reader.image_dependencies(va))

    def name(self, tr):
        p = self.rm.swift_reflection_copyNameForTypeRef(self.rc, tr, False)
        if not p:
            return None
        s = C.string_at(p).decode()
        C.CDLL(None).free(C.c_void_p(p))
        return s

    def typeref(self, mangled):
        return self.rm.swift_reflection_typeRefForMangledTypeName(self.rc, mangled.encode(),
                                                                  len(mangled))

    def fields(self, mangled):
        """[(field name, type name)] of the type *mangled* names, or None without a layout."""
        tr = self.typeref(mangled)
        if not tr:
            return None
        info = self.rm.swift_reflection_infoForTypeRef(self.rc, tr)
        if info.Kind == 0:
            return None
        children = (self.rm.swift_reflection_childOfTypeRef(self.rc, tr, i)
                    for i in range(info.NumFields))
        return [(ch.Name.decode() if ch.Name else None, self.name(ch.TR)) for ch in children]

    def class_fields(self, metadata):
        """[(field name, type name)] of an instance of the class whose metadata is at *metadata*,
        or None."""
        self.fake_isa = metadata
        info = self.rm.swift_reflection_infoForInstance(self.rc, FAKE_OBJECT)
        if info.Kind == 0:
            return None
        children = (self.rm.swift_reflection_childOfInstance(self.rc, FAKE_OBJECT, i)
                    for i in range(info.NumFields))
        return [(ch.Name.decode() if ch.Name else None, self.name(ch.TR)) for ch in children]

    def layout_kind(self, mangled):
        tr = self.typeref(mangled)
        return self.rm.swift_reflection_infoForTypeRef(self.rc, tr).Kind if tr else 0


# ── the comparison ───────────────────────────────────────────────────────────

_KIND_CODE = {TR._STRUCT_KIND: "V", TR._ENUM_KIND: "O", TR._CLASS_KIND: "C"}
_SCALAR = {"Swift.Int": "int64", "Swift.UInt": "uint64", "Swift.String": "string",
           "Foundation.Data": "bytes", "Swift.Bool": "bool", "Swift.Int32": "int32",
           "Swift.Int64": "int64", "Swift.UInt32": "uint32", "Swift.UInt64": "uint64",
           "Swift.Float": "float", "Swift.Double": "double"}


def _mangled(ctx, desc):
    """``$s<module><Name>V...``: the mangled name of a nominal type nested only in nominal types
    (None for one in an extension or anonymous context)."""
    parts, cur = [], desc
    while cur:
        kind, name = TR._desc_kind(ctx, cur), TR._desc_name(ctx, cur)
        if kind == 0:
            return "$s%d%s" % (len(name), name) + "".join(
                "%d%s%s" % (len(n), n, c) for n, c in reversed(parts))
        if kind not in _KIND_CODE or not name:
            return None
        parts.append((name, _KIND_CODE[kind]))
        cur = TR._parent_desc(ctx, cur)
    return None


def _split_args(s):
    out, depth, cur = [], 0, ""
    for ch in s:
        depth += (ch == "<") - (ch == ">")
        if ch == "," and depth == 0:
            out.append(cur.strip())
            cur = ""
        else:
            cur += ch
    return out + [cur.strip()]


def proto_of(t):
    """Remote Mirror's type name -> the proto type it stands for (written apart from ours)."""
    m = re.fullmatch(r"Swift\.Optional<(.*)>", t)
    if m:
        return proto_of(m.group(1))
    m = re.fullmatch(r"Swift\.Array<(.*)>", t)
    if m:
        return "repeated " + proto_of(m.group(1))
    m = re.fullmatch(r"Swift\.Dictionary<(.*)>", t)
    if m:
        k, v = _split_args(m.group(1))
        return "map<%s, %s>" % (proto_of(k), proto_of(v))
    if t in _SCALAR:
        return _SCALAR[t]
    return t.split(".", 1)[1] if "." in t else t       # a nominal type: the module dropped


def _same_name(name, prop=False):
    """A field's proto name and its Swift property's (*prop*), alike: swift-protobuf's property is
    the name in lower camel case, ``_p`` added where it would collide (``has_version`` ->
    ``hasVersion_p``, ``user_id`` -> ``userID``; a proto name may end in ``_p`` itself)."""
    n = name[:-2] if prop and name.endswith("_p") else name
    return n.replace("_", "").lower()


# the proto scalar types each Swift scalar stands for, by the one proto_of names
_SAME_SWIFT = {"sint32": "int32", "sfixed32": "int32", "sint64": "int64", "sfixed64": "int64",
               "fixed32": "uint32", "fixed64": "uint64"}


def _as_swift(proto_type):
    """*proto_type* as its Swift type tells it: the encodings of one width alike."""
    return re.sub(r"\b(%s)\b" % "|".join(_SAME_SWIFT), lambda m: _SAME_SWIFT[m.group(1)],
                  proto_type)


def _storage_metadata(ctx, types):
    """message name -> its ``_StorageClass``'s metadata: a Swift class's metadata is an ObjC class
    object (in ``__objc_classlist``) whose nominal type descriptor is at +0x40."""
    by_desc = {}
    try:
        cl = ctx.section("__DATA_CONST", "__objc_classlist")
    except Exception:
        return {}
    for a in range(cl.vmaddr, cl.vmaddr + cl.vmsize, 8):
        try:
            md = ctx.read_ptr(a)
            by_desc[ctx.read_ptr(md + 0x40)] = md
        except Exception:
            continue
    return {TR._owner_type_name(ctx, d): by_desc[d] for d in types
            if TR._desc_kind(ctx, d) == TR._CLASS_KIND and d in by_desc
            and TR._desc_name(ctx, d) == "_StorageClass"}


class Result(collections.namedtuple("Result", "stats differences")):
    """``stats``: a Counter of messages compared / agreeing / not compared (and why);
    ``differences``: ``[(message, what, detail)]``."""


def compare(mirror, image):
    """:class:`Result` for *image*, with *mirror* (a :class:`CacheMirror` over its cache)."""
    mirror.add(image)
    ctx = load_cache_image(mirror.reader, mirror.reader.find_image_header(image)).ctx
    meta = TR.collect_field_types(ctx)
    emitted = {m.qualified.split(".", 1)[1]: m for m in SW.swift_messages(ctx)}
    sec = ctx.section("__TEXT", "__swift5_types")
    descs = []
    for i in range(sec.vmsize // 4):
        try:
            d = TR._type_record(ctx, sec.vmaddr + i * 4)
        except Exception:
            continue
        if d:
            descs.append(d)
    storage = _storage_metadata(ctx, descs)
    by_name = {TR._qualified_name(ctx, d): d for d in descs}
    stats, differences, seen = collections.Counter(), [], set()
    for desc in descs:
        if TR._desc_kind(ctx, desc) != TR._STRUCT_KIND:
            continue
        q, mn = TR._qualified_name(ctx, desc), _mangled(ctx, desc)
        if q not in emitted:
            continue
        seen.add(q)
        stats["messages"] += 1
        if not mn:
            stats["not compared: no mangled name"] += 1
            continue
        rm = mirror.fields(mn)
        if rm is None:
            stats["not compared: no layout"] += 1
            differences.append((q, "no layout", mn))
            continue
        theirs = {n.lstrip("_"): t for n, t in rm if n}
        if "storage" in theirs:                # copy-on-write: the storage class's fields
            st = mirror.class_fields(storage[q]) if q in storage else None
            if st is None:
                stats["not compared: no storage class layout"] += 1
                differences.append((q, "no storage class layout", mn))
                continue
            del theirs["storage"]
            theirs.update({n.lstrip("_"): t for n, t in st if n})
        one_case = False
        for t in list(theirs.values()):        # a oneof: its property and its cases
            m = re.fullmatch(r"Swift\.Optional<[^.<>]+\.([\w.]+)>", t)
            ed = by_name.get(m.group(1)) if m else None
            if ed is None or TR._desc_kind(ctx, ed) != TR._ENUM_KIND or not _mangled(ctx, ed):
                continue
            enum = _mangled(ctx, ed)           # (OneOf_X nested in the message, or X a type
            if mirror.layout_kind(enum) == STRUCT_LAYOUT:   # of its own: Apple's generators)
                one_case = True
                break
            cases = [(n, ct) for n, ct in mirror.fields(enum) or [] if n]
            if any(ct for n, ct in cases if n != "UNRECOGNIZED"):   # cases with payloads: a
                theirs.update(cases)           # oneof (an enum's only payload: UNRECOGNIZED(Int))
        if one_case:
            stats["not compared: a one-case oneof"] += 1
            continue
        theirs.pop("unknownFields", None)
        ours, ours_t = meta.stored.get(q, set()), meta.types.get(q, {})   # (none: an empty message)
        if ours != set(theirs):
            differences.append((q, "field set", "ours only %s, theirs only %s"
                                % (sorted(ours - set(theirs)), sorted(set(theirs) - ours))))
            continue
        untyped = ours - set(ours_t)           # (a case with no payload has no type to recover)
        stats["fields with no payload"] += sum(1 for f in untyped if theirs.get(f) == "")
        stats["fields with no type recovered"] += sum(1 for f in untyped if theirs.get(f) != "")
        bad = [(f, ours_t[f], proto_of(theirs[f])) for f in sorted(ours_t)
               if theirs.get(f) and proto_of(theirs[f]) != ours_t[f]]
        # what is emitted: each field the serializer gives, paired with its property by name
        props = collections.defaultdict(list)
        for n in theirs:
            props[_same_name(n, prop=True)].append(n)
        out = []
        for f in emitted[q].fields:
            p = props.get(_same_name(f.name), [])
            if len(p) != 1:
                stats["emitted fields with no one property of their name"] += 1
                continue
            if f.proto_type is None:
                stats["emitted fields with no type" if theirs[p[0]] else
                      "emitted fields with no payload"] += 1
                continue
            stats["emitted fields compared"] += 1
            if _as_swift(f.proto_type) != _as_swift(proto_of(theirs[p[0]])):
                out.append((f.name, f.proto_type, proto_of(theirs[p[0]])))
        if bad:
            differences.append((q, "field types", bad))
        if out:
            differences.append((q, "emitted field types", out))
        if not bad and not out:
            stats["agree"] += 1
    stats["not compared: emitted, no type descriptor"] += len(set(emitted) - seen)
    return Result(stats, differences)


def main(argv):
    if library() is None:
        sys.exit("no libswiftRemoteMirror at %s (MACHO_REMOTE_MIRROR)" % artifacts.remote_mirror_lib())
    mirror = CacheMirror(argv[0])
    for image in argv[1:]:
        res = compare(mirror, image)
        print("===", image, dict(res.stats))
        for row in res.differences[:20]:
            print("  ", row)


if __name__ == "__main__":
    main(sys.argv[1:])
