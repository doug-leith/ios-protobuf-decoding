# Why the proto `package` is reconstructed (and why a wrong one is harmless)

The emitted `.proto` carries a reminder above its package line:

```proto
// package reconstructed from the ObjC class-name prefix (not stored in the
// binary); may be inexact, harmless — see PACKAGE_NAMES.md
package geo;
```

This is the same situation as the enum *type* name (see `ENUM_TYPE_NAMES.md`):
the value is not recorded in the binary, so it is reconstructed from the strongest
available signal, and getting it wrong costs nothing but a cosmetic label.

> **One-line summary:** the proto `package` is not in the binary; it is derived
> from the ObjC class-name prefix; a wrong package only changes a namespace label
> and never affects field numbers, values, or wire behavior.

---

## 1. The package name is not in the binary

A proto `package` is declared in the `.proto` source. After compilation to
Objective-C it would survive only if the runtime kept a fully-qualified message
name (e.g. in a reflection descriptor). Apple's GEOPD / PB proto classes use a
**custom `readFrom:` / `writeTo:` runtime** — the `_reader` / `_readerLock` ivar
pattern — with **no `GPBDescriptor`** and no stored type name. So there is nothing
to read.

We verified this by scanning every string in the GeoServices image (~60k
strings). The only dotted, package-shaped strings present are **bundle
identifiers, XPC service names, and dispatch-queue labels**:

```
com.apple.GeoServices
com.apple.geo.ETARequester
com.apple.geo.DataSession
…
```

None of these is a proto package, and none is structurally linked to a message
class. (The only genuine protobuf *descriptor* strings in the binary —
`descriptor.cc`, `"is not a message type"` — belong to a **separate**
`libaddr_obj` component that embeds Google protobuf for address parsing; they do
not describe the GEOPD classes.)

So the package cannot be looked up. The **ObjC class-name prefix** (`GEO…`, `PD…`)
is the only available signal.

## 2. How the package is reconstructed

`package_for_class` (in `proto/emitter.py`):

1. An explicit prefix→package map (`GEO` → `geo`, …), extensible per binary.
2. Otherwise, the leading all-caps run of the class name, lowercased
   (`APPLFoo` → `appl`).

This is deterministic and applied identically to every class sharing a prefix.

## 3. Why a wrong package is harmless

The package name is a **namespace label**. It affects nothing functional:

- **Wire / semantics — zero impact.** The package never appears on the wire and
  has no effect on field numbers, values, or decoding. Serialize / deserialize /
  round-trip / interop are identical regardless of the package.
- **Internal consistency — preserved.** Because it is derived deterministically
  from the prefix, every class with the same prefix gets the same package, so the
  emitted file's cross-package qualification stays consistent even if the chosen
  name differs from Apple's original.
- **What you actually lose: a label.** If you `protoc`-generate code, the
  generated namespace differs from Apple's, but the messages still interoperate
  byte-for-byte.

This is the opposite end of the risk spectrum from a wrong field *number* or a
wrong message/enum element *type*, which do corrupt decoding and are handled with
much more rigor. Inferring the package is therefore acceptable.

## Where this lives in the code

- `proto/emitter.py` — `package_for_class` (the reconstruction, with the full
  rationale in its docstring) and `_PACKAGE_RECON_NOTE` (the emitted reminder).

See also: `ENUM_TYPE_NAMES.md` (the analogous enum-type-name case),
`FIELD_TYPE_INFERENCE.md`.
