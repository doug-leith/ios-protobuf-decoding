# apple_protobuf_extractor

Reconstruct protobuf `.proto` schemas from compiled Apple binaries — no headers,
no `.proto` sources, just the shipped Mach-O. It handles three protobuf runtimes.
For Apple's Objective-C `PBCodable` subclasses it statically analyses the generated
code: field numbers and wire types from each class's `writeTo:` / `readFrom:` ARM64
code, field names and base types from the ivar layout, and enum value↔name tables
from the `xAsString:` methods. For Google's C++ `libprotobuf` it decodes the
descriptors the binary embeds, which gives exact schemas. For `swift-protobuf` it reads
field names and numbers from each message's name map and types from Swift reflection
metadata. Works on a standalone Mach-O file or directly on an image inside a dyld
shared cache.

## Install

Part of this repo; install it into the repo venv (Python >= 3.10). The only
runtime dependency is `capstone` (ARM64 disassembly), installed editable into the
venv so `proto` / `macho` resolve from any working directory:

```sh
# from the repo root
./venv/bin/python3 -m pip install setuptools wheel             # build backend (one-time)
./venv/bin/python3 -m pip install -e ./apple_protobuf_extractor # editable install
```

(The repo-root `requirements.txt` includes this editable install, so a normal
`pip install -r requirements.txt` covers it. `venv/` is gitignored — after
recreating it, re-run the editable install or `import proto` / `import macho` fail.)

> **Platform note.** Examples call the venv interpreter as `./venv/bin/python3`
> (macOS/Linux). On **Windows** use `venv\Scripts\python` instead, or
> `venv\Scripts\activate` once and then just `python`. Create the venv with
> `python3 -m venv venv` (Windows: `py -3.14 -m venv venv`).

## Run

```sh
# from the repo root.  --help prints full usage + the output caveats.
./venv/bin/python3 apple_protobuf_extractor/cli.py --help

# Extract one framework from the dyld cache  ->  ./protos/*.proto
./venv/bin/python3 apple_protobuf_extractor/cli.py \
    --framework GeoServices --cache iphone8_data/dylib -o ./protos/

# Extract from a standalone Mach-O binary (no cache needed)
./venv/bin/python3 apple_protobuf_extractor/cli.py --binary iphone8_data/locationd -o ./protos/

# List every framework/dylib embedded in the cache (one per line)
./venv/bin/python3 apple_protobuf_extractor/cli.py --list-frameworks --cache iphone8_data/dylib

# Dry run (stats only, no files) restricted to a class-name prefix
./venv/bin/python3 apple_protobuf_extractor/cli.py \
    --framework GeoServices --cache iphone8_data/dylib --prefix GEO --dry-run

# All messages into one file instead of one-per-ObjC-prefix
./venv/bin/python3 apple_protobuf_extractor/cli.py \
    --framework HealthKit --cache iphone8_data/dylib --single-file -o ./protos/

# Report which protobuf runtimes an image uses (PBCodable / C++ / swift / GPB)
./venv/bin/python3 apple_protobuf_extractor/cli.py --binary iphone8_data/locationd --list-serializers

# swift-protobuf: writes remindd.proto and swiftprotobuf.proto (the well-known types it links)
./venv/bin/python3 apple_protobuf_extractor/cli.py --binary iphone8_data/libexec/remindd -o ./protos/

# PBCodable and C++ libprotobuf together: locationd gives 65 PBCodable and 334 C++ messages
./venv/bin/python3 apple_protobuf_extractor/cli.py --binary iphone8_data/locationd -o ./protos/
```

`--cache` accepts either the cache directory or a direct path to the main cache
file; numbered sub-caches (`.01`, `.02`, …) and the `.symbols` file are picked up
automatically. A dry run prints a per-framework summary (messages, confirmed vs
estimated field numbers, enums, output files). Other flags: `--package` (override
the output package name), `--verbose`, `--version`.

## What it recovers — and the honest caveats

- **Field numbers, names, types, repeated/optional, nested messages, enums** —
  recovered structurally from the binary.
- **Every uncertain field is flagged** with an inline `//` comment (an estimated
  number, or a repeated element that fell back to `bytes`). A field with no comment
  was confirmed from the code.
- **int32 vs uint32 (and int64/uint64) is not recoverable** — both compile to the
  same ivar + wire encoding; the tool emits a canonical default. `sint*`, `fixed*`,
  `sfixed*` (distinct wire encodings/helpers) *are* distinguished.
- **Names are ObjC-derived** (ivar / class names); usually but not always identical
  to the original `.proto`.
- **Three protobuf runtimes are decoded.**
    - Apple's Objective-C `PBCodable` classes: the tool disassembles the generated
      `writeTo:` / `readFrom:` code (everything above).
    - Google's C++ `libprotobuf` (the full runtime): an exact decode of the
      `FileDescriptorProto` descriptors the binary embeds, with no estimates. See
      [C++ `libprotobuf` extraction](#c-libprotobuf-extraction).
    - `swift-protobuf`: names and numbers are read from each message's name map and
      types from Swift reflection metadata. See [swift-protobuf extraction](#swift-protobuf-extraction).
- **Two more runtimes are detected but not decoded.** Google's Objective-C runtime
  (`GPBMessage` / `protobuf-objc`, for example Apple's **Key Transparency** classes in
  `transparencyd`) and C++ `libprotobuf-lite`, which strips its descriptors so no names
  or numbers can be recovered. When an image carries messages from either, the tool prints
  one consolidated warning naming them, and `--list-serializers` lists them.
  - Detection also tells apart a top-level `google::protobuf` from vendored static copies
    such as Apple Wireless Diagnostics' `wireless_diagnostics::google::protobuf`. Merely
    *linking* `libprotobuf.dylib` without referencing it does not trip the detector.

All three decoded runtimes work on a standalone Mach-O and, with `--framework`, on an
image inside a dyld cache (which uses the cache's `.symbols` file).

`cli.py --help` lists the full set of caveats; see [Limitations](#limitations) for
the accepted, well-characterised output gaps.

## Input artifacts

All inputs live in **one directory**, resolved through the single config module
`artifacts.py`. The default is `<repo>/iphone8_data/`:

```
iphone8_data/
  dylib/            # the dyld shared cache (dyld_shared_cache_arm64 + .symbols + sub-caches)
  GeoServices       # standalone framework binary (208 MB)
  locationd         # standalone executable (30 MB)
  geod              # standalone executable
```

Point the tool at a different dump with one env var — no code edits:

```sh
export MACHO_DATA_DIR=/path/to/some_other_dump      # the whole tool follows
```

Per-artifact overrides are also honoured: `MACHO_TEST_CACHE` (cache dir),
`MACHO_TEST_BINARY` (GeoServices), `MACHO_TEST_LOCATIOND`, `MACHO_TEST_GEOD`.
These artifacts are gitignored (multi-GB).

## Tests

```sh
# from the repo root; live tests auto-skip if the artifacts are absent
./venv/bin/python3 -m pytest
```

Live tests load the real cache / binaries and gate on artifact presence (the
`iphone8_data/` dir, or the `MACHO_*` env overrides above); they skip cleanly when
the artifacts aren't there.

## Checking the output by hand

Three small tools give an independent check on the extractor. They use raw disassembly, not the
production decoder, so a bug in one is unlikely to be a bug in the other. They need the Apple artifacts
(see the repository README) and run from the repo root:

```sh
# Every field's type against its ivar's Objective-C @encode (the compiler-emitted storage type)
./venv/bin/python3 apple_protobuf_extractor/gt_types.py CoreLocationProtobuf

# A simple linear-scan oracle: the field numbers and ivars a class's writeTo: writes
./venv/bin/python3 apple_protobuf_extractor/gt_fields.py CoreLocationProtobuf CLPPressure

# The symbolized disassembly of a class's writeTo: (or readFrom:), 40 instructions, to read by hand
./venv/bin/python3 apple_protobuf_extractor/gt_dump.py CoreLocationProtobuf CLPPressure 'writeTo:' 40
```

On `CoreLocationProtobuf`, `gt_types.py` checks 530 fields against their `@encode` and finds no
contradictions. `gt_fields.py` is deliberately simple and cannot follow jump tables or compare chains;
where it disagrees with the extractor, `gt_dump.py` shows the assembly to settle which is right.

## C++ `libprotobuf` extraction

Separate from the PBCodable machinery, this recovers **exact** `.proto` schemas
from binaries built against the *full* C++ protobuf runtime, by decoding the
serialized `FileDescriptorProto` descriptors the generated `.pb.cc` embeds (the
`descriptor_table_protodef_*` arrays). Because that blob *is* the schema, output is
complete and faithful — message/field/enum names, numbers, types, labels, nesting,
oneofs — and validated field-for-field against `descriptor_pb2`.

`cli.py --binary` runs it automatically alongside the other runtimes (see [Run](#run)).
It can also be run on its own:

```sh
./venv/bin/python3 apple_protobuf_extractor/serializers/cpp_descriptor_extract.py \
    iphone8_data/locationd -o ./protos_cpp/
```

Self-contained (hand-rolled descriptor decoder, no `protobuf` dependency). Only
works on *full*-runtime binaries; `libprotobuf-lite` strips descriptors, so those are
detected and reported by the foreign-protobuf warning instead.

## swift-protobuf extraction

A `swift-protobuf` message has no single descriptor. Its schema is split across two
tables in the binary, which the tool joins by field name:

- the `_protobuf_nameMap` that `protoc-gen-swift` emits, which maps each field number
  to its name; and
- the Swift reflection metadata (`__swift5_fieldmd`), which gives each stored
  property's type (`Int32`, `String`, `Array`, `Optional`, `Dictionary`, or another
  message or enum).

Names and numbers are read literally from the binary, including the several ways
compilers lower the name map across iOS versions and optimisation levels. Well-known
types built at runtime (`Google_Protobuf_*`), `oneof` members and copy-on-write
storage fields are recovered. For example, `remindd` gives its own messages in
`remindd.proto` and the Google well-known types it links in `swiftprotobuf.proto`:

```sh
./venv/bin/python3 apple_protobuf_extractor/cli.py --binary iphone8_data/libexec/remindd -o ./protos/
```

The accepted gaps ([LIMITATIONS.md](LIMITATIONS.md), section 10): the number of a
single-field message can be an estimate (flagged `// number estimated`); integer
subtypes are collapsed to `int32` / `uint32` / `int64` / `uint64` (not flagged, and
wire-incorrect for a genuine `sint*` or `fixed*` field, though none is known in the
binaries surveyed); and a container element that does not decode is shown as `bytes`
with a note.

## Limitations

A few small, well-characterised slices of the output are **accepted limitations**
(not bugs — the degraded fields are flagged inline in the `.proto`, except where
there's no field to flag): a `map<>` field whose entry writer isn't found (or whose key/value
type isn't proven) falls back to `bytes` / `repeated bytes` — map fields that are
serialized by `writeTo:` are otherwise recovered as `map<K, V>`; repeated messages with an
unresolved element type emit as `repeated bytes`; ivar-less *delegated* fields are
omitted; a wire number of 0 (Apple's illegal-in-proto 0-based numbering) gets a
flagged, non-wire-accurate estimate; and proto-to-proto subclasses omit inherited
parent fields (noted with `// inherits all fields from …`). See
[`LIMITATIONS.md`](LIMITATIONS.md) for the full list, affected fields, and consumer
workarounds.

**Newest builds (iPhone17,3, macOS 27).** These arm64e images are supported, but on
them a small number of repeated-message fields — about 10 of the ~3,700 message-typed
GeoServices fields — come back as `repeated bytes` (flagged inline) because the tool
cannot confirm which class's field-dispatch code it is reading. See
[`LIMITATIONS.md`](LIMITATIONS.md) item 11.
