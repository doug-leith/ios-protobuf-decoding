# apple_protobuf_extractor

Reconstruct protobuf `.proto` schemas from compiled Apple binaries — no headers,
no `.proto` sources, just the shipped Mach-O. It statically analyses the
Objective-C `PBCodable` subclasses Apple's protobuf compiler emits: field numbers
and wire types from each class's `writeTo:` / `readFrom:` ARM64 code, field names
and base types from the ivar layout, and enum value↔name tables from the
`xAsString:` methods. Works on a standalone Mach-O file or directly on an image
inside a dyld shared cache.

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
- **Objective-C `PBCodable` protobufs only.** The tool disassembles the generated
  `writeTo:`/`readFrom:` code of Apple's `PBCodable` subclasses. It does **not**
  decode protobufs from other libraries — Google's ObjC runtime (`GPBMessage` /
  `protobuf-objc`), Swift protobuf (`SwiftProtobuf`), or C++ `libprotobuf`
  (`google::protobuf`) — because those share a descriptor/reflection runtime with no
  per-class serialization code to analyse. Such messages are simply absent from the
  output (the framework yields 0 messages), not mis-decoded. When an image *also*
  carries messages from these runtimes, **the tool prints one consolidated warning**
  naming each, so they read as recognised-but-skipped:
    - `GPBMessage`-derived ObjC classes — named (e.g. Apple's **Key Transparency** /
      `transparencyd`).
    - Swift `swift-protobuf` types — named, via export-trie protocol-conformance
      descriptors (e.g. `bookdatastored`'s `PBProperty…` structs).
    - C++ `google::protobuf` — symbol count + namespace(s), distinguishing top-level
      `google::protobuf` from vendored static copies such as Apple Wireless
      Diagnostics' `wireless_diagnostics::google::protobuf`. (locationd, for example,
      emits its 65 PBCodable messages **and** AWD telemetry via the vendored C++
      runtime — both reported.) Merely *linking* `libprotobuf.dylib` without
      referencing it does not trip the detector.
  Swift/C++ detection reads the binary's symbol table + dyld export trie, so it works
  on a **standalone Mach-O**; for a cache image, extract the binary to detect these
  (the cache's shared symbol table isn't addressable per-image).

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
# from the repo root — hardcoded module list, not pytest auto-discovery
./venv/bin/python3 run_tests.py            # full suite (live tests auto-skip if artifacts absent)
./venv/bin/python3 -m pytest               # if you prefer pytest
```

Live tests load the real cache / binaries and gate on artifact presence (the
`iphone8_data/` dir, or the `MACHO_*` env overrides above); they skip cleanly when
the artifacts aren't there.

## C++ `libprotobuf` extraction

Separate from the PBCodable machinery, this recovers **exact** `.proto` schemas
from binaries built against the *full* C++ protobuf runtime, by decoding the
serialized `FileDescriptorProto` descriptors the generated `.pb.cc` embeds (the
`descriptor_table_protodef_*` arrays). Because that blob *is* the schema, output is
complete and faithful — message/field/enum names, numbers, types, labels, nesting,
oneofs — and validated field-for-field against `descriptor_pb2`.

```sh
./venv/bin/python3 apple_protobuf_extractor/cpp_descriptor_extract.py \
    iphone8_data/libexec/nearbyd -o ./protos_cpp/
```

Self-contained (hand-rolled descriptor decoder, no `protobuf` dependency). Only
works on *full*-runtime binaries; `libprotobuf-lite` strips descriptors — those are
detected and reported by the foreign-protobuf warning instead. Swift
(`swift-protobuf`) and Google ObjC (`GPBMessage`) are detected but not yet decoded.

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
