# swift-protobuf oracle fixture

A genuinely-compiled Swift executable (`oracle`) built from `oracle.proto` by
a real `protoc` + `protoc-gen-swift` + Swift compiler — real chained-fixups
Mach-O, not hand-packed bytes — used as KNOWN ground truth by:

* `tests/test_swift_descriptor_extract.py::TestLiveStaticOracle` (field
  names + numbers, via `serializers/swift_descriptor_extract.py`)
* `tests/test_swift_type_recovery.py::TestOracleExactTypes` (field TYPES,
  via `serializers/swift_type_recovery.py`)

Both classes are gated on `MACHO_TEST_SWIFT_ORACLE`; `artifacts.py`'s
`swift_oracle_path()` defaults to this directory's committed `oracle` binary,
so no environment setup or toolchain is needed to run them.

## Why this needs its own fixture (not `tests/synthetic_fixtures/`)

`synthetic_fixtures/` covers the ObjC/PBCodable recovery path (clang, iOS
SDK). This exercises the *Swift*-protobuf recovery path
(`serializers/swift_*.py`), a structurally different Mach-O shape (Swift
type/field reflection metadata, `_NameMap` static initializers, chained
fixups binds to the Swift stdlib) that needs a real Swift toolchain to
produce, not clang.

## Regenerating

Only needed when editing `oracle.proto`. Run `./build_oracle.sh`, then
`git diff --stat oracle` and re-run the two test classes above
(`MACHO_TEST_SWIFT_ORACLE=$(pwd)/oracle`) before committing the regenerated
binary alongside the source diff. See `build_oracle.sh`'s header comment for
the two non-obvious requirements (protoc-gen-swift version pin, chained-fixups
linker flag) — skipping either silently produces a fixture the tool can't
fully decode rather than a build error.

## Layout

```
oracle.proto           the known schema (source of truth)
Package.swift          SPM package: links SwiftProtobuf 1.30.0, forces
                        -fixup_chains
Sources/oracle/
  oracle.pb.swift       protoc-gen-swift 1.30.0 output (checked in so the
                        generator's exact lowering is reviewable in git diffs)
  main.swift            instantiates + serializes every message so the
                        optimizer can't dead-strip their metadata
build_oracle.sh         regenerates oracle.pb.swift + the `oracle` binary
oracle                  the committed binary (~3.7MB, arm64 macOS Mach-O)
```

## Known residual gap (documented, not hidden)

Discovered while building this fixture, NOT introduced by it: newer
`protoc-gen-swift` (>=1.31, commit `0f043ac2`) emits `_NameMap` as a compact
bytecode program (`_NameMap(bytecode: "...")`) instead of the classic
array/dictionary literal. `serializers/swift_descriptor_extract.py`'s
`_extract_namemap` does not yet decode that bytecode form — real device
binaries compiled by an old-enough Xcode are unaffected, but a
`protoc-gen-swift` >=1.31-built binary's fields would currently recover as
empty. Pinning this fixture's codegen to 1.30.0 avoids the gap here; adding a
bytecode-program decoder (the format is fully specified in swift-protobuf's
own `Sources/SwiftProtobuf/{NameMap,BytecodeReader}.swift`) is a follow-up,
not part of this fixture.
