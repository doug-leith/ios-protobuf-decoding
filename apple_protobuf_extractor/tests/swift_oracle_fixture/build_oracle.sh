#!/usr/bin/env bash
# Rebuild the swift-protobuf ORACLE fixture binary from source.
#
# The binary IS committed to the repo (~4MB, no proprietary Apple code) so
# tests/test_swift_descriptor_extract.py::TestLiveStaticOracle and
# tests/test_swift_type_recovery.py::TestOracleExactTypes need no Xcode/SPM
# toolchain at test time. Run this script only when editing oracle.proto,
# then `git diff --stat` the regenerated binary and re-run the two test
# classes above (MACHO_TEST_SWIFT_ORACLE=<path to the rebuilt `oracle`>)
# before committing.
#
# Two non-obvious requirements discovered while building this fixture:
#
# 1. **protoc-gen-swift MUST be pinned to <1.31** (we use 1.30.0). Starting
#    with swift-protobuf commit 0f043ac2 (first released in 1.31.0),
#    protoc-gen-swift emits `_NameMap(bytecode: "...")` — a compact varint/
#    string bytecode program — instead of the classic
#    `_NameMap = [1: .same(proto: "x"), ...]` array/dictionary literal.
#    serializers/swift_descriptor_extract.py's `_extract_namemap` does not
#    yet decode the bytecode form (a well-specified but separate format —
#    see swift-protobuf's Sources/SwiftProtobuf/{NameMap,BytecodeReader}.swift
#    if someone wants to add support later); pinning to a pre-bytecode
#    release keeps the oracle on the lowering the tool already handles. This
#    is a `protoc-gen-swift` (codegen) version constraint, independent of
#    which SwiftProtobuf runtime version the binary links — both are pinned
#    to 1.30.0 here for simplicity.
#
# 2. **Link with `-Xlinker -fixup_chains`.** Without it, `swift build`
#    produces a plain `LC_DYLD_INFO_ONLY` executable (legacy bind opcodes);
#    macho/memory.py's `import_name_for_bind` (used by
#    serializers/swift_type_recovery.py to resolve external Swift stdlib
#    field types like Int32/Int64/Foundation.Data via GOT-indirect symbolic
#    references) only understands `LC_DYLD_CHAINED_FIXUPS` binds. This is
#    the same requirement synthetic_fixtures/README.md gotcha 1 documents
#    for the ObjC fixtures (there achieved by linking against a real dylib
#    instead of `-undefined dynamic_lookup`); here it's a linker flag
#    because we're producing a plain Swift executable, not enabling/disabling
#    lazy binding.
#
# Usage:
#   ./build_oracle.sh
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

PROTOC_GEN_SWIFT_VERSION=1.30.0

command -v protoc >/dev/null || { echo "protoc not found — 'brew install protobuf'"; exit 1; }
command -v swift  >/dev/null || { echo "swift not found — install Xcode command line tools"; exit 1; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

echo "Cloning swift-protobuf $PROTOC_GEN_SWIFT_VERSION to build a matching protoc-gen-swift..."
git clone --quiet --depth 1 --branch "$PROTOC_GEN_SWIFT_VERSION" \
    https://github.com/apple/swift-protobuf.git "$WORK/swift-protobuf-src"
(cd "$WORK/swift-protobuf-src" && swift build -c release --product protoc-gen-swift -q)
PROTOC_GEN_SWIFT="$WORK/swift-protobuf-src/.build/release/protoc-gen-swift"

echo "Regenerating oracle.pb.swift (protoc-gen-swift $PROTOC_GEN_SWIFT_VERSION lowering)..."
protoc --plugin="protoc-gen-swift=$PROTOC_GEN_SWIFT" \
    --swift_out=Sources/oracle oracle.proto

echo "Building the oracle executable (chained fixups)..."
swift build -c release
cp .build/release/oracle ./oracle

echo "Done: $(pwd)/oracle"
file ./oracle
otool -l ./oracle | grep -A1 'cmd LC_DYLD_CHAINED_FIXUPS' || {
    echo "WARNING: LC_DYLD_CHAINED_FIXUPS not found in the built binary — check the linker flag." >&2
    exit 1
}
