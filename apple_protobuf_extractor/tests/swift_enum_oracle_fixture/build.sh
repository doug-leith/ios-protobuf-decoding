#!/usr/bin/env bash
# Rebuild the two swift-protobuf ENUM/packed-name-map oracle binaries from enum_oracle.proto.
#
#   eo_classic   protoc-gen-swift + runtime 1.30.0  -> classic `_NameMap` dictionary literal
#                (compiler-folded to a static array for most types, as in the existing
#                tests/swift_oracle_fixture/oracle)
#   eo_bytecode  protoc-gen-swift + runtime 1.33.3  -> `_NameMap(bytecode: "...")`, the packed
#                form used by newer toolchains (iOS 27)
#
# Both link with `-Xlinker -fixup_chains` (see swift_oracle_fixture/build_oracle.sh for why)
# and are committed (~3.7 MB each) so the tests need no Swift toolchain.  Only rerun this
# when editing enum_oracle.proto.  Needs: protoc, swift 5.9+, network access to github.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
build() {   # version outname
  local V=$1 OUT=$2 W; W=$(mktemp -d); trap 'rm -rf "$W"' RETURN
  git clone --quiet --depth 1 --branch "$V" https://github.com/apple/swift-protobuf.git "$W/src"
  (cd "$W/src" && swift build -c release --product protoc-gen-swift -q)
  mkdir -p "$W/pkg/Sources/eo"
  protoc --plugin=protoc-gen-swift="$W/src/.build/release/protoc-gen-swift" --swift_out="$W/pkg/Sources/eo" enum_oracle.proto
  cp main.swift "$W/pkg/Sources/eo/main.swift"
  cat > "$W/pkg/Package.swift" <<PKG
// swift-tools-version:5.9
import PackageDescription
let package = Package(name: "eo",
  dependencies: [ .package(path: "../src") ],
  targets: [ .executableTarget(name: "eo", dependencies: [ .product(name: "SwiftProtobuf", package: "src") ],
    linkerSettings: [ .unsafeFlags(["-Xlinker", "-fixup_chains"]) ]) ])
PKG
  (cd "$W/pkg" && swift build -c release 2>&1 | tail -2)
  cp "$W/pkg/.build/release/eo" "./$OUT"
}
build 1.30.0 eo_classic
build 1.33.3 eo_bytecode
ls -l eo_classic eo_bytecode
