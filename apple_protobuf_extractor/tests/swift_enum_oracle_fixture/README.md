# swift-protobuf enum / packed-name-map oracle

Genuinely compiled Swift executables built from `enum_oracle.proto` (enums with value 0,
a negative value, a large value, a proto2 enum whose first value is not 0, an aliased enum,
a nested enum, plus a message with a field-number gap).  Used as KNOWN ground truth by
`tests/test_swift_descriptor_extract.py::TestEnumOracle`.

| binary | protoc-gen-swift / runtime | name-map lowering |
|---|---|---|
| `eo_classic` | 1.30.0 | classic dictionary literal (static array) |
| `eo_bytecode` | 1.33.3 | packed `_NameMap(bytecode:)` (iOS 27 form) |

`./build.sh` rebuilds both (needs network + a Swift toolchain); the binaries are committed
so the tests do not.  Known gap: the aliased enum is recovered only from the packed form; in
the classic form it is built at runtime and reported as having no cases (never wrong cases).
