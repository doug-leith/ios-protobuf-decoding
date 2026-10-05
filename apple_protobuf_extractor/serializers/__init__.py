"""serializers — decoders for the non-PBCodable protobuf runtimes this tool
supports alongside Apple's own PBCodable: swift-protobuf (swift_descriptor_extract
+ swift_type_recovery) and C++ google::protobuf (cpp_descriptor_extract).

Each is a genuinely separate wire runtime with almost no shared code with the
PBCodable path in proto/*.py; proto/foreign.py adapts their output into the same
package-grouped .proto emission.
"""
