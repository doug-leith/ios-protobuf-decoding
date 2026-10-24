#import <Foundation/Foundation.h>

// Canonical synthetic-fixture runtime shim: trivial stand-ins for Apple's
// private PBCodable / PBDataWriter / PBDataReader classes and the C-linkage
// field helpers ProtocolBuffer.framework exposes to generated writeTo:/
// readFrom: code. See ../README.md for why this needs to be a REAL linked
// dylib (not `-undefined dynamic_lookup`) and why the field helpers below are
// plain C functions, not ObjC methods.

@interface PBDataWriter : NSObject
@end

@interface PBDataReader : NSObject
@end

@interface PBCodable : NSObject
- (void)writeTo:(PBDataWriter *)writer;
- (BOOL)readFrom:(PBDataReader *)reader;
@end

// Plain C-linkage helpers, NOT ObjC methods — matches real Apple codegen
// (direct `bl`, args in x0/x1/w2, bypassing objc_msgSend entirely).
extern void PBWriteStringField(PBDataWriter *writer, id value, uint32_t tag);
extern void PBWriteMessageField(PBDataWriter *writer, id value, uint32_t tag);
extern uint32_t PBReadTag(PBDataReader *reader);
extern void PBHandleUnknownField(id self, uint32_t field);

// Plain-varint / bytes / FP field helpers. int32/uint32/int64/uint64/bool/enum
// all collapse onto the SAME plain-varint wire family in real binaries — the
// TYPE comes entirely from the ivar's own @encode (proto/protocore.py), never
// from which of these is called — so one helper per width here is just for
// realistic call-site variety, not because the classifier cares which is used.
// float/double follow AAPCS64: the FP value occupies s0/d0 (not x1/w1), so the
// tag lands in w1 instead of w2 — see
// proto/writeto.py:_writeto_field_number_before.
extern void PBWriteInt32Field(PBDataWriter *writer, int32_t value, uint32_t tag);
extern void PBWriteUInt32Field(PBDataWriter *writer, uint32_t value, uint32_t tag);
extern void PBWriteInt64Field(PBDataWriter *writer, int64_t value, uint32_t tag);
extern void PBWriteUInt64Field(PBDataWriter *writer, uint64_t value, uint32_t tag);
extern void PBWriteBoolField(PBDataWriter *writer, BOOL value, uint32_t tag);
extern void PBWriteFloatField(PBDataWriter *writer, float value, uint32_t tag);
extern void PBWriteDoubleField(PBDataWriter *writer, double value, uint32_t tag);
extern void PBWriteBytesField(PBDataWriter *writer, id value, uint32_t tag);
extern void PBWritePackedInt64Field(PBDataWriter *writer, int64_t *list, uint32_t tag);
extern void PBWritePackedFloatField(PBDataWriter *writer, float *list, uint32_t tag);

// ProtocolBuffer.framework's length-delimited marks, under their real names (f22): a
// sub-message's begin mark (a frame scratch and the field number) and end mark (the same
// scratch).
extern void PBDataWriterPlaceMark(PBDataWriter *writer, void *mark, uint32_t tag);
extern void PBDataWriterRecallMark(PBDataWriter *writer, const void *mark);

// ProtocolBuffer.framework's own field writers, under their real names (f29): a standalone
// binary imports them by name, and the name is the wire encoding.
extern void PBDataWriterWriteInt32Field(PBDataWriter *writer, int32_t value, uint32_t tag);
extern void PBDataWriterWriteUint32Field(PBDataWriter *writer, uint32_t value, uint32_t tag);
extern void PBDataWriterWriteSint32Field(PBDataWriter *writer, int32_t value, uint32_t tag);
extern void PBDataWriterWriteSint64Field(PBDataWriter *writer, int64_t value, uint32_t tag);
extern void PBDataWriterWriteFixed32Field(PBDataWriter *writer, uint32_t value, uint32_t tag);
extern void PBDataWriterWriteSfixed32Field(PBDataWriter *writer, int32_t value, uint32_t tag);
extern void PBDataWriterWriteFixed64Field(PBDataWriter *writer, uint64_t value, uint32_t tag);
extern void PBDataWriterWriteSfixed64Field(PBDataWriter *writer, int64_t value, uint32_t tag);
extern void PBDataWriterWriteInt64Field(PBDataWriter *writer, int64_t value, uint32_t tag);
extern void PBDataWriterWriteUint64Field(PBDataWriter *writer, uint64_t value, uint32_t tag);
