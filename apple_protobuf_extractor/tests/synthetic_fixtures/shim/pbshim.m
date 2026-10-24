#import "pbshim.h"

@implementation PBDataWriter
@end

@implementation PBDataReader
@end

@implementation PBCodable
- (void)writeTo:(PBDataWriter *)writer {
    (void)writer;
}
- (BOOL)readFrom:(PBDataReader *)reader {
    (void)reader;
    return YES;
}
@end

void PBWriteStringField(PBDataWriter *writer, id value, uint32_t tag) {
    (void)writer; (void)value; (void)tag;
}

void PBWriteMessageField(PBDataWriter *writer, id value, uint32_t tag) {
    (void)writer; (void)value; (void)tag;
}

void PBWritePackedInt32Field(PBDataWriter *writer, int32_t *list, uint32_t tag) {
    (void)writer; (void)list; (void)tag;
}

void PBWriteInt32Field(PBDataWriter *writer, int32_t value, uint32_t tag) {
    (void)writer; (void)value; (void)tag;
}

void PBWriteUInt32Field(PBDataWriter *writer, uint32_t value, uint32_t tag) {
    (void)writer; (void)value; (void)tag;
}

void PBWriteInt64Field(PBDataWriter *writer, int64_t value, uint32_t tag) {
    (void)writer; (void)value; (void)tag;
}

void PBWriteUInt64Field(PBDataWriter *writer, uint64_t value, uint32_t tag) {
    (void)writer; (void)value; (void)tag;
}

void PBWriteBoolField(PBDataWriter *writer, BOOL value, uint32_t tag) {
    (void)writer; (void)value; (void)tag;
}

void PBWriteFloatField(PBDataWriter *writer, float value, uint32_t tag) {
    (void)writer; (void)value; (void)tag;
}

void PBWriteDoubleField(PBDataWriter *writer, double value, uint32_t tag) {
    (void)writer; (void)value; (void)tag;
}

void PBWriteBytesField(PBDataWriter *writer, id value, uint32_t tag) {
    (void)writer; (void)value; (void)tag;
}

void PBWritePackedInt64Field(PBDataWriter *writer, int64_t *list, uint32_t tag) {
    (void)writer; (void)list; (void)tag;
}

void PBWritePackedFloatField(PBDataWriter *writer, float *list, uint32_t tag) {
    (void)writer; (void)list; (void)tag;
}

uint32_t PBReadTag(PBDataReader *reader) {
    (void)reader;
    return 0;
}

void PBHandleUnknownField(id self, uint32_t field) {
    (void)self; (void)field;
}

void PBDataWriterWriteInt32Field(PBDataWriter *writer, int32_t value, uint32_t tag) {
    (void)writer; (void)value; (void)tag;
}

void PBDataWriterWriteUint32Field(PBDataWriter *writer, uint32_t value, uint32_t tag) {
    (void)writer; (void)value; (void)tag;
}

void PBDataWriterWriteSint32Field(PBDataWriter *writer, int32_t value, uint32_t tag) {
    (void)writer; (void)value; (void)tag;
}

void PBDataWriterWriteSint64Field(PBDataWriter *writer, int64_t value, uint32_t tag) {
    (void)writer; (void)value; (void)tag;
}

void PBDataWriterWriteFixed32Field(PBDataWriter *writer, uint32_t value, uint32_t tag) {
    (void)writer; (void)value; (void)tag;
}

void PBDataWriterWriteSfixed32Field(PBDataWriter *writer, int32_t value, uint32_t tag) {
    (void)writer; (void)value; (void)tag;
}

void PBDataWriterWriteFixed64Field(PBDataWriter *writer, uint64_t value, uint32_t tag) {
    (void)writer; (void)value; (void)tag;
}

void PBDataWriterWriteSfixed64Field(PBDataWriter *writer, int64_t value, uint32_t tag) {
    (void)writer; (void)value; (void)tag;
}

void PBDataWriterWriteInt64Field(PBDataWriter *writer, int64_t value, uint32_t tag) {
    (void)writer; (void)value; (void)tag;
}

void PBDataWriterWriteUint64Field(PBDataWriter *writer, uint64_t value, uint32_t tag) {
    (void)writer; (void)value; (void)tag;
}

void PBDataWriterPlaceMark(PBDataWriter *writer, void *mark, uint32_t tag) {
    (void)writer; (void)mark; (void)tag;
}

void PBDataWriterRecallMark(PBDataWriter *writer, const void *mark) {
    (void)writer; (void)mark;
}
