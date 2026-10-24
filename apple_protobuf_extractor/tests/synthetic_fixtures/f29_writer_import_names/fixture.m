#import "pbshim.h"

// Ground truth (see expected.py):
//   message TestWriterNames {
//     int32    i32   = 1;   uint32   u32   = 2;
//     sint32   s32   = 3;   sint64   s64   = 4;
//     fixed32  f32   = 5;   sfixed32 sf32  = 6;
//     fixed64  f64   = 7;   sfixed64 sf64  = 8;
//     int64    i64   = 9;   uint64   u64   = 10;
//     int32    other = 11;  // written by a helper whose name shows no encoding
//     bytes    num   = 12;  // NSNumber ivar: names no wire type
//     bytes    obj   = 13;  // bare id ivar: names no wire type
//   }
//
// A standalone binary calls ProtocolBuffer.framework's writers through import stubs, so
// the helper's code is not in the binary; the stub's bound name is the encoding
// (proto/write_helpers.py:_family_from_import).  `other` goes through the shim's own
// PBWriteInt32Field, a name that says nothing, so the field is flagged instead.

@interface TestWriterNames : PBCodable {
    int32_t  _i32;
    uint32_t _u32;
    int32_t  _s32;
    int64_t  _s64;
    uint32_t _f32;
    int32_t  _sf32;
    uint64_t _f64;
    int64_t  _sf64;
    int64_t  _i64;
    uint64_t _u64;
    int32_t  _other;
    NSNumber *_num;
    id        _obj;
}
@end

@implementation TestWriterNames

- (void)writeTo:(PBDataWriter *)writer {
    PBDataWriterWriteInt32Field(writer, _i32, 1);
    PBDataWriterWriteUint32Field(writer, _u32, 2);
    PBDataWriterWriteSint32Field(writer, _s32, 3);
    PBDataWriterWriteSint64Field(writer, _s64, 4);
    PBDataWriterWriteFixed32Field(writer, _f32, 5);
    PBDataWriterWriteSfixed32Field(writer, _sf32, 6);
    PBDataWriterWriteFixed64Field(writer, _f64, 7);
    PBDataWriterWriteSfixed64Field(writer, _sf64, 8);
    PBDataWriterWriteInt64Field(writer, _i64, 9);
    PBDataWriterWriteUint64Field(writer, _u64, 10);
    PBWriteInt32Field(writer, _other, 11);
    PBWriteBytesField(writer, _num, 12);
    PBWriteBytesField(writer, _obj, 13);
}

@end

int main(void) { return 0; }
