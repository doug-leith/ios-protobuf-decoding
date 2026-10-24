#import "pbwiretypes.h"

// Ground truth (see expected.py):
//   message TestWireTypes {
//     sint32   sVal32   = 1;
//     sint64   sVal64   = 2;
//     fixed32  fVal32   = 3;
//     sfixed32 sfVal32  = 4;
//     fixed64  fVal64   = 5;
//     sfixed64 sfVal64  = 6;
//   }
//
// All six ivars decode to the SAME canonical @encode-derived default
// (int32/uint32/int64/uint64) — the true wire-type family is recoverable
// ONLY by disassembling the per-field write-helper each writeTo: field-write
// calls (proto/write_helpers.py:_classify_write_helper), never from the ivar
// shape alone. This fixture exercises the sint32/64 zigzag signal and the
// fixed32/64 tag-build signal, plus the signed-ivar -> sfixed / unsigned-ivar
// -> fixed disambiguation done at the call site
// (proto/extractor.py:_refine_int_wire_form).

@interface TestWireTypes : PBCodable {
    int32_t  _sVal32;
    int64_t  _sVal64;
    uint32_t _fVal32;
    int32_t  _sfVal32;
    uint64_t _fVal64;
    int64_t  _sfVal64;
    struct {
        unsigned has_sVal32:1;
        unsigned has_sVal64:1;
        unsigned has_fVal32:1;
        unsigned has_sfVal32:1;
        unsigned has_fVal64:1;
        unsigned has_sfVal64:1;
    } _has;
}
@end

@implementation TestWireTypes

- (void)writeTo:(PBDataWriter *)writer {
    if (_has.has_sVal32)  PBWriteSInt32Field(writer, _sVal32, 1);
    if (_has.has_sVal64)  PBWriteSInt64Field(writer, _sVal64, 2);
    if (_has.has_fVal32)  PBWriteFixed32Field(writer, _fVal32, 3);
    if (_has.has_sfVal32) PBWriteFixed32Field(writer, (uint32_t)_sfVal32, 4);
    if (_has.has_fVal64)  PBWriteFixed64Field(writer, _fVal64, 5);
    if (_has.has_sfVal64) PBWriteFixed64Field(writer, (uint64_t)_sfVal64, 6);
}

@end

int main(void) { return 0; }
