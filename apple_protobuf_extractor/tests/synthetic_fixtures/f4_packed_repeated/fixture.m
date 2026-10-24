#import "pbshim.h"

// Ground truth (see expected.py):
//   message TestPackedList {
//     repeated int32 values = 7 [packed=true];
//   }
//
// Apple's packed-repeated scalar storage is a C array struct
// `{?="list"^i"count"Q"size"Q}` — proto/protocore.py:_is_packed_list_enc
// recognizes this SHAPE alone (no disassembly dependency): the element C-type
// (`^i`) names the proto scalar directly, and the shape itself implies the
// REPEATED label (proto/protocore.py:_field_label). This fixture's job is
// verifying that pure-ivar-encoding decision on a genuinely-compiled class,
// distinct from every other fixture here (all of which depend on writeTo:/
// readFrom: disassembly for their key recovery). The field NUMBER (7) still
// comes from the ordinary writeTo: CFG walk, unaffected by the packed shape.

extern void PBWritePackedInt32Field(PBDataWriter *writer, int32_t *list, uint32_t tag);

@interface TestPackedList : PBCodable {
    struct {
        int32_t *list;
        unsigned long long count;
        unsigned long long size;
    } _values;
    struct { unsigned has_values:1; } _has;
}
@end

@implementation TestPackedList

- (void)writeTo:(PBDataWriter *)writer {
    if (_has.has_values) PBWritePackedInt32Field(writer, _values.list, 7);
}

@end

int main(void) { return 0; }
