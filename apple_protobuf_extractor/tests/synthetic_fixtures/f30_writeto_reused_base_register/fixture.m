#import "pbshim.h"

// Ground truth (see expected.py).  Covers proto/arm64cfg.py:_resolve_offset_addr's
// base register (TODO #81 (2)): the writeTo: walk resolves an ivar-offset load
// `ldrsw x8,[x8,#k]` by the value of its base register x8 -- which must be x8's
// NEAREST definition before the load, not the first `adrp x8 ; add x8,x8,#o` in
// the block prefix.
//
// The stack block below makes the compiler materialise the block descriptor's
// address in x8 (`adrp x8,<desc page> ; add x8,x8,#<desc off>`); the same
// register is then reused for the ivar-offset page of _values and _items
// (`adrp x8,<ivar page> ; ldrsw x8,[x8,#k] ; add x1,x20,x8`) in the same walk
// block.  The first-adrp+add resolver read the ivar offset from the descriptor's
// page (an address no ivar-offset variable lives at), so both field numbers
// came out ESTIMATED.  Real case: iOS 27 GeoServices
// -[GEOPairedDeviceSubscriptionStatesSummary writeTo:] (isUpdateAvailable at
// 0x191a891f4, old 0x1e0a94efc vs the ivar's slot 0x1e4567114), whose number
// field 2 was estimated before the fix.
//
//   message TestReusedBase {
//     repeated int64 values = 1;   // packed: &_values passed (add x1, self, off)
//     repeated bytes items = 2;    // NSArray of messages, element class unknown
//   }
//
// The block itself writes no field (PBHandleUnknownField is only there to make it
// capture `writer`, i.e. a stack block with a descriptor).

@interface TestReusedBase : PBCodable {
  @public
    struct { int64_t *list; unsigned long long count; unsigned long long size; } _values;
    NSArray *_items;
}
@end

@implementation TestReusedBase

- (void)writeTo:(PBDataWriter *)writer {
    [[NSDictionary dictionary] enumerateKeysAndObjectsUsingBlock:^(id key, id obj, BOOL *stop) {
        PBHandleUnknownField(writer, 0);
    }];
    PBWritePackedInt64Field(writer, (int64_t *)&_values, 1);
    for (id item in _items) PBWriteMessageField(writer, item, 2);
}

@end

int main(void) { return 0; }
