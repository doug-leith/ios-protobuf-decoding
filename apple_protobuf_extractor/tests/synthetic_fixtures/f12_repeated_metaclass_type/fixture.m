#import "pbshim.h"

// Ground truth (see expected.py). This fixture covers proto/repeated.py's
// PRIMARY, highest-real-world-usage repeated-message element-type resolver
// (Strategy 1 of _repeated_element_type: the `+[Cls xyzType]` metaclass
// method, read via _class_from_type_method_imp), which had ZERO synthetic
// coverage before this fixture — f2/f5/f8 (the existing repeated-message
// fixtures) all resolve their element type via readFrom: dispatch instead
// (Strategy 1's sibling/fallback mechanism). Per repeated.py's own measured
// tally (a per-path census across three real binaries, see the "KEEP THIS —
// it does real work" comment above _repeated_element_type's Strategy 2):
//
//   path                       GeoServices  locationd  CoreLocationProtobuf
//   dispatch (readFrom:, addr)      17          23            27
//   metaclass +xyzType (this)      503           5            16
//
// i.e. the metaclass method is the DOMINANT real-world path for GeoServices
// (503 fields) and CoreLocationProtobuf (16 fields), yet every existing
// fixture only exercises the minority dispatch path.
//
//   message TestRepElem {
//     string value = 1;
//   }
//
//   message TestRepContainer {
//     repeated TestRepElem items = 6;
//   }
//
// TestRepContainer deliberately declares NO readFrom: override (only
// PBCodable's abstract declaration is inherited) — so the readFrom:
// dispatch path categorically cannot contribute an element-type answer
// here (proto/dispatch.py has no core to walk), making this an unambiguous
// test of the metaclass path alone. writeTo:'s CFG walk still confirms the
// field NUMBER independently (see f2_readfrom_element_type's docstring for
// why writeTo: can give the number but never the element TYPE — every
// message-typed field, singular or repeated, goes through the same generic
// PBWriteMessageField helper).
//
// +(Class)itemType follows Apple's real convention documented in
// proto/repeated.py:_class_from_type_method_imp: `adrp x8,<page>;
// ldr x0,[x8,#off]; b <thunk>` — a classref-table load, tail-called.
// Verified by disassembly (gotcha 4) to compile exactly that way from
// `+(Class)itemType { return [TestRepElem class]; }` on the first attempt.
//
// Selector name convention: ivar `_items` -> proto name "items" -> singular
// "item" (trailing 's' stripped) -> type selector "itemType", matching
// _repeated_element_type's `f"{singular}Type"` check.

@interface TestRepElem : PBCodable {
  @public
    NSString *_value;
    struct { unsigned has_value:1; } _has;
}
@end

@implementation TestRepElem

- (void)writeTo:(PBDataWriter *)writer {
    if (_has.has_value) PBWriteStringField(writer, _value, 1);
}

@end

@interface TestRepContainer : PBCodable {
  @public
    NSMutableArray *_items;
}
+ (Class)itemType;
@end

@implementation TestRepContainer

+ (Class)itemType { return [TestRepElem class]; }

- (void)writeTo:(PBDataWriter *)writer {
    for (id elem in _items) {
        PBWriteMessageField(writer, elem, 6);
    }
}

@end

int main(void) { return 0; }
