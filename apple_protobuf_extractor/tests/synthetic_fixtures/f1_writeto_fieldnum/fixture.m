#import "pbshim.h"

// Ground truth (see expected.py):
//   message TestMessage {
//     string first  = 5;
//     string second = 2;
//     string third  = 9;
//   }
//
// Field numbers are deliberately NON-MONOTONIC relative to ivar declaration
// order, so a tool that fell back to naive ivar-order numbering (1,2,3)
// would be caught immediately. Field writes call a plain C-linkage helper
// directly (matches real Apple codegen), not an ObjC message send — see
// ../README.md gotcha 3.

@interface TestMessage : PBCodable {
    NSString *_first;
    NSString *_second;
    NSString *_third;
    struct { unsigned has_first:1; unsigned has_second:1; unsigned has_third:1; } _has;
}
@end

@implementation TestMessage

- (void)writeTo:(PBDataWriter *)writer {
    if (_has.has_first)  PBWriteStringField(writer, _first, 5);
    if (_has.has_second) PBWriteStringField(writer, _second, 2);
    if (_has.has_third)  PBWriteStringField(writer, _third, 9);
    [super writeTo:writer];
}

@end

int main(void) { return 0; }
