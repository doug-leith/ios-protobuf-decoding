#import "testelement.h"

// Ground truth (see expected.py):
//   message TestContainer {
//     repeated TestElement testElements = 5;
//   }
//
// writeTo: gives the field NUMBER (5); it can NEVER give the element's
// concrete TYPE, because every message-typed field — singular or repeated,
// whatever the element class — goes through the SAME generic write-message
// helper (PBWriteMessageField here). readFrom: is the only static source for
// the element type, because it must statically reference the element class's
// own reader to construct instances. See proto/repeated.py
// _resolve_repeated_via_dispatch's docstring for the full argument.

@interface TestContainer : PBCodable {
  @public
    NSMutableArray *_testElements;
}
@end

extern void TestContainerReadFrom_core(TestContainer *self, PBDataReader *reader);

@implementation TestContainer

- (void)writeTo:(PBDataWriter *)writer {
    for (id elem in _testElements) {
        PBWriteMessageField(writer, elem, 5);
    }
    [super writeTo:writer];
}

- (BOOL)readFrom:(PBDataReader *)reader {
    TestContainerReadFrom_core(self, reader);
    return YES;
}

@end

void TestContainerReadFrom_core(TestContainer *self, PBDataReader *reader) {
    uint32_t tag = PBReadTag(reader);
    uint32_t field = tag >> 3;
    if (field == 5) {
        TestElement *e = [TestElement new];
        TestElementReadFrom_core(e, reader);
        if (self->_testElements == nil) {
            self->_testElements = [NSMutableArray new];
        }
        [self->_testElements addObject:e];
    } else if (field == 9) {
        // Second dispatch arm + opaque fallback below force clang to
        // materialize `lsr Wf,Wtag,#3` instead of folding the single
        // `field==5` compare into a masked compare — see README.md gotcha 4b.
        PBHandleUnknownField(self, field);
    } else {
        PBHandleUnknownField(self, field);
    }
}

int main(void) { return 0; }
