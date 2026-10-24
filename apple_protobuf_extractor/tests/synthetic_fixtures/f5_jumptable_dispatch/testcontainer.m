#import "testelement.h"

// Ground truth (see expected.py):
//   message TestJumpContainer {
//     repeated TestJumpElement items = 5;
//   }
//
// Distinct from f2_readfrom_element_type: f2's dispatch core is an if/else
// COMPARE CHAIN (`cmp Wf,#5; b.ne ...`); this one is a real ARM64 JUMP TABLE
// (`sub Wi,Wt,#bias; cmp Wi,#count-1; b.hi oob; adr Rbase; ldrb/ldrh
// Roff,[Rtab,Xi]; add Rbase,Rbase,Roff,lsl#2; br Rbase`), which
// proto/dispatch.py's raw-word scanner (_find_dispatch_cluster,
// _decode_readfrom_jumptable) decodes separately from the compare-chain path
// (proto/dispatch.py:_dominance_field_of) — different recovery code,
// needs its own ground truth. A `switch` over 8 densely-numbered field cases
// (1..8) at -Os reliably compiles to this jump-table shape (confirmed by
// disassembly at fixture-authoring time — see README.md gotcha 4b: always
// verify, don't assume). Fields 1-4 and 6-8 are unknown-field filler arms
// that only exist to give the table enough entries to be a real jump table
// rather than a 1-2 case if/else; field 5 is the one under test.

@interface TestJumpContainer : PBCodable {
  @public
    NSMutableArray *_items;
}
@end

extern void TestJumpContainerReadFrom_core(TestJumpContainer *self, PBDataReader *reader);

@implementation TestJumpContainer

- (void)writeTo:(PBDataWriter *)writer {
    for (id elem in _items) {
        PBWriteMessageField(writer, elem, 5);
    }
}

- (BOOL)readFrom:(PBDataReader *)reader {
    TestJumpContainerReadFrom_core(self, reader);
    return YES;
}

@end

__attribute__((noinline)) void TestJumpContainerReadFrom_core(TestJumpContainer *self, PBDataReader *reader) {
    uint32_t tag = PBReadTag(reader);
    uint32_t field = tag >> 3;
    switch (field) {
        case 1: PBHandleUnknownField(self, field); break;
        case 2: PBHandleUnknownField(self, field); break;
        case 3: PBHandleUnknownField(self, field); break;
        case 4: PBHandleUnknownField(self, field); break;
        case 5: {
            TestJumpElement *e = [TestJumpElement new];
            TestJumpElementReadFrom_core(e, reader);
            if (self->_items == nil) {
                self->_items = [NSMutableArray new];
            }
            [self->_items addObject:e];
            break;
        }
        case 6: PBHandleUnknownField(self, field); break;
        case 7: PBHandleUnknownField(self, field); break;
        case 8: PBHandleUnknownField(self, field); break;
        default: PBHandleUnknownField(self, field); break;
    }
}

int main(void) { return 0; }
