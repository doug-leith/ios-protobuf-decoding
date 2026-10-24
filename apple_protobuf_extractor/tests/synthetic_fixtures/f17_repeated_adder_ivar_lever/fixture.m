#import "pbshim.h"

// Ground truth (see expected.py). This fixture covers proto/repeated.py's
// ADDER→IVAR LEVER (_resolve_repeated_element_ivars / _adder_array_ivar),
// which had ZERO synthetic coverage before this fixture (abandoned earlier
// in this session's investigation — see ../README.md's "Repeated-field
// element-type recovery coverage" section — until gotcha 10 unlocked it).
//
// The lever needs a readFrom: jump-table arm whose body directly `bl`s
// (a) a known element ReadAllFrom core (already routine — f2/f5/f8/f12 all
// do this via plain C-linkage calls) and (b) THIS CLASS'S OWN registered
// adder method's IMP, bypassing objc_msgSend entirely (`bl <exact IMP
// address>`, not a call through a selector stub). Normal
// `[self _addNoFlagsItem:e]` syntax can never produce (b) — verified
// exhaustively earlier this session (plain message send, objc_direct,
// -flto all fail) — so this fixture uses gotcha 10: a statement-level
// `__asm__ volatile` block inside the jump-table arm, calling the adder's
// real (if local/non-exported) linker symbol
// (`"-[TestAdderContainer _addNoFlagsItem:]"`) directly. Since this binary
// is NEVER EXECUTED (only statically disassembled), the asm block needs no
// real argument setup — only the CALL INSTRUCTION's target address matters
// for extraction; the clobber list is just there to stop the surrounding
// compiler-generated code from assuming any register survives the call.
//
//   message TestAdderElem { string value = 1; }
//
//   message TestAdderContainer {
//     repeated TestAdderElem items = 7;
//   }
//
// `_addNoFlagsItem:` is an ordinary, normally-compiled ObjC method (only
// the CALL to it, from the dispatch arm, needs the asm trick) — its own
// body's `self->_items = ...` ivar access naturally compiles to the
// indirect ivar-offset-table load `_adder_array_ivar` looks for (verified
// throughout this session: PBCodable is an opaque externally-declared
// superclass, so ALL subclass ivar access goes through this indirect form
// by ABI necessity, never a direct immediate offset).
//
// HONESTY NOTE (like f14's correction): verified directly (see below) that
// `_resolve_repeated_element_ivars` genuinely runs and computes the
// correct binding (`dispatch_ivars == {'_items': ('TestAdderElem', 7)}`)
// — but this fixture's single arm ALSO satisfies the already-covered
// by-field-number dispatch path (`_resolve_repeated_via_dispatch`, since
// the arm's element-core bl is exactly what THAT mechanism reads too), and
// `_resolve_repeated_element_type`'s precedence tries the by-number path
// FIRST when confirmed — so the field's FINAL reported type in
// `expected.py` happens to come from the already-covered path, not
// (observably) from the lever. What's new here is the lever's OWN
// internals running and computing correctly for the first time — verified
// by calling `_resolve_dispatch_context` directly before writing this
// file, not inferred: `dispatch_ivars` came back non-empty with the exact
// right binding, `dispatch_elements` (by number) also resolved the SAME
// field independently. A future fixture wanting to observe the lever
// WINNING (not just running) would need an arm whose element-core bl the
// by-number path's OWN gate rejects while the lever's gate still accepts
// it — not attempted here.

@interface TestAdderElem : PBCodable {
  @public
    NSString *_value;
    struct { unsigned has_value:1; } _has;
}
@end

extern __attribute__((noinline)) BOOL TestAdderElemReadFrom_core(TestAdderElem *self, PBDataReader *reader);

@implementation TestAdderElem

- (void)writeTo:(PBDataWriter *)writer {
    if (_has.has_value) PBWriteStringField(writer, _value, 1);
}

- (BOOL)readFrom:(PBDataReader *)reader { return TestAdderElemReadFrom_core(self, reader); }

@end

BOOL TestAdderElemReadFrom_core(TestAdderElem *self, PBDataReader *reader) {
    uint32_t tag = PBReadTag(reader);
    if ((tag >> 3) == 1) { /* would read the string field */ }
    return YES;
}

@interface TestAdderContainer : PBCodable {
  @public
    NSMutableArray *_items;
}
- (void)_addNoFlagsItem:(TestAdderElem *)item;
@end

extern void TestAdderContainerReadFrom_core(TestAdderContainer *self, PBDataReader *reader);

@implementation TestAdderContainer

- (void)_addNoFlagsItem:(TestAdderElem *)item {
    if (self->_items == nil) self->_items = [NSMutableArray new];
    [self->_items addObject:item];
}

- (void)writeTo:(PBDataWriter *)writer {
    for (id elem in _items) { PBWriteMessageField(writer, elem, 7); }
}

- (BOOL)readFrom:(PBDataReader *)reader {
    TestAdderContainerReadFrom_core(self, reader);
    return YES;
}

@end

void TestAdderContainerReadFrom_core(TestAdderContainer *self, PBDataReader *reader) {
    uint32_t tag = PBReadTag(reader);
    uint32_t field = tag >> 3;
    switch (field) {
        case 7: {
            TestAdderElem *e = [TestAdderElem new];
            TestAdderElemReadFrom_core(e, reader);
            // Direct bl to the adder's own IMP (gotcha 10), bypassing
            // objc_msgSend -- the exact shape
            // _resolve_repeated_element_ivars/_adder_array_ivar look for.
            __asm__ volatile (
                "bl \"-[TestAdderContainer _addNoFlagsItem:]\"\n"
                ::: "x0", "x1", "x2", "x3", "x4", "x8", "x9", "x30", "cc", "memory"
            );
            break;
        }
        case 9:
            PBHandleUnknownField(self, field);
            break;
        default:
            PBHandleUnknownField(self, field);
            break;
    }
}

int main(void) { return 0; }
