#import "pbshim.h"

@interface TestElement : PBCodable {
  @public
    NSString *_value;
    struct { unsigned has_value:1; } _has;
}
@end

// Plain C-linkage per-class ReadAllFrom core (analogous to a real Apple
// generated ReadAllFrom function) — TestContainer's dispatch core calls this
// directly, exactly the way real code statically references the element
// class's reader rather than going through an ObjC message send.
// `noinline` is required: clang -Os will otherwise inline this tiny body
// into -[TestElement readFrom:], erasing the `bl` the tool looks for
// (see ../README.md gotcha 3b).
extern __attribute__((noinline)) BOOL TestElementReadFrom_core(TestElement *self, PBDataReader *reader);
