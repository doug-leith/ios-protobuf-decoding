#import "pbshim.h"

@interface TestJumpElement : PBCodable {
  @public
    NSString *_value;
    struct { unsigned has_value:1; } _has;
}
@end

// See f2_readfrom_element_type/testelement.h for why this must be noinline
// (gotcha 3b) — same requirement here.
extern __attribute__((noinline)) BOOL TestJumpElementReadFrom_core(TestJumpElement *self, PBDataReader *reader);
