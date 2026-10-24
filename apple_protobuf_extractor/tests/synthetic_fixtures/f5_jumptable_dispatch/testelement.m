#import "testelement.h"

@implementation TestJumpElement

- (void)writeTo:(PBDataWriter *)writer {
    if (_has.has_value) PBWriteStringField(writer, _value, 1);
}

- (BOOL)readFrom:(PBDataReader *)reader {
    return TestJumpElementReadFrom_core(self, reader);
}

@end

__attribute__((noinline)) BOOL TestJumpElementReadFrom_core(TestJumpElement *self, PBDataReader *reader) {
    (void)reader;
    self->_has.has_value = 1;
    return YES;
}
