#import "testelement.h"

@implementation TestElement

- (void)writeTo:(PBDataWriter *)writer {
    if (_has.has_value) PBWriteStringField(writer, _value, 1);
}

- (BOOL)readFrom:(PBDataReader *)reader {
    return TestElementReadFrom_core(self, reader);
}

@end

__attribute__((noinline)) BOOL TestElementReadFrom_core(TestElement *self, PBDataReader *reader) {
    (void)reader;
    self->_has.has_value = 1;
    return YES;
}
