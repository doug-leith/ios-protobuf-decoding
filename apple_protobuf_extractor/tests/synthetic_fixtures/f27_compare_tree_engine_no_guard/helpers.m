#import "pbshim.h"

// Opaque helpers in their own translation unit (as f22/f25's are) so the
// compiler cannot see through them and drop the call-site argument setup.

__attribute__((noinline)) int PBReaderMode(PBDataReader *r) {
    return (int)((uintptr_t)(__bridge void *)r % 2);
}

__attribute__((noinline)) int PBValidateReader(PBDataReader *r) { return r != nil; }

__attribute__((noinline)) void PBUseTable(const uint8_t *t) { (void)t; }
