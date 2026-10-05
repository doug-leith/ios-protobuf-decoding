#import "pbshim.h"

// Opaque helpers, deliberately in their OWN translation unit (as f22's are) so
// the compiler cannot see through them and drop the call-site argument setup.
//
// PBAppendMessageAtOffset / PBReadEmbeddedMessage are the GENERIC,
// ivar-offset-parameterised "read an embedded message / append it to the
// array at this byte offset" helpers a newer Apple toolchain's dispatch arms
// call instead of a per-class accessor or a per-class ReadAllFrom core: shared
// verbatim across unrelated classes and fields.

__attribute__((noinline)) void PBAppendMessageAtOffset(id self, uint32_t off, id obj) {
    void **slot = (void **)((char *)(__bridge void *)self + off);
    if (*slot == NULL) *slot = (void *)CFBridgingRetain([NSMutableArray new]);
    [(__bridge NSMutableArray *)*slot addObject:obj];
}

__attribute__((noinline)) void PBReadEmbeddedMessage(PBDataReader *r, id msg) { [msg readFrom:r]; }

__attribute__((noinline)) int PBReaderMode(PBDataReader *r) {
    return (int)((uintptr_t)(__bridge void *)r % 2);
}

__attribute__((noinline)) int PBValidateReader(PBDataReader *r) { return r != nil; }

__attribute__((noinline)) void PBUseTable(const uint8_t *t) { (void)t; }
