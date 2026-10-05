// Opaque, separately-compiled definitions for fixture.m's begin/end-nested
// helpers. Kept in their own translation unit (no -flto in this suite's
// build flags) specifically so fixture.m's compiler CANNOT see these bodies
// and dead-argument-eliminate the call-site argument setup -- with a visible
// empty body in the SAME file, clang dropped the `add x1,sp,#N`/`mov w2,#N`
// setup entirely (confirmed by trying that first: the real Apple call-site
// shape vanished). A real, unexported Apple helper is genuinely opaque to
// its caller's TU the same way an object file boundary is here.
#include <stdint.h>

void TestBeginNestedField(void *writer, void *scratch, uint32_t tag) {
    (void)writer; (void)scratch; (void)tag;
}

void TestEndNestedField(void *writer, void *scratch) {
    (void)writer; (void)scratch;
}
