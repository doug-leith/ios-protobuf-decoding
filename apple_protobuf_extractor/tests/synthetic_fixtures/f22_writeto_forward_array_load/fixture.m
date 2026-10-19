#import "pbshim.h"

// Ground truth (see expected.py). Written for the writeTo: walk (deleted
// 2026-10-19, TODO #85; expected.py says what covers it now). It covered proto/writeto.py's
// _forward_self_load_off — the "container array" forwarder for an INLINE
// repeated-message field, previously ZERO synthetic coverage (no fixture in
// this suite reached it at all: verified via a monkeypatched trace against
// the real GeoServices/CoreLocationProtobuf/locationd corpus before writing
// this fixture -- 0 hits with a broken probe first, then 80 real hits once
// the probe was fixed to thread ctx._writeto_indeg the way extract_all does).
//
//   message TestForwardContainer {
//     message TestForwardElem {
//       int32 a = 1;
//     }
//     repeated TestForwardElem items = 1;
//   }
//
// REAL Apple shape confirmed by direct disassembly of GeoServices'
// GEOFlyoverRegionVersions._regions (a repeated GEOFlyoverRegion field):
// unlike f8/f12's NSMutableArray-backed repeated-message fields (a
// countByEnumeratingWithState: fast-enumeration loop calling
// PBWriteMessageField per element -- see f8's fixture.m), some repeated
// MESSAGE fields are stored as an INLINE C ARRAY, managed by THREE
// SEPARATE ordinary ivars (`_regions`/`_regionsCount`/`_regionsSpace`,
// confirmed by dumping the real class's ivar list: three independent
// offsets, not one combined struct) -- NOT the single combined-struct
// `{list,count,size}` ivar f4_packed_repeated uses for a packed SCALAR
// list (`_is_packed_list_enc`'s shape), which the compiler lowers
// differently (a precomputed struct-base register, offset-only loads)
// from three independent ivars (each its own ivar-offset variable, loaded
// via a genuine base+register-offset `ldr`) -- confirmed by trying the
// combined-struct form FIRST and finding it produced offset-only loads
// that `_forward_self_load_off`'s own `pl[2] is not None` check rejects.
// writeTo: then emits a raw indexed loop (no objc_msgSend at all) that:
//   1. loads the COUNT ivar once before the loop (the bound);
//   2. inside the loop, calls a BEGIN helper with a small STACK SCRATCH
//      buffer as its value arg (`add x1,sp,#N`) and the CONTAINER field
//      number (1) as its tag arg -- `_value_is_stack_scratch` detects this
//      as a begin-submessage write;
//   3. reloads the ARRAY POINTER ivar from self, JUST AFTER that begin
//      call (the compiler cannot hoist it across the opaque call), and
//      indexes into it for the element's own field writes;
//   4. calls an END helper with the same scratch buffer.
// _forward_self_load_off's job is exactly step 3: scan forward from the
// begin call (stopping at the next `bl`) for the first `ldr Xd,[self,Xoff]`
// and resolve ITS ivar offset as the container field's real offset --
// distinct from the COUNT ivar's offset threaded in from step 1, which is
// what a naive "field number 1 = whatever offset is already tracked" binder
// would wrongly attribute the write to (Issue B: count-vs-array, see the
// function's own docstring).
//
// The begin/end helper functions below are plain, locally-declared C
// externs with made-up names/signatures -- their REAL names in GeoServices
// are unexported local symbols (no `; symbol stub for:` annotation on their
// `bl` in the real disassembly), so extraction never inspects the callee by
// name, only the calling shape (stack-scratch x1, tag in w2 before the
// call). Confirmed via `otool -tV` on the real GEOFlyoverRegionVersions
// binary before writing this fixture, not assumed.
//
// TestForwardElem's own field (`a`) is a PLAIN C STRUCT here, not a
// PBCodable ObjC object (matching the real inline-array-of-structs storage
// -- an object array would need NSMutableArray, which is f8/f12's
// DIFFERENT, already-covered idiom). protocore.py's packed-list-shape
// detector (_is_packed_list_enc) only names SCALAR element types
// (`^i`→int32 etc); a struct element falls back to the accepted `bytes`
// degradation, the same one already documented for a *singular* embedded
// struct field (LIMITATIONS.md (2)) -- this fixture is about the CONTAINER
// field's NUMBER, not its element type, so the degradation is expected and
// not itself under test here.

struct TestForwardElem {
    int32_t a;
    struct { unsigned has_a:1; } has;
};

// Defined opaquely in helpers.m (a separate translation unit) -- see that
// file's header for why a same-file empty body doesn't work here.
extern void TestBeginNestedField(PBDataWriter *writer, void *scratch, uint32_t tag);
extern void TestEndNestedField(PBDataWriter *writer, void *scratch);

@interface TestForwardContainer : PBCodable {
  @public
    struct TestForwardElem *_items;
    unsigned long long _itemsCount;
    unsigned long long _itemsSpace;
    struct { unsigned has_items:1; } _has;
}
@end

@implementation TestForwardContainer

- (void)writeTo:(PBDataWriter *)writer {
    if (_items) {
        for (unsigned long long i = 0; i < _itemsCount; i++) {
            uint64_t scratch = 0;
            TestBeginNestedField(writer, &scratch, 1);
            struct TestForwardElem *e = &_items[i];
            if (e->has.has_a) PBWriteInt32Field(writer, e->a, 1);
            TestEndNestedField(writer, &scratch);
        }
    }
    [super writeTo:writer];
}

@end

int main(void) { return 0; }
