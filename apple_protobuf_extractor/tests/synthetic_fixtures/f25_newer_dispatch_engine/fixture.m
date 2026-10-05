#import "pbshim.h"

// Ground truth (see expected.py). Exercises, on REAL compiled code, three of
// proto/dispatch.py's newer-toolchain mechanisms that until now had only
// hand-built raw-word tests (tests/test_readfrom_dispatch.py):
//
//   1. multi-jump-table table-base aliasing (_decode_readfrom_jumptable's
//      reaching-definition table base) — the engine below holds TWO
//      independent jump tables whose `adrp+add` table bases land in the SAME
//      scratch register (x9, confirmed by disassembly); resolving the
//      field-dispatch table as "the first adrp+add into x9 in the function"
//      reads the WIRE-TYPE table's data instead;
//   2. the classref fallback (_scan_arm_for_core_or_classref /
//      _walk_jumptable_arms / _any_arm_loads_known_classref) — no arm calls
//      an own-class accessor, and none `bl`s a per-class ReadAllFrom core:
//      each arm loads a classref for its element class (`[Elem alloc]`) and
//      then calls the GENERIC ivar-offset-parameterised helpers in
//      helpers.m; the wrapper's call site picks one of two `__const` data
//      tables via `csel` (_call_site_selects_data_table), which together
//      with the classref stands in for the accessor-based ownership check;
//   3. _find_dispatch_cluster's function-boundary bound — TestNtShortGuard
//      is a short function with NO jump table placed immediately before the
//      engine (which does have one); a scan that ignores the function's own
//      `ret` finds the engine's cluster and reports it as the guard's.
//
//   message TestNtElemA { optional string value = 1; }
//   message TestNtElemB { optional string label = 1; }
//   message TestNtContainer {
//     repeated TestNtElemA alphas = 5;
//     repeated TestNtElemB betas  = 6;
//   }
//
// The shapes mirror what was traced on real GeoServices classes
// (GEOPDBusinessHours, GEORPFeedbackDetails, ...): readFrom: tail-calls a thin
// wrapper with an early-return fast path, whose `bl` to the engine selects a
// data table by `csel`; the engine's field switch is 1..8 (bias 1) so it
// compiles to `sub; cmp; b.hi; adr; ldrb; add; br` (f5's proven shape).
// Built twice: plain arm64 (testnde) and arm64e (testnde_e — PAC-signed code,
// chained-fixup format 12, and a signed-difference jump table, `ldrsw`
// instead of `ldrb`, which is the idiom the real newer-toolchain images use).
// Neither build models the iPhone17,3 / macOS-27 engines, which dispatch with
// a compare TREE on the field number (no jump table, no range guard) rather
// than a jump table — see LIMITATIONS.md item 11. (Neither do they use
// PAC-authenticated indirect dispatch: the `braa` seen in those images is in
// the runtime's call stubs, not in any readFrom: engine examined.)
//
// Real compiled code, this repo's normal (Xcode 15) clang at -Os; the shapes
// above were verified by disassembly before expected.py was written
// (README gotcha 4) -- see the README's f25 entry.

@interface TestNtElemA : PBCodable {
  @public
    NSString *_value;
    struct { unsigned has_value:1; } _has;
}
@end
@interface TestNtElemB : PBCodable {
  @public
    NSString *_label;
    struct { unsigned has_label:1; } _has;
}
@end

extern __attribute__((noinline)) BOOL TestNtElemAReadFrom_core(TestNtElemA *self, PBDataReader *reader);
extern __attribute__((noinline)) BOOL TestNtElemBReadFrom_core(TestNtElemB *self, PBDataReader *reader);

@implementation TestNtElemA
- (void)writeTo:(PBDataWriter *)w { if (_has.has_value) PBWriteStringField(w, _value, 1); [super writeTo:w]; }
- (BOOL)readFrom:(PBDataReader *)r { return TestNtElemAReadFrom_core(self, r); }
@end
@implementation TestNtElemB
- (void)writeTo:(PBDataWriter *)w { if (_has.has_label) PBWriteStringField(w, _label, 1); [super writeTo:w]; }
- (BOOL)readFrom:(PBDataReader *)r { return TestNtElemBReadFrom_core(self, r); }
@end

BOOL TestNtElemAReadFrom_core(TestNtElemA *self, PBDataReader *reader) {
    uint32_t tag = PBReadTag(reader);
    if ((tag >> 3) == 1) { /* would read the string field */ }
    return YES;
}
BOOL TestNtElemBReadFrom_core(TestNtElemB *self, PBDataReader *reader) {
    uint32_t tag = PBReadTag(reader);
    if ((tag >> 3) == 1) { /* would read the string field */ }
    return YES;
}

extern void PBAppendMessageAtOffset(id self, uint32_t off, id obj);
extern void PBReadEmbeddedMessage(PBDataReader *r, id msg);
extern int PBReaderMode(PBDataReader *r);
extern int PBValidateReader(PBDataReader *r);
extern void PBUseTable(const uint8_t *t);

@interface TestNtContainer : PBCodable {
  @public
    NSMutableArray *_alphas;   // ivar offset 8
    NSMutableArray *_betas;    // ivar offset 16
}
@end

// Two distinct read-only tables in __TEXT,__const (not __text): the wrapper's
// call site chooses between them with a `csel`.
static const uint8_t kTabA[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
static const uint8_t kTabB[16] = {16,15,14,13,12,11,10,9,8,7,6,5,4,3,2,1};

extern __attribute__((noinline)) BOOL TestNtContainerReadFrom_wrapper(TestNtContainer *self, PBDataReader *reader);
extern __attribute__((noinline)) int TestNtShortGuard(PBDataReader *reader);
extern __attribute__((noinline)) void TestNtEngine(TestNtContainer *self, PBDataReader *reader, const uint8_t *table);

@implementation TestNtContainer
- (void)writeTo:(PBDataWriter *)w {
    for (id e in _alphas) PBWriteMessageField(w, e, 5);
    for (id e in _betas) PBWriteMessageField(w, e, 6);
    [super writeTo:w];
}
- (BOOL)readFrom:(PBDataReader *)r { return TestNtContainerReadFrom_wrapper(self, r); }
@end

// Thin wrapper: an early-return fast path, THEN the engine call selecting one
// of two data tables. The guard call precedes the engine call, so the
// wrapper's own callee scan visits the short guard function first.
BOOL TestNtContainerReadFrom_wrapper(TestNtContainer *self, PBDataReader *reader) {
    if (!PBValidateReader(reader)) return NO;
    if (!TestNtShortGuard(reader)) return NO;
    TestNtEngine(self, reader, PBReaderMode(reader) ? kTabA : kTabB);
    return YES;
}

// Short, leaf-shaped, NO jump table -- and placed immediately before the
// engine (source order == text order here), whose jump-table cluster lies a
// few instructions past this function's own `ret`.
int TestNtShortGuard(PBDataReader *reader) {
    return PBReaderMode(reader) != 2;
}

void TestNtEngine(TestNtContainer *self, PBDataReader *reader, const uint8_t *table) {
    uint32_t tag = PBReadTag(reader);
    // First jump table: the wire type (cases 0..7, bias 0 -- no feeding `sub`).
    // Its `adrp+add` table base lands in the same register as the field
    // switch's below.
    switch (tag & 7) {
        case 0: PBUseTable(table); break;
        case 1: PBUseTable(table + 1); break;
        case 2: PBUseTable(table + 2); break;
        case 3: PBUseTable(table + 3); break;
        case 4: PBUseTable(table + 4); break;
        case 5: PBUseTable(table + 5); break;
        case 6: PBUseTable(table + 6); break;
        case 7: PBUseTable(table + 7); break;
    }
    // Second jump table: the field number (cases 1..8, bias 1). Fields 5/6 are
    // the two repeated-message arms; each loads its element class's classref
    // and calls ONLY the generic helpers -- no own accessor, no ReadAllFrom
    // core.
    uint32_t field = tag >> 3;
    switch (field) {
        case 1: PBHandleUnknownField(self, field); break;
        case 2: PBHandleUnknownField(self, field); break;
        case 3: PBHandleUnknownField(self, field); break;
        case 4: PBHandleUnknownField(self, field); break;
        case 5: {
            id e = [TestNtElemA alloc];
            PBReadEmbeddedMessage(reader, e);
            PBAppendMessageAtOffset(self, 8, e);
            break;
        }
        case 6: {
            id e = [TestNtElemB alloc];
            PBReadEmbeddedMessage(reader, e);
            PBAppendMessageAtOffset(self, 16, e);
            break;
        }
        case 7: PBHandleUnknownField(self, field); break;
        case 8: PBHandleUnknownField(self, field); break;
        default: PBHandleUnknownField(self, field); break;
    }
}

int main(void) { return 0; }
