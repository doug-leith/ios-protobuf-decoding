#import "pbshim.h"

// Ground truth (see expected.py). Covers the compare-chain tier of
// proto/dispatch.py:_find_dispatch_core_via_wrapper for the NEWEST arm64e
// toolchain's engines (iPhone17,3 / macOS 27), which dispatch with a compare
// TREE on the field number and — unlike every engine this tier had seen —
// have NO `cmp Wn,#N; b.hi` field-count range guard. The tier used to require
// that guard (`_find_field_count(core) > 0`) as one of its ownership signals,
// so on those builds 133 message fields in 95 GeoServices classes degraded to
// `bytes`. It now accepts a guard-less engine only when it ALSO loads the
// class's OWN ivar-offset variables (by slot address).
//
//   message TestGrElemA { optional string value = 1; }
//   message TestGrElemB { optional string label = 1; }
//
//   message TestGrContainer {          // engine, csel call site, own ivars
//     repeated TestGrElemA alphas = 5;     -> MUST resolve (element type)
//     repeated TestGrElemB betas  = 6;     -> MUST resolve
//   }
//   message TestGrPlainCall {          // same engine shape, but a plain
//     repeated TestGrElemA gammas = 5;     call site (no csel) and no own
//   }                                      accessor -> MUST stay bytes
//   message TestGrForeignEngine {      // csel call site, but the engine it
//     repeated TestGrElemA deltas = 5;     calls stores into ANOTHER class's
//   }                                      ivars -> MUST stay bytes
//
// TestGrContainer reproduces the real shape: readFrom: tail-calls a thin
// wrapper (early-return fast path, then a `bl` to the engine with a `csel`
// between two __const data tables); the engine reads a tag, compares
// `tag >> 3` against 5 and 6 in a tree, and each arm `bl`s the element's own
// ReadFrom core then appends into the class's own ivar array. No own accessor
// is ever called, and there is no range guard (verified by disassembly: the
// engine has no `cmp;b.hi` — README gotcha 4).
//
// The two negatives isolate WHICH signal blocks acceptance:
//   * TestGrPlainCall's wrapper calls a copy of the engine with a plain table
//     argument -> `_call_site_selects_data_table` is False;
//   * TestGrForeignEngine's wrapper has the csel, but calls TestGrContainer's
//     engine with its own instance, so the engine loads TestGrContainer's
//     ivar-offset variables, never TestGrForeignEngine's -> the ownership
//     check rejects it (this is the "wrapper calls someone else's reader"
//     case the check exists for). Field names are deliberately unrelated to
//     the element class names so the classlist name-suffix fallback can't
//     resolve them behind the tier's back.
//
// Built for arm64 and arm64e (testgr / testgr_e).

@interface TestGrElemA : PBCodable {
  @public
    NSString *_value;
    struct { unsigned has_value:1; } _has;
}
@end
@interface TestGrElemB : PBCodable {
  @public
    NSString *_label;
    struct { unsigned has_label:1; } _has;
}
@end

extern __attribute__((noinline)) BOOL TestGrElemAReadFrom_core(TestGrElemA *self, PBDataReader *reader);
extern __attribute__((noinline)) BOOL TestGrElemBReadFrom_core(TestGrElemB *self, PBDataReader *reader);

@implementation TestGrElemA
- (void)writeTo:(PBDataWriter *)w { if (_has.has_value) PBWriteStringField(w, _value, 1); }
- (BOOL)readFrom:(PBDataReader *)r { return TestGrElemAReadFrom_core(self, r); }
@end
@implementation TestGrElemB
- (void)writeTo:(PBDataWriter *)w { if (_has.has_label) PBWriteStringField(w, _label, 1); }
- (BOOL)readFrom:(PBDataReader *)r { return TestGrElemBReadFrom_core(self, r); }
@end

BOOL TestGrElemAReadFrom_core(TestGrElemA *self, PBDataReader *reader) {
    uint32_t tag = PBReadTag(reader);
    if ((tag >> 3) == 1) { /* would read the string field */ }
    return YES;
}
BOOL TestGrElemBReadFrom_core(TestGrElemB *self, PBDataReader *reader) {
    uint32_t tag = PBReadTag(reader);
    if ((tag >> 3) == 1) { /* would read the string field */ }
    return YES;
}

extern int PBReaderMode(PBDataReader *r);
extern int PBValidateReader(PBDataReader *r);
extern void PBUseTable(const uint8_t *t);

// Two read-only tables. kTabB is page-aligned so the wrapper's `csel` needs an
// INDEPENDENT `adrp+add` for each — adjacent, the compiler derives the second
// address from the first's page register (`add x9, x8, #16`) and the call site
// no longer has the real toolchain's two-independent-constants shape (found
// building this fixture: the very first build had exactly that layout).
static const uint8_t kTabA[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
static const uint8_t kTabB[16] __attribute__((aligned(4096))) =
    {16,15,14,13,12,11,10,9,8,7,6,5,4,3,2,1};

// ── TestGrContainer: resolves ───────────────────────────────────────────────
@interface TestGrContainer : PBCodable {
  @public
    NSMutableArray *_alphas;
    NSMutableArray *_betas;
}
@end
extern __attribute__((noinline)) BOOL TestGrContainerReadFrom_wrapper(TestGrContainer *self, PBDataReader *reader);
extern __attribute__((noinline)) void TestGrEngine(TestGrContainer *self, PBDataReader *reader, const uint8_t *table);

@implementation TestGrContainer
- (void)writeTo:(PBDataWriter *)w {
    for (id e in _alphas) PBWriteMessageField(w, e, 5);
    for (id e in _betas) PBWriteMessageField(w, e, 6);
}
- (BOOL)readFrom:(PBDataReader *)r { return TestGrContainerReadFrom_wrapper(self, r); }
@end

BOOL TestGrContainerReadFrom_wrapper(TestGrContainer *self, PBDataReader *reader) {
    if (!PBValidateReader(reader)) return NO;
    TestGrEngine(self, reader, PBReaderMode(reader) ? kTabA : kTabB);
    return YES;
}

// The engine: a compare TREE on the field number, NO range guard. Each arm
// bl's the element's own ReadFrom core, then appends into an OWN ivar array.
void TestGrEngine(TestGrContainer *self, PBDataReader *reader, const uint8_t *table) {
    uint32_t tag = PBReadTag(reader);
    uint32_t field = tag >> 3;
    if (field == 5) {
        TestGrElemA *e = [TestGrElemA new];
        TestGrElemAReadFrom_core(e, reader);
        if (self->_alphas == nil) self->_alphas = [NSMutableArray new];
        [self->_alphas addObject:e];
    } else if (field == 6) {
        TestGrElemB *e = [TestGrElemB new];
        TestGrElemBReadFrom_core(e, reader);
        if (self->_betas == nil) self->_betas = [NSMutableArray new];
        [self->_betas addObject:e];
    } else {
        PBHandleUnknownField(self, field);
    }
    PBUseTable(table);      // keeps the argument live so the call site keeps its setup
}

// ── TestGrPlainCall: same engine shape, plain call site -> stays bytes ──────
@interface TestGrPlainCall : PBCodable {
  @public
    NSMutableArray *_gammas;
}
@end
extern __attribute__((noinline)) BOOL TestGrPlainCallReadFrom_wrapper(TestGrPlainCall *self, PBDataReader *reader);
extern __attribute__((noinline)) void TestGrPlainEngine(TestGrPlainCall *self, PBDataReader *reader, const uint8_t *table);

@implementation TestGrPlainCall
- (void)writeTo:(PBDataWriter *)w {
    for (id e in _gammas) PBWriteMessageField(w, e, 5);
}
- (BOOL)readFrom:(PBDataReader *)r { return TestGrPlainCallReadFrom_wrapper(self, r); }
@end

BOOL TestGrPlainCallReadFrom_wrapper(TestGrPlainCall *self, PBDataReader *reader) {
    if (!PBValidateReader(reader)) return NO;
    TestGrPlainEngine(self, reader, kTabA);          // ONE table: no csel
    return YES;
}

void TestGrPlainEngine(TestGrPlainCall *self, PBDataReader *reader, const uint8_t *table) {
    uint32_t tag = PBReadTag(reader);
    uint32_t field = tag >> 3;
    if (field == 5) {
        TestGrElemA *e = [TestGrElemA new];
        TestGrElemAReadFrom_core(e, reader);
        if (self->_gammas == nil) self->_gammas = [NSMutableArray new];
        [self->_gammas addObject:e];
    } else {
        PBHandleUnknownField(self, field);
    }
    PBUseTable(table);      // keeps the argument live so the call site keeps its setup
}

// ── TestGrForeignEngine: csel call site, but calls ANOTHER class's engine ───
@interface TestGrForeignEngine : PBCodable {
  @public
    NSMutableArray *_deltas;
}
@end
extern __attribute__((noinline)) BOOL TestGrForeignEngineReadFrom_wrapper(TestGrForeignEngine *self, PBDataReader *reader);

@implementation TestGrForeignEngine
- (void)writeTo:(PBDataWriter *)w {
    for (id e in _deltas) PBWriteMessageField(w, e, 5);
}
- (BOOL)readFrom:(PBDataReader *)r { return TestGrForeignEngineReadFrom_wrapper(self, r); }
@end

BOOL TestGrForeignEngineReadFrom_wrapper(TestGrForeignEngine *self, PBDataReader *reader) {
    if (!PBValidateReader(reader)) return NO;
    // csel between two data tables, exactly like TestGrContainer's wrapper —
    // but the engine called is TestGrContainer's, which stores into
    // TestGrContainer's ivars, not this class's.
    TestGrEngine((TestGrContainer *)(id)self, reader, PBReaderMode(reader) ? kTabA : kTabB);
    return YES;
}

int main(void) { return 0; }
