#import "pbshim.h"

// Ground truth (see expected.py). This fixture covers proto/dispatch.py's
// THICK-WRAPPER-VS-DIRECT-CORE PICKER (_core_resolves_compare_chain, used
// by _locate_dispatch_arms), plus the wrapper-discovery machinery it
// depends on (_find_dispatch_core_via_wrapper's compare-chain branch,
// _func_calls_own_method). Zero prior synthetic coverage — flagged
// earlier this session as too CFG-intricate to attempt, until gotcha 10
// (direct-symbol-call inline asm) made the "belongs to this class"
// confirmation gate tractable.
//
// CORRECTION (found by tracing the actual decoder against the real built
// binary, not assumed from the design): this fixture was INTENDED to hit
// the "simple" sub-case (read_specified_va=None entirely, matching real
// GEOPDBatchSpatialLookupResult). It doesn't — and what it hits instead is
// arguably MORE valuable: `_find_field_count`'s raw-word scan has no
// function-boundary awareness (it scans up to 256 words from `func_va`
// regardless of an intervening `ret`), so scanning from the WRAPPER it
// bleeds straight through the wrapper's own short body into the
// IMMEDIATELY-FOLLOWING compare-chain core's range guard and reports
// `read_specified_va == readfrom_va` (the wrapper itself!) with
// field_count=80 — a real, reproducible decoder quirk, not a fixture bug
// (confirmed: `_readspecified_and_count` returns the wrapper's own
// address, not None). This means the FULL symmetric picker logic runs:
// `_core_resolves_compare_chain` is called on the (wrong) direct
// candidate FIRST and correctly returns False (the wrapper itself
// dispatches nothing), THEN on the wrapper-discovered `wcore` and
// correctly returns True, so `core_va` ends up adopting `wcore` — the
// "compare BOTH candidates, the wrapper-found one wins because the direct
// one doesn't dispatch" scenario, closer to the real GEOPDExternalAction
// shape (a genuine two-candidate comparison) than the "trivially None"
// simple case this fixture was designed around.
//
//   message TestPickerElem { string value = 1; }
//
//   message TestPickerContainer {
//     repeated TestPickerElem children = 5;
//   }
//
// TestPickerContainer's `readFrom:` tail-calls a THICK WRAPPER
// (TestPickerContainerReadFrom_wrapper) padded with NOPs so the real
// dispatch core's call sits past _readspecified_and_count's cheap
// 20-instruction lookahead — the DIRECT hop fails to find the real core
// (see the CORRECTION above for exactly what `read_specified_va` resolves
// to instead), forcing the full _find_dispatch_core_via_wrapper fallback
// (a wider 256-word scan) to find TestPickerContainerReadFrom_core, a real
// COMPARE-CHAIN dispatcher (f2_readfrom_element_type's proven pattern:
// `if(field==N)...else if(field==M)`).
//
// TWO extra requirements beyond f2's minimal compare-chain, both found by
// tracing the actual decoder (not assumed from reading the source):
//
//   1. Unlike f2 (whose `readFrom:` tail-calls STRAIGHT into its
//      compare-chain core, so the "core_va is None -> fall back to
//      readfrom_va" default in proto/repeated.py happens to already BE
//      the right answer — f2 never actually exercises this picker),
//      HERE `readfrom_va` is the WRAPPER, not the core, so the picker
//      must genuinely find and adopt the real core for the field to
//      resolve at all.
//   2. `_find_dispatch_core_via_wrapper`'s compare-chain branch requires
//      `_find_field_count(ctx, target) > 0` — a `cmp wN,#count;
//      b.hi/b.hs` GATE — which f2's bare 2-field `if/else if` chain does
//      NOT naturally compile (confirmed: field_count comes back 0 for
//      f2's own core too). An explicit `if (field > 9) { ...; return; }`
//      guard before the chain supplies this gate; verified by disassembly
//      that it produces the expected `cmp+b.hi` and NOTHING ELSE changes
//      about the compare-chain shape itself.
//
// The compare-chain core's field-5 arm also `bl`s its own `_addNoFlags`
// accessor's IMP directly (gotcha 10 — a statement-level `__asm__` calling
// the real, if local/non-exported, linker symbol
// `"-[TestPickerContainer _addNoFlagsChild:]"`) — required for
// `_func_calls_own_method`'s "this core belongs to THIS class, not a
// nested message's reader" confirmation, without which
// `_find_dispatch_core_via_wrapper` would refuse to adopt the core at all.
//
// Verified end-to-end (not just internal state) before writing
// expected.py: calling `_locate_dispatch_arms` directly on the built
// binary returns `core_va` pointing exactly at the real compare-chain
// core; `children`'s element type resolves to `TestPickerElem` (not the
// `bytes` fallback a failed picker would produce — confirmed by
// re-running the SAME probe with the range guard removed, which
// reproducibly reverts the field to `bytes`).

@interface TestPickerElem : PBCodable {
  @public
    NSString *_value;
    struct { unsigned has_value:1; } _has;
}
@end

extern __attribute__((noinline)) BOOL TestPickerElemReadFrom_core(TestPickerElem *self, PBDataReader *reader);

@implementation TestPickerElem

- (void)writeTo:(PBDataWriter *)writer {
    if (_has.has_value) PBWriteStringField(writer, _value, 1);
    [super writeTo:writer];
}

- (BOOL)readFrom:(PBDataReader *)reader { return TestPickerElemReadFrom_core(self, reader); }

@end

BOOL TestPickerElemReadFrom_core(TestPickerElem *self, PBDataReader *reader) {
    uint32_t tag = PBReadTag(reader);
    if ((tag >> 3) == 1) { /* would read the string field */ }
    return YES;
}

@interface TestPickerContainer : PBCodable {
  @public
    NSMutableArray *_children;
}
- (void)_addNoFlagsChild:(TestPickerElem *)item;
@end

extern __attribute__((noinline)) void TestPickerContainerReadFrom_core(TestPickerContainer *self, PBDataReader *reader);
extern __attribute__((noinline)) BOOL TestPickerContainerReadFrom_wrapper(TestPickerContainer *self, PBDataReader *reader);

@implementation TestPickerContainer

- (void)_addNoFlagsChild:(TestPickerElem *)item {
    if (self->_children == nil) self->_children = [NSMutableArray new];
    [self->_children addObject:item];
}

- (void)writeTo:(PBDataWriter *)writer {
    for (id elem in _children) { PBWriteMessageField(writer, elem, 5); }
    [super writeTo:writer];
}

- (BOOL)readFrom:(PBDataReader *)reader { return TestPickerContainerReadFrom_wrapper(self, reader); }

@end

// "Thick wrapper": padded with NOPs so the real dispatch core's call sits
// well past _readspecified_and_count's cheap 20-instruction lookahead,
// forcing the full _find_dispatch_core_via_wrapper fallback scan.
BOOL TestPickerContainerReadFrom_wrapper(TestPickerContainer *self, PBDataReader *reader) {
    __asm__ volatile (
        "nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n"
        "nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n"
        "nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n"
        ::: "memory"
    );
    TestPickerContainerReadFrom_core(self, reader);
    return YES;
}

// The REAL compare-chain dispatch core (f2's proven pattern, plus an
// explicit range guard so _find_field_count sees a gate) -- only
// reachable through the padded wrapper above.
void TestPickerContainerReadFrom_core(TestPickerContainer *self, PBDataReader *reader) {
    uint32_t tag = PBReadTag(reader);
    uint32_t field = tag >> 3;
    if (field > 9) { PBHandleUnknownField(self, field); return; }
    if (field == 5) {
        TestPickerElem *e = [TestPickerElem new];
        TestPickerElemReadFrom_core(e, reader);
        // Direct bl to the adder's own IMP (gotcha 10), bypassing
        // objc_msgSend -- confirms this core "belongs to this class" for
        // _find_dispatch_core_via_wrapper's _func_calls_own_method gate.
        __asm__ volatile (
            "bl \"-[TestPickerContainer _addNoFlagsChild:]\"\n"
            ::: "x0", "x1", "x2", "x3", "x4", "x8", "x9", "x30", "cc", "memory"
        );
    } else if (field == 9) {
        PBHandleUnknownField(self, field);
    }
}

int main(void) { return 0; }
