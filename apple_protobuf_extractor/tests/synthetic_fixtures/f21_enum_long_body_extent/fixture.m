#import "pbshim.h"

// Ground truth (see expected.py). Covers proto/enums.py's TODO #58 fallback:
// _extract_jumptable_enum_values probes an xAsString: method's body with a
// cheap 1000-instruction disasm first; if that probe runs out of budget
// before reaching `ret`, it recomputes the true function extent via
// _function_body_extent (up to a 40000-insn hard cap) so a long method still
// gets its values harvested instead of silently truncating at 1000. Every
// prior fixture's xAsString: bodies close on `ret` well under 1000 insns, so
// this path had zero synthetic coverage despite handling a real, documented
// case (the GeoServices LogMsg-family methods, ~12k insns).
//
//   message TestLongBodyEnum {
//     enum Mode {
//       TEST_LONG_MODE_ALPHA = 0;
//       TEST_LONG_MODE_BRAVO = 1;
//       TEST_LONG_MODE_CHARLIE = 2;
//     }
//     Mode mode = 3;
//   }
//
// modeAsString: is f11's exact proven pointer-table shape (same 3-case
// 0-based switch), preceded by 400 real, PLAIN C padding statements
// (`pad_sink += 1;` on a local `volatile int32_t`) -- REAL COMPILED CODE,
// no hand-asm at all. `volatile` forces each read-modify-write to be a
// genuine, unremovable instruction triple (`ldr`/`add`/`str`), so -Os
// cannot coalesce or strip them; 400 triples clear the 1000-instruction
// probe cap with margin even after the method's own prologue/epilogue.
//
// GOTCHA (found replacing the original `.rept`/`nop` hand-asm version of
// this padding with real code): a GLOBAL `volatile` padding variable
// breaks this fixture, silently. The compiler addresses a global via
// `adrp x8,#page; add x8,x8,#off` ONCE, and reuses x8 for every
// read-modify-write triple after that -- and the switch's OWN
// pointer-table base later ALSO lands in x8 (register allocation, not a
// deliberate choice). `find_adrp_add_target(insns, "x8")` finds the
// FIRST matching adrp+add pair for that register in the window, so it
// silently picks up the PADDING variable's address instead of the
// table's, and the enum comes back empty with no error at all -- a real,
// narrow footgun in any fixture that pads with global state ahead of a
// register-anchored table read. Fixed by making the padding sink a LOCAL
// stack variable instead (`ldr/str [sp,#off]`, no adrp/add and no
// register collision with the table base at all) -- verified by
// disassembly that this restores the exact same table read shape f11
// uses, unaffected by the padding ahead of it.
//
// Verified by disassembly before writing expected.py: the initial
// disasm(ctx, imp, max_insns=1000) probe returns exactly 1000 instructions
// NOT ending on `ret` (mid-padding) -- confirming _disasm_truncated(...)==
// True and the _function_body_extent fallback fires; the recomputed
// extent then reaches the switch's own `ldr x0,[x8,w2,sxtw #3]`
// pointer-table load and closes on its real `ret`, well under the 40000
// hard cap.
//
// FOUND, NOT DESIGNED: the recomputed body's shape is a POINTER TABLE, but
// _extract_jumptable_enum_values' three harvesters only understand
// jump-table/segment shapes -- a real gap, since the pointer-table read
// logic lived only in the separate _extract_enum_values' 80-insn primary
// probe, never re-run on the longer recomputed body. Closed by adding
// _try_pointer_table_in (reuses _harvest_dictrep_enums' own
// _decode_ldr_reg_off-based pointer-table read technique, anchored on the
// recomputed insns/words with _find_field_count/_find_index_bias re-anchored
// near the LOCATED load rather than `imp`). See expected.py for the full
// before/after and proto/enums.py's _try_pointer_table_in docstring.

@interface TestLongBodyEnum : PBCodable {
    int32_t _mode;
    struct { unsigned has_mode:1; } _has;
}
- (NSString *)modeAsString:(int32_t)value;
@end

@implementation TestLongBodyEnum

- (NSString *)modeAsString:(int32_t)value {
    volatile int32_t pad_sink = 0;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
        pad_sink += 1;
    switch (value) {
        case 0: return @"TEST_LONG_MODE_ALPHA";
        case 1: return @"TEST_LONG_MODE_BRAVO";
        case 2: return @"TEST_LONG_MODE_CHARLIE";
        default: return nil;
    }
}

- (void)writeTo:(PBDataWriter *)writer {
    if (_has.has_mode) PBWriteInt32Field(writer, _mode, 3);
}

@end

int main(void) { return 0; }
