#import "pbshim.h"

// Ground truth (see expected.py). This fixture covers proto/enums.py's
// LARGEST previously-uncovered block: the `_dictionaryRepresentation:`
// enum harvester's TWO idioms (_harvest_dictrep_enums):
//
//   * `category` — the JUMP-TABLE idiom (_read_dictrep_switch_pairs,
//     _iter_table_loads): a byte-indexed table + adr/br dispatch, exactly
//     like f16/f18's enum harvesters, just keyed by IVAR OFFSET
//     (_last_ivar_offset_in_window) instead of an xAsString: argument.
//   * `status` — the POINTER-TABLE idiom (_read_dictrep_pointer_pairs):
//     an 8-byte-entry table read via `ldr xR,[table,value,lsl #3]`,
//     exactly like f11's pointer-table enum, again keyed by ivar offset
//     via the same mechanism.
//
// BACKGROUND: some Apple PBCodable classes recover a scalar int field's
// enum value NAMES not from an `xAsString:`/`StringAsX:` companion
// selector (f11/f16/f18's mechanism) but from the class's OWN
// `-[Class _dictionaryRepresentation:]` method, which builds a debug
// dictionary keyed by field name and, for enum-shaped int fields, switches
// on the field's VALUE to pick a name string (see
// `_collect_enum_definitions`'s "Phase 1.5" comment: e.g. real
// GEOComponentType/ComponentStatus on GEOPDComponent). This only runs
// when a field has NO xAsString: companion at all.
//
//   message TestDictRep {
//     enum Category {              // NO categoryAsString: selector exists —
//       ALPHA=0; BETA=1; GAMMA=2;   // the enum can ONLY be recovered via the
//       DELTA=3; EPSILON=4;         // _dictionaryRepresentation: JUMP-TABLE
//       ZETA=5; ETA=6; THETA=7;
//     }
//     Category category = 5;
//
//     enum Cacheability {          // REAL enum, real field: GEOPDComponent's
//       UNKNOWN_CACHEABILITY = 0;   // ._cacheControl (offset 64) in the real
//       UNCACHEABLE = 1;            // iphone8_data/dylib GeoServices cache --
//       CACHEABLE = 2;              // _dictionaryRepresentation: POINTER-TABLE
//     }
//     Cacheability cacheControl = 6;
//   }
//
// `category` is REAL COMPILED CODE (gotcha 13, old-clang-frontend/
// modern-linker hybrid — see build_fixtures.sh's build_fixture_oldxc): a
// plain 8-case switch storing into the dict. 8 cases is required — with
// only 3 the compiler lowers to isolated compares instead of a jump
// table, which _harvest_dictrep_enums doesn't recognise; 8 dense cases
// reliably triggers the same byte-table+adr+br jump-table lowering f18
// uses. Needed ZERO decoder changes: it hit exactly the shape
// _read_dictrep_switch_pairs/_iter_table_loads already expect, first try.
//
// `cacheControl` stays HAND-WRITTEN (gotcha 9) — genuinely, not for lack
// of trying, and investigated thoroughly against real Apple binaries, not
// just assumed. Tried: 3 different C structures (a direct switch storing
// into a local var, an inlined static helper function, a switch storing
// straight into the dict) x 2 old-clang versions (Xcode 8.0, 11.1) x 4
// optimization levels (-Os/-O1/-O2/-O3) x 2 real-field case counts (3
// cases matching `_cacheControl` itself, and separately 9 cases matching
// a SECOND real pointer-table field, GEOTFIncident's `_laneClosureType`)
// -- every single combination lowers to a jump table (byte-table +
// per-case code block) or, at only 3 cases, isolated compares -- NEVER a
// pure pointer table. Ruled out along the way: it is NOT that the case
// body must "return immediately" (an earlier, wrong theory) -- disassembly
// of the REAL GEOPDComponent binary shows its pointer-table read lands in
// a scratch register (x22) and is used several instructions later, deep
// inside a much larger function, same as this fixture's own structure.
// It is NOT case count either -- `_laneClosureType`'s real 9-case
// reimplementation still lowers to jump-table under public clang, the
// same as `category`'s invented 8 cases. The two compilers appear to
// simply prefer a DIFFERENT lowering STRATEGY (per-case code block vs.
// pure data table) for a switch whose every case is one assignment --
// Apple's internal compiler reaches for the pure table far more readily
// than any public clang release tried here does, at any case count or
// optimization level. A genuine, thoroughly investigated negative result.
//
// Its VALUES are real, though, not invented: this fixture originally
// modeled the hand-written field on GEOPDComponent's `_status`
// (ComponentStatus) field, assuming it was a pointer-table example — it
// isn't. Traced directly against the real cache
// (iphone8_data/dylib/dyld_shared_cache_arm64, macho.dyld_cache +
// macho.local_symbols.apply_to_classes, monkeypatching
// _read_dictrep_switch_pairs/_read_dictrep_pointer_pairs to see which
// fires for which ivar offset): `_status` is actually the COMBINED
// jump-table(low dense 0-2)+isolated-compares(sparse high 5/20/30/40/50/60)
// idiom `_scan_dictrep_isolated_cmps` targets (a DIFFERENT, still-unbuilt
// fixture opportunity) — the genuinely pointer-table field on the same
// real class is `_cacheControl` (offset 64), confirmed by the same trace:
// `_read_dictrep_pointer_pairs` fires for it and only it, recovering
// exactly `UNKNOWN_CACHEABILITY=0/UNCACHEABLE=1/CACHEABLE=2`. Renamed the
// fixture's hand-written field from `status`/OK-FAILED-PENDING (invented)
// to `cacheControl`/UNKNOWN_CACHEABILITY-UNCACHEABLE-CACHEABLE (real) once
// this was found.
//
// GOTCHA (found building the original hand-asm version of this fixture):
// the harvester's value strings MUST be genuine CFString structs in
// `__DATA_CONST,__cfstring` (`_block_cfstring_target` scans specifically
// for an `adrp+add` landing inside THAT section for the jump-table idiom;
// `_read_enum_string` reads the pointer-table idiom's entries the same
// way) — a plain `static const char[]` (which f16/f18 used successfully
// for the xAsString: path, since `_read_enum_string` there accepts raw
// char*) is NOT accepted here. Real Objective-C `@"..."` literals compile
// to exactly this shape automatically, but `cacheControl`'s dispatch is
// still hand-asm, so it hand-builds the CFString struct directly instead:
// `{isa=___CFConstantStringClassReference, flags=0x7c8, pad,
// data=<cstring>, length}` in `.section __DATA,__cfstring` (confirmed via
// a throwaway real `@"..."` literal compile + `.s` dump) — the LINKER
// moves that section's content into `__DATA_CONST,__cfstring` in the
// final binary (verified via `otool -l`, not assumed).
//
// `cacheControl`'s ivar value is read via the real ivar-offset-variable
// symbol Apple/clang exports for every ivar
// (`_OBJC_IVAR_$_TestDictRep._cacheControl`, confirmed via `nm`) — the
// same mechanism every other fixture's normal ivar access already goes
// through, just referenced explicitly since only `cacheControl`'s own
// dispatch is hand-written now.
//
// Verified by disassembly (gotcha 4) and end-to-end extraction before
// writing expected.py: `category` becomes `ENUM:TestCategory` (8 values,
// jump-table idiom, values_confirmed=False) and `cacheControl` becomes
// `ENUM:TestDictRepCacheControl` (3 values, pointer-table idiom,
// values_confirmed=False).
//
// FOUND, NOT DESIGNED (later session): `category`'s real compiled case
// blocks are 5 instructions each (they reload the dictionary KEY string
// via a second adrp+add before the merge branch, unlike the simpler
// 3-instruction real GEOPDComponent shape checked earlier), not the
// 3-4 _read_dictrep_switch_pairs' merge-target scan assumed — a real,
// too-tight probe window silently returned merge_target=None for this
// (perfectly ordinary) shape, which also silently suppressed
// _scan_dictrep_isolated_cmps entirely (its caller only invokes it when a
// merge target was found). Fixed by making that scan stop at the case
// block's own terminal instruction (reusing _CASE_TERMINALS, the same
// idiom _read_case_string already uses) instead of trusting a fixed
// instruction count — a real, if narrow, production fix this fixture's
// real compiled code surfaced that hand-asm never would have.

@interface TestDictRep : PBCodable {
  @public
    int32_t _category;
    int32_t _cacheControl;
    struct { unsigned has_category:1; unsigned has_cacheControl:1; } _has;
}
@end

@implementation TestDictRep

- (id)_dictionaryRepresentation:(id)arg {
    NSMutableDictionary *d = [NSMutableDictionary new];

    // ---- category: JUMP-TABLE dictRep idiom (real compiled code) ----
    switch (_category) {
        case 0: d[@"category"] = @"TEST_CATEGORY_ALPHA"; break;
        case 1: d[@"category"] = @"TEST_CATEGORY_BETA"; break;
        case 2: d[@"category"] = @"TEST_CATEGORY_GAMMA"; break;
        case 3: d[@"category"] = @"TEST_CATEGORY_DELTA"; break;
        case 4: d[@"category"] = @"TEST_CATEGORY_EPSILON"; break;
        case 5: d[@"category"] = @"TEST_CATEGORY_ZETA"; break;
        case 6: d[@"category"] = @"TEST_CATEGORY_ETA"; break;
        case 7: d[@"category"] = @"TEST_CATEGORY_THETA"; break;
    }

    // ---- cacheControl: POINTER-TABLE dictRep idiom (hand-written,
    // gotcha 9 -- see header for why this one couldn't be made to compile
    // naturally; values are GEOPDComponent's real ._cacheControl, the
    // genuine real-world pointer-table example on this class) ----
    register id selfPtr asm("x1") = self;
    register id cacheControlVal asm("x0");
    __asm__ volatile (
        "adrp x8, _OBJC_IVAR_$_TestDictRep._cacheControl@PAGE\n"
        "ldrsw x8, [x8, _OBJC_IVAR_$_TestDictRep._cacheControl@PAGEOFF]\n"
        "ldr w9, [x1, x8]\n"
        "cmp w9, #3\n"
        "b.hs 18f\n"
        "adrp x10, 15f@PAGE\n"
        "add x10, x10, 15f@PAGEOFF\n"
        "ldr x0, [x10, w9, uxtw #3]\n"
        "b 19f\n"
        ".section __DATA_CONST,__const\n"
        ".p2align 3\n"
        "15:\n"
        ".quad cfsA\n.quad cfsB\n.quad cfsC\n"
        ".text\n"
        ".p2align 2\n"
        "18:\n"
        "mov x0, #0\n"
        "19:\n"
        // ---- real CFString structs, matching what @"..." compiles to ----
        ".section __TEXT,__cstring,cstring_literals\n"
        "strA: .asciz \"UNKNOWN_CACHEABILITY\"\n"
        "strB: .asciz \"UNCACHEABLE\"\n"
        "strC: .asciz \"CACHEABLE\"\n"
        ".section __DATA,__cfstring\n"
        ".p2align 3\n"
        "cfsA:\n"
        ".quad ___CFConstantStringClassReference\n"
        ".long 1992\n.space 4\n.quad strA\n.quad 20\n"
        "cfsB:\n"
        ".quad ___CFConstantStringClassReference\n"
        ".long 1992\n.space 4\n.quad strB\n.quad 11\n"
        "cfsC:\n"
        ".quad ___CFConstantStringClassReference\n"
        ".long 1992\n.space 4\n.quad strC\n.quad 9\n"
        ".text\n"
        : "=r"(cacheControlVal)
        : "r"(selfPtr)
        : "x8", "x9", "x10", "cc"
    );
    d[@"cacheControl"] = cacheControlVal;

    return d;
}

- (void)writeTo:(PBDataWriter *)writer {
    if (_has.has_category) PBWriteInt32Field(writer, _category, 5);
    if (_has.has_cacheControl) PBWriteInt32Field(writer, _cacheControl, 6);
}

@end

int main(void) { return 0; }
