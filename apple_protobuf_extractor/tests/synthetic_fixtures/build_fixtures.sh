#!/usr/bin/env bash
# Rebuild the synthetic ground-truth fixture binaries from source.
#
# Fixture binaries ARE committed to the repo (small, no proprietary Apple
# code) so `tests/test_synthetic_fixtures.py` needs no toolchain at test
# time. Run this script only when authoring a new fixture or editing an
# existing one's .m/.h source, then `git diff` the regenerated binary and
# re-verify its disassembly still matches the fixture's documented shape
# (see README.md gotcha 4b — compiler idiom is not fully predictable).
#
# Toolchain: the committed binaries were built with Xcode 15.4 (15F31d; clang
# 1500.3.9.4, ld 1053.12, iPhoneOS 17.5 SDK); f16/f18/f19 also need Xcode 11.1
# (11A1027) for their object files. See README.md, "Toolchain the committed
# binaries were built with".
#
# Usage:
#   ./build_fixtures.sh            # rebuild everything
#   ./build_fixtures.sh f1_writeto_fieldnum   # rebuild just one fixture
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

SDK=$(xcrun --sdk iphoneos --show-sdk-path)
ARCH_FLAGS=(-arch arm64 -isysroot "$SDK" -miphoneos-version-min=15.0 -fobjc-arc -Os)

echo "Building shim dylib..."
clang "${ARCH_FLAGS[@]}" -dynamiclib -install_name @rpath/libpbshim.dylib \
    -o shim/libpbshim.dylib shim/pbshim.m

SHIM_DIR="$(pwd)/shim"

# arm64e variant (pointer-authenticated code, DYLD_CHAINED_PTR_ARM64E_USERLAND24
# chained fixups — the format a current toolchain emits for arm64e dylibs and
# executables, and the format of the real macOS/iPhone17,3 images). Only the
# f24/f25/f26 fixtures have arm64e builds; each links its own copy of the shim
# because a shim dylib's architecture must match its client's.
ARCH_FLAGS_E=(-arch arm64e -isysroot "$SDK" -miphoneos-version-min=15.0 -fobjc-arc -Os)
echo "Building arm64e shim dylib..."
clang "${ARCH_FLAGS_E[@]}" -dynamiclib -install_name @rpath/libpbshim_e.dylib \
    -o shim/libpbshim_e.dylib shim/pbshim.m

build_fixture_e() {
    local name="$1"; shift
    echo "Building $name (arm64e)..."
    clang "${ARCH_FLAGS_E[@]}" -I shim -L shim -lpbshim_e \
        -Wl,-rpath,"$SHIM_DIR" "$@"
}

build_fixture() {
    local name="$1"; shift
    echo "Building $name..."
    # Only the linker needs the dylib to be present (to satisfy symbol
    # references) — the extractor never executes these binaries, only reads
    # their Mach-O bytes as data, so the rpath is a best-effort convenience
    # for manual sanity runs, not a test-harness requirement.
    clang "${ARCH_FLAGS[@]}" -I shim -L shim -lpbshim \
        -Wl,-rpath,"$SHIM_DIR" "$@"
}

# ── Old-clang-frontend / modern-linker HYBRID build (gotcha 13) ───────────────
#
# A handful of fixtures (f16, f18, f19's jump-table field) need pre-2020 LLVM
# if-conversion / tail-duplication heuristics — this repo's normal (Xcode 15)
# clang always if-converts small isolated compares to a branchless `csel` and
# tail-duplicates each multi-segment jump-table's own `ret` instead of
# funnelling every arm to one shared epilogue (see README.md's "isolated
# compares" and "multi-segment" findings). An old Apple clang fixes that —
# Xcode 11.1 (build 11A1027, clang 11.0.0 / clang-1100.0.33.8) is the exact
# version actually used below: Xcode 8.0 (build 8A218a, clang 8.0.0 /
# clang-800.0.38) produces the identical isolated-compares shape but a
# DIFFERENT multi-segment jump-table encoding (adrp+add/ldrsw 4-byte
# relative offsets) that this suite's harvester doesn't recognise — Xcode
# 11.1 uses the same adrp+add-table-base/separate-adr-case-base/ldrb-entry
# shape real Apple binaries do (confirmed against GEOTelemetricEntity), so
# it's the one standardised on for every old-codegen fixture, not just
# f18's.  Xcode 12.1 (build 12A7403, clang 12.0.0 / clang-1200.0.32.21) is
# already back to if-converting to `csel` — the window is narrow, not "any
# sufficiently old clang". All three verified directly this session by
# compiling the same probe source and disassembling the result — not
# assumed from release notes or version numbers alone.
#
# But an old Apple clang's OWN linker predates "chained fixups" (checked:
# still absent from Xcode 12.1's ld64 too) entirely — it links with the
# classic bind/rebase opcodes instead, which macho/memory.py does not parse
# AT ALL (this repo only targets modern, chained-fixups-linked binaries,
# matching what `apple_protobuf_extractor` actually analyses in practice).
# An old-clang-LINKED executable's ivar-offset/superclass pointers come back
# completely unresolved (`superclass_vmaddr == 0`), and `extract_all` refuses
# to run at all ("proto-class detection FAILED STRUCTURALLY").
#
# Fix: the LINKER decides the fixup format; the COMPILER decides
# instruction-level codegen. These are independent axes, so compile the .m to
# a .o with the OLD clang (old codegen), then link that .o with THIS
# environment's normal (modern) clang/ld (chained fixups) — never with the old
# clang's own linker. Verified: the resulting binary both parses cleanly AND
# keeps the old codegen shape (checked by disassembly before trusting it, same
# as every other fixture in this suite).
#
# Not a normal part of any Xcode install — override via OLDXC_CLANG/OLDXC_SDK
# if you have a copy elsewhere. Skipped (not failed) when absent: the fixture
# binaries this needs are already committed, so `./build_fixtures.sh` without
# a copy of an old Xcode still succeeds for everything else.
_OLDXC_DEFAULT_ROOT="$(cd ../../.. && pwd)"   # apple_protobuf_extractor/tests/synthetic_fixtures -> repo root
OLDXC_CLANG="${OLDXC_CLANG:-$_OLDXC_DEFAULT_ROOT/Xcode11.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang}"
OLDXC_SDK="${OLDXC_SDK:-$_OLDXC_DEFAULT_ROOT/Xcode11.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS13.1.sdk}"

build_fixture_oldxc() {
    local name="$1"; shift
    if [ ! -x "$OLDXC_CLANG" ] || [ ! -d "$OLDXC_SDK" ]; then
        echo "SKIP $name: old Apple clang not found at $OLDXC_CLANG" \
             "(set OLDXC_CLANG/OLDXC_SDK to override) — binary is already" \
             "committed; only needed to rebuild this fixture from source."
        return 0
    fi
    echo "Building $name (old-clang-frontend + modern-linker hybrid)..."
    local out="$1"; shift
    local src="$1"; shift
    local obj="${out}.oldxc.o"
    "$OLDXC_CLANG" -arch arm64 -isysroot "$OLDXC_SDK" -miphoneos-version-min=13.0 \
        -fobjc-arc -Os -I shim -c "$src" -o "$obj"
    clang "${ARCH_FLAGS[@]}" -L shim -lpbshim -Wl,-rpath,"$SHIM_DIR" \
        -framework Foundation -lobjc -o "$out" "$obj" "$@"
    rm -f "$obj"
}

FILTER="${1:-}"
want() { [ -z "$FILTER" ] || [ "$FILTER" == "$1" ]; }

if want f1_writeto_fieldnum; then
    build_fixture f1_writeto_fieldnum \
        -o f1_writeto_fieldnum/testmsg f1_writeto_fieldnum/fixture.m
fi

if want f2_readfrom_element_type; then
    build_fixture f2_readfrom_element_type \
        -o f2_readfrom_element_type/testrf \
        f2_readfrom_element_type/testelement.m f2_readfrom_element_type/testcontainer.m
fi

if want f3_write_helper_family; then
    # pbwiretypes.s is compiled DIRECTLY into this fixture's own executable
    # (not into the shared shim dylib): _classify_write_helper's stub-follow
    # only recognizes ProtocolBuffer.framework's specific 12-byte
    # adrp/add/br PLT shape (see README.md gotcha 6) — a standard ld64
    # cross-dylib lazy stub doesn't match it. Keeping the helpers local
    # exercises the "direct (non-stub) helper" fallback path instead, which
    # is exactly what --binary (standalone) mode always uses in practice.
    build_fixture f3_write_helper_family \
        -o f3_write_helper_family/testwt \
        f3_write_helper_family/fixture.m shim/pbwiretypes.s
fi

if want f4_packed_repeated; then
    build_fixture f4_packed_repeated \
        -o f4_packed_repeated/testpr f4_packed_repeated/fixture.m
fi

if want f5_jumptable_dispatch; then
    build_fixture f5_jumptable_dispatch \
        -o f5_jumptable_dispatch/testjt \
        f5_jumptable_dispatch/testelement.m f5_jumptable_dispatch/testcontainer.m
fi

if want f6_geo_route_incident; then
    # Real GEORouteIncident schema (tests/golden/GeoServices.json). Uses
    # sfixed64 (startTime/endTime/updateTime) -> pbwiretypes.s linked
    # directly, same reasoning as f3 (README.md gotcha 6).
    build_fixture f6_geo_route_incident \
        -o f6_geo_route_incident/testri \
        f6_geo_route_incident/nested.m f6_geo_route_incident/fixture.m shim/pbwiretypes.s
fi

if want f7_geo_tf_road_speed; then
    # Real GEOTFRoadSpeed schema. sint64 -> pbwiretypes.s linked directly.
    build_fixture f7_geo_tf_road_speed \
        -o f7_geo_tf_road_speed/testrs \
        f7_geo_tf_road_speed/fixture.m shim/pbwiretypes.s
fi

if want f8_geo_companion_drive_step; then
    # Real GEOCompanionDriveStep schema. sint32 -> pbwiretypes.s linked
    # directly.
    build_fixture f8_geo_companion_drive_step \
        -o f8_geo_companion_drive_step/testcds \
        f8_geo_companion_drive_step/nested.m f8_geo_companion_drive_step/fixture.m \
        shim/pbwiretypes.s
fi

if want f9_clp_location; then
    # Real CLPLocation schema (tests/golden/CoreLocationProtobuf.json) — the
    # OTHER framework this tool targets, not GeoServices. No sint/fixed
    # fields, so no pbwiretypes.s needed.
    build_fixture f9_clp_location \
        -o f9_clp_location/testcl \
        f9_clp_location/nested.m f9_clp_location/fixture.m
fi

if want f10_geo_log_message; then
    # Real GEOLogMessage + a representative real subset of its GEOLogMsgEvent
    # element (tests/golden/GeoServices.json). Extreme sparse field numbers
    # (102/1000/2000) + a 2-level repeated-message dispatch chain.
    build_fixture f10_geo_log_message \
        -o f10_geo_log_message/testlm \
        f10_geo_log_message/nested.m f10_geo_log_message/fixture.m
fi

if want f11_enum_pointer_table; then
    # Enum-value recovery: the pointer-table path (_extract_enum_values),
    # 0-based baseline + real GEOMapRegionSourceType 1-based/bias variant.
    build_fixture f11_enum_pointer_table \
        -o f11_enum_pointer_table/testenum \
        f11_enum_pointer_table/fixture.m
fi

if want f12_repeated_metaclass_type; then
    # Repeated-message element-type recovery via the +[Cls xyzType]
    # metaclass method (Strategy 1) — the dominant real-world path, with
    # zero prior synthetic coverage.
    build_fixture f12_repeated_metaclass_type \
        -o f12_repeated_metaclass_type/testrmt \
        f12_repeated_metaclass_type/fixture.m
fi

if want f13_writeto_accessor_sourced; then
    # writeTo: field-number binding for a message-typed field written via
    # its property GETTER (self.context) rather than a direct ivar load —
    # bind_write's accessor-sourced tier, zero prior synthetic coverage.
    build_fixture f13_writeto_accessor_sourced \
        -o f13_writeto_accessor_sourced/testgac \
        f13_writeto_accessor_sourced/fixture.m
fi

if want f14_repeated_suffix_ambiguity; then
    # Repeated fields with no structural element-type evidence: originally the
    # fixture for the (since deleted) name-suffix matcher and its uniqueness
    # guard; now the guard against re-introducing a name-based guess.
    build_fixture f14_repeated_suffix_ambiguity \
        -o f14_repeated_suffix_ambiguity/testrsa \
        f14_repeated_suffix_ambiguity/fixture.m
fi

if want f15_opaque_passthrough; then
    # Opaque-passthrough detector (_is_opaque_passthrough): a field-less
    # class whose writeTo: is a pure tail-call to its _unknownFields bag —
    # "0 fields" is ground truth, not an extraction gap. Plus a deliberate
    # lookalike that should be rejected. Zero prior synthetic coverage.
    build_fixture f15_opaque_passthrough \
        -o f15_opaque_passthrough/testop \
        f15_opaque_passthrough/fixture.m
fi

if want f17_repeated_adder_ivar_lever; then
    # Repeated-message element-type resolution via the adder->ivar lever
    # (_resolve_repeated_element_ivars): a jump-table dispatch arm calls
    # its own adder method's IMP directly (gotcha 10), bypassing
    # objc_msgSend. Zero prior synthetic coverage.
    build_fixture f17_repeated_adder_ivar_lever \
        -o f17_repeated_adder_ivar_lever/testrail \
        f17_repeated_adder_ivar_lever/fixture.m
fi

if want f20_dispatch_wrapper_core_picker; then
    # dispatch.py's thick-wrapper-vs-direct-core picker
    # (_core_resolves_compare_chain / _find_dispatch_core_via_wrapper) --
    # the simple case (read_specified_va=None, single wcore adopted).
    # Zero prior synthetic coverage. Needs gotcha 10 (direct-symbol-call
    # inline asm).
    build_fixture f20_dispatch_wrapper_core_picker \
        -o f20_dispatch_wrapper_core_picker/testdwp \
        f20_dispatch_wrapper_core_picker/fixture.m
fi

if want f19_enum_dictrep_switch; then
    # -[Class _dictionaryRepresentation:] switch-table enum harvest
    # (_harvest_dictrep_enums), both idioms. `category` (jump-table) is
    # REAL COMPILED CODE now (gotcha 13, old-clang-frontend/modern-linker
    # hybrid -- needs 8 dense cases to trigger jump-table lowering at all).
    # `cacheControl` (pointer-table, real GEOPDComponent._cacheControl
    # values) stays hand-written (gotcha 9/11, real CFString structs) --
    # a genuine, thoroughly investigated negative result, not a shortcut;
    # see fixture.m header for the full matrix of what was tried. The
    # whole file goes through build_fixture_oldxc since it's one
    # translation unit mixing both.
    build_fixture_oldxc f19_enum_dictrep_switch \
        f19_enum_dictrep_switch/testeds \
        f19_enum_dictrep_switch/fixture.m
fi

if want f18_enum_multi_segment; then
    # Multi-segment jump-table enum harvest (_harvest_jumptable_segments'
    # Idiom-B routing) with a genuine SHARED epilogue, matching real Apple
    # codegen (confirmed via the real dyld cache earlier this session).
    # REAL compiled code now (gotcha 13): the old-clang/modern-linker
    # hybrid produces exactly this shape -- two independently-gated
    # adrp+add/adr/ldrb jump tables, both funnelling to one shared
    # epilogue -- not the disjoint-per-segment-ret artifact this repo's
    # normal (Xcode 15) clang produces from the same source. See
    # fixture.m's header.
    build_fixture_oldxc f18_enum_multi_segment \
        f18_enum_multi_segment/testems \
        f18_enum_multi_segment/fixture.m
fi

if want f16_enum_isolated_compares; then
    # Branch-based sparse-enum harvesters (_harvest_isolated_compares,
    # _harvest_cbz_value0). REAL compiled code now (gotcha 13): the
    # old-clang-frontend/modern-linker hybrid produces genuine
    # cmp+b.eq/cbnz — this repo's normal (Xcode 15) clang always
    # if-converts the same source to a branchless csel. See fixture.m's
    # header.
    build_fixture_oldxc f16_enum_isolated_compares \
        f16_enum_isolated_compares/testeic \
        f16_enum_isolated_compares/fixture.m
fi

if want f21_enum_long_body_extent; then
    # _extract_jumptable_enum_values' TODO #58 fallback: a >1000-insn
    # xAsString: body forces _function_body_extent to recompute the real
    # extent instead of trusting the cheap 1000-insn probe. Zero prior
    # synthetic coverage.
    build_fixture f21_enum_long_body_extent \
        -o f21_enum_long_body_extent/testlbe \
        f21_enum_long_body_extent/fixture.m
fi

if want f22_writeto_forward_array_load; then
    # proto/writeto.py's _forward_self_load_off (the inline-repeated-message
    # container-array forwarder). Confirmed real via a corpus trace
    # (GeoServices' GEOFlyoverRegionVersions._regions) before writing this
    # fixture -- zero prior synthetic coverage. Needs the helper calls in a
    # SEPARATE translation unit (see helpers.m's header) so the compiler
    # can't see they're no-ops and drop the call-site argument setup.
    build_fixture f22_writeto_forward_array_load \
        -o f22_writeto_forward_array_load/testfwd \
        f22_writeto_forward_array_load/fixture.m \
        f22_writeto_forward_array_load/helpers.m
fi

if want f23_writeto_hoisted_value; then
    # proto/writeto.py's _trace_hoisted_self_value ("S1" hoisted value-load).
    # Confirmed real via a corpus trace (CoreLocationProtobuf's
    # CLPPressure._timestamp-shaped field) before writing this fixture --
    # zero prior synthetic coverage.
    build_fixture f23_writeto_hoisted_value \
        -o f23_writeto_hoisted_value/testhoist \
        f23_writeto_hoisted_value/fixture.m
fi

if want f24_dictrep_compare_chain; then
    # _harvest_dictrep_enums' compare-chain/tree pass (newer toolchain's
    # dictionaryRepresentation enum shape). Real compiled code from this
    # repo's normal clang -- the `default:` arm's +stringWithFormat: call
    # keeps the chain from being if-converted to `csel`.
    build_fixture f24_dictrep_compare_chain \
        -o f24_dictrep_compare_chain/testdcc \
        f24_dictrep_compare_chain/fixture.m
fi

if want f25_newer_dispatch_engine; then
    # Newer-toolchain readFrom: dispatch engine: multi-jump-table table-base
    # aliasing, the classref fallback + ownership gate, and
    # _find_dispatch_cluster's function-boundary bound. Opaque helpers live
    # in a separate translation unit (helpers.m) as in f22.
    build_fixture f25_newer_dispatch_engine \
        -o f25_newer_dispatch_engine/testnde \
        f25_newer_dispatch_engine/fixture.m \
        f25_newer_dispatch_engine/helpers.m
fi

if want f24_dictrep_compare_chain; then
    build_fixture_e f24_dictrep_compare_chain \
        -o f24_dictrep_compare_chain/testdcc_e \
        f24_dictrep_compare_chain/fixture.m
fi

if want f25_newer_dispatch_engine; then
    build_fixture_e f25_newer_dispatch_engine \
        -o f25_newer_dispatch_engine/testnde_e \
        f25_newer_dispatch_engine/fixture.m \
        f25_newer_dispatch_engine/helpers.m
fi

if want f26_arm64e_fixups; then
    # Chained-fixup FORMAT 12 decode (macho/memory.py), checked against Apple's
    # own `dyld_info -fixups` output for this binary (see expected.py). Needs no
    # shim: the source is a bare ObjC class.
    echo "Building f26_arm64e_fixups (arm64e)..."
    clang "${ARCH_FLAGS_E[@]}" -o f26_arm64e_fixups/testfx_e \
        f26_arm64e_fixups/fixture.m
fi

if want f27_compare_tree_engine_no_guard; then
    # Compare-chain tier for the newest arm64e engines: a compare TREE on the
    # field number with NO cmp;b.hi range guard, accepted only with the
    # call-site csel + an independent dispatch check + the class's own ivar
    # slots. Plus two negatives (plain call site; a foreign engine).
    build_fixture f27_compare_tree_engine_no_guard \
        -o f27_compare_tree_engine_no_guard/testgr \
        f27_compare_tree_engine_no_guard/fixture.m \
        f27_compare_tree_engine_no_guard/helpers.m
    build_fixture_e f27_compare_tree_engine_no_guard \
        -o f27_compare_tree_engine_no_guard/testgr_e \
        f27_compare_tree_engine_no_guard/fixture.m \
        f27_compare_tree_engine_no_guard/helpers.m
fi

if want f24_enum_dictrep_hybrid; then
    # Hybrid `_dictionaryRepresentation:` enum (jump table for the dense low
    # values + isolated compares for the sparse high ones), real
    # ComponentStatus values. Real compiled code via the old-clang hybrid
    # (gotcha 13): this repo's normal clang lowers the sparse half differently.
    build_fixture_oldxc f24_enum_dictrep_hybrid \
        f24_enum_dictrep_hybrid/testedh \
        f24_enum_dictrep_hybrid/fixture.m
fi

if want f25_enum_large_bias; then
    # _leading_materialized_bias: a jump-table segment whose index bias (50000)
    # is too large for `sub #imm12` and is materialised in a register. Real
    # compiled code via the old-clang hybrid (gotcha 13), so the low segment
    # keeps the shared-epilogue shape (as f18).
    build_fixture_oldxc f25_enum_large_bias \
        f25_enum_large_bias/testelb \
        f25_enum_large_bias/fixture.m
fi

if want f28_enum_dictrep_biased; then
    # 1-based dictRep-only enum (`sub w9,w8,#1 ; cmp w9,#N-1 ; b.hi ; ldr x,[table,
    # w9,uxtw #3]` -- the iOS 16 GeoServices shape of GEOPDGroundDataBuild.type,
    # which gates `cmp #N ; b.hs`: the same unsigned range) in a binary where
    # ANOTHER class defines typeAsString: -- regression for the shared-selector-pool
    # false positive in _field_routes_through_xasstring.  Plain real compiled code.
    build_fixture f28_enum_dictrep_biased \
        -o f28_enum_dictrep_biased/testbiased \
        f28_enum_dictrep_biased/fixture.m
fi

echo "Done."
