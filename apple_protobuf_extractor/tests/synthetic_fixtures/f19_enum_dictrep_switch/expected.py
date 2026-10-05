"""Ground truth for f19_enum_dictrep_switch/testeds — authored by hand in
fixture.m, not derived from any tool output (except the enum type-name
strings, the tool's own documented best-effort reconstruction from each
value-string common prefix).

    message TestDictRep {
      enum TestCategory {           // JUMP-TABLE dictRep idiom (real compiled code)
        TEST_CATEGORY_ALPHA = 0;
        TEST_CATEGORY_BETA = 1;
        TEST_CATEGORY_GAMMA = 2;
        TEST_CATEGORY_DELTA = 3;
        TEST_CATEGORY_EPSILON = 4;
        TEST_CATEGORY_ZETA = 5;
        TEST_CATEGORY_ETA = 6;
        TEST_CATEGORY_THETA = 7;
      }
      TestCategory category = 5;

      enum TestDictRepCacheControl {  // POINTER-TABLE dictRep idiom (hand-written,
                                       // real GEOPDComponent._cacheControl values)
        TEST_DICT_REP_CACHE_CONTROL_UNKNOWN_CACHEABILITY = 0;
        TEST_DICT_REP_CACHE_CONTROL_UNCACHEABLE = 1;
        TEST_DICT_REP_CACHE_CONTROL_CACHEABLE = 2;
      }
      TestDictRepCacheControl cacheControl = 6;
    }

Neither `_category` nor `_cacheControl` has an xAsString: companion
selector anywhere in this binary — both enums can ONLY be recovered via
`-[TestDictRep _dictionaryRepresentation:]`'s table dispatches
(_harvest_dictrep_enums: `category` via the jump-table idiom,
`cacheControl` via the pointer-table idiom). `category` is a plain 8-case
switch — REAL COMPILED CODE (gotcha 13); 8 cases needed since fewer
lowers to isolated compares instead of a jump table. `cacheControl` stays
hand-written (gotcha 9) — a genuine, thoroughly investigated negative
result (see fixture.m's header for the full matrix: 3 C structures x 2
old-clang versions x 4 optimization levels x 2 real field case counts,
including a SECOND real pointer-table field with 9 cases — every
combination lowers to jump-table or isolated-compares, never a pointer
table; the two compilers simply prefer a different lowering strategy for
this shape, not something case count or C structure changes). Its
VALUES are real, not invented, though: traced directly against the real
iphone8_data/dylib GeoServices cache (monkeypatching
_read_dictrep_switch_pairs/_read_dictrep_pointer_pairs to see which fires
per ivar offset on the real GEOPDComponent class) to confirm
`_cacheControl` (offset 64) — not `_status`, this fixture's original,
WRONG assumption — is the class's genuine pointer-table field, recovering
exactly UNKNOWN_CACHEABILITY=0/UNCACHEABLE=1/CACHEABLE=2.

The enum type name and each value's prefix here are the tool's own
best-effort reconstruction, verified (not assumed) before writing this
file: `_enum_name_from_pairs` finds no shared SCREAMING_SNAKE prefix
across "UNKNOWN_CACHEABILITY"/"UNCACHEABLE"/"CACHEABLE" (they don't share
one), so it falls back to the field-derived qualifier
(`TestDictRepCacheControl`) and each raw value name gets that qualifier's
SCREAMING_SNAKE form prepended — unlike `category`'s values, which
already share the `TEST_CATEGORY_` prefix verbatim.

Verified end-to-end before writing this file: `category` becomes
ENUM:TestCategory with all 8 values recovered, `cacheControl` becomes
ENUM:TestDictRepCacheControl with all 3 values recovered (both
values_confirmed=False, as for every non-xAsString: enum path).
"""

_CATEGORY_VALUES = [
    (0, "TEST_CATEGORY_ALPHA"),
    (1, "TEST_CATEGORY_BETA"),
    (2, "TEST_CATEGORY_GAMMA"),
    (3, "TEST_CATEGORY_DELTA"),
    (4, "TEST_CATEGORY_EPSILON"),
    (5, "TEST_CATEGORY_ZETA"),
    (6, "TEST_CATEGORY_ETA"),
    (7, "TEST_CATEGORY_THETA"),
]

_CACHE_CONTROL_VALUES = [
    (0, "TEST_DICT_REP_CACHE_CONTROL_UNKNOWN_CACHEABILITY"),
    (1, "TEST_DICT_REP_CACHE_CONTROL_UNCACHEABLE"),
    (2, "TEST_DICT_REP_CACHE_CONTROL_CACHEABLE"),
]

EXPECTED = {
    "TestDictRep": {
        "fields": [
            {"name": "category", "number": 5, "type_name": "TestCategory",
             "label": "optional", "number_confirmed": True,
             "type_class": "ENUM:TestCategory"},
            {"name": "cacheControl", "number": 6,
             "type_name": "TestDictRepCacheControl",
             "label": "optional", "number_confirmed": True,
             "type_class": "ENUM:TestDictRepCacheControl"},
        ],
        "enums": {
            "TestCategory": {
                "values": _CATEGORY_VALUES,
                "values_confirmed": False,
                "values_truncated": False,
            },
            "TestDictRepCacheControl": {
                "values": _CACHE_CONTROL_VALUES,
                "values_confirmed": False,
                "values_truncated": False,
            },
        },
    },
}
