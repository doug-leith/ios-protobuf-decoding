"""Ground truth for f5_jumptable_dispatch/testjt — authored by hand across
testelement.m/testcontainer.m, not derived from any tool output.

    message TestJumpContainer {
      repeated TestJumpElement items = 5;
    }
    message TestJumpElement {
      string value = 1;
    }

Same architectural point as f2_readfrom_element_type (the element TYPE is
only recoverable from readFrom: disassembly, never writeTo:), but exercised
via a genuinely different disassembly mechanism: TestJumpContainerReadFrom_
core compiles (real clang -Os, confirmed by disassembly at authoring time,
not assumed) to an actual ARM64 indirect jump table — `sub Wi,Wt,#bias; cmp
Wi,#count-1; b.hi oob; adr Rbase; ldrb Roff,[Rtab,Xi]; add
Rbase,Rbase,Roff,lsl#2; br Rbase` — decoded by proto/dispatch.py's raw-word
scanner (_find_dispatch_cluster / _decode_readfrom_jumptable), which is
entirely separate code from the if/else COMPARE-CHAIN decoder
(_dominance_field_of, dominance-attributed over a complete CFG) that f2's
fixture exercises. Verified directly (not
just via the final ProtoMessage output) that _find_dispatch_cluster resolves
a real 8-entry cluster (bias=1, count=8, entry_size=1) and
_decode_readfrom_jumptable's arm-5 target lands on the TestJumpElement-
constructing block — see the fixture-authoring probe in this repo's session
notes; a compare-chain probe on the same core returns no chain (the switch
never compiles to a linear cmp sequence), confirming this is genuinely the
jump-table path, not a fallback.
"""

EXPECTED = {
    "TestJumpContainer": {
        "fields": [
            {"name": "items", "number": 5, "type_name": "TestJumpElement",
             "label": "repeated", "type_class": "TestJumpElement",
             "number_confirmed": True},
        ],
    },
    "TestJumpElement": {
        "fields": [
            {"name": "value", "number": 1, "type_name": "string",
             "label": "optional", "number_confirmed": True},
        ],
    },
}
