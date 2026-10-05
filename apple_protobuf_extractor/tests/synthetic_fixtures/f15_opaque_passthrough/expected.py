"""Ground truth for f15_opaque_passthrough/testop — authored by hand in
fixture.m, not derived from any tool output.

    message TestOpaquePassthrough {
      // no fields — writeTo: is a pure tail-call to _unknownFields, the
      // real "opaque passthrough" shape (78 real GeoServices classes match
      // this exact pattern) — opaque_passthrough=True
    }

    message TestNotOpaque {
      // no RECOVERED fields either, but this is a deliberate lookalike,
      // not the real pattern: writeTo: does one more thing after
      // delegating, so it is NOT flagged opaque — opaque_passthrough=False
    }

Confirmed by calling _is_opaque_passthrough directly before writing this
file, not inferred from the source alone: True for TestOpaquePassthrough
(compiled writeTo: is exactly ivar-offset-table load + `ldr x0,[x0,x8]` +
a bare tail-call `b`, no stack frame, no bl/ret/stp), False for
TestNotOpaque (the extra call forces a real stack frame and a `bl`).
"""

EXPECTED = {
    "TestOpaquePassthrough": {
        "opaque_passthrough": True,
        "fields": [],
    },
    "TestNotOpaque": {
        "opaque_passthrough": False,
        "fields": [],
    },
}
