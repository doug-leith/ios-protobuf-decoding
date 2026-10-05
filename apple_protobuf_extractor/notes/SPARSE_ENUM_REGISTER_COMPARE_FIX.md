# Fix: sparse-enum values > 4095 dropped (register-materialized compares)

**Date:** 2026-06-09. Originally a read-only pickup note; **APPLIED 2026-06-09.**
Found validating `CLPLocation.proto` against CoreLocationProtobuf
(`CLPMotionActivityType` recovered 26/32 values).

Independent of [PACKED_REPEATED_LABEL_FIX.md] — different function, different
symptom. That one touches `_field_label`; this one touches
`_extract_jumptable_enum_values`.

---

## ✅ DONE 2026-06-09

Implemented exactly as proposed: a **register-compare arm** in the isolated-value
loop of `_extract_jumptable_enum_values`, plus four small raw-word decoders
(`_decode_cmp_reg`, `_decode_movz`, `_decode_movk`, `_materialized_value`). The
arm runs only when `_decode_cmp_imm` misses (`cmp wN, wReg` register form), reads
the constant back from the preceding `movz`[/`movk`], **OR-composes** the halves,
and bounds the value by int32 (not `_SPARSE_MAX_RANGE`). All raw-word based, so it
works under both the native decoder and capstone. Additive: the immediate /
jump-table / cbz arms are untouched and `_add`'s `seen_values` dedup prevents
double-counting.

**Verified (before/after, all 3 artifacts):**
- **Field-level snapshot diff EMPTY** — 0 type/number/confirmed/note changes.
  Purely additive at the field level.
- **Enum-value diff: 11 enums gain values, all > 4095, ZERO removals.**
  `CLPMotionActivity.MotionActivityType` 26→32 (the 6 documented values, incl.
  `90603 → MOTION_ACTIVITY_TYPE_OUTDOOR_WHEELCHAIR`, movz+movk composed
  correctly); plus 10 GeoServices enums (`GEOLogMessage.LogMessageType` 8→17,
  several `…Action`/`…Trigger` 198→203, `GEOTelemetricEntity` 41→43, etc.). Every
  added value is a clean round sentinel (10000/20000/50001/90010…), never garbled
  — the signature of correct half-composition.
- **Binary-confirmed** `GEOLogMessage.logMessageTypeAsString:`: disassembling its
  9 register-compare sites reproduces the tool's exact value→string map
  (`10000→USAGE` … `40000→TELEMETRY`).
- Full suite **1016 pass** (+5 unit tests in `TestRegisterMaterializedCompare`);
  `validate_ref` baselines unchanged (GEOPDComponent 11/14,
  GEOPDPlaceGlobalCommonResult 1/1).

Everything below is the original analysis (now implemented).

---

## TL;DR

The sparse-enum extractor's isolated-value detector matches only the **immediate**
compare `cmp wN, #imm`. ARM64 encodes that immediate in 12 bits (≤ 0xFFF = 4095),
so the compiler materializes any larger enum value into a register
(`movz [+ movk]`) and does a **register compare** `cmp wN, wReg` — which the
detector never matches. Every enum value > 4095 is silently dropped. Add a
register-compare arm → recovers them.

## Symptom

`CLPMotionActivityType`: tool recovers 26/32 values (dense 0–11, sparse to 3015);
**misses the 6 values ≥ 11805** (`11805, 12150, 17150, 18240, 19150, 90603` — the
wheelchair / outdoor-sport / HKWorkout types, 0x2e1d–0x161eb).

## Root cause (exact)

`_extract_jumptable_enum_values` (`proto/extractor.py:794`), isolated-value loop
(~line 1010):

```python
cmp = _decode_cmp_imm(w0)          # matches  cmp wN, #imm12  ONLY
if cmp is None: continue
_, imm = cmp
if imm == 0 or imm > _SPARSE_MAX_RANGE:   # _SPARSE_MAX_RANGE = 4096
    continue
```

Disassembly of `-[CLPMotionActivity typeAsString:]` (0x1c826cabc) shows the two
forms side by side:

```
; value 2065 — fits 12-bit immediate → recovered
cmp  w2, #0x811
b.eq <string>

; value 11805 (0x2e1d) — exceeds 12 bits → materialized, MISSED
mov  w8, #0x2e1d
cmp  w2, w8
b.eq <string>

; value 90603 (0x161eb) — needs movz+movk → MISSED
mov  w8, #0x61eb
movk w8, #1, lsl #16
cmp  w2, w8
b.ne <fallthrough string>
```

`_decode_cmp_imm` returns None for `cmp w2, w8` (register form), so the loop
`continue`s. Even if it matched, the `imm > 4096` guard would reject the value.
Net: all enum values > 4095 are invisible.

## Proposed change

Add a **register-compare arm** alongside the existing immediate arm in the
isolated-value loop. Pseudocode:

```python
# Existing immediate arm handles  cmp wN, #imm12  (values ≤ 4095).
# New arm: register-materialized compare for values that exceed 12 bits.
#   movz wReg, #lo16  [; movk wReg, #hi16, lsl #16]
#   cmp  wTest, wReg
#   b.eq <string@target>  |  b.ne <string@fallthrough>
if _is_cmp_reg_reg(w0):                       # cmp wA, wB  (no immediate)
    reg = _cmp_second_reg(w0)                 # wB
    val = _materialized_value(insns, words, i, reg)   # scan back ≤4 insns
    if val is None or not (0 < val < (1 << 31)):
        continue
    cond = _decode_bcond(w1)
    if cond == _COND_EQ:   string_va = <b.eq target, same as immediate arm>
    elif cond == _COND_NE: string_va = insns[i + 1].addr   # fall-through (i is cmp)
    else: continue
    # ... identical _read_enum_string(find_adrp_add_target(...)) as immediate arm
    _add(val, name)
```

`_materialized_value(insns, words, cmp_idx, reg)`:
- scan backward up to ~4 instructions for `movz reg, #lo16` and (optionally)
  `movk reg, #hi16, lsl #16`;
- compose `value = lo16 | (hi16 << 16)` — **compose both halves, never let one
  overwrite the other** (the movz sets bits [15:0], the movk sets [31:16]);
- return None if no movz found.

Notes:
- Bound by `< 2**31` (or the proto int32 range), NOT `_SPARSE_MAX_RANGE`. The 4096
  cap is meaningful only for the 12-bit immediate form; the whole point of this
  arm is large values.
- Reuse the existing b.eq-target / b.ne-fall-through string-location logic and the
  preceding-SUB bias handling verbatim — only the value source changes (register
  materialization instead of the cmp immediate).
- Decode helpers needed: a `cmp` shifted-register form check and movz/movk
  immediate+shift extraction from the raw word. The native mini-decoder may render
  some of these as `unk`; capstone (the venv decoder) decodes them. Gate on the
  mnemonic/op_str when capstone output is available, mirroring how the rest of the
  extractor already reads `ins.mnemonic`/`ins.op_str`.

## Verification (prototype confirmed)

A standalone prototype of the register-compare arm over `typeAsString:` recovers
exactly the six missing values with correct names:

```
11805 -> TypePushingWheelchair
12150 -> TypeIndoorRunning
17150 -> TypeIndoorWalking
18240 -> TypeSwimming
19150 -> TypeDownhillSkiing
90603 -> TypeOutdoorWheelchair     # = 0x61eb | (1<<16); compose movz+movk
```

→ `CLPMotionActivityType` 26 → 32 values. (The prototype initially yielded 25067
for the last one by iterating movk before movz and overwriting; the real fix must
OR the halves — final value is 0x161eb = 90603.)

## Scope / risks

- General: fixes any sparse enum with values > 4095 (HKWorkout-derived types, large
  sentinels). Most common enums stay ≤ 4095 and are unaffected.
- Additive only — a new detection arm; the immediate / jump-table / cbz arms are
  unchanged, so existing recoveries can't regress. New pairs flow through the same
  `_add` dedup (`seen_values`), so a value already found by another arm won't
  double-count.
- Snapshot churn limited to enums that actually contain >4095 values (regenerate
  and review). `confirmed` stays False for the jump-table path (gaps skipped), so
  no confirmation-flag surprises.

## Verification recipe

```python
# CLPMotionActivityType (CoreLocationProtobuf) must reach 32 values incl. 90603:
vals = _extract_jumptable_enum_values(ctx, typeAsString_imp, st)[0]
assert {11805,12150,17150,18240,19150,90603} <= {v for v,_ in vals}
assert dict(vals)[90603] == 'TypeOutdoorWheelchair'   # movz+movk composed correctly
```
