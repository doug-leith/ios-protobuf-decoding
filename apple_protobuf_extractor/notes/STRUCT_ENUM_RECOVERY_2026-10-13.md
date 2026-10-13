# Enum members of inline C structs, and the PDDepartureSequence.operatingHours binding — 2026-10-13

Trigger: `report_on_apple_location_services/notes/codex_eval/more_specific_check.md` listed five messages
(`GenericTile`, `JunctionElement`, `NavigationAudioFeedback`, `Timepoint`, `VLFPositionContextClassification`;
6 enum fields) "with no ObjC class" that the Extractor schema types as plain `int32`, and
`PDDepartureSequence` field 11 as `operatingHoursCount uint64`.

## 1. What the extractor did before this change

* **The five structs were already recovered.** They are exactly what to-do #37 (`proto/structfields.py`,
  commit 8e7521c, regenerated into `ios_decoder/protos` in 268e0c9) handles: all-scalar C structs held by
  value / as an array in a PBCodable parent. Message name and layout come from the parent ivar `@encode`
  (`{GEOTimepoint=…}`), member numbers from the C serialiser, member names from the `@encode` or the
  dictionary representation. The "no ObjC class" observation is true but is the very case #37 solves, so no new
  "follow the trail from the parent" mechanism is needed.
* **Their enum members were typed `int32`** (`tileType`, `type`, `usage`, `currentRouteTypeAtEndOfNav`,
  Timepoint `type`, VLF `type`): `finalize_struct_fields` built every field from the `@encode` scalar code and
  only ever read the dictionary representation for *names*.
* **`PDDepartureSequence.operatingHours`** was emitted as `repeated bytes operatingHours = 3 // number estimated`
  plus a phantom `uint64 operatingHoursCount = 11`. The array is `^{GEOPDTimeRange=II{?=b1b1}}` (12-byte
  elements, i.e. the same `PDTimeRange` #37 already emits elsewhere); the count ivar is `+0x38`
  (`more_specific_check.md`'s "+0x288" is the address-page offset of the count's *offset variable*, not an ivar
  offset). Root cause, found in the disassembly: this function addresses its stack locals from the frame pointer,
  so the begin/end-mark scratch argument is `sub x1, x29, #0xd8`, not `add x1, sp, #K`. Both
  `writeto._value_is_stack_scratch` and `mapfields._scratch_slot_of` only knew the `sp` form, so the begin mark
  was taken for a plain scalar write and bound to the last offset variable seen (the count's); #37 never saw a
  begin-mark and left the field as bytes.

## 2. Is a general mechanism feasible? Yes — for enum members it is read directly, not guessed

For every struct member the dictionary representation (a called C function, or inlined into the owner's
`_dictionaryRepresentation:`) has, between the member's load and its key, either `+[NSNumber numberWith…]`
(plain number) or the compiler-inlined `xAsString:` name switch that ends in the CFString `"(unknown: %i)"`.
Validated in `more_specific_check.md` (0 of 373 classes over-count, 552/671 known enums carry it, 0 known enums
are emitted through a bare NSNumber). New code (`proto/structfields.py`):

| step | source | reliability |
|---|---|---|
| member is an enum | the member's own code span (first load → key) references the `"(unknown: %i)"` CFString | structural; no false positive on the 17 non-enum members of the five structs |
| value → name pairs | the same compare chain (`cbz` / `cmp #n; b.eq|b.ne`, each arm loading its CFString) or 8-byte pointer table (`cmp #n; b.hs unknown; ldr x,[table, idx, lsl #3]`, with `sub idx,val,#bias` re-added) the class-level recovery reads — the readers in `proto/enums.py` are reused | structural; values are the binary's own (Nav `currentRouteTypeAtEndOfNav` is 1-based because of `sub w9,w8,#1`; GenericTile `tileType` is 1,2 with 0 the unknown branch) |
| agreement across owners | an owner showing a plain number vetoes the enum; owners that name a value differently drop the values (field becomes the existing "unresolved enum" `int32` + comment) | conservative |
| enum **type name** | `_enum_name_from_pairs` (common SCREAMING_SNAKE value prefix), else a CamelCase head spelled in the values (`VLFPositionContextType_UNKNOWN`), else `<Message><Member>` | HEURISTIC, cosmetic: the name is not in the binary and never reaches the wire (same status as `ENUM_TYPE_NAMES.md`) |

A key-pairing hole this exposed: `NavigationAudioFeedback`'s dictionary keys are chosen with
`csel x3, <BTHFP…>, <bTHFP…>` (two spellings differing only in the first letter's case), which the old rule
(exactly one candidate without `_`) rejected, discarding the whole helper. Such a key now files its member
without naming it (`MemberDict.key = None`; the name comes from the `@encode`), so no spelling is chosen.

Sparse enums: a pointer table with holes is gated by `mov/movk ; lsr ; tbnz|tbz #0` (bit v set = declared);
the holes' slots hold a filler name. `proto.enums._valid_value_bitmask` (shared with the xAsString path) reads
the `tbz` form by default; a struct member's dictionary representation uses the other polarity (`tbnz` TO the
table load, GEOProblemDetail), read only with `allow_tbnz=True` and only when the `tbnz` target is a pointer-table
load. **The xAsString path deliberately does not opt in**: reading every `lsr ; tbnz` there as a validity mask
drops values 0-15 of `ModuleType` (GEOPDModule etc.) and the `UNKNOWN_n` fillers of ~29 enums (golden
`GeoServices.json` caught it). Why that `tbnz` is not a bit-set=declared mask is unexplained -- open question.
The range gate is the nearest `cmp ; b.hs|b.hi` in the member's span
(the class-level reader's 16-instruction look-back is too short once the mask test sits in between).

Owner agreement (`finalize_struct_fields`): the @encode of an array (`^{Tag=II…}`) names no members while
the by-value form does, which made `GEOPDTimeRange`'s owners "disagree" as soon as `operatingHours` joined
them. Layouts are now compared by `(offset, code)`; member names are merged by offset (@encode names first,
dictionary keys for the rest; two sources that name one offset differently still reject the struct).

Not covered: a struct enum whose name switch is a `br` jump table (needs the class-level jump-table reader
refactored to take a span; none of the 6 fields uses one — an enum member that references `"(unknown: %i)"` but
whose switch is not read stays `int32` with the "unresolved enum" comment, never silently a plain integer).

## 3. Results (GeoServices, iPhone 8 cache; whole-image regeneration vs HEAD, which reproduces the committed geo.proto byte for byte)

Only these lines of `geo.proto` change (everything else identical):

* 9 struct enum members become enums: `GenericTile.tileType`, `JunctionElement.type/usage`,
  `NavigationAudioFeedback.currentRouteTypeAtEndOfNav`, `Timepoint.type`, `VLFPositionContextClassification.type`
  (the six from `more_specific_check.md`), plus three it did not list: `ActiveResourceFilter.scale/scenario`
  (`ResourceFilterScale` 0-3, `ResourceFilterScenario` 0-4) and `ProblemDetail.problemType` (sparse, 1-based,
  values 6 and 7 are holes).
* `PDDepartureSequence`: `repeated PDTimeRange operatingHours = 11` replaces `repeated bytes operatingHours = 3`
  (estimated) + `uint64 operatingHoursCount = 11`.
* 0 unresolved enums, 0 messages lost, 0 renumbered fields elsewhere. Goldens `GeoServices.json` (+8 entries,
  20 changed) and `writeto_walk_GeoServices.json` (the two operatingHours bindings) updated; all other
  frameworks' goldens unchanged.
* `ios_decoder/protos` NOT regenerated (needs Doug's OK: it feeds the eval grader and paper numbers).

Enum type names are reconstructed (cosmetic); value numbers and names are the binary's.

## 4. Heuristic status

Principled: frame-pointer scratch; enum-ness via the `"(unknown: %i)"` branch; values/bias/mask from the
instructions; refusal to guess (unresolved enum stays `int32` + comment; owner disagreement drops the claim).
Heuristic, cosmetic, registered: the enum TYPE name (`struct-enum-type-name`). Assumption: the range gate is
the nearest preceding `cmp ; b.hs|hi` in the member's span.

## 5. Adjacent, not done

The 37 class-level enum fields in `more_specific_check.md` (34 `repeated int32`, 3 singular such as
`PDWebModuleConfiguration.type`) are not struct members. The same `"(unknown: %i)"` signal would mark them, but
the class-level harvester reads only multi-valued, non-repeated switches keyed by ivar offset (it requires
>= 2 pairs and has no loop form), so they remain `int32`. That is a separate change in `proto/enums.py`
(currently being edited by another session).
