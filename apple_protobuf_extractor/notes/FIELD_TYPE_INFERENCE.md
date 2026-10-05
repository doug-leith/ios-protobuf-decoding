# How repeated-message field types are inferred

When this tool emits a `.proto`, the element type of a `repeated <message>` field
is not stored anywhere in the binary as a name — it has to be recovered from the
compiled code. The tool uses four tiers, tried in order of decreasing
reliability. **Only the last name-based tier is a guess, and fields resolved by
it are flagged with an inline comment** (see [The warning comment](#the-warning-comment)).

## The resolution tiers

### 1. `readFrom:` dispatch walk — *principled, by address*
The strongest signal. Each proto class has a `readFrom:` parser that routes each
wire field to a handler which `bl`s the element class's `ReadAllFrom` C-core. The
tool builds a binary-wide `{ReadAllFrom address → class name}` index and names the
element by the **call-target address** the handler invokes. This needs no symbols
and cannot be fooled by names — it reads what the deserializer actually
constructs. (`_resolve_repeated_via_dispatch` in `proto/extractor.py`.)

The compiler emits the field→handler routing in two encodings, and the tool reads
both:

- **Jump table** (larger messages): `table[field# − bias] → handler arm`, ending
  in a computed `br`. Each arm's element `bl` names its field's class.
  (`_decode_readfrom_jumptable`.)
- **Compare chain** (few-field messages, and the low fields of a hybrid reader):
  a tag-decode loop with explicit `cmp Wf, #N; b.cond TGT`, where `Wf` is the
  field-number register (`field# = tag >> 3`). The tool resolves each field's
  **handler block by control flow** (`_compare_chain_blocks`): `b.eq TGT` puts
  field `N`'s handler at `TGT`, `b.ne TGT` puts it at the fall-through. Each
  element `bl` is bound to the field whose block address-range contains it
  (`_field_for_addr`). This matters because Apple often places a field's handler
  as a **forward-branch target at a higher address** than the textually-preceding
  compare — a naive "most recent `cmp` wins" scan mis-attributes those (e.g. it
  tagged `GEOPDExternalAction`'s field-2 block as field 1). Only comparisons on
  `Wf` with a legal field number (≥ 1) define a block, so a `bl` outside every
  field block (a runtime helper in the preamble) is ignored.
  (`_resolve_compare_chain_elements`.)

The jump table takes precedence; the compare chain fills any field it doesn't
cover (so a hybrid reader gets both, and a table-less reader still resolves).

**Applying a dispatch result safely.** The dispatch map is keyed by field
*number*, so a result is attached to an ivar only when the ivar↔number match is
trustworthy: the number is **confirmed** (from the writeTo:/pointer-table
analysis), or the message has a **single field** and the dispatch resolved a
single entry (unambiguous). An unconfirmed ordinal is otherwise not trusted —
the dispatch map also contains singular message fields, so binding by ordinal
could attach a sibling field's type. An ABI-confirmed `repeated string` (distinct
write helper) is never overridden by a dispatch hit.

**The adder→ivar lever — binding by ivar instead of by number.** The
number-keyed application above can't reach a repeated-message field whose number
the writeTo:/pointer-table pass left *unconfirmed*. For those, a second pass
reads the binding **directly from each dispatch handler**, with no field number
involved (`_resolve_repeated_via_dispatch_ivars`). A repeated-message handler —
whether a jump-table arm or a `cmp Wf,#N` compare-chain block — contains two
calls: a `bl` to the element class's `ReadAllFrom` core (names the *element
type*), and a `bl` to the field's generated `_addNoFlags<X>:` accessor (names the
*ivar*). The accessor pins the exact backing ivar **structurally**: it loads its
array through the runtime ivar-offset variable (`adrp+ldrsw` → a slot whose 4-byte
value *is* the ivar's byte offset), and that offset is matched against the class's
`NSArray`/`NSMutableArray` field ivars (`_adder_array_ivar`). This excludes the
flags/has-bits ivar the accessor also touches and every singular-message ivar, so
the element type is attached to the right ivar with no ordinal guess. A *singular*
message field has a setter, not an adder, so it is never bound here — which is
exactly what avoids the singular-vs-repeated mis-binding that defeated an
ordinal-based attempt (e.g. `GEOETARequest`'s singular field-3 `GEOWaypoint` vs
repeated field-4 `destinations`). The lever binds only the **type**; it never
adopts the dispatch's field *number* (some readers yield an unreliable index, and
the writeTo:/pointer-table pass owns number confirmation), and it never overrides
an ABI-confirmed `repeated string`. On GeoServices this types 10 fields the
heuristics left as `bytes` and converts 3 name-suffix guesses into confirmed
ground truth, with no changes on locationd / CoreLocationProtobuf.

> **Wrapper→separate-core classes.** Some classes wrap their dispatch in a
> separate `ReadSpecified` core that the `readFrom:` anchor only *calls* past an
> early `ret` (e.g. `GEOPDDepartureSequence`). `_find_dispatch_core_via_wrapper`
> reaches that core: it scans the wrapper (bounded to the function, via raw
> words) for the `b`/`bl` callee whose body decodes into a validated jump table
> **and** whose arms call one of *this* class's own method IMPs — the identity
> check that rejects a nested message's reader the wrapper also calls. The arms
> are then keyed by field number as usual, and bound to ivars by the
> writeTo:-confirmed number (these classes do have confirmable numbers, contrary
> to an earlier assumption). On GeoServices this resolves ~120 previously-`bytes`
> repeated-message fields and replaces ~35 Strategy-2 guesses with ground truth;
> it never overrides a principled Strategy-1 type. (`_resolve_repeated_via_dispatch`
> runs it only when the direct decode found no table, so it is purely additive.)

### 2. Strategy 1 — `+[Class xyzType]` metaclass method — *structural*
Apple's generated metaclass exposes a `+fooType` method whose body returns
`[GEOFoo class]`. The tool finds the method and **disassembles its IMP** to read
the returned class. The method name is derived from the field name, but the
resulting *class* comes from the code, so name ambiguity can't mislead it.
(Strategy 1 in `_repeated_element_type` + `_resolve_repeated_type`.)

### 3. Write-helper string reclassification — *ABI-confirmed*
A distinct ABI write helper is used for `NSString` vs message elements, so a
field matching the string write helper is definitively `repeated string`.

### 4. Strategy 2 — name-suffix classlist match — **a guess**
The fallback. The field's ivar name is singularized and capitalized
(`_mapsResults` → `MapsResult`), and the tool looks for **exactly one** class in
the binary whose name ends with that string (`GEOPDMapsResult`). If the match is
unique it is used; if two or more classes share the suffix (generic suffixes like
`Value`, `Result`, `Info`) the field falls back to the safe `repeated bytes`
instead of guessing.

This is a **name-based heuristic**. The uniqueness guard is its only safety net,
so a uniquely-matching-but-wrong class can still slip through. Every field
resolved this way is therefore flagged (below).

If none of the four tiers fires, the field is emitted as the safe
`repeated bytes`.

## Why Strategy 2 is kept (it does real work)

A census tallied every repeated-message field across three
binaries by the tier that resolved it (after the compare-chain tier was added
2026-06-08):

The census counts each tier's **net contribution** — fields it resolved that the
name heuristics did not, or resolved differently:

| tier                          | GeoServices | locationd | CoreLocationProtobuf |
|-------------------------------|------------:|----------:|---------------------:|
| 1. dispatch (net, by address) |          42 |         2 |                    — |
| 2. Strategy 1 (metaclass)     |         516 |        25 |                   43 |
| 4. Strategy 2 (name-suffix)   |          77 |         4 |                    0 |

The compare-chain encoding + single-field rule resolve fields that previously fell
back to `repeated bytes` (e.g.
`GEOPDPlaceGlobalCommonResult.placeContextMetadatas → GEOPDPlaceContextMetadata`),
and several the heuristics had only name-guessed now come from principled dispatch
(3 fewer Strategy-2 guesses). Total repeated-message resolution on GeoServices rose
to 635 of the candidate fields.

Strategy 2 is still the **sole** resolver for 77 message fields that neither the
dispatch walk nor the metaclass method can reach — e.g.
`GEOLPRWorld.powerTypes → GEOLPRPowerType` and
`TRANSITPbLocationFingerprint.macs → TRANSITPbTransitMac`. It earns its place,
which is why it is not removed.

(For contrast, two older name-overlap fallbacks — "Pass A" exact pool-suffix and
"Pass B" word-overlap exclusion — resolved **zero** fields in the same census and
were removed on 2026-06-08. Strategy 2 is different: it carries real load.)

## The warning comment

Because Strategy 2 is a guess, any field it resolves is emitted with an inline
comment so you are alerted that the type is less certain than the rest:

```proto
repeated GEOLPRPowerType powerTypes = 4;  // type guessed from field name (name-suffix heuristic / Strategy 2), unverified — see FIELD_TYPE_INFERENCE.md
```

This is independent of the `number estimated` comment, which is about the field
*number* (recovered from ivar order rather than the dispatch table), not its
type. A field can carry both comments.

### What to do when you see it
- Treat the element type as a hypothesis, not a fact.
- To verify, check whether the named class is the real element type — e.g. look
  at the class's `readFrom:`/`writeTo:` in a disassembler, or cross-check against
  a hand-decoded reference.
- A cache-native extraction (`--framework` + `--cache`) resolves more selectors,
  which lets the stronger tiers (1 and 2) fire and removes many of these guesses.

## Where this lives in the code
- `proto/extractor.py`
  - `_resolve_repeated_via_dispatch` — tier 1 (by field number); runs both
    dispatch encodings.
  - `_resolve_repeated_via_dispatch_ivars` — tier 1 by **ivar** (the adder→ivar
    lever); `_resolve_repeated_element_ivars` (jump table) +
    `_resolve_compare_chain_ivars` (compare chain) + `_adder_array_ivar`
    (accessor's ivar-offset variable → backing ivar). `_locate_dispatch_arms`
    memoises the shared arm decode for both tier-1 resolvers.
  - `_decode_readfrom_jumptable` / `_find_dispatch_cluster` — the jump-table form.
  - `_resolve_compare_chain_elements` / `_find_field_number_register` /
    `_decode_lsr_imm` — the compare-chain form.
  - `_repeated_element_type` — Strategies 1 and 2; the census note is inline here.
  - `_resolve_repeated_field_type` — sets `via_name_suffix=True` on the result
    when a concrete class came from Strategy 2.
  - `extract_proto_message` — attaches `_NAME_SUFFIX_GUESS_NOTE` to the
    `ProtoField.type_inference_note` for flagged fields.
- `proto/models.py` — `ProtoField.type_inference_note`.
- `proto/emitter.py` — `_emit_field` renders the note as an inline `//` comment.
