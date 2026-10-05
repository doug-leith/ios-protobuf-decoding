# ios_decoder

Offline decoder for captured iOS network traffic. Point it at a mitmproxy `.mitm`
capture and it prints, per flow, the decoded request/response bodies — Apple
protobuf, Siri, ad telemetry, DNS lookups, certificates, map/location tiles, and
more — plus the `+++` analysis markers used for scripted grep/awk analysis.

It is a clean, offline rewrite of the original live mitmproxy addon
(`addon_ios/ios_decoding_helpers.py`). Decoding is **decoupled from capture**: it
reads a saved `.mitm` file via `mitmproxy.io.FlowReader`, so a capture can be
re-decoded reproducibly every time the schemas improve. Protobuf is decoded with
**pure `google.protobuf`** — `protoc` is used only as a one-time `.proto` →
descriptor compiler (cached), never at decode time.

## Install

`ios_decoder` lives in this repo and shares its virtualenv (Python
3.12+). The one non-pip system dependency is **`protoc`** (used to compile the
`.proto` schemas once); install it separately, e.g. `brew install protobuf`.

| OS | install `protoc` |
|----|------------------|
| macOS | `brew install protobuf` |
| Debian/Ubuntu | `sudo apt install protobuf-compiler` |
| Windows | `choco install protoc` (or download a release) |

```sh
# from the repo root
python3 -m venv venv                               # Windows: py -3.12 -m venv venv
./venv/bin/python3 -m pip install -r requirements.txt
```

That pulls in everything `ios_decoder` needs: `mitmproxy` (capture reading) +
`protobuf`, plus `cryptography` (certs/OCSP) and `hpack`/`h2` (Siri HTTP/2) which
come with mitmproxy, and `dnspython` (DoH). `cbor2` is optional — without it,
`application/cbor` bodies degrade to a clear note instead of decoding.

> **Platform note.** Examples call the venv interpreter as `./venv/bin/python3`
> (macOS/Linux). On **Windows** use `venv\Scripts\python` instead, or
> `venv\Scripts\activate` once and then just `python`.

## Test

```sh
./venv/bin/python3 -m pytest ios_decoder/tests/      # a few hundred self-contained tests
```

Tests are self-contained (they synthesise their own fixtures). A few are
*live-gated*: they run only when real, git-ignored capture fixtures are present and
skip otherwise.

## Usage

```sh
./venv/bin/python3 -m ios_decoder.report CAPTURE.mitm [options]
```

| Option | Effect |
|--------|--------|
| `--url REGEX` | only flows whose URL matches `REGEX` |
| `--decoded-only` | only flows that produced a protobuf/ARPC/structured decode |
| `--limit N` | stop after `N` flows with decoded output |
| `--max-flows N` | process at most `N` flows (after filtering) |
| `--user-agent SNIPPET` | only flows whose `User-Agent` starts with `SNIPPET` (case-insensitive prefix) |
| `--start-time` / `--end-time EPOCH` | only flows in this request-timestamp window (epoch seconds) |
| `--hex` | show undecoded bodies as a hex dump instead of `repr()` |
| `--full-bodies` | show undecoded bodies in full instead of a truncated preview |
| `--no-request-log` | suppress the `+++REQUEST` / `+++REQHEADERS` summary lines |
| `--proto-dir DIR` | directory of `.proto` schemas for named decoding (repeatable; default: the committed `protos/` extractor schemas) |

### Examples

```sh
# Everything in a capture, decoded flows only
./venv/bin/python3 -m ios_decoder.report capture.mitm --decoded-only

# Just the Siri traffic (ACE stream + the gRPC sidecar)
./venv/bin/python3 -m ios_decoder.report capture.mitm --url 'guzzoni|swallow' --decoded-only

# What domains did the device resolve? (DNS-over-HTTPS)
./venv/bin/python3 -m ios_decoder.report capture.mitm --url 'dns-query' --decoded-only

# GeoServices place lookups, first 5, raw bodies in full
./venv/bin/python3 -m ios_decoder.report capture.mitm --url 'dispatcher\.arpc' --limit 5 --full-bodies

# Pull just the analysis markers for scripting (grep/awk on the +++ lines)
./venv/bin/python3 -m ios_decoder.report capture.mitm | grep '^+++'
```

The `+++` markers (`+++REQUEST`, `+++REQHEADERS`, `+++XYZ`, `+++LATLON`,
`+++LATLON_BOUNDBOX`, `+++XP`, `+++AMP`, …) are a stable line format meant to be
grepped out and parsed — that contract is preserved from the original addon.

## What it decodes

- **Apple `PBCodable` protobuf** over ARPC (GeoServices / locationd), against named
  `.proto` schemas where known, else schema-free.
- **Unknown fields exactly like `protoc --decode_raw`** — a partial schema still
  prints the fields it doesn't know, by number (the reason `protoc` was originally
  used), with matching hex/float/escaping.
- **Siri** (raw TCP): the ACE stream to `guzzoni` (plist/ping/pong/**speech** packets,
  Opus frames summarised) and HTTP/2 + gRPC to `swallow` (protobuf; FlatBuffers
  bodies are surfaced as a flagged hex preview).
- **Ad telemetry**: iAd (`iadsdk`), and XP / AMP (`xp.apple.com`, `amp-api…`) with
  recursive expansion of nested base64 / JSON / gzip / protobuf.
- **DNS-over-HTTPS** (`application/dns-message` + the `?dns=` GET form) → question +
  answer records (CNAME chains, A/AAAA, HTTPS/SVCB).
- **Certificates / OCSP** (PEM + DER chains; OCSP status with issuer CA).
- **Map/location tiles** (wifi, hrse, cell, cldem, cldavl, global cell, …) via the
  tile-tool library — see [Tile tools](#tile-tools).
- **Heavy MIME**: zip, cbor (optional), img4, plists (incl. embedded base64), gzip,
  JSON, form, XML, text. Anything it can't decode is surfaced as a one-line summary
  (or `--hex`), never silently dropped.

## Tile tools

Apple's map/location tile parsers live in `ios_decoder/tile_tools/` as a uniform
library: each exposes `parse(bytes) → tile`, `render(tile) → str`, and
`bounds(tile) → Bounds | None`. The `report` tool decodes tiles automatically when a
capture contains them (e.g. `cl3.apple.com/3/v2/cldavl.avl.gz`).

Each tool is also a **standalone CLI** (`python -m ios_decoder.tile_tools.<name> FILE`) for
decoding a tile file directly:

```sh
# Apple DEM tile-availability file (cldavl.avl[.gz])
./venv/bin/python3 -m ios_decoder.tile_tools.cldavl cldavl.avl.gz --count
./venv/bin/python3 -m ios_decoder.tile_tools.cldavl cldavl.avl.gz --lookup 53.3 -6.2   # is there a tile here?

# WiFi tile (cl2.apple.com/1/v1/…)
./venv/bin/python3 -m ios_decoder.tile_tools.wifi tile.gz --json

# GSM / LTE / global cell tiles, elevation, signal-environment, …
./venv/bin/python3 -m ios_decoder.tile_tools.gsmcell tile.gz --lookup 1 100
./venv/bin/python3 -m ios_decoder.tile_tools.cldem tile.gz
```

All eight parsers — `cldavl`, `wifi`, `hrse`, `cldem`, `gsmcell`, `ltecell`, `clsef`,
`globalcell` — live in the committed `tile_tools/` library and present the uniform
`parse(bytes)` / `render(tile) -> str` / `bounds(tile)` contract, so `report` drives them
with no shim. (Run each with `--help` for its options.)

## Notes / limitations

- **Named-schema decoding is self-contained.** The `.proto` schemas are the committed
  `apple_protobuf_extractor` output under `ios_decoder/protos/<Framework>/` (GeoServices,
  locationd, CoreLocationProtobuf for the geo + positioning endpoints, plus the smoot `/fb`
  types) — every endpoint in the table resolves against them, so a fresh clone decodes named
  messages with **no `addon_ios` at all**. You can still add extra schema dirs with
  `--proto-dir DIR` (repeatable). With no schema resolvable, protobuf still decodes
  schema-free (fields by number, à la `--decode_raw`) with a one-line note. The tile parsers
  and gloria tile-id math (`+++XYZ`/`+++LATLON` markers) are likewise committed under the
  package.
- **Scope is Apple `PBCodable` protobuf** (see the repo README). Foreign runtimes are
  surfaced honestly, not mis-decoded: FlatBuffers bodies (Siri auth) are shown as a
  flagged hex preview rather than guessed.
- **Apple VMP4 vector tiles** (the `gspe19-ssl.ls.apple.com/tile.vf` responses) are a
  binary container, **not** protobuf: after optional gzip the body starts with the ASCII
  bytes `VMP4`, then a little-endian table of typed, partly zlib-compressed sections. Apple
  hand-parses them (`GEOVectorTile`) and there is no schema, so their bodies are **not**
  decoded. The `gspe79-ssl.ls.apple.com/{style}/v2/{style}/{quad}` tiles (style 72) are a
  different thing: plain protobuf (`SmartInterfaceSelectionTile`, hand-crafted descriptor in
  `addon_ios/SmartInterfaceSelection.proto`). A standalone *layout detector* for those
  protobuf tiles is vendored at [`vmp4.py`](vmp4.py)
  (`is_smart_interface_selection_tile(bytes)`, formerly `is_vmp4`; CLI
  `python -m ios_decoder.vmp4 [--scan] PATH`). The module keeps its old file name; the
  detector does not match real VMP4 `tile.vf` bodies. It is not yet wired into `report`. See
  `../notes/VMP4_TILE_FORMAT.md` (corrected 2026-10-04).
- Per-flow failures are isolated — one malformed body is reported to stderr and the
  rest of the capture still decodes.

## Lessons learned — abandoned approaches to *automatic* schema selection

The production decoder uses an **explicit endpoint table** (`endpoints.py`): each URL
pattern is mapped, by hand, to the request/response message and framing. This is
deliberate. Two attempts at *automatically* picking the right protobuf schema for an
arbitrary captured body were tried and abandoned. Both are recorded here so the same
dead ends aren't re-explored.

1. **`find_protobuf_for_url` — derive the schema from the binary, per URL.**
   The idea was to statically analyse a framework/binary (`GeoServices`, `locationd`, …)
   and, for a given URL or lookup-name, recover the exact request/response protobuf
   classes and wire format directly from the ObjC metadata and arm64 code — no manual
   table. It works well as an *inventory* tool (now retired; it was a separate tool in the
   author's earlier research repo and is not included here) and was
   the right way to enumerate the `(functionId, requestProto, responseProto)` triples a
   single image declares.

   It failed as a *general URL → schema resolver* because **every framework/binary has a
   different request/response handler pipeline**. The way a URL is bound to its dispatch
   site, where the `functionId` and `responseClass` come from, whether the body is ARPC-
   or plain-framed, how the endpoint string is stored and reached — all of this varies
   per image. There was no single dispatch shape to key off, so a *unified* resolver
   would have needed bespoke per-framework anchoring logic. At that point you've written
   the endpoint table anyway, only less legibly and with a static-analysis engine in the
   loop. The hand-maintained table is smaller, auditable, and doesn't silently mis-bind.

2. **Fuzzy locator + structural matcher — guess the schema from the bytes.**
   The idea was schema-free: given a captured body, (a) a *locator* would narrow the
   universe of candidate frameworks/binaries down to a handful (e.g. by searching image
   metadata for endpoint/host strings), then (b) a *structural matcher*
   (now [`matcher.py`](matcher.py), ported from the retired `mitm_traffic_parser.match`)
   would score the body's wire shape (field numbers, wire types, nesting) against each
   candidate message descriptor and pick the best fit.

   It failed at **both** stages:
   - The **locator couldn't reliably reduce to a small candidate set.** Simple string/
     metadata searches didn't pin a body to one or two images — endpoint strings are
     scattered, shared, or absent, so the candidate set stayed large or missed the true
     producer entirely.
   - The **matcher is unreliable on small protobufs.** A short message exposes only a few
     field numbers and wire types, and many unrelated descriptors are wire-compatible
     with that thin evidence (wire type 2 fits a string, bytes, *and* any sub-message;
     low field numbers are ubiquitous). The score is near-degenerate, so the "best match"
     is frequently wrong with no honest way to flag the ambiguity. (The matcher is still
     useful as a *verification* aid against a known-true schema — which is what
     `ios_decoder` keeps it for — just not as a blind classifier.)

   The structural matcher remains valuable for confirming that an *already-chosen* schema
   is consistent with real wire traffic; it is not a substitute for knowing which schema
   to choose.

**Takeaway:** for this corpus, an explicit, auditable URL→schema table beats both
binary-derived and bytes-derived automation. The hard part isn't decoding a body once you
know its type — it's reliably *choosing the type*, and neither automated approach did that
without guessing. If automation is revisited, treat it as a *suggestion* that must be
confirmed against the binary or wire, never as a silent classifier.

### Using the matcher to double-check table changes (optional)

The surviving useful half of approach (2) — the structural **matcher** — is wired up as
an *optional* cross-check so a table edit can be validated against real wire traffic.
The matcher itself is now native to ios_decoder ([`matcher.py`](matcher.py), built on
`rawproto` + a `protoc`-compiled `DescriptorPool` — no cross-tool dependency); the
harness and tests live in the test tree and never enter the production package:

- [`matcher.py`](matcher.py) — the standalone structural matcher (ported from the
  retired `mitm_traffic_parser`): excludes messages whose declared wire types
  contradict the body, then ranks the rest by explained-field count.
- [`tests/matcher_harness.py`](tests/matcher_harness.py) — the reusable harness. It
  reproduces the locator→extract→match pipeline with step (i) (the unreliable
  keyword search) replaced by a **manually-named framework**: point it at a framework's
  extracted descriptors (the committed `protos/<Framework>/` dirs, or a live
  `extract_descriptors(...)` run against a dyld cache), then `crosscheck(body, dir,
  expected_message)` returns a `MatchVerdict`. Only `protoc` is needed.
- [`tests/test_matcher_crosscheck.py`](tests/test_matcher_crosscheck.py) — example
  cross-checks of the `/fb` table against real captures.
- [`tests/locator.py`](tests/locator.py) + [`tests/test_locator_recall.py`](tests/test_locator_recall.py)
  — the actual step-(i) **locator**, for when you want the *full* automated pipeline
  rather than a manually-named framework. It fuses three signals — UA→daemon
  `otool -L`, host/path→framework (the documented manifest-resolver fallback), and
  URL-token→binary string-search — into a candidate framework set. The recall test
  evaluates it against `notes/proto_match_groundtruth.json` (does the candidate set
  contain the true framework?) and currently locates 13/13 evaluable producers while
  routing the third-party producers to nothing. It needs the libexec daemon binaries +
  `otool` and skips when they're absent. This is the *fragile* half (the reason
  approach (2) was abandoned) — kept as a regression gauge, not a production path.

```sh
# -s prints the per-body verdict report (matcher winner, rank, confidence)
./venv/bin/python3 -m pytest -s ios_decoder/tests/test_matcher_crosscheck.py
```

The harness asserts only the **reliable** signal — *exclusion*: if the matcher proves the
table's claimed message could not have produced a real body (a hard wire-type
contradiction), the test fails. Ranking and confidence are reported for inspection but
never asserted, because small payloads tie across many messages (the documented matcher
weakness). The whole module **skips** cleanly when its heavier deps (`protoc` +
`mitmproxy`), the framework's descriptors, or a capture aren't present — so it never
breaks a normal run. To cover a new endpoint, add its `(framework, message)` and point the
harness at that framework's descriptor dir.
