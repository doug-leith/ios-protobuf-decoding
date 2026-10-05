# ios_decoder — TODO

Design principles (see memory `design-principles`): transparent · cautious · portable · robust.

## Open

### Label tile bodies in `report` (VMP4 container vs style-72 protobuf tile)
Two different tile bodies currently show as unmatched/raw (CORRECTED 2026-10-04; earlier
text here treated them as one thing called VMP4):

1. **Real VMP4** (`gspe19-ssl.ls.apple.com/tile.vf`): not protobuf. After optional gunzip
   the body starts with the bytes `VMP4` (all 159 successful iphone8 responses do), followed
   by a little-endian section table. Detect with `gunzip(body)[:4] == b"VMP4"`; `is_smart_interface_selection_tile`
   (formerly `is_vmp4`) does NOT match these. **Consider** emitting a one-liner such as `// Apple VMP4 vector
   tile (hand-parsed GEOVectorTile, not protobuf; not decoded)` instead of a raw dump.
2. **Style-72 protobuf tiles** (`gspe79-ssl.ls.apple.com/72/v2/72/{quadkey}`): protobuf that
   parses as `SmartInterfaceSelectionTile` (hand-crafted descriptor, owner-confirmed
   2026-06-17). These are what `ios_decoder/vmp4.py` `is_smart_interface_selection_tile(bytes)` detects (gzip-transparent,
   25/25 recall / 0 FP on the capture corpora). It is NOT yet wired into the decode path.
   **Consider** wiring the matcher entry for this tile type rather than a label. (The
   function was renamed from `is_vmp4` on 2026-10-04; the module file is still `vmp4.py`.)

Detection/labelling only: neither body type has a recoverable PBCodable schema. Full writeup:
`notes/VMP4_TILE_FORMAT.md`.

### Locator TABLE: connection fingerprint → framework/binary with proto descriptor
Distinct from the URL→message **matcher table** (`endpoints.py`) and from the *fuzzy*
locator (`tests/locator.py`, the deliberately-fragile string-search half). The idea: a
small, explicit, auditable **locator table** keyed by a connection fingerprint
(host/path/UA, or a host glob) → the framework/binary that holds the request/response
proto descriptors. This is the reliable, owner-curated counterpart to the fuzzy locator —
no string-search guessing. **The table can be constructed directly from the existing
ground truth** (`notes/proto_match_groundtruth.json` + `notes/host_producer_map.md`): both
already map producer/host → framework for the full evaluable producer set (13/13 located
in `tests/test_locator_recall.py`). Use it to (a) drive the locator→extract→match
cross-check without the fragile step (i), and (b) optionally inform `report` which
framework's descriptors to load for a given connection. Build it from the GT if it
doesn't exist yet.

### ~~Custom unknown-field renderer~~ DONE (2026-06-15, `rawproto.py`)
Unknown fields now render via `rawproto` to match `protoc --decode_raw` byte-for-byte
(hex i64/i32, parse-fully-or-string rule, C-escaping); known fields via `text_format`
(`PrintField`, `as_utf8=False` so non-ASCII octal-escapes like protoc). Verified on the
120-flow `comparison/` golden: 0 unknown-field diffs.

### Remaining old-addon parity gaps (from the comparison golden)
- ~~Float formatting~~ DONE (`rawproto.format_double`/`format_float`, protoc's %.15g/%.17g
  and %.6g/%.9g ladders; render_message formats double/float fields directly). 0 float diffs;
  tested vs the protoc binary.
- ~~wifi_request_tile `Not Found`~~ DONE: `endpoints._text_sentinel` recognizes a short,
  all-printable, non-protobuf body (e.g. the tile server's literal `Not Found`) and renders it as
  `// server returned a plain-text body, not protobuf:\n<text>` instead of a protobuf-decode error.
  Cautious gate (3..256 bytes, printable+a letter, not protobuf-parseable) so a truncated binary
  body still errors. Applied to schema rules + the generic ARPC raw decoders.
- ~~cldavl tile wrapper wording~~ RESOLVED (intentional): the new wording (`First 32 available DEM
  tiles:`) is a clean rewrite; the `+++` markers (the grep/awk contract) already match the addon,
  and this is human-readable body text only, so the wording diff is harmless.
- ~~iAd empty-payload verbosity~~ RESOLVED (intentional): the new `(empty payload)` line is the
  transparent choice — the old addon silently printed nothing. Kept (paired with `length=0`).


### ~~Tile-tool refactor — make the parsers natively uniform~~ DONE (8/8)
The 8 `parse_*.py` tile tools (in gitignored `addon_ios/`) were wrapped by the `tiles.py`
adapter, which hid their inconsistency (3 load idioms, 5 render-fn names, print-based output)
behind a tempfile + stdout-capture shim. They are being migrated into the **committed**
`ios_decoder/tile_tools/` package, one at a time, to the uniform contract:

    parse(data: bytes) -> Tile      # raw body in (gunzips if needed)
    render(tile) -> str             # returns text, never prints
    bounds(tile) -> Bounds | None   # uniform geographic extent for markers (None if N/A)
    + a CLI: `python -m ios_decoder.tile_tools.<name> FILE`

`TileAdapter` gained a `module=` path that drives a migrated tool through that contract with
**no tempfile and no stdout capture**; the legacy shim still covers the not-yet-migrated tools.

All 8 migrated to `ios_decoder/tile_tools/`: cldavl, wifi, hrse, cldem, gsmcell, ltecell, clsef,
globalcell. `tiles.py` now imports **zero** `addon_ios/parse_*` modules — the legacy shim
(tempfile + stdout capture + sys.path hack) is removed; `TileAdapter` is just
`{name, module, render_kwargs}`. Each tool keeps a standalone CLI
(`python -m ios_decoder.tile_tools.<name> FILE …`). Markers: wifi emits `+++XYZ` (via the optional
`tile_xyz` hook) + `+++LATLON_BOUNDBOX`; **every cell + DEM tile (hrse/cldem/gsmcell/ltecell/
global_*) emits `+++LATLON_BOUNDBOX <type>_tile`** from its real extent (owner-requested); only
cldavl/clsef return `bounds()=None` (near-global rasters, no single box). globalcell's 4 endpoints
share one parser, differing only in the CID column label (`render_kwargs={"kind": …}`).

**Real-tile regression tests** (2026-06-15): `extract_tile_samples.py` pulls one real body of
*every* tile type out of the captures (richest = `mitm_17feb_cont5.mitm`) into
`tests/fixtures/tiles_real/<type>.bin` (committed); each `test_tile_*` has a live test (`saved_tile(name)`,
skips if absent) that decodes the real tile + asserts markers. **All 11 types found and decode
clean on real data** — this validated the previously synthetic-only ports (hrse/ltecell/clsef/
global_*) against real Apple tiles. 227 tests, 0 skips (with fixtures present).

### Remaining addon decoders to port
- ~~Heavy MIME types~~ DONE: `certs.py` (PEM+DER X.509 chains + OCSP, via `cryptography`,
  replacing the old openssl-subprocess / dump_object mess — OCSP went 275 spam lines → 5 clean),
  `archives.py` (zip→entries+nested plist, cbor [cbor2 optional], img4 [ipsw, graceful]). Wired
  in `mime.py` (ocsp/cert/zip/cbor handlers + zip-PK + img4 magic) and endpoints (humbug/baa,
  swallow GetCertificate). Verified vs old tool: same facts, far tidier; new also decodes
  `x-x509-ca-cert` the old tool dumped raw.
- ~~DNS-over-HTTPS~~ DONE (`doh.py`, via `dnspython`): decodes `application/dns-message` bodies
  (POST request + all responses) and the GET `?dns=<base64url>` query param; renders question +
  answer records (CNAME chains, A/AAAA, HTTPS/SVCB). Wired in `mime.py` (`dns-message` handler) +
  `report.py` (GET `?dns=` request summary). dnspython imported lazily (graceful note if absent).
  Verified on real Google DoH traffic (`8.8.8.8/dns-query`); module named `doh` not `dns` to avoid
  shadowing the dnspython package. 7 tests.
- ~~Geo URL/header markers~~ DONE (`geo.py`): `+++XYZ`/`+++LATLON` from URLs + `maps-tile-*`/
  `X-tilekey` headers; +++LATLON byte-identical to old addon, XYZ unified `(x,y,z)`.
- ~~Per-flow log lines~~ DONE (`reqlog.py`): `+++REQUEST`/`+++REQHEADERS` (+ header hashing) +
  `--user-agent`/`--start-time`/`--end-time`/`--max-flows` filters + `--no-request-log`.
  Both marker streams verified identical to the old addon on the comparison golden.
- ~~iAd telemetry~~ DONE (`iad.py`, both header variants, verified on real traffic).
- ~~XP / AMP telemetry + plist-base64~~ DONE (`nested.py` + `telemetry.py`):
  A1 pattern-based identifier markers (`+++XP`/`+++AMP`), B1 cautious
  expansion (only when confidently typed), C1 inline tree + `<base64 → protobuf>` annotations +
  `// nested-decoded …` note, D = XP + AMP + all plists. Verified on real traffic (XP IDs, full
  AMP onion, 419/419 plists). plist wired via `mime.py` (+ bplist magic catch).
- ~~Siri~~ DONE (`siri.py`): two transports decoded from raw `TCPFlow`s —
  **ACE stream** (`guzzoni`, magic `AA CC EE` + per-direction zlib → plist/nop/ping/pong/speech
  packets; ACE plists rendered with `$class`/`$group`/`$v` label + nested-field expansion) and
  **HTTP/2 + gRPC** (`swallow`, passive frame + HPACK parser, DATA → gRPC → gzip → protobuf;
  non-protobuf e.g. FlatBuffers falls back to a hex preview + format hint). Detection is
  content-based (client stream prefix), per-flow/per-direction state (no singletons), and
  concatenates per direction (segmentation-independent) — fixing the old addon's hard-coded-IP /
  shared-`Siri()` / running-`posn` faults. Wired into `report.py` (TCP-flow branch; non-Siri TCP
  surfaced as a raw summary, never dropped). 15 tests (synthesized ACE/H2 + live-gated real
  fixtures). **Open follow-ups**: speech-packet layout is unverified (no speech fixture in the
  captures — parsing is best-effort, flagged in output); FlatBuffers bodies are shown as hex, not
  decoded (a FlatBuffers reflection decoder would be a separate feature).
