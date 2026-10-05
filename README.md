# ios_protobuf_decoding

Two tools for working with the protobuf traffic that iOS devices exchange with Apple:

| Package | What it does |
|---|---|
| [`apple_protobuf_extractor/`](apple_protobuf_extractor/README.md) | Reconstructs `.proto` schemas from compiled Apple binaries (Objective-C `PBCodable` classes in a Mach-O file or dyld shared cache), with no headers or `.proto` sources. |
| [`ios_decoder/`](ios_decoder/README.md) | Decodes captured iOS network traffic (mitmproxy `.mitm` files) into readable protobuf, using the schemas the extractor produced (committed under `ios_decoder/protos/`). |

## Setup

```sh
python3 -m venv venv                       # Python 3.12+ for the full requirements
./venv/bin/python3 -m pip install -r requirements.txt
```

`protoc` must also be on `PATH` (for example `brew install protobuf`). See each package's README
for details.

## Tests

```sh
./venv/bin/python3 -m pytest
```

Without Apple artifacts or captures, a large part of the suite skips by design (232 tests in
a clean checkout: 227 in the extractor suite, 5 in `ios_decoder`). The summary says so, and a green run in that state does **not**
mean the extractor was exercised against real binaries.

- **Live extractor tests** need the Apple artifacts: a dyld shared cache and the `locationd`
  binary. Put them in `./iphone8_data/` (gitignored), or point `MACHO_DATA_DIR` at a directory
  that holds them. Set `MACHO_REQUIRE_LIVE=1` to make a missing artifact a failure instead of a skip.
  The 8 iOS 27 tests (`test_newer_toolchain_ios27.py`) look for `./ios27_data/dylib/dyld_shared_cache_arm64e`,
  or for the directory named by `MACHO_TEST_IOS27_CACHE`.
- **Real tile, Siri, ARPC and `/fb` tests** use extracts of real captured traffic that are committed
  under `ios_decoder/tests/fixtures/` (about 2.8 MB). The author judged them not sensitive. They can be
  regenerated from your own `.mitm` captures with `extract_tile_samples.py`, `extract_tcp_samples.py`
  and `extract_request_samples.py` (all in `ios_decoder/tests/`); no capture is needed to run the tests.
- **Locator tests** (5) need `notes/proto_match_groundtruth.json` and a set of daemon binaries
  under `iphone8_data/`. The ground-truth file is not part of this repository, so these always skip here.

## Getting the Apple artifacts (optional)

The live tests analyse Apple's own dyld shared caches and binaries. That software is Apple's, so
this repository does not include it, and those tests skip when it is absent. To run them you can
fetch your own copy from Apple's public firmware with [`ipsw`](https://github.com/blacktop/ipsw)
(use is subject to Apple's licence terms). Everything below is written into `iphone8_data/` and
`ios27_data/`, which are gitignored, so none of it can be committed by accident. Run the commands
from the repository root, in a `bash` or `zsh` shell.

**Which firmware.** The golden outputs were generated from an iPhone 8 on **iOS 16.7.11, build
20H360**. `iPhone10,1` and `iPhone10,4` share that firmware. A different build will not match the
golden files.

**1. Install `ipsw`.** The commands here were written for ipsw 3.1.x.

```sh
brew install blacktop/tap/ipsw        # macOS; Homebrew may ask you to run: brew trust blacktop/tap
sudo snap install ipsw                # Linux
scoop bucket add blacktop https://github.com/blacktop/scoop-bucket.git && scoop install blacktop/ipsw   # Windows
```

Release binaries are also on the [ipsw releases page](https://github.com/blacktop/ipsw/releases/latest).

**2. Download the iPhone 8 firmware (about 6 GB).** `--urls` instead prints Apple's download URL without
downloading anything.

```sh
mkdir -p iphone8_data/ipsw iphone8_data/dylib
ipsw download ipsw --device iPhone10,1 --build 20H360 --output iphone8_data/ipsw --confirm
IPSW=$(find iphone8_data/ipsw -name '*20H360*.ipsw' | head -1); echo "$IPSW"
```

**3. Extract the dyld shared cache.** This writes `dyld_shared_cache_arm64` and its numbered
sub-caches. If `ipsw` puts them in a sub-folder, the second command moves them up to where the tests look.

```sh
ipsw extract --dyld --dyld-arch arm64 --output iphone8_data/dylib "$IPSW"
find iphone8_data/dylib -mindepth 2 -name 'dyld_shared_cache_arm64*' -exec mv {} iphone8_data/dylib/ \;
```

Check that you have the right cache:

```sh
ipsw dyld info iphone8_data/dylib/dyld_shared_cache_arm64 | grep -E 'OS Version|Num Images|Cache UUID'
# expect:  OS Version = 16.7,  Num Images = 2705,  Cache UUID: F203FF1D-3CE6-3F7A-9849-791B1C1F4B8B
```

**4. Extract the standalone binaries** (`locationd`, `geod`, `remindd`, `transparencyd`,
`nptocompaniond`, `DPSubmissionService`) and put them where the tests expect them.

```sh
ipsw extract --files --flat --output iphone8_data/extracted \
  --pattern '(usr/libexec/(locationd|remindd|transparencyd|nptocompaniond)|GeoServices\.framework/geod|DPSubmissionService\.xpc/DPSubmissionService)$' \
  "$IPSW"
mkdir -p iphone8_data/libexec
mv iphone8_data/extracted/{remindd,transparencyd,nptocompaniond} iphone8_data/libexec/
mv iphone8_data/extracted/{locationd,geod,DPSubmissionService} iphone8_data/
```

**5. Extract the GeoServices image from the cache.** This prints an "experimental" warning; that is expected.

```sh
ipsw dyld extract iphone8_data/dylib/dyld_shared_cache_arm64 GeoServices --output iphone8_data
```

**6. iOS 27 cache (optional; about 12 GB).** Only the 8 tests in `test_newer_toolchain_ios27.py`
use it. This extracts just the cache from Apple's server, without keeping the whole firmware.

```sh
mkdir -p ios27_data/dylib
ipsw download ipsw --device iPhone17,3 --build 24A437 --dyld --dyld-arch arm64e --output ios27_data/dylib --confirm
find ios27_data/dylib -mindepth 2 -name 'dyld_shared_cache_arm64e*' -exec mv {} ios27_data/dylib/ \;
```

**7. Run the suite with the live tests enforced.**

```sh
MACHO_REQUIRE_LIVE=1 ./venv/bin/python3 -m pytest
```

With everything in place, only the 5 locator tests should still skip. The firmware downloaded in step 2
can be deleted afterwards (`rm -r iphone8_data/ipsw`); the tests do not use it.

## Provenance

This repository was created as a snapshot of two directories from a larger private research
repository, taken at its commit `9115ef2`. It starts with no history. Some things you will meet in
the code reflect that origin:

- Comments and notes refer to predecessor tools that are not included (`mitm_traffic_parser`,
  `addon_ios`, `find_protobuf_for_url`, `proto_diff`, `macho_disasm`) and to commit hashes from the
  original repository.
- The generated `.proto` files carry the header `// Generated by macho_project`. That is the
  original repository's name, kept so the committed outputs stay byte-identical to what the
  extractor emits.
- `apple_protobuf_extractor/validate_ref.py` and `scripts/oneoff/validate_protos_dump.py` read a
  hand-decoded reference set (`iphone8_reference_protos/`) that is not part of this repository.
- The compiled test fixtures under `apple_protobuf_extractor/tests/` were built on the author's
  machine. Their embedded build paths were replaced in place with a same-length neutral path
  (`/build/./././…/ios_protobuf_decoding`) and nothing else in them was changed. The Swift oracle
  binary was re-signed ad hoc afterwards.
- `ios_decoder/tests/fixtures/` (real tile, Siri, ARPC and `/fb` extracts) was added after the initial snapshot,
  copied from the author's local, gitignored fixture directories; it was not in the original
  repository's git history.
- The real latitude/longitude values that a formatter test used were replaced with synthetic numbers
  that exercise the same behaviour.

## Licence

No licence has been chosen yet.
