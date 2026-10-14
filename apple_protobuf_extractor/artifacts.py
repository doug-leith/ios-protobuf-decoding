"""Single source of truth for where the iPhone8 input artifacts live.

Every path the tool/tests/probes need derives from ONE knob — the *data
directory* that holds the dyld shared cache (``dylib/``) and the standalone
``locationd`` / ``geod`` / ``GeoServices`` binaries:

    MACHO_DATA_DIR env var, else  <repo>/iphone8_data

So relocating or renaming the artifact folder is a one-line change here
(:data:`DEFAULT_DATA_DIRNAME`) or a single env var (``MACHO_DATA_DIR``) — no
edits scattered across the codebase.

Per-artifact env overrides are still honoured (back-compat / one-offs), and take
precedence over the data dir:

    MACHO_TEST_CACHE      cache directory (containing dyld_shared_cache_arm64*)
    MACHO_TEST_LOCATIOND  standalone locationd binary
    MACHO_TEST_BINARY     standalone GeoServices binary
    MACHO_TEST_GEOD       standalone geod binary
"""
import os

#: Repo root = parent of the ``apple_protobuf_extractor/`` package dir this file lives in.
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

#: Folder (under the repo root) holding the iPhone8 artifacts.  THE knob — change
#: this (or set ``MACHO_DATA_DIR``) to point the whole tool at a different dump.
DEFAULT_DATA_DIRNAME = "iphone8_data"

#: Cache file basenames, in preference order (arm64e before arm64).
CACHE_BASENAMES = ("dyld_shared_cache_arm64e", "dyld_shared_cache_arm64")


def data_dir():
    """Root directory of the iPhone8 artifacts (cache + standalone binaries)."""
    return os.environ.get("MACHO_DATA_DIR", "").strip() or \
        os.path.join(REPO_ROOT, DEFAULT_DATA_DIRNAME)


def cache_dirs():
    """Ordered candidate dirs for the dyld cache: ``MACHO_TEST_CACHE`` (if set)
    first, then ``<data_dir>/dylib``.  Callers that scan for the cache file use
    this so an explicit override that lacks the file falls back to the default."""
    dirs = []
    env = os.environ.get("MACHO_TEST_CACHE", "").strip()
    if env:
        dirs.append(env)
    dirs.append(os.path.join(data_dir(), "dylib"))
    return dirs


def cache_dir():
    """First existing cache dir (override first), else the default dir."""
    for d in cache_dirs():
        if os.path.isdir(d):
            return d
    return cache_dirs()[-1]


def cache_file():
    """Absolute path to the main dyld cache file, or ``None`` if not present."""
    for d in cache_dirs():
        for name in CACHE_BASENAMES:
            p = os.path.join(d, name)
            if os.path.isfile(p):
                return p
    return None


def locationd_path():
    return os.environ.get("MACHO_TEST_LOCATIOND", "").strip() or \
        os.path.join(data_dir(), "locationd")


#: Relative path, under ``data_dir()``, of the GeoServices image inside the
#: dylib/ cache-file tree — see :func:`geoservices_path`.
_GEOSERVICES_CACHE_TREE_REL = os.path.join(
    "dylib", "System", "Library", "PrivateFrameworks",
    "GeoServices.framework", "GeoServices")


def geoservices_path():
    """Path to a GeoServices Mach-O image, for tests that don't need a
    genuinely standalone binary (see the big caveat below).

    Search order: ``MACHO_TEST_BINARY`` env var, then ``<data_dir>/GeoServices``
    (a real standalone copy, if one is ever placed there), then the
    dylib/-cache-tree copy already present under ``data_dir()`` (see
    :data:`_GEOSERVICES_CACHE_TREE_REL`).

    CAVEAT: on-device, GeoServices only ships inside the dyld shared cache —
    there is no genuinely standalone build. The dylib/-tree copy this falls
    back to is a cache EXTRACTION: its ObjC selector names do not resolve
    (0% — they live in the cache's shared string table, outside this image's
    own vmaddr range; see commit 148f9a5, "Replace no-symbols fallbacks with
    an up-front error/warning gate"). It's fine for callers that don't need
    selector-name resolution (raw section presence, embedded C++ descriptor
    bytes); `proto.extractor.extract_all()`'s full ObjC-selector-based
    pipeline will correctly refuse it (ProtoClassDetectionError /
    SelectorsUnresolvedError) — that is NOT a bug to work around here."""
    override = os.environ.get("MACHO_TEST_BINARY", "").strip()
    if override:
        return override
    standalone = os.path.join(data_dir(), "GeoServices")
    if os.path.isfile(standalone):
        return standalone
    return os.path.join(data_dir(), _GEOSERVICES_CACHE_TREE_REL)


def swift_oracle_path():
    """Path to the committed swift-protobuf ORACLE fixture binary (see
    tests/swift_oracle_fixture/README.md) — a genuinely-compiled, known-schema
    Swift executable used as ground truth by the swift-protobuf recovery
    tests. ``MACHO_TEST_SWIFT_ORACLE`` overrides for a locally-rebuilt binary."""
    return os.environ.get("MACHO_TEST_SWIFT_ORACLE", "").strip() or \
        os.path.join(REPO_ROOT, "apple_protobuf_extractor", "tests",
                      "swift_oracle_fixture", "oracle")
