"""Filesystem locations ios_decoder reads by default."""

from __future__ import annotations

from pathlib import Path

# repo root = parent of this package
REPO_ROOT = Path(__file__).resolve().parents[1]
_PKG_DIR = Path(__file__).resolve().parent

# ``ios_decoder/protos`` holds COMPLETE, UNMODIFIED apple_protobuf_extractor output — one
# subdirectory per extracted framework (e.g. ``protos/CoreParsec/``), package names and
# ``// Source:`` headers preserved, so each subdir is a full record of one extraction run.
PROTOS_ROOT = _PKG_DIR / "protos"
# Every framework subdir is its own search + protoc ``-I`` include path (the extractor's
# imports are bare filenames resolved within a framework). Globbed so dropping in a new
# extraction needs no code change. The root itself is listed first so the compiled
# descriptor cache lands at ``protos/.descriptor_cache`` (not inside a framework subdir).
_FRAMEWORK_DIRS = sorted(
    p for p in PROTOS_ROOT.glob("*") if p.is_dir() and not p.name.startswith(".")
) if PROTOS_ROOT.is_dir() else []

# Default schema dirs, searched in order: the ``protos`` root + each committed
# framework subdir (apple_protobuf_extractor output — GeoServices/locationd/
# CoreLocationProtobuf for the geo+positioning endpoints, plus the smoot /fb types).
# Every endpoint in the table now resolves against this committed output, so the
# decoder is self-contained — the external hand-curated ``addon_ios`` oracle is no
# longer in the path (a caller can still add it via report's ``--proto-dir``).
# Tile parsing and gloria tile-id math need nothing from here.
DEFAULT_PROTO_DIRS = [PROTOS_ROOT, *_FRAMEWORK_DIRS]
