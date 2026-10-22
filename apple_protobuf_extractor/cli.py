"""
cli.py — Command-line interface for the iOS Mach-O proto extractor.

Usage
-----
    # (paths below assume the default data dir <repo>/iphone8_data/;
    #  run from the repo root, e.g. ./venv/bin/python3 apple_protobuf_extractor/cli.py …)

    # Extract directly from the dyld shared cache (no binary file needed)
    python3 cli.py --framework GeoServices --cache iphone8_data/dylib -o ./protos/

    # Extract from a standalone Mach-O binary file (no cache needed)
    python3 cli.py --binary iphone8_data/locationd -o ./protos/

    # List all frameworks embedded in a dyld shared cache
    python3 cli.py --list-frameworks --cache iphone8_data/dylib

    # Dry run (stats only) with a class-name prefix filter
    python3 cli.py --framework GeoServices --cache iphone8_data/dylib --prefix GEO --dry-run

    # All messages into a single file instead of one per ObjC prefix
    python3 cli.py --framework HealthKit --cache iphone8_data/dylib --single-file -o ./protos/

Two input modes:
  * --binary PATH    standalone Mach-O; selectors resolved from the binary's
                     own sections.  --cache is not used.
  * --framework NAME cache-native; selectors resolved through the cache's
                     unified selector pool and the .symbols local-symbol table.
                     Requires --cache.

How to read the output (.proto) — caveats
------------------------------------------
The schema is reverse-engineered from compiled ObjC PBCodable classes, so a few
properties of the original .proto cannot be recovered exactly.  Where the tool is
uncertain it says so in the output; where a fact is physically absent from the binary
it picks a safe canonical default.  Specifically:

  1. int32 vs uint32 is NOT recoverable.  Both compile to the same 32-bit integer ivar
     and the same plain-varint wire encoding (likewise int64/uint64); the only
     tie-breaker is the ivar's signed/unsigned @encode, and Apple often uses a signed
     ivar even for uint32.  The tool emits a canonical default (signed int32 / int64,
     or uint where the ivar is explicitly unsigned); if you know a field is really
     uint32, adjust it by hand — the wire type is already correct.  (NOTE: sint32/sint64
     (zigzag) and the fixed32/fixed64/sfixed* family use DISTINCT wire encodings and
     distinct serializer helpers, so they ARE distinguishable in principle from the
     code — the tool does not yet emit them and currently shows them as int32 (a
     to-do).  bool, float, double, string, bytes, messages and enums are unaffected.)

  2. ESTIMATES ARE ALWAYS MARKED.  When a field NUMBER or TYPE is inferred by a
     heuristic rather than read directly from the class's writeTo:/readFrom: code, the
     emitted field carries an inline `//` comment saying so (e.g. an estimated field
     number, or a repeated-message element that fell back to bytes).  A field with no
     such comment was confirmed from the binary.  Grep the output for these comments to
     see every place the tool was not certain.

  3. Names are ObjC-derived.  Field and message names come from ivar and class names in
     the binary.  These usually match the original .proto, but Apple's ObjC class name
     can differ from the .proto message name (e.g. the class `GEOURLInfo` for a .proto
     message named `URLWithHeaders`).  The tool reports what is in the binary.

  4. Unresolved repeated-message elements fall back to `repeated bytes` (with a
     comment).  The wire encoding is correct (length-delimited), but the element's
     message type could not be named — typically because it is written by an inline C
     struct-writer rather than a normal sub-message.  Treat these as "a repeated
     message whose type we could not identify", not as actual bytes fields.
"""

from __future__ import annotations

import argparse
import logging
import sys
import time
from contextlib import contextmanager
from pathlib import Path
from typing import List, Optional


# ── Argument parser ────────────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    from version import __version__
    p = argparse.ArgumentParser(
        prog="apple_protobuf_extractor",
        description=(
            "Extract .proto schemas (edition 2023: proto3 syntax with explicit field "
            "presence) from protobuf classes in arm64 Mach-O binaries and dyld caches: "
            "Apple PBCodable, C++ libprotobuf and swift-protobuf."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    # ── Source: exactly one of --binary, --framework, --list-frameworks ───────
    src = p.add_mutually_exclusive_group()
    src.add_argument(
        "--binary",
        metavar="PATH",
        default=None,
        help=(
            "Path to a standalone arm64 Mach-O binary file (dylib, framework "
            "binary, or executable).  Selector names are resolved entirely "
            "from the binary's own sections; --cache is not used in this mode."
        ),
    )
    src.add_argument(
        "--framework",
        metavar="NAME",
        default=None,
        help=(
            "Framework (or dylib) name to extract directly from the dyld "
            "shared cache.  Requires --cache.  Matched as a case-sensitive "
            "substring against the image paths embedded in the cache "
            "(e.g. 'GeoServices', 'Foundation', 'libobjc.A.dylib').  "
            "No binary file is needed."
        ),
    )
    src.add_argument(
        "--list-frameworks",
        action="store_true",
        default=False,
        help=(
            "Print all framework/dylib paths embedded in the dyld shared "
            "cache to stdout, one per line.  Requires --cache.  "
            "No extraction is performed."
        ),
    )

    # ── Cache ─────────────────────────────────────────────────────────────────
    p.add_argument(
        "--cache",
        metavar="PATH",
        default=None,
        help=(
            "Path to a dyld shared cache file or directory containing one.  "
            "Required for --framework and --list-frameworks; not valid with "
            "--binary.  Accepts a direct path to the main cache file "
            "(e.g. dyld_shared_cache_arm64) or a folder; numbered sub-cache "
            "files (.01, .02, …) are discovered automatically."
        ),
    )

    # ── Output / filtering ────────────────────────────────────────────────────
    p.add_argument(
        "-o", "--output",
        metavar="DIR",
        default="./protos",
        help="Output directory for .proto files (default: ./protos).",
    )
    p.add_argument(
        "--single-file",
        action="store_true",
        help=(
            "Write all messages to a single <package>.proto instead of "
            "one file per ObjC prefix."
        ),
    )
    p.add_argument(
        "--package",
        metavar="NAME",
        default=None,
        help=(
            "Package name override.  Used with --single-file; "
            "defaults to a sanitised version of the binary/framework name."
        ),
    )
    p.add_argument(
        "--prefix",
        metavar="PREFIX",
        action="append",
        dest="prefixes",
        default=None,
        help=(
            "Only extract classes whose ObjC name begins with PREFIX.  "
            "May be repeated: --prefix GEO --prefix CLP."
        ),
    )
    p.add_argument(
        "--no-cross-image",
        action="store_true",
        help=(
            "--framework mode: do NOT pull in message classes defined in other cache "
            "images.  By default a field typed by a PBCodable class from another image "
            "(e.g. CloudKitDaemon's CKDPRecordIdentifier, defined in CloudKit) is resolved "
            "to the image that defines it (through the class reference the cache binds, "
            "else the one linked image defining that name) and that message is emitted "
            "too, so the output compiles with real message types; with this flag such a "
            "field stays `bytes  // unresolved: <Class>`."
        ),
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Parse and report statistics; do not write any files.",
    )
    p.add_argument(
        "--list-serializers",
        action="store_true",
        help="Print the protobuf serializers present (PBCodable, C++ libprotobuf, "
             "swift-protobuf, GPBMessage, protobuf-c) and the message names under each, then "
             "exit — a quick overview without full extraction.",
    )

    # ── Diagnostics ───────────────────────────────────────────────────────────
    p.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable debug logging from the extractor.",
    )
    p.add_argument(
        "--debug-enums",
        metavar="FILE",
        default=None,
        help=(
            "Write a JSON Lines file with one diagnostic record per "
            "int32/uint32 fallback field, explaining why the field was not "
            "classified as an enum."
        ),
    )
    return p


# ── Cache resolution ───────────────────────────────────────────────────────────

_CACHE_NAMES = (
    "dyld_shared_cache_arm64e",
    "dyld_shared_cache_arm64",
)


def _resolve_cache_path(cache_arg: str, prefer_arm64e: bool = False) -> Optional[Path]:
    """
    Return the main cache file path from *cache_arg*, or None with a warning.

    *cache_arg* may be a direct path to the main cache file, or a directory
    that is searched for dyld_shared_cache_arm64{e}.
    """
    p = Path(cache_arg)

    if p.is_file():
        return p

    if p.is_dir():
        names = (
            [_CACHE_NAMES[0], _CACHE_NAMES[1]] if prefer_arm64e
            else [_CACHE_NAMES[1], _CACHE_NAMES[0]]
        )
        for name in names:
            candidate = p / name
            if candidate.is_file():
                return candidate
        print(
            f"  warning: no dyld_shared_cache_arm64{{e}} found in {p}; "
            "running without cache",
            file=sys.stderr,
        )
        return None

    print(
        f"  warning: --cache path not found: {p}; running without cache",
        file=sys.stderr,
    )
    return None


# ── Progress helpers ───────────────────────────────────────────────────────────

def _step(msg: str) -> float:
    print(f"  {msg}", file=sys.stderr, flush=True)
    return time.monotonic()


def _done(t0: float) -> None:
    elapsed = time.monotonic() - t0
    print(f"    done ({elapsed:.1f}s)", file=sys.stderr, flush=True)


# ── --list-frameworks handler ──────────────────────────────────────────────────

def _cmd_list_frameworks(cache_arg: str) -> int:
    """Print all framework paths in the cache, one per line, to stdout."""
    from macho.dyld_cache import DyldCacheReader
    import warnings

    cache_path = _resolve_cache_path(cache_arg)
    if cache_path is None:
        print("error: could not locate dyld shared cache", file=sys.stderr)
        return 1

    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")   # suppress missing-subcache warnings
            cache = DyldCacheReader(str(cache_path))
    except (NameError, ImportError):
        raise
    except Exception as exc:
        print(f"error: could not open cache {cache_path}: {exc}", file=sys.stderr)
        return 1

    try:
        images = cache.list_images()
    finally:
        cache.close()

    if not images:
        print("warning: cache contains no imagesText array (old format?)",
              file=sys.stderr)
        return 0

    # Full paths to stdout (greppable), summary to stderr.
    for _va, path in images:
        print(path)

    print(
        f"\n{len(images)} framework(s) in {cache_path.name}",
        file=sys.stderr,
    )
    return 0


# ── main() pipeline stages ─────────────────────────────────────────────────────
# Carved out of main() so the entry point reads as a short pipeline (load →
# extract → emit) and each self-contained phase is a named unit.  main() still
# owns the cache lifecycle, source-mode branching, and the extraction core (whose
# finally-block cache close is intentionally kept there).

def _cmd_list_serializers(ctx, cl, list_bytes, source_name, cache, cache_native) -> int:
    """--list-serializers: print which protobuf runtimes are present and the
    message names under each, then exit (no full per-message disassembly).
    ``list_bytes`` is the raw image bytes in binary mode (lets the C++ scan sweep
    the whole image) or None cache-native (decoders read sections/.symbols via ctx)."""
    from proto.foreign import summarize_serializers
    summaries = summarize_serializers(ctx, cl, list_bytes)
    print(f"\nProtobuf serializers in {source_name}:")
    if not summaries:
        print("  (none detected)")
    for s in summaries:
        tag = "" if s.decodable else "  [DETECTED — not decodable by this tool]"
        note = s.note
        if not s.names and note:
            # name-less detect-only entry (e.g. libprotobuf-lite)
            print(f"\n  {s.label}{tag}:")
            print(f"    {note}")
        else:
            print(f"\n  {s.label} — {len(s.names)} message(s){tag}:")
            if note:
                print(f"    ({note})")
            for n in s.names:
                print(f"    {n}")
    if summaries:
        print(
            "\n  ℹ Decodes: PBCodable, C++ libprotobuf-full (exact schema), "
            "swift-protobuf (names+numbers; types from reflection, int "
            "subtype/oneof limited)."
            "\n    Detect-only: C++ libprotobuf-lite (descriptors stripped — "
            "names/numbers unrecoverable), GPBMessage (not decoded), "
            "protobuf-c (descriptor names listed; fields not decoded)."
            "\n    Cache-native (--framework) decodes PBCodable + C++-full + "
            "swift and detects lite/GPB/protobuf-c, all via the .symbols nlist / "
            "descriptor sections."
        )
    print()
    if cache is not None and cache_native:
        cache.close()
    return 0


@contextmanager
def _stage(label: str):
    """A progress line for one stage of the run and its time (see _step / _done)."""
    t = _step(label)
    yield
    _done(t)


def _report_symbol_recovery(counts) -> None:
    """Cache-native: what the .symbols local symbols did to the method names
    (:func:`macho.load.load_classes`), or that the sub-cache does not list the image."""
    if counts is not None:
        print(
            f"    method names: {counts['renamed']} resolved, "
            f"{counts['corrected']} corrected, "
            f"{counts['added']} added, "
            f"{counts['meta_added']} class methods from local symbols",
            file=sys.stderr,
        )
    else:
        print(
            "    no local symbols found (.symbols file absent or "
            "image not listed) — selector names may be incomplete",
            file=sys.stderr,
        )


#: Exit status of a run that COMPLETED but dropped or distrusts part of its output: a class or
#: a protobuf runtime failed (its messages are missing), or enum fields were left unresolved
#: where that is a tool bug.  0 = clean, 1 = could not run / bad input, 2 = usage (argparse).
EXIT_INCOMPLETE = 3


def _build_and_write_output(messages, args, source_name, ctx, input_kind) -> int:
    """Resolve cross-references, group by package, print the summary, and write
    the .proto files (unless --dry-run).  Returns the process exit code
    (``EXIT_INCOMPLETE`` when the output is known to be missing something)."""
    from proto.emitter import (build_proto_files, write_proto_files,
                               print_summary, enum_error_escalated)
    t = _step("resolving cross-references and grouping by package")
    proto_files = build_proto_files(
        messages,
        single_file=args.single_file,
        package_override=args.package,
        source_name=source_name,
        prefixes=args.prefixes or (),
        input_kind=input_kind,
    )
    _done(t)

    from proto.models import get_diagnostics
    diag = get_diagnostics(ctx)
    print_summary(messages, proto_files, source_name=source_name, diagnostics=diag)
    # A run that completed but is known to have dropped or distrusted output must not exit 0.
    status = (EXIT_INCOMPLETE if diag.n_errors or enum_error_escalated(messages, proto_files)
              else 0)

    if args.dry_run:
        print("\n(dry run — no files written)", file=sys.stderr)
        return status

    output_dir = Path(args.output)

    try:
        t = _step(f"writing .proto files to {output_dir}/")
        written = write_proto_files(proto_files, output_dir)
        _done(t)
    except OSError as exc:
        print(f"error: could not write output: {exc}", file=sys.stderr)
        return 1

    print(f"\nWrote {len(written)} file(s):", file=sys.stderr)
    for path in written:
        msgs = next(
            (pf for pf in proto_files if pf.filename == path.name), None
        )
        n_msgs = len(msgs.messages) if msgs else 0
        print(f"  {path}  ({n_msgs} messages)", file=sys.stderr)

    return status


# ── main() helpers ─────────────────────────────────────────────────────────────
#
# main() is argument dispatch, not binary-format reasoning, so it splits along
# the CLI's own phase boundaries with nothing lost.  Each helper below owns one
# phase and prints its own diagnostics; a phase that cannot continue raises
# _CliAbort, which main() turns into the exit status.  Messages and exit codes
# are unchanged from when this was one 209-line function.


class _CliAbort(Exception):
    """A terminal CLI failure whose diagnostic is already on stderr.

    Raised instead of `return 1` so the phase helpers stay linear.  Carries the
    exit code only; the message has been printed at the raise site so ordering
    relative to progress output is preserved exactly.
    """

    def __init__(self, code: int = 1):
        super().__init__(code)
        self.code = code


def _validate_source_selection(parser: argparse.ArgumentParser, args) -> None:
    """Reject argument combinations that name no source, or two conflicting ones.

    Uses ``parser.error`` (exit 2 + usage), not _CliAbort: these are usage errors,
    and argparse owns that exit path.
    """
    if not args.binary and not args.framework and not args.list_frameworks:
        parser.error(
            "specify a source: --binary PATH, --framework NAME, "
            "or --list-frameworks"
        )
    if args.framework and not args.cache:
        parser.error("--framework requires --cache")
    if args.list_frameworks and not args.cache:
        parser.error("--list-frameworks requires --cache")
    if args.binary and args.cache:
        parser.error(
            "--cache is not valid with --binary (standalone-binary mode "
            "resolves selectors from the binary itself); use "
            "--framework NAME --cache … for cache-native extraction"
        )


def _configure_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.WARNING,
        format="%(levelname)-8s %(name)s: %(message)s",
        stream=sys.stderr,
    )


def _open_cache(cache_arg, cache_native: bool):
    """Resolve and open the dyld shared cache; returns the reader or None.

    None means "no cache in play", which is only legal in --binary mode --
    --framework without an openable cache raises _CliAbort.  Only
    --framework / --list-frameworks reach here with a cache at all: --binary is
    standalone, and --binary + --cache is rejected during validation.
    """
    cache = None
    if cache_arg is not None:
        from macho.dyld_cache import DyldCacheReader

        cache_path = _resolve_cache_path(cache_arg)
        if cache_path is not None:
            try:
                t = _step(f"loading dyld shared cache ({cache_path.name})")
                cache = DyldCacheReader(str(cache_path))
                _done(t)
                n_maps    = cache.mapping_count()
                n_missing = cache.missing_subcache_count()
                print(f"    {n_maps} mapping(s) across cache files",
                      file=sys.stderr)
                if n_missing:
                    print(
                        f"    WARNING: {n_missing} expected sub-cache file(s) "
                        f"not found.",
                        file=sys.stderr,
                    )
            except (NameError, ImportError):
                raise
            except Exception as exc:
                print(
                    f"  warning: could not open cache {cache_path}: {exc}",
                    file=sys.stderr,
                )
                cache = None
                if cache_native:
                    print("error: cache is required for --framework mode but "
                          "could not be opened", file=sys.stderr)
                    raise _CliAbort() from exc

    if cache_native and cache is None:
        # Reached when --cache named a path that would not resolve at all.  The
        # open-failure case above reports its own (more specific) message first.
        print("error: --cache must be supplied and openable for --framework mode",
              file=sys.stderr)
        raise _CliAbort()

    return cache


def _load_cache_native_context(args, cache, BinaryContext):
    """Resolve --framework inside the cache and build its BinaryContext.

    Returns ``(ctx, mach_va)``.  Closes *cache* before aborting, since main()'s
    post-extraction close is not reached on these paths.
    """
    from macho.dyld_cache import AmbiguousImageError, ImageNotFoundError

    t = _step(f"locating {args.framework!r} in cache")
    try:
        mach_va = cache.resolve_image(args.framework)
    except AmbiguousImageError as exc:
        print(
            f"error: {args.framework!r} matches "
            f"{len(exc.candidates)} images in the cache:",
            file=sys.stderr,
        )
        for path in exc.candidates:
            print(f"    {path}", file=sys.stderr)
        print(
            "  Re-run --framework with a more specific name or the full "
            "image path to disambiguate.",
            file=sys.stderr,
        )
        cache.close()
        raise _CliAbort() from exc
    except ImageNotFoundError as exc:
        print(
            f"error: {args.framework!r} not found in cache.\n"
            f"  Tip: run --list-frameworks --cache {args.cache} "
            f"to see all available image paths.",
            file=sys.stderr,
        )
        cache.close()
        raise _CliAbort() from exc
    _done(t)
    print(
        f"\nLoading {args.framework} from cache "
        f"(mach-o @ 0x{mach_va:x}) …",
        file=sys.stderr,
    )
    try:
        ctx = BinaryContext.from_cache(cache, mach_va)
    except (NameError, ImportError):
        raise
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        cache.close()
        raise _CliAbort() from exc
    return ctx, mach_va


def _load_binary_context(args, BinaryContext):
    """Read a standalone binary and build its BinaryContext.

    Returns ``(ctx, data)``; *data* is the (possibly thinned) image bytes, which
    the C++ descriptor sweep and --list-serializers need in binary mode.
    """
    binary_path = Path(args.binary)
    if not binary_path.exists():
        print(f"error: binary not found: {binary_path}", file=sys.stderr)
        raise _CliAbort()
    print(f"\nLoading {binary_path.name} …", file=sys.stderr)
    t = _step(f"reading {binary_path.stat().st_size / 1_048_576:.0f} MB")
    try:
        data = binary_path.read_bytes()
    except OSError as exc:
        print(f"error: could not read binary: {exc}", file=sys.stderr)
        raise _CliAbort() from exc
    # Accept fat (universal) binaries by selecting the arm64e/arm64 slice —
    # many framework/XPC binaries on disk are fat, and the downstream
    # BinaryContext requires a single-arch slice.
    from serializers.swift_descriptor_extract import load_macho_slice
    data = load_macho_slice(data)
    _done(t)
    try:
        t = _step("parsing Mach-O structure")
        ctx = BinaryContext(data)
        _done(t)
    except (NameError, ImportError):
        raise
    except Exception as exc:
        print(f"error: not a valid arm64 Mach-O binary: {exc}",
              file=sys.stderr)
        raise _CliAbort() from exc
    return ctx, data


def _open_enum_debug_writer(path):
    """Open --debug-enums as a JSONL sink; returns ``(handle, writer)``.

    Both are None when no path was given or it could not be opened (a warning,
    not a failure: the debug trace is diagnostic, so extraction still runs).
    """
    if not path:
        return None, None
    import json as _json
    try:
        fh = open(path, 'w', encoding='utf-8')
    except OSError as exc:
        print(f"  warning: could not open --debug-enums file: {exc}",
              file=sys.stderr)
        return None, None

    def _write_debug_record(rec: dict) -> None:
        fh.write(_json.dumps(rec, ensure_ascii=False) + '\n')
        fh.flush()

    print(f"  enum debug → {path}", file=sys.stderr)
    return fh, _write_debug_record


def _merge_foreign_messages(ctx, image_bytes, messages):
    """Append messages from non-PBCodable runtimes (C++ libprotobuf, swift-protobuf).

    The tool's primary path decodes Apple PBCodable; an image may *also* carry
    protobuf messages built with other runtimes whose descriptors we can decode.
    They join the same package-grouped output, each tagged with its serializer
    (the emitter attributes provenance in the file/message headers).  Works in
    BOTH modes: binary-mode passes the raw bytes (C++ sweeps the whole image);
    cache-native passes None and the decoders read the descriptor sections (C++)
    / .symbols nlist (swift) through ctx.
    """
    from proto.foreign import collect_foreign_messages
    foreign = collect_foreign_messages(ctx, image_bytes)
    if not foreign:
        return messages
    from collections import Counter
    by_ser = Counter(m.serializer for m in foreign)
    for ser, n in sorted(by_ser.items()):
        print(f"  + {n} message(s) from {ser}", file=sys.stderr)
    return messages + foreign


def _add_cross_image_messages(cache, mach_va, messages, prefixes, ctx):
    """Cache-native: append the messages other images define that *messages* reference as
    field types (transitively), each tagged with its defining image — see
    :mod:`proto.cross_image`.  Reports on stderr what was added and what stays unresolved;
    the other images' diagnostics (and an image that failed) join *ctx*'s."""
    from collections import Counter
    from proto.cross_image import resolve_cross_image
    from proto.models import get_diagnostics
    t = _step("resolving message classes defined in other images")
    res = resolve_cross_image(cache, mach_va, messages, prefixes=prefixes)
    _done(t)
    for image, n in sorted(Counter(m.defined_in for m in res.added).items()):
        print(f"  + {n} message(s) defined in {image}", file=sys.stderr)
    diag = get_diagnostics(ctx)
    for image, other in sorted(res.diagnostics.items()):
        diag.merge(other, image)
    for image, err in sorted(res.image_errors.items()):
        print(f"  warning: could not extract {image}: {err}", file=sys.stderr)
        diag.failed_passes.append((f"cross-image extraction of {image}", err,
                                   "the messages it defines are not added"))
    for cname, why in sorted(res.unresolved.items()):
        print(f"  unresolved {cname}: {why}", file=sys.stderr)
    return messages + res.added


def _apply_prefix_filter(messages, prefixes):
    """Keep only messages whose ObjC class name starts with one of *prefixes*."""
    if not prefixes:
        return messages
    before = len(messages)
    messages = [
        m for m in messages
        if any(m.class_name.startswith(p) for p in prefixes)
    ]
    print(
        f"  prefix filter ({', '.join(prefixes)}): "
        f"{before} → {len(messages)} messages",
        file=sys.stderr,
    )
    return messages


# ── Main entry point ───────────────────────────────────────────────────────────

def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args   = parser.parse_args(argv)

    _validate_source_selection(parser, args)

    # ── Early exit: --list-frameworks ─────────────────────────────────────────
    if args.list_frameworks:
        return _cmd_list_frameworks(args.cache)

    _configure_logging(args.verbose)

    from macho.memory    import BinaryContext
    from macho.load      import load_classes
    from proto.extractor import extract_all, SelectorsUnresolvedError
    from proto.emitter   import InputKind

    # ObjC class-name prefixes to strip → threaded into extract_all(prefixes=…);
    # None means use proto.defaults.DEFAULT_PREFIXES.  The emitter's package names take
    # them on top of the defaults (build_proto_files(prefixes=…)).
    _prefixes = tuple(args.prefixes) if args.prefixes else None

    # ── Determine mode ────────────────────────────────────────────────────────
    cache_native = (args.framework is not None)
    source_name  = (Path(args.framework).stem if cache_native
                    else Path(args.binary).stem)

    cache = None
    data = None            # binary mode only; stays None cache-native
    mach_va = None         # cache-native only
    try:
        cache = _open_cache(args.cache, cache_native)
        reader = cache     # kept past the post-extraction close (handles reopen lazily)

        if cache_native:
            ctx, mach_va = _load_cache_native_context(args, cache, BinaryContext)
        else:
            ctx, data = _load_binary_context(args, BinaryContext)
    except _CliAbort as abort:
        return abort.code

    # The input kind decides what an ambiguous enum means (proto.emitter.InputKind): a
    # cache image or a standalone executable (MH_EXECUTE) is self-contained, so one is an
    # error; a binary-only dylib may reference cache data, so it stays a note.  (Cache
    # images report as dylibs, hence the cache test first.)
    input_kind = (InputKind.CACHE_IMAGE if cache_native else
                  InputKind.EXECUTABLE if ctx.is_executable else InputKind.DYLIB)

    # ── String table, ObjC class list, .symbols method names ─────────────────
    # The one front end every image extraction runs (macho.load), so the images the
    # cross-image resolver pulls messages from load exactly like this one.  In both modes
    # selector cstrings are read through ctx: cache-native routes ctx.read_cstring to the
    # cache's unified selector pool; binary-only reads the binary's own sections.
    img = load_classes(ctx, cache if cache_native else None, mach_va, step=_stage)
    st, cl = img.st, img.cl
    if cache_native:
        _report_symbol_recovery(img.symbol_counts)

    # ── Quick serializer inventory (--list-serializers) ───────────────────────
    # Print which protobuf runtimes are present and their message names, then
    # exit — no full per-message disassembly.  All of PBCodable / C++ / swift /
    # GPB resolve in BOTH modes now (cache-native C++ reads descriptor sections,
    # swift reads the .symbols nlist, both through ctx); passing `data` only when
    # present lets the binary-mode C++ scan sweep the whole image.
    if args.list_serializers:
        return _cmd_list_serializers(
            ctx, cl, data, source_name, cache, cache_native)

    # ── Proto extraction ──────────────────────────────────────────────────────
    t = _step("extracting proto schemas")
    _debug_fh, _enum_writer = _open_enum_debug_writer(args.debug_enums)
    try:
        messages = extract_all(ctx, st, cl,
                               prefixes=_prefixes,
                               enum_debug_writer=_enum_writer)
    except SelectorsUnresolvedError as exc:
        # No ObjC selector names resolved in a mode where that is fatal
        # (cache-native or a standalone executable).  Fail loudly rather than
        # emit silently-degraded schemas.
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        if _debug_fh is not None:
            _debug_fh.close()
        # cache-native: close after extraction is complete.
        if cache is not None and cache_native:
            cache.close()
            cache = None
    _done(t)

    messages = _merge_foreign_messages(ctx, data, messages)
    messages = _apply_prefix_filter(messages, args.prefixes)
    if cache_native and messages and not args.no_cross_image:
        try:
            messages = _add_cross_image_messages(reader, mach_va, messages, _prefixes, ctx)
        finally:
            reader.close()

    if not messages:
        print("warning: no proto messages found", file=sys.stderr)
        from proto.models import get_diagnostics
        from proto.emitter import print_summary
        diag = get_diagnostics(ctx)
        if diag.n_errors:
            # nothing was written AND something failed: not a clean "there is no protobuf here"
            print_summary([], [], source_name=source_name, diagnostics=diag)
            return EXIT_INCOMPLETE
        return 0

    # ── Build + write proto files ──────────────────────────────────────────────
    return _build_and_write_output(messages, args, source_name, ctx, input_kind)


if __name__ == "__main__":
    sys.exit(main())
