"""
Frequency instrumentation for the extractor/macho/emitter heuristics.

Counts FUNCTION ENTRIES (sys.settrace 'call' events) for every function defined
in the target source files — robust to line-number drift and a clean "how often
was this code path consulted" metric.  Also keeps raw per-line hit counts so a
specific sub-branch can be resolved when one function hosts several heuristics.

Runs the REAL pipeline per artifact: extract_all THEN emission
(build_proto_files + ProtoFile.emit), so emitter heuristics are exercised too.
Tracing is scoped to the target files; every other frame gets a None local
tracer, so the giant cache-parse loops are not traced and overhead stays bounded.

Output per artifact:
    /tmp/heur_calls_<artifact>.json   "relpath:co_name:firstlineno" -> entry count
    /tmp/heur_lines_<artifact>.json   "relpath:lineno"              -> line hits

Usage: python3 heuristic_freq.py {geoservices|locationd|corelocationprotobuf|all}
"""
import glob
import json
import os
import sys
from collections import Counter

import census_repeated as C

_ROOT = os.path.dirname(os.path.abspath(__file__))

# Trace EVERY proto/*.py module, not a fixed list: the 2026-06-10 monolith split
# moved most heuristics out of proto/extractor.py into focused submodules
# (enums.py, repeated.py, dispatch.py, protocore.py, writeto.py, …).  A hand-kept
# file list silently drifts out of sync with heuristic_registry.py — relocated
# functions then trace to nothing and their counts read 0 — so glob the package
# to keep the tracer and the registry in lockstep.  The macho/* heuristics live
# in a known, stable handful, listed explicitly.
_TARGETS = set(glob.glob(os.path.join(_ROOT, "proto", "*.py")))
_TARGETS |= {os.path.join(_ROOT, "macho", p) for p in (
    "memory.py", "disasm.py", "classlist.py", "cache_classlist.py",
    "dyld_cache.py", "local_symbols.py", "strings.py",
)}

_calls = Counter()
_lines = Counter()


def _local(frame, event, arg):
    if event == "line":
        _lines[(frame.f_code.co_filename, frame.f_lineno)] += 1
    return _local


def _glob(frame, event, arg):
    if event == "call":
        co = frame.f_code
        if co.co_filename in _TARGETS:
            _calls[(co.co_filename, co.co_name, co.co_firstlineno)] += 1
            return _local
        return None
    return None


def _emit(messages):
    """Run the emission half so emitter.py heuristics are exercised."""
    from proto.emitter import build_proto_files, package_for_class
    proto_files = build_proto_files(messages, single_file=False)
    class_to_pkg = {m.class_name: package_for_class(m.class_name)
                    for m in messages}
    for pf in proto_files:
        pf.emit(class_to_pkg=class_to_pkg)


_DRIVERS = {
    "geoservices": C.run_geoservices,
    "locationd": C.run_locationd,
    "corelocationprotobuf": C.run_corelocationprotobuf,
}


def run_one(name):
    _calls.clear(); _lines.clear()
    driver = _DRIVERS[name]
    sys.settrace(_glob)
    try:
        result = driver()
        if result is not None:
            _emit(result)
    finally:
        sys.settrace(None)
    if result is None:
        print(f"  {name}: artifact not found, skipped", file=sys.stderr)
        return
    calls = {f"{os.path.relpath(fn, _ROOT)}:{nm}:{ln}": c
             for (fn, nm, ln), c in _calls.items()}
    lines = {f"{os.path.relpath(fn, _ROOT)}:{ln}": c
             for (fn, ln), c in _lines.items()}
    with open(f"/tmp/heur_calls_{name}.json", "w") as fh:
        json.dump(calls, fh)
    with open(f"/tmp/heur_lines_{name}.json", "w") as fh:
        json.dump(lines, fh)
    print(f"  {name}: {len(result)} messages, {len(calls)} functions entered, "
          f"{sum(_calls.values())} total entries", file=sys.stderr)


def main():
    which = sys.argv[1] if len(sys.argv) > 1 else "all"
    for n in (list(_DRIVERS) if which == "all" else [which]):
        print(f"Running {n} ...", file=sys.stderr, flush=True)
        run_one(n)


if __name__ == "__main__":
    main()
