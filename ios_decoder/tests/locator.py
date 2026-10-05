"""Optional fuzzy LOCATOR (pipeline step i) — connection → candidate frameworks.

This is the *deliberately fragile* half of the abandoned bytes-derived approach (the
reason it was abandoned; see ios_decoder/README.md and notes/LOCATOR_STEP1_FINDINGS.md):
given an observed connection, search frameworks/binaries by connection keywords to
produce a SMALL CANDIDATE SET that should contain the image holding the connection's
proto descriptors.  The extractor then extracts that candidate set (step ii) and the
matcher scans it (step iii).

It exists here so the locator→matcher path can be *tested for recall* — does the
candidate set contain the true framework? — against notes/proto_match_groundtruth.json.
It is test-only and optional: every entry point needs heavy artifacts (the dyld cache,
the libexec daemon binaries, `otool`) and degrades to a skip when they're absent.  No
production code imports it; nothing here is a runtime dependency.

Three complementary signals are fused (their blind spots don't overlap — only the
UNION reached full recall in the prototype):

  A. UA → daemon binary → `otool -L`.  The producer token names a libexec daemon;
     its directly-linked frameworks (and the daemon itself) are candidates.  Strong
     for clean-UA daemons (geod→GeoServices, cloudd→CloudKitDaemon, locationd-self).
  B. host/path → framework (manifest-resolver fallback).  Encodes the captures-derived
     host_producer_map (owner-approved fallback): the manifest resolver live-decodes
     geo_manifest URLs to *.ls.apple.com→GeoServices, etc.; this table records that
     same outcome plus the other stable host→framework facts.  Catches indirect
     producers (photoanalysisd/settings via a Maps service host, applenews via
     ckdatabase) that UA/otool miss.
  C. URL token → binary string-search.  Tokenize the URL (host labels + FULL path
     segments) and grep the libexec binaries' embedded C-strings; a binary that hard-
     codes a (rare) URL token is the producer.  Self-evidencing, no fixed map — but
     blind to service-routed URLs that aren't literal in any binary (photoanalysisd
     `poi/data`), which signal B covers.
"""

from __future__ import annotations

import fnmatch
import functools
import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

_REPO = Path(__file__).resolve().parents[2]
_DEFAULT_BINARIES_DIR = _REPO / "iphone8_data"
_DEFAULT_CACHE = _REPO / "iphone8_data" / "dylib"


# --- connection model --------------------------------------------------------

@dataclass
class Connection:
    """One observed connection to locate: who made it (UA), and to what URL."""
    producer: str            # UA token / daemon name (e.g. "geod", "com.apple.transparency")
    host: str = ""           # e.g. "gsp51-ssl.ls.apple.com"
    path: str = ""           # e.g. "/api/v1.0/poi/data"

    @classmethod
    def from_url(cls, producer: str, url: str) -> "Connection":
        m = re.match(r"(?:[a-z]+://)?([^/]+)(/.*)?$", url)
        host = m.group(1) if m else url
        path = (m.group(2) or "") if m else ""
        return cls(producer=producer, host=host, path=path)


@dataclass
class LocateResult:
    """Candidate frameworks/binaries + which signal contributed each."""
    candidates: set = field(default_factory=set)          # normalized framework/binary names
    by_signal: dict = field(default_factory=dict)         # signal letter -> set of names

    def add(self, signal: str, names) -> None:
        names = {n for n in names if n}
        self.candidates |= names
        self.by_signal.setdefault(signal, set()).update(names)

    def summary(self) -> str:
        per = "; ".join(f"{s}:{sorted(v)}" for s, v in sorted(self.by_signal.items()) if v)
        return f"{sorted(self.candidates)}  ({per or 'no signal fired'})"


# --- artifact gating ---------------------------------------------------------

def _have_otool() -> bool:
    from shutil import which
    return which("otool") is not None


def artifacts_reason(binaries_dir=_DEFAULT_BINARIES_DIR) -> Optional[str]:
    """Skip reason if the locator can't run here (no binaries / no otool), else None."""
    if not Path(binaries_dir).is_dir():
        return f"locator artifacts absent: no binaries dir at {binaries_dir}"
    if not _have_otool():
        return "locator needs `otool` (macOS) to read linked frameworks"
    return None


# --- signal A: UA → daemon binary → otool -L ---------------------------------

_FRAMEWORK_RE = re.compile(r"/([A-Za-z0-9_]+)\.framework/")


def otool_frameworks(binary_path) -> set:
    """Framework names directly linked by `binary_path` (via `otool -L`)."""
    try:
        out = subprocess.run(["otool", "-L", str(binary_path)],
                             capture_output=True, text=True, timeout=60)
    except Exception:
        return set()
    if out.returncode != 0:
        return set()
    return {m.group(1) for m in _FRAMEWORK_RE.finditer(out.stdout)}


def daemon_binary(producer: str, binaries_dir=_DEFAULT_BINARIES_DIR) -> Optional[Path]:
    """Resolve a producer token to a libexec daemon binary file, or None.

    Tries the token as-is, with the leading ``com.apple.`` stripped, and with a
    trailing ``d`` appended (``transparency`` → ``transparencyd``) — the suffix the
    findings doc notes recovers daemon producers named without it.
    """
    base = producer.split("/")[0]
    base = re.sub(r"^com\.apple\.", "", base)
    for name in (base, base + "d"):
        p = Path(binaries_dir) / name
        if p.is_file():
            return p
    return None


def ua_candidates(conn: Connection, binaries_dir=_DEFAULT_BINARIES_DIR) -> set:
    """Signal A: the daemon's own name + its directly-linked frameworks."""
    binp = daemon_binary(conn.producer, binaries_dir)
    if binp is None:
        return set()
    return {binp.name} | otool_frameworks(binp)


# --- signal B: host/path → framework (manifest-resolver fallback) ------------
#
# Encodes notes/host_producer_map.md.  Each rule is (host_glob, path_substr, framework);
# path_substr "" matches any path.  First-match-wins order is broad-to-specific safe
# because the globs are disjoint except where a more specific path is listed first.

_HOST_RULES = [
    ("*.ls.apple.com",        "",                "GeoServices"),
    ("gsp*-ssl.apple.com",    "/hcy/pbcwloc",    "CoreLocationProtobuf"),
    ("gsp*-ssl.apple.com",    "",                "GeoServices"),
    ("gs-loc.apple.com",      "",                "locationd"),
    ("fbs.smoot.apple.com",   "",                "CoreParsec"),
    ("*.smoot.apple.com",     "",                "CoreParsec"),
    ("mask-api.icloud.com",   "",                "NetworkServiceProxy"),
    ("gateway.icloud.com",    "",                "CloudKitDaemon"),
    ("*.icloud.com",          "ckdatabase",      "CloudKitDaemon"),
    ("kt-prod.ess.apple.com", "",                "transparencyd"),
    ("iadsdk.apple.com",      "",                "AdCore"),
    ("*.iadsdk.apple.com",    "",                "AdCore"),
    ("cl4.apple.com",         "",                "CoreIndoor"),
    ("se2.itunes.apple.com",  "",                "iTunesCloud"),
    ("radio-services.itunes.apple.com", "",      "iTunesCloud"),
]


def host_candidates(conn: Connection) -> set:
    """Signal B: framework(s) the host/path resolves to via the documented map."""
    out = set()
    for host_glob, path_sub, framework in _HOST_RULES:
        if fnmatch.fnmatch(conn.host, host_glob) and (not path_sub or path_sub in conn.path):
            out.add(framework)
    return out


# --- signal C: URL token → binary C-string search ----------------------------

def _iter_ascii_strings(data: bytes, min_len: int = 4):
    """Yield printable-ASCII runs (>= min_len) from `data` — a portable `strings`."""
    run = bytearray()
    for b in data:
        if 0x20 <= b < 0x7F:
            run.append(b)
        else:
            if len(run) >= min_len:
                yield run.decode("ascii")
            run = bytearray()
    if len(run) >= min_len:
        yield run.decode("ascii")


def url_tokens(conn: Connection) -> list:
    """Discriminating URL tokens: host labels + FULL path segments (not split on '_').

    Path segments stay whole (``consistency_proof``/``pbcwloc`` are single tokens, not
    split on '_') and keep short-but-specific names (``poi``); the rarity guard in
    :func:`url_search_candidates` drops common segments (``api``, ``v1``) that appear in
    many binaries.  Host labels keep a length-4 floor to drop ``ls``/``ess``/``apple``/``com``.
    """
    toks = [t for t in conn.host.split(".") if len(t) >= 4 and t not in ("apple", "com")]
    toks += [seg for seg in conn.path.split("/") if len(seg) >= 3]
    # de-dup, keep order
    seen, out = set(), []
    for t in toks:
        if t not in seen:
            seen.add(t); out.append(t)
    return out


def url_search_candidates(conn: Connection, binaries_dir=_DEFAULT_BINARIES_DIR) -> set:
    """Signal C: libexec binaries that hard-code one of the URL's tokens.

    A binary embedding a path/host token IS the producer image, so it alone is the
    candidate (its own descriptors get extracted in step ii) — we do NOT expand it
    by its `otool` link closure, which would bury the answer in 100 frameworks and
    defeat the point of a *small* candidate set (that expansion is signal A's job,
    and only after a high-precision UA match).  Bounded to the local libexec set
    (fast); a token shared by many binaries carries no locating signal and is dropped.
    """
    toks = url_tokens(conn)
    if not toks:
        return set()
    index = _binary_string_index(str(binaries_dir))   # {binary name: one big joined blob}
    hits: dict = {t: set() for t in toks}
    for name, blob in index.items():
        masked = _masked_spans(blob)         # one scan per binary, reused across tokens
        for t in toks:
            if _token_hit(t, blob, masked):
                hits[t].add(name)
    out = set()
    for t, bins in hits.items():
        if not bins or len(bins) > 4:        # >4 binaries share it -> not discriminating
            continue
        out |= bins                          # the producing image itself, not its links
    return out


# Host/URL-shaped constants that ship inside serialization runtimes rather than naming
# anything the binary talks to.  `type.googleapis.com/` is the google.protobuf.Any type-URL
# prefix, so ANY image statically linking C++ libprotobuf carries it — which made the token
# `googleapis` "locate" GeoServices for Google's own firebaselogging-pa.googleapis.com
# traffic.  The rarity guard cannot catch this: only one binary in the libexec set links
# libprotobuf, so the token looks maximally discriminating precisely because it is a runtime
# constant.  Matched as substrings of the surrounding string, not as whole tokens, because
# `googleapis` is a legitimate host label *within* type.googleapis.com/ — the problem is the
# context it appears in, which a boundary check cannot see.
_RUNTIME_HOST_CONSTANTS = (
    "type.googleapis.com/",       # google.protobuf.Any type URL prefix
    "type.googleprod.com/",       # ditto, Google-internal variant
)


def _masked_spans(blob: str) -> list:
    """``[(start, end)]`` of every :data:`_RUNTIME_HOST_CONSTANTS` occurrence in *blob*."""
    spans = []
    for const in _RUNTIME_HOST_CONSTANTS:
        start = 0
        while (j := blob.find(const, start)) >= 0:
            spans.append((j, j + len(const)))
            start = j + 1
    return spans


def _token_hit(token: str, blob: str, masked: list = None) -> bool:
    """True if *token* occurs in *blob* outside every serialization-runtime constant.

    Every occurrence is checked, not just the first: a token that appears ONLY inside
    :data:`_RUNTIME_HOST_CONSTANTS` carries no locating signal, but one that also appears
    on its own still counts — so masking a runtime constant can never hide a real hit.
    Pass *masked* (from :func:`_masked_spans`) to reuse one scan across several tokens.
    """
    if masked is None:
        masked = _masked_spans(blob)
    start = 0
    while (i := blob.find(token, start)) >= 0:
        end = i + len(token)
        if not any(a <= i and end <= b for a, b in masked):
            return True                      # a genuine occurrence, outside any constant
        start = i + 1
    return False


@functools.lru_cache(maxsize=None)
def _binary_string_index(binaries_dir: str) -> dict:
    """{binary name: newline-joined C-strings} for the libexec set (built once)."""
    out = {}
    for p in sorted(Path(binaries_dir).glob("*")):
        if not p.is_file() or p.name.startswith("."):
            continue
        try:
            data = p.read_bytes()
        except Exception:
            continue
        out[p.name] = "\n".join(_iter_ascii_strings(data))
    return out


# --- fuse the signals --------------------------------------------------------

def locate(conn: Connection, *, binaries_dir=_DEFAULT_BINARIES_DIR,
           use_url_search: bool = True) -> LocateResult:
    """Run the available signals and return the UNION candidate set with provenance."""
    res = LocateResult()
    res.add("A", ua_candidates(conn, binaries_dir))
    res.add("B", host_candidates(conn))
    if use_url_search:
        res.add("C", url_search_candidates(conn, binaries_dir))
    return res
