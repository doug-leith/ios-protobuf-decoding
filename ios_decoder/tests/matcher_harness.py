"""Optional fuzzy locator + matcher harness — double-checks the endpoint table.

The production decoder maps a URL to a schema with an explicit, hand-maintained
table (``ios_decoder.endpoints``).  This harness is an INDEPENDENT cross-check for
table changes: it takes a real captured body and asks the structural matcher
"could the message the table claims actually have produced these bytes, and what
does the matcher think it is?".  It is *test-only* and *optional* — nothing in the
production package imports it, and every entry point degrades to a skip when its
(heavier) dependencies aren't installed.

The pipeline it reproduces (see notes/LOCATOR_STEP1_FINDINGS.md) has three steps:

  (i)   LOCATOR — search frameworks/binaries by connection keywords to get a small
        candidate set of images that hold the connection's proto descriptors.
        *For testing this unreliable step is REPLACED by a manually-named
        framework/binary* (the ``framework`` / ``binary`` argument below).
  (ii)  EXTRACT — run apple_protobuf_extractor over those candidates to get all
        their descriptors.  ``descriptor_dir`` either points at saved extractor
        output (the committed ``ios_decoder/protos/<framework>/`` dirs) or is
        produced live by :func:`extract_descriptors`.
  (iii) MATCH — scan that descriptor set structurally against the body
        (:mod:`ios_decoder.matcher`), returning ranked candidates.

What is and isn't reliable (so tests assert the right thing):

  * RELIABLE — *exclusion*.  If a candidate message DEFINES an observed field
    number with an incompatible wire type, no serialization of it could produce
    the bytes, so it is impossible.  A table mapping whose claimed message is
    excluded for a real body is almost certainly wrong → assert on this.
  * NOT RELIABLE — *ranking*.  Small payloads expose few fields and tie across
    many messages (the documented matcher weakness), so "is it ranked #1" is
    informational only.  The harness reports rank/confidence but tests must not
    fail on them for small bodies.
"""

from __future__ import annotations

import glob
import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import pytest

_REPO = Path(__file__).resolve().parents[2]
_PROTOS_ROOT = Path(__file__).resolve().parents[1] / "protos"


# --- dependency probe (the harness is optional) ------------------------------

def _harness_reason() -> Optional[str]:
    """Return why the harness can't run (a skip reason), or None if it can.

    The matcher is now native to ios_decoder; the only external need is ``protoc``
    to compile a framework's .proto set into descriptors.
    """
    from shutil import which
    if which("protoc") is None:
        return "matcher harness needs `protoc` to compile descriptor sets"
    return None


HARNESS_REASON = _harness_reason()
HARNESS_AVAILABLE = HARNESS_REASON is None
# Decorate optional cross-check tests with this:  @matcher_harness.requires_harness
requires_harness = pytest.mark.skipif(not HARNESS_AVAILABLE, reason=HARNESS_REASON or "")


# --- step (i) stand-in + step (ii): descriptor sources -----------------------

def committed_descriptor_dir(framework: str) -> Optional[Path]:
    """Saved extractor output for `framework` under ios_decoder/protos/, or None.

    The committed per-framework dirs ARE step-(ii) output captured once and checked
    in (one subdir per extracted framework).  Using them keeps cross-check tests
    deterministic and cache-free.  Matched case-insensitively against the subdir name.
    """
    if not _PROTOS_ROOT.is_dir():
        return None
    want = framework.lower()
    for p in sorted(_PROTOS_ROOT.glob("*")):
        if p.is_dir() and not p.name.startswith(".") and p.name.lower() == want:
            return p
    return None


def extract_descriptors(out_dir: Path, *, framework: Optional[str] = None,
                        binary: Optional[str] = None, cache: Optional[str] = None,
                        extractor_dir: Optional[Path] = None) -> Path:
    """Run apple_protobuf_extractor (step ii) into `out_dir`; return that dir.

    The faithful full pipeline: extract every descriptor from a MANUALLY-named
    framework (cache-native) or standalone `binary`.  Raises RuntimeError if the
    extractor or its inputs aren't available, so callers can gate/skip on it.
    Tests that want a cache-free run should prefer :func:`committed_descriptor_dir`.
    """
    ext = Path(extractor_dir or (_REPO / "apple_protobuf_extractor"))
    cli = ext / "cli.py"
    if not cli.exists():
        raise RuntimeError(f"extractor CLI not found at {cli}")
    cmd = [sys.executable, str(cli), "-o", str(out_dir)]
    if binary:
        cmd += ["--binary", str(binary)]
    elif framework:
        if not cache:
            raise RuntimeError("--framework extraction requires a cache path")
        cmd += ["--framework", framework, "--cache", str(cache)]
    else:
        raise RuntimeError("specify either framework (+cache) or binary")
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"extractor failed ({proc.returncode}): {proc.stderr[-500:]}")
    return out_dir


# --- step (iii): the structural matcher --------------------------------------

@dataclass
class MatchVerdict:
    """Structured outcome of cross-checking one body against one descriptor set."""
    expected: str                       # leaf message name the table claims
    excluded: bool                      # the matcher PROVES this message impossible
    feasible: bool                      # not excluded (could have produced the bytes)
    explained: int                      # fields the expected message accounts for
    observed: int                       # fields present in the body's wire tree
    violations: int                     # hard wire-type contradictions for `expected`
    confident: bool                     # matcher's own confidence in its top pick
    winner: Optional[str]               # matcher's top-ranked candidate
    rank: Optional[int]                 # 1-based rank of `expected`, or None if not listed
    candidates: list = field(default_factory=list)   # ranked candidate leaf names

    def summary(self) -> str:
        tag = "EXCLUDED" if self.excluded else "feasible"
        rank = f"#{self.rank}" if self.rank else "unranked"
        return (f"{self.expected}: {tag} ({self.explained}/{self.observed} fields, "
                f"{self.violations} violations); matcher winner={self.winner!r} "
                f"[{rank}, {'confident' if self.confident else 'ambiguous'}]")


def _leaf(message: str) -> str:
    """Strip a package qualifier: '_cpusageenvelope._CPUsageEnvelope' -> '_CPUsageEnvelope'."""
    return message.rsplit(".", 1)[-1]


def load_corpus(descriptor_dir):
    """Compile every .proto under `descriptor_dir` into a matcher DescriptorSet.

    Memoized per directory inside :func:`ios_decoder.matcher.load_descriptor_set`
    (the protoc compile is the slow step and the result is read-only).
    """
    from ios_decoder import matcher
    return matcher.load_descriptor_set(str(descriptor_dir))


def crosscheck(body: bytes, descriptor_dir, expected_message: str, *,
               direction: Optional[str] = None, max_violations: int = 0,
               top_k: int = 8) -> MatchVerdict:
    """Cross-check `body` against the descriptor set for one `expected_message`.

    Computes BOTH the reliable exclusion signal (does the expected message's own
    fit contain a hard wire-type contradiction?) and the informational ranking
    (where the matcher places it).  Returns a :class:`MatchVerdict`.

    Raises ValueError if the body isn't parseable protobuf or the expected message
    isn't in the descriptor set (a table/descriptor mismatch worth surfacing loudly).
    """
    from ios_decoder import matcher
    descriptors = load_corpus(descriptor_dir)
    leaf = _leaf(expected_message)
    msg = descriptors.resolve(leaf)
    if msg is None:
        raise ValueError(f"{leaf!r} is not in the descriptor set at {descriptor_dir}")
    try:
        tree = matcher.parse_tree(body)
    except matcher.MatchError as e:
        raise ValueError(f"body is not parseable protobuf: {e}")

    # reliable signal: the expected message's own fit (recursing into sub-messages)
    explained, observed, violations = matcher.fit(tree, msg)
    excluded = violations > max_violations

    # informational signal: full ranking over the descriptor set
    res = matcher.match_tree(tree, descriptors, top_k=top_k,
                             max_violations=max_violations, direction=direction)
    cands = [c.message for c in res.candidates]
    rank = (cands.index(leaf) + 1) if leaf in cands else None
    return MatchVerdict(
        expected=leaf, excluded=excluded, feasible=not excluded,
        explained=explained, observed=observed, violations=violations,
        confident=res.confident, winner=(cands[0] if cands else None),
        rank=rank, candidates=cands,
    )


# --- capture-body discovery (live cross-checks) ------------------------------

def capture_bodies(url_substr: str):
    """(url, body, direction) for flows whose URL contains `url_substr`.

    Reads the git-ignored .mitm captures (none committed — device data is private);
    returns [] when no capture is present so live tests skip.  Both the request and
    the response body are yielded (direction tags which).
    """
    try:
        from mitmproxy import io as mio
    except Exception:
        return []
    caps = (sorted(glob.glob(str(_REPO / "ios_decoder" / "comparison" / "*.mitm")))
            + sorted(glob.glob(str(_REPO / "iphone8_data" / "captures" / "*.mitm")))
            + sorted(glob.glob(str(_REPO / "iphone12_data" / "captures" / "*.mitm"))))
    out = []
    for cap in caps:
        try:
            with open(cap, "rb") as fh:
                flows = list(mio.FlowReader(fh).stream())
        except Exception:
            continue
        for fl in flows:
            req = getattr(fl, "request", None)
            if req is None or url_substr not in req.pretty_url:
                continue
            if req.content:
                out.append((req.pretty_url, req.content, "request"))
            resp = getattr(fl, "response", None)
            if resp is not None and resp.content:
                out.append((req.pretty_url, resp.content, "response"))
    return out
