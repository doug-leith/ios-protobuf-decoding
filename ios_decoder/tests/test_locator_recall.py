"""OPTIONAL recall eval of the fuzzy locator (pipeline step i) vs ground truth.

Measures the locator's job: for a real connection, does the candidate set it returns
CONTAIN the true producing framework (notes/proto_match_groundtruth.json)?  Recall —
not precision — is what matters: step (ii) extracts every candidate and step (iii)'s
matcher disambiguates, so a candidate set that misses the truth is the only fatal error.

This is the deliberately-fragile half of the abandoned approach, exercised here only as
a regression gauge.  It needs heavy artifacts (the libexec daemon binaries + `otool`)
and SKIPS when they're absent — none are committed.

The locator's INPUT is a connection URL; the test supplies the canonical endpoint per
producer (from the committed notes/host_producer_map.md + the GT), then evaluates the
locator's OUTPUT against the GT framework.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from . import locator as L

_REPO = Path(__file__).resolve().parents[2]
_GT = _REPO / "notes" / "proto_match_groundtruth.json"

requires_artifacts = pytest.mark.skipif(
    L.artifacts_reason() is not None, reason=L.artifacts_reason() or "")

# Canonical (host, path) per evaluable GT producer — the connection the locator sees.
# Hosts/paths are the documented endpoints (notes/host_producer_map.md, GT entries).
_CONNECTIONS = {
    "geod":                       ("gsp57-ssl.ls.apple.com", "/dispatcher.arpc"),
    "locationd":                  ("gs-loc.apple.com", "/clls/wloc"),
    "corelocationprotobuf":       ("gsp10-ssl.apple.com", "/hcy/pbcwloc"),
    "parsecd":                    ("fbs.smoot.apple.com", "/fb"),
    "itunescloudd":               ("se2.itunes.apple.com", "/WebObjects/MZStore.woa"),
    "cloudkit":                   ("gateway.icloud.com", "/ckdatabase/api/client/query"),
    "transparent_network_proxy":  ("mask-api.icloud.com", "/"),
    "com.apple.transparency":     ("kt-prod.ess.apple.com", "/kt_client/public_keys"),
    "photoanalysisd":             ("gsp51-ssl.ls.apple.com", "/api/v1.0/poi/data"),
    "mapspushd":                  ("gspe35-ssl.ls.apple.com", "/config/announcements"),
    "settings":                   ("sundew.ls.apple.com", "/v1/feedback/submission"),
    "applenews":                  ("gateway.icloud.com", "/ckdatabase/api/client/zone"),
    "adprivacyd":                 ("iadsdk.apple.com", "/adserver/2.6/feedback"),
}


def _producers():
    return json.loads(_GT.read_text())["producers"]


def _gt_framework(entry) -> str:
    return entry.get("framework", "").split()[0]


def _located(gt_framework: str, candidates) -> bool:
    """A candidate set hits if it names the GT framework (case-insensitive), allowing
    short GT aliases like 'Ad' to match a concrete framework 'AdCore'."""
    g = gt_framework.lower()
    return any(g == c.lower() or c.lower().startswith(g) or g.startswith(c.lower())
               for c in candidates)


@requires_artifacts
def test_locator_recall_on_ground_truth(capsys):
    """The locator must locate every evaluable protobuf producer (recall = 100%)."""
    producers = _producers()
    rows, misses = [], []
    for name, (host, path) in _CONNECTIONS.items():
        entry = producers.get(name)
        if entry is None:
            continue
        gt = _gt_framework(entry)
        res = L.locate(L.Connection(producer=entry.get("ua_token", name), host=host, path=path))
        hit = _located(gt, res.candidates)
        rows.append((name, gt, hit, len(res.candidates), res))
        if not hit:
            misses.append(f"{name} → {gt!r}: {res.summary()}")

    with capsys.disabled():
        print("\n[locator recall] connection → candidate set vs ground truth:")
        for name, gt, hit, n, res in rows:
            mark = "OK " if hit else "MISS"
            print(f"  {mark} {name:24} gt={gt:20} n={n:<3} "
                  f"signals={ {s: sorted(v) for s, v in res.by_signal.items() if v} }")
        located = sum(1 for *_, hit, _, _ in rows if hit) if rows else 0
        print(f"  recall: {located}/{len(rows)}")

    assert rows, "no evaluable producers found in the ground truth"
    assert not misses, "locator failed to locate:\n  " + "\n  ".join(misses)


@requires_artifacts
def test_locator_excludes_third_party_producers():
    """Out-of-scope third-party producers (Google) must locate NOTHING — the locator
    must not route them to an Apple framework."""
    producers = _producers()
    third_party = {name: e for name, e in producers.items()
                   if isinstance(e, dict) and e.get("status") == "out_of_scope_thirdparty"}
    assert third_party, "GT should list third-party producers to test the negative"
    for name, entry in third_party.items():
        host = entry.get("host", "").split()[0].split("/")[0]
        res = L.locate(L.Connection(producer=name, host=host))
        assert not res.candidates, f"{name} ({host}) wrongly located {sorted(res.candidates)}"


# --- signal C runtime-constant masking --------------------------------------

def test_token_hit_ignores_occurrences_inside_runtime_constants():
    """A token appearing ONLY inside a serialization-runtime constant is not a hit.

    `type.googleapis.com/` is the google.protobuf.Any type-URL prefix, so every image
    statically linking C++ libprotobuf carries it — it names nothing the binary talks to.
    """
    assert L._token_hit("googleapis", "google.protobuf.Any\ntype.googleapis.com/\n") is False


def test_token_hit_still_fires_when_the_token_also_stands_alone():
    """Masking a runtime constant must never hide a genuine occurrence elsewhere."""
    blob = "type.googleapis.com/\nfirebaselogging-pa.googleapis.com\n"
    assert L._token_hit("googleapis", blob) is True
    assert L._token_hit("googleapis", "some.googleapis.com/v1/thing") is True


def test_token_hit_leaves_unrelated_tokens_alone():
    assert L._token_hit("poi", "gsp51-ssl.ls.apple.com/poi/data") is True


@requires_artifacts
def test_signal_c_does_not_route_google_traffic_to_a_libprotobuf_linking_image():
    """Regression: `googleapis` used to locate GeoServices for Google's own Firebase host.

    GeoServices links C++ libprotobuf and so embeds `type.googleapis.com/`. The rarity
    guard could not catch it — only one binary in the libexec set links libprotobuf, so the
    token looked maximally discriminating precisely because it was a runtime constant.
    """
    conn = L.Connection(producer="datatransport", host="firebaselogging-pa.googleapis.com")
    assert L.url_search_candidates(conn) == set()


# --- per-signal unit checks (each gated on the artifact it needs) ------------

@requires_artifacts
def test_signal_a_otool_links_expected_framework():
    binp = L.daemon_binary("geod")
    assert binp is not None, "geod binary expected in the libexec artifacts"
    assert "GeoServices" in L.otool_frameworks(binp)


def test_signal_b_host_map_resolves_known_hosts():
    # pure table lookup — no artifacts needed
    assert "GeoServices" in L.host_candidates(L.Connection("x", "gsp51-ssl.ls.apple.com", "/poi"))
    assert "CoreLocationProtobuf" in L.host_candidates(
        L.Connection("x", "gsp10-ssl.apple.com", "/hcy/pbcwloc"))
    assert "CloudKitDaemon" in L.host_candidates(L.Connection("x", "gateway.icloud.com", "/ckdatabase"))
    assert L.host_candidates(L.Connection("x", "firebaselogging-pa.googleapis.com", "/")) == set()


def test_signal_b_pbcwloc_path_beats_bare_geo_host():
    # the path discriminates the harvest endpoint (CLP) from generic GeoServices
    clp = L.Connection("x", "gsp10-ssl.apple.com", "/hcy/pbcwloc")
    assert "CoreLocationProtobuf" in L.host_candidates(clp)


@requires_artifacts
def test_signal_c_url_token_finds_producer_binary():
    # 'pbcwloc' is hard-coded in the locationd binary -> URL search must surface it
    conn = L.Connection("x", "gsp10-ssl.apple.com", "/hcy/pbcwloc")
    assert "locationd" in L.url_search_candidates(conn)


def test_url_tokens_keeps_full_path_segments():
    conn = L.Connection("x", "gsp51-ssl.ls.apple.com", "/api/v1.0/poi/data")
    toks = L.url_tokens(conn)
    assert "poi" in toks and "data" in toks
    assert "gsp51-ssl" in toks            # host label kept
    assert "apple" not in toks and "com" not in toks   # noise dropped


def test_url_tokens_do_not_split_on_underscore():
    # the findings doc's key property: a compound path segment stays one token
    conn = L.Connection("x", "kt-prod.ess.apple.com", "/kt_client/consistency_proof")
    toks = L.url_tokens(conn)
    assert "consistency_proof" in toks
    assert "consistency" not in toks and "proof" not in toks
