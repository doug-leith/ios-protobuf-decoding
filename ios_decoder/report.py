"""Offline CLI: decode an iOS ``.mitm`` capture, mirroring the old live addon's output.

Reads a mitmdump ``.mitm`` file via ``mitmproxy.io.FlowReader`` (no live proxy) and,
for each HTTP flow, prints the request/response line and the decoded protobuf/ARPC
bodies — the same decoding the addon did, but reproducibly and re-runnably.

Usage:
    python -m ios_decoder.report CAPTURE.mitm [--url REGEX] [--limit N] [--decoded-only]
"""

from __future__ import annotations

import argparse
import datetime
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from . import doh, geo, mime, reqlog, siri
from .bodies import BodyDisplayOptions, summarize_undecoded
from .decode import decode_request_body, decode_response_body
from .endpoints import DecodeContext, default_table
from .paths import DEFAULT_PROTO_DIRS
from .schemas import SchemaRegistry


def _content(msg) -> tuple[bytes, bool]:
    """Return ``(body, fell_back)``.

    ``msg.content`` applies the Content-Encoding (gunzip, etc.); if that raises — a corrupt or
    unknown encoding — we fall back to the raw, still-encoded bytes and signal it via
    ``fell_back`` so the caller can flag in the output that the preview isn't the real body.
    """
    try:
        return (msg.content or b""), False
    except Exception:
        return (msg.raw_content or b""), True


def _ct(headers) -> str:
    return headers.get("content-type", "")


def _fmt_time(ts: Optional[float]) -> str:
    if not ts:
        return "?"
    return f"{ts} ({datetime.datetime.fromtimestamp(ts, datetime.timezone.utc)} UTC)"


@dataclass
class _FlowOutput:
    """One HTTP flow's decoded artifacts, handed from the decode phase to the emit phase."""
    geo_findings: list
    req_out: Optional[str]
    res_out: Optional[str]
    req_ct: str
    res_ct: str
    rbody: bytes
    sbody: bytes
    decoded_any: bool
    notes: list


def _decode_flow(flow, table, ctx) -> _FlowOutput:
    """Decode one HTTP flow's request/response bodies and recover its geo markers.

    Each body is tried as protobuf/ARPC first (endpoint rule or generic), then by
    Content-Type.  Geographic markers are emitted into ``ctx.markers`` (cleared first); the
    decoded text plus raw bodies/content-types the emitter needs are returned.
    """
    url = flow.request.pretty_url
    ctx.markers.clear()                 # markers are collected per flow, emitted once below
    headers = list(flow.request.headers.items())

    geo_findings = geo.request_findings(url, headers, dict(flow.request.query))
    for f in geo_findings:
        ctx.markers.emit(f.marker)

    req_out = res_out = None
    req_ct = res_ct = ""
    notes: list = []
    rbody, rfell = _content(flow.request)
    if rfell:
        notes.append("request content-decoding failed; showing raw (still-encoded) bytes")
    if rbody:
        req_ct = _ct(flow.request.headers)
        req_out = decode_request_body(url, rbody, table, ctx, req_ct)
        if req_out is None:
            req_out = mime.decode_by_content_type(rbody, req_ct)
    if req_out is None:                 # DoH GET carries the query in ?dns=, not a body
        req_out = doh.doh_request_summary(url)
    sbody = b""
    if flow.response is not None:
        sbody, sfell = _content(flow.response)
        if sfell:
            notes.append("response content-decoding failed; showing raw (still-encoded) bytes")
        if sbody:
            res_ct = _ct(flow.response.headers)
            res_out = decode_response_body(url, sbody, table, ctx, res_ct)
            if res_out is None:
                res_out = mime.decode_by_content_type(sbody, res_ct)

    decoded_any = req_out is not None or res_out is not None or bool(ctx.markers)
    return _FlowOutput(geo_findings, req_out, res_out, req_ct, res_ct, rbody, sbody,
                       decoded_any, notes)


def _emit_flow(flow, ctx, out: _FlowOutput, body_opts: BodyDisplayOptions,
               request_log: bool) -> None:
    """Print one already-decoded flow: bodies, geo lines, ``+++`` markers, request log."""
    url = flow.request.pretty_url
    print(f"\ntimestamp {_fmt_time(flow.request.timestamp_start)}")
    print(f"{flow.request.method} {url}")
    for note in out.notes:               # e.g. content-decoding fell back to raw bytes
        print(f"// note: {note}")
    if out.req_out is not None:
        print("Request body (decoded):")
        print(out.req_out)
    elif out.rbody:
        print("Request body " + summarize_undecoded(out.rbody, out.req_ct, body_opts))
    if out.res_out is not None:
        print("Response body (decoded):")
        print(out.res_out)
    elif out.sbody:
        print("Response body " + summarize_undecoded(out.sbody, out.res_ct, body_opts))
    for f in out.geo_findings:           # human-readable geo lines
        print(f"  {f.description}")
    for line in ctx.markers.lines():     # +++XYZ / +++LATLON / +++LATLON_BOUNDBOX
        print(line)
    if request_log:                      # +++REQUEST / +++REQHEADERS (per-flow metadata)
        headers = list(flow.request.headers.items())
        ua = flow.request.headers.get("user-agent", "")
        for m in reqlog.request_log(url, headers, out.rbody, flow.request.timestamp_start, ua):
            print(m.line())


def _print_flow(flow, table, ctx, decoded_only: bool,
                body_opts: BodyDisplayOptions, request_log: bool = True) -> bool:
    """Decode one flow and print it; return True if anything decoded.

    ``--decoded-only`` suppresses a flow that produced no decode (an undecoded body alone
    doesn't qualify, so it stays hidden there); normal mode surfaces it.
    """
    out = _decode_flow(flow, table, ctx)
    if decoded_only and not out.decoded_any:
        return False
    _emit_flow(flow, ctx, out, body_opts, request_log)
    return out.decoded_any


def _tcp_endpoint(flow) -> str:
    """Human-readable ``host:port`` for a TCP flow (SNI if known, else peer address)."""
    sc = getattr(flow, "server_conn", None)
    if sc is None:                  # malformed flow — must not raise (used in the error handler)
        return "?:?"
    sni = getattr(sc, "sni", None)
    if isinstance(sni, bytes):
        sni = sni.decode("ascii", "replace")
    addr = sc.peername or sc.address or (None, None)
    return f"{sni or addr[0]}:{addr[1]}"


def _print_tcp_flow(flow, decoded_only: bool, body_opts: BodyDisplayOptions) -> bool:
    """Print one raw TCP flow: Siri (ACE / HTTP-2) decoded, else a raw-bytes summary.

    Returns True if the flow was decoded as Siri.  Non-Siri TCP is surfaced (unless
    ``--decoded-only``) as a one-line-per-direction byte summary — never silently dropped.
    """
    endpoint = _tcp_endpoint(flow)
    messages = [(m.from_client, m.content) for m in flow.messages]
    decoded = siri.decode_tcp_flow(messages)
    if decoded is None and decoded_only:
        return False

    ts = flow.client_conn.timestamp_start if flow.client_conn else None
    print(f"\ntimestamp {_fmt_time(ts)}")
    if decoded is not None:
        print(f"TCP {endpoint}  (Siri)")
        print(decoded)
        return True
    print(f"TCP {endpoint}  (not Siri)")
    client, server = siri.split_directions(messages)
    print("  client → server " + summarize_undecoded(client, "", body_opts))
    print("  server → client " + summarize_undecoded(server, "", body_opts))
    return False


def _process_one_flow(flow, is_tcp: bool, table, ctx, decoded_only: bool,
                      body_opts: BodyDisplayOptions, request_log: bool) -> bool:
    """Decode + print one flow, ISOLATING per-flow failures: a single malformed body must
    not abort the whole capture. On any error, log to stderr and return False (so the run
    loop treats it as not-decoded and carries on to the next flow). Returns True iff the
    flow produced decoded output.
    """
    try:
        if is_tcp:
            return _print_tcp_flow(flow, decoded_only, body_opts)
        return _print_flow(flow, table, ctx, decoded_only, body_opts, request_log)
    except Exception as e:  # noqa: BLE001 - last-resort per-flow guard
        where = _tcp_endpoint(flow) if is_tcp else getattr(flow.request, "pretty_url", "?")
        print(f"[ios_decoder] ERROR decoding flow {where}: "
              f"{type(e).__name__}: {e}", file=sys.stderr)
        return False


def _flow_passes_filters(flow, is_tcp: bool, url_re, ua_prefix: Optional[str],
                         start_time: Optional[float], end_time: Optional[float]) -> bool:
    """Apply the pre-decode filters to one flow.

    ``ua_prefix`` is a lower-cased snippet matched against the *start* of the request's
    User-Agent (prefix match, case-insensitive) — same as the old addon's anchored filter.
    TCP flows (Siri etc.) have no URL/UA, so they match the URL filter against the endpoint
    and skip the UA filter rather than being dropped outright.
    """
    if is_tcp:
        if url_re and not url_re.search(_tcp_endpoint(flow)):
            return False
        ts = flow.client_conn.timestamp_start if flow.client_conn else None
    else:
        if url_re and not url_re.search(flow.request.pretty_url):
            return False
        if ua_prefix and not flow.request.headers.get("user-agent", "").lower().startswith(ua_prefix):
            return False
        ts = flow.request.timestamp_start
    if start_time and ts and ts < start_time:
        return False
    if end_time and ts and ts > end_time:
        return False
    return True


def _resolve_proto_dirs(proto_dirs) -> tuple[list, Optional[str]]:
    """Pick the schema-source dirs and a transparency note if none of them exist.

    Named-schema decoding is optional: the .proto files live in the external addon_ios oracle
    (or wherever ``--proto-dir`` points).  When no dir is present the decoder still works via
    raw protobuf, but the user should know *why* the output is unnamed — hence the note.
    """
    dirs = list(proto_dirs) if proto_dirs else list(DEFAULT_PROTO_DIRS)
    if any(Path(d).is_dir() for d in dirs):
        return dirs, None
    note = ("[ios_decoder] note: no .proto schema dir found (looked in: "
            + ", ".join(str(d) for d in dirs)
            + "); named-schema decoding is disabled — bodies are shown via raw protobuf "
              "decode. Pass --proto-dir DIR to enable named schemas.")
    return dirs, note


def run(mitm_path: str, *, url_filter: Optional[str] = None, limit: int = -1,
        decoded_only: bool = False, body_opts: BodyDisplayOptions = BodyDisplayOptions(),
        user_agent: Optional[str] = None, start_time: Optional[float] = None,
        end_time: Optional[float] = None, max_flows: int = -1,
        request_log: bool = True, proto_dirs=None) -> int:
    """Decode flows from ``mitm_path``; returns the number of flows with output.

    Filters (applied before decoding): ``url_filter`` regex, ``user_agent`` prefix snippet
    (case-insensitive, matched at the start of the UA), ``start_time``/``end_time``
    request-timestamp bounds (epoch seconds), and ``max_flows`` (cap on flows processed after
    filtering).  ``request_log`` toggles the +++REQUEST/+++REQHEADERS lines.
    ``proto_dirs`` overrides the schema source for named-endpoint decoding (default:
    :data:`~ios_decoder.paths.DEFAULT_PROTO_DIRS`); when no dir exists, decoding falls back to
    raw protobuf and a one-line note is emitted to stderr.
    """
    from mitmproxy import io, http, tcp
    from mitmproxy.exceptions import FlowReadException

    dirs, schema_note = _resolve_proto_dirs(proto_dirs)
    if schema_note:
        print(schema_note, file=sys.stderr)
    table = default_table()
    ctx = DecodeContext(schemas=SchemaRegistry(dirs))
    url_re = re.compile(url_filter) if url_filter else None
    ua_prefix = user_agent.lower() if user_agent else None

    processed = decoded = 0
    with open(mitm_path, "rb") as fh:
        try:
            for flow in io.FlowReader(fh).stream():
                is_tcp = isinstance(flow, tcp.TCPFlow)
                if not isinstance(flow, http.HTTPFlow) and not is_tcp:
                    continue
                if not _flow_passes_filters(flow, is_tcp, url_re, ua_prefix,
                                            start_time, end_time):
                    continue
                processed += 1
                if max_flows > 0 and processed > max_flows:
                    break
                if _process_one_flow(flow, is_tcp, table, ctx, decoded_only,
                                     body_opts, request_log):
                    decoded += 1
                    if limit > 0 and decoded >= limit:
                        break
        except FlowReadException as e:
            print(f"[ios_decoder] flow read error: {e}", file=sys.stderr)
    return decoded


def main(argv: Optional[list[str]] = None) -> int:
    from . import __version__
    ap = argparse.ArgumentParser(
        description="Decode an iOS .mitm capture (offline)",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--version", action="version",
                    version=f"%(prog)s {__version__}")
    ap.add_argument("mitm", help="input .mitm file")
    ap.add_argument("--url", help="only flows whose URL matches this regex")
    ap.add_argument("--limit", type=int, default=-1,
                    help="stop after N flows with decoded output")
    ap.add_argument("--decoded-only", action="store_true",
                    help="print only flows that produced a protobuf/ARPC decode")
    ap.add_argument("--hex", action="store_true",
                    help="show undecoded bodies as a hex dump instead of repr()")
    ap.add_argument("--full-bodies", action="store_true",
                    help="show undecoded bodies in full instead of truncating the preview")
    ap.add_argument("--user-agent", metavar="SNIPPET",
                    help="only flows whose User-Agent starts with SNIPPET "
                         "(case-insensitive prefix; e.g. 'com.apple.geod')")
    ap.add_argument("--start-time", type=float, metavar="EPOCH",
                    help="only flows at/after this request timestamp (epoch seconds)")
    ap.add_argument("--end-time", type=float, metavar="EPOCH",
                    help="only flows at/before this request timestamp (epoch seconds)")
    ap.add_argument("--max-flows", type=int, default=-1,
                    help="process at most N flows (after filtering)")
    ap.add_argument("--no-request-log", action="store_true",
                    help="suppress the +++REQUEST / +++REQHEADERS summary lines")
    ap.add_argument("--proto-dir", action="append", metavar="DIR",
                    help="directory of .proto schema files for named-endpoint decoding "
                         "(repeatable; default: the addon_ios dir if present). Without any, "
                         "bodies are decoded as raw protobuf.")
    args = ap.parse_args(argv)
    body_opts = BodyDisplayOptions(hexdump=args.hex, full=args.full_bodies)
    proto_dirs = [Path(d) for d in args.proto_dir] if args.proto_dir else None
    n = run(args.mitm, url_filter=args.url, limit=args.limit,
            decoded_only=args.decoded_only, body_opts=body_opts,
            user_agent=args.user_agent, start_time=args.start_time,
            end_time=args.end_time, max_flows=args.max_flows,
            request_log=not args.no_request_log, proto_dirs=proto_dirs)
    print(f"\n[ios_decoder] {n} flow(s) decoded", file=sys.stderr)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
