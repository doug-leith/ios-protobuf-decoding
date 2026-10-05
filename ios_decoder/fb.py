"""smoot /fb feedback uploads: resolve the polymorphic ``?type=`` channel to its message.

``fbs.smoot.apple.com/fb?type=<X>`` (and the ``api.`` host) is parsecd's feedback upload
endpoint. The ``?type=`` query param is a ``KnownFeedbackType`` channel name that selects a
DIFFERENT message per channel, each owned by the producing framework — parsecd is only the
uploader, so one static URL→message rule cannot serve it. Every mapping below was
reverse-engineered and protoc-verified against real wire bodies on 2026-06-17
(notes/FB_TYPE_DISPATCH_RE_2026-06-17.md). A ``?type=`` we have NOT verified is raw-decoded
(honest), never guessed.
"""

from __future__ import annotations

import re

from .rules import DecodeContext, Rule, decode_arpc_or_raw

__all__ = ["decode_fb", "fb_type", "FB_TYPE_MAP"]

# ?type= -> (schema_file, fully-qualified message). The schema files are UNMODIFIED
# apple_protobuf_extractor output under ios_decoder/protos/<Framework>/ (package names
# kept, so the message is package-qualified); the framework each came from is named in
# the file's ``// Source:`` header and is the subdir it lives in.
FB_TYPE_MAP = {
    "FeedbackV2PB":                    ("_cpclientsession.proto", "_cpclientsession._CPClientSession"),
    "Usage":                           ("_cpusageenvelope.proto", "_cpusageenvelope._CPUsageEnvelope"),
    "ProactiveEventTracker":           ("pet.proto", "pet.PETUpload"),
    "ProactiveEventTrackerAggregated": ("pet.proto", "pet.PETUpload"),
    "DuetExpert":                      ("atx.proto", "atx.ATXNotificationsPBLogWrapper"),
}

_TYPE_RE = re.compile(r"[?&]type=([^&]+)")


def fb_type(url: str):
    """The ``?type=`` channel name in *url*, or ``None``."""
    m = _TYPE_RE.search(url or "")
    return m.group(1) if m else None


def decode_fb(body: bytes, ctx: DecodeContext) -> str:
    """Decode a smoot /fb feedback body by its ``?type=`` channel (read from ``ctx.url``).

    A mapped channel is decoded against its verified schema (with the usual partial-schema
    note + raw fallback from the schema rule). An unmapped/absent channel is raw-decoded
    under an explicit note — the type is producer-set, so we never guess it from the body.
    """
    t = fb_type(ctx.url)
    head = f"// smoot /fb feedback channel: type={t!r}\n"
    mapped = FB_TYPE_MAP.get(t)
    if mapped is None:
        return (head
                + "// note: no RE-verified schema for this /fb channel; raw decode\n"
                + decode_arpc_or_raw(body, "plain"))
    schema_file, message = mapped
    # The type is ASSERTED from the ?type= channel (a producer-set key), not confirmed against
    # this body — say so, so a plausible-but-wrong decode under a confident name is never silent.
    note = (f"// note: message type {message} asserted from the ?type= channel (RE-verified "
            f"against sample bodies 2026-06-17), not confirmed against this body\n")
    return head + note + Rule(schema_file, message, "plain").decode(body, ctx)
