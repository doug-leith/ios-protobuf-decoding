"""Standalone structural protobuf matcher — score a wire body against a schema set.

Ported into ios_decoder (from the now-retired ``mitm_traffic_parser.match`` /
``corpus`` / ``wireparse``) so the optional match cross-check has NO cross-tool
dependency.  It is built entirely on ios_decoder's own primitives:

  * the wire tree comes from :func:`ios_decoder.rawproto.parse_fields` (the
    ``protoc``-verified scanner the raw decoder already uses), and
  * the schema set is a ``google.protobuf`` ``DescriptorPool`` compiled from a
    directory of ``.proto`` files with ``protoc`` — the same toolchain
    :class:`ios_decoder.schemas.SchemaRegistry` uses.

The algorithm is unchanged from the reference implementation it replaces:

1. **Hard constraints (exclusion).**  If a candidate message *defines* an observed
   field number with an incompatible wire type, no serialization of it could produce
   the observed bytes — it is impossible and excluded.  (Undefined observed fields are
   NOT a violation: protobuf permits unknown fields.)
2. **Fuzzy ranking** of the surviving candidates by how many fields they *explain*
   (defined with a compatible wire type, recursing into sub-messages), aggregated over
   all nesting levels.

It is inherently fuzzy — it can only find a type that was extracted, and small payloads
are ambiguous — so results are ranked candidates with a confidence flag, not a single
hard answer.  This module is used only by the optional test-time cross-check; nothing in
the production decode path imports it.
"""

from __future__ import annotations

import functools
import glob
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass, field
from typing import Optional

from google.protobuf import descriptor_pb2, descriptor_pool
from google.protobuf.descriptor import Descriptor, FieldDescriptor

from . import rawproto

# protobuf wire types (https://protobuf.dev/programming-guides/encoding)
WIRE_VARINT, WIRE_I64, WIRE_LEN, WIRE_I32 = 0, 1, 2, 5

# FieldDescriptor.type -> the single wire type a field of that declared type must use.
_TYPE_WIRE = {
    FieldDescriptor.TYPE_DOUBLE: WIRE_I64,
    FieldDescriptor.TYPE_FLOAT: WIRE_I32,
    FieldDescriptor.TYPE_INT64: WIRE_VARINT,
    FieldDescriptor.TYPE_UINT64: WIRE_VARINT,
    FieldDescriptor.TYPE_INT32: WIRE_VARINT,
    FieldDescriptor.TYPE_FIXED64: WIRE_I64,
    FieldDescriptor.TYPE_FIXED32: WIRE_I32,
    FieldDescriptor.TYPE_BOOL: WIRE_VARINT,
    FieldDescriptor.TYPE_STRING: WIRE_LEN,
    FieldDescriptor.TYPE_GROUP: WIRE_LEN,       # groups are rare; treat structurally as LEN
    FieldDescriptor.TYPE_MESSAGE: WIRE_LEN,
    FieldDescriptor.TYPE_BYTES: WIRE_LEN,
    FieldDescriptor.TYPE_UINT32: WIRE_VARINT,
    FieldDescriptor.TYPE_ENUM: WIRE_VARINT,
    FieldDescriptor.TYPE_SFIXED32: WIRE_I32,
    FieldDescriptor.TYPE_SFIXED64: WIRE_I64,
    FieldDescriptor.TYPE_SINT32: WIRE_VARINT,
    FieldDescriptor.TYPE_SINT64: WIRE_VARINT,
}


class MatchError(Exception):
    """Raised when a payload can't be parsed as protobuf wire for matching."""


def wire_compatible(fld: FieldDescriptor, wire_type: int) -> bool:
    """Is an observed `wire_type` consistent with field `fld`'s declared type?

    Exact wire-type match, OR a scalar field carried packed-repeated (any scalar may
    appear as one length-delimited blob — covers packed repeated scalars and enums).
    """
    expected = _TYPE_WIRE.get(fld.type)
    if expected is None:
        return True                       # unknown type -> don't manufacture a violation
    if wire_type == expected:
        return True
    return wire_type == WIRE_LEN and expected in (WIRE_VARINT, WIRE_I32, WIRE_I64)


# --- wire tree ---------------------------------------------------------------

@dataclass
class WireField:
    """One decoded wire field: number, wire type, and parsed sub-message (or None)."""
    number: int
    wire_type: int
    message: Optional[list] = None        # parsed sub-tree if the LEN bytes parse as protobuf


def _build_tree(data: bytes, depth: int = 0, max_depth: int = 64) -> Optional[list]:
    """Recursive wire tree for `data`, or None if it isn't valid protobuf wire.

    Length-delimited fields default to a parsed sub-message when their bytes parse
    cleanly and completely as protobuf (protoc's "parse fully or it's a string" rule,
    via rawproto.parse_fields); otherwise `message` stays None.
    """
    fields = rawproto.parse_fields(data)
    if fields is None:
        return None
    nodes = []
    for number, wt, val in fields:
        sub = None
        if wt == WIRE_LEN and isinstance(val, (bytes, bytearray)) and val and depth < max_depth:
            sub = _build_tree(bytes(val), depth + 1, max_depth)
        nodes.append(WireField(number=number, wire_type=wt, message=sub))
    return nodes


def parse_tree(payload: bytes) -> list:
    """Wire tree for a top-level payload; raises MatchError if it isn't matchable.

    Both an unparseable body (None) and an empty one (no fields) raise — there is
    nothing to structurally match in either case.
    """
    tree = _build_tree(payload)
    if not tree:
        raise MatchError("payload is not valid (or is empty) protobuf wire format")
    return tree


def _observed_field_map(tree: list) -> dict:
    """Group a level's fields by field number (repeats collected)."""
    out: dict = {}
    for wf in tree:
        out.setdefault(wf.number, []).append(wf)
    return out


# --- schema set (a directory of .proto compiled with protoc) -----------------

@dataclass
class DescriptorSet:
    """All message descriptors compiled from one framework's .proto directory."""
    messages: list                        # list[(leaf_name, Descriptor)]
    skipped: tuple = ()                   # .proto files protoc rejected (and why), reported not hidden

    def iter_messages(self):
        return iter(self.messages)

    def resolve(self, leaf_name: str) -> Optional[Descriptor]:
        for name, d in self.messages:
            if name == leaf_name:
                return d
        return None


def _collect_messages(desc: Descriptor, out: list) -> None:
    out.append((desc.name, desc))
    for nested in desc.nested_types:
        _collect_messages(nested, out)


# protoc error lines start "name.proto:line:col:" or "name.proto: Import ... had errors".
# The name may be the bare argument or the resolved ABSOLUTE path -- protoc 33 prints the
# latter even when invoked with a basename plus -I, so always basename it before matching
# against the file list (which holds basenames), or no rejected file is ever identified
# and a single bad file fails the whole set instead of being dropped and reported.
_PROTOC_FILE_RE = re.compile(r"^(\S+\.proto):")


def _compile_dir(proto_dir: str, protoc: str):
    """Compile a dir's .proto into a FileDescriptorSet, dropping files protoc rejects.

    Returns (FileDescriptorSet, skipped) where `skipped` is [(file, first error line)].
    A malformed file (e.g. extractor output predating a fix) is dropped and reported —
    a structural cross-check over the rest is still useful — rather than failing the
    whole set.  Raises MatchError only if protoc is missing or nothing compiles.
    """
    names = sorted(os.path.basename(f) for f in glob.glob(os.path.join(proto_dir, "*.proto")))
    if not names:
        raise MatchError(f"no .proto files in {proto_dir}")
    skipped = []
    while names:
        with tempfile.TemporaryDirectory() as td:
            out_pb = os.path.join(td, "set.pb")
            cmd = [protoc, "-I", proto_dir, "--include_imports",
                   f"--descriptor_set_out={out_pb}"] + names
            try:
                proc = subprocess.run(cmd, capture_output=True)
            except FileNotFoundError as e:
                raise MatchError(f"protoc not found: {protoc!r}") from e
            if proc.returncode == 0:
                fds = descriptor_pb2.FileDescriptorSet()
                with open(out_pb, "rb") as fh:
                    fds.ParseFromString(fh.read())
                return fds, skipped
            # find the offending file(s) in stderr, drop them, and retry
            stderr = proc.stderr.decode(errors="replace")
            bad = {}
            for line in stderr.splitlines():
                m = _PROTOC_FILE_RE.match(line)
                if not m:
                    continue
                base = os.path.basename(m.group(1))
                if base in names:
                    bad.setdefault(base, line.strip())
            if not bad:                    # unparseable failure -> surface it
                raise MatchError(f"protoc failed in {proto_dir}:\n{stderr}")
            for f, why in bad.items():
                skipped.append((f, why))
                names.remove(f)
    raise MatchError(f"every .proto in {proto_dir} was rejected by protoc")


@functools.lru_cache(maxsize=None)
def load_descriptor_set(proto_dir: str, protoc: str = "protoc") -> DescriptorSet:
    """Compile every .proto under `proto_dir` into a DescriptorSet (memoized per dir).

    Files protoc rejects are dropped and recorded in ``DescriptorSet.skipped`` rather
    than failing the whole set.  Raises MatchError if protoc is missing or no file compiles.
    """
    fds, skipped = _compile_dir(proto_dir, protoc)
    pool = descriptor_pool.DescriptorPool()
    for f in fds.file:
        pool.Add(f)
    messages: list = []
    for f in fds.file:
        prefix = (f.package + ".") if f.package else ""
        for mt in f.message_type:
            desc = pool.FindMessageTypeByName(prefix + mt.name)
            _collect_messages(desc, messages)
    return DescriptorSet(messages=messages, skipped=tuple(skipped))


# --- the matcher (algorithm unchanged from the reference implementation) ------

_MIN_MATCHED = 3
_MIN_RATIO = 0.7
_MARGIN = 2.0
_CLEAR_RATIO = 0.9
_RATIO_GAP = 0.2
_DEFAULT_MIN_RATIO = 0.5


@dataclass(order=True)
class Candidate:
    """One scored candidate message for a wire tree."""
    matched: int
    observed: int = field(compare=False)
    message: str = field(compare=False, default="")

    @property
    def ratio(self) -> float:
        return self.matched / self.observed if self.observed else 0.0


@dataclass
class MatchResult:
    """Ranked structural-match candidates for a payload."""
    candidates: list
    confident: bool
    pruned: list = field(default_factory=list)

    @property
    def best(self) -> Optional[Candidate]:
        return self.candidates[0] if self.candidates else None


def fit(tree: list, message: Descriptor, depth: int = 0) -> tuple:
    """(matched, observed, violations) of `message` against `tree`, over all levels.

    - matched: fields the schema defines with a compatible wire type (recursing).
    - observed: total fields in the wire tree (all levels).
    - violations: defined fields whose observed wire type is incompatible — a hard
      contradiction proving this message cannot be the type.
    """
    obs = _observed_field_map(tree)
    schema = {f.number: f for f in message.fields}
    matched = 0
    observed = len(obs)
    violations = 0
    for num, occ in obs.items():
        fld = schema.get(num)
        if fld is None:
            continue                       # undefined field -> unknown, not a violation
        wf = occ[0]
        if not wire_compatible(fld, wf.wire_type):
            violations += 1                # HARD constraint: defined but wrong wire type
            continue
        is_msg = fld.type in (FieldDescriptor.TYPE_MESSAGE, FieldDescriptor.TYPE_GROUP)
        if is_msg and wf.message is not None and depth < 8:
            m2, o2, v2 = fit(wf.message, fld.message_type, depth + 1)
            matched += 1 + m2
            observed += o2
            violations += v2
        else:
            matched += 1
    return matched, observed, violations


def _is_confident(cands: list) -> bool:
    """Whether the top candidate clearly out-explains the runner-up (see thresholds)."""
    if not (cands and cands[0].matched >= _MIN_MATCHED and cands[0].ratio >= _MIN_RATIO):
        return False
    if len(cands) > 1:
        w, r = cands[0], cands[1]
        return (w.matched >= _MARGIN * max(r.matched, 1)
                or (w.ratio >= _CLEAR_RATIO and w.ratio - r.ratio >= _RATIO_GAP))
    return True


def _name_matches_direction(name: str, direction: str) -> bool:
    """False only when a message name's Request/Response suffix contradicts `direction`."""
    if direction == "request" and name.endswith("Response"):
        return False
    if direction == "response" and name.endswith("Request"):
        return False
    return True


def match_tree(tree: list, descriptors: DescriptorSet, *, top_k: int = 5,
               min_ratio: float = _DEFAULT_MIN_RATIO, max_violations: int = 0,
               direction: Optional[str] = None) -> MatchResult:
    """Rank feasible messages in `descriptors` by how well they explain `tree`."""
    feasible: list = []
    for name, m in descriptors.iter_messages():
        matched, observed, violations = fit(tree, m)
        if violations > max_violations:
            continue
        if observed and matched / observed >= min_ratio:
            feasible.append(Candidate(matched=matched, observed=observed, message=name))
    feasible.sort(reverse=True)

    pruned: list = []
    if direction:
        kept = [c for c in feasible if _name_matches_direction(c.message, direction)]
        pruned = [c for c in feasible if not _name_matches_direction(c.message, direction)]
    else:
        kept = feasible

    cands = kept[:top_k]
    confident = _is_confident(cands)
    broke_ties = []
    if cands and pruned:
        win = cands[0].matched
        broke_ties = [c.message for c in pruned if 2 * c.matched > win]
    return MatchResult(cands, confident, broke_ties)


def match_payload(payload: bytes, descriptors: DescriptorSet, **kw) -> Optional[MatchResult]:
    """Structurally match a raw protobuf payload, or None if it doesn't parse."""
    try:
        tree = parse_tree(payload)
    except MatchError:
        return None
    return match_tree(tree, descriptors, **kw)
