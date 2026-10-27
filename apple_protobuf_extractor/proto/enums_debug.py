"""proto/enums_debug — ``--debug-enums`` diagnostic record builders.

The diagnostic surface for the enum-fallback instrumentation, apart from the
schema-recovery code it audits.  This module is never
exercised by the synthetic-fixture suite (the diagnostic sink is off in normal
extraction) — see tests/synthetic_fixtures/README.md.

Zero-overhead opt-in: every builder here is only called when the caller
supplies an ``enum_debug_writer=`` sink to ``extract_all`` (see
``proto.config._dbg_enum``); when it is ``None`` (the default) none of this
code runs.

Three failure modes are distinguished:

  A  scalar_no_enum_tag   — instance_method_names non-empty (--cache path) but
                            xAsString:/StringAsX: not detected in those names.
                            The methname fallback is silently skipped, leaving
                            the field as int32 with no annotation.

  B  methname_not_found   — instance_method_names empty (no-cache path) and
                            _enum_name_from_methname returned None; the selector
                            genuinely absent from __objc_methname.

  C  revert_to_scalar     — ENUM: tag was set (either path), but the enum
                            collection loop reverted it: no values were recovered
                            (proto.enums._recover_enum_values).
                            Sub-reasons: no_candidates | all_phase1_rejected.

Record format: JSON Lines (one JSON object per line). Each record contains the
class, field, and all diagnostic state available at the point of failure so
the cause can be determined without re-running the extraction.

Imports from proto.enums at module scope (``_extract_xasstring``, ``_xasstring_flow``,
``_enum_name_from_pairs``) — callers in proto.enums must therefore import this module
lazily (inside the function that needs it, not at module load time) to avoid a cycle;
proto.extractor, which sits above both, imports this module normally.
"""
from __future__ import annotations
from typing import Any, Callable, Dict, List, Set, Tuple

from macho.memory     import BinaryContext, PROGRAM_ERRORS
from macho.strings    import StringTable
from macho.classlist  import ObjcClass, ObjcIvar
from proto.models     import ProtoField
from proto.protocore  import _proto_name, enum_base_name, enum_selectors
from proto.config     import _dbg_enum
from proto.enums      import _enum_name_from_pairs, _extract_xasstring, _xasstring_flow


# ObjC type encodings that identify a genuine ``xAsString:`` method.
# An xAsString: method for an int32/uint32 enum field takes (self @0, SEL @8,
# enum_value i/I @16) and returns id (@), giving a total frame of 20 bytes.
# Requiring this encoding eliminates short stub methods, getters (@16@0:8),
# void setters (v24@0:8@16), and other false-positive candidates whose IMP
# happens to be adjacent to the real enum method in memory, causing the
# linear-disassembly pattern scan to pick up the pointer-table code that
# belongs to the real method.
_ASSTRING_INT_TYPES: frozenset = frozenset({
    "@20@0:8i16",  # standard: returns id, frame 20, int32 arg
    "@20@0:8I16",  # unsigned int32 variant
    "@24@0:8i16",  # 24-byte frame (some ABI variants)
    "@24@0:8I16",
})


def _xasstring_gate_span(ctx: BinaryContext, imp: int) -> int:
    """Number of values the widest ordered gate on the argument of ``-[C xAsString:]`` at
    *imp* (``w2``) admits, along the CFG from the entry (:meth:`Flow.candidates`):
    ``cmp w2, #N ; b.hi`` admits N + 1, ``b.hs`` N, a bias (``sub w8, w2, #k``) shifts the
    range without widening it.  0 when no gate guards the value."""
    if imp == 0:
        return 0
    flow, _ = _xasstring_flow(ctx, imp)
    if flow is None:
        return 0
    scan = flow.candidates(-1, 'x2', (-(1 << 31), 1 << 31))
    return max((hi - lo + 1 for lo, hi in scan.intervals), default=0)


def _extract_enum_values(
    ctx: BinaryContext,
    imp: int,
) -> Tuple[List[Tuple[int, str]], bool, bool]:
    """``(pairs, confirmed, truncated)`` of the ``xAsString:`` method at *imp*
    (:func:`_extract_xasstring` without the reason)."""
    r = _extract_xasstring(ctx, imp)
    return r.pairs, r.confirmed, r.truncated


def _gather_asstring_methname_hits(
    pname: str,
    st: StringTable,
) -> Dict[str, Any]:
    """
    Search ``__objc_methname`` for xAsString:/StringAsX: selectors that match
    *pname* and return a small diagnostic dict.

    Used by Modes A, B and C to answer the key question: "does this selector
    exist anywhere in the binary?" independently of whether it was resolved
    as a method name on the class.
    """
    xas_sel, strx_sel = enum_selectors(pname)

    # Direct presence check (fast path via inverted index)
    xas_in_mn  = bool(st.find(xas_sel))
    strx_in_mn = bool(st.find(strx_sel))

    # Collect ALL *AsString: selectors in methname that contain the field name
    # fragment — useful for spotting near-misses (e.g. "componentTypeAsString:"
    # when we searched for "typeAsString:").
    related: List[str] = []
    pname_lower = pname.lower()
    for entry in st.all_in_section('__objc_methname'):
        v = entry.value
        if 'AsString:' in v and pname_lower in v.lower():
            related.append(v)

    return {
        "xasstring_sel":          xas_sel,
        "stringasx_sel":          strx_sel,
        "xasstring_in_methname":  xas_in_mn,
        "stringasx_in_methname":  strx_in_mn,
        "related_asstring_sels":  sorted(set(related))[:20],  # cap for readability
    }


def _gather_type_compatible_methods(
    cls: ObjcClass,
    ctx: BinaryContext,
) -> List[Dict[str, Any]]:
    """
    Return a list of methods on *cls* whose type encoding matches
    ``_ASSTRING_INT_TYPES`` (the signature of a genuine xAsString: method).

    For each such method, attempt to extract a few enum value strings so the
    debug record can show what enum they actually belong to.

    Called lazily only when the debug sink is active — performance is not a
    concern here.
    """
    results: List[Dict[str, Any]] = []
    seen_imps: Set[int] = set()
    for m in cls.methods:
        if m.imp == 0 or m.imp in seen_imps:
            continue
        if m.types and m.types not in _ASSTRING_INT_TYPES:
            continue
        seen_imps.add(m.imp)
        entry: Dict[str, Any] = {
            "imp":   f"0x{m.imp:x}",
            "types": m.types or "",
            "name":  m.name,   # None when unresolved
        }
        # the enum values, to identify what enum it is
        try:
            entry["field_count"] = _xasstring_gate_span(ctx, m.imp)
            pairs = _extract_enum_values(ctx, m.imp)[0] if entry["field_count"] >= 1 else []
            entry["pairs_count"] = len(pairs)
            entry["sample_values"] = [v for _, v in pairs[:6]]
            entry["derived_name"] = _enum_name_from_pairs(pairs, "\x00") if pairs else "\x00"
        except PROGRAM_ERRORS:
            raise
        except Exception as exc:
            entry["error"] = str(exc)
        results.append(entry)
    return results


def _emit_mode_a_debug(ctx: BinaryContext, cls: ObjcClass, st: StringTable,
                       ivar: ObjcIvar, scalar_type: str,
                       instance_method_names: Set[str],
                       writer: Callable[[Dict[str, Any]], None]) -> None:
    """Mode-A enum-fallback diagnostic: a scalar int ivar got no ENUM: tag, but its
    ``xAsString:``/``StringAsX:`` selector DOES exist in ``__objc_methname`` — positive
    evidence the field should be an enum but wasn't detected for this class. Emits only
    when that selector exists (keeps the debug file to actionable misses); only runs under
    ``--debug-enums``."""
    pname_a = _proto_name(ivar.name)
    hits = _gather_asstring_methname_hits(pname_a, st)
    if not (hits["xasstring_in_methname"] or hits["stringasx_in_methname"]):
        return
    xas_a, stx_a = hits["xasstring_sel"], hits["stringasx_sel"]
    _dbg_enum({
        "mode":                       "A_scalar_no_enum_tag",
        "class":                      cls.name,
        "class_vmaddr":               f"0x{cls.vmaddr:x}",
        "field":                      pname_a,
        "ivar":                       ivar.name,
        "type_enc":                   ivar.type_enc,
        "scalar_type":                scalar_type,
        **hits,
        "xasstring_in_instance_methods": xas_a in instance_method_names,
        "stringasx_in_instance_methods": stx_a in instance_method_names,
        "type_compatible_candidates": _gather_type_compatible_methods(cls, ctx),
        "methods_total":              len(cls.methods),
        "methods_null_name":          sum(1 for m in cls.methods if m.name is None),
        "instance_method_names_asstring": sorted(
            n for n in instance_method_names if "AsString" in n
        )[:20],
    }, writer=writer)


def _emit_mode_b_debug(ctx: BinaryContext, cls: ObjcClass, fld: ProtoField,
                       st: StringTable, writer: Callable[[Dict[str, Any]], None]) -> None:
    """Mode-B enum-fallback diagnostic: an int field had no ``xAsString:``/
    ``StringAsX:`` methname match in the shared-cache scan. Self-contained record
    builder carved out of :func:`proto.enums._collect_enum_definitions` (only runs
    under ``--debug-enums``)."""
    _dbg_enum({
        "mode":       "B_methname_not_found",
        "class":      cls.name,
        "class_vmaddr": f"0x{cls.vmaddr:x}",
        "field":      fld.name,
        "scalar_type": fld.type_name,
        **_gather_asstring_methname_hits(fld.name, st),
        "all_asstring_in_methname": sorted({
            e.value for e in st.all_in_section('__objc_methname')
            if 'AsString:' in e.value
        })[:40],
        "type_compatible_candidates": _gather_type_compatible_methods(cls, ctx),
        "methods_total":  len(cls.methods),
        "methods_null_name": sum(1 for m in cls.methods if m.name is None),
    }, writer=writer)


def _emit_mode_c_debug(ctx: BinaryContext, cls: ObjcClass, fld: ProtoField,
                       st: StringTable, enum_name: str, as_method,
                       instance_method_names: Set[str],
                       writer: Callable[[Dict[str, Any]], None]) -> None:
    """Mode-C enum-fallback diagnostic: an ``ENUM:``-tagged field reverted to scalar
    because no ``xAsString:`` method could be resolved/extracted. Builds the candidate
    list + record. Carved out of :func:`proto.enums._collect_enum_definitions` (only
    runs under ``--debug-enums``)."""
    cap = enum_base_name(fld.name)
    candidates_info = [
        c if "error" in c else {**c, "phase1_match": c["derived_name"] != "\x00"
                                and c["derived_name"].endswith(cap)}
        for c in _gather_type_compatible_methods(cls, ctx)
        if "error" in c or c["field_count"] >= 2]
    if not candidates_info:
        _sub = "no_candidates"
    elif all(c.get("derived_name", "\x00") != "\x00" for c in candidates_info):
        _sub = "all_phase1_rejected"
    else:
        _sub = "no_candidates"
    _dbg_enum({
        "mode":                   "C_revert_to_scalar",
        "sub_reason":             _sub,
        "class":                  cls.name,
        "class_vmaddr":           f"0x{cls.vmaddr:x}",
        "field":                  fld.name,
        "enum_name":              enum_name,
        "instance_method_names_empty": not instance_method_names,
        "as_method_found_by_name": (
            {"imp": f"0x{as_method.imp:x}", "types": as_method.types}
            if as_method is not None else None
        ),
        "candidates":             candidates_info,
        **_gather_asstring_methname_hits(fld.name, st),
        "methods_total":          len(cls.methods),
        "methods_null_name":      sum(1 for m in cls.methods if m.name is None),
        "instance_method_names_asstring_sample": sorted(
            n for n in instance_method_names if "AsString" in n
        )[:20],
    }, writer=writer)
