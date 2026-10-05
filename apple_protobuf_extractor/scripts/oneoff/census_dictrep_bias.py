"""Census for TODO #54 — biased dictRep-only enums.

The dictRep enum harvester (`proto.enums._harvest_dictrep_enums`) reads enum
values as the raw table index / compare immediate; it does NOT subtract a leading
``sub wIdx, wValue, #bias`` the way the xAsString: path does (`_find_index_bias`).
So a 1-based (or N-based) enum that is stored in ``-[Cls _dictionaryRepresentation:]``
AND has no ``xAsString:`` selector would come out off by the bias.

This census hunts for real instances of that exact set across cache frameworks:

  biased dispatch (leading `sub #N` before the jump/pointer table)
    ∩ dictRep-recovered enum (the harvester returned ≥2 values for that ivar)
    ∩ NO xAsString:/StringAsX: selector for the field   (else it routes through
                                                          the bias-aware path)

For every match it prints (framework, class, field, bias, the CURRENTLY-emitted
values) so the wrong-by-bias values can be Hopper-confirmed.  An empty result on
a wide sweep is itself the finding: #54 is latent, not active.

Run: ./venv/bin/python3 census_dictrep_bias.py [fw1 fw2 ...]
"""
import sys

import proto.enums as EN
from validate_lever import _load_cache, _load_binary

# Validated set + the 10 portability-test frameworks (HealthKit & iCloudDriveCore
# are where the known biased — but xAsString-routed — enums live).
_CACHE_FWS = [
    "GeoServices", "CoreLocationProtobuf",
    "NewsTransport", "BiomeStreams", "NanoMailKitServer", "CoreSuggestionsInternals",
    "ActivitySharing", "TrialProto", "StatusKitAgentCore", "iCloudDriveCore",
    "HealthKit", "EmailDaemon",
]


def _dictrep_insns(ctx, cls):
    """Disassemble -[cls _dictionaryRepresentation:] exactly as the harvester does
    (probe budget, then function-extent if the probe was truncated)."""
    m = cls.get_method('_dictionaryRepresentation:')
    if m is None or m.imp == 0:
        return None
    try:
        insns = EN.disasm(ctx, m.imp, max_insns=EN._DICTREP_PROBE_INSNS)
    except Exception:
        return None
    if not insns:
        return None
    if EN._disasm_truncated(insns, EN._DICTREP_PROBE_INSNS):
        body = EN._function_body_extent(ctx, m.imp, EN._DICTREP_HARD_CAP)
        if body:
            insns = body
    return insns


def _sub_imm_to_reg(insns, words, lo, hi, idx_reg):
    """Imm of the last ``sub w<idx_reg>, wRn, #imm12`` (shift 0) in ``insns[lo:hi]``.

    The dest register MUST be the table's INDEX register.  Without this guard a
    `sub` belonging to a *neighbouring* field's dispatch (which shares the same
    20-insn window) is wrongly attributed — the window-bleed false positive that
    `_leading_sub_bias` alone produces (e.g. GEOPD…SpellCorrection: the 1-based
    `resultStatus` sub bleeding onto the 0-based `spellerRankerModelType`)."""
    bias = 0
    for k in range(lo, hi):
        w = words.get(insns[k].addr, 0)
        if (w & EN._SUB_W_IMM_MASK) == EN._SUB_W_IMM_PATTERN:
            rd = w & 0x1F
            sh = (w >> 22) & 0x3
            imm = (w >> 10) & 0xFFF
            if rd == idx_reg and sh == 0 and 0 < imm < EN._SPARSE_MAX_RANGE:
                bias = imm
    return bias


def _bias_by_ivar(ctx, cls, insns):
    """Map ivar_offset -> bias for every enum dispatch whose TABLE INDEX register
    is produced by a leading `sub #bias`.  Mirrors the two dispatch idioms in
    `_harvest_dictrep_enums` (jump table via adr+br; pointer table via 8-byte
    register-offset load), and requires the sub's dest == the table index reg."""
    words = {}
    for ins in insns:
        w = EN._read_raw_word(ctx, ins.addr)
        if w is not None:
            words[ins.addr] = w
    valid = {iv.offset for iv in cls.ivars}
    out = {}

    # Idiom 1 — jump table: adrp case-base + `br` within a few insns.  The index
    # register is the rm of the ldrb/ldrh table-base read inside the window.
    for i, ins in enumerate(insns):
        if EN._decode_adr(words.get(ins.addr, 0), ins.addr) is None:
            continue
        if not any(EN._is_br_insn(words.get(insns[j].addr, 0))
                   for j in range(i, min(i + 6, len(insns)))):
            continue
        lo = max(0, i - 20)
        win = insns[lo:i + 2]
        off = EN._last_ivar_offset_in_window(ctx, win)
        if off is None or off not in valid:
            continue
        idx_reg = None
        for ins2 in win:
            d = EN._decode_ldr_reg_off(words.get(ins2.addr, 0))
            if d is not None and d[0] in (1, 2):
                idx_reg = d[2]                       # rm of the table read
        if idx_reg is None:
            continue
        bias = _sub_imm_to_reg(insns, words, lo, i, idx_reg)
        if bias and off not in out:
            out[off] = bias

    # Idiom 2 — pointer table: 8-byte `ldr xR, [table, value, lsl #3]`.
    for i, ins in enumerate(insns):
        d = EN._decode_ldr_reg_off(words.get(ins.addr, 0))
        if d is None or d[0] != 8:
            continue
        idx_reg = d[2]                               # rm = the index register
        lo = max(0, i - 16)
        win = insns[lo:i + 1]
        off = EN._last_ivar_offset_in_window(ctx, win)
        if off is None or off not in valid:
            continue
        bias = _sub_imm_to_reg(insns, words, lo, i, idx_reg)
        if bias and off not in out:
            out[off] = bias
    return out


def _has_xasstring(cls, st, pname):
    """True if the field has an xAsString:/StringAsX: selector anywhere (so the
    production tool routes it through the bias-aware path, not dictRep)."""
    cap = pname[:1].upper() + pname[1:]
    if cls.get_method(f"{pname}AsString:") or cls.get_method(f"StringAs{cap}:"):
        return True
    return bool(st.find(f"{pname}AsString:") or st.find(f"StringAs{cap}:"))


def run(label, loaded):
    if loaded is None:
        print(f"== {label}: SKIPPED (not found)")
        return []
    ctx, st, cl = loaded
    hits = []
    n_dictrep = 0
    for cls in cl:
        if getattr(cls, "is_meta", False):
            continue
        insns = _dictrep_insns(ctx, cls)
        if insns is None:
            continue
        dr = EN._harvest_dictrep_enums(ctx, cls, st)
        if not dr:
            continue
        n_dictrep += 1
        biased = _bias_by_ivar(ctx, cls, insns)
        name_by_off = {iv.offset: iv.name for iv in cls.ivars if iv.name}
        for off, pairs in dr.items():
            bias = biased.get(off)
            if not bias:
                continue
            pname = EN._proto_name(name_by_off.get(off, f"off_{off:#x}"))
            if _has_xasstring(cls, st, pname):
                continue                      # xAsString-routed → bias handled
            hits.append((label, cls.name, pname, bias, sorted(pairs)))
    print(f"== {label}: {n_dictrep} classes with dictRep enums, "
          f"{len(hits)} BIASED dictRep-only")
    for _, cn, pn, b, pairs in hits:
        print(f"   !! {cn}.{pn}  bias={b}  current(0-based)={pairs[:6]}"
              f"  → should be {[(v + b, nm) for v, nm in pairs[:6]]}")
    return hits


def main():
    fws = sys.argv[1:] or _CACHE_FWS
    all_hits = []
    for fw in fws:
        all_hits += run(f"{fw} (cache)", _load_cache(fw))
    if not sys.argv[1:]:
        all_hits += run("locationd (binary)",
                        _load_binary("MACHO_TEST_LOCATIOND", "locationd"))
    print(f"\n{'='*60}\nTOTAL biased dictRep-only enums: {len(all_hits)}")
    if not all_hits:
        print("→ none found: #54 is LATENT across the swept frameworks.")


if __name__ == "__main__":
    main()
