"""Differential cross-check: tool-emitted field numbers vs the independent
linear-scan oracle (gt_fields), for every proto message in a framework.

For each emitted ProtoMessage whose ObjC class has a writeTo:, compare the set
of field numbers the TOOL produced against the set the independent oracle reads
straight from the `mov w2,#imm` immediates.  Prints only MISMATCHES (plus a
summary), so a clean framework is a short report and disagreements are the
manual-drill-down worklist.

Usage:
    ../venv/bin/python3 gt_compare.py <framework>
"""
import sys

import proto.extractor as E
from gt_fields import load, fields_of, all_imp_bounds


def main():
    fw = sys.argv[1]
    ctx, st, cl = load(fw)
    bounds = all_imp_bounds(cl)
    msgs = E.extract_all(ctx, st, cl)
    by_cls = {m.class_name: m for m in msgs}
    n_msg = n_cmp = n_ok = 0
    mism = []
    for cls, m in sorted(by_cls.items()):
        c = cl.find(cls)
        if c is None or c.get_method("writeTo:") is None:
            continue
        oracle = fields_of(ctx, c, bounds)
        if oracle is None:
            continue
        n_cmp += 1
        tool_nums = sorted({f.number for f in m.fields})
        ora_nums = sorted({num for num, _iv, _w, _h in oracle})
        # only count fields the tool confirmed from writeTo (number_confirmed);
        # estimated numbers are a separate, already-flagged category.
        conf_nums = sorted({f.number for f in m.fields if f.number_confirmed})
        if tool_nums == ora_nums:
            n_ok += 1
        else:
            mism.append((cls, tool_nums, ora_nums, conf_nums,
                         [f.number_confirmed for f in m.fields]))
    print(f"\n=== {fw}: {len(msgs)} msgs, {n_cmp} with writeTo: compared, "
          f"{n_ok} number-sets IDENTICAL, {len(mism)} differ ===")
    for cls, t, o, conf, _ in mism:
        only_tool = sorted(set(t) - set(o))
        only_ora = sorted(set(o) - set(t))
        print(f"\n  {cls}")
        print(f"    tool : {t}")
        print(f"    oracle:{o}")
        if only_tool:
            print(f"    tool-only (not seen by oracle): {only_tool}")
        if only_ora:
            print(f"    oracle-only (tool missed?):     {only_ora}")


if __name__ == "__main__":
    main()
