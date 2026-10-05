"""For each framework, classify every tool/oracle field-number disagreement:
is each oracle-MISSED field flagged by the tool as estimated (honest) or claimed
confirmed (potential bug)?  And is each tool-MISSED field a real oracle blind
spot?  Also reports, per oracle-missed field, whether the writeTo: block sets the
field number to a literal 0 (the invalid-number → estimate path).
"""
import sys
import proto.extractor as E
from gt_fields import load, fields_of, all_imp_bounds

fw = sys.argv[1]
ctx, st, cl = load(fw)
bounds = all_imp_bounds(cl)
msgs = E.extract_all(ctx, st, cl)
by_cls = {m.class_name: m for m in msgs}

honest = bug = oracle_blind = 0
for cls, m in sorted(by_cls.items()):
    c = cl.find(cls)
    if c is None or c.get_method("writeTo:") is None:
        continue
    oracle = fields_of(ctx, c, bounds)
    if oracle is None:
        continue
    ora_nums = {num for num, _i, _w, _h in oracle}
    tool_nums = {f.number for f in m.fields}
    if ora_nums == tool_nums:
        continue
    conf = {f.number: f.number_confirmed for f in m.fields}
    only_tool = sorted(tool_nums - ora_nums)
    only_ora = sorted(ora_nums - tool_nums)
    print(f"\n{cls}")
    for n in only_tool:
        c_ = conf.get(n)
        tag = "CONFIRMED(!)" if c_ else "estimated(flagged)"
        if c_:
            bug += 1
        else:
            honest += 1
        print(f"   tool-only #{n}: {tag}")
    for n in only_ora:
        oracle_blind += 1
        print(f"   oracle-only #{n}: (tool MISSED — real gap?)")
print(f"\n== {fw}: tool-only estimated/flagged={honest}  "
      f"tool-only CONFIRMED-but-oracle-missed={bug}  "
      f"oracle-only(tool-missed)={oracle_blind} ==")
