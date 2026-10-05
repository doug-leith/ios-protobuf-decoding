import json
from collections import Counter, defaultdict
D=json.load(open('/tmp/valcmp.json'))
SCALARS={'int32','int64','uint32','uint64','sint32','sint64','fixed32','fixed64','sfixed32','sfixed64','bool','float','double','string','bytes'}
INTFAM={'int32','uint32','sint32','fixed32','sfixed32','int64','uint64','sint64','fixed64','sfixed64'}
FLOATS={'float','double'}
def strip_pref(n):
    for p in ('GEO','CLP','CLM','CLN'):
        if n.startswith(p): return n[len(p):]
    return n
def tool_idx(td):
    idx={}
    for cn,m in td.items():
        for k in {cn,m['proto'],strip_pref(cn)}: idx.setdefault(k,m)
    return idx
def find(idx,mn): return idx.get(mn) or idx.get('GEO'+mn) or idx.get('CLP'+mn) or idx.get(strip_pref(mn))

def classify(rt,rl,tf):
    tn,tcls,tl,conf=tf[1],tf[2],tf[3],tf[4]
    tool_is_enum = bool(tcls) and tcls.startswith('ENUM:')
    tool_is_msg  = bool(tcls) and not tool_is_enum and tn not in SCALARS
    rc='scalar' if rt in SCALARS else 'msgenum'
    if rt=='bytes' and tn!='bytes':
        c='TOOL_recovered(ref=bytes)'   # manual punted a packed-repeated/sub-msg to bytes
    elif rc=='scalar' and tn in SCALARS:
        if rt==tn: c='ok_scalar'
        elif rt in FLOATS and tn in FLOATS: c='amb_float_double'
        elif rt in INTFAM and tn in INTFAM: c='amb_int_signedness'
        else: c='REAL_scalar_mismatch'
    elif rc=='scalar' and tool_is_enum:
        c='TOOL_recovered_enum' if rt in INTFAM else 'REAL_scalar_as_enum'
    elif rc=='scalar' and tool_is_msg:
        c='TOOL_recovered_msg' if rt=='bytes' else 'REAL_scalar_as_msg'
    elif rc=='msgenum' and tn in SCALARS:
        c='TOOL_failsafe_bytes' if tn=='bytes' else 'REAL_msg_as_scalar'
    else:  # both msg/enum-ish
        c='ok_msgenum' if (strip_pref(rt).lstrip('.')==strip_pref(tn) or strip_pref(rt) in tn or strip_pref(tn) in rt) else 'NAME_msgenum_diff'
    return c,(rl!=tl),conf

BAD={'REAL_scalar_mismatch','REAL_scalar_as_msg','REAL_msg_as_scalar','REAL_scalar_as_enum','MISSING'}
for binkey,bn in [('geo_tool','GEO'),('clp_tool','CLP')]:
    idx=tool_idx(D[binkey])
    # gather per (msg,num) best verdict + per-(file,msg) skew detection
    msg_fields=defaultdict(list)  # (file,msg)->[(num,cat)]
    best={}  # (msg,num)->(cat,labeldiff,conf,detail)
    rank={'ok_scalar':0,'ok_msgenum':0,'TOOL_recovered(ref=bytes)':1,'TOOL_recovered_enum':1,'TOOL_recovered_msg':1,'amb_float_double':1,'amb_int_signedness':1,
          'NAME_msgenum_diff':2,'TOOL_failsafe_bytes':3,'REAL_scalar_mismatch':4,'REAL_msg_as_scalar':4,'REAL_scalar_as_msg':4,'REAL_scalar_as_enum':4,'MISSING':5}
    for fn,msgs in D['refs'].items():
        b='clp' if fn.lower().startswith('clp') else 'geo'
        if b!=bn.lower(): continue
        for mn,fields in msgs.items():
            tm=find(idx,mn)
            if tm is None: continue
            tfs=tm['fields']
            for num,(rname,rt,rl) in fields.items():
                tf=tfs.get(str(num)) or tfs.get(num)
                if tf is None:
                    cat=('MISSING',False,None,(rname,rt,'-'))
                else:
                    c,ld,cf=classify(rt,rl,tf); cat=(c,ld,cf,(rname,rt,tf[1]))
                msg_fields[(fn,mn)].append((int(num),cat[0]))
                key=(mn,int(num)); prev=best.get(key)
                if prev is None or rank.get(cat[0],9)<rank.get(prev[0],9): best[key]=cat
    # version skew: a (file,msg) where >50% of >=4 fields are BAD
    skewed=set()
    for (fn,mn),lst in msg_fields.items():
        if len(lst)>=4:
            badf=sum(1 for _,c in lst if c in BAD)
            if badf/len(lst) > 0.5: skewed.add(mn)
    C=Counter(); conf=Counter(); genuine=[]
    for (mn,num),(cat,ld,cf,det) in best.items():
        C[cat]+=1
        if cf is True: conf['confirmed']+=1
        elif cf is False: conf['estimated']+=1
        if cat in BAD and mn not in skewed:
            genuine.append((mn,num,det,cf,cat))
    tot=sum(C.values())
    print(f"\n================= {bn} : {tot} distinct ref fields =================")
    for k in sorted(C,key=lambda k:-C[k]): print(f"   {k:26} {C[k]}")
    print(f"   confirmed={conf['confirmed']} estimated={conf['estimated']}")
    print(f"   version-skewed messages (excluded from genuine): {len(skewed)}")
    print(f"   GENUINE candidate mistakes (non-skewed messages): {len(genuine)}")
    for mn,num,det,cf,cat in sorted(genuine)[:40]:
        print(f"      {cat:22} {mn}.#{num} {det[0]}: ref={det[1]} tool={det[2]} conf={cf}")
