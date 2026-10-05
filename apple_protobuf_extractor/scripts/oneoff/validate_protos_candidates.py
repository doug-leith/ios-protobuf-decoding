import json,re
d=json.load(open('/tmp/valcmp.json'))
refs=d['refs']
def strip_pref(n):
    for p in ('GEO','CLP','CLM','CLN','PB','PD'):
        while n.startswith(p): n=n[len(p):]
    return n
SCAL={'string','bytes','bool','double','float','int32','int64','uint32','uint64','sint32','sint64','fixed32','fixed64','sfixed32','sfixed64'}
INT={'int32','uint32','int64','uint64','sint32','sint64','fixed32','fixed64','sfixed32','sfixed64'}
def build_idx(tool):
    idx={}
    for cn,m in tool.items():
        for k in {cn,m['proto'],strip_pref(cn)}: idx.setdefault(k,m)
    return idx
def find(idx,mn): return idx.get(mn) or idx.get('GEO'+mn) or idx.get('CLP'+mn) or idx.get(strip_pref(mn))

def classify(rt,tf):
    # tf = tool field [name,raw,resolved,label,conf] or None
    if tf is None: return 'MISSING','-',None
    tn=tf[2] or tf[1]; conf=tf[4]
    sr,st=strip_pref(str(rt).replace('ENUM:','')),strip_pref(str(tn).replace('ENUM:',''))
    if sr==st: return 'ok',tn,conf
    rs,ts=sr in SCAL,st in SCAL
    # tool-better buckets
    if rt=='bytes' and not ts: return 'TOOLrec_msg',tn,conf
    if rt in INT and str(tf[2] or '').startswith('ENUM'): return 'TOOLrec_enum',tn,conf
    # encoding-ambiguous
    if rs and ts and sr in INT and st in INT: return 'amb_signed',tn,conf
    if {sr,st}=={'float','double'}: return 'amb_fd',tn,conf
    # name-only msg/enum diff
    if (not rs) and (not ts):
        if sr in st or st in sr: return 'NAMEdiff',tn,conf
        return 'TYPE_msgmsg',tn,conf
    if st=='bytes': return 'TYPE_tobytes',tn,conf
    return 'TYPE_scalar',tn,conf

GENUINE={'MISSING','TYPE_msgmsg','TYPE_tobytes','TYPE_scalar'}
for binkey,refsel in [('geo_tool',lambda k:not k.startswith('CLP') and k!='geo1.proto'),
                      ('clp_tool',lambda k:k.startswith('CLP'))]:
    idx=build_idx(d[binkey])
    cand={}
    for rf in [k for k in refs if refsel(k)]:
        for mn,fields in refs[rf].items():
            tm=find(idx,mn)
            tfs=tm['fields'] if tm else None
            for num,fr in fields.items():
                tf=(tfs.get(str(num)) or tfs.get(num)) if tfs else None
                # if whole message absent from tool, treat as message-missing not field-missing
                cat,tn,conf=classify(fr[1],tf)
                if cat in GENUINE:
                    cand.setdefault(strip_pref(mn),{})[int(num)]=(fr[0],fr[1],tn,conf,cat,tm is not None)
    # dedupe across ref files done by dict key; print
    tot=sum(len(v) for v in cand.values())
    print(f'\n========== {binkey}: {len(cand)} messages, {tot} GENUINE candidate fields ==========')
    for mn,fl in sorted(cand.items(),key=lambda kv:-len(kv[1])):
        present='' if list(fl.values())[0][5] else '  [TOOL HAS NO SUCH MESSAGE]'
        print(f'### {mn} ({len(fl)}){present}')
        for num in sorted(fl):
            name,rt,tn,conf,cat,_=fl[num]
            print(f'   #{num:>3} {name:<30} ref={rt:<26} tool={tn:<22} conf={conf} {cat}')
