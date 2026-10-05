import re, glob, os, sys, json
sys.path.insert(0,'.')
_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # repo root (iphone8_reference_protos/ lives there)
def strip_pref(n):
    for p in ('GEO','CLP','CLM','CLN'):
        if n.startswith(p): return n[len(p):]
    return n
def parse_proto(path):
    txt=open(path,errors='ignore').read()
    txt=re.sub(r'/\*.*?\*/','',txt,flags=re.S); txt=re.sub(r'//[^\n]*','',txt)
    M={}; stk=[]; sc=[]
    fre=re.compile(r'^(?:(optional|required|repeated)\s+)?(map<[^>]+>|[\w.]+)\s+(\w+)\s*=\s*(\d+)\b')
    ore=re.compile(r'^(message|enum|oneof)\s+(\w+)')
    for raw in txt.split('\n'):
        line=raw.strip()
        if not line: continue
        om=ore.match(line)
        if om and '{' in line:
            k,nm=om.group(1),om.group(2); sc.append((k,nm))
            if k=='message': stk.append(nm); M.setdefault(''.join(stk),{})
            continue
        if line.startswith('}'):
            if sc:
                k,_=sc.pop()
                if k=='message' and stk: stk.pop()
            continue
        if sc and sc[-1][0] in ('message','oneof') and stk:
            fm=fre.match(line)
            if fm: M[''.join(stk)][int(fm.group(4))]=(fm.group(3),fm.group(2),fm.group(1) or 'optional')
    return M
# refs per file
refs={}  # file -> {msg:{num:[name,type,label]}}
for f in sorted(glob.glob(os.path.join(_REPO, 'iphone8_reference_protos', '*.proto'))):
    refs[os.path.basename(f)]=parse_proto(f)
# tool dump
import proto.extractor as E, validate_lever as V
def tool_dump(loader):
    out={}
    for m in E.extract_all(*loader()):
        d={}
        for x in m.fields:
            d[x.number]=[x.name,x.type_name,x.type_class,str(x.label).split('.')[-1].lower(),bool(x.number_confirmed)]
        out[m.class_name]={'proto':m.name,'fields':d}
    return out
dump={'refs':refs,
      'geo_tool':tool_dump(lambda:V._load_cache('GeoServices')),
      'clp_tool':tool_dump(lambda:V._load_cache('CoreLocationProtobuf'))}
json.dump(dump,open('/tmp/valcmp.json','w'))
print("dumped:", len(refs),"ref files,", len(dump['geo_tool']),"geo tool msgs,", len(dump['clp_tool']),"clp tool msgs")
