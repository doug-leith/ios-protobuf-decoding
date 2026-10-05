import json, re
d=json.load(open('/tmp/valcmp.json'))
gt=d['geo_tool']; g1=d['refs']['geo1.proto']

def norm_type(t):
    if t is None: return None
    t=str(t)
    # strip ENUM: marker
    t=t.replace('ENUM:','')
    # strip repeated/optional words if present
    # normalize message names: drop leading GEO/PB/PD prefixes for loose compare
    base=t
    base=re.sub(r'^(GEO|PB|PD)+','',base)
    return base

SCALARS={'string','bytes','bool','double','float','int32','int64','uint32','uint64',
         'sint32','sint64','fixed32','fixed64','sfixed32','sfixed64'}

# index current tool by proto name -> (classname, fields dict)
cur_by_proto={}
for cls,rec in gt.items():
    pn=rec.get('proto') or cls
    cur_by_proto[pn]=(cls,rec['fields'])

dropped_msgs=[]      # in geo1, absent in current
dropped_fields=[]    # field# in geo1, absent in current msg
to_bytes=[]          # geo1 concrete -> current bytes
concrete_change=[]   # geo1 msgA -> current msgB (both non-bytes, differ)
scalar_change=[]     # geo1 scalarA -> current scalarB differ

for pn,fields in g1.items():
    if pn not in cur_by_proto:
        dropped_msgs.append(pn); continue
    cls,cfields=cur_by_proto[pn]
    for num,fr in fields.items():
        gname,gtype,glabel=fr[0],fr[1],fr[2] if len(fr)>2 else 'optional'
        if num not in cfields:
            dropped_fields.append((pn,num,gname,gtype)); continue
        cf=cfields[num]
        cname,craw,cres=cf[0],cf[1],cf[2]
        ctype=cres if cres else craw
        ng=norm_type(gtype); nc=norm_type(ctype)
        if ng==nc: continue
        g_is_scalar=(ng in SCALARS)
        c_is_scalar=(nc in SCALARS)
        if nc=='bytes' and ng!='bytes':
            to_bytes.append((pn,num,gname,gtype,ctype)); 
        elif (not g_is_scalar) and (not c_is_scalar):
            concrete_change.append((pn,num,gname,gtype,ctype))
        elif g_is_scalar and c_is_scalar:
            scalar_change.append((pn,num,gname,gtype,ctype))
        else:
            # scalar<->message mismatch
            concrete_change.append((pn,num,gname,gtype,ctype))

print("=== geo1 (old tool output) vs current tool — REGRESSION-ORIENTED diff ===")
print("geo1 messages:", len(g1), " current messages:", len(gt),
      " overlap:", sum(1 for p in g1 if p in cur_by_proto))
print()
print("DROPPED messages (in geo1, missing now):", len(dropped_msgs))
print("  ", dropped_msgs[:30])
print()
print("DROPPED fields (msg present, field# gone):", len(dropped_fields))
for r in dropped_fields[:30]: print("   ", r)
print()
print("DOWNGRADED to bytes (geo1 concrete -> current bytes):", len(to_bytes))
for r in to_bytes[:40]: print("   ", r)
print()
print("CONCRETE type CHANGED (msg/scalar mismatch):", len(concrete_change))
for r in concrete_change[:60]: print("   ", r)
print()
print("scalar type changed:", len(scalar_change))
for r in scalar_change[:30]: print("   ", r)
