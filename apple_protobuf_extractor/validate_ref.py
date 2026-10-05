"""Validate tool output against the hand-decoded GEOPDPlaceResponse.proto reference.

Compares, per message, field NUMBER -> (type token, repeated?) and separately the
five enums' value maps.  Operates at the extractor level (raw ObjC class names),
since the reference field types use ObjC-ish names (GEOPDPlace, GEOComponentType).
"""
import os, re, sys
from macho.dyld_cache import DyldCacheReader
from macho.memory import BinaryContext
from macho.strings import build_string_table
from macho import classlist as CL
from macho.local_symbols import apply_to_classes
from proto.extractor import extract_proto_message
from proto.write_helpers import _identify_string_write_helpers
from proto.dispatch  import _build_readfrom_core_index

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # repo root
REF = os.path.join(_REPO, "iphone8_reference_protos", "GEOPDPlaceResponse.proto")
SCALARS = {'bytes','string','bool','double','float','int32','int64','uint32',
           'uint64','sint32','sint64','fixed32','fixed64','sfixed32','sfixed64'}

# ── Parse reference ────────────────────────────────────────────────────────────
text = open(REF).read()
# strip /* */ block comments and // line comments for the parse
def strip_comments(s):
    s = re.sub(r'/\*.*?\*/', '', s, flags=re.S)
    out = []
    for ln in s.splitlines():
        out.append(re.sub(r'//.*$', '', ln))
    return "\n".join(out)
clean = strip_comments(text)

ref_msgs = {}   # name -> {num: (type, repeated)}
ref_enums = {}  # name -> {value: symbol}

# messages
for m in re.finditer(r'message\s+(\w+)\s*\{(.*?)\}', clean, flags=re.S):
    name, body = m.group(1), m.group(2)
    fields = {}
    for fm in re.finditer(r'(?:(repeated|optional)\s+)?(\w+)\s+(\w+)\s*=\s*(\d+)\s*;',
                          body):
        rep, typ, fname, num = fm.group(1), fm.group(2), fm.group(3), int(fm.group(4))
        fields[num] = (typ, rep == 'repeated', fname)
    ref_msgs[name] = fields

for m in re.finditer(r'enum\s+(\w+)\s*\{(.*?)\}', clean, flags=re.S):
    name, body = m.group(1), m.group(2)
    vals = {}
    for fm in re.finditer(r'(\w+)\s*=\s*(\d+)\s*;', body):
        vals[int(fm.group(2))] = fm.group(1)
    ref_enums[name] = vals

# ── Build tool output ──────────────────────────────────────────────────────────
import artifacts
reader = DyldCacheReader(artifacts.cache_file())
mach_va = reader.find_image_header('GeoServices')
ctx = BinaryContext.from_cache(reader, mach_va)
st = build_string_table(ctx)
cl = CL.build_class_list(ctx, st)
apply_to_classes(cl, reader.image_local_symbols(mach_va))

# Binary-wide pre-passes (mirror extract_all) so per-message extraction reflects
# the real pipeline — in particular the readFrom: dispatch element-type resolver.
_str_helpers = frozenset(_identify_string_write_helpers(ctx, cl))
_core_index  = _build_readfrom_core_index(ctx, cl)

# Messages to validate: those whose name is a real ObjC class.  A few reference
# messages use a logical name != ObjC class — map them.
NAME_MAP = {
    'GEOPDBoundingBox': 'GEOPDBounds',  # reference notes class is GEOPDBounds
}

def tool_fields(cls_name):
    c = cl.find(cls_name)
    if not c:
        return None
    msg = extract_proto_message(ctx, st, cl, c,
                                string_write_helpers=_str_helpers,
                                readfrom_core_index=_core_index)
    d = {}
    for f in msg.fields:
        rep = str(getattr(f, 'label', '')).endswith('REPEATED')
        d[f.number] = (f.type_name, rep, f.name)
    return d

def base(t):
    # normalise a type token for comparison: scalar stays; message/enum compared
    # loosely (the tool may keep GEOPD prefix; reference uses same).
    return t

print("=" * 78)
print("MESSAGE FIELD VALIDATION  (number -> type, repeated)")
print("=" * 78)
focus = ['GEOPDPlaceResponse','GEOPDMapsResult','GEOPDPlaceGlobalResult',
         'GEOPDPlace','GEOPDComponent','GEOPDComponentValue','GEOPDDatasetABStatus',
         'GEOPDEntity','GEOPDLocalizedName','GEOPDPlaceInfoValue','GEOPDStructuredAddress',
         'GEOPDAddressLines','GEOPDGroundViewLabel','GEOPDGroundViewLabelContent',
         'GEOPDBoundingBox','GEOBoundingBoxEntry','GEOPDSource',
         'GEOPDPlaceGlobalCommonResult','GEOPDReverseGeocodingResult']

summary = []
for ref_name in focus:
    if ref_name not in ref_msgs:
        continue
    objc = NAME_MAP.get(ref_name, ref_name)
    tf = tool_fields(objc)
    rf = ref_msgs[ref_name]
    if tf is None:
        print(f"\n## {ref_name}: CLASS NOT FOUND in tool ({objc})")
        summary.append((ref_name, 'MISSING', 0, 0, len(rf)))
        continue
    match = num_only = typ_mismatch = missing = extra = 0
    lines = []
    for num, (rtyp, rrep, rname) in sorted(rf.items()):
        if num not in tf:
            missing += 1
            lines.append(f"   ✗ #{num:<4} ref={rtyp:<28} {rname:<22} → TOOL MISSING")
            continue
        ttyp, trep, tname = tf[num]
        # compare type category
        rscalar = rtyp in SCALARS
        tscalar = ttyp in SCALARS
        # type identity check (loose: message token equality, scalar equality)
        ok_type = (ttyp == rtyp)
        ok_rep = (trep == rrep)
        if ok_type and ok_rep:
            match += 1
        else:
            # categorise
            tag = []
            if not ok_type: tag.append(f"type {ttyp}≠{rtyp}")
            if not ok_rep:  tag.append(f"rep {trep}≠{rrep}")
            typ_mismatch += 1
            lines.append(f"   ~ #{num:<4} ref={rtyp:<20}{'[rep]' if rrep else '     '} "
                         f"tool={ttyp:<20}{'[rep]' if trep else '     '}  ({'; '.join(tag)})")
    extra = sum(1 for n in tf if n not in rf)
    print(f"\n## {ref_name}  (class {objc}): {match}/{len(rf)} exact match, "
          f"{typ_mismatch} differ, {missing} missing, {extra} extra-in-tool")
    for ln in lines:
        print(ln)
    summary.append((ref_name, 'OK', match, typ_mismatch+missing, len(rf)))

# ── Enum validation ─────────────────────────────────────────────────────────────
print("\n" + "=" * 78)
print("ENUM VALUE VALIDATION  (compare value->presence; names differ by convention)")
print("=" * 78)
# Build tool enums: gather all enums from the messages that reference them.
# Easiest: extract the owning class and read its enum field's resolved enum.
# We compare the value sets recovered by the tool for the key enums.
from proto.extractor import extract_all
# Reuse already-built cl; extract everything once to get enums.
msgs = extract_all(ctx, st, cl)
tool_enums = {}   # enum_name -> {value: symbol}
for m in msgs:
    for e in getattr(m, 'enums', []) or []:
        d = {v.number: v.name for v in e.values}
        tool_enums.setdefault(e.name, {}).update(d)
# also some emitters attach enums at file level; try a global registry
print("tool enum names sample:", sorted(tool_enums.keys())[:20], "...total", len(tool_enums))

def find_tool_enum(values_needed):
    # find a tool enum whose value set best matches the reference values
    best = (None, -1)
    for en, vals in tool_enums.items():
        common = len(set(values_needed) & set(vals))
        if common > best[1]:
            best = (en, common)
    return best

for ren, rvals in ref_enums.items():
    en, common = find_tool_enum(rvals.keys())
    tvals = tool_enums.get(en, {})
    only_ref = sorted(set(rvals) - set(tvals))
    only_tool = sorted(set(tvals) - set(rvals))
    print(f"\n## {ren}: ref has {len(rvals)} values; best tool match = {en} "
          f"({common}/{len(rvals)} values present)")
    if only_ref:
        print("   values in ref but NOT tool:", only_ref)
    if only_tool:
        print("   values in tool but NOT ref:", only_tool[:20])

reader.close()
