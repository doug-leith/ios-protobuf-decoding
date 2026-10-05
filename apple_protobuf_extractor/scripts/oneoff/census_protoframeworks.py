"""Census: which cache images contain protobuf (PBCodable) message classes.

Iterates every image in the dyld shared cache, builds its class list, and counts
proto message classes via the production detector (`_proto_class_set`).  Writes a
JSON list of {path, n_proto, n_classes} for images with >=1 proto class, sorted
by proto count.  Reusable artifact for the portability test.

Run:
    ../venv/bin/python3 census_protoframeworks.py <cache_path> <out.json> [limit]
"""
import json
import sys
import time

from macho.dyld_cache import DyldCacheReader
from macho.memory import BinaryContext
from macho.strings import build_string_table
from macho import classlist as CL
from macho.local_symbols import apply_to_classes
import proto.extractor as E


def main():
    cache_path = sys.argv[1]
    out_path = sys.argv[2]
    limit = int(sys.argv[3]) if len(sys.argv) > 3 else None
    start_idx = int(sys.argv[4]) if len(sys.argv) > 4 else 0

    reader = DyldCacheReader(cache_path)
    images = reader.list_images()          # [(addr, path)]
    if limit is not None:
        images = images[start_idx:start_idx + limit]
    results = []
    t0 = time.time()
    for i, (addr, path) in enumerate(images):
        try:
            mv = reader.find_image_header(path)
            if mv is None:
                continue
            ctx = BinaryContext.from_cache(reader, mv)
            st = build_string_table(ctx)
            cl = CL.build_class_list(ctx, st)
            syms = reader.image_local_symbols(mv)
            if syms:
                apply_to_classes(cl, syms)
            proto = E._proto_class_set(ctx, cl)
            n_classes = sum(1 for c in cl if not c.is_meta)
            if proto:
                results.append({"path": path, "n_proto": len(proto),
                                "n_classes": n_classes})
        except Exception as e:
            sys.stderr.write(f"[ERR] {path}: {type(e).__name__}: {e}\n")
            continue
        if (i + 1) % 100 == 0:
            el = time.time() - t0
            sys.stderr.write(f"  {i+1}/{len(images)} images, "
                             f"{len(results)} with proto, {el:.0f}s\n")
    results.sort(key=lambda r: -r["n_proto"])
    with open(out_path, "w") as fh:
        json.dump(results, fh, indent=1)
    sys.stderr.write(f"DONE: {len(results)} proto images / {len(images)} "
                     f"in {time.time()-t0:.0f}s -> {out_path}\n")


if __name__ == "__main__":
    main()
