# One-off investigation scripts (archived)

These are standalone scripts written for specific, now-completed investigations.
They have **no importers** and are **not part of the test suite or packaging** —
they were moved here (2026-06-15) to declutter the top-level package directory
while preserving them in git history for reference.

Each was used once to land a feature/fix and is kept only as a worked example of
how that analysis was done. They are **not maintained** and may bit-rot as the
APIs they call evolve.

| Script | Investigation it supported |
|---|---|
| `probe_fieldlabel_60.py` | swift COW `_storage` / oneof field-label probe (#60). |
| `probe_methlist.py` | ObjC method-list layout probe. |
| `probe_dataconst.py` | `__DATA_CONST` cfstring/pointer-section probe. |
| `probe_readfrom_resolver.py` | Stage-0 probe for the readFrom CFG/dominator resolver (#42); the resolver shipped. |
| `census_dictrep_bias.py` | dictRep enum off-by-bias census (#54). |
| `census_enumname.py` | enum type-name reconstruction census (#57). |
| `census_protoframeworks.py` | proto-framework census across the cache (#49). |

## Running one

They import the package modules (`artifacts`, `proto.extractor`, …) assuming the
package directory is on `sys.path`, so run them with the package root on
`PYTHONPATH`:

```sh
cd apple_protobuf_extractor
PYTHONPATH=. ../venv/bin/python3 scripts/oneoff/<script>.py
```

The maintained oracles/tooling stay at the package top level: `gt_*.py`,
`validate_lever.py`, `snapshot_output.py`,
`heuristic_freq.py`, `heuristic_registry.py`, `census_repeated.py`,
`artifacts.py`.
