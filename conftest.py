"""
conftest.py — repo-root pytest configuration.

Puts the repo root on sys.path so `import ios_decoder` and the root-level extractor
helpers resolve when pytest is run from the repo root.
"""
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
