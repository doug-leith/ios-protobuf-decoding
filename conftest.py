"""
conftest.py — repo-root pytest configuration.

Puts the repo root on sys.path so `import ios_decoder` and the root-level extractor
helpers resolve when pytest is run from the repo root.
"""
import os
import sys

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)


@pytest.hookimpl(tryfirst=True)          # before xdist's, which reads the groups
def pytest_collection_modifyitems(config, items):
    """Under pytest-xdist's ``--dist loadgroup``, a test class's tests run on one worker, so its
    ``setUpClass`` (often a whole-image extraction) runs once: each class without an
    ``xdist_group`` of its own is a group.  Without xdist the mark is inert."""
    for item in items:
        if item.cls is not None and item.get_closest_marker('xdist_group') is None:
            item.add_marker(pytest.mark.xdist_group(item.nodeid.rsplit('::', 1)[0]))
