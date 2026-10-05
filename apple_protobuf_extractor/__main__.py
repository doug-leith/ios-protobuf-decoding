"""
Entry point for ``python3 -m apple_protobuf_extractor``.

Run from the repo root:

    python3 -m apple_protobuf_extractor GeoServices -o ./protos/
"""
import sys
from cli import main

sys.exit(main())
