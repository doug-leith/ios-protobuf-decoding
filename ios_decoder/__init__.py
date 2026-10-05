"""ios_decoder — decode captured iOS (Apple GeoServices / locationd / …) network
traffic into readable protobuf/text, without ``protoc`` at decode time.

A cleaner rewrite of ``addon_ios/ios_decoding_helpers.py``: the protobuf core
(:mod:`ios_decoder.protobuf`) and named-schema registry (:mod:`ios_decoder.schemas`)
are a plain, testable library; the live mitmproxy addon is a thin wrapper on top.
"""

from __future__ import annotations

__version__ = "1.0.0"   # keep in step with pyproject.toml [project].version

from .protobuf import DecodeError, decode_to_text
from .schemas import SchemaError, SchemaRegistry

__all__ = [
    "__version__",
    "decode_to_text",
    "DecodeError",
    "SchemaRegistry",
    "SchemaError",
]
