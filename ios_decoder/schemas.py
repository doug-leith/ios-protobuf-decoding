"""Named-schema registry: ``.proto`` files → loaded message classes, pure-Python decode.

``protoc`` is used **only as a one-time compiler** — each ``.proto`` is compiled to a
self-contained ``FileDescriptorSet`` (``--include_imports``) and cached on disk.  Runtime
decoding then goes through ``google.protobuf`` with no subprocess, so per-flow decoding
stays fast.

Each ``.proto`` gets its **own** :class:`DescriptorPool`.  The schema files were written
for separate ``protoc --decode=T file.proto`` invocations and freely reuse package/message
names across files; isolating pools avoids duplicate-symbol clashes that a single shared
pool would hit.

Cache freshness is checked against **every** file in the compiled set — the ``.proto`` and
all its imports — so editing an imported file invalidates the cache too (a plain
top-level-mtime check would silently keep decoding against the stale schema).
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Optional

from google.protobuf import descriptor_pb2, descriptor_pool, message_factory
from google.protobuf.message import Message

from .protobuf import parse, to_text, nested_unknown_field_count, unknown_field_numbers

__all__ = ["SchemaError", "SchemaRegistry"]


class SchemaError(Exception):
    """A ``.proto`` could not be compiled, or a message name was not found in it."""


class SchemaRegistry:
    """Resolves ``(proto_file, message_name)`` to a decoder, compiling lazily.

    Args:
        proto_dirs: directories searched (in order) for ``.proto`` files and used as
            ``protoc`` include paths.
        cache_dir: where compiled ``.pb`` descriptor sets are cached.  Defaults to
            ``<first proto_dir>/.descriptor_cache``.
        protoc: the ``protoc`` executable to invoke for compilation.
    """

    def __init__(
        self,
        proto_dirs,
        cache_dir: Optional[str | Path] = None,
        protoc: str = "protoc",
    ) -> None:
        self.proto_dirs = [Path(d) for d in proto_dirs]
        if not self.proto_dirs:
            raise ValueError("proto_dirs must not be empty")
        self.cache_dir = (
            Path(cache_dir)
            if cache_dir is not None
            else self.proto_dirs[0] / ".descriptor_cache"
        )
        self.protoc = protoc
        self._pools: dict[str, descriptor_pool.DescriptorPool] = {}
        self._classes: dict[tuple[str, str], type[Message]] = {}

    # -- locating + compiling --------------------------------------------------

    def _find(self, proto_file: str) -> Optional[Path]:
        """Resolve a (possibly import-relative) proto name to a path, or None."""
        for d in self.proto_dirs:
            cand = d / proto_file
            if cand.is_file():
                return cand
        return None

    def _resolve_proto(self, proto_file: str) -> Path:
        src = self._find(proto_file)
        if src is None:
            raise SchemaError(
                f"{proto_file!r} not found in {[str(d) for d in self.proto_dirs]}"
            )
        return src

    def _cache_is_fresh(self, cache_path: Path, proto_file: str) -> bool:
        """True if ``cache_path`` is newer than the proto *and all its imports*.

        The compiled set lists every dependency; if any of them can't be resolved or
        is newer than the cache, the cache is stale and must be rebuilt.
        """
        if not cache_path.is_file():
            return False
        cache_mtime = cache_path.stat().st_mtime
        try:
            fds = descriptor_pb2.FileDescriptorSet()
            fds.ParseFromString(cache_path.read_bytes())
        except Exception:
            return False  # unreadable cache => rebuild
        names = [f.name for f in fds.file] or [proto_file]
        for name in names:
            src = self._find(name)
            if src is None or src.stat().st_mtime > cache_mtime:
                return False
        return True

    def _descriptor_set_bytes(self, proto_file: str) -> bytes:
        """Compiled FileDescriptorSet for ``proto_file`` (from cache when fresh)."""
        self._resolve_proto(proto_file)  # raises SchemaError if the top-level is missing
        cache = self.cache_dir / (Path(proto_file).stem + ".pb")
        if self._cache_is_fresh(cache, proto_file):
            return cache.read_bytes()

        self.cache_dir.mkdir(parents=True, exist_ok=True)
        includes: list[str] = []
        for d in self.proto_dirs:
            includes += ["-I", str(d)]
        # Compile straight to the cache file (portable — no /dev/stdout).
        try:
            subprocess.run(
                [self.protoc, *includes, "--include_imports",
                 f"--descriptor_set_out={cache}", proto_file],
                check=True, capture_output=True,
            )
        except FileNotFoundError as e:
            raise SchemaError(f"protoc not found: {self.protoc!r}") from e
        except subprocess.CalledProcessError as e:
            raise SchemaError(
                f"protoc failed on {proto_file}:\n{e.stderr.decode(errors='replace')}"
            ) from e
        return cache.read_bytes()

    def _pool(self, proto_file: str) -> descriptor_pool.DescriptorPool:
        pool = self._pools.get(proto_file)
        if pool is None:
            fds = descriptor_pb2.FileDescriptorSet()
            fds.ParseFromString(self._descriptor_set_bytes(proto_file))
            pool = descriptor_pool.DescriptorPool()
            for f in fds.file:
                pool.Add(f)
            self._pools[proto_file] = pool
        return pool

    # -- public API ------------------------------------------------------------

    def message_class(self, proto_file: str, message_name: str) -> type[Message]:
        """The generated message class for ``message_name`` defined in ``proto_file``."""
        key = (proto_file, message_name)
        cls = self._classes.get(key)
        if cls is None:
            pool = self._pool(proto_file)
            try:
                desc = pool.FindMessageTypeByName(message_name)
            except KeyError as e:
                raise SchemaError(
                    f"message {message_name!r} not found in {proto_file}"
                ) from e
            cls = message_factory.GetMessageClass(desc)
            self._classes[key] = cls
        return cls

    def decode_with_coverage(
        self, proto_file: str, message_name: str, data: bytes, embedded=None
    ) -> tuple[str, list[int], int]:
        """Like :meth:`decode` but also report partial-schema coverage as
        ``(text, top_level_unknown_numbers, nested_unknown_count)`` — the by-number fields the
        schema didn't declare, both at the top level (numbers) and nested inside known
        sub-messages (count). Both empty/zero == the schema fully covered the body.

        ``embedded`` maps a ``bytes`` field's full name (``"geo.Msg.field"``) to the
        ``(proto_file, message_name)`` of the protobuf serialised inside it; those fields are
        decoded and rendered as nested messages (see :func:`protobuf.render_message`)."""
        msg = parse(data, self.message_class(proto_file, message_name))
        resolver = None
        if embedded:
            def resolver(field):
                target = embedded.get(field.full_name)
                return self.message_class(*target) if target else None
        return (to_text(msg, resolver), unknown_field_numbers(msg),
                nested_unknown_field_count(msg, resolver))
