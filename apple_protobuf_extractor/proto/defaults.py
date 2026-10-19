"""
proto/defaults.py — Shared defaults for the proto extraction/emission pipeline.

This is the single canonical definition of the ObjC class-name prefix set.
Both :mod:`proto.extractor` and :mod:`proto.emitter` import from here so
that a change to the defaults only needs to be made in one place.
"""

#: Default ObjC class-name prefixes.
#:
#: These are the leading uppercase tokens that identify Apple framework proto
#: classes.  They serve two purposes:
#:
#: 1. **Name-stripping** — stripped when forming proto message names:
#:    ``GEOPDPlace`` → ``PDPlace``, ``CLPLocation`` → ``Location``.
#:
#: 2. **Package derivation** — lowercased to produce proto package names:
#:    ``GEO`` → package ``geo``, ``CLP`` → package ``clp``.
#:
#: Pass ``prefixes=`` to :func:`proto.extractor.extract_all` and to
#: :func:`proto.emitter.build_proto_files` (or just use the ``--prefix`` CLI flag,
#: which passes both) for other binaries.
DEFAULT_PREFIXES: tuple = ("GEO", "CLP", "CLM", "CLN")
