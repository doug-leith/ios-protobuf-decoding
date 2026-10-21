"""Independent oracles for the extractor's layers, run over whole images rather than by example
(TODO #123, #124):

* :mod:`oracles.operands` -- ``proto.arm64_operands.reads()`` / ``writes()`` against capstone's own
  register-access lists;
* :mod:`oracles.method_names` -- the class-list parser's method names against the dyld cache's
  ``.symbols`` (``-[Class sel]`` at each IMP);
* :mod:`oracles.swift_mirror` -- the Swift field lists and types against Apple's Swift Remote Mirror
  (``libswiftRemoteMirror``, from a swift.org toolchain), served from a dyld cache.

Each module's ``compare`` returns what disagrees after the oracle's own known errors are allowed
for; ``tests/test_oracles.py`` asserts it is empty (a sample by default, every image with
``MACHO_TEST_ORACLE_FULL=1``), and ``python -m oracles.<module> ...`` prints a sweep."""
