"""Independent oracles for the extractor's layers, run over whole images rather than by example
(TODO #123-#128):

* :mod:`oracles.operands` -- ``proto.arm64_operands.reads()`` / ``writes()`` against capstone's own
  register-access lists;
* :mod:`oracles.method_names` -- the class-list parser's methods and ivars against the dyld
  cache's ``.symbols`` (``-[Class sel]`` at each IMP, ``_OBJC_IVAR_$_Class.ivar``);
* :mod:`oracles.swift_mirror` -- the Swift field lists and types against Apple's Swift Remote Mirror
  (``libswiftRemoteMirror``, from a swift.org toolchain), served from a dyld cache;
* :mod:`oracles.flow_emulation`, :mod:`oracles.callreads_emulation`, :mod:`oracles.writer_emulation`,
  :mod:`oracles.reader_emulation`, :mod:`oracles.enum_emulation` -- Flow, ``call_reads`` and the
  emitted ObjC messages and enums against concrete runs in Unicorn;
* :mod:`oracles.call_models` -- the call models (RUNTIME_CONTRACTS, CALL_CLOBBERS,
  RETURNS_ARGUMENT) against runs of the runtime functions themselves, from a dyld cache;
* :mod:`oracles.swift_types` -- an image's Swift nominal types, read for the oracles apart from
  the analysis's readers.

An oracle states what it needs of an ABI itself (the Swift and C calling conventions, the Swift
type records, a Visitor method's arguments from its demangled signature) rather than borrowing
the rule of the layer it checks; what it does share is checked by another oracle (the runtime
contracts, by :mod:`oracles.call_models`).

Each module's ``compare`` returns what disagrees after the oracle's own known errors are corrected
for; ``tests/test_oracles.py`` asserts it is empty (a sample by default, every image with
``MACHO_TEST_ORACLE_FULL=1``), and ``python -m oracles.<module> ...`` prints a sweep."""
