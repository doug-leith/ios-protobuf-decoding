"""Ground truth for f2_readfrom_element_type/testrf — authored by hand across
testelement.m/testcontainer.m, not derived from any tool output.

    message TestContainer {
      repeated TestElement testElements = 5;
    }
    message TestElement {
      string value = 1;
    }

The field NUMBER (5) is recoverable from TestContainer's writeTo: alone (the
generic PBWriteMessageField helper carries no type information). The element
TYPE ("TestElement") can only come from disassembling TestContainer's
readFrom: dispatch core, which statically calls TestElement's own C-level
reader (TestElementReadFrom_core) — see testcontainer.m's header comment and
proto/repeated.py's _resolve_repeated_via_dispatch docstring. A tool that only
implemented writeTo:-based recovery would get the field number right but
could never name the element class.
"""

EXPECTED = {
    "TestContainer": {
        "fields": [
            {"name": "testElements", "number": 5, "type_name": "TestElement",
             "label": "repeated", "type_class": "TestElement",
             "number_confirmed": True},
        ],
    },
    "TestElement": {
        "fields": [
            {"name": "value", "number": 1, "type_name": "string",
             "label": "optional", "number_confirmed": True},
        ],
    },
}
