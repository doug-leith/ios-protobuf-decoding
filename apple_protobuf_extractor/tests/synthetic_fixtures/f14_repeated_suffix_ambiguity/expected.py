"""Ground truth for f14_repeated_suffix_ambiguity/testrsa — authored by
hand in fixture.m, not derived from any tool output.

    message TestSuffixWidget   { string value = 1; }
    message TestSuffixFooValue { string value = 1; }
    message TestSuffixBarValue { string value = 1; }

    message TestSuffixContainer {
      repeated TestSuffixWidget widgets = 5;   // unique "Widget" suffix
      repeated bytes values = 6;               // ambiguous "Value" suffix
    }

No readFrom: override and no +xyzType metaclass method anywhere in this
fixture, so the binary carries NO evidence of either repeated field's element
class -- only the field NAMES hint at it.  Until 2026-10-13 a name-suffix
matcher ("Strategy 2") resolved `widgets` (exactly one class ends in "Widget")
and gave up on `values` (TWO classes end in "Value").  That matcher is deleted:
it guessed wrong on real images (a repeated string became a message), so both
fields are now the honest `repeated bytes`.  The hand-authored truth above is
what the source says; the tool must not reconstruct it from names.
"""

EXPECTED = {
    "TestSuffixWidget": {
        "fields": [
            {"name": "value", "number": 1, "type_name": "string",
             "label": "optional", "number_confirmed": True},
        ],
    },
    "TestSuffixFooValue": {
        "fields": [
            {"name": "value", "number": 1, "type_name": "string",
             "label": "optional", "number_confirmed": True},
        ],
    },
    "TestSuffixBarValue": {
        "fields": [
            {"name": "value", "number": 1, "type_name": "string",
             "label": "optional", "number_confirmed": True},
        ],
    },
    "TestSuffixContainer": {
        "fields": [
            {"name": "widgets", "number": 5, "type_name": "bytes",
             "label": "repeated", "number_confirmed": True,
             "type_class": None},
            {"name": "values", "number": 6, "type_name": "bytes",
             "label": "repeated", "number_confirmed": True,
             "type_class": None},
        ],
    },
}
