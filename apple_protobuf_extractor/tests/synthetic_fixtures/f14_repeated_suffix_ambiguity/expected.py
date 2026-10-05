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
fixture, so only Strategy 2 (name-suffix classlist matching) can resolve
either repeated field's element type. Confirmed by calling
_resolve_repeated_field_type directly before writing this file: `widgets`
returns via_name_suffix=True/type_class='TestSuffixWidget' (exactly one
class ends in "Widget"); `values` returns element_unresolved=True/
type_name='bytes' (TWO classes -- TestSuffixFooValue, TestSuffixBarValue --
end in "Value", so the uniqueness guard safely gives up rather than
guessing).
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
            {"name": "widgets", "number": 5, "type_name": "TestSuffixWidget",
             "label": "repeated", "number_confirmed": True,
             "type_class": "TestSuffixWidget"},
            {"name": "values", "number": 6, "type_name": "bytes",
             "label": "repeated", "number_confirmed": True,
             "type_class": None},
        ],
    },
}
