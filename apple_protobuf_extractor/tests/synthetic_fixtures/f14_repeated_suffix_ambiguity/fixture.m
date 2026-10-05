#import "pbshim.h"

// Ground truth (see expected.py). This fixture covers proto/repeated.py's
// Strategy-2 name-suffix matcher (_repeated_element_type's second tier) and
// its uniqueness guard — pure classlist name-matching, no disassembly
// involved at all.
//
// CORRECTION (checked with --branch coverage before finalising this
// fixture, since line coverage for repeated.py did not move at all after
// adding it): the len(matches)==1 SUCCESS line was already incidentally
// covered before this fixture existed — f2_readfrom_element_type's own
// TestElement/_testElements happens to suffix-match unintentionally (it
// isolates the readFrom: dispatch path, not Strategy 2, but Strategy 2
// still runs as an unconditional pre-computation regardless of which path
// ultimately wins — see _resolve_repeated_element_type's precedence logic).
// So the claim here is narrower than "zero prior coverage": this is the
// first fixture that specifically targets Strategy 2 IN ISOLATION (no
// dispatch/metaclass path can override its answer) with the outcome
// independently verified, and the first covering the genuinely-ambiguous
// (2+ matches) case at all — every prior repeated-field fixture either had
// a unique suffix or went through a different resolver entirely.
//
// Real, measured usage (see _repeated_element_type's own docstring/comment):
// Strategy 2 is the SOLE resolver for ~40 real GeoServices message fields
// that neither the readFrom: dispatch walk nor the metaclass +xyzType
// method (Strategy 1, covered by f12) can reach — but it is a NAME-BASED
// GUESS, so it only fires when the suffix match is UNIQUE across the whole
// classlist; two-or-more classes sharing a suffix (e.g. real "Value",
// "Result", "Info") make it safely give up to `bytes` instead of guessing
// wrong.
//
//   message TestSuffixWidget { string value = 1; }
//   message TestSuffixFooValue { string value = 1; }
//   message TestSuffixBarValue { string value = 1; }
//
//   message TestSuffixContainer {
//     repeated TestSuffixWidget widgets = 5;    // UNIQUE "Widget" suffix -> resolved
//     repeated bytes values = 6;                // AMBIGUOUS "Value" suffix (2 classes
//                                                // share it) -> safe "bytes" fallback
//   }
//
// TestSuffixContainer deliberately has NO readFrom: override and NO
// +xyzType metaclass method on any class here, so neither the dispatch
// resolver (f2/f5/f8) nor Strategy 1 (f12) can contribute an answer for
// EITHER field — this isolates Strategy 2 (and its uniqueness guard)
// unambiguously, the same way f12 isolated Strategy 1 by omitting
// readFrom:. writeTo:'s CFG walk still confirms both field NUMBERS
// independently (see f2's docstring: writeTo: gives the number, never the
// element TYPE).
//
// Verified by calling _resolve_repeated_field_type directly before writing
// this file (not inferred from the source alone): `widgets` resolves with
// via_name_suffix=True, type_class='TestSuffixWidget'; `values` resolves
// with element_unresolved=True, type_name='bytes', type_class=None.

@interface TestSuffixWidget : PBCodable {
  @public
    NSString *_value;
    struct { unsigned has_value:1; } _has;
}
@end

@implementation TestSuffixWidget

- (void)writeTo:(PBDataWriter *)writer {
    if (_has.has_value) PBWriteStringField(writer, _value, 1);
    [super writeTo:writer];
}

@end

@interface TestSuffixFooValue : PBCodable {
  @public
    NSString *_value;
    struct { unsigned has_value:1; } _has;
}
@end

@implementation TestSuffixFooValue

- (void)writeTo:(PBDataWriter *)writer {
    if (_has.has_value) PBWriteStringField(writer, _value, 1);
    [super writeTo:writer];
}

@end

@interface TestSuffixBarValue : PBCodable {
  @public
    NSString *_value;
    struct { unsigned has_value:1; } _has;
}
@end

@implementation TestSuffixBarValue

- (void)writeTo:(PBDataWriter *)writer {
    if (_has.has_value) PBWriteStringField(writer, _value, 1);
    [super writeTo:writer];
}

@end

@interface TestSuffixContainer : PBCodable {
  @public
    NSMutableArray *_widgets;
    NSMutableArray *_values;
}
@end

@implementation TestSuffixContainer

- (void)writeTo:(PBDataWriter *)writer {
    for (id e in _widgets) { PBWriteMessageField(writer, e, 5); }
    for (id e in _values)  { PBWriteMessageField(writer, e, 6); }
    [super writeTo:writer];
}

@end

int main(void) { return 0; }
