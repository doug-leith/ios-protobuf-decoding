"""A proto class with no ``writeTo:`` of its own is serialised by an ancestor's ``writeTo:``,
which cannot reach the class's own ivars: they are not wire fields.

Before this, every such ivar was emitted with an ivar-order "number estimated" field number,
and those numbers collided with the parent's real fields (GEOAnalyticsPipelineSharedStateData
1-19 on GEOAnalyticsPipelineStateData's 1-19, GEOComposedWaypointEVStop 1-6 on
GEOComposedWaypoint's 1-5; whole-image IDA cross-check 2026-10-15).
"""
import unittest
from unittest import mock

from macho.classlist import ClassList, ObjcClass, ObjcIvar, ObjcMethod
import proto.extractor as E
from proto.emitter import ProtoFile
from proto.models import ProtoMessage


def _cls(va, name, super_va, super_name, methods=(), ivars=()):
    return ObjcClass(vmaddr=va, name=name, is_meta=False, superclass_vmaddr=super_va,
                     superclass_name=super_name, ro_flags=0, instance_size=0x40,
                     methods=[ObjcMethod(n, "v@:", imp) for n, imp in methods],
                     ivars=list(ivars))


def _family(child_methods=(("name", 0x3000),), mid=None):
    """PBCodable-style parent with writeTo:, optional intermediate class, child without."""
    parent = _cls(0x100, "GEOParent", 0, None, [("writeTo:", 0x1000), ("readFrom:", 0x1100)])
    classes = [parent]
    sup_va, sup_name = 0x100, "GEOParent"
    if mid is not None:
        classes.append(_cls(0x180, "GEOMid", 0x100, "GEOParent", mid))
        sup_va, sup_name = 0x180, "GEOMid"
    child = _cls(0x200, "GEOChild", sup_va, sup_name, child_methods,
                 [ObjcIvar("_name", '@"NSString"', 0x40, 8)])
    classes.append(child)
    return ClassList(classes), child, parent


class TestInheritedWriteToOwner(unittest.TestCase):
    def _owner(self, cl, cls, sent=frozenset({"readAll:"})):
        with mock.patch.object(E, "writeto_sent_selectors", return_value=sent) as m:
            return E._inherited_writeto_owner(None, cl, cls), m

    def test_child_without_writeto_is_serialised_by_parent(self):
        cl, child, parent = _family()
        owner, m = self._owner(cl, child)
        self.assertIs(owner, parent)
        m.assert_called_once_with(None, parent)   # the PARENT's writeTo: is examined

    def test_class_with_its_own_writeto_is_not_affected(self):
        cl, _child, parent = _family()
        self.assertIsNone(self._owner(cl, parent)[0])

    def test_unresolved_method_name_cannot_tell(self):
        # An unresolved selector could be writeTo: itself.
        cl, child, _ = _family(child_methods=(("name", 0x3000), (None, 0x3100)))
        self.assertIsNone(self._owner(cl, child)[0])

    def test_unresolved_name_on_intermediate_class_cannot_tell(self):
        cl, child, _ = _family(mid=((None, 0x2800),))
        self.assertIsNone(self._owner(cl, child)[0])

    def test_ancestor_outside_the_image_cannot_tell(self):
        child = _cls(0x200, "GEOChild", 0x999, "PBCodable", [("name", 0x3000)])
        self.assertIsNone(self._owner(ClassList([child]), child)[0])

    def test_inherited_writeto_sending_an_overridden_selector_cannot_tell(self):
        # The parent's writeTo: sends -name, which the child implements: the child's
        # code runs inside the inherited serialiser, so its ivars could reach the wire.
        cl, child, _ = _family()
        self.assertIsNone(self._owner(cl, child, frozenset({"readAll:", "name"}))[0])

    def test_selector_implemented_by_intermediate_class_counts_too(self):
        cl, child, _ = _family(mid=(("isEqual:", 0x2800),))
        self.assertIsNone(self._owner(cl, child, frozenset({"isEqual:"}))[0])

    def test_unexamined_inherited_writeto_cannot_tell(self):
        cl, child, _ = _family()
        self.assertIsNone(self._owner(cl, child, None)[0])

    def test_own_readfrom_cannot_tell(self):
        # A message the client only reads is defined by its readFrom:, not by the inherited
        # writeTo:; a class that overrides readFrom: may read fields its parent never writes.
        cl, child, _ = _family(child_methods=(("name", 0x3000), ("readFrom:", 0x3100)))
        self.assertIsNone(self._owner(cl, child)[0])

    def test_readfrom_on_intermediate_class_cannot_tell(self):
        cl, child, _ = _family(mid=(("readFrom:", 0x2800),))
        self.assertIsNone(self._owner(cl, child)[0])

    def test_superclass_cycle_terminates(self):
        a = _cls(0x100, "GEOA", 0x200, "GEOB", [("name", 0x3000)])
        b = _cls(0x200, "GEOB", 0x100, "GEOA", [("other", 0x3100)])
        self.assertIsNone(self._owner(ClassList([a, b]), a)[0])


class TestSerialisedByEmission(unittest.TestCase):
    def _render(self, msg):
        pf = ProtoFile(package="test", filename="test.proto", messages=[], imports=[])
        return "\n".join(pf._emit_message(msg, {}))

    def test_comment_replaces_no_fields_recovered(self):
        out = self._render(ProtoMessage(name="Child", class_name="GEOChild",
                                        inherits_from="Parent", serialised_by="Parent"))
        self.assertIn("// inherits all fields from Parent", out)
        self.assertIn("no writeTo: of its own: serialised by Parent's writeTo:", out)
        self.assertNotIn("(no fields recovered)", out)

    def test_other_field_less_message_unchanged(self):
        out = self._render(ProtoMessage(name="M", class_name="GEOM"))
        self.assertIn("// (no fields recovered)", out)
        self.assertNotIn("no writeTo: of its own", out)


try:
    import live_artifacts as _V
    _LOADED = _V.load_cache("GeoServices")
except Exception:
    _LOADED = None


@unittest.skipUnless(_LOADED is not None, "GeoServices cache not available")
class TestInheritedWriteToLive(unittest.TestCase):
    """The four GeoServices subclasses with no writeTo: of their own."""
    EXPECTED = {
        "GEOAnalyticsPipelineSharedStateData": "AnalyticsPipelineStateData",
        "GEOComposedWaypointEVStop": "ComposedWaypoint",
        "GEOSearchRequest": "PlaceSearchRequest",
        "GEOSearchResponse": "PlaceSearchResponse",
    }

    @classmethod
    def setUpClass(cls):
        cls.ctx, cls.st, cls.cl = _LOADED

    def test_subclasses_have_no_fields_and_name_the_serialiser(self):
        for name, parent in self.EXPECTED.items():
            m = E.extract_proto_message(self.ctx, self.st, self.cl, self.cl.find(name))
            self.assertIsNotNone(m, name)
            self.assertEqual(m.fields, [], name)
            self.assertEqual(m.serialised_by, parent, name)
            self.assertEqual(m.inherits_from, parent, name)

    def test_class_with_own_writeto_keeps_its_fields(self):
        m = E.extract_proto_message(self.ctx, self.st, self.cl,
                                    self.cl.find("GEOComposedWaypoint"))
        self.assertIsNone(m.serialised_by)
        self.assertEqual(sorted(f.number for f in m.fields), [1, 2, 3, 4, 5])

    def test_inherited_writeto_sends_none_of_the_subclass_selectors(self):
        from proto.writeto import writeto_sent_selectors
        from proto.write_helpers import _ensure_writeto_prepass
        _ensure_writeto_prepass(self.ctx, self.cl)          # the image's writer flow
        parent = self.cl.find("GEOComposedWaypoint")
        sent = writeto_sent_selectors(self.ctx, parent)
        self.assertIsNotNone(sent)
        self.assertIn("readAll:", sent)             # [self readAll:NO] in the prologue
        child = {m.name for m in self.cl.find("GEOComposedWaypointEVStop").methods}
        self.assertFalse(sent & child)


if __name__ == "__main__":
    unittest.main()
