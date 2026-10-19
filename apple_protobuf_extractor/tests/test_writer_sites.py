"""proto.writer_flow write sites and the bindings proto.writeto reads off them: every call of
a ``writeTo:`` handed the writer, read off WriterFlow's fixpoint -- the field number its w2
(w1 for a float / double writer) holds on every path into it, where its value comes from,
and the length-delimited marks open at it.

On every compiled fixture each binding must be the number the fixture's source was authored
with (its expected.py); the binder's rules are checked on hand-built sites.
"""
import os
import unittest
from types import SimpleNamespace

from macho.classlist import build_class_list
from macho.memory import BinaryContext
from macho.strings import build_string_table
from proto.protocore import _INTERNAL_PB_IVARS, _is_proto_flags_ivar, _proto_name
from proto.write_helpers import _ensure_writeto_prepass
from proto.writer_flow import WriteSite
import proto.writeto as W
from tests.test_synthetic_fixtures import (_FIXTURES, _FIXTURES_DIR, _extract, _load_expected,
                                           load_macho_slice)


class TestBindingsAreTheAuthoredNumbers(unittest.TestCase):

    def _check(self, fixture_dir, binary_name):
        path = os.path.join(_FIXTURES_DIR, fixture_dir, binary_name)
        if not os.path.exists(path):
            self.skipTest(f"{fixture_dir}: binary not built")
        with open(path, 'rb') as fh:
            ctx = BinaryContext(load_macho_slice(fh.read()))
        cl = build_class_list(ctx, build_string_table(ctx))
        _ensure_writeto_prepass(ctx, cl)
        expected = _load_expected(fixture_dir)
        message_of = {m.class_name: m.name for m in _extract(path).values()}
        checked = 0
        for cls in cl:
            if cls.is_meta or cls.get_method("writeTo:") is None:
                continue
            fivars = [iv for iv in cls.ivars if not _is_proto_flags_ivar(iv) and iv.name
                      and iv.name not in _INTERNAL_PB_IVARS]
            want = {f["name"]: f["number"]
                    for f in expected.get(message_of.get(cls.name), {}).get("fields", ())}
            for ivar, n in W._extract_writeto_field_numbers(ctx, cls, fivars).numbers.items():
                self.assertEqual(want.get(_proto_name(ivar)), n, f"{cls.name}.{ivar}")
                checked += 1
        return checked

    def test_every_fixture(self):
        total = 0
        for fixture_dir, binary_name in _FIXTURES:
            with self.subTest(fixture=f"{fixture_dir}/{binary_name}"):
                total += self._check(fixture_dir, binary_name)
        self.assertGreater(total, 50)


_W = frozenset({'W'})
_TOP = frozenset({()})


def _site(addr, n, ivars=(), *, name="_PBDataWriterWriteInt32Field", target=0x9000, slot=None,
          marks=_TOP, x2=None):
    """A writer-in-x0 call handed field number *n* in w2, its value from *ivars*."""
    val = frozenset(('I', iv) for iv in ivars)
    args = (('x0', _W),) + ((('x1', val),) if val else ())
    return WriteSite(addr, target, name, 'x0', None, n if x2 is None else x2, args, frozenset(),
                     slot, marks)


def _field_ivars(*names):
    return [SimpleNamespace(name=n, offset=8 * (i + 1)) for i, n in enumerate(names)]


class TestSiteBindings(unittest.TestCase):
    """proto.writeto._site_bindings: what the write sites bind, on hand-built sites."""

    def test_scalar_write_binds_its_ivar_number_and_helper(self):
        b = W._site_bindings([_site(0x10, 3, ['_a'])], _field_ivars('_a'))
        self.assertEqual(b.numbers, {'_a': 3})
        self.assertEqual(b.helpers, {'_a': 0x9000})
        self.assertEqual(b.writes['_a'], dict(n=3, write_addr=0x10, bracket=False,
                                              elem_helper_vas=[]))

    def test_value_from_two_ivars_binds_nothing(self):
        self.assertEqual(W._site_bindings([_site(0x10, 3, ['_a', '_b'])],
                                          _field_ivars('_a', '_b')).numbers, {})

    def test_the_first_call_binding_an_ivar_wins(self):
        b = W._site_bindings([_site(0x10, 1, ['_a']), _site(0x20, 4, ['_a'])], _field_ivars('_a'))
        self.assertEqual(b.numbers, {'_a': 1})

    def test_an_ivar_that_is_not_a_field_is_not_bound(self):
        self.assertEqual(W._site_bindings([_site(0x10, 1, ['_lock'])], _field_ivars('_a')).numbers, {})

    def test_packed_list_binds_the_begin_mark_and_its_element_writer(self):
        inside = frozenset({((0x40, 0x20),)})
        sites = [_site(0x20, 4, name="_PBDataWriterPlaceMark", slot=0x40),
                 _site(0x30, -1, ['_list'], target=0x9100, marks=inside),
                 _site(0x34, -1, ['_list'], target=0x9100, marks=inside),
                 _site(0x38, None, name="_PBDataWriterRecallMark", slot=0x40, marks=inside)]
        b = W._site_bindings(sites, _field_ivars('_list'))
        self.assertEqual(b.numbers, {'_list': 4})
        self.assertEqual(b.writes['_list']['bracket'], True)
        self.assertEqual(b.writes['_list']['elem_helper_vas'], [0x9100])

    def test_a_nested_mark_is_the_elements_own_field(self):
        # message Outer { Sub sub = 7; }  with Sub's packed field 2 written inline
        outer = frozenset({((0x40, 0x20),)})
        inner = frozenset({((0x40, 0x20), (0x50, 0x30))})
        sites = [_site(0x20, 7, name="_PBDataWriterPlaceMark", slot=0x40),
                 _site(0x24, 1, ['_sub'], marks=outer),
                 _site(0x30, 2, name="_PBDataWriterPlaceMark", slot=0x50, marks=outer),
                 _site(0x34, -1, ['_x'], target=0x9100, marks=inner)]
        b = W._site_bindings(sites, _field_ivars('_sub', '_x'))
        self.assertEqual(b.numbers, {'_sub': 7})
        self.assertEqual(b.writes['_sub']['elem_helper_vas'], [])

    def test_field_number_zero_is_a_zero_field_unless_also_bound(self):
        b = W._site_bindings([_site(0x10, 0, ['_k']), _site(0x20, 0, ['_a']),
                              _site(0x30, 2, ['_a'])], _field_ivars('_k', '_a'))
        self.assertEqual(b.zero_fields, {'_k'})
        self.assertEqual(b.numbers, {'_a': 2})


if __name__ == '__main__':
    unittest.main()
