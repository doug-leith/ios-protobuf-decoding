"""proto.writer_flow write sites: every call of a ``writeTo:`` handed the writer, read off
WriterFlow's fixpoint -- the field number its w2 (w1 for a float / double writer) holds on
every path into it, where its value comes from, and the length-delimited marks open at it.

On every compiled fixture the sites must give what the writeTo: walk binds: each bound field's
number at its write call, and the ivar its value (or, for a begin / end-marked sub-message or
packed list, the values written inside the marks) comes from.
"""
import os
import unittest

from macho.classlist import build_class_list
from macho.memory import BinaryContext
from macho.strings import build_string_table
from proto.protocore import _INTERNAL_PB_IVARS, _is_proto_flags_ivar
from proto.write_helpers import _ensure_writeto_indegree
from proto.writer_flow import WriterFlow
import proto.writeto as W
from tests.test_synthetic_fixtures import _FIXTURES, _FIXTURES_DIR, load_macho_slice


def _ivars(origins):
    return {o[1] for o in origins if isinstance(o, tuple) and o[0] == 'I'}


def _bracket_ivars(sites, begin):
    inner = [s for s in sites if not s.is_mark
             and any(stk and stk[-1][1] == begin for stk in s.open_marks)]
    return set().union(*(_ivars(s.value_origins) for s in inner)) if inner else set()


class TestWriteSitesGiveTheWalksBindings(unittest.TestCase):

    def _check(self, fixture_dir, binary_name):
        path = os.path.join(_FIXTURES_DIR, fixture_dir, binary_name)
        if not os.path.exists(path):
            self.skipTest(f"{fixture_dir}: binary not built")
        with open(path, 'rb') as fh:
            ctx = BinaryContext(load_macho_slice(fh.read()))
        cl = build_class_list(ctx, build_string_table(ctx))
        _ensure_writeto_indegree(ctx, cl)
        wf = WriterFlow(ctx, cl)
        checked = 0
        for cls in cl:
            m = None if cls.is_meta else cls.get_method("writeTo:")
            if m is None or not m.imp:
                continue
            fivars = [iv for iv in cls.ivars if not _is_proto_flags_ivar(iv) and iv.name
                      and iv.name not in _INTERNAL_PB_IVARS]
            walk = W._walk_field_numbers(ctx, cls, fivars, ctx._writeto_indeg,
                                         ctx._writeto_foreign_imps)
            if not walk.numbers:
                continue
            sites = wf.write_sites(cls)
            self.assertIsNotNone(sites, f"{cls.name}: {wf.analyse(cls)[1]}")
            by_addr = {s.addr: s for s in sites}
            for ivar, w in walk.writes.items():
                s = by_addr.get(w['write_addr'])
                self.assertIsNotNone(s, f"{cls.name}.{ivar}: no site at {w['write_addr']:#x}")
                self.assertEqual(s.number, w['n'], f"{cls.name}.{ivar}")
                got = (_bracket_ivars(sites, s.addr) if w.get('bracket')
                       else _ivars(s.value_origins))
                self.assertEqual(got, {ivar}, f"{cls.name}.{ivar} at {s.addr:#x}")
                checked += 1
        return checked

    def test_every_fixture(self):
        total = 0
        for fixture_dir, binary_name in _FIXTURES:
            with self.subTest(fixture=f"{fixture_dir}/{binary_name}"):
                total += self._check(fixture_dir, binary_name)
        self.assertGreater(total, 50)


if __name__ == '__main__':
    unittest.main()
