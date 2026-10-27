"""
tests/test_live_locationd.py
============================
Live **pure binary-only** (path ii) tests against the standalone ``locationd``
executable — a normal arm64 Mach-O whose ``__objc_methname`` holds real selector
strings, so extraction works with NO dyld shared cache.

This complements the GeoServices live tests (which are cache-native, path i) and
the synthetic mini-binary tests: locationd is a *real* framework-scale binary
exercised end-to-end through ``build_class_list`` (binary-only) + ``extract_all``.

All field-number anchors are verified against Hopper's disassembly of the
``-[Class writeTo:]`` methods (see inline notes).  In particular
``ALSLocation.infoMask = 13`` and ``ALSCellTower.psc = 12`` are the **last**
field of their message, serialised via a tail-call ``b`` to the PB write helper
with the epilogue hoisted in between — the case fixed in
``_extract_writeto_field_numbers`` / ``proto.writer_flow.WriteSite.number``.  They must
be binary-confirmed (not next_unconfirmed filler).

Gated on the binary's presence: set the ``MACHO_TEST_LOCATIOND`` env var (see
``artifacts.py``), or place ``locationd`` under the data dir (default
``<repo>/iphone8_data/locationd``).
"""

import os
import artifacts
import struct
import unittest


def _find_binary() -> str:
    from_env = os.environ.get('MACHO_TEST_LOCATIOND', '').strip()
    if from_env:
        return from_env
    return artifacts.locationd_path()


BINARY      = _find_binary()
HAS_BINARY  = os.path.isfile(BINARY)
SKIP_MSG    = ('locationd binary not found — place it at <repo>/iphone8_data/locationd '
               'or set MACHO_TEST_LOCATIOND=PATH')

# Build the constants below were verified against (informational; the field-number
# assertions are proto-schema facts and should hold across close builds).
EXPECTED_UUID = '3DE54D44-C608-319E-9B01-0CA5A1ABD4A4'


@unittest.skipUnless(HAS_BINARY, SKIP_MSG)
class TestLocationdBinaryOnly(unittest.TestCase):
    """End-to-end binary-only extraction (no cache)."""

    @classmethod
    def setUpClass(cls):
        from macho.memory import BinaryContext
        from macho.strings import build_string_table
        from macho import classlist as CL
        from proto.extractor import extract_all

        with open(BINARY, 'rb') as fh:
            data = fh.read()
        cls.ctx = BinaryContext(data)                 # standalone binary, NO cache
        cls.st  = build_string_table(cls.ctx)
        cls.cl  = CL.build_class_list(cls.ctx, cls.st)  # pure binary-only (no cache)
        cls.msgs = {m.class_name: m for m in extract_all(cls.ctx, cls.st, cls.cl)}

    def _fields(self, class_name):
        msg = self.msgs.get(class_name)
        self.assertIsNotNone(msg, f'{class_name} must be extracted')
        return {f.name: f for f in msg.fields}

    # ── Structural ────────────────────────────────────────────────────────────

    def test_pure_binary_only_extraction(self):
        # No cache was supplied; a substantial set of proto messages is recovered
        # purely from the binary's own selector strings.
        self.assertGreaterEqual(len(self.msgs), 60)
        self.assertIn('ALSLocation', self.msgs)
        self.assertIn('ALSCellTower', self.msgs)

    def test_no_unresolved_type_refs(self):
        # Every message-typed field resolves to an extracted message.
        for m in self.msgs.values():
            for f in m.fields:
                self.assertIsNone(
                    getattr(f, 'unresolved_type_class', None),
                    f'{m.class_name}.{f.name} should not be unresolved')

    def test_high_confirmed_ratio(self):
        # With the tail-call writeTo: fix, ~99% of field numbers are binary
        # confirmed (was ~89% before — the last field of many messages is a
        # tail-call write that used to fall to filler).
        total = sum(len(m.fields) for m in self.msgs.values())
        conf  = sum(1 for m in self.msgs.values()
                    for f in m.fields if f.number_confirmed)
        self.assertGreater(total, 0)
        self.assertGreaterEqual(conf / total, 0.95,
                                f'{conf}/{total} confirmed')

    # ── Field-number anchors (Hopper-verified) ────────────────────────────────

    def test_alslocation_field_numbers(self):
        # -[ALSLocation writeTo:] @ 0x100aa5c14
        f = self._fields('ALSLocation')
        expected = {
            'latitude': (1, 'int64'),  'longitude': (2, 'int64'),
            'accuracy': (3, 'int32'),  'locationType': (4, 'int32'),
            'altitude': (5, 'int32'),  'verticalAccuracy': (6, 'int32'),
            'confidence': (7, 'int32'),'score': (11, 'uint32'),
            'reach': (12, 'int32'),    'infoMask': (13, 'uint32'),
        }
        for name, (num, typ) in expected.items():
            self.assertIn(name, f, f'ALSLocation.{name} missing')
            self.assertEqual(f[name].number, num, f'ALSLocation.{name} number')
            self.assertEqual(f[name].type_name, typ, f'ALSLocation.{name} type')

    def test_alscelltower_field_numbers(self):
        # -[ALSCellTower writeTo:] @ 0x100aa3f7c
        f = self._fields('ALSCellTower')
        expected = {
            'mcc': (1, 'int32'), 'mnc': (2, 'int32'),
            'cellID': (3, 'int32'), 'lacID': (4, 'int32'),
            'location': (5, 'ALSLocation'),   # submessage
            'arfcn': (11, 'int32'), 'psc': (12, 'int32'),
        }
        for name, spec in expected.items():
            self.assertIn(name, f, f'ALSCellTower.{name} missing')
            self.assertEqual(f[name].number, spec[0], f'ALSCellTower.{name} number')
            self.assertEqual(f[name].type_name, spec[1], f'ALSCellTower.{name} type')

    # ── Enum VALUE recovery (standalone __DATA/__cfstring) ────────────────────

    def _enum(self, class_name, enum_name):
        msg = self.msgs.get(class_name)
        self.assertIsNotNone(msg, f'{class_name} must be extracted')
        e = next((en for en in msg.enums if en.name == enum_name), None)
        self.assertIsNotNone(e, f'{class_name} must define enum {enum_name}')
        return e

    def test_enum_values_recovered_from_data_cfstring(self):
        # Regression for the CFString-reader fix: locationd stores enum value
        # strings as __DATA/__cfstring constant-string structs whose +16 char*
        # field is a chained-fixup pointer.  Before the fix the enum-string reader
        # only handled __DATA_CONST/__cfstring with a 36-bit cache mask, so every
        # enum reverted to a placeholder.  ALSNearbyRequest.technology is a
        # bitmask enum (1,2,4,8) — assert the real values came back.
        e = self._enum('ALSNearbyRequest', 'ALSNearbyRequestTechnology')
        self.assertGreaterEqual(len(e.values), 4,
                                'technology enum values must be recovered, not placeholder')
        nums = {v.number for v in e.values}
        self.assertEqual({1, 2, 4, 8} & nums, {1, 2, 4, 8},
                         f'expected bitmask values 1,2,4,8; got {sorted(nums)}')
        self.assertTrue(any('GSM' in v.name for v in e.values),
                        'expected a kRadioAccessTechnologyGSM-derived value name')

    def test_cbz_two_value_enum_recovered(self):
        # Regression for the cbz/cbnz value-0 fix: the smallest enums compile to
        # `cbz w2, L0` (value 0) + `cmp w2,#1; b.ne` (value 1) with NO jump
        # table.  Before the fix the value-0 arm was missed, leaving a single
        # value (<2) so the whole enum was dropped to a placeholder.
        e = self._enum('ALCLBodyMetrics', 'ALCLBodyMetricsGender')
        nums = {v.number for v in e.values}
        self.assertEqual(nums, {0, 1}, f'gender must be a 2-value enum; got {sorted(nums)}')
        self.assertTrue(any('MALE' in v.name and 'FEMALE' not in v.name
                            for v in e.values))
        self.assertTrue(any('FEMALE' in v.name for v in e.values))

    def test_all_enums_recovered_no_placeholders(self):
        # With the CFString-reader fix (__DATA/__cfstring + read_ptr) AND the
        # cbz/cbnz value-0 fix, every locationd enum recovers real values — none
        # falls back to the `// values not recovered` placeholder.
        all_enums = [en for m in self.msgs.values() for en in m.enums]
        self.assertGreaterEqual(len(all_enums), 40)
        placeholders = [en.name for en in all_enums if not en.values]
        self.assertEqual(placeholders, [],
                         f'all enums should recover values; placeholders: {placeholders}')

    def test_tailcall_last_field_is_confirmed(self):
        # The regression anchor for the tail-call writeTo: fix: the LAST field of
        # these messages is written via `b _PBDataWriterWrite…Field` (not `bl`)
        # with the epilogue between `mov w2,#N` and the branch.  Both must be
        # binary-CONFIRMED at their true tag, not next_unconfirmed filler.
        loc = self._fields('ALSLocation')['infoMask']
        self.assertEqual(loc.number, 13)
        self.assertTrue(loc.number_confirmed,
                        'infoMask must be binary-confirmed (tail-call write)')
        psc = self._fields('ALSCellTower')['psc']
        self.assertEqual(psc.number, 12)
        self.assertTrue(psc.number_confirmed,
                        'psc must be binary-confirmed (tail-call write)')

    def test_submessage_cross_reference(self):
        # ALSCellTower.location (field 5) is a submessage whose element type is
        # the separately-extracted ALSLocation message.
        loc = self._fields('ALSCellTower')['location']
        self.assertEqual(loc.type_name, 'ALSLocation')
        self.assertIn('ALSLocation', self.msgs)

    # ── Enum detection (values are a known binary-only gap) ────────────────────

    def test_enums_detected(self):
        # Binary-only mode detects enum-typed fields (the field type becomes an
        # enum).  NOTE: enum *values* are currently not recovered in binary-only
        # mode for locationd — a separate known gap — so we assert detection
        # only, not value contents.
        n_enums = sum(len(m.enums) for m in self.msgs.values())
        self.assertGreaterEqual(n_enums, 40)


@unittest.skipUnless(HAS_BINARY, SKIP_MSG)
class TestLocationdBuildIdentity(unittest.TestCase):
    """Records which build the field-number anchors were verified against."""

    def test_uuid_matches_expected_build(self):
        with open(BINARY, 'rb') as fh:
            data = fh.read(8192)
        magic = struct.unpack_from('<I', data)[0]
        if magic not in (0xFEEDFACF, 0xCEFAEDFE):
            self.skipTest('not a 64-bit Mach-O')
        ncmds = struct.unpack_from('<I', data, 16)[0]
        off = 32
        uuid = ''
        for _ in range(ncmds):
            cmd, cmdsize = struct.unpack_from('<II', data, off)
            if cmd == 0x1B:   # LC_UUID
                ub = data[off + 8: off + 24]
                uuid = '-'.join([
                    ub[:4].hex(), ub[4:6].hex(), ub[6:8].hex(),
                    ub[8:10].hex(), ub[10:].hex(),
                ]).upper()
                break
            off += cmdsize
        if uuid != EXPECTED_UUID:
            self.skipTest(
                f'locationd build {uuid} != anchored {EXPECTED_UUID}; '
                f'structural tests still apply, exact-number anchors may differ')
        self.assertEqual(uuid, EXPECTED_UUID)


if __name__ == '__main__':
    unittest.main()
