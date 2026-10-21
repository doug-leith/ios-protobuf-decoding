"""Targeted regression tests for the three classlist/dyld_cache fixes."""
import sys, struct, unittest

from macho.classlist import _is_valid_selector

class TestSelectorValidation(unittest.TestCase):
    """_is_valid_selector rejects binary garbage, accepts real selectors."""

    def test_simple_getter(self):
        self.assertTrue(_is_valid_selector('status'))

    def test_with_colon(self):
        self.assertTrue(_is_valid_selector('setStatus:'))
        self.assertTrue(_is_valid_selector('statusAsString:'))

    def test_proto_selectors(self):
        for sel in ('readFrom:', 'writeTo:', 'mergeFrom:', 'copyTo:',
                    'isEqual:', 'hash', 'description'):
            self.assertTrue(_is_valid_selector(sel), f'Expected valid: {sel!r}')

    def test_empty_rejected(self):
        self.assertFalse(_is_valid_selector(''))
        self.assertFalse(_is_valid_selector(None))

    def test_single_char_accepted(self):
        # Single-char ObjC property getters like x, y, z are valid selectors.
        # The old validator incorrectly required len > 1; this was fixed because
        # ipsw-extracted binaries resolve single-char selectors from methname and
        # the rejection caused 'x' to fall through to (failing) cache lookups.
        self.assertTrue(_is_valid_selector('x'))
        self.assertTrue(_is_valid_selector('z'))

    def test_the_compiler_generated_cxx_selectors_accepted(self):
        # clang's C++ / ARC ivar destructor and constructor; macOS 27 GeoServices'
        # GEOComposedRouteAnchorPoint has .cxx_destruct (no .symbols file restores it there)
        self.assertTrue(_is_valid_selector('.cxx_destruct'))
        self.assertTrue(_is_valid_selector('.cxx_construct'))
        self.assertFalse(_is_valid_selector('.cxx_other'))
        self.assertFalse(_is_valid_selector('.x'))

    def test_control_chars_rejected(self):
        self.assertFalse(_is_valid_selector('\x01\\'))   # bytes from chained fixup
        self.assertFalse(_is_valid_selector('\x00abc'))

    def test_binary_garbage_rejected(self):
        # The old 'spatch_queue>",R,N,V_serverQueue' garbage
        self.assertFalse(_is_valid_selector('spatch_queue>",R,N,V_serverQueue'))
        # Curly braces, quotes, spaces — none are valid in selector names
        self.assertFalse(_is_valid_selector('some thing'))
        self.assertFalse(_is_valid_selector('foo{bar}'))

    def test_too_long_rejected(self):
        self.assertFalse(_is_valid_selector('a' * 201))

    def test_max_length_accepted(self):
        self.assertTrue(_is_valid_selector('a' * 200))

    def test_starts_with_digit_rejected(self):
        self.assertFalse(_is_valid_selector('2bad'))

    def test_underscore_start_ok(self):
        self.assertTrue(_is_valid_selector('_privateMethod'))
        self.assertTrue(_is_valid_selector('_internal:with:args:'))


class TestHasDirectFlagPropagation(unittest.TestCase):
    """Verify that _parse_methods extracts the has_direct bit
    (METHOD_FLAG_PREOPTIMIZED_RELATIVE_METHOD_SELECTORS, 0x40000000, in
    entsizeAndFlags) from a real method_list_t and threads it into
    _parse_relative_method correctly.

    A prior version of this class only called _is_valid_selector directly and
    never built a fixture or called _parse_methods at all (found during a
    2026-07-22 testing-gap audit) --
    its docstring promised has_direct-propagation coverage that the assertions
    never actually exercised. This version builds one minimal synthetic
    Mach-O binary with a single relative method_t entry whose nameOffset
    points at a raw selector string ("status\\0\\0", 8 bytes so it also forms
    a plausible-looking (but wrong) pointer value when misread) and parses it
    twice, toggling only the has_direct bit in entsizeAndFlags:

      * has_direct=True  -> Step 1b reads sel_ref_va AS the cstring directly
        -> name resolves to "status".
      * has_direct=False -> Format A instead treats sel_ref_va as a POINTER,
        dereferencing the same 8 bytes as a u64 address -> an unmapped
        garbage address -> ValueError, caught -> name stays None.

    Same raw bytes, opposite outcome purely from the flag -- this is the
    propagation the class name promises.
    """

    @staticmethod
    def _minimal_macho_with_one_section(text_vmaddr: int, text_data: bytes) -> bytes:
        """Build a minimal arm64 Mach-O with one __TEXT segment whose fileoff
        correctly points at *text_data*'s real position in the returned bytes
        (unlike some other synthetic-fixture helpers in this suite, which set
        fileoff=0 and get away with it only because their tests never read
        specific content back out of the segment)."""
        seg_name = b'__TEXT\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        nsects = 0
        hdr_size = 32     # sizeof(mach_header_64)
        seg_cmdsize = 72 + nsects * 80
        fileoff = hdr_size + seg_cmdsize
        seg_cmd = struct.pack(
            '<II16sQQQQiiii', 0x19, seg_cmdsize, seg_name,
            text_vmaddr, len(text_data), fileoff, len(text_data), 7, 5, nsects, 0,
        )
        hdr = struct.pack('<IIIIIIII', 0xFEEDFACF, 0x0100000C, 0, 0x6,
                           1, seg_cmdsize, 0, 0)
        assert len(hdr) == hdr_size
        return hdr + seg_cmd + text_data

    def _parse_one_relative_method(self, has_direct: bool):
        from macho.memory import BinaryContext
        from macho.classlist import _parse_methods
        from macho.strings import StringTable
        from macho.objc_abi import METHOD_FLAG_RELATIVE

        BASE = 0x18c000000
        # Layout inside the __TEXT segment (all offsets relative to BASE):
        #   [0:8)   method_list_t header: entsizeAndFlags(u32), count(u32)
        #   [8:20)  one relative method_t: name_rel/types_rel/imp_rel (s32 x3)
        #   [20:28) the raw selector bytes name_rel points at
        entry_va_off = 8
        str_off = entry_va_off + 12
        name_rel = str_off - entry_va_off
        sel_bytes = b'status\x00\x00'   # 8 bytes: a valid selector, and (when
                                          # misread as a little-endian u64) an
                                          # address nowhere near this tiny
                                          # binary's mapped range.
        flags = METHOD_FLAG_RELATIVE | (0x40000000 if has_direct else 0)
        header = struct.pack('<II', flags, 1)          # count=1
        entry  = struct.pack('<iii', name_rel, 0, 0)   # types_rel=0 -> types=''
        text_data = header + entry + sel_bytes

        ctx = BinaryContext(self._minimal_macho_with_one_section(BASE, text_data))
        methods = _parse_methods(ctx, BASE, StringTable())
        self.assertEqual(len(methods), 1)
        return methods[0]

    def test_has_direct_true_reads_cstring_directly(self):
        m = self._parse_one_relative_method(has_direct=True)
        self.assertEqual(m.name, 'status')

    def test_has_direct_false_misreads_same_bytes_as_pointer(self):
        # Identical bytes, only the flag differs -> Format A's pointer
        # dereference fails against the unmapped "address" and leaves name=None
        # (recoverable later via .symbols in cache-native mode), instead of
        # silently returning the wrong-but-plausible string.
        m = self._parse_one_relative_method(has_direct=False)
        self.assertIsNone(m.name)


class TestDyldCacheReadU64(unittest.TestCase):
    """DyldCacheReader.read_u64 returns little-endian u64 from a mapped region."""

    def _make_reader(self, vmaddr: int, payload: bytes):
        """Return a DyldCacheReader whose single mapping covers vmaddr..vmaddr+len(payload)."""
        import io, tempfile, os
        from macho.dyld_cache import DyldCacheReader, _MAPPING_STRIDE

        # Build a minimal cache file:
        # Header (0x1a0 bytes) + mapping array (one entry) + payload data
        hdr_size    = 0x1a0
        map_offset  = hdr_size
        data_offset = map_offset + _MAPPING_STRIDE
        total       = data_offset + len(payload)

        buf = bytearray(total)
        # magic
        buf[0:16] = b'dyld_v1   arm64\x00'
        # mappingOffset, mappingCount
        struct.pack_into('<II', buf, 0x10, map_offset, 1)
        # subCacheArrayOffset=0, subCacheArrayCount=0
        struct.pack_into('<II', buf, 0x188, 0, 0)
        # dyld_cache_mapping_info: address, size, fileOffset, max_protection, init_protection
        struct.pack_into('<QQQ', buf, map_offset,
                         vmaddr, len(payload), data_offset)
        buf[data_offset:data_offset + len(payload)] = payload

        fd, path = tempfile.mkstemp()
        try:
            os.write(fd, buf)
            os.close(fd)
            reader = DyldCacheReader(path)
            return reader, path
        except:
            os.close(fd)
            os.unlink(path)
            raise

    def test_read_u64_success(self):
        import os
        vmaddr = 0x18d000000
        raw_val = 0x1001FFFF00005C01
        payload = struct.pack('<Q', raw_val) + b'\x00' * 8
        reader, path = self._make_reader(vmaddr, payload)
        try:
            result = reader.read_u64(vmaddr)
            self.assertEqual(result, raw_val)
        finally:
            reader.close()
            os.unlink(path)

    def test_read_u64_unmapped_returns_none(self):
        import os
        vmaddr = 0x18d000000
        payload = struct.pack('<Q', 0xDEADBEEF) + b'\x00' * 8
        reader, path = self._make_reader(vmaddr, payload)
        try:
            result = reader.read_u64(0x99999999)   # not mapped
            self.assertIsNone(result)
        finally:
            reader.close()
            os.unlink(path)

    def test_read_u64_near_end_of_mapping(self):
        """Returns None when fewer than 8 bytes remain in the mapping."""
        import os
        vmaddr = 0x18d000000
        payload = struct.pack('<Q', 0x1234)  # exactly 8 bytes
        reader, path = self._make_reader(vmaddr, payload)
        try:
            # 8 bytes available from start → success
            self.assertIsNotNone(reader.read_u64(vmaddr))
            # 7 bytes from vmaddr+1 → None
            self.assertIsNone(reader.read_u64(vmaddr + 1))
        finally:
            reader.close()
            os.unlink(path)

    def test_read_cstring_in_same_mapping(self):
        """read_cstring still works after adding read_u64."""
        import os
        vmaddr = 0x18d000000
        payload = b'readFrom:\x00' + b'\x00' * 10
        reader, path = self._make_reader(vmaddr, payload)
        try:
            result = reader.read_cstring(vmaddr)
            self.assertEqual(result, 'readFrom:')
        finally:
            reader.close()
            os.unlink(path)


if __name__ == '__main__':
    unittest.main(verbosity=2)
