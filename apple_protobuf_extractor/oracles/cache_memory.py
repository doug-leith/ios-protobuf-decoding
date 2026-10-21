"""A dyld cache's memory as a process would see it, for the oracles that run code from one (the
emulators, Remote Mirror): bytes from the cache files with every pointer location the cache's
slide info lists decoded (unslid).  Slide info versions 2 (arm64: the iPhone 8 cache) and 5
(iOS / macOS 26 and later)."""
import bisect
import struct

# version 2: a page start's attribute bits, in u16 units of 4 bytes
_V2_ATTR_EXTRA, _V2_ATTR_NO_REBASE, _V2_ATTR_END = 0x8000, 0x4000, 0x8000
_V2_OFFSET = 0x3FFF


class SlideInfo:
    """The pointer locations of every slid mapping of a cache (the mappingWithSlide array at
    header 0x138 / count 0x13C of each file, 56-byte records: address, size, fileOffset,
    slideInfoFileOffset, slideInfoFileSize, ...).

    * version 2: per page a u16 start (in 4-byte units; with the extra bit, an index into the
      extras, each a chain start until one has the end bit); each pointer's ``delta_mask`` bits
      are the distance to the next (in 4-byte units), the rest its value, plus ``value_add``
      when nonzero;
    * version 5: per page a u16 start in bytes (0xFFFF: none); each pointer's 11-bit ``next``
      (bits 52-62) in 8-byte strides, its value ``value_add`` plus its low 34 bits."""

    def __init__(self, reader):
        self.reader, self.maps, self._pages = reader, [], {}
        for path in {m.path for m in reader._mappings}:
            with open(path, "rb") as fh:
                off, cnt = struct.unpack_from("<II", fh.read(0x140), 0x138)
                fh.seek(off)
                raw = fh.read(cnt * 56)
                for i in range(cnt):
                    addr, size, _fo, info_off, info_size = struct.unpack_from("<QQQQQ", raw, i * 56)
                    if info_size:
                        fh.seek(info_off)
                        self.maps.append((addr, addr + size, fh.read(info_size)))
        self.maps.sort()
        self._starts = [m[0] for m in self.maps]

    def _page(self, m, pg):
        """{offset in page: decoded target} of page *pg* of mapping *m*."""
        key = (m[0], pg)
        if key not in self._pages:
            version = struct.unpack_from("<I", m[2], 0)[0]
            if version == 2:
                self._pages[key] = self._page_v2(m, pg)
            elif version == 5:
                self._pages[key] = self._page_v5(m, pg)
            else:
                raise NotImplementedError("slide info version %d" % version)
        return self._pages[key]

    def _word(self, va):
        return struct.unpack("<Q", self.reader.read_raw(va, 8))[0]

    def _page_v2(self, m, pg):
        blob = m[2]
        (_v, page_size, starts_off, starts_n, extras_off, extras_n, delta_mask,
         value_add) = struct.unpack_from("<IIIIIIQQ", blob, 0)
        base = m[0] + pg * page_size
        shift = (delta_mask & -delta_mask).bit_length() - 1 - 2
        start = struct.unpack_from("<H", blob, starts_off + 2 * pg)[0]
        out = {}

        def chain(off):
            while True:
                raw = self._word(base + off)
                delta = (raw & delta_mask) >> shift
                value = raw & ~delta_mask & ((1 << 64) - 1)
                out[off] = value + value_add if value else 0
                if not delta:
                    return
                off += delta

        if start & _V2_ATTR_NO_REBASE:
            return out
        if start & _V2_ATTR_EXTRA:
            i = start & _V2_OFFSET
            while True:
                extra = struct.unpack_from("<H", blob, extras_off + 2 * i)[0]
                chain((extra & _V2_OFFSET) * 4)
                if extra & _V2_ATTR_END:
                    break
                i += 1
        else:
            chain(start * 4)
        return out

    def _page_v5(self, m, pg):
        blob = m[2]
        _v, page_size, n = struct.unpack_from("<III", blob, 0)
        value_add = struct.unpack_from("<Q", blob, 16)[0]
        off = struct.unpack_from("<H", blob, 24 + 2 * pg)[0]
        out = {}
        if off != 0xFFFF:                          # DYLD_CACHE_SLIDE_V5_PAGE_ATTR_NO_REBASE
            base = m[0] + pg * page_size
            while True:
                raw = self._word(base + off)
                out[off] = value_add + (raw & ((1 << 34) - 1))
                step = (raw >> 52) & 0x7FF
                if not step:
                    break
                off += step * 8
        return out

    def _page_size(self, m):
        return struct.unpack_from("<I", m[2], 4)[0]

    def apply(self, addr, raw):
        """*raw* (the bytes at *addr*) with every pointer location in it decoded."""
        i = bisect.bisect_right(self._starts, addr) - 1
        if i < 0 or addr >= self.maps[i][1]:
            return raw
        m = self.maps[i]
        size = self._page_size(m)
        buf, a, end = bytearray(raw), addr, addr + len(raw)
        while a < min(end, m[1]):
            pg = (a - m[0]) // size
            base = m[0] + pg * size
            for off, v in self._page(m, pg).items():
                if addr <= base + off and base + off + 8 <= end:
                    struct.pack_into("<Q", buf, base + off - addr, v)
            a = base + size
        return bytes(buf)
