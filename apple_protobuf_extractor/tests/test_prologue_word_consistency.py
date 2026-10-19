"""
tests/test_prologue_word_consistency.py — regression guard for the
special-purpose arm64 instruction words that ``macho/disasm.py``'s
capstone-fallback native decoder hardcodes.

``_native_decode`` once mislabeled ``0xD503233F`` (real ``paciasp``) as ``isb``;
a sibling boundary detector (since deleted) confused ``autibsp`` with
``pacibsp``.  Both were caught by diffing against capstone ground truth.  This
module pins the encodings against capstone and asserts ``_native_decode`` agrees
on every word it claims to recognize, so a future mismatch fails loudly instead
of silently corrupting fallback disassembly.
"""

from __future__ import annotations

import struct

import capstone
import pytest

from macho.disasm import _native_decode


_CS = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)


def _capstone_mnemonic(word: int) -> str:
    encoded = struct.pack('<I', word)
    insns = list(_CS.disasm(encoded, 0))
    assert insns, f'capstone failed to decode word 0x{word:08X}'
    return insns[0].mnemonic


# Every special-purpose word the decoder hardcodes by exact value.
_CANONICAL_WORDS = {
    0xD65F03C0: 'ret',
    0xD65F0BFF: 'retaa',
    0xD65F0FFF: 'retab',
    0xD503201F: 'nop',
    0xD503233F: 'paciasp',
    0xD503237F: 'pacibsp',
    0xD5033FDF: 'isb',
    0xD50323FF: 'autibsp',   # epilogue (return-address auth), NOT pacibsp
}


@pytest.mark.parametrize('word,mnemonic', _CANONICAL_WORDS.items())
def test_canonical_words_match_capstone_ground_truth(word, mnemonic):
    # Test-infrastructure / ground-truth self-check ONLY: confirms this file's
    # hardcoded _CANONICAL_WORDS table agrees with capstone (the oracle the
    # test below diffs production against), via the local _capstone_mnemonic
    # helper. It calls NO project production code — in particular it does not
    # exercise macho.disasm._native_decode (the fallback decoder these constants
    # exist to guard); that production comparison is covered by the sibling
    # test_native_decode_agrees_with_capstone_when_recognized below. So this is
    # NOT a regression test for the decoder, only a guard that the oracle table
    # itself is transcribed correctly.
    assert _capstone_mnemonic(word) == mnemonic


@pytest.mark.parametrize('word,mnemonic', _CANONICAL_WORDS.items())
def test_native_decode_agrees_with_capstone_when_recognized(word, mnemonic):
    """disasm.py's fallback decoder must not silently mislabel a word it claims
    to recognize; 'unk' (not yet handled) is fine, a wrong mnemonic is not."""
    got_mnemonic, _ = _native_decode(word, pc=0x1000)
    if got_mnemonic == 'unk':
        pytest.skip(f'0x{word:08X} not yet handled by _native_decode')
    assert got_mnemonic == mnemonic

