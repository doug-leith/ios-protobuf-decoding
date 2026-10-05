"""
tests/test_prologue_word_consistency.py — cross-file regression guard for the
special-purpose arm64 instruction words that ``macho/disasm.py`` (the
capstone-fallback native decoder) and ``macho/arm64decode.py`` (the
prologue/epilogue boundary detector used by proto/dispatch.py) both hardcode.

This exists because ``_native_decode`` and ``_is_func_prologue_word`` each
independently hardcoded the *same* 32-bit words with mismatched labels:
``0xD503233F`` (real ``paciasp``) was mislabeled ``isb`` in disasm.py, and
``0xD50323FF`` (real ``autibsp``, a *return*-authentication epilogue
instruction) was mislabeled ``pacibsp`` in arm64decode.py while the true
``pacibsp`` encoding (``0xD503237F``) went unrecognized. Both were caught by
diffing against capstone ground truth. This module pins the correct
encodings against capstone directly, and then asserts the two hand-rolled
decoders agree with each other and with capstone on every word they claim to
recognize, so a future mismatch fails loudly instead of silently corrupting
fallback disassembly or dispatch-boundary scanning.
"""

from __future__ import annotations

import struct

import capstone
import pytest

from macho.arm64decode import _is_func_prologue_word, _is_ret_word
from macho.disasm import _native_decode


_CS = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)


def _capstone_mnemonic(word: int) -> str:
    encoded = struct.pack('<I', word)
    insns = list(_CS.disasm(encoded, 0))
    assert insns, f'capstone failed to decode word 0x{word:08X}'
    return insns[0].mnemonic


# Every special-purpose word either decoder hardcodes by exact value, paired
# with whether it is a genuine function-PROLOGUE opener (as opposed to an
# epilogue instruction, a no-op, or an unrelated barrier).
_CANONICAL_WORDS = {
    0xD65F03C0: ('ret',     False),
    0xD65F0BFF: ('retaa',   False),
    0xD65F0FFF: ('retab',   False),
    0xD503201F: ('nop',     False),
    0xD503233F: ('paciasp', True),
    0xD503237F: ('pacibsp', True),
    0xD5033FDF: ('isb',     False),
    0xD50323FF: ('autibsp', False),   # epilogue (return-address auth), NOT pacibsp
}


@pytest.mark.parametrize('word,expected', _CANONICAL_WORDS.items())
def test_canonical_words_match_capstone_ground_truth(word, expected):
    # Test-infrastructure / ground-truth self-check ONLY: confirms this file's
    # hardcoded _CANONICAL_WORDS table agrees with capstone (the oracle the
    # other tests below diff production against), via the local _capstone_mnemonic
    # helper. It calls NO project production code — in particular it does not
    # exercise macho.disasm._native_decode (the fallback decoder these constants
    # exist to guard); that production comparison is covered by the sibling
    # test_native_decode_agrees_with_capstone_when_recognized below. So this is
    # NOT a regression test for the decoder, only a guard that the oracle table
    # itself is transcribed correctly.
    mnemonic, _is_prologue = expected
    assert _capstone_mnemonic(word) == mnemonic


@pytest.mark.parametrize('word,expected', _CANONICAL_WORDS.items())
def test_native_decode_agrees_with_capstone_when_recognized(word, expected):
    """disasm.py's fallback decoder must not silently mislabel a word it claims
    to recognize; 'unk' (not yet handled) is fine, a wrong mnemonic is not."""
    mnemonic, _is_prologue = expected
    got_mnemonic, _ = _native_decode(word, pc=0x1000)
    if got_mnemonic == 'unk':
        pytest.skip(f'0x{word:08X} not yet handled by _native_decode')
    assert got_mnemonic == mnemonic


@pytest.mark.parametrize('word,expected', _CANONICAL_WORDS.items())
def test_func_prologue_word_agrees_with_capstone_ground_truth(word, expected):
    """arm64decode.py's boundary detector must only fire on genuine prologue
    openers (paciasp/pacibsp), never on epilogue/return/no-op/barrier words —
    the exact confusion (autibsp mistaken for pacibsp) that caused the bug."""
    _mnemonic, is_prologue = expected
    assert _is_func_prologue_word(word) == is_prologue


def test_cross_file_agreement_on_shared_special_words():
    """The two independently-hand-rolled decoders must not disagree about
    which of these shared words are prologue-openers: whatever _native_decode
    names 'paciasp'/'pacibsp' must be True in _is_func_prologue_word, and
    every other canonical word it recognizes must be False there."""
    for word, (mnemonic, is_prologue) in _CANONICAL_WORDS.items():
        native_mnemonic, _ = _native_decode(word, pc=0x1000)
        if native_mnemonic == 'unk':
            continue
        assert native_mnemonic == mnemonic
        assert _is_func_prologue_word(word) == (mnemonic in ('paciasp', 'pacibsp')), (
            f'0x{word:08X}: _native_decode names it {native_mnemonic!r} but '
            f'_is_func_prologue_word disagrees on whether that is a prologue opener'
        )


def test_ret_words_are_never_mistaken_for_prologue_openers():
    """Sanity cross-check: every word _is_ret_word() accepts must be rejected
    by _is_func_prologue_word(), and vice versa for the PAC-sign words —
    prologue and epilogue/return detection must stay mutually exclusive."""
    for word, (mnemonic, is_prologue) in _CANONICAL_WORDS.items():
        if _is_ret_word(word):
            assert not _is_func_prologue_word(word), (
                f'0x{word:08X} ({mnemonic}) is a return word but was also '
                f'flagged as a function-prologue opener'
            )
