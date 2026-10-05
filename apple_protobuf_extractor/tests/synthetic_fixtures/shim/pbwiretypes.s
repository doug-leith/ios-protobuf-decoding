// Hand-assembled (not clang-compiled) wire-type-family write helpers for
// f3_write_helper_family. See ../README.md gotcha 6: unlike the ObjC classes
// around them, these leaf helpers must reproduce EXACT instruction shapes
// (proto/write_helpers.py:_classify_write_helper scans for them literally),
// and clang -Os idiom for the C equivalents is not reliably predictable
// (gotcha 4b already burned us once on a simpler pattern). Hand-writing the
// four helpers directly sidesteps that risk while still being real, toolchain
// -assembled arm64 machine code (`as`/clang integrated assembler), not
// hand-packed Mach-O bytes.
//
// Calling convention matches gotcha 3 (plain C linkage): x0=writer (unused),
// x1/w1=value, w2=field tag (unused by these helpers — only the wire-type
// family constant matters to the classifier, not the actual tag value).

    .section __TEXT,__text,regular,pure_instructions
    .p2align 2

// sint32: zigzag-encode the VALUE arg (w1). Matches the real PB sint32
// helper shape documented in write_helpers.py: `lsl w_,w1,#1 ; eor
// w_,w_,w1,asr #31`.
    .globl _PBWriteSInt32Field
_PBWriteSInt32Field:
    lsl w8, w1, #1
    eor w8, w8, w1, asr #31
    ret

// sint64: same idiom on the 64-bit value arg (x1).
    .globl _PBWriteSInt64Field
_PBWriteSInt64Field:
    lsl x8, x1, #1
    eor x8, x8, x1, asr #63
    ret

// fixed32: builds the field tag as `mov w_,#5 ; bfi w_,w2,#3,#0x1d`
// (tag = (field<<3)|wiretype, wiretype 5 = 32-bit fixed).
    .globl _PBWriteFixed32Field
_PBWriteFixed32Field:
    mov w9, #5
    bfi w9, w2, #3, #0x1d
    ret

// fixed64: same idiom, wiretype 1 = 64-bit fixed.
    .globl _PBWriteFixed64Field
_PBWriteFixed64Field:
    mov w9, #1
    bfi w9, w2, #3, #0x1d
    ret
