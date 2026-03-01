//go:build arm64 && darwin

#include "textflag.h"

// func uuidv4(out *[16]byte)
TEXT ·uuidv4(SB), NOSPLIT, $0-8
    // Load output pointer into R0
    MOVD out+0(FP), R0

    // Save buffer pointer in R3 (to use after syscall)
    MOVD R0, R3

    // Arguments for getentropy(void *buf, size_t buflen)
    MOVD $16, R1   // length = 16

    // macOS syscall number for getentropy is 0x1000000 | 500
    MOVD $(0x1000000 | 500), R16

    SVC $0         // perform syscall

    CMP $0, R0     // check return value
    BNE error      // non-zero -> error

    // --- Set version bits ---
    MOVBU 6(R3), R2
    AND $0x0F, R2
    ORR $0x40, R2, R2
    MOVB R2, 6(R3)

    // --- Set variant bits ---
    MOVBU 8(R3), R2
    AND $0x3F, R2
    ORR $0x80, R2, R2
    MOVB R2, 8(R3)

    RET

error:
    // If getentropy fails, zero out the buffer
    MOVD $0, R2
    MOVD R2, 0(R3)
    MOVD R2, 8(R3)
    RET
