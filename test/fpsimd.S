/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Hold sentinels across a real nanosleep syscall. Return zero on success. */
.text
.balign 4
.global kclf_test_fp_sleep
.type kclf_test_fp_sleep, %function
kclf_test_fp_sleep:
    sub sp, sp, #48
    stp q8, q9, [sp]
    mrs x9, fpcr
    mrs x10, fpsr
    stp x9, x10, [sp, #32]
    mov x9, #0x400000
    msr fpcr, x9
    mov x9, #1
    msr fpsr, x9
    movi v0.16b, #0x33
    movi v8.16b, #0x5a
    movi v31.16b, #0xa5
    mov x1, #0
    mov x8, #101
    svc #0
    cmp x0, #0
    cset w11, ne
    movi v9.16b, #0x33
    eor v9.16b, v9.16b, v0.16b
    umaxv b9, v9.16b
    umov w9, v9.b[0]
    cbz w9, 1f
    orr w11, w11, #2
1:
    movi v9.16b, #0x5a
    eor v9.16b, v9.16b, v8.16b
    umaxv b9, v9.16b
    umov w9, v9.b[0]
    cbz w9, 2f
    orr w11, w11, #4
2:
    movi v9.16b, #0xa5
    eor v9.16b, v9.16b, v31.16b
    umaxv b9, v9.16b
    umov w9, v9.b[0]
    cbz w9, 3f
    orr w11, w11, #8
3:
    mrs x9, fpcr
    mov x10, #0x400000
    cmp x9, x10
    b.eq 4f
    orr w11, w11, #16
4:
    mrs x9, fpsr
    cmp x9, #1
    b.eq 5f
    orr w11, w11, #32
5:
    ldp x9, x10, [sp, #32]
    msr fpcr, x9
    msr fpsr, x10
    ldp q8, q9, [sp]
    add sp, sp, #48
    mov w0, w11
    ret
.size kclf_test_fp_sleep, .-kclf_test_fp_sleep
.section .note.GNU-stack,"",%progbits
