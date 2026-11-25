/* Exercise the special TLSDESC register contract on both allocation and reuse. */
.text
.global check_tls_registers
.type check_tls_registers, %function
check_tls_registers:
    sub sp, sp, #240
    stp x19, x20, [sp, #0]
    stp x21, x22, [sp, #16]
    stp x23, x24, [sp, #32]
    stp x25, x26, [sp, #48]
    stp x27, x28, [sp, #64]
    stp x29, x30, [sp, #80]
    stp d8, d9, [sp, #96]
    stp d10, d11, [sp, #112]
    stp d12, d13, [sp, #128]
    stp d14, d15, [sp, #144]
    stp x0, x1, [sp, #160]
    str x18, [sp, #176]
    mrs x2, fpcr
    mrs x3, fpsr
    stp x2, x3, [sp, #184]
    mov x2, #0x1000000
    msr fpcr, x2
    mov x2, #0x10
    msr fpsr, x2
    mov x2, #0xa0000000
    msr nzcv, x2
    .irp reg,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,19,20,21,22,23,24,25,26,27,28,29
        mov x\reg, #\reg
    .endr
    .irp reg,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31
        movi v\reg\().16b, #0x5a
    .endr
    ldr x30, [sp, #168]
    blr x30
    mrs x0, nzcv
    mov x30, #0xa0000000
    cmp x0, x30
    b.ne .Lbad
    .irp reg,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,19,20,21,22,23,24,25,26,27,28,29
        cmp x\reg, #\reg
        b.ne .Lbad
    .endr
    ldr x0, [sp, #176]
    cmp x0, x18
    b.ne .Lbad
    movz x30, #0x5a5a
    movk x30, #0x5a5a, lsl #16
    movk x30, #0x5a5a, lsl #32
    movk x30, #0x5a5a, lsl #48
    .irp reg,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31
        umov x0, v\reg\().d[0]
        cmp x0, x30
        b.ne .Lbad
        umov x0, v\reg\().d[1]
        cmp x0, x30
        b.ne .Lbad
    .endr
    mrs x0, fpcr
    mov x30, #0x1000000
    cmp x0, x30
    b.ne .Lbad
    mrs x0, fpsr
    cmp x0, #0x10
    b.ne .Lbad
    mov x0, #0
    b .Lout
.Lbad:
    mov x0, #1
.Lout:
    ldp x2, x3, [sp, #184]
    msr fpcr, x2
    msr fpsr, x3
    ldp x19, x20, [sp, #0]
    ldp x21, x22, [sp, #16]
    ldp x23, x24, [sp, #32]
    ldp x25, x26, [sp, #48]
    ldp x27, x28, [sp, #64]
    ldp x29, x30, [sp, #80]
    ldp d8, d9, [sp, #96]
    ldp d10, d11, [sp, #112]
    ldp d12, d13, [sp, #128]
    ldp d14, d15, [sp, #144]
    add sp, sp, #240
    ret
.size check_tls_registers, .-check_tls_registers
.section .note.GNU-stack, "", %progbits
