/* Only the fixture-owned guarded worker calls this boundary. No patching or
 * interposition on bionic, ART or business threads. x16 is caller-saved at the
 * C ABI boundary, but the raw Linux syscall preserves it. */
.text
.p2align 2
.global passive_guarded_sleep
.type passive_guarded_sleep, %function
passive_guarded_sleep:
    stp x29, x30, [sp, #-32]!
    stp x19, x20, [sp, #16]
    mov x29, sp
    mov x19, x1
    mov x20, x2
    mov x16, x2
    mov x1, xzr
    mov x8, #101
    svc #0
.Lafter_sleep:
    str x16, [x19]
    str x20, [x19, #8]
    adr x9, .Lafter_sleep
    str x9, [x19, #16]
    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp], #32
    ret
.size passive_guarded_sleep, .-passive_guarded_sleep
.section .note.GNU-stack,"",%progbits
