/* Test-only syscall gateway: handler emulation must not recursively SIGSYS.
 * x6/x7 are cleared so a handler syscall cannot consume a KCLF completion. */
.text
.align 2
.global audit_syscall6
.hidden audit_syscall6
.type audit_syscall6, %function
audit_syscall6:
    mov x8, x0
    mov x0, x1
    mov x1, x2
    mov x2, x3
    mov x3, x4
    mov x4, x5
    mov x5, x6
    mov x6, xzr
    mov x7, xzr
    svc #0
.global audit_after_svc
.hidden audit_after_svc
audit_after_svc:
    ret
.size audit_syscall6, .-audit_syscall6

/* Position-independent benign anonymous-code control, copied before filtering.
 * Calls the libc function supplied in x1, without KCLF's completion protocol. */
.align 2
.global audit_benign_begin
.hidden audit_benign_begin
audit_benign_begin:
    bti c
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    blr x1
    ldp x29, x30, [sp], #16
    ret
.global audit_benign_end
.hidden audit_benign_end
audit_benign_end:
.section .note.GNU-stack,"",%progbits
