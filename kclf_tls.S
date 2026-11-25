/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copied as one position-independent block into EL0. All branches/ADR operands
 * are local to this section. External calls use validated libc entry points
 * from the state block. Never execute these routines in kernel context.
 *
 * One pthread key owns each module's per-thread blocks. Its destructor uses
 * munmap, so this code and the key stay live until process exit (NODELETE).
 * Anonymous mappings supply zero-filled .tbss without allocator locks. Slow
 * initialization blocks signals and rechecks the key, preventing a nested
 * signal handler from observing or replacing a partially initialized block.
 */
#include "kclf_tls.h"

.section .rodata.kclf_tls, "a"
.balign 16
.global kclf_tls_start, kclf_tls_end, kclf_tls_init, kclf_tls_resolve
kclf_tls_start:
kclf_tls_init:
    .inst 0xd503245f                 // bti c
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    ldr x16, [x0, #KT_KEY_CREATE]
    adr x1, .Ldestroy
    // x0 points at the pthread_key_t field, which is first in the state.
    blr x16
    neg w0, w0
    sxtw x0, w0                     // return zero or negative pthread errno
    ldp x29, x30, [sp], #16
    ret

.Ldestroy:
    .inst 0xd503245f                 // pthread key destructor
    ldr x1, [x0]                    // allocation length
    mov x8, #215                    // __NR_munmap
    svc #0
    ret

.balign 16
kclf_tls_resolve:
    .inst 0xd503245f
    // TLSDESC preserves every GPR except x0 and all SIMD registers. Save the
    // FP control/status and condition flags too. x18 is never used as scratch.
    sub sp, sp, #800
    stp x1, x2, [sp, #0]
    stp x3, x4, [sp, #16]
    stp x5, x6, [sp, #32]
    stp x7, x8, [sp, #48]
    stp x9, x10, [sp, #64]
    stp x11, x12, [sp, #80]
    stp x13, x14, [sp, #96]
    stp x15, x16, [sp, #112]
    stp x17, x18, [sp, #128]
    stp x19, x20, [sp, #144]
    stp x21, x22, [sp, #160]
    stp x23, x24, [sp, #176]
    stp x25, x26, [sp, #192]
    stp x27, x28, [sp, #208]
    stp x29, x30, [sp, #224]
    mrs x9, fpcr
    mrs x10, fpsr
    stp x9, x10, [sp, #240]
    stp q0, q1, [sp, #256]
    stp q2, q3, [sp, #288]
    stp q4, q5, [sp, #320]
    stp q6, q7, [sp, #352]
    stp q8, q9, [sp, #384]
    stp q10, q11, [sp, #416]
    stp q12, q13, [sp, #448]
    stp q14, q15, [sp, #480]
    stp q16, q17, [sp, #512]
    stp q18, q19, [sp, #544]
    stp q20, q21, [sp, #576]
    stp q22, q23, [sp, #608]
    stp q24, q25, [sp, #640]
    stp q26, q27, [sp, #672]
    stp q28, q29, [sp, #704]
    stp q30, q31, [sp, #736]
    mrs x9, nzcv
    str x9, [sp, #768]

    ldr x0, [x0, #8]                // descriptor argument {state, TLS offset}
    ldp x19, x20, [x0]
    ldr w0, [x19, #KT_KEY]
    ldr x16, [x19, #KT_GETSPECIFIC]
    blr x16
    cbnz x0, .Lready

    // rt_sigprocmask(SIG_SETMASK, &all, &old, sizeof(kernel_sigset_t))
    mov x0, #2
    mov x1, #-1
    str x1, [sp, #792]
    add x1, sp, #792
    add x2, sp, #784
    mov x3, #8
    mov x8, #135
    svc #0
    cbnz x0, .Lfatal
    ldr w0, [x19, #KT_KEY]
    ldr x16, [x19, #KT_GETSPECIFIC]
    blr x16
    mov x21, x0
    cbnz x21, .Lrestore_mask

    ldr x1, [x19, #KT_MEMSZ]
    ldr x2, [x19, #KT_ALIGN]
    add x22, x1, x2
    add x22, x22, #16               // mapping header and alignment slack
    mov x0, #0
    mov x1, x22
    mov x2, #3                      // PROT_READ | PROT_WRITE
    mov x3, #0x22                   // MAP_PRIVATE | MAP_ANONYMOUS
    mov x4, #-1
    mov x5, #0
    mov x8, #222                    // __NR_mmap
    svc #0
    cmn x0, #4095
    b.hs .Lrestore_mask             // x21 is still zero on allocation failure
    mov x21, x0
    str x22, [x21]
    ldr x1, [x19, #KT_ALIGN]
    sub x2, x1, #1
    ldr x3, [x19, #KT_FIRSTBYTE]
    add x0, x21, #16
    add x0, x0, x2
    sub x0, x0, x3
    neg x1, x1
    and x0, x0, x1
    add x0, x0, x3
    sub x1, x0, x21
    str x1, [x21, #8]               // aligned TLS data offset in allocation
    ldr x1, [x19, #KT_TEMPLATE]
    ldr x2, [x19, #KT_FILESZ]
    cmp x2, #16
    b.lo .Lcopy_tail
.Lcopy_words:
    ldp x3, x4, [x1], #16
    stp x3, x4, [x0], #16
    sub x2, x2, #16
    cmp x2, #16
    b.hs .Lcopy_words
.Lcopy_tail:
    cbz x2, .Lpublish
.Lcopy:
    ldrb w3, [x1], #1
    strb w3, [x0], #1
    subs x2, x2, #1
    b.ne .Lcopy
.Lpublish:
    ldr w0, [x19, #KT_KEY]
    mov x1, x21
    ldr x16, [x19, #KT_SETSPECIFIC]
    blr x16
    cbz w0, .Lrestore_mask
    mov x0, x21
    ldr x1, [x21]
    mov x8, #215
    svc #0
    mov x21, #0
.Lrestore_mask:
    mov x0, #2
    add x1, sp, #784
    mov x2, #0
    mov x3, #8
    mov x8, #135
    svc #0
    cbnz x0, .Lfatal
    cbz x21, .Lfatal
    mov x0, x21
.Lready:
    ldr x1, [x0, #8]
    add x0, x0, x1
    add x0, x0, x20
    mrs x1, tpidr_el0
    sub x0, x0, x1                  // TLSDESC returns TP-relative offset

    ldp x9, x10, [sp, #240]
    msr fpcr, x9
    msr fpsr, x10
    ldr x9, [sp, #768]
    msr nzcv, x9
    ldp q0, q1, [sp, #256]
    ldp q2, q3, [sp, #288]
    ldp q4, q5, [sp, #320]
    ldp q6, q7, [sp, #352]
    ldp q8, q9, [sp, #384]
    ldp q10, q11, [sp, #416]
    ldp q12, q13, [sp, #448]
    ldp q14, q15, [sp, #480]
    ldp q16, q17, [sp, #512]
    ldp q18, q19, [sp, #544]
    ldp q20, q21, [sp, #576]
    ldp q22, q23, [sp, #608]
    ldp q24, q25, [sp, #640]
    ldp q26, q27, [sp, #672]
    ldp q28, q29, [sp, #704]
    ldp q30, q31, [sp, #736]
    ldp x1, x2, [sp, #0]
    ldp x3, x4, [sp, #16]
    ldp x5, x6, [sp, #32]
    ldp x7, x8, [sp, #48]
    ldp x9, x10, [sp, #64]
    ldp x11, x12, [sp, #80]
    ldp x13, x14, [sp, #96]
    ldp x15, x16, [sp, #112]
    ldp x17, x18, [sp, #128]
    ldp x19, x20, [sp, #144]
    ldp x21, x22, [sp, #160]
    ldp x23, x24, [sp, #176]
    ldp x25, x26, [sp, #192]
    ldp x27, x28, [sp, #208]
    ldp x29, x30, [sp, #224]
    add sp, sp, #800
    ret
.Lfatal:
    // Like bionic's dynamic TLS, address resolution cannot report ENOMEM.
    ldr x16, [x19, #KT_ABORT]
    blr x16
    brk #0
kclf_tls_end:
.section .note.GNU-stack, "", %progbits
