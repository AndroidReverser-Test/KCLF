/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * KCLF EL0 trampoline.
 *
 * This blob is copied verbatim (relocation free) into an anonymous executable
 * page of the target process. It is entered through an exception return, so it
 * must not rely on any register state:
 *
 *   - the parameter block pointer is patched into the movz/movk sequence at
 *     kclf_tramp_ptr_slot by the kernel side;
 *   - offset 0 is a branch to offset 4, because the syscall restart path may
 *     rewind the return PC by one instruction (regs->pc -= 4);
 *   - the loader result is returned in x1/x2/x3, not left in target memory;
 *   - the used parameter region (rounded to 16 bytes) is zeroed before the
 *     completion trap; the unused page tail is untouched;
 *   - the last action is a getpid syscall carrying the request cookie, which
 *     the kernel hook consumes. The kernel then restores the original register
 *     file, so the trampoline never returns anywhere on its own.
 */
#include "kclf_param.h"

	.section .text.kclf_tramp, "ax"
	.balign 4
	.global kclf_tramp_start
	.global kclf_tramp_ptr_slot
	.global kclf_tramp_end
	.global kclf_tramp_return

kclf_tramp_start:
	b	1f			/* restart pad: regs->pc -= 4 lands here */
1:
	bti	c			/* harmless when BTI is disabled */
	/* This is an asynchronous diversion, not an ABI call by the target.
	 * Preserve ALL FPSIMD registers and control/status, including caller-saved
	 * registers. SVE/SME targets are rejected before diversion. */
	sub	sp, sp, #528
	stp	q0, q1, [sp, #0]
	stp	q2, q3, [sp, #32]
	stp	q4, q5, [sp, #64]
	stp	q6, q7, [sp, #96]
	stp	q8, q9, [sp, #128]
	stp	q10, q11, [sp, #160]
	stp	q12, q13, [sp, #192]
	stp	q14, q15, [sp, #224]
	stp	q16, q17, [sp, #256]
	stp	q18, q19, [sp, #288]
	stp	q20, q21, [sp, #320]
	stp	q22, q23, [sp, #352]
	stp	q24, q25, [sp, #384]
	stp	q26, q27, [sp, #416]
	stp	q28, q29, [sp, #448]
	stp	q30, q31, [sp, #480]
	mrs	x9, fpcr
	mrs	x10, fpsr
	str	x9, [sp, #512]
	str	x10, [sp, #520]
kclf_tramp_ptr_slot:			/* patched: x19 = parameter block */
	movz	x19, #0
	movk	x19, #0, lsl #16
	movk	x19, #0, lsl #32
	movk	x19, #0, lsl #48
	ldr	w9, [x19, #KCLF_P_MANUAL]
	cbnz	w9, .Lmanual

	add	x0, x19, #KCLF_P_PATH
	ldr	w1, [x19, #KCLF_P_FLAGS]
	ldr	x2, [x19, #KCLF_P_CALLER]
	ldr	x16, [x19, #KCLF_P_FN]
	blr	x16
	str	x0, [x19, #KCLF_P_HANDLE]
	cbnz	x0, 2f

	/* loader failed: collect the dlerror() pointer for the kernel to read */
	ldr	x16, [x19, #KCLF_P_DLERROR]
	cbz	x16, 3f
	blr	x16
	str	x0, [x19, #KCLF_P_ERRPTR]
	b	3f
2:
	/* optional fire-and-forget mode: undo the persistent linker record */
	ldr	w3, [x19, #KCLF_P_UNLOAD]
	cbz	w3, 3f
	ldr	x16, [x19, #KCLF_P_DLCLOSE]
	cbz	x16, 3f
	ldr	x0, [x19, #KCLF_P_HANDLE]
	blr	x16
	mov	x10, x0
	b	4f
3:
	mov	x10, #0
	b	4f

.Lmanual:
	/* No bionic loader API: imported IFUNC resolvers, then validated ELF calls.
	 * x19-x21 are callee-saved; the interrupted values live in kernel pt_regs. */
	ldr	x20, [x19, #KCLF_P_IFUNCV]
	ldr	x21, [x19, #KCLF_P_IFUNCN]
.Lifunc_next:
	cbz	x21, .Lprotect_begin
	ldr	x16, [x20]
	ldr	x0, [x19, #(KCLF_P_IFARG + 8)]
	mov	x9, #0x4000000000000000
	orr	x0, x0, x9
	add	x1, x19, #KCLF_P_IFARG
	blr	x16
	cbz	x0, .Lifunc_error
	tst	x0, #3
	b.ne	.Lifunc_error
	ldr	x9, [x20, #8]
	ldr	x10, [x20, #16]
	add	x0, x0, x10
	str	x0, [x9]
	add	x20, x20, #24
	sub	x21, x21, #1
	b	.Lifunc_next
.Lprotect_begin:
	ldr	x20, [x19, #KCLF_P_PROTV]
	ldr	x21, [x19, #KCLF_P_PROTN]
.Lprotect_next:
	cbz	x21, .Linit_begin
	ldp	x0, x1, [x20], #16
	mov	x2, #1
	mov	x8, #226	/* __NR_mprotect, not libc mprotect/syscall */
	svc	#0
	cbnz	x0, .Lmanual_error
	sub	x21, x21, #1
	b	.Lprotect_next
.Lifunc_error:
	mov	x0, #-8	/* ENOEXEC: invalid resolver result */
.Lmanual_error:
	str	xzr, [x19, #KCLF_P_HANDLE]
	mov	x10, x0
	b	4f
.Linit_begin:
	ldr	x20, [x19, #KCLF_P_INITV]
	ldr	x21, [x19, #KCLF_P_INITN]
.Linit_next:
	cbz	x21, .Lfini_begin
	ldr	x16, [x20], #8
	mov	x0, #0
	mov	x1, #0
	mov	x2, #0
	blr	x16
	sub	x21, x21, #1
	b	.Linit_next
.Lfini_begin:
	ldr	x20, [x19, #KCLF_P_FINIV]
	ldr	x21, [x19, #KCLF_P_FININ]
.Lfini_next:
	cbz	x21, .Lmanual_done
	ldr	x16, [x20], #8
	blr	x16
	sub	x21, x21, #1
	b	.Lfini_next
.Lmanual_done:
	mov	x10, #0
4:
    /* keep results only in registers while the used parameter region is wiped */
	ldr	x1, [x19, #KCLF_P_HANDLE]
	ldr	x2, [x19, #KCLF_P_ERRPTR]
	ldr	x9, [x19, #KCLF_P_COOKIE]
	mov	x3, x19
	ldr	x4, [x19, #KCLF_P_USED]
	add	x4, x19, x4
5:
	stp	xzr, xzr, [x3], #16
	cmp	x3, x4
	b.lo	5b

	mov	x0, x9
	mov	x3, x10
	ldr	x11, [sp, #512]
	ldr	x12, [sp, #520]
	msr	fpcr, x11
	msr	fpsr, x12
	ldp	q0, q1, [sp, #0]
	ldp	q2, q3, [sp, #32]
	ldp	q4, q5, [sp, #64]
	ldp	q6, q7, [sp, #96]
	ldp	q8, q9, [sp, #128]
	ldp	q10, q11, [sp, #160]
	ldp	q12, q13, [sp, #192]
	ldp	q14, q15, [sp, #224]
	ldp	q16, q17, [sp, #256]
	ldp	q18, q19, [sp, #288]
	ldp	q20, q21, [sp, #320]
	ldp	q22, q23, [sp, #352]
	ldp	q24, q25, [sp, #384]
	ldp	q26, q27, [sp, #416]
	ldp	q28, q29, [sp, #448]
	ldp	q30, q31, [sp, #480]
	add	sp, sp, #528
	mov	x8, #KCLF_COMPLETION_NR
	svc	#0
kclf_tramp_return:
6:
	b	6b
kclf_tramp_end:
