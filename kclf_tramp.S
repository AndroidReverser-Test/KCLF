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
 *   - the whole parameter page (including the library path and the cookie) is
 *     zeroed before the completion trap;
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

kclf_tramp_start:
	b	1f			/* restart pad: regs->pc -= 4 lands here */
1:
	bti	c			/* harmless when BTI is disabled */
kclf_tramp_ptr_slot:			/* patched: x19 = parameter block */
	movz	x19, #0
	movk	x19, #0, lsl #16
	movk	x19, #0, lsl #32
	movk	x19, #0, lsl #48

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
4:
	/* keep results only in registers while the page is wiped */
	ldr	x1, [x19, #KCLF_P_HANDLE]
	ldr	x2, [x19, #KCLF_P_ERRPTR]
	ldr	x9, [x19, #KCLF_P_COOKIE]
	mov	x3, x19
	add	x4, x19, #KCLF_P_SIZE
5:
	stp	xzr, xzr, [x3], #16
	cmp	x3, x4
	b.lo	5b

	mov	x0, x9
	mov	x3, x10
	mov	x8, #KCLF_COMPLETION_NR
	svc	#0
6:
	b	6b
kclf_tramp_end:
