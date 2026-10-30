/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * KCLF EL0 trampoline generator.
 *
 * The trampoline is no longer a fixed blob copied from .text: every request
 * emits a fresh AArch64 program with a random register assignment, a random
 * FPSIMD save/restore permutation, random filler instructions and a random
 * entry/completion position inside the code page.  A detector that compares
 * the executed code against one shipped reference therefore has nothing to
 * match, and neither the entry nor the completion offset is predictable.
 *
 * The generated program has a single completion syscall site.  Its syscall
 * number is read from the private parameter page (xored with a per-request
 * key), so the code carries no literal syscall number.  If the target's
 * seccomp policy converts that attempt into a signal, the program simply tries
 * the next entry from the list; after the last one it restores the original
 * register file from the private page and returns to the interrupted PC.
 *
 * The recovery marker is not a fixed magic value: the kernel stores a random
 * 64-bit token in the private page and the program copies it into the bail
 * slot.  A scanner therefore cannot recognize the generated code (or the
 * mapping it runs from) by an embedded "KCLF" tag.
 */
#ifndef _KCLF_CODEGEN_H_
#define _KCLF_CODEGEN_H_

#ifdef KCLF_CODEGEN_HOST
#include <stdint.h>
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
#else
#include <ktypes.h>
#endif

/* private parameter page, relative to param_addr + page_size */
#define KCLF_PV_SAVED 0x000 /* u64[31]: x0..x30, then sp, pc, nzcv */
#define KCLF_PV_SP 0x0f8
#define KCLF_PV_PC 0x100
#define KCLF_PV_NZCV 0x108
#define KCLF_PV_BAIL 0x110 /* written by the EL0 bail-out path */
#define KCLF_PV_NRKEY 0x118 /* u32 xor key for the syscall list */
#define KCLF_PV_NRCNT 0x11c /* u32 number of completion attempts */
#define KCLF_PV_NRS 0x120 /* u32[16] ciphered syscall numbers, ends at 0x160 */
#define KCLF_PV_NRS_MAX 16
#define KCLF_PV_HANDLE 0x160 /* loader result handed to the kernel */
#define KCLF_PV_ERRPTR 0x168
#define KCLF_PV_RC 0x170
#define KCLF_PV_BAILTOK 0x178 /* per-request random token, copied to BAIL */
#define KCLF_PV_MPROT 0x180 /* u32 ciphered __NR_mprotect (IFUNC RELRO pass) */
#define KCLF_PV_SIZE 0x188

#define KCLF_TRAMP_FRAME 528 /* 16 q pairs + fpcr/fpsr */

struct kclf_prog
{
    u32 entry_off; /* entry point offset inside the code page */
    u32 compl_off; /* completion resume PC offset (svc + 4) */
    u32 length; /* emitted bytes, starting at entry_off - 4 */
};

/*
 * Fill @page (which must be @page_size bytes) with a generated program for
 * @param_addr.  @seed must be unpredictable per request; the same seed always
 * produces the same bytes, which is only used by the host-side generator test.
 * Returns 0 on success.
 */
int kclf_prog_build(u8 *page, int page_size, u64 param_addr, u64 seed, struct kclf_prog *out);

#endif
