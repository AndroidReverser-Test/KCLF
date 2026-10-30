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
 * Completion is deliberately *not* a syscall instruction inside the generated
 * page.  The program tail calls a real libc entry (usleep(), or open() as a
 * second candidate) with a random cookie in the caller-saved x6/x7 scratch
 * registers.  At the kernel-visible svc the instruction pointer and the link
 * register therefore belong to libc, the syscall arguments are the harmless
 * ones the libc wrapper itself computes, and the syscall number is the normal
 * one for that wrapper.  A seccomp observer cannot see a syscall whose resume
 * PC lies in the transient anonymous page, which removes the 1.4.3
 * "completion tail" event anchor entirely.
 *
 * The private parameter page layout is randomized per request: every field
 * (saved register file, FPSIMD file, completion function table, cookie, keys,
 * result slots and the EL0 recovery marker) is placed at an independent random
 * offset.  The generated program carries the offsets as immediates, so neither
 * a fixed ABI layout nor the 1.4.3 register-file/bail-token structure is
 * available to a scanner.
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

#define KCLF_COMPL_MAX 3
#define KCLF_SAVED_WORDS 34 /* x0..x30, sp, pc, nzcv */

/*
 * Private parameter page layout.  Filled by the kernel for each request and
 * consumed by both sides.  All offsets are byte offsets from the start of the
 * private page and stay below one 4 KiB layout window even on 16/64 KiB page
 * kernels; the rest of the page is random filler.
 */
struct kclf_priv_layout
{
    u16 saved; /* u64[34]: x0..x30, sp, pc, nzcv */
    u16 qregs; /* q0..q31, 16-byte aligned, 512 bytes */
    u16 fpcr; /* u64 */
    u16 fpsr; /* u64 */
    u16 bail; /* u64 written by the EL0 recovery path */
    u16 bailtok; /* u64 per-request random token */
    u16 nrkey; /* u32 */
    u16 nrcnt; /* u32 number of completion attempts */
    u16 nrs; /* u32[16], ciphered completion syscall numbers */
    u16 handle; /* u64 loader result */
    u16 errptr; /* u64 loader error string pointer */
    u16 rc; /* u64 dlclose / negative errno */
    u16 cookie; /* u64 completion cookie */
    u16 mprotfn; /* u64 resolved libc mprotect entry */
    u16 complfn[KCLF_COMPL_MAX]; /* u64 resolved libc completion entries */
    u16 complarg0[KCLF_COMPL_MAX]; /* u64 first argument for each entry */
    u16 path; /* 64-byte path for the open() candidate */
    u16 end; /* first byte after the highest placed field */
};

#define KCLF_SAVED_SP (31 * 8)
#define KCLF_SAVED_PC (32 * 8)
#define KCLF_SAVED_NZCV (33 * 8)
#define KCLF_SAVED_BYTES (KCLF_SAVED_WORDS * 8)
#define KCLF_QREGS_BYTES (32 * 16)
#define KCLF_COMPL_PATH 64
/* Headroom reserved at the top of the transient stack block.  The generated
 * program keeps its private-page pointer here across libc calls (the callee's
 * frame starts below SP, so this slot is never touched by it). */
#define KCLF_STACK_SLOT 0x80

struct kclf_prog
{
    u32 entry_off; /* entry point offset inside the code page */
    u32 length; /* emitted bytes, starting at entry_off - 4 */
};

/*
 * Fill @page (which must be @page_size bytes) with a generated program for
 * @param_addr / @priv_addr.  @pl describes the randomized private-page layout,
 * @compl_count is the number of resolved libc completion entries in @pl.
 * @seed must be unpredictable per request; the same seed always produces the
 * same bytes, which is only used by the host-side generator test.
 * Returns 0 on success.
 */
int kclf_prog_build(u8 *page, int page_size, u64 param_addr, u64 priv_addr,
                    const struct kclf_priv_layout *pl, int compl_count, u64 seed,
                    struct kclf_prog *out);

#endif
