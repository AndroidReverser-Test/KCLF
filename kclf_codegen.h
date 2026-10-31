/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * KCLF EL0 trampoline generator.
 *
 * The trampoline is no longer a fixed blob copied from .text: every request
 * emits a fresh AArch64 program with a random register assignment, a random
 * FPSIMD save/restore permutation, random filler instructions and a random
 * entry position inside the code page.  A detector that compares the executed
 * code against one shipped reference therefore has nothing to match, and
 * neither the entry nor the shape of the tail is predictable.
 *
 * Completion is deliberately *not* a syscall and *not* a library call.  After
 * the payload work the program restores the interrupted thread's whole register
 * file in EL0, publishes a per-request random token in its private page and
 * branches back to the interrupted PC itself.  The kernel notices the token
 * when the thread enters an ordinary watched syscall, or from a controller poll
 * callback, and then tears the transient mapping down.
 *
 * Consequence for an observer: there is no completion syscall to trap, no
 * libc frame whose saved link register points into the transient code page, no
 * fixed call stub and no private-page pointer in a fixed stack slot.  The one
 * register the EL0 branch cannot restore is x16/IP0, which has to hold the
 * resume address; x16 is caller-saved scratch in the supported ABI.
 *
 * The private page layout is randomized per request: every field (saved
 * register file, FPSIMD file, completion token, result slots) is placed at an
 * independent random offset.  The generated program carries the offsets as
 * immediates.
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

#define KCLF_SAVED_WORDS 34 /* x0..x30, sp, pc, nzcv */

/*
 * Private page layout.  Filled by the kernel for each request and consumed by
 * both sides.  All offsets are byte offsets from the start of the private page
 * and stay below one 4 KiB layout window even on 16/64 KiB page kernels; the
 * rest of the page is random filler.
 */
struct kclf_priv_layout
{
    u16 saved; /* u64[34]: x0..x30, sp, pc, nzcv */
    u16 qregs; /* q0..q31, 16-byte aligned, 512 bytes */
    u16 fpcr; /* u64 */
    u16 fpsr; /* u64 */
    u16 done; /* u64 completion token written by the EL0 recovery path */
    u16 donetok; /* u64 per-request random token */
    u16 handle; /* u64 loader result */
    u16 errptr; /* u64 loader error string pointer */
    u16 rc; /* u64 dlclose / negative errno */
    u16 end; /* first byte after the highest placed field */
};

#define KCLF_SAVED_SP (31 * 8)
#define KCLF_SAVED_PC (32 * 8)
#define KCLF_SAVED_NZCV (33 * 8)
#define KCLF_SAVED_BYTES (KCLF_SAVED_WORDS * 8)
#define KCLF_QREGS_BYTES (32 * 16)

struct kclf_prog
{
    u32 entry_off; /* entry point offset inside the code page */
    u32 length; /* emitted bytes, starting at entry_off - 4 */
};

/*
 * Fill @page (which must be @page_size bytes) with a generated program for
 * @param_addr / @priv_addr.  @pl describes the randomized private-page layout.
 * @seed must be unpredictable per request; the same seed always produces the
 * same bytes, which is only used by the host-side generator test.
 * Returns 0 on success.
 */
int kclf_prog_build(u8 *page, int page_size, u64 param_addr, u64 priv_addr,
                    const struct kclf_priv_layout *pl, u64 seed, struct kclf_prog *out);

#endif
