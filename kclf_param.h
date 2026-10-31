/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * KCLF shadow loading backend - EL0 payload ABI.
 *
 * The parameter block lives in a private anonymous page inside the target
 * address space. Offsets below are shared by the kernel side (kclf_exec.c) and
 * by the position independent trampoline emitted by kclf_codegen.c; both
 * include this header, so the layout can only change in one place.
 *
 * The trampoline scrubs the whole ABI page before it finishes; results and the
 * randomized private page (kclf_codegen.h struct kclf_priv_layout) live in a
 * separate mapping.  Completion never issues a syscall: the program restores
 * the original register file in EL0, writes a per-request random token into the
 * private page and branches back to the interrupted PC.  The kernel notices the
 * token on the thread's next watched syscall or from a controller poll.  The
 * ABI page therefore never carries a syscall number, cookie, completion
 * function or stack slot an observer could anchor on.
 */
#ifndef _KCLF_PARAM_H_
#define _KCLF_PARAM_H_

/* parameter block, one page */
#define KCLF_P_FN 0x00 /* u64: resolved loader entry (dlopen)          */
#define KCLF_P_DLERROR 0x08 /* u64: resolved dlerror entry, 0 if absent     */
#define KCLF_P_CALLER 0x10 /* u64: caller address used for namespace bind  */
#define KCLF_P_HANDLE 0x18 /* u64: scratch for the loader result           */
#define KCLF_P_FLAGS 0x28 /* u32: dlopen flags                            */
#define KCLF_P_DLCLOSE 0x30 /* u64: resolved dlclose entry, 0 if absent     */
#define KCLF_P_UNLOAD 0x38 /* u32: call dlclose after a successful load    */
#define KCLF_P_PATH 0x40 /* char[256]: library path in target namespace  */
#define KCLF_P_ERRPTR 0x140 /* u64: dlerror() string, read by the kernel    */
#define KCLF_P_MANUAL 0x148 /* u32: manual initializer/finalizer dispatch */
#define KCLF_P_INITV 0x150 /* u64: validated constructor vector */
#define KCLF_P_INITN 0x158 /* u64: constructor count */
#define KCLF_P_FINIV 0x160 /* u64: validated finalizer vector (already reversed) */
#define KCLF_P_FININ 0x168 /* u64: finalizer count */
#define KCLF_P_IFUNCV 0x178 /* resolver, destination, addend triples */
#define KCLF_P_IFUNCN 0x180
#define KCLF_P_IFARG 0x188 /* AArch64 __ifunc_arg_t: size, hwcap, hwcap2 */
#define KCLF_P_SIZE 0x1c0

#define KCLF_PATH_MAX 256
#define KCLF_ERR_MAX 256

#endif

