/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * KCLF shadow loading backend - EL0 payload ABI.
 *
 * The parameter block lives in a private anonymous page inside the target
 * address space. Offsets below are shared by the kernel side (kclf_exec.c) and
 * by the position independent trampoline (kclf_tramp.S); both include this
 * header, so the layout can only change in one place.
 *
 * The trampoline scrubs the used region (rounded to 16 bytes) before the
 * completion trap; the unused page tail is untouched. Results are
 * handed to the kernel through x1 (loader handle), x2 (dlerror string pointer)
 * and x3 (dlclose return code), never through persistent target memory.
 */
#ifndef _KCLF_PARAM_H_
#define _KCLF_PARAM_H_

/* parameter block, one page */
#define KCLF_P_FN 0x00 /* u64: resolved loader entry (dlopen)          */
#define KCLF_P_DLERROR 0x08 /* u64: resolved dlerror entry, 0 if absent     */
#define KCLF_P_CALLER 0x10 /* u64: caller address used for namespace bind  */
#define KCLF_P_HANDLE 0x18 /* u64: scratch for the loader result           */
#define KCLF_P_COOKIE 0x20 /* u64: completion cookie, consumed by kernel   */
#define KCLF_P_FLAGS 0x28 /* u32: dlopen flags                            */
#define KCLF_P_DLCLOSE 0x30 /* u64: resolved dlclose entry, 0 if absent     */
#define KCLF_P_UNLOAD 0x38 /* u32: call dlclose after a successful load    */
#define KCLF_P_PATH 0x40 /* char[256]: library path in target namespace  */
#define KCLF_P_ERRPTR 0x140 /* u64: dlerror() string, read by the kernel    */
#define KCLF_P_SIZE 0x148

#define KCLF_PATH_MAX 256
#define KCLF_ERR_MAX 256

/* completion trap: getpid with a magic x0, consumed by the kernel hook */
#define KCLF_COMPLETION_NR 172

#endif
