/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <kclf_internal.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <common.h>
#include <log.h>
#include <uapi/asm-generic/errno.h>
#include "kclf_btf.h"

int kclf_regs_size;
int kclf_btf_ok;
int kclf_vma_start_off = -1;
int kclf_vma_end_off = -1;
int kclf_mmap_lock_off = -1;
int kclf_vma_direct;
int kclf_wake_supported;
u64 kclf_trace_mask, kclf_vector_mask;
const char *kclf_wake_abi = "version";

struct mm_struct *kclf_task_mm(struct task_struct *task)
{
    struct mm_struct *mm;

    if (!task) return 0;
    if (kclf_mm_off > 0)
        return __atomic_load_n((struct mm_struct **)((char *)task + kclf_mm_off), __ATOMIC_ACQUIRE);
    /* Older KP hosts do not discover task_struct.mm without BTF. Use the
     * kernel accessor instead of scanning an unknown task allocation. */
    mm = kclf_ks.get_task_mm(task);
    if (mm) kclf_ks.mmput_async(mm);
    return mm;
}

int kclf_scnprintf(char *out, int size, const char *fmt, ...)
{
    va_list ap;
    int n;

    if (size <= 0) return 0;
    va_start(ap, fmt);
    n = vsnprintf(out, (size_t)size, fmt, ap);
    va_end(ap);
    return n < 0 ? 0 : (n >= size ? size - 1 : n);
}

void kclf_mmap_read_lock(struct mm_struct *mm)
{
    if (kclf_mmap_lock_off >= 0)
        kclf_ks.down_read((char *)mm + kclf_mmap_lock_off);
    else
        kclf_ks.mmap_read_lock(mm);
}

void kclf_mmap_read_unlock(struct mm_struct *mm)
{
    if (kclf_mmap_lock_off >= 0)
        kclf_ks.up_read((char *)mm + kclf_mmap_lock_off);
    else
        kclf_ks.mmap_read_unlock(mm);
}

int kclf_compat_init(void)
{
    unsigned long start = kclf_lookup("__start_BTF");
    unsigned long end = kclf_lookup("__stop_BTF");
    struct kclf_btf b;
    struct mm_struct *mm;
    int valid, cancel_abi = 0;

#ifdef KCLF_TEST_NO_BTF
    start = end = 0; /* exercise accessor/procfs/wrapper fallback on a BTF kernel */
#endif

    /* Supported ABI family, not a promise for every vendor configuration. */
    if (kver < VERSION(5, 0, 0) || kver >= VERSION(7, 0, 0)) return -EOPNOTSUPP;
    /* Upstream 5.8 already has the integer TWA_SIGNAL ABI. Older bool
     * implementations only understand RESUME=1. Do not pass 2 to those. */
    kclf_wake_supported = kver >= VERSION(5, 8, 0);
    /* TIF_* are macros, not BTF data. arm64 lazy preemption moved UPROBE
     * from bit 4 to bit 5 in 6.16. Do not use the build host's old headers.
     * A vendor that backports this renumbering needs its own verified profile. */
    kclf_trace_mask = (1ULL << 8) | (1ULL << 12) | (1ULL << 21) |
                      (1ULL << (kver >= VERSION(6, 16, 0) ? 5 : 4));
    /* Bit 27 is reserved before SME; checking it unconditionally also covers
     * vendor SME backports. The generated code only preserves base FPSIMD. */
    kclf_vector_mask = (1ULL << 23) | (1ULL << 27);
    if (start && end) {
        const struct kclf_btf_type *t;
        int signal_abi;
        if (end <= start || end - start > 64 * 1024 * 1024 || kclf_btf_open(&b, (const void *)start, end - start))
            return -EOPNOTSUPP;
        signal_abi = kclf_btf_signal_abi(&b);
        if (signal_abi == -2) return -EOPNOTSUPP;
        if (signal_abi >= 0) {
            kclf_wake_supported = signal_abi;
            kclf_wake_abi = "btf";
        }
        cancel_abi = kclf_btf_cancel_abi(&b);
        kclf_mm_off = kclf_btf_member_range(&b, "task_struct", "mm", 8, 8);
        kclf_vma_start_off = kclf_btf_member_range(&b, "vm_area_struct", "vm_start", 8, 8);
        kclf_vma_end_off = kclf_btf_member_range(&b, "vm_area_struct", "vm_end", 8, 8);
        t = kclf_btf_find(&b, "rw_semaphore", 0);
        if (t && t->size >= 16 && t->size <= 512) {
            kclf_mmap_lock_off = kclf_btf_member_range(&b, "mm_struct", "mmap_lock", t->size, 8);
            if (kclf_mmap_lock_off < 0)
                kclf_mmap_lock_off = kclf_btf_member_range(&b, "mm_struct", "mmap_sem", t->size, 8);
        }
        t = kclf_btf_find(&b, "pt_regs", 0);
        if (t && (t->size < 288 || t->size > 512 || (t->size & 15) ||
            kclf_btf_member_offset(&b, "pt_regs", "regs") != 0 || kclf_btf_member_offset(&b, "pt_regs", "sp") != 248 ||
            kclf_btf_member_offset(&b, "pt_regs", "pc") != 256 ||
            kclf_btf_member_offset(&b, "pt_regs", "pstate") != 264 ||
            kclf_btf_member_offset(&b, "pt_regs", "orig_x0") != 272 ||
            kclf_btf_member_offset(&b, "pt_regs", "syscallno") != 280))
            return -EOPNOTSUPP;
        if (t) kclf_regs_size = t->size;
        t = kclf_btf_find(&b, "thread_info", 0);
        if (t && kclf_btf_member_range(&b, "thread_info", "flags", 8, 8) != 0)
            return -EOPNOTSUPP;
        kclf_btf_ok = 1;
    }
    if (!kclf_ks.task_work_cancel_match && !kclf_ks.task_work_cancel_func) {
        unsigned long cancel = kclf_lookup("task_work_cancel");
        if (cancel_abi == 2)
            kclf_ks.task_work_cancel_object = (typeof(kclf_ks.task_work_cancel_object))cancel;
        else if (cancel_abi == 1 || (!cancel_abi && kver < VERSION(5, 13, 0)))
            kclf_ks.task_work_cancel_func = (typeof(kclf_ks.task_work_cancel_func))cancel;
        /* After upstream 5.13 introduced cancel_match, missing both unambiguous
         * names is not evidence that the remaining symbol has the old ABI. */
        if (!kclf_ks.task_work_cancel_object && !kclf_ks.task_work_cancel_func) {
            logki("kclf: task_work_cancel ABI unavailable/unsupported\n");
            return -EOPNOTSUPP;
        }
    }
    /* Old hosts can export a shorter task_struct_offset table. Do not read
     * newer fields from that host object: no BTF means accessor-only mm. */
    if (kclf_mm_off <= 0 || kclf_mm_off > 0x4000 || (kclf_mm_off & 7)) kclf_mm_off = -1;
    /* Cross-check a BTF-derived offset against the kernel's own accessor. */
    mm = kclf_ks.get_task_mm(current);
    if (!mm) return -ESRCH;
    valid = kclf_mm_off > 0 && kclf_task_mm(current) == mm;
    kclf_ks.mmput_async(mm);
    if (!valid) kclf_mm_off = -1;

    /* With no verified VMA/lock layout, procfs provides a kernel-locked VMA
     * iterator. No mmap_sem offsets or rb-tree/maple-tree internals are guessed. */
    kclf_vma_direct = kclf_btf_ok && kclf_vma_start_off >= 0 && kclf_vma_end_off >= 0 &&
                      kclf_vma_start_off != kclf_vma_end_off && kclf_ks.find_vma &&
                      ((kclf_mmap_lock_off >= 0 && kclf_ks.down_read && kclf_ks.up_read) ||
                       (kclf_mmap_lock_off < 0 && kclf_ks.mmap_read_lock && kclf_ks.mmap_read_unlock));
    logki("kclf: kernel=%x btf=%d mm=%d mmap_lock=%d regs=%d vma=%s\n", kver, kclf_btf_ok, kclf_mm_off,
          kclf_mmap_lock_off, kclf_regs_size, kclf_vma_direct ? "locked" : "proc_maps");
    return 0;
}
