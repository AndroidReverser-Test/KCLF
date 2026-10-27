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
int kclf_vma_start_off = 0;
int kclf_vma_end_off = 8;
int kclf_mmap_lock_off = -1;

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
    int off;

    /* Supported ABI family, not a promise for every vendor configuration. */
    if (kver < VERSION(5, 0, 0) || kver >= VERSION(7, 0, 0)) return -EOPNOTSUPP;
    if (start && end) {
        const struct kclf_btf_type *t;
        if (end <= start || end - start > 64 * 1024 * 1024 || kclf_btf_open(&b, (const void *)start, end - start))
            return -EOPNOTSUPP;
        kclf_mm_off = kclf_btf_member_range(&b, "task_struct", "mm", 8, 8);
        kclf_vma_start_off = kclf_btf_member_range(&b, "vm_area_struct", "vm_start", 8, 8);
        kclf_vma_end_off = kclf_btf_member_range(&b, "vm_area_struct", "vm_end", 8, 8);
        if (kclf_mm_off <= 0 || kclf_vma_start_off < 0 || kclf_vma_end_off < 0 ||
            kclf_vma_start_off == kclf_vma_end_off)
            return -EOPNOTSUPP;
        t = kclf_btf_find(&b, "rw_semaphore", 0);
        if (!t || t->size < 16 || t->size > 512) return -EOPNOTSUPP;
        kclf_mmap_lock_off = kclf_btf_member_range(&b, "mm_struct", "mmap_lock", t->size, 8);
        if (kclf_mmap_lock_off < 0) kclf_mmap_lock_off = kclf_btf_member_range(&b, "mm_struct", "mmap_sem", t->size, 8);
        if (kclf_mmap_lock_off < 0) return -EOPNOTSUPP;
        t = kclf_btf_find(&b, "pt_regs", 0);
        if (!t || t->size < 288 || t->size > 512 || (t->size & 15) ||
            kclf_btf_member_offset(&b, "pt_regs", "regs") != 0 || kclf_btf_member_offset(&b, "pt_regs", "sp") != 248 ||
            kclf_btf_member_offset(&b, "pt_regs", "pc") != 256 ||
            kclf_btf_member_offset(&b, "pt_regs", "pstate") != 264 ||
            kclf_btf_member_offset(&b, "pt_regs", "orig_x0") != 272 ||
            kclf_btf_member_offset(&b, "pt_regs", "syscallno") != 280)
            return -EOPNOTSUPP;
        kclf_regs_size = t->size;
        kclf_btf_ok = 1;
    }
    if (kclf_mm_off <= 0) kclf_mm_off = task_struct_offset.mm_offset;
    if (kclf_mm_off <= 0 || kclf_mm_off > 0x4000 || (kclf_mm_off & 7)) return -EOPNOTSUPP;
    /* Verify even KP-supplied offsets against an accessor, never blind-scan
     * beyond an unknown task_struct allocation. */
    mm = kclf_ks.get_task_mm(current);
    if (!mm) return -ESRCH;
    off = kclf_task_mm(current) == mm;
    kclf_ks.mmput_async(mm);
    if (!off) return -EOPNOTSUPP;

    if (kclf_mmap_lock_off >= 0) {
        if (!kclf_ks.down_read || !kclf_ks.up_read) return -EOPNOTSUPP;
    } else if (!kclf_ks.mmap_read_lock || !kclf_ks.mmap_read_unlock) {
        logke("kclf: no BTF mmap_lock offset or callable mmap_read_lock pair\n");
        return -EOPNOTSUPP;
    }
    logki("kclf: kernel=%x btf=%d mm=%d mmap_lock=%d regs=%d\n", kver, kclf_btf_ok, kclf_mm_off, kclf_mmap_lock_off,
          kclf_regs_size);
    return 0;
}
