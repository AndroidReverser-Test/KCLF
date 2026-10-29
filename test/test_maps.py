#!/usr/bin/env python3
"""Compile the actual VMA iterator with mocked kernel accessors under ASan/UBSan."""
from pathlib import Path
import subprocess
import tempfile

MODULE = Path(__file__).resolve().parents[1]
execution = (MODULE / "kclf_exec.c").read_text()
iterator = execution[execution.index("struct kclf_vma\n"):execution.index("int kclf_walk_vmas(")]
PRELUDE = r'''
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "kclf_maps.h"
typedef uint64_t u64;
typedef int64_t loff_t;
#define KCLF_O_RDONLY 0
#define KCLF_USER_MAX (1ULL << 48)
#define KCLF_MAX_VMA 16384
struct mm_struct { int unused; } mm;
struct vm_area_struct { u64 start, end; } vmas[] = {{0x1000, 0x2000}, {0x3000, 0x4000}, {0x5000, 0x6000}};
struct file { int unused; } file;
static int kclf_vma_direct, kclf_vma_start_off, kclf_vma_end_off = 8;
static int locks, opened, closed, io_error, open_error, copy_error;
static size_t chunk = 512;
static char text[8192], scratch[512];
static int kclf_is_err(const void *p) { return (uintptr_t)p >= (uintptr_t)-4095; }
static struct file *fake_open(const char *path, int flags, unsigned short mode) {
    assert(!strcmp(path, "/proc/thread-self/maps") && !flags && !mode);
    if (open_error) return (void *)(intptr_t)open_error;
    opened++;
    return &file;
}
static void fake_close(struct file *f) { assert(f == &file); closed++; }
static long fake_read(struct file *f, char *to, unsigned long count, loff_t *pos) {
    assert(!locks && f == &file && to == scratch && count <= sizeof(scratch));
    if (io_error) return io_error;
    size_t n = strlen(text) - (size_t)*pos;
    if (n > count) n = count;
    if (n > chunk) n = chunk;
    memcpy(to, text + *pos, n);
    *pos += n;
    return (long)n;
}
static int kclf_urds(u64 addr, void *buf, int len) {
    assert(!locks && addr == (uintptr_t)scratch && len >= 0 && len <= 512);
    if (copy_error) return copy_error;
    memcpy(buf, scratch, (size_t)len);
    return 0;
}
static void kclf_mmap_read_lock(struct mm_struct *m) { assert(m == &mm); locks++; }
static void kclf_mmap_read_unlock(struct mm_struct *m) { assert(m == &mm && locks == 1); locks--; }
static struct vm_area_struct *fake_find(struct mm_struct *m, unsigned long addr) {
    assert(m == &mm && locks == 1);
    for (unsigned int i = 0; i < 3; i++) if (vmas[i].end > addr) return &vmas[i];
    return NULL;
}
static struct {
    struct file *(*filp_open)(const char *, int, unsigned short);
    long (*vfs_read)(struct file *, char *, unsigned long, loff_t *);
    void (*fput)(struct file *);
    struct vm_area_struct *(*find_vma)(struct mm_struct *, unsigned long);
} kclf_ks = {fake_open, fake_read, fake_close, fake_find};
'''
MAIN = r'''
int main(void) {
    struct kclf_vma_iter it;
    struct kclf_vma v;
    u64 first, last;
    assert(!kclf_maps_range("0-1000 r--p", KCLF_USER_MAX, &first, &last));
    assert(!kclf_maps_range("A000-b000 r-xp", KCLF_USER_MAX, &first, &last));
    assert(first == 0xa000 && last == 0xb000);
    const char *bad[] = {"", "1- ", "-2 ", "1-1 ", "2-1 ", "1-2x", "1-2", "10000000000000000-2 ",
                         "1-ffffffffffffffff ", "1:2 ", "1-1000000000001 "};
    for (unsigned int i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
        assert(kclf_maps_range(bad[i], KCLF_USER_MAX, &first, &last));
    puts("maps hex/range/overflow/delimiter checks: PASS");
    strcpy(text, "1000-2000 r-xp 00000000 00:00 0 ");
    size_t n = strlen(text);
    memset(text + n, 'x', 3000); /* path longer than every buffer */
    strcpy(text + n + 3000, "\n3000-4000 rw-p 0 00:00 0\n5000-6000 ---p 0 00:00 0"); /* no final newline */
    const size_t chunks[] = {1, 2, 7, 31, 47, 48, 511, 512};
    for (unsigned int c = 0; c < sizeof(chunks) / sizeof(chunks[0]); c++) {
        chunk = chunks[c];
        assert(!kclf_vma_iter_open(&it, &mm, (uintptr_t)scratch));
        for (unsigned int i = 0; i < 3; i++) {
            assert(kclf_vma_next(&it, &v) == 1);
            assert(v.start == vmas[i].start && v.end == vmas[i].end);
        }
        assert(!kclf_vma_next(&it, &v));
        kclf_vma_iter_close(&it);
        assert(opened == closed);
        assert(!kclf_vma_at(&mm, 0x2800, &v, (uintptr_t)scratch) && v.start == 0x3000);
        assert(kclf_vma_at(&mm, 0x7000, &v, (uintptr_t)scratch) == -ENOENT);
    }
    puts("actual proc iterator: short reads, split lines, long paths, EOF, holes: PASS");
    io_error = -EIO;
    assert(kclf_vma_at(&mm, 0, &v, (uintptr_t)scratch) == -EIO);
    io_error = 0; copy_error = -EFAULT;
    assert(kclf_vma_at(&mm, 0, &v, (uintptr_t)scratch) == -EFAULT);
    copy_error = 0; open_error = -EACCES;
    assert(kclf_vma_at(&mm, 0, &v, (uintptr_t)scratch) == -EACCES);
    open_error = 0;
    strcpy(text, "invalid\n");
    assert(kclf_vma_at(&mm, 0, &v, (uintptr_t)scratch) == -EINVAL);
    text[0] = 0;
    assert(kclf_vma_at(&mm, 0, &v, (uintptr_t)scratch) == -ENOENT);
    assert(opened == closed);
    puts("maps errors remain errors, never mistaken for successful reclamation: PASS");
    kclf_vma_direct = 1;
    assert(!kclf_vma_iter_open(&it, &mm, 0));
    for (unsigned int i = 0; i < 3; i++) {
        assert(kclf_vma_next(&it, &v) == 1 && !locks);
        assert(v.start == vmas[i].start && v.end == vmas[i].end);
    }
    assert(!kclf_vma_next(&it, &v) && !locks);
    kclf_vma_iter_close(&it);
    assert(!kclf_vma_at(&mm, 0x3800, &v, 0) && v.start == 0x3000);
    assert(kclf_vma_at(&mm, 0x8000, &v, 0) == -ENOENT);
    vmas[0].end = KCLF_USER_MAX + 1;
    assert(kclf_vma_at(&mm, 0, &v, 0) == -EFAULT && !locks);
    assert(opened == closed);
    puts("actual BTF/locked iterator: snapshots and lock balance: PASS");
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix="kclf-maps-") as directory:
    source = Path(directory) / "test.c"
    executable = Path(directory) / "test"
    source.write_text(PRELUDE + iterator + MAIN)
    subprocess.run(["gcc", "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-g",
                    "-fsanitize=address,undefined", "-I", str(MODULE), str(source), "-o", str(executable)], check=True)
    subprocess.run([str(executable)], check=True)
