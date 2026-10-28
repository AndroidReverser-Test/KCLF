#!/usr/bin/env python3
"""Exercise actual runtime compatibility selection with mock kernel accessors.

Optional argument: a saved device vmlinux BTF blob. This is a host test, not
a substitute for booting any of the tested kernel-version labels.
"""
from pathlib import Path
import subprocess
import sys
import tempfile

MODULE = Path(__file__).resolve().parents[1]
source = (MODULE / "kclf_compat.c").read_text()
implementation = source[source.index("int kclf_regs_size;"):]
PRELUDE = r'''
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "kclf_btf.h"
#define VERSION(a,b,c) (((a) << 16) | ((b) << 8) | (c))
#define logki(...) ((void)0)
struct mm_struct { int unused; } target_mm;
struct task_struct { unsigned char bytes[16384]; } task;
#define current (&task)
static unsigned int kver;
static int kclf_mm_off = -1, gets, puts_count;
static unsigned char *btf;
static size_t btf_len;
static struct mm_struct *fake_get(struct task_struct *p) { assert(p == current); gets++; return &target_mm; }
static void fake_put(struct mm_struct *mm) { assert(mm == &target_mm); puts_count++; }
static void fake_lock(void *p) { (void)p; }
static void fake_mmap_lock(struct mm_struct *p) { (void)p; }
static struct {
    struct mm_struct *(*get_task_mm)(struct task_struct *);
    void (*mmput_async)(struct mm_struct *);
    void (*down_read)(void *), (*up_read)(void *);
    void (*mmap_read_lock)(struct mm_struct *), (*mmap_read_unlock)(struct mm_struct *);
    void *find_vma;
} kclf_ks = {fake_get, fake_put, fake_lock, fake_lock, NULL, NULL, (void *)1};
static unsigned long kclf_lookup(const char *name) {
    if (!btf) return 0;
    if (!strcmp(name, "__start_BTF")) return (unsigned long)btf;
    if (!strcmp(name, "__stop_BTF")) return (unsigned long)(btf + btf_len);
    return 0;
}
'''
MAIN = r'''
static void reset(unsigned int version) {
    kver = version;
    kclf_mm_off = kclf_vma_start_off = kclf_vma_end_off = kclf_mmap_lock_off = -1;
    kclf_btf_ok = kclf_regs_size = kclf_vma_direct = kclf_wake_supported = 0;
    kclf_ks.down_read = kclf_ks.up_read = fake_lock;
    kclf_ks.mmap_read_lock = kclf_ks.mmap_read_unlock = NULL;
    kclf_ks.find_vma = (void *)1;
    gets = puts_count = 0;
}
int main(int argc, char **argv) {
    const unsigned int versions[] = { VERSION(5,0,0), VERSION(5,4,0), VERSION(5,7,0), VERSION(5,8,0),
        VERSION(5,10,66), VERSION(5,11,0), VERSION(5,15,0), VERSION(6,1,0), VERSION(6,6,0), VERSION(6,12,0) };
    for (unsigned int i = 0; i < sizeof(versions) / sizeof(versions[0]); i++) {
        reset(versions[i]);
        assert(!kclf_compat_init());
        assert(!kclf_btf_ok && !kclf_vma_direct && !kclf_regs_size && kclf_mm_off == -1);
        assert(kclf_wake_supported == (kver >= VERSION(5,8,0)));
        assert(kclf_task_mm(current) == &target_mm);
        assert(gets == puts_count && gets > 0);
    }
    puts("5.0/5.4/5.7/5.8/5.10/5.11/5.15/6.1/6.6/6.12 selection: PASS (mock versions, not devices)");
    struct {
        struct kclf_btf_header h;
        char strings[4];
    } empty = { .h = {.magic=0xeb9f, .version=1, .hdr_len=24, .str_len=4} };
    btf = (void *)&empty; btf_len = sizeof(empty);
    reset(VERSION(6,1,0));
    assert(!kclf_compat_init());
    assert(kclf_btf_ok && !kclf_vma_direct && !kclf_regs_size && kclf_mm_off == -1);
    assert(gets == puts_count);
    puts("partial BTF uses accessor/procfs/wrapper fallbacks independently: PASS");
    if (argc == 2) {
        FILE *f = fopen(argv[1], "rb");
        long size;
        struct kclf_btf b;
        struct mm_struct *mm = &target_mm;
        int offset;
        assert(f && !fseek(f, 0, SEEK_END));
        size = ftell(f);
        assert(size > 0 && size < 64 * 1024 * 1024);
        rewind(f);
        btf = malloc((size_t)size); btf_len = (size_t)size;
        assert(btf && fread(btf, 1, btf_len, f) == btf_len);
        fclose(f);
        assert(!kclf_btf_open(&b, btf, btf_len));
        offset = kclf_btf_member_range(&b, "task_struct", "mm", 8, 8);
        assert(offset > 0 && offset < (int)sizeof(task) - 8);
        memcpy(task.bytes + offset, &mm, sizeof(mm));
        reset(VERSION(6,1,134));
        assert(!kclf_compat_init() && kclf_btf_ok && kclf_vma_direct && kclf_regs_size == 336);
        assert(kclf_mm_off == offset && gets == puts_count);
        kclf_mmap_read_lock(&target_mm); kclf_mmap_read_unlock(&target_mm);
        reset(VERSION(6,1,134));
        kclf_ks.down_read = NULL;
        assert(!kclf_compat_init() && !kclf_vma_direct && kclf_regs_size == 336);
        assert(gets == puts_count);
        reset(VERSION(6,1,134));
        kclf_ks.find_vma = NULL;
        assert(!kclf_compat_init() && !kclf_vma_direct);
        reset(VERSION(6,1,134));
        memset(task.bytes + offset, 0, sizeof(mm));
        assert(!kclf_compat_init() && kclf_mm_off == -1);
        assert(kclf_task_mm(current) == &target_mm && gets == puts_count);
        free(btf);
        puts("saved 6.1 BTF: real layout selection, missing-symbol fallback, balanced mm references: PASS");
    }
    kclf_mmap_lock_off = -1;
    kclf_ks.mmap_read_lock = kclf_ks.mmap_read_unlock = fake_mmap_lock;
    kclf_mmap_read_lock(&target_mm); kclf_mmap_read_unlock(&target_mm);
    char out[4];
    assert(kclf_scnprintf(out, sizeof(out), "%s", "abcdef") == 3 && !strcmp(out,"abc"));
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix="kclf-compat-") as directory:
    test = Path(directory) / "test.c"
    exe = Path(directory) / "test"
    test.write_text(PRELUDE + implementation + MAIN)
    subprocess.run(["gcc", "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-g", "-fsanitize=address,undefined",
                    "-I", str(MODULE), str(test), "-o", str(exe)], check=True)
    subprocess.run([str(exe)] + sys.argv[1:], check=True)
