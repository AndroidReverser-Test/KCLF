#!/usr/bin/env python3
"""Production tmpfs-copy and code-mapping fault tests (ASan/UBSan, no device)."""
from pathlib import Path
import subprocess
import tempfile

module = Path(__file__).resolve().parents[1]
backing = (module / "kclf_file.c").read_text()
backing = backing[backing.index("int kclf_tmp_path("):]
execution = (module / "kclf_exec.c").read_text()
mapping = execution[execution.index("long kclf_map_file_code("):execution.index("/* bounded, NUL terminated user string")]
manual = (module / "kclf_manual.c").read_text()
reap = manual[manual.index("void kclf_manual_reap("):manual.index("int kclf_manual_busy(")]
shutdown = manual[manual.index("int kclf_manual_shutdown("):]
status = manual[manual.index("int kclf_manual_status("):manual.index("int kclf_manual_shutdown(")]
prelude = r'''
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
typedef uint8_t u8;
typedef uint64_t u64;
#define KCLF_PATH_MAX 256
#define KCLF_O_RDONLY 0
#define KCLF_PROT_READ 1
#define KCLF_PROT_EXEC 4
#define KCLF_MAP_PRIVATE 2
struct file { int refs; } staged, original;
struct pid { int unused; } owner;
#define KM_IMAGES 3
#define KM_BUSY 1
#define KM_LIVE 2
#define KM_NODELETE_ELF 1
#define KM_NODELETE_EMUTLS 2
#define KM_NODELETE_TLS 4
struct kclf_manual_image {
    int state; struct file *backing; struct pid *owner; u64 mm;
    u64 id, map, length; unsigned refs; int original_tid, hdr_kept, nodelete;
    char path[KCLF_PATH_MAX];
} images[KM_IMAGES];
static int registry_depth, lock_failure, owner_puts;
static int lock_registry(void) { if (lock_failure) return 0; assert(!registry_depth); registry_depth++; return 1; }
static void unlock_registry(void) { assert(registry_depth == 1); registry_depth--; }
static int kclf_process_mm_alive(struct pid *p, u64 mm) { assert(p == &owner && registry_depth); return mm == 1; }
static void put_pid(struct pid *p) { assert(p == &owner); owner_puts++; }
static u8 data[200003], output[sizeof(data)], code[65536];
static int kclf_tmp_backing = 1;
static int creates, writes, puts_count, opens, maps, copies, unmaps;
static int create_error, write_error, map_error, copy_error, bad_write, bad_range;
static unsigned long quantum, max_write;
static int kclf_scnprintf(char *out, int len, const char *fmt, ...) {
    va_list ap; va_start(ap, fmt); int n = vsnprintf(out, (size_t)len, fmt, ap); va_end(ap);
    return n < len ? n : len - 1;
}
static struct file *create(const char *name, loff_t size, unsigned long flags) {
    assert(!strcmp(name, "kclf:payload.so") && size == sizeof(data) && !flags);
    creates++;
    if (create_error) return (void *)(intptr_t)create_error;
    assert(!staged.refs); staged.refs = 1; return &staged;
}
static long write_file(struct file *f, const void *bytes, unsigned long n, loff_t *pos) {
    assert(f == &staged && f->refs && n <= 65536 && *pos >= 0);
    assert(n <= sizeof(output) - (unsigned long)*pos);
    assert(bytes == data + *pos); writes++;
    if (n > max_write) max_write = n;
    if (write_error && writes == 2) return write_error;
    if (bad_write == 1) return 0;
    if (bad_write == 2) return (long)n + 1;
    if (bad_write == 3) return (long)n;
    if (n > quantum) n = quantum;
    memcpy(output + *pos, bytes, n); *pos += (loff_t)n;
    return (long)n;
}
static void put(struct file *f) { assert(f->refs > 0 && !registry_depth); f->refs--; puts_count++; }
static struct file *open_file(const char *path, int flags, unsigned short mode) {
    assert(!strcmp(path, "/ordinary/payload.so") && !flags && !mode);
    opens++; original.refs++; return &original;
}
static u64 map_file(void *file, u64 at, u64 size, unsigned long prot, unsigned long flags, u64 offset) {
    struct file *f = file;
    assert(f && f->refs && !at && size >= 4096 && size <= 65536);
    assert(prot == 5 && flags == 2 && !offset); maps++;
    return map_error ? (u64)(long)map_error : 0x100000;
}
static int unmap(unsigned long addr, size_t n) { assert(addr == 0x100000 && n); unmaps++; return 0; }
static int kclf_uwr_force(u64 at, const void *bytes, int n) {
    assert(at == 0x100000 && bytes == code && n >= 4096); copies++;
    return copy_error;
}
static int kclf_user_range(u64 at, u64 len) { assert(at && len); return !bad_range; }
static int kclf_is_err(const void *p) { return (uintptr_t)p >= (uintptr_t)-4095; }
static struct {
    struct file *(*shmem_file_setup)(const char *, loff_t, unsigned long);
    long (*kernel_write)(struct file *, const void *, unsigned long, loff_t *);
    void (*fput)(struct file *);
    struct file *(*filp_open)(const char *, int, unsigned short);
    u64 (*vm_mmap)(void *, u64, u64, unsigned long, unsigned long, u64);
    int (*vm_munmap)(unsigned long, size_t);
    void (*put_pid)(struct pid *);
} kclf_ks = { create, write_file, put, open_file, map_file, unmap, put_pid };
static void reset(void) {
    assert(!staged.refs && !original.refs);
    memset(output, 0, sizeof(output));
    creates = writes = puts_count = opens = maps = copies = unmaps = 0;
    create_error = write_error = map_error = copy_error = bad_write = bad_range = 0;
    quantum = 65536; max_write = 0; kclf_tmp_backing = 1;
    kclf_ks.shmem_file_setup = create; kclf_ks.kernel_write = write_file;
}
'''
main = r'''
int main(void) {
    struct file *f;
    u64 address;
    const char *path = "/data/local/tmp/nested/payload.so";
    for (unsigned i = 0; i < sizeof(data); i++) data[i] = (u8)(i * 13 + 7);
    assert(kclf_tmp_path(path) && !kclf_tmp_path(NULL));
    assert(!kclf_tmp_path("/data/local/tmpx/payload.so") && !kclf_tmp_path("/data/local/tmp/"));
    reset(); kclf_tmp_backing = 0;
    assert(kclf_stage_tmp_file(path, data, sizeof(data), &f) == -EOPNOTSUPP && !f && !creates);
    reset(); kclf_ks.kernel_write = NULL;
    assert(kclf_stage_tmp_file(path, data, sizeof(data), &f) == -EOPNOTSUPP && !f && !creates);
    reset(); create_error = -ENOMEM;
    assert(kclf_stage_tmp_file(path, data, sizeof(data), &f) == -ENOMEM && !f && !puts_count);
    for (int fault = 1; fault <= 3; fault++) {
        reset(); bad_write = fault;
        assert(kclf_stage_tmp_file(path, data, sizeof(data), &f) == -EIO && !f && puts_count == 1);
    }
    reset(); write_error = -ENOSPC;
    assert(kclf_stage_tmp_file(path, data, sizeof(data), &f) == -ENOSPC && !f && puts_count == 1);
    for (unsigned chunk = 17; chunk <= 65536; chunk = 65536) {
        reset(); quantum = chunk;
        assert(!kclf_stage_tmp_file(path, data, sizeof(data), &f));
        assert(f == &staged && f->refs == 1 && !puts_count && max_write == 65536);
        assert(!memcmp(data, output, sizeof(data)));
        for (u64 page = 4096; page <= 65536; page *= 4) {
            address = 0;
            assert(!kclf_map_file_code(f, path, code, page, &address) && address == 0x100000);
            assert(f->refs == 1 && !opens && !puts_count);
        }
        put(f);
        if (chunk == 65536) break;
    }
    reset();
    assert(!kclf_map_file_code(NULL, "/ordinary/payload.so", code, 4096, &address));
    assert(opens == 1 && puts_count == 1 && copies == 1 && !original.refs);
    for (int fault = 0; fault < 3; fault++) {
        reset(); assert(!kclf_stage_tmp_file(path, data, sizeof(data), &f)); address = 0;
        if (!fault) map_error = -EACCES;
        if (fault == 1) copy_error = -EFAULT;
        if (fault == 2) bad_range = 1;
        assert(kclf_map_file_code(f, path, code, 16384, &address) < 0 && !address);
        assert(unmaps == (fault != 0) && !puts_count && f->refs == 1);
        put(f);
    }
    reset();
    staged.refs = 3;
    for (int i = 0; i < KM_IMAGES; i++)
        images[i] = (struct kclf_manual_image){.state=i + 1, .backing=&staged, .owner=&owner, .mm=2};
    lock_failure = 1; kclf_manual_reap(); assert(!puts_count && staged.refs == 3);
    lock_failure = 0; kclf_manual_reap();
    assert(puts_count == 2 && owner_puts == 2 && staged.refs == 1 && images[0].state == KM_BUSY);
    assert(!images[1].backing && !images[2].backing);
    images[0].state = 2; images[0].mm = 1;
    kclf_manual_reap(); assert(puts_count == 2 && staged.refs == 1);
    assert(kclf_manual_shutdown() == 1 && puts_count == 3 && owner_puts == 3 && !staged.refs);
    assert(!kclf_manual_shutdown() && puts_count == 3);
    reset();
    for (int i = 0; i < 2; i++) {
        images[i].state = KM_LIVE; images[i].backing = &staged;
        images[i].id = images[i].map = images[i].length = UINT64_MAX;
        images[i].refs = UINT32_MAX; images[i].original_tid = INT32_MIN;
        images[i].nodelete = KM_NODELETE_ELF | KM_NODELETE_EMUTLS;
        memset(images[i].path, 'a', KCLF_PATH_MAX - 1);
    }
    char report[600];
    int used = kclf_manual_status(report, sizeof(report), 0);
    assert(used > 400 && used < (int)sizeof(report) && strstr(report, "backing=shmem\n"));
    assert(strstr(report, "next=1 (use images,1)\n"));
    used = kclf_manual_status(report, sizeof(report), 1);
    assert(used > 400 && used < (int)sizeof(report) && strstr(report, "backing=shmem\n"));
    assert(!strstr(report, "next="));
    memset(images, 0, sizeof(images));
    puts("tmpfs lifetime: busy/live/dead images, abandoned reap, forced shutdown, exact-once fput outside registry lock: PASS");
    puts("image status: maximum path/numeric fields remain complete across pagination: PASS");
    puts("tmpfs backing: exact bounded copy, short writes, faults, policy denial, borrowed references, 4K/16K/64K code maps: PASS");
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix="kclf-file-") as directory:
    source = Path(directory) / "test.c"
    executable = Path(directory) / "test"
    source.write_text(prelude + backing + mapping + reap + shutdown + status + main)
    subprocess.run(["gcc", "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-g",
                    "-fsanitize=address,undefined", "-fno-omit-frame-pointer", str(source),
                    "-o", str(executable)], check=True)
    subprocess.run([str(executable)], check=True)
