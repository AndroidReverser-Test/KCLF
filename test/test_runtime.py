#!/usr/bin/env python3
"""Fault-injection tests of production parameter, uaccess and cleanup routines.

Runs on Linux/WSL with ASan/UBSan. Kernel calls are mocks; this does not prove
task_work scheduling, ARM64 execution or real-device failure handling.
"""
from pathlib import Path
import subprocess
import tempfile

MODULE = Path(__file__).resolve().parents[1]


def function(source, signature):
    start = source.index(signature + "\n{")
    opening = source.index("{", start)
    depth = 0
    for i in range(opening, len(source)):
        depth += (source[i] == "{") - (source[i] == "}")
        if not depth:
            return source[start:i + 1]
    raise AssertionError(signature)


PRELUDE = r'''
#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include "kclf_param.h"
typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int64_t s64;
#define KCLF_PROT_READ 1
#define KCLF_RTLD_NOW 2
#define __NR_mprotect 226
#define KCLF_TWA_RESUME 1
#define current ((void *)1)
#define local_container_of(p, type, field) ((type *)((char *)(p) - offsetof(type, field)))
#define KCLF_USER_MAX kclf_user_limit
static u64 kclf_user_limit = 1ULL << 48;
static int kclf_user_tbi = 1;
struct callback_head { int unused; };
struct kclf_req {
    int state, stage, busy, completing, finished, cleanup_tries, flags;
    u64 mm, map_addr, map_len, image_id;
    void *image;
    u32 relro_count, relro_done;
    u64 relro[KCLF_MAX_RELRO][2];
    s64 handle;
    struct { u64 fn, dlerror, dlclose, caller; } ld;
    char path[KCLF_PATH_MAX], err[KCLF_ERR_MAX];
    struct callback_head work_cleanup;
};
static int protects, fail_protect, finishes, fail_finish, queued, fail_queue, abandoned;
static int copies, short_copy;
static u64 mm_identity = 0x55, last_start;
static long raw_syscall3(int nr, long start, long len, long prot) {
    assert(nr == __NR_mprotect && len == 4096 && prot == KCLF_PROT_READ);
    protects++;
    last_start = (u64)start;
    return fail_protect == protects || fail_protect == -1 ? -EACCES : 0;
}
static int kclf_state_load(const struct kclf_req *r) { return r->state; }
static void *kclf_task_mm(void *task) { assert(task == current); return (void *)mm_identity; }
static void kclf_manual_abandon(struct kclf_req *r) { abandoned++; r->image = NULL; }
static long kclf_exec_finish(struct kclf_req *r, int capture) {
    assert(capture == 1);
    finishes++;
    if (fail_finish) return -ENOMEM;
    r->map_addr = r->map_len = 0;
    r->image = NULL;
    return 0;
}
static int kclf_queue_work(struct kclf_req *r, void *task, struct callback_head *head, int notify) {
    assert(task == current && head == &r->work_cleanup && notify == KCLF_TWA_RESUME);
    queued++;
    return fail_queue ? -ESRCH : 0;
}
static void kclf_fail(struct kclf_req *r, int state, int stage, long error, const char *fmt, ...) {
    (void)error;
    r->state = state; r->stage = stage;
    if (fmt) {
        va_list ap; va_start(ap, fmt); vsnprintf(r->err, sizeof(r->err), fmt, ap); va_end(ap);
    }
}
static u64 get_random_u64(void) { return 0xa5a5a5a5a5a5a5a5ULL; }
static void kclf_manual_params(struct kclf_req *r, u8 *p) {
    *(u32 *)(p + KCLF_P_MANUAL) = 1;
    *(u64 *)(p + KCLF_P_HANDLE) = r->image_id;
}
static int copy_user(void *task, unsigned long at, void *buf, int len, unsigned flags) {
    assert(task == current && at == 0x1000 && buf && flags == 1);
    copies++;
    return short_copy ? len - 1 : len;
}
static struct {
    int (*access_process_vm)(void *, unsigned long, void *, int, unsigned);
} kclf_ks = {copy_user};
'''

MAIN = r'''
static struct kclf_req fresh(void) {
    struct kclf_req r = { .state = KCLF_DONE, .handle = 1, .mm = 0x55,
        .map_addr = 0x10000, .map_len = 0x4000, .image = (void *)1, .relro_count = 3,
        .relro = {{0x20000, 4096}, {0x21000, 4096}, {0x22000, 4096}} };
    protects = fail_protect = finishes = fail_finish = queued = fail_queue = abandoned = 0;
    mm_identity = r.mm;
    return r;
}
int main(void) {
    struct kclf_req r = fresh();
    fail_protect = 2;
    kclf_work_cleanup_body(&r.work_cleanup);
    assert(r.relro_done == 1 && protects == 2 && queued == 1 && !finishes);
    assert(!r.finished && r.map_addr && r.image && r.state == KCLF_DONE);
    kclf_work_cleanup_body(&r.work_cleanup);
    assert(r.relro_done == 3 && protects == 4 && last_start == 0x22000 && finishes == 1);
    assert(r.finished && !r.map_addr && !r.image && r.state == KCLF_DONE);
    assert(!kclf_apply_relro(&r) && protects == 4); /* idempotent */
    puts("RELRO resumes at failed range; commit/unmap only after every protection succeeds: PASS");

    r = fresh(); fail_protect = -1;
    for (int i = 0; i <= KCLF_CLEANUP_RETRIES; i++) kclf_work_cleanup_body(&r.work_cleanup);
    assert(r.state == KCLF_FAILED && r.stage == KCLF_ST_RESTORE && !r.finished);
    assert(r.relro_done == 0 && r.map_addr && r.image && !finishes && !abandoned);
    assert(queued == KCLF_CLEANUP_RETRIES && strstr(r.err, "RELRO protection failed"));
    r = fresh(); fail_protect = fail_queue = 1;
    kclf_work_cleanup_body(&r.work_cleanup);
    assert(r.state == KCLF_FAILED && !r.finished && r.map_addr && r.image && !finishes);
    puts("persistent RELRO/queue failure is FAILED, not success or unsafe rollback: PASS");

    r = fresh(); fail_finish = 1;
    kclf_work_cleanup_body(&r.work_cleanup);
    assert(r.relro_done == 3 && protects == 3 && queued == 1 && r.map_addr && !r.finished);
    fail_finish = 0;
    kclf_work_cleanup_body(&r.work_cleanup);
    assert(r.finished && protects == 3 && finishes == 2);
    r = fresh(); fail_finish = fail_queue = 1;
    kclf_work_cleanup_body(&r.work_cleanup);
    assert(r.state == KCLF_FAILED && !r.finished && strstr(r.err, "resource cleanup failed"));
    r = fresh(); mm_identity++;
    kclf_work_cleanup_body(&r.work_cleanup);
    assert(r.finished && !r.map_addr && abandoned == 1 && !protects && !finishes);
    r = fresh(); r.relro_count = KCLF_MAX_RELRO + 1;
    assert(kclf_apply_relro(&r) == -EINVAL && !protects);
    r.relro_count = 1; r.relro_done = 2;
    assert(kclf_apply_relro(&r) == -EINVAL && !protects);
    puts("cleanup retry, queue rejection, replaced mm, malformed progress bounds: PASS");

    u8 params[KCLF_P_SIZE] __attribute__((aligned(8)));
    r = fresh(); r.flags = KCLF_F_LINKER;
    r.ld.fn = 1; r.ld.dlerror = 2; r.ld.dlclose = 3; r.ld.caller = 4;
    memset(r.path, 'x', sizeof(r.path)); r.path[0] = '/'; r.path[sizeof(r.path) - 1] = 0;
    kclf_init_params(&r, params);
    assert(*(u64 *)(params + KCLF_P_FN) == 1 && *(u64 *)(params + KCLF_P_DLERROR) == 2);
    assert(*(u64 *)(params + KCLF_P_DLCLOSE) == 3 && *(u64 *)(params + KCLF_P_CALLER) == 4);
    assert(*(u64 *)(params + KCLF_P_HANDLE) == 0 && *(u64 *)(params + KCLF_P_ERRPTR) == 0);
    assert(*(u32 *)(params + KCLF_P_MANUAL) == 0 && *(u32 *)(params + KCLF_P_UNLOAD) == 0);
    assert(*(u32 *)(params + KCLF_P_FLAGS) == KCLF_RTLD_NOW);
    assert(!strcmp((char *)params + KCLF_P_PATH, r.path));
    r.flags = KCLF_F_UNLOAD; r.image_id = 123;
    kclf_init_params(&r, params);
    assert(*(u64 *)(params + KCLF_P_HANDLE) == 123 && *(u64 *)(params + KCLF_P_ERRPTR) == 0);
    assert(*(u32 *)(params + KCLF_P_MANUAL) == 1 && *(u32 *)(params + KCLF_P_UNLOAD) == 1);
    puts("all result/control fields initialized for linker and manual backends: PASS");

    u64 word = 0;
    assert(!kclf_uwr(0xab00000000001000ULL, &word, 8) && copies == 1);
    short_copy = 1;
    assert(kclf_uwr(0x1000, &word, 8) == -EFAULT && copies == 2);
    assert(kclf_uwr(0, &word, 8) == -EFAULT);
    assert(kclf_uwr(kclf_user_limit, &word, 0) == -EFAULT);
    assert(kclf_uwr(kclf_user_limit - 4, &word, 8) == -EFAULT);
    assert(kclf_uwr(UINT64_MAX - 3, &word, 8) == -EFAULT);
    assert(kclf_uwr(0x1000, &word, -1) == -EFAULT && copies == 2);
    kclf_user_tbi = 0;
    assert(kclf_uwr(0xab00000000001000ULL, &word, 8) == -EFAULT && copies == 2);
    puts("user write range/tag/short-copy errors consistently return -EFAULT: PASS");
    return 0;
}
'''

header = (MODULE / "kclf_internal.h").read_text()
limits = "\n".join(line for line in header.splitlines() if line.startswith((
    "#define KCLF_MAX_RELRO ", "#define KCLF_CLEANUP_RETRIES ")))
enums = header[header.index("enum kclf_state"):header.index("struct kclf_manual_image;")]
control = (MODULE / "kclf.c").read_text()
execution = (MODULE / "kclf_exec.c").read_text()
parts = [function(execution, signature) for signature in (
    "static int kclf_user_range(u64 addr, u64 len)",
    "int kclf_uwr(u64 addr, const void *buf, int len)",
    "static void kclf_init_params(struct kclf_req *r, u8 pbuf[KCLF_P_SIZE])",
    "long kclf_apply_relro(struct kclf_req *r)",
)]
parts.append(function(control, "static void kclf_work_cleanup_body(struct callback_head *head)"))
with tempfile.TemporaryDirectory(prefix="kclf-runtime-") as directory:
    source = Path(directory) / "test.c"
    exe = Path(directory) / "test"
    source.write_text(limits + "\n" + enums + PRELUDE + "\n".join(parts) + MAIN)
    subprocess.run(["gcc", "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-g", "-O2",
                    "-fno-strict-aliasing", "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                    "-I", str(MODULE), str(source), "-o", str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
