#!/usr/bin/env python3
"""Exercise real completion/poll routines without a kernel (ASan + UBSan)."""
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
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
typedef uint64_t u64;
typedef int64_t s64;
typedef int32_t s32;
typedef uint8_t u8;
struct callback_head { int unused; };
struct pt_regs { u64 pc; } regs;
static int regs_available = 1;
static struct pt_regs *kclf_find_regs(void) { return regs_available ? &regs : NULL; }
struct kclf_req {
    int state, priv_layout_ok, flags, completing, busy, stage, unloaded;
    s32 unload_rc;
    s64 handle;
    u64 err_user, priv_addr, mm, done_token, map_addr, map_len, j_done;
    u8 completion_via;
    struct { u64 done, handle, errptr, rc; } pl;
    struct callback_head work_poll, work_cleanup;
};
#define local_container_of(p, type, field) ((type *)((char *)(p) - offsetof(type, field)))
#define current ((void *)1)
#define KCLF_F_UNLOAD 8
#define KCLF_VIA_SYSCALL 1
#define KCLF_VIA_POLL 2
#define KCLF_RUNNING 4
#define KCLF_DONE 5
#define KCLF_ST_RESTORE 5
#define KCLF_TWA_SIGNAL 2
#define KCLF_TWA_RESUME 1
static int kclf_loading_num, kclf_wake_supported = 1;
static int nofault_available, reads, fault_reads, fail_at, queued;
static u64 words[4];
static int read_user(u64 addr, void *out, int n, int sleepable) {
    reads++;
    if (sleepable) fault_reads++;
    if ((!sleepable && !nofault_available) || fail_at == reads) return -EFAULT;
    assert(n == 8 && addr >= 0x1000 && addr < 0x1020 && !(addr & 7));
    memcpy(out, (char *)words + addr - 0x1000, 8);
    return 0;
}
static int kclf_urd(u64 a, void *b, int n) { return read_user(a, b, n, 0); }
static int kclf_urds(u64 a, void *b, int n) { return read_user(a, b, n, 1); }
static void *kclf_task_mm(void *t) { (void)t; return (void *)0x55; }
static int kclf_state_load(struct kclf_req *r) { return r->state; }
static void kclf_state_store(struct kclf_req *r, int st) { r->state = st; }
static u64 kclf_now(void) { return 42; }
static void kclf_set_err(struct kclf_req *r, const char *s) { (void)r; (void)s; }
static int kclf_queue_work(struct kclf_req *r, void *t, struct callback_head *w, int n) {
    (void)t; (void)n; assert(w == &r->work_cleanup); queued++; return 0;
}
'''

MAIN = r'''
static struct kclf_req fresh(void) {
    struct kclf_req r = { .state = KCLF_RUNNING, .priv_layout_ok = 1, .flags = KCLF_F_UNLOAD,
        .priv_addr = 0x1000, .mm = 0x55, .done_token = 123, .map_addr = 0x1000, .map_len = 0x3000,
        .pl = { 0, 8, 16, 24 } };
    words[0] = 123; words[1] = 789; words[2] = 0; words[3] = 0;
    reads = fault_reads = queued = fail_at = 0;
    regs.pc = 0x8000; regs_available = 1; kclf_loading_num = 1;
    return r;
}
int main(void) {
    struct kclf_req r = fresh();
    nofault_available = 0;
    kclf_complete(&r, KCLF_VIA_SYSCALL, 1);
    assert(r.state == KCLF_RUNNING && !fault_reads && !queued && kclf_loading_num == 1);
    kclf_work_poll_body(&r.work_poll);
    assert(r.state == KCLF_DONE && r.handle == 789 && r.unloaded && r.completion_via == KCLF_VIA_POLL);
    assert(fault_reads == 4 && queued == 1 && kclf_loading_num == 0);
    puts("no nofault accessor: syscall stays nonfaulting, task_work poll completes via GUP: PASS");
    r = fresh(); nofault_available = 1;
    kclf_complete(&r, KCLF_VIA_SYSCALL, 1);
    assert(r.state == KCLF_DONE && !fault_reads && queued == 1);
    for (int i = 1; i <= 3; i++) {
        r = fresh(); fail_at = i;
        kclf_complete(&r, KCLF_VIA_SYSCALL, 1);
        assert(r.state == KCLF_RUNNING && !queued && !r.handle && kclf_loading_num == 1);
        fail_at = 0;
        kclf_work_poll_body(&r.work_poll);
        assert(r.state == KCLF_DONE && r.handle == 789);
    }
    puts("partial result reads never commit zero/partial results; retry succeeds: PASS");
    r = fresh(); words[0] = 0;
    kclf_work_poll_body(&r.work_poll);
    assert(r.state == KCLF_RUNNING && !queued);
    words[0] = 123;
    for (u64 pc = 0x1000; pc < 0x4000; pc += 4) {
        regs.pc = pc;
        kclf_work_poll_body(&r.work_poll);
        assert(r.state == KCLF_RUNNING && !queued);
    }
    regs_available = 0;
    kclf_work_poll_body(&r.work_poll);
    assert(r.state == KCLF_RUNNING);
    regs_available = 1; regs.pc = 0x4000;
    kclf_work_poll_body(&r.work_poll);
    assert(r.state == KCLF_DONE && queued == 1);
    puts("poll defers while return PC is in transient pages or frame is unavailable: PASS");
    return 0;
}
'''

control = (MODULE / "kclf.c").read_text()
execution = (MODULE / "kclf_exec.c").read_text()
parts = [function(execution, "int kclf_exec_poll_ready(const struct kclf_req *r)")]
parts += [function(control, signature) for signature in (
    "static int kclf_read_results(struct kclf_req *r, int sleepable)",
    "static void kclf_complete(struct kclf_req *r, int via, int force_drain)",
    "static void kclf_work_poll_body(struct callback_head *head)",
)]
with tempfile.TemporaryDirectory(prefix="kclf-completion-") as directory:
    source = Path(directory) / "test.c"
    exe = Path(directory) / "test"
    source.write_text(PRELUDE + "\n".join(parts) + MAIN)
    subprocess.run(["gcc", "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-g",
                    "-fsanitize=address,undefined", str(source), "-o", str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
