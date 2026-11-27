#!/usr/bin/env python3
"""Fault and scheduling interleavings against the production worker/ctl code.

Kernel calls are mocked with explicit scheduler boundaries. ASan/UBSan cannot
certify kernel scheduling; these tests catch ownership and reference regressions.
"""
from pathlib import Path
import os
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


header = (MODULE / "kclf_internal.h").read_text()
control = (MODULE / "kclf.c").read_text()
types = header[header.index("#define KCLF_MAX_REQ"):header.index("extern struct kclf_syms")]
worker = control[control.index("#define KCLF_WORKER_IDLE_MS"):control.index("static void kclf_work_prepare_body")]

PRELUDE = r'''
#include <assert.h>
#include <stdbool.h>
#include <errno.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#define KCLF_CODEGEN_HOST
#include "kclf_codegen.h"
#include "kclf_param.h"
typedef int32_t s32;
typedef int64_t s64;
typedef unsigned short umode_t;
struct mm_struct { int refs; } target_mm, replaced_mm;
struct cred { int refs; } target_cred, original_cred;
struct pid { int refs; } target_pid;
struct task_struct { int unused; } target_task, worker_task;
struct callback_head { void (*func)(struct callback_head *); };
struct vm_area_struct; struct file;
#define current (&worker_task)
#define KCLF_TWA_RESUME 1
#define KCLF_TWA_SIGNAL 2
#define logki(...) ((void)0)
'''

MOCKS = r'''
static struct kclf_syms kclf_ks;
static struct kclf_req kclf_reqs[KCLF_MAX_REQ];
static struct mm_struct *kclf_io_mm;
static struct task_struct *kclf_io_worker;
static s32 kclf_io_tgid;
static int kclf_unloading, kclf_control_busy, kclf_wake_supported = 1;
static int create_fail, prepare_fail, finish_fail, queue_fail, cancel_ok = 1;
static int alive = 1, rcu_depth, enters, leaves, overrides, reverts;
static int cancel_during_prepare, cancel_during_queue, finish_during_queue;
static int stop_calls, stop_after, finishes, resets, dropped_mm, manual_reaps;
static int replace_mm;
static struct kclf_req *active;
static long kclf_cancel_request(struct kclf_req *r);
static int kclf_slot_reclaimable(struct kclf_req *r);
static int kclf_worker_busy(const struct kclf_req *r);
static long kclf_cmd_reap(char *out, int outlen, int *off);
static void kclf_rcu_read_lock(void) { rcu_depth++; }
static void kclf_rcu_read_unlock(void) { assert(rcu_depth == 1); rcu_depth--; }
static struct task_struct *pid_task(struct pid *pid, int type) {
    assert(pid == &target_pid && type == 0 && rcu_depth == 1);
    return alive ? &target_task : NULL;
}
static struct mm_struct *kclf_task_mm(struct task_struct *p) {
    assert(p == &target_task); return alive ? &target_mm : NULL;
}
static struct mm_struct *get_mm(struct task_struct *p) {
    assert(p == &target_task && rcu_depth == 1);
    struct mm_struct *mm = replace_mm ? &replaced_mm : &target_mm;
    mm->refs++; return mm;
}
static void put_mm(struct mm_struct *mm) {
    assert((mm == &target_mm || mm == &replaced_mm) && !rcu_depth && mm->refs > 0);
    mm->refs--; dropped_mm++;
    /* A controller can run between reference release and worker return. */
    if (active) {
        assert(kclf_worker_busy(active));
        assert(!kclf_slot_reclaimable(active));
    }
}
static void put_cred(const struct cred *cred) {
    assert(cred == &target_cred && target_cred.refs > 0); target_cred.refs--;
}
static void put_pid(struct pid *pid) { assert(pid == &target_pid && pid->refs > 0); pid->refs--; }
static const struct cred *get_cred(struct task_struct *p) { (void)p; return &target_cred; }
static const struct cred *override(const struct cred *p) {
    assert(p == &target_cred); overrides++; return &original_cred;
}
static void revert(const struct cred *p) { assert(p == &original_cred); reverts++; }
static void use_mm(struct mm_struct *p) { assert(p == &target_mm); enters++; }
static void unuse_mm(struct mm_struct *p) { assert(p == &target_mm); leaves++; }
static int remote(struct mm_struct *p, unsigned long a, void *b, int n, unsigned int f) {
    (void)p; (void)a; (void)b; (void)f; return n;
}
static struct task_struct *create(int (*fn)(void *), void *data, int node, const char *name, ...) {
    assert(fn && !data && node == -1 && !strcmp(name, "kclf-prep"));
    return create_fail ? (void *)(long)-ENOMEM : &worker_task;
}
static int wake(struct task_struct *p) { assert(p == &worker_task); return 1; }
static int should_stop(void) { return stop_calls++ >= stop_after; }
static int stop(struct task_struct *p) { assert(p == &worker_task); return 0; }
static void sleep_ms(unsigned ms) { assert(ms == 5 || ms == 20); }
static u64 kclf_now(void) { return 1; }
static void kclf_set_err(struct kclf_req *r, const char *fmt, ...) { (void)r; (void)fmt; }
static void kclf_fail(struct kclf_req *r, int state, int stage, long err, const char *fmt, ...) {
    (void)err; (void)fmt; r->stage = stage; kclf_state_store(r, state);
}
static long kclf_exec_prepare(struct kclf_req *r) {
    assert(kclf_io_mm == &target_mm && kclf_io_worker == current);
    if (cancel_during_prepare) {
        assert(kclf_cancel_request(r) == -EBUSY);
        assert(r->state == KCLF_PREPARING && !r->finished);
    }
    r->map_addr = 4096;
    return prepare_fail ? -EIO : 0;
}
static long kclf_exec_finish(struct kclf_req *r, int capture) {
    assert(!capture); finishes++;
    if (finish_fail) return -ENOMEM;
    r->map_addr = r->map_len = r->code_addr = r->code_len = 0;
    return 0;
}
static void kclf_manual_abandon(struct kclf_req *r) { r->image = NULL; }
static int kclf_queue_work(struct kclf_req *r, struct task_struct *p, struct callback_head *w, int notify) {
    assert(p == &target_task && w == &r->work_hijack && notify == KCLF_TWA_RESUME);
    if (cancel_during_queue) {
        assert(kclf_cancel_request(r) == -EBUSY);
        assert(r->state == KCLF_READY);
    }
    if (queue_fail) return -ESRCH;
    r->pending++;
    if (finish_during_queue) {
        r->pending--; r->map_addr = 0; r->finished = 1; r->state = KCLF_DONE;
        assert(!kclf_slot_reclaimable(r));
    }
    return 0;
}
static int kclf_cancel_work(struct kclf_req *r, struct callback_head *w) {
    (void)w;
    if (cancel_ok && r->pending) { r->pending--; return 1; }
    return 0;
}
static void kclf_slot_reset(struct kclf_req *r) { resets++; memset(r, 0, sizeof(*r)); }
static void kclf_poll_running(void) {}
static void kclf_manual_reap(void) { manual_reaps++; }
static int kclf_manual_busy(void) { return 0; }
static int kclf_loading_num;
static int kclf_scnprintf(char *out, int n, const char *fmt, ...) {
    (void)out; (void)n; (void)fmt; return 0;
}
'''

MAIN = r'''
static void reset(void) {
    memset(kclf_reqs, 0, sizeof(kclf_reqs));
    kclf_worker_task = NULL; kclf_worker_ok = 0;
    kclf_unloading = kclf_control_busy = 0;
    create_fail = prepare_fail = finish_fail = queue_fail = 0;
    cancel_during_prepare = cancel_during_queue = finish_during_queue = 0;
    enters = leaves = overrides = reverts = finishes = resets = dropped_mm = 0;
    stop_calls = 0; stop_after = 1; active = NULL; alive = cancel_ok = 1;
    replace_mm = replaced_mm.refs = 0;
    target_mm.refs = target_cred.refs = target_pid.refs = 0;
    kclf_ks = (struct kclf_syms){.pid_task=pid_task, .put_pid=put_pid, .get_task_mm=get_mm,
        .mmput=put_mm, .put_cred=put_cred, .get_task_cred=get_cred, .override_creds=override,
        .revert_creds=revert, .kthread_use_mm=use_mm, .kthread_unuse_mm=unuse_mm,
        .access_remote_vm=remote, .kthread_create_on_node=create, .wake_up_process=wake,
        .kthread_should_stop=should_stop, .kthread_stop=stop, .msleep=sleep_ms};
    assert(!kclf_worker_init());
}
static struct kclf_req *armed(unsigned i) {
    struct kclf_req *r = &kclf_reqs[i];
    r->state = KCLF_ARMED; r->worker_phase = 1;
    r->task = (u64)&target_task; r->mm = (u64)&target_mm; r->pid_ref = &target_pid;
    r->mm_ref = &target_mm; r->cred_ref = &target_cred; r->owner_pid = &target_pid;
    target_mm.refs++; target_cred.refs++; target_pid.refs++;
    strcpy(r->path, "/test.so"); return r;
}
int main(void) {
    char out[16]; int off = 0;
    reset(); kclf_worker_ok = 0; kclf_ks.get_task_cred = NULL;
    assert(kclf_worker_init() == -EOPNOTSUPP && !kclf_worker_available());
    reset(); kclf_worker_ok = 0; kclf_ks.access_remote_vm = NULL;
    assert(kclf_worker_init() == -EOPNOTSUPP && !kclf_worker_available());
    puts("worker requires target credentials and remote-mm access: PASS");

    reset(); struct kclf_req *r = armed(0); r->worker_phase = 0; create_fail = 1;
    assert(kclf_worker_submit(r) == -ENOMEM);
    assert(!target_mm.refs && !target_cred.refs && !target_pid.refs && dropped_mm == 1);
    assert(!r->mm_ref && !r->cred_ref && !r->owner_pid && !r->worker_phase);
    puts("worker creation failure releases exactly one mm/cred/PID reference: PASS");

    reset(); r = armed(0);
    assert(!kclf_cancel_request(r) && r->state == KCLF_CANCELLED && r->finished);
    assert(!target_mm.refs && !target_cred.refs && !target_pid.refs);
    assert(kclf_slot_reclaimable(r));
    reset(); r = armed(0); struct kclf_req *taken;
    assert(kclf_worker_take(&taken) && taken == r);
    assert(kclf_cancel_request(r) == -EBUSY && r->state == KCLF_ARMED && !r->finished);
    alive = 0;
    assert(!kclf_cmd_reap(out, sizeof(out), &off) && !resets && r->mm_ref);
    alive = 1; r->worker_phase = 1;
    active = r; cancel_during_prepare = cancel_during_queue = finish_during_queue = 1;
    assert(!kclf_worker_fn(NULL)); active = NULL;
    assert(r->state == KCLF_DONE && r->worker_phase == 3 && kclf_slot_reclaimable(r));
    assert(!target_mm.refs && !target_cred.refs && !target_pid.refs);
    assert(enters == leaves && overrides == reverts && !rcu_depth);
    puts("cancel/reap cannot steal active preparation; early callback completion cannot recycle worker slot: PASS");

    reset(); r = armed(0); r->worker_phase = 2;
    assert(kclf_cmd_quiesce(out, sizeof(out), &off) == -EBUSY);
    assert(r->state == KCLF_ARMED && !r->finished);
    r->worker_phase = 1; active = r;
    assert(!kclf_worker_fn(NULL)); active = NULL;
    assert(r->worker_phase == 3 && r->state == KCLF_CANCELLED && kclf_slot_reclaimable(r));
    puts("quiesce leaves active ownership intact and worker drains cancellation: PASS");

    reset(); r = armed(0); active = r;
    assert(!kclf_worker_fn(NULL)); active = NULL;
    assert(r->state == KCLF_READY && r->pending == 1 && r->worker_phase == 3);
    assert(!kclf_cancel_request(r) && r->worker_phase == 4 && !r->pending);
    assert(!kclf_slot_reclaimable(r)); stop_calls = 0;
    assert(!kclf_worker_fn(NULL));
    assert(r->worker_phase == 3 && kclf_slot_reclaimable(r) && !target_mm.refs);
    puts("READY cancellation rolls back with exclusive worker ownership: PASS");

    reset(); r = armed(0); active = r;
    assert(!kclf_worker_fn(NULL)); active = NULL;
    assert(!kclf_cancel_request(r)); replace_mm = 1; stop_calls = 0;
    assert(!kclf_worker_fn(NULL));
    assert(!finishes && !replaced_mm.refs && kclf_slot_reclaimable(r));
    puts("rollback validates the pinned mm after exec; never unmaps the replacement mm: PASS");

    for (int fault = 0; fault < 3; fault++) {
        reset(); r = armed(0); active = r;
        prepare_fail = fault != 1; queue_fail = fault == 1; finish_fail = fault == 2;
        assert(!kclf_worker_fn(NULL)); active = NULL;
        assert(r->state == KCLF_FAILED && r->worker_phase == 3);
        assert(kclf_slot_reclaimable(r) == !finish_fail);
        assert(!target_mm.refs && !target_cred.refs && !target_pid.refs);
    }
    puts("prepare/queue/rollback failures retain mappings or release refs without premature reuse: PASS");

    reset(); r = armed(0); struct kclf_req *q = &kclf_reqs[1];
    q->state = KCLF_READY; q->mm = r->mm; strcpy(q->path, r->path);
    assert(kclf_prepare_busy(r)); q->mm++;
    assert(!kclf_prepare_busy(r)); q->mm = r->mm; q->flags = KCLF_F_LINKER;
    assert(!kclf_prepare_busy(r)); q->flags = 0;
    strcpy(q->path, "/different.so"); assert(kclf_prepare_busy(r));
    r->flags = KCLF_F_RELEASE; assert(kclf_prepare_busy(r)); r->flags = 0;
    kclf_control_busy = 1; assert(kclf_prepare_busy(r) && kclf_control_busy); kclf_control_busy = 0;
    alive = 0; active = r; assert(!kclf_worker_fn(NULL)); active = NULL;
    assert(r->state == KCLF_FAILED && !target_mm.refs && !r->prep_retries);
    puts("payload serialization is scoped to mm/manual; dead queued targets release mm before retry: PASS");

    reset();
    for (unsigned i = 0; i < KCLF_MAX_REQ; i++) kclf_reqs[i].worker_phase = 1;
    unsigned seen = 0;
    for (unsigned i = 0; i < KCLF_MAX_REQ; i++) {
        assert(kclf_worker_take(&taken));
        unsigned index = (unsigned)(taken - kclf_reqs);
        assert(!(seen & (1U << index))); seen |= 1U << index;
        taken->worker_phase = 1; /* blocked request immediately requeues */
    }
    assert(seen == (1U << KCLF_MAX_REQ) - 1);
    puts("round-robin retries do not starve later slots: PASS");
    reset(); r = armed(0); r->worker_phase = 0;
    assert(!kclf_worker_submit(r)); active = r; assert(!kclf_worker_fn(NULL)); active = NULL;
    kclf_worker_shutdown(); assert(!kclf_worker_task);
    return 0;
}
'''

parts = [function(control, signature) for signature in (
    "static int kclf_worker_busy(const struct kclf_req *r)",
    "static int kclf_slot_reclaimable(struct kclf_req *r)",
    "static int kclf_task_alive(struct task_struct *task, struct kclf_req *r)",
    "static long kclf_cancel_request(struct kclf_req *r)",
    "static long kclf_cmd_reap(char *out, int outlen, int *off)",
    "static int kclf_has_work(void)",
    "static long kclf_cmd_quiesce(char *out, int outlen, int *off)",
)]
with tempfile.TemporaryDirectory(prefix="kclf-worker-") as directory:
    test = Path(directory) / "test.c"
    exe = Path(directory) / "test"
    test.write_text(PRELUDE + types + MOCKS + worker + "\n".join(parts) + MAIN)
    subprocess.run(["gcc", "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-g",
                    "-fsanitize=address,undefined", "-I", str(MODULE), str(test),
                    "-o", str(exe)], check=True)
    subprocess.run([str(exe)], check=True,
                   env={**os.environ, "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1"})
