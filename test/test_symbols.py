#!/usr/bin/env python3
"""Check the actual symbol resolver against missing/renamed kernel APIs."""
from pathlib import Path
import subprocess
import tempfile

MODULE = Path(__file__).resolve().parents[1]
header = (MODULE / "kclf_internal.h").read_text()
symbols = header[header.index("struct kclf_syms\n"):header.index("extern struct kclf_syms")]
control = (MODULE / "kclf.c").read_text()
resolver = control[control.index("int kclf_sym_lookup_all(void)"):control.index("/* RESUME=1")]
cancel = control[control.index("static bool kclf_work_matches("):control.index("static int kclf_queue_work(")]
PRELUDE = r'''
#include <assert.h>
#include <stdbool.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
typedef uint64_t u64;
typedef unsigned short umode_t;
struct task_struct; struct callback_head; struct pid; struct mm_struct; struct vm_area_struct; struct file;
#define logke(...) ((void)0)
static void (*kclf_rcu_read_lock)(void), (*kclf_rcu_read_unlock)(void);
static u64 (*kclf_ktime_get)(void);
static const char *absent[4];
static unsigned long kclf_lookup(const char *name) {
    for (int i = 0; i < 4; i++) if (absent[i] && !strcmp(absent[i], name)) return 0;
    /* Unique dummy address; none of these mock function pointers is invoked. */
    return !strcmp(name, "vmalloc_noprof") ? 2 : !strcmp(name, "probe_user_read") ? 3 : 1;
}
'''
CANCEL_PRELUDE = r'''
struct task_struct { int unused; } task;
struct callback_head { void (*func)(struct callback_head *); } work;
struct kclf_req { struct pid *pid_ref; u64 task; int pending; };
static int rcu_depth, should_cancel;
static void mock_lock(void) { rcu_depth++; }
static void mock_unlock(void) { assert(rcu_depth == 1); rcu_depth--; }
static void mock_work(struct callback_head *w) { (void)w; }
static struct task_struct *mock_pid_task(struct pid *p, int type) {
    assert(p && type == 0 && rcu_depth == 1); return &task;
}
static struct callback_head *mock_match(struct task_struct *t,
                                      bool (*match)(struct callback_head *, void *), void *data) {
    assert(t == &task && data == &work && rcu_depth == 1 && match(&work, data));
    return should_cancel ? &work : NULL;
}
static struct callback_head *mock_func(struct task_struct *t, void (*fn)(struct callback_head *)) {
    assert(t == &task && fn == mock_work && rcu_depth == 1);
    return should_cancel ? &work : NULL;
}
static bool mock_object(struct task_struct *t, struct callback_head *w) {
    assert(t == &task && w == &work && rcu_depth == 1); return should_cancel;
}
'''
MAIN = r'''
int main(void) {
    assert(!kclf_sym_lookup_all());
    absent[0] = "vmalloc";
    assert(!kclf_sym_lookup_all() && (uintptr_t)kclf_ks.vmalloc == 2);
    absent[1] = "vmalloc_noprof";
    assert(kclf_sym_lookup_all() == -ENOENT);
    memset(absent, 0, sizeof(absent)); absent[0] = "vfree";
    assert(kclf_sym_lookup_all() == -ENOENT);
    absent[0] = "copy_from_user_nofault";
    assert(!kclf_sym_lookup_all() && (uintptr_t)kclf_ks.copy_from_user_nofault == 3);
    absent[1] = "probe_user_read";
    assert(!kclf_sym_lookup_all() && !kclf_ks.copy_from_user_nofault);
    memset(absent, 0, sizeof(absent));
    absent[0] = "task_work_cancel_match"; absent[1] = "task_work_cancel_func";
    assert(!kclf_sym_lookup_all()); /* deferred to BTF-aware compatibility init */
    assert(!kclf_ks.task_work_cancel_func && !kclf_ks.task_work_cancel_match && !kclf_ks.task_work_cancel_object);
    memset(absent, 0, sizeof(absent)); absent[0] = "__rcu_read_lock";
    assert(kclf_sym_lookup_all() == -EOPNOTSUPP);
    puts("vmalloc_noprof/probe_user_read aliases; required allocators; optional nofault; ambiguous cancel deferral: PASS");
    kclf_rcu_read_lock = mock_lock; kclf_rcu_read_unlock = mock_unlock;
    kclf_ks.pid_task = mock_pid_task; work.func = mock_work;
    for (int mode = 0; mode < 3; mode++) {
        kclf_ks.task_work_cancel_match = mode == 0 ? mock_match : NULL;
        kclf_ks.task_work_cancel_func = mode == 1 ? mock_func : NULL;
        kclf_ks.task_work_cancel_object = mode == 2 ? mock_object : NULL;
        for (should_cancel = 0; should_cancel <= 1; should_cancel++) {
            struct kclf_req r = { .pid_ref = (void *)1, .task = (u64)&task, .pending = 1 };
            assert(kclf_cancel_work(&r, &work) == should_cancel);
            assert(r.pending == 1 - should_cancel && !rcu_depth);
            r.task = 0;
            assert(!kclf_cancel_work(&r, &work) && !rcu_depth);
        }
    }
    puts("match/function/object cancellation: argument and return ABIs, RCU and pending accounting: PASS");
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix="kclf-symbols-") as directory:
    source = Path(directory) / "test.c"
    exe = Path(directory) / "test"
    source.write_text(PRELUDE + symbols + "\nstruct kclf_syms kclf_ks;\n" + resolver + CANCEL_PRELUDE + cancel + MAIN)
    subprocess.run(["gcc", "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-g",
                    "-fsanitize=address,undefined", str(source), "-o", str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
