/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * KCLF - Kernel Controlled Loading Framework, KPM implementation.
 *
 * Deviations from kclf-design.md required by the KPM environment (they are
 * documented rather than silently ignored):
 *
 *   - UAPI: a misc device with ioctl/poll is replaced by the KernelPatch
 *     superkey protected ctl0 string channel. ABI, state machine, error model
 *     and audit output are kept.
 *   - The framework runs entirely from a loadable module, so the fault-time
 *     dispatch point (handle_mm_fault) of kclf-shadow-design.md is not
 *     available. The trigger uses task_work (the target already entered the
 *     kernel: no ptrace or SIGSTOP). Preparation and loading may sleep, and
 *     the return-to-user register file redirects one thread to the trampoline.
 *   - Cleanup attempts to remove the transient trampoline mapping and now
 *     verifies the munmap result instead of clearing the bookkeeping
 *     unconditionally. Libraries loaded by dlopen retain their normal
 *     mappings and linker records unless the caller opts into "unload", in
 *     which case the trampoline calls __loader_dlclose after the constructors
 *     ran. Other threads can still observe changes to the shared address
 *     space during loading.
 *   - Syscall based completion replaces a write-fault trap. Its cookie lives
 *     in target memory only until the trampoline scrubs its parameter page;
 *     the loader result is handed back in x1/x2/x3. Correlation is not a
 *     security boundary.
 */
#include <kclf_internal.h>
#include <log.h>
#include <kputils.h>
#include <pgtable.h>
#include <syscall.h>
#include <asm/processor.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <uapi/asm-generic/errno.h>
#include <uapi/asm-generic/unistd.h>

KPM_NAME("kclf");
KPM_VERSION(KCLF_VER);
KPM_LICENSE("GPL v2");
KPM_AUTHOR("bmax121");
KPM_DESCRIPTION("Kernel Controlled Loading Framework - shadow library loading backend");

struct kclf_syms kclf_ks;
struct kclf_req kclf_reqs[KCLF_MAX_REQ];
volatile int kclf_unloading;
volatile int kclf_loading_num;
int kclf_page_size;
int kclf_ready;
int kclf_mm_off = -1;
int kclf_pid_off = -1;

static u64 kclf_next_id = 1;
static int kclf_hook_ok;
static void (*kclf_rcu_read_lock)(void);
static void (*kclf_rcu_read_unlock)(void);
static u64 (*kclf_ktime_get)(void);

#define KCLF_SLOT_OFFSET(r) ((int)((r) - kclf_reqs))

/*
 * KernelPatch probes task_struct_offset.mm_offset by looking for init_mm, which
 * is not always resolvable, so fall back to deriving it from get_task_mm().
 * kthreadd (mm == NULL, active_mm == init_mm) disambiguates the field from
 * active_mm when it is reachable.
 */
static int kclf_probe_mm_offset(void)
{
    struct mm_struct *mm;
    struct task_struct *kt;
    u64 want;
    int off, found = -1;

    if (task_struct_offset.mm_offset > 0) return task_struct_offset.mm_offset;
    if (!kclf_ks.get_task_mm || !kclf_ks.mmput || !kclf_ks.find_task_by_vpid) return -1;

    mm = kclf_ks.get_task_mm(current);
    if (!mm) return -1;
    want = (u64)mm;

    if (kclf_rcu_read_lock) kclf_rcu_read_lock();
    kt = kclf_ks.find_task_by_vpid(2);
    if (kclf_rcu_read_lock) {
        for (off = 0; off + 8 <= 0x1800; off += 8) {
            if (*(u64 *)((char *)current + off) != want) continue;
            if (kt && *(u64 *)((char *)kt + off) == 0) {
                found = off;
                break;
            }
            if (found < 0) found = off;
        }
        kclf_rcu_read_unlock();
    } else {
        for (off = 0; off + 8 <= 0x1800; off += 8) {
            if (*(u64 *)((char *)current + off) == want) {
                found = off;
                break;
            }
        }
    }
    kclf_ks.mmput(mm);
    return found;
}

/* the module cannot link against the kernel's page_size symbol */
static int kclf_detect_page_size(void)
{
    u64 tcr = 0;
    u64 tg0;

    asm volatile("mrs %0, tcr_el1" : "=r"(tcr));
    tg0 = (tcr >> 14) & 3;
    if (tg0 == 0) return 4096;
    if (tg0 == 2) return 16384;
    if (tg0 == 1) return 65536;
    return 4096;
}

static const char *kclf_state_name(int state)
{
    switch (state) {
    case KCLF_IDLE: return "idle";
    case KCLF_ARMED: return "armed";
    case KCLF_PREPARING: return "preparing";
    case KCLF_READY: return "ready";
    case KCLF_RUNNING: return "running";
    case KCLF_DONE: return "done";
    case KCLF_FAILED: return "failed";
    case KCLF_CANCELLED: return "cancelled";
    default: return "?";
    }
}

static const char *kclf_stage_name(int stage)
{
    switch (stage) {
    case KCLF_ST_NONE: return "-";
    case KCLF_ST_QUEUE: return "queue";
    case KCLF_ST_PREPARE: return "prepare";
    case KCLF_ST_HIJACK: return "hijack";
    case KCLF_ST_LOADER: return "loader";
    case KCLF_ST_RESTORE: return "restore";
    default: return "?";
    }
}

u64 kclf_now(void)
{
    return kclf_ktime_get ? kclf_ktime_get() : 0;
}

void kclf_set_err(struct kclf_req *r, const char *fmt, ...)
{
    va_list args;

    if (!fmt || !fmt[0]) return;
    va_start(args, fmt);
    vsnprintf(r->err, sizeof(r->err), fmt, args);
    va_end(args);
}

/* ------------------------------------------------------------------ */
/* symbol resolution                                                    */
/* ------------------------------------------------------------------ */

/* plain name lookup; safe from any context (no symbol table walk) */
unsigned long kclf_lookup(const char *name)
{
    return kallsyms_lookup_name(name);
}

int kclf_sym_lookup_all(void)
{
    const char *missing = 0;

    memset(&kclf_ks, 0, sizeof(kclf_ks));

#define KCLF_KS(field, symbol)                                    \
    do {                                                          \
        kclf_ks.field = (typeof(kclf_ks.field))kclf_lookup(symbol); \
        if (!kclf_ks.field && !missing) missing = symbol;         \
    } while (0)

    KCLF_KS(task_work_add, "task_work_add");
    kclf_ks.task_work_cancel = (typeof(kclf_ks.task_work_cancel))kclf_lookup("task_work_cancel");
    if (!kclf_ks.task_work_cancel)
        kclf_ks.task_work_cancel = (typeof(kclf_ks.task_work_cancel))kclf_lookup("task_work_cancel_func");
    if (!kclf_ks.task_work_cancel && !missing) missing = "task_work_cancel";
    kclf_ks.signal_wake_up_state = (typeof(kclf_ks.signal_wake_up_state))kclf_lookup("signal_wake_up_state");
    if (!kclf_ks.signal_wake_up_state)
        kclf_ks.signal_wake_up_state = (typeof(kclf_ks.signal_wake_up_state))kclf_lookup("signal_wake_up");
    KCLF_KS(find_task_by_vpid, "find_task_by_vpid");
    KCLF_KS(vm_mmap, "vm_mmap");
    KCLF_KS(vm_munmap, "vm_munmap");
    KCLF_KS(find_vma, "find_vma");
    KCLF_KS(filp_open, "filp_open");
    KCLF_KS(kernel_read, "kernel_read");
    KCLF_KS(fput, "fput");
    kclf_ks.copy_from_user = (typeof(kclf_ks.copy_from_user))kclf_lookup("__arch_copy_from_user");
    if (!kclf_ks.copy_from_user)
        kclf_ks.copy_from_user = (typeof(kclf_ks.copy_from_user))kclf_lookup("_copy_from_user");
    if (!kclf_ks.copy_from_user)
        kclf_ks.copy_from_user = (typeof(kclf_ks.copy_from_user))kclf_lookup("copy_from_user_nofault");
    if (!kclf_ks.copy_from_user) logkw("kclf: no user copy primitive\n");
    kclf_ks.copy_to_user = (typeof(kclf_ks.copy_to_user))kclf_lookup("__arch_copy_to_user");
    if (!kclf_ks.copy_to_user) kclf_ks.copy_to_user = (typeof(kclf_ks.copy_to_user))kclf_lookup("_copy_to_user");
    kclf_ks.fault_in_pages_readable =
        (typeof(kclf_ks.fault_in_pages_readable))kclf_lookup("fault_in_pages_readable");
    kclf_ks.access_process_vm = (typeof(kclf_ks.access_process_vm))kclf_lookup("access_process_vm");
#undef KCLF_KS

    kclf_rcu_read_lock = (typeof(kclf_rcu_read_lock))kclf_lookup("__rcu_read_lock");
    kclf_rcu_read_unlock = (typeof(kclf_rcu_read_unlock))kclf_lookup("__rcu_read_unlock");
    kclf_ktime_get = (typeof(kclf_ktime_get))kclf_lookup("ktime_get");
    kclf_ks.msleep = (typeof(kclf_ks.msleep))kclf_lookup("msleep");
    kclf_ks.get_task_mm = (typeof(kclf_ks.get_task_mm))kclf_lookup("get_task_mm");
    kclf_ks.mmput = (typeof(kclf_ks.mmput))kclf_lookup("mmput");

    if (missing) {
        logke("kclf: kernel symbol missing: %s\n", missing);
        return -ENOENT;
    }
    if (!kclf_rcu_read_lock || !kclf_rcu_read_unlock) {
        /* not fatal: task_work cancellation then falls back to a verified
         * lookup only, see kclf_cancel_work() */
        logkw("kclf: rcu primitives not resolvable\n");
    }
    return 0;
}

/* task_work notify modes (enum task_work_notify_mode since 5.17) */
#define KCLF_TWA_RESUME 1
#define KCLF_TWA_SIGNAL 2

/* ------------------------------------------------------------------ */
/* slot bookkeeping                                                     */
/* ------------------------------------------------------------------ */

static int kclf_task_alive(struct task_struct *task, struct kclf_req *r)
{
    if (!task) return 0;
    if ((u64)kclf_task_mm(task) != r->mm) return 0;
    return 1;
}

/* cancel a queued task_work of @r on the task identified by @r->pid */
static void kclf_cancel_work(struct kclf_req *r, struct callback_head *work)
{
    struct task_struct *task;

    if (!kclf_ks.task_work_cancel || !r->pid) return;

    if (kclf_rcu_read_lock) {
        kclf_rcu_read_lock();
        task = kclf_ks.find_task_by_vpid(r->pid);
        if (task) kclf_ks.task_work_cancel(task, work);
        kclf_rcu_read_unlock();
        return;
    }
    task = kclf_ks.find_task_by_vpid(r->pid);
    if (kclf_task_alive(task, r)) kclf_ks.task_work_cancel(task, work);
}

static void kclf_work_prepare(struct callback_head *head);
static void kclf_work_hijack(struct callback_head *head);
static void kclf_work_cleanup(struct callback_head *head);

static void kclf_slot_reset(struct kclf_req *r)
{
    memset(r, 0, sizeof(*r));
    r->state = KCLF_IDLE;
    r->work_prepare.func = kclf_work_prepare;
    r->work_hijack.func = kclf_work_hijack;
    r->work_cleanup.func = kclf_work_cleanup;
}

static struct kclf_req *kclf_slot_alloc(void)
{
    struct kclf_req *free_slot = 0;
    int i;

    for (i = 0; i < KCLF_MAX_REQ; i++) {
        struct kclf_req *r = &kclf_reqs[i];
        if (r->state == KCLF_IDLE) return r;
        /* only reclaim slots whose target side resources are gone */
        if (r->finished && !r->busy && !r->completing && !r->map_addr &&
            (r->state == KCLF_DONE || r->state == KCLF_FAILED || r->state == KCLF_CANCELLED)) {
            if (!free_slot || r->j_done < free_slot->j_done) free_slot = r;
        }
    }
    if (free_slot) {
        kclf_slot_reset(free_slot);
        return free_slot;
    }
    return 0;
}

struct kclf_req *kclf_slot_by_task(struct task_struct *task)
{
    int i;
    for (i = 0; i < KCLF_MAX_REQ; i++) {
        struct kclf_req *r = &kclf_reqs[i];
        if (r->state == KCLF_RUNNING && r->run_task == (u64)task) return r;
    }
    return 0;
}

static void kclf_free_user(struct kclf_req *r, int capture_err)
{
    if (r->map_addr && (u64)kclf_task_mm(current) == r->mm) {
        long rc = kclf_exec_finish(r, capture_err);
        if (rc) {
            /* Keep the range and retry from the cleanup callback, which runs
             * in the same target context.  Never pretend a failed munmap made
             * the transient mapping disappear. */
            kclf_set_err(r, "munmap failed rc=%ld", rc);
            r->cleanup_tries = 0;
            kclf_ks.task_work_add(current, &r->work_cleanup, KCLF_TWA_RESUME);
            return;
        }
    } else {
        r->map_addr = 0;
        r->map_len = 0;
    }
    r->finished = 1;
}

void kclf_fail(struct kclf_req *r, int state, int stage, long err, const char *fmt, ...)
{
    va_list args;

    r->stage = stage;
    if (fmt && fmt[0]) {
        va_start(args, fmt);
        vsnprintf(r->err, sizeof(r->err), fmt, args);
        va_end(args);
    }
    if (!r->err[0]) snprintf(r->err, sizeof(r->err), "err %ld (0x%llx)", err, (unsigned long long)err);
    r->state = state;
    r->j_done = kclf_now();
}

/* ------------------------------------------------------------------ */
/* task_work callbacks (run inside the target task, mm == target mm)     */
/* ------------------------------------------------------------------ */

static void kclf_work_prepare(struct callback_head *head)
{
    struct kclf_req *r = local_container_of(head, struct kclf_req, work_prepare);
    struct mm_struct *mm;
    long rc;

    if (kclf_unloading || r->state != KCLF_ARMED) return;
    r->busy = 1;
    r->state = KCLF_PREPARING;

    mm = kclf_task_mm(current);
    if (!mm || (u64)mm != r->mm) {
        kclf_fail(r, KCLF_FAILED, KCLF_ST_PREPARE, -ESRCH, "target address space replaced");
        r->busy = 0;
        return;
    }

    rc = kclf_exec_prepare(r);
    if (rc) {
        kclf_free_user(r, 0);
        kclf_fail(r, KCLF_FAILED, KCLF_ST_PREPARE, rc, "");
        r->busy = 0;
        return;
    }

    r->j_ready = kclf_now();
    r->state = KCLF_READY;
    rc = kclf_ks.task_work_add(current, &r->work_hijack, KCLF_TWA_RESUME);
    if (rc) {
        kclf_free_user(r, 0);
        kclf_fail(r, KCLF_FAILED, KCLF_ST_HIJACK, rc, "cannot arm return boundary work");
    }
    r->busy = 0;
}

static void kclf_work_hijack(struct callback_head *head)
{
    struct kclf_req *r = local_container_of(head, struct kclf_req, work_hijack);
    int rc;

    if (kclf_unloading || r->state != KCLF_READY) return;
    r->busy = 1;

    if ((u64)kclf_task_mm(current) != r->mm) {
        kclf_free_user(r, 0);
        kclf_fail(r, KCLF_FAILED, KCLF_ST_HIJACK, -ESRCH, "target address space replaced");
        r->busy = 0;
        return;
    }

    rc = kclf_exec_hijack(r);
    if (rc == -EAGAIN) {
        if (++r->retries < 8) {
            kclf_ks.task_work_add(current, &r->work_hijack, KCLF_TWA_RESUME);
            r->busy = 0;
            return;
        }
        kclf_free_user(r, 0);
        kclf_fail(r, KCLF_FAILED, KCLF_ST_HIJACK, rc,
                  "no safe point in %u attempts (busy linker/allocator context); retry or use force",
                  r->retries);
        r->busy = 0;
        return;
    }
    if (rc) {
        kclf_free_user(r, 0);
        kclf_fail(r, KCLF_FAILED, KCLF_ST_HIJACK, rc, rc == -EOPNOTSUPP ? "32-bit target unsupported" : "");
        r->busy = 0;
        return;
    }

    r->run_task = (u64)current;
    __atomic_add_fetch(&kclf_loading_num, 1, __ATOMIC_SEQ_CST);
    r->state = KCLF_RUNNING;
    r->busy = 0;
}

static void kclf_work_cleanup(struct callback_head *head)
{
    struct kclf_req *r = local_container_of(head, struct kclf_req, work_cleanup);
    int st = r->state;
    s64 handle = r->handle;
    long rc = 0;

    r->busy = 1;
    if ((u64)kclf_task_mm(current) == r->mm) {
        if (r->map_addr) {
            rc = kclf_exec_finish(r, 1);
            if (rc && ++r->cleanup_tries <= 8) {
                kclf_ks.task_work_add(current, &r->work_cleanup, KCLF_TWA_RESUME);
                r->busy = 0;
                return;
            }
            if (rc) kclf_set_err(r, "munmap failed rc=%ld after %d retries", rc, r->cleanup_tries);
        }
    } else {
        /* The address space is gone; its mappings went with it. */
        r->map_addr = 0;
        r->map_len = 0;
    }
    r->finished = 1;
    r->busy = 0;

    if (st == KCLF_RUNNING) {
        /* trampoline finished but the completion trap was not consumed */
        kclf_fail(r, KCLF_FAILED, KCLF_ST_RESTORE, -EPROTO, "completion trap missed");
    } else if (st == KCLF_DONE && !handle) {
        /* the framework restored the target, the loader itself failed */
        kclf_fail(r, KCLF_FAILED, KCLF_ST_LOADER, 0, "");
        if (!r->err[0]) snprintf(r->err, sizeof(r->err), "loader returned no handle");
    }
}

/* ------------------------------------------------------------------ */
/* completion trap: getpid(cookie) is consumed here                     */
/* ------------------------------------------------------------------ */

static void kclf_getpid_before(hook_fargs4_t *args, void *udata)
{
    struct pt_regs *regs;
    struct kclf_req *r;

    (void)udata;
    if (!kclf_loading_num || !has_syscall_wrapper) return;
    regs = (struct pt_regs *)args->args[0];
    if (!regs) return;
    r = kclf_slot_by_task(current);
    if (!r || !r->saved_valid || r->state != KCLF_RUNNING) return;
    if (regs->regs[0] != r->cookie) return;
    if (regs->regs[8] != KCLF_COMPLETION_NR) return;
    /* The trampoline passes the loader result in registers because its
     * parameter page has already been scrubbed. */
    r->handle = (s64)regs->regs[1];
    r->err_user = regs->regs[2];
    r->unload_rc = (s32)regs->regs[3];
    if (r->flags & KCLF_F_UNLOAD) r->unloaded = (r->unload_rc == 0);
    r->completing = 1;
    args->skip_origin = 1;
    args->ret = 0;
}

static void kclf_getpid_after(hook_fargs4_t *args, void *udata)
{
    struct pt_regs *regs;
    struct kclf_req *r;

    (void)udata;
    if (!kclf_loading_num) return;
    r = kclf_slot_by_task(current);
    if (!r || !r->completing) return;
    r->completing = 0;
    regs = (struct pt_regs *)args->args[0];
    if (!regs) {
        kclf_fail(r, KCLF_FAILED, KCLF_ST_RESTORE, -EPROTO, "no register frame on completion");
        return;
    }
    kclf_exec_restore(r, regs);
    /* the wrapper writes its return value into x0 after this hook; hand it the
     * value the interrupted program must observe */
    args->ret = regs->regs[0];
    r->state = KCLF_DONE;
    r->j_done = kclf_now();
    __atomic_sub_fetch(&kclf_loading_num, 1, __ATOMIC_SEQ_CST);
    kclf_ks.task_work_add(current, &r->work_cleanup, KCLF_TWA_RESUME);
}

static int kclf_hook_install(void)
{
    hook_err_t rc;

    if (!has_syscall_wrapper) {
        logkw("kclf: no syscall wrapper, completion backend unavailable\n");
        return 0;
    }
    rc = hook_syscalln(KCLF_COMPLETION_NR, 0, kclf_getpid_before, kclf_getpid_after, 0);
    if (rc) {
        logke("kclf: hook getpid failed: %d\n", rc);
        return rc;
    }
    kclf_hook_ok = 1;
    return 0;
}

/* ------------------------------------------------------------------ */
/* control plane                                                        */
/* ------------------------------------------------------------------ */

static void kclf_status_line(char *out, int outlen, int *off, struct kclf_req *r)
{
    int i = KCLF_SLOT_OFFSET(r);
    *off += snprintf(out + *off, outlen - *off, "#%d id=%llu pid=%d(%s) state=%s stage=%s", i,
                     (unsigned long long)r->id, r->pid, r->comm, kclf_state_name(r->state),
                     kclf_stage_name(r->stage));
    if (r->state == KCLF_DONE) {
        *off += snprintf(out + *off, outlen - *off, " handle=%llx", (unsigned long long)r->handle);
        if (r->ld.sym)
            *off += snprintf(out + *off, outlen - *off, " via=%s", r->ld.sym);
        if (r->flags & KCLF_F_UNLOAD) {
            *off += snprintf(out + *off, outlen - *off, " unload=%s rc=%d",
                             r->unloaded ? "ok" : "failed", r->unload_rc);
            if (r->ld.close_sym)
                *off += snprintf(out + *off, outlen - *off, " by=%s", r->ld.close_sym);
        }
    }
    if (r->map_addr)
        *off += snprintf(out + *off, outlen - *off, " map=%llx+%llu", (unsigned long long)r->map_addr,
                         (unsigned long long)r->map_len);
    if (r->err[0]) *off += snprintf(out + *off, outlen - *off, " err=\"%s\"", r->err);
    *off += snprintf(out + *off, outlen - *off, "\n");
}

static long kclf_cmd_inject(char *tok[], int ntok, char *out, int outlen, int *off)
{
    long pid = 0;
    const char *path;
    int flags = 0;
    int i;
    struct kclf_req *r;
    struct task_struct *task;
    struct mm_struct *mm;
    u64 cookie;
    int rc;

    if (!kclf_hook_ok) {
        *off += snprintf(out + *off, outlen - *off, "error: completion backend unavailable\n");
        return -EOPNOTSUPP;
    }
    if (!kclf_ks.copy_from_user) {
        *off += snprintf(out + *off, outlen - *off, "error: user copy primitive unavailable\n");
        return -EOPNOTSUPP;
    }
    if (ntok < 3) {
        *off += snprintf(out + *off, outlen - *off,
                         "error: usage inject,<tid>,<path>[,force][,wake][,unload]\n");
        return -EINVAL;
    }
    for (i = 0; tok[1][i]; i++) {
        if (tok[1][i] < '0' || tok[1][i] > '9') {
            *off += snprintf(out + *off, outlen - *off, "error: bad tid\n");
            return -EINVAL;
        }
        pid = pid * 10 + (tok[1][i] - '0');
    }
    if (!pid) {
        *off += snprintf(out + *off, outlen - *off, "error: bad tid\n");
        return -EINVAL;
    }
    path = tok[2];
    for (i = 3; i < ntok; i++) {
        if (strstr(tok[i], "force")) flags |= KCLF_F_FORCE;
        if (strstr(tok[i], "wake")) flags |= KCLF_F_WAKE;
        if (strstr(tok[i], "unload")) flags |= KCLF_F_UNLOAD;
        /* "resume" is accepted for compatibility: it is the default now */
    }
    if (path[0] != '/') {
        *off += snprintf(out + *off, outlen - *off, "error: path must be absolute\n");
        return -EINVAL;
    }
    if (strlen(path) >= KCLF_PATH_MAX) {
        *off += snprintf(out + *off, outlen - *off, "error: path too long\n");
        return -EINVAL;
    }

    r = kclf_slot_alloc();
    if (!r) {
        *off += snprintf(out + *off, outlen - *off, "error: no free request slot\n");
        return -EBUSY;
    }

    task = kclf_ks.find_task_by_vpid((pid_t)pid);
    if (!task) {
        *off += snprintf(out + *off, outlen - *off, "error: no such task\n");
        kclf_slot_reset(r);
        return -ESRCH;
    }
    mm = kclf_task_mm(task);
    if (!mm) {
        *off += snprintf(out + *off, outlen - *off, "error: kernel thread\n");
        kclf_slot_reset(r);
        return -EINVAL;
    }
    if (!thread_size) {
        *off += snprintf(out + *off, outlen - *off, "error: thread size unknown\n");
        kclf_slot_reset(r);
        return -EINVAL;
    }

    kclf_slot_reset(r);
    r->id = __atomic_fetch_add(&kclf_next_id, 1, __ATOMIC_SEQ_CST);
    r->pid = (pid_t)pid;
    r->tgid = (pid_t)pid;
    r->mm = (u64)mm;
    r->pgd = kclf_mm_pgd(mm);
    r->task = (u64)task;
    r->flags = flags;
    r->stage = KCLF_ST_QUEUE;
    snprintf(r->comm, sizeof(r->comm), "%s", get_task_comm(task));
    strncpy(r->path, path, sizeof(r->path) - 1);
    cookie = get_random_u64();
    r->cookie = cookie ? cookie : 0x6b636c66deadbeefULL;
    r->j_queued = kclf_now();
    r->state = KCLF_ARMED;

    /*
     * Default is TWA_RESUME: the request is picked up at the next return to
     * user mode without touching the target's signal state, waking it, or
     * restarting an interrupted syscall.  A target blocked in an interruptible
     * sleep only processes it when that sleep ends; the "wake" flag opts back
     * into the old signal-assisted path when low latency matters more than
     * leaving the target's timing alone.
     */
    r->woke = 0;
    if ((flags & KCLF_F_WAKE) && kclf_ks.signal_wake_up_state) {
        kclf_ks.signal_wake_up_state(task, 0);
        r->woke = 1;
    }

    rc = kclf_ks.task_work_add(task, &r->work_prepare,
                               r->woke ? KCLF_TWA_SIGNAL : KCLF_TWA_RESUME);
    if (rc) {
        *off += snprintf(out + *off, outlen - *off, "error: queue failed %d\n", rc);
        kclf_fail(r, KCLF_FAILED, KCLF_ST_QUEUE, rc, "task_work_add failed");
        return rc;
    }

    *off += snprintf(out + *off, outlen - *off, "queued id=%llu tid=%d comm=%s path=%s mode=%s%s%s\n",
                     (unsigned long long)r->id, r->pid, r->comm, r->path,
                     (flags & KCLF_F_FORCE) ? "force" : "safe", (flags & KCLF_F_WAKE) ? ",wake" : "",
                     (flags & KCLF_F_UNLOAD) ? ",unload" : "");
    return 0;
}

static long kclf_cmd_cancel(char *tok[], int ntok, char *out, int outlen, int *off)
{
    int idx = 0;
    int i;
    struct kclf_req *r;

    if (ntok < 2) {
        *off += snprintf(out + *off, outlen - *off, "error: usage cancel,<slot>\n");
        return -EINVAL;
    }
    for (i = 0; tok[1][i]; i++) {
        if (tok[1][i] < '0' || tok[1][i] > '9') {
            *off += snprintf(out + *off, outlen - *off, "error: usage cancel,<slot>\n");
            return -EINVAL;
        }
        idx = idx * 10 + (tok[1][i] - '0');
    }
    if (idx < 0 || idx >= KCLF_MAX_REQ) return -EINVAL;
    r = &kclf_reqs[idx];

    if (r->state == KCLF_RUNNING) {
        *off += snprintf(out + *off, outlen - *off, "error: request already in loader, not cancellable\n");
        return -EBUSY;
    }
    if (r->state == KCLF_IDLE) {
        *off += snprintf(out + *off, outlen - *off, "error: idle slot\n");
        return -EINVAL;
    }
    if (r->state == KCLF_ARMED || r->state == KCLF_READY) {
        kclf_cancel_work(r, &r->work_prepare);
        kclf_cancel_work(r, &r->work_hijack);
    }
    r->stage = KCLF_ST_HIJACK;
    r->state = KCLF_CANCELLED;
    r->j_done = kclf_now();
    snprintf(r->err, sizeof(r->err), "cancelled by controller");
    *off += snprintf(out + *off, outlen - *off, "cancelled #%d id=%llu\n", idx, (unsigned long long)r->id);
    return 0;
}

static long kclf_cmd_status(char *out, int outlen, int *off)
{
    int i, n = 0;
    for (i = 0; i < KCLF_MAX_REQ; i++) {
        struct kclf_req *r = &kclf_reqs[i];
        if (r->state == KCLF_IDLE) continue;
        kclf_status_line(out, outlen, off, r);
        n++;
    }
    if (!n) *off += snprintf(out + *off, outlen - *off, "no requests\n");
    *off += snprintf(out + *off, outlen - *off, "hook=%s loading=%d page=%d\n", kclf_hook_ok ? "getpid" : "none",
                     kclf_loading_num, kclf_page_size);
    return 0;
}

static long kclf_cmd_reap(char *out, int outlen, int *off)
{
    int i;
    for (i = 0; i < KCLF_MAX_REQ; i++) {
        struct kclf_req *r = &kclf_reqs[i];
        struct task_struct *task = 0;
        int alive;

        if (r->state == KCLF_IDLE || r->busy) continue;
        if (r->state == KCLF_DONE || r->state == KCLF_FAILED || r->state == KCLF_CANCELLED) {
            if (r->finished && !r->map_addr) {
                kclf_slot_reset(r);
                *off += snprintf(out + *off, outlen - *off, "reclaimed #%d\n", i);
            } else if (r->map_addr) {
                *off += snprintf(out + *off, outlen - *off, "cleanup incomplete #%d map=%llx len=%llu\n", i,
                                 (unsigned long long)r->map_addr, (unsigned long long)r->map_len);
            }
            continue;
        }
        if (kclf_rcu_read_lock) {
            kclf_rcu_read_lock();
            task = kclf_ks.find_task_by_vpid(r->pid);
            alive = kclf_task_alive(task, r);
            kclf_rcu_read_unlock();
        } else {
            task = kclf_ks.find_task_by_vpid(r->pid);
            alive = kclf_task_alive(task, r);
        }
        if (!alive) {
            *off += snprintf(out + *off, outlen - *off, "target gone for #%d id=%llu\n", i,
                             (unsigned long long)r->id);
            kclf_fail(r, KCLF_FAILED, r->stage, -ESRCH, "target exited or exec'd");
            r->map_addr = 0;
            r->finished = 1;
        }
    }
    return 0;
}

static long kclf_cmd_sym(char *out, int outlen, int *off)
{
    static const char *const names[] = {
        "__copy_from_user",       "copy_from_user",        "fault_in_pages_readable", "access_process_vm",
        "_copy_from_user",        "__arch_copy_from_user", "__arch_copy_to_user",     "_copy_to_user",
        "copy_from_user_nofault", "task_work_add",         "task_work_cancel",        "task_work_cancel_func",
        "find_task_by_vpid",      "vm_mmap",               "vm_munmap",               "find_vma",
        "filp_open",              "kernel_read",           "fput",                    "get_task_mm",
        "mmput",                  "__rcu_read_lock",       "__rcu_read_unlock",       "ktime_get",
        "msleep",                 "init_mm",               "init_task",               "page_offset_base",
    };
    unsigned int i;

    *off += snprintf(out + *off, outlen - *off, "copiers: from=%llx to=%llx\n",
                     (unsigned long long)kclf_ks.copy_from_user, (unsigned long long)kclf_ks.copy_to_user);
    for (i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        unsigned long a = kclf_lookup(names[i]);
        *off += snprintf(out + *off, outlen - *off, "%-24s %llx\n", names[i], (unsigned long long)a);
    }
    *off += snprintf(out + *off, outlen - *off, "mm_off=%d stack_off=%d pid_off=%d tsize=%d\n", kclf_mm_off,
                     stack_in_task_offset, task_struct_offset.pid_offset, thread_size);
    return 0;
}

/*
 * The ctl0 channel reaches the module as a single string; controllers may
 * quote it or not, so the grammar is separator tolerant:
 *
 *   inject,<tid>,<path>[,force][,wake][,unload]
 *   inject <tid> <path> [force] [wake] [unload]
 */
#define KCLF_MAX_TOK 8

static int kclf_tokenize(const char *args, char *buf, int buflen, char *tok[], int maxtok)
{
    int n = 0;
    int len = 0;

    while (args[len] && len < buflen - 1) {
        char c = args[len];
        buf[len] = (c == ',' || c == '\t' || c == '\n') ? ' ' : c;
        len++;
    }
    buf[len] = 0;

    for (int i = 0; i < len && n < maxtok;) {
        while (buf[i] == ' ') buf[i++] = 0;
        if (!buf[i]) break;
        tok[n++] = buf + i;
        while (buf[i] && buf[i] != ' ') i++;
    }
    return n;
}

static void kclf_usage(char *out, int outlen, int *off)
{
    *off += snprintf(out + *off, outlen - *off,
                     "kclf " KCLF_VER " - no-ptrace library loading\n"
                     "  probe                      resolve loader symbols, check the trap\n"
                     "  inject,<tid>,<path>[,force][,wake][,unload]   queue a load request\n"
                     "  status                     request table\n"
                     "  cancel,<slot>              cancel a queued request\n"
                     "  reap                       reclaim finished slots / dead targets\n"
                     "  sym                        kernel symbol resolution dump\n"
                     "  help                       this text\n");
}

static long kclf_ctl0(const char *args, char *__user out_msg, int outlen)
{
    char out[1024];
    char argv_buf[512];
    char *tok[KCLF_MAX_TOK];
    int ntok = 0;
    int off = 0;
    long rc = 0;

    if (!args) return -EINVAL;
    out[0] = 0;
    ntok = kclf_tokenize(args, argv_buf, sizeof(argv_buf), tok, KCLF_MAX_TOK);

    if (!ntok) {
        kclf_usage(out, sizeof(out), &off);
    } else if (!strcmp(tok[0], "probe")) {
        int n = kclf_exec_probe(out, sizeof(out) - 64);
        if (n > 0) off = n;
        off += snprintf(out + off, sizeof(out) - off, "hook=%s syscall_wrapper=%d\n", kclf_hook_ok ? "getpid" : "none",
                        has_syscall_wrapper);
    } else if (!strcmp(tok[0], "inject")) {
        rc = kclf_cmd_inject(tok, ntok, out, sizeof(out), &off);
    } else if (!strcmp(tok[0], "status")) {
        rc = kclf_cmd_status(out, sizeof(out), &off);
    } else if (!strcmp(tok[0], "cancel")) {
        rc = kclf_cmd_cancel(tok, ntok, out, sizeof(out), &off);
    } else if (!strcmp(tok[0], "reap")) {
        rc = kclf_cmd_reap(out, sizeof(out), &off);
    } else if (!strcmp(tok[0], "sym")) {
        rc = kclf_cmd_sym(out, sizeof(out), &off);
    } else {
        kclf_usage(out, sizeof(out), &off);
        if (strcmp(tok[0], "help")) rc = -EINVAL;
    }

    if (out_msg && outlen > 0) {
        if (off > outlen - 1) off = outlen - 1;
        if (off < 0) off = 0;
        out[off] = 0;
        compat_copy_to_user(out_msg, out, off + 1);
    }
    return rc;
}

/* ------------------------------------------------------------------ */
/* lifecycle                                                            */
/* ------------------------------------------------------------------ */

static long kclf_init(const char *args, const char *event, void *reserved)
{
    int rc;

    (void)args;
    (void)event;
    (void)reserved;

    for (rc = 0; rc < KCLF_MAX_REQ; rc++) kclf_slot_reset(&kclf_reqs[rc]);
    kclf_page_size = kclf_detect_page_size();
    if (!kclf_page_size || (kclf_page_size & (kclf_page_size - 1))) {
        logke("kclf: bad page size %d\n", kclf_page_size);
        return -EINVAL;
    }
    if (stack_in_task_offset <= 0 || !thread_size) {
        logke("kclf: task layout unknown stack=%d tsize=%d\n", stack_in_task_offset, thread_size);
        return -EINVAL;
    }

    rc = kclf_sym_lookup_all();
    if (rc) return rc;

    kclf_mm_off = kclf_probe_mm_offset();
    if (kclf_mm_off <= 0) {
        logke("kclf: cannot determine task_struct.mm offset\n");
        return -EINVAL;
    }
    kclf_pid_off = task_struct_offset.pid_offset;
    kclf_exec_init();

    rc = kclf_hook_install();
    if (rc) {
        /* keep the module loaded so the failure is inspectable */
        logkw("kclf: running without completion backend\n");
    }

    kclf_ready = 1;
    return 0;
}

static long kclf_exit(void *reserved)
{
    int i;
    int wait;

    (void)reserved;
    kclf_unloading = 1;

    /* drop queued work: leaving a callback_head in a task_work list after the
     * module text is freed would be an arbitrary call into freed memory */
    for (i = 0; i < KCLF_MAX_REQ; i++) {
        struct kclf_req *r = &kclf_reqs[i];
        if (r->state == KCLF_IDLE) continue;
        if (r->state == KCLF_ARMED) kclf_cancel_work(r, &r->work_prepare);
        if (r->state == KCLF_READY) kclf_cancel_work(r, &r->work_hijack);
        if (r->state == KCLF_PREPARING) r->state = KCLF_CANCELLED;
    }

    /* Let in-flight callbacks drain before the completion hook disappears.
     * Removing the hook first would make a trampoline that is already running
     * execute the real getpid and then spin forever at its final branch.  A
     * request that still owns a transient map also has a cleanup callback
     * pending, even after loading_num reached zero. */
    for (wait = 0; wait < 3000; wait++) {
        int busy = 0;
        for (i = 0; i < KCLF_MAX_REQ; i++) {
            struct kclf_req *r = &kclf_reqs[i];
            if (r->busy || r->completing) busy = 1;
            if (r->state != KCLF_IDLE && r->map_addr) busy = 1;
        }
        if (!busy && !kclf_loading_num) break;
        if (kclf_ks.msleep)
            kclf_ks.msleep(1);
        else
            break;
    }
    for (i = 0; i < KCLF_MAX_REQ; i++) {
        struct kclf_req *r = &kclf_reqs[i];
        if (r->state == KCLF_IDLE) continue;
        /* A retry must not call into module text after it is freed.  If it did
         * not run during the drain window, the transient map leaks until the
         * target exits; that is safer than a use-after-free callback. */
        kclf_cancel_work(r, &r->work_cleanup);
    }
    if (kclf_hook_ok) {
        unhook_syscalln(KCLF_COMPLETION_NR, kclf_getpid_before, kclf_getpid_after);
        kclf_hook_ok = 0;
    }
    for (i = 0; i < KCLF_MAX_REQ; i++) {
        if (kclf_reqs[i].busy || kclf_reqs[i].completing)
            logkw("kclf: unloaded with request %d still in flight\n", i);
    }
    kclf_ready = 0;
    return 0;
}

KPM_INIT(kclf_init);
KPM_CTL0(kclf_ctl0);
KPM_EXIT(kclf_exit);
