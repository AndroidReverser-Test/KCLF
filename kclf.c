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
#include <common.h>
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
u64 kclf_user_limit;
int kclf_user_tbi;
int kclf_ready;
int kclf_mm_off = -1;

static u64 kclf_next_id = 1;
static int kclf_hook_ok;
static int kclf_control_busy;
static void (*kclf_rcu_read_lock)(void);
static void (*kclf_rcu_read_unlock)(void);
static u64 (*kclf_ktime_get)(void);

#define KCLF_SLOT_OFFSET(r) ((int)((r)-kclf_reqs))

/* the module cannot link against the kernel's page_size symbol */
static int kclf_detect_page_size(void)
{
    u64 tcr = 0;
    u64 tg0;

    asm volatile("mrs %0, tcr_el1" : "=r"(tcr));
    unsigned int va_bits = 64 - (tcr & 63);
    if (va_bits < 32 || va_bits > 52) return 0;
    kclf_user_limit = 1ULL << va_bits;
    kclf_user_tbi = !!(tcr & (1ULL << 37));
    tg0 = (tcr >> 14) & 3;
    if (tg0 == 0) return 4096;
    if (tg0 == 2) return 16384;
    if (tg0 == 1) return 65536;
    return 0; /* reserved granule: fail closed */
}

static const char *kclf_state_name(int state)
{
    switch (state) {
    case KCLF_IDLE:
        return "idle";
    case KCLF_ARMED:
        return "armed";
    case KCLF_PREPARING:
        return "preparing";
    case KCLF_READY:
        return "ready";
    case KCLF_RUNNING:
        return "running";
    case KCLF_DONE:
        return "done";
    case KCLF_FAILED:
        return "failed";
    case KCLF_CANCELLED:
        return "cancelled";
    default:
        return "?";
    }
}

static const char *kclf_stage_name(int stage)
{
    switch (stage) {
    case KCLF_ST_NONE:
        return "-";
    case KCLF_ST_QUEUE:
        return "queue";
    case KCLF_ST_PREPARE:
        return "prepare";
    case KCLF_ST_HIJACK:
        return "hijack";
    case KCLF_ST_LOADER:
        return "loader";
    case KCLF_ST_RESTORE:
        return "restore";
    default:
        return "?";
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

/* Exact-name lookup; do not guess unrelated LTO/CFI symbol suffixes. */
unsigned long kclf_lookup(const char *name)
{
    return kallsyms_lookup_name(name);
}

int kclf_sym_lookup_all(void)
{
    const char *missing = 0;

    memset(&kclf_ks, 0, sizeof(kclf_ks));

#define KCLF_KS(field, symbol)                                      \
    do {                                                            \
        kclf_ks.field = (typeof(kclf_ks.field))kclf_lookup(symbol); \
        if (!kclf_ks.field && !missing) missing = symbol;           \
    } while (0)

    KCLF_KS(task_work_add, "task_work_add");
    /* Android backports changed task_work_cancel from func->pointer to
     * object->bool. Prefer the unambiguous match/func APIs, not a version test. */
    kclf_ks.task_work_cancel_match = (typeof(kclf_ks.task_work_cancel_match))kclf_lookup("task_work_cancel_match");
    kclf_ks.task_work_cancel_func = (typeof(kclf_ks.task_work_cancel_func))kclf_lookup("task_work_cancel_func");
    if (!kclf_ks.task_work_cancel_func && !kclf_ks.task_work_cancel_match)
        kclf_ks.task_work_cancel_func = (typeof(kclf_ks.task_work_cancel_func))kclf_lookup("task_work_cancel");
    if (!kclf_ks.task_work_cancel_func && !kclf_ks.task_work_cancel_match) missing = "task_work_cancel*";
    KCLF_KS(find_get_pid, "find_get_pid");
    KCLF_KS(pid_task, "pid_task");
    KCLF_KS(put_pid, "put_pid");
    kclf_ks.get_task_pid = (typeof(kclf_ks.get_task_pid))kclf_lookup("get_task_pid");
    kclf_ks.vmalloc = (typeof(kclf_ks.vmalloc))kclf_lookup("vmalloc");
    if (!kclf_ks.vmalloc) kclf_ks.vmalloc = (typeof(kclf_ks.vmalloc))kclf_lookup("vmalloc_noprof");
    kclf_ks.vfree = (typeof(kclf_ks.vfree))kclf_lookup("vfree");
    kclf_ks.vfs_llseek = (typeof(kclf_ks.vfs_llseek))kclf_lookup("vfs_llseek");
    KCLF_KS(vm_mmap, "vm_mmap");
    KCLF_KS(vm_munmap, "vm_munmap");
    kclf_ks.find_vma = (typeof(kclf_ks.find_vma))kclf_lookup("find_vma");
    KCLF_KS(filp_open, "filp_open");
    KCLF_KS(kernel_read, "kernel_read");
    kclf_ks.vfs_read = (typeof(kclf_ks.vfs_read))kclf_lookup("vfs_read");
    KCLF_KS(fput, "fput");
    kclf_ks.copy_from_user_nofault = (typeof(kclf_ks.copy_from_user_nofault))kclf_lookup("copy_from_user_nofault");
    if (!kclf_ks.copy_from_user_nofault)
        kclf_ks.copy_from_user_nofault = (typeof(kclf_ks.copy_from_user_nofault))kclf_lookup("probe_user_read");
    KCLF_KS(access_process_vm, "access_process_vm");
    KCLF_KS(get_task_mm, "get_task_mm");
    KCLF_KS(mmput_async, "mmput_async");
#undef KCLF_KS

    kclf_rcu_read_lock = (typeof(kclf_rcu_read_lock))kclf_lookup("__rcu_read_lock");
    kclf_rcu_read_unlock = (typeof(kclf_rcu_read_unlock))kclf_lookup("__rcu_read_unlock");
    kclf_ktime_get = (typeof(kclf_ktime_get))kclf_lookup("ktime_get");
    kclf_ks.down_read = (typeof(kclf_ks.down_read))kclf_lookup("down_read");
    kclf_ks.up_read = (typeof(kclf_ks.up_read))kclf_lookup("up_read");
    kclf_ks.mmap_read_lock = (typeof(kclf_ks.mmap_read_lock))kclf_lookup("mmap_read_lock");
    kclf_ks.mmap_read_unlock = (typeof(kclf_ks.mmap_read_unlock))kclf_lookup("mmap_read_unlock");
    kclf_ks.msleep = (typeof(kclf_ks.msleep))kclf_lookup("msleep");

    if (missing) {
        logke("kclf: kernel symbol missing: %s\n", missing);
        return -ENOENT;
    }
    if (!kclf_rcu_read_lock || !kclf_rcu_read_unlock) {
        logke("kclf: RCU accessor pair required for task lookup\n");
        return -EOPNOTSUPP;
    }
    return 0;
}

/* RESUME=1 is also true for the old bool task_work_add ABI. */
#define KCLF_TWA_RESUME 1
#define KCLF_TWA_SIGNAL 2

/* ------------------------------------------------------------------ */
/* slot bookkeeping                                                     */
/* ------------------------------------------------------------------ */

static int kclf_task_alive(struct task_struct *task, struct kclf_req *r)
{
    if (!task || (u64)task != r->task) return 0;
    if ((u64)kclf_task_mm(task) != r->mm) return 0;
    return 1;
}

int kclf_process_mm_alive(struct pid *pid, u64 identity)
{
    struct task_struct *task;
    struct mm_struct *mm = 0;
    int alive;
    kclf_rcu_read_lock();
    task = pid ? kclf_ks.pid_task(pid, 1 /* PIDTYPE_TGID */) : 0;
    if (task) mm = kclf_task_mm(task);
    /* A zombie group leader may have living threads with the original mm. */
    alive = task && (!mm || (u64)mm == identity);
    kclf_rcu_read_unlock();
    return alive;
}

static bool kclf_work_matches(struct callback_head *work, void *data)
{
    return work == data;
}

/* Only one active request per task; the old function-based cancellation is
 * therefore unambiguous too. RCU protects lookup through cancellation. */
static int kclf_cancel_work(struct kclf_req *r, struct callback_head *work)
{
    struct task_struct *task;
    struct callback_head *removed = 0;

    kclf_rcu_read_lock();
    task = r->pid_ref ? kclf_ks.pid_task(r->pid_ref, 0) : 0;
    if (task && (u64)task == r->task) {
        if (kclf_ks.task_work_cancel_match)
            removed = kclf_ks.task_work_cancel_match(task, kclf_work_matches, work);
        else
            removed = kclf_ks.task_work_cancel_func(task, work->func);
    }
    kclf_rcu_read_unlock();
    if (removed != work) return 0; /* already detached/running is NOT cancelled */
    __atomic_sub_fetch(&r->pending, 1, __ATOMIC_RELEASE);
    return 1;
}

static int kclf_queue_work(struct kclf_req *r, struct task_struct *task, struct callback_head *work, int notify)
{
    int rc;
    __atomic_add_fetch(&r->pending, 1, __ATOMIC_ACQ_REL);
    rc = kclf_ks.task_work_add(task, work, notify);
    if (rc) __atomic_sub_fetch(&r->pending, 1, __ATOMIC_RELEASE);
    return rc;
}

static void kclf_work_prepare(struct callback_head *head);
static void kclf_work_hijack(struct callback_head *head);
static void kclf_work_cleanup(struct callback_head *head);

static void kclf_slot_reset(struct kclf_req *r)
{
    if (r->image) kclf_manual_abandon(r);
    /* The target mm is deliberately NOT pinned for the request lifetime.
     * Holding mm_users after the target exits defers exit_mmap(), which in
     * turn defers binder VMA teardown and makes ActivityManager wait for a
     * process that is already gone ("refused to die"). The (pinned) struct pid
     * keeps the PID identity stable; callbacks verify current->mm instead. */
    if (r->pid_ref) kclf_ks.put_pid(r->pid_ref);
    memset(r, 0, sizeof(*r));
    kclf_state_store(r, KCLF_IDLE);
    r->work_prepare.func = kclf_work_prepare;
    r->work_hijack.func = kclf_work_hijack;
    r->work_cleanup.func = kclf_work_cleanup;
}

static int kclf_slot_reclaimable(struct kclf_req *r)
{
    int state;
    if (!__atomic_load_n(&r->finished, __ATOMIC_ACQUIRE)) return 0;
    state = kclf_state_load(r);
    if (state != KCLF_DONE && state != KCLF_FAILED && state != KCLF_CANCELLED) return 0;
    /* Completion must precede the FINAL reference check: RUNNING/0 can race
     * newly queued cleanup publishing finished=1 while still in its callback. */
    return !r->map_addr && !r->busy && !r->completing && !__atomic_load_n(&r->pending, __ATOMIC_ACQUIRE);
}

static struct kclf_req *kclf_slot_alloc(void)
{
    struct kclf_req *free_slot = 0;
    int i;

    for (i = 0; i < KCLF_MAX_REQ; i++) {
        struct kclf_req *r = &kclf_reqs[i];
        if (kclf_state_load(r) == KCLF_IDLE) return r;
        /* only reclaim slots whose target side resources are gone */
        if (kclf_slot_reclaimable(r)) {
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
        if (kclf_state_load(r) != KCLF_RUNNING || r->run_task != (u64)task) continue;
        /* A reused task_struct address must not be mistaken for the thread
         * that actually runs the trampoline: the pinned struct pid is the
         * authoritative identity. */
        if (r->pid_ref) {
            struct task_struct *owner;
            kclf_rcu_read_lock();
            owner = kclf_ks.pid_task(r->pid_ref, 0);
            kclf_rcu_read_unlock();
            if (owner != task) continue;
        }
        return r;
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
            if (kclf_queue_work(r, current, &r->work_cleanup, KCLF_TWA_RESUME))
                kclf_set_err(r, "munmap failed; cleanup queue rejected");
            return;
        }
    } else {
        kclf_manual_abandon(r);
        r->map_addr = 0;
        r->map_len = 0;
    }
    __atomic_store_n(&r->finished, 1, __ATOMIC_RELEASE);
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
    kclf_state_store(r, state);
    r->j_done = kclf_now();
}

/* ------------------------------------------------------------------ */
/* task_work callbacks (run inside the target task, mm == target mm)     */
/* ------------------------------------------------------------------ */

static void kclf_work_prepare_body(struct callback_head *head)
{
    struct kclf_req *r = local_container_of(head, struct kclf_req, work_prepare);
    struct mm_struct *mm;
    long rc;

    if ((kclf_unloading && !(r->flags & KCLF_F_RELEASE)) || kclf_state_load(r) != KCLF_ARMED) {
        kclf_fail(r, KCLF_CANCELLED, KCLF_ST_QUEUE, -ECANCELED, "quiescing");
        __atomic_store_n(&r->finished, 1, __ATOMIC_RELEASE);
        return;
    }
    r->busy = 1;
    kclf_state_store(r, KCLF_PREPARING);
    r->stage = KCLF_ST_PREPARE;

    mm = kclf_task_mm(current);
    if (!mm || (u64)mm != r->mm) {
        kclf_fail(r, KCLF_FAILED, KCLF_ST_PREPARE, -ESRCH, "target address space replaced");
        __atomic_store_n(&r->finished, 1, __ATOMIC_RELEASE);
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
    r->stage = KCLF_ST_HIJACK;
    kclf_state_store(r, KCLF_READY);
    rc = kclf_queue_work(r, current, &r->work_hijack, KCLF_TWA_RESUME);
    if (rc) {
        kclf_free_user(r, 0);
        kclf_fail(r, KCLF_FAILED, KCLF_ST_HIJACK, rc, "cannot arm return boundary work");
    }
    r->busy = 0;
}

static void kclf_work_hijack_body(struct callback_head *head)
{
    struct kclf_req *r = local_container_of(head, struct kclf_req, work_hijack);
    int rc;

    if ((kclf_unloading && !(r->flags & KCLF_F_RELEASE)) || kclf_state_load(r) != KCLF_READY) {
        kclf_free_user(r, 0);
        kclf_fail(r, KCLF_CANCELLED, KCLF_ST_HIJACK, -ECANCELED, "quiescing");
        return;
    }
    r->busy = 1;

    if ((u64)kclf_task_mm(current) != r->mm) {
        kclf_free_user(r, 0);
        kclf_fail(r, KCLF_FAILED, KCLF_ST_HIJACK, -ESRCH, "target address space replaced");
        r->busy = 0;
        return;
    }

    rc = kclf_exec_hijack(r);
    if (rc == -EAGAIN) {
        /* Requeueing inside task_work_run repeats the SAME return boundary;
         * it cannot find a different safe point. Fail and let the caller retry. */
        kclf_free_user(r, 0);
        kclf_fail(r, KCLF_FAILED, KCLF_ST_HIJACK, rc, "unsafe return boundary; retry later");
        r->busy = 0;
        return;
    }
    if (rc) {
        kclf_free_user(r, 0);
        kclf_fail(r, KCLF_FAILED, KCLF_ST_HIJACK, rc, "");
        r->busy = 0;
        return;
    }

    r->run_task = (u64)current;
    r->stage = KCLF_ST_LOADER;
    __atomic_add_fetch(&kclf_loading_num, 1, __ATOMIC_SEQ_CST);
    kclf_state_store(r, KCLF_RUNNING);
    r->busy = 0;
}

static void kclf_work_cleanup_body(struct callback_head *head)
{
    struct kclf_req *r = local_container_of(head, struct kclf_req, work_cleanup);
    int st = kclf_state_load(r);
    s64 handle = r->handle;
    long rc = 0;

    r->busy = 1;
    if ((u64)kclf_task_mm(current) == r->mm) {
        if (r->map_addr) {
            rc = kclf_exec_finish(r, 1);
            if (rc && ++r->cleanup_tries <= 8) {
                if (!kclf_queue_work(r, current, &r->work_cleanup, KCLF_TWA_RESUME)) {
                    r->busy = 0;
                    return;
                }
            }
            if (rc) kclf_set_err(r, "munmap failed rc=%ld after %d retries", rc, r->cleanup_tries);
        }
    } else {
        /* The address space is gone; its mappings went with it. */
        kclf_manual_abandon(r);
        r->map_addr = 0;
        r->map_len = 0;
    }
    __atomic_store_n(&r->finished, !r->map_addr, __ATOMIC_RELEASE);

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
/* Callback references include detached-but-not-entered work. Controllers must
 * never reset a slot until the final reference is released. */
#define KCLF_WORK_WRAPPER(name)                                                      \
    static void kclf_work_##name(struct callback_head *head)                         \
    {                                                                                \
        struct kclf_req *r = local_container_of(head, struct kclf_req, work_##name); \
        kclf_work_##name##_body(head);                                               \
        r->busy = 0;                                                                 \
        __atomic_sub_fetch(&r->pending, 1, __ATOMIC_RELEASE);                        \
    }
KCLF_WORK_WRAPPER(prepare)
KCLF_WORK_WRAPPER(hijack)
KCLF_WORK_WRAPPER(cleanup)

/* completion trap: getpid(cookie) is consumed here                     */
/* ------------------------------------------------------------------ */

static void kclf_getpid_before(hook_fargs4_t *args, void *udata)
{
    struct pt_regs *regs;
    struct kclf_req *r;

    (void)udata;
    if (!has_syscall_wrapper) return;
    regs = (struct pt_regs *)args->args[0];
    if (!regs) return;
    /* Learn the actual frame from a syscall wrapper on non-BTF kernels. */
    if (!kclf_regs_size) {
        u64 top = (u64)get_stack(current) + (u64)thread_size;
        u64 size = top - (u64)regs;
        if (size >= 288 && size <= 512 && !(size & 15)) __atomic_store_n(&kclf_regs_size, (int)size, __ATOMIC_RELEASE);
    }
    if (!kclf_loading_num) return;
    r = kclf_slot_by_task(current);
    if (!r || !r->saved_valid || kclf_state_load(r) != KCLF_RUNNING) return;
    if (regs->regs[0] != r->cookie) return;
    if (regs->regs[8] != KCLF_COMPLETION_NR) return;
    extern const char kclf_tramp_start[], kclf_tramp_return[];
    if ((u64)kclf_task_mm(current) != r->mm || regs->pc != r->code_addr + (u64)(kclf_tramp_return - kclf_tramp_start))
        return;
    /* The trampoline passes the loader result in registers because its
     * parameter page has already been scrubbed. */
    r->handle = (s64)regs->regs[1];
    r->err_user = regs->regs[2];
    r->unload_rc = (s32)regs->regs[3];
    if (r->flags & KCLF_F_UNLOAD) r->unloaded = r->handle && (r->unload_rc == 0);
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
    kclf_state_store(r, KCLF_DONE);
    r->stage = KCLF_ST_RESTORE;
    r->j_done = kclf_now();
    __atomic_sub_fetch(&kclf_loading_num, 1, __ATOMIC_SEQ_CST);
    if (kclf_queue_work(r, current, &r->work_cleanup, KCLF_TWA_RESUME))
        kclf_set_err(r, "cleanup queue rejected; mapping retained");
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
    *off += kclf_scnprintf(out + *off, outlen - *off, "#%d id=%llu pid=%d(%s) state=%s stage=%s", i,
                           (unsigned long long)r->id, r->pid, r->comm, kclf_state_name(kclf_state_load(r)),
                           kclf_stage_name(r->stage));
    if (kclf_state_load(r) == KCLF_ARMED && r->j_queued && kclf_now() - r->j_queued > 1000000000ULL)
        *off += kclf_scnprintf(out + *off, outlen - *off, " hint=blocked(use wake)");
    if (__atomic_load_n(&r->pending, __ATOMIC_ACQUIRE) || r->completing) {
        *off += kclf_scnprintf(out + *off, outlen - *off, " pending=%d\n", r->pending);
        return;
    }
    if (kclf_state_load(r) == KCLF_DONE) {
        *off += kclf_scnprintf(out + *off, outlen - *off, " handle=%llx", (unsigned long long)r->handle);
        if (r->ld.sym) *off += kclf_scnprintf(out + *off, outlen - *off, " via=%s", r->ld.sym);
        if (!(r->flags & KCLF_F_LINKER))
            *off += kclf_scnprintf(out + *off, outlen - *off, " image=%llu refs=%u resident=%llx+%llu",
                                  (unsigned long long)r->image_id, r->image_refs,
                                  (unsigned long long)r->image_addr, (unsigned long long)r->image_len);
        if (r->flags & KCLF_F_UNLOAD) {
            *off += kclf_scnprintf(out + *off, outlen - *off, " unload=%s rc=%d", r->unloaded ? "ok" : "failed",
                                   r->unload_rc);
            if (r->ld.close_sym) *off += kclf_scnprintf(out + *off, outlen - *off, " by=%s", r->ld.close_sym);
        }
    }
    if (r->map_addr)
        *off += kclf_scnprintf(out + *off, outlen - *off, " map=%llx+%llu", (unsigned long long)r->map_addr,
                               (unsigned long long)r->map_len);
    if (r->err[0]) *off += kclf_scnprintf(out + *off, outlen - *off, " err=\"%s\"", r->err);
    *off += kclf_scnprintf(out + *off, outlen - *off, "\n");
}

static long kclf_cmd_inject(char *tok[], int ntok, char *out, int outlen, int *off)
{
    long pid = 0;
    const char *path;
    int release = !strcmp(tok[0], "release");
    int flags = release ? (KCLF_F_RELEASE | KCLF_F_UNLOAD) : 0;
    int backend_seen = 0;
    u64 requested_image = 0;
    int i;
    struct kclf_req *r;
    struct task_struct *task;
    struct mm_struct *mm;
    struct pid *pid_ref;
    u64 cookie;
    int rc;

    if (!kclf_hook_ok) {
        *off += kclf_scnprintf(out + *off, outlen - *off, "error: completion backend unavailable\n");
        return -EOPNOTSUPP;
    }
    if (kclf_unloading && !release) {
        *off += kclf_scnprintf(out + *off, outlen - *off, "error: module quiescing\n");
        return -ESHUTDOWN;
    }
    if (!kclf_ks.access_process_vm) {
        *off += kclf_scnprintf(out + *off, outlen - *off, "error: user copy primitive unavailable\n");
        return -EOPNOTSUPP;
    }
    if (ntok < 3) {
        *off += kclf_scnprintf(out + *off, outlen - *off, "error: inject,<tid>,<path>[,manual|linker][,force][,wake][,unload] or release,<tid>,<image-id>[,wake]\n");
        return -EINVAL;
    }
    for (i = 0; tok[1][i]; i++) {
        if (tok[1][i] < '0' || tok[1][i] > '9') {
            *off += kclf_scnprintf(out + *off, outlen - *off, "error: bad tid\n");
            return -EINVAL;
        }
        if (pid > (2147483647L - (tok[1][i] - '0')) / 10) return -ERANGE;
        pid = pid * 10 + (tok[1][i] - '0');
    }
    if (!pid) {
        *off += kclf_scnprintf(out + *off, outlen - *off, "error: bad tid\n");
        return -EINVAL;
    }
    path = tok[2];
    for (i = 3; i < ntok; i++) {
        if (!strcmp(tok[i], "force"))
            flags |= KCLF_F_FORCE;
        else if (!strcmp(tok[i], "wake"))
            flags |= KCLF_F_WAKE;
        else if (!strcmp(tok[i], "unload") && !release)
            flags |= KCLF_F_UNLOAD;
        else if ((!strcmp(tok[i], "manual") || !strcmp(tok[i], "linker")) && !release) {
            if (backend_seen++) return -EINVAL;
            if (!strcmp(tok[i], "linker")) flags |= KCLF_F_LINKER;
        }
        else if (strcmp(tok[i], "resume"))
            return -EINVAL;
    }
    /* 5.8-5.10 use JOBCTL_TASK_WORK; 5.11+ use NOTIFY_SIGNAL. Both execute
     * task_work in target context. Pending signals are not a refusal. */
    if ((flags & KCLF_F_WAKE) && !kclf_wake_supported) return -EOPNOTSUPP;
    if (release) {
        for (i = 0; path[i]; i++) {
            if (path[i] < '0' || path[i] > '9' || requested_image > (~0ULL - (path[i] - '0')) / 10) return -EINVAL;
            requested_image = requested_image * 10 + path[i] - '0';
        }
        if (!requested_image) return -EINVAL;
    } else if (path[0] != '/') {
        *off += kclf_scnprintf(out + *off, outlen - *off, "error: path must be absolute\n");
        return -EINVAL;
    }
    if (strlen(path) >= KCLF_PATH_MAX) {
        *off += kclf_scnprintf(out + *off, outlen - *off, "error: path too long\n");
        return -EINVAL;
    }

    for (i = 0; i < KCLF_MAX_REQ; i++) {
        struct kclf_req *q = &kclf_reqs[i];
        if (kclf_state_load(q) != KCLF_IDLE && q->pid == pid &&
            (!__atomic_load_n(&q->finished, __ATOMIC_ACQUIRE) || q->map_addr ||
             __atomic_load_n(&q->pending, __ATOMIC_ACQUIRE))) {
            *off += kclf_scnprintf(out + *off, outlen - *off, "error: task already has a request\n");
            return -EBUSY;
        }
    }
    r = kclf_slot_alloc();
    if (!r) {
        *off += kclf_scnprintf(out + *off, outlen - *off, "error: no free request slot\n");
        return -EBUSY;
    }

    pid_ref = kclf_ks.find_get_pid((int)pid);
    kclf_rcu_read_lock();
    task = pid_ref ? kclf_ks.pid_task(pid_ref, 0) : 0;
    if (!task) {
        kclf_rcu_read_unlock();
        if (pid_ref) kclf_ks.put_pid(pid_ref);
        *off += kclf_scnprintf(out + *off, outlen - *off, "error: no such task\n");
        kclf_slot_reset(r);
        return -ESRCH;
    }
    mm = kclf_ks.get_task_mm(task);
    if (!mm) {
        kclf_rcu_read_unlock();
        kclf_ks.put_pid(pid_ref);
        *off += kclf_scnprintf(out + *off, outlen - *off, "error: kernel thread\n");
        kclf_slot_reset(r);
        return -EINVAL;
    }
    kclf_slot_reset(r);
    r->id = __atomic_fetch_add(&kclf_next_id, 1, __ATOMIC_SEQ_CST);
    r->pid = (pid_t)pid;
    r->pid_ref = pid_ref;
    r->mm = (u64)mm;
    /* Only the address-space identity is needed; release the temporary
     * reference immediately so a later target exit is not held up. */
    kclf_ks.mmput_async(mm);
    r->task = (u64)task;
    r->flags = flags;
    r->image_id = requested_image;
    r->stage = KCLF_ST_QUEUE;
    snprintf(r->comm, sizeof(r->comm), "%s", get_task_comm(task));
    strncpy(r->path, path, sizeof(r->path) - 1);
    cookie = get_random_u64();
    r->cookie = cookie ? cookie : 0x6b636c66deadbeefULL;
    r->j_queued = kclf_now();
    kclf_state_store(r, KCLF_ARMED);

    /* Queue before notification; never synthesize TIF_SIGPENDING. */
    r->woke = !!(flags & KCLF_F_WAKE);
    rc = kclf_queue_work(r, task, &r->work_prepare, r->woke ? KCLF_TWA_SIGNAL : KCLF_TWA_RESUME);
    kclf_rcu_read_unlock();
    if (rc) {
        *off += kclf_scnprintf(out + *off, outlen - *off, "error: queue failed %d\n", rc);
        kclf_fail(r, KCLF_FAILED, KCLF_ST_QUEUE, rc, "task_work_add failed");
        __atomic_store_n(&r->finished, 1, __ATOMIC_RELEASE);
        return rc;
    }

    *off += kclf_scnprintf(out + *off, outlen - *off, "queued id=%llu tid=%d comm=%s path=%s mode=%s%s%s\n",
                           (unsigned long long)r->id, r->pid, r->comm, r->path,
                           (flags & KCLF_F_FORCE) ? "force" : "safe", (flags & KCLF_F_WAKE) ? ",wake" : "",
                           (flags & KCLF_F_UNLOAD) ? ",unload" : "");
    return 0;
}

static long kclf_cmd_cancel(char *tok[], int ntok, char *out, int outlen, int *off)
{
    int idx;
    struct kclf_req *r;

    if (ntok != 2 || tok[1][0] < '0' || tok[1][0] > '3' || tok[1][1]) return -EINVAL;
    idx = tok[1][0] - '0';
    r = &kclf_reqs[idx];
    if (kclf_state_load(r) != KCLF_ARMED || !kclf_cancel_work(r, &r->work_prepare)) {
        *off += kclf_scnprintf(out + *off, outlen - *off, "error: work already running or not armed\n");
        return -EBUSY;
    }
    kclf_fail(r, KCLF_CANCELLED, KCLF_ST_QUEUE, -ECANCELED, "cancelled by controller");
    __atomic_store_n(&r->finished, 1, __ATOMIC_RELEASE);
    *off += kclf_scnprintf(out + *off, outlen - *off, "cancelled #%d id=%llu\n", idx, (unsigned long long)r->id);
    return 0;
}

static long kclf_cmd_status(char *out, int outlen, int *off)
{
    int i, n = 0;
    for (i = 0; i < KCLF_MAX_REQ; i++) {
        struct kclf_req *r = &kclf_reqs[i];
        if (kclf_state_load(r) == KCLF_IDLE) continue;
        kclf_status_line(out, outlen, off, r);
        n++;
    }
    if (!n) *off += kclf_scnprintf(out + *off, outlen - *off, "no requests\n");
    *off += kclf_scnprintf(out + *off, outlen - *off, "hook=%s loading=%d page=%d\n", kclf_hook_ok ? "getpid" : "none",
                           kclf_loading_num, kclf_page_size);
    return 0;
}

static long kclf_cmd_reap(char *out, int outlen, int *off)
{
    int i;
    for (i = 0; i < KCLF_MAX_REQ; i++) {
        struct kclf_req *r = &kclf_reqs[i];
        struct task_struct *task;
        int alive;
        if (kclf_state_load(r) == KCLF_IDLE || __atomic_load_n(&r->pending, __ATOMIC_ACQUIRE) || r->completing)
            continue;
        kclf_rcu_read_lock();
        task = r->pid_ref ? kclf_ks.pid_task(r->pid_ref, 0) : 0;
        alive = kclf_task_alive(task, r);
        kclf_rcu_read_unlock();
        if (!alive && !__atomic_load_n(&r->finished, __ATOMIC_ACQUIRE)) {
            if (__atomic_load_n(&r->pending, __ATOMIC_ACQUIRE) || r->completing) continue;
            if (kclf_state_load(r) == KCLF_RUNNING) __atomic_sub_fetch(&kclf_loading_num, 1, __ATOMIC_SEQ_CST);
            kclf_fail(r, KCLF_FAILED, r->stage, -ESRCH, "target exited or exec'd");
            kclf_manual_abandon(r);
            if (r->map_addr) {
                *off += kclf_scnprintf(out + *off, outlen - *off,
                                       "orphaned map #%d %llx+%llu (released with old mm, not unmapped here)\n", i,
                                       (unsigned long long)r->map_addr, (unsigned long long)r->map_len);
                r->map_addr = r->map_len = 0;
            }
            __atomic_store_n(&r->finished, 1, __ATOMIC_RELEASE);
        }
        if (kclf_slot_reclaimable(r)) {
            kclf_slot_reset(r);
            *off += kclf_scnprintf(out + *off, outlen - *off, "reclaimed #%d\n", i);
        } else if (r->map_addr) {
            *off += kclf_scnprintf(out + *off, outlen - *off, "cleanup incomplete #%d\n", i);
        }
    }
    kclf_manual_reap();
    return 0;
}

static int kclf_has_work(void)
{
    int i;
    for (i = 0; i < KCLF_MAX_REQ; i++) {
        struct kclf_req *r = &kclf_reqs[i];
        if (kclf_state_load(r) != KCLF_IDLE && !kclf_slot_reclaimable(r)) return 1;
    }
    return kclf_manual_busy();
}

static long kclf_cmd_quiesce(char *out, int outlen, int *off)
{
    int i, busy;
    __atomic_store_n(&kclf_unloading, 1, __ATOMIC_RELEASE);
    for (i = 0; i < KCLF_MAX_REQ; i++) {
        struct kclf_req *r = &kclf_reqs[i];
        if (!(r->flags & KCLF_F_RELEASE) && kclf_state_load(r) == KCLF_ARMED && kclf_cancel_work(r, &r->work_prepare)) {
            kclf_fail(r, KCLF_CANCELLED, KCLF_ST_QUEUE, -ECANCELED, "quiescing");
            __atomic_store_n(&r->finished, 1, __ATOMIC_RELEASE);
        }
    }
    kclf_manual_reap();
    busy = kclf_has_work();
    *off += kclf_scnprintf(out + *off, outlen - *off, "quiesce=%s; new requests disabled\n",
                           busy ? "busy (wait/reap, DO NOT unload)" : "idle");
    return busy ? -EBUSY : 0;
}

static long kclf_cmd_sym(char *out, int outlen, int *off)
{
    static const char *const names[] = {
        "__copy_from_user",
        "copy_from_user",
        "fault_in_pages_readable",
        "access_process_vm",
        "_copy_from_user",
        "__arch_copy_from_user",
        "__arch_copy_to_user",
        "_copy_to_user",
        "copy_from_user_nofault",
        "task_work_add",
        "task_work_cancel",
        "task_work_cancel_func",
        "find_task_by_vpid",
        "vm_mmap",
        "vm_munmap",
        "find_vma",
        "filp_open",
        "kernel_read",
        "fput",
        "get_task_mm",
        "mmput",
        "__rcu_read_lock",
        "__rcu_read_unlock",
        "ktime_get",
        "msleep",
        "init_mm",
        "init_task",
        "page_offset_base",
    };
    unsigned int i;

    *off += kclf_scnprintf(out + *off, outlen - *off, "user_io=access_process_vm nofault=%llx\n",
                           (unsigned long long)kclf_ks.copy_from_user_nofault);
    for (i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        unsigned long a = kclf_lookup(names[i]);
        *off += kclf_scnprintf(out + *off, outlen - *off, "%-24s %llx\n", names[i], (unsigned long long)a);
    }
    *off += kclf_scnprintf(out + *off, outlen - *off, "mm_off=%d stack_off=%d pid_off=%d tsize=%d\n", kclf_mm_off,
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

    while (len < buflen - 1 && args[len]) {
        char c = args[len];
        buf[len] = (c == ',' || c == '\t' || c == '\n') ? ' ' : c;
        len++;
    }
    buf[len] = 0;
    if (args[len]) return -E2BIG;

    for (int i = 0; i < len;) {
        while (buf[i] == ' ')
            buf[i++] = 0;
        if (!buf[i]) break;
        if (n == maxtok) return -E2BIG;
        tok[n++] = buf + i;
        while (buf[i] && buf[i] != ' ')
            i++;
    }
    return n;
}

static void kclf_usage(char *out, int outlen, int *off)
{
    *off += kclf_scnprintf(out + *off, outlen - *off,
                           "kclf " KCLF_VER " - no-ptrace library loading\n"
                           "  probe                      runtime compatibility diagnostics\n"
                           "  inject,<tid>,<path>[,manual|linker][,force][,wake][,unload] (default manual)\n"
                           "  images[,cursor]            list resident manual images (paged)\n"
                           "  release,<tid>,<image-id>[,wake][,force]   release one manual reference\n"
                           "  status                     request table\n"
                           "  cancel,<slot>              cancel a queued request\n"
                           "  reap                       reclaim finished slots / dead targets\n"
                           "  quiesce                    stop accepting loads; check drain before unload\n"
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
    if (__atomic_exchange_n(&kclf_control_busy, 1, __ATOMIC_ACQUIRE)) return -EBUSY;
    out[0] = 0;
    ntok = kclf_tokenize(args, argv_buf, sizeof(argv_buf), tok, KCLF_MAX_TOK);

    if (ntok < 0) {
        rc = ntok;
        off = kclf_scnprintf(out, sizeof(out), "error: command too long or too many tokens\n");
    } else if (!ntok) {
        kclf_usage(out, sizeof(out), &off);
    } else if (ntok != 1 && strcmp(tok[0], "inject") && strcmp(tok[0], "release") && strcmp(tok[0], "cancel") && strcmp(tok[0], "images")) {
        rc = -EINVAL;
        off = kclf_scnprintf(out, sizeof(out), "error: unexpected arguments\n");
    } else if (!strcmp(tok[0], "probe")) {
        int n = kclf_exec_probe(out, sizeof(out) - 64);
        if (n > 0) off = n;
        off += kclf_scnprintf(out + off, sizeof(out) - off, "hook=%s syscall_wrapper=%d\n",
                              kclf_hook_ok ? "getpid" : "none", has_syscall_wrapper);
    } else if (!strcmp(tok[0], "inject") || !strcmp(tok[0], "release")) {
        rc = kclf_cmd_inject(tok, ntok, out, sizeof(out), &off);
    } else if (!strcmp(tok[0], "images")) {
        unsigned cursor = 0;
        int j;
        if (ntok > 2) rc = -EINVAL;
        if (ntok == 2) for (j = 0; tok[1][j]; j++) {
            if (tok[1][j] < '0' || tok[1][j] > '9' || cursor > 3) { rc = -EINVAL; break; }
            cursor = cursor * 10 + tok[1][j] - '0';
        }
        if (cursor >= 32) rc = -EINVAL;
        if (!rc) {
            kclf_manual_reap();
            off = kclf_manual_status(out, sizeof(out), cursor);
        }
    } else if (!strcmp(tok[0], "quiesce")) {
        rc = kclf_cmd_quiesce(out, sizeof(out), &off);
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
        if (compat_copy_to_user(out_msg, out, off + 1) != off + 1) rc = -EFAULT;
    }
    __atomic_store_n(&kclf_control_busy, 0, __ATOMIC_RELEASE);
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

    for (rc = 0; rc < KCLF_MAX_REQ; rc++)
        kclf_slot_reset(&kclf_reqs[rc]);
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

    rc = kclf_compat_init();
    if (rc) return rc;
    kclf_exec_init();

    rc = kclf_hook_install();
    if (rc) {
        /* keep the module loaded so the failure is inspectable */
        logkw("kclf: running without completion backend\n");
    }

    kclf_ready = 1;
    return 0;
}

/* Module text is only safe to release when no callback can enter it and no
 * trampoline is still executing. A leftover transient mapping (no callback)
 * is a leak, not a use-after-free. */
static int kclf_exit_unsafe(void)
{
    int i;
    for (i = 0; i < KCLF_MAX_REQ; i++) {
        struct kclf_req *r = &kclf_reqs[i];
        int st = kclf_state_load(r);
        if (st == KCLF_IDLE) continue;
        if (st == KCLF_RUNNING || st == KCLF_PREPARING || st == KCLF_READY) return 1;
        if (r->busy || r->completing || __atomic_load_n(&r->pending, __ATOMIC_ACQUIRE)) return 1;
    }
    return 0;
}

static long kclf_exit(void *reserved)
{
    int i, tries, unsafe;

    (void)reserved;
    /* The stock KernelPatch loader frees the module even if this callback
     * returns an error, so the controller MUST obtain quiesce=idle first.
     * What we can do here is cancel queued work and wait a bounded time for
     * in-flight callbacks. The syscall hook is removed unconditionally: on a
     * stock host the alternative is a global getpid hook pointing at freed
     * module text. A task_work callback that is still queued cannot be fixed
     * from here; quiesce/drain is the only safe path. */
    kclf_unloading = 1;
    for (i = 0; i < KCLF_MAX_REQ; i++) {
        struct kclf_req *r = &kclf_reqs[i];
        if (kclf_state_load(r) == KCLF_ARMED && kclf_cancel_work(r, &r->work_prepare)) {
            kclf_fail(r, KCLF_CANCELLED, KCLF_ST_QUEUE, -ECANCELED, "module unload");
            __atomic_store_n(&r->finished, 1, __ATOMIC_RELEASE);
        }
    }
    for (tries = 0; tries < 200 && kclf_exit_unsafe(); tries++) {
        if (!kclf_ks.msleep) break;
        kclf_ks.msleep(10);
    }
    unsafe = __atomic_load_n(&kclf_control_busy, __ATOMIC_ACQUIRE) || kclf_exit_unsafe();
    if (kclf_hook_ok) {
        unhook_syscalln(KCLF_COMPLETION_NR, kclf_getpid_before, kclf_getpid_after);
        kclf_hook_ok = 0;
    }
    if (unsafe) {
        logke("kclf: unload with live callbacks; hook removed, but stock KP frees module text. "
              "Quiesce and drain before unload.\n");
        return -EBUSY;
    }
    for (i = 0; i < KCLF_MAX_REQ; i++)
        kclf_slot_reset(&kclf_reqs[i]);
    i = kclf_manual_shutdown();
    kclf_ready = 0;
    if (i) logke("kclf: forced unload orphaned %d manual images; target process exit required\n", i);
    return i ? -EBUSY : 0;
}

KPM_INIT(kclf_init);
KPM_CTL0(kclf_ctl0);
KPM_EXIT(kclf_exit);
