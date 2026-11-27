/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * KCLF - Kernel Controlled Loading Framework, shadow loading backend (KPM).
 *
 * Layering follows kclf-design.md / kclf-shadow-design.md:
 *
 *   control plane   -> KPM ctl0 string ABI (superkey protected, kpatch)
 *   target manager  -> slot table with pinned PID and borrowed mm identities
 *   request machine -> IDLE/ARMED/PREPARING/READY/RUNNING/DONE/FAILED
 *   execution       -> EL0 trampoline in a transient private mapping
 *   completion      -> EL0 restores the register file itself and publishes a
 *                      per-request token; ordinary target syscalls or the
 *                      controller's poll observe it.  No syscall, signal or
 *                      fault belongs to the framework's completion path
 */
#ifndef _KCLF_INTERNAL_H_
#define _KCLF_INTERNAL_H_

#include <ktypes.h>
#include <compiler.h>
#include <stddef.h>
#include <stdbool.h>
#include <kpmodule.h>
#include <kpmalloc.h>
#include <hook.h>
#include <linux/sched.h>
#include <linux/mm_types.h>
#include <asm/current.h>
#include <asm/ptrace.h>
#include <kclf_param.h>
#include <kclf_codegen.h>

struct file;

#define KCLF_NAME "kclf"
#define KCLF_VER "1.6.4"

#define KCLF_MAX_REQ 4
#define KCLF_MAX_IMAGES 32
#define KCLF_MAX_VMA 16384
#define KCLF_CLEANUP_RETRIES 8
/* GNU_RELRO ranges whose protection is applied from the kernel once the EL0
 * phase finished (IFUNC results must be written before they turn read-only). */
#define KCLF_MAX_RELRO 8

/* mapping layout: the anonymous transient region carries only non-executable
 * blocks (the RW ABI parameter page, the RW private parameter page and, only
 * when the target's own stack cannot be borrowed, a PROT_NONE guard + RW
 * stack) placed in a random order with random pad pages between them.  The
 * private page is therefore not adjacent to the ABI page.  The EL0 trampoline
 * is not part of that region: every executable page the framework creates in
 * a target is a private file-backed mapping of the payload, because a
 * process-local /proc/<pid>/maps scan treats r-xp without a pathname as
 * injected code.  Sizes are randomized too.  Every transient page that is not
 * immediately overwritten carries random data. */
#define KCLF_MIN_STACK_PAGES 6
#define KCLF_STACK_PAGES_SPAN 9
#define KCLF_STACK_HEADROOM 0x100
/* Upper bound on how much of a borrowed thread stack the EL0 tail wipes
 * before resuming.  Payload frames otherwise leave return addresses into the
 * transient code page and the module image in the unused stack area, where a
 * process-local scanner can still find them after the request completed. */
#define KCLF_STACK_SCRUB_MAX (256 * 1024)

/* request states, only mutated by the owner of the request */
enum kclf_state
{
    KCLF_IDLE = 0,
    KCLF_ARMED, /* task_work queued, waiting for a kernel entry */
    KCLF_PREPARING, /* preparation running in the target context */
    KCLF_READY, /* payload mapped, return boundary work queued */
    KCLF_RUNNING, /* target EL0 is executing the trampoline */
    KCLF_DONE,
    KCLF_FAILED,
    KCLF_CANCELLED,
};

/* last stage reached, reported on failure (design ch. 14) */
enum kclf_stage
{
    KCLF_ST_NONE = 0,
    KCLF_ST_QUEUE,
    KCLF_ST_PREPARE,
    KCLF_ST_HIJACK,
    KCLF_ST_LOADER,
    KCLF_ST_RESTORE,
};

#define KCLF_F_FORCE 0x1 /* skip conservative safe point heuristics */
#define KCLF_F_WAKE 0x4 /* force the target out of an interruptible sleep */
#define KCLF_F_UNLOAD 0x8 /* release after constructors (backend-specific) */
#define KCLF_F_LINKER 0x10 /* explicit legacy bionic backend; manual is default */
#define KCLF_F_RELEASE 0x20 /* release a manual image reference */
#define KCLF_F_KEEPELF 0x40 /* keep in-memory ELF/program headers (manual) */
#define KCLF_F_BORROWSTACK 0x80 /* legacy: run on the interrupted thread stack */

struct kclf_manual_image;

/* saved EL0 register file: the part the kernel reloads on exception return */
struct kclf_regs
{
    u64 regs[31];
    u64 sp;
    u64 pc;
    u64 pstate;
};

struct cred;

struct kclf_loader
{
    u64 fn; /* loader entry (dlopen / __loader_dlopen) */
    u64 dlerror; /* dlerror / __loader_dlerror, 0 when unavailable */
    u64 dlclose; /* dlclose / __loader_dlclose, 0 when unavailable */
    u64 caller; /* caller address used for namespace selection */
    u64 linker_base;
    u64 linker_end;
    u64 libdl_base;
    u64 libc_base;
    const char *sym;
    const char *close_sym;
};

struct kclf_req
{
    int state;
    int stage;
    int flags;
    u64 id;
    pid_t pid; /* thread the work is armed on */
    struct pid *pid_ref; /* stable identity across PID reuse and namespaces */
    u64 mm; /* identity only; never dereferenced after dropping the mm reference */
    u64 task; /* informational only, never dereferenced */
    char comm[16];
    char path[KCLF_PATH_MAX];
    char code_path[KCLF_PATH_MAX]; /* file whose first page backs code_addr */
    struct file *code_file; /* borrowed from the BUSY manual image, never owns a reference */

    /* transient mapping inside the target */
    u64 map_addr;
    u64 map_len;
    u64 code_addr; /* one-page EL0 trampoline, private file mapping of code_path */
    u64 code_len;
    u64 guard_addr; /* PROT_NONE page below the transient stack */
    u64 param_addr;
    u64 priv_addr; /* separate page: saved register/FPSIMD file and keys */
    u64 stack_top;
    u64 stack_ref_sp; /* user SP observed when stack_top was chosen */
    u64 stack_scrub; /* borrowed-stack bytes the EL0 tail wipes, zero if none */
    u64 dedicated_stack_top; /* transient stack top fixed at preparation time */
    u64 entry_pc; /* where EL0 starts executing the generated program */
    u64 done_token; /* per-request EL0 completion marker (never a fixed magic) */
    u8 stack_borrowed; /* stack_top points into the interrupted thread stack */
    u8 stack_state; /* diagnostics: why borrowing succeeded/failed */
    u8 completion_via; /* 1: watched syscall, 2: controller poll */
    u32 priv_layout_ok;
    struct kclf_priv_layout pl;

    /* deferred GNU_RELRO protection (kernel-side, after the EL0 phase) */
    u32 relro_count;
    u32 relro_done; /* number of ranges successfully protected; retry cursor */
    u64 relro[KCLF_MAX_RELRO][2];

    struct kclf_loader ld;
    struct kclf_manual_image *image; /* transaction; never the sole resident owner */
    int image_action;
    u64 image_id, image_addr, image_len;
    u32 image_refs, init_count, fini_count;
    u32 ifunc_count, protect_count;
    u32 image_hdr_kept; /* the resident manual image kept its ELF headers */
    u64 hwcap, hwcap2;
    u64 tls_init, tls_arg;

    /* saved context */
    struct kclf_regs saved;
    u64 saved_orig_x0;
    s32 saved_syscallno;
    u32 saved_valid;
    u32 woke; /* TWA_SIGNAL requested; no synthetic pending signal */

    /* result */
    s64 handle;
    u64 err_user; /* dlerror() string pointer captured at the trap */
    s32 unload_rc;
    u32 unloaded;
    char err[KCLF_ERR_MAX];

    /* timing, kernel nanoseconds */
    u64 j_queued, j_ready, j_done;

    /* bookkeeping */
    int busy;
    int completing;
    int poll_queued; /* one controller poll callback per request at a time */
    int finished;
    int cleanup_tries;
    int pending; /* queued + executing task_work references; acquire/release */
    u64 run_task; /* task currently executing the payload */

    /* Preparation context.  Mapping, ELF parsing and relocation all run on a
     * kernel worker that entered the target mm (kthread_use_mm), never on the
     * borrowed target thread: every page the loader faults in would otherwise
     * be charged to that thread's /proc/<pid>/task/<tid>/stat accounting
     * (min_flt/stime), which is a trivially observable "code just ran here"
     * signature for an in-process anti-cheat.  The references below keep the
     * address space, the target credentials and the process identity alive
     * while the worker runs; they are dropped before the EL0 phase so a
     * target exit is never held up by a pending request. */
    struct mm_struct *mm_ref;
    const struct cred *cred_ref;
    struct pid *owner_pid;
    int worker_phase; /* 0 none, 1 queued, 2 preparing, 3 idle, 4 rollback queued, 5 rollback running */
    u32 prep_worker;
    u32 prep_retries;
    s32 tgid; /* target thread-group id for /proc/<tgid>/maps in the worker */

    struct callback_head work_prepare;
    struct callback_head work_hijack;
    struct callback_head work_cleanup;
    struct callback_head work_poll;
};

static inline int kclf_state_load(const struct kclf_req *r)
{
    return __atomic_load_n(&r->state, __ATOMIC_ACQUIRE);
}

static inline void kclf_state_store(struct kclf_req *r, int state)
{
    __atomic_store_n(&r->state, state, __ATOMIC_RELEASE);
}

/* kernel functions that are not part of the exported KPM API */
struct kclf_syms
{
    int (*task_work_add)(struct task_struct *task, struct callback_head *work, int notify);
    struct callback_head *(*task_work_cancel_func)(struct task_struct *task, void (*func)(struct callback_head *));
    struct callback_head *(*task_work_cancel_match)(struct task_struct *task,
                                                    bool (*match)(struct callback_head *, void *), void *data);
    bool (*task_work_cancel_object)(struct task_struct *task, struct callback_head *work);
    struct pid *(*find_get_pid)(int nr);
    struct task_struct *(*pid_task)(struct pid *pid, int type);
    void (*put_pid)(struct pid *pid);
    struct pid *(*get_task_pid)(struct task_struct *task, int type);
    /* Rendered pid_t of a task in the caller's pid namespace: the preparation
     * worker needs the target's TGID to read /proc/<tgid>/maps for it. */
    s32 (*task_pid_nr_ns)(struct task_struct *task, int type, void *ns);
    void *(*vmalloc)(unsigned long size);
    void (*vfree)(const void *ptr);
    loff_t (*vfs_llseek)(struct file *file, loff_t offset, int whence);
    unsigned long (*vm_mmap)(void *file, unsigned long addr, unsigned long size, unsigned long prot, unsigned long flag,
                             unsigned long offset);
    int (*vm_munmap)(unsigned long start, size_t len);
    struct vm_area_struct *(*find_vma)(struct mm_struct *mm, unsigned long addr);
    struct vm_area_struct *(*find_vma_prev)(struct mm_struct *mm, unsigned long addr,
                                          struct vm_area_struct **prev);
    long (*copy_from_user_nofault)(void *to, const void *from, unsigned long n);
    int (*access_process_vm)(struct task_struct *tsk, unsigned long addr, void *buf, int len, unsigned int gup_flags);
    /* access_process_vm() goes through get_task_mm(), which deliberately returns
     * NULL for PF_KTHREAD tasks, so the preparation worker addresses the target
     * address space through access_remote_vm() instead. */
    int (*access_remote_vm)(struct mm_struct *mm, unsigned long addr, void *buf, int len, unsigned int gup_flags);
    struct file *(*filp_open)(const char *name, int flags, umode_t mode);
    long (*kernel_read)(struct file *file, void *buf, unsigned long count, loff_t *pos);
    long (*kernel_write)(struct file *file, const void *buf, unsigned long count, loff_t *pos);
    struct file *(*shmem_file_setup)(const char *name, loff_t size, unsigned long flags);
    long (*vfs_read)(struct file *file, char *buf, unsigned long count, loff_t *pos);
    void (*fput)(struct file *file);
    /* Resolve an open file's path from its struct path.  The manual backend
     * uses it to give every provider a real pathname even when the target is
     * non-dumpable and /proc/<tgid>/maps cannot be opened with its credentials. */
    char *(*d_path)(const void *path, char *buf, int buflen);
    struct mm_struct *(*get_task_mm)(struct task_struct *task);
    void (*mmput_async)(struct mm_struct *mm);
    void (*mmap_read_lock)(struct mm_struct *mm);
    void (*mmap_read_unlock)(struct mm_struct *mm);
    void (*down_read)(void *sem);
    void (*up_read)(void *sem);
    void (*msleep)(unsigned int msecs);
    /* Preparation worker: a kernel thread that enters the target mm so the
     * borrowed thread's scheduling/page-fault accounting stays untouched. */
    struct task_struct *(*kthread_create_on_node)(int (*fn)(void *), void *data, int node, const char *name, ...);
    int (*wake_up_process)(struct task_struct *task);
    int (*kthread_should_stop)(void);
    int (*kthread_stop)(struct task_struct *task);
    void (*kthread_use_mm)(struct mm_struct *mm);
    void (*kthread_unuse_mm)(struct mm_struct *mm);
    void (*mmput)(struct mm_struct *mm);
    /* The payload file must still be opened with the target's credentials, also
     * when the worker (a kernel thread) performs the open. */
    const struct cred *(*get_task_cred)(struct task_struct *task);
    const struct cred *(*override_creds)(const struct cred *cred);
    void (*revert_creds)(const struct cred *old);
    void (*put_cred)(const struct cred *cred);
    /* AArch64 ELF_HWCAP accessors. The target may be non-dumpable, so its
     * /proc/<pid>/auxv can be unreadable even from its own credentials. */
    u64 (*cpu_get_elf_hwcap)(void);
    u64 (*cpu_get_elf_hwcap2)(void);
};

extern struct kclf_syms kclf_ks;
extern struct kclf_req kclf_reqs[KCLF_MAX_REQ];
extern volatile int kclf_unloading;
extern volatile int kclf_loading_num;
extern int kclf_page_size;
extern u64 kclf_user_limit;
extern int kclf_user_tbi;
extern int kclf_ready;
/* syscalls whose entry is used to observe the EL0 completion token; they are
 * never consumed or modified, the callback only reads the private page */
extern const int kclf_watch_pool[];
extern const int kclf_watch_pool_num;

/* kclf.c */
int kclf_sym_lookup_all(void);
struct kclf_req *kclf_slot_by_task(struct task_struct *task);
void kclf_fail(struct kclf_req *r, int state, int stage, long err, const char *fmt, ...)
    __attribute__((format(printf, 5, 6)));
void kclf_set_err(struct kclf_req *r, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
u64 kclf_now(void);
/* preparation worker (task_work-free, target mm via kthread_use_mm) */
int kclf_worker_init(void);
void kclf_worker_shutdown(void);
int kclf_worker_available(void);
/* Takes ownership of preparation references, including on submission failure. */
int kclf_worker_submit(struct kclf_req *r);
int kclf_worker_cancel(struct kclf_req *r);

/* kclf_exec.c */
long kclf_exec_prepare(struct kclf_req *r);
int kclf_exec_hijack(struct kclf_req *r);
int kclf_exec_poll_ready(const struct kclf_req *r);
long kclf_apply_relro(struct kclf_req *r);
long kclf_exec_finish(struct kclf_req *r, int capture_err);
int kclf_exec_probe(char *out, int outlen);
int kclf_exec_init(void);
/* Map one page of borrowed @backing (or reopen @path) read+execute and write
 * @code through its private COW page. The VMA keeps its own file reference. */
long kclf_map_file_code(struct file *backing, const char *path, const void *code, u64 page, u64 *addr);
int kclf_tmp_path(const char *path);
int kclf_stage_tmp_file(const char *path, const void *data, unsigned long size, struct file **out);
int kclf_urd(u64 addr, void *buf, int len);
int kclf_urds(u64 addr, void *buf, int len);
int kclf_uwr(u64 addr, const void *buf, int len);
/* Fault every page of a target range in from the calling context, so the
 * borrowed thread that later executes the payload takes no page fault (and
 * therefore no min_flt) for pages the framework itself installed. */
void kclf_prefault_user(u64 start, u64 len);
/* Write through a COW mapping that is not writable from EL0 (FOLL_FORCE). */
int kclf_uwr_force(u64 addr, const void *buf, int len);
int kclf_walk_vmas(u64 scratch, int (*visit)(u64, const char *, u64, void *), void *context);
struct kclf_vm_range { u64 start, end; int prot; };
int kclf_snapshot_vmas(u64 scratch, struct kclf_vm_range *ranges, unsigned capacity);
/* 0 only when the process identity disappeared or demonstrably exec'd. */
int kclf_process_mm_alive(struct pid *pid, u64 mm);

/* manual backend: memory preparation in EL1, initializers exclusively in EL0 */
long kclf_manual_prepare(struct kclf_req *r);
void kclf_manual_params(struct kclf_req *r, u8 *params);
long kclf_manual_finish(struct kclf_req *r);
void kclf_manual_abandon(struct kclf_req *r);
void kclf_manual_prefault(struct kclf_req *r);
void kclf_manual_reap(void);
int kclf_manual_status(char *out, int length, unsigned start);
int kclf_manual_busy(void);
int kclf_manual_shutdown(void);

/* kclf_compat.c: runtime layout, no version-based structure guesses. */
extern int kclf_regs_size;
extern int kclf_vma_start_off, kclf_vma_end_off, kclf_mmap_lock_off;
/* Verified by BTF: the locked VMA walker can recover the same metadata procfs
 * exposes (pathname, file offset, permissions), which non-dumpable app
 * processes deny to /proc/<tgid>/maps. */
extern int kclf_vma_file_off, kclf_vma_pgoff_off, kclf_vma_flags_off, kclf_file_path_off;
extern int kclf_btf_ok;
extern int kclf_vma_direct;
extern int kclf_wake_supported;
extern int kclf_tmp_backing;
extern u64 kclf_trace_mask, kclf_vector_mask;
extern const char *kclf_wake_abi;
unsigned long kclf_lookup(const char *name);
int kclf_compat_init(void);
void kclf_mmap_read_lock(struct mm_struct *mm);
void kclf_mmap_read_unlock(struct mm_struct *mm);
int kclf_scnprintf(char *out, int size, const char *fmt, ...) __attribute__((format(printf, 3, 4)));

/* helpers shared between both halves */
extern int kclf_mm_off;

/* Current's mm stays live during its callback. For another task the caller
 * holds RCU and may only compare this borrowed identity, never dereference it. */
struct mm_struct *kclf_task_mm(struct task_struct *task);

/* Non-NULL only while the preparation worker is inside the target mm.  Target
 * memory access must then go through the request's mm: the worker is a kernel
 * thread and get_task_mm() hides its mm from access_process_vm(). */
extern struct mm_struct *kclf_io_mm;
extern struct task_struct *kclf_io_worker;
extern s32 kclf_io_tgid;

#endif
