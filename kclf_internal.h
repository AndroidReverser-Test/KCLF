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
 *   completion      -> real libc call (usleep/open) whose syscall is consumed
 *                      by the kernel hook; no svc in the generated page
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
#define KCLF_VER "1.5.0"

#define KCLF_MAX_REQ 4

/* mapping layout: one anonymous region whose blocks (RX code, RW ABI
 * parameter page, RW private parameter page and, only when the target's own
 * stack cannot be borrowed, a PROT_NONE guard + RW stack) are placed in a
 * random order with random pad pages between them.  The private page is
 * therefore not adjacent to the ABI page.  Sizes are randomized too. */
#define KCLF_MIN_STACK_PAGES 6
#define KCLF_STACK_PAGES_SPAN 9
#define KCLF_STACK_HEADROOM 0x100

#if KCLF_STACK_SLOT + 16 > KCLF_STACK_HEADROOM
#error "completion stack slot does not fit in the reserved headroom"
#endif

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

struct kclf_manual_image;

/* saved EL0 register file: the part the kernel reloads on exception return */
struct kclf_regs
{
    u64 regs[31];
    u64 sp;
    u64 pc;
    u64 pstate;
};

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
    u64 cookie;
    pid_t pid; /* thread the work is armed on */
    struct pid *pid_ref; /* stable identity across PID reuse and namespaces */
    u64 mm; /* identity only; never dereferenced after dropping the mm reference */
    u64 task; /* informational only, never dereferenced */
    char comm[16];
    char path[KCLF_PATH_MAX];

    /* transient mapping inside the target */
    u64 map_addr;
    u64 map_len;
    u64 code_addr;
    u64 guard_addr; /* PROT_NONE page below the transient stack */
    u64 param_addr;
    u64 priv_addr; /* separate page: saved register/FPSIMD file and keys */
    u64 stack_top;
    u64 stack_ref_sp; /* user SP observed when stack_top was chosen */
    u64 entry_pc; /* where EL0 starts executing the generated program */
    u64 bail_token; /* per-request EL0 recovery marker (never a fixed magic) */
    u64 compl_fn[KCLF_COMPL_MAX]; /* resolved libc completion entries */
    u64 compl_arg0[KCLF_COMPL_MAX]; /* matching harmless first argument */
    u64 mprot_fn; /* resolved libc mprotect entry (manual RELRO) */
    u64 compl_obs_pc; /* diagnostics: svc+4 observed by the completion hook */
    u64 compl_obs_lr;
    u64 compl_obs_sp;
    u8 compl_nrs[KCLF_COMPL_MAX]; /* matching syscall numbers */
    u8 compl_count;
    u8 stack_borrowed; /* stack_top points into the interrupted thread stack */
    u8 stack_state; /* diagnostics: why borrowing succeeded/failed */
    u32 priv_layout_ok;
    struct kclf_priv_layout pl;

    struct kclf_loader ld;
    struct kclf_manual_image *image; /* transaction; never the sole resident owner */
    int image_action;
    u64 image_id, image_addr, image_len;
    u32 image_refs, init_count, fini_count;
    u32 ifunc_count, protect_count;
    u32 image_hdr_kept; /* the resident manual image kept its ELF headers */
    u64 hwcap, hwcap2;

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
    int finished;
    int cleanup_tries;
    int pending; /* queued + executing task_work references; acquire/release */
    u64 run_task; /* task currently executing the payload */

    struct callback_head work_prepare;
    struct callback_head work_hijack;
    struct callback_head work_cleanup;
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
    struct pid *(*find_get_pid)(int nr);
    struct task_struct *(*pid_task)(struct pid *pid, int type);
    void (*put_pid)(struct pid *pid);
    struct pid *(*get_task_pid)(struct task_struct *task, int type);
    void *(*vmalloc)(unsigned long size);
    void (*vfree)(const void *ptr);
    loff_t (*vfs_llseek)(struct file *file, loff_t offset, int whence);
    unsigned long (*vm_mmap)(void *file, unsigned long addr, unsigned long size, unsigned long prot, unsigned long flag,
                             unsigned long offset);
    int (*vm_munmap)(unsigned long start, size_t len);
    struct vm_area_struct *(*find_vma)(struct mm_struct *mm, unsigned long addr);
    long (*copy_from_user_nofault)(void *to, const void *from, unsigned long n);
    int (*access_process_vm)(struct task_struct *tsk, unsigned long addr, void *buf, int len, unsigned int gup_flags);
    struct file *(*filp_open)(const char *name, int flags, umode_t mode);
    long (*kernel_read)(struct file *file, void *buf, unsigned long count, loff_t *pos);
    long (*vfs_read)(struct file *file, char *buf, unsigned long count, loff_t *pos);
    void (*fput)(struct file *file);
    struct mm_struct *(*get_task_mm)(struct task_struct *task);
    void (*mmput_async)(struct mm_struct *mm);
    void (*mmap_read_lock)(struct mm_struct *mm);
    void (*mmap_read_unlock)(struct mm_struct *mm);
    void (*down_read)(void *sem);
    void (*up_read)(void *sem);
    void (*msleep)(unsigned int msecs);
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
/* randomized completion syscall pool, registered by kclf.c */
extern const int kclf_compl_pool[];
extern const int kclf_compl_pool_num;

/* kclf.c */
int kclf_sym_lookup_all(void);
struct kclf_req *kclf_slot_by_task(struct task_struct *task);
void kclf_fail(struct kclf_req *r, int state, int stage, long err, const char *fmt, ...);
void kclf_set_err(struct kclf_req *r, const char *fmt, ...);
u64 kclf_now(void);

/* kclf_exec.c */
long kclf_exec_prepare(struct kclf_req *r);
int kclf_exec_hijack(struct kclf_req *r);
void kclf_exec_restore(struct kclf_req *r, struct pt_regs *regs);
long kclf_exec_finish(struct kclf_req *r, int capture_err);
int kclf_exec_probe(char *out, int outlen);
int kclf_exec_init(void);
int kclf_urd(u64 addr, void *buf, int len);
int kclf_urds(u64 addr, void *buf, int len);
int kclf_uwr(u64 addr, const void *buf, int len);
int kclf_walk_vmas(u64 scratch, int (*visit)(u64, const char *, void *), void *context);
/* 0 only when the process identity disappeared or demonstrably exec'd. */
int kclf_process_mm_alive(struct pid *pid, u64 mm);

/* manual backend: memory preparation in EL1, initializers exclusively in EL0 */
long kclf_manual_prepare(struct kclf_req *r);
void kclf_manual_params(struct kclf_req *r, u8 *params);
long kclf_manual_finish(struct kclf_req *r);
void kclf_manual_abandon(struct kclf_req *r);
void kclf_manual_reap(void);
int kclf_manual_status(char *out, int length, unsigned start);
int kclf_manual_busy(void);
int kclf_manual_shutdown(void);

/* kclf_compat.c: runtime layout, no version-based structure guesses. */
extern int kclf_regs_size;
extern int kclf_vma_start_off, kclf_vma_end_off, kclf_mmap_lock_off;
extern int kclf_btf_ok;
extern int kclf_vma_direct;
extern int kclf_wake_supported;
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

#endif
