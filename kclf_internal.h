/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * KCLF - Kernel Controlled Loading Framework, shadow loading backend (KPM).
 *
 * Layering follows kclf-design.md / kclf-shadow-design.md:
 *
 *   control plane   -> KPM ctl0 string ABI (superkey protected, kpatch)
 *   target manager  -> slot table keyed by tid + mm generation
 *   request machine -> IDLE/ARMED/PREPARING/READY/RUNNING/DONE/FAILED
 *   execution       -> EL0 trampoline in a transient private mapping
 *   completion      -> private getpid trap consumed by the syscall hook
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

struct file;

#define KCLF_NAME "kclf"
#define KCLF_VER "1.1.0"

#define KCLF_MAX_REQ 4
#define KCLF_CODE_MAX 512 /* trampoline blob upper bound */

/* mapping layout inside the target: [code page][param page][stack pages] */
#define KCLF_STACK_PAGES 8

/* request states, only mutated by the owner of the request */
enum kclf_state
{
    KCLF_IDLE = 0,
    KCLF_ARMED,     /* task_work queued, waiting for a kernel entry */
    KCLF_PREPARING, /* preparation running in the target context */
    KCLF_READY,     /* payload mapped, return boundary work queued */
    KCLF_RUNNING,   /* target EL0 is executing the trampoline */
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

#define KCLF_F_FORCE 0x1  /* skip conservative safe point heuristics */
#define KCLF_F_WAKE 0x4   /* force the target out of an interruptible sleep */
#define KCLF_F_UNLOAD 0x8 /* dlclose the payload after its constructors ran */

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
    u64 fn;      /* loader entry (dlopen / __loader_dlopen) */
    u64 dlerror; /* dlerror / __loader_dlerror, 0 when unavailable */
    u64 dlclose; /* dlclose / __loader_dlclose, 0 when unavailable */
    u64 caller;  /* caller address used for namespace selection */
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
    pid_t pid;  /* thread the work is armed on */
    pid_t tgid; /* reporting */
    u64 mm;     /* address space identity captured at attach */
    u64 pgd;    /* second half of the generation check */
    u64 task;   /* informational only, never dereferenced */
    char comm[16];
    char path[KCLF_PATH_MAX];

    /* transient mapping inside the target */
    u64 map_addr;
    u64 map_len;
    u64 code_addr;
    u64 param_addr;
    u64 stack_top;

    struct kclf_loader ld;

    /* saved context */
    struct kclf_regs saved;
    u64 saved_orig_x0;
    s32 saved_syscallno;
    u32 saved_valid;
    u32 woke; /* we raised the target's pending-signal flag to unblock it */
    u32 retries;

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
    u64 run_task; /* task currently executing the payload */

    struct callback_head work_prepare;
    struct callback_head work_hijack;
    struct callback_head work_cleanup;
    u8 codebuf[KCLF_CODE_MAX];
};

/* kernel functions that are not part of the exported KPM API */
struct kclf_syms
{
    int (*task_work_add)(struct task_struct *task, struct callback_head *work, int notify);
    struct callback_head *(*task_work_cancel)(struct task_struct *task, struct callback_head *work);
    void (*signal_wake_up_state)(struct task_struct *task, unsigned int state);
    struct task_struct *(*find_task_by_vpid)(pid_t nr);
    unsigned long (*vm_mmap)(void *file, unsigned long addr, unsigned long size, unsigned long prot,
                             unsigned long flag, unsigned long offset);
    int (*vm_munmap)(unsigned long start, size_t len);
    struct vm_area_struct *(*find_vma)(struct mm_struct *mm, unsigned long addr);
    unsigned long (*copy_from_user)(void *to, const void *from, unsigned long n);
    unsigned long (*copy_to_user)(void *to, const void *from, unsigned long n);
    int (*fault_in_pages_readable)(const void *uaddr, int size);
    int (*access_process_vm)(struct task_struct *tsk, unsigned long addr, void *buf, int len,
                             unsigned int gup_flags);
    struct file *(*filp_open)(const char *name, int flags, umode_t mode);
    long (*kernel_read)(struct file *file, void *buf, unsigned long count, loff_t *pos);
    void (*fput)(struct file *file);
    void (*msleep)(unsigned int msecs);
    struct mm_struct *(*get_task_mm)(struct task_struct *task);
    void (*mmput)(struct mm_struct *mm);
};

extern struct kclf_syms kclf_ks;
extern struct kclf_req kclf_reqs[KCLF_MAX_REQ];
extern volatile int kclf_unloading;
extern volatile int kclf_loading_num;
extern int kclf_page_size;
extern int kclf_ready;

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

/* helpers shared between both halves */
extern int kclf_mm_off;
extern int kclf_pid_off;

static inline struct mm_struct *kclf_task_mm(struct task_struct *task)
{
    if (!task || kclf_mm_off <= 0) return 0;
    return *(struct mm_struct **)((char *)task + kclf_mm_off);
}

static inline pid_t kclf_task_pid(struct task_struct *task)
{
    if (!task || kclf_pid_off <= 0) return -1;
    return *(pid_t *)((char *)task + kclf_pid_off);
}

static inline u64 kclf_mm_pgd(struct mm_struct *mm)
{
    if (!mm || mm_struct_offset.pgd_offset <= 0) return 0;
    return *(u64 *)((char *)mm + mm_struct_offset.pgd_offset);
}

#endif
