#define _GNU_SOURCE
#include <jni.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <time.h>
#include <ucontext.h>
#include <unistd.h>

/* Target: unmodified KCLF 1.5.0 and the audited device bionic wrappers.
 * No root, ptrace, /proc/self/mem, payload signature, or injector-supplied
 * address is used by the detector. A failed read is NOT a positive.
 * TSYNC covers existing threads, and new threads inherit the filter.
 * This is a diagnostic fixture, not a production SIGSYS interposer. */
extern long audit_syscall6(long, long, long, long, long, long, long);
extern char audit_after_svc[], audit_benign_begin[], audit_benign_end[];
static int log_fd = -1, app_pid, kill_on_detect, deny_exec;
static int start_workers, workers_ready;
static uintptr_t libc_usleep, libc_open;
static void *benign_code;
static unsigned detections;
static __thread unsigned thread_traps;
static char library_path[512], mode_name[32];

static long sc(long nr, long a, long b, long c, long d, long e, long f)
{
    return audit_syscall6(nr, a, b, c, d, e, f);
}

static void event(const char *fmt, ...)
{
    char line[1024];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);
    if (n > 0 && n < (int)sizeof(line)) sc(__NR_write, log_fd, (long)line, n, 0, 0, 0);
}

static int read_self(uintptr_t at, void *out, size_t size)
{
    if (at < 4096 || at + size < at) return 0;
    struct iovec local = {out, size}, remote = {(void *)at, size};
    return sc(__NR_process_vm_readv, app_pid, (long)&local, 1,
              (long)&remote, 1, 0) == (long)size;
}

static uint32_t mov(unsigned rd, unsigned rm) { return 0xaa0003e0u | (rm << 16) | rd; }
static uint32_t ldr(unsigned rt, unsigned rn, unsigned off)
{
    return 0xf9400000u | ((off / 8u) << 10) | (rn << 5) | rt;
}

struct finding { uintptr_t caller, private_page; uint64_t cookie; };
static int completion_match(int nr, ucontext_t *uc, struct finding *out)
{
    uint64_t *r = (uint64_t *)(void *)uc->uc_mcontext.regs;
    uint64_t fp = r[29], ret = 0, priv = 0, cookie = 0, fn = 0, arg = 0;
    uint32_t w[18];
    if ((fp & 15) || !read_self(fp + 8, &ret, sizeof(ret)) || ret < 72) return 0;
    if (!read_self(ret - 72, w, sizeof(w))) return 0;
    if (w[0] != ldr(9, 31, 0x80)) return 0;
    const uint32_t offmask = 0x003ffc00u;
    if ((w[1] & ~offmask) != ldr(0, 9, 0) ||
        (w[2] & ~offmask) != ldr(16, 9, 0) ||
        (w[3] & ~offmask) != ldr(6, 9, 0)) return 0;
    unsigned n = 4;
    if (w[n++] != mov(7, 6)) return 0;
    for (unsigned i = 1; i <= 5; i++) if (w[n++] != mov(i, 31)) return 0;
    for (unsigned i = 10; i <= 15; i++) if (w[n++] != mov(i, 31)) return 0;
    if (w[n++] != mov(9, 31) || w[n++] != 0xd63f0200u || n != 18) return 0;

    /* Both audited libc frames store x29/x30 together; their frame-pointer
     * offsets from the caller SP are 0x20 and 0x50 respectively. Runtime
     * prologue checks below reject an incompatible bionic before testing. */
    uintptr_t caller_sp = fp + (nr == __NR_nanosleep ? 0x20 : 0x50);
    if (!read_self(caller_sp + 0x80, &priv, 8) || (priv & 4095)) return 0;
    unsigned arg_off = ((w[1] >> 10) & 0xfff) * 8;
    unsigned fn_off = ((w[2] >> 10) & 0xfff) * 8;
    unsigned cookie_off = ((w[3] >> 10) & 0xfff) * 8;
    if (arg_off > 4088 || fn_off > 4088 || cookie_off > 4088) return 0;
    if (!read_self(priv + arg_off, &arg, 8) || !read_self(priv + fn_off, &fn, 8) ||
        !read_self(priv + cookie_off, &cookie, 8)) return 0;
    if (!cookie || r[6] != cookie || r[7] != cookie) return 0;
    if (nr == __NR_nanosleep) {
        uint64_t ts[2];
        if (fn != libc_usleep || arg || !read_self(r[0], ts, sizeof(ts)) || ts[0] || ts[1]) return 0;
    } else if (fn != libc_open || arg != r[1]) return 0;
    out->caller = ret;
    out->private_page = priv;
    out->cookie = cookie;
    return 1;
}

/* Signal-safe fixed-buffer formatting; do not call printf/dlopen/malloc here. */
static char *literal(char *p, const char *s) { while (*s) *p++ = *s++; return p; }
static char *hex(char *p, uint64_t v)
{
    static const char digits[] = "0123456789abcdef";
    *p++ = '0'; *p++ = 'x';
    for (int shift = 60; shift >= 0; shift -= 4) *p++ = digits[(v >> shift) & 15];
    return p;
}
static void on_sigsys(int sig, siginfo_t *info, void *context)
{
    ucontext_t *uc = context;
    int nr = info->si_syscall;
    if (sig != SIGSYS || info->si_code != SYS_SECCOMP || info->si_arch != AUDIT_ARCH_AARCH64 ||
        (nr != __NR_nanosleep && nr != __NR_openat)) {
        sc(__NR_exit_group, 90, 0, 0, 0, 0, 0);
        return;
    }
    thread_traps++;
    struct finding found;
    if (completion_match(nr, uc, &found)) {
        char line[512], *p = line;
        __atomic_add_fetch(&detections, 1, __ATOMIC_RELAXED);
        p = literal(p, "DETECT tid="); p = hex(p, (uint64_t)sc(__NR_gettid, 0, 0, 0, 0, 0, 0));
        p = literal(p, " nr="); p = hex(p, (uint64_t)nr);
        p = literal(p, " pc="); p = hex(p, uc->uc_mcontext.pc);
        p = literal(p, " lr="); p = hex(p, uc->uc_mcontext.regs[30]);
        p = literal(p, " caller="); p = hex(p, found.caller);
        p = literal(p, " private="); p = hex(p, found.private_page);
        p = literal(p, " cookie="); p = hex(p, found.cookie);
        p = literal(p, " evidence=code72+stack+cookie+libc\n");
        sc(__NR_write, log_fd, (long)line, p - line, 0, 0, 0);
        if (kill_on_detect) {
            static const char stop[] = "RESPONSE exit_group AFTER completion detection\n";
            sc(__NR_write, log_fd, (long)stop, sizeof(stop) - 1, 0, 0, 0);
            sc(__NR_exit_group, 86, 0, 0, 0, 0, 0);
        }
    }
    /* Reissue legitimate calls through the BPF-approved gateway. Its x6/x7
     * are zero, so KCLF cannot mistake the handler for its completion call.
     * Detected calls also return normally; both attempts then reach EL0 bail. */
    uint64_t *r = (uint64_t *)(void *)uc->uc_mcontext.regs;
    r[0] = (uint64_t)sc(nr, r[0], r[1], r[2], r[3], r[4], r[5]);
}

static int altstack(void)
{
    stack_t stack = {.ss_sp = malloc(65536), .ss_size = 65536, .ss_flags = 0};
    return !stack.ss_sp || sigaltstack(&stack, NULL);
}

static int install_filter(void)
{
    struct sock_filter code[32];
    unsigned n = 0, op, ns, mp = 0, mm = 0;
#define PUSH(c,jt,jf,k) (code[n++] = (struct sock_filter){c,jt,jf,k})
    PUSH(BPF_LD | BPF_W | BPF_ABS, 0, 0, offsetof(struct seccomp_data, arch));
    PUSH(BPF_JMP | BPF_JEQ | BPF_K, 1, 0, AUDIT_ARCH_AARCH64);
    PUSH(BPF_RET | BPF_K, 0, 0, SECCOMP_RET_KILL_PROCESS);
    PUSH(BPF_LD | BPF_W | BPF_ABS, 0, 0, offsetof(struct seccomp_data, nr));
    op = n; PUSH(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, __NR_openat);
    ns = n; PUSH(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, __NR_nanosleep);
    if (deny_exec) {
        mp = n; PUSH(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, __NR_mprotect);
        mm = n; PUSH(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, __NR_mmap);
    }
    PUSH(BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ALLOW);
    unsigned gate = n;
    uintptr_t ip = (uintptr_t)audit_after_svc;
    PUSH(BPF_LD | BPF_W | BPF_ABS, 0, 0, offsetof(struct seccomp_data, instruction_pointer) + 4);
    PUSH(BPF_JMP | BPF_JEQ | BPF_K, 0, 3, (uint32_t)(ip >> 32));
    PUSH(BPF_LD | BPF_W | BPF_ABS, 0, 0, offsetof(struct seccomp_data, instruction_pointer));
    PUSH(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, (uint32_t)ip);
    PUSH(BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ALLOW);
    PUSH(BPF_RET | BPF_K, 0, 0, SECCOMP_RET_TRAP);
    code[op].jt = gate - op - 1;
    code[ns].jt = gate - ns - 1;
    if (deny_exec) {
        unsigned test = n;
        PUSH(BPF_LD | BPF_W | BPF_ABS, 0, 0, offsetof(struct seccomp_data, args[2]));
        PUSH(BPF_JMP | BPF_JSET | BPF_K, 0, 1, PROT_EXEC);
        PUSH(BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ERRNO | EPERM);
        PUSH(BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ALLOW);
        code[mp].jt = test - mp - 1;
        code[mm].jt = test - mm - 1;
    }
#undef PUSH
    struct sock_fprog prog = {.len = (unsigned short)n, .filter = code};
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) return -1;
    return (int)syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC, &prog);
}

static void negative_controls(const char *label)
{
    unsigned before = thread_traps;
    int errors = 0;
    for (int i = 0; i < 200; i++) {
        if (((int (*)(unsigned))libc_usleep)(0)) errors++;
        int fd = ((int (*)(const char *, int, ...))libc_open)("/proc/self/status", O_RDONLY);
        if (fd < 0) errors++; else close(fd);
        if (((int (*)(unsigned, uintptr_t))benign_code)(0, libc_usleep)) errors++;
    }
    event("CONTROL label=%s tid=%d calls=600 traps=%u errors=%d detections=%u\n",
          label, gettid(), thread_traps - before, errors, __atomic_load_n(&detections, __ATOMIC_RELAXED));
}

static void pause_once(void)
{
    struct timespec t = {0, 10000000};
    sc(__NR_clock_nanosleep, CLOCK_MONOTONIC, 0, (long)&t, 0, 0, 0);
    /* This untrapped hooked syscall lets KCLF notice an EL0 bail token. */
    sc(__NR_sched_yield, 0, 0, 0, 0, 0, 0);
}

static void *worker(void *argument)
{
    const char *label = argument;
    pthread_setname_np(pthread_self(), label);
    if (altstack()) { event("ERROR altstack label=%s\n", label); return NULL; }
    while (!__atomic_load_n(&start_workers, __ATOMIC_ACQUIRE)) pause_once();
    negative_controls(label);
    event("THREAD_READY label=%s tid=%d\n", label, gettid());
    __atomic_add_fetch(&workers_ready, 1, __ATOMIC_RELEASE);
    for (;;) pause_once();
    return NULL;
}

static void identity(void)
{
    event("IDENTITY pid=%d main=%d uid=%d euid=%d dumpable=%d mode=%s\n",
          app_pid, gettid(), getuid(), geteuid(), prctl(PR_GET_DUMPABLE), mode_name);
    char line[1024];
    FILE *f = fopen("/proc/self/status", "re");
    if (f) {
        while (fgets(line, sizeof(line), f))
            if (!strncmp(line, "CapEff:", 7) || !strncmp(line, "Seccomp:", 8) ||
                !strncmp(line, "NoNewPrivs:", 11)) event("%s", line);
        fclose(f);
    }
    f = fopen("/proc/self/attr/current", "re");
    if (f) { if (fgets(line, sizeof(line), f)) event("CONTEXT %s\n", line); fclose(f); }
}

JNIEXPORT void JNICALL Java_com_kclf_selfcheckv15_MainActivity_start(
    JNIEnv *env, jclass klass, jstring files, jstring libraries, jstring mode)
{
    (void)klass;
    if (log_fd >= 0) return;
    const char *f = (*env)->GetStringUTFChars(env, files, NULL);
    const char *l = (*env)->GetStringUTFChars(env, libraries, NULL);
    const char *m = (*env)->GetStringUTFChars(env, mode, NULL);
    char path[1024];
    snprintf(path, sizeof(path), "%s/events.txt", f);
    snprintf(library_path, sizeof(library_path), "%s", l);
    snprintf(mode_name, sizeof(mode_name), "%s", m);
    (*env)->ReleaseStringUTFChars(env, files, f);
    (*env)->ReleaseStringUTFChars(env, libraries, l);
    (*env)->ReleaseStringUTFChars(env, mode, m);
    log_fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_APPEND | O_CLOEXEC, 0600);
    app_pid = getpid();
    kill_on_detect = !strcmp(mode_name, "terminate");
    deny_exec = !strcmp(mode_name, "denyexec");
    libc_usleep = (uintptr_t)dlsym(RTLD_DEFAULT, "usleep");
    libc_open = (uintptr_t)dlsym(RTLD_DEFAULT, "open");
    identity();
    uint32_t us[4], op[7];
    if (!read_self(libc_usleep, us, sizeof(us)) || !read_self(libc_open, op, sizeof(op)) ||
        us[0] != 0xd10103ff || us[1] != 0xa9027bfd || us[3] != 0x910083fd ||
        op[0] != 0xd104c3ff || op[1] != 0xa90e7bfd || op[6] != 0x910383fd) {
        event("ERROR unsupported libc frame or self-read denied\n"); return;
    }
    event("ABI_OK libc_usleep=%lx libc_open=%lx self_read=1\n", libc_usleep, libc_open);
    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    benign_code = mmap(NULL, page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (benign_code == MAP_FAILED) { event("ERROR benign mmap\n"); return; }
    memcpy(benign_code, audit_benign_begin, (size_t)(audit_benign_end - audit_benign_begin));
    __builtin___clear_cache(benign_code, (char *)benign_code + page);
    if (mprotect(benign_code, page, PROT_READ | PROT_EXEC) || altstack()) {
        event("ERROR benign protection or altstack\n"); return;
    }
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = on_sigsys;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGSYS, &sa, NULL)) { event("ERROR sigaction\n"); return; }
    pthread_t pre, post;
    if (pthread_create(&pre, NULL, worker, "audit-pre")) { event("ERROR pre worker\n"); return; }
    int rc = install_filter();
    event("FILTER tsync_rc=%d errno=%d deny_exec=%d\n", rc, errno, deny_exec);
    if (rc) { event("ERROR TSYNC not installed\n"); return; }
    if (pthread_create(&post, NULL, worker, "audit-new")) { event("ERROR post worker\n"); return; }
    __atomic_store_n(&start_workers, 1, __ATOMIC_RELEASE);
    negative_controls("main");
    if (deny_exec) {
        void *p = mmap(NULL, page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        errno = 0;
        int mr = p == MAP_FAILED ? -2 : mprotect(p, page, PROT_READ | PROT_EXEC);
        int me = errno;
        if (p != MAP_FAILED) munmap(p, page);
        errno = 0;
        p = mmap(NULL, page, PROT_READ | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        int xe = errno, blocked = p == MAP_FAILED;
        if (p != MAP_FAILED) munmap(p, page);
        event("EXEC_GUARD mprotect_rc=%d errno=%d mmap_blocked=%d mmap_errno=%d\n", mr, me, blocked, xe);
    }
    while (__atomic_load_n(&workers_ready, __ATOMIC_ACQUIRE) != 2) pause_once();
    event("READY pid=%d main=%d mode=%s library=%s detections=%u\n", app_pid, gettid(), mode_name,
          library_path, __atomic_load_n(&detections, __ATOMIC_RELAXED));
}
