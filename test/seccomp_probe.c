/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Device-side detection probe for the 1.5.0 completion redesign.
 *
 * It installs the same kind of seccomp policy a hostile app can install on its
 * own thread (SECCOMP_RET_TRAP for nanosleep/openat), catches SIGSYS, and logs
 * the true syscall frame: PC, LR, SP and x0..x7.  It also classifies PC/LR as
 * libc file-backed code and SP as the thread's [stack] mapping, which are the
 * properties the old 1.4.3 "anonymous completion suffix" rule relied on being
 * absent/present.
 *
 * The handler is async-signal-safe on purpose: a fixed log fd, write(2), and
 * clock_nanosleep(2) (not trapped) to emulate the target's own sleep.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <time.h>
#include <ucontext.h>
#include <unistd.h>

static int log_fd = -1;
static uint64_t libc_lo, libc_hi, stack_lo, stack_hi;

static char *put_hex(char *p, uint64_t v)
{
    static const char digits[] = "0123456789abcdef";
    int shift;
    *p++ = '0';
    *p++ = 'x';
    for (shift = 60; shift >= 0; shift -= 4) *p++ = digits[(v >> shift) & 15];
    return p;
}

static void log_frame(unsigned long nr, ucontext_t *uc)
{
    char buf[256];
    char *p = buf;
    uint64_t *r = (uint64_t *)(void *)uc->uc_mcontext.regs;
    uint64_t pc = (uint64_t)uc->uc_mcontext.pc;
    uint64_t lr = r[30];
    uint64_t sp = (uint64_t)uc->uc_mcontext.sp;
    memcpy(p, "TRAP nr=", 8); p += 8;
    p = put_hex(p, nr);
    memcpy(p, " pc=", 4); p += 4; p = put_hex(p, pc);
    memcpy(p, " lr=", 4); p += 4; p = put_hex(p, lr);
    memcpy(p, " sp=", 4); p += 4; p = put_hex(p, sp);
    memcpy(p, " in_libc=", 9); p += 9;
    *p++ = (pc >= libc_lo && pc < libc_hi) ? '1' : '0';
    *p++ = (lr >= libc_lo && lr < libc_hi) ? '1' : '0';
    memcpy(p, " in_stack=", 10); p += 10;
    *p++ = (sp >= stack_lo && sp < stack_hi) ? '1' : '0';
    memcpy(p, " x0=", 4); p += 4; p = put_hex(p, r[0]);
    memcpy(p, " x6=", 4); p += 4; p = put_hex(p, r[6]);
    memcpy(p, " x7=", 4); p += 4; p = put_hex(p, r[7]);
    *p++ = '\n';
    syscall(SYS_write, log_fd, buf, (size_t)(p - buf));
}

static void on_sigsys(int sig, siginfo_t *info, void *context)
{
    ucontext_t *uc = context;
    if (sig != SIGSYS || info->si_code != SYS_SECCOMP || info->si_arch != AUDIT_ARCH_AARCH64) _exit(91);
    log_frame((unsigned long)info->si_syscall, uc);
    uc->uc_mcontext.regs[0] = (uint64_t)-ENOENT;
}

static void parse_range(const char *line, const char *needle, uint64_t *lo, uint64_t *hi)
{
    if (!strstr(line, needle)) return;
    if (!strcmp(needle, "libc.so") && !strstr(line, "r-xp")) return;
    unsigned long long a, b;
    if (sscanf(line, "%llx-%llx", &a, &b) == 2) {
        *lo = a;
        *hi = b;
    }
}

static int read_maps(void)
{
    char buf[8192];
    int fd = open("/proc/self/maps", O_RDONLY | O_CLOEXEC);
    size_t used = 0, i;
    ssize_t got;
    if (fd < 0) return -1;
    while ((got = read(fd, buf + used, sizeof(buf) - 1 - used)) > 0) {
        used += (size_t)got;
        buf[used] = 0;
        size_t start = 0;
        for (i = 0; i < used; i++) {
            if (buf[i] == '\n') {
                buf[i] = 0;
                parse_range(buf + start, "libc.so", &libc_lo, &libc_hi);
                parse_range(buf + start, "[stack]", &stack_lo, &stack_hi);
                start = i + 1;
            }
        }
        if (start) {
            memmove(buf, buf + start, used - start);
            used -= start;
        }
        if (used == sizeof(buf) - 1) break;
    }
    close(fd);
    return (libc_lo && stack_lo) ? 0 : -1;
}

static int install_filter(void)
{
    struct sock_filter code[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (uint32_t)offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_AARCH64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_THREAD),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (uint32_t)offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_openat, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
    };
    struct sock_fprog program = { .len = (unsigned short)(sizeof(code) / sizeof(code[0])), .filter = code };
    return prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) || prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program);
}

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    log_fd = open("/data/local/tmp/kclf-seccomp.log", O_CREAT | O_WRONLY | O_TRUNC | O_CLOEXEC, 0666);
    if (log_fd < 0) return 2;
    if (read_maps()) return 3;
    stack_t ss;
    ss.ss_sp = malloc(65536);
    ss.ss_size = 65536;
    ss.ss_flags = 0;
    if (!ss.ss_sp || sigaltstack(&ss, NULL)) return 4;
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = on_sigsys;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGSYS, &sa, NULL)) return 5;
    if (install_filter()) return 6;
    syscall(SYS_write, log_fd, "READY\n", 6);
    struct timespec ts = { .tv_sec = 0, .tv_nsec = 10000000 };
    for (;;) {
        nanosleep(&ts, NULL);
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now); /* hooked, untrapped: notice bail */
        syscall(SYS_sched_yield); /* hooked, untrapped: fallback notification */
    }
    return 0;
}
