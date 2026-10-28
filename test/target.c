/* KCLF test target: a long-lived native process used to validate injection.
 * It makes a syscall on every loop iteration so a task_work based trigger
 * always has a return-to-user boundary to hook.
 *
 * Environment knobs (all optional):
 *   KCLF_TEST_SLEEP_MS   per-iteration nanosleep (default 20)
 *   KCLF_TEST_VERBOSE    report interrupted / long sleeps
 *   KCLF_TEST_PHDR_EVERY dump this process's dl_iterate_phdr list every N loops
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <link.h>
#include <sys/prctl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

static int verbose;
extern int kclf_test_fp_sleep(const struct timespec *ts);

static int phdr_cb(struct dl_phdr_info *info, size_t size, void *data)
{
    (void)size;
    (void)data;
    printf("phdr name=%s addr=%p phnum=%d\n", info->dlpi_name ? info->dlpi_name : "(null)", (void *)info->dlpi_addr,
           info->dlpi_phnum);
    return 0;
}

static void dump_phdr(void)
{
    dl_iterate_phdr(phdr_cb, NULL);
    fflush(stdout);
}

int main(int argc, char **argv)
{
    long loops = argc > 1 ? atol(argv[1]) : 0;
    const char *s;
    long sleep_ms = 20;
    long phdr_every = 0;
    int test_fp = getenv("KCLF_TEST_FP") != NULL;
    struct timespec ts;
    struct timespec t0, t1;

    verbose = (s = getenv("KCLF_TEST_VERBOSE")) && *s;
    if ((s = getenv("KCLF_TEST_SLEEP_MS")) && *s) {
        sleep_ms = atol(s);
        if (sleep_ms <= 0) sleep_ms = 20;
    }
    if ((s = getenv("KCLF_TEST_PHDR_EVERY")) && *s) {
        phdr_every = atol(s);
        if (phdr_every < 0) phdr_every = 0;
    }

    printf("kclf-target pid=%d tgid=%d sleep_ms=%ld\n", getpid(), gettid(), sleep_ms);
    fflush(stdout);
    if (phdr_every) dump_phdr();

    /* touch the linker once so libdl.so is mapped before injection */
    void *h = dlopen("libdl.so", RTLD_NOW);
    printf("kclf-target dlopen(libdl.so)=%p\n", h);
    fflush(stdout);

    if (argc > 2 && argv[2][0]) {
        void *p = dlopen(argv[2], RTLD_NOW);
        printf("kclf-target dlopen(%s)=%p err=%s\n", argv[2], p, p ? "-" : dlerror());
        fflush(stdout);
    }

    if (getenv("KCLF_TEST_SECCOMP")) {
        /* Allow every syscall, including the getpid completion trap. KCLF must
         * accept a seccomp-filtered target instead of refusing every app. */
        struct sock_filter instructions[] = { BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW) };
        struct sock_fprog program = { .len = 1, .filter = instructions };
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) || prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program)) {
            perror("seccomp test setup");
            return 4;
        }
        puts("seccomp-test-ready");
        fflush(stdout);
    }

    ts.tv_sec = sleep_ms / 1000;
    ts.tv_nsec = (sleep_ms % 1000) * 1000000L;

    for (long i = 0; loops <= 0 || i < loops; i++) {
        int rc;
        long long elapsed_us;

        clock_gettime(CLOCK_MONOTONIC, &t0);
        /* nanosleep is a real syscall: guarantees a kernel entry per loop */
        rc = test_fp ? kclf_test_fp_sleep(&ts) : nanosleep(&ts, NULL);
        if (test_fp && rc) {
            printf("fp-state-failure mask=%d\n", rc);
            return 3;
        }
        clock_gettime(CLOCK_MONOTONIC, &t1);
        elapsed_us = (long long)(t1.tv_sec - t0.tv_sec) * 1000000LL + (t1.tv_nsec - t0.tv_nsec) / 1000;
        if (verbose && (rc != 0 || elapsed_us < sleep_ms * 1000 - 2000 || elapsed_us > sleep_ms * 1000 + 20000)) {
            char buf[160];
            int n = snprintf(buf, sizeof(buf), "sleep anomaly i=%ld rc=%d errno=%d elapsed_us=%lld\n", i, rc,
                             rc ? errno : 0, elapsed_us);
            if (write(1, buf, n) < 0) { /* ignore */
            }
        }
        if (phdr_every && (i % phdr_every) == 0 && i != 0) dump_phdr();
        if ((i % 25) == 0) {
            char buf[64];
            int n = snprintf(buf, sizeof(buf), "tick %ld\n", i);
            if (write(1, buf, n) < 0) { /* ignore */
            }
        }
    }
    printf("kclf-target exit\n");
    return 0;
}
