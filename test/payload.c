/* KCLF test payload.
 *
 * By default the constructor is completely silent: injection is verified by
 * the KPM status output (the loader handle), not by side effects inside the
 * target.  Set KCLF_TEST_VERBOSE=1 to write the old marker file and stdout
 * line, and KCLF_TEST_HOLD_MS=<n> to keep the constructor (and therefore the
 * transient mapping) alive for a while when measuring.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <sys/syscall.h>

static void kclf_test_marker(void)
{
    const char *verbose = getenv("KCLF_TEST_VERBOSE");
    const char *directory = getenv("KCLF_TEST_DIR");
    char path[256];
    char buf[256];
    long pid;
    long tid;
    int fd;

    if (!verbose || !*verbose) return;

    pid = syscall(__NR_getpid);
    tid = syscall(__NR_gettid);
    snprintf(path, sizeof(path), "%s/hit_%ld", directory ? directory : "/data/local/tmp", pid);
    fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0666);
    if (fd >= 0) {
        int n = snprintf(buf, sizeof(buf), "pid=%ld tid=%ld payload=%p\n", pid, tid, (void *)kclf_test_marker);
        if (write(fd, buf, n) < 0) { /* ignore */
        }
        close(fd);
    }
    snprintf(buf, sizeof(buf), "kclf payload constructed in pid=%ld tid=%ld\n", pid, tid);
    if (write(1, buf, strlen(buf)) < 0) { /* ignore */
    }
}

__attribute__((constructor)) static void kclf_payload_init(void)
{
    const char *hold = getenv("KCLF_TEST_HOLD_MS");
    long ms = hold && *hold ? strtol(hold, NULL, 10) : 0;

    if (ms > 0) {
        struct timespec ts;
        ts.tv_sec = ms / 1000;
        ts.tv_nsec = (ms % 1000) * 1000000L;
        nanosleep(&ts, NULL);
    }
    kclf_test_marker();
    if (getenv("KCLF_TEST_CLOBBER_FP")) {
        /* Deliberately change caller-saved vector registers and FP controls;
         * the framework must restore the asynchronously interrupted task. */
        __asm__ volatile("movi v0.16b, #0\n\tmovi v31.16b, #0\n\t"
                         "msr fpcr, xzr\n\tmsr fpsr, xzr" ::
                             : "v0", "v31", "memory");
    }
}
