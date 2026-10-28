/* Ordinary-app payload: no JNI, no dlopen, no ART calls. It only writes a
 * marker into the app's own files directory, which the app UID may access. */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#ifndef KCLF_APP_FILES
#define KCLF_APP_FILES "/data/user/0/com.kclf.apptest/files"
#endif
#ifndef KCLF_APP_DEFAULT_HOLD_MS
#define KCLF_APP_DEFAULT_HOLD_MS 0
#endif

__attribute__((constructor)) static void kclf_app_payload_init(void)
{
    char path[256];
    char buf[256];
    long pid = syscall(__NR_getpid);
    long tid = syscall(__NR_gettid);
    const char *hold = getenv("KCLF_APP_HOLD_MS");
    int fd;

    {
        struct timespec ts;
        long ms = hold && *hold ? strtol(hold, 0, 10) : KCLF_APP_DEFAULT_HOLD_MS;
        if (ms > 0) {
            ts.tv_sec = ms / 1000;
            ts.tv_nsec = (ms % 1000) * 1000000L;
            nanosleep(&ts, 0);
        }
    }

    snprintf(path, sizeof(path), KCLF_APP_FILES "/hit_%ld", pid);
    fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0666);
    if (fd >= 0) {
        int n = snprintf(buf, sizeof(buf), "pid=%ld tid=%ld marker=%p\n", pid, tid,
                         (void *)kclf_app_payload_init);
        if (write(fd, buf, (size_t)n) < 0) { /* ignore */ }
        close(fd);
    }
    snprintf(buf, sizeof(buf), "KCLF_APP_PAYLOAD pid=%ld tid=%ld\n", pid, tid);
    if (write(1, buf, strlen(buf)) < 0) { /* ignore */ }
#ifdef KCLF_APP_CLOBBER_FP
    __asm__ volatile("movi v0.16b, #0\n\tmovi v31.16b, #0\n\t"
                     "msr fpcr, xzr\n\tmsr fpsr, xzr" ::: "v0", "v31", "memory");
#endif
}
