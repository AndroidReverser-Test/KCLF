#include <fcntl.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#ifndef HOLD_US
#define HOLD_US 0
#endif
/* Independent ground truth. The detector neither opens this log nor receives
 * a payload identity, injection address or injection notification. */
static void marker(const char *phase)
{
    struct timespec now;
    char line[200];
    clock_gettime(CLOCK_MONOTONIC, &now);
    int n = snprintf(line, sizeof(line), "PAYLOAD phase=%s hold_us=%d pid=%d tid=%d ns=%lld\n",
                     phase, HOLD_US, getpid(), gettid(), (long long)now.tv_sec * 1000000000LL + now.tv_nsec);
    int fd = open("/data/user/0/com.kclf.passive151/files/events.txt", O_WRONLY | O_APPEND | O_CLOEXEC);
    if (fd >= 0) { if (write(fd, line, (size_t)n) < 0) { } close(fd); }
}
__attribute__((constructor)) static void init(void)
{
    marker("BEGIN");
    if (HOLD_US) {
        struct timespec request = {HOLD_US / 1000000, (HOLD_US % 1000000) * 1000L};
        while (nanosleep(&request, &request) && request.tv_sec >= 0) { }
    }
    marker("END");
}
__attribute__((destructor)) static void fini(void) { marker("FINI"); }
