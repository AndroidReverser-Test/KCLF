#include <fcntl.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

/* Ground truth only. The detector never matches this string or this payload. */
static void marker(const char *phase)
{
    struct timespec now;
    char line[160];
    clock_gettime(CLOCK_MONOTONIC, &now);
    int n = snprintf(line, sizeof(line), "PAYLOAD_%s pid=%d tid=%d time=%lld.%09ld\n",
                     phase, getpid(), gettid(), (long long)now.tv_sec, now.tv_nsec);
    int fd = open("/data/user/0/com.kclf.selfcheckv15/files/events.txt",
                  O_WRONLY | O_APPEND | O_CLOEXEC);
    if (fd >= 0) {
        if (write(fd, line, (size_t)n) < 0) { }
        close(fd);
    }
}
__attribute__((constructor)) static void initialize(void) { marker("INIT"); }
__attribute__((destructor)) static void finalize(void) { marker("FINI"); }
