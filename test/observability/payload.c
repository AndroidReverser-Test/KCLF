#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

#ifndef OBS_ALTERNATE
#define OBS_ALTERNATE 0
#endif

__attribute__((visibility("default"), noinline))
int observation_payload_identity(void)
{
    return OBS_ALTERNATE ? 0x2468 : 0x1357;
}

static void marker(const char *phase)
{
    char line[128];
    int n = snprintf(line, sizeof(line), "%s pid=%d tid=%d identity=%x\n",
                     phase, getpid(), gettid(), observation_payload_identity());
    int fd = open("/data/user/0/com.kclf.obsprobe/files/payload.txt",
                  O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0600);
    if (fd >= 0) {
        if (write(fd, line, (size_t)n) < 0) { /* runner checks the marker */ }
        close(fd);
    }
}

__attribute__((constructor)) static void initialize(void) { marker("init"); }
__attribute__((destructor)) static void finalize(void) { marker("fini"); }
