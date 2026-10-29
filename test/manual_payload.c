/* Runtime test: normal libc imports, imported data, weak undefined, data and
 * function relocations, constructor/destructor ordering, no background work. */
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

extern char **environ;
extern int kclf_missing_weak(void) __attribute__((weak));
int kclf_manual_value = 0x2468;
int *volatile kclf_manual_pointer = &kclf_manual_value;
static void marker(const char *phase)
{
    char path[512], text[160];
    const char *dir = getenv("KCLF_TEST_DIR");
    if (!dir) return;
    snprintf(path, sizeof(path), "%s/manual_%d.log", dir, getpid());
    int fd = open(path, O_CREAT | O_WRONLY | O_APPEND, 0600);
    if (fd < 0) return;
    int n = snprintf(text, sizeof(text), "%s value=%x data=%d weak=%d\n", phase,
                     *kclf_manual_pointer, environ != NULL, kclf_missing_weak == NULL);
    if (write(fd, text, (size_t)n) < 0) { }
    close(fd);
}
__attribute__((constructor(101))) static void first(void) { marker("init-101"); }
__attribute__((constructor(102))) static void second(void) { marker("init-102"); }
__attribute__((destructor(101))) static void fini_first(void) { marker("fini-101"); }
__attribute__((destructor(102))) static void fini_second(void) { marker("fini-102"); }
