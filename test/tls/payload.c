/* Inject into test/tls/host.c. The marker attests actual TLSDESC execution. */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static _Thread_local int initialized = 7;
static _Thread_local int zeroed;
_Thread_local int exported = 3;
static _Thread_local unsigned char aligned[8193] __attribute__((aligned(65536)));
static int global = 123;
static _Thread_local int *volatile pointer = &global;

static int sample(void)
{
    if (initialized != 7 || zeroed != 0 || exported != 3 || aligned[8192] != 0 ||
        ((uintptr_t)aligned & 65535) || pointer != &global || *pointer != 123) return 1;
    initialized = 9; zeroed = 17; exported = 11; aligned[8192] = 71;
    return 0;
}

static void *worker(void *unused)
{
    (void)unused;
    return (void *)(uintptr_t)sample();
}

__attribute__((constructor)) static void initialize(void)
{
    unsigned failed = sample();
    pthread_t threads[8];
    unsigned created = 0;
    for (; created < 8; created++) {
        if (pthread_create(&threads[created], NULL, worker, NULL)) { failed++; break; }
    }
    for (unsigned i = 0; i < created; i++) {
        void *result;
        if (pthread_join(threads[i], &result)) failed++;
        else failed += (unsigned)(uintptr_t)result;
    }
    failed += initialized != 9 || zeroed != 17 || exported != 11 || aligned[8192] != 71;
    const char *directory = getenv("KCLF_TLS_DIR");
#ifdef KCLF_TLS_APP
    if (!directory) directory = "/data/user/0/com.kclf.apptest/files";
#endif
    if (!directory) return;
    char path[512];
    snprintf(path, sizeof(path), "%s/result-%d", directory, getpid());
    FILE *file = fopen(path, "w");
    if (!file) return;
    fprintf(file, "TLS failed=%u threads=%u tid=%d\n", failed, created, gettid());
    fclose(file);
}
