#include <jni.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

extern int kclf_test_fp_sleep(const struct timespec *ts);
static pthread_mutex_t probe_lock = PTHREAD_MUTEX_INITIALIZER;
static int probes_started;
static int idle_pipes[4][2];
static int idle_index[4] = { 0, 1, 2, 3 };

static void *idle_probe(void *arg)
{
    int index = *(int *)arg;
    char name[16], byte;
    snprintf(name, sizeof(name), "kclf-idle%d", index);
    pthread_setname_np(pthread_self(), name);
    /* The write end stays open. No synthetic signals or debugger are needed
     * to test queued cancellation and TWA_SIGNAL on an indefinitely blocked app thread. */
    while (read(idle_pipes[index][0], &byte, 1) >= 0 || errno == EINTR) {}
    return NULL;
}

static void *fp_probe(void *arg)
{
    char path[256], line[96];
    const struct timespec delay = { .tv_sec = 0, .tv_nsec = 100000000 };
    unsigned long tick = 0;
    (void)arg;
    pthread_setname_np(pthread_self(), "kclf-fp");
    snprintf(path, sizeof(path), "/data/user/0/com.kclf.apptest/files/fp_%d", getpid());
    for (;;) {
        int rc = kclf_test_fp_sleep(&delay);
        if (rc || !(tick % 10)) {
            int n = snprintf(line, sizeof(line), "tick=%lu fp-state-failure=%d\n", tick, rc);
            int fd = open(path, O_CREAT | O_WRONLY | O_APPEND, 0600);
            if (fd >= 0) {
                if (write(fd, line, (size_t)n) < 0) { /* test runner checks the log */ }
                close(fd);
            }
        }
        if (rc) return NULL;
        tick++;
    }
}

JNIEXPORT jint JNICALL Java_com_kclf_apptest_MainActivity_startProbes(JNIEnv *env, jclass cls)
{
    pthread_t thread;
    int rc = 0;
    (void)env;
    (void)cls;
    pthread_mutex_lock(&probe_lock);
    if (!probes_started) {
        probes_started = 1;
        for (int i = 0; i < 4; i++) {
            if (pipe(idle_pipes[i])) { rc = errno; break; }
            rc = pthread_create(&thread, NULL, idle_probe, &idle_index[i]);
            if (rc) {
                close(idle_pipes[i][0]);
                close(idle_pipes[i][1]);
                break;
            }
            pthread_detach(thread);
        }
        if (!rc) {
            rc = pthread_create(&thread, NULL, fp_probe, NULL);
            if (!rc) pthread_detach(thread);
        }
    }
    pthread_mutex_unlock(&probe_lock);
    return rc;
}

/* Presence of one JNI library makes the package's nativeLibraryDir real and
 * gives the app linker namespace a permitted /data/app/.../lib/arm64 path. */
JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved)
{
    (void)vm;
    (void)reserved;
    return JNI_VERSION_1_6;
}
