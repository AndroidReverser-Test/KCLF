/* Android regression for the exact position-independent runtime shipped by KCLF. */
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "kclf_tls.h"

static uint64_t state[KT_SIZE / 8], argument[2], descriptor[2];
static unsigned char initial[19] = {7, 8, 9, 10, [18] = 11};
static pthread_barrier_t start;
static long (*resolve_tls)(void *);
static uintptr_t last_block;
static int nested_initialization;
static volatile sig_atomic_t signal_seen;

extern int check_tls_registers(void *descriptor, void *resolver);

static unsigned char *address(void)
{
    uintptr_t tp;
    __asm__ volatile("mrs %0, tpidr_el0" : "=r"(tp));
    return (unsigned char *)(tp + resolve_tls(descriptor));
}

static void signal_handler(int signo)
{
    (void)signo;
    unsigned char *p = address();
    assert(p[0] == 7);
    p[0] = 8;
    signal_seen++;
}

static void *nested_getspecific(pthread_key_t key)
{
    void *result = pthread_getspecific(key);
    if (!nested_initialization) {
        nested_initialization = 1;
        raise(SIGUSR1);
    }
    return result;
}

static void verify_initial(unsigned char *p)
{
    assert(((uintptr_t)p & 65535) == 3);
    assert(!memcmp(p, initial, sizeof(initial)));
    for (int i = sizeof(initial); i < 8193; i++) assert(p[i] == 0);
}

static void *worker(void *unused)
{
    (void)unused;
    pthread_barrier_wait(&start);
    unsigned char *p = address();
    verify_initial(p);
    p[0] = 25;
    p[8192] = 92;
    assert(address() == p && p[0] == 25 && p[8192] == 92);
    return NULL;
}

static void *exiting_worker(void *unused)
{
    (void)unused;
    verify_initial(address());
    last_block = (uintptr_t)pthread_getspecific((pthread_key_t)state[KT_KEY / 8]);
    return NULL;
}

static int failed_key_create(pthread_key_t *key, void (*destructor)(void *))
{
    (void)key;
    (void)destructor;
    return EAGAIN;
}

static int failed_setspecific(pthread_key_t key, const void *value)
{
    (void)key;
    (void)value;
    return EINVAL;
}

static void deny_syscall(int number)
{
    struct sock_filter instructions[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (unsigned)number, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | ENOMEM),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog filter = {.len = sizeof(instructions) / sizeof(instructions[0]), .filter = instructions};
    assert(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0);
    assert(prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &filter) == 0);
}

int main(void)
{
    const size_t page = (size_t)sysconf(_SC_PAGESIZE);
    size_t bytes = (size_t)(kclf_tls_end - kclf_tls_start);
    void *code = mmap(NULL, page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(code != MAP_FAILED && bytes <= page);
    memcpy(code, kclf_tls_start, bytes);
    __builtin___clear_cache(code, (char *)code + bytes);
    assert(mprotect(code, page, PROT_READ | PROT_EXEC) == 0);
    int (*initialize)(void *) = (void *)((char *)code + (kclf_tls_init - kclf_tls_start));
    resolve_tls = (void *)((char *)code + (kclf_tls_resolve - kclf_tls_start));
    state[KT_MEMSZ / 8] = 8193;
    state[KT_FILESZ / 8] = sizeof(initial);
    state[KT_ALIGN / 8] = 65536;
    state[KT_FIRSTBYTE / 8] = 3;
    state[KT_TEMPLATE / 8] = (uintptr_t)initial;
    state[KT_GETSPECIFIC / 8] = (uintptr_t)pthread_getspecific;
    state[KT_SETSPECIFIC / 8] = (uintptr_t)pthread_setspecific;
    state[KT_ABORT / 8] = (uintptr_t)abort;
    state[KT_KEY_CREATE / 8] = (uintptr_t)failed_key_create;
    assert(initialize(state) == -EAGAIN);
    state[KT_KEY_CREATE / 8] = (uintptr_t)pthread_key_create;

    pthread_t old_threads[8], new_threads[8];
    assert(pthread_barrier_init(&start, NULL, 17) == 0);
    for (int i = 0; i < 8; i++) assert(pthread_create(&old_threads[i], NULL, worker, NULL) == 0);
    assert(initialize(state) == 0);
    argument[0] = (uintptr_t)state;
    descriptor[0] = (uintptr_t)resolve_tls;
    descriptor[1] = (uintptr_t)argument;
    for (int i = 0; i < 8; i++) assert(pthread_create(&new_threads[i], NULL, worker, NULL) == 0);
    pthread_barrier_wait(&start);
    assert(check_tls_registers(descriptor, resolve_tls) == 0);
    unsigned char *main_tls = address();
    verify_initial(main_tls);
    main_tls[0] = 31;
    for (int i = 0; i < 8; i++) {
        assert(pthread_join(old_threads[i], NULL) == 0);
        assert(pthread_join(new_threads[i], NULL) == 0);
    }
    assert(address() == main_tls && main_tls[0] == 31);
    assert(check_tls_registers(descriptor, resolve_tls) == 0);
    assert(pthread_barrier_destroy(&start) == 0);

    struct timespec begin, end;
    assert(clock_gettime(CLOCK_MONOTONIC, &begin) == 0);
    for (int i = 0; i < 1000000; i++) assert(address() == main_tls);
    assert(clock_gettime(CLOCK_MONOTONIC, &end) == 0);
    printf("TLS warm resolver: %.1f ns/access (1000000 calls)\n",
           ((end.tv_sec - begin.tv_sec) * 1e9 + end.tv_nsec - begin.tv_nsec) / 1e6);

    for (int i = 0; i < 32; i++) {
        pthread_t thread;
        assert(pthread_create(&thread, NULL, exiting_worker, NULL) == 0);
        assert(pthread_join(thread, NULL) == 0);
        unsigned char residency;
        errno = 0;
        assert(mincore((void *)last_block, page, &residency) == -1 && errno == ENOMEM);
    }

    /* A signal can initialize the key after the first getspecific snapshot.
     * The slow-path recheck must reuse that block and preserve its contents. */
    assert(initialize(state) == 0);
    struct sigaction action = {.sa_handler = signal_handler};
    sigemptyset(&action.sa_mask);
    assert(sigaction(SIGUSR1, &action, NULL) == 0);
    state[KT_GETSPECIFIC / 8] = (uintptr_t)nested_getspecific;
    sigset_t before, after;
    assert(pthread_sigmask(SIG_SETMASK, NULL, &before) == 0);
    unsigned char *nested_tls = address();
    assert(nested_tls[0] == 8 && signal_seen == 1);
    assert(pthread_sigmask(SIG_SETMASK, NULL, &after) == 0);
    assert(!memcmp(&before, &after, sizeof(before)));
    state[KT_GETSPECIFIC / 8] = (uintptr_t)pthread_getspecific;

    for (int failure = 0; failure < 3; failure++) {
        pid_t child = fork();
        assert(child >= 0);
        if (child == 0) {
            assert(initialize(state) == 0);
            if (failure == 0) state[KT_SETSPECIFIC / 8] = (uintptr_t)failed_setspecific;
            if (failure == 1) deny_syscall(__NR_mmap);
            if (failure == 2) deny_syscall(__NR_rt_sigprocmask);
            (void)address();
            _exit(99);
        }
        int status;
        assert(waitpid(child, &status, 0) == child && WIFSIGNALED(status) && WTERMSIG(status) == SIGABRT);
    }
    puts("PASS TLS runtime: old/new threads, template/BSS, 64K alignment, register preservation, key failure, destructor, signal reentry, setspecific/mmap/signal-mask failure");
    return 0;
}
