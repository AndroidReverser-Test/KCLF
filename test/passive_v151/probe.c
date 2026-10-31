#define _GNU_SOURCE
#include <jni.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>
#include "signature.h"
#include "../../kclf_codegen.h"

/* Observation only: no seccomp installation, signal handler, ptrace, target
 * register writes, suspension, or loader-list locks. Test controls and business
 * work below are explicitly fixture code, not detector dependencies. */
#define MAP_LIMIT 8192
#define SCAN_BUDGET (256 * 1024)
#ifndef PERIOD_NS
#define PERIOD_NS 50000000ULL
#endif
#define HIST 128
#define ADD(p,v) __atomic_fetch_add((p),(v),__ATOMIC_RELAXED)
#define GET(p) __atomic_load_n((p),__ATOMIC_RELAXED)
#define SET(p,v) __atomic_store_n((p),(v),__ATOMIC_RELAXED)
static int log_fd = -1, app_pid, enabled = 1, ready_threads;
static int scanner_tid, pre_tid, new_tid, guarded_tid;
static size_t page_size;
static char library_dir[512], mode_name[32];
static uint64_t scans, cpu_ns, wall_ns, max_scan_ns, reads, read_fail, maps_fail, limited;
static uint64_t structural, rejected, detected, workload_count, workload_errors, churn_count;
static uint64_t guarded_calls, guarded_detections, guarded_unexpected, guarded_ns;
static uint64_t scan_hist[HIST], work_hist[HIST], frame_hist[HIST], ui_work_hist[HIST];
static uint64_t frames, ui_work_ns, ui_max_ns;
static uint64_t frame_max_ns, frame_over_25ms, frame_over_100ms;
struct region { uintptr_t begin, end; unsigned long inode; char permissions[5]; };
static struct region regions[MAP_LIMIT];
static unsigned region_count;
static unsigned char page_bytes[65536] __attribute__((aligned(8)));
static char maps_buffer[32768];
static uintptr_t scan_cursor, last_code;
static uint64_t last_token;

static uint64_t now(clockid_t clock)
{
    struct timespec t;
    clock_gettime(clock, &t);
    return (uint64_t)t.tv_sec * 1000000000ULL + t.tv_nsec;
}
static void pause_ns(uint64_t ns)
{
    struct timespec t = {(time_t)(ns / 1000000000), (long)(ns % 1000000000)};
    while (nanosleep(&t, &t) && errno == EINTR) { }
}
static void maximum(uint64_t *p, uint64_t v)
{
    uint64_t old = GET(p);
    while (old < v && !__atomic_compare_exchange_n(p, &old, v, 0, __ATOMIC_RELAXED, __ATOMIC_RELAXED)) { }
}
static void histogram(uint64_t *h, uint64_t ns, uint64_t width)
{
    uint64_t n = ns / width;
    ADD(h + (n < HIST ? n : HIST - 1), 1);
}
static void event(const char *fmt, ...)
{
    char line[1400];
    va_list args;
    va_start(args, fmt);
    int n = vsnprintf(line, sizeof(line), fmt, args);
    va_end(args);
    if (n > 0 && n < (int)sizeof(line) && write(log_fd, line, (size_t)n) != n) ADD(&workload_errors, 1);
}
static int read_self(uintptr_t at, void *to, size_t size)
{
    struct iovec local = {to, size}, remote = {(void *)at, size};
    ADD(&reads, 1);
    if (at < 4096 || at + size < at ||
        syscall(__NR_process_vm_readv, app_pid, &local, 1, &remote, 1, 0) != (ssize_t)size) {
        ADD(&read_fail, 1);
        return 0;
    }
    return 1;
}
static int integer(const char **cursor, const char *end, unsigned base, uintptr_t *value)
{
    const char *p = *cursor;
    uintptr_t n = 0;
    unsigned digits = 0;
    while (p < end) {
        unsigned d = (*p >= '0' && *p <= '9') ? (unsigned)(*p - '0') :
                     (*p >= 'a' && *p <= 'f') ? (unsigned)(*p - 'a' + 10) : 99;
        if (d >= base) break;
        if (n > (UINTPTR_MAX - d) / base) return 0;
        n = n * base + d; p++; digits++;
    }
    if (!digits) return 0;
    *cursor = p; *value = n;
    return 1;
}
static int map_line(const char *p, const char *end, struct region *r)
{
    uintptr_t inode;
    if (!integer(&p,end,16,&r->begin) || p == end || *p++ != '-' ||
        !integer(&p,end,16,&r->end) || p == end || *p++ != ' ' || r->begin >= r->end) return 0;
    while (p < end && *p == ' ') p++;
    if (end - p < 5 || p[4] != ' ') return 0;
    memcpy(r->permissions,p,4); r->permissions[4]=0; p+=5;
    for (unsigned field=0;field<2;field++) {
        while (p < end && *p == ' ') p++;
        while (p < end && *p != ' ') p++;
    }
    while (p < end && *p == ' ') p++;
    if (!integer(&p,end,10,&inode)) return 0;
    r->inode=(unsigned long)inode;
    return 1;
}
static int snapshot(void)
{
    /* A bounded streaming parser avoids per-line scanf and stdio locking. It
     * does not cache a stale maps list across scans or trust pathname labels. */
    int fd = open("/proc/self/maps", O_RDONLY | O_CLOEXEC), ok = 1;
    size_t carried = 0;
    region_count = 0;
    if (fd < 0) { ADD(&maps_fail,1); return 0; }
    for (;;) {
        ssize_t n=read(fd,maps_buffer+carried,sizeof(maps_buffer)-carried);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { if(n < 0 || carried) ok=0; break; }
        size_t used=carried+(size_t)n;
        char *p=maps_buffer, *end=maps_buffer+used, *newline;
        while ((newline=memchr(p,'\n',(size_t)(end-p)))) {
            if (region_count == MAP_LIMIT || !map_line(p,newline,regions+region_count)) { ok=0; goto finish; }
            region_count++; p=newline+1;
        }
        carried=(size_t)(end-p);
        if (carried == sizeof(maps_buffer)) { ok=0; break; }
        if (carried) memmove(maps_buffer,p,carried);
    }
finish:
    close(fd);
    if (!ok) ADD(&maps_fail,1);
    return ok;
}
static const struct region *region_at(uintptr_t at, size_t size)
{
    if (at < 4096 || at + size < at) return NULL;
    for (unsigned i = 0; i < region_count; i++)
        if (at >= regions[i].begin && at + size <= regions[i].end) return regions + i;
    return NULL;
}
static int private_rw(uintptr_t at)
{
    const struct region *r = region_at(at, page_size);
    return r && !r->inode && r->permissions[0] == 'r' && r->permissions[1] == 'w' && r->permissions[2] != 'x';
}
static int file_exec(uintptr_t at)
{
    const struct region *r = region_at(at, 4);
    return r && r->inode && r->permissions[0] == 'r' && r->permissions[2] == 'x';
}
static uint64_t read_le64(const unsigned char *b, unsigned off)
{ uint64_t n; memcpy(&n, b + off, 8); return n; }
static uint32_t read_le32(const unsigned char *b, unsigned off)
{ uint32_t n; memcpy(&n, b + off, 4); return n; }

static int corroborate(uintptr_t code, const struct candidate *c)
{
    unsigned char private_bytes[4096] __attribute__((aligned(8)));
    unsigned char abi[448] __attribute__((aligned(8)));
    uint64_t saved_again[34], token_again;
    uint32_t tail_again[34];
    if ((c->abi & (page_size - 1)) || (c->priv & (page_size - 1)) ||
        c->abi == code || c->priv == code || !private_rw(c->abi) || !private_rw(c->priv)) return 0;
    if (!read_self(c->priv, private_bytes, sizeof(private_bytes)) || !read_self(c->abi, abi, sizeof(abi))) return 0;
    uint64_t pc = read_le64(private_bytes, c->saved + 256), sp = read_le64(private_bytes, c->saved + 248);
    uint64_t nzcv = read_le64(private_bytes, c->saved + 264);
    uint64_t token = read_le64(private_bytes, c->token), done = read_le64(private_bytes, c->done);
    const struct region *stack = region_at(sp, 8);
    if (!token || (pc & 3) || !file_exec(pc) || (sp & 15) || !stack ||
        stack->permissions[0] != 'r' || stack->permissions[1] != 'w' || (nzcv & ~0xf0000000ULL)) return 0;
    int zero = 1;
    for (unsigned i = 0; i < sizeof(abi); i++) if (abi[i]) { zero = 0; break; }
    if (done == token) {
        if (!zero) return 0;
    } else {
        uint32_t manual = read_le32(abi, 0x148);
        if (manual > 1 || read_le32(abi, 0x28) != 2 || read_le32(abi, 0x38) > 1 ||
            !memchr(abi + 0x40, 0, 256)) return 0;
        if (abi[0x40] != '/' && (abi[0x40] < '0' || abi[0x40] > '9')) return 0;
        if (manual) {
            uint64_t ni = read_le64(abi, 0x158), nf = read_le64(abi, 0x168), nr = read_le64(abi, 0x180);
            if (!read_le64(abi, 0x18) || ni > 256 || nf > 256 || nr > 128 ||
                448 + (ni + nf) * 8 + nr * 24 > page_size ||
                read_le64(abi, 0x150) != c->abi + 448 ||
                read_le64(abi, 0x160) != c->abi + 448 + ni * 8 ||
                read_le64(abi, 0x178) != c->abi + 448 + (ni + nf) * 8) return 0;
        } else if (!file_exec(read_le64(abi, 0))) return 0;
    }
    /* Re-read immutable evidence to reject unmap/reuse races. A failed read is
     * inconclusive, never a positive or proof of absence. */
    if (!read_self(code + c->tail_word * 4, tail_again, sizeof(tail_again)) ||
        memcmp(tail_again, page_bytes + c->tail_word * 4, sizeof(tail_again)) ||
        !read_self(c->priv + c->saved, saved_again, sizeof(saved_again)) ||
        memcmp(saved_again, private_bytes + c->saved, sizeof(saved_again)) ||
        !read_self(c->priv + c->token, &token_again, 8) || token_again != token) return 0;
    if (last_code != code || last_token != token) {
        last_code = code; last_token = token;
        ADD(&detected, 1);
        event("DETECT rule=ctx_v151 observer=%d ns=%" PRIu64 " code=%" PRIxPTR " private=%" PRIxPTR
              " original_pc=%" PRIx64 " original_sp=%" PRIx64 " phase=%s\n",
              gettid(), now(CLOCK_MONOTONIC), code, c->priv, pc, sp, done == token ? "complete" : "running");
    }
    return 1;
}
static void scan_once(void)
{
    uint64_t begin = now(CLOCK_MONOTONIC), cpu = now(CLOCK_THREAD_CPUTIME_ID);
    if (snapshot()) {
        size_t spent = 0;
        uintptr_t next = 0;
        for (unsigned i = 0; i < region_count; i++) {
            struct region *r = regions + i;
            if (r->inode || r->permissions[0] != 'r' || r->permissions[1] == 'w' || r->permissions[2] != 'x') continue;
            for (uintptr_t at = r->begin; at + page_size <= r->end; at += page_size) {
                if (scan_cursor && at < scan_cursor) continue;
                if (spent + page_size > SCAN_BUDGET) { next = at; goto budget; }
                spent += page_size;
                if (read_self(at, page_bytes, page_size)) {
                    struct candidate c;
                    if (recognize((const uint32_t *)page_bytes, page_size / 4, &c)) {
                        ADD(&structural, 1);
                        if (!corroborate(at, &c)) ADD(&rejected, 1);
                    }
                }
            }
        }
budget:
        scan_cursor = next;
        if (next) ADD(&limited, 1);
    }
    uint64_t elapsed = now(CLOCK_MONOTONIC) - begin;
    ADD(&scans, 1); ADD(&wall_ns, elapsed); ADD(&cpu_ns, now(CLOCK_THREAD_CPUTIME_ID) - cpu);
    maximum(&max_scan_ns, elapsed); histogram(scan_hist, elapsed, 100000);
}
static void health(void)
{
    event("HEALTH scans=%" PRIu64 " cpu_ns=%" PRIu64 " wall_ns=%" PRIu64 " max_scan_ns=%" PRIu64
          " reads=%" PRIu64 " read_fail=%" PRIu64 " maps_fail=%" PRIu64 " limited=%" PRIu64
          " structural=%" PRIu64 " rejected=%" PRIu64 " detections=%" PRIu64 " work=%" PRIu64
          " errors=%" PRIu64 " churn=%" PRIu64 " frames=%" PRIu64 " ui_work_ns=%" PRIu64 " ui_max_ns=%" PRIu64
          " guarded_calls=%" PRIu64 " guarded_detections=%" PRIu64 " guarded_unexpected=%" PRIu64 " guarded_check_ns=%" PRIu64
          " frame_max_ns=%" PRIu64 " frame_over_25ms=%" PRIu64 " frame_over_100ms=%" PRIu64 "\n",
          GET(&scans), GET(&cpu_ns), GET(&wall_ns), GET(&max_scan_ns), GET(&reads), GET(&read_fail), GET(&maps_fail),
          GET(&limited), GET(&structural), GET(&rejected), GET(&detected), GET(&workload_count), GET(&workload_errors),
          GET(&churn_count), GET(&frames), GET(&ui_work_ns), GET(&ui_max_ns),
          GET(&guarded_calls), GET(&guarded_detections), GET(&guarded_unexpected), GET(&guarded_ns),
          GET(&frame_max_ns), GET(&frame_over_25ms), GET(&frame_over_100ms));
}
static void *scanner(void *unused)
{
    (void)unused;
    pthread_setname_np(pthread_self(), "passive-scan");
    int priority_rc = setpriority(PRIO_PROCESS, 0, 10);
    SET(&scanner_tid, gettid()); ADD(&ready_threads, 1);
    event("THREAD label=scanner tid=%d nice=%d priority_rc=%d\n", gettid(), getpriority(PRIO_PROCESS, 0), priority_rc);
    uint64_t last = now(CLOCK_MONOTONIC);
    for (;;) {
        uint64_t start = now(CLOCK_MONOTONIC);
        if (GET(&enabled)) scan_once();
        if (start - last >= 1000000000ULL) { health(); last = start; }
        uint64_t elapsed = now(CLOCK_MONOTONIC) - start;
        pause_ns(elapsed < PERIOD_NS ? PERIOD_NS - elapsed : 1000000);
    }
    return NULL;
}
static void *victim(void *which)
{
    int is_new = (int)(intptr_t)which;
    pthread_setname_np(pthread_self(), is_new ? "passive-new" : "passive-pre");
    SET(is_new ? &new_tid : &pre_tid, gettid()); ADD(&ready_threads, 1);
    event("THREAD label=%s tid=%d\n", is_new ? "new" : "pre", gettid());
    for (;;) pause_ns(5000000);
    return NULL;
}
static void *helper(void *x) { return x; }
struct guard_result { uint64_t observed, expected, return_pc; };
extern long passive_guarded_sleep(const struct timespec *, struct guard_result *, uint64_t);
static void *guarded_worker(void *unused)
{
    (void)unused;
    pthread_setname_np(pthread_self(),"passive-guard");
    SET(&guarded_tid,gettid()); ADD(&ready_threads,1);
    event("THREAD label=guarded tid=%d\n",gettid());
    for (uint64_t i=1;;i++) {
        struct timespec t={0,5000000};
        struct guard_result r={0};
        uint64_t sentinel=0xeac0000000000000ULL | (i & 0x000fffffffffffffULL);
        (void)passive_guarded_sleep(&t,&r,sentinel);
        uint64_t begin=now(CLOCK_THREAD_CPUTIME_ID);
        ADD(&guarded_calls,1);
        if(r.observed!=r.expected) {
            /* A restarted syscall resumes at the SVC itself (PC-4); a normal
             * return resumes at the following store. Both must match this
             * fixture's exact, known instruction boundary, not an arbitrary PC. */
            if(r.expected==sentinel && (r.observed==r.return_pc || r.observed==r.return_pc-4)) {
                ADD(&guarded_detections,1);
                event("DETECT rule=x16_boundary observer=%d ns=%" PRIu64 " observed=%" PRIx64
                      " expected=%" PRIx64 " return_pc=%" PRIx64 "\n",
                      gettid(),now(CLOCK_MONOTONIC),r.observed,r.expected,r.return_pc);
            } else {
                ADD(&guarded_unexpected,1);
                event("INCONCLUSIVE rule=x16_boundary observed=%" PRIx64 " expected=%" PRIx64
                      " return_pc=%" PRIx64 "\n",r.observed,r.expected,r.return_pc);
            }
        }
        ADD(&guarded_ns,now(CLOCK_THREAD_CPUTIME_ID)-begin);
    }
    return NULL;
}
static void *business(void *unused)
{
    (void)unused;
    pthread_setname_np(pthread_self(), "passive-work");
    char normal[600];
    snprintf(normal, sizeof(normal), "%s/libnormal.so", library_dir);
    uint64_t count = 0;
    for (;;) {
        uint64_t begin = now(CLOCK_MONOTONIC);
        uint64_t *buffer = malloc(4096);
        if (!buffer) { ADD(&workload_errors, 1); break; }
        for (unsigned i = 0; i < 512; i++) buffer[i] = (count ^ i) * 0x123456789ULL;
        for (unsigned i = 0; i < 512; i++) if (buffer[i] != (count ^ i) * 0x123456789ULL) ADD(&workload_errors, 1);
        free(buffer);
        char name[64];
        int fd = open("/proc/self/comm", O_RDONLY | O_CLOEXEC);
        if (fd < 0 || read(fd, name, sizeof(name)) <= 0) ADD(&workload_errors, 1);
        if (fd >= 0) close(fd);
        if (!(count % 16)) {
            void *lib = dlopen(normal, RTLD_NOW | RTLD_LOCAL);
            int (*fn)(int) = lib ? (int (*)(int))dlsym(lib, "ordinary_calculation") : NULL;
            if (!fn || fn(13) != ((13 * 7 + 3) ^ 123)) ADD(&workload_errors, 1);
            if (lib) dlclose(lib);
        }
        if (!(count % 128)) {
            pthread_t p; void *answer = NULL;
            if (pthread_create(&p, NULL, helper, (void *)(uintptr_t)123)) ADD(&workload_errors, 1);
            else if (pthread_join(p, &answer) || answer != (void *)(uintptr_t)123) ADD(&workload_errors, 1);
        }
        histogram(work_hist, now(CLOCK_MONOTONIC) - begin, 50000);
        ADD(&workload_count, 1); count++;
        pause_ns(5000000);
    }
    return NULL;
}
static void *churn(void *unused)
{
    (void)unused;
    pthread_setname_np(pthread_self(), "passive-maps");
    uint64_t seed = 123;
    for (;;) {
        uint32_t *p = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) { ADD(&workload_errors, 1); continue; }
        for (size_t i = 0; i < page_size / 4; i++) { seed = seed * 6364136223846793005ULL + 1; p[i] = seed >> 32; }
        if (mprotect(p, page_size, PROT_READ | PROT_EXEC)) ADD(&workload_errors, 1);
        pause_ns(1000000);
        if (munmap(p, page_size)) ADD(&workload_errors, 1);
        ADD(&churn_count, 1);
        pause_ns(1000000);
    }
    return NULL;
}
static int controls(void)
{
    uint32_t *exec = mmap(NULL, page_size, 3, 0x22, -1, 0);
    uint32_t *data = mmap(NULL, page_size, 3, 0x22, -1, 0);
    uint32_t *ordinary = mmap(NULL, page_size, 3, 0x22, -1, 0);
    if (exec == MAP_FAILED || data == MAP_FAILED || ordinary == MAP_FAILED) return 0;
    struct kclf_priv_layout pl = {.saved=0, .qregs=288, .fpcr=800, .fpsr=808, .done=816,
                                  .donetok=824, .handle=832, .errptr=840, .rc=848, .end=856};
    struct kclf_prog program;
    /* Exact current template with intentionally absent private/ABI pages:
     * byte-template evidence alone MUST NOT produce a detection. */
    if (kclf_prog_build((u8 *)exec, page_size, 0x10000, 0x20000, &pl, 0x9911aabb, &program)) return 0;
    memcpy(data, exec, page_size);
    struct candidate candidate;
    if (!recognize(exec, page_size / 4, &candidate)) return 0;
    ordinary[0] = 0xd2800540u; ordinary[1] = 0xd65f03c0u;
    __builtin___clear_cache((char *)ordinary, (char *)ordinary + 8);
    if (mprotect(exec, page_size, 5) || mprotect(ordinary, page_size, 5)) return 0;
    int (*fn)(void) = (int (*)(void))ordinary;
    for (unsigned i = 0; i < 1000; i++) if (fn() != 42) return 0;
    event("CONTROLS exact_template_rx=%" PRIxPTR " exact_template_rw=%" PRIxPTR
          " ordinary_rx=%" PRIxPTR " calls=1000 expected=42\n", (uintptr_t)exec, (uintptr_t)data, (uintptr_t)ordinary);
    return 1;
}

struct sample { uint64_t scans, cpu, work, frames, errors, detections, wall, hist[4][HIST]; };
static void sample(struct sample *s)
{
    s->scans=GET(&scans); s->cpu=GET(&cpu_ns); s->work=GET(&workload_count); s->frames=GET(&frames);
    s->errors=GET(&workload_errors); s->detections=GET(&detected); s->wall=now(CLOCK_MONOTONIC);
    for (unsigned i=0; i<HIST; i++) {
        s->hist[0][i]=GET(scan_hist+i); s->hist[1][i]=GET(work_hist+i);
        s->hist[2][i]=GET(frame_hist+i); s->hist[3][i]=GET(ui_work_hist+i);
    }
}
static unsigned percentile(const struct sample *a, const struct sample *b, unsigned h, unsigned p, unsigned width)
{
    uint64_t total=0, running=0;
    for (unsigned i=0;i<HIST;i++) total+=b->hist[h][i]-a->hist[h][i];
    if (!total) return 0;
    for (unsigned i=0;i<HIST;i++) {
        running+=b->hist[h][i]-a->hist[h][i];
        if (running * 100 >= total * p) return (i+1)*width;
    }
    return HIST * width;
}
static void *benchmark(void *unused)
{
    (void)unused;
    static const int order[] = {0,1,1,0,1,0,0,1};
    pause_ns(2000000000ULL);
    for (unsigned phase=0;phase<8;phase++) {
        struct sample a,b;
        SET(&enabled,order[phase]);
        pause_ns(1000000000ULL); sample(&a);
        pause_ns(4000000000ULL); sample(&b);
        event("BENCH phase=%u enabled=%d elapsed_ns=%" PRIu64 " scans=%" PRIu64 " cpu_ns=%" PRIu64
              " work=%" PRIu64 " frames=%" PRIu64 " errors=%" PRIu64 " detections=%" PRIu64
              " scan_p99_us=%u work_p95_us=%u work_p99_us=%u frame_p95_us=%u frame_p99_us=%u ui_p99_us=%u\n",
              phase,order[phase],b.wall-a.wall,b.scans-a.scans,b.cpu-a.cpu,b.work-a.work,b.frames-a.frames,
              b.errors-a.errors,b.detections-a.detections,percentile(&a,&b,0,99,100),
              percentile(&a,&b,1,95,50),percentile(&a,&b,1,99,50),percentile(&a,&b,2,95,1000),
              percentile(&a,&b,2,99,1000),percentile(&a,&b,3,99,50));
    }
    SET(&enabled,1); health(); event("BENCH_DONE\n");
    return NULL;
}
JNIEXPORT void JNICALL Java_com_kclf_passive151_MainActivity_frame(JNIEnv *env,jclass type,jlong interval,jlong work)
{
    (void)env; (void)type;
    ADD(&frames,1); ADD(&ui_work_ns,(uint64_t)work); maximum(&ui_max_ns,work);
    maximum(&frame_max_ns,(uint64_t)interval);
    if(interval>25000000) ADD(&frame_over_25ms,1);
    if(interval>100000000) ADD(&frame_over_100ms,1);
    histogram(frame_hist,interval,1000000); histogram(ui_work_hist,work,50000);
}
JNIEXPORT void JNICALL Java_com_kclf_passive151_MainActivity_start(JNIEnv *env,jclass type,jstring files,jstring libs,jstring mode)
{
    (void)type;
    const char *f=(*env)->GetStringUTFChars(env,files,NULL), *l=(*env)->GetStringUTFChars(env,libs,NULL);
    const char *m=(*env)->GetStringUTFChars(env,mode,NULL);
    char path[640]; snprintf(path,sizeof(path),"%s/events.txt",f);
    snprintf(library_dir,sizeof(library_dir),"%s",l); snprintf(mode_name,sizeof(mode_name),"%s",m);
    (*env)->ReleaseStringUTFChars(env,files,f); (*env)->ReleaseStringUTFChars(env,libs,l); (*env)->ReleaseStringUTFChars(env,mode,m);
    log_fd=open(path,O_WRONLY|O_CREAT|O_TRUNC|O_APPEND|O_CLOEXEC,0600);
    if(log_fd<0) return;
    app_pid=getpid(); page_size=(size_t)sysconf(_SC_PAGESIZE);
    event("IDENTITY pid=%d uid=%d euid=%d dumpable=%d seccomp=%d no_new_privs=%d page=%zu\n",
          app_pid,getuid(),geteuid(),prctl(PR_GET_DUMPABLE),prctl(PR_GET_SECCOMP),prctl(PR_GET_NO_NEW_PRIVS,0,0,0,0),page_size);
    FILE *status=fopen("/proc/self/status","re"); char line[256];
    if(status){while(fgets(line,sizeof(line),status)) if(!strncmp(line,"CapEff:",7)||!strncmp(line,"Seccomp:",8))event("%s",line);fclose(status);}
    status=fopen("/proc/self/attr/current","re");
    if(status){if(fgets(line,sizeof(line),status))event("CONTEXT %s\n",line);fclose(status);}
    uint64_t value=0x12345678, copy=0;
    if(page_size>sizeof(page_bytes)||!read_self((uintptr_t)&value,&copy,8)||copy!=value||!controls()){
        event("ERROR startup controls/self-read unsupported\n");return;
    }
    SET(&enabled,strcmp(mode_name,"bench")!=0);
    pthread_t threads[7];
    if(pthread_create(threads,NULL,victim,(void *)0)||pthread_create(threads+1,NULL,scanner,NULL)||
       pthread_create(threads+2,NULL,victim,(void *)1)||pthread_create(threads+3,NULL,business,NULL)||
       pthread_create(threads+4,NULL,churn,NULL)||pthread_create(threads+5,NULL,guarded_worker,NULL)){
        event("ERROR thread creation\n");return;}
    for(unsigned i=0;i<1000&&GET(&ready_threads)<4;i++)pause_ns(1000000);
    if(GET(&ready_threads)!=4){event("ERROR readiness\n");return;}
    event("READY pid=%d main=%d pre=%d new=%d scanner=%d guarded=%d mode=%s library=%s period_ms=%u budget_bytes=%d\n",
          app_pid,gettid(),GET(&pre_tid),GET(&new_tid),GET(&scanner_tid),GET(&guarded_tid),mode_name,library_dir,
          (unsigned)(PERIOD_NS/1000000),SCAN_BUDGET);
    if(!strcmp(mode_name,"bench")&&pthread_create(threads+6,NULL,benchmark,NULL))event("ERROR benchmark thread\n");
}
