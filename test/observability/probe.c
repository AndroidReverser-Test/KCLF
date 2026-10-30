#define _GNU_SOURCE
#include <jni.h>
#include <dlfcn.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <link.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <ucontext.h>
#include <unistd.h>

/*
 * Fixture for the hardened KCLF (1.4.2) observability report.
 *
 * It implements three independent rules:
 *
 *   1. LEGACY_MANUAL  - the exact "known payload" rule of 1.4.1: an anonymous
 *      readable mapping whose *start* is a byte-identical copy of the known ELF
 *      header, whose PT_LOADs are fully covered, and which is not registered
 *      with the linker.  This must no longer produce a positive.
 *
 *   2. KNOWN_HEADER   - a stronger anchor: scan every readable anonymous page
 *      for the full known ELF header, ignoring where the mapping starts.  The
 *      default manual backend scrubs the header, so this must also stay silent;
 *      with "keepelf" it is expected to find the retained header.
 *
 *   3. RESIDUAL_TEXT  - a content scan that needs no ELF metadata: look for a
 *      known .text signature in anonymous executable mappings.  This one is
 *      expected to match while the payload is resident: readable code cannot be
 *      hidden from the process that owns it.  It is reported separately so the
 *      report can state the residual exposure honestly.
 *
 *   4. RESIDUAL_TAG   - the 1.4.2 generated EL0 program embedded the ASCII
 *      marker "KCLFBAIL" in the executable code page.  A scanner that does not
 *      know the payload could still recognize the framework by that literal.
 *      1.4.3 uses a per-request random token kept in the private page, so this
 *      rule must never fire.
 *
 * A seccomp guard traps the cheap informational syscalls that a detector can
 * convert into a signal without breaking itself (getpid/gettid/getuid/...).
 * KCLF 1.4.3 issues none of them during injection, so the guard must observe
 * zero unexpected traps.  A local anonymous stub triggers the same guard in a
 * controlled way, proving the guard is armed.
 */

#define MAX_MAPS 8192
#define MAX_PHDR 64
#define MAX_PAYLOAD (1024 * 1024)
#define MAX_TRAPS 64
#define MAX_REPORTED 16
#define SCAN_BUDGET (8 * 1024 * 1024)
#define SCAN_CHUNK (64 * 1024)

struct region {
    uintptr_t begin, end;
    unsigned long inode;
    char perms[5];
};
static struct region regions[MAX_MAPS];
static unsigned nregions;
static unsigned char *reference;
static size_t reference_size, page_size;
static Elf64_Ehdr expected_header;
static Elf64_Phdr expected_phdr[MAX_PHDR];
static unsigned char text_signature[32];
static size_t text_signature_size;
static int events_fd = -1;
static pid_t app_pid, app_ppid, observer_tid;
/* Cached before the filter is armed: the handler must not issue syscalls. */
static unsigned cached_uid, cached_euid, cached_gid, cached_egid;
static char files_path[512], library_path[512], mode_name[32];

struct trap_record {
    unsigned long nr;
    uintptr_t pc;
    unsigned kind; /* 0 control stub, 1 file-backed code, 2 anonymous code */
};
static volatile struct trap_record traps[MAX_TRAPS];
static volatile unsigned trap_count;
static volatile unsigned control_traps;
static volatile unsigned known_code_traps;
static volatile unsigned unexpected_traps;
static volatile uintptr_t control_rx_begin, control_rx_end;
static unsigned logged_traps;

/* File-backed executable mappings known before the guard is installed.  A
 * trapped syscall executed from libc/linker is ordinary app code; one executed
 * from anonymous memory is what the framework's generated code would look like.
 * The transient KCLF code page is never part of this list. */
#define MAX_KNOWN_CODE 1024
static struct {
    uintptr_t begin, end;
} known_code[MAX_KNOWN_CODE];
static unsigned n_known_code;

static int pc_is_known_code(uintptr_t pc)
{
    for (unsigned i = 0; i < n_known_code; i++)
        if (pc >= known_code[i].begin && pc < known_code[i].end) return 1;
    return 0;
}

static uintptr_t reported_manual;
static uintptr_t reported_header[MAX_REPORTED];
static unsigned nreported_header;
static uintptr_t reported_text[MAX_REPORTED];
static unsigned nreported_text;
/* 1.4.2 embedded this literal in the generated code page. */
static const unsigned char tag_signature[] = "KCLFBAIL";
static uintptr_t reported_tag[MAX_REPORTED];
static unsigned nreported_tag;

/* The fixture must not report its own reference copy as a finding. */
struct own_range {
    uintptr_t begin, end;
};
static struct own_range own_ranges[4];
static unsigned nown_ranges;

static int own_memory(uintptr_t at, size_t length)
{
    for (unsigned i = 0; i < nown_ranges; i++)
        if (at >= own_ranges[i].begin && at + length <= own_ranges[i].end) return 1;
    return 0;
}

static void event(const char *format, ...)
{
    char line[1024];
    va_list args;
    va_start(args, format);
    int n = vsnprintf(line, sizeof(line), format, args);
    va_end(args);
    if (n > 0 && n < (int)sizeof(line)) {
        if (write(events_fd, line, (size_t)n) < 0) { /* evidence collection fails */ }
    }
}

/* A failed/racing read is not a positive. No /proc/self/mem access is used. */
static int read_self(uintptr_t address, void *buffer, size_t size)
{
    struct iovec local = { buffer, size };
    struct iovec remote = { (void *)address, size };
    return syscall(__NR_process_vm_readv, app_pid, &local, 1, &remote, 1, 0) == (ssize_t)size;
}

static unsigned maps_parse_errors;

static int maps_snapshot(void)
{
    char line[4096];
    FILE *fp = fopen("/proc/self/maps", "re");
    nregions = 0;
    maps_parse_errors = 0;
    if (!fp) return 0;
    while (fgets(line, sizeof(line), fp)) {
        struct region item;
        if (sscanf(line, "%" SCNxPTR "-%" SCNxPTR " %4s %*s %*s %lu",
                   &item.begin, &item.end, item.perms, &item.inode) != 4) {
            /* A truncated long pathname must not discard the whole snapshot. */
            maps_parse_errors++;
            continue;
        }
        if (nregions == MAX_MAPS) break;
        regions[nregions++] = item;
    }
    int ok = !ferror(fp);
    fclose(fp);
    return ok;
}

static int covered(uintptr_t begin, size_t length, int executable, int anonymous)
{
    if (begin + length < begin) return 0;
    uintptr_t end = begin + length;
    for (unsigned i = 0; i < nregions && begin < end; i++) {
        const struct region *m = &regions[i];
        if (m->end <= begin) continue;
        if (m->begin > begin || m->perms[0] != 'r' ||
            (executable && m->perms[2] != 'x') || (anonymous && m->inode)) return 0;
        begin = m->end < end ? m->end : end;
    }
    return begin == end;
}

static int registered_callback(struct dl_phdr_info *info, size_t size, void *context)
{
    (void)size;
    return (uintptr_t)info->dlpi_addr == *(uintptr_t *)context;
}

/* Rule 1: the exact 1.4.1 known-manual-image rule. */
static uintptr_t legacy_known_manual(void)
{
    unsigned char block[2048];
    if (!maps_snapshot()) return 0;
    for (unsigned i = 0; i < nregions; i++) {
        const struct region *m = &regions[i];
        Elf64_Ehdr header;
        if (m->inode || m->perms[0] != 'r' || m->end - m->begin < sizeof(header) ||
            !read_self(m->begin, &header, sizeof(header)) ||
            memcmp(&header, &expected_header, sizeof(header))) continue;
        uintptr_t bias = 0;
        int found_base = 0;
        for (unsigned p = 0; p < expected_header.e_phnum; p++) {
            if (expected_phdr[p].p_type == PT_LOAD && !expected_phdr[p].p_offset &&
                expected_phdr[p].p_filesz >= sizeof(header) &&
                m->begin >= expected_phdr[p].p_vaddr) {
                bias = m->begin - expected_phdr[p].p_vaddr;
                found_base = 1;
            }
        }
        if (!found_base || dl_iterate_phdr(registered_callback, &bias)) continue;
        int ok = 1, executable = 0;
        for (unsigned p = 0; ok && p < expected_header.e_phnum; p++) {
            const Elf64_Phdr *ph = &expected_phdr[p];
            if (ph->p_type != PT_LOAD || !ph->p_memsz) continue;
            if (ph->p_vaddr > UINTPTR_MAX - bias || ph->p_memsz > SIZE_MAX ||
                !covered(bias + ph->p_vaddr, (size_t)ph->p_memsz,
                         !!(ph->p_flags & PF_X), 1)) { ok = 0; break; }
            if (ph->p_flags & PF_X) executable++;
            if (ph->p_flags & PF_W) continue; /* relocations change writable bytes */
            for (size_t at = 0; ok && at < ph->p_filesz; ) {
                size_t n = (size_t)ph->p_filesz - at;
                if (n > sizeof(block)) n = sizeof(block);
                if (!read_self(bias + ph->p_vaddr + at, block, n) ||
                    memcmp(block, reference + ph->p_offset + at, n)) ok = 0;
                at += n;
            }
        }
        if (ok && executable) return bias;
    }
    return 0;
}

static int already_reported(uintptr_t *list, unsigned *count, uintptr_t value)
{
    for (unsigned i = 0; i < *count; i++)
        if (list[i] == value) return 1;
    if (*count < MAX_REPORTED) list[(*count)++] = value;
    return 0;
}

struct scan_cursor {
    unsigned region;
    uintptr_t offset;
};
static struct scan_cursor header_cursor, text_cursor, tag_cursor;

/* Search [begin,end) for @needle within @budget bytes.  On return *resume is
 * where the next call must continue, and *budget is what is left. */
static uintptr_t scan_region(uintptr_t begin, uintptr_t end, const void *needle, size_t length,
                             size_t *budget, uintptr_t *resume)
{
    unsigned char buffer[SCAN_CHUNK + 64];
    uintptr_t at = begin;
    *resume = begin;
    if (!length || length > sizeof(buffer)) return 0;
    while (at + length <= end) {
        size_t want = (size_t)(end - at);
        uintptr_t found;
        if (want > SCAN_CHUNK + length) want = SCAN_CHUNK + length;
        if (want > *budget) want = *budget;
        if (want < length) return 0;
        if (!read_self(at, buffer, want)) {
            /* unreadable hole: skip a page and charge it to the budget */
            at += page_size;
            *budget = *budget > page_size ? *budget - page_size : 0;
            *resume = at;
            continue;
        }
        *budget -= want;
        for (size_t i = 0; i + length <= want; i += 4) {
            if (!memcmp(buffer + i, needle, length)) {
                if (own_memory(at + i, length)) continue; /* the fixture's own copy */
                found = at + i;
                return found;
            }
        }
        at += want - length + 1;
        *resume = at;
    }
    return 0;
}

static void report_header(uintptr_t at)
{
    if (!already_reported(reported_header, &nreported_header, at))
        event("KNOWN_HEADER addr=%" PRIxPTR "\n", at);
}

static void report_text(uintptr_t at)
{
    if (!already_reported(reported_text, &nreported_text, at))
        event("RESIDUAL_TEXT addr=%" PRIxPTR "\n", at);
}

static void report_tag(uintptr_t at)
{
    if (!already_reported(reported_tag, &nreported_tag, at))
        event("RESIDUAL_TAG addr=%" PRIxPTR "\n", at);
}

/* Rule 2: the known ELF header anywhere in readable anonymous memory.
 * Rule 3: a known .text signature in anonymous executable memory (residual). */
static void region_scan(int exec_only, const void *needle, size_t length, struct scan_cursor *cursor,
                        void (*report)(uintptr_t))
{
    size_t budget = SCAN_BUDGET;
    if (!length || !maps_snapshot()) return;
    while (budget && cursor->region < nregions) {
        const struct region *m = &regions[cursor->region];
        /* The ELF header can only live in a non-writable anonymous segment; the
         * text scan only needs anonymous executable mappings.  Skipping rw-p
         * anonymous memory (Dalvik heap) keeps a sweep short enough to finish
         * while the payload is resident. */
        int match = !m->inode && m->perms[0] == 'r' && m->perms[1] == '-' &&
                    (!exec_only || m->perms[2] == 'x');
        uintptr_t start = m->begin + cursor->offset;
        if (match && start < m->end && m->end - start >= length) {
            uintptr_t resume = start;
            uintptr_t at = scan_region(start, m->end, needle, length, &budget, &resume);
            if (at) report(at);
            if (!budget) {
                if (resume < m->end) {
                    cursor->offset = resume - m->begin;
                    return; /* continue from here on the next tick */
                }
                cursor->offset = 0;
                cursor->region++;
                break;
            }
        }
        cursor->offset = 0;
        cursor->region++;
    }
    if (cursor->region >= nregions) cursor->region = 0;
}

static void known_header_scan(void)
{
    region_scan(0, &expected_header, sizeof(expected_header), &header_cursor, report_header);
}

static void residual_text_scan(void)
{
    region_scan(1, text_signature, text_signature_size, &text_cursor, report_text);
}

/* Rule 4: the old fixed framework tag anywhere in anonymous executable memory. */
static void residual_tag_scan(void)
{
    region_scan(1, tag_signature, sizeof(tag_signature) - 1, &tag_cursor, report_tag);
}

/* ------------------------------------------------------------------ */
/* cheap informational syscall guard                                    */
/* ------------------------------------------------------------------ */

static const long guarded_syscalls[] = {
    __NR_getpid, __NR_gettid, __NR_getuid, __NR_geteuid, __NR_getgid, __NR_getegid,
    __NR_getppid, __NR_getpgid, __NR_sched_getscheduler, __NR_getpriority,
};

static long emulate_syscall(unsigned long nr)
{
    switch (nr) {
    case __NR_getpid: return app_pid;
    case __NR_gettid: return observer_tid;
    case __NR_getuid: return cached_uid;
    case __NR_geteuid: return cached_euid;
    case __NR_getgid: return cached_gid;
    case __NR_getegid: return cached_egid;
    case __NR_getppid: return app_ppid;
    case __NR_getpgid: return app_pid;
    case __NR_sched_getscheduler: return 0;
    case __NR_getpriority: return 20;
    default: return 0;
    }
}

static void syscall_trap(int signal_number, siginfo_t *info, void *context)
{
    int saved_errno = errno;
    ucontext_t *uc = context;
    if (signal_number != SIGSYS || info->si_code != SYS_SECCOMP || info->si_arch != AUDIT_ARCH_AARCH64)
        _exit(91);
    uintptr_t pc = (uintptr_t)uc->uc_mcontext.pc;
    unsigned long nr = (unsigned long)info->si_syscall;
    unsigned index = trap_count;
    unsigned kind;
    if (control_rx_begin && pc > control_rx_begin && pc < control_rx_end) {
        kind = 0;
        control_traps++;
    } else if (pc_is_known_code(pc)) {
        kind = 1;
        known_code_traps++;
    } else {
        kind = 2;
        unexpected_traps++;
    }
    if (index < MAX_TRAPS) {
        traps[index].nr = nr;
        traps[index].pc = pc;
        traps[index].kind = kind;
        trap_count = index + 1;
    }
    /* Return a plausible value and let the kernel advance past the svc. */
    uc->uc_mcontext.regs[0] = (uint64_t)emulate_syscall(nr);
    errno = saved_errno;
}

static int install_guard(void)
{
    stack_t stack = { .ss_sp = malloc(65536), .ss_size = 65536 };
    struct sigaction action;
    struct sock_filter code[8 + sizeof(guarded_syscalls) / sizeof(guarded_syscalls[0])];
    unsigned n = 0, i, count = (unsigned)(sizeof(guarded_syscalls) / sizeof(guarded_syscalls[0]));
    memset(&action, 0, sizeof(action));
    action.sa_sigaction = syscall_trap;
    action.sa_flags = SA_SIGINFO | SA_ONSTACK;
    sigemptyset(&action.sa_mask);
    if (!stack.ss_sp || sigaltstack(&stack, NULL) || sigaction(SIGSYS, &action, NULL)) return -1;
    /* Remember which executable mappings are ordinary file-backed code before
     * the filter is armed; the handler can then classify a trap without any
     * syscall or allocation. */
    int snapshot_ok = maps_snapshot();
    if (snapshot_ok) {
        for (unsigned r = 0; r < nregions && n_known_code < MAX_KNOWN_CODE; r++) {
            if (regions[r].inode && regions[r].perms[0] == 'r' && regions[r].perms[2] == 'x') {
                known_code[n_known_code].begin = regions[r].begin;
                known_code[n_known_code].end = regions[r].end;
                n_known_code++;
            }
        }
    }
    event("GUARD maps=%d regions=%u parse_errors=%u known_code=%u\n", snapshot_ok, nregions,
          maps_parse_errors, n_known_code);
#define GUARD_PUSH(c, a_jt, a_jf, kk)                 \
    do {                                    \
        code[n].code = (c);                 \
        code[n].jt = (a_jt);                  \
        code[n].jf = (a_jf);                  \
        code[n].k = (kk);                   \
        n++;                                \
    } while (0)
    GUARD_PUSH(BPF_LD | BPF_W | BPF_ABS, 0, 0, (uint32_t)offsetof(struct seccomp_data, arch));
    GUARD_PUSH(BPF_JMP | BPF_JEQ | BPF_K, 1, 0, AUDIT_ARCH_AARCH64);
    GUARD_PUSH(BPF_RET | BPF_K, 0, 0, SECCOMP_RET_KILL_THREAD);
    GUARD_PUSH(BPF_LD | BPF_W | BPF_ABS, 0, 0, (uint32_t)offsetof(struct seccomp_data, nr));
    for (i = 0; i < count; i++) {
        /* all matching jumps land on the final TRAP instruction */
        unsigned trap_index = 4 + count + 1;
        unsigned jt = trap_index - n - 1;
        GUARD_PUSH(BPF_JMP | BPF_JEQ | BPF_K, (uint8_t)jt, 0, (uint32_t)guarded_syscalls[i]);
    }
    GUARD_PUSH(BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ALLOW);
    GUARD_PUSH(BPF_RET | BPF_K, 0, 0, SECCOMP_RET_TRAP);
#undef GUARD_PUSH
    struct sock_fprog program = { (unsigned short)n, code };
    return prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) ||
           prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program);
}

static void log_traps(void)
{
    while (logged_traps < trap_count) {
        const char *kind = traps[logged_traps].kind == 0 ? "control"
                           : traps[logged_traps].kind == 1 ? "file" : "unexpected";
        event("SYS_TRAP nr=%lu pc=%" PRIxPTR " kind=%s\n", traps[logged_traps].nr,
              traps[logged_traps].pc, kind);
        logged_traps++;
    }
}

/* ------------------------------------------------------------------ */
/* reference and negative controls                                      */
/* ------------------------------------------------------------------ */

static int load_reference(void)
{
    char path[1024];
    snprintf(path, sizeof(path), "%s/libobspayload.so", library_path);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    struct stat st;
    if (fd < 0 || fstat(fd, &st) || st.st_size < (off_t)sizeof(expected_header) || st.st_size > MAX_PAYLOAD) {
        if (fd >= 0) close(fd);
        return 0;
    }
    reference_size = (size_t)st.st_size;
    reference = malloc(reference_size);
    size_t at = 0;
    while (reference && at < reference_size) {
        ssize_t n = read(fd, reference + at, reference_size - at);
        if (n <= 0) break;
        at += (size_t)n;
    }
    close(fd);
    if (!reference || at != reference_size) return 0;
    own_ranges[nown_ranges].begin = (uintptr_t)reference;
    own_ranges[nown_ranges].end = (uintptr_t)reference + reference_size;
    nown_ranges++;
    own_ranges[nown_ranges].begin = (uintptr_t)&expected_header;
    own_ranges[nown_ranges].end = (uintptr_t)&expected_header + sizeof(expected_header);
    nown_ranges++;
    memcpy(&expected_header, reference, sizeof(expected_header));
    if (memcmp(expected_header.e_ident, ELFMAG, SELFMAG) || expected_header.e_phnum > MAX_PHDR ||
        expected_header.e_phentsize != sizeof(Elf64_Phdr) ||
        expected_header.e_phoff > reference_size ||
        expected_header.e_phnum * sizeof(Elf64_Phdr) > reference_size - expected_header.e_phoff) return 0;
    memcpy(expected_phdr, reference + expected_header.e_phoff,
           expected_header.e_phnum * sizeof(Elf64_Phdr));
    for (unsigned i = 0; i < expected_header.e_phnum; i++) {
        const Elf64_Phdr *ph = &expected_phdr[i];
        if (ph->p_offset > reference_size || ph->p_filesz > reference_size - ph->p_offset) return 0;
        if ((ph->p_flags & PF_X) && ph->p_type == PT_LOAD && !text_signature_size) {
            text_signature_size = ph->p_filesz < sizeof(text_signature) ? (size_t)ph->p_filesz
                                                                       : sizeof(text_signature);
            if (text_signature_size < 16) text_signature_size = 0;
            else memcpy(text_signature, reference + ph->p_offset, text_signature_size);
        }
    }
    return 1;
}

static void describe_self(void)
{
    char line[512];
    event("IDENTITY pid=%d tid=%d uid=%d euid=%d dumpable=%d\n",
          app_pid, observer_tid, getuid(), geteuid(), prctl(PR_GET_DUMPABLE));
    FILE *fp = fopen("/proc/thread-self/status", "re");
    if (fp) {
        while (fgets(line, sizeof(line), fp))
            if (!strncmp(line, "CapEff:", 7) || !strncmp(line, "Seccomp:", 8) ||
                !strncmp(line, "NoNewPrivs:", 11)) event("%s", line);
        fclose(fp);
    }
    fp = fopen("/proc/self/attr/current", "re");
    if (fp) {
        if (fgets(line, sizeof(line), fp)) event("SELINUX %s\n", line);
        fclose(fp);
    }
    int fd = open("/proc/self/mem", O_RDONLY | O_CLOEXEC);
    int error = fd < 0 ? errno : 0;
    if (fd >= 0) close(fd);
    event("SELF_MEM readable=%d errno=%d\n", fd >= 0, error);
}

static int negative_controls(int guarded)
{
    unsigned char *rx = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    unsigned char *data = mmap(NULL, reference_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (rx == MAP_FAILED || data == MAP_FAILED) return 0;
    memcpy(data, reference, reference_size); /* exact ELF bytes, but only data */
    unsigned before_control = control_traps, before_known = known_code_traps;
    unsigned before_unexpected = unexpected_traps;
    /* getpid; ret */
    const uint32_t svc[] = { 0xd2801588, 0xd4000001, 0xd65f03c0 };
    memcpy(rx, svc, sizeof(svc));
    __builtin___clear_cache((char *)rx, (char *)rx + page_size);
    if (mprotect(rx, page_size, PROT_READ | PROT_EXEC)) return 0;
    long (*anonymous_getpid)(void) = (void *)rx;
    control_rx_begin = (uintptr_t)rx;
    control_rx_end = (uintptr_t)rx + page_size;
    for (int i = 0; i < 100; i++)
        if (getpid() != app_pid || anonymous_getpid() != app_pid) return 0;
    control_rx_begin = control_rx_end = 0;
    unsigned control = control_traps - before_control;
    unsigned known = known_code_traps - before_known;
    unsigned unexpected = unexpected_traps - before_unexpected;
    /* Without the guard the local getpid calls must not trap at all.  With it,
     * the 100 stub calls must be classified as anonymous control traps and the
     * 100 libc calls as file-backed code; nothing may look like generated code. */
    if (guarded && control != 100) return 0;
    if (!guarded && (control || known || unexpected)) return 0;
    if (unexpected) return 0;
    if (legacy_known_manual()) return 0;
    event("NEGATIVE normal_getpid=100 anonymous_getpid=100 elf_data=1 anonymous_rx=1 guard=%d "
          "control_traps=%u file_traps=%u unexpected=%u\n", guarded, control, known, unexpected);
    if (munmap(rx, page_size) || munmap(data, reference_size)) return 0;
    return 1;
}

static void *observe(void *unused)
{
    (void)unused;
    pthread_setname_np(pthread_self(), "kclf-observe");
    observer_tid = gettid();
    page_size = (size_t)sysconf(_SC_PAGESIZE);
    unsigned char copy[16];
    if (!load_reference() || !read_self((uintptr_t)reference, copy, sizeof(copy)) ||
        memcmp(copy, reference, sizeof(copy))) {
        event("ERROR self_read_or_reference errno=%d\n", errno);
        return NULL;
    }
    cached_uid = getuid();
    cached_euid = geteuid();
    cached_gid = getgid();
    cached_egid = getegid();
    int guarded = !strcmp(mode_name, "guard");
    if (guarded && install_guard()) {
        event("ERROR install_guard errno=%d\n", errno);
        return NULL;
    }
    describe_self();
    if (!negative_controls(guarded)) { event("ERROR negative_controls\n"); return NULL; }
    if (!strcmp(mode_name, "normal")) {
        char path[1024];
        snprintf(path, sizeof(path), "%s/libobspayload.so", library_path);
        void *handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
        if (!handle || legacy_known_manual()) { event("ERROR normal_dlopen\n"); return NULL; }
        event("NEGATIVE normal_dlopen=1 positives=0\n");
    }
    event("READY pid=%d tid=%d mode=%s library=%s signature=%zu\n", app_pid, observer_tid,
          mode_name, library_path, text_signature_size);
    for (;;) {
        uintptr_t image;
        log_traps();
        image = legacy_known_manual();
        if (image && image != reported_manual)
            event("KNOWN_MANUAL base=%" PRIxPTR " exact_readonly_loads=1 anonymous_loads=1 registered=0\n", image);
        if (!image && reported_manual) event("KNOWN_GONE\n");
        reported_manual = image;
        known_header_scan();
        residual_text_scan();
        residual_tag_scan();
        usleep(100000);
    }
    return NULL;
}

JNIEXPORT void JNICALL Java_com_kclf_obsprobe_MainActivity_start(
    JNIEnv *env, jclass cls, jstring files, jstring libraries, jstring mode)
{
    (void)cls;
    const char *f = (*env)->GetStringUTFChars(env, files, NULL);
    const char *l = (*env)->GetStringUTFChars(env, libraries, NULL);
    const char *m = (*env)->GetStringUTFChars(env, mode, NULL);
    snprintf(files_path, sizeof(files_path), "%s", f);
    snprintf(library_path, sizeof(library_path), "%s", l);
    snprintf(mode_name, sizeof(mode_name), "%s", m);
    (*env)->ReleaseStringUTFChars(env, files, f);
    (*env)->ReleaseStringUTFChars(env, libraries, l);
    (*env)->ReleaseStringUTFChars(env, mode, m);
    char path[1024];
    snprintf(path, sizeof(path), "%s/events.txt", files_path);
    events_fd = open(path, O_CREAT | O_WRONLY | O_TRUNC | O_CLOEXEC, 0600);
    app_pid = getpid();
    app_ppid = getppid();
    pthread_t thread;
    if (events_fd < 0 || pthread_create(&thread, NULL, observe, NULL)) return;
    pthread_detach(thread);
}
