/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Manual backend. Never calls bionic's dlopen/dlsym/dlclose, or edits soinfo.
 * The caller must keep all preloaded dependency providers resident throughout
 * the payload lifetime. This is an explicit, isolated dependency scope, not a
 * reconstruction of bionic namespace/global interposition state. */
#include "kclf_internal.h"
#include "kclf_elf.h"
#include <kputils.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <syscall.h>
#include <uapi/asm-generic/unistd.h>
#include <uapi/asm-generic/errno.h>

#define KM_IMAGES 32
#define KM_PROVIDERS 512
#define KM_SCOPE 128
#define KM_CALLS 128
#define KM_IFUNCS 64
#define KM_FILE_MAX (64UL * 1024 * 1024)
#define KM_FREE 0
#define KM_BUSY 1
#define KM_LIVE 2
#define KM_ABANDONED 3
#define KM_NEW 1
#define KM_GET 2
#define KM_PUT 3
#define KM_DROP 4

struct kclf_manual_image {
    int state;
    u32 refs, nfini;
    u64 id, mm, map, length, bias;
    struct pid *owner; /* process (TGID), not the borrowed execution thread */
    char path[KCLF_PATH_MAX];
    u64 fini[KM_CALLS];
    int nodelete;
    int hdr_kept; /* the creating injection kept the in-memory ELF headers */
    pid_t original_tid;
    u64 linker_base, linker_end;
};

struct km_provider {
    struct ke_object object;
    char name[KE_NAME]; /* DT_SONAME */
    char path[KCLF_PATH_MAX]; /* maps pathname: namespace/load-origin evidence */
};
struct km_context {
    struct kclf_req *r;
    struct ke_io io;
    struct ke_object object, candidate;
    struct km_provider providers[KM_PROVIDERS];
    unsigned nproviders, nscope, scope[KM_SCOPE];
    void *snapshot;
    unsigned long file_size;
    u64 *values;
    u8 *resolved;
    u64 fixups[KM_IFUNCS][3];
    u64 protections[KE_PHNUM][2];
};

static struct kclf_manual_image images[KM_IMAGES];
static int registry_lock;
static u64 next_image = 1;

/* Non-sleeping metadata transactions. Never hold this lock across GUP, VFS,
 * mmap, callbacks or user code. A contending controller simply retries. */
static int lock_registry(void)
{
    return !__atomic_exchange_n(&registry_lock, 1, __ATOMIC_ACQUIRE);
}
static void unlock_registry(void) { __atomic_store_n(&registry_lock, 0, __ATOMIC_RELEASE); }

static void *allocate(unsigned long size)
{
    void *p = kclf_ks.vmalloc(size);
    if (p) memset(p, 0, size);
    return p;
}
static int user_read(void *ctx, u64 at, void *p, unsigned long n)
{
    (void)ctx;
    return n > 0x7fffffffUL ? -E2BIG : kclf_urds(at, p, (int)n);
}
static int user_write(void *ctx, u64 at, const void *p, unsigned long n)
{
    (void)ctx;
    return n > 0x7fffffffUL ? -E2BIG : kclf_uwr(at, p, (int)n);
}
static int file_read(void *context, u64 at, void *p, unsigned long n)
{
    struct km_context *c = context;
    if (at > c->file_size || n > c->file_size - at) return -ENOEXEC;
    memcpy(p, (u8 *)c->snapshot + at, n);
    return 0;
}
static void report(void *context, const char *why, const char *detail)
{
    struct km_context *c = context;
    /* Preserve the first, more specific error (e.g. an unresolved symbol). */
    if (!c->r->err[0]) kclf_set_err(c->r, "manual: %s%s%s", why, *detail ? ": " : "", detail);
}

static int own_mapping(u64 mm, u64 address)
{
    int i, found = 0;
    if (!lock_registry()) return -EBUSY;
    for (i = 0; i < KM_IMAGES; i++) {
        const struct kclf_manual_image *m = &images[i];
        if (m->state && m->mm == mm && address >= m->map && address - m->map < m->length) { found = 1; break; }
    }
    unlock_registry();
    return found;
}

static int collect(u64 address, const char *path, void *context)
{
    struct km_context *c = context;
    struct ke_io quiet = c->io;
    struct ke_object *o = &c->candidate;
    struct km_provider *provider;
    u32 magic;
    unsigned i;
    char name[KE_NAME];
    int own;
    quiet.error = 0;
    if (kclf_urds(address, &magic, 4) || magic != 0x464c457fU) return 0;
    own = own_mapping(c->r->mm, address);
    if (own < 0) return own;
    if (own) return 0; /* manual modules are not implicitly dependency providers */
    if (ke_open(&quiet, address, o, 0) || !o->soname || ke_string(&quiet, o, o->soname, name)) return 0;
    for (i = 0; i < c->nproviders; i++) if (c->providers[i].object.bias == o->bias) return 0;
    if (c->nproviders == KM_PROVIDERS) { report(c, "provider scan limit exceeded", ""); return -E2BIG; }
    provider = &c->providers[c->nproviders];
    memset(provider, 0, sizeof(*provider));
    memcpy(&provider->object, o, sizeof(*o));
    memcpy(provider->name, name, strlen(name) + 1);
    if (path && *path) {
        strncpy(provider->path, path, sizeof(provider->path) - 1);
        provider->path[sizeof(provider->path) - 1] = 0;
    }
    c->nproviders++;
    if (!strcmp(name, "ld-android.so")) {
        c->r->ld.linker_base = o->bias + o->low;
        c->r->ld.linker_end = o->bias + o->high;
    }
    return 0;
}

/* Loaded providers are chosen with the same origin-first idea bionic uses for
 * a namespace's local group. A plain global SONAME table cannot distinguish
 * e.g. the four libc++.so copies that Android 12 keeps for different APEX
 * namespaces; the mapping pathname identifies the load origin. */
static int same_dir(const char *a, const char *b)
{
    const char *as = 0, *bs = 0, *p;
    if (!a || !b || !*a || !*b) return 0;
    for (p = a; *p; p++) if (*p == '/') as = p;
    for (p = b; *p; p++) if (*p == '/') bs = p;
    if (!as || !bs || as - a != bs - b) return 0;
    return !memcmp(a, b, (size_t)(as - a));
}

static int same_apex(const char *a, const char *b)
{
    const char *ae, *be;
    if (!a || !b || strncmp(a, "/apex/", 6) || strncmp(b, "/apex/", 6)) return 0;
    a += 6; b += 6;
    for (ae = a; *ae && *ae != '/'; ae++);
    for (be = b; *be && *be != '/'; be++);
    return ae - a == be - b && !memcmp(a, b, (size_t)(ae - a));
}

static int same_partition(const char *a, const char *b)
{
    const char *ae, *be;
    if (!a || !b || *a != '/' || *b != '/') return 0;
    /* APEX modules are separate namespaces even though they share /apex.
     * /data is a filesystem root, not a shared load origin: /data/local/tmp
     * must not be treated as related to an app's private library directory. */
    if (!strncmp(a, "/apex/", 6) || !strncmp(b, "/apex/", 6)) return 0;
    if (!strncmp(a, "/data/", 6) || !strncmp(b, "/data/", 6)) return 0;
    for (ae = a + 1; *ae && *ae != '/'; ae++);
    for (be = b + 1; *be && *be != '/'; be++);
    return ae - a == be - b && !memcmp(a, b, (size_t)(ae - a));
}

static unsigned common_prefix(const char *a, const char *b)
{
    unsigned n = 0;
    while (a[n] && a[n] == b[n] && n < 4095) n++;
    return n;
}

static int vendor_origin(const char *path)
{
    return !strncmp(path, "/vendor/", 8) || !strncmp(path, "/odm/", 5);
}

/* Higher score means a closer load origin. The bands leave room for the
 * common-prefix tie-breaker inside each class. */
static int provider_score(const char *importer, const struct km_provider *p)
{
    if (!importer || !*importer || !p->path[0]) return 0;
    if (!strcmp(importer, p->path)) return 1000000;
    if (same_dir(importer, p->path)) return 800000;
    if (same_apex(importer, p->path)) return 600000;
    if (same_partition(importer, p->path)) return 400000;
    /* Vendor/ODM namespaces normally link against the VNDK APEX, not the
     * platform's /system copy of the same SONAME. */
    if (vendor_origin(importer) && !strncmp(p->path, "/apex/com.android.vndk.", 23)) return 300000;
    if (!strncmp(p->path, "/system/", 8) || !strncmp(p->path, "/system_ext/", 12) ||
        !strncmp(p->path, "/product/", 9)) return 200000;
    if (!strncmp(p->path, "/apex/com.android.runtime/", 26)) return 150000;
    return (int)common_prefix(importer, p->path);
}

static int in_scope(const struct km_context *c, unsigned index)
{
    unsigned i;
    for (i = 0; i < c->nscope; i++) if (c->scope[i] == index) return 1;
    return 0;
}

static int select_provider(struct km_context *c, const char *importer, const char *name)
{
    int best = -1, best_score = -1, distinct = 0;
    const char *best_path = 0;
    unsigned j;
    for (j = 0; j < c->nproviders; j++) {
        const struct km_provider *p = &c->providers[j];
        int score;
        if (strcmp(p->name, name)) continue;
        if (!p->path[0]) {
            /* No mapping pathname (direct-VMA fallback). A single candidate
             * is still unambiguous; multiple ones cannot be distinguished. */
            if (best < 0) {
                best = (int)j;
                best_score = 0;
                best_path = p->path;
                distinct = 0;
            } else if (best_score <= 0) {
                distinct = 1;
            }
            continue;
        }
        score = provider_score(importer, p);
        if (score > best_score) {
            best = (int)j;
            best_score = score;
            best_path = p->path;
            distinct = 0;
        } else if (score == best_score) {
            if (strcmp(best_path, p->path)) distinct = 1;
            else if (!in_scope(c, (unsigned)best) && in_scope(c, j)) best = (int)j;
        }
    }
    if (best < 0) {
        report(c, "DT_NEEDED is not already loaded", name);
        return -ENOENT;
    }
    if (distinct) {
        report(c, "ambiguous loaded SONAME (no namespace match)", name);
        return -EEXIST;
    }
    return best;
}

static int add_needed(struct km_context *c, const struct ke_object *o, const char *importer)
{
    unsigned i, j;
    for (i = 0; i < o->nneeded; i++) {
        char name[KE_NAME];
        int found;
        if (ke_string(&c->io, o, o->needed[i], name)) return -ENOEXEC;
        if (!name[0]) return -ENOEXEC;
        found = select_provider(c, importer, name);
        if (found < 0) return found;
        for (j = 0; j < c->nscope; j++) if (c->scope[j] == (unsigned)found) break;
        if (j < c->nscope) continue;
        if (c->nscope == KM_SCOPE) return -E2BIG;
        c->scope[c->nscope++] = (unsigned)found;
    }
    return 0;
}

static int resolve_import(void *context, u32 index, u64 *value)
{
    struct km_context *c = context;
    struct ke_object *o = &c->object;
    struct ke_sym s;
    char name[KE_NAME], version[KE_NAME];
    u32 hash;
    unsigned i, type;
    int rc;
    if (index >= o->symcount) return -ENOEXEC;
    if (c->resolved[index]) { *value = c->values[index]; return c->resolved[index] == 2 ? 1 : 0; }
    if (ke_symbol(&c->io, o, index, &s) || ke_string(&c->io, o, s.name, name)) return -ENOEXEC;
    type = s.info & 15;
    if ((s.info >> 4) == 10 || (type != 0 && type != 1 && type != 2 && type != 10)) {
        report(c, "payload GNU_UNIQUE/TLS/IFUNC symbol unsupported", name);
        return -EOPNOTSUPP;
    }
    /* These registrations need loader-owned metadata for safe lifetime/CFI.
     * Ordinary malloc/pthread/libc calls are allowed and resolved normally. */
    if (!strcmp(name, "__cxa_thread_atexit_impl") || !strcmp(name, "__cxa_thread_atexit") ||
        !strcmp(name, "__emutls_get_address") ||
        !strcmp(name, "__cfi_slowpath") || !strcmp(name, "__cfi_slowpath_diag")) {
        report(c, "loader-integrated TLS destructor/cross-DSO CFI unsupported", name);
        return -EOPNOTSUPP;
    }
    if (s.shndx) {
        if (type == 10) { report(c, "payload-defined IFUNC/IRELATIVE unsupported", name); return -EOPNOTSUPP; }
        if (s.shndx == 0xfff1) *value = s.value;
        else {
            if (s.shndx >= 0xff00 || s.value >= c->io.limit - o->bias) return -ENOEXEC;
            *value = o->bias + s.value;
            if (!ke_contains(o, *value, s.size ? s.size : 1, type == 2 ? 1 : 0)) return -ENOEXEC;
        }
    } else {
        if ((s.info >> 4) != 1 && (s.info >> 4) != 2) return -ENOEXEC;
        if (s.other & 3) {
            report(c, "non-default visibility on undefined symbol", name);
            return -ENOEXEC;
        }
        if (ke_required_version(&c->io, o, index, version, &hash)) return -ENOEXEC;
        for (i = 0; i < c->nscope; i++) {
            struct ke_sym provider_symbol;
            rc = ke_lookup(&c->io, &c->providers[c->scope[i]].object, name, version, hash, &provider_symbol, value);
            if (rc < 0) return rc;
            if (rc) {
                if ((provider_symbol.info & 15) == 10) {
                    c->values[index] = *value;
                    c->resolved[index] = 2;
                    return 1; /* run the already-loaded provider's resolver in EL0 */
                }
                break;
            }
        }
        if (i == c->nscope) {
            if ((s.info >> 4) != 2) { report(c, "unresolved import/version", name); return -ENOENT; }
            *value = 0; /* ELF undefined weak symbol */
        }
    }
    c->values[index] = *value;
    c->resolved[index] = 1;
    return 0;
}

static int defer_ifunc(void *context, u64 where, u32 index, s64 addend)
{
    struct km_context *c = context;
    struct ke_object *o = &c->object;
    unsigned n = c->r->ifunc_count;
    /* Call vectors are validated/snapshotted before entering EL0. A deferred
     * write here would otherwise silently omit (or retain a stale) callback. */
    if ((where >= o->init_array && where - o->init_array < o->init_count * 8) ||
        (where >= o->fini_array && where - o->fini_array < o->fini_count * 8)) {
        report(c, "IFUNC initializer/finalizer pointer unsupported", "");
        return -EOPNOTSUPP;
    }
    if (n == KM_IFUNCS) { report(c, "too many IFUNC fixups", ""); return -E2BIG; }
    c->fixups[n][0] = c->values[index];
    c->fixups[n][1] = where;
    c->fixups[n][2] = (u64)addend;
    c->r->ifunc_count++;
    return 0;
}

static int read_hwcap(struct km_context *c)
{
    struct file *f;
    loff_t pos = 0;
    unsigned i;
    int ended = 0, got_hwcap = 0, rc = 0;
    /* AT_HWCAP is a CPU/kernel property, identical for every AArch64 process.
     * Prefer the kernel accessors: Android marks app processes non-dumpable,
     * which makes even /proc/thread-self/auxv root-owned and unreadable with
     * the target's own credentials. */
    if (kclf_ks.cpu_get_elf_hwcap) {
        c->r->hwcap = kclf_ks.cpu_get_elf_hwcap();
        c->r->hwcap2 = kclf_ks.cpu_get_elf_hwcap2 ? kclf_ks.cpu_get_elf_hwcap2() : 0;
        return 0;
    }
    f = kclf_ks.filp_open("/proc/thread-self/auxv", 0, 0);
    if (!f) { report(c, "cannot open target auxv", ""); return -ENOENT; }
    if ((unsigned long)f >= (unsigned long)-4095) {
        rc = (int)(long)f;
        report(c, "cannot open target auxv (credentials/non-dumpable)", "");
        return rc;
    }
    for (i = 0; i < 128; i++) {
        u64 pair[2];
        /* The real target buffer also works with legacy procfs ->read. */
        long n = kclf_ks.vfs_read(f, (char *)c->r->param_addr, 16, &pos);
        if (n != 16 || kclf_urds(c->r->param_addr, pair, 16)) { rc = -EIO; break; }
        if (!pair[0]) { ended = 1; break; }
        if (pair[0] == 16) { c->r->hwcap = pair[1]; got_hwcap = 1; }
        if (pair[0] == 26) c->r->hwcap2 = pair[1];
    }
    kclf_ks.fput(f);
    if (!ended || !got_hwcap) rc = -ENOEXEC;
    if (rc) report(c, "cannot read target AT_HWCAP/AT_HWCAP2", "");
    return rc;
}

static int read_snapshot(struct km_context *c)
{
    struct file *f = kclf_ks.filp_open(c->r->path, 0, 0);
    loff_t size, pos = 0;
    int rc = 0;
    if (!f || (unsigned long)f >= (unsigned long)-4095) {
        rc = f ? (int)(long)f : -ENOENT;
        kclf_set_err(c->r, "manual: open library failed rc=%d", rc);
        return rc;
    }
    size = kclf_ks.vfs_llseek(f, 0, 2);
    if (size < (loff_t)sizeof(struct ke_ehdr) || size > (loff_t)KM_FILE_MAX) { rc = -ENOEXEC; goto out; }
    c->file_size = (unsigned long)size;
    c->snapshot = allocate(c->file_size);
    if (!c->snapshot) { rc = -ENOMEM; goto out; }
    while (pos < size) {
        unsigned long n = size - pos;
        long got;
        if (n > 65536) n = 65536;
        got = kclf_ks.kernel_read(f, (u8 *)c->snapshot + pos, n, &pos);
        if (got <= 0 || (unsigned long)got > n) { rc = got < 0 ? (int)got : -ENOEXEC; break; }
    }
out:
    kclf_ks.fput(f);
    if (rc) kclf_set_err(c->r, "manual: file snapshot failed rc=%d (limit 64 MiB)", rc);
    return rc;
}

static int map_image(struct km_context *c)
{
    struct ke_object *o = &c->object;
    struct kclf_manual_image *m = c->r->image;
    struct ke_io fileio = c->io;
    u64 base, length, bias, header = 0, pad;
    unsigned i;
    int rc;
    fileio.read = file_read;
    if ((rc = ke_headers(&fileio, 0, o)) || (rc = ke_file_layout(&fileio, o, c->file_size, kclf_page_size))) return rc;
    /* A random pad in front of the image keeps the ELF header away from every
     * VMA boundary: the pad is given the first segment's protection later, so
     * it merges into one mapping and a scanner that anchors on mapping starts
     * never reads the header. */
    pad = (u64)(1 + (int)(get_random_u64() % 8)) * (u64)kclf_page_size;
    length = o->high - o->low + o->alignment + pad;
    base = kclf_ks.vm_mmap(0, 0, length, 3, 0x22, 0);
    if (!base || base >= (u64)-4095) return base ? (int)(long)base : -ENOMEM;
    /* Record ownership before any fallible write, so rollback cannot leak it. */
    m->map = base; m->length = length;
    if (base < o->low || base >= kclf_user_limit || length > kclf_user_limit - base) return -EFAULT;
    bias = (base + pad - o->low + o->alignment - 1) & ~(o->alignment - 1);
    m->bias = bias;
    for (i = 0; i < o->phnum; i++) {
        const struct ke_phdr *p = &o->ph[i];
        u64 copied = 0;
        if (p->type != 1 || !p->memsz) continue;
        if (!p->offset) header = bias + p->vaddr;
        while (copied < p->filesz) {
            u64 n = p->filesz - copied;
            if (n > 16384) n = 16384;
            if (kclf_uwr(bias + p->vaddr + copied, (u8 *)c->snapshot + p->offset + copied, (int)n)) return -EFAULT;
            copied += n;
        }
        /* Anonymous memory is zero-filled, including partial-page BSS. */
    }
    return ke_open(&c->io, header, o, 1);
}

static int append_call(struct km_context *c, u64 address, u64 *vector, u32 *count)
{
    if (!address || address == ~0ULL) return 0;
    if (*count == KM_CALLS || (address & 3) || !ke_contains(&c->object, address, 4, 1)) {
        report(c, "invalid/non-local initializer or too many initializers", "");
        return -ENOEXEC;
    }
    vector[(*count)++] = address;
    return 0;
}

static int prepare_calls(struct km_context *c)
{
    struct kclf_req *r = c->r;
    struct kclf_manual_image *m = r->image;
    struct ke_object *o = &c->object;
    u64 init[KM_CALLS];
    u64 i, fn;
    int rc;
    if ((rc = append_call(c, o->init, init, &r->init_count))) return rc;
    for (i = 0; i < o->init_count; i++) {
        if (kclf_urds(o->init_array + i * 8, &fn, 8) || (rc = append_call(c, fn, init, &r->init_count))) return -ENOEXEC;
    }
    for (i = o->fini_count; i; i--) {
        if (kclf_urds(o->fini_array + (i - 1) * 8, &fn, 8) || (rc = append_call(c, fn, m->fini, &m->nfini))) return -ENOEXEC;
    }
    if ((rc = append_call(c, o->fini, m->fini, &m->nfini))) return rc;
    if (r->flags & KCLF_F_UNLOAD) r->fini_count = m->nfini;
    if (KCLF_P_SIZE + (r->init_count + r->fini_count) * 8 > (u32)kclf_page_size) return -E2BIG;
    if (r->init_count && kclf_uwr(r->param_addr + KCLF_P_SIZE, init, r->init_count * 8)) return -EFAULT;
    if (r->fini_count && kclf_uwr(r->param_addr + KCLF_P_SIZE + r->init_count * 8, m->fini, r->fini_count * 8)) return -EFAULT;
    return 0;
}

static int protect_image(struct km_context *c)
{
    struct ke_object *o = &c->object;
    struct kclf_manual_image *m = c->r->image;
    u64 page = kclf_page_size;
    unsigned i;
    long rc = raw_syscall3(__NR_mprotect, m->map, m->length, 0);
    if (rc) return (int)rc;
    for (i = 0; i < o->phnum; i++) {
        const struct ke_phdr *p = &o->ph[i];
        u64 first, end;
        unsigned prot;
        if (p->type != 1 || !p->memsz) continue;
        first = (o->bias + p->vaddr) & ~(page - 1);
        end = (o->bias + p->vaddr + p->memsz + page - 1) & ~(page - 1);
        prot = ((p->flags & 4) ? 1 : 0) | (p->flags & 2) | ((p->flags & 1) ? 4 : 0);
        rc = raw_syscall3(__NR_mprotect, first, end - first, prot);
        if (rc) return (int)rc;
    }
    for (i = 0; i < o->phnum; i++) {
        const struct ke_phdr *p = &o->ph[i];
        u64 first, end;
        if (p->type != 0x6474e552U || !p->memsz) continue;
        if (!ke_contains(o, o->bias + p->vaddr, p->memsz, 2)) return -ENOEXEC;
        first = (o->bias + p->vaddr) & ~(page - 1);
        end = (o->bias + p->vaddr + p->memsz + page - 1) & ~(page - 1);
        if (c->r->ifunc_count) {
            unsigned n = c->r->protect_count++;
            c->protections[n][0] = first;
            c->protections[n][1] = end - first;
        } else {
            rc = raw_syscall3(__NR_mprotect, first, end - first, 1);
            if (rc) return (int)rc;
        }
    }
    /*
     * The randomized pad in front of the image takes the first load segment's
     * protection.  vm_area merging then makes the header page the middle of a
     * mapping instead of its start, so a detector that anchors a candidate on
     * /proc/self/maps region boundaries never sees an ELF header there.
     */
    {
        u64 img = (o->bias + o->low) & ~(page - 1);
        unsigned prot = 0;
        int have = 0;
        for (i = 0; i < o->phnum; i++) {
            const struct ke_phdr *p = &o->ph[i];
            if (p->type != 1 || !p->memsz) continue;
            if (o->low >= p->vaddr && o->low - p->vaddr < p->memsz) {
                prot = ((p->flags & 4) ? 1 : 0) | (p->flags & 2) | ((p->flags & 1) ? 4 : 0);
                have = 1;
                break;
            }
        }
        if (have && img > m->map) {
            rc = raw_syscall3(__NR_mprotect, m->map, img - m->map, prot);
            if (rc) return (int)rc;
        }
    }
    return 0;
}

/*
 * The manual loader has already consumed the ELF and program headers, and this
 * backend rejects payload TLS/IFUNC/exceptions and never registers the image
 * with the linker, so nothing re-reads them at runtime.  A byte-identical ELF
 * header left in target memory is exactly what a known-payload detector anchors
 * on, so drop it.  "keepelf" keeps the legacy layout for payloads that inspect
 * their own __ehdr_start.
 */
static int scrub_headers(struct km_context *c)
{
    struct ke_object *o = &c->object;
    struct ke_ehdr eh;
    u8 zeros[sizeof(struct ke_ehdr) + KE_PHNUM * sizeof(struct ke_phdr)];
    u64 total = sizeof(eh);

    if (kclf_urds(o->header, &eh, sizeof(eh))) return -EFAULT;
    if (eh.phoff >= sizeof(eh) && eh.phnum && eh.phnum <= KE_PHNUM && eh.phentsize == sizeof(struct ke_phdr)) {
        u64 end = eh.phoff + (u64)eh.phnum * sizeof(struct ke_phdr);
        if (end <= (u64)kclf_page_size && end <= (u64)sizeof(zeros)) total = end;
    }
    memset(zeros, 0, sizeof(zeros));
    return kclf_uwr(o->header, zeros, (int)total);
}

static int reserve_image(struct kclf_req *r)
{
    struct kclf_manual_image *m = 0, *free_slot = 0;
    struct pid *owner;
    int i, rc = 0;
    /* PIDTYPE_TGID=1 is the supported kernel ABI. get_task_pid takes a ref. */
    owner = kclf_ks.get_task_pid(current, 1);
    if (!owner) return -ESRCH;
    if (!lock_registry()) { kclf_ks.put_pid(owner); return -EBUSY; }
    for (i = 0; i < KM_IMAGES; i++) {
        struct kclf_manual_image *q = &images[i];
        if (!q->state) { if (!free_slot) free_slot = q; continue; }
        if (q->mm != r->mm || q->owner != owner) continue;
        if (q->state == KM_BUSY) { rc = -EBUSY; goto out; }
        if ((r->flags & KCLF_F_RELEASE) ? q->id == r->image_id : !strcmp(q->path, r->path)) m = q;
    }
    if (m) {
        if (m->state != KM_LIVE) { rc = -EOWNERDEAD; goto out; }
        if (r->flags & KCLF_F_RELEASE) {
            if (m->nodelete) { rc = -EOPNOTSUPP; goto out; }
            r->image_action = m->refs > 1 ? KM_PUT : KM_DROP;
        } else {
            if (!(r->flags & KCLF_F_UNLOAD) && m->refs == 0xffffffffU) { rc = -EOVERFLOW; goto out; }
            r->image_action = KM_GET;
        }
    } else {
        if (r->flags & KCLF_F_RELEASE) { rc = -ENOENT; goto out; }
        if (!free_slot) { rc = -ENOSPC; goto out; }
        m = free_slot;
        memset(m, 0, sizeof(*m));
        m->id = next_image++;
        m->mm = r->mm;
        m->original_tid = r->pid;
        m->owner = owner;
        m->hdr_kept = !!(r->flags & KCLF_F_KEEPELF);
        owner = 0;
        strncpy(m->path, r->path, sizeof(m->path) - 1);
        r->image_action = KM_NEW;
    }
    m->state = KM_BUSY;
    r->image = m;
    r->image_id = m->id;
    r->image_hdr_kept = (u32)m->hdr_kept;
out:
    unlock_registry();
    if (owner) kclf_ks.put_pid(owner);
    if (rc) kclf_set_err(r, "manual: image transaction rejected rc=%d (busy/unknown/abandoned/nodelete)", rc);
    return rc;
}

long kclf_manual_prepare(struct kclf_req *r)
{
    struct km_context *c = 0;
    const char *step = "initialization";
    int rc;
    unsigned i;
    if (!kclf_ks.vmalloc || !kclf_ks.vfree || !kclf_ks.vfs_llseek || !kclf_ks.get_task_pid) {
        kclf_set_err(r, "manual: kernel vmalloc/vfree/vfs_llseek/get_task_pid unavailable");
        return -EOPNOTSUPP;
    }
    if ((rc = reserve_image(r))) return rc;
    r->ld.sym = "manual";
    r->ld.close_sym = "manual";
    if (r->image_action != KM_NEW) {
        r->ld.linker_base = r->image->linker_base;
        r->ld.linker_end = r->image->linker_end;
        if (r->image_action == KM_DROP) {
            r->fini_count = r->image->nfini;
            if (r->fini_count && kclf_uwr(r->param_addr + KCLF_P_SIZE, r->image->fini, r->fini_count * 8)) return -EFAULT;
        }
        return 0;
    }
    c = allocate(sizeof(*c));
    if (!c) {
        kclf_set_err(r, "manual: allocation of preparation context failed");
        return -ENOMEM;
    }
    c->r = r;
    c->io = (struct ke_io){c, kclf_user_limit, user_read, user_write, report, defer_ifunc};
    if ((rc = read_snapshot(c))) { step = "file snapshot"; goto out; }
    if ((rc = map_image(c))) { step = "ELF mapping"; goto out; }
    if (!(r->flags & KCLF_F_KEEPELF)) {
        if ((rc = scrub_headers(c))) { step = "ELF header scrub"; goto out; }
    }
    r->image->nodelete = !!(c->object.flags1 & 8);
    if (r->image->nodelete && (r->flags & KCLF_F_UNLOAD)) {
        report(c, "DT_FLAGS_1 NODELETE conflicts with unload", ""); rc = -EOPNOTSUPP; step = "NODELETE policy"; goto out;
    }
    if ((rc = kclf_walk_vmas(r->param_addr, collect, c))) { step = "target mapping scan"; goto out; }
    r->image->linker_base = r->ld.linker_base;
    r->image->linker_end = r->ld.linker_end;
    if ((rc = add_needed(c, &c->object, r->path))) { step = "payload dependency lookup"; goto out; }
    /* Breadth-first DT_NEEDED closure, with stable order and cycle detection.
     * Each edge is resolved using the importing library's load origin. */
    for (i = 0; i < c->nscope; i++) {
        const struct km_provider *p = &c->providers[c->scope[i]];
        if ((rc = add_needed(c, &p->object, p->path))) { step = "transitive dependency lookup"; goto out; }
    }
    c->values = allocate((unsigned long)c->object.symcount * sizeof(u64));
    c->resolved = allocate(c->object.symcount);
    if (!c->values || !c->resolved) { rc = -ENOMEM; step = "relocation table allocation"; goto out; }
    if ((rc = ke_relocate(&c->io, &c->object, resolve_import, c))) { step = "symbol resolution/relocation"; goto out; }
    if (r->ifunc_count && (rc = read_hwcap(c))) { step = "IFUNC HWCAP read"; goto out; }
    if ((rc = prepare_calls(c))) { step = "initializer/finalizer validation"; goto out; }
    if ((rc = protect_image(c))) { step = "segment protection/RELRO"; goto out; }
    {
        u64 offset = KCLF_P_SIZE + (r->init_count + r->fini_count) * 8;
        if (offset + r->ifunc_count * 24 + r->protect_count * 16 > (u64)kclf_page_size) {
            rc = -E2BIG; report(c, "initializer/IFUNC metadata exceeds parameter page", ""); step = "call metadata"; goto out;
        }
        if (r->ifunc_count && kclf_uwr(r->param_addr + offset, c->fixups, r->ifunc_count * 24)) {
            rc = -EFAULT; step = "IFUNC fixup export"; goto out;
        }
        offset += r->ifunc_count * 24;
        if (r->protect_count && kclf_uwr(r->param_addr + offset, c->protections, r->protect_count * 16)) {
            rc = -EFAULT; step = "RELRO metadata export"; goto out;
        }
    }
out:
    if (rc && !r->err[0]) kclf_set_err(r, "manual: %s failed rc=%d", step, rc);
    if (c->resolved) kclf_ks.vfree(c->resolved);
    if (c->values) kclf_ks.vfree(c->values);
    if (c->snapshot) kclf_ks.vfree(c->snapshot);
    kclf_ks.vfree(c);
    return rc;
}

void kclf_manual_params(struct kclf_req *r, u8 *p)
{
    *(u32 *)(p + KCLF_P_MANUAL) = 1;
    *(u64 *)(p + KCLF_P_HANDLE) = r->image_id;
    *(u64 *)(p + KCLF_P_INITV) = r->param_addr + KCLF_P_SIZE;
    *(u64 *)(p + KCLF_P_INITN) = r->init_count;
    *(u64 *)(p + KCLF_P_FINIV) = r->param_addr + KCLF_P_SIZE + r->init_count * 8;
    *(u64 *)(p + KCLF_P_FININ) = r->fini_count;
    *(u64 *)(p + KCLF_P_IFUNCV) = r->param_addr + KCLF_P_SIZE + (r->init_count + r->fini_count) * 8;
    *(u64 *)(p + KCLF_P_IFUNCN) = r->ifunc_count;
    *(u64 *)(p + KCLF_P_IFARG) = 24;
    *(u64 *)(p + KCLF_P_IFARG + 8) = r->hwcap;
    *(u64 *)(p + KCLF_P_IFARG + 16) = r->hwcap2;
    *(u64 *)(p + KCLF_P_PROTV) = *(u64 *)(p + KCLF_P_IFUNCV) + r->ifunc_count * 24;
    *(u64 *)(p + KCLF_P_PROTN) = r->protect_count;
    *(u64 *)(p + KCLF_P_USED) = KCLF_P_SIZE + (r->init_count + r->fini_count) * 8 +
                               r->ifunc_count * 24 + r->protect_count * 16;
}

long kclf_manual_finish(struct kclf_req *r)
{
    struct kclf_manual_image *m = r->image;
    struct pid *owner = 0;
    int ok, drop;
    long rc;
    if (!m) return 0;
    ok = kclf_state_load(r) == KCLF_DONE && (u64)r->handle == m->id;
    /* An entered initializer with a corrupted completion result cannot be
     * rolled back safely: it may have registered callbacks or spawned threads. */
    if (!ok && r->saved_valid && !r->unload_rc) {
        kclf_manual_abandon(r);
        kclf_fail(r, KCLF_FAILED, KCLF_ST_LOADER, -EPROTO, "manual: invalid completion; image abandoned until process exit");
        return 0;
    }
    drop = (r->image_action == KM_NEW && (!ok || (r->flags & KCLF_F_UNLOAD))) ||
           (ok && r->image_action == KM_DROP);
    if (drop && m->map) {
        rc = kclf_ks.vm_munmap(m->map, m->length);
        if (rc) return rc; /* retain ownership; the common cleanup retries */
        m->map = m->length = 0;
    }
    if (!lock_registry()) return -EAGAIN;
    if (ok) {
        if (r->image_action == KM_NEW) m->refs = 1;
        else if (r->image_action == KM_GET && !(r->flags & KCLF_F_UNLOAD)) m->refs++;
        else if (r->image_action == KM_PUT) m->refs--;
    }
    r->image_addr = m->map; r->image_len = m->length; r->image_refs = drop ? 0 : m->refs;
    if (drop) {
        owner = m->owner;
        memset(m, 0, sizeof(*m));
    } else m->state = KM_LIVE;
    r->image = 0;
    unlock_registry();
    if (owner) kclf_ks.put_pid(owner);
    if (!ok && r->unload_rc)
        kclf_fail(r, KCLF_FAILED, KCLF_ST_LOADER, r->unload_rc, "manual: IFUNC/RELRO failed before constructors rc=%d", r->unload_rc);
    return 0;
}

void kclf_manual_abandon(struct kclf_req *r)
{
    struct kclf_manual_image *m = r->image;
    if (!m) return;
    /* Request ownership excludes other transactions on this image. Publishing
     * ABANDONED is the final operation; reap will only discard dead processes. */
    r->image_addr = m->map; r->image_len = m->length; r->image_refs = m->refs;
    r->image = 0;
    __atomic_store_n(&m->state, KM_ABANDONED, __ATOMIC_RELEASE);
}

void kclf_manual_reap(void)
{
    int i;
    if (!lock_registry()) return;
    for (i = 0; i < KM_IMAGES; i++) {
        struct kclf_manual_image *m = &images[i];
        if (!m->state || m->state == KM_BUSY) continue;
        if (!kclf_process_mm_alive(m->owner, m->mm)) {
            kclf_ks.put_pid(m->owner);
            memset(m, 0, sizeof(*m)); /* old mm, not the controller's mm, owns the mapping */
        }
    }
    unlock_registry();
}

int kclf_manual_busy(void)
{
    int i, busy = 0;
    if (!lock_registry()) return 1;
    for (i = 0; i < KM_IMAGES; i++) if (images[i].state) { busy = 1; break; }
    unlock_registry();
    return busy;
}

int kclf_manual_status(char *out, int length, unsigned start)
{
    unsigned i;
    int off = 0, count = 0;
    if (start >= KM_IMAGES) return kclf_scnprintf(out, length, "invalid image cursor (0..31)\n");
    if (!lock_registry()) return kclf_scnprintf(out, length, "images busy; retry\n");
    for (i = start; i < KM_IMAGES; i++) {
        struct kclf_manual_image *m = &images[i];
        if (!m->state) continue;
        /* Reserve enough space for a complete path/status and continuation;
         * never silently truncate an image that the controller must release. */
        if (length - off < 416) {
            off += kclf_scnprintf(out + off, length - off, "next=%u (use images,%u)\n", i, i);
            break;
        }
        count++;
        if (m->state == KM_BUSY) {
            off += kclf_scnprintf(out + off, length - off, "image=%llu state=busy original_tid=%d path=%s\n",
                                  (unsigned long long)m->id, m->original_tid, m->path);
            continue;
        }
        off += kclf_scnprintf(out + off, length - off, "image=%llu state=%s refs=%u original_tid=%d base=%llx size=%llu hdr=%s path=%s%s\n",
                             (unsigned long long)m->id, m->state == KM_LIVE ? "live" :
                             (m->state == KM_BUSY ? "busy" : "abandoned"), m->refs, m->original_tid,
                             (unsigned long long)m->map, (unsigned long long)m->length,
                             m->hdr_kept ? "kept" : "scrubbed", m->path,
                             m->nodelete ? " nodelete" : "");
    }
    if (!count) off += kclf_scnprintf(out + off, length - off, "no manual images\n");
    unlock_registry();
    return off;
}

int kclf_manual_shutdown(void)
{
    int i, orphaned = 0;
    /* Only called after all callbacks have drained. A stock KP host ignores
     * exit errors: do not leak kernel PID references on a forced unload.
     * User mappings are NOT torn down behind live payload code. */
    for (i = 0; i < KM_IMAGES; i++) {
        if (!images[i].state) continue;
        orphaned++;
        if (images[i].owner) kclf_ks.put_pid(images[i].owner);
        memset(&images[i], 0, sizeof(images[i]));
    }
    return orphaned;
}
