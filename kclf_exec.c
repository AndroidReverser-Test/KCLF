/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * KCLF execution engine: everything that has to run inside the target task
 * context (current->mm == target mm).
 *
 * The engine runs with the request's pinned PID/mm identity and never stops the target:
 *   - preparation runs from a task_work callback (sleepable, target context),
 *   - the register file is only touched at the return-to-user boundary,
 *   - the payload is entered once through a per-request generated EL0 program,
 *     which restores the interrupted register file in EL0 and publishes a
 *     per-request token.  Ordinary target syscalls (or the controller's poll)
 *     observe that token; no syscall, signal, library call or kernel fault
 *     belongs to the framework's completion path.
 */
#include <kclf_internal.h>
#include <common.h>
#include <cache.h>
#include <syscall.h>
#include <kputils.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <uapi/asm-generic/unistd.h>
#include <asm/thread_info.h>
#include <asm/processor.h>
#include "kclf_maps.h"

/* values are kept local so the module does not depend on uapi stubs */
#define KCLF_PROT_READ 0x1
#define KCLF_PROT_WRITE 0x2
#define KCLF_PROT_EXEC 0x4
#define KCLF_MAP_PRIVATE 0x02
#define KCLF_MAP_ANONYMOUS 0x20
#define KCLF_RTLD_NOW 0x2
#define KCLF_O_RDONLY 0

#define KCLF_USER_MAX kclf_user_limit
/* Ordinary Android app processes routinely have well over two thousand VMAs
 * (graphics, JIT, profile buffers, binder). The walk stops as soon as the
 * linker, libdl and libc are known, so this is a safety bound, not a cost. */
#define KCLF_MAX_VMA 16384
#define KCLF_MAX_DYN 512
#define KCLF_MAX_SYM 200000

#define ELF_MAGIC 0x464c457f
#define ELFCLASS64 2
#define ELFDATA2LSB 1
#define ET_DYN 3
#define EM_AARCH64 183
#define PT_LOAD 1
#define PT_DYNAMIC 2
#define DT_NULL 0
#define DT_HASH 4
#define DT_STRTAB 5
#define DT_SYMTAB 6
#define DT_SYMENT 11
#define DT_STRSZ 10
#define DT_SONAME 14
#define DT_GNU_HASH 0x6ffffef5

struct kclf_ehdr
{
    u8 ident[16];
    u16 type;
    u16 machine;
    u32 version;
    u64 entry;
    u64 phoff;
    u64 shoff;
    u32 flags;
    u16 ehsize;
    u16 phentsize;
    u16 phnum;
    u16 shentsize;
    u16 shnum;
    u16 shstrndx;
};

struct kclf_phdr
{
    u32 type;
    u32 flags;
    u64 offset;
    u64 vaddr;
    u64 paddr;
    u64 filesz;
    u64 memsz;
    u64 align;
};

struct kclf_dyn
{
    s64 tag;
    u64 val;
};

struct kclf_sym
{
    u32 name;
    u8 info;
    u8 other;
    u16 shndx;
    u64 value;
    u64 size;
};

struct kclf_elf
{
    u64 bias; /* load bias: mapping_start - p_vaddr of the offset 0 segment */
    u64 start; /* lowest mapped address of the module */
    u64 end; /* highest mapped address of the module */
    u64 dyn; /* bias + PT_DYNAMIC vaddr */
    u64 dynsz; /* PT_DYNAMIC memsz */
    u64 phdr;
    u16 phnum;
};

struct kclf_dyninfo
{
    u64 symtab;
    u64 strtab;
    u64 strsz;
    u64 soname;
    u64 gnu_hash;
    u64 hash;
};

static const u8 kclf_elf_magic[4] = { 0x7f, 'E', 'L', 'F' };

/* kernel pointers are negative when cast to long: never use sign tests */
#define KCLF_MAX_ERRNO 4095UL
static inline int kclf_is_err(const void *p)
{
    return (unsigned long)p >= (unsigned long)-KCLF_MAX_ERRNO;
}

static struct pt_regs *kclf_find_regs(void);

/* ------------------------------------------------------------------ */
/* user memory access                                                   */
/* ------------------------------------------------------------------ */

static int kclf_user_range(u64 addr, u64 len)
{
    return addr && addr < KCLF_USER_MAX && len <= KCLF_USER_MAX - addr;
}

/* Watched-syscall hooks cannot fault. Keep this API separate from the sleepable
 * GUP accessor: nofault returns 0/-errno, access_process_vm returns bytes. */
int kclf_urd(u64 addr, void *buf, int len)
{
    if (kclf_user_tbi) addr &= 0x00ffffffffffffffULL;
    if (len < 0 || !kclf_user_range(addr, (u64)len) || !kclf_ks.copy_from_user_nofault) return -EFAULT;
    return kclf_ks.copy_from_user_nofault(buf, (const void *)addr, len) ? -EFAULT : 0;
}

int kclf_urds(u64 addr, void *buf, int len)
{
    if (kclf_user_tbi) addr &= 0x00ffffffffffffffULL;
    if (len < 0 || !kclf_user_range(addr, (u64)len)) return -EFAULT;
    return kclf_ks.access_process_vm(current, addr, buf, len, 0) == len ? 0 : -EFAULT;
}

static int kclf_urds_u32(u64 addr, u32 *out)
{
    return kclf_urds(addr, out, sizeof(*out));
}

int kclf_uwr(u64 addr, const void *buf, int len)
{
    if (kclf_user_tbi) addr &= 0x00ffffffffffffffULL;
    if (len < 0 || !kclf_user_range(addr, (u64)len)) return -EFAULT;
    /* FOLL_WRITE=1 is stable on the supported kernels. GUP handles PAN,
     * cold pages and the mmap lock; never use a raw arch uaccess symbol. */
    return kclf_ks.access_process_vm(current, addr, (void *)buf, len, 1) == len ? 0 : -EFAULT;
}

/* bounded, NUL terminated user string copy (fault-tolerant) */
static int kclf_urd_strs(u64 addr, char *buf, int len)
{
    int copied = 0;
    if (kclf_user_tbi) addr &= 0x00ffffffffffffffULL;
    if (len <= 0) return -EINVAL;
    while (copied < len - 1) {
        int i, n = kclf_page_size - ((addr + copied) & (kclf_page_size - 1));
        if (n > len - 1 - copied) n = len - 1 - copied;
        if (!kclf_user_range(addr, (u64)copied + n) || kclf_urds(addr + copied, buf + copied, n)) return -EFAULT;
        for (i = 0; i < n; i++)
            if (!buf[copied + i]) return 0;
        copied += n;
    }
    buf[len - 1] = 0;
    return 0;
}

/* ------------------------------------------------------------------ */
/* ELF parsing (in-target memory)                                       */
/* ------------------------------------------------------------------ */

static int kclf_elf_open(u64 map_start, struct kclf_elf *ei)
{
    struct kclf_ehdr eh;
    int i;
    int have_base = 0;
    u64 low = ~0ULL, high = 0;

    if (kclf_urds(map_start, &eh, sizeof(eh))) return -1;
    if (memcmp(eh.ident, kclf_elf_magic, 4)) return -1;
    if (eh.ident[4] != ELFCLASS64 || eh.ident[5] != ELFDATA2LSB) return -1;
    if (eh.machine != EM_AARCH64 || eh.ident[6] != 1 || eh.version != 1 || eh.ehsize != sizeof(eh)) return -1;
    if (eh.type != ET_DYN && eh.type != 2 /* ET_EXEC */) return -1;
    if (eh.phentsize != sizeof(struct kclf_phdr) || eh.phnum == 0 || eh.phnum > 64) return -1;
    if (eh.phoff > 1024 * 1024 || !kclf_user_range(map_start, eh.phoff + (u64)eh.phnum * sizeof(struct kclf_phdr)))
        return -1;

    memset(ei, 0, sizeof(*ei));
    ei->phdr = map_start + eh.phoff;
    ei->phnum = eh.phnum;
    for (i = 0; i < eh.phnum; i++) {
        struct kclf_phdr ph;
        u64 pha = map_start + eh.phoff + (u64)i * sizeof(ph);
        if (pha > KCLF_USER_MAX - sizeof(ph)) return -1;
        if (kclf_urds(pha, &ph, sizeof(ph))) return -1;
        if (ph.vaddr >= KCLF_USER_MAX || ph.memsz > KCLF_USER_MAX - ph.vaddr) return -1;
        if (ph.type == PT_LOAD) {
            if (ph.offset == 0 && !have_base) {
                if (ph.vaddr > map_start) return -1;
                ei->bias = map_start - ph.vaddr;
                have_base = 1;
            }
            if (ph.vaddr < low) low = ph.vaddr;
            if (ph.vaddr + ph.memsz > high) high = ph.vaddr + ph.memsz;
        } else if (ph.type == PT_DYNAMIC) {
            ei->dynsz = ph.memsz;
            ei->dyn = ph.vaddr; /* bias added below */
        }
    }
    if (!have_base || high <= low || !kclf_user_range(ei->bias + low, high - low) || high > KCLF_USER_MAX - ei->bias)
        return -1;
    ei->start = ei->bias + low;
    ei->end = ei->bias + high;
    if (!ei->dyn || ei->dyn < low || ei->dyn >= high || ei->dynsz > high - ei->dyn) return -1;
    ei->dyn += ei->bias;
    return 0;
}

static int kclf_elf_range(const struct kclf_elf *ei, u64 addr, u64 len)
{
    return addr >= ei->start && addr < ei->end && len <= ei->end - addr;
}

static int kclf_elf_executable(const struct kclf_elf *ei, u64 addr)
{
    int i;
    if (!kclf_elf_range(ei, addr, 4)) return 0;
    for (i = 0; i < ei->phnum; i++) {
        struct kclf_phdr ph;
        if (kclf_urds(ei->phdr + (u64)i * sizeof(ph), &ph, sizeof(ph))) return 0;
        if (ph.type != PT_LOAD || !(ph.flags & 1) || ph.vaddr > addr - ei->bias) continue;
        if (addr - ei->bias - ph.vaddr < ph.memsz && ph.memsz - (addr - ei->bias - ph.vaddr) >= 4) return 1;
    }
    return 0;
}

static int kclf_elf_dyninfo(const struct kclf_elf *ei, struct kclf_dyninfo *di)
{
    u64 off;
    u64 limit;

    memset(di, 0, sizeof(*di));
    if (!ei->dyn || !ei->dynsz) return -1;
    limit = ei->dynsz / sizeof(struct kclf_dyn);
    if (limit > KCLF_MAX_DYN) limit = KCLF_MAX_DYN;

    for (off = 0; off < limit; off++) {
        struct kclf_dyn d;
        if (kclf_urds(ei->dyn + off * sizeof(d), &d, sizeof(d))) return -1;
        if (d.tag == DT_NULL) break;
        if ((d.tag == DT_SYMTAB || d.tag == DT_STRTAB || d.tag == DT_GNU_HASH || d.tag == DT_HASH) &&
            (d.val >= KCLF_USER_MAX - ei->bias || ei->bias + d.val < ei->start || ei->bias + d.val >= ei->end))
            return -1;
        switch (d.tag) {
        case DT_SYMTAB:
            di->symtab = ei->bias + d.val;
            break;
        case DT_STRTAB:
            di->strtab = ei->bias + d.val;
            break;
        case DT_STRSZ:
            di->strsz = d.val;
            break;
        case DT_SYMENT:
            if (d.val != sizeof(struct kclf_sym)) return -1;
            break;
        case DT_SONAME:
            di->soname = d.val;
            break;
        case DT_GNU_HASH:
            di->gnu_hash = ei->bias + d.val;
            break;
        case DT_HASH:
            di->hash = ei->bias + d.val;
            break;
        default:
            break;
        }
    }
    if (off == limit || !di->symtab || !di->strtab || !di->strsz ||
        !kclf_elf_range(ei, di->symtab, sizeof(struct kclf_sym)) || !kclf_elf_range(ei, di->strtab, di->strsz))
        return -1;
    return 0;
}

static int kclf_elf_symcount(const struct kclf_elf *ei, const struct kclf_dyninfo *di, u32 *count)
{
    u32 n = 0;

    if (di->hash) {
        /* DT_HASH: nbucket, nchain */
        u32 buckets;
        if (!kclf_elf_range(ei, di->hash, 8) || kclf_urds_u32(di->hash, &buckets) || kclf_urds_u32(di->hash + 4, &n))
            return -1;
        if (!buckets || buckets > KCLF_MAX_SYM || n > KCLF_MAX_SYM ||
            !kclf_elf_range(ei, di->hash, (2ULL + buckets + n) * 4))
            return -1;
        *count = n;
        return 0;
    }
    if (di->gnu_hash) {
        u32 nbuckets = 0, symoffset = 0, bloom_size = 0;
        u32 i, best = 0;
        u64 buckets, chain;

        if (!kclf_elf_range(ei, di->gnu_hash, 16) || kclf_urds_u32(di->gnu_hash, &nbuckets) ||
            kclf_urds_u32(di->gnu_hash + 4, &symoffset) || kclf_urds_u32(di->gnu_hash + 8, &bloom_size))
            return -1;
        if (!nbuckets || nbuckets > 65536 || !bloom_size || bloom_size > 4096 || symoffset >= KCLF_MAX_SYM) return -1;
        if (!kclf_elf_range(ei, di->gnu_hash, 16ULL + (u64)bloom_size * 8 + (u64)nbuckets * 4)) return -1;
        buckets = di->gnu_hash + 16 + (u64)bloom_size * 8;
        for (i = 0; i < nbuckets; i++) {
            u32 v = 0;
            if (kclf_urds_u32(buckets + (u64)i * 4, &v)) return -1;
            if (v >= KCLF_MAX_SYM) return -1;
            if (v > best) best = v;
        }
        if (!best) {
            *count = symoffset;
            return 0;
        }
        chain = buckets + (u64)nbuckets * 4;
        for (;;) {
            u32 h = 0;
            if (best < symoffset) return -1;
            u64 entry = chain + (u64)(best - symoffset) * 4;
            if (!kclf_elf_range(ei, entry, 4) || kclf_urds_u32(entry, &h)) return -1;
            if (h & 1) break;
            if (++best >= KCLF_MAX_SYM) return -1;
        }
        *count = best + 1;
        return 0;
    }
    /* no hash table: bounded scan, the symbol table is followed by the string table */
    u64 limit = ei->end > di->symtab ? (ei->end - di->symtab) / sizeof(struct kclf_sym) : 0;
    *count = limit > KCLF_MAX_SYM ? KCLF_MAX_SYM : (u32)limit;
    (void)n;
    return 0;
}

static int kclf_elf_lookup(const struct kclf_elf *ei, const struct kclf_dyninfo *di, const char *name, u64 *out_addr)
{
    u32 count = 0, i;
    size_t want = strlen(name);

    if (kclf_elf_symcount(ei, di, &count)) return -1;
    if (!kclf_elf_range(ei, di->symtab, (u64)count * sizeof(struct kclf_sym))) return -1;
    for (i = 1; i < count; i++) {
        struct kclf_sym sym;
        char buf[128];
        u64 nameaddr;

        if (kclf_urds(di->symtab + (u64)i * sizeof(sym), &sym, sizeof(sym))) return -1;
        if (!sym.name || sym.name >= di->strsz) continue;
        if (!sym.value || sym.value >= KCLF_USER_MAX - ei->bias || sym.shndx == 0 || (sym.info & 15) != 2)
            continue; /* undefined */
        nameaddr = di->strtab + sym.name;
        if (di->strsz - sym.name <= want || want >= sizeof(buf)) continue;
        if (kclf_urds(nameaddr, buf, (int)want + 1)) continue;
        buf[sizeof(buf) - 1] = 0;
        if (strncmp(buf, name, sizeof(buf)) != 0) continue;
        if (strlen(buf) != want) continue;
        if ((sym.value & 3) || !kclf_elf_executable(ei, ei->bias + sym.value)) continue;
        *out_addr = ei->bias + sym.value;
        return 0;
    }
    return -1;
}

static int kclf_elf_soname(const struct kclf_elf *ei, const struct kclf_dyninfo *di, char *buf, int len)
{
    if (!di->soname || di->soname >= di->strsz) return -1;
    if ((u64)len > di->strsz - di->soname) len = (int)(di->strsz - di->soname);
    return kclf_urd_strs(di->strtab + di->soname, buf, len);
}

/* ------------------------------------------------------------------ */
/* loader discovery                                                     */
/* ------------------------------------------------------------------ */

struct kclf_vma
{
    u64 start;
    u64 end;
    char path[KCLF_MAPS_PATH];
};

struct kclf_vma_iter
{
    struct mm_struct *mm;
    struct file *file;
    loff_t pos;
    u64 addr;
    u64 user_buffer;
    int offset, used;
    char buffer[512];
};

/* force_proc selects the procfs iterator even when the direct mm/VMA walker is
 * available. The manual loader needs pathnames for namespace-aware dependency
 * selection, and procfs is the only portable place to obtain them. */
static long kclf_vma_iter_open(struct kclf_vma_iter *it, struct mm_struct *mm, u64 user_buffer,
                               int force_proc)
{
    memset(it, 0, sizeof(*it));
    it->mm = mm;
    it->user_buffer = user_buffer;
    if (force_proc || !kclf_vma_direct) {
        if (!kclf_ks.vfs_read) return -ENOSYS;
        /* This callback is current in the target mount/PID namespace. procfs
         * owns the VMA locking and handles both rb-tree and maple-tree kernels.
         * Read it only in sleepable target callbacks, never in ctl0/hooks. */
        it->file = kclf_ks.filp_open("/proc/thread-self/maps", KCLF_O_RDONLY, 0);
        if (!it->file) return -ENOENT;
        if (kclf_is_err(it->file)) {
            long rc = (long)it->file;
            it->file = 0;
            return rc;
        }
    }
    return 0;
}

static void kclf_vma_iter_close(struct kclf_vma_iter *it)
{
    if (it->file) kclf_ks.fput(it->file);
    it->file = 0;
}

/* 1 = range, 0 = EOF, negative = error. Never conflate an I/O failure with
 * an empty range when deciding whether a mapping has been reclaimed. */
static long kclf_vma_next(struct kclf_vma_iter *it, struct kclf_vma *out)
{
    if (!it->file) {
        struct vm_area_struct *vma;
        kclf_mmap_read_lock(it->mm);
        vma = kclf_ks.find_vma(it->mm, it->addr);
        if (!vma) {
            kclf_mmap_read_unlock(it->mm);
            return 0;
        }
        out->start = *(u64 *)((char *)vma + kclf_vma_start_off);
        out->end = *(u64 *)((char *)vma + kclf_vma_end_off);
        kclf_mmap_read_unlock(it->mm);
        if (out->end <= out->start || out->end <= it->addr || out->end > KCLF_USER_MAX) return -EFAULT;
        out->path[0] = 0;
        it->addr = out->end;
        return 1;
    }
    for (;;) {
        char line[KCLF_MAPS_LINE];
        unsigned int n = 0;
        for (;;) {
            char c;
            if (it->offset == it->used) {
                /* Some 5.10 procfs files only implement ->read, whereas
                 * kernel_read requires ->read_iter. vfs_read accepts either;
                 * give it real target memory, not a kernel pointer/set_fs.
                 * The request's still-RW parameter page is scratch until the
                 * loader has been resolved. No extra fd or mapping is leaked. */
                long count = kclf_ks.vfs_read(it->file, (char *)it->user_buffer, sizeof(it->buffer), &it->pos);
                if (count < 0) return count;
                if (!count) {
                    if (!n) return 0;
                    break;
                }
                if (count > (long)sizeof(it->buffer)) return -EIO;
                if (kclf_urds(it->user_buffer, it->buffer, (int)count)) return -EFAULT;
                it->used = (int)count;
                it->offset = 0;
            }
            c = it->buffer[it->offset++];
            if (c == '\n') break;
            if (n < sizeof(line) - 1) line[n++] = c;
        }
        line[n] = 0;
        if (kclf_maps_range(line, KCLF_USER_MAX, &out->start, &out->end)) return -EINVAL;
        if (kclf_maps_path(line, out->path, sizeof(out->path))) return -EINVAL;
        if (out->end <= it->addr) continue;
        it->addr = out->end;
        return 1;
    }
}

static long kclf_vma_at(struct mm_struct *mm, u64 addr, struct kclf_vma *out, u64 user_buffer)
{
    struct kclf_vma_iter it;
    long rc = kclf_vma_iter_open(&it, mm, user_buffer, 0);
    int i;

    if (rc) return rc;
    it.addr = addr;
    for (i = 0; i < KCLF_MAX_VMA; i++) {
        rc = kclf_vma_next(&it, out);
        if (rc <= 0 || out->end > addr) break;
    }
    kclf_vma_iter_close(&it);
    if (i == KCLF_MAX_VMA) return -E2BIG;
    return rc > 0 ? 0 : (rc ? rc : -ENOENT);
}

int kclf_walk_vmas(u64 scratch, int (*visit)(u64, const char *, void *), void *context)
{
    struct kclf_vma_iter it;
    struct kclf_vma vma;
    struct mm_struct *mm = kclf_task_mm(current);
    int i, rc;
    if (!mm) return -ESRCH;
    /* Pathnames come from procfs. The direct walker remains a fallback for
     * kernels where the target's maps file cannot be opened. */
    rc = (int)kclf_vma_iter_open(&it, mm, scratch, 1);
    if (rc && kclf_vma_direct) rc = (int)kclf_vma_iter_open(&it, mm, scratch, 0);
    if (rc) return rc;
    for (i = 0; i < KCLF_MAX_VMA; i++) {
        rc = (int)kclf_vma_next(&it, &vma);
        if (rc <= 0) break;
        rc = visit(vma.start, vma.path, context);
        if (rc) break;
    }
    kclf_vma_iter_close(&it);
    return i == KCLF_MAX_VMA ? -E2BIG : rc;
}

static long kclf_resolve(struct kclf_req *r)
{
    struct mm_struct *mm = kclf_task_mm(current);
    struct kclf_elf ldr, dl, libc;
    struct kclf_dyninfo ldr_di, dl_di;
    int have_ldr = 0, have_dl = 0, have_libc = 0;
    int have_ldr_di = 0, have_dl_di = 0;
    struct kclf_vma_iter it;
    long rc;
    int i;
    int nelf = 0, ndyn = 0, nson = 0;

    if (!mm) return -ESRCH;
    memset(&ldr, 0, sizeof(ldr));
    memset(&dl, 0, sizeof(dl));
    memset(&libc, 0, sizeof(libc));
    rc = kclf_vma_iter_open(&it, mm, r->param_addr, 0);
    if (rc) {
        kclf_set_err(r, "open target maps failed rc=%ld", rc);
        return rc;
    }

    for (i = 0; i < KCLF_MAX_VMA; i++) {
        struct kclf_vma vma;
        struct kclf_elf ei;
        struct kclf_dyninfo di;
        char soname[64];

        rc = kclf_vma_next(&it, &vma);
        if (rc <= 0) break;

        /*
         * vm_flags is not at a stable offset across vendor kernels, so do not
         * filter by it: try the ELF header at every VMA start and let the
         * header validation reject anonymous/guard mappings.
         */
        if (kclf_elf_open(vma.start, &ei)) continue;
        nelf++;
        if (kclf_elf_dyninfo(&ei, &di)) continue;
        ndyn++;
        if (kclf_elf_soname(&ei, &di, soname, sizeof(soname))) continue;
        nson++;

        if (!have_ldr && !strcmp(soname, "ld-android.so")) {
            ldr = ei;
            ldr_di = di;
            have_ldr = 1;
            have_ldr_di = 1;
        } else if (!have_dl && !strcmp(soname, "libdl.so")) {
            dl = ei;
            dl_di = di;
            have_dl = 1;
            have_dl_di = 1;
        } else if (!have_libc && !strcmp(soname, "libc.so")) {
            libc = ei;
            have_libc = 1;
        }
        if (have_ldr && have_dl && have_libc) break;
    }
    kclf_vma_iter_close(&it);
    if (rc < 0) {
        kclf_set_err(r, "read target maps failed rc=%ld", rc);
        return rc;
    }

    r->ld.linker_base = have_ldr ? ldr.start : 0;
    r->ld.linker_end = have_ldr ? ldr.end : 0;
    r->ld.libdl_base = have_dl ? dl.start : 0;
    r->ld.libc_base = have_libc ? libc.start : 0;

    /* preferred: call the real loader entry with an explicit caller address so
     * the target namespace (not an anonymous one) is used */
    if (have_ldr_di && !kclf_elf_lookup(&ldr, &ldr_di, "__loader_dlopen", &r->ld.fn)) {
        r->ld.sym = "__loader_dlopen";
        if (kclf_elf_lookup(&ldr, &ldr_di, "__loader_dlerror", &r->ld.dlerror)) r->ld.dlerror = 0;
        if (!kclf_elf_lookup(&ldr, &ldr_di, "__loader_dlclose", &r->ld.dlclose)) {
            r->ld.close_sym = "__loader_dlclose";
        } else {
            r->ld.dlclose = 0;
        }
        if (have_libc)
            r->ld.caller = libc.start;
        else if (have_dl)
            r->ld.caller = dl.start;
        else
            r->ld.caller = ldr.start;
    } else if (have_dl_di && !kclf_elf_lookup(&dl, &dl_di, "dlopen", &r->ld.fn)) {
        r->ld.sym = "dlopen";
        if (kclf_elf_lookup(&dl, &dl_di, "dlerror", &r->ld.dlerror)) r->ld.dlerror = 0;
        if (!kclf_elf_lookup(&dl, &dl_di, "dlclose", &r->ld.dlclose)) {
            r->ld.close_sym = "dlclose";
        } else {
            r->ld.dlclose = 0;
        }
        r->ld.caller = dl.start;
    } else {
        kclf_set_err(r, "resolve loader failed elf=%d dyn=%d son=%d ld=%d dl=%d libc=%d", nelf, ndyn, nson, have_ldr,
                     have_dl, have_libc);
        return -ENOENT;
    }

    if (!r->ld.fn || r->ld.fn >= KCLF_USER_MAX || (r->ld.fn & 3)) {
        r->ld.fn = 0;
        kclf_set_err(r, "resolve loader failed invalid fn ld=%d dl=%d", have_ldr, have_dl);
        return -ENOENT;
    }
    if (r->ld.dlclose && (r->ld.dlclose >= KCLF_USER_MAX || (r->ld.dlclose & 3))) {
        r->ld.dlclose = 0;
        r->ld.close_sym = 0;
    }
    if ((r->flags & KCLF_F_UNLOAD) && !r->ld.dlclose) {
        kclf_set_err(r, "dlclose unavailable for unload mode");
        return -EOPNOTSUPP;
    }
    if (!(have_dl && r->ld.fn >= dl.start && r->ld.fn < dl.end) &&
        !(have_ldr && r->ld.fn >= ldr.start && r->ld.fn < ldr.end)) {
        r->ld.fn = 0;
        return -ENOENT;
    }
    return 0;
}

int kclf_exec_init(void)
{
    return 0;
}

/* ------------------------------------------------------------------ */
/* EL0 completion                                                      */
/* ------------------------------------------------------------------ */

/* The completion path makes no syscall and calls no library function: the
 * generated program restores the interrupted register file itself, publishes a
 * per-request random token in its private page and branches back to the
 * interrupted PC.  A seccomp filter, a ptrace tracer or a library interposer
 * therefore has no completion event to observe.
 *
 * The kernel notices the token from an ordinary syscall entry of the hijacked
 * thread (the list below) or from the controller's status/reap/quiesce poll.
 * Neither path consumes or modifies the syscall, and neither touches the
 * target's register file.  A gated host (syscall-hook callbacks restricted to
 * privileged UIDs) simply never fires these; the controller poll and the
 * watched set are independent of each other. */
const int kclf_watch_pool[] = {
    /* metadata / process state */
    17,  /* getcwd */
    172, /* getpid */
    173, /* getppid */
    174, /* getuid */
    175, /* geteuid */
    176, /* getgid */
    177, /* getegid */
    178, /* gettid */
    160, /* uname */
    134, /* rt_sigaction */
    135, /* rt_sigprocmask */
    139, /* rt_sigreturn */
    130, /* tkill */
    131, /* tgkill */
    129, /* kill */
    /* memory */
    214, /* brk */
    215, /* munmap */
    216, /* mremap */
    222, /* mmap */
    226, /* mprotect */
    233, /* madvise */
    278, /* getrandom */
    279, /* memfd_create */
    /* file descriptor and path traffic */
    56,  /* openat */
    57,  /* close */
    59,  /* pipe2 */
    61,  /* getdents64 */
    62,  /* lseek */
    63,  /* read */
    64,  /* write */
    65,  /* readv */
    66,  /* writev */
    67,  /* pread64 */
    68,  /* pwrite64 */
    79,  /* newfstatat */
    80,  /* fstat */
    82,  /* fsync */
    35,  /* unlinkat */
    23,  /* dup */
    25,  /* fcntl */
    /* waiting, timers and scheduler */
    22,  /* epoll_pwait */
    441, /* epoll_pwait2 */
    20,  /* epoll_create1 */
    21,  /* epoll_ctl */
    72,  /* pselect6 */
    73,  /* ppoll */
    98,  /* futex */
    449, /* futex_waitv */
    101, /* nanosleep */
    113, /* clock_gettime */
    115, /* clock_nanosleep */
    124, /* sched_yield */
    260, /* wait4 */
    /* binder / sockets / ioctl */
    29,  /* ioctl */
    198, /* socket */
    200, /* bind */
    201, /* listen */
    202, /* accept */
    203, /* connect */
    204, /* getsockname */
    205, /* getpeername */
    206, /* sendto */
    207, /* recvfrom */
    208, /* setsockopt */
    209, /* getsockopt */
    210, /* shutdown */
    211, /* sendmsg */
    212, /* recvmsg */
    /* exit */
    93,  /* exit */
    94,  /* exit_group */
};
const int kclf_watch_pool_num = (int)(sizeof(kclf_watch_pool) / sizeof(kclf_watch_pool[0]));

static int kclf_rand_below(int n)
{
    return n > 1 ? (int)(get_random_u64() % (u64)n) : 0;
}

/* Fill user memory with random bytes.  The transient region must not look like
 * a freshly mapped, zero-filled anonymous range: every page that is not
 * immediately overwritten (pad pages, stack) carries random data. */
static long kclf_fill_random(u64 addr, u64 len)
{
    u8 buf[256] __attribute__((aligned(8)));
    int word;

    while (len) {
        u32 n = len > sizeof(buf) ? (u32)sizeof(buf) : (u32)len;
        for (word = 0; word + 8 <= (int)n; word += 8) *(u64 *)(buf + word) = get_random_u64();
        if (word < (int)n) *(u64 *)buf = get_random_u64();
        if (kclf_uwr(addr, buf, (int)n)) return -EFAULT;
        addr += n;
        len -= n;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* randomized private-page layout                                       */
/* ------------------------------------------------------------------ */

struct kclf_layout_slot
{
    u16 size;
    u16 align;
    u16 *field;
};

static u64 kclf_layout_random(u64 *state)
{
    u64 z = (*state += 0x9e3779b97f4a7c15ULL);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}

static int kclf_layout_try(struct kclf_priv_layout *pl, u64 *state)
{
    struct kclf_layout_slot slots[] = {
        { KCLF_SAVED_BYTES, 8, &pl->saved },
        { KCLF_QREGS_BYTES, 16, &pl->qregs },
        { 8, 8, &pl->fpcr },
        { 8, 8, &pl->fpsr },
        { 8, 8, &pl->done },
        { 8, 8, &pl->donetok },
        { 8, 8, &pl->handle },
        { 8, 8, &pl->errptr },
        { 8, 8, &pl->rc },
    };
    int n = (int)(sizeof(slots) / sizeof(slots[0]));
    int i, cursor;

    for (i = n - 1; i > 0; i--) {
        int j = (int)(kclf_layout_random(state) % (u64)(i + 1));
        struct kclf_layout_slot t = slots[i];
        slots[i] = slots[j];
        slots[j] = t;
    }
    cursor = (int)(kclf_layout_random(state) % 16u) * 8;
    for (i = 0; i < n; i++) {
        int align = slots[i].align;
        int gap = (int)(kclf_layout_random(state) % 4u) * 8;
        cursor = (cursor + gap + align - 1) & ~(align - 1);
        if (cursor + slots[i].size > 4080) return -1;
        *slots[i].field = (u16)cursor;
        cursor += slots[i].size;
    }
    pl->end = (u16)cursor;
    return 0;
}

static int kclf_layout_init(struct kclf_req *r, u64 seed)
{
    u64 state = seed | 1;
    int tries;

    memset(&r->pl, 0, sizeof(r->pl));
    for (tries = 0; tries < 8; tries++)
        if (!kclf_layout_try(&r->pl, &state)) {
            r->priv_layout_ok = 1;
            return 0;
        }
    /* Defensive compact fallback: random placement can theoretically fail
     * through fragmentation.  Still do not reuse the historical fixed ABI. */
    memset(&r->pl, 0, sizeof(r->pl));
    r->pl.saved = 0x000;
    r->pl.qregs = 0x120;
    r->pl.fpcr = 0x320;
    r->pl.fpsr = 0x328;
    r->pl.done = 0x330;
    r->pl.donetok = 0x338;
    r->pl.handle = 0x340;
    r->pl.errptr = 0x348;
    r->pl.rc = 0x350;
    r->pl.end = 0x358;
    r->priv_layout_ok = 1;
    return 0;
}

/* ------------------------------------------------------------------ */
/* private page export                                                  */
/* ------------------------------------------------------------------ */

/* Export the per-request completion token and the randomized field layout.
 * The saved register file is copied in later, at the hijack boundary, because
 * only then are the interrupted registers known.  Results (handle/errptr/rc)
 * are written by the generated program just before it completes. */
static int kclf_export_private(struct kclf_req *r)
{
    u64 page = (u64)kclf_page_size;
    u64 tok = r->done_token;

    if (!r->priv_layout_ok || r->pl.end > page) return -EINVAL;
    if (kclf_fill_random(r->priv_addr, page)) return -EFAULT;
    if (kclf_uwr(r->priv_addr + r->pl.donetok, &tok, sizeof(tok))) return -EFAULT;
    return 0;
}

/* ------------------------------------------------------------------ */
/* prepare                                                             */
/* ------------------------------------------------------------------ */

static long kclf_check_library(const char *path)
{
    struct file *f;
    u8 hdr[64];
    loff_t pos = 0;
    long n;

    f = kclf_ks.filp_open(path, KCLF_O_RDONLY, 0);
    if (!f) return -ENOENT;
    if (kclf_is_err(f)) return (long)(unsigned long)f;
    n = kclf_ks.kernel_read(f, hdr, sizeof(hdr), &pos);
    if (kclf_ks.fput) kclf_ks.fput(f);
    if (n < 0) return n;
    if (n < (long)sizeof(hdr)) return -ENOEXEC;
    if (memcmp(hdr, kclf_elf_magic, 4)) return -ENOEXEC;
    if (hdr[4] != ELFCLASS64 || hdr[5] != ELFDATA2LSB) return -ENOEXEC;
    if (*(u16 *)(hdr + 18) != EM_AARCH64) return -ENOEXEC;
    if (*(u16 *)(hdr + 16) != ET_DYN) return -ENOEXEC;
    return 0;
}

/* Try to run the generated program on the interrupted thread's own stack.
 *
 * The prepare callback runs at the same return-to-user boundary as the later
 * hijack, so the pt_regs frame still carries the user SP the thread will resume
 * with.  Using a region below that SP keeps SP (and, for usleep(), the timespec
 * pointer in x0) inside the thread's normal stack mapping instead of a
 * short-lived anonymous block.  If the frame cannot be located, the stack is a
 * small altstack, or the thread is too close to its guard page, the caller
 * keeps the dedicated transient stack block. */
static int kclf_choose_stack(struct kclf_req *r)
{
    struct pt_regs *regs = kclf_find_regs();
    struct mm_struct *mm = kclf_task_mm(current);
    struct kclf_vma vma;
    u64 sp, scratch, top;
    long rc;

    if (!mm || !regs) return -ENOENT;
    sp = regs->sp;
    if (!sp || (sp & 0xf) || sp >= KCLF_USER_MAX) return -EINVAL;
    scratch = (sp - 0x800) & ~0xfULL;
    if (scratch < 0x1000) return -EFAULT;
    rc = kclf_vma_at(mm, sp, &vma, scratch);
    if (rc) { r->stack_state = 1; return (int)rc; }
    if (sp < vma.start || sp >= vma.end) { r->stack_state = 2; return -EFAULT; }
    if (vma.end - vma.start < 128 * 1024) { r->stack_state = 3; return -ENOSPC; }
    if (sp - vma.start < 48 * 1024) { r->stack_state = 4; return -ENOSPC; }
    top = (sp - 0x100) & ~0xfULL;
    if (top <= vma.start + 32 * 1024) { r->stack_state = 5; return -ENOSPC; }
    r->stack_top = top;
    r->stack_ref_sp = sp;
    r->stack_borrowed = 1;
    r->stack_state = 6;
    return 0;
}

/* Initialize every field consumed by EL0, even on a branch that skips dlerror.
 * Padding may be random; a result pointer must never be random. */
static void kclf_init_params(struct kclf_req *r, u8 pbuf[KCLF_P_SIZE])
{
    int i;

    for (i = 0; i < KCLF_P_SIZE / 8; i++) ((u64 *)pbuf)[i] = get_random_u64();
    *(u64 *)(pbuf + KCLF_P_FN) = r->ld.fn;
    *(u64 *)(pbuf + KCLF_P_DLERROR) = r->ld.dlerror;
    *(u64 *)(pbuf + KCLF_P_DLCLOSE) = r->ld.dlclose;
    *(u64 *)(pbuf + KCLF_P_CALLER) = r->ld.caller;
    *(u64 *)(pbuf + KCLF_P_HANDLE) = 0;
    *(u64 *)(pbuf + KCLF_P_ERRPTR) = 0;
    *(u32 *)(pbuf + KCLF_P_FLAGS) = KCLF_RTLD_NOW;
    *(u32 *)(pbuf + KCLF_P_UNLOAD) = !!(r->flags & KCLF_F_UNLOAD);
    *(u32 *)(pbuf + KCLF_P_MANUAL) = 0;
    /* r->path is a fixed, zero-initialized request field, not an unbounded
     * user pointer. Copy its complete extent without strncpy truncation. */
    memcpy(pbuf + KCLF_P_PATH, r->path, KCLF_PATH_MAX);
    pbuf[KCLF_P_PATH + KCLF_PATH_MAX - 1] = 0;
    if (!(r->flags & KCLF_F_LINKER)) kclf_manual_params(r, pbuf);
}

long kclf_exec_prepare(struct kclf_req *r)
{
    struct mm_struct *mm = kclf_task_mm(current);
    u64 page = (u64)kclf_page_size;
    u64 len;
    u64 addr;
    u8 pbuf[KCLF_P_SIZE] __attribute__((aligned(8)));
    u8 *scratch;
    struct kclf_prog prog;
    u64 seed;
    long rc;
    long mret;
    int stack_pages, i;

    if (!mm || (u64)mm != r->mm) return -ESRCH;
    if (!page) return -EINVAL;
    /* Optional: borrow the thread's own stack.  A failure here is not fatal;
     * the dedicated stack block below remains the fallback. */
    (void)kclf_choose_stack(r);

    if (r->flags & KCLF_F_LINKER) {
        rc = kclf_check_library(r->path);
        if (rc) {
            kclf_set_err(r, "open library failed rc=%ld", rc);
            return rc;
        }
    }

    /* The transient region is one anonymous mapping whose blocks are placed in
     * a random order with random pad pages between them: RX code (1 page), RW
     * ABI parameters (1 page), RW private parameters (1 page) and, only when
     * the thread's own stack cannot be borrowed, a PROT_NONE guard + RW stack
     * (1 + S pages, S = 6..14).  The code page is therefore not the region
     * base, the private page is an independent block rather than ABI+page, the
     * guard position and the total length are unpredictable, and every page
     * that is not immediately overwritten is filled with random data. */
    seed = get_random_u64();
    if (kclf_layout_init(r, seed)) {
        kclf_set_err(r, "private layout generation failed");
        return -ENOMEM;
    }
    stack_pages = KCLF_MIN_STACK_PAGES + kclf_rand_below(KCLF_STACK_PAGES_SPAN);
    {
        /* code, ABI, private, guard+stack */
        int order[4] = { 0, 1, 2, 3 };
        u64 block[4] = { 0, 0, 0, 0 };
        u64 cursor;
        int pads[5];
        int nblocks = r->stack_borrowed ? 3 : 4;
        int pages = 3 + (r->stack_borrowed ? 0 : 1 + stack_pages);
        int k;

        for (i = nblocks - 1; i > 0; i--) {
            int j = kclf_rand_below(i + 1), t = order[i];
            order[i] = order[j];
            order[j] = t;
        }
        for (i = 0; i < nblocks + 1; i++) {
            pads[i] = kclf_rand_below(3);
            pages += pads[i];
        }
        len = (u64)pages * page;
        addr = kclf_ks.vm_mmap(0, 0, len, KCLF_PROT_READ | KCLF_PROT_WRITE,
                               KCLF_MAP_PRIVATE | KCLF_MAP_ANONYMOUS, 0);
        if (!addr || kclf_is_err((void *)addr)) {
            kclf_set_err(r, "mmap failed 0x%llx", (unsigned long long)addr);
            return addr ? (long)addr : -ENOMEM;
        }
        r->map_addr = addr;
        r->map_len = len;
        if (!kclf_user_range(addr, len)) return -EFAULT;
        cursor = addr + (u64)pads[0] * page;
        for (k = 0; k < nblocks; k++) {
            int b = order[k];
            u64 size = (b == 3) ? (u64)(1 + stack_pages) * page : page;
            block[b] = cursor;
            cursor += size + (u64)pads[k + 1] * page;
        }
        r->code_addr = block[0];
        r->param_addr = block[1];
        r->priv_addr = block[2];
        if (!r->stack_borrowed) {
            r->guard_addr = block[3];
            /* Leave a little slack above the trampoline's initial SP: its own
             * frame is empty, but the payload's constructors run on this stack
             * and a callee's frame starts below SP. */
            r->stack_top = block[3] + (u64)(1 + stack_pages) * page - KCLF_STACK_HEADROOM;
        }
    }
    /* Randomize the region before anything writes its real contents: pad pages
     * and the transient stack keep the random data, the code/parameter pages
     * are overwritten below. */
    if (kclf_fill_random(r->map_addr, r->map_len)) {
        kclf_set_err(r, "randomize transient pages failed");
        return -EFAULT;
    }

    rc = (r->flags & KCLF_F_LINKER) ? kclf_resolve(r) : kclf_manual_prepare(r);
    if (rc) {
        if (!r->err[0]) kclf_set_err(r, "resolve loader failed rc=%ld", rc);
        return rc;
    }
    r->done_token = get_random_u64();
    if (!r->done_token) r->done_token = 1;

    /* Per-request generated trampoline: no fixed blob, no fixed entry, no
     * syscall, no library call and no faulting store. */
    scratch = kclf_ks.vmalloc((unsigned long)page);
    if (!scratch) {
        kclf_set_err(r, "trampoline allocation failed");
        rc = -ENOMEM;
        goto fail;
    }
    if (kclf_prog_build(scratch, (int)page, r->param_addr, r->priv_addr, &r->pl, seed, &prog)) {
        kclf_ks.vfree(scratch);
        kclf_set_err(r, "trampoline generation failed");
        rc = -EFAULT;
        goto fail;
    }
    if (kclf_uwr(r->code_addr, scratch, (int)page)) {
        kclf_ks.vfree(scratch);
        kclf_set_err(r, "copy trampoline failed");
        rc = -EFAULT;
        goto fail;
    }
    r->entry_pc = r->code_addr + prog.entry_off;
    kclf_ks.vfree(scratch);

    kclf_init_params(r, pbuf);

    if (kclf_uwr(r->param_addr, pbuf, sizeof(pbuf))) {
        kclf_set_err(r, "copy parameters failed");
        rc = -EFAULT;
        goto fail;
    }

    /* per-request completion token and randomized private layout */
    if (kclf_export_private(r)) {
        kclf_set_err(r, "copy private completion state failed");
        rc = -EFAULT;
        goto fail;
    }

    /* code page becomes read+execute, no RWX mapping is left behind */
    mret = raw_syscall3(__NR_mprotect, (long)r->code_addr, (long)page, KCLF_PROT_READ | KCLF_PROT_EXEC);
    if (mret) {
        kclf_set_err(r, "mprotect failed rc=%ld", mret);
        rc = mret;
        goto fail;
    }
    if (!r->stack_borrowed) {
        mret = raw_syscall3(__NR_mprotect, (long)r->guard_addr, (long)page, 0);
        if (mret) {
            kclf_set_err(r, "stack guard failed rc=%ld", mret);
            rc = mret;
            goto fail;
        }
    }
    flush_icache_all();
    return 0;

fail:
    /* Caller owns rollback and checked munmap/retry accounting. */
    return rc;
}

/* Copy the saved register file into the private page so the EL0 path can
 * restore the interrupted context itself before branching back to it. */
static int kclf_export_saved(struct kclf_req *r)
{
    u64 buf[34];

    memcpy(&buf[0], &r->saved.regs[0], 31 * sizeof(u64));
    buf[31] = r->saved.sp;
    buf[32] = r->saved.pc;
    buf[33] = r->saved.pstate & 0xF0000000ULL; /* NZCV only */
    if (!r->priv_layout_ok) return -EINVAL;
    return kclf_uwr(r->priv_addr + r->pl.saved, buf, sizeof(buf));
}

/* ------------------------------------------------------------------ */
/* hijack                                                              */
/* ------------------------------------------------------------------ */

static int kclf_regs_basic(struct pt_regs *regs, u64 stack_top)
{
    u64 addr = (u64)regs;
    u64 pc, sp;

    if (addr < stack_top - 1024 || addr >= stack_top) return 0;
    if (addr & 7) return 0;
    pc = regs->pc;
    sp = regs->sp;
    if (pc < 0x1000 || pc >= KCLF_USER_MAX || (pc & 3)) return 0;
    if (sp < 0x1000 || sp >= KCLF_USER_MAX || (sp & 0xf)) return 0;
    if (regs->pstate & PSR_MODE_MASK) return 0; /* must be EL0t */
    if (regs->pstate >> 32) return 0;
    return 1;
}

static int kclf_regs_sane(struct pt_regs *regs, u64 stack_top)
{
    if (!kclf_regs_basic(regs, stack_top)) return 0;
    if (regs->syscallno < -1 || regs->syscallno > 600) return 0;
    /* Do not require syscallno == regs[8]: when a real signal was delivered
     * before task_work ran, the frame is a signal-handler entry and the
     * register file no longer has a 1:1 syscall-number/x8 relationship. The
     * frame address itself is exact (BTF-validated or learned from the first
     * syscall wrapper frame observed by the watched-syscall hook). */
    return 1;
}

/* locate the pt_regs frame that will be consumed by the next exception return */
static struct pt_regs *kclf_find_regs(void)
{
    u64 stack = (u64)get_stack(current);
    u64 top = stack + (u64)thread_size;
    struct pt_regs *regs;
    int size = __atomic_load_n(&kclf_regs_size, __ATOMIC_ACQUIRE);

    if (!stack || !top || size < 288 || size > 512 || (size & 15)) return 0;
    regs = (struct pt_regs *)(top - (u64)size);
    return kclf_regs_sane(regs, top) ? regs : 0;
}

/* A timer interrupt can run poll task_work between the EL0 token store and
 * the final branch. Do not reclaim the instruction/private pages until the
 * interrupted PC has left the transient allocation. */
int kclf_exec_poll_ready(const struct kclf_req *r)
{
    struct pt_regs *regs = kclf_find_regs();
    return regs && !(regs->pc >= r->map_addr && regs->pc - r->map_addr < r->map_len);
}

/* Heuristic only: syscall numbers cannot prove that a userspace lock is not
 * held. Use an application-controlled idle point for reliable loading.
 *
 * The list is deliberately biased towards calls an application thread blocks
 * in (epoll/ppoll/futex/ioctl/nanosleep/read) plus cheap metadata calls. That
 * is what makes injecting an already running app practical: the return
 * boundary we get after a "wake" is normally the interrupted blocking call.
 * It does not make the payload safe to run at an arbitrary protocol point;
 * see README for the app-side constraints. */
static int kclf_syscall_safe(s32 nr)
{
    switch (nr) {
    case 7: /* fsetxattr (AArch64; retained legacy heuristic entry) */
    case 22: /* epoll_pwait */
    case 23: /* dup (AArch64; retained legacy heuristic entry) */
    case 29: /* ioctl (binder and most driver traffic) */
    case 35: /* unlinkat */
    case 61: /* getdents64 */
    case 62: /* lseek */
    case 63: /* read */
    case 64: /* write */
    case 65: /* readv */
    case 66: /* writev */
    case 72: /* pselect6 */
    case 73: /* ppoll */
    case 79: /* newfstatat */
    case 80: /* fstat */
    case 82: /* fsync */
    case 98: /* futex (ART monitors, pthread mutexes, condvars) */
    case 101: /* nanosleep */
    case 115: /* clock_nanosleep */
    case 124: /* sched_yield */
    case 135: /* rt_sigprocmask */
    case 137: /* rt_sigtimedwait */
    case 172: /* getpid */
    case 174: /* getuid */
    case 178: /* gettid */
    case 204: /* getsockname */
    case 205: /* getpeername */
    case 206: /* sendto */
    case 207: /* recvfrom */
    case 211: /* sendmsg */
    case 212: /* recvmsg */
    case 243: /* recvmmsg */
    case 269: /* sendmmsg */
    case 441: /* epoll_pwait2 */
    case 449: /* futex_waitv */
        return 1;
    default:
        return 0;
    }
}

int kclf_exec_hijack(struct kclf_req *r)
{
    struct pt_regs *regs;
    u64 tif;

    regs = kclf_find_regs();
    if (!regs) {
        kclf_set_err(r, "no pt_regs frame at return boundary");
        return -EFAULT;
    }
    if (regs->pstate & PSR_MODE32_BIT) {
        kclf_set_err(r, "32-bit target unsupported");
        return -EOPNOTSUPP;
    }
    if (r->stack_borrowed && r->stack_ref_sp) {
        u64 sp = regs->sp;
        if (sp + 0x1000 < r->stack_ref_sp || sp > r->stack_ref_sp + 0x1000) {
            kclf_set_err(r, "borrowed stack moved before hijack");
            return -EAGAIN;
        }
    }
    tif = __atomic_load_n(&current_thread_info()->flags, __ATOMIC_RELAXED);
    /* FPSIMD is preserved by the trampoline, but SVE/SME scalable state is
     * not. Reject it even with force. Real pending signals are handled by the
     * exception return path; they are not ignored (see README). */
    if (tif & kclf_vector_mask) {
        kclf_set_err(r, "SVE/SME target state unsupported");
        return -EOPNOTSUPP;
    }

    /* A tracer or syscall emulator can alter the target's return path and
     * observe the transient mapping, so do not redirect a thread while one is
     * attached. A seccomp filter is *not* a refusal: ordinary Android app
     * processes always have the zygote filter installed, and the framework's
     * completion path no longer depends on any syscall being allowed. */
    if (tif & kclf_trace_mask) {
        kclf_set_err(r, "traced/emulated target unsupported");
        return -EOPNOTSUPP;
    }

    if (!(r->flags & KCLF_F_FORCE)) {
        /* never call the loader from inside the loader itself */
        if (r->ld.linker_base && regs->pc >= r->ld.linker_base && regs->pc < r->ld.linker_end) return -EAGAIN;
        if (regs->syscallno >= 0 && !kclf_syscall_safe(regs->syscallno)) return -EAGAIN;
    }

    memcpy(&r->saved.regs[0], &regs->regs[0], 31 * sizeof(u64));
    r->saved.sp = regs->sp;
    r->saved.pc = regs->pc;
    r->saved.pstate = regs->pstate;
    r->saved_syscallno = regs->syscallno;
    r->saved_orig_x0 = regs->orig_x0;
    r->saved_valid = 1;

    /* The EL0 completion path needs the original register file inside the
     * target mapping: it restores the interrupted context and branches back to
     * the interrupted PC without any kernel completion event. */
    if (kclf_export_saved(r)) {
        r->saved_valid = 0;
        kclf_set_err(r, "export saved register file failed");
        return -EFAULT;
    }

    /* Only the values that select the payload are changed. The EL0 tail
     * restores the interrupted register file except its return register x16. */
    regs->pc = r->entry_pc;
    regs->sp = r->stack_top;
    regs->pstate &= ~(3UL << 10); /* clear BTI branch type for the new entry */
    /* the payload entry is not a syscall return; keep the restart machinery away */
    regs->syscallno = -1;
    return 0;
}

/* Apply the deferred GNU_RELRO protection.  It has to wait until the EL0 phase
 * (IFUNC resolution) has written its results, and it is applied from the
 * completion path in EL1 so the generated program never issues mprotect. */
long kclf_apply_relro(struct kclf_req *r)
{
    if (r->relro_count > KCLF_MAX_RELRO || r->relro_done > r->relro_count) return -EINVAL;
    while (r->relro_done < r->relro_count) {
        u64 start = r->relro[r->relro_done][0];
        u64 len = r->relro[r->relro_done][1];
        long rc;

        if (len) {
            rc = raw_syscall3(__NR_mprotect, (long)start, (long)len, KCLF_PROT_READ);
            if (rc) return rc;
        }
        /* Publish progress only after success; a failed range is retried. */
        r->relro_done++;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* result collection and teardown                                       */
/* ------------------------------------------------------------------ */

long kclf_exec_finish(struct kclf_req *r, int capture_err)
{
    long rc = 0;

    if (!(r->flags & KCLF_F_LINKER)) {
        rc = kclf_manual_finish(r);
        if (rc) return rc;
    }

    if ((r->flags & KCLF_F_LINKER) && capture_err && r->err_user) {
        if (!kclf_urd_strs(r->err_user, r->err, sizeof(r->err))) {
            r->err[sizeof(r->err) - 1] = 0;
        }
        r->err_user = 0;
    }
    if (r->map_addr) {
        rc = kclf_ks.vm_munmap(r->map_addr, r->map_len);
        if (rc == -EINVAL) {
            /* EINVAL can also mean the range was already removed.  Only treat
             * it as success when no VMA still covers the base. */
            struct mm_struct *mm = kclf_task_mm(current);
            struct kclf_vma check;
            if (mm) {
                long found = kclf_vma_at(mm, r->map_addr, &check, r->param_addr);
                if (found == -ENOENT || (!found && check.start >= r->map_addr + r->map_len)) rc = 0;
            }
        }
        if (!rc) {
            r->map_addr = 0;
            r->map_len = 0;
        }
    }
    return rc;
}

/* ------------------------------------------------------------------ */
/* diagnostics: no faulting ELF walk in ctl0 (older KP holds RCU there). */
/* ------------------------------------------------------------------ */

int kclf_exec_probe(char *out, int outlen)
{
    int off = 0;
    struct pt_regs *regs = kclf_find_regs();
    off += kclf_scnprintf(out + off, outlen - off, "kernel=%x btf=%d mm_off=%d mmap_lock_off=%d vma=%d/%d\n", kver,
                          kclf_btf_ok, kclf_mm_off, kclf_mmap_lock_off, kclf_vma_start_off, kclf_vma_end_off);
    off += kclf_scnprintf(out + off, outlen - off, "pt_regs=%s size=%d thread_size=%d page=%d\n",
                          regs ? "ok" : "unavailable", kclf_regs_size, thread_size, kclf_page_size);
    off += kclf_scnprintf(out + off, outlen - off, "user_limit=%llx tbi=%d\n", (unsigned long long)kclf_user_limit,
                          kclf_user_tbi);
    off += kclf_scnprintf(out + off, outlen - off, "vma_backend=%s mm_access=%s\n",
                          kclf_vma_direct ? "locked" : "proc_maps", kclf_mm_off > 0 ? "offset" : "get_task_mm");
    off += kclf_scnprintf(out + off, outlen - off, "cancel=%s user_io=access_process_vm wake=%s quiescing=%d\n",
                          kclf_ks.task_work_cancel_match ? "match" : (kclf_ks.task_work_cancel_object ? "object" : "func"),
                          kclf_wake_supported ? "task_work_signal" : "unsupported", kclf_unloading);
    off += kclf_scnprintf(out + off, outlen - off, "wake_abi=%s trace_mask=%llx vector_mask=%llx nofault=%d poll_io=gup\n",
                          kclf_wake_abi, (unsigned long long)kclf_trace_mask, (unsigned long long)kclf_vector_mask,
                          !!kclf_ks.copy_from_user_nofault);
    if (kclf_ks.cpu_get_elf_hwcap)
        off += kclf_scnprintf(out + off, outlen - off, "hwcap=%llx hwcap2=%llx source=kernel\n",
                              (unsigned long long)kclf_ks.cpu_get_elf_hwcap(),
                              (unsigned long long)(kclf_ks.cpu_get_elf_hwcap2 ? kclf_ks.cpu_get_elf_hwcap2() : 0));
    else
        off += kclf_scnprintf(out + off, outlen - off, "hwcap=auxv-fallback (target must be dumpable)\n");
    if (!kclf_regs_size)
        off += kclf_scnprintf(out + off, outlen - off,
                              "run a native syscall to learn pt_regs before injection\n");
    return off;
}
