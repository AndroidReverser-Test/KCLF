/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * KCLF execution engine: everything that has to run inside the target task
 * context (current->mm == target mm).
 *
 * The engine never allocates a task reference and never stops the target:
 *   - preparation runs from a task_work callback (sleepable, target context),
 *   - the register file is only touched at the return-to-user boundary,
 *   - the payload is entered once and gives control back through a private
 *     getpid trap, after which the original register file is restored.
 */
#include <kclf_internal.h>
#include <cache.h>
#include <syscall.h>
#include <kputils.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <uapi/asm-generic/unistd.h>
#include <asm/thread_info.h>
#include <asm/processor.h>

/* values are kept local so the module does not depend on uapi stubs */
#define KCLF_PROT_READ 0x1
#define KCLF_PROT_WRITE 0x2
#define KCLF_PROT_EXEC 0x4
#define KCLF_MAP_PRIVATE 0x02
#define KCLF_MAP_ANONYMOUS 0x20
#define KCLF_RTLD_NOW 0x2
#define KCLF_O_RDONLY 0

#define KCLF_USER_MAX 0x0000800000000000UL
#define KCLF_MAX_VMA 2048
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
    u64 bias;  /* load bias: mapping_start - p_vaddr of the offset 0 segment */
    u64 start; /* lowest mapped address of the module */
    u64 end;   /* highest mapped address of the module */
    u64 dyn;   /* bias + PT_DYNAMIC vaddr */
    u64 dynsz; /* PT_DYNAMIC memsz */
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

static const u64 kclf_vma_off_start = 0;
static const u64 kclf_vma_off_end = 8;

static const u8 kclf_elf_magic[4] = { 0x7f, 'E', 'L', 'F' };

/* kernel pointers are negative when cast to long: never use sign tests */
#define KCLF_MAX_ERRNO 4095UL
static inline int kclf_is_err(const void *p)
{
    return (unsigned long)p >= (unsigned long)-KCLF_MAX_ERRNO;
}

extern const char kclf_tramp_start[];
extern const char kclf_tramp_end[];
extern const char kclf_tramp_ptr_slot[];

static struct pt_regs *kclf_find_regs(void);

/* ------------------------------------------------------------------ */
/* user memory access                                                   */
/* ------------------------------------------------------------------ */

static int kclf_urd(u64 addr, void *buf, int len)
{
    if (!addr || len < 0 || (u64)len > KCLF_USER_MAX || addr > KCLF_USER_MAX - (u64)len) return -1;
    return kclf_ks.copy_from_user(buf, (const void *)addr, len) ? -1 : 0;
}

/*
 * raw_copy_from_user() only succeeds when the source page is already present.
 * Touching one byte per page first makes file-backed mappings (linker, libc,
 * a cold payload) fault in, without walking every byte of a large dynsym.
 * Must only be used from sleepable contexts.
 */
static int kclf_prefault(u64 addr, u64 len)
{
    u64 p, end;
    u64 page = (u64)kclf_page_size;

    if (!len) return 0;
    if (!addr || (u64)len > KCLF_USER_MAX || addr > KCLF_USER_MAX - (u64)len) return -1;
    if (!kclf_ks.fault_in_pages_readable) return 0;
    if (!page) page = 4096;
    end = addr + len;
    p = addr & ~(page - 1);
    for (; p < end; p += page) {
        if (kclf_ks.fault_in_pages_readable((const void *)p, 1)) return -1;
    }
    return 0;
}

static int kclf_urds(u64 addr, void *buf, int len)
{
    int rc;

    if (!kclf_prefault(addr, (u64)len)) {
        rc = kclf_urd(addr, buf, len);
        if (!rc) return 0;
    }
    /* Last resort for kernels without fault_in_pages_readable, or a range
     * whose first page is a hole: let GUP fault the pages in for us. */
    if (kclf_ks.access_process_vm) {
        int n = kclf_ks.access_process_vm(current, (unsigned long)addr, buf, len, 0);
        if (n == len) return 0;
    }
    return -1;
}

static int kclf_urds_u32(u64 addr, u32 *out)
{
    return kclf_urds(addr, out, sizeof(*out));
}

static int kclf_uwr(u64 addr, const void *buf, int len)
{
    if (!addr || len < 0 || (u64)len > KCLF_USER_MAX || addr > KCLF_USER_MAX - (u64)len) return -1;
    if (kclf_ks.copy_to_user) return kclf_ks.copy_to_user((void *)addr, buf, len) ? -1 : 0;
    /* KernelPatch helper: positive return means "copied length" */
    return compat_copy_to_user((void __user *)addr, buf, len) == len ? 0 : -1;
}

/* bounded, NUL terminated user string copy (fault-tolerant) */
static int kclf_urd_strs(u64 addr, char *buf, int len)
{
    int i;

    if (len <= 0) return -1;
    for (i = 0; i < len - 1; i++) {
        char c;
        if (kclf_urds(addr + i, &c, 1)) return -1;
        buf[i] = c;
        if (!c) return 0;
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
    if (eh.machine != EM_AARCH64) return -1;
    if (eh.type != ET_DYN && eh.type != 2 /* ET_EXEC */) return -1;
    if (eh.phentsize != sizeof(struct kclf_phdr) || eh.phnum == 0 || eh.phnum > 64) return -1;
    if (eh.phoff > KCLF_USER_MAX - map_start) return -1;

    memset(ei, 0, sizeof(*ei));
    for (i = 0; i < eh.phnum; i++) {
        struct kclf_phdr ph;
        u64 pha = map_start + eh.phoff + (u64)i * sizeof(ph);
        if (pha > KCLF_USER_MAX - sizeof(ph)) return -1;
        if (kclf_urds(pha, &ph, sizeof(ph))) return -1;
        if (ph.type == PT_LOAD) {
            if (ph.offset == 0 && !have_base) {
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
    if (!have_base) return -1;
    ei->start = ei->bias + low;
    ei->end = ei->bias + high;
    ei->dyn = ei->dyn ? ei->bias + ei->dyn : 0;
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
        switch (d.tag) {
        case DT_SYMTAB: di->symtab = ei->bias + d.val; break;
        case DT_STRTAB: di->strtab = ei->bias + d.val; break;
        case DT_STRSZ: di->strsz = d.val; break;
        case DT_SONAME: di->soname = d.val; break;
        case DT_GNU_HASH: di->gnu_hash = ei->bias + d.val; break;
        case DT_HASH: di->hash = ei->bias + d.val; break;
        default: break;
        }
    }
    if (!di->symtab || !di->strtab || !di->strsz) return -1;
    return 0;
}

static int kclf_elf_symcount(const struct kclf_elf *ei, const struct kclf_dyninfo *di, u32 *count)
{
    u32 n = 0;

    if (di->hash) {
        /* DT_HASH: nbucket, nchain */
        if (kclf_urds_u32(di->hash + 4, &n)) return -1;
        if (n > KCLF_MAX_SYM) return -1;
        *count = n;
        return 0;
    }
    if (di->gnu_hash) {
        u32 nbuckets = 0, symoffset = 0, bloom_size = 0;
        u32 i, best = 0;
        u64 buckets, chain;

        if (kclf_urds_u32(di->gnu_hash, &nbuckets) || kclf_urds_u32(di->gnu_hash + 4, &symoffset) ||
            kclf_urds_u32(di->gnu_hash + 8, &bloom_size))
            return -1;
        if (!nbuckets || nbuckets > 65536 || bloom_size > 4096) return -1;
        buckets = di->gnu_hash + 16 + (u64)bloom_size * 8;
        for (i = 0; i < nbuckets; i++) {
            u32 v = 0;
            if (kclf_urds_u32(buckets + (u64)i * 4, &v)) return -1;
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
            if (kclf_urds_u32(chain + (u64)(best - symoffset) * 4, &h)) return -1;
            if (h & 1) break;
            if (++best >= KCLF_MAX_SYM) return -1;
        }
        *count = best + 1;
        return 0;
    }
    /* no hash table: bounded scan, the symbol table is followed by the string table */
    *count = (u32)(ei->end > di->symtab ? (ei->end - di->symtab) / sizeof(struct kclf_sym) : 0);
    if (*count > KCLF_MAX_SYM) *count = KCLF_MAX_SYM;
    (void)n;
    return 0;
}

static int kclf_elf_lookup(const struct kclf_elf *ei, const struct kclf_dyninfo *di, const char *name,
                           u64 *out_addr)
{
    u32 count = 0, i;
    size_t want = strlen(name);

    if (kclf_elf_symcount(ei, di, &count)) return -1;
    if (!di->symtab || di->symtab >= KCLF_USER_MAX) return -1;
    if (count && (u64)count > (KCLF_USER_MAX - di->symtab) / sizeof(struct kclf_sym)) return -1;
    for (i = 1; i < count; i++) {
        struct kclf_sym sym;
        char buf[128];
        u64 nameaddr;

        if (kclf_urds(di->symtab + (u64)i * sizeof(sym), &sym, sizeof(sym))) return -1;
        if (!sym.name || sym.name >= di->strsz) continue;
        if (!sym.value || sym.shndx == 0) continue; /* undefined */
        nameaddr = di->strtab + sym.name;
        if (kclf_urd_strs(nameaddr, buf, (int)sizeof(buf))) continue;
        buf[sizeof(buf) - 1] = 0;
        if (strncmp(buf, name, sizeof(buf)) != 0) continue;
        if (strlen(buf) != want) continue;
        *out_addr = ei->bias + sym.value;
        return 0;
    }
    return -1;
}

static int kclf_elf_soname(const struct kclf_elf *ei, const struct kclf_dyninfo *di, char *buf, int len)
{
    if (!di->soname) return -1;
    return kclf_urd_strs(di->strtab + di->soname, buf, len);
}

/* ------------------------------------------------------------------ */
/* loader discovery                                                     */
/* ------------------------------------------------------------------ */

struct kclf_vma
{
    u64 start;
    u64 end;
};

static int kclf_vma_at(struct mm_struct *mm, u64 addr, struct kclf_vma *out)
{
    struct vm_area_struct *vma;
    u64 start, end;

    vma = kclf_ks.find_vma(mm, addr);
    if (!vma) return -1;
    start = *(u64 *)((char *)vma + kclf_vma_off_start);
    end = *(u64 *)((char *)vma + kclf_vma_off_end);
    if (end <= start || end > KCLF_USER_MAX) return -1;
    out->start = start;
    out->end = end;
    return 0;
}

static long kclf_resolve(struct kclf_req *r)
{
    struct mm_struct *mm = kclf_task_mm(current);
    struct kclf_elf ldr, dl, libc;
    struct kclf_dyninfo ldr_di, dl_di;
    int have_ldr = 0, have_dl = 0, have_libc = 0;
    int have_ldr_di = 0, have_dl_di = 0;
    u64 addr = 0x1000;
    int i;
    int nelf = 0, ndyn = 0, nson = 0;

    if (!mm) return -ESRCH;
    memset(&ldr, 0, sizeof(ldr));
    memset(&dl, 0, sizeof(dl));
    memset(&libc, 0, sizeof(libc));

    for (i = 0; i < KCLF_MAX_VMA; i++) {
        struct kclf_vma vma;
        struct kclf_elf ei;
        struct kclf_dyninfo di;
        char soname[64];

        if (addr >= KCLF_USER_MAX) break;
        if (kclf_vma_at(mm, addr, &vma)) break;
        if (vma.start > addr) addr = vma.start;
        addr = vma.end;

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
        kclf_set_err(r, "resolve loader failed elf=%d dyn=%d son=%d ld=%d dl=%d libc=%d", nelf, ndyn, nson,
                     have_ldr, have_dl, have_libc);
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
    if (have_dl && (r->ld.fn < dl.start || r->ld.fn >= dl.end) && have_ldr &&
        (r->ld.fn < ldr.start || r->ld.fn >= ldr.end)) {
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
/* trampoline patching                                                  */
/* ------------------------------------------------------------------ */

/* movz/movk x19, #imm16, lsl #(16*hw); kept scalar and volatile so the
 * compiler cannot merge the four stores into a vector sequence */
static u32 kclf_movw(u32 hw, u32 chunk)
{
    u32 insn = (hw == 0) ? 0xd2800000u : 0xf2800000u; /* movz / movk x19 */
    insn += hw * 0x200000u;                           /* hw << 21 */
    insn += (chunk & 0xffffu) * 32u;                  /* imm16 << 5 */
    insn += 19u;                                      /* Rd = x19 */
    return insn;
}

static void kclf_patch_ptr(u32 *slot, u64 value)
{
    volatile u32 *p = slot;

    p[0] = kclf_movw(0, (u32)value);
    p[1] = kclf_movw(1, (u32)(value >> 16));
    p[2] = kclf_movw(2, (u32)(value >> 32));
    p[3] = kclf_movw(3, (u32)(value >> 48));
}

/* verify the patched sequence really materialises @expect in x19 */
static int kclf_verify_patch(const u32 *slot, u64 expect)
{
    u64 value = 0;
    int i;

    for (i = 0; i < 4; i++) {
        u32 insn = slot[i];
        u32 op = insn & 0xffe0001fu; /* opcode + hw + rd */
        u32 want = (i == 0) ? 0xd2800013u : (0xf2800013u + (u32)i * 0x200000u);
        if ((op & 0x7fe0001fu) != (want & 0x7fe0001fu)) return -1;
        value |= (u64)((insn >> 5) & 0xffff) << (16 * i);
    }
    return value == expect ? 0 : -1;
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
    if (n < (long)sizeof(hdr)) return -ENOEXEC;
    if (memcmp(hdr, kclf_elf_magic, 4)) return -ENOEXEC;
    if (hdr[4] != ELFCLASS64 || hdr[5] != ELFDATA2LSB) return -ENOEXEC;
    if (*(u16 *)(hdr + 18) != EM_AARCH64) return -ENOEXEC;
    if (*(u16 *)(hdr + 16) != ET_DYN) return -ENOEXEC;
    return 0;
}

long kclf_exec_prepare(struct kclf_req *r)
{
    struct mm_struct *mm = kclf_task_mm(current);
    u64 len;
    u64 addr;
    u64 code_len;
    u64 ptr_off;
    u8 pbuf[KCLF_P_SIZE];
    long rc;
    long mret;

    if (!mm) return -ESRCH;
    if (!kclf_page_size) return -EINVAL;

    rc = kclf_check_library(r->path);
    if (rc) {
        kclf_set_err(r, "open library failed rc=%ld", rc);
        return rc;
    }

    rc = kclf_resolve(r);
    if (rc) {
        if (!r->err[0]) kclf_set_err(r, "resolve loader failed rc=%ld", rc);
        return rc;
    }

    len = (u64)(2 + KCLF_STACK_PAGES) * kclf_page_size;
    addr = kclf_ks.vm_mmap(0, 0, len, KCLF_PROT_READ | KCLF_PROT_WRITE, KCLF_MAP_PRIVATE | KCLF_MAP_ANONYMOUS, 0);
    if (!addr || kclf_is_err((void *)addr)) {
        kclf_set_err(r, "mmap failed 0x%llx", (unsigned long long)addr);
        return addr ? (long)addr : -ENOMEM;
    }

    r->map_addr = addr;
    r->map_len = len;
    r->code_addr = addr;
    r->param_addr = addr + kclf_page_size;
    r->stack_top = addr + len;

    code_len = (u64)(kclf_tramp_end - kclf_tramp_start);
    ptr_off = (u64)(kclf_tramp_ptr_slot - kclf_tramp_start);
    if (!code_len || code_len > KCLF_CODE_MAX || ptr_off + 16 > code_len) {
        rc = -EINVAL;
        goto fail;
    }

    memset(r->codebuf, 0, KCLF_CODE_MAX);
    memcpy(r->codebuf, kclf_tramp_start, code_len);
    kclf_patch_ptr((u32 *)(r->codebuf + ptr_off), r->param_addr);
    if (kclf_verify_patch((const u32 *)(r->codebuf + ptr_off), r->param_addr)) {
        kclf_set_err(r, "trampoline patch verification failed");
        rc = -EFAULT;
        goto fail;
    }

    if (kclf_uwr(r->code_addr, r->codebuf, (int)code_len)) {
        kclf_set_err(r, "copy trampoline failed");
        rc = -EFAULT;
        goto fail;
    }

    memset(pbuf, 0, sizeof(pbuf));
    *(u64 *)(pbuf + KCLF_P_FN) = r->ld.fn;
    *(u64 *)(pbuf + KCLF_P_DLERROR) = r->ld.dlerror;
    *(u64 *)(pbuf + KCLF_P_DLCLOSE) = r->ld.dlclose;
    *(u64 *)(pbuf + KCLF_P_CALLER) = r->ld.caller;
    *(u64 *)(pbuf + KCLF_P_COOKIE) = r->cookie;
    *(u32 *)(pbuf + KCLF_P_FLAGS) = KCLF_RTLD_NOW;
    *(u32 *)(pbuf + KCLF_P_UNLOAD) = (r->flags & KCLF_F_UNLOAD) ? 1 : 0;
    strncpy((char *)pbuf + KCLF_P_PATH, r->path, KCLF_PATH_MAX - 1);

    if (kclf_uwr(r->param_addr, pbuf, sizeof(pbuf))) {
        kclf_set_err(r, "copy parameters failed");
        rc = -EFAULT;
        goto fail;
    }

    /* code page becomes read+execute, no RWX mapping is left behind */
    mret = raw_syscall3(__NR_mprotect, (long)r->code_addr, (long)kclf_page_size, KCLF_PROT_READ | KCLF_PROT_EXEC);
    if (mret) {
        kclf_set_err(r, "mprotect failed rc=%ld", mret);
        rc = mret;
        goto fail;
    }
    flush_icache_all();
    return 0;

fail:
    if (r->map_addr) {
        kclf_ks.vm_munmap(r->map_addr, r->map_len);
        r->map_addr = 0;
        r->map_len = 0;
    }
    return rc;
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
    if (regs->syscallno >= 0 && regs->syscallno != (s32)regs->regs[8]) return 0;
    return 1;
}

/* locate the pt_regs frame that will be consumed by the next exception return */
static struct pt_regs *kclf_find_regs(void)
{
    u64 stack = (u64)get_stack(current);
    u64 top = stack + (u64)thread_size;
    struct pt_regs *regs;
    u64 size;

    if (!stack || !top) return 0;

    /*
     * Do not depend on KernelPatch's _task_pt_reg export: older builds do not
     * export it and the KPM would fail to load.  The frame is always the last
     * sizeof(struct pt_regs) bytes below the thread stack top, so scan the
     * sizes used by the supported kernels and validate every candidate.
     */
    for (size = 288; size <= 400; size += 8) {
        regs = (struct pt_regs *)(top - size);
        if (kclf_regs_sane(regs, top)) return regs;
    }
    return 0;
}

/* syscalls that are known not to be issued from inside the allocator or the
 * linker critical sections; used to avoid a recursive dlopen deadlock */
static int kclf_syscall_safe(s32 nr)
{
    switch (nr) {
    case 22:  /* epoll_pwait */
    case 29:  /* ioctl */
    case 35:  /* unlinkat */
    case 61:  /* getdents64 */
    case 62:  /* lseek */
    case 63:  /* read */
    case 64:  /* write */
    case 65:  /* readv */
    case 66:  /* writev */
    case 73:  /* ppoll */
    case 79:  /* newfstatat */
    case 80:  /* fstat */
    case 82:  /* fsync */
    case 101: /* nanosleep */
    case 115: /* clock_nanosleep */
    case 124: /* sched_yield */
    case 135: /* rt_sigprocmask */
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
    if (regs->pstate & PSR_MODE32_BIT) return -EOPNOTSUPP;

    if (!(r->flags & KCLF_F_FORCE)) {
        /* never call the loader from inside the loader itself */
        if (r->ld.linker_base && regs->pc >= r->ld.linker_base && regs->pc < r->ld.linker_end) return -EAGAIN;
        if (regs->syscallno >= 0 && !kclf_syscall_safe(regs->syscallno)) return -EAGAIN;
        /*
         * A signal that really needs delivery would build its frame around the
         * hijacked context. The flag we raised ourselves in order to unblock the
         * task is not such a signal, so it does not disqualify this boundary.
         */
        tif = current_thread_info()->flags;
        if (tif & _TIF_NOTIFY_SIGNAL) return -EAGAIN;
        if ((tif & _TIF_SIGPENDING) && !r->woke) return -EAGAIN;
    }

    memcpy(&r->saved.regs[0], &regs->regs[0], 31 * sizeof(u64));
    r->saved.sp = regs->sp;
    r->saved.pc = regs->pc;
    r->saved.pstate = regs->pstate;
    r->saved_syscallno = regs->syscallno;
    r->saved_orig_x0 = regs->orig_x0;
    r->saved_valid = 1;

    /* only the two values that select the payload are changed; the register
     * file itself is restored verbatim on completion */
    regs->pc = r->code_addr + 4;
    regs->sp = r->stack_top;
    /* the payload entry is not a syscall return; keep the restart machinery away */
    regs->syscallno = -1;
    return 0;
}

#define KCLF_SVC0 0xd4000001u

/* is the instruction at @addr a syscall instruction? */
static int kclf_is_svc(u64 addr)
{
    u32 insn = 0;

    if (!addr || addr >= KCLF_USER_MAX) return 0;
    if (kclf_urd(addr, &insn, sizeof(insn))) return 0;
    return insn == KCLF_SVC0;
}

void kclf_exec_restore(struct kclf_req *r, struct pt_regs *regs)
{
    s64 x0 = (s64)r->saved.regs[0];

    if (!r->saved_valid) return;
    memcpy(&regs->regs[0], &r->saved.regs[0], 31 * sizeof(u64));
    regs->sp = r->saved.sp;
    regs->pc = r->saved.pc;
    regs->pstate = r->saved.pstate;

    /*
     * The trampoline ran from the signal boundary. If the interrupted syscall
     * returned one of the restart codes, arm64 do_signal() has usually already
     * rewound pc to the svc and reset x0 to orig_x0 before get_signal() is
     * entered; rewinding a second time would resume in the middle of the call
     * sequence. Tell the two cases apart by looking at the instruction the
     * saved pc points to.
     */
    regs->syscallno = r->saved_syscallno;
    if (r->saved_syscallno >= 0 && x0 >= -516 && x0 <= -512) {
        if (kclf_is_svc(r->saved.pc)) {
            /* already rewound: keep as is, re-executes the svc */
        } else if (kclf_is_svc(r->saved.pc - 4)) {
            regs->pc = r->saved.pc - 4;
            regs->regs[0] = r->saved_orig_x0;
            if (x0 == -516) regs->regs[8] = 219; /* __NR_restart_syscall */
            /* do_signal() would otherwise rewind a second time for this frame */
            regs->syscallno = -1;
        } else {
            /* neither position looks like a syscall: hand back the return
             * value the program would have seen */
            regs->regs[0] = -4; /* EINTR */
        }
    }
}

/* ------------------------------------------------------------------ */
/* result collection and teardown                                       */
/* ------------------------------------------------------------------ */

long kclf_exec_finish(struct kclf_req *r, int capture_err)
{
    long rc = 0;

    if (capture_err && r->err_user) {
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
            if (!mm || kclf_vma_at(mm, r->map_addr, &check)) rc = 0;
        }
        if (!rc) {
            r->map_addr = 0;
            r->map_len = 0;
        }
    }
    return rc;
}

/* ------------------------------------------------------------------ */
/* diagnostics                                                          */
/* ------------------------------------------------------------------ */

int kclf_exec_probe(char *out, int outlen)
{
    struct mm_struct *mm = kclf_task_mm(current);
    struct kclf_elf ldr, dl, libc;
    struct kclf_dyninfo di;
    int have_ldr = 0, have_dl = 0, have_libc = 0;
    u64 addr = 0x1000;
    u32 nvma = 0;
    u32 nelf = 0, ndyn = 0, nson = 0;
    int i;
    int off = 0;
    struct pt_regs *regs;
    u64 stack_top;

    if (!mm) return -ESRCH;
    memset(&ldr, 0, sizeof(ldr));
    memset(&dl, 0, sizeof(dl));
    memset(&libc, 0, sizeof(libc));

    for (i = 0; i < KCLF_MAX_VMA; i++) {
        struct kclf_vma vma;
        struct kclf_elf ei;
        struct kclf_dyninfo d;
        char soname[64];

        if (addr >= KCLF_USER_MAX) break;
        if (kclf_vma_at(mm, addr, &vma)) break;
        if (vma.start > addr) addr = vma.start;
        addr = vma.end;
        nvma++;
        if (kclf_elf_open(vma.start, &ei)) continue;
        nelf++;
        if (kclf_elf_dyninfo(&ei, &d)) continue;
        ndyn++;
        if (kclf_elf_soname(&ei, &d, soname, sizeof(soname))) continue;
        nson++;
        if (nson <= 10)
            off += snprintf(out + off, outlen - off, "  vma %llx soname=%s\n", (unsigned long long)vma.start,
                            soname);
        if (!have_ldr && !strcmp(soname, "ld-android.so")) {
            ldr = ei;
            have_ldr = 1;
        } else if (!have_dl && !strcmp(soname, "libdl.so")) {
            dl = ei;
            have_dl = 1;
        } else if (!have_libc && !strcmp(soname, "libc.so")) {
            libc = ei;
            have_libc = 1;
        }
    }

    off += snprintf(out + off, outlen - off, "vma scanned: %u elf=%u dyn=%u soname=%u\n", nvma, nelf, ndyn, nson);
    off += snprintf(out + off, outlen - off, "linker(ld-android.so): %s [%llx-%llx]\n", have_ldr ? "yes" : "no",
                    (unsigned long long)ldr.start, (unsigned long long)ldr.end);
    off += snprintf(out + off, outlen - off, "libdl.so: %s [%llx-%llx]\n", have_dl ? "yes" : "no",
                    (unsigned long long)dl.start, (unsigned long long)dl.end);
    off += snprintf(out + off, outlen - off, "libc.so: %s [%llx-%llx]\n", have_libc ? "yes" : "no",
                    (unsigned long long)libc.start, (unsigned long long)libc.end);

    if (have_ldr && !kclf_elf_dyninfo(&ldr, &di)) {
        u64 a = 0, b = 0;
        if (!kclf_elf_lookup(&ldr, &di, "__loader_dlopen", &a))
            off += snprintf(out + off, outlen - off, "__loader_dlopen: %llx\n", (unsigned long long)a);
        else
            off += snprintf(out + off, outlen - off, "__loader_dlopen: not found\n");
        if (!kclf_elf_lookup(&ldr, &di, "__loader_dlerror", &b))
            off += snprintf(out + off, outlen - off, "__loader_dlerror: %llx\n", (unsigned long long)b);
    }
    if (have_dl && !kclf_elf_dyninfo(&dl, &di)) {
        u64 a = 0;
        if (!kclf_elf_lookup(&dl, &di, "dlopen", &a))
            off += snprintf(out + off, outlen - off, "dlopen: %llx\n", (unsigned long long)a);
        else
            off += snprintf(out + off, outlen - off, "dlopen: not found\n");
    }

    stack_top = (u64)get_stack(current) + (u64)thread_size;
    regs = kclf_find_regs();
    off += snprintf(out + off, outlen - off, "pt_regs: %s off=%lld sane=%d scno=%d\n", regs ? "ok" : "missing",
                    regs ? (long long)(stack_top - (u64)regs) : -1LL, regs ? kclf_regs_sane(regs, stack_top) : 0,
                    regs ? regs->syscallno : -999);
    off += snprintf(out + off, outlen - off, "thread_size=%d page=%d wrapper=%d\n", thread_size, kclf_page_size,
                    has_syscall_wrapper);
    return off;
}

