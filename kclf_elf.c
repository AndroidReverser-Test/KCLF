/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "kclf_elf.h"
#ifdef KCLF_ELF_HOST
#include <string.h>
#include <errno.h>
#else
#include <linux/string.h>
#include <uapi/asm-generic/errno.h>
#endif

static int fail(struct ke_io *io, int rc, const char *why)
{
    if (io->error) io->error(io->ctx, why, "");
    return rc;
}

static int rd(struct ke_io *io, u64 at, void *p, unsigned long n)
{
    if (at >= io->limit || n > io->limit - at || io->read(io->ctx, at, p, n))
        return fail(io, -ENOEXEC, "ELF read out of bounds/failed");
    return 0;
}

int ke_contains(const struct ke_object *o, u64 at, u64 n, unsigned flags)
{
    unsigned i;
    if (at < o->bias) return 0;
    at -= o->bias;
    for (i = 0; i < o->phnum; i++) {
        const struct ke_phdr *p = &o->ph[i];
        if (p->type == 1 && (p->flags & flags) == flags && at >= p->vaddr &&
            at - p->vaddr < p->memsz && n <= p->memsz - (at - p->vaddr)) return 1;
    }
    return 0;
}

static int objrd(struct ke_io *io, const struct ke_object *o, u64 at, void *p, unsigned long n)
{
    if (!ke_contains(o, at, n, 4)) return fail(io, -ENOEXEC, "ELF table outside readable PT_LOAD");
    return rd(io, at, p, n);
}

/* loaded=0 is the strict file/payload contract: a payload has to be a complete
 * ET_DYN/EM_AARCH64 image.  loaded=1 is used while scanning target VMAs, which
 * does not prove that an object was accepted by the target's linker: a mapped
 * data file can also start with an ELF header.  Keep the architecture/type/
 * version checks unless e_ident[8..15] exactly matches the observed AArch64
 * ldr x16,#8; br x16 veneer.  That veneer's following address overwrites
 * e_type/e_machine/e_version.  All structural fields and later bounds remain
 * mandatory even for this recognized overwrite. */
static int ke_headers_impl(struct ke_io *io, u64 header, struct ke_object *o, int loaded)
{
    struct ke_ehdr h;
    unsigned i;
    memset(o, 0, sizeof(*o));
    if (rd(io, header, &h, sizeof(h))) return -ENOEXEC;
    if (memcmp(h.ident, "\177ELF\2\1\1", 7))
        return fail(io, -ENOEXEC, loaded ? "loaded image is not ELF64 little-endian"
                                         : "expected bounded ELF64 little-endian AArch64 ET_DYN");
    if ((h.type != 3 || h.machine != 183 || h.version != 1) &&
        !(loaded && !memcmp(h.ident + 8, "\x50\x00\x00\x58\x00\x02\x1f\xd6", 8)))
        return fail(io, -ENOEXEC, "expected bounded ELF64 little-endian AArch64 ET_DYN");
    if (h.ehsize != sizeof(h) || h.phentsize != sizeof(struct ke_phdr) || !h.phnum || h.phnum > KE_PHNUM ||
        h.phoff < sizeof(h) || h.phoff > 1024 * 1024 || h.phoff > io->limit - header)
        return fail(io, -ENOEXEC, loaded ? "loaded ELF header is structurally invalid" : "expected bounded ELF64 little-endian AArch64 ET_DYN");
    o->phnum = h.phnum;
    o->header = header;
    if (rd(io, header + h.phoff, o->ph, h.phnum * sizeof(o->ph[0]))) return -ENOEXEC;
    o->low = ~0ULL;
    o->alignment = 1;
    for (i = 0; i < o->phnum; i++) {
        struct ke_phdr *p = &o->ph[i];
        if (p->vaddr >= io->limit || p->memsz > io->limit - p->vaddr || p->filesz > p->memsz)
            return fail(io, -ENOEXEC, "invalid program-header size");
        if (p->type == 7) o->tls = 1;
        if (p->type != 1 || !p->memsz) continue;
        if (p->align > 1 && ((p->align & (p->align - 1)) || (p->offset % p->align != p->vaddr % p->align)))
            return fail(io, -ENOEXEC, "invalid PT_LOAD alignment");
        if (p->vaddr < o->low) o->low = p->vaddr;
        if (p->vaddr + p->memsz > o->high) o->high = p->vaddr + p->memsz;
        if (p->align > o->alignment) o->alignment = p->align;
    }
    if (o->low == ~0ULL || o->high <= o->low || o->high - o->low > KE_IMAGE_MAX || o->alignment > KE_IMAGE_MAX)
        return fail(io, -E2BIG, "ELF image/alignment limit exceeded");
    return 0;
}

int ke_headers(struct ke_io *io, u64 header, struct ke_object *o)
{
    return ke_headers_impl(io, header, o, 0);
}

int ke_file_layout(struct ke_io *io, struct ke_object *o, u64 size, u64 page)
{
    unsigned i, j;
    int header = 0;
    if (!page || (page & (page - 1))) return -EINVAL;
    if (o->tls) return fail(io, -EOPNOTSUPP, "payload PT_TLS is not supported");
    for (i = 0; i < o->phnum; i++) {
        const struct ke_phdr *p = &o->ph[i];
        u64 first, last;
        if (p->offset > size || p->filesz > size - p->offset)
            return fail(io, -ENOEXEC, "program header exceeds file snapshot");
        if (p->type == 0x6474e553U) {
            /* GNU properties can require BTI, PAC or other ABI handling. Do
             * not silently execute an image with an unimplemented contract. */
            return fail(io, -EOPNOTSUPP, "PT_GNU_PROPERTY payload ABI unsupported");
        }
        if (p->type == 3) return fail(io, -EOPNOTSUPP, "PT_INTERP executable is not a payload");
        if (p->type == 0x6474e551U && (p->flags & 1))
            return fail(io, -EOPNOTSUPP, "executable PT_GNU_STACK unsupported");
        if (p->type != 1 || !p->memsz) continue;
        if (!(p->flags & 4) || (p->flags & ~7U) || (p->flags & 3) == 3)
            return fail(io, -EOPNOTSUPP, "non-readable or writable-executable PT_LOAD");
        if (p->offset % page != p->vaddr % page)
            return fail(io, -ENOEXEC, "PT_LOAD does not match device page alignment");
        if (!p->offset && p->filesz >= sizeof(struct ke_ehdr)) header++;
        first = p->vaddr & ~(page - 1);
        last = (p->vaddr + p->memsz + page - 1) & ~(page - 1);
        for (j = 0; j < i; j++) {
            const struct ke_phdr *q = &o->ph[j];
            if (q->type != 1 || !q->memsz) continue;
            if (first < ((q->vaddr + q->memsz + page - 1) & ~(page - 1)) &&
                (q->vaddr & ~(page - 1)) < last)
                return fail(io, -EOPNOTSUPP, "overlapping PT_LOAD pages are not supported");
        }
    }
    if (header != 1) return fail(io, -ENOEXEC, "ELF needs exactly one offset-zero load segment");
    o->low &= ~(page - 1);
    o->high = (o->high + page - 1) & ~(page - 1);
    if (o->alignment < page) o->alignment = page;
    return 0;
}

int ke_string(struct ke_io *io, const struct ke_object *o, u32 off, char out[KE_NAME])
{
    unsigned i;
    if (off >= o->strsz) return fail(io, -ENOEXEC, "string offset outside DT_STRTAB");
    for (i = 0; i < KE_NAME; i++) {
        if (i >= o->strsz - off || objrd(io, o, o->strtab + off + i, out + i, 1)) return -ENOEXEC;
        if (!out[i]) return 0;
    }
    return fail(io, -E2BIG, "ELF symbol/SONAME/version name exceeds 255 bytes");
}

static int symcount(struct ke_io *io, struct ke_object *o)
{
    u32 h[4], i, best = 0;
    u64 buckets, chain;
    if (o->hash) {
        if (objrd(io, o, o->hash, h, 8)) return -ENOEXEC;
        if (!h[0] || !h[1] || h[0] > KE_SYMS || h[1] > KE_SYMS ||
            !ke_contains(o, o->hash, (2ULL + h[0] + h[1]) * 4, 4)) return -ENOEXEC;
        o->symcount = h[1];
    } else if (o->gnu_hash) {
        if (objrd(io, o, o->gnu_hash, h, sizeof(h))) return -ENOEXEC;
        if (!h[0] || h[0] > KE_SYMS || h[1] > KE_SYMS || !h[2] || h[2] > KE_SYMS || h[3] >= 64)
            return -ENOEXEC;
        buckets = o->gnu_hash + 16 + (u64)h[2] * 8;
        if (!ke_contains(o, o->gnu_hash, 16ULL + (u64)h[2] * 8 + (u64)h[0] * 4, 4)) return -ENOEXEC;
        for (i = 0; i < h[0]; i++) {
            u32 b;
            if (objrd(io, o, buckets + (u64)i * 4, &b, 4) || b >= KE_SYMS) return -ENOEXEC;
            if (b > best) best = b;
        }
        chain = buckets + (u64)h[0] * 4;
        if (!best) o->symcount = h[1];
        else {
            if (best < h[1]) return -ENOEXEC;
            for (;;) {
                u32 v;
                if (objrd(io, o, chain + (u64)(best - h[1]) * 4, &v, 4)) return -ENOEXEC;
                if (v & 1) break;
                if (++best >= KE_SYMS) return -E2BIG;
            }
            o->symcount = best + 1;
        }
    } else return fail(io, -EOPNOTSUPP, "dynamic object has neither DT_HASH nor DT_GNU_HASH");
    if (!o->symcount || !ke_contains(o, o->symtab, (u64)o->symcount * sizeof(struct ke_sym), 4)) return -ENOEXEC;
    return 0;
}

int ke_open(struct ke_io *io, u64 header, struct ke_object *o, int payload)
{
    u64 dyn = 0, dynsz = 0, syment = 0, relaent = 24, relrent = 8, pltrel = 7;
    unsigned i, bases = 0;
    int ended = 0, rc;
    /* VMA candidates keep the strict contract except for the recognized
     * header veneer; the scan alone does not establish linker provenance.
     * Payload images always keep the ET_DYN/EM_AARCH64/version contract. */
    if ((rc = ke_headers_impl(io, header, o, !payload))) return rc;
    for (i = 0; i < o->phnum; i++) {
        const struct ke_phdr *p = &o->ph[i];
        if (p->type == 1 && !p->offset && p->filesz >= sizeof(struct ke_ehdr)) {
            if (p->vaddr > header || ++bases != 1) return -ENOEXEC;
            o->bias = header - p->vaddr;
        }
        if (p->type == 2) {
            if (dynsz) return fail(io, -ENOEXEC, "multiple PT_DYNAMIC segments");
            dyn = p->vaddr;
            dynsz = p->memsz;
        }
    }
    if (!bases || o->high >= io->limit || o->bias >= io->limit - o->high || !dynsz ||
        dynsz / sizeof(struct ke_dyn) > 4096 || !ke_contains(o, o->bias + dyn, dynsz, 4)) return -ENOEXEC;
    if (payload && o->tls) return fail(io, -EOPNOTSUPP, "payload PT_TLS is not supported");
    for (i = 0; i < dynsz / sizeof(struct ke_dyn); i++) {
        struct ke_dyn d;
        if (objrd(io, o, o->bias + dyn + i * sizeof(d), &d, sizeof(d))) return -ENOEXEC;
        if (!d.tag) { ended = 1; break; }
#define PTR(tag, field) case tag: if (o->field || d.val >= io->limit - o->bias) return -ENOEXEC; o->field = o->bias + d.val; break
#define VAL(tag, field) case tag: if (o->field) return -ENOEXEC; o->field = d.val; break
        switch (d.tag) {
        case 1:
            if (o->nneeded == KE_NEEDED || d.val > 0xffffffffU) return -E2BIG;
            o->needed[o->nneeded++] = (u32)d.val;
            break;
        PTR(4, hash); PTR(5, strtab); PTR(6, symtab); PTR(7, rela);
        VAL(8, relasz); case 9: relaent = d.val; break;
        VAL(10, strsz); case 11: syment = d.val; break;
        PTR(12, init); PTR(13, fini);
        case 14:
            if (o->soname || d.val > 0xffffffffU) return -ENOEXEC;
            o->soname = (u32)d.val;
            break;
        case 16: o->symbolic = 1; break;
        case 20: pltrel = d.val; break;
        PTR(23, jmprel); VAL(2, pltsz);
        PTR(25, init_array); PTR(26, fini_array); VAL(27, init_count); VAL(28, fini_count);
        VAL(30, flags); VAL(0x6ffffffb, flags1);
        case 36: case 0x6fffe000:
            if (o->relr || d.val >= io->limit - o->bias) return -ENOEXEC;
            o->relr = o->bias + d.val;
            break;
        VAL(35, relrsz); case 0x6fffe001: if (o->relrsz) return -ENOEXEC; o->relrsz = d.val; break;
        case 37: case 0x6fffe003: relrent = d.val; break;
        PTR(0x60000011, packed); VAL(0x60000012, packedsz);
        PTR(0x6ffffef5, gnu_hash); PTR(0x6ffffff0, versym);
        PTR(0x6ffffffe, verneed); VAL(0x6fffffff, verneednum);
        PTR(0x6ffffffc, verdef); VAL(0x6ffffffd, verdefnum);
        case 17: case 18: case 19: case 22: case 0x6000000f: case 0x60000010:
        case 0x7fffffff: case 0x7ffffffd: case 32: case 33:
            if (payload) return fail(io, -EOPNOTSUPP, "REL/textrel/filter/preinit dynamic tag unsupported");
            break;
        default: break;
        }
#undef PTR
#undef VAL
    }
    if (!ended || !o->strtab || !o->symtab || !o->strsz || syment != sizeof(struct ke_sym) ||
        !ke_contains(o, o->strtab, o->strsz, 4) || o->verneednum > 256 || o->verdefnum > 4096 ||
        (!!o->verneed != !!o->verneednum) || (!!o->verdef != !!o->verdefnum)) return -ENOEXEC;
    if ((rc = symcount(io, o))) return fail(io, rc, "invalid dynamic symbol/hash table");
    if (o->versym && !ke_contains(o, o->versym, (u64)o->symcount * 2, 4)) return -ENOEXEC;
    if (!payload) return 0;
    if (o->flags & ~(1ULL | 2ULL | 8ULL)) return fail(io, -EOPNOTSUPP, "unsupported DT_FLAGS (including TEXTREL/STATIC_TLS)");
    if (o->flags1 & ~(1ULL | 8ULL)) return fail(io, -EOPNOTSUPP, "unsupported DT_FLAGS_1 semantics");
    if (o->flags & 2) o->symbolic = 1;
    if (relaent != 24 || relrent != 8 || pltrel != 7 || o->relasz % 24 || o->pltsz % 24 || o->relrsz % 8 ||
        o->init_count % 8 || o->fini_count % 8 || o->init_count > 8192 || o->fini_count > 8192 ||
        o->relasz / 24 + o->pltsz / 24 + o->relrsz / 8 > KE_RELOCS || o->packedsz > 16 * 1024 * 1024)
        return fail(io, -ENOEXEC, "invalid relocation/initializer dimensions");
#define TABLE(ptr, bytes) if ((!!o->ptr != !!o->bytes) || (o->bytes && !ke_contains(o, o->ptr, o->bytes, 4))) return -ENOEXEC
    TABLE(rela, relasz); TABLE(jmprel, pltsz); TABLE(packed, packedsz); TABLE(relr, relrsz);
    TABLE(init_array, init_count); TABLE(fini_array, fini_count);
#undef TABLE
    if ((o->init && !ke_contains(o, o->init, 4, 1)) || (o->fini && !ke_contains(o, o->fini, 4, 1))) return -ENOEXEC;
    o->init_count /= 8;
    o->fini_count /= 8;
    return 0;
}

int ke_symbol(struct ke_io *io, const struct ke_object *o, u32 i, struct ke_sym *s)
{
    if (i >= o->symcount) return fail(io, -ENOEXEC, "relocation symbol index out of bounds");
    return objrd(io, o, o->symtab + (u64)i * sizeof(*s), s, sizeof(*s));
}

int ke_required_version(struct ke_io *io, const struct ke_object *o, u32 index, char out[KE_NAME], u32 *hash)
{
    u16 v = 0;
    u64 at = o->verneed;
    unsigned i;
    out[0] = 0; *hash = 0;
    if (!o->versym) return 0;
    if (index >= o->symcount || objrd(io, o, o->versym + (u64)index * 2, &v, 2)) return -ENOEXEC;
    v &= 0x7fff;
    if (v < 2) return 0;
    for (i = 0; i < o->verneednum; i++) {
        struct ke_verneed n;
        u64 aux;
        unsigned j;
        if (objrd(io, o, at, &n, sizeof(n)) || n.version != 1 || !n.cnt || n.cnt > 256 || n.aux < sizeof(n)) return -ENOEXEC;
        aux = at + n.aux;
        for (j = 0; j < n.cnt; j++) {
            struct ke_vernaux a;
            if (objrd(io, o, aux, &a, sizeof(a))) return -ENOEXEC;
            if ((a.other & 0x7fff) == v) { *hash = a.hash; return ke_string(io, o, a.name, out); }
            if (j + 1 < n.cnt && a.next < sizeof(a)) return -ENOEXEC;
            aux += a.next;
        }
        if (i + 1 < o->verneednum && n.next < sizeof(n)) return -ENOEXEC;
        at += n.next;
    }
    return fail(io, -ENOEXEC, "missing version requirement record");
}

static int version_match(struct ke_io *io, const struct ke_object *o, u32 index, const char *want, u32 hash)
{
    u16 v = 1;
    unsigned i;
    u64 at = o->verdef;
    if (o->versym && objrd(io, o, o->versym + (u64)index * 2, &v, 2)) return -ENOEXEC;
    if (!want[0]) return !(v & 0x8000) && (v & 0x7fff) != 0;
    v &= 0x7fff;
    if (v < 2) return 0;
    for (i = 0; i < o->verdefnum; i++) {
        struct ke_verdef d;
        if (objrd(io, o, at, &d, sizeof(d)) || d.version != 1 || !d.cnt || d.aux < sizeof(d)) return -ENOEXEC;
        if ((d.ndx & 0x7fff) == v) {
            struct ke_verdaux a;
            char name[KE_NAME];
            if (d.hash != hash) return 0;
            if (objrd(io, o, at + d.aux, &a, sizeof(a)) || ke_string(io, o, a.name, name)) return -ENOEXEC;
            return !strcmp(name, want);
        }
        if (i + 1 < o->verdefnum && d.next < sizeof(d)) return -ENOEXEC;
        at += d.next;
    }
    return fail(io, -ENOEXEC, "missing version definition record");
}

static u32 elf_hash(const char *name)
{
    u32 h = 0, g;
    while (*name) { h = (h << 4) + (u8)*name++; g = h & 0xf0000000U; h ^= g >> 24; h &= ~g; }
    return h;
}

static int candidate(struct ke_io *io, const struct ke_object *o, u32 index, const char *name,
                     const char *version, u32 hash, struct ke_sym *s, u64 *address)
{
    char actual[KE_NAME];
    int v;
    unsigned type, bind;
    if (ke_symbol(io, o, index, s)) return -ENOEXEC;
    bind = s->info >> 4; type = s->info & 15;
    if (!s->shndx || (bind != 1 && bind != 2 && bind != 10) || (s->other & 3) == 1 || (s->other & 3) == 2) return 0;
    if (ke_string(io, o, s->name, actual)) return -ENOEXEC;
    if (strcmp(actual, name)) return 0;
    v = version_match(io, o, index, version, hash);
    if (v <= 0) return v;
    if (bind == 10 || (type != 0 && type != 1 && type != 2 && type != 10)) {
        if (io->error) io->error(io->ctx, "unsupported GNU_UNIQUE/TLS symbol", name);
        return -EOPNOTSUPP;
    }
    if (s->shndx == 0xfff1) { *address = s->value; return 1; }
    if (s->shndx >= 0xff00 || s->value >= io->limit - o->bias) return -ENOEXEC;
    *address = o->bias + s->value;
    if (!ke_contains(o, *address, s->size ? s->size : 1, (type == 2 || type == 10) ? 1 : 0)) return -ENOEXEC;
    return 1;
}

int ke_lookup(struct ke_io *io, const struct ke_object *o, const char *name, const char *version,
              u32 hash, struct ke_sym *s, u64 *address)
{
    u32 h[4], index, steps = 0;
    u64 chains;
    if (o->gnu_hash) {
        u32 gh = 5381, ch;
        const char *p;
        for (p = name; *p; p++) gh = gh * 33 + (u8)*p;
        if (objrd(io, o, o->gnu_hash, h, sizeof(h)) || !h[0] || !h[2] || h[0] > KE_SYMS || h[2] > KE_SYMS) return -ENOEXEC;
        chains = o->gnu_hash + 16 + (u64)h[2] * 8 + (u64)h[0] * 4;
        if (objrd(io, o, o->gnu_hash + 16 + (u64)h[2] * 8 + (u64)(gh % h[0]) * 4, &index, 4)) return -ENOEXEC;
        if (!index) return 0;
        if (index < h[1]) return -ENOEXEC;
        for (;;) {
            int rc;
            if (index >= o->symcount || ++steps > o->symcount ||
                objrd(io, o, chains + (u64)(index - h[1]) * 4, &ch, 4)) return -ENOEXEC;
            if ((ch | 1U) == (gh | 1U)) {
                rc = candidate(io, o, index, name, version, hash, s, address);
                if (rc) return rc;
            }
            if (ch & 1) return 0;
            index++;
        }
    }
    if (!o->hash || objrd(io, o, o->hash, h, 8) || !h[0] || h[0] > KE_SYMS || h[1] != o->symcount) return -ENOEXEC;
    if (objrd(io, o, o->hash + 8 + (u64)(elf_hash(name) % h[0]) * 4, &index, 4)) return -ENOEXEC;
    chains = o->hash + 8 + (u64)h[0] * 4;
    while (index) {
        int rc;
        if (index >= o->symcount || ++steps > o->symcount) return -ENOEXEC;
        rc = candidate(io, o, index, name, version, hash, s, address);
        if (rc) return rc;
        if (objrd(io, o, chains + (u64)index * 4, &index, 4)) return -ENOEXEC;
    }
    return 0;
}

static int relocate_one(struct ke_io *io, const struct ke_object *o, const struct ke_rela *r,
                        ke_resolve_fn resolve, void *ctx)
{
    u32 type = (u32)r->info, sym = r->info >> 32;
    u64 at, value = 0;
    int rc;
    if (!type) return 0;
    if (r->offset >= io->limit - o->bias) return -ENOEXEC;
    at = o->bias + r->offset;
    if ((at & 7) || !ke_contains(o, at, 8, 2)) return fail(io, -ENOEXEC, "relocation target outside writable PT_LOAD");
    switch (type) {
    case 1027: /* R_AARCH64_RELATIVE */
        if (sym) return -ENOEXEC;
        value = o->bias;
        break;
    case 257: case 1025: case 1026: /* ABS64/GLOB_DAT/JUMP_SLOT */
        if (sym && (rc = resolve(ctx, sym, &value))) {
            if (rc == 1 && io->defer_ifunc) return io->defer_ifunc(io->ctx, at, sym, r->addend);
            return rc < 0 ? rc : -EOPNOTSUPP;
        }
        break;
    default: return fail(io, -EOPNOTSUPP, "unsupported AArch64 relocation (TLS/IFUNC/textrel)");
    }
    value += (u64)r->addend; /* ELF specifies modular address arithmetic. */
    if (!io->write || io->write(io->ctx, at, &value, 8)) return fail(io, -EFAULT, "relocation write failed");
    return 0;
}

struct packed_cursor { u64 at, end; };
static int sleb(struct ke_io *io, struct packed_cursor *c, s64 *result)
{
    u64 v = 0;
    unsigned i;
    for (i = 0; i < 10; i++) {
        u8 b;
        if (c->at == c->end || rd(io, c->at++, &b, 1)) return -ENOEXEC;
        if (i == 9 && b != 0 && b != 0x7f) return -ENOEXEC;
        v |= (u64)(b & 0x7f) << (i * 7);
        if (!(b & 0x80)) {
            if (i < 9 && (b & 0x40)) v |= ~0ULL << ((i + 1) * 7);
            *result = (s64)v;
            return 0;
        }
    }
    return -ENOEXEC;
}

static int packed(struct ke_io *io, const struct ke_object *o, ke_resolve_fn resolve, void *ctx, u64 *writes)
{
    struct packed_cursor c = {o->packed + 4, o->packed + o->packedsz};
    struct ke_rela r = {0, 0, 0};
    s64 count, start, done = 0;
    char magic[4];
    if (o->packedsz < 6 || objrd(io, o, o->packed, magic, 4) || memcmp(magic, "APS2", 4) ||
        sleb(io, &c, &count) || sleb(io, &c, &start) || count < 0 || count > KE_RELOCS || start < 0) return -ENOEXEC;
    if ((u64)count > KE_RELOCS - *writes) return -E2BIG;
    *writes += (u64)count;
    r.offset = (u64)start;
    while (done < count) {
        s64 n, flags, delta = 0, info = 0, add = 0, i;
        if (sleb(io, &c, &n) || sleb(io, &c, &flags) || n <= 0 || n > count - done || flags < 0 ||
            (flags & ~15) || ((flags & 4) && !(flags & 8))) return -ENOEXEC;
        if ((flags & 2) && sleb(io, &c, &delta)) return -ENOEXEC;
        if ((flags & 1) && (sleb(io, &c, &info) || info < 0)) return -ENOEXEC;
        if ((flags & 12) == 12) {
            if (sleb(io, &c, &add)) return -ENOEXEC;
            r.addend = (s64)((u64)r.addend + (u64)add);
        } else if (!(flags & 8)) r.addend = 0;
        for (i = 0; i < n; i++) {
            int rc;
            if (!(flags & 2) && sleb(io, &c, &delta)) return -ENOEXEC;
            r.offset += (u64)delta;
            if (!(flags & 1) && (sleb(io, &c, &info) || info < 0)) return -ENOEXEC;
            r.info = (u64)info;
            if ((flags & 12) == 8) {
                if (sleb(io, &c, &add)) return -ENOEXEC;
                r.addend = (s64)((u64)r.addend + (u64)add);
            }
            if ((rc = relocate_one(io, o, &r, resolve, ctx))) return rc;
        }
        done += n;
    }
    return c.at == c.end ? 0 : -ENOEXEC;
}

static int relr_one(struct ke_io *io, const struct ke_object *o, u64 offset)
{
    u64 at, value;
    if (offset >= io->limit - o->bias || (offset & 7)) return -ENOEXEC;
    at = o->bias + offset;
    if (!ke_contains(o, at, 8, 2) || objrd(io, o, at, &value, 8)) return -ENOEXEC;
    value += o->bias;
    return io->write(io->ctx, at, &value, 8) ? -EFAULT : 0;
}

int ke_relocate(struct ke_io *io, const struct ke_object *o, ke_resolve_fn resolve, void *ctx)
{
    u64 i, where = 0, writes = 0;
    int have_where = 0, rc;
    if (!io->write || !resolve) return -EINVAL;
    /* RELR precedes other relocations. No IFUNC execution is permitted here. */
    for (i = 0; i < o->relrsz / 8; i++) {
        u64 entry;
        if (objrd(io, o, o->relr + i * 8, &entry, 8)) return -ENOEXEC;
        if (!(entry & 1)) {
            if (++writes > KE_RELOCS) return -E2BIG;
            if ((have_where && entry < where) || (rc = relr_one(io, o, entry))) return -ENOEXEC;
            where = entry + 8; have_where = 1;
        } else {
            unsigned bit;
            if (!have_where || where > io->limit - 63 * 8) return -ENOEXEC;
            for (bit = 1; bit < 64; bit++) if (entry & (1ULL << bit)) {
                if (++writes > KE_RELOCS || (rc = relr_one(io, o, where + (bit - 1) * 8))) return -ENOEXEC;
            }
            where += 63 * 8;
        }
    }
    if (o->packedsz && (rc = packed(io, o, resolve, ctx, &writes))) return fail(io, rc, "invalid/unsupported APS2 relocations");
    if (o->relasz / 24 > KE_RELOCS - writes) return -E2BIG;
    writes += o->relasz / 24;
    if (o->pltsz / 24 > KE_RELOCS - writes) return -E2BIG;
    for (i = 0; i < o->relasz / 24 + o->pltsz / 24; i++) {
        struct ke_rela r;
        u64 at = i < o->relasz / 24 ? o->rela + i * 24 : o->jmprel + (i - o->relasz / 24) * 24;
        if (objrd(io, o, at, &r, sizeof(r))) return -ENOEXEC;
        if ((rc = relocate_one(io, o, &r, resolve, ctx))) return rc;
    }
    return 0;
}
