/* Host-only tests of the exact ELF parser/relocator linked into the KPM. */
#include "kclf_elf.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BASE 0x10000000ULL
#define CAP (1024 * 1024)
static unsigned char memory[CAP], snapshot[CAP];
static size_t file_size;
static int file_mode, errors, resolutions;
static int deferred, defer_error;
static char last_error[512];
static int read_mem(void *c, u64 at, void *out, unsigned long n)
{
    (void)c;
    if (file_mode) {
        if (at > file_size || n > file_size - at) return -1;
        memcpy(out, snapshot + at, n);
    } else {
        if (at < BASE || at - BASE > CAP || n > CAP - (at - BASE)) return -1;
        memcpy(out, memory + at - BASE, n);
    }
    return 0;
}
static int write_mem(void *c, u64 at, const void *in, unsigned long n)
{
    (void)c;
    if (at < BASE || at - BASE > CAP || n > CAP - (at - BASE)) return -1;
    memcpy(memory + at - BASE, in, n);
    return 0;
}
static void error(void *c, const char *why, const char *detail)
{
    (void)c;
    errors++;
    snprintf(last_error, sizeof(last_error), "%s %s", why, detail);
}
static struct ke_io io = {0, 1ULL << 48, read_mem, write_mem, error, 0};
static int resolve(void *c, u32 index, u64 *out)
{
    (void)c;
    assert(index < KE_SYMS);
    *out = 0x20000000 + index * 16;
    resolutions++;
    return 0;
}
static int resolve_ifunc(void *c, u32 index, u64 *out)
{
    resolve(c, index, out);
    return 1;
}
static int defer_ifunc(void *c, u64 at, u32 index, s64 addend)
{
    (void)c;
    assert(at == BASE + 0x2000 && index == 1 && addend == -8);
    deferred++;
    return defer_error;
}
static void init_fixture(void)
{
    struct ke_ehdr *h = (void *)memory;
    struct ke_phdr *p = (void *)(memory + 64);
    struct ke_dyn *d = (void *)(memory + 0x200);
    struct ke_sym *s = (void *)(memory + 0x600);
    u32 *hash = (void *)(memory + 0xa00);
    memset(memory, 0, sizeof(memory));
    memcpy(h->ident, "\177ELF\2\1\1", 7);
    h->type = 3; h->machine = 183; h->version = 1; h->ehsize = 64;
    h->phoff = 64; h->phnum = 4; h->phentsize = 56;
    p[0] = (struct ke_phdr){1, 4, 0, 0, 0, 0x1000, 0x1000, 0x1000};
    p[1] = (struct ke_phdr){1, 6, 0x1000, 0x2000, 0, 0x1000, 0x1000, 0x1000};
    p[2] = (struct ke_phdr){1, 5, 0x2000, 0x4000, 0, 0x1000, 0x1000, 0x1000};
    p[3] = (struct ke_phdr){2, 4, 0x200, 0x200, 0, 0x200, 0x200, 8};
    d[0] = (struct ke_dyn){6, 0x600}; d[1] = (struct ke_dyn){5, 0x800};
    d[2] = (struct ke_dyn){10, 256}; d[3] = (struct ke_dyn){11, 24};
    d[4] = (struct ke_dyn){4, 0xa00};
    memcpy(memory + 0x800, "\0fun\0data\0V1\0libdep.so\0", 23);
    s[1] = (struct ke_sym){1, 0x12, 0, 1, 0x4000, 4};
    s[2] = (struct ke_sym){5, 0x11, 0, 1, 0x2100, 8};
    hash[0] = 1; hash[1] = 3; hash[2] = 1; hash[3] = 0; hash[4] = 2; hash[5] = 0;
    file_mode = 0; errors = 0; resolutions = 0;
}
static void symbol_tests(void)
{
    struct ke_object o;
    struct ke_sym s;
    u64 value;
    init_fixture();
    assert(!ke_open(&io, BASE, &o, 1));
    assert(ke_lookup(&io, &o, "fun", "", 0, &s, &value) == 1 && value == BASE + 0x4000);
    assert(ke_lookup(&io, &o, "data", "", 0, &s, &value) == 1 && value == BASE + 0x2100);
    assert(!ke_lookup(&io, &o, "missing", "", 0, &s, &value));
    ((struct ke_sym *)(memory + 0x600))[1].other = 2;
    assert(!ke_lookup(&io, &o, "fun", "", 0, &s, &value));
    ((struct ke_sym *)(memory + 0x600))[1].other = 0;
    ((struct ke_sym *)(memory + 0x600))[1].info = 0x1a;
    assert(ke_lookup(&io, &o, "fun", "", 0, &s, &value) == 1 && (s.info & 15) == 10);
    ((struct ke_sym *)(memory + 0x600))[1].info = 0x16;
    assert(ke_lookup(&io, &o, "fun", "", 0, &s, &value) == -EOPNOTSUPP);
    ((struct ke_sym *)(memory + 0x600))[1].info = 0x12;
    /* VERSYM + VERDEF: named versions and hidden versions. */
    o.versym = BASE + 0xb00; o.verdef = BASE + 0xb10; o.verdefnum = 1;
    ((u16 *)(memory + 0xb00))[1] = 2;
    *(struct ke_verdef *)(memory + 0xb10) = (struct ke_verdef){1, 0, 2, 1, 1234, 20, 0};
    *(struct ke_verdaux *)(memory + 0xb24) = (struct ke_verdaux){10, 0};
    assert(ke_lookup(&io, &o, "fun", "V1", 1234, &s, &value) == 1);
    assert(!ke_lookup(&io, &o, "fun", "V2", 1234, &s, &value));
    ((u16 *)(memory + 0xb00))[1] = 0x8002;
    assert(!ke_lookup(&io, &o, "fun", "", 0, &s, &value));
    assert(ke_lookup(&io, &o, "fun", "V1", 1234, &s, &value) == 1);
    o.verneed = BASE + 0xc00; o.verneednum = 1;
    *(struct ke_verneed *)(memory + 0xc00) = (struct ke_verneed){1, 1, 13, 16, 0};
    *(struct ke_vernaux *)(memory + 0xc10) = (struct ke_vernaux){1234, 0, 2, 10, 0};
    char name[KE_NAME]; u32 hash;
    assert(!ke_required_version(&io, &o, 1, name, &hash) && !strcmp(name, "V1") && hash == 1234);
    ((struct ke_vernaux *)(memory + 0xc10))->other = 3;
    assert(ke_required_version(&io, &o, 1, name, &hash));
    puts("manual symbol/data/visibility/IFUNC/TLS/version matching: PASS");
}
static void relocation_tests(void)
{
    struct ke_object o;
    struct ke_rela *r = (void *)(memory + 0xe00);
    init_fixture(); assert(!ke_open(&io, BASE, &o, 1));
    o.rela = BASE + 0xe00; o.relasz = 4 * 24;
    r[0] = (struct ke_rela){0x2000, 1027, 0x4000};
    r[1] = (struct ke_rela){0x2008, (1ULL << 32) | 1026, 4};
    r[2] = (struct ke_rela){0x2010, (2ULL << 32) | 1025, 8};
    r[3] = (struct ke_rela){0x2018, (2ULL << 32) | 257, -8};
    assert(!ke_relocate(&io, &o, resolve, 0) && resolutions == 3);
    assert(*(u64 *)(memory + 0x2000) == BASE + 0x4000);
    assert(*(u64 *)(memory + 0x2008) == 0x20000014);
    assert(*(u64 *)(memory + 0x2010) == 0x20000028);
    assert(*(u64 *)(memory + 0x2018) == 0x20000018);
    r[0].offset = 0x1000; assert(ke_relocate(&io, &o, resolve, 0)); /* gap */
    r[0].offset = 0x4000; assert(ke_relocate(&io, &o, resolve, 0)); /* text */
    r[0].offset = ~0ULL; assert(ke_relocate(&io, &o, resolve, 0));
    r[0].offset = 0x2000; r[0].info = 1032;
    assert(ke_relocate(&io, &o, resolve, 0) == -EOPNOTSUPP);
    o.relasz = 0;
    o.relr = BASE + 0xd00; o.relrsz = 16;
    *(u64 *)(memory + 0xd00) = 0x2080;
    *(u64 *)(memory + 0xd08) = 1 | (1 << 1) | (1 << 3);
    *(u64 *)(memory + 0x2080) = 8;
    *(u64 *)(memory + 0x2088) = 16;
    *(u64 *)(memory + 0x2098) = 32;
    assert(!ke_relocate(&io, &o, resolve, 0));
    assert(*(u64 *)(memory + 0x2080) == BASE + 8 && *(u64 *)(memory + 0x2088) == BASE + 16);
    assert(*(u64 *)(memory + 0x2098) == BASE + 32);
    *(u64 *)(memory + 0xd00) = 3;
    assert(ke_relocate(&io, &o, resolve, 0));
    o.relrsz = 0;
    /* APS2: count=2, start=0x2000, group=2, flags=15,
     * offset delta=8, type=RELATIVE(1027), group addend=0x4000. */
    const u8 aps[] = {'A','P','S','2',2,0x80,0xc0,0,2,15,8,0x83,8,0x80,0x80,1};
    o.packed = BASE + 0xd00; o.packedsz = sizeof(aps);
    memcpy(memory + 0xd00, aps, sizeof(aps));
    assert(!ke_relocate(&io, &o, resolve, 0));
    assert(*(u64 *)(memory + 0x2008) == BASE + 0x4000 && *(u64 *)(memory + 0x2010) == BASE + 0x4000);
    memory[0xd08] = 0; assert(ke_relocate(&io, &o, resolve, 0)); /* zero group */
    memcpy(memory + 0xd00, aps, sizeof(aps));
    o.packedsz--; assert(ke_relocate(&io, &o, resolve, 0)); /* truncated SLEB */
    puts("manual RELA/RELR/APS2, signed addends, invalid targets/encoding: PASS");
}
static void ifunc_tests(void)
{
    struct ke_object o;
    init_fixture(); assert(!ke_open(&io, BASE, &o, 1));
    o.rela = BASE + 0xe00; o.relasz = 24;
    *(struct ke_rela *)(memory + 0xe00) = (struct ke_rela){0x2000, (1ULL << 32) | 257, -8};
    *(u64 *)(memory + 0x2000) = 0xfeed;
    assert(ke_relocate(&io, &o, resolve_ifunc, 0) == -EOPNOTSUPP);
    io.defer_ifunc = defer_ifunc;
    deferred = defer_error = 0;
    assert(!ke_relocate(&io, &o, resolve_ifunc, 0) && deferred == 1);
    assert(*(u64 *)(memory + 0x2000) == 0xfeed); /* EL1 must not execute/store a resolver. */
    defer_error = -E2BIG;
    assert(ke_relocate(&io, &o, resolve_ifunc, 0) == -E2BIG && deferred == 2);
    io.defer_ifunc = 0;
    io.write = 0;
    assert(ke_relocate(&io, &o, resolve, 0) == -EINVAL);
    io.write = write_mem;
    puts("imported IFUNC deferral, signed addend, callback failure, missing writer: PASS");
}
static u32 gnu_hash(const char *s)
{
    u32 h = 5381;
    while (*s) h = h * 33 + (u8)*s++;
    return h;
}
static void malformed_tests(void)
{
    struct ke_object o;
    struct ke_sym s;
    u64 value;
    struct ke_dyn *d = (void *)(memory + 0x200);
    u32 *h = (void *)(memory + 0xa00);
    init_fixture();
    d[5] = (struct ke_dyn){0x6fffe000, ~0ULL}; /* Android RELR pointer must not wrap. */
    d[6] = (struct ke_dyn){0x6fffe001, 8};
    assert(ke_open(&io, BASE, &o, 1));
    init_fixture();
    d[5] = (struct ke_dyn){14, (1ULL << 32) + 13};
    assert(ke_open(&io, BASE, &o, 1)); /* SONAME offset must not truncate. */
    init_fixture();
    d[5] = (struct ke_dyn){30, 0x100};
    assert(ke_open(&io, BASE, &o, 1) == -EOPNOTSUPP);
    init_fixture();
    d[5] = (struct ke_dyn){8, 24};
    assert(ke_open(&io, BASE, &o, 1)); /* size without a table */
    init_fixture();
    d[4] = (struct ke_dyn){0x6ffffef5, 0xa00};
    h[0] = 1; h[1] = 1; h[2] = 1; h[3] = 5;
    h[4] = h[5] = ~0U; h[6] = 1;
    h[7] = gnu_hash("fun") & ~1U; h[8] = gnu_hash("data") | 1U;
    assert(!ke_open(&io, BASE, &o, 1) && o.symcount == 3);
    assert(ke_lookup(&io, &o, "fun", "", 0, &s, &value) == 1 && value == BASE + 0x4000);
    assert(ke_lookup(&io, &o, "data", "", 0, &s, &value) == 1 && value == BASE + 0x2100);
    assert(!ke_lookup(&io, &o, "missing", "", 0, &s, &value));
    h[1] = 2;
    assert(ke_open(&io, BASE, &o, 1)); /* bucket precedes the symbol offset */
    init_fixture(); assert(!ke_open(&io, BASE, &o, 1));
    h[4] = 1;
    assert(ke_lookup(&io, &o, "missing", "", 0, &s, &value) == -ENOEXEC); /* cyclic SysV chain */
    o.rela = BASE + 0xe00; o.relasz = ((u64)KE_RELOCS + 1) * 24;
    assert(ke_relocate(&io, &o, resolve, 0) == -E2BIG);
    puts("GNU/SysV hash bounds/cycles, dynamic pointer/offset overflow, relocation budget: PASS");
}
static void file_tests(const char *path)
{
    struct ke_object o;
    FILE *f = fopen(path, "rb");
    assert(f);
    file_size = fread(snapshot, 1, sizeof(snapshot), f); assert(!ferror(f)); fclose(f);
    file_mode = 1;
    assert(!ke_headers(&io, 0, &o));
    assert(!ke_file_layout(&io, &o, file_size, 4096));
    assert(o.high < CAP);
    memset(memory, 0, sizeof(memory));
    u64 header = 0;
    for (unsigned i = 0; i < o.phnum; i++) if (o.ph[i].type == 1) {
        assert(o.ph[i].vaddr + o.ph[i].memsz < CAP);
        memcpy(memory + o.ph[i].vaddr, snapshot + o.ph[i].offset, o.ph[i].filesz);
        if (!o.ph[i].offset) header = BASE + o.ph[i].vaddr;
    }
    file_mode = 0;
    assert(!ke_open(&io, header, &o, 1));
    assert(o.nneeded && o.init_count);
    assert(!ke_relocate(&io, &o, resolve, 0));
    /* Every mutation is parsed through the same bounded production reader. */
    file_mode = 1;
    size_t full_size = file_size;
    for (size_t n = 0; n < 64; n++) { file_size = n; assert(ke_headers(&io, 0, &o)); }
    file_size = full_size;
    assert(!ke_headers(&io, 0, &o));
    o.ph[0].offset = ~0ULL; assert(ke_file_layout(&io, &o, file_size, 4096));
    assert(!ke_headers(&io, 0, &o));
    for (unsigned i = 0; i < o.phnum; i++) if (o.ph[i].type == 1) { o.ph[i].flags = 7; break; }
    assert(ke_file_layout(&io, &o, file_size, 4096));
    assert(!ke_headers(&io, 0, &o));
    o.tls = 1; assert(ke_file_layout(&io, &o, file_size, 4096));
    assert(!ke_headers(&io, 0, &o));
    o.ph[0].type = 0x6474e553U;
    assert(ke_file_layout(&io, &o, file_size, 4096) == -EOPNOTSUPP);
    assert(!ke_headers(&io, 0, &o));
    o.ph[0].type = 3;
    assert(ke_file_layout(&io, &o, file_size, 4096) == -EOPNOTSUPP);
    puts("existing Android payload, truncation, mapping and W^X rejection: PASS");
}
static void set_soname(void)
{
    ((struct ke_dyn *)(memory + 0x200))[5] = (struct ke_dyn){14, 13}; /* "libdep.so" */
}
static void loaded_veneer_fixture(void)
{
    init_fixture(); set_soname();
    memcpy(memory + 8, "\x50\x00\x00\x58\x00\x02\x1f\xd6\xfc\x8c\xce\x0c\x79\x00\x00\x00", 16);
}
static void loaded_header_tests(void)
{
    struct ke_object strict, loaded;
    char name[KE_NAME];
    /* An intact AArch64 provider has the same header contract as a payload. */
    init_fixture(); set_soname();
    assert(!ke_open(&io, BASE, &strict, 1));
    assert(!ke_open(&io, BASE, &loaded, 0));
    assert(loaded.symcount == strict.symcount && loaded.soname == 13);
    assert(!ke_string(&io, &loaded, loaded.soname, name) && !strcmp(name, "libdep.so"));

    /* A VMA can contain a mapped data file rather than a linker-loaded DSO.
     * Intact foreign architectures and arbitrary damaged headers must not
     * become providers just because the ELF magic and tables are plausible. */
    init_fixture(); set_soname();
    ((struct ke_ehdr *)memory)->machine = 62; /* EM_X86_64 */
    assert(ke_open(&io, BASE, &loaded, 0) == -ENOEXEC);
    assert(ke_open(&io, BASE, &strict, 1) == -ENOEXEC);
    init_fixture(); set_soname();
    ((struct ke_ehdr *)memory)->type = 2; /* ET_EXEC */
    assert(ke_open(&io, BASE, &loaded, 0) == -ENOEXEC);
    init_fixture(); set_soname();
    ((struct ke_ehdr *)memory)->version = 2;
    assert(ke_open(&io, BASE, &loaded, 0) == -ENOEXEC);
    init_fixture(); set_soname();
    memset(memory + 8, 0xa5, 16);
    assert(ke_open(&io, BASE, &loaded, 0) == -ENOEXEC);

    /* Anti-tamper veneer observed in the field: 16 bytes written at offset 8
     * clobber e_ident[8..15], e_type, e_machine and e_version.  A payload must
     * still be rejected; only the exact recognized veneer permits a provider. */
    loaded_veneer_fixture();
    assert(ke_open(&io, BASE, &loaded, 1));
    assert(ke_headers(&io, BASE, &strict));
    assert(!ke_open(&io, BASE, &loaded, 0));
    assert(loaded.symcount == 3 && loaded.soname == 13);
    assert(!ke_string(&io, &loaded, loaded.soname, name) && !strcmp(name, "libdep.so"));
    for (unsigned i = 8; i < 16; i++) {
        loaded_veneer_fixture();
        memory[i] ^= 1; /* Every byte in both instructions is mandatory. */
        assert(ke_open(&io, BASE, &loaded, 0) == -ENOEXEC);
    }

    /* The recognized overwrite never relaxes structural/table bounds. */
    loaded_veneer_fixture();
    ((struct ke_ehdr *)memory)->phnum = 0;
    assert(ke_open(&io, BASE, &loaded, 0));
    loaded_veneer_fixture();
    ((struct ke_ehdr *)memory)->phnum = KE_PHNUM + 1;
    assert(ke_open(&io, BASE, &loaded, 0));
    loaded_veneer_fixture();
    ((struct ke_ehdr *)memory)->ehsize = 8;
    assert(ke_open(&io, BASE, &loaded, 0));
    loaded_veneer_fixture();
    ((struct ke_ehdr *)memory)->phentsize = 8;
    assert(ke_open(&io, BASE, &loaded, 0));
    loaded_veneer_fixture();
    ((struct ke_ehdr *)memory)->phoff = 0xffffffffULL;
    assert(ke_open(&io, BASE, &loaded, 0));
    loaded_veneer_fixture();
    ((struct ke_phdr *)(memory + 64))[0].memsz = ~0ULL;
    assert(ke_open(&io, BASE, &loaded, 0));
    loaded_veneer_fixture();
    ((struct ke_dyn *)(memory + 0x200))[0].val = ~0ULL;
    assert(ke_open(&io, BASE, &loaded, 0));
    loaded_veneer_fixture();
    ((u32 *)(memory + 0xa00))[1] = KE_SYMS + 1;
    assert(ke_open(&io, BASE, &loaded, 0));
    loaded_veneer_fixture();
    memory[1] = 'X';
    assert(ke_open(&io, BASE, &loaded, 0));
    puts("loaded headers: strict architecture/type/version, recognized veneer only, bounded tables: PASS");
}
int main(int argc, char **argv)
{
    assert(argc == 2);
    symbol_tests(); relocation_tests(); ifunc_tests(); malformed_tests(); file_tests(argv[1]);
    loaded_header_tests();
    return 0;
}
