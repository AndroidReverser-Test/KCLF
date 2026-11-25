/* Host/Android regression for PT_TLS validation and TLSDESC relocation bounds. */
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include "kclf_elf.h"

#define BASE 0x100000ULL
static unsigned char bytes[8192];
static u64 read_base, captured_offset;
static unsigned descriptors;

static int read_bytes(void *context, u64 at, void *out, unsigned long n)
{
    (void)context;
    if (at < read_base || at - read_base > sizeof(bytes) || n > sizeof(bytes) - (at - read_base)) return -1;
    memcpy(out, bytes + at - read_base, n);
    return 0;
}

static int write_bytes(void *context, u64 at, const void *in, unsigned long n)
{
    (void)context;
    if (at < read_base || at - read_base > sizeof(bytes) || n > sizeof(bytes) - (at - read_base)) return -1;
    memcpy(bytes + at - read_base, in, n);
    return 0;
}

static int tlsdesc(void *context, u64 where, u64 offset)
{
    (void)context;
    assert(where == BASE + 4096 || where == BASE + 4112);
    descriptors++;
    captured_offset = offset;
    return 0;
}

static int resolve(void *context, u32 index, u64 *value)
{
    (void)context;
    (void)index;
    *value = 0;
    return 0;
}

int main(void)
{
    struct ke_io io = {.limit = 1ULL << 48, .read = read_bytes, .write = write_bytes, .tlsdesc = tlsdesc};
    struct ke_object object;
    struct ke_ehdr header = {0};
    struct ke_phdr ph[4] = {0};
    memcpy(header.ident, "\177ELF\2\1\1", 7);
    header.type = 3; header.machine = 183; header.version = 1;
    header.ehsize = sizeof(header); header.phoff = sizeof(header);
    header.phentsize = sizeof(ph[0]); header.phnum = 3;
    ph[0] = (struct ke_phdr){.type = 1, .flags = 4, .filesz = 4096, .memsz = 4096, .align = 4096};
    ph[1] = (struct ke_phdr){.type = 1, .flags = 6, .offset = 4096, .vaddr = 4096,
                           .filesz = 4096, .memsz = 4096, .align = 4096};
    ph[2] = (struct ke_phdr){.type = 7, .flags = 4, .offset = 4096, .vaddr = 4096,
                           .filesz = 8, .memsz = 16, .align = 8};
    memcpy(bytes, &header, sizeof(header));
    memcpy(bytes + sizeof(header), ph, sizeof(ph));
    assert(ke_headers(&io, 0, &object) == 0 && object.tls && object.tls_index == 2);
    assert(ke_file_layout(&io, &object, sizeof(bytes), 4096) == 0);

    /* File and virtual addresses must describe the same initialized bytes. */
    ph[2].offset += 4;
    memcpy(bytes + sizeof(header), ph, sizeof(ph));
    assert(ke_headers(&io, 0, &object) == 0);
    assert(ke_file_layout(&io, &object, sizeof(bytes), 4096) == -ENOEXEC);
    ph[2].vaddr += 4;
    memcpy(bytes + sizeof(header), ph, sizeof(ph));
    assert(ke_headers(&io, 0, &object) == 0);
    assert(ke_file_layout(&io, &object, sizeof(bytes), 4096) == 0);
    ph[2].vaddr -= 4;
    ph[2].offset -= 4;

    for (int test = 0; test < 8; test++) {
        struct ke_phdr saved = ph[2];
        if (test == 0) { header.phnum = 4; ph[3] = ph[2]; }
        if (test == 1) ph[2].align = 3;
        if (test == 2) ph[2].filesz = 17;
        if (test == 3) ph[2].memsz = KE_IMAGE_MAX + 1;
        if (test == 4) ph[2].offset = sizeof(bytes);
        if (test == 5) ph[2].vaddr = sizeof(bytes) + 4096;
        if (test == 6) ph[2].memsz = KE_IMAGE_MAX;
        if (test == 7) ph[2].align = KE_IMAGE_MAX;
        memcpy(bytes, &header, sizeof(header));
        memcpy(bytes + sizeof(header), ph, sizeof(ph));
        int rc = ke_headers(&io, 0, &object);
        if (test >= 4) {
            assert(rc == 0);
            rc = ke_file_layout(&io, &object, sizeof(bytes), 4096);
        }
        assert(rc == (test >= 6 ? -E2BIG : -ENOEXEC));
        ph[2] = saved; header.phnum = 3;
    }
    memset(&object, 0, sizeof(object));
    object.phnum = 3; object.tls = 1; object.tls_index = 2;
    memcpy(object.ph, ph, 3 * sizeof(ph[0]));
    object.bias = read_base = BASE;
    object.rela = BASE + 768; object.relasz = sizeof(struct ke_rela);
    object.symtab = BASE + 1024; object.symcount = 2;
    struct ke_rela rela = {.offset = 4096, .info = 1031, .addend = 0};
    struct ke_sym symbol = {.info = 0x16, .shndx = 1, .value = 8, .size = 8};
    memcpy(bytes + 1024 + sizeof(symbol), &symbol, sizeof(symbol));
    memcpy(bytes + 768, &rela, sizeof(rela));
    assert(ke_relocate(&io, &object, resolve, NULL) == 0 && descriptors == 1 && captured_offset == 0);
    rela.info |= 1ULL << 32;
    rela.addend = -2;
    memcpy(bytes + 768, &rela, sizeof(rela));
    assert(ke_relocate(&io, &object, resolve, NULL) == 0 && descriptors == 2 && captured_offset == 6);
    rela.addend = -9;
    memcpy(bytes + 768, &rela, sizeof(rela));
    assert(ke_relocate(&io, &object, resolve, NULL) == -ENOEXEC && descriptors == 2);
    rela.addend = 8;
    memcpy(bytes + 768, &rela, sizeof(rela));
    assert(ke_relocate(&io, &object, resolve, NULL) == -ENOEXEC && descriptors == 2);
    rela.addend = 0; rela.offset = sizeof(bytes) - 8;
    memcpy(bytes + 768, &rela, sizeof(rela));
    assert(ke_relocate(&io, &object, resolve, NULL) == -ENOEXEC && descriptors == 2);
    rela.offset = 4096;
    memcpy(bytes + 768, &rela, sizeof(rela));
    symbol.shndx = 0;
    memcpy(bytes + 1024 + sizeof(symbol), &symbol, sizeof(symbol));
    assert(ke_relocate(&io, &object, resolve, NULL) == -EOPNOTSUPP && descriptors == 2);
    symbol.shndx = 1; symbol.info = 0x11;
    memcpy(bytes + 1024 + sizeof(symbol), &symbol, sizeof(symbol));
    assert(ke_relocate(&io, &object, resolve, NULL) == -EOPNOTSUPP && descriptors == 2);

    /* Two symbol-zero TLSDESC relocations encoded as one APS2 group. */
    const unsigned char aps2[] = {'A', 'P', 'S', '2', 2, 0xf0, 0x1f, 2, 15, 16, 0x87, 8, 0};
    memcpy(bytes + 768, aps2, sizeof(aps2));
    object.rela = object.relasz = 0;
    object.packed = BASE + 768; object.packedsz = sizeof(aps2);
    assert(ke_relocate(&io, &object, resolve, NULL) == 0 && descriptors == 4);
    io.tlsdesc = NULL;
    assert(ke_relocate(&io, &object, resolve, NULL) == -EOPNOTSUPP && descriptors == 4);
    puts("PASS ELF TLS: segment validation, local symbols, signed addends, 16-byte destination, external-symbol rejection, APS2, missing runtime");
    return 0;
}
