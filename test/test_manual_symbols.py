#!/usr/bin/env python3
"""Run the production manual resolver/ELF reader with long names and emutls policy."""
from pathlib import Path
import subprocess
import tempfile

MODULE = Path(__file__).resolve().parents[1]
manual = (MODULE / "kclf_manual.c").read_text()
start = manual.index("static int read_symbol_name(")
end = manual.index("static int defer_ifunc(", start)
resolver = manual[start:end]

PRELUDE = r'''
#include "kclf_elf.h"
#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define KM_FILE_MAX (64UL * 1024 * 1024)
#define KM_NODELETE_EMUTLS 2
#define KCLF_F_UNLOAD 0x8
#define BASE 0x10000000ULL
#define CAP (1024 * 1024)
static unsigned char memory[CAP];
struct kclf_manual_image { int nodelete; };
struct kclf_req { char err[256]; unsigned flags; struct kclf_manual_image *image; };
struct km_provider { struct ke_object object; };
struct km_context {
    struct kclf_req *r;
    struct ke_io io;
    struct ke_object object;
    struct km_provider *providers;
    unsigned nscope, scope[1];
    u64 *values;
    u8 *resolved;
    char *symbol_name;
    unsigned long symbol_name_cap;
};
static unsigned live_allocations, allocation_calls;
static int fail_allocation;
static void *allocate(unsigned long size) {
    allocation_calls++;
    if (fail_allocation) return NULL;
    void *p = calloc(1, size);
    assert(p); live_allocations++;
    return p;
}
static void release(const void *p) { assert(p && live_allocations); live_allocations--; free((void *)p); }
static struct { void (*vfree)(const void *); } kclf_ks = {release};
static void kclf_set_err(struct kclf_req *r, const char *fmt, ...) {
    va_list ap; va_start(ap, fmt); vsnprintf(r->err, sizeof(r->err), fmt, ap); va_end(ap);
}
static void report(void *ctx, const char *why, const char *detail) {
    struct km_context *c = ctx;
    kclf_set_err(c->r, "%s: %s", why, detail);
}
static int rd(void *ctx, u64 at, void *out, unsigned long n) {
    (void)ctx;
    if (at < BASE || at - BASE > CAP || n > CAP - (at - BASE)) return -1;
    memcpy(out, memory + at - BASE, n); return 0;
}
static int wr(void *ctx, u64 at, const void *in, unsigned long n) {
    (void)ctx;
    if (at < BASE || at - BASE > CAP || n > CAP - (at - BASE)) return -1;
    memcpy(memory + at - BASE, in, n); return 0;
}
'''

MAIN = r'''
static struct km_context c;
static struct kclf_req request;
static struct kclf_manual_image image;
static struct km_provider provider;
static u64 values[2];
static u8 resolved[2];
static void reset(unsigned length, unsigned shndx, unsigned binding) {
    assert(!live_allocations);
    memset(&c, 0, sizeof(c)); memset(&request, 0, sizeof(request));
    memset(memory, 0, sizeof(memory)); memset(values, 0, sizeof(values)); memset(resolved, 0, sizeof(resolved));
    memset(&image, 0, sizeof(image)); request.image = &image;
    c.r = &request; c.io = (struct ke_io){&c, 1ULL << 48, rd, wr, report, NULL, NULL};
    c.values = values; c.resolved = resolved; c.providers = &provider;
    c.object.phnum = 1;
    c.object.ph[0] = (struct ke_phdr){1, 7, 0, 0, 0, CAP, CAP, 1};
    c.object.bias = BASE; c.object.symtab = BASE + 0x100; c.object.symcount = 2;
    c.object.strtab = BASE + 0x10000; c.object.strsz = length + 2;
    struct ke_sym *s = (void *)(memory + 0x100);
    s[1] = (struct ke_sym){1, (u8)((binding << 4) | 2), 0, (u16)shndx, 0x4000, 104};
    for (unsigned i = 0; i < length; i++) memory[0x10001 + i] = (u8)('a' + i % 26);
    provider.object = c.object;
    provider.object.symtab = BASE + 0x2000; provider.object.strtab = BASE + 0x30000;
    provider.object.hash = BASE + 0x2800;
    memcpy(memory + 0x30000, memory + 0x10000, length + 2);
    s = (void *)(memory + 0x2000);
    s[1] = (struct ke_sym){1, 0x12, 0, 1, 0x6000, 4};
    u32 *h = (void *)(memory + 0x2800);
    h[0] = 1; h[1] = 2; h[2] = 1;
    fail_allocation = 0; allocation_calls = 0;
}
static void finish(void) {
    if (c.symbol_name) release(c.symbol_name);
    c.symbol_name = NULL; assert(!live_allocations);
}
int main(void) {
    const unsigned lengths[] = {255, 256, 285, 4096};
    for (unsigned i = 0; i < sizeof(lengths) / sizeof(lengths[0]); i++) {
        u64 value = 0;
        reset(lengths[i], 15, 2);
        assert(!prepare_tls_policy(&c) && !image.nodelete);
        c.object.jmprel = BASE + 0x7000; c.object.pltsz = 24;
        *(struct ke_rela *)(memory + 0x7000) = (struct ke_rela){0x8000, (1ULL << 32) | 1026, 0};
        assert(!ke_relocate(&c.io, &c.object, resolve_import, &c));
        assert(*(u64 *)(memory + 0x8000) == BASE + 0x4000);
        unsigned calls = allocation_calls;
        assert(!resolve_import(&c, 1, &value) && value == BASE + 0x4000 && allocation_calls == calls);
        finish();
        reset(lengths[i], 0, 1); c.nscope = 1;
        assert(!resolve_import(&c, 1, &value) && value == BASE + 0x6000);
        finish();
        reset(lengths[i], 0, 2); c.nscope = 1;
        memory[0x30000 + lengths[i]] ^= 1;
        assert(!resolve_import(&c, 1, &value) && !value); /* weak, missing */
        finish();
    }
    puts("manual real JUMP_SLOT + defined/imported/weak/cache names 255/256/285/4096: PASS");
    u64 value;
    reset(285, 15, 2); fail_allocation = 1;
    assert(resolve_import(&c, 1, &value) == -ENOMEM && !live_allocations && !resolved[1]);
    fail_allocation = 0;
    assert(!resolve_import(&c, 1, &value));
    char *old = c.symbol_name; unsigned long cap = c.symbol_name_cap;
    memset(memory + 0x10001, 'b', 4096); memory[0x11001] = 0;
    c.object.strsz = 4098; resolved[1] = 0; fail_allocation = 1;
    assert(resolve_import(&c, 1, &value) == -ENOMEM && c.symbol_name == old && c.symbol_name_cap == cap);
    finish();
    reset(285, 15, 2);
    memory[0x10001 + 285] = 'x';
    assert(resolve_import(&c, 1, &value) == -ENOEXEC && !live_allocations);
    finish();
    reset(285, 15, 2); ((struct ke_sym *)(memory + 0x100))[1].name = 287;
    assert(resolve_import(&c, 1, &value) == -ENOEXEC && !live_allocations); finish();
    puts("manual name errors preserve errno; allocation/growth failures retain ownership: PASS");
    const char *blocked[] = {"__cxa_thread_atexit_impl", "__cxa_thread_atexit", "__cfi_slowpath", "__cfi_slowpath_diag"};
    for (unsigned i = 0; i < sizeof(blocked) / sizeof(blocked[0]); i++) {
        for (unsigned defined = 0; defined <= 1; defined++) {
            reset((unsigned)strlen(blocked[i]), defined, 1);
            strcpy((char *)memory + 0x10001, blocked[i]);
            assert(resolve_import(&c, 1, &value) == -EOPNOTSUPP && !resolved[1]); finish();
        }
    }
    const unsigned bad_info[] = {0x16, 0xa2, 0x1a};
    for (unsigned i = 0; i < sizeof(bad_info) / sizeof(bad_info[0]); i++) {
        reset(285, 15, 1); ((struct ke_sym *)(memory + 0x100))[1].info = (u8)bad_info[i];
        assert(resolve_import(&c, 1, &value) == -EOPNOTSUPP); finish();
    }
    puts("defined/undefined TLS destructor, CFI and GNU_UNIQUE/TLS/IFUNC refusal preserved: PASS");
    const char *emutls = "__emutls_get_address";
    reset((unsigned)strlen(emutls), 15, 2);
    strcpy((char *)memory + 0x10001, emutls);
    /* No relocation: even a directly bound local call must pin the image. */
    assert(!prepare_tls_policy(&c) && image.nodelete == KM_NODELETE_EMUTLS);
    assert(!resolve_import(&c, 1, &value) && value == BASE + 0x4000); finish();
    reset((unsigned)strlen(emutls), 15, 0);
    strcpy((char *)memory + 0x10001, emutls);
    assert(!prepare_tls_policy(&c) && image.nodelete == KM_NODELETE_EMUTLS); finish();
    reset((unsigned)strlen(emutls), 15, 2);
    strcpy((char *)memory + 0x10001, emutls); request.flags = KCLF_F_UNLOAD;
    assert(prepare_tls_policy(&c) == -EOPNOTSUPP && !image.nodelete);
    assert(strstr(request.err, "conflicts with unload")); finish();
    const unsigned invalid_sections[] = {0, 0xfff1, 0xff00};
    for (unsigned i = 0; i < sizeof(invalid_sections) / sizeof(invalid_sections[0]); i++) {
        reset((unsigned)strlen(emutls), invalid_sections[i], 2);
        strcpy((char *)memory + 0x10001, emutls);
        assert(prepare_tls_policy(&c) == -EOPNOTSUPP && !image.nodelete); finish();
    }
    reset((unsigned)strlen(emutls), 15, 2);
    strcpy((char *)memory + 0x10001, emutls); c.object.ph[0].flags = 6;
    assert(prepare_tls_policy(&c) == -ENOEXEC && !image.nodelete); finish();
    for (unsigned defined = 0; defined <= 1; defined++) {
        const char *control = "__emutls_v.test";
        reset((unsigned)strlen(control), defined, 1);
        strcpy((char *)memory + 0x10001, control);
        assert(prepare_tls_policy(&c) == -EOPNOTSUPP && !image.nodelete); finish();
    }
    reset(285, 15, 2);
    u64 budget = 128; c.io.string_budget = &budget;
    assert(prepare_tls_policy(&c) == -E2BIG && !image.nodelete && !live_allocations); finish();
    puts("local emutls pins without relocations; unload/imported/ABS/invalid/control-only cases reject; budget enforced: PASS");
    return 0;
}
'''

with tempfile.TemporaryDirectory(prefix="kclf-manual-symbols-") as directory:
    source, executable = Path(directory) / "test.c", Path(directory) / "test"
    source.write_text(PRELUDE + resolver + MAIN)
    subprocess.run(["gcc", "-std=gnu11", "-DKCLF_ELF_HOST", "-Wall", "-Wextra", "-Werror", "-g",
                    "-fsanitize=address,undefined", "-fno-omit-frame-pointer", "-I", str(MODULE),
                    str(MODULE / "kclf_elf.c"), str(source), "-o", str(executable)], check=True)
    subprocess.run([str(executable)], check=True)
